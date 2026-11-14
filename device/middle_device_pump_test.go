package device

import (
	"bytes"
	"os"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// scriptedReadResult is one canned result returned by scriptedTun.Read.
type scriptedReadResult struct {
	packets [][]byte
	err     error
}

// scriptedTun is a fake tun.Device whose Read returns a fixed sequence of
// results and then blocks until the device is closed.
type scriptedTun struct {
	mu      sync.Mutex
	results []scriptedReadResult
	closed  chan struct{}
	once    sync.Once
	events  chan tun.Event
}

func newScriptedTun(results ...scriptedReadResult) *scriptedTun {
	return &scriptedTun{
		results: results,
		closed:  make(chan struct{}),
		events:  make(chan tun.Event),
	}
}

func (s *scriptedTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	s.mu.Lock()
	if len(s.results) == 0 {
		s.mu.Unlock()
		<-s.closed
		return 0, os.ErrClosed
	}
	res := s.results[0]
	s.results = s.results[1:]
	s.mu.Unlock()

	for i, pkt := range res.packets {
		sizes[i] = copy(bufs[i][offset:], pkt)
	}
	return len(res.packets), res.err
}

func (s *scriptedTun) File() *os.File                   { return nil }
func (s *scriptedTun) Write([][]byte, int) (int, error) { return 0, nil }
func (s *scriptedTun) MTU() (int, error)                { return 1420, nil }
func (s *scriptedTun) Name() (string, error)            { return "scripted0", nil }
func (s *scriptedTun) Events() <-chan tun.Event         { return s.events }
func (s *scriptedTun) BatchSize() int                   { return 4 }
func (s *scriptedTun) Close() error                     { s.once.Do(func() { close(s.closed) }); return nil }

// TestMiddleDeviceReadSurvivesTooManySegments verifies that a transient
// tun.ErrTooManySegments from the underlying device neither drops the packets
// returned alongside it nor stops the pump, so later packets still reach the
// reader.
func TestMiddleDeviceReadSurvivesTooManySegments(t *testing.T) {
	first := buildIPv4UDPPacket([]byte("first-packet"))
	second := buildIPv4UDPPacket([]byte("second-packet"))

	fake := newScriptedTun(
		scriptedReadResult{packets: [][]byte{first}, err: tun.ErrTooManySegments},
		scriptedReadResult{packets: [][]byte{second}},
	)
	md := NewMiddleDevice(fake)
	defer md.Close()

	const offset = 16
	got := make(chan []byte, 8)
	go func() {
		for {
			bufs := make([][]byte, 4)
			sizes := make([]int, 4)
			for i := range bufs {
				bufs[i] = make([]byte, 2048)
			}
			n, err := md.Read(bufs, sizes, offset)
			if err != nil && err != tun.ErrTooManySegments {
				close(got)
				return
			}
			for i := 0; i < n; i++ {
				got <- append([]byte(nil), bufs[i][offset:offset+sizes[i]]...)
			}
		}
	}()

	want := [][]byte{first, second}
	deadline := time.After(2 * time.Second)
	for _, w := range want {
		select {
		case pkt, ok := <-got:
			if !ok {
				t.Fatalf("Read returned a fatal error before packet %q arrived", w[28:])
			}
			if !bytes.Equal(pkt, w) {
				t.Fatalf("got packet %q, want %q", pkt[28:], w[28:])
			}
		case <-deadline:
			t.Fatalf("timed out waiting for packet %q: pump stopped after transient read error", w[28:])
		}
	}
}
