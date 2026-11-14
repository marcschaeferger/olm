package dns

import (
	"net"
	"sync"
	"testing"

	"github.com/fosrl/newt/logger"
	"github.com/miekg/dns"
)

// closedUDPAddr returns a loopback UDP address with nothing listening on it,
// so upstream queries to it fail fast instead of waiting for a timeout.
func closedUDPAddr(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve UDP port: %v", err)
	}
	addr := conn.LocalAddr().String()
	conn.Close()
	return addr
}

// TestRuntimeSettersConcurrentWithUpstreamForwarding exercises the runtime
// setters (SetUpstreamDNS, SetTunnelDNS, SetJITHandler) while queries are being
// forwarded upstream from other goroutines, as happens when the server pushes a
// new DNS config while the proxy is serving traffic. Run with -race.
func TestRuntimeSettersConcurrentWithUpstreamForwarding(t *testing.T) {
	// The newt logger initializes itself lazily without synchronization;
	// initialize it up front so the race detector only reports DNSProxy state.
	logger.Init(nil)

	one := []string{closedUDPAddr(t)}
	two := []string{closedUDPAddr(t), closedUDPAddr(t)}

	proxy := &DNSProxy{
		upstreamDNS:       one,
		recordStore:       NewDNSRecordStore(),
		tunnelActivePorts: make(map[uint16]bool),
	}

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	const iterations = 200
	var wg sync.WaitGroup

	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				proxy.forwardToUpstream(query.Copy())
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			if i%2 == 0 {
				proxy.SetUpstreamDNS(two)
			} else {
				proxy.SetUpstreamDNS(one)
			}
			proxy.SetTunnelDNS(false)
			proxy.SetJITHandler(func(int) {})
		}
	}()

	wg.Wait()
}
