package api

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestStatusConcurrentWithPeerUpdates ensures /status and GetStatus can be
// served while peer statuses are being added, updated and removed. Before the
// fix the handler marshalled the live peer map after releasing the lock, which
// the Go runtime aborts with "concurrent map iteration and map write".
func TestStatusConcurrentWithPeerUpdates(t *testing.T) {
	s := NewAPIStub()
	for id := 0; id < 16; id++ {
		s.AddPeerStatus(id, "site", true, time.Millisecond, "1.2.3.4:51820", false, false)
	}
	s.SetGatewayStatus(true, 1, []int{1, 2})

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			id := i % 32
			s.UpdatePeerStatus(id, i%2 == 0, time.Duration(i), "5.6.7.8:51820", i%3 == 0, false)
			s.UpdatePeerHolepunchStatus(id, i%2 == 1)
			s.RemovePeerStatus((i + 7) % 32)
			s.SetGatewayStatus(true, 1, []int{id})
		}
	}()

	for i := 0; i < 2000; i++ {
		rec := httptest.NewRecorder()
		s.handleStatus(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
		if rec.Code != http.StatusOK {
			close(stop)
			wg.Wait()
			t.Fatalf("unexpected status code %d", rec.Code)
		}

		status := s.GetStatus()
		for _, p := range status.PeerStatuses {
			_ = p.Connected
		}
		_ = len(status.GatewaySiteIds)
	}

	close(stop)
	wg.Wait()
}

// TestGetStatusReturnsSnapshot ensures callers of GetStatus receive a copy that
// is not affected by later updates to the API's internal state.
func TestGetStatusReturnsSnapshot(t *testing.T) {
	s := NewAPIStub()
	s.AddPeerStatus(1, "site", true, time.Millisecond, "1.2.3.4:51820", false, false)

	snap := s.GetStatus()

	s.UpdatePeerStatus(1, false, time.Second, "5.6.7.8:51820", true, false)
	s.AddPeerStatus(2, "other", true, 0, "", false, false)

	if len(snap.PeerStatuses) != 1 {
		t.Fatalf("snapshot peer count changed to %d", len(snap.PeerStatuses))
	}
	if p := snap.PeerStatuses[1]; !p.Connected || p.Endpoint != "1.2.3.4:51820" {
		t.Fatalf("snapshot peer mutated: %+v", *p)
	}
}
