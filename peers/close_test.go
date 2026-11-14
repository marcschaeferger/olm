package peers

import (
	"fmt"
	"testing"
	"time"

	"github.com/fosrl/olm/api"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// newClosedTestManager returns a PeerManager in the state Close() leaves
// behind: no peer monitor. Resource routes are marked suppressed so AddPeer/
// UpdatePeer/RemovePeer skip the OS routing table (see addRoutes/
// addServerRoute), keeping the test free of privileges and side effects.
func newClosedTestManager(t *testing.T) *PeerManager {
	t.Helper()
	dev, privKey := newTestDevice(t)
	pm := &PeerManager{
		device:                   dev,
		privateKey:               privKey,
		peers:                    make(map[int]SiteConfig),
		allowedIPOwners:          make(map[string]int),
		allowedIPClaims:          make(map[string]map[int]bool),
		lastOwnerChange:          make(map[string]time.Time),
		gatewaySiteIds:           make(map[int]bool),
		gatewayExcludedIPs:       make(map[string]int),
		gatewayExtraEndpoints:    make(map[string]bool),
		APIServer:                api.NewAPIStub(),
		interfaceName:            "fake0",
		localIP:                  "100.90.128.8",
		resourceRoutesSuppressed: true,
	}
	pm.Close()
	return pm
}

func callNoPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s after Close panicked: %v", name, r)
		}
	}()
	fn()
}

// TestOptimizeRoutesConcurrentWithCloseDoesNotPanic covers the teardown race:
// the route optimizer goroutine can be blocked on pm.mu while Close() nils
// out pm.peerMonitor, and then runs with shared claims still registered.
func TestOptimizeRoutesConcurrentWithCloseDoesNotPanic(t *testing.T) {
	pm := &PeerManager{
		peers:           make(map[int]SiteConfig),
		allowedIPOwners: map[string]int{"10.0.0.0/24": 1},
		allowedIPClaims: map[string]map[int]bool{
			"10.0.0.0/24": {1: true, 2: true},
		},
		lastOwnerChange: make(map[string]time.Time),
	}

	pm.mu.Lock()
	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("optimizeRoutes after Close panicked: %v", r)
				return
			}
			done <- nil
		}()
		pm.optimizeRoutes()
	}()
	// Apply Close's state change while the optimizer waits for the lock.
	pm.peerMonitor = nil
	pm.mu.Unlock()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("optimizeRoutes did not return")
	}
}

// TestPeerMutatorsAfterCloseDoNotPanic verifies the public PeerManager
// mutators tolerate being called after Close() has released the peer monitor
// (e.g. a websocket message handled during tunnel teardown).
func TestPeerMutatorsAfterCloseDoNotPanic(t *testing.T) {
	pm := newClosedTestManager(t)

	otherKey := mustPublicKey(t)
	site := SiteConfig{
		SiteId:        7,
		PublicKey:     mustPublicKey(t),
		Endpoint:      "127.0.0.1:1", // never dialed - IpcSet doesn't connect
		ServerIP:      "100.90.128.1/20",
		ServerPort:    51820,
		RemoteSubnets: []string{"172.18.21.0/24"},
	}
	other := site
	other.SiteId = 8
	other.PublicKey = otherKey
	other.ServerIP = "100.90.128.2/20"

	callNoPanic(t, "AddPeer", func() {
		if err := pm.AddPeer(site); err != nil {
			t.Fatalf("AddPeer: %v", err)
		}
		if err := pm.AddPeer(other); err != nil {
			t.Fatalf("AddPeer (other): %v", err)
		}
	})

	callNoPanic(t, "UpdatePeer", func() {
		updated := site
		updated.RemoteSubnets = []string{"172.18.22.0/24"}
		if err := pm.UpdatePeer(updated); err != nil {
			t.Fatalf("UpdatePeer: %v", err)
		}
	})

	callNoPanic(t, "MarkPeerRelayed", func() { pm.MarkPeerRelayed(site.SiteId, true) })
	callNoPanic(t, "UnRelayPeer", func() {
		if err := pm.UnRelayPeer(site.SiteId, "127.0.0.1:2"); err != nil {
			t.Fatalf("UnRelayPeer: %v", err)
		}
	})
	callNoPanic(t, "optimizeRoutes", pm.optimizeRoutes)

	callNoPanic(t, "RemovePeer", func() {
		if err := pm.RemovePeer(site.SiteId); err != nil {
			t.Fatalf("RemovePeer: %v", err)
		}
	})
}

func mustPublicKey(t *testing.T) string {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	return k.PublicKey().String()
}
