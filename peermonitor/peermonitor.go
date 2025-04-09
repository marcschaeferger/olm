package peermonitor

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/fosrl/olm/wgtester"
)

// PeerMonitorCallback is the function type for connection status change callbacks
type PeerMonitorCallback func(siteID int, connected bool, rtt time.Duration)

// PeerMonitor handles monitoring the connection status to multiple WireGuard peers
type PeerMonitor struct {
	monitors    map[int]*wgtester.Client
	callback    PeerMonitorCallback
	mutex       sync.Mutex
	running     bool
	interval    time.Duration
	timeout     time.Duration
	maxAttempts int
}

// NewPeerMonitor creates a new peer monitor with the given callback
func NewPeerMonitor(callback PeerMonitorCallback) *PeerMonitor {
	return &PeerMonitor{
		monitors:    make(map[int]*wgtester.Client),
		callback:    callback,
		interval:    5 * time.Second, // Default check interval
		timeout:     500 * time.Millisecond,
		maxAttempts: 3,
	}
}

// SetInterval changes how frequently peers are checked
func (pm *PeerMonitor) SetInterval(interval time.Duration) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.interval = interval

	// Update interval for all existing monitors
	for _, client := range pm.monitors {
		client.SetPacketInterval(interval)
	}
}

// SetTimeout changes the timeout for waiting for responses
func (pm *PeerMonitor) SetTimeout(timeout time.Duration) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.timeout = timeout

	// Update timeout for all existing monitors
	for _, client := range pm.monitors {
		client.SetTimeout(timeout)
	}
}

// SetMaxAttempts changes the maximum number of attempts for TestConnection
func (pm *PeerMonitor) SetMaxAttempts(attempts int) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.maxAttempts = attempts

	// Update max attempts for all existing monitors
	for _, client := range pm.monitors {
		client.SetMaxAttempts(attempts)
	}
}

// AddPeer adds a new peer to monitor
func (pm *PeerMonitor) AddPeer(siteID int, endpoint string) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// Check if we're already monitoring this peer
	if _, exists := pm.monitors[siteID]; exists {
		// Update the endpoint instead of creating a new monitor
		pm.RemovePeer(siteID)
	}

	// Add UDP port if not present, assuming default WireGuard port
	if _, _, err := net.SplitHostPort(endpoint); err != nil {
		endpoint = endpoint + ":51820" // Default WireGuard port
	}

	client, err := wgtester.NewClient(endpoint)
	if err != nil {
		return err
	}

	// Configure the client with our settings
	client.SetPacketInterval(pm.interval)
	client.SetTimeout(pm.timeout)
	client.SetMaxAttempts(pm.maxAttempts)

	// Store the client
	pm.monitors[siteID] = client

	// If monitor is already running, start monitoring this peer
	if pm.running {
		siteIDCopy := siteID // Create a copy for the closure
		err = client.StartMonitor(func(status wgtester.ConnectionStatus) {
			pm.callback(siteIDCopy, status.Connected, status.RTT)
		})
	}

	return err
}

// RemovePeer stops monitoring a peer and removes it from the monitor
func (pm *PeerMonitor) RemovePeer(siteID int) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	client, exists := pm.monitors[siteID]
	if !exists {
		return
	}

	client.StopMonitor()
	client.Close()
	delete(pm.monitors, siteID)
}

// Start begins monitoring all peers
func (pm *PeerMonitor) Start() {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if pm.running {
		return // Already running
	}

	pm.running = true

	// Start monitoring all peers
	for siteID, client := range pm.monitors {
		siteIDCopy := siteID // Create a copy for the closure
		client.StartMonitor(func(status wgtester.ConnectionStatus) {
			pm.callback(siteIDCopy, status.Connected, status.RTT)
		})
	}
}

// Stop stops monitoring all peers
func (pm *PeerMonitor) Stop() {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if !pm.running {
		return
	}

	pm.running = false

	// Stop all monitors
	for _, client := range pm.monitors {
		client.StopMonitor()
	}
}

// Close stops monitoring and cleans up resources
func (pm *PeerMonitor) Close() {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// Stop and close all clients
	for siteID, client := range pm.monitors {
		client.StopMonitor()
		client.Close()
		delete(pm.monitors, siteID)
	}

	pm.running = false
}

// TestPeer tests connectivity to a specific peer
func (pm *PeerMonitor) TestPeer(siteID int) (bool, time.Duration, error) {
	pm.mutex.Lock()
	client, exists := pm.monitors[siteID]
	pm.mutex.Unlock()

	if !exists {
		return false, 0, fmt.Errorf("peer with siteID %d not found", siteID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), pm.timeout*time.Duration(pm.maxAttempts))
	defer cancel()

	connected, rtt := client.TestConnection(ctx)
	return connected, rtt, nil
}

// TestAllPeers tests connectivity to all peers
func (pm *PeerMonitor) TestAllPeers() map[int]struct {
	Connected bool
	RTT       time.Duration
} {
	pm.mutex.Lock()
	peers := make(map[int]*wgtester.Client, len(pm.monitors))
	for siteID, client := range pm.monitors {
		peers[siteID] = client
	}
	pm.mutex.Unlock()

	results := make(map[int]struct {
		Connected bool
		RTT       time.Duration
	})
	for siteID, client := range peers {
		ctx, cancel := context.WithTimeout(context.Background(), pm.timeout*time.Duration(pm.maxAttempts))
		connected, rtt := client.TestConnection(ctx)
		cancel()

		results[siteID] = struct {
			Connected bool
			RTT       time.Duration
		}{
			Connected: connected,
			RTT:       rtt,
		}
	}

	return results
}
