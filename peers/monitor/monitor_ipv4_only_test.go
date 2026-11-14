package monitor

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestInitNetstackRejectsIPv6LocalIP(t *testing.T) {
	pm := &PeerMonitor{localIP: "fd00::1"}
	defer func() {
		if pm.stack != nil {
			pm.stack.Close()
		}
	}()

	// The monitor netstack is IPv4-only; an IPv6 local IP must be an error, not a panic.
	if err := pm.initNetstack(); err == nil {
		t.Fatal("Expected error for an IPv6 local IP, got nil")
	}
}

func TestDialRejectsNonIPv4Addresses(t *testing.T) {
	tests := []struct {
		name    string
		localIP string
		addr    string
	}{
		{name: "IPv6 remote", localIP: "100.90.128.1", addr: "[2001:db8::1]:21820"},
		{name: "empty remote host", localIP: "100.90.128.1", addr: ":21820"},
		{name: "IPv6 local", localIP: "fd00::1", addr: "100.90.128.2:21820"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm := &PeerMonitor{
				localIP:     tt.localIP,
				stack:       stack.New(stack.Options{}),
				activePorts: make(map[uint16]bool),
			}
			defer pm.stack.Close()

			// The server-supplied address must be rejected with an error rather than panicking.
			conn, err := pm.dial("udp", tt.addr)
			if err == nil {
				conn.Close()
				t.Fatalf("Expected error dialing %q from %q, got nil", tt.addr, tt.localIP)
			}
		})
	}
}
