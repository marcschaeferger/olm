package dns

import (
	"net/netip"
	"testing"
)

func TestNewDNSProxyRejectsIPv6UtilitySubnet(t *testing.T) {
	// The proxy netstack is IPv4-only, so an IPv6 utility subnet must be
	// reported as an error rather than panicking in As4().
	proxy, err := NewDNSProxy(nil, 1420, "fd00:1234::/64", []string{"8.8.8.8:53"}, false, "", nil, nil)
	if err == nil {
		proxy.Stop()
		t.Fatal("Expected error for an IPv6 utility subnet, got nil")
	}
}

func TestInitTunnelNetstackRejectsIPv6TunnelIP(t *testing.T) {
	proxy := &DNSProxy{
		mtu:      1420,
		tunnelIP: netip.MustParseAddr("fd00::1"),
	}
	defer func() {
		if proxy.tunnelStack != nil {
			proxy.tunnelStack.Close()
		}
	}()

	if err := proxy.initTunnelNetstack(); err == nil {
		t.Fatal("Expected error for an IPv6 tunnel IP, got nil")
	}
}

func TestInitTunnelNetstackRejectsMissingTunnelIP(t *testing.T) {
	proxy := &DNSProxy{mtu: 1420}
	defer func() {
		if proxy.tunnelStack != nil {
			proxy.tunnelStack.Close()
		}
	}()

	if err := proxy.initTunnelNetstack(); err == nil {
		t.Fatal("Expected error for a missing tunnel IP, got nil")
	}
}
