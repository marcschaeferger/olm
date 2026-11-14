package peers

import (
	"net"
	"testing"
	"time"

	"github.com/fosrl/olm/api"
	"github.com/fosrl/olm/dns"
	"github.com/fosrl/olm/peers/monitor"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	sharedAliasName = "shared.example.com"
	sharedAliasIP   = "100.96.0.50"
)

// newSharedAliasTestManager returns a PeerManager with a real DNS proxy
// (record store only - no tunnel DNS, so no MiddleDevice is needed) and two
// site peers (1 and 2) that both publish the same alias -> IP mapping, the
// way AddPeer would register them. A zero-value PeerMonitor and an API stub
// stand in for the parts of RemovePeer unrelated to DNS.
func newSharedAliasTestManager(t *testing.T) (*PeerManager, *dns.DNSProxy) {
	t.Helper()

	proxy, err := dns.NewDNSProxy(nil, 1420, "100.96.128.0/24", []string{"127.0.0.1:53"}, false, "", nil, nil)
	if err != nil {
		t.Fatalf("NewDNSProxy: %v", err)
	}
	t.Cleanup(proxy.Stop)

	dev, privKey := newTestDevice(t)

	pm := &PeerManager{
		device:                dev,
		dnsProxy:              proxy,
		peerMonitor:           &monitor.PeerMonitor{},
		APIServer:             api.NewAPIStub(),
		peers:                 make(map[int]SiteConfig),
		allowedIPOwners:       make(map[string]int),
		allowedIPClaims:       make(map[string]map[int]bool),
		lastOwnerChange:       make(map[string]time.Time),
		gatewaySiteIds:        make(map[int]bool),
		gatewayExcludedIPs:    make(map[string]int),
		gatewayExtraEndpoints: make(map[string]bool),
		privateKey:            privKey,
		interfaceName:         "fake0",
		localIP:               "100.90.128.8",
	}

	for _, siteId := range []int{1, 2} {
		peerKey, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			t.Fatalf("GeneratePrivateKey: %v", err)
		}
		pm.peers[siteId] = SiteConfig{
			SiteId:    siteId,
			PublicKey: peerKey.PublicKey().String(),
			Aliases:   []Alias{{Alias: sharedAliasName, AliasAddress: sharedAliasIP}},
		}
		pm.addDNSRecord(sharedAliasName, net.ParseIP(sharedAliasIP), siteId)
	}

	return pm, proxy
}

func requireSharedAliasResolves(t *testing.T, proxy *dns.DNSProxy, context string) {
	t.Helper()
	ips, ok := proxy.GetDNSRecords(sharedAliasName, dns.RecordTypeA)
	if !ok || len(ips) != 1 || !ips[0].Equal(net.ParseIP(sharedAliasIP)) {
		t.Fatalf("%s: alias %s still published by site 2 must keep resolving to %s, got %v (exists=%v)",
			context, sharedAliasName, sharedAliasIP, ips, ok)
	}
}

// TestRemovePeerKeepsAliasSharedWithOtherSite verifies that removing one site
// only drops that site's ownership of a shared alias record, so the alias
// keeps resolving for the other site that still publishes it.
func TestRemovePeerKeepsAliasSharedWithOtherSite(t *testing.T) {
	pm, proxy := newSharedAliasTestManager(t)
	requireSharedAliasResolves(t, proxy, "setup")

	if err := pm.RemovePeer(1); err != nil {
		t.Fatalf("RemovePeer(1): %v", err)
	}
	requireSharedAliasResolves(t, proxy, "after RemovePeer(1)")

	if err := pm.RemovePeer(2); err != nil {
		t.Fatalf("RemovePeer(2): %v", err)
	}
	if ips, ok := proxy.GetDNSRecords(sharedAliasName, dns.RecordTypeA); ok {
		t.Fatalf("alias must be gone once its last owner is removed, got %v", ips)
	}
}

// TestUpdatePeerDroppingAliasKeepsAliasSharedWithOtherSite verifies that an
// update which drops a shared alias from one site does not remove the record
// still published by another site.
func TestUpdatePeerDroppingAliasKeepsAliasSharedWithOtherSite(t *testing.T) {
	pm, proxy := newSharedAliasTestManager(t)

	// Empty PublicKey: UpdatePeer only reconciles aliases and returns early,
	// which is exactly the part under test.
	if err := pm.UpdatePeer(SiteConfig{SiteId: 1}); err != nil {
		t.Fatalf("UpdatePeer(1): %v", err)
	}
	requireSharedAliasResolves(t, proxy, "after UpdatePeer(1) dropped the alias")
}
