package dns

import (
	"net/netip"
	"reflect"
	"sync"
	"testing"
)

// stubReachable overrides dnsServerReachable for the duration of the test so
// tests don't depend on real network access, restoring the original on
// cleanup.
func stubReachable(t *testing.T, fn func(server string) bool) {
	t.Helper()
	orig := dnsServerReachable
	dnsServerReachable = func(server string) (bool, error) { return fn(server), nil }
	t.Cleanup(func() { dnsServerReachable = orig })
}

func allReachable(t *testing.T) {
	stubReachable(t, func(string) bool { return true })
}

func TestReportExternalFiltersExcludedIP(t *testing.T) {
	allReachable(t)

	var got []string
	m := &SystemDNSMonitor{
		excludeIPs: make(map[netip.Addr]bool),
		onChange: func(servers []string) {
			got = servers
		},
	}
	m.SetExcludeIP(netip.MustParseAddr("10.0.0.1"))

	m.ReportExternal([]string{"10.0.0.1:53", "8.8.8.8:53"})

	want := []string{"8.8.8.8:53"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("onChange servers = %v, want %v", got, want)
	}
	if !reflect.DeepEqual(m.Current(), want) {
		t.Fatalf("Current() = %v, want %v", m.Current(), want)
	}
}

func TestReportExternalAllExcludedIsNoop(t *testing.T) {
	allReachable(t)

	called := false
	m := &SystemDNSMonitor{
		excludeIPs: make(map[netip.Addr]bool),
		current:    []string{"1.1.1.1:53"},
		onChange: func(servers []string) {
			called = true
		},
	}
	m.SetExcludeIP(netip.MustParseAddr("10.0.0.1"))

	m.ReportExternal([]string{"10.0.0.1:53"})

	if called {
		t.Fatal("onChange should not fire when all reported servers are excluded")
	}
	want := []string{"1.1.1.1:53"}
	if !reflect.DeepEqual(m.Current(), want) {
		t.Fatalf("Current() = %v, want unchanged %v", m.Current(), want)
	}
}

func TestReportExternalOnlyFiresOnChange(t *testing.T) {
	allReachable(t)

	calls := 0
	m := &SystemDNSMonitor{
		excludeIPs: make(map[netip.Addr]bool),
		onChange: func(servers []string) {
			calls++
		},
	}

	m.ReportExternal([]string{"8.8.8.8:53"})
	m.ReportExternal([]string{"8.8.8.8:53"})

	if calls != 1 {
		t.Fatalf("onChange fired %d times, want 1", calls)
	}
}

func TestReportExternalDropsUnreachableServer(t *testing.T) {
	// Simulates e.g. T-Mobile's private ULA DNS64 resolver: technically "the
	// system DNS" per the OS, but doesn't actually answer queries.
	stubReachable(t, func(server string) bool {
		return server != "[fd00:976a::9]:53"
	})

	var got []string
	m := &SystemDNSMonitor{
		excludeIPs: make(map[netip.Addr]bool),
		onChange: func(servers []string) {
			got = servers
		},
	}

	m.ReportExternal([]string{"[fd00:976a::9]:53", "8.8.8.8:53"})

	want := []string{"8.8.8.8:53"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("onChange servers = %v, want %v", got, want)
	}
}

func TestReportExternalKeepsPreviousValueWhenAllUnreachable(t *testing.T) {
	stubReachable(t, func(string) bool { return true })

	called := false
	m := &SystemDNSMonitor{
		excludeIPs: make(map[netip.Addr]bool),
		current:    []string{"1.1.1.1:53"},
		onChange: func(servers []string) {
			called = true
		},
	}

	// Now simulate every candidate failing the health check (e.g. moved to a
	// network where none of the reported servers actually respond).
	stubReachable(t, func(string) bool { return false })

	m.ReportExternal([]string{"[fd00:976a::9]:53", "[fd00:976a::10]:53"})

	if called {
		t.Fatal("onChange should not fire when no candidate passes the health check")
	}
	want := []string{"1.1.1.1:53"}
	if !reflect.DeepEqual(m.Current(), want) {
		t.Fatalf("Current() = %v, want unchanged %v", m.Current(), want)
	}
}

func TestFilterUnreachable(t *testing.T) {
	stubReachable(t, func(server string) bool {
		return server == "8.8.8.8:53"
	})

	got := filterUnreachable([]string{"10.0.0.1:53", "8.8.8.8:53", "9.9.9.9:53"})
	want := []string{"8.8.8.8:53"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filterUnreachable() = %v, want %v", got, want)
	}
}

func TestApplyCandidatesRevalidatesAfterFailedHealthCheck(t *testing.T) {
	// The new DNS server is not answering yet when it is first reported (e.g.
	// the link is still coming up) but starts answering shortly after. The
	// unchanged candidate list must be re-probed on later polls instead of
	// being cached as "already seen".
	var mu sync.Mutex
	probes := 0
	stubReachable(t, func(server string) bool {
		mu.Lock()
		defer mu.Unlock()
		probes++
		return probes > 1
	})

	var got []string
	m := &SystemDNSMonitor{
		excludeIPs: make(map[netip.Addr]bool),
		current:    []string{"10.0.0.1:53"},
		onChange: func(servers []string) {
			got = servers
		},
	}

	for i := 0; i < 3; i++ {
		m.applyCandidates([]string{"192.168.50.1:53"})
	}

	want := []string{"192.168.50.1:53"}
	if !reflect.DeepEqual(m.Current(), want) {
		t.Fatalf("Current() = %v, want %v once the server answers", m.Current(), want)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("onChange servers = %v, want %v", got, want)
	}
}

func TestApplyCandidatesRevalidatesPartiallyReachableList(t *testing.T) {
	// One of two candidates fails its first health check. Later polls with the
	// same candidate list must re-probe it so it is picked up once it answers.
	var mu sync.Mutex
	failedOnce := false
	stubReachable(t, func(server string) bool {
		mu.Lock()
		defer mu.Unlock()
		if server == "192.168.50.2:53" && !failedOnce {
			failedOnce = true
			return false
		}
		return true
	})

	m := &SystemDNSMonitor{excludeIPs: make(map[netip.Addr]bool)}

	raw := []string{"192.168.50.1:53", "192.168.50.2:53"}
	m.applyCandidates(raw)
	if want := []string{"192.168.50.1:53"}; !reflect.DeepEqual(m.Current(), want) {
		t.Fatalf("after first poll Current() = %v, want %v", m.Current(), want)
	}

	m.applyCandidates(raw)
	if !reflect.DeepEqual(m.Current(), raw) {
		t.Fatalf("after second poll Current() = %v, want %v", m.Current(), raw)
	}
}
