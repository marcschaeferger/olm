//go:build (linux && !android) || freebsd

package dns

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDetectDNSManagerFallsBackToFileWhenResolvedUnreachable covers a
// resolv.conf that names systemd-resolved while resolved cannot be reached
// over D-Bus. Detection must fall back to FileManager instead of exiting the
// process (the Go test runner fails a test that calls os.Exit(0)).
func TestDetectDNSManagerFallsBackToFileWhenResolvedUnreachable(t *testing.T) {
	dir := t.TempDir()
	resolvConf := filepath.Join(dir, "resolv.conf")
	content := "# This is /run/systemd/resolve/stub-resolv.conf managed by man:systemd-resolved(8).\n" +
		"nameserver 127.0.0.53\n"
	if err := os.WriteFile(resolvConf, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	orig := defaultResolvConfPath
	defaultResolvConfPath = resolvConf
	t.Cleanup(func() { defaultResolvConfPath = orig })

	// Point the system bus at a socket that does not exist so systemd-resolved
	// is reported as unavailable regardless of the host.
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path="+filepath.Join(dir, "no-such-bus"))

	if hint := DetectDNSManagerFromFile(); hint != SystemdResolvedManager {
		t.Fatalf("DetectDNSManagerFromFile() = %v, want %v", hint, SystemdResolvedManager)
	}

	if got := DetectDNSManager("olm0"); got != FileManager {
		t.Fatalf("DetectDNSManager() = %v, want %v", got, FileManager)
	}
}
