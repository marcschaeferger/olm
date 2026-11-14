//go:build linux && !android

package dns

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	dbus "github.com/godbus/dbus/v5"
)

// startPrivateSystemBus starts a throwaway dbus-daemon and points
// DBUS_SYSTEM_BUS_ADDRESS at it so dbus.SystemBus() never reaches the host bus.
func startPrivateSystemBus(t *testing.T) {
	t.Helper()

	daemon, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Skip("dbus-daemon not available")
	}

	dir := t.TempDir()
	sock := filepath.Join(dir, "bus.sock")
	cmd := exec.Command(daemon, "--session", "--nofork", "--nopidfile", "--address=unix:path="+sock)
	if err := cmd.Start(); err != nil {
		t.Skipf("start dbus-daemon: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Skip("dbus-daemon did not create its socket in time")
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path="+sock)
}

// The connection returned by dbus.SystemBus() is process-wide and shared with
// concurrent callers (e.g. the system DNS monitor); helpers must not close it.
func TestDBusHelpersKeepSharedSystemBusOpen(t *testing.T) {
	startPrivateSystemBus(t)

	helpers := map[string]func(){
		"IsSystemdResolvedAvailable": func() { IsSystemdResolvedAvailable() },
		"IsNetworkManagerAvailable":  func() { IsNetworkManagerAvailable() },
		"GetNetworkManagerVersion":   func() { _, _ = GetNetworkManagerVersion() },
	}

	for name, helper := range helpers {
		t.Run(name, func(t *testing.T) {
			conn, err := dbus.SystemBus()
			if err != nil {
				t.Fatalf("connect to private system bus: %v", err)
			}

			helper()

			if !conn.Connected() {
				t.Fatalf("%s closed the shared system bus connection", name)
			}
			if err := conn.BusObject().Call("org.freedesktop.DBus.Peer.Ping", 0).Store(); err != nil {
				t.Fatalf("ping on shared system bus connection after %s: %v", name, err)
			}
		})
	}
}
