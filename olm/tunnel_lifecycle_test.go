package olm

import (
	"context"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/fosrl/olm/api"
	"github.com/fosrl/olm/dns"
	"github.com/fosrl/olm/websocket"
)

// newRunningTunnelOlm returns an Olm that looks like StartTunnel got past its
// setup and is waiting on the tunnel context, without touching the host
// (NativeDNSManaged keeps Close from restoring system DNS).
func newRunningTunnelOlm(t *testing.T) (*Olm, context.Context) {
	t.Helper()

	tunnelCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	o := &Olm{
		olmCtx:          context.Background(),
		apiServer:       api.NewAPIStub(),
		stopPeerSends:   make(map[string]func()),
		stopPeerInits:   make(map[string]func()),
		jitPendingSites: make(map[int]string),
		tunnelRunning:   true,
		registered:      true,
		tunnelCancel:    cancel,
		tunnelConfig:    TunnelConfig{NativeDNSManaged: true},
	}
	return o, tunnelCtx
}

func assertTunnelStopped(t *testing.T, o *Olm, tunnelCtx context.Context) {
	t.Helper()

	if o.tunnelRunning {
		t.Error("tunnelRunning is still true after the tunnel was torn down; a new connect would be ignored as \"already running\"")
	}
	if o.registered {
		t.Error("registered is still true after the tunnel was torn down; the next tunnel would skip registration")
	}
	select {
	case <-tunnelCtx.Done():
	default:
		t.Error("tunnel context was not cancelled; the StartTunnel goroutine would stay blocked and hold tunnelWg")
	}
}

func TestHandleTerminateResetsTunnelRunning(t *testing.T) {
	o, tunnelCtx := newRunningTunnelOlm(t)

	o.handleTerminate(websocket.WSMessage{
		Type: "olm/terminate",
		Data: map[string]any{"code": "TERMINATED_BY_ADMIN", "message": "terminated"},
	})

	assertTunnelStopped(t, o, tunnelCtx)
}

func TestHandleAuthErrorResetsTunnelRunning(t *testing.T) {
	o, tunnelCtx := newRunningTunnelOlm(t)

	o.handleAuthError(401, "unauthorized")

	assertTunnelStopped(t, o, tunnelCtx)
}

// dnsMonitorRunning reports whether a SystemDNSMonitor polling goroutine is
// still alive.
func dnsMonitorRunning() bool {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	return strings.Contains(string(buf[:n]), "(*SystemDNSMonitor).run")
}

// TestFailStartReleasesStartResources builds the state StartTunnel has when
// it gives up after initTunnelInfo (DNS monitor polling on olmCtx, an
// unconnected websocket client, the shared bind and hole punch manager) and
// checks that failStart releases it instead of leaking it into the next try.
func TestFailStartReleasesStartResources(t *testing.T) {
	o, tunnelCtx := newRunningTunnelOlm(t)

	// olmCtx outlives a failed start, so only an explicit Stop ends the
	// monitor; cancel it at cleanup purely to not leak into other tests.
	olmCtx, cancelOlm := context.WithCancel(context.Background())
	t.Cleanup(cancelOlm)
	o.olmCtx = olmCtx

	o.dnsMonitor = dns.NewSystemDNSMonitor(0, func([]string) {})
	o.dnsMonitor.Start(o.olmCtx)

	ws, err := websocket.NewClient("id", "secret", "", "org", "https://example.invalid", 30*time.Second)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	o.websocket = ws

	if err := o.initTunnelInfo("test-client"); err != nil {
		t.Fatalf("initTunnelInfo: %v", err)
	}
	sharedBind := o.sharedBind
	t.Cleanup(func() {
		for sharedBind.GetRefCount() > 0 {
			_ = sharedBind.Release()
		}
	})
	refsBefore := sharedBind.GetRefCount()

	if !dnsMonitorRunning() {
		t.Fatal("test setup: DNS monitor goroutine is not running")
	}

	logFile, err := os.CreateTemp(t.TempDir(), "olm-*.log")
	if err != nil {
		t.Fatalf("create log file: %v", err)
	}
	t.Cleanup(func() { _ = logFile.Close() })
	o.logFile = logFile

	o.failStart()

	// The process stays up for a retry, so the log file (the logger's output)
	// must stay open.
	if o.logFile != logFile {
		t.Error("failStart dropped the log file; later log output would be lost")
	}
	if _, err := logFile.WriteString("still writable\n"); err != nil {
		t.Errorf("log file was closed by failStart: %v", err)
	}

	assertTunnelStopped(t, o, tunnelCtx)
	if o.dnsMonitor != nil {
		t.Error("dnsMonitor was not cleared; the next StartTunnel overwrites it and leaks the running monitor")
	}
	deadline := time.Now().Add(2 * time.Second)
	for dnsMonitorRunning() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if dnsMonitorRunning() {
		t.Error("DNS monitor goroutine still running after a failed start")
	}
	if o.websocket != nil {
		t.Error("websocket client was not released after a failed start")
	}
	if o.holePunchManager != nil {
		t.Error("holePunchManager was not released after a failed start")
	}
	if o.sharedBind != nil {
		t.Error("sharedBind was not released after a failed start")
	}
	if got := sharedBind.GetRefCount(); got != refsBefore-1 {
		t.Errorf("shared bind refcount = %d after a failed start, want %d (hole punch reference released)", got, refsBefore-1)
	}
}

// installTempLogFile gives o a log file the way Init does for --log-file.
func installTempLogFile(t *testing.T, o *Olm) *os.File {
	t.Helper()

	logFile, err := os.CreateTemp(t.TempDir(), "olm-*.log")
	if err != nil {
		t.Fatalf("create log file: %v", err)
	}
	t.Cleanup(func() { _ = logFile.Close() })
	o.logFile = logFile
	return logFile
}

// TestTunnelTeardownKeepsLogFileOpen checks that ending only the tunnel
// (disconnect, org switch, server terminate, auth error) leaves the
// process-lifetime log file open, since the logger keeps writing to it.
func TestTunnelTeardownKeepsLogFileOpen(t *testing.T) {
	teardowns := map[string]func(o *Olm){
		"StopTunnel": func(o *Olm) {
			if err := o.StopTunnel(); err != nil {
				t.Fatalf("StopTunnel: %v", err)
			}
		},
		"handleTerminate": func(o *Olm) {
			o.handleTerminate(websocket.WSMessage{
				Type: "olm/terminate",
				Data: map[string]any{"code": "TERMINATED_BY_ADMIN", "message": "terminated"},
			})
		},
		"handleAuthError": func(o *Olm) { o.handleAuthError(401, "unauthorized") },
	}

	for name, teardown := range teardowns {
		t.Run(name, func(t *testing.T) {
			o, _ := newRunningTunnelOlm(t)
			logFile := installTempLogFile(t, o)

			teardown(o)

			if o.logFile != logFile {
				t.Error("tunnel teardown dropped the log file; Close at shutdown could no longer close it")
			}
			if _, err := logFile.WriteString("still writable\n"); err != nil {
				t.Errorf("log file was closed by a tunnel teardown, later log output is lost: %v", err)
			}
		})
	}
}

// TestCloseClosesLogFile checks that process shutdown still closes the log
// file.
func TestCloseClosesLogFile(t *testing.T) {
	o, _ := newRunningTunnelOlm(t)
	logFile := installTempLogFile(t, o)

	o.Close()

	if o.logFile != nil {
		t.Error("Close kept the log file")
	}
	if _, err := logFile.WriteString("after shutdown\n"); err == nil {
		t.Error("log file is still open after Close")
	}
}
