package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadConfigDNSBoolPrecedence checks that overrideDNS and tunnelDNS
// follow the documented precedence (CLI > env > file > default), including
// an explicit false that has to beat a default of true.
func TestLoadConfigDNSBoolPrecedence(t *testing.T) {
	tests := []struct {
		name            string
		file            string // config file contents; empty means no file
		env             map[string]string
		args            []string
		wantOverrideDNS bool
		wantTunnelDNS   bool
		wantOverrideSrc string
		wantTunnelSrc   string
	}{
		{
			name:            "defaults without file",
			wantOverrideDNS: true,
			wantTunnelDNS:   false,
			wantOverrideSrc: string(SourceDefault),
			wantTunnelSrc:   string(SourceDefault),
		},
		{
			name:            "file omits both keeps defaults",
			file:            `{"mtu": 1400}`,
			wantOverrideDNS: true,
			wantTunnelDNS:   false,
			wantOverrideSrc: string(SourceDefault),
			wantTunnelSrc:   string(SourceDefault),
		},
		{
			name:            "file explicit false overrideDNS and true tunnelDNS",
			file:            `{"overrideDNS": false, "tunnelDNS": true}`,
			wantOverrideDNS: false,
			wantTunnelDNS:   true,
			wantOverrideSrc: string(SourceFile),
			wantTunnelSrc:   string(SourceFile),
		},
		{
			name:            "env false overrides file true",
			file:            `{"overrideDNS": true, "tunnelDNS": true}`,
			env:             map[string]string{"OVERRIDE_DNS": "false", "TUNNEL_DNS": "false"},
			wantOverrideDNS: false,
			wantTunnelDNS:   false,
			wantOverrideSrc: string(SourceEnv),
			wantTunnelSrc:   string(SourceEnv),
		},
		{
			name:            "env true overrides file false",
			file:            `{"overrideDNS": false, "tunnelDNS": false}`,
			env:             map[string]string{"OVERRIDE_DNS": "true", "TUNNEL_DNS": "true"},
			wantOverrideDNS: true,
			wantTunnelDNS:   true,
			wantOverrideSrc: string(SourceEnv),
			wantTunnelSrc:   string(SourceEnv),
		},
		{
			name:            "cli overrides env and file",
			file:            `{"overrideDNS": false, "tunnelDNS": true}`,
			env:             map[string]string{"OVERRIDE_DNS": "false", "TUNNEL_DNS": "true"},
			args:            []string{"--override-dns=true", "--tunnel-dns=false"},
			wantOverrideDNS: true,
			wantTunnelDNS:   false,
			wantOverrideSrc: string(SourceCLI),
			wantTunnelSrc:   string(SourceCLI),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.json")
			if tt.file != "" {
				if err := os.WriteFile(configPath, []byte(tt.file), 0o600); err != nil {
					t.Fatalf("write config file: %v", err)
				}
			}
			t.Setenv("CONFIG_FILE", configPath)
			t.Setenv("OVERRIDE_DNS", "")
			t.Setenv("TUNNEL_DNS", "")
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			cfg, _, _, err := LoadConfig(tt.args)
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}

			if cfg.OverrideDNS != tt.wantOverrideDNS {
				t.Errorf("OverrideDNS = %v, want %v", cfg.OverrideDNS, tt.wantOverrideDNS)
			}
			if cfg.TunnelDNS != tt.wantTunnelDNS {
				t.Errorf("TunnelDNS = %v, want %v", cfg.TunnelDNS, tt.wantTunnelDNS)
			}
			if got := cfg.sources["overrideDNS"]; got != tt.wantOverrideSrc {
				t.Errorf("overrideDNS source = %q, want %q", got, tt.wantOverrideSrc)
			}
			if got := cfg.sources["tunnelDNS"]; got != tt.wantTunnelSrc {
				t.Errorf("tunnelDNS source = %q, want %q", got, tt.wantTunnelSrc)
			}
		})
	}
}

// TestNewTunnelConfigCarriesDNSFlags checks that the DNS booleans from the
// loaded configuration reach the tunnel configuration handed to olm.
func TestNewTunnelConfigCarriesDNSFlags(t *testing.T) {
	for _, tc := range []struct{ override, tunnel bool }{
		{false, true},
		{true, false},
	} {
		cfg := DefaultConfig()
		cfg.OverrideDNS = tc.override
		cfg.TunnelDNS = tc.tunnel

		tunnelConfig := newTunnelConfig(cfg)

		if tunnelConfig.OverrideDNS != tc.override {
			t.Errorf("TunnelConfig.OverrideDNS = %v, want %v", tunnelConfig.OverrideDNS, tc.override)
		}
		if tunnelConfig.TunnelDNS != tc.tunnel {
			t.Errorf("TunnelConfig.TunnelDNS = %v, want %v", tunnelConfig.TunnelDNS, tc.tunnel)
		}
	}
}
