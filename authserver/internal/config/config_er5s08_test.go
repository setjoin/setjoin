package config

// ER5 er5-s08 occurrence tests (insecure-transport.authserver-standalone-default):
// the unconfigured listen address is loopback-scoped, and a cleartext bind
// beyond loopback (including the wildcard forms) refuses startup with
// remediation guidance instead of serving credentials in the clear.

import (
	"os"
	"strings"
	"testing"
	"time"

	sharedcfg "setjoin.com/shared/config"
)

func requireNoListenEnv(t *testing.T) {
	t.Helper()
	t.Setenv("LISTEN_ADDR", "")
	os.Unsetenv("LISTEN_ADDR")
}

// TestDefaultListenAddrIsLoopback pins the corrected compiled default: a bare
// `docker run authserverd` with no listen config binds 127.0.0.1 only — the
// old ":8443" wildcard served bearer credentials in cleartext on every
// interface by default (gateway topologies are unaffected: they derive the
// address from AUTHSERVER_URL or set LISTEN_ADDR).
func TestDefaultListenAddrIsLoopback(t *testing.T) {
	authConfigEnv(t)
	requireNoListenEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load with defaults: %v", err)
	}
	if cfg.ListenAddr != defaultListenAddr {
		t.Fatalf("default ListenAddr = %q, want %q", cfg.ListenAddr, defaultListenAddr)
	}
	if strings.HasPrefix(cfg.ListenAddr, ":") || strings.HasPrefix(cfg.ListenAddr, "0.0.0.0") {
		t.Fatalf("default ListenAddr %q binds a wildcard interface", cfg.ListenAddr)
	}
}

// TestCleartextNonLoopbackListenRefused runs the validation matrix: every
// cleartext bind beyond loopback (wildcards, LAN IPs, IPv6 any) refuses with
// actionable guidance; loopback binds stay legal for gateway-proxied
// deployments; a TLS-configured non-loopback bind stays legal for direct
// deployments.
func TestCleartextNonLoopbackListenRefused(t *testing.T) {
	cases := []struct {
		name    string
		addr    string
		tlsCert string
		wantErr bool
	}{
		{"wildcard ipv4 cleartext", ":8443", "", true},
		{"wildcard ipv6 cleartext", "[::]:8443", "", true},
		{"any-address ipv4 cleartext", "0.0.0.0:8443", "", true},
		{"lan ipv4 cleartext", "10.0.8.5:8443", "", true},
		{"loopback ipv4 cleartext ok", "127.0.0.1:8443", "", false},
		{"loopback ipv6 cleartext ok", "[::1]:8443", "", false},
		{"localhost name cleartext ok", "localhost:8443", "", false},
		{"lan ipv4 with tls ok", "10.0.8.5:8443", "/tmp/er5s08-cert.pem", false},
		{"wildcard with tls ok", ":8443", "/tmp/er5s08-cert.pem", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{BaseConfig: *minimalValidBase(t)}
			c.ListenAddr = tc.addr
			c.JWTExpiry = time.Hour
			c.JWTRefreshExpiry = 720 * time.Hour
			c.ThreatSprayWindowSecs = 300
			c.ThreatSprayMaxUsers = 5
			c.ThreatSprayLockoutMins = 30
			c.ThreatCaptchaWindowMins = 5
			c.ThreatCaptchaThreshold = 3
			c.ThreatTarpitWindowMins = 15
			c.ThreatTarpitThreshold = 3
			c.ThreatRateLimitPerMin = 20
			c.TLSCertFile = tc.tlsCert
			if tc.tlsCert != "" {
				c.TLSKeyFile = "/tmp/er5s08-key.pem"
			}
			err := c.validate()
			if tc.wantErr && err == nil {
				t.Fatalf("validate(ListenAddr=%q, TLS=%q) = nil, want a refusal naming the remediation", tc.addr, tc.tlsCert)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validate(ListenAddr=%q, TLS=%q) = %v, want nil", tc.addr, tc.tlsCert, err)
			}
			if tc.wantErr && err != nil && !strings.Contains(err.Error(), "TLS_CERT") {
				t.Fatalf("refusal must name the TLS remediation path, got: %v", err)
			}
		})
	}
}

func minimalValidBase(t *testing.T) *sharedcfg.BaseConfig {
	t.Helper()
	return &sharedcfg.BaseConfig{
		DatabaseDSN: "postgres://test:test@127.0.0.1:5432/testdb",
		JWTSecret:   "er5s08-test-secret-32-bytes-long!!!",
	}
}

// TestListenHostAndLoopbackHelpers pin the listen-address host extraction the
// cleartext validation keys on.
func TestListenHostAndLoopbackHelpers(t *testing.T) {
	cases := []struct {
		addr, wantHost string
	}{
		{"127.0.0.1:8443", "127.0.0.1"},
		{":8443", ""},
		{"[::1]:8443", "::1"},
		{"localhost:8443", "localhost"},
		{"bare-host", "bare-host"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := listenHost(tc.addr); got != tc.wantHost {
			t.Errorf("listenHost(%q) = %q, want %q", tc.addr, got, tc.wantHost)
		}
	}
	if !isLoopbackHostname("localhost") || !isLoopbackHostname("API.Localhost") || !isLoopbackHostname("x.localhost") {
		t.Error("localhost-family hostnames must read as loopback")
	}
	if isLoopbackHostname("mail.example.com") || isLoopbackHostname("evil-localhost.com") {
		t.Error("non-local hostnames must not read as loopback")
	}
}
