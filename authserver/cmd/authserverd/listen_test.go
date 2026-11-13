package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"setjoin.com/authserver/internal/config"
	sharedcfg "setjoin.com/shared/config"
)

// compiledDefaultListenAddr is config.go's compiled listen default
// (post-processing + listenAddrFallback). Tests use the literal directly:
// main.go no longer compares against the default to detect "unconfigured" —
// presence is tracked by cfg.ListenAddrExplicit (AUTHSERVERD-005 finding 1).
const compiledDefaultListenAddr = ":8443"

// newCaptureLogger returns a slog logger writing at Debug level into buf so
// tests can assert both the always-on resolution Debug line and the
// conditional non-loopback WARN (D-AUTHSERVER-CMD-AUTHSERVERD-005).
func newCaptureLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// listenCfg builds the config slice resolveAuthListenAddr consumes: the
// decoded listen address plus the PRESENCE flag captured by config.Load
// (AUTHSERVERD-005 finding 1).
func listenCfg(addr string, explicit bool) *config.Config {
	return &config.Config{
		BaseConfig:         sharedcfg.BaseConfig{ListenAddr: addr},
		ListenAddrExplicit: explicit,
	}
}

// resolve resolves and fails the test on an unexpected startup refusal.
func resolve(t *testing.T, cfg *config.Config, fromEnv bool, authserverURL string) (resolvedAuthListen, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	res, err := resolveAuthListenAddr(cfg, fromEnv, authserverURL, newCaptureLogger(&buf))
	if err != nil {
		t.Fatalf("unexpected startup refusal: %v", err)
	}
	return res, &buf
}

// TestResolveAuthListenAddr_LoopbackURLDerivesLoopbackListen: with no explicit
// LISTEN_ADDR and no YAML listen.addr, a loopback AUTHSERVER_URL derives the
// matching loopback listen (install.sh parity) and logs no WARN.
func TestResolveAuthListenAddr_LoopbackURLDerivesLoopbackListen(t *testing.T) {
	res, buf := resolve(t, listenCfg(compiledDefaultListenAddr, false), false, "http://127.0.0.1:8443")

	if res.Addr != "127.0.0.1:8443" {
		t.Errorf("Addr = %q, want %q (derived from loopback AUTHSERVER_URL)", res.Addr, "127.0.0.1:8443")
	}
	if res.Source != listenSourceAuthURL {
		t.Errorf("Source = %q, want %q", res.Source, listenSourceAuthURL)
	}
	if !res.Derived {
		t.Error("Derived = false, want true (address came from AUTHSERVER_URL)")
	}
	if res.NonLoopback {
		t.Error("NonLoopback = true, want false for a 127.0.0.1 derivation")
	}
	if strings.Contains(buf.String(), "level=WARN") {
		t.Errorf("loopback derivation must not WARN, got log:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "auth listen address resolved") {
		t.Errorf("resolution Debug line missing from log:\n%s", buf.String())
	}
}

// TestResolveAuthListenAddr_NonLoopbackURLWarns: a non-loopback AUTHSERVER_URL
// derives a non-loopback listen and emits the operator-verification WARN. The
// URL is usable, so no refusal — split-host is a supported topology.
func TestResolveAuthListenAddr_NonLoopbackURLWarns(t *testing.T) {
	res, buf := resolve(t, listenCfg(compiledDefaultListenAddr, false), false, "https://auth.example.com:8443")

	if res.Addr != "auth.example.com:8443" {
		t.Errorf("Addr = %q, want %q (non-loopback derivation)", res.Addr, "auth.example.com:8443")
	}
	if res.Source != listenSourceAuthURL {
		t.Errorf("Source = %q, want %q", res.Source, listenSourceAuthURL)
	}
	if !res.NonLoopback {
		t.Error("NonLoopback = false, want true for a non-loopback derivation")
	}
	logged := buf.String()
	if !strings.Contains(logged, "level=WARN") {
		t.Fatalf("non-loopback derivation must WARN, got log:\n%s", logged)
	}
	if !strings.Contains(logged, "verify this exposure is intentional") {
		t.Errorf("WARN must ask the operator to verify the exposure is intentional, got:\n%s", logged)
	}
	if !strings.Contains(logged, "auth.example.com:8443") {
		t.Errorf("WARN must name the resolved address, got:\n%s", logged)
	}
}

// TestResolveAuthListenAddr_ExplicitEnvWins: an explicit LISTEN_ADDR
// (auth.env / process env) always beats the AUTHSERVER_URL derivation — even
// when the URL points at a non-loopback host, which must NOT warn because the
// operator's explicit bind already states their intent.
func TestResolveAuthListenAddr_ExplicitEnvWins(t *testing.T) {
	res, buf := resolve(t, listenCfg("127.0.0.1:9999", true), true, "http://10.1.2.3:8443")

	if res.Addr != "127.0.0.1:9999" {
		t.Errorf("Addr = %q, want %q (explicit LISTEN_ADDR must win)", res.Addr, "127.0.0.1:9999")
	}
	if res.Source != listenSourceEnv {
		t.Errorf("Source = %q, want %q", res.Source, listenSourceEnv)
	}
	if res.Derived {
		t.Error("Derived = true, want false when LISTEN_ADDR overrides the derivation")
	}
	if strings.Contains(buf.String(), "level=WARN") {
		t.Errorf("explicit override must not WARN even for a non-loopback AUTHSERVER_URL, got:\n%s", buf.String())
	}
}

// TestResolveAuthListenAddr_YAMLExplicitWinsOverDerivation: a SETJOIN_CONFIG
// listen.addr differing from the compiled default is explicit operator config
// and beats the AUTHSERVER_URL derivation.
func TestResolveAuthListenAddr_YAMLExplicitWinsOverDerivation(t *testing.T) {
	res, buf := resolve(t, listenCfg("0.0.0.0:9999", true), false, "http://127.0.0.1:8443")

	if res.Addr != "0.0.0.0:9999" {
		t.Errorf("Addr = %q, want %q (explicit YAML listen.addr must win)", res.Addr, "0.0.0.0:9999")
	}
	if res.Source != listenSourceYAML {
		t.Errorf("Source = %q, want %q", res.Source, listenSourceYAML)
	}
	if res.Derived {
		t.Error("Derived = true, want false when YAML overrides the derivation")
	}
	if strings.Contains(buf.String(), "level=WARN") {
		t.Errorf("explicit YAML bind must not WARN, got:\n%s", buf.String())
	}
}

// TestResolveAuthListenAddr_YAMLDefaultExplicitWinsOverDerivation
// (AUTHSERVERD-005 finding 1, the core pin): an explicit YAML listen.addr that
// EQUALS the compiled default ":8443" is still explicit — value equality with
// the default must never demote it to "unconfigured" — so it beats the
// AUTHSERVER_URL derivation.
func TestResolveAuthListenAddr_YAMLDefaultExplicitWinsOverDerivation(t *testing.T) {
	res, buf := resolve(t, listenCfg(compiledDefaultListenAddr, true), false, "http://127.0.0.1:9999")

	if res.Addr != compiledDefaultListenAddr {
		t.Errorf("Addr = %q, want %q (explicit YAML value wins even when equal to the compiled default)", res.Addr, compiledDefaultListenAddr)
	}
	if res.Source != listenSourceYAML {
		t.Errorf("Source = %q, want %q (explicitly configured, not derived)", res.Source, listenSourceYAML)
	}
	if res.Derived {
		t.Error("Derived = true, want false: AUTHSERVER_URL must not replace an explicit :8443")
	}
	if strings.Contains(buf.String(), "level=WARN") {
		t.Errorf("explicit YAML bind must not WARN, got:\n%s", buf.String())
	}
}

// TestResolveAuthListenAddr_RefusesWildcardDefaultWithoutURL: nothing
// explicit and no AUTHSERVER_URL — the compiled all-interfaces ":8443" default
// REFUSES startup instead of silently listening on every interface
// (AUTHSERVERD-005 finding 2, safe-default work).
func TestResolveAuthListenAddr_RefusesWildcardDefaultWithoutURL(t *testing.T) {
	var buf bytes.Buffer
	res, err := resolveAuthListenAddr(listenCfg(compiledDefaultListenAddr, false), false, "", newCaptureLogger(&buf))
	if err == nil {
		t.Fatalf("effective wildcard %q with no AUTHSERVER_URL must refuse startup, got addr %q", compiledDefaultListenAddr, res.Addr)
	}
	for _, want := range []string{"listen.addr", "AUTHSERVER_URL"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal error must name remediation key %q, got: %v", want, err)
		}
	}
	if res.Source != listenSourceDefault {
		t.Errorf("Source = %q, want %q (refused boot keeps the default provenance)", res.Source, listenSourceDefault)
	}
}

// TestResolveAuthListenAddr_RefusesNonLoopbackWithMalformedURL: a malformed or
// non-http(s) AUTHSERVER_URL is not a reachability contract — a non-loopback
// effective bind under it refuses startup (AUTHSERVERD-005 finding 2).
func TestResolveAuthListenAddr_RefusesNonLoopbackWithMalformedURL(t *testing.T) {
	for name, raw := range map[string]string{
		"garbage":      "not a url",
		"empty host":   "http://",
		"other scheme": "ftp://auth.example.com:8443",
		"bad IPv6":     "http://[::1:8443",
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			res, err := resolveAuthListenAddr(listenCfg(compiledDefaultListenAddr, false), false, raw, newCaptureLogger(&buf))
			if err == nil {
				t.Fatalf("unusable AUTHSERVER_URL %q with non-loopback default must refuse startup, got addr %q", raw, res.Addr)
			}
			if res.Source != listenSourceDefault || res.Derived {
				t.Errorf("refused resolution must keep default provenance, got source %q derived %v", res.Source, res.Derived)
			}
		})
	}
}

// TestResolveAuthListenAddr_RefusesExplicitNonLoopbackWithoutURL: even an
// explicitly configured wildcard/non-loopback bind refuses when AUTHSERVER_URL
// is absent — the refusal keys off the EFFECTIVE bind, not the config layer
// that produced it (AUTHSERVERD-005 finding 2).
func TestResolveAuthListenAddr_RefusesExplicitNonLoopbackWithoutURL(t *testing.T) {
	for name, tc := range map[string]struct {
		addr    string
		fromEnv bool
	}{
		"explicit yaml wildcard":    {":8443", false},
		"explicit yaml all-ipv4":    {"0.0.0.0:9999", false},
		"explicit env private host": {"10.1.2.3:8443", true},
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			if _, err := resolveAuthListenAddr(listenCfg(tc.addr, true), tc.fromEnv, "", newCaptureLogger(&buf)); err == nil {
				t.Fatalf("explicit non-loopback bind %q without AUTHSERVER_URL must refuse startup", tc.addr)
			}
		})
	}
}

// TestResolveAuthListenAddr_LoopbackWithoutURLStarts: loopback binds stay
// allowed with no AUTHSERVER_URL — the refusal targets exposed binds only.
func TestResolveAuthListenAddr_LoopbackWithoutURLStarts(t *testing.T) {
	t.Run("explicit yaml loopback", func(t *testing.T) {
		res, buf := resolve(t, listenCfg("127.0.0.1:8443", true), false, "")
		if res.Addr != "127.0.0.1:8443" || res.Source != listenSourceYAML {
			t.Errorf("got addr %q source %q, want explicit yaml loopback preserved", res.Addr, res.Source)
		}
		if strings.Contains(buf.String(), "level=WARN") {
			t.Errorf("loopback bind must not WARN, got:\n%s", buf.String())
		}
	})
	t.Run("explicit env loopback", func(t *testing.T) {
		res, _ := resolve(t, listenCfg("localhost:9443", true), true, "")
		if res.Addr != "localhost:9443" || res.Source != listenSourceEnv {
			t.Errorf("got addr %q source %q, want explicit env loopback preserved", res.Addr, listenSourceEnv)
		}
	})
}

// TestResolveAuthListenAddr_URLWithoutPortFallsBackToStockPort: a portless
// AUTHSERVER_URL derives the stock 8443, mirroring install.sh's standard port.
func TestResolveAuthListenAddr_URLWithoutPortFallsBackToStockPort(t *testing.T) {
	res, buf := resolve(t, listenCfg(compiledDefaultListenAddr, false), false, "http://127.0.0.1")

	if res.Addr != "127.0.0.1:8443" {
		t.Errorf("Addr = %q, want %q (stock port fallback)", res.Addr, "127.0.0.1:8443")
	}
	if strings.Contains(buf.String(), "level=WARN") {
		t.Errorf("loopback derivation must not WARN, got:\n%s", buf.String())
	}
}

// TestResolveAuthListenAddr_IPv6LoopbackURL: bracketed IPv6 hosts derive the
// re-bracketed Go listen form.
func TestResolveAuthListenAddr_IPv6LoopbackURL(t *testing.T) {
	res, buf := resolve(t, listenCfg(compiledDefaultListenAddr, false), false, "http://[::1]:8444")

	if res.Addr != "[::1]:8444" {
		t.Errorf("Addr = %q, want %q (IPv6 listen form)", res.Addr, "[::1]:8444")
	}
	if res.NonLoopback {
		t.Error("NonLoopback = true, want false for ::1")
	}
	if strings.Contains(buf.String(), "level=WARN") {
		t.Errorf("IPv6 loopback derivation must not WARN, got:\n%s", buf.String())
	}
}

// TestResolveAuthListenAddr_DebugLogNamesSource: the resolution Debug line
// always reports the derivation source (startup documentation contract). The
// compiled-default source cannot appear here — with the finding-2 refusal an
// unusable AUTHSERVER_URL never resolves successfully on a non-loopback
// default, and a usable one always derives.
func TestResolveAuthListenAddr_DebugLogNamesSource(t *testing.T) {
	for _, tc := range []struct {
		name       string
		addr       string
		explicit   bool
		fromEnv    bool
		url        string
		wantSource string
	}{
		{"env", "127.0.0.1:8443", true, true, "http://127.0.0.1:8443", listenSourceEnv},
		// Explicit :8443 (equal to the compiled default) + usable URL: the
		// explicit YAML layer wins, no refusal (URL present), Debug logs
		// source=listen.addr (AUTHSERVERD-005 finding 1).
		{"yaml", compiledDefaultListenAddr, true, false, "http://127.0.0.1:8443", listenSourceYAML},
		{"derived", compiledDefaultListenAddr, false, false, "http://127.0.0.1:8443", listenSourceAuthURL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if _, err := resolveAuthListenAddr(listenCfg(tc.addr, tc.explicit), tc.fromEnv, tc.url, newCaptureLogger(&buf)); err != nil {
				t.Fatalf("unexpected refusal: %v", err)
			}
			if !strings.Contains(buf.String(), "source="+tc.wantSource) {
				t.Errorf("Debug log must name source=%q, got:\n%s", tc.wantSource, buf.String())
			}
		})
	}
}

// TestIsLoopbackListenHost pins the loopback classification used for the
// non-loopback WARN and the startup refusal, including the all-interfaces
// empty-host case.
func TestIsLoopbackListenHost(t *testing.T) {
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"127.0.0.1", true},
		{"127.9.9.9", true},
		{"::1", true},
		{"::ffff:127.0.0.1", true}, // v4-mapped loopback
		{"localhost", true},
		{"LocalHost", true}, // case-folded
		{"", false},         // ":port" binds ALL interfaces
		{"0.0.0.0", false},
		{"::", false},
		{"10.1.2.3", false},
		{"192.168.1.10", false},
		{"auth.example.com", false},
	} {
		if got := isLoopbackListenHost(tc.host); got != tc.want {
			t.Errorf("isLoopbackListenHost(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

// TestListenHostSplitsBindHost pins host extraction for the WARN classifier.
func TestListenHostSplitsBindHost(t *testing.T) {
	for _, tc := range []struct {
		addr string
		want string
	}{
		{"127.0.0.1:8443", "127.0.0.1"},
		{":8443", ""},
		{"[::1]:8444", "::1"},
		{"auth.example.com:8443", "auth.example.com"},
		{"no-port-here", ""},
	} {
		if got := listenHost(tc.addr); got != tc.want {
			t.Errorf("listenHost(%q) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}

// TestAuthserverURLHostPort_PortRange (AUTHSERVERD-005 r3 P2): pins the
// explicit-port usability contract at the parse seam. net/url does NOT
// range-check ports — on go1.27.1 validOptionalPort only requires digits, so
// url.Parse accepts 65536 and arbitrarily large digit strings and u.Port()
// returns them verbatim; the 1..65535 bound plus the strconv.Atoi overflow
// rejection live in authserverURLHostPort. Portless and default-port URLs
// keep the stock 8443 fallback.
func TestAuthserverURLHostPort_PortRange(t *testing.T) {
	for _, tc := range []struct {
		name     string
		raw      string
		wantOK   bool
		wantPort string
	}{
		{"port 1", "http://127.0.0.1:1", true, "1"},
		{"just inside", "http://127.0.0.1:65535", true, "65535"},
		{"just outside", "http://127.0.0.1:65536", false, ""},
		{"well outside", "http://127.0.0.1:70000", false, ""},
		{"port 0", "http://127.0.0.1:0", false, ""},
		{"oversized digit string overflows Atoi", "http://127.0.0.1:99999999999999999999", false, ""},
		{"no explicit port keeps 8443 fallback", "http://127.0.0.1", true, "8443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host, port, ok := authserverURLHostPort(tc.raw)
			if ok != tc.wantOK {
				t.Fatalf("authserverURLHostPort(%q) ok = %v, want %v", tc.raw, ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if port != tc.wantPort {
				t.Errorf("authserverURLHostPort(%q) port = %q, want %q", tc.raw, port, tc.wantPort)
			}
			if host != "127.0.0.1" {
				t.Errorf("authserverURLHostPort(%q) host = %q, want %q", tc.raw, host, "127.0.0.1")
			}
		})
	}
}

// TestResolveAuthListenAddr_RefusesWildcardWithOutOfRangeURLPort
// (AUTHSERVERD-005 r3 P2): an explicit URL port outside 1..65535 is an
// UNUSABLE reachability contract, so a wildcard effective bind under it must
// take the same refusal path as any other unusable URL. Before the range
// check, LISTEN_ADDR=:8443 with AUTHSERVER_URL=http://127.0.0.1:65536 booted
// the all-interfaces bind because url.Parse accepted the port and the refusal
// treated the URL as usable.
func TestResolveAuthListenAddr_RefusesWildcardWithOutOfRangeURLPort(t *testing.T) {
	for name, raw := range map[string]string{
		"port 65536":             "http://127.0.0.1:65536",
		"port 70000":             "http://127.0.0.1:70000",
		"oversized digit string": "http://127.0.0.1:99999999999999999999",
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			res, err := resolveAuthListenAddr(listenCfg(":8443", true), true, raw, newCaptureLogger(&buf))
			if err == nil {
				t.Fatalf("explicit wildcard bind with unusable-URL %q must refuse startup, got addr %q", raw, res.Addr)
			}
			if !strings.Contains(err.Error(), raw) {
				t.Errorf("refusal must name the bad AUTHSERVER_URL %q, got: %v", raw, err)
			}
			if res.Source != listenSourceEnv || res.Derived {
				t.Errorf("refused resolution must keep env provenance, got source %q derived %v", res.Source, res.Derived)
			}
		})
	}

	// No explicit listen config: the unusable-port URL cannot seed the
	// derivation, so the compiled all-interfaces default survives — and the
	// refusal must fire for it exactly as it already does for other malformed
	// URLs (TestResolveAuthListenAddr_RefusesNonLoopbackWithMalformedURL).
	t.Run("derivation falls back to refused default", func(t *testing.T) {
		var buf bytes.Buffer
		res, err := resolveAuthListenAddr(listenCfg(compiledDefaultListenAddr, false), false, "http://127.0.0.1:65536", newCaptureLogger(&buf))
		if err == nil {
			t.Fatalf("unusable-URL port must not seed the derivation; default %q must refuse startup", res.Addr)
		}
		if res.Source != listenSourceDefault || res.Derived {
			t.Errorf("refused resolution must keep default provenance, got source %q derived %v", res.Source, res.Derived)
		}
	})
}

// TestResolveAuthListenAddr_LoopbackBindWithOutOfRangeURLPortStarts
// (AUTHSERVERD-005 r3 P2): a loopback effective bind still starts with an
// out-of-range URL port, mirroring exactly what malformed URLs do on loopback
// binds today — no refusal and no WARN (the WARN is reserved for derived
// non-loopback binds; loopback-with-unusable-URL has never warned).
func TestResolveAuthListenAddr_LoopbackBindWithOutOfRangeURLPortStarts(t *testing.T) {
	for name, raw := range map[string]string{
		"port 65536": "http://127.0.0.1:65536",
		"port 70000": "http://127.0.0.1:70000",
	} {
		t.Run(name, func(t *testing.T) {
			res, buf := resolve(t, listenCfg("127.0.0.1:8443", true), true, raw)
			if res.Addr != "127.0.0.1:8443" || res.Source != listenSourceEnv {
				t.Errorf("got addr %q source %q, want explicit loopback bind preserved", res.Addr, listenSourceEnv)
			}
			if strings.Contains(buf.String(), "level=WARN") {
				t.Errorf("loopback bind with unusable URL must not WARN (parity with malformed-URL treatment), got:\n%s", buf.String())
			}
		})
	}
}

// TestResolveAuthListenAddr_Port65535IsUsable (AUTHSERVERD-005 r3 P2
// boundary): the range check must not over-refuse — 65535 is a legal port, so
// the URL counts as usable: an explicit wildcard bind does not refuse, and a
// loopback URL still seeds the derivation.
func TestResolveAuthListenAddr_Port65535IsUsable(t *testing.T) {
	t.Run("explicit wildcard bind does not refuse", func(t *testing.T) {
		res, _ := resolve(t, listenCfg(":8443", true), true, "http://127.0.0.1:65535")
		if res.Addr != ":8443" || res.Source != listenSourceEnv {
			t.Errorf("got addr %q source %q, want explicit wildcard bind preserved (usable URL, no refusal)", res.Addr, listenSourceEnv)
		}
	})
	t.Run("loopback URL derives", func(t *testing.T) {
		res, buf := resolve(t, listenCfg(compiledDefaultListenAddr, false), false, "http://127.0.0.1:65535")
		if res.Addr != "127.0.0.1:65535" {
			t.Errorf("Addr = %q, want %q (usable boundary port seeds the derivation)", res.Addr, "127.0.0.1:65535")
		}
		if strings.Contains(buf.String(), "level=WARN") {
			t.Errorf("loopback derivation must not WARN, got:\n%s", buf.String())
		}
	})
}

// TestResolveAuthListenAddr_DefaultPortURLKeepsPassing (AUTHSERVERD-005 r3
// P2): a portless http URL is still a usable contract — an explicit wildcard
// bind under it must NOT trigger the refusal, and the stock 8443 fallback
// keeps applying on the derivation path (loopback variant already pinned by
// TestResolveAuthListenAddr_URLWithoutPortFallsBackToStockPort).
func TestResolveAuthListenAddr_DefaultPortURLKeepsPassing(t *testing.T) {
	res, _ := resolve(t, listenCfg(":8443", true), true, "http://auth.example.com")
	if res.Addr != ":8443" || res.Source != listenSourceEnv {
		t.Errorf("got addr %q source %q, want explicit wildcard bind preserved for a portless (default-port) usable URL", res.Addr, listenSourceEnv)
	}
}
