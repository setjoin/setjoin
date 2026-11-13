package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSetAccessCookieDevHTTP(t *testing.T) {
	h := &deps{cookieSecure: false}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "http://localhost/auth/login", nil)
	h.setAccessCookie(rec, r, "tok-abc", 900)
	res := rec.Result()
	var c *http.Cookie
	for _, ck := range res.Cookies() {
		if ck.Name == "access_token" {
			c = ck
		}
	}
	if c == nil {
		t.Fatal("expected access_token cookie")
	}
	if c.Value != "tok-abc" || !c.HttpOnly || c.Path != "/" {
		t.Fatalf("bad cookie: %+v", c)
	}
	if c.Secure {
		t.Fatal("dev HTTP (cookieSecure=false, no TLS): Secure must be false")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Fatal("expected SameSite=Strict")
	}
	if c.MaxAge != 900 {
		t.Fatalf("MaxAge = %d, want 900", c.MaxAge)
	}
}

func TestSetAccessCookieSecureWhenConfigured(t *testing.T) {
	h := &deps{cookieSecure: true}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "https://app/auth/login", nil)
	h.setAccessCookie(rec, r, "t", 900)
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == "access_token" && !ck.Secure {
			t.Fatal("cookieSecure=true must set Secure")
		}
	}
}

// -- wave-7 quirk 2: session cookie Secure behind a TLS-terminating gateway --
//
// authserver previously keyed Secure off its OWN TLS listener (cookieSecure or
// r.TLS != nil), so the standard single-node deploy — the gateway terminates
// TLS at :443 and proxies to authserver over 127.0.0.1 plain HTTP — shipped
// the session cookie without Secure: authserver's own r.TLS is nil on that
// proxied connection. The fix (forwardedHTTPS/isTrustedProxyPeer in auth.go)
// honors X-Forwarded-Proto, but ONLY when the immediate peer is loopback or
// explicitly allowlisted (auth.trusted_proxy_cidrs — since AUTHSERVERD-005
// finding 3 a private-range peer is NOT implicitly trusted) or AUTH_TRUST_PROXY
// is set — never for an arbitrary peer, which could otherwise spoof the header.

func cookieAfterSetAccess(t *testing.T, h *deps, r *http.Request) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	h.setAccessCookie(rec, r, "t", 900)
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == "access_token" {
			return ck
		}
	}
	t.Fatal("expected access_token cookie")
	return nil
}

func TestSetAccessCookie_ForwardedProto_LoopbackPeer_SetsSecure(t *testing.T) {
	h := &deps{cookieSecure: false}
	r := httptest.NewRequest(http.MethodPost, "http://localhost/auth/login", nil)
	r.RemoteAddr = "127.0.0.1:54321" // the gateway's proxied hop in a single-node deploy
	r.Header.Set("X-Forwarded-Proto", "https")
	if c := cookieAfterSetAccess(t, h, r); !c.Secure {
		t.Fatal("X-Forwarded-Proto=https from a loopback peer must set Secure, even with cookieSecure=false and r.TLS==nil")
	}
}

// AUTHSERVERD-005 finding 3 safe default: a private-range peer is NOT
// implicitly trusted anymore — every RFC 1918/4193 neighbor (container
// bridge, Wi-Fi client, compromised LAN host) could otherwise forge the
// header. Its X-Forwarded-Proto must be ignored until the operator
// allowlists the proxy's network.
func TestSetAccessCookie_ForwardedProto_PrivatePeerWithoutAllowlist_IsIgnored(t *testing.T) {
	h := &deps{cookieSecure: false} // default: loopback-only trust
	r := httptest.NewRequest(http.MethodPost, "http://localhost/auth/login", nil)
	r.RemoteAddr = "10.0.3.4:54321" // RFC 1918 private, but NOT allowlisted
	r.Header.Set("X-Forwarded-Proto", "https")
	if c := cookieAfterSetAccess(t, h, r); c.Secure {
		t.Fatal("a private-range peer without an allowlist entry must NOT set Secure — private-wide proxy trust was removed (AUTHSERVERD-005 finding 3)")
	}
}

// An explicit auth.trusted_proxy_cidrs allowlist entry covering the private
// proxy hop restores forwarded-header trust for that network.
func TestSetAccessCookie_ForwardedProto_AllowlistedPrivatePeer_SetsSecure(t *testing.T) {
	h := &deps{cookieSecure: false, trustedProxyCIDRs: parseTrustedProxyCIDRs([]string{"10.0.0.0/8"})}
	r := httptest.NewRequest(http.MethodPost, "http://localhost/auth/login", nil)
	r.RemoteAddr = "10.0.3.4:54321" // inside the allowlisted proxy network
	r.Header.Set("X-Forwarded-Proto", "https")
	if c := cookieAfterSetAccess(t, h, r); !c.Secure {
		t.Fatal("X-Forwarded-Proto=https from an allowlisted private proxy peer must set Secure")
	}
	// The allowlist is not blanket: a peer outside the listed range stays untrusted.
	r2 := httptest.NewRequest(http.MethodPost, "http://localhost/auth/login", nil)
	r2.RemoteAddr = "192.168.5.9:54321" // private, but outside 10.0.0.0/8
	r2.Header.Set("X-Forwarded-Proto", "https")
	if c := cookieAfterSetAccess(t, h, r2); c.Secure {
		t.Fatal("a private peer outside the allowlisted ranges must NOT set Secure")
	}
}

func TestSetAccessCookie_ForwardedProto_UntrustedPublicPeer_IsIgnored(t *testing.T) {
	h := &deps{cookieSecure: false}
	r := httptest.NewRequest(http.MethodPost, "http://localhost/auth/login", nil)
	r.RemoteAddr = "203.0.113.9:54321" // TEST-NET-3 — public, not loopback/private
	r.Header.Set("X-Forwarded-Proto", "https")
	if c := cookieAfterSetAccess(t, h, r); c.Secure {
		t.Fatal("X-Forwarded-Proto from an untrusted public peer must NOT set Secure — a client could spoof the header to fake TLS")
	}
}

func TestSetAccessCookie_ForwardedProto_UntrustedPeer_ExplicitTrustProxy_SetsSecure(t *testing.T) {
	h := &deps{cookieSecure: false, trustProxy: true} // operator-set AUTH_TRUST_PROXY
	r := httptest.NewRequest(http.MethodPost, "http://localhost/auth/login", nil)
	r.RemoteAddr = "203.0.113.9:54321" // public peer, but the operator explicitly trusts it
	r.Header.Set("X-Forwarded-Proto", "https")
	if c := cookieAfterSetAccess(t, h, r); !c.Secure {
		t.Fatal("AUTH_TRUST_PROXY must widen trust to a non-loopback/private peer")
	}
}

func TestSetAccessCookie_LoopbackPeer_NoForwardedProtoHeader_NotSecure(t *testing.T) {
	h := &deps{cookieSecure: false}
	r := httptest.NewRequest(http.MethodPost, "http://localhost/auth/login", nil)
	r.RemoteAddr = "127.0.0.1:54321" // trusted peer, but no header (direct plain HTTP, no gateway)
	if c := cookieAfterSetAccess(t, h, r); c.Secure {
		t.Fatal("a trusted peer with no X-Forwarded-Proto header must not set Secure")
	}
}

func TestSetAccessCookie_LoopbackPeer_ForwardedProtoHTTP_NotSecure(t *testing.T) {
	h := &deps{cookieSecure: false}
	r := httptest.NewRequest(http.MethodPost, "http://localhost/auth/login", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	r.Header.Set("X-Forwarded-Proto", "http") // gateway itself is plain HTTP
	if c := cookieAfterSetAccess(t, h, r); c.Secure {
		t.Fatal("X-Forwarded-Proto=http must not set Secure")
	}
}

func TestClearAuthCookie_PreservesForwardedHTTPSSecureAuthorityAndExplicitPath(t *testing.T) {
	h := &deps{cookieSecure: false}
	r := httptest.NewRequest(http.MethodGet, "http://localhost/auth/oidc/callback", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	r.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	h.clearAuthCookie(rec, r, identityLinkFlowCookie, "/")

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("clear cookies = %d, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != identityLinkFlowCookie || cookie.Path != "/" ||
		cookie.MaxAge >= 0 || !cookie.HttpOnly || !cookie.Secure ||
		cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("identity-link clear descriptor = %#v", cookie)
	}
}

// TestIsTrustedProxyPeer pins the AUTHSERVERD-005 finding 3 trust table:
// loopback ALWAYS trusted (no config needed for the standard single-node
// proxy hop); other peers only via the explicit allowlist; the blanket
// AUTH_TRUST_PROXY flag is a separate, wider switch (forwardedHTTPS).
func TestIsTrustedProxyPeer(t *testing.T) {
	h := &deps{trustedProxyCIDRs: parseTrustedProxyCIDRs([]string{"10.0.8.0/24", "fd7a::/48"})}
	cases := []struct {
		remoteAddr string
		want       bool
	}{
		{"127.0.0.1:1234", true},    // loopback — always trusted
		{"[::1]:1234", true},        // loopback (v6) — always trusted
		{"10.0.8.5:1234", true},     // inside an allowlisted range
		{"[fd7a::20]:1234", true},   // inside an allowlisted IPv6 range
		{"10.0.9.5:1234", false},    // RFC 1918, but OUTSIDE the allowlist
		{"172.16.5.1:1234", false},  // RFC 1918, unlisted — no implicit private trust
		{"192.168.1.1:1234", false}, // RFC 1918, unlisted
		{"8.8.8.8:1234", false},     // public
		{"203.0.113.9:1234", false}, // public (TEST-NET-3)
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
		r.RemoteAddr = c.remoteAddr
		if got := h.isTrustedProxyPeer(r); got != c.want {
			t.Errorf("isTrustedProxyPeer(%q) = %v, want %v", c.remoteAddr, got, c.want)
		}
	}

	// Loopback-only default: no allowlist configured at all.
	hLoopbackOnly := &deps{}
	for _, addr := range []string{"127.0.0.1:1234", "[::1]:1234"} {
		r := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
		r.RemoteAddr = addr
		if !hLoopbackOnly.isTrustedProxyPeer(r) {
			t.Errorf("isTrustedProxyPeer(%q) with no allowlist = false, want true (loopback is always trusted)", addr)
		}
	}
	for _, addr := range []string{"10.0.8.5:1234", "8.8.8.8:1234"} {
		r := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
		r.RemoteAddr = addr
		if hLoopbackOnly.isTrustedProxyPeer(r) {
			t.Errorf("isTrustedProxyPeer(%q) with no allowlist = true, want false (loopback-only default)", addr)
		}
	}

	// Unparseable RemoteAddr never earns trust, even with an allowlist that
	// would match everything short of the default route.
	r := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	r.RemoteAddr = "not-an-addr"
	if h.isTrustedProxyPeer(r) {
		t.Error("unparseable RemoteAddr must never be a trusted proxy peer")
	}
}
