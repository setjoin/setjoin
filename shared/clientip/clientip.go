// Package clientip resolves the real client IP and client-facing scheme of an
// HTTP request that arrives behind a trusted reverse proxy. It is a leaf
// package (standard library only, no upward imports) so httputil, middleware,
// threat, and the authproxy can all share ONE X-Forwarded-For trust boundary —
// previously copy-pasted three times and silently drifting — without the
// httputil↔middleware↔threat import cycle.
//
// Trust is anchored to the IMMEDIATE PEER (the socket RemoteAddr), never to
// data found inside the request: exactly one hop is trusted, and only when the
// socket peer itself is a trusted proxy are forwarded headers consulted at
// all. Headers arriving from an untrusted peer are discarded as spoofed.
package clientip

import (
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
)

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

// trustedProxyIP holds the single peer address whose forwarded headers are
// trusted. Read once from TRUSTED_PROXY_IP at init; empty disables
// forwarded-header trust entirely (RemoteAddr is always used), which is the
// safe default. Stored atomically: the test-only SetTrustedProxy override must
// never race concurrent Extract/ForwardedProto readers
// (mutable-trust-global hardening) — production binaries never call the
// setter, so the value is effectively fixed at process start.
var trustedProxyIP atomic.Value // string

func init() {
	trustedProxyIP.Store(os.Getenv("TRUSTED_PROXY_IP"))
}

// SetTrustedProxy overrides the trusted proxy IP. Test hook only.
// The store is atomic, so an override cannot race concurrent readers.
func SetTrustedProxy(ip string) { trustedProxyIP.Store(ip) }

// configuredTrustedProxy returns the configured trusted proxy address
// ("" when forwarded-header trust is disabled).
func configuredTrustedProxy() string {
	if v, ok := trustedProxyIP.Load().(string); ok {
		return v
	}
	return ""
}

// Extract returns the client IP using the env-configured trusted proxy: when
// TRUSTED_PROXY_IP is set and the immediate peer matches it, the rightmost
// X-Forwarded-For value (validated as an IP) is trusted; otherwise RemoteAddr
// (minus port) is returned.
func Extract(r *http.Request) string {
	return ExtractWithTrust(r, defaultTrust)
}

// ExtractWithTrust returns the client IP using a caller-supplied trust
// predicate over the immediate peer's host. Exactly one hop is trusted (the
// immediate peer), so when trust returns true the RIGHTMOST X-Forwarded-For
// value is used, not the leftmost: a reverse proxy appends the connecting
// peer's address to whatever XFF the client already sent, so the leftmost
// entry is attacker-controlled and the rightmost is the one the trusted
// proxy itself observed and appended.
//
// The FULL chain is parsed: every X-Forwarded-For header line is joined into
// one comma-separated sequence before the rightmost entry is taken. Reading
// only the first line (Header.Get) would let a spoofed attacker-controlled
// line win whenever the trusted proxy emits or preserves a second line.
//
// A malformed rightmost value FAILS CLOSED to the socket peer (the trusted
// proxy's own address). Earlier chain entries are never scanned as a
// fallback: they are earlier, strictly more attacker-controlled hops.
//
// IPv6 entries are accepted in bare and bracketed form, with a zone suffix
// (fe80::1%eth0, [fe80::1%25eth0]) which is stripped before validation; the
// validated address is returned in normalized form. Callers must let the
// trust predicate see the REAL socket peer — it is derived from r.RemoteAddr
// here, never from request-owned identity fields.
func ExtractWithTrust(r *http.Request, trust func(remoteHost string) bool) string {
	remoteHost := peerHost(r)
	if !trust(remoteHost) {
		// Untrusted peer: any forwarded header is spoofed input.
		return remoteHost
	}
	if ip, ok := rightmostForwardedFor(r.Header.Values("X-Forwarded-For")); ok {
		return ip
	}
	// No forwarded chain (or malformed rightmost entry): fail closed to the
	// socket peer rather than degrading to attacker-controlled data.
	return remoteHost
}

// ForwardedProto returns the client-facing request scheme ("https" or
// "http") using the env-configured trusted proxy. X-Forwarded-Proto is
// accepted ONLY from the trusted immediate peer; an untrusted peer's header
// is discarded as spoofed and the socket decides.
func ForwardedProto(r *http.Request) string {
	return ForwardedProtoWithTrust(r, defaultTrust)
}

// ForwardedProtoWithTrust returns the client-facing scheme using a
// caller-supplied trust predicate over the immediate peer's host. Direct TLS
// on this socket is authoritative ("https") and forwarded headers are never
// consulted. Otherwise the scheme is honored from the trusted immediate peer
// only: the LAST X-Forwarded-Proto header line wins (same rightmost-hop
// discipline as XFF — the value closest to the trusted proxy), compared
// case-insensitively against the known schemes. A missing or malformed value
// fails closed to "http": only an explicit https from a trusted peer grants
// TLS treatment (HSTS, Secure cookies).
func ForwardedProtoWithTrust(r *http.Request, trust func(remoteHost string) bool) string {
	if r.TLS != nil {
		return schemeHTTPS
	}
	if trust(peerHost(r)) {
		if lines := r.Header.Values("X-Forwarded-Proto"); len(lines) > 0 {
			switch strings.ToLower(strings.TrimSpace(lines[len(lines)-1])) {
			case schemeHTTPS:
				return schemeHTTPS
			case schemeHTTP:
				return schemeHTTP
			}
		}
	}
	return schemeHTTP
}

// defaultTrust is the env-configured single trusted proxy match.
func defaultTrust(remoteHost string) bool {
	tp := configuredTrustedProxy()
	return tp != "" && remoteHost == tp
}

// peerHost returns the real socket peer host (RemoteAddr minus port). This —
// never a request-owned header — anchors the trust decision.
func peerHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// rightmostForwardedFor joins every X-Forwarded-For header line into one
// comma-separated chain and validates the RIGHTMOST entry — the single hop
// the trusted immediate proxy itself observed and appended. The first
// return value is the normalized address; ok is false when the chain is
// absent or the rightmost entry is malformed (fail closed; earlier entries
// are never used as a fallback).
func rightmostForwardedFor(lines []string) (string, bool) {
	if len(lines) == 0 {
		return "", false
	}
	chain := lines[len(lines)-1]
	if len(lines) > 1 {
		chain = strings.Join(lines, ",")
	}
	entry := chain
	if i := strings.LastIndexByte(chain, ','); i != -1 {
		entry = chain[i+1:]
	}
	ip, ok := parseForwardedIP(entry)
	if !ok {
		return "", false
	}
	return ip.String(), true
}

// parseForwardedIP validates one XFF chain entry: surrounding whitespace is
// trimmed, optional surrounding brackets are stripped, and an IPv6 zone
// suffix (%eth0, %25eth0) is removed before net.ParseIP validation. The
// zone is an interface-scoped qualifier with no cross-hop meaning and is
// dropped from the validated address.
func parseForwardedIP(entry string) (net.IP, bool) {
	s := strings.TrimSpace(entry)
	if s == "" {
		return nil, false
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		s = s[1 : len(s)-1]
	}
	if i := strings.IndexByte(s, '%'); i != -1 {
		s = s[:i]
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, false
	}
	return ip, true
}
