package ssrf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// ErrRedirectRefused is returned when a TrustedOriginHTTPClient receives a
// 3xx. Redirects are never followed: the operator configured one exact URL,
// and a redirect must not be able to widen what the client will contact.
var ErrRedirectRefused = errors.New("ssrf: redirect refused for trusted-origin client")

// origin is the scheme + host + port triple an operator-configured URL names.
type origin struct {
	scheme, host, port string
}

func originOf(u *url.URL) (origin, bool) {
	if u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return origin{}, false
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	return origin{scheme: u.Scheme, host: canonicalHost(u.Hostname()), port: port}, true
}

// canonicalHost folds the spellings of one host name or IP literal onto a
// single form: case and a trailing root dot for names, the canonical text form
// for IP literals (so [0:0:0:0:0:0:0:1] and [::1] are the same origin).
func canonicalHost(host string) string {
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// trustedDialAllowed is the connect-time address rule for the trusted origin.
// Compared with IsBlockedIP it opens exactly two classes, loopback and private
// (RFC 1918 / ULA); every permanently-blocked range (link-local incl. the
// 169.254.169.254 metadata endpoint and fe80::/10, multicast, unspecified,
// and the IANA special-purpose blockedNets) stays refused even for the
// operator-named host, so a rebinding DNS answer cannot reach them.
func trustedDialAllowed(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() {
		return true
	}
	return !IsBlockedIP(ip)
}

// TrustedOriginHTTPClient returns a client for ONE operator-configured internal
// endpoint (e.g. the authserver JWKS URL, issue #221). Requests whose scheme,
// host and port exactly match trustedURL (host compared case-insensitively,
// trailing root dot ignored, IP literals canonicalized, default port implied)
// may additionally reach loopback and private addresses; every
// permanently-blocked range stays refused (trustedDialAllowed). The trusted
// transport resolves the name itself at dial time, refuses the whole answer set
// if any address is outside that rule, and dials only a validated concrete
// address, so a rebinding name cannot reach cloud metadata. Every other
// destination goes through the same strict post-DNS guard as SafeHTTPClient.
// The trust is decided once, here, from the configured string: a redirect is
// never followed (ErrRedirectRefused), and a DNS answer cannot add an origin
// because matching is on the configured host, never on resolved addresses. No
// proxy is consulted, so environment proxy settings cannot reroute the dial.
//
// Never pass a URL derived from request or tenant input: this is an explicit,
// operator-owned allowlist entry, not a general SSRF relaxation.
func TrustedOriginHTTPClient(trustedURL string, timeout time.Duration) (*http.Client, error) {
	plain := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: trustedControl}
	return trustedOriginHTTPClient(trustedURL, timeout, net.DefaultResolver.LookupIPAddr, plain.DialContext)
}

// trustedControl re-checks the concrete socket address at connect time, as a
// second line behind the resolve-then-dial check.
func trustedControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if !trustedDialAllowed(net.ParseIP(host)) {
		return ErrUnsafeURL
	}
	return nil
}

func trustedOriginHTTPClient(trustedURL string, timeout time.Duration, lookup lookupIPAddrFunc, dial dialContextFunc) (*http.Client, error) {
	u, err := url.Parse(trustedURL)
	if err != nil {
		return nil, fmt.Errorf("ssrf: trusted URL: %w", err)
	}
	if u.User != nil {
		return nil, fmt.Errorf("ssrf: trusted URL must not carry userinfo")
	}
	trusted, ok := originOf(u)
	if !ok {
		return nil, fmt.Errorf("ssrf: trusted URL must be http(s) with a host")
	}

	trustedTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, splitErr := net.SplitHostPort(address)
			if splitErr != nil {
				return nil, splitErr
			}
			// Belt and braces: even if routing below were bypassed, this
			// transport dials only the configured host:port.
			if canonicalHost(host) != trusted.host || port != trusted.port {
				return nil, ErrUnsafeURL
			}
			ips, lookupErr := lookup(ctx, host)
			if lookupErr != nil || len(ips) == 0 {
				return nil, ErrUnsafeURL
			}
			for _, candidate := range ips {
				if !trustedDialAllowed(candidate.IP) {
					return nil, ErrUnsafeURL
				}
			}
			var lastErr error
			for _, candidate := range ips {
				conn, dialErr := dial(ctx, network, net.JoinHostPort(candidate.IP.String(), port))
				if dialErr == nil {
					return conn, nil
				}
				lastErr = dialErr
			}
			return nil, lastErr
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	guarded := SafeHTTPClient(timeout).Transport

	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return ErrRedirectRefused
		},
		Transport: originRouter{trusted: trusted, trustedRT: trustedTransport, guardedRT: guarded},
	}, nil
}

// originRouter sends exact-origin requests to the trusted transport and every
// other request through the strict SSRF guard.
type originRouter struct {
	trusted   origin
	trustedRT http.RoundTripper
	guardedRT http.RoundTripper
}

func (r originRouter) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.User == nil {
		if o, ok := originOf(req.URL); ok && o == r.trusted {
			return r.trustedRT.RoundTrip(req)
		}
	}
	return r.guardedRT.RoundTrip(req)
}
