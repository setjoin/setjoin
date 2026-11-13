package middleware

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

// CSRF validates the Origin/Referer scheme+host+port tuple on state-changing
// requests. GET/HEAD/OPTIONS pass through — only POST/PUT/PATCH/DELETE are
// checked. If both Origin and Referer are missing, the request is allowed only
// when it does not identify itself as a cross-site browser navigation: modern
// browsers always attach Sec-Fetch-Site, so a browser cross-site request that
// arrives without Origin/Referer (stripped by an intermediate, an exotic
// client, or a future browser policy) is denied via its Sec-Fetch-Site:
// cross-site value instead of sailing through the header-absence fallback.
// Requests with no fetch-metadata headers at all remain allowed
// (browserless clients, native apps, S2S calls).
//
// ER5 occ_c4b68750211fc1a7e3eb82e9 (csrf-origin-port-elision): the comparison
// is the full scheme+host+port tuple, not a host-only suffix match. The
// earlier host-only comparison accepted an http:// origin on an https site
// (scheme downgrade) and any attacker-chosen port on the right host, because
// both sides' ports were stripped before comparing. Scheme now comes from the
// client-facing edge (see expectedScheme) and ports are compared with
// scheme-default normalization (a default-less https origin means :443, not
// "any port").
func CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		expectedScheme := expectedScheme(r)
		// Behind the gateway's authproxy the upstream Host is rewritten to
		// AUTHSERVER_URL's host (pr.Out.Host = target.Host), so r.Host here is
		// e.g. "127.0.0.1:8444" while a real browser's Origin names the SITE
		// (https://mail.example.com) — comparing Origin against r.Host 403'd
		// EVERY browser login on any deploy whose public hostname differs from
		// the authserver upstream host (found live by the B1 webmail-UI gate;
		// curl-based smokes never caught it because they send no Origin).
		// X-Forwarded-Host is trustworthy here: the gateway strips any
		// client-supplied X-Forwarded-* before SetXForwarded() re-derives them
		// (authproxy.New), and a cross-site attacker cannot attach custom
		// headers to a victim's browser request without a CORS preflight.
		// As in-package defense for a topology whose proxy does NOT strip, a
		// multi-valued or malformed X-Forwarded-Host (list syntax, whitespace,
		// control characters) is ignored — a re-derived header is always a
		// single host token, so anything else was not set by the gateway.
		expectedHost := sanitizedForwardedHost(r.Header.Get("X-Forwarded-Host"))
		if expectedHost == "" {
			expectedHost = r.Host
		}

		origin := r.Header.Get("Origin")
		if origin != "" {
			if !originMatches(origin, expectedHost, expectedScheme) {
				denyJSON(w, http.StatusForbidden, "csrf_failed", "CSRF validation failed")
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		referer := r.Header.Get("Referer")
		if referer != "" {
			if !originMatches(referer, expectedHost, expectedScheme) {
				denyJSON(w, http.StatusForbidden, "csrf_failed", "CSRF validation failed")
				return
			}
		}

		// Fetch-metadata factor for the header-absence path: a request that
		// self-identifies as cross-site browser traffic is denied even though
		// its Origin/Referer are absent. Non-browser clients send no
		// Sec-Fetch-Site and keep the documented passthrough.
		if secFetchSite := r.Header.Get("Sec-Fetch-Site"); secFetchSite == "cross-site" {
			denyJSON(w, http.StatusForbidden, "csrf_failed", "CSRF validation failed")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// expectedScheme resolves the scheme the CLIENT used, which the Origin header
// also carries. Behind the gateway the re-derived X-Forwarded-Proto is the
// client-facing scheme (client-supplied X-Forwarded-* are stripped by the
// authproxy before re-derivation — the same trust argument as
// sanitizedForwardedHost). Direct deployments fall back to the connection: a
// TLS-terminated request is https, anything else http. The value only ever
// decides ALLOW or DENY of an attacker-controlled Origin header, so a wrong
// guess cannot smuggle a request past a host that already matched — it can
// only flip a correct match to a denial, which is the safe direction.
func expectedScheme(r *http.Request) string {
	if p := sanitizedForwardedProto(r.Header.Get("X-Forwarded-Proto")); p != "" {
		return p
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// sanitizedForwardedProto accepts only a single well-formed scheme token.
// List syntax, whitespace, or any other value yields "" and the caller falls
// back to the connection-derived scheme (mirrors sanitizedForwardedHost).
func sanitizedForwardedProto(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "http":
		return "http"
	case "https":
		return "https"
	default:
		return ""
	}
}

// originMatches reports whether rawURL (an Origin or Referer value) carries
// exactly the expected scheme+host+port tuple. Ports normalize to their
// scheme's default, so `https://mail.example.com` and
// `https://mail.example.com:443` are the same origin while
// `https://mail.example.com:8443` is not.
func originMatches(rawURL, expectedHost, expectedScheme string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return false
	}
	if !strings.EqualFold(parsed.Scheme, expectedScheme) {
		return false
	}
	host, port, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		// No port (or unbracketed input): the scheme default applies. A
		// bracketed IPv6 host without a port keeps its brackets on BOTH
		// sides of the comparison, so it matches an equally portless
		// bracketed expected host; the safe residual is a false DENIAL for
		// mixed port-form IPv6 origins (e.g. [::1] expected, "[::1]:443"
		// presented), never a false allow.
		host = parsed.Host
		port = schemeDefaultPort(parsed.Scheme)
	}
	expectedHostname, expectedPort := splitExpectedHost(expectedHost, expectedScheme)
	return strings.EqualFold(host, expectedHostname) && port == expectedPort
}

// splitExpectedHost splits the sanitized X-Forwarded-Host / r.Host value into
// hostname and effective port, applying the scheme default when absent.
func splitExpectedHost(expectedHost, expectedScheme string) (hostname, port string) {
	host, p, err := net.SplitHostPort(expectedHost)
	if err != nil {
		return expectedHost, schemeDefaultPort(expectedScheme)
	}
	return host, p
}

// schemeDefaultPort returns the default port for the scheme. Only the schemes
// expectedScheme can produce (http, https) reach this function; anything else
// is treated as portless.
func schemeDefaultPort(scheme string) string {
	if strings.EqualFold(scheme, "https") {
		return "443"
	}
	return "80"
}

// sanitizedForwardedHost returns the X-Forwarded-Host value only when it is a
// single well-formed host token: no list separators, whitespace, or control
// characters. Anything else (a header that survived from a client, appended
// values, injection attempts) yields "" and the middleware falls back to
// r.Host.
func sanitizedForwardedHost(value string) string {
	if value == "" {
		return ""
	}
	if len(value) > 255 {
		return ""
	}
	for _, c := range value {
		// Host tokens: unreserved chars, ':' port separator, '[' ']' IPv6
		// brackets. Everything else — commas (list syntax), spaces, control
		// and non-ASCII bytes — disqualifies the header.
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '-' || c == '_' || c == ':' || c == '[' || c == ']':
		default:
			return ""
		}
	}
	return value
}
