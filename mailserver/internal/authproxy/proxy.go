package authproxy

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"setjoin.com/mailserver/internal/config"
	"setjoin.com/shared/clientip"
	sharedmw "setjoin.com/shared/middleware"
)

// New returns a reverse proxy that forwards authserver-owned routes, including
// /auth/* and the root-level OIDC Provider/OAuth protocol endpoints. The proxy
// preserves cookies, Authorization headers, and request bodies so the auth
// server can issue and validate tokens transparently.
//
// The Rewrite API (not the deprecated Director) unconditionally strips the
// client-supplied Forwarded, X-Forwarded-For, X-Forwarded-Host, and
// X-Forwarded-Proto headers before Rewrite runs, so what this proxy forwards
// is solely what it sets here: the OBSERVED client identity resolved through
// the shared clientip trust boundary, never pass-through request data.
//
// pr.SetXForwarded() would derive everything from the gateway's own socket,
// which is wrong in the documented HTTPMode=proxy topology (TLS terminated
// upstream): the gateway's peer there is the reverse proxy, so per-client-IP
// controls on the auth server (rate limiting, spray detection, geo/CA,
// audit) would attribute ALL traffic to the proxy IP, and X-Forwarded-Proto
// would read "http" even though the browser connection was TLS, dropping
// Secure from the auth server's session cookies. Instead:
//
//   - X-Forwarded-For is set to the observed client IP (rightmost-trusted-hop
//     resolution anchored to the real socket peer, per shared/clientip);
//     direct-TLS deployments without TRUSTED_PROXY_IP keep getting the socket
//     peer, i.e. unchanged behavior.
//   - X-Forwarded-Proto carries the client-facing scheme (https when a
//     trusted proxy reports upstream TLS termination or the socket is TLS).
//   - X-Forwarded-Host carries the inbound Host, as before.
//
// The auth server uses X-Forwarded-For for IP-based threat detection
// (rate limiting, spray detection, geo-blocking, CAPTCHA, tarpit) so
// it is critical that the gateway is the sole authority on these headers.
//
// Transport isolation (D-MAILSERVER-INTERNAL-AUTHPROXY-002, project invariant 5):
// the proxy MUST NOT ride http.DefaultTransport. A dedicated transport with
// Proxy: nil keeps credential-bearing auth hops (cookies, Authorization
// headers, bodies) out of any environment-configured HTTP_PROXY route; the
// header/connect/response timeouts and bounded per-host connection pool stop a
// slow or wedged authserver from pinning gateway connections indefinitely.
func New(cfg *config.Config) (http.Handler, error) {
	target, err := url.Parse(cfg.AuthServerURL)
	if err != nil {
		return nil, fmt.Errorf("invalid AUTHSERVER_URL: %w", err)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil          // internal fixed target — never env-proxy a credential hop
	transport.MaxConnsPerHost = 64 // bounded pool per authserver host
	transport.IdleConnTimeout = 90 * time.Second
	transport.ResponseHeaderTimeout = 15 * time.Second
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.ExpectContinueTimeout = 1 * time.Second
	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = target.Scheme
			pr.Out.URL.Host = target.Host
			pr.Out.Host = target.Host
			pr.Out.Header.Set("X-Forwarded-For", clientip.Extract(pr.In))
			pr.Out.Header.Set("X-Forwarded-Proto", clientip.ForwardedProto(pr.In))
			pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)

			// Pass request ID for cross-service log correlation.
			if rid := sharedmw.GetRequestID(pr.In.Context()); rid != "" {
				pr.Out.Header.Set("X-Request-ID", rid)
			}
		},
	}
	return proxy, nil
}
