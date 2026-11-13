// Package ssrf is a server-side-request-forgery guard for outbound HTTP whose
// destination host is derived from untrusted input: a user-registered webhook
// URL, a sender's List-Unsubscribe header, an admin-registered SAML IdP
// metadata URL, an autodiscovery ?domain=. The authoritative protection is
// SafeHTTPClient, whose dialer Control hook runs AFTER DNS resolution on the
// concrete dial address — so it blocks internal targets even when a public
// hostname resolves (or is rebound) to an internal IP. ValidateURL is a cheap
// fail-fast pre-check for UX; it is not sufficient on its own.
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

// ErrUnsafeURL is returned when a destination uses a non-http(s) scheme or
// resolves to a non-routable / internal address. Blocking these prevents SSRF:
// an outbound request to an untrusted-derived host must never reach loopback,
// private, link-local (incl. the 169.254.169.254 cloud-metadata endpoint), or
// unspecified addresses.
var ErrUnsafeURL = errors.New("URL is not allowed (must be http/https to a public host)")

// blockedNets lists ranges not covered by net.IP's stdlib classifiers that must
// also be blocked for SSRF safety (ssrf.webhook-special-use-addresses,
// occ_8e399e220a93691f19b6c1d9 — the IANA special-purpose registries below are
// NEVER routable to a public destination, so a webhook/fetch policy must treat
// them as internal):
//   - 0.0.0.0/8       "this network" (RFC 791); only the exact 0.0.0.0 is
//     IsUnspecified, the rest of the /8 dial-loops locally
//   - 100.64.0.0/10   RFC 6598 CGNAT (used internally by AWS EKS and overlays)
//   - 192.0.0.0/24    IETF protocol assignments
//   - 192.0.2.0/24    RFC 5737 TEST-NET-1 (documentation)
//   - 198.51.100.0/24 RFC 5737 TEST-NET-2 (documentation)
//   - 203.0.113.0/24  RFC 5737 TEST-NET-3 (documentation)
//   - 192.31.196.0/24 AS112 anycast (underquake)
//   - 192.52.193.0/24 AS112 anycast (prisoner)
//   - 192.88.99.0/24  deprecated 6to4 relay anycast (RFC 7526)
//   - 192.175.48.0/24 AS112 anycast (domain-scope)
//   - 198.18.0.0/15   RFC 2544 benchmarking
//   - 240.0.0.0/4     Reserved/future + 255.255.255.255 broadcast (IsMulticast covers 224-239 only)
//   - 100::/64        RFC 6666 discard-only
//   - 2001:db8::/32   RFC 3849 documentation
//   - 64:ff9b::/96    NAT64 well-known prefix (maps to internal IPv4 on NAT64 networks)
var blockedNets = func() []*net.IPNet {
	cidrs := []string{
		"0.0.0.0/8",
		"100.64.0.0/10",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"192.31.196.0/24",
		"192.52.193.0/24",
		"192.88.99.0/24",
		"192.175.48.0/24",
		"198.18.0.0/15",
		"240.0.0.0/4",
		"100::/64",
		"2001:db8::/32",
		"64:ff9b::/96",
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}()

// IsBlockedIP reports whether an IP must never be dialed for an SSRF-sensitive
// outbound request. net.IP's classifiers fold IPv4-mapped IPv6 forms
// (e.g. ::ffff:127.0.0.1) into the v4 checks, so one predicate set covers both:
//   - IsLoopback:           127.0.0.0/8, ::1
//   - IsPrivate:            10/8, 172.16/12, 192.168/16, fc00::/7 (ULA)
//   - IsLinkLocalUnicast:   169.254.0.0/16 (incl. metadata), fe80::/10
//   - IsLinkLocalMulticast / IsMulticast / IsUnspecified: the rest
//
// Additionally, blockedNets covers the IANA special-purpose ranges net.IP
// misses (this-network, CGNAT, TEST-NETs, AS112 anycast, 6to4 relay,
// benchmarking, discard-only, documentation, reserved, NAT64).
func IsBlockedIP(ip net.IP) bool {
	if ip == nil ||
		ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() {
		return true
	}
	for _, n := range blockedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidateURL is a cheap, fail-fast check (e.g. at registration time) so an
// obviously unsafe destination (bad scheme, missing host, literal internal IP)
// is rejected early with a clear error. It is best-effort UX only — a hostname
// that resolves to an internal IP cannot be caught here; that is the job of
// SafeHTTPClient's dial-time guard, which also defeats DNS rebinding.
func ValidateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return ErrUnsafeURL
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ErrUnsafeURL
	}
	host := u.Hostname()
	if host == "" {
		return ErrUnsafeURL
	}
	if ip := net.ParseIP(host); ip != nil && IsBlockedIP(ip) {
		return ErrUnsafeURL
	}
	return nil
}

// safeControl is a net.Dialer.Control hook. It runs after DNS resolution with
// the concrete address the socket is about to connect to, so it rejects
// connections to blocked IPs even when a public hostname resolves (or is
// rebound) to an internal address. This is the authoritative SSRF guard.
func safeControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if IsBlockedIP(net.ParseIP(host)) {
		return ErrUnsafeURL
	}
	return nil
}

// SafeHTTPClient returns an http.Client whose dialer refuses connections to
// non-public addresses. Redirects are not followed: a 3xx to an internal URL
// would otherwise bypass the original ValidateURL check (the dialer guard still
// applies on the redirected dial, but disabling redirects keeps behaviour
// simple and avoids leaking payloads to unexpected hosts).
func SafeHTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   safeControl,
	}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

// PrivatePolicy is the explicit exception used by on-premise integrations.
// A private address is accepted only when both the original URL hostname and
// the resolved address match this compiled policy. Loopback, link-local,
// multicast, unspecified, this-network, CGNAT, protocol-assignment, TEST-NET,
// AS112 anycast, 6to4 relay, benchmark, discard-only, documentation, reserved
// and NAT64 addresses remain permanently blocked and cannot be allowlisted.
type PrivatePolicy struct {
	hosts map[string]struct{}
	nets  []*net.IPNet
}

// CompilePrivatePolicy validates and compiles an exact hostname/private-CIDR
// policy. Empty policies are valid and behave like SafeHTTPClient.
func CompilePrivatePolicy(hosts, cidrs []string) (*PrivatePolicy, error) {
	p := &PrivatePolicy{hosts: make(map[string]struct{}, len(hosts))}
	for _, raw := range hosts {
		host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
		if host == "" || strings.ContainsAny(host, "/:@[]") || net.ParseIP(host) != nil {
			return nil, fmt.Errorf("invalid private-policy hostname %q", raw)
		}
		p.hosts[host] = struct{}{}
	}
	for _, raw := range cidrs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil || !privateOnlyNetwork(network) {
			return nil, fmt.Errorf("invalid private-policy CIDR %q", raw)
		}
		p.nets = append(p.nets, network)
	}
	if len(p.hosts) == 0 && len(p.nets) != 0 || len(p.hosts) != 0 && len(p.nets) == 0 {
		return nil, errors.New("private-policy hosts and CIDRs must be configured together")
	}
	return p, nil
}

func privateOnlyNetwork(network *net.IPNet) bool {
	if network == nil {
		return false
	}
	// Only RFC1918 or IPv6 ULA ranges may be exceptions. Checking both the
	// network address and its last address prevents a broad CIDR from crossing
	// into a permanently blocked range.
	first := network.IP
	last := append(net.IP(nil), network.IP...)
	for i := range last {
		last[i] |= ^network.Mask[i]
	}
	return first.IsPrivate() && last.IsPrivate()
}

func (p *PrivatePolicy) hostAllowed(host string) bool {
	if p == nil {
		return false
	}
	_, ok := p.hosts[strings.ToLower(strings.TrimSuffix(host, "."))]
	return ok
}

func (p *PrivatePolicy) ipAllowed(ip net.IP) bool {
	if p == nil || !ip.IsPrivate() || permanentlyBlockedIP(ip) {
		return false
	}
	for _, network := range p.nets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func permanentlyBlockedIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, network := range blockedNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidateURLWithPrivatePolicy performs the cheap URL check while permitting
// only an exact allowlisted hostname to name a private target. Dial-time DNS
// resolution remains authoritative.
func ValidateURLWithPrivatePolicy(raw string, policy *PrivatePolicy) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return ErrUnsafeURL
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if IsBlockedIP(ip) {
			return ErrUnsafeURL // literal private addresses are never accepted
		}
		return nil
	}
	if !policy.hostAllowed(host) && strings.HasSuffix(strings.ToLower(host), ".local") {
		return ErrUnsafeURL
	}
	return nil
}

// SafeHTTPClientWithPrivatePolicy returns an HTTPS client that resolves each
// destination itself, rejects mixed unsafe DNS answers, and dials the validated
// concrete address so DNS cannot be rebound between validation and connect.
func SafeHTTPClientWithPrivatePolicy(timeout time.Duration, policy *PrivatePolicy) *http.Client {
	transport := &http.Transport{
		ForceAttemptHTTP2: true, MaxIdleConns: 100, IdleConnTimeout: 90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second, ExpectContinueTimeout: time.Second,
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return DialContextWithPrivatePolicy(ctx, network, address, policy)
	}
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     transport,
	}
}

// DialContextWithPrivatePolicy is the raw-TCP counterpart to the guarded HTTP
// client. It resolves every A/AAAA answer, rejects the entire set if any answer
// falls outside policy, and then dials only a validated concrete address. IMAP
// and other non-HTTP protocols must use this instead of a preflight DNS check.
func DialContextWithPrivatePolicy(ctx context.Context, network, address string, policy *PrivatePolicy) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return dialContextWithPrivatePolicy(ctx, network, address, policy, net.DefaultResolver.LookupIPAddr, dialer.DialContext)
}

type lookupIPAddrFunc func(context.Context, string) ([]net.IPAddr, error)
type dialContextFunc func(context.Context, string, string) (net.Conn, error)

func dialContextWithPrivatePolicy(
	ctx context.Context,
	network string,
	address string,
	policy *PrivatePolicy,
	lookup lookupIPAddrFunc,
	dial dialContextFunc,
) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ips, err := lookup(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, ErrUnsafeURL
	}
	allowPrivate := policy.hostAllowed(host)
	for _, candidate := range ips {
		if IsBlockedIP(candidate.IP) && !(allowPrivate && policy.ipAllowed(candidate.IP)) {
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
}
