package smtp

import (
	"context"
	"net"

	"setjoin.com/shared/dnsresolver"
)

// makeTXTResolver creates a LookupTXT-compatible function that delegates to the
// DNSSEC-aware dnsresolver.Resolver. The SecurityLevel is dropped since the
// SPF/DKIM/DMARC lookups do not currently consume DNSSEC validation state
// (they operate on the DNS record content, not the security of its delivery).
func makeTXTResolver(r *dnsresolver.Resolver) func(domain string) ([]string, error) {
	if r == nil {
		return func(domain string) ([]string, error) {
			return nil, nil
		}
	}
	return func(domain string) ([]string, error) {
		txts, _, err := r.LookupTXT(context.Background(), domain)
		return txts, err
	}
}

// makeMXResolver creates a LookupMX-compatible function that delegates to the
// DNSSEC-aware dnsresolver.Resolver.
func makeMXResolver(r *dnsresolver.Resolver) func(domain string) ([]*net.MX, error) {
	if r == nil {
		return func(domain string) ([]*net.MX, error) {
			return nil, nil
		}
	}
	return func(domain string) ([]*net.MX, error) {
		mxs, _, err := r.LookupMX(context.Background(), domain)
		return mxs, err
	}
}

// makeIPResolver creates a LookupIP-compatible function that delegates to the
// DNSSEC-aware dnsresolver.Resolver.
func makeIPResolver(r *dnsresolver.Resolver) func(host string) ([]net.IP, error) {
	if r == nil {
		return func(host string) ([]net.IP, error) {
			return nil, nil
		}
	}
	return func(host string) ([]net.IP, error) {
		ips, _, err := r.LookupIP(context.Background(), host)
		return ips, err
	}
}

// makeAddrResolver creates a LookupAddr-compatible function that delegates to the
// DNSSEC-aware dnsresolver.Resolver.
func makeAddrResolver(r *dnsresolver.Resolver) func(addr string) ([]string, error) {
	if r == nil {
		return func(addr string) ([]string, error) {
			return nil, nil
		}
	}
	return func(addr string) ([]string, error) {
		names, _, err := r.LookupPTR(context.Background(), addr)
		return names, err
	}
}

// UseDNSResolver atomically swaps all four DNS lookup functions (TXT, MX, IP,
// PTR) to use the given DNSSEC-aware resolver. Pass nil to reset to system
// defaults. This is the single wiring point for injecting a custom DNS resolver
// at startup.
func UseDNSResolver(r *dnsresolver.Resolver) {
	if r == nil {
		ResetDNSResolver()
		return
	}
	setDNSResolvers(
		makeTXTResolver(r),
		makeMXResolver(r),
		makeIPResolver(r),
		makeAddrResolver(r),
	)
}
