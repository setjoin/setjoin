package federation

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// srvService/srvProto are the DNS SRV service/proto pair Global Constraints
// locks discovery to: `_setjoin-im._tcp.<domain>`, MX-shaped, no central
// directory.
const (
	srvService = "setjoin-im"
	srvProto   = "tcp"
)

// PeerEndpoint is a federation peer domain's resolved network location.
type PeerEndpoint struct {
	Domain string // the federation domain, e.g. "alpha.test"
	Target string // SRV target hostname (FQDN, trailing dot stripped)
	Port   uint16
}

// Resolver is the injectable DNS seam ResolvePeer uses: net.DefaultResolver
// (via NetResolver) in production, testharness/srvstub.go's loopback stub in
// tests and on the harness.
type Resolver interface {
	LookupSRV(ctx context.Context, service, proto, name string) (cname string, addrs []*net.SRV, err error)
}

// NetResolver adapts a *net.Resolver to the Resolver seam. A nil R falls
// back to net.DefaultResolver.
type NetResolver struct{ R *net.Resolver }

func (n NetResolver) LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
	r := n.R
	if r == nil {
		r = net.DefaultResolver
	}
	return r.LookupSRV(ctx, service, proto, name)
}

// ResolvePeer discovers a federation peer's endpoint via DNS SRV
// (_setjoin-im._tcp.<domain> — Global Constraints). Go's net.LookupSRV
// already returns records sorted by priority then weight (RFC 2782); this
// spike dials the first (best) record and does not implement weighted
// selection among equal-priority records.
func ResolvePeer(ctx context.Context, r Resolver, domain string) (PeerEndpoint, error) {
	_, addrs, err := r.LookupSRV(ctx, srvService, srvProto, domain)
	if err != nil {
		return PeerEndpoint{}, fmt.Errorf("federation: SRV lookup for %s: %w", domain, err)
	}
	if len(addrs) == 0 {
		return PeerEndpoint{}, fmt.Errorf("federation: no SRV records for _%s._%s.%s", srvService, srvProto, domain)
	}
	best := addrs[0]
	return PeerEndpoint{
		Domain: domain,
		Target: strings.TrimSuffix(best.Target, "."),
		Port:   best.Port,
	}, nil
}
