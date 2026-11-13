package testharness

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// SRVResolver builds a *net.Resolver that dials stubAddr for every lookup —
// the custom-Dial shape StubSRVServer's own Resolver() method uses,
// decoupled from a live *StubSRVServer so an instance that is NOT the
// designated stub host (see ParseStubARecords below) can still point
// federation.ResolvePeer at one running elsewhere. Hoisted from
// cmd/fedharness so cmd/fedservice shares it (no cross-package copy-paste).
func SRVResolver(stubAddr string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, stubAddr)
		},
	}
}

// ParseStubARecords parses the --stub-a-records flag: a comma-separated list
// of "domain=host:port" pairs, one per federating domain. Only the ONE
// instance designated as the stub host passes this flag (README.md); every
// other instance passes only --srv-stub, pointing at that host.
func ParseStubARecords(s string) ([]SRVRecord, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var recs []SRVRecord
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		domain, hostport, ok := strings.Cut(pair, "=")
		if !ok {
			return nil, fmt.Errorf("testharness: malformed --stub-a-records entry %q (want domain=host:port)", pair)
		}
		host, portStr, err := net.SplitHostPort(hostport)
		if err != nil {
			return nil, fmt.Errorf("testharness: malformed --stub-a-records entry %q: %w", pair, err)
		}
		var port uint16
		if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
			return nil, fmt.Errorf("testharness: bad port in --stub-a-records entry %q: %w", pair, err)
		}
		recs = append(recs, SRVRecord{Domain: domain, Target: host, Port: port})
	}
	return recs, nil
}
