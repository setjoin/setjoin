package testharness

import (
	"context"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/federation"
)

// TestStubSRVServerResolvesPeer proves the stub round-trips through
// federation.ResolvePeer's Resolver seam exactly the way a real fedharness
// instance will: query _setjoin-im._tcp.<domain>, get back a target+port.
func TestStubSRVServerResolvesPeer(t *testing.T) {
	srv, err := NewStubSRVServer("127.0.0.1:0", []SRVRecord{
		{Domain: "alpha.test", Target: "alpha-host.test", Port: 5269, Priority: 0, Weight: 0},
	})
	if err != nil {
		t.Fatalf("NewStubSRVServer: %v", err)
	}
	defer srv.Shutdown()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ep, err := federation.ResolvePeer(ctx, federation.NetResolver{R: srv.Resolver()}, "alpha.test")
	if err != nil {
		t.Fatalf("ResolvePeer: %v", err)
	}
	if ep.Target != "alpha-host.test" || ep.Port != 5269 {
		t.Fatalf("ResolvePeer = %+v, want target=alpha-host.test port=5269", ep)
	}
}

// TestDomainFromSRVName pins the one bit of string-parsing this stub does —
// a broken parse here would silently answer 0 records for every query
// (indistinguishable from "no peer" without this check).
func TestDomainFromSRVName(t *testing.T) {
	cases := []struct {
		name   string
		domain string
		ok     bool
	}{
		{"_setjoin-im._tcp.alpha.test.", "alpha.test", true},
		{"_setjoin-im._tcp.alpha.test", "alpha.test", true}, // dns.Fqdn adds the trailing dot
		{"_other-service._tcp.alpha.test.", "", false},
		{"alpha.test.", "", false},
	}
	for _, c := range cases {
		domain, ok := domainFromSRVName(c.name)
		if ok != c.ok || domain != c.domain {
			t.Errorf("domainFromSRVName(%q) = (%q, %v), want (%q, %v)", c.name, domain, ok, c.domain, c.ok)
		}
	}
}
