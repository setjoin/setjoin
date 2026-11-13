// Package testharness holds C0 spike-only scaffolding: per-domain test
// certs (gen-certs.sh), a stub DNS SRV server (this file), and the
// fedharness daemon skeleton (cmd/fedharness). None of this is production
// code — it exists to stand up the alpha/bravo/charlie instances the spike's
// experiments run against. See README.md.
package testharness

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// SRVRecord is one DNS SRV record StubSRVServer answers for
// _setjoin-im._tcp.<domain> queries.
type SRVRecord struct {
	Domain   string // the federation domain, e.g. "alpha.test"
	Target   string // SRV target hostname — an /etc/hosts A record, see README.md
	Port     uint16
	Priority uint16
	Weight   uint16
}

// StubSRVServer is a loopback-only DNS server answering ONLY
// `_setjoin-im._tcp.<domain>` SRV queries from a fixed in-memory record set.
// Harness-only, never production: A records for the SRV targets are left to
// /etc/hosts (README.md) — this stub exists solely so ResolvePeer's DNS SRV
// discovery step has something real to query without a public DNS zone.
type StubSRVServer struct {
	records map[string][]SRVRecord // keyed by federation domain
	srv     *dns.Server
}

// NewStubSRVServer starts a UDP DNS server on addr (use "127.0.0.1:0" for an
// ephemeral port) serving recs. Callers should defer Shutdown.
func NewStubSRVServer(addr string, recs []SRVRecord) (*StubSRVServer, error) {
	byDomain := make(map[string][]SRVRecord, len(recs))
	for _, r := range recs {
		byDomain[r.Domain] = append(byDomain[r.Domain], r)
	}
	s := &StubSRVServer{records: byDomain}

	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("testharness: listen %s: %w", addr, err)
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handle)
	s.srv = &dns.Server{PacketConn: pc, Handler: mux}

	started := make(chan struct{})
	s.srv.NotifyStartedFunc = func() { close(started) }
	errCh := make(chan error, 1)
	go func() { errCh <- s.srv.ActivateAndServe() }()

	select {
	case <-started:
	case err := <-errCh:
		return nil, fmt.Errorf("testharness: stub SRV server failed to start: %w", err)
	}
	return s, nil
}

// Addr returns the server's listening address (host:port) — feed it to
// Resolver's custom net.Resolver.Dial hook.
func (s *StubSRVServer) Addr() string {
	return s.srv.PacketConn.LocalAddr().String()
}

// Resolver returns a *net.Resolver that routes lookups to this stub via a
// custom Dial (README.md's documented shape: SRV records come from here; A
// records for the SRV *targets* still come from the system resolver via
// /etc/hosts on a real multi-instance box — a test that needs both wires a
// second, unmodified resolver for A lookups).
func (s *StubSRVServer) Resolver() *net.Resolver {
	addr := s.Addr()
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
}

// Shutdown stops the stub server.
func (s *StubSRVServer) Shutdown() error {
	return s.srv.ShutdownContext(context.Background())
}

func (s *StubSRVServer) handle(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	for _, q := range r.Question {
		if q.Qtype != dns.TypeSRV {
			continue
		}
		domain, ok := domainFromSRVName(q.Name)
		if !ok {
			continue
		}
		for _, rec := range s.records[domain] {
			m.Answer = append(m.Answer, &dns.SRV{
				Hdr:      dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 60},
				Priority: rec.Priority,
				Weight:   rec.Weight,
				Port:     rec.Port,
				Target:   dns.Fqdn(rec.Target),
			})
		}
	}
	_ = w.WriteMsg(m)
}

// domainFromSRVName extracts the federation domain from a query name of the
// form "_setjoin-im._tcp.<domain>." — the only shape this stub answers.
func domainFromSRVName(name string) (string, bool) {
	const prefix = "_setjoin-im._tcp."
	fqdn := dns.Fqdn(name)
	if !strings.HasPrefix(fqdn, prefix) {
		return "", false
	}
	return strings.TrimSuffix(fqdn[len(prefix):], "."), true
}
