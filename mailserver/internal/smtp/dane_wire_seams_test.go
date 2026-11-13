package smtp

// Wire-level seam coverage the scripted-seam matrix cannot reach: the real
// tlsaUpstreamAddr resolution (resolv.conf read — a file, never a network
// call), the real defaultExchangeTLSA wire exchange against a LOOPBACK stub
// DNS server, the non-TLSA answer skip in LookupTLSA, and the PKIX-TA
// chain-walk in daneRecordMatches against matching and non-matching chains.

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// loopbackDNSStub serves scripted DNS responses over UDP on 127.0.0.1 —
// loopback only, no external traffic.
type loopbackDNSStub struct {
	server *dns.Server
	addr   string
}

func newLoopbackDNSStub(t *testing.T, answer func(*dns.Msg) *dns.Msg) *loopbackDNSStub {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("stub dns listen: %v", err)
	}
	stub := &loopbackDNSStub{}
	stub.server = &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		resp := answer(r)
		if resp == nil {
			resp = new(dns.Msg)
			resp.SetRcode(r, dns.RcodeSuccess)
		}
		_ = w.WriteMsg(resp)
	})}
	go func() { _ = stub.server.ActivateAndServe() }()
	stub.addr = pc.LocalAddr().String()
	t.Cleanup(func() { _ = stub.server.Shutdown() })
	return stub
}

// TestTLSAUpstreamAddrReadsSystemResolver pins the one-shot default-upstream
// resolution: it returns a host:port (the system resolver's first server on
// port 53 when resolv.conf carries no port directive, or the documented
// DNSSEC default when resolv.conf is unreadable/empty) — and is stable across
// calls.
func TestTLSAUpstreamAddrReadsSystemResolver(t *testing.T) {
	first := tlsaUpstreamAddr()
	if first == "" {
		t.Fatal("tlsaUpstreamAddr returned an empty upstream address")
	}
	if second := tlsaUpstreamAddr(); second != first {
		t.Fatalf("tlsaUpstreamAddr unstable: %q then %q", first, second)
	}
	if _, _, err := net.SplitHostPort(first); err != nil {
		t.Fatalf("upstream %q is not host:port: %v", first, err)
	}
}

// TestDefaultExchangeTLSAWireRoundTrip drives the real exchange path against
// a loopback stub DNS server: a successful exchange returns the stub's
// response verbatim (the DO-bit/EDNS0 request is exercised on the wire), and
// an unreachable upstream surfaces a typed network error.
func TestDefaultExchangeTLSAWireRoundTrip(t *testing.T) {
	orig := tlsaUpstreamAddr() // fire the one-shot so the stub override is ours to restore
	t.Cleanup(func() { tlsaResolverAddr = orig })

	tlsa := tlsaRR(3, 1, 1, []byte{0xaa})
	stub := newLoopbackDNSStub(t, func(r *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.SetRcode(r, dns.RcodeSuccess)
		resp.Answer = []dns.RR{tlsa}
		return resp
	})
	tlsaResolverAddr = stub.addr

	const name = "_25._tcp.mx.example.test."
	resp, err := defaultExchangeTLSA(name)
	if err != nil {
		t.Fatalf("defaultExchangeTLSA against loopback stub: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("stub answer carried %d records, want the scripted TLSA RR", len(resp.Answer))
	}
	if got, ok := resp.Answer[0].(*dns.TLSA); !ok || got.Certificate != tlsa.Certificate {
		t.Fatalf("round-trip answer mismatch: %v", resp.Answer[0])
	}

	// An unreachable (closed loopback port) upstream is a lookup failure —
	// the typed error the DANE classification treats as unreachable.
	tlsaResolverAddr = "127.0.0.1:1"
	if _, err := defaultExchangeTLSA(name); err == nil {
		t.Fatal("defaultExchangeTLSA against a closed port returned nil error")
	} else if !strings.Contains(err.Error(), "TLSA lookup network error") {
		t.Fatalf("error %v does not name the TLSA network failure", err)
	}
}

// TestLookupTLSASkipsNonTLSAAnswers pins the RRset-order walk: a non-TLSA
// record in the answer section (aliases ride along on CNAME chasing) is
// skipped without ending the walk or corrupting the returned records.
func TestLookupTLSASkipsNonTLSAAnswers(t *testing.T) {
	assoc := []byte{0x01, 0x02, 0x03}
	cname := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: "_25._tcp.mx.example.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET},
		Target: "mx.example.test.",
	}
	fakeExchangeTLSA(t, dnsResponse(true, dns.RcodeSuccess, cname, tlsaRR(3, 1, 1, assoc)), nil)

	records, sec, err := LookupTLSA("mx.example.test")
	if err != nil {
		t.Fatalf("LookupTLSA: %v", err)
	}
	if sec != DANESecureSecurity {
		t.Fatalf("security = %q, want secure", sec)
	}
	if len(records) != 1 || records[0].Usage != 3 || len(records[0].CertAssoc) != 3 {
		t.Fatalf("records = %+v, want only the TLSA record with its decoded association", records)
	}
}

// danePKIXConnectionState assembles a fake TLS connection state whose leaf is
// chained under the given intermediate, with a PKIX-verified chain attached.
func danePKIXConnectionState(t *testing.T, leaf, intermediate *x509.Certificate) tls.ConnectionState {
	t.Helper()
	return tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf, intermediate},
		VerifiedChains:   [][]*x509.Certificate{{leaf, intermediate}},
	}
}

// TestDaneRecordMatchesPKIXTAChainWalk pins usage-0 (PKIX-TA) evaluation: the
// record binds ONE certificate of the validated chain — the leaf OR a CA
// above it — so a match on any chain member authenticates, and no match at
// all is a mismatch (the caller's DANECertMismatch outcome), not a skip.
func TestDaneRecordMatchesPKIXTAChainWalk(t *testing.T) {
	leaf, _ := newSelfSignedCert(t, "mx.example.test", "mx.example.test")
	intermediate, _ := newSelfSignedCert(t, "Test Intermediate CA")
	ca, _ := newSelfSignedCert(t, "Test Root CA")
	cs := danePKIXConnectionState(t, leaf, intermediate)
	logger := discardLogger()

	pkixTA := func(cert *x509.Certificate) *TLSARecord {
		return &TLSARecord{Usage: 0, Selector: 0, MatchingType: 1, CertAssoc: sha256Assoc(cert)}
	}

	// Match on the intermediate CA: chain walk finds it after the leaf fails.
	if !daneRecordMatches(cs, pkixTA(intermediate), "mx.example.test", logger) {
		t.Fatal("PKIX-TA record binding the intermediate CA did not match the chain")
	}
	// Match on the leaf itself (first candidate).
	if !daneRecordMatches(cs, pkixTA(leaf), "mx.example.test", logger) {
		t.Fatal("PKIX-TA record binding the leaf did not match")
	}
	// No chain member matches: false — an evaluated mismatch, never a skip.
	if daneRecordMatches(cs, pkixTA(ca), "mx.example.test", logger) {
		t.Fatal("PKIX-TA record bound to an unrelated CA matched the chain")
	}

	// End-to-end: an authenticated RRset binding the intermediate
	// authenticates the connection (DANESecure); an unrelated binding is a
	// hard DANECertMismatch even though the chain is CA-valid.
	fakeExchangeTLSA(t, dnsResponse(true, dns.RcodeSuccess, tlsaRR(0, 0, 1, sha256Assoc(intermediate))), nil)
	if got := ValidateDANEConnection(cs, "mx.example.test", logger); got != DANESecure {
		t.Fatalf("ValidateDANEConnection with chain-bound CA = %v, want DANESecure", got)
	}
	fakeExchangeTLSA(t, dnsResponse(true, dns.RcodeSuccess, tlsaRR(0, 0, 1, sha256Assoc(ca))), nil)
	if got := ValidateDANEConnection(cs, "mx.example.test", logger); got != DANECertMismatch {
		t.Fatalf("ValidateDANEConnection with unrelated CA binding = %v, want DANECertMismatch", got)
	}
}
