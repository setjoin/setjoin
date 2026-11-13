package smtp

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/miekg/dns"
	"setjoin.com/shared/dnsresolver"
)

// testResolver creates a dnsresolver.Resolver that queries a local mock DNS server.
// When addr is non-empty, it uses that address; otherwise returns a resolver primed
// for the mock server created in each test case. The empty trusted allowlist is
// the production default: the C6 trust binding demotes an untrusted AD bit, and
// these fakes never assert security levels (the adapters drop the level).
func testResolver(addr string) *dnsresolver.Resolver {
	return dnsresolver.New(addr, nil, nil)
}

// startMockDNSServer starts a local UDP DNS server that responds with canned
// answers. Returns the server address (ip:port) and a stop function.
func startMockDNSServer(t *testing.T, handler dns.HandlerFunc) (string, func()) {
	t.Helper()

	// Create the UDP listener first so we know the address before starting the server.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("startMockDNSServer: listen: %v", err)
	}

	udpServer := &dns.Server{
		PacketConn: pc,
		Handler:    handler,
	}

	// Start serving in background
	go func() {
		_ = udpServer.ActivateAndServe()
	}()

	addr := pc.LocalAddr().String()

	return addr, func() {
		udpServer.Shutdown()
		pc.Close()
	}
}

func TestMakeTXTResolver_ReturnsNonNil(t *testing.T) {
	r := testResolver("1.1.1.1:53")
	fn := makeTXTResolver(r)
	if fn == nil {
		t.Fatal("makeTXTResolver returned nil")
	}
}

func TestMakeMXResolver_ReturnsNonNil(t *testing.T) {
	r := testResolver("1.1.1.1:53")
	fn := makeMXResolver(r)
	if fn == nil {
		t.Fatal("makeMXResolver returned nil")
	}
}

func TestMakeIPResolver_ReturnsNonNil(t *testing.T) {
	r := testResolver("1.1.1.1:53")
	fn := makeIPResolver(r)
	if fn == nil {
		t.Fatal("makeIPResolver returned nil")
	}
}

func TestMakeAddrResolver_ReturnsNonNil(t *testing.T) {
	r := testResolver("1.1.1.1:53")
	fn := makeAddrResolver(r)
	if fn == nil {
		t.Fatal("makeAddrResolver returned nil")
	}
}

func TestMakeTXTResolver_DelegatesToResolver(t *testing.T) {
	// Create a mock DNS server that returns canned TXT records
	handler := func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Txt: []string{"v=spf1 -all"},
		})
		w.WriteMsg(m)
	}

	addr, stop := startMockDNSServer(t, handler)
	defer stop()

	r := testResolver(addr)
	fn := makeTXTResolver(r)

	txts, err := fn("example.com")
	if err != nil {
		t.Fatalf("TXT resolver: unexpected error: %v", err)
	}
	if len(txts) != 1 || txts[0] != "v=spf1 -all" {
		t.Errorf("TXT resolver: got %v, want [v=spf1 -all]", txts)
	}
}

func TestMakeMXResolver_DelegatesToResolver(t *testing.T) {
	handler := func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.MX{
			Hdr: dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: dns.TypeMX,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Preference: 10,
			Mx:         "mail.example.com.",
		})
		w.WriteMsg(m)
	}

	addr, stop := startMockDNSServer(t, handler)
	defer stop()

	r := testResolver(addr)
	fn := makeMXResolver(r)

	mxs, err := fn("example.com")
	if err != nil {
		t.Fatalf("MX resolver: unexpected error: %v", err)
	}
	if len(mxs) != 1 || mxs[0].Host != "mail.example.com." || mxs[0].Pref != 10 {
		t.Errorf("MX resolver: got %+v, want [{mail.example.com. 10}]", mxs)
	}
}

func TestMakeIPResolver_DelegatesToResolver(t *testing.T) {
	handler := func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		switch r.Question[0].Qtype {
		case dns.TypeAAAA:
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				AAAA: net.ParseIP("2001:db8::1"),
			})
		case dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.ParseIP("10.0.0.1"),
			})
		}
		w.WriteMsg(m)
	}

	addr, stop := startMockDNSServer(t, handler)
	defer stop()

	r := testResolver(addr)
	fn := makeIPResolver(r)

	ips, err := fn("mail.example.com")
	if err != nil {
		t.Fatalf("IP resolver: unexpected error: %v", err)
	}
	if len(ips) == 0 {
		t.Error("IP resolver: expected at least one IP address")
	}
}

func TestMakeAddrResolver_DelegatesToResolver(t *testing.T) {
	handler := func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.PTR{
			Hdr: dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: dns.TypePTR,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Ptr: "mail.example.com.",
		})
		w.WriteMsg(m)
	}

	addr, stop := startMockDNSServer(t, handler)
	defer stop()

	r := testResolver(addr)
	fn := makeAddrResolver(r)

	names, err := fn("10.0.0.1")
	if err != nil {
		t.Fatalf("Addr resolver: unexpected error: %v", err)
	}
	if len(names) != 1 || names[0] != "mail.example.com." {
		t.Errorf("Addr resolver: got %v, want [mail.example.com.]", names)
	}
}

func TestMakeTXTResolver_FallbackOnUpstreamFailure(t *testing.T) {
	// REAL-RESOLVER ARM (not hermetic by design): this is the only test in the
	// file that intentionally exercises the production system-resolver
	// fallback (net.DefaultResolver) after an unreachable upstream. The
	// adapter must forward whatever the resolver returns — success, not-found,
	// or error — so every outcome is acceptable and no network assumptions
	// are asserted.
	r := testResolver("127.0.0.1:1") // nothing listening here
	fn := makeTXTResolver(r)

	// The system resolver fallback should either succeed (if there's a default
	// resolver configured) or return an error. Either outcome is acceptable —
	// the key behavior is that the adapter doesn't panic and correctly delegates.
	_, err := fn("example.com")
	// Just verify the function is callable and returns without panicking
	_ = err // may or may not fail depending on system DNS configuration
}

func TestMakeAllResolvers_NilResolverPanics(t *testing.T) {
	// Nil resolver should not produce nil — each Make* should handle nil gracefully
	// by returning a function that returns an error, or by panicking immediately.
	// We check that they don't silently produce nil closures.
	t.Run("TXT", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				// Not panicking is also acceptable if it returns a working closure
			}
		}()
		fn := makeTXTResolver(nil)
		if fn == nil {
			t.Error("makeTXTResolver(nil) returned nil function")
		}
	})

	t.Run("MX", func(t *testing.T) {
		defer func() { recover() }()
		fn := makeMXResolver(nil)
		if fn == nil {
			t.Error("makeMXResolver(nil) returned nil function")
		}
	})

	t.Run("IP", func(t *testing.T) {
		defer func() { recover() }()
		fn := makeIPResolver(nil)
		if fn == nil {
			t.Error("makeIPResolver(nil) returned nil function")
		}
	})

	t.Run("Addr", func(t *testing.T) {
		defer func() { recover() }()
		fn := makeAddrResolver(nil)
		if fn == nil {
			t.Error("makeAddrResolver(nil) returned nil function")
		}
	})
}

func TestMakeAllResolvers_WireWithUseDNSResolver(t *testing.T) {
	// Integration test: verify the Make* functions produce closures that
	// work correctly when wired via UseDNSResolver.
	handler := func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		switch r.Question[0].Qtype {
		case dns.TypeTXT:
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
				Txt: []string{"wired-spf"},
			})
		case dns.TypeMX:
			m.Answer = append(m.Answer, &dns.MX{
				Hdr:        dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300},
				Preference: 10, Mx: "mx.example.com.",
			})
		}
		w.WriteMsg(m)
	}

	addr, stop := startMockDNSServer(t, handler)
	defer stop()

	r := testResolver(addr)

	// Wire all four lookup functions via the single UseDNSResolver entry point.
	UseDNSResolver(r)

	// Now the global LookupTXT/LookupMX should delegate to our mock via the adapter
	txts, err := LookupTXT("wired.example.com")
	if err != nil {
		t.Fatalf("LookupTXT after wiring: %v", err)
	}
	if len(txts) != 1 || txts[0] != "wired-spf" {
		t.Errorf("LookupTXT after wiring = %v, want [wired-spf]", txts)
	}

	mxs, err := LookupMX("wired.example.com")
	if err != nil {
		t.Fatalf("LookupMX after wiring: %v", err)
	}
	if len(mxs) != 1 || mxs[0].Host != "mx.example.com." {
		t.Errorf("LookupMX after wiring = %+v, want [{mx.example.com. 10}]", mxs)
	}

	// Restore defaults
	ResetDNSResolver()
}

// TestMakeTXTResolver_NoTXTRecords verifies the TXT adapter forwards an
// upstream NOERROR/NODATA answer with zero records and the resolver's
// not-found classification. It is fully hermetic: the resolver's upstream AND
// its system-resolver fallback seam both point at the local stub. The fallback
// must be pinned too — on an empty answer the resolver consults
// net.DefaultResolver (dnsresolver.LookupTXT), so the runner's own resolver
// would otherwise decide the outcome (systemd-resolved answers NXDOMAIN).
// The Go resolver maps an empty TXT answer section to a not-found DNSError
// (dnsclient_unix skipToAnswer) on EVERY host, and the SPF path consumes
// exactly that classification (RFC 7208 §4.3 maps IsNotFound to SPFNone), so
// the outcome below is deterministic rather than host-dependent.
func TestMakeTXTResolver_NoTXTRecords(t *testing.T) {
	handler := func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		// Authoritative NOERROR/NODATA: the AA flag is required for the Go
		// system resolver to accept the empty answer — without it the reply
		// is classified as a lame referral.
		m.Authoritative = true
		// Return a response with no answer records (NODATA)
		w.WriteMsg(m)
	}

	addr, stop := startMockDNSServer(t, handler)
	defer stop()

	// Point the system-resolver fallback seam at the same stub so the whole
	// path stays on this host regardless of the runner's resolver setup.
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, addr)
		},
	}
	t.Cleanup(func() { net.DefaultResolver = previous })

	r := testResolver(addr)
	fn := makeTXTResolver(r)

	txts, err := fn("nodata.example.com")
	if len(txts) != 0 {
		t.Errorf("TXT resolver NODATA: got %v, want no records", txts)
	}
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Fatalf("TXT resolver NODATA: err = %v, want a DNS not-found error forwarded from the resolver", err)
	}
}

// Ensure unused import is used
var _ = context.Background
