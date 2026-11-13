package ssrf

import (
	"context"
	"errors"
	"net"
	"net/http"
	"syscall"
	"testing"
	"time"
)

func TestIsBlockedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1",              // loopback v4
		"::1",                    // loopback v6
		"10.1.2.3",               // private
		"172.16.0.1",             // private
		"192.168.1.1",            // private
		"169.254.169.254",        // cloud metadata (link-local)
		"fe80::1",                // link-local v6
		"fc00::1",                // ULA
		"0.0.0.0",                // unspecified
		"::",                     // unspecified v6
		"::ffff:127.0.0.1",       // IPv4-mapped loopback
		"::ffff:169.254.169.254", // IPv4-mapped metadata
		"224.0.0.1",              // multicast
		// blockedNets ranges — not covered by stdlib classifiers
		"100.64.1.1",       // RFC 6598 CGNAT (AWS EKS pod IPs, overlays)
		"100.127.255.1",    // CGNAT upper end
		"192.0.0.1",        // IETF protocol assignments
		"198.18.0.1",       // RFC 2544 benchmarking
		"198.19.255.1",     // benchmarking upper end
		"240.0.0.1",        // reserved/future
		"255.255.255.255",  // broadcast
		"64:ff9b::1.2.3.4", // NAT64 well-known prefix
	}
	for _, s := range blocked {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test setup: %q did not parse", s)
		}
		if !IsBlockedIP(ip) {
			t.Errorf("IsBlockedIP(%s) = false, want true (internal/non-routable)", s)
		}
	}

	allowed := []string{
		"8.8.8.8",
		"1.1.1.1",
		"93.184.216.34", // example.com
		"2606:2800:220:1:248:1893:25c8:1946",
	}
	for _, s := range allowed {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test setup: %q did not parse", s)
		}
		if IsBlockedIP(ip) {
			t.Errorf("IsBlockedIP(%s) = true, want false (public)", s)
		}
	}
}

// TestIsBlockedIP_SpecialUseRanges pins the special-use closure
// (occ_8e399e220a93691f19b6c1d9): the IANA special-purpose ranges the stdlib
// classifiers miss are never dialable for an SSRF-sensitive outbound request,
// at validation time or dial time. Every range here is non-routable to a
// public destination, so a webhook policy that permitted any of them would let
// a user-registered URL name an internal or sinkhole destination.
func TestIsBlockedIP_SpecialUseRanges(t *testing.T) {
	blocked := []string{
		"0.1.2.3",            // this-network /8 interior (only 0.0.0.0 is IsUnspecified)
		"0.255.255.255",      // this-network upper end
		"192.0.2.1",          // TEST-NET-1
		"198.51.100.7",       // TEST-NET-2
		"203.0.113.99",       // TEST-NET-3
		"192.31.196.1",       // AS112 anycast
		"192.52.193.1",       // AS112 anycast
		"192.88.99.1",        // deprecated 6to4 relay anycast
		"192.175.48.1",       // AS112 anycast
		"100::1",             // RFC 6666 discard-only
		"100::abcd:0:0",      // discard-only interior
		"2001:db8::1",        // documentation
		"2001:db8:1234::567", // documentation interior
	}
	for _, s := range blocked {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test setup: %q did not parse", s)
		}
		if !IsBlockedIP(ip) {
			t.Errorf("IsBlockedIP(%s) = false, want true (special-use, non-public)", s)
		}
	}

	// The block also holds through the fail-fast URL check and the dial-time
	// control hook — both routes to a real socket must refuse.
	for _, host := range []string{"203.0.113.10", "2001:db8::10"} {
		if err := ValidateURL("http://" + net.JoinHostPort(host, "80") + "/hook"); err == nil {
			t.Errorf("ValidateURL accepted special-use literal %s", host)
		}
		var rc syscall.RawConn
		if err := safeControl("tcp", net.JoinHostPort(host, "443"), rc); err == nil {
			t.Errorf("safeControl allowed special-use address %s", host)
		}
	}

	// Permanent denials cannot be punched through by a private-policy
	// exception either.
	policy, err := CompilePrivatePolicy([]string{"mdm.internal.example"}, []string{"203.0.113.0/24"})
	if err == nil {
		t.Fatal("CompilePrivatePolicy accepted TEST-NET-3 CIDR, want rejection")
	}
	if policy != nil {
		t.Fatal("failed CompilePrivatePolicy must return a nil policy (fail closed)")
	}
}

func TestValidateURL(t *testing.T) {
	bad := []string{
		"",                       // empty
		"://nohost",              // unparseable scheme
		"ftp://example.com/x",    // wrong scheme
		"file:///etc/passwd",     // wrong scheme
		"gopher://example.com",   // wrong scheme
		"http://127.0.0.1/admin", // loopback literal
		"https://169.254.169.254/latest/meta-data/", // metadata literal
		"http://10.0.0.5:8080/hook",                 // private literal
		"http://[::1]:9000/x",                       // loopback v6 literal
		"https://",                                  // no host
	}
	for _, u := range bad {
		if err := ValidateURL(u); err == nil {
			t.Errorf("ValidateURL(%q) = nil, want error", u)
		}
	}

	good := []string{
		"https://hooks.example.com/ingest",
		"http://example.org/webhook",
		"https://api.partner.io:8443/events",
	}
	for _, u := range good {
		if err := ValidateURL(u); err != nil {
			t.Errorf("ValidateURL(%q) = %v, want nil", u, err)
		}
	}
}

func TestSafeControlRejectsInternal(t *testing.T) {
	var rc syscall.RawConn // nil is fine; safeControl never touches it
	if err := safeControl("tcp", "169.254.169.254:80", rc); err == nil {
		t.Error("safeControl allowed metadata address, want rejection")
	}
	if err := safeControl("tcp", "127.0.0.1:25", rc); err == nil {
		t.Error("safeControl allowed loopback, want rejection")
	}
	if err := safeControl("tcp", "8.8.8.8:443", rc); err != nil {
		t.Errorf("safeControl rejected public address: %v", err)
	}
}

func TestCompilePrivatePolicy(t *testing.T) {
	policy, err := CompilePrivatePolicy([]string{"office.internal.example"}, []string{"10.40.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	if !policy.hostAllowed("OFFICE.INTERNAL.EXAMPLE.") {
		t.Fatal("exact allowlisted hostname was not normalized")
	}
	if !policy.ipAllowed(net.ParseIP("10.40.2.8")) {
		t.Fatal("approved RFC1918 address was rejected")
	}
	for _, raw := range []string{"127.0.0.1", "169.254.169.254", "10.41.0.1", "100.64.0.1"} {
		if policy.ipAllowed(net.ParseIP(raw)) {
			t.Fatalf("policy accepted permanently blocked or out-of-scope address %s", raw)
		}
	}
	for _, tc := range []struct {
		hosts []string
		cidrs []string
	}{
		{[]string{"office.internal.example"}, nil},
		{nil, []string{"10.0.0.0/8"}},
		{[]string{"10.0.0.1"}, []string{"10.0.0.0/8"}},
		{[]string{"office.internal.example"}, []string{"0.0.0.0/0"}},
		{[]string{"office.internal.example"}, []string{"127.0.0.0/8"}},
	} {
		if _, err := CompilePrivatePolicy(tc.hosts, tc.cidrs); err == nil {
			t.Fatalf("unsafe policy accepted: %#v", tc)
		}
	}
}

func TestValidateURLWithPrivatePolicy(t *testing.T) {
	policy, err := CompilePrivatePolicy([]string{"office.internal.example"}, []string{"10.40.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		"https://office.internal.example/browser/dist/admin/admin.html",
		"https://public.example.com/hosting/discovery",
	} {
		if err := ValidateURLWithPrivatePolicy(raw, policy); err != nil {
			t.Fatalf("ValidateURLWithPrivatePolicy(%q)=%v", raw, err)
		}
	}
	for _, raw := range []string{
		"http://office.internal.example/hosting/discovery",
		"https://127.0.0.1/hosting/discovery",
		"https://169.254.169.254/latest/meta-data",
		"https://" + "user:pass@" + "office.internal.example/hosting/discovery",
	} {
		if err := ValidateURLWithPrivatePolicy(raw, policy); err == nil {
			t.Fatalf("unsafe URL accepted: %s", raw)
		}
	}
}

func TestPrivatePolicyHelperAndDialBoundaries(t *testing.T) {
	if privateOnlyNetwork(nil) || (*PrivatePolicy)(nil).hostAllowed("x") || (*PrivatePolicy)(nil).ipAllowed(net.ParseIP("10.0.0.1")) {
		t.Fatal("nil private policy helper allowed a target")
	}
	if !permanentlyBlockedIP(nil) || !permanentlyBlockedIP(net.ParseIP("224.0.0.1")) || !permanentlyBlockedIP(net.ParseIP("100.64.0.1")) {
		t.Fatal("permanently blocked helper missed a target")
	}
	if _, err := CompilePrivatePolicy([]string{"office.internal"}, []string{"bad"}); err == nil {
		t.Fatal("invalid CIDR accepted")
	}
	policy, err := CompilePrivatePolicy([]string{"office.internal"}, []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateURLWithPrivatePolicy("https://8.8.8.8/path", policy); err != nil {
		t.Fatalf("public literal rejected: %v", err)
	}
	if err := ValidateURLWithPrivatePolicy("https://printer.local/path", policy); !errors.Is(err, ErrUnsafeURL) {
		t.Fatalf("unlisted local URL=%v", err)
	}

	client := SafeHTTPClientWithPrivatePolicy(time.Second, policy)
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.DialContext == nil {
		t.Fatal("private-policy transport missing dial guard")
	}
	if err := client.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("redirect=%v", err)
	}
	if _, err := transport.DialContext(context.Background(), "tcp", "missing-port"); err == nil {
		t.Fatal("invalid address accepted")
	}
	if _, err := transport.DialContext(context.Background(), "tcp", "does-not-exist.invalid:443"); !errors.Is(err, ErrUnsafeURL) {
		t.Fatalf("unresolved host=%v", err)
	}
	if _, err := transport.DialContext(context.Background(), "tcp", "localhost:443"); !errors.Is(err, ErrUnsafeURL) {
		t.Fatalf("loopback host=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := transport.DialContext(ctx, "tcp", "8.8.8.8:443"); err == nil {
		t.Fatal("canceled public dial succeeded")
	}
}

func TestDialContextRejectsReboundAndMixedDNSAnswersBeforeDial(t *testing.T) {
	policy, err := CompilePrivatePolicy([]string{"office.internal.example"}, []string{"10.40.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateURLWithPrivatePolicy("https://office.internal.example/EWS/Exchange.asmx", policy); err != nil {
		t.Fatalf("registration precheck rejected approved hostname: %v", err)
	}

	for _, answers := range [][]net.IPAddr{
		{{IP: net.ParseIP("169.254.169.254")}},
		{{IP: net.ParseIP("10.40.2.8")}, {IP: net.ParseIP("169.254.169.254")}},
	} {
		dialed := false
		_, err := dialContextWithPrivatePolicy(
			t.Context(), "tcp", "office.internal.example:443", policy,
			func(context.Context, string) ([]net.IPAddr, error) { return answers, nil },
			func(context.Context, string, string) (net.Conn, error) {
				dialed = true
				return nil, errors.New("unexpected dial")
			},
		)
		if !errors.Is(err, ErrUnsafeURL) {
			t.Fatalf("rebound answers %v error = %v, want ErrUnsafeURL", answers, err)
		}
		if dialed {
			t.Fatalf("rebound answers %v reached the socket dialer", answers)
		}
	}
}

// TestDialRefusesNonAllowlistedRFC1918TargetDespiteExceptions is the
// dialer-level interception stand-in for the proposed
// disposable-network-namespace integration test (network namespaces are
// unavailable in this environment): an RFC1918 address INSIDE the admin CIDR
// exception must still never reach the socket dialer when the destination
// HOSTNAME is not the allowlisted one — exceptions require the exact name.
func TestDialRefusesNonAllowlistedRFC1918TargetDespiteExceptions(t *testing.T) {
	policy, err := CompilePrivatePolicy([]string{"imap.fortest.example"}, []string{"10.40.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	dialed := false
	_, err = dialContextWithPrivatePolicy(
		t.Context(), "tcp", "other.host.example:993", policy,
		func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("10.40.2.8")}}, nil
		},
		func(context.Context, string, string) (net.Conn, error) {
			dialed = true
			return nil, errors.New("unexpected dial")
		},
	)
	if !errors.Is(err, ErrUnsafeURL) {
		t.Fatalf("non-allowlisted host inside admin CIDR error = %v, want ErrUnsafeURL", err)
	}
	if dialed {
		t.Fatal("non-allowlisted RFC1918 target reached the socket dialer")
	}
}

// TestDialPermanentDenialsHoldDespiteAllowlistedExceptions pins ssrf.go's
// ipAllowed/permanentlyBlockedIP ordering at the dial boundary: loopback,
// link-local/169.254.169.254 metadata, CGNAT, broadcast and IPv4-mapped forms
// stay BLOCKED even when the destination host IS the allowlisted name and a
// legal admin CIDR exception is in force.
func TestDialPermanentDenialsHoldDespiteAllowlistedExceptions(t *testing.T) {
	policy, err := CompilePrivatePolicy([]string{"imap.fortest.example"}, []string{"10.40.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{
		"127.0.0.1",
		"169.254.169.254",
		"fe80::1",
		"100.64.1.1",
		"255.255.255.255",
		"::ffff:169.254.169.254",
		"0.0.0.0",
	} {
		dialed := false
		_, err := dialContextWithPrivatePolicy(
			t.Context(), "tcp", "imap.fortest.example:993", policy,
			func(context.Context, string) ([]net.IPAddr, error) {
				return []net.IPAddr{{IP: net.ParseIP(ip)}}, nil
			},
			func(context.Context, string, string) (net.Conn, error) {
				dialed = true
				return nil, errors.New("unexpected dial")
			},
		)
		if !errors.Is(err, ErrUnsafeURL) {
			t.Fatalf("permanent-denial address %s error = %v, want ErrUnsafeURL", ip, err)
		}
		if dialed {
			t.Fatalf("permanent-denial address %s reached the socket dialer", ip)
		}
	}
}

// TestDialAllowsAllowlistedHostWithInPolicyAnswers is the positive control
// for the exception path: the allowlisted hostname resolving to in-CIDR
// RFC1918 answers DOES dial the validated concrete address, and the dialer
// receives the resolved IP (not the hostname), so DNS rebinding between
// validation and connect cannot re-enter.
func TestDialAllowsAllowlistedHostWithInPolicyAnswers(t *testing.T) {
	policy, err := CompilePrivatePolicy([]string{"imap.fortest.example"}, []string{"10.40.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	var dialedAddresses []string
	_, err = dialContextWithPrivatePolicy(
		t.Context(), "tcp", "imap.fortest.example:993", policy,
		func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{
				{IP: net.ParseIP("10.40.9.9")},
				{IP: net.ParseIP("10.40.0.1")},
			}, nil
		},
		func(_ context.Context, network, address string) (net.Conn, error) {
			dialedAddresses = append(dialedAddresses, network+"|"+address)
			return nil, errors.New("dial stop")
		},
	)
	if err == nil {
		t.Fatal("dial guard returned success for a stub dialer, want the stub error")
	}
	want := []string{"tcp|10.40.9.9:993", "tcp|10.40.0.1:993"}
	if len(dialedAddresses) != len(want) {
		t.Fatalf("dialer addresses = %v, want %v", dialedAddresses, want)
	}
	for i := range want {
		if dialedAddresses[i] != want[i] {
			t.Fatalf("dialer addresses = %v, want %v", dialedAddresses, want)
		}
	}
}

// TestCompilePrivatePolicyRejectsPermanentDenialRanges pins that the ranges
// permanentlyBlockedIP denies can never be authored into a policy at compile
// time — the build-time half of "never allowlistable".
func TestCompilePrivatePolicyRejectsPermanentDenialRanges(t *testing.T) {
	for _, cidr := range []string{
		"127.0.0.0/8",    // loopback
		"169.254.0.0/16", // link-local incl. cloud metadata
		"fe80::/10",      // link-local v6
		"::1/128",        // loopback v6
		"0.0.0.0/0",      // unspecified boundary
		"100.64.0.0/10",  // CGNAT
		"224.0.0.0/4",    // multicast
		"192.0.2.0/24",   // TEST-NET-1 (not RFC1918)
	} {
		if _, err := CompilePrivatePolicy([]string{"host.example"}, []string{cidr}); err == nil {
			t.Fatalf("permanent-denial CIDR %s accepted into policy", cidr)
		}
	}
	for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"} {
		if _, err := CompilePrivatePolicy([]string{"host.example"}, []string{cidr}); err != nil {
			t.Fatalf("legal RFC1918/ULA exception CIDR %s rejected: %v", cidr, err)
		}
	}
}
