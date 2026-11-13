package ssrf

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func countingServer(t *testing.T, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, c *http.Client, raw string) (*http.Response, error) {
	t.Helper()
	resp, err := c.Get(raw)
	if resp != nil {
		_ = resp.Body.Close()
	}
	return resp, err
}

func TestTrustedOriginClient_ConfiguredLoopbackOriginAllowed(t *testing.T) {
	var hits atomic.Int32
	srv := countingServer(t, &hits)
	c, err := TrustedOriginHTTPClient(srv.URL+"/jwks", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := get(t, c, srv.URL+"/jwks")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("trusted origin fetch: resp=%v err=%v", resp, err)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits=%d, want 1", hits.Load())
	}
}

func TestTrustedOriginClient_OtherDestinationsStillGuarded(t *testing.T) {
	var trustedHits, otherHits atomic.Int32
	trusted := countingServer(t, &trustedHits)
	other := countingServer(t, &otherHits) // same host, different port
	c, err := TrustedOriginHTTPClient(trusted.URL+"/jwks", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	tu, _ := url.Parse(trusted.URL)
	_, port, _ := net.SplitHostPort(tu.Host)

	for name, target := range map[string]string{
		"different port":         other.URL + "/jwks",
		"different private host": "http://10.0.0.1:" + port + "/jwks",
		"link-local metadata":    "http://169.254.169.254/latest/meta-data",
		"scheme mismatch":        "https://" + tu.Host + "/jwks",
		// The trusted name is matched as configured; its DNS answer is never
		// promoted to a trusted origin of its own.
		"resolved address of trusted name": "http://[::1]:" + port + "/jwks",
		"userinfo on trusted origin":       "http://u:p@" + tu.Host + "/jwks",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := get(t, c, target); !errors.Is(err, ErrUnsafeURL) {
				t.Fatalf("%s: err=%v, want ErrUnsafeURL", target, err)
			}
		})
	}
	if otherHits.Load() != 0 || trustedHits.Load() != 0 {
		t.Fatalf("guarded destinations reached a server: other=%d trusted=%d", otherHits.Load(), trustedHits.Load())
	}
}

func TestTrustedOriginClient_LocalhostNameDoesNotTrustItsAddress(t *testing.T) {
	var hits atomic.Int32
	srv := countingServer(t, &hits)
	su, _ := url.Parse(srv.URL)
	_, port, _ := net.SplitHostPort(su.Host)

	c, err := TrustedOriginHTTPClient("http://localhost:"+port+"/jwks", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := get(t, c, "http://localhost:"+port+"/jwks"); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("configured name: resp=%v err=%v", resp, err)
	}
	if _, err := get(t, c, "http://127.0.0.1:"+port+"/jwks"); !errors.Is(err, ErrUnsafeURL) {
		t.Fatalf("address the trusted name resolves to: err=%v, want ErrUnsafeURL", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits=%d, want 1", hits.Load())
	}
}

func TestTrustedOriginClient_RedirectsNeverFollowed(t *testing.T) {
	var targetHits atomic.Int32
	target := countingServer(t, &targetHits)
	mux := http.NewServeMux()
	mux.HandleFunc("/away", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/jwks", http.StatusFound)
	})
	mux.HandleFunc("/same", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/jwks", http.StatusFound)
	})
	var sameHits atomic.Int32
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) { sameHits.Add(1) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c, err := TrustedOriginHTTPClient(srv.URL+"/away", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/away", "/same"} {
		if _, err := get(t, c, srv.URL+p); !errors.Is(err, ErrRedirectRefused) {
			t.Fatalf("%s: err=%v, want ErrRedirectRefused", p, err)
		}
	}
	if targetHits.Load() != 0 || sameHits.Load() != 0 {
		t.Fatalf("redirect followed: away=%d same=%d", targetHits.Load(), sameHits.Load())
	}
}

func TestTrustedOriginClient_RejectsUnusableTrustedURL(t *testing.T) {
	for _, raw := range []string{"", "ftp://authserver/jwks", "http:///jwks", "http://u:p@authserver/jwks", "://bad"} {
		if _, err := TrustedOriginHTTPClient(raw, time.Second); err == nil {
			t.Errorf("TrustedOriginHTTPClient(%q) accepted", raw)
		}
	}
}

// fakeNet is the in-package resolver/dial seam: it answers every name with a
// fixed address set, records the concrete address the trusted transport asked
// to dial, and connects to a real test server so a request can complete.
type fakeNet struct {
	answers []string
	backend string // host:port of the real server every dial lands on
	dialed  []string
}

func (f *fakeNet) lookup(_ context.Context, _ string) ([]net.IPAddr, error) {
	out := make([]net.IPAddr, 0, len(f.answers))
	for _, a := range f.answers {
		out = append(out, net.IPAddr{IP: net.ParseIP(a)})
	}
	return out, nil
}

func (f *fakeNet) dial(ctx context.Context, network, address string) (net.Conn, error) {
	f.dialed = append(f.dialed, address)
	var d net.Dialer
	return d.DialContext(ctx, network, f.backend)
}

func fakeTrustedClient(t *testing.T, trustedURL string, f *fakeNet) *http.Client {
	t.Helper()
	c, err := trustedOriginHTTPClient(trustedURL, 5*time.Second, f.lookup, f.dial)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestTrustedOriginClient_TrustedNameNeverReachesPermanentlyBlockedRanges(t *testing.T) {
	var hits atomic.Int32
	srv := countingServer(t, &hits)
	backend := srv.Listener.Addr().String()
	for _, answers := range [][]string{
		{"169.254.169.254"}, // cloud metadata (the trusted name rebinding)
		{"fe80::1"},         // IPv6 link-local
		{"224.0.0.1"},       // multicast
		{"ff02::1"},         // IPv6 multicast
		{"0.0.0.0"},         // unspecified
		{"::"},              // IPv6 unspecified
		{"240.0.0.1"},       // reserved
		{"100.64.0.1"},      // CGNAT
		{"::ffff:169.254.169.254"},
		{"10.0.0.5", "169.254.169.254"}, // mixed answer set: refuse all
	} {
		t.Run(strings.Join(answers, ","), func(t *testing.T) {
			f := &fakeNet{answers: answers, backend: backend}
			c := fakeTrustedClient(t, "http://authserver:8080/jwks", f)
			if _, err := get(t, c, "http://authserver:8080/jwks"); !errors.Is(err, ErrUnsafeURL) {
				t.Fatalf("err=%v, want ErrUnsafeURL", err)
			}
			if len(f.dialed) != 0 {
				t.Fatalf("dialed %v before refusing", f.dialed)
			}
		})
	}
	if hits.Load() != 0 {
		t.Fatalf("blocked range reached the server %d times", hits.Load())
	}
}

func TestTrustedOriginClient_TrustedNameMayReachLoopbackAndPrivate(t *testing.T) {
	var hits atomic.Int32
	srv := countingServer(t, &hits)
	backend := srv.Listener.Addr().String()
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.9", "192.168.1.1", "::1", "fd00::7"} {
		t.Run(ip, func(t *testing.T) {
			f := &fakeNet{answers: []string{ip}, backend: backend}
			c := fakeTrustedClient(t, "http://authserver:8080/jwks", f)
			resp, err := get(t, c, "http://authserver:8080/jwks")
			if err != nil || resp.StatusCode != http.StatusOK {
				t.Fatalf("resp=%v err=%v", resp, err)
			}
			if want := net.JoinHostPort(ip, "8080"); len(f.dialed) != 1 || f.dialed[0] != want {
				t.Fatalf("dialed %v, want exactly the validated concrete address %s", f.dialed, want)
			}
		})
	}
}

func TestTrustedOriginClient_OriginMatchingForms(t *testing.T) {
	var hits atomic.Int32
	srv := countingServer(t, &hits)
	backend := srv.Listener.Addr().String()
	cases := []struct {
		name, trusted, request string
		allowed                bool
	}{
		{"trailing dot on request", "http://authserver:8080/jwks", "http://authserver.:8080/jwks", true},
		{"trailing dot on config", "http://authserver.:8080/jwks", "http://authserver:8080/jwks", true},
		{"case-insensitive host", "http://AuthServer:8080/jwks", "http://authserver:8080/jwks", true},
		{"ipv6 literal same form", "http://[::1]:8080/jwks", "http://[::1]:8080/jwks", true},
		{"ipv6 literal expanded form", "http://[::1]:8080/jwks", "http://[0:0:0:0:0:0:0:1]:8080/jwks", true},
		{"ipv6 literal different address", "http://[::1]:8080/jwks", "http://[fd00::1]:8080/jwks", false},
		{"ipv4-mapped ipv6 is not the v6 literal", "http://[::1]:8080/jwks", "http://[::ffff:127.0.0.1]:8080/jwks", false},
		{"explicit default port on request (http)", "http://authserver/jwks", "http://authserver:80/jwks", true},
		{"explicit default port on config (http)", "http://authserver:80/jwks", "http://authserver/jwks", true},
		{"explicit default port on request (https)", "https://authserver/jwks", "https://authserver:443/jwks", true},
		{"non-default port differs from default", "http://authserver/jwks", "http://authserver:8080/jwks", false},
		{"scheme mismatch http->https same host:port", "http://authserver:8080/jwks", "https://authserver:8080/jwks", false},
		{"scheme mismatch https->http same host:port", "https://authserver:8443/jwks", "http://authserver:8443/jwks", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The answer is private: only a trusted-origin match may reach it, so
			// a refused case also proves the request went to the strict guard.
			f := &fakeNet{answers: []string{"10.0.0.8"}, backend: backend}
			c := fakeTrustedClient(t, tc.trusted, f)
			resp, err := get(t, c, tc.request)
			if !tc.allowed {
				if len(f.dialed) != 0 || err == nil {
					t.Fatalf("non-matching origin used the trusted dial: dialed=%v err=%v", f.dialed, err)
				}
				return
			}
			if len(f.dialed) != 1 {
				t.Fatalf("matching origin not dialed via the trusted transport: dialed=%v err=%v", f.dialed, err)
			}
			// https cases hit a plain-HTTP backend; reaching the dial is the proof.
			if !strings.HasPrefix(tc.request, "https") && (err != nil || resp.StatusCode != http.StatusOK) {
				t.Fatalf("resp=%v err=%v", resp, err)
			}
		})
	}
}
