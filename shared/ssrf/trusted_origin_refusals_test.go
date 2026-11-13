package ssrf

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

func trustedDialContext(t *testing.T, trustedURL string, lookup lookupIPAddrFunc, dial dialContextFunc) func(context.Context, string, string) (net.Conn, error) {
	t.Helper()
	c, err := trustedOriginHTTPClient(trustedURL, time.Second, lookup, dial)
	if err != nil {
		t.Fatal(err)
	}
	return c.Transport.(originRouter).trustedRT.(*http.Transport).DialContext
}

func TestTrustedDialAllowed_NilRefused(t *testing.T) {
	if trustedDialAllowed(nil) {
		t.Fatal("nil IP must be refused")
	}
}

func TestTrustedControl_RefusesMalformedAndBlockedSocketAddresses(t *testing.T) {
	if err := trustedControl("tcp", "no-port", nil); err == nil {
		t.Fatal("address without port must error")
	}
	for _, addr := range []string{"169.254.169.254:80", "[fe80::1]:80", "0.0.0.0:80", "not-an-ip:80"} {
		if err := trustedControl("tcp", addr, nil); !errors.Is(err, ErrUnsafeURL) {
			t.Fatalf("%s: err=%v, want ErrUnsafeURL", addr, err)
		}
	}
	for _, addr := range []string{"127.0.0.1:80", "10.1.2.3:80"} {
		if err := trustedControl("tcp", addr, nil); err != nil {
			t.Fatalf("%s: err=%v, want allowed", addr, err)
		}
	}
}

func TestTrustedOriginDial_RefusalsAndFailover(t *testing.T) {
	ok := func(_ context.Context, _ string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("10.0.0.5")}}, nil
	}
	neverDial := func(context.Context, string, string) (net.Conn, error) {
		t.Error("dial must not be reached on a refused address")
		return nil, errors.New("unreachable")
	}
	ctx := context.Background()
	const trustedURL = "http://jwks.internal:8080/"

	if _, err := trustedDialContext(t, trustedURL, ok, neverDial)(ctx, "tcp", "no-port"); err == nil || errors.Is(err, ErrUnsafeURL) {
		t.Fatalf("malformed dial address: err=%v, want split error", err)
	}
	for _, addr := range []string{"evil.example:8080", "jwks.internal:9999"} {
		if _, err := trustedDialContext(t, trustedURL, ok, neverDial)(ctx, "tcp", addr); !errors.Is(err, ErrUnsafeURL) {
			t.Fatalf("%s: err=%v, want ErrUnsafeURL", addr, err)
		}
	}
	failing := func(context.Context, string) ([]net.IPAddr, error) { return nil, errors.New("nxdomain") }
	empty := func(context.Context, string) ([]net.IPAddr, error) { return nil, nil }
	for name, lk := range map[string]lookupIPAddrFunc{"lookup error": failing, "empty answer": empty} {
		if _, err := trustedDialContext(t, trustedURL, lk, neverDial)(ctx, "tcp", "jwks.internal:8080"); !errors.Is(err, ErrUnsafeURL) {
			t.Fatalf("%s: err=%v, want ErrUnsafeURL", name, err)
		}
	}

	// Every validated address failing to connect surfaces the last dial error.
	var tried []string
	boom := errors.New("connection refused")
	two := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("10.0.0.5")}, {IP: net.ParseIP("10.0.0.6")}}, nil
	}
	dial := func(_ context.Context, _, address string) (net.Conn, error) {
		tried = append(tried, address)
		return nil, boom
	}
	if _, err := trustedDialContext(t, trustedURL, two, dial)(ctx, "tcp", "jwks.internal:8080"); !errors.Is(err, boom) {
		t.Fatalf("err=%v, want last dial error", err)
	}
	if len(tried) != 2 || tried[0] != "10.0.0.5:8080" || tried[1] != "10.0.0.6:8080" {
		t.Fatalf("tried=%v, want both validated concrete addresses", tried)
	}
}
