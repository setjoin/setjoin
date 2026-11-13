package push

// webpush_test.go — the sender-side dial-time SSRF guard (ER6 residual rollup,
// Astra window-15 P2 on occ_770fab's registration-time validation). A
// registered subscription endpoint can REBIND to internal space after the
// fact, so WebPushDispatcher's HTTP client must refuse at DIAL time — after
// DNS resolution, on the concrete address — any destination in loopback,
// private, link-local or special-use space (shared/ssrf control genre, same
// family migration/IMAP bind). Refusals ride the same redaction seam as every
// other egress error: the endpoint URL is the device's bearer capability.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"setjoin.com/shared/ssrf"
)

func newSSRFTestDispatcher(t *testing.T) *WebPushDispatcher {
	t.Helper()
	return NewWebPushDispatcher(testVAPIDPrivateKey(t), "mailto:test@example.com")
}

// hitCountingServer returns an httptest server that counts every request that
// actually reaches it — the guard's promise is that a refused dial never does.
func hitCountingServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// TestWebPushDialTimeRefusesLoopbackEndpoint: a subscription endpoint on the
// literal loopback address (the exact shape an attacker-controlled
// registration or a post-registration rebind produces) must be refused at
// dial time — ssrf.ErrUnsafeURL in the error chain, zero requests reaching
// the listener, and no endpoint-path material in the redacted error text.
func TestWebPushDialTimeRefusesLoopbackEndpoint(t *testing.T) {
	t.Parallel()
	srv, hits := hitCountingServer(t)

	d := newSSRFTestDispatcher(t)
	err := d.Send(context.Background(), testWebPushSubscription(t, srv.URL+"/wpush/v2/endpoint-capability"), []byte(`{}`))
	if err == nil {
		t.Fatal("a subscription endpoint on loopback must be refused at dial time")
	}
	if !errors.Is(err, ssrf.ErrUnsafeURL) {
		t.Fatalf("error = %v, want ssrf.ErrUnsafeURL in the unwrap chain", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("guarded dial reached the loopback listener %d time(s)", hits.Load())
	}
	if strings.Contains(err.Error(), "/wpush/v2/") {
		t.Fatalf("refusal text leaks the endpoint capability path: %v", err)
	}
}

// TestWebPushDialTimeRefusesHostnameOnBlockedRange: the same refusal for a
// HOSTNAME that resolves into blocked space — the dial-time resolution check
// (not the URL string) must be the thing that catches it. The httptest server
// really listens on 127.0.0.1:<port>, but the endpoint names "localhost", so
// only a resolved-address guard can refuse without ever trusting the URL.
func TestWebPushDialTimeRefusesHostnameOnBlockedRange(t *testing.T) {
	t.Parallel()
	srv, hits := hitCountingServer(t)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse httptest URL: %v", err)
	}
	endpoint := fmt.Sprintf("http://localhost:%s/wpush/v2/endpoint-capability", u.Port())

	d := newSSRFTestDispatcher(t)
	err = d.Send(context.Background(), testWebPushSubscription(t, endpoint), []byte(`{}`))
	if err == nil {
		t.Fatal("a subscription hostname resolving to loopback must be refused at dial time")
	}
	if !errors.Is(err, ssrf.ErrUnsafeURL) {
		t.Fatalf("error = %v, want ssrf.ErrUnsafeURL in the unwrap chain", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("guarded dial reached the loopback listener %d time(s)", hits.Load())
	}
}

// TestWebPushZeroValueKeepsGuard pins the Send-time fallback: a dispatcher
// built as a bare struct literal (httpClient nil) still dials through the
// SSRF-guarded client — the guard is a property of the dispatcher, not of
// the constructor's wiring.
func TestWebPushZeroValueKeepsGuard(t *testing.T) {
	t.Parallel()
	srv, hits := hitCountingServer(t)

	d := &WebPushDispatcher{
		vapidPrivate: testVAPIDPrivateKey(t),
		vapidSubject: "mailto:test@example.com",
		ttl:          60,
	}
	if err := d.Send(context.Background(), testWebPushSubscription(t, srv.URL+"/wpush/v2/endpoint-capability"), []byte(`{}`)); err == nil {
		t.Fatal("zero-value dispatcher must refuse a loopback endpoint too")
	}
	if hits.Load() != 0 {
		t.Fatalf("unguarded dial reached the loopback listener %d time(s)", hits.Load())
	}
}

// TestWebPushDeliversToPublicEndpoint pins the positive leg: with a client
// that permits the destination, Send delivers end to end (VAPID auth header,
// encrypted body, 2xx ⇒ nil).
//
// The injection seam is necessary, not a bypass: the production client's
// permanently-blocked set includes loopback, and loopback is the ONLY address
// a local httptest server can bind — a "public" endpoint cannot exist in a
// unit test. The refusal legs above run against the PRODUCTION dispatcher
// (no seam), so the guard itself stays the tested control.
func TestWebPushDeliversToPublicEndpoint(t *testing.T) {
	t.Parallel()
	const endpointPath = "/wpush/v2/delivered-capability"
	var hits atomic.Int32
	var gotPath, gotAuth string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read pushed body: %v", err)
		}
		gotBody = body
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(srv.Close)

	d := newSSRFTestDispatcher(t)
	d.httpClient = &http.Client{} // tests-only seam (see doc comment above)
	if err := d.Send(context.Background(), testWebPushSubscription(t, srv.URL+endpointPath), []byte(`{"ping":1}`)); err != nil {
		t.Fatalf("Send to a permitted endpoint: %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("listener hit %d time(s), want exactly 1", hits.Load())
	}
	if gotPath != endpointPath {
		t.Fatalf("request path = %q, want %q", gotPath, endpointPath)
	}
	if !strings.HasPrefix(gotAuth, "vapid ") {
		t.Fatalf("Authorization = %q, want a VAPID scheme header", gotAuth)
	}
	if len(gotBody) == 0 {
		t.Fatal("pushed body is empty — the encrypted payload never reached the endpoint")
	}
}
