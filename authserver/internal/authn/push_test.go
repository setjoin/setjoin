package authn

import (
	"bytes"
	"context"
	"crypto/ecdh"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"

	"setjoin.com/shared/ssrf"
	"setjoin.com/shared/testsupport"
)

// TestDeriveVAPIDPublicKey_MatchesGeneratedPair proves the derived public key
// equals what webpush-go's own GenerateVAPIDKeys produced for that private
// key — the QoL #9 /.well-known/setjoin vapid_public_key must be usable by
// pushManager.subscribe() to VAPID-authenticate to the same private key the
// server signs push payloads with.
func TestDeriveVAPIDPublicKey_MatchesGeneratedPair(t *testing.T) {
	priv, wantPub, err := webpush.GenerateVAPIDKeys()
	if err != nil {
		t.Fatalf("GenerateVAPIDKeys: %v", err)
	}
	gotPub, err := DeriveVAPIDPublicKey(priv)
	if err != nil {
		t.Fatalf("DeriveVAPIDPublicKey: %v", err)
	}
	if gotPub != wantPub {
		t.Errorf("derived public key mismatch:\n got  %s\n want %s", gotPub, wantPub)
	}
}

func TestDeriveVAPIDPublicKey_InvalidKey(t *testing.T) {
	if _, err := DeriveVAPIDPublicKey("not-valid-base64!!!"); err == nil {
		t.Error("expected an error for an undecodable key")
	}
}

// TestIPRateLimiter_PerIPBudget proves the per-IP limiter blocks a single
// source IP after the budget is exhausted — the gap the old code left, where a
// single IP could fan push challenges across many accounts while staying under
// each account's per-user cap.
func TestIPRateLimiter_PerIPBudget(t *testing.T) {
	l := NewIPRateLimiter(3, time.Minute)

	for i := 0; i < 3; i++ {
		if !l.Allow("203.0.113.7") {
			t.Fatalf("request %d should be allowed within budget", i+1)
		}
	}
	if l.Allow("203.0.113.7") {
		t.Error("4th request from same IP should be rate-limited")
	}

	// A different IP has its own independent budget.
	if !l.Allow("198.51.100.9") {
		t.Error("first request from a fresh IP must be allowed")
	}
}

// TestIPRateLimiter_WindowReset verifies the fixed window resets so legitimate
// users are not locked out forever.
func TestIPRateLimiter_WindowReset(t *testing.T) {
	l := NewIPRateLimiter(2, time.Minute)
	now := time.Unix(1_000_000, 0)
	l.now = func() time.Time { return now }

	if !l.Allow("ip") || !l.Allow("ip") {
		t.Fatal("first two requests should be allowed")
	}
	if l.Allow("ip") {
		t.Fatal("third request should be limited within window")
	}

	// Advance past the window — budget resets.
	now = now.Add(61 * time.Second)
	if !l.Allow("ip") {
		t.Error("request after window expiry should be allowed again")
	}
}

// TestIPRateLimiter_EmptyKeyFailOpen documents that an unresolved client IP is
// never limited by the per-IP layer (the per-user DB limit + threat interceptor
// still apply).
func TestIPRateLimiter_EmptyKeyFailOpen(t *testing.T) {
	l := NewIPRateLimiter(1, time.Minute)
	for i := 0; i < 5; i++ {
		if !l.Allow("") {
			t.Fatalf("empty key must never be limited (iteration %d)", i)
		}
	}
}

// TestNumberMatchPushProvider_AllowIP wires the limiter through the provider's
// public method the handler calls.
func TestNumberMatchPushProvider_AllowIP(t *testing.T) {
	p := &NumberMatchPushProvider{ipLimiter: NewIPRateLimiter(2, time.Minute)}
	if !p.AllowIP("10.0.0.1") || !p.AllowIP("10.0.0.1") {
		t.Fatal("first two from an IP should be allowed")
	}
	if p.AllowIP("10.0.0.1") {
		t.Error("third from the same IP should be blocked")
	}
	// Nil limiter must fail open (never panic / never block).
	pNil := &NumberMatchPushProvider{}
	if !pNil.AllowIP("10.0.0.1") {
		t.Error("provider with nil limiter must allow")
	}
}

func TestGenerateDecoys(t *testing.T) {
	correct := "42"
	for i := 0; i < 100; i++ {
		decoys := generateDecoys(correct, 2)
		if len(decoys) != 2 {
			t.Fatalf("run %d: generateDecoys returned %d decoys, want 2", i, len(decoys))
		}
		if decoys[0] == correct || decoys[1] == correct {
			t.Errorf("run %d: decoy matches correct answer %q", i, correct)
		}
		if decoys[0] == decoys[1] {
			t.Errorf("run %d: decoys are identical", i)
		}
		for _, d := range decoys {
			if len(d) != 2 {
				t.Errorf("run %d: decoy %q is not 2 digits", i, d)
			}
			// Must be numeric
			if _, err := fmt.Sscanf(d, "%d", new(int)); err != nil {
				t.Errorf("run %d: decoy %q is not numeric", i, d)
			}
		}
	}
}

func TestShuffleOptionButtons(t *testing.T) {
	correct := "42"
	decoys := []string{"17", "89"}

	// Run 100 times to verify correct is always present but order varies
	foundOrder := make(map[string]int)
	for i := 0; i < 100; i++ {
		options := shuffleOptionButtons(correct, decoys)
		if len(options) != 3 {
			t.Fatalf("run %d: got %d options, want 3", i, len(options))
		}

		var hasCorrect bool
		order := ""
		for _, opt := range options {
			order += opt["value"]
			if opt["value"] == correct {
				hasCorrect = true
			}
		}
		if !hasCorrect {
			t.Errorf("run %d: correct answer %q not in options", i, correct)
		}
		foundOrder[order]++
	}
	if len(foundOrder) < 2 {
		t.Errorf("shuffle produced only %d unique ordering(s) in 100 runs — likely not random", len(foundOrder))
	}
}

func TestChallengeResponseSerialization(t *testing.T) {
	resp := ChallengeResponse{
		Method:     "push",
		Nonce:      "abc123",
		TTLSeconds: 120,
		Fallback:   "totp",
	}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	wantKeys := []string{"mfa_method", "nonce", "ttl_seconds", "fallback"}
	for _, k := range wantKeys {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %q in JSON: %s", k, b)
		}
	}
	// SECURITY (C10): the correct number-match code must never be serialized into
	// any response the login client can read. Assert no answer-carrying field
	// leaks back in-band.
	for _, k := range []string{"challenge_number", "challenge_code", "code", "answer"} {
		if _, ok := m[k]; ok {
			t.Errorf("ChallengeResponse leaked answer-carrying key %q in-band: %s", k, b)
		}
	}
}

func TestGenerateDecoys_EdgeCases(t *testing.T) {
	// All 100 possible 2-digit codes
	for correct := 0; correct < 100; correct++ {
		correctStr := fmt.Sprintf("%02d", correct)
		decoys := generateDecoys(correctStr, 2)
		if len(decoys) != 2 {
			t.Fatalf("correct=%q: got %d decoys", correctStr, len(decoys))
		}
		if decoys[0] == correctStr || decoys[1] == correctStr {
			t.Errorf("correct=%q: decoy matches correct", correctStr)
		}
	}
}

func TestGenerateDecoys_SingleDigit(t *testing.T) {
	for n := 0; n < 10; n++ {
		correct := fmt.Sprintf("%02d", n)
		decoys := generateDecoys(correct, 2)
		if len(decoys) != 2 {
			t.Fatalf("correct=%q: got %d decoys", correct, len(decoys))
		}
	}
}

// ── Sender-side dial-time SSRF guard (ER6 residual, authserver lane) ────────
//
// occ_770fab validates a WebPush subscription endpoint at REGISTRATION time;
// a registered endpoint can still REBIND to internal space after the fact, so
// the send itself must dial through ssrf.SafeHTTPClientWithPrivatePolicy — the
// same sender-side guard shared/push.WebPushDispatcher carries. These tests
// prove the send-time defense in depth: a loopback (or loopback-resolving)
// endpoint is refused on the resolved address before a socket is opened, and a
// permitted endpoint receives the VAPID-authenticated delivery.

// pushGuardVAPIDKey returns a throwaway generated VAPID private key so the
// send path's VAPID signing runs for real (a garbage key fails before dialing
// and would make a refusal pass for the wrong reason).
func pushGuardVAPIDKey(t *testing.T) string {
	t.Helper()
	priv, _, err := webpush.GenerateVAPIDKeys()
	if err != nil {
		t.Fatalf("GenerateVAPIDKeys: %v", err)
	}
	return priv
}

// pushGuardSubscription returns a webpush.Subscription JSON body (fresh ECIES
// keys, the given endpoint) in the exact shape stored in push_token_enc.
func pushGuardSubscription(t *testing.T, endpoint string) string {
	t.Helper()
	key, err := ecdh.P256().GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("generate subscription key: %v", err)
	}
	auth := make([]byte, 16)
	if _, err := cryptorand.Read(auth); err != nil {
		t.Fatalf("generate subscription auth secret: %v", err)
	}
	return fmt.Sprintf(
		`{"endpoint":%q,"keys":{"p256dh":%q,"auth":%q}}`,
		endpoint,
		base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()),
		base64.RawURLEncoding.EncodeToString(auth),
	)
}

// pushGuardHitServer returns an httptest server that counts every request that
// actually reaches it — the guard's promise is that a refused dial never does.
func pushGuardHitServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// TestSendWebPushSubscription_RefusesLoopbackEndpoint proves the send-time
// guard on the PRODUCTION path (no client seam): a subscription endpoint on
// the literal loopback address — the exact shape a post-registration rebind
// produces — must fail with ssrf.ErrUnsafeURL in the chain, and zero requests
// may reach the loopback listener.
func TestSendWebPushSubscription_RefusesLoopbackEndpoint(t *testing.T) {
	srv, hits := pushGuardHitServer(t)

	p := &NumberMatchPushProvider{
		vapidPrivate: pushGuardVAPIDKey(t),
		vapidSubject: "mailto:push-guard-test@example.com",
	}
	var sub webpush.Subscription
	if err := json.Unmarshal(
		[]byte(pushGuardSubscription(t, srv.URL+"/wpush/v2/endpoint-capability")), &sub); err != nil {
		t.Fatalf("unmarshal subscription: %v", err)
	}

	err := p.sendWebPushSubscription([]byte(`{}`), &sub, 30)
	if err == nil {
		t.Fatal("a subscription endpoint on loopback must be refused at send time")
	}
	if !errors.Is(err, ssrf.ErrUnsafeURL) {
		t.Fatalf("error = %v, want ssrf.ErrUnsafeURL in the unwrap chain", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("send-time dial reached the loopback listener %d time(s)", hits.Load())
	}
}

// TestSendWebPushSubscription_RefusesHostnameOnBlockedRange proves the refusal
// rides the RESOLVED address, not the URL string: the endpoint names
// "localhost" (an innocuous public-looking name), the listener is really on
// loopback, and only a dial-time resolved-address check can refuse it.
func TestSendWebPushSubscription_RefusesHostnameOnBlockedRange(t *testing.T) {
	srv, hits := pushGuardHitServer(t)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse httptest URL: %v", err)
	}
	endpoint := fmt.Sprintf("http://localhost:%s/wpush/v2/rebind-capability", u.Port())

	p := &NumberMatchPushProvider{
		vapidPrivate: pushGuardVAPIDKey(t),
		vapidSubject: "mailto:push-guard-test@example.com",
	}
	var sub webpush.Subscription
	if err := json.Unmarshal([]byte(pushGuardSubscription(t, endpoint)), &sub); err != nil {
		t.Fatalf("unmarshal subscription: %v", err)
	}

	if err := p.sendWebPushSubscription([]byte(`{}`), &sub, 30); err == nil {
		t.Fatal("a subscription hostname resolving to loopback must be refused at send time")
	} else if !errors.Is(err, ssrf.ErrUnsafeURL) {
		t.Fatalf("error = %v, want ssrf.ErrUnsafeURL in the unwrap chain", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("send-time dial reached the loopback listener %d time(s)", hits.Load())
	}
}

// TestSendWebPushSubscription_DeliversToPushService pins the positive leg:
// with a client that permits the destination, the send delivers end to end —
// VAPID auth header, TTL, encrypted payload body, 2xx ⇒ nil.
//
// The injection seam is necessary, not a bypass: the production client's
// permanently-blocked set includes loopback, and loopback is the ONLY address
// a local httptest server can bind. The refusal legs above run the production
// default (no seam), so the guard itself stays the tested control.
func TestSendWebPushSubscription_DeliversToPushService(t *testing.T) {
	const endpointPath = "/wpush/v2/delivered-capability"
	var hits atomic.Int32
	var gotPath, gotAuth, gotTTL string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotTTL = r.Header.Get("TTL")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read pushed body: %v", err)
		}
		gotBody = body
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(srv.Close)

	p := &NumberMatchPushProvider{
		vapidPrivate:      pushGuardVAPIDKey(t),
		vapidSubject:      "mailto:push-guard-test@example.com",
		webPushHTTPClient: &http.Client{}, // tests-only seam (see doc comment above)
	}
	var sub webpush.Subscription
	if err := json.Unmarshal(
		[]byte(pushGuardSubscription(t, srv.URL+endpointPath)), &sub); err != nil {
		t.Fatalf("unmarshal subscription: %v", err)
	}

	if err := p.sendWebPushSubscription([]byte(`{"ping":1}`), &sub, 30); err != nil {
		t.Fatalf("send to a permitted endpoint: %v", err)
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
	if gotTTL != "30" {
		t.Fatalf("TTL header = %q, want %q", gotTTL, "30")
	}
	if len(gotBody) == 0 {
		t.Fatal("pushed body is empty — the encrypted payload never reached the endpoint")
	}
}

// TestSendWebPushTo_RefusesLoopbackEndpoint_DB runs the FULL production send
// path — stored ciphertext → pgp_sym_decrypt → subscription unmarshal →
// guarded send — against a loopback endpoint and proves the refusal is what
// the send half logs (sendWebPushTo swallows the error into errLabel logging,
// so the log line is the observable). DB-backed: skips without DB_DSN (CI
// sets REQUIRE_DB so it cannot silently skip there).
func TestSendWebPushTo_RefusesLoopbackEndpoint_DB(t *testing.T) {
	pool := testsupport.OpenTestPoolWithGUC(t, pushGUCGuardKey)
	srv, hits := pushGuardHitServer(t)

	var logBuf bytes.Buffer
	p := &NumberMatchPushProvider{
		pool:         pool,
		logger:       slog.New(slog.NewTextHandler(&logBuf, nil)),
		vapidPrivate: pushGuardVAPIDKey(t),
		vapidSubject: "mailto:push-guard-test@example.com",
	}
	tokenEnc := encryptPushGUCGuardToken(t, pool,
		pushGuardSubscription(t, srv.URL+"/wpush/v2/rebind-capability"))

	p.sendWebPushTo(context.Background(), tokenEnc, []byte(`{}`), 30, "push send failed")

	if hits.Load() != 0 {
		t.Fatalf("full-path dial reached the loopback listener %d time(s)", hits.Load())
	}
	if !strings.Contains(logBuf.String(), ssrf.ErrUnsafeURL.Error()) {
		t.Fatalf("send-time refusal must surface the guard error in the %q log, log = %q",
			"push send failed", logBuf.String())
	}
}

// TestSendWebPushTo_DeliversToPushService_DB is the full-path positive leg:
// the stored-subscription send delivers to a permitted endpoint with no error
// logged. The plain-client injection seam is tests-only (loopback is the only
// bindable address in-process); the refusal legs above pin the production
// default.
func TestSendWebPushTo_DeliversToPushService_DB(t *testing.T) {
	pool := testsupport.OpenTestPoolWithGUC(t, pushGUCGuardKey)

	var hits atomic.Int32
	var gotAuth string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		gotAuth = r.Header.Get("Authorization")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read pushed body: %v", err)
		}
		gotBody = body
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(srv.Close)

	var logBuf bytes.Buffer
	p := &NumberMatchPushProvider{
		pool:              pool,
		logger:            slog.New(slog.NewTextHandler(&logBuf, nil)),
		vapidPrivate:      pushGuardVAPIDKey(t),
		vapidSubject:      "mailto:push-guard-test@example.com",
		webPushHTTPClient: &http.Client{}, // tests-only seam (see doc comment above)
	}
	tokenEnc := encryptPushGUCGuardToken(t, pool,
		pushGuardSubscription(t, srv.URL+"/wpush/v2/delivered-capability"))

	p.sendWebPushTo(context.Background(), tokenEnc, []byte(`{"ping":1}`), 30, "push send failed")

	if hits.Load() != 1 {
		t.Fatalf("listener hit %d time(s), want exactly 1", hits.Load())
	}
	if !strings.HasPrefix(gotAuth, "vapid ") {
		t.Fatalf("Authorization = %q, want a VAPID scheme header", gotAuth)
	}
	if len(gotBody) == 0 {
		t.Fatal("pushed body is empty — the encrypted payload never reached the endpoint")
	}
	if logBuf.Len() != 0 {
		t.Fatalf("a delivered send must not log an error, log = %q", logBuf.String())
	}
}
