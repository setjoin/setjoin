package device

// Tests for the med-shard2-006 replay binding: the device HMAC proof is bound
// to the full request shape (method, request URI, body hash) plus a single-use
// nonce consumed atomically deployment-wide (device_nonce_claim, committed
// before acceptance), and revoked devices lose the trust channel outright.
//
// Pure-unit tests run without a DB (every rejection before the DB touch); the
// DB-backed tests need DB_DSN (testsupport skips otherwise) and prove the
// replay/concurrency contract against the real nonce store.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/testsupport"
)

// testSecretCodec seals/opens device HMAC secrets in the _enc tests. The
// master key is test-only material (same raw-secret contract as production).
var testSecretCodec = NewSecretCodec([]byte("device-test-master-secret-key"), cryptokey.ProfileStandard)

// ── Pure unit coverage: challenge shape and pre-DB rejection paths ──────────

func TestChallengeForRequest_BindsMethodPathBodyAndNonce(t *testing.T) {
	base := ChallengeForRequest(7, "ts", "POST", "/device/checkin", "aa", "n1")

	// Every cell must change the challenge so a proof minted for one exact
	// request shape cannot be replayed against another (endpoint ⇄ endpoint,
	// method ⇄ method, body ⇄ body).
	cells := map[string]string{
		"device id":   ChallengeForRequest(8, "ts", "POST", "/device/checkin", "aa", "n1"),
		"timestamp":   ChallengeForRequest(7, "ts2", "POST", "/device/checkin", "aa", "n1"),
		"method":      ChallengeForRequest(7, "ts", "GET", "/device/checkin", "aa", "n1"),
		"request uri": ChallengeForRequest(7, "ts", "POST", "/device/policy", "aa", "n1"),
		"body hash":   ChallengeForRequest(7, "ts", "POST", "/device/checkin", "bb", "n1"),
		"nonce":       ChallengeForRequest(7, "ts", "POST", "/device/checkin", "aa", "n2"),
	}
	for name, mutated := range cells {
		if mutated == base {
			t.Errorf("challenge must differ when the %s cell changes", name)
		}
	}

	// Deterministic and prefix-compatible with ChallengeFor.
	if got, want := ChallengeForRequest(42, "T", "GET", "/p", "cc", "nn"),
		"42:T:GET:/p:cc:nn"; got != want {
		t.Errorf("ChallengeForRequest = %q, want %q", got, want)
	}
	if got := ChallengeForRequest(42, "T", "GET", "/p", "cc", "nn"); len(got) <= len(ChallengeFor(42, "T")) {
		t.Error("request challenge must extend the device+timestamp prefix")
	}
}

func TestVerifyDeviceRequest_RejectsBeforeDBWithoutSecretOrStore(t *testing.T) {
	// These rejection paths fire BEFORE any DB access, so a nil pool proves
	// they fail closed without one.
	req := httptest.NewRequest(http.MethodPost, "/device/checkin", nil)

	if err := VerifyDeviceRequest(context.Background(), nil, 1, req, testSecretCodec); err == nil {
		t.Error("missing HMAC must be rejected")
	}

	nonce := "nonce-unit"
	bh := hex.EncodeToString(make([]byte, sha256.Size)) // all-zero hex, right length
	req = httptest.NewRequest(http.MethodPost, "/device/checkin", nil)
	req.Header.Set(HeaderHMAC, "ab")
	req.Header.Set(HeaderTimestamp, time.Now().UTC().Format(time.RFC3339))
	// No nonce → rejected.
	if err := VerifyDeviceRequest(context.Background(), nil, 1, req, testSecretCodec); err == nil {
		t.Error("missing nonce must be rejected")
	}
	// Nonce + malformed body hash → rejected.
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set(HeaderBodyHash, "xyz")
	if err := VerifyDeviceRequest(context.Background(), nil, 1, req, testSecretCodec); err == nil {
		t.Error("malformed body hash must be rejected")
	}
	// Well-formed shape but stale timestamp → rejected.
	req.Header.Set(HeaderBodyHash, bh)
	req.Header.Set(HeaderTimestamp, time.Now().Add(-10*time.Minute).UTC().Format(time.RFC3339))
	if err := VerifyDeviceRequest(context.Background(), nil, 1, req, testSecretCodec); err == nil {
		t.Error("stale timestamp must be rejected")
	}
}

// ── DB-backed coverage: the real nonce store and revocation filter ──────────

// openNonceFixture provisions an isolated domain + user + device (default
// 'unenrolled' enroll state, a known HMAC secret) and returns a cleanup-faithful
// pool plus ids. Cleanup order: nonce rows + enroll events (device-scoped),
// then the device, then the user, then the domain.
func openNonceFixture(t *testing.T, tag string) (*pgxpool.Pool, int64, string) {
	t.Helper()
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	unix := time.Now().UnixNano()

	var domainID int64
	domainName := tag + "-device.example"
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ($1)
		 ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id`,
		domainName).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM domains WHERE id = $1`, domainID)
	})

	var userID int64
	username := tag + fmt.Sprintf("-%d", unix)
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name, password_hash)
		 VALUES ($1, $2, $3, 'Nonce Fixture', 'x') RETURNING id`,
		username, domainID, username+"@"+domainName).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM users WHERE id = $1`, userID)
	})

	secret := "nonce-fixture-device-secret-" + fmt.Sprintf("%d", unix)
	fingerprint := fmt.Sprintf("%s-fp-%040d", tag, unix)
	var deviceID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO devices (user_id, fingerprint, hmac_secret, platform)
		 VALUES ($1, $2, $3, 'ios') RETURNING id`,
		userID, fingerprint, secret).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		// device_enroll_events + device_auth_nonces cascade from devices.
		_, _ = pool.Exec(c, `DELETE FROM devices WHERE id = $1`, deviceID)
	})

	return pool, deviceID, secret
}

// signedProofRequest builds a request carrying a complete remediated proof.
// A non-empty body is attached as the actual request bytes; the empty body
// yields the bodyless shape (server-style empty body).
func signedProofRequest(method, target, secret string, deviceID int64, ts, nonce, body string) *http.Request {
	return capturedProofHeaders(method, target, secret, deviceID, ts, nonce, body).Request(method, target, body)
}

// capturedProofHeaders mints the header set of a complete device proof (HMAC
// over the full request challenge) for the given body, decoupled from any
// request object — the shape of a captured proof an attacker replays
// unchanged against substituted, empty, or previously consumed bytes.
func capturedProofHeaders(method, target, secret string, deviceID int64, ts, nonce, body string) proofHeaders {
	sum := sha256.Sum256([]byte(body))
	bodyHash := hex.EncodeToString(sum[:])
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ChallengeForRequest(deviceID, ts, method, target, bodyHash, nonce)))
	return proofHeaders{
		deviceID: deviceID, ts: ts, nonce: nonce, bodyHash: bodyHash,
		hmac: hex.EncodeToString(mac.Sum(nil)),
	}
}

// proofHeaders is a captured proof's header set; Request attaches it to a
// fresh request exactly as captured.
type proofHeaders struct {
	deviceID int64
	ts       string
	nonce    string
	bodyHash string
	hmac     string
}

// Request attaches the captured header set to a fresh request whose actual
// bytes are body ("" builds the bodyless shape). The headers are NEVER
// adjusted to match a substituted body — that is the whole point of an
// unchanged-proof test.
func (h proofHeaders) Request(method, target, body string) *http.Request {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, target, nil)
	} else {
		req = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	req.Header.Set(HeaderDeviceID, fmt.Sprintf("%d", h.deviceID))
	req.Header.Set(HeaderTimestamp, h.ts)
	req.Header.Set(HeaderNonce, h.nonce)
	req.Header.Set(HeaderBodyHash, h.bodyHash)
	req.Header.Set(HeaderHMAC, h.hmac)
	return req
}

func freshTS() string { return time.Now().UTC().Format(time.RFC3339) }

// ── Unchanged-proof body binding (wave67 HOLD: verify.go:215) ───────────────
//
// These tests replay ONE captured proof — headers minted over the original
// body, never re-signed — against requests whose actual bytes were
// substituted, stripped, or already consumed before verification. Telemetry
// and the login CA evaluation verify AFTER their handlers consumed the body,
// so the verifier must never treat the signed hash header as its own proof:
// an unobservable body fails closed unless a trusted server-computed digest
// binds it. Every rejection here fires before any DB touch (nil pool).

const (
	proofTarget     = "/device/telemetry"
	proofBody       = `{"crash_count":1,"app_version":"5.4.1"}`
	substitutedBody = `{"crash_count":999,"app_version":"9.9.9"}`
)

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// consume drains a request body the way the telemetry handler or the login CA
// evaluation does BEFORE the device proof is verified.
func consumeBody(t *testing.T, r *http.Request) {
	t.Helper()
	if _, err := io.ReadAll(r.Body); err != nil {
		t.Fatalf("consume request body: %v", err)
	}
}

// TestVerifyDeviceRequest_UnchangedProofRejectsSubstitutedBody: a captured
// proof authenticates only the exact bytes it was minted for — observable
// substituted bytes are hashed and compared against the signed commitment,
// never waved through on the strength of the hash header.
func TestVerifyDeviceRequest_UnchangedProofRejectsSubstitutedBody(t *testing.T) {
	capture := capturedProofHeaders("POST", proofTarget, "secret", 1, freshTS(), "nonce-substituted", proofBody)
	req := capture.Request("POST", proofTarget, substitutedBody)
	err := VerifyDeviceRequest(context.Background(), nil, 1, req, testSecretCodec)
	if err == nil {
		t.Fatal("captured proof must not authenticate substituted body bytes")
	}
	if !strings.Contains(err.Error(), "body hash does not match") {
		t.Fatalf("rejection must be the body binding (not a later check), got: %v", err)
	}
}

// TestVerifyDeviceRequest_UnchangedProofRejectsEmptyBody: the same captured
// proof replayed with the body stripped entirely must fail — a proof binding
// a non-empty body cannot authenticate a bodyless request.
func TestVerifyDeviceRequest_UnchangedProofRejectsEmptyBody(t *testing.T) {
	capture := capturedProofHeaders("POST", proofTarget, "secret", 1, freshTS(), "nonce-stripped", proofBody)
	req := capture.Request("POST", proofTarget, "")
	if err := VerifyDeviceRequest(context.Background(), nil, 1, req, testSecretCodec); err == nil {
		t.Fatal("captured proof must not authenticate a stripped/empty body")
	} else if !strings.Contains(err.Error(), "body hash does not match") {
		t.Fatalf("rejection must be the body binding, got: %v", err)
	}
}

// TestVerifyDeviceRequest_UnchangedProofRejectsPreviouslyConsumedBody: the
// verify-after-consume shape — the handler consumed the request bytes before
// the proof is verified, so the verifier observes only an empty remainder.
// With no trusted server-computed digest the binding is unprovable and must
// fail closed: for substituted bytes, for the originally signed bytes, and
// for an empty-body capture replayed over consumed substituted bytes.
func TestVerifyDeviceRequest_UnchangedProofRejectsPreviouslyConsumedBody(t *testing.T) {
	capture := capturedProofHeaders("POST", proofTarget, "secret", 1, freshTS(), "nonce-consumed", proofBody)

	// Substituted bytes consumed before verification: the substitution must
	// not slip through just because the verifier can no longer see them.
	substituted := capture.Request("POST", proofTarget, substitutedBody)
	consumeBody(t, substituted)
	err := VerifyDeviceRequest(context.Background(), nil, 1, substituted, testSecretCodec)
	if err == nil {
		t.Fatal("consumed substituted bytes must fail closed without a trusted digest")
	}
	if !strings.Contains(err.Error(), "consumed before verification") {
		t.Fatalf("rejection must be the consumed-body fail-closed path, got: %v", err)
	}

	// Even the ORIGINALLY signed bytes, once consumed before verification,
	// are unverifiable from the verifier's seat: verify before consuming, or
	// carry a trusted digest.
	matching := capture.Request("POST", proofTarget, proofBody)
	consumeBody(t, matching)
	if err := VerifyDeviceRequest(context.Background(), nil, 1, matching, testSecretCodec); err == nil {
		t.Fatal("consumed bytes cannot be bound to the proof without trusted evidence")
	}

	// An empty-body capture unlocks nothing either: ContentLength > 0 proves
	// bytes existed on the wire, and none of them are verifiable here.
	emptyCapture := capturedProofHeaders("POST", proofTarget, "secret", 1, freshTS(), "nonce-empty-capture", "")
	emptySub := emptyCapture.Request("POST", proofTarget, substitutedBody)
	consumeBody(t, emptySub)
	if err := VerifyDeviceRequest(context.Background(), nil, 1, emptySub, testSecretCodec); err == nil {
		t.Fatal("empty-body capture must not authenticate consumed substituted bytes")
	}
}

// TestVerifyBodyHash_TrustedServerDigestBindsConsumedBody: the approved
// alternative for verify-after-consume flows — the server component that
// consumed the body records a trusted server-computed digest and the verifier
// binds the signed commitment to it. The digest is trusted evidence, not a
// rubber stamp: it must agree with the signed commitment, and a consumed body
// without it still fails closed.
func TestVerifyBodyHash_TrustedServerDigestBindsConsumedBody(t *testing.T) {
	capture := capturedProofHeaders("POST", proofTarget, "secret", 1, freshTS(), "nonce-digest", proofBody)

	req := capture.Request("POST", proofTarget, proofBody)
	consumeBody(t, req) // handler consumes the bytes before verifying

	// Consumed bytes + trusted digest matching the signed commitment → bound.
	if err := verifyBodyHash(WithServerBodyDigest(req, sha256Hex(proofBody)), capture.bodyHash); err != nil {
		t.Fatalf("trusted server digest must bind the consumed body: %v", err)
	}

	// A trusted digest that disagrees with the signed commitment rejects.
	if err := verifyBodyHash(WithServerBodyDigest(req, sha256Hex(substitutedBody)), capture.bodyHash); err == nil {
		t.Fatal("a server digest that disagrees with the signed commitment must reject")
	}

	// Without the trusted digest marker the consumed body stays fail-closed.
	if err := verifyBodyHash(req, capture.bodyHash); err == nil {
		t.Fatal("consumed body without the trusted digest must fail closed")
	}
}

// TestVerifyBodyHash_AllEvidenceMustAgree: where the body is still observable
// AND a trusted digest is carried, both must match the commitment — one piece
// of matching evidence never neutralizes the other's disagreement.
func TestVerifyBodyHash_AllEvidenceMustAgree(t *testing.T) {
	capture := capturedProofHeaders("POST", proofTarget, "secret", 1, freshTS(), "nonce-agree", proofBody)

	agree := capture.Request("POST", proofTarget, proofBody)
	if err := verifyBodyHash(WithServerBodyDigest(agree, sha256Hex(proofBody)), capture.bodyHash); err != nil {
		t.Fatalf("matching bytes and agreeing digest must verify: %v", err)
	}

	disagree := capture.Request("POST", proofTarget, proofBody)
	if err := verifyBodyHash(WithServerBodyDigest(disagree, sha256Hex(substitutedBody)), capture.bodyHash); err == nil {
		t.Fatal("an observable match must not neutralize a disagreeing trusted digest")
	}
}

// TestVerifyBodyHash_ProvablyEmptyBodiesRequireEmptyCommitment: bodyless
// requests verify against the empty-string hash — the actual bytes ARE empty,
// so a compliant bodyless proof passes and a non-empty commitment fails.
func TestVerifyBodyHash_ProvablyEmptyBodiesRequireEmptyCommitment(t *testing.T) {
	emptyHash := sha256Hex("")

	// Server-shaped bodyless request (ContentLength 0).
	bodyless := httptest.NewRequest("GET", "/device/policy", nil)
	if err := verifyBodyHash(bodyless, emptyHash); err != nil {
		t.Fatalf("bodyless request with empty commitment must verify: %v", err)
	}
	if err := verifyBodyHash(bodyless, sha256Hex(proofBody)); err == nil {
		t.Fatal("bodyless request must not satisfy a non-empty commitment")
	}

	// The explicit http.NoBody shape behaves identically.
	nobody := httptest.NewRequest("POST", proofTarget, http.NoBody)
	if err := verifyBodyHash(nobody, emptyHash); err != nil {
		t.Fatalf("http.NoBody with empty commitment must verify: %v", err)
	}
	if err := verifyBodyHash(nobody, sha256Hex(proofBody)); err == nil {
		t.Fatal("http.NoBody must not satisfy a non-empty commitment")
	}
}

// TestVerifyBodyHash_ObservableBodyBindsCommitment: regression anchor for the
// middleware (verify-before-consume) flow — matching observable bytes verify,
// substituted observable bytes are caught, and the body is restored for the
// downstream handler either way.
func TestVerifyBodyHash_ObservableBodyBindsCommitment(t *testing.T) {
	bodyHash := sha256Hex(proofBody)

	matching := httptest.NewRequest("POST", proofTarget, strings.NewReader(proofBody))
	if err := verifyBodyHash(matching, bodyHash); err != nil {
		t.Fatalf("matching observable body must verify: %v", err)
	}
	rest, err := io.ReadAll(matching.Body)
	if err != nil || string(rest) != proofBody {
		t.Fatalf("body must be restored for the handler: %q, %v", rest, err)
	}

	substituted := httptest.NewRequest("POST", proofTarget, strings.NewReader(substitutedBody))
	if err := verifyBodyHash(substituted, bodyHash); err == nil {
		t.Fatal("substituted observable bytes must be caught")
	}
}

// TestVerifyDeviceRequest_AcceptsBodyfulProofThenRejectsSubstitution: the
// full seam accepts a bodyful proof whose observable bytes match its signed
// commitment, and the SAME captured headers replayed against substituted
// bytes are rejected at the body binding — pinned by message, so a bypass
// that falls through to the (spent) nonce store cannot mask the regression.
func TestVerifyDeviceRequest_AcceptsBodyfulProofThenRejectsSubstitution(t *testing.T) {
	pool, deviceID, secret := openNonceFixture(t, "bodybind")
	ctx := context.Background()

	proof := signedProofRequest("POST", "/device/checkin", secret, deviceID, freshTS(), "nonce-bodybind-1", proofBody)
	if err := VerifyDeviceRequest(ctx, pool, deviceID, proof, testSecretCodec); err != nil {
		t.Fatalf("bodyful acceptance: %v", err)
	}

	substituted := capturedProofHeaders("POST", "/device/checkin", secret, deviceID,
		proof.Header.Get(HeaderTimestamp), "nonce-bodybind-1", proofBody).
		Request("POST", "/device/checkin", substitutedBody)
	err := VerifyDeviceRequest(ctx, pool, deviceID, substituted, testSecretCodec)
	if err == nil {
		t.Fatal("substituted bytes under the captured proof must be rejected")
	}
	if !strings.Contains(err.Error(), "body hash does not match") {
		t.Fatalf("rejection must be the body binding, got: %v", err)
	}
}

// TestVerifyDeviceRequest_AcceptsOnceThenRejectsReplay: one captured proof is
// accepted exactly once; the verbatim replay within the freshness window —
// same headers, same everything — is rejected by the nonce store.
func TestVerifyDeviceRequest_AcceptsOnceThenRejectsReplay(t *testing.T) {
	pool, deviceID, secret := openNonceFixture(t, "once")
	ctx := context.Background()

	proof := signedProofRequest("POST", "/device/checkin", secret, deviceID, freshTS(), "nonce-once-1", "")
	if err := VerifyDeviceRequest(ctx, pool, deviceID, proof, testSecretCodec); err != nil {
		t.Fatalf("first acceptance: %v", err)
	}
	// A verbatim replay is a NEW request object with the SAME captured headers.
	replay := signedProofRequest("POST", "/device/checkin", secret, deviceID, freshTS(), "nonce-once-1", "")
	if err := VerifyDeviceRequest(ctx, pool, deviceID, replay, testSecretCodec); err == nil {
		t.Fatal("verbatim replay of the captured proof must be rejected")
	}
	var claims int
	if err := pool.QueryRow(ctx,
		`SELECT count(*)::int FROM device_auth_nonces WHERE device_id = $1 AND nonce = 'nonce-once-1'`,
		deviceID).Scan(&claims); err != nil {
		t.Fatalf("count nonce claims: %v", err)
	}
	if claims != 1 {
		t.Fatalf("nonce claims = %d, want exactly 1", claims)
	}
}

// TestVerifyDeviceRequest_BindingCellsRejectCrossEndpoint: one captured header
// set cannot be replayed against the SECOND endpoint (method/URI/body cells) —
// even with a nonce the attacker did not capture (which fails the HMAC), and
// the correctly-signed different-endpoint proof consumes its own nonce without
// legitimizing the first.
func TestVerifyDeviceRequest_BindingCellsRejectCrossEndpoint(t *testing.T) {
	pool, deviceID, secret := openNonceFixture(t, "bind")
	ctx := context.Background()
	ts := freshTS()
	nonce := "nonce-bind-1"

	// Proof minted for POST /device/checkin...
	checkin := signedProofRequest("POST", "/device/checkin", secret, deviceID, ts, nonce, "")
	if err := VerifyDeviceRequest(ctx, pool, deviceID, checkin, testSecretCodec); err != nil {
		t.Fatalf("checkin acceptance: %v", err)
	}

	// ...replayed against GET /device/policy with the SAME captured nonce and
	// body-hash headers: the URI/method cells change the challenge, and the
	// nonce is already spent anyway — must be rejected either way.
	cross := signedProofRequest("GET", "/device/policy?device_id=x", secret, deviceID, ts, "nonce-bind-2", "")
	cross.Header.Set("X-Device-Nonce", nonce) // captured nonce, different endpoint
	if err := VerifyDeviceRequest(ctx, pool, deviceID, cross, testSecretCodec); err == nil {
		t.Fatal("captured proof replayed against the second endpoint must be rejected")
	}

	// A differently-shaped body (different hash cell) with the same captured
	// nonce fails too: the body hash is inside the HMAC.
	bodySwap := signedProofRequest("POST", "/device/checkin", secret, deviceID, ts, "nonce-bind-3", `{"tampered":true}`)
	bodySwap.Header.Set("X-Device-Nonce", nonce)
	if err := VerifyDeviceRequest(ctx, pool, deviceID, bodySwap, testSecretCodec); err == nil {
		t.Fatal("proof with a different body hash under a spent nonce must be rejected")
	}
}

// TestCheckTimestampFresh_WindowIsExactlyMaxClockSkew pins the freshness
// window of the capture-replay closure (occ_62f8783b829eed710a62a702): a
// captured proof is acceptable only while |now − ts| ≤ MaxClockSkew (five
// minutes, both directions for clock drift) — one tick inside either bound is
// accepted, one tick outside either bound is rejected. This is the boundary
// that turns a correctly-signed HMAC into a short-lived proof.
func TestCheckTimestampFresh_WindowIsExactlyMaxClockSkew(t *testing.T) {
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name    string
		ts      time.Time
		wantErr bool
	}{
		{"fresh now", now, false},
		{"one tick inside past bound", now.Add(-MaxClockSkew + time.Second), false},
		{"one tick inside future bound", now.Add(MaxClockSkew - time.Second), false},
		{"exactly at past bound", now.Add(-MaxClockSkew), false},
		{"exactly at future bound", now.Add(MaxClockSkew), false},
		{"one tick past the past bound", now.Add(-MaxClockSkew - time.Second), true},
		{"one tick past the future bound", now.Add(MaxClockSkew + time.Second), true},
		{"far stale (the five-minute reuse window closed)", now.Add(-10 * time.Minute), true},
		{"zero time (far stale)", time.Time{}, true},
	}
	for _, tc := range cases {
		err := CheckTimestampFresh(tc.ts.UTC().Format(time.RFC3339), now)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: CheckTimestampFresh = %v, wantErr %v", tc.name, err, tc.wantErr)
		}
	}
	// Missing / unparseable values fail closed with the same sentinel.
	if err := CheckTimestampFresh("", now); err == nil {
		t.Error("empty timestamp accepted")
	}
	if err := CheckTimestampFresh("not-a-timestamp", now); err == nil {
		t.Error("unparseable timestamp accepted")
	}
}

// TestVerifyDeviceRequest_WindowExpiredProofIsDead is the DB-backed leg of the
// five-minute reuse window: a proof captured outside MaxClockSkew — even one
// whose nonce was NEVER claimed — is rejected outright, and the rejection
// fires before the nonce claim, so an expired-window capture does not even
// spend the replay budget. Together with the single-use nonce
// (TestVerifyDeviceRequest_AcceptsOnceThenRejectsReplay) and the
// method/URI/body binding cells this closes the "reusable across requests and
// operations for five minutes" finding: a proof is valid for exactly one
// request shape, exactly once, within MaxClockSkew.
func TestVerifyDeviceRequest_WindowExpiredProofIsDead(t *testing.T) {
	pool, deviceID, secret := openNonceFixture(t, "stale")
	ctx := context.Background()

	staleTS := time.Now().Add(-(MaxClockSkew + time.Minute)).UTC().Format(time.RFC3339)
	dead := signedProofRequest("POST", "/device/checkin", secret, deviceID, staleTS, "nonce-stale-dead", "")
	if err := VerifyDeviceRequest(ctx, pool, deviceID, dead, testSecretCodec); err == nil {
		t.Fatal("proof outside the freshness window accepted")
	} else if !strings.Contains(err.Error(), "stale") {
		t.Fatalf("error = %v, want the stale-timestamp rejection", err)
	}

	var claims int
	if err := pool.QueryRow(ctx,
		`SELECT count(*)::int FROM device_auth_nonces WHERE device_id = $1 AND nonce = 'nonce-stale-dead'`,
		deviceID).Scan(&claims); err != nil {
		t.Fatalf("count nonce claims: %v", err)
	}
	if claims != 0 {
		t.Fatalf("expired-window proof spent the nonce claim (%d), want 0 (rejected before the claim)", claims)
	}
}

// TestVerifyDeviceRequest_ConcurrentReplayExactlyOneAccept is the deployment-
// wide double-spend proof (row acceptance test): two SEPARATE verifier
// instances (distinct pools, as on two replicas sharing the database) process
// ONE captured proof simultaneously behind a start barrier. Exactly one of
// them accepts; the other loses the atomic nonce claim. The winner is
// scheduler-dependent; the count is not.
func TestVerifyDeviceRequest_ConcurrentReplayExactlyOneAccept(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set — skipping DB-backed concurrent replay test")
	}
	pool, deviceID, secret := openNonceFixture(t, "race")
	replicaB, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("open second verifier pool: %v", err)
	}
	t.Cleanup(func() { replicaB.Close() })

	const rounds = 3 // fresh proof per round; the single-accept invariant holds per round
	for round := 0; round < rounds; round++ {
		ts := freshTS()
		nonce := fmt.Sprintf("nonce-race-%d-%d", time.Now().UnixNano(), round)
		mkProof := func() *http.Request {
			return signedProofRequest("POST", "/device/checkin", secret, deviceID, ts, nonce, "")
		}

		start := make(chan struct{})
		errs := make([]error, 2)
		var wg sync.WaitGroup
		wg.Add(2)
		for i, p := range []*pgxpool.Pool{pool, replicaB} {
			go func(i int, p *pgxpool.Pool) {
				defer wg.Done()
				<-start // barrier: both replicas fire the captured proof together
				errs[i] = VerifyDeviceRequest(context.Background(), p, deviceID, mkProof(), testSecretCodec)
			}(i, p)
		}
		close(start)
		wg.Wait()

		accepted := 0
		for i, err := range errs {
			switch {
			case err == nil:
				accepted++
			default:
				t.Logf("round %d replica %d rejected (expected for the loser): %v", round, i, err)
			}
		}
		if accepted != 1 {
			t.Fatalf("round %d: exactly one verifier replica must accept the captured proof, got %d accepted (%v / %v)",
				round, accepted, errs[0], errs[1])
		}

		var claims int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*)::int FROM device_auth_nonces WHERE device_id = $1 AND nonce = $2`,
			deviceID, nonce).Scan(&claims); err != nil {
			t.Fatalf("round %d: count claims: %v", round, err)
		}
		if claims != 1 {
			t.Fatalf("round %d: exactly one claim row may exist, got %d", round, claims)
		}
	}
}

// TestGetDeviceSecret_RevokedDeviceLosesTrustChannel: a revoked device's
// secret lookup fails (indistinguishable from unknown), and the revocation
// reducer has rotated the stored secret underneath it.
func TestGetDeviceSecret_RevokedDeviceLosesTrustChannel(t *testing.T) {
	pool, deviceID, secret := openNonceFixture(t, "revoked")
	ctx := context.Background()

	if _, err := GetDeviceSecret(ctx, pool, deviceID, testSecretCodec); err != nil {
		t.Fatalf("pre-revoke secret lookup: %v", err)
	}

	// Revoke through the lifecycle reducer (unenrolled -> enrolled -> revoked),
	// with the device's owner as the actor (devices.enrolled_by has an FK to
	// users, so the actor must be a real user id).
	var ownerID int64
	if err := pool.QueryRow(ctx,
		`SELECT user_id FROM devices WHERE id = $1`, deviceID).Scan(&ownerID); err != nil {
		t.Fatalf("load device owner: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT device_enroll_transition($1, $2, 'enrolled', 'test')`,
		ownerID, deviceID); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT device_enroll_transition($1, $2, 'revoked', 'test')`,
		ownerID, deviceID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if _, err := GetDeviceSecret(ctx, pool, deviceID, testSecretCodec); err == nil {
		t.Fatal("revoked device secret lookup must fail (trust channel ends)")
	}

	// The revocation reducer also rotated the stored secret: the old value is
	// gone from the row even directly in the database.
	var stored string
	if err := pool.QueryRow(ctx,
		`SELECT hmac_secret FROM devices WHERE id = $1`, deviceID).Scan(&stored); err != nil {
		t.Fatalf("read stored secret: %v", err)
	}
	if stored == secret {
		t.Fatal("revocation must rotate the stored hmac_secret away from the issued value")
	}

	// And the rotated secret proves nothing either — the filter rejects before
	// the HMAC is even consulted.
	proof := signedProofRequest("POST", "/device/checkin", stored, deviceID, freshTS(), "nonce-revoked-1", "")
	if err := VerifyDeviceRequest(ctx, pool, deviceID, proof, testSecretCodec); err == nil {
		t.Fatal("a revoked device must fail verification even with the rotated secret")
	}
}
