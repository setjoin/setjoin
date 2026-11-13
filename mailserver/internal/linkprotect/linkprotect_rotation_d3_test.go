package linkprotect

// MAILSERVERD-004 (owner decision D3): dual-key overlap rotation for
// link-protect tokens. Tokens live 30 days in delivered mail, so a key
// rotation must NOT orphan them: during the transition window the retiring
// key keeps VERIFYING while the current key alone SIGNS; draining the
// retiring key ends the window and old-key tokens are rejected again.
//
// These tests pin the three contract arms — transition acceptance, post-drain
// rejection, current-version-only signing — plus the version-1 compatibility
// rails the rotation leans on (the version-1 derivation label is
// byte-identical to the historical key, so pre-rotation tokens never
// re-sign).

import (
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Rotation fixtures, deliberately distinct from testSecret (the version-1
// default fixture) so every assertion proves key/version independence rather
// than accidentally reusing the default derivation.
var (
	rotOldSecret = []byte("rotation-retiring-secret-32-bytes!!")
	rotNewSecret = []byte("rotation-current-secret-32-bytes!!")
)

// rotTransition is the mid-rotation key set: new secret bumped to version 2,
// retiring secret still configured for verification.
func rotTransition() TokenKeys {
	return TokenKeys{Secret: rotNewSecret, Version: 2, PreviousSecret: rotOldSecret}
}

// rotDrained is the post-transition key set: the retiring secret has been
// dropped and only the current key verifies.
func rotDrained() TokenKeys {
	return TokenKeys{Secret: rotNewSecret, Version: 2}
}

func rotClaims(url string) TokenClaims {
	return TokenClaims{
		URL:       url,
		MessageID: "msg-rotation",
		MailboxID: 7,
		ExpiresAt: time.Now().Add(tokenExpiry).Unix(),
	}
}

func rotSign(claims TokenClaims, keys TokenKeys) string {
	t, err := SignTokenN(claims, keys)
	if err != nil {
		panic("SignTokenN: " + err.Error())
	}
	return t
}

// TestTokenKeyN_Version1MatchesLegacy pins the rotation compatibility rail
// the linkprotect.go contract names: the version-1 derivation label renders
// byte-identically to the historical tokenKeyInfo label, so every token
// signed before any rotation keeps verifying under the version-1 key.
func TestTokenKeyN_Version1MatchesLegacy(t *testing.T) {
	if got := tokenKeyInfoN(tokenKeyVersion1); got != tokenKeyInfo {
		t.Fatalf("tokenKeyInfoN(1) = %q, want the historical label %q", got, tokenKeyInfo)
	}
	if !hmac.Equal(tokenKeyN(rotOldSecret, tokenKeyVersion1), tokenKey(rotOldSecret)) {
		t.Fatal("version-1 derivation must equal the historical tokenKey derivation")
	}

	// And end-to-end: a token signed through the version-1 shorthand verifies
	// through the historical single-key verify, unchanged.
	token := rotSign(rotClaims("https://example.com/legacy"), TokenKeys{Secret: rotOldSecret, Version: tokenKeyVersion1})
	claims, err := VerifyToken(token, rotOldSecret)
	if err != nil {
		t.Fatalf("pre-rotation token must keep verifying unchanged: %v", err)
	}
	if claims.URL != "https://example.com/legacy" {
		t.Fatalf("claims.URL = %q, want the signed destination", claims.URL)
	}
}

// TestTokenKeyN_VersionsAndSecretsDeriveDistinctKeys pins the derivation
// discipline the overlap safety rests on: distinct versions of the SAME
// secret derive distinct keys (a version bump alone invalidates old
// signatures), and distinct secrets at the same version derive distinct keys.
func TestTokenKeyN_VersionsAndSecretsDeriveDistinctKeys(t *testing.T) {
	if hmac.Equal(tokenKeyN(rotNewSecret, 1), tokenKeyN(rotNewSecret, 2)) {
		t.Fatal("same secret at versions 1 and 2 must derive different keys")
	}
	if hmac.Equal(tokenKeyN(rotOldSecret, 2), tokenKeyN(rotNewSecret, 2)) {
		t.Fatal("different secrets at the same version must derive different keys")
	}
	if hmac.Equal(tokenKeyN(rotOldSecret, 1), tokenKeyN(rotNewSecret, 2)) {
		t.Fatal("old-secret/v1 and new-secret/v2 must derive different keys")
	}
}

// TestVerifyTokenN_DualKeyOverlapDuringTransition pins the TRANSITION arm of
// MAILSERVERD-004: with the rotation wired (new secret at version 2, retiring
// secret still configured), BOTH generations verify — tokens already
// delivered under the old key keep resolving for their 30-day lifetime, and
// freshly minted tokens verify under the current key.
func TestVerifyTokenN_DualKeyOverlapDuringTransition(t *testing.T) {
	// Pre-rotation token: signed under the retiring secret at version 1 —
	// exactly the shape already sitting in live mail.
	oldToken := rotSign(rotClaims("https://example.com/old-key"),
		TokenKeys{Secret: rotOldSecret, Version: 1})
	// Post-rotation token: signed under the current secret at version 2.
	newToken := rotSign(rotClaims("https://example.com/new-key"), rotTransition())

	transition := rotTransition()

	claims, err := VerifyTokenN(oldToken, transition)
	if err != nil {
		t.Fatalf("old-key token must verify during the transition window: %v", err)
	}
	if claims.URL != "https://example.com/old-key" {
		t.Fatalf("old-key claims.URL = %q, want the signed destination", claims.URL)
	}

	claims, err = VerifyTokenN(newToken, transition)
	if err != nil {
		t.Fatalf("current-key token must verify during the transition window: %v", err)
	}
	if claims.URL != "https://example.com/new-key" {
		t.Fatalf("new-key claims.URL = %q, want the signed destination", claims.URL)
	}
}

// TestVerifyTokenN_PostDrainRejectsOldKeyTokens pins the DRAIN arm: once the
// retiring secret is dropped from the key set, old-key tokens are rejected
// again (signature mismatch), while tokens minted under the current key keep
// verifying — draining cannot strand anything signed after the bump.
func TestVerifyTokenN_PostDrainRejectsOldKeyTokens(t *testing.T) {
	oldToken := rotSign(rotClaims("https://example.com/old-key"),
		TokenKeys{Secret: rotOldSecret, Version: 1})
	newToken := rotSign(rotClaims("https://example.com/new-key"), rotTransition())

	drained := rotDrained()

	if _, err := VerifyTokenN(oldToken, drained); !errors.Is(err, errTokenSignatureMismatch) {
		t.Fatalf("old-key token must be rejected after drain with a signature mismatch, got %v", err)
	}
	if _, err := VerifyTokenN(newToken, drained); err != nil {
		t.Fatalf("current-key token must keep verifying after drain: %v", err)
	}
}

// TestSignTokenN_SignsCurrentVersionOnly pins the SIGN arm: a token minted
// under the transition key set is signed by the CURRENT secret at the CURRENT
// version and by nothing else — so it (a) survives draining (the overlap key
// is never needed to verify fresh tokens), (b) is not verifiable by the
// retiring secret, and (c) is not verifiable under the old derivation label,
// proving the version actually moved.
func TestSignTokenN_SignsCurrentVersionOnly(t *testing.T) {
	token := rotSign(rotClaims("https://example.com/fresh"), rotTransition())

	// (a) Draining immediately after minting leaves the fresh token valid.
	if _, err := VerifyTokenN(token, rotDrained()); err != nil {
		t.Fatalf("freshly minted token must verify with the overlap key drained: %v", err)
	}

	// (b) The retiring secret never signs: a key set holding ONLY the old
	// secret (at any version) cannot verify the fresh token.
	for _, v := range []int{1, 2} {
		if _, err := VerifyTokenN(token, TokenKeys{Secret: rotOldSecret, Version: v}); !errors.Is(err, errTokenSignatureMismatch) {
			t.Fatalf("fresh token must not verify under the retiring secret (v%d), got %v", v, err)
		}
	}

	// (c) The current secret under the OLD label version must not verify it
	// either: the version participates in the derivation, so signing really
	// moved to version 2.
	if _, err := VerifyTokenN(token, TokenKeys{Secret: rotNewSecret, Version: 1}); !errors.Is(err, errTokenSignatureMismatch) {
		t.Fatalf("fresh token must not verify under the version-1 derivation, got %v", err)
	}

	// And the version-2 signature is byte-distinguishable from the version-1
	// signature of the same payload.
	v1Token := rotSign(rotClaims("https://example.com/fresh"), TokenKeys{Secret: rotNewSecret, Version: 1})
	if token == v1Token {
		t.Fatal("version-2 and version-1 signatures of the same claims must differ")
	}
}

// TestVerifyToken_ShorthandEquivalenceWithVersion1KeySet pins the
// compatibility shorthands: SignToken/VerifyToken are exactly the version-1
// key set of the N-forms, and a zero-valued TokenKeys normalizes to the
// version-1 derivation of its (nil) secret — which verifies nothing signed
// under a real secret.
func TestVerifyToken_ShorthandEquivalenceWithVersion1KeySet(t *testing.T) {
	token := rotSign(rotClaims("https://example.com/shorthand"),
		TokenKeys{Secret: rotOldSecret, Version: tokenKeyVersion1})

	// N-form at version 1 with the same secret == the single-key shorthand.
	if _, err := VerifyTokenN(token, TokenKeys{Secret: rotOldSecret}); err != nil {
		t.Fatalf("VerifyTokenN at the version-1 default must equal VerifyToken: %v", err)
	}
	if _, err := VerifyToken(token, rotOldSecret); err != nil {
		t.Fatalf("version-1 shorthand verify failed: %v", err)
	}

	// A zero-valued key set verifies nothing real: normalization clamps the
	// version but cannot conjure a secret.
	if _, err := VerifyTokenN(token, TokenKeys{}); !errors.Is(err, errTokenSignatureMismatch) {
		t.Fatalf("zero-valued key set must not verify a real token, got %v", err)
	}
}

// TestVerifyTokenN_KeyIndependentFailuresShortCircuit pins the fall-through
// discipline: only a SIGNATURE MISMATCH under the current key may fall
// through to the overlap key. Expired claims, malformed formats, and invalid
// signature encodings surface immediately; and an old-key token whose claims
// have expired is never resurrected by the overlap window.
func TestVerifyTokenN_KeyIndependentFailuresShortCircuit(t *testing.T) {
	// Expired old-key token: the overlap key WOULD match its signature, but
	// expiry is key-independent and must still refuse it.
	expired := rotClaims("https://example.com/expired")
	expired.ExpiresAt = time.Now().Add(-time.Minute).Unix()
	expiredOldToken := rotSign(expired, TokenKeys{Secret: rotOldSecret, Version: 1})
	if _, err := VerifyTokenN(expiredOldToken, rotTransition()); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired old-key token must fail on expiry during the window, got %v", err)
	}
	// After the drain the same old-key token is refused even EARLIER — its
	// signature matches no configured key, so it is a mismatch, not an expiry.
	if _, err := VerifyTokenN(expiredOldToken, rotDrained()); !errors.Is(err, errTokenSignatureMismatch) {
		t.Fatalf("expired old-key token after drain must be a signature mismatch, got %v", err)
	}

	// Expiry is equally key-independent for the CURRENT key: an expired
	// current-key token still fails on expiry after drain.
	expiredNewToken := rotSign(expired, rotTransition())
	if _, err := VerifyTokenN(expiredNewToken, rotDrained()); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired current-key token must fail on expiry after drain, got %v", err)
	}

	// Malformed format: no separator is key-independent — no key can match.
	if _, err := VerifyTokenN("not-a-token", rotTransition()); err == nil || !strings.Contains(err.Error(), "invalid token format") {
		t.Fatalf("malformed token must fail with a format error, got %v", err)
	}

	// Invalid signature ENCODING on an otherwise real token: flip the payload
	// separator token into a non-base64 signature, key-independent failure.
	good := rotSign(rotClaims("https://example.com/ok"), rotTransition())
	badSig := good[:strings.LastIndex(good, ".")+1] + "!!not-base64!!"
	if _, err := VerifyTokenN(badSig, rotTransition()); err == nil || !strings.Contains(err.Error(), "invalid signature encoding") {
		t.Fatalf("invalid signature encoding must surface immediately, got %v", err)
	}

	// A tampered payload under the transition set tries both keys and still
	// refuses with a signature mismatch: flip one byte of the decoded claims
	// and keep the (now stale) signature.
	payloadB64, sigB64, ok := strings.Cut(good, ".")
	if !ok {
		t.Fatalf("fixture token %q has no separator", good)
	}
	payload, perr := base64.URLEncoding.DecodeString(payloadB64)
	if perr != nil {
		t.Fatalf("decode fixture payload: %v", perr)
	}
	payload[0] ^= 0x01
	tampered := base64.URLEncoding.EncodeToString(payload) + "." + sigB64
	if _, err := VerifyTokenN(tampered, rotTransition()); !errors.Is(err, errTokenSignatureMismatch) {
		t.Fatalf("tampered token must be refused with a signature mismatch, got %v", err)
	}
}

// TestLinkProtectHandler_TokenKeyRotationArms walks the click handler through
// the full rotation lifecycle. With a nil pool every VERIFIED token fails the
// audit step and lands on the fail-closed warn page (200) — so 200 means "the
// token verified" and 400 means "token verification rejected it":
//   - unwired (constructor default): version-1 tokens verify, rotated tokens
//     do not — rotation is OFF until the keys are wired;
//   - transition (SetTokenKeys with PreviousSecret): both generations verify;
//   - drained (SetTokenKeys without PreviousSecret): old-key tokens are
//     rejected, current-key tokens keep verifying.
func TestLinkProtectHandler_TokenKeyRotationArms(t *testing.T) {
	oldToken := rotSign(rotClaims("https://example.com/old-key"),
		TokenKeys{Secret: rotOldSecret, Version: 1})
	newToken := rotSign(rotClaims("https://example.com/new-key"), rotTransition())

	get := func(h *LinkProtectHandler, token string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/link-protect?token="+token, nil)
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	t.Run("unwired-default-verifies-only-version-1", func(t *testing.T) {
		h := NewLinkProtectHandler(nil, nil, testLogger(), nil, rotOldSecret)
		if code := get(h, oldToken); code != http.StatusOK {
			t.Fatalf("unwired handler must keep verifying version-1 tokens (200), got %d", code)
		}
		if code := get(h, newToken); code != http.StatusBadRequest {
			t.Fatalf("unwired handler must reject version-2 tokens (400), got %d", code)
		}
	})

	t.Run("transition-accepts-both-generations", func(t *testing.T) {
		h := NewLinkProtectHandler(nil, nil, testLogger(), nil, rotOldSecret)
		h.SetTokenKeys(rotTransition())
		if code := get(h, oldToken); code != http.StatusOK {
			t.Fatalf("transition handler must verify old-key tokens (200), got %d", code)
		}
		if code := get(h, newToken); code != http.StatusOK {
			t.Fatalf("transition handler must verify current-key tokens (200), got %d", code)
		}
	})

	t.Run("drained-rejects-old-key-tokens", func(t *testing.T) {
		h := NewLinkProtectHandler(nil, nil, testLogger(), nil, rotOldSecret)
		h.SetTokenKeys(rotDrained())
		if code := get(h, oldToken); code != http.StatusBadRequest {
			t.Fatalf("drained handler must reject old-key tokens (400), got %d", code)
		}
		if code := get(h, newToken); code != http.StatusOK {
			t.Fatalf("drained handler must keep verifying current-key tokens (200), got %d", code)
		}
	})
}

// rotPlainMessage wraps a text/plain body in the minimal RFC 5322 framing the
// delivery-path rewrite/unwrap pair parses.
func rotPlainMessage(body string) []byte {
	return []byte("From: sender@example.com\r\n" +
		"To: rcpt@example.com\r\n" +
		"Subject: rotation delivery path\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" + body)
}

// rotFirstToken extracts the token of the FIRST /link-protect redirect in a
// rewritten delivery body.
func rotFirstToken(t *testing.T, body []byte) string {
	t.Helper()
	sub := protectedURLRegex.FindStringSubmatch(string(body))
	if sub == nil {
		t.Fatalf("rewritten body carries no /link-protect redirect:\n%s", body)
	}
	return sub[1]
}

// TestRewriteMessageBodyN_MintsCurrentVersionToken pins the DELIVERY-PATH
// sign arm of MAILSERVERD-004 (the Astra HOLD gap): a body rewritten by the
// LIVE seam (RewriteMessageBodyN with the configured key set) mints tokens
// under the CURRENT key version — NOT the version-1 shorthand. After the
// handler is wired for {new/v2, old/v1}, a newly delivered token must match
// the current key (and survive a drain), and match neither key only if the
// threading were broken.
func TestRewriteMessageBodyN_MintsCurrentVersionToken(t *testing.T) {
	rewritten, n, err := RewriteMessageBodyN(
		rotPlainMessage("see https://example.com/delivered-after-rotation now"),
		rotTransition(), nil, "msg-d1", 7)
	if err != nil {
		t.Fatalf("RewriteMessageBodyN: %v", err)
	}
	if n != 1 {
		t.Fatalf("rewrite count = %d, want 1", n)
	}
	token := rotFirstToken(t, rewritten)

	// The minted token verifies under the CURRENT key set...
	if _, err := VerifyTokenN(token, rotTransition()); err != nil {
		t.Fatalf("delivered token must verify under the transition key set: %v", err)
	}
	// ...survives draining the overlap window...
	if _, err := VerifyTokenN(token, rotDrained()); err != nil {
		t.Fatalf("delivered token must verify after the window drains: %v", err)
	}
	// ...and is NOT a version-1 token: the pre-fix path (SignToken shorthand)
	// minted new/v1 tokens, which after wiring {new/v2, old/v1} matched
	// NEITHER key. The version must actually be threaded through the rewrite.
	if _, err := VerifyTokenN(token, TokenKeys{Secret: rotNewSecret, Version: tokenKeyVersion1}); !errors.Is(err, errTokenSignatureMismatch) {
		t.Fatalf("delivered token must NOT verify under the version-1 derivation of the new secret, got %v", err)
	}
	if _, err := VerifyToken(token, rotNewSecret); !errors.Is(err, errTokenSignatureMismatch) {
		t.Fatalf("delivered token must not verify through the v1 shorthand of the new secret, got %v", err)
	}
}

// TestUnwrapMessageBodyN_RotationDeliveryLifecycle walks the delivery-path
// round trip across a rotation: a body rewritten BEFORE the rotation (v1
// tokens, the shape sitting in live mail) still un-rewrites on egress during
// the overlap window, stops un-rewriting once drained, and a body rewritten
// AFTER the rotation keeps un-rewriting even with the window drained.
func TestUnwrapMessageBodyN_RotationDeliveryLifecycle(t *testing.T) {
	// Pre-rotation delivery: the version-1 shorthand is exactly what the
	// pre-rotation rewriter minted.
	oldMsg, n, err := RewriteMessageBodyN(
		rotPlainMessage("old https://example.com/old-key link"),
		TokenKeys{Secret: rotOldSecret, Version: tokenKeyVersion1}, nil, "msg-d2", 7)
	if err != nil || n != 1 {
		t.Fatalf("pre-rotation rewrite: n=%d err=%v", n, err)
	}

	// Mid-rotation egress: the retiring key still verifies, so the forwarded
	// copy un-rewrites cleanly.
	unwrapped, n, err := UnwrapMessageBodyN(oldMsg, rotTransition())
	if err != nil {
		t.Fatalf("transition unwrap: %v", err)
	}
	if n != 1 || !strings.Contains(string(unwrapped), "https://example.com/old-key") || strings.Contains(string(unwrapped), "/link-protect?token=") {
		t.Fatalf("transition unwrap must restore the original URL (n=%d):\n%s", n, unwrapped)
	}

	// Post-drain egress: the retiring key no longer verifies, so the old
	// redirect is left in place (inert) — the body ships byte-exact.
	drainedOut, n, err := UnwrapMessageBodyN(oldMsg, rotDrained())
	if err != nil {
		t.Fatalf("drained unwrap: %v", err)
	}
	if n != 0 || string(drainedOut) != string(oldMsg) {
		t.Fatalf("drained unwrap must leave the old-key redirect untouched (n=%d)", n)
	}

	// Post-rotation delivery + drained egress: tokens minted under the CURRENT
	// key keep un-rewriting with the window already closed — a fresh token can
	// never be stranded by the drain.
	newMsg, n, err := RewriteMessageBodyN(
		rotPlainMessage("new https://example.com/new-key link"),
		rotTransition(), nil, "msg-d3", 7)
	if err != nil || n != 1 {
		t.Fatalf("post-rotation rewrite: n=%d err=%v", n, err)
	}
	unwrapped, n, err = UnwrapMessageBodyN(newMsg, rotDrained())
	if err != nil {
		t.Fatalf("drained unwrap of post-rotation delivery: %v", err)
	}
	if n != 1 || !strings.Contains(string(unwrapped), "https://example.com/new-key") {
		t.Fatalf("drained unwrap must restore the current-key URL (n=%d):\n%s", n, unwrapped)
	}
}
