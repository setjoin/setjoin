package handlers

// possession_matrix_test.go — possession fix round 8: the §4 acceptance
// matrix scenarios the fix7 receipt named as still absent, written at
// handler level against the REAL handlers (scheme v7 references):
//
//   - TestTOTPReplaceEndToEndWithGrant (§4.4 case 1): TOTP-authorized
//     replacement end-to-end — the active factor is never the staged secret
//     between setup and confirm.
//   - TestRepeatedSetupDistinctEnrollmentIDs (§4.4 case 2): stale-ID
//     refusals (each grant dies its own §1.7 death), same-JTI resume, and
//     the bound-grant/dead-target 409 — on separately fixtured grants.
//   - TestSurvivingRecoveryGrantUsableAfterFamilyRevocation (§4.4 case 6
//     Scenario B): a family-F₂ recovery grant SURVIVES a narrow family-F
//     revocation and remains USABLE (consumption completes).
//   - TestAllSessionRevocationThenFreshLoginManagesFactors (§4.2 case 8):
//     after revoke_user_sessions(scope='all') the old/missing-iat/boundary
//     tokens are refused by the durable watermark while FRESH logins — C1
//     proof issuance → grant → consumption, and the C3 bootstrap — all
//     complete, with the row retained for its 31-day life.
//   - TestMutationInventoryComplete (§4.2): the single inventory guard —
//     every §3 gated-mutation arm refuses WITHOUT its grant, and the
//     inventory is pinned TWO ways: grant-touching handlers to the §3 list,
//     and — gate-INDEPENDENTLY (r9) — every mux route on the
//     factor/enrollment path to either a gated mutation (whose handler must
//     AST-prove it reaches the grant store) or an explicitly-exempt arm, so
//     a future ungated mutation is discovered by its ROUTE even when it
//     never touches a grant API.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/jwtutil"
)

// --- shared matrix helpers ---

// matrixSetup drives the GET setup arm with the grant token in the header
// (the transport a real GET uses).
func matrixSetup(t *testing.T, h *AuthHandler, claims *token.Claims, grantToken string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/auth/totp/setup", nil)
	if grantToken != "" {
		req.Header.Set(ReauthTokenHeader, grantToken)
	}
	req = req.WithContext(ContextWithUser(req.Context(), claims))
	rr := httptest.NewRecorder()
	h.TOTPSetup(rr, req)
	return rr
}

// matrixConfirm drives the POST confirm arm (token via header — both
// transports are accepted; the header is the parity transport).
func matrixConfirm(t *testing.T, h *AuthHandler, claims *token.Claims, code, grantToken, enrollmentID string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"code": code, "enrollment_id": enrollmentID})
	req := httptest.NewRequest(http.MethodPost, "/auth/totp/confirm", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	if grantToken != "" {
		req.Header.Set(ReauthTokenHeader, grantToken)
	}
	req = req.WithContext(ContextWithUser(req.Context(), claims))
	rr := httptest.NewRecorder()
	h.TOTPConfirm(rr, req)
	return rr
}

// matrixProof mints a fresh session-scope TOTP-proof grant through the real
// possession endpoint (public flows only) and returns the raw token.
func matrixProof(t *testing.T, h *AuthHandler, claims *token.Claims, operation string) string {
	t.Helper()
	code, err := totp.GenerateCode(removalTestSecret, time.Now())
	if err != nil {
		t.Fatalf("proof code: %v", err)
	}
	rr := postPossession(h, "/auth/mfa/possession/totp",
		map[string]any{"operation": operation, "code": code}, nil, claims)
	if rr.Code != http.StatusOK {
		t.Fatalf("possession proof (%s) status = %d body %s, want 200", operation, rr.Code, rr.Body.String())
	}
	var out struct {
		ReauthToken string `json:"reauth_token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || out.ReauthToken == "" {
		t.Fatalf("proof body %s carries no reauth_token (%v)", rr.Body.String(), err)
	}
	return out.ReauthToken
}

// resetReplayMarker clears last_totp_used_at so a SECOND proof inside the
// same 30-second RFC 6238 window is not rejected as a replay — the same
// fixture discipline the overlap tests use between consecutive proofs.
func resetReplayMarker(t *testing.T, h *AuthHandler, userID int64) {
	t.Helper()
	if _, err := h.pool.Exec(context.Background(),
		`UPDATE users SET last_totp_used_at = NULL WHERE id = $1`, userID,
	); err != nil {
		t.Fatalf("reset replay marker: %v", err)
	}
}

// activeTOTPSecret decrypts the user's ACTIVE totp_secret_enc (the staged
// pending secret lives in totp_pending_enrollments, never here — §1.6).
func activeTOTPSecret(t *testing.T, h *AuthHandler, userID int64) string {
	t.Helper()
	var secret string
	if err := h.pool.QueryRow(context.Background(),
		`SELECT pgp_sym_decrypt(totp_secret_enc::bytea, current_setting('app.encryption_key'))
		   FROM users WHERE id = $1`, userID,
	).Scan(&secret); err != nil {
		t.Fatalf("decrypt active secret: %v", err)
	}
	return secret
}

func totpEnabled(t *testing.T, h *AuthHandler, userID int64) bool {
	t.Helper()
	var enabled bool
	if err := h.pool.QueryRow(context.Background(),
		`SELECT COALESCE(totp_enabled, FALSE) FROM users WHERE id = $1`, userID,
	).Scan(&enabled); err != nil {
		t.Fatalf("read totp_enabled: %v", err)
	}
	return enabled
}

// --- §4.4 case 1 ---

// TestTOTPReplaceEndToEndWithGrant is §4.4 case 1: the TOTP-authorized
// replacement end-to-end through public flows. Between the setup (staged
// secret S₂, target bound) and the confirm, the ACTIVE factor stays S₁ —
// the staged secret is never installed early — and the confirm promotes in
// ONE commit: pending deleted, S₂ active, generation G→G+1, grant consumed.
func TestTOTPReplaceEndToEndWithGrant(t *testing.T) {
	h := newPossessionHarness(t)
	userID, claims := newPossessionUser(t, h, "replacee2e", true)
	seedEnabledTOTP(t, h, userID)
	G := readFactorGeneration(t, h, userID)

	// (a) a current S₁ code at the C1 proof arm mints the totp.replace grant
	// {target NULL, proof totp, bound generation G}.
	tok := matrixProof(t, h, claims, "totp.replace")
	var op string
	var target *string
	var proofMethod string
	var boundGen int64
	if err := h.pool.QueryRow(context.Background(),
		`SELECT operation, target_ref, proof_method, bound_factor_generation
		   FROM mfa_reauth_step_ups WHERE user_id = $1`, userID,
	).Scan(&op, &target, &proofMethod, &boundGen); err != nil {
		t.Fatalf("(a) grant row missing: %v", err)
	}
	if op != "totp.replace" || target != nil || proofMethod != "totp" || boundGen != G {
		t.Fatalf("(a) grant = {%q %v %q gen %d}, want {totp.replace <nil> totp gen %d}", op, target, proofMethod, boundGen, G)
	}

	// (b) setup peeks the grant, binds target E₁, stages secret S₂ — the
	// ACTIVE factor is STILL S₁ and enabled.
	sr := matrixSetup(t, h, claims, tok)
	if sr.Code != http.StatusOK {
		t.Fatalf("(b) setup status = %d body %s, want 200", sr.Code, sr.Body.String())
	}
	_, E1 := setupBody(t, sr)
	S2 := provisioningSecret(t, sr)
	if got := activeTOTPSecret(t, h, userID); got != removalTestSecret {
		t.Fatalf("(b) active secret changed at setup: %q, want the original S₁", got)
	}
	if !totpEnabled(t, h, userID) {
		t.Fatal("(b) active factor disabled at setup")
	}
	var pendingSecret string
	if err := h.pool.QueryRow(context.Background(),
		`SELECT pgp_sym_decrypt(secret_enc::bytea, current_setting('app.encryption_key'))
		   FROM totp_pending_enrollments WHERE id = $1 AND user_id = $2`, E1, userID,
	).Scan(&pendingSecret); err != nil || pendingSecret != S2 {
		t.Fatalf("(b) staged row = %q (%v), want the staged S₂ (active secret untouched)", pendingSecret, err)
	}

	// (c) confirm with an S₂ code: promotion + generation bump + grant
	// consumption + audit — one commit.
	code, err := totp.GenerateCode(S2, time.Now())
	if err != nil {
		t.Fatalf("(c) code: %v", err)
	}
	cr := matrixConfirm(t, h, claims, code, tok, E1)
	if cr.Code != http.StatusNoContent {
		t.Fatalf("(c) confirm status = %d body %s, want 204", cr.Code, cr.Body.String())
	}
	if got := activeTOTPSecret(t, h, userID); got != S2 {
		t.Fatal("(c) active secret is not the staged S₂ after confirm")
	}
	if got := readFactorGeneration(t, h, userID); got != G+1 {
		t.Fatalf("(c) factor_generation = %d, want %d (the replacement bump)", got, G+1)
	}
	if n := countGrantsFor(t, h, userID); n != 0 {
		t.Fatalf("(c) grant rows = %d after confirm, want 0 (consumed)", n)
	}
	var pending int
	if err := h.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM totp_pending_enrollments WHERE user_id = $1`, userID,
	).Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("(c) pending rows = %d (%v), want 0 (deleted in the promotion tx)", pending, err)
	}
	var audits int
	if err := h.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM admin_audit_log WHERE user_id = $1 AND action = 'totp_confirmed'`, userID,
	).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("(c) totp_confirmed audit rows = %d (%v), want 1", audits, err)
	}
}

// --- §4.4 case 2 ---

// TestRepeatedSetupDistinctEnrollmentIDs is §4.4 case 2 (r4-corrected):
// consistent refusal semantics on SEPARATELY-fixture'd grants — no sub-case
// reuses a grant after a §1.7 tuple-mismatch death.
func TestRepeatedSetupDistinctEnrollmentIDs(t *testing.T) {
	h := newPossessionHarness(t)
	userID, claims := newPossessionUser(t, h, "repeatsetup", true)
	seedEnabledTOTP(t, h, userID)

	// (a) stale-ID refusals: G₂ → E₁ abandoned; proof → G₃; setup → E₂.
	// Confirm {E₁ + G₃} refuses on the peek's target mismatch and G₃ dies
	// its §1.7 death (committed). The re-inserted G₂-shaped row bound to the
	// dead E₁ then refuses at the staged-row read — and that §1.7 cleanup
	// COMMITS (r8): the burned grant stays dead for the next attempt.
	tok2 := matrixProof(t, h, claims, "totp.replace")
	sr2 := matrixSetup(t, h, claims, tok2)
	if sr2.Code != http.StatusOK {
		t.Fatalf("(a) setup(G2) status = %d body %s, want 200", sr2.Code, sr2.Body.String())
	}
	_, E1 := setupBody(t, sr2)

	resetReplayMarker(t, h, userID)
	tok3 := matrixProof(t, h, claims, "totp.replace") // issuance deletes G2's row
	if n := countGrantsFor(t, h, userID); n != 1 {
		t.Fatalf("(a) grant rows after the second proof = %d, want 1 (issuance deletes the prior grant)", n)
	}
	sr3 := matrixSetup(t, h, claims, tok3)
	if sr3.Code != http.StatusOK {
		t.Fatalf("(a) setup(G3) status = %d body %s, want 200", sr3.Code, sr3.Body.String())
	}
	_, E2 := setupBody(t, sr3)
	if E2 == E1 {
		t.Fatal("(a) the second setup reused the abandoned enrollment ID — one pending row per user must mint a NEW uuid")
	}

	cr1 := matrixConfirm(t, h, claims, "000000", tok3, E1)
	if cr1.Code != http.StatusForbidden {
		t.Fatalf("(a) confirm {E1 + G3} status = %d body %s, want 403", cr1.Code, cr1.Body.String())
	}
	if n := countGrantsFor(t, h, userID); n != 0 {
		t.Fatalf("(a) G3 survived the target-mismatch refusal: %d rows, want 0 (§1.7)", n)
	}
	if got := activeTOTPSecret(t, h, userID); got != removalTestSecret || !totpEnabled(t, h, userID) {
		t.Fatal("(a) the refusal disturbed the active factor")
	}
	// Bounded fixture: re-insert a G2-shaped row bound to the dead E₁,
	// bypassing issuance's delete convention.
	tokX := seedSessionGrant(t, h, userID, claims.JTI, "totp.replace", &E1, "totp", nil)
	cr2 := matrixConfirm(t, h, claims, "000000", tokX, E1)
	if cr2.Code != http.StatusForbidden {
		t.Fatalf("(a) confirm {E1 + re-inserted row} status = %d body %s, want 403 (pending id E1 no longer resolves)", cr2.Code, cr2.Body.String())
	}
	if n := countGrantsFor(t, h, userID); n != 0 {
		t.Fatalf("(a) the staged-row mismatch cleanup did not commit: %d grant row(s) survive", n)
	}
	var liveE2 int
	if err := h.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM totp_pending_enrollments
		  WHERE user_id = $1 AND id = $2 AND expires_at > now()`, userID, E2,
	).Scan(&liveE2); err != nil || liveE2 != 1 {
		t.Fatalf("(a) E2 still live = %d (%v), want 1", liveE2, err)
	}

	// (b) same-JTI resume on a fresh grant G₄: retrying setup returns E₃'s
	// provisioning URI unchanged, no new rows, binding untouched.
	resetReplayMarker(t, h, userID)
	tok4 := matrixProof(t, h, claims, "totp.replace")
	sr4 := matrixSetup(t, h, claims, tok4)
	if sr4.Code != http.StatusOK {
		t.Fatalf("(b) setup(G4) status = %d body %s, want 200", sr4.Code, sr4.Body.String())
	}
	uri3, E3 := setupBody(t, sr4)
	sr4b := matrixSetup(t, h, claims, tok4)
	if sr4b.Code != http.StatusOK {
		t.Fatalf("(b) resume setup status = %d body %s, want 200", sr4b.Code, sr4b.Body.String())
	}
	uri3b, E3b := setupBody(t, sr4b)
	if E3b != E3 || uri3b != uri3 {
		t.Fatalf("(b) resume returned {E %q uri equal %v}, want the SAME E₃/URI (no second secret)", E3b, uri3b == uri3)
	}
	var pendingRows, grantRows int
	if err := h.pool.QueryRow(context.Background(),
		`SELECT (SELECT count(*) FROM totp_pending_enrollments WHERE user_id = $1),
		        (SELECT count(*) FROM mfa_reauth_step_ups WHERE user_id = $1)`, userID,
	).Scan(&pendingRows, &grantRows); err != nil || pendingRows != 1 || grantRows != 1 {
		t.Fatalf("(b) rows after resume = {pending %d, grants %d} (%v), want {1, 1, binding untouched}", pendingRows, grantRows, err)
	}

	// (c) bound grant with a dead target on a fresh grant G₅: setup again →
	// typed 409 proof_already_bound (not resumable).
	resetReplayMarker(t, h, userID)
	tok5 := matrixProof(t, h, claims, "totp.replace")
	sr5 := matrixSetup(t, h, claims, tok5)
	if sr5.Code != http.StatusOK {
		t.Fatalf("(c) setup(G5) status = %d body %s, want 200", sr5.Code, sr5.Body.String())
	}
	if _, err := h.pool.Exec(context.Background(),
		`UPDATE totp_pending_enrollments SET expires_at = now() - interval '1 second' WHERE user_id = $1`, userID,
	); err != nil {
		t.Fatalf("(c) expire staged row: %v", err)
	}
	sr5b := matrixSetup(t, h, claims, tok5)
	if sr5b.Code != http.StatusConflict {
		t.Fatalf("(c) setup over a dead target status = %d body %s, want 409 proof_already_bound", sr5b.Code, sr5b.Body.String())
	}
	if !strings.Contains(sr5b.Body.String(), "proof_already_bound") {
		t.Fatalf("(c) refusal body %s does not name proof_already_bound", sr5b.Body.String())
	}
}

// --- §4.4 case 6 Scenario B ---

// TestSurvivingRecoveryGrantUsableAfterFamilyRevocation is §4.4 case 6
// Scenario B on its own fixture (no registration generation trap): a
// family-F₂ recovery grant survives a narrow family-F revocation AND
// consumes normally — survival is USABILITY, not mere presence.
func TestSurvivingRecoveryGrantUsableAfterFamilyRevocation(t *testing.T) {
	h := newPossessionHarness(t)
	userID, _ := newPossessionUser(t, h, "scenb", true)
	seedEnabledTOTP(t, h, userID)
	G := readFactorGeneration(t, h, userID)

	// The surviving family-F₂ session: public-flow proof → recovery grant.
	claims2 := removalClaims(userID, "jti3-scenb")
	claims2.FamilyID = "F2"
	tokC := matrixProof(t, h, claims2, "recovery.regenerate")

	// The doomed family-F grant is a bounded direct INSERT: a public-flow
	// mint would delete tokC's row (issuance removes every prior grant).
	tokD := "fixture-family-f-grant-token"
	if _, err := h.pool.Exec(context.Background(),
		`INSERT INTO mfa_reauth_step_ups
		   (token_hash, user_id, session_jti, operation, target_ref,
		    proof_method, proving_factor_id, bound_factor_generation,
		    token_scope, refresh_family_id, expires_at)
		 VALUES ($1, $2, 'jti2-scenb-fixture', 'recovery.regenerate', NULL,
		         'totp', NULL,
		         (SELECT factor_generation FROM users WHERE id = $2),
		         'session', 'F', now() + interval '5 minutes')`,
		sha256SumHex(tokD), userID,
	); err != nil {
		t.Fatalf("seed family-F fixture grant: %v", err)
	}
	countByFamily := func(t *testing.T, family string) int {
		t.Helper()
		var n int
		var fam any
		if family == "" {
			fam = nil
		} else {
			fam = family
		}
		if err := h.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM mfa_reauth_step_ups WHERE user_id = $1 AND refresh_family_id IS NOT DISTINCT FROM $2`, userID, fam,
		).Scan(&n); err != nil {
			t.Fatalf("count family grants: %v", err)
		}
		return n
	}
	if got := countByFamily(t, "F"); got != 1 {
		t.Fatalf("(a) family-F rows = %d, want 1 (the doomed fixture)", got)
	}
	if got := countByFamily(t, "F2"); got != 1 {
		t.Fatalf("(a) family-F2 rows = %d, want 1 (the surviving grant)", got)
	}

	// Narrow family-F revocation: exactly its own rows die.
	var revoked int64
	if err := h.pool.QueryRow(context.Background(),
		`SELECT revoke_user_sessions($1, 'family', 'possession-matrix-scenb', NULL, NULL, 'F')`, userID,
	).Scan(&revoked); err != nil {
		t.Fatalf("revoke family F: %v", err)
	}
	if got := countByFamily(t, "F"); got != 0 {
		t.Fatalf("(b) family-F rows after the revocation = %d, want 0", got)
	}
	if got := countByFamily(t, "F2"); got != 1 {
		t.Fatalf("(b) family-F2 rows after the revocation = %d, want 1 (the narrow predicate does not widen)", got)
	}

	// (c) the F₂ bearer consumes the surviving grant: 200, generation bump
	// at consumption, grant gone.
	gr := httptest.NewRequest(http.MethodPost, "/auth/backup-codes/generate", strings.NewReader(`{}`))
	gr.Header.Set("Content-Type", "application/json")
	gr.Header.Set(ReauthTokenHeader, tokC)
	gr = gr.WithContext(ContextWithUser(gr.Context(), claims2))
	rr := httptest.NewRecorder()
	h.GenerateBackupCodes(rr, gr)
	if rr.Code != http.StatusOK {
		t.Fatalf("(c) consumption status = %d body %s, want 200 (survival is USABILITY)", rr.Code, rr.Body.String())
	}
	if got := readFactorGeneration(t, h, userID); got != G+1 {
		t.Fatalf("(c) factor_generation = %d, want %d (the §1.8 bump at consumption)", got, G+1)
	}
	if n := countGrantsFor(t, h, userID); n != 0 {
		t.Fatalf("(c) grant rows after consumption = %d, want 0", n)
	}
	// Contrast: the revoked family's bearer is refused by the durable
	// recheck even though its account holds live factors.
	claimsF := removalClaims(userID, "jti2-scenb-fixture")
	claimsF.FamilyID = "F"
	fr := postPossession(h, "/auth/mfa/possession/totp",
		map[string]any{"operation": "recovery.regenerate", "code": "000000"}, nil, claimsF)
	if fr.Code != http.StatusForbidden {
		t.Fatalf("revoked-family bearer proof status = %d body %s, want 403", fr.Code, fr.Body.String())
	}
}

// --- §4.2 case 8 ---

// revokeAllAndSettle runs revoke_user_sessions(scope='all') and waits past
// not_before's whole-second boundary: tokens carry second-precision iat and
// the watermark is boundary-INCLUSIVE — a token minted in the same second as
// the revocation is (correctly) still denied, so a genuinely fresh login
// must happen in a LATER second. Returns the row's not_before.
func revokeAllAndSettle(t *testing.T, h *AuthHandler, userID int64) time.Time {
	t.Helper()
	if _, err := h.pool.Exec(context.Background(),
		`SELECT revoke_user_sessions($1, 'all', 'possession-matrix-wm', NULL, NULL, NULL)`, userID,
	); err != nil {
		t.Fatalf("revoke all: %v", err)
	}
	var notBefore time.Time
	if err := h.pool.QueryRow(context.Background(),
		`SELECT not_before FROM session_revocations WHERE user_id = $1 AND scope = 'all'`, userID,
	).Scan(&notBefore); err != nil {
		t.Fatalf("read watermark row: %v", err)
	}
	// r11: normalize the PERSISTED watermark to whole seconds so the boundary
	// claim (iat == not_before, exact) discriminates `<=` from `<` — with
	// fractional seconds retained, a second-precision boundary iat only
	// exercises `<` and a production regression from `<=` to `<` would escape.
	notBefore = notBefore.Truncate(time.Second)
	if _, err := h.pool.Exec(context.Background(),
		`UPDATE session_revocations SET not_before = $2 WHERE user_id = $1 AND scope = 'all'`, userID, notBefore,
	); err != nil {
		t.Fatalf("normalize watermark: %v", err)
	}
	if d := time.Until(notBefore.Add(1100 * time.Millisecond)); d > 0 {
		time.Sleep(d)
	}
	return notBefore
}

// TestAllSessionRevocationThenFreshLoginManagesFactors is §4.2 case 8 at
// handler level: after revoke_user_sessions(scope='all') the retained
// watermark row refuses every token issued at-or-before it (and missing-iat
// tokens, fail-closed) for its full retention, while FRESH logins manage
// factors end-to-end — the C1 proof issuance → grant → consumption chain
// and the C3 bootstrap both complete.
//
// The negatives bind to LIVE grants (r9): each claimant holds its own
// separately-seeded, tuple-exact grant created after the revocation, so the
// §2.2 watermark recheck is the only thing that can refuse them — and each
// refusal is proven to PRESERVE those grants. An after-watermark control
// over the identical state consumes, pinning the refusals on the iat
// watermark alone.
func TestAllSessionRevocationThenFreshLoginManagesFactors(t *testing.T) {
	h := newPossessionHarness(t)

	// (a) C1 account with TOTP enabled; the OLD session's claims predate the
	// revocation and hold an unconsumed grant. The seeded grant is
	// family-NULL and the claims carry NO family — the refusals in (b) must
	// come from the WATERMARK, never from a tuple mismatch (which would
	// consume the grant per §1.7).
	userID, email, _ := seedC1UserWithPassword(t, h, "wmall", nil)
	seedEnabledTOTP(t, h, userID)
	claimsOld := removalClaims(userID, "jti1-wm")
	claimsOld.IssuedAt = jwtutil.NewNumericDate(time.Now().Add(-time.Minute))
	tokOld := seedSessionGrant(t, h, userID, claimsOld.JTI, "recovery.regenerate", nil, "totp", nil)
	if n := countGrantsFor(t, h, userID); n != 1 {
		t.Fatalf("(a) seeded grant rows = %d, want 1", n)
	}

	notBefore := revokeAllAndSettle(t, h, userID)
	// §2.5: the revocation itself deletes the user's outstanding grants —
	// the watermark is the second, iat-based line of defense for tokens
	// minted after the artifacts died.
	if n := countGrantsFor(t, h, userID); n != 0 {
		t.Fatalf("(a) the all-revocation left %d grant row(s), want 0 (artifact delete)", n)
	}

	consume := func(claims *token.Claims, tok string) *httptest.ResponseRecorder {
		gr := httptest.NewRequest(http.MethodPost, "/auth/backup-codes/generate", strings.NewReader(`{}`))
		gr.Header.Set("Content-Type", "application/json")
		gr.Header.Set(ReauthTokenHeader, tok)
		gr = gr.WithContext(ContextWithUser(gr.Context(), claims))
		rr := httptest.NewRecorder()
		h.GenerateBackupCodes(rr, gr)
		return rr
	}

	// (b) the watermark negatives must be refusable by the WATERMARK alone,
	// so each claimant gets its own separately-keyed, otherwise-valid grant
	// seeded AFTER the revocation: the §2.5 delete has already run, and every
	// tuple member matches its bearer exactly (jti, recovery.regenerate,
	// unbound target, session scope, NULL family, live generation) — the
	// grant gate CANNOT refuse these requests. (seedSessionGrant cannot seed
	// four siblings: issuance's one-live-row convention wipes the user's
	// other grants.) Each refusal is followed by a FRESH-transaction read
	// proving the refusal PRESERVES the live grants — the fenced tx rolls
	// back without a §1.7 mismatch death — so the 403s cannot be the
	// missing-row artifact the pre-r9 shape hid behind.
	claimsBoundary := removalClaims(userID, "jti1-wm-boundary")
	// iat == not_before EXACTLY (both whole-second after the normalization):
	// the production `<=` refuses this token; a regression to `<` would
	// ADMIT it exactly like claimsAfter — this case is the discriminator.
	claimsBoundary.IssuedAt = jwtutil.NewNumericDate(notBefore)
	claimsMissing := removalClaims(userID, "jti1-wm-missing") // no IssuedAt claim
	claimsAfter := removalClaims(userID, "jti1-wm-after")
	claimsAfter.IssuedAt = jwtutil.NewNumericDate(time.Now()) // strictly after not_before (the settle slept past the boundary)
	seedLiveGrant := func(claims *token.Claims) string {
		t.Helper()
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			t.Fatalf("grant entropy: %v", err)
		}
		tok := hexEncode(raw)
		if _, err := h.pool.Exec(context.Background(),
			`INSERT INTO mfa_reauth_step_ups
			   (token_hash, user_id, session_jti, operation, target_ref,
			    proof_method, proving_factor_id, bound_factor_generation,
			    token_scope, refresh_family_id, expires_at)
			 VALUES ($1, $2, $3, 'recovery.regenerate', NULL,
			         'totp', NULL,
			         (SELECT factor_generation FROM users WHERE id = $2),
			         'session', NULL, now() + interval '5 minutes')`,
			sha256SumHex(tok), userID, claims.JTI,
		); err != nil {
			t.Fatalf("seed live grant for %s: %v", claims.JTI, err)
		}
		return tok
	}
	tokOld = seedLiveGrant(claimsOld)
	tokBoundary := seedLiveGrant(claimsBoundary)
	tokMissing := seedLiveGrant(claimsMissing)
	tokAfter := seedLiveGrant(claimsAfter)
	if n := countGrantsFor(t, h, userID); n != 4 {
		t.Fatalf("(b) seeded live grants = %d, want 4 (one per claimant)", n)
	}

	if rr := consume(claimsOld, tokOld); rr.Code != http.StatusForbidden {
		t.Fatalf("(b) old-iat consumption status = %d body %s, want 403 (watermark)", rr.Code, rr.Body.String())
	}
	if n := countGrantsFor(t, h, userID); n != 4 {
		t.Fatalf("(b) the old-iat refusal disturbed the live grants: %d rows, want 4 (a watermark refusal rolls back — no §1.7 kill)", n)
	}
	if rr := consume(claimsBoundary, tokBoundary); rr.Code != http.StatusForbidden {
		t.Fatalf("(b) iat==not_before consumption status = %d body %s, want 403 (boundary inclusive)", rr.Code, rr.Body.String())
	}
	if n := countGrantsFor(t, h, userID); n != 4 {
		t.Fatalf("(b) the boundary-iat refusal disturbed the live grants: %d rows, want 4", n)
	}
	if rr := consume(claimsMissing, tokMissing); rr.Code != http.StatusForbidden {
		t.Fatalf("(b) missing-iat consumption status = %d body %s, want 403 (fail-closed)", rr.Code, rr.Body.String())
	}
	if n := countGrantsFor(t, h, userID); n != 4 {
		t.Fatalf("(b) the missing-iat refusal disturbed the live grants: %d rows, want 4", n)
	}

	// (b+) the bypass-demonstration control, over the IDENTICAL state: a
	// fourth claimant issued STRICTLY AFTER not_before, holding an
	// identically-seeded live grant, CONSUMES. The only discriminator
	// between this arm and the three refusals is iat vs the watermark — a
	// bypassed durable recheck would answer 200 for ALL four (the fault
	// injection in the fix receipt failed exactly here).
	if rr := consume(claimsAfter, tokAfter); rr.Code != http.StatusOK {
		t.Fatalf("(b+) after-watermark control status = %d body %s, want 200 (same live-grant state; iat past the watermark is the only difference)", rr.Code, rr.Body.String())
	}
	if n := countGrantsFor(t, h, userID); n != 3 {
		t.Fatalf("(b+) control grant rows = %d, want 3 (the control CONSUMED its grant)", n)
	}

	// (c) fresh login AFTER the revocation: full second factor completes,
	// then the NEW session runs the whole C1 chain — proof → grant →
	// consumption.
	code, T := loginForBootstrap(t, h, email, "correct-horse-battery")
	if T == "" {
		t.Fatalf("(c) login status = %d body, want an mfa_token (mfa_required)", code)
	}
	vr := postEnrollmentJSON(t, "/auth/totp/verify", map[string]any{"mfa_token": T, "code": mustFreshTOTPCode(t)}, h.TOTPVerify)
	if vr.Code != http.StatusOK {
		t.Fatalf("(c) TOTP verify status = %d body %s, want 200", vr.Code, vr.Body.String())
	}
	access := accessTokenFromBody(t, vr)
	claimsNew, err := h.jwt.Validate(access)
	if err != nil {
		t.Fatalf("(c) validate fresh access token: %v", err)
	}
	if claimsNew.IssuedAt == nil || !claimsNew.IssuedAt.Time.After(notBefore) {
		t.Fatalf("(c) fresh iat %v not after not_before %v", claimsNew.IssuedAt, notBefore)
	}
	// The login's verify claimed the current window; the fresh proof needs a
	// fresh claim slot.
	resetReplayMarker(t, h, userID)
	tokNew := matrixProof(t, h, claimsNew, "recovery.regenerate")
	if rr := consume(claimsNew, tokNew); rr.Code != http.StatusOK {
		t.Fatalf("(c) fresh-session consumption status = %d body %s, want 200", rr.Code, rr.Body.String())
	}

	// (d) the C3 contrast account: revoke all → fresh login → the bootstrap
	// enrollment completes (issuance is NOT blocked by the retained row).
	c3ID, c3Email, _ := seedC1UserWithPassword(t, h, "wmallc3", nil)
	revokeAllAndSettle(t, h, c3ID)
	dcode, T3 := loginForBootstrap(t, h, c3Email, "correct-horse-battery")
	if dcode != http.StatusForbidden || T3 == "" {
		t.Fatalf("(d) C3 login status = %d T present = %v, want 403 enrollment_required with mfa_token", dcode, T3 != "")
	}
	sr := postEnrollmentJSON(t, "/auth/totp/enroll/setup", map[string]any{"mfa_token": T3}, h.TOTPEnrollmentSetup)
	if sr.Code != http.StatusOK {
		t.Fatalf("(d) enroll/setup status = %d body %s, want 200", sr.Code, sr.Body.String())
	}
	E1 := enrollmentIDFromBody(t, sr.Body.Bytes())
	stagedSecret := provisioningSecret(t, sr)
	confirmCode, err := totp.GenerateCode(stagedSecret, time.Now())
	if err != nil {
		t.Fatalf("(d) code: %v", err)
	}
	cr := postEnrollmentJSON(t, "/auth/totp/enroll/confirm", map[string]any{
		"mfa_token": T3, "code": confirmCode, "enrollment_id": E1,
	}, h.TOTPEnrollmentConfirm)
	if cr.Code != http.StatusOK {
		t.Fatalf("(d) enroll/confirm status = %d body %s, want 200", cr.Code, cr.Body.String())
	}
	if !totpEnabled(t, h, c3ID) {
		t.Fatal("(d) C3 bootstrap did not enable TOTP")
	}

	// (e) the durable row is RETAINED through all of it (31-day predicate
	// life) — the fresh logins succeeded on iat, not on row removal.
	var rows int
	if err := h.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM session_revocations WHERE user_id IN ($1, $2) AND scope = 'all'`, userID, c3ID,
	).Scan(&rows); err != nil || rows != 2 {
		t.Fatalf("(e) retained watermark rows = %d (%v), want 2", rows, err)
	}
}

// mustFreshTOTPCode generates a current code for the seeded active secret.
func mustFreshTOTPCode(t *testing.T) string {
	t.Helper()
	code, err := totp.GenerateCode(removalTestSecret, time.Now())
	if err != nil {
		t.Fatalf("code: %v", err)
	}
	return code
}

// --- §4.2 TestMutationInventoryComplete ---

// mutationInventoryRow maps one §3 gated-mutation arm to its drive (a real
// handler invocation WITHOUT any proof grant) and the expected typed
// refusal.
type mutationInventoryRow struct {
	name    string
	refusal int // the status the arm answers without the correct grant
	drive   func(t *testing.T, h *AuthHandler)
}

// possessionGateMarkers are the grant-store call sites that make a handler a
// gated arm (directly, or transitively via requirePossessionGrant /
// promoteBootstrapTOTPEnrollment). The AST scans below pin the inventory to
// exactly these.
var possessionGateMarkers = []string{
	"authn.PeekGrant",
	"authn.ConsumeGrant",
	"authn.BindGrantTarget",
}

// possessionFactorRoutePrefixes are the mux path prefixes that mint or
// activate persistent authentication capability — the §3 factor/enrollment
// path. Route enumeration over these prefixes is the gate-INDEPENDENT
// mutation-surface discovery (r9): a surface is found by its ROUTE, never by
// grant-API references in its handler.
var possessionFactorRoutePrefixes = []string{
	"/auth/totp",
	"/auth/webauthn",
	"/auth/backup-codes",
	"/auth/device",
	"/auth/mfa/reauth",
	"/auth/mfa/possession",
}

// possessionGatedMutationArms maps each §3 gated-mutation route to its mux
// handler. The route-table guard proves each handler reaches the grant store
// (directly, or transitively through requirePossessionGrant /
// promoteBootstrapTOTPEnrollment) — and that the route still exists.
var possessionGatedMutationArms = map[string]string{
	"GET /auth/totp/setup":                  "TOTPSetup",
	"POST /auth/totp/confirm":               "TOTPConfirm",
	"POST /auth/totp/enroll/setup":          "TOTPEnrollmentSetup",
	"POST /auth/totp/enroll/confirm":        "TOTPEnrollmentConfirm",
	"GET /auth/webauthn/register/begin":     "WebAuthnRegisterBegin",
	"POST /auth/webauthn/register/finish":   "WebAuthnRegisterFinish",
	"DELETE /auth/webauthn/credential/{id}": "WebAuthnRevokeCredential",
	"POST /auth/device/register":            "DeviceRegister",
	"POST /auth/backup-codes/generate":      "GenerateBackupCodes",
}

// possessionExemptFactorArms accounts for every OTHER factor-path route,
// with its reason. The guard fails on any factor-path route present in
// NEITHER map — a new surface cannot ship silently (and exempting a real
// mutation is a deliberate, reviewed §3 change).
var possessionExemptFactorArms = map[string]string{
	"GET /auth/webauthn/login/begin":            "pre-auth login ceremony — proves no factor",
	"POST /auth/webauthn/login/finish":          "pre-auth login ceremony",
	"GET /auth/webauthn/credentials":            "read-only credential list",
	"PUT /auth/webauthn/credential/{id}/name":   "display-name metadata; factor-set membership untouched",
	"POST /auth/totp/verify":                    "login second factor",
	"POST /auth/totp/remove/begin":              "removal step-up — its own password+code mechanism (totp_removal.go)",
	"POST /auth/totp/remove":                    "removal step-up confirm",
	"POST /auth/mfa/reauth":                     "proof ISSUANCE (password) — mints grants, mutates no factor",
	"POST /auth/mfa/possession/totp":            "proof ISSUANCE (TOTP)",
	"POST /auth/mfa/possession/webauthn/begin":  "proof ISSUANCE (UV assertion)",
	"POST /auth/mfa/possession/webauthn/finish": "proof ISSUANCE (UV assertion)",
	"POST /auth/backup-codes/verify":            "login second factor",
}

// possessionFactorPath reports whether a mux route path lies on the
// factor/enrollment path.
func possessionFactorPath(path string) bool {
	for _, prefix := range possessionFactorRoutePrefixes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

// possessionFactorRoutesFromSources parses mux-builder sources and returns
// every registered route whose path lies on the factor/enrollment path, as
// "METHOD path" → mux handler selector. Discovery consults ONLY the route
// table — never grant-API references — so an ungated mutation with zero
// grant calls is still discovered.
func possessionFactorRoutesFromSources(t *testing.T, sources map[string][]byte) map[string]string {
	t.Helper()
	routes := map[string]string{}
	filenames := make([]string, 0, len(sources))
	for filename := range sources {
		filenames = append(filenames, filename)
	}
	sort.Strings(filenames)
	fset := gotoken.NewFileSet()
	for _, filename := range filenames {
		file, err := parser.ParseFile(fset, filename, sources[filename], 0)
		if err != nil {
			t.Fatalf("parse %s: %v", filename, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			recv, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc" {
				return true
			}
			if !strings.HasSuffix(recv.Name, "mux") && !strings.HasSuffix(recv.Name, "Mux") {
				return true
			}
			if len(call.Args) == 0 {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != gotoken.STRING {
				return true
			}
			route, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			method, path, ok := strings.Cut(route, " ")
			if !ok || !possessionFactorPath(path) {
				return true
			}
			handler := ""
			for _, arg := range call.Args[1:] {
				if id, ok := arg.(*ast.Ident); ok {
					// HandleFunc's direct function-value form
					// (mux.HandleFunc(pattern, someFunc)).
					handler = id.Name
					continue
				}
				ast.Inspect(arg, func(m ast.Node) bool {
					hsel, ok := m.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					hrecv, ok := hsel.X.(*ast.Ident)
					if ok && hrecv.Name == "authH" && handler == "" {
						handler = hsel.Sel.Name
					}
					return true
				})
			}
			key := method + " " + path
			if prev, dup := routes[key]; dup && prev != handler {
				t.Fatalf("route %s registered twice with different handlers (%q vs %q)", key, prev, handler)
			}
			routes[key] = handler
			return true
		})
	}
	return routes
}

// classifyPossessionFactorRoute returns "" when the factor-path route is
// accounted for (§3 gated mutation or exempt arm), else the guard's
// rejection reason.
func classifyPossessionFactorRoute(route string) string {
	if _, ok := possessionGatedMutationArms[route]; ok {
		return ""
	}
	if _, ok := possessionExemptFactorArms[route]; ok {
		return ""
	}
	return "unclassified factor-path route " + route +
		" — map it in §3 (gated mutation arm or exempt arm) before shipping"
}

// possessionPackageSources reads the package's non-test sources (tests run
// with the package directory as cwd).
func possessionPackageSources(t *testing.T) map[string][]byte {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	sources := make(map[string][]byte)
	for _, filename := range files {
		if strings.HasSuffix(filename, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		sources[filename] = raw
	}
	return sources
}

// possessionHandlerFuncs parses the given sources into FuncDecls by name
// (function and method names are unique across the package's handler files).
func possessionHandlerFuncs(t *testing.T, sources map[string][]byte) map[string]*ast.FuncDecl {
	t.Helper()
	funcs := map[string]*ast.FuncDecl{}
	filenames := make([]string, 0, len(sources))
	for filename := range sources {
		filenames = append(filenames, filename)
	}
	sort.Strings(filenames)
	fset := gotoken.NewFileSet()
	for _, filename := range filenames {
		file, err := parser.ParseFile(fset, filename, sources[filename], 0)
		if err != nil {
			t.Fatalf("parse %s: %v", filename, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			funcs[fn.Name.Name] = fn
		}
	}
	return funcs
}

// reachesGrantStore reports whether the function's transitive in-package
// call graph touches the grant store: a direct
// authn.PeekGrant/ConsumeGrant/BindGrantTarget call, or any call into a
// package function that does (requirePossessionGrant,
// promoteBootstrapTOTPEnrollment). This is the GATE classification — it is
// applied to surfaces discovered independently (by route), never used for
// discovery itself.
func reachesGrantStore(fn *ast.FuncDecl, funcs map[string]*ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}
	visited := map[string]bool{fn.Name.Name: true}
	var walk func(fd *ast.FuncDecl) bool
	walk = func(fd *ast.FuncDecl) bool {
		found := false
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if found {
				return false
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "authn" {
				for _, marker := range possessionGateMarkers {
					if sel.Sel.Name == strings.TrimPrefix(marker, "authn.") {
						found = true
						return false
					}
				}
				return true
			}
			callee := funcs[sel.Sel.Name]
			if callee != nil && !visited[sel.Sel.Name] {
				visited[sel.Sel.Name] = true
				if walk(callee) {
					found = true
					return false
				}
			}
			return true
		})
		return found
	}
	return walk(fn)
}

// TestMutationInventoryComplete is §4.2's inventory guard: (1) every §3
// gated-mutation arm refuses WITHOUT its grant through the real handler, and
// (2) the enumerated inventory is COMPLETE against the package sources — the
// set of grant-touching handlers must equal the set the inventory accounts
// for, so a future ungated mutation (or an unlisted gated arm) fails here.
func TestMutationInventoryComplete(t *testing.T) {
	h := newPossessionHarness(t)

	// Fixture accounts: a C1-with-TOTP session user for the session-scope
	// arms and a zero-factor (C3) account for the mfa_pending bootstrap arms
	// (whose bare token is VALID but carries NO grant).
	c1ID, c1Claims := newPossessionUser(t, h, "inventory", true)
	seedEnabledTOTP(t, h, c1ID)
	c3ID, c3Email, _ := seedC1UserWithPassword(t, h, "inventoryc3", nil)
	bareT, err := h.jwt.IssueMFAPending(c3ID, c3Email)
	if err != nil {
		t.Fatalf("mint bare mfa_pending token: %v", err)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate device key: %v", err)
	}
	pubKeyHex := "04" + fmt.Sprintf("%064x%064x", priv.PublicKey.X, priv.PublicKey.Y) // uncompressed point

	inventory := []mutationInventoryRow{
		{"GET /auth/totp/setup", http.StatusForbidden, func(t *testing.T, h *AuthHandler) {
			rr := matrixSetup(t, h, c1Claims, "")
			if rr.Code != http.StatusForbidden {
				t.Fatalf("status = %d body %s, want 403", rr.Code, rr.Body.String())
			}
		}},
		{"POST /auth/totp/confirm", http.StatusForbidden, func(t *testing.T, h *AuthHandler) {
			rr := matrixConfirm(t, h, c1Claims, "000000", "", "00000000-0000-0000-0000-000000000000")
			if rr.Code != http.StatusForbidden {
				t.Fatalf("status = %d body %s, want 403", rr.Code, rr.Body.String())
			}
		}},
		{"POST /auth/totp/enroll/setup", http.StatusForbidden, func(t *testing.T, h *AuthHandler) {
			rr := postEnrollmentJSON(t, "/auth/totp/enroll/setup", map[string]any{"mfa_token": bareT}, h.TOTPEnrollmentSetup)
			if rr.Code != http.StatusForbidden {
				t.Fatalf("status = %d body %s, want 403 (a valid mfa_pending token WITHOUT its grant)", rr.Code, rr.Body.String())
			}
		}},
		{"POST /auth/totp/enroll/confirm", http.StatusForbidden, func(t *testing.T, h *AuthHandler) {
			rr := postEnrollmentJSON(t, "/auth/totp/enroll/confirm", map[string]any{
				"mfa_token": bareT, "code": "000000", "enrollment_id": "00000000-0000-0000-0000-000000000000",
			}, h.TOTPEnrollmentConfirm)
			if rr.Code != http.StatusForbidden {
				t.Fatalf("status = %d body %s, want 403", rr.Code, rr.Body.String())
			}
		}},
		{"GET /auth/webauthn/register/begin", http.StatusForbidden, func(t *testing.T, h *AuthHandler) {
			req := httptest.NewRequest(http.MethodGet, "/auth/webauthn/register/begin", nil)
			req = req.WithContext(ContextWithUser(req.Context(), c1Claims))
			rr := httptest.NewRecorder()
			h.WebAuthnRegisterBegin(rr, req)
			if rr.Code != http.StatusForbidden {
				t.Fatalf("status = %d body %s, want 403", rr.Code, rr.Body.String())
			}
		}},
		{"DELETE /auth/webauthn/credential/{id}", http.StatusForbidden, func(t *testing.T, h *AuthHandler) {
			del := httptest.NewRequest(http.MethodDelete, "/auth/webauthn/credential/aWQ", nil)
			del.SetPathValue("id", "aWQ")
			del = del.WithContext(ContextWithUser(del.Context(), c1Claims))
			rr := httptest.NewRecorder()
			h.WebAuthnRevokeCredential(rr, del)
			if rr.Code != http.StatusForbidden {
				t.Fatalf("status = %d body %s, want 403", rr.Code, rr.Body.String())
			}
		}},
		{"POST /auth/backup-codes/generate", http.StatusForbidden, func(t *testing.T, h *AuthHandler) {
			req := httptest.NewRequest(http.MethodPost, "/auth/backup-codes/generate", strings.NewReader(`{}`))
			req.Header.Set("Content-Type", "application/json")
			req = req.WithContext(ContextWithUser(req.Context(), c1Claims))
			rr := httptest.NewRecorder()
			h.GenerateBackupCodes(rr, req)
			if rr.Code != http.StatusForbidden {
				t.Fatalf("status = %d body %s, want 403", rr.Code, rr.Body.String())
			}
		}},
		{"POST /auth/device/register (native)", http.StatusForbidden, func(t *testing.T, h *AuthHandler) {
			body, _ := json.Marshal(map[string]any{
				"provider": "apns", "push_token": "inventory-token",
				"device_public_key": pubKeyHex, "device_name": "inventory",
			})
			req := httptest.NewRequest(http.MethodPost, "/auth/device/register", strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/json")
			req = req.WithContext(ContextWithUser(req.Context(), c1Claims))
			rr := httptest.NewRecorder()
			h.DeviceRegister(rr, req)
			if rr.Code != http.StatusForbidden {
				t.Fatalf("status = %d body %s, want 403", rr.Code, rr.Body.String())
			}
		}},
	}
	seen := map[string]bool{}
	for _, row := range inventory {
		if seen[row.name] {
			t.Fatalf("duplicate inventory row %q", row.name)
		}
		seen[row.name] = true
		t.Run("refuses without grant: "+row.name, func(t *testing.T) {
			row.drive(t, h)
		})
	}

	// Completeness, direction 1 (r8, preserved): the grant-touching handlers
	// in the package sources must be exactly the set the inventory + its two
	// shared helpers account for, so an unlisted GATED arm fails here.
	// (WebAuthnRegisterFinish and GenerateBackupCodes/DeviceRegister reach
	// the store through requirePossessionGrant; TOTPEnrollmentConfirm through
	// promoteBootstrapTOTPEnrollment — both helpers are inventory members
	// themselves.)
	cwdSources := possessionPackageSources(t)
	owners := possessionGateOwnersFromSources(t, cwdSources)
	wantOwners := []string{
		"device.go:DeviceRegister",
		"mfa_reauth.go:requirePossessionGrant",
		"totp.go:TOTPConfirm",
		"totp.go:TOTPEnrollmentSetup",
		"totp.go:TOTPSetup",
		"totp.go:promoteBootstrapTOTPEnrollment",
		"webauthn.go:WebAuthnRegisterBegin",
		"webauthn.go:WebAuthnRegisterFinish",
		"webauthn.go:WebAuthnRevokeCredential",
	}
	if got := owners; !equalStrings(got, wantOwners) {
		t.Fatalf("the gated-mutation inventory changed — re-map §3 before shipping\n got: %v\nwant: %v", got, wantOwners)
	}

	// Completeness, direction 2 (r9, gate-INDEPENDENT): the mux route table
	// is the mutation surface. Every factor-path route must be accounted
	// for — a §3 gated mutation whose handler AST-proves it reaches the
	// grant store, or an explicitly-exempt arm. Discovery keys on the
	// ROUTE, so a new factor mutation with ZERO grant-API calls is still
	// found (the r8 direction above could not see it).
	muxRaw, err := os.ReadFile(filepath.Join("..", "..", "cmd", "authserverd", "main.go"))
	if err != nil {
		t.Fatalf("read mux builder (route-table discovery parses cmd/authserverd/main.go): %v", err)
	}
	routes := possessionFactorRoutesFromSources(t, map[string][]byte{
		"cmd/authserverd/main.go": muxRaw,
	})
	handlersByName := possessionHandlerFuncs(t, cwdSources)
	for route, handler := range routes {
		if want, isMutation := possessionGatedMutationArms[route]; isMutation {
			if handler != want {
				t.Fatalf("factor route %s now binds %q, want %q — re-map §3 before shipping", route, handler, want)
			}
			if handler == "" {
				t.Fatalf("factor route %s binds no resolvable authH handler — cannot verify its gate", route)
			}
			if !reachesGrantStore(handlersByName[handler], handlersByName) {
				t.Fatalf("§3 mutation %s -> %s reaches NO grant-store call (directly or via requirePossessionGrant/promoteBootstrapTOTPEnrollment) — it is UNGATED", route, handler)
			}
		} else if reason := classifyPossessionFactorRoute(route); reason != "" {
			t.Fatalf("%s (binds %q)", reason, handler)
		}
	}
	for route := range possessionGatedMutationArms {
		if _, ok := routes[route]; !ok {
			t.Fatalf("§3 mutation route %q is no longer registered in the mux — re-map §3 before shipping", route)
		}
	}

	// The guard has teeth (r9): the planted source registers a NEW factor
	// route whose handler contains ZERO grant-store interaction — the shape
	// a genuinely ungated mutation ships as, and invisible to the r8
	// grant-API-keyed discovery (whose fixture, tellingly, had to call
	// PeekGrant to be seen). Route enumeration finds it by its PATH and the
	// classification rejects it.
	plantedSrc := []byte(`package handlers

import "net/http"

func plantedFactorRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /auth/totp/force-enable", plantedUngatedFactorEnable)
}

// plantedUngatedFactorEnable flips factor state with NO grant-store call of
// any kind.
func plantedUngatedFactorEnable(w http.ResponseWriter, r *http.Request) {
}
`)
	plantedRoutes := possessionFactorRoutesFromSources(t, map[string][]byte{
		"cmd/authserverd/main.go": muxRaw,
		"planted_ungated.go":      plantedSrc,
	})
	if got := plantedRoutes["POST /auth/totp/force-enable"]; got != "plantedUngatedFactorEnable" {
		t.Fatalf("planted ungated factor route not discovered by route enumeration: got %q in %v", got, plantedRoutes)
	}
	if reason := classifyPossessionFactorRoute("POST /auth/totp/force-enable"); reason == "" {
		t.Fatal("the inventory check ACCEPTED the planted ungated factor route")
	}

	// And the gate-scan itself bites on the same fixture: it scans the
	// planted setter as UNGATED while every mapped §3 mutation scans as
	// gated — transitively, through the shared helpers.
	plantFuncs := possessionHandlerFuncs(t, map[string][]byte{
		"planted_ungated.go": plantedSrc,
		"mfa_reauth.go":      cwdSources["mfa_reauth.go"],
		"totp.go":            cwdSources["totp.go"],
		"webauthn.go":        cwdSources["webauthn.go"],
		"device.go":          cwdSources["device.go"],
	})
	if reachesGrantStore(plantFuncs["plantedUngatedFactorEnable"], plantFuncs) {
		t.Fatal("the planted ungated factor setter scans as grant-gated — the gate-scan cannot distinguish it from the real arms")
	}
	for _, gated := range possessionGatedMutationArms {
		if !reachesGrantStore(handlersByName[gated], handlersByName) {
			t.Fatalf("mapped §3 mutation %s does not scan as grant-gated — the gate-scan regressed", gated)
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// possessionGateOwnersFromSources scans the given package sources for
// functions whose bodies touch the grant store directly (the r8
// "unlisted gated arm" detector; discovery itself is route-based — see
// possessionFactorRoutesFromSources).
func possessionGateOwnersFromSources(t *testing.T, sources map[string][]byte) []string {
	t.Helper()
	var owners []string
	filenames := make([]string, 0, len(sources))
	for filename := range sources {
		filenames = append(filenames, filename)
	}
	sort.Strings(filenames)
	fset := gotoken.NewFileSet()
	for _, filename := range filenames {
		file, err := parser.ParseFile(fset, filename, sources[filename], 0)
		if err != nil {
			t.Fatalf("parse %s: %v", filename, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			marker := ""
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if marker != "" {
					return false
				}
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				for _, m := range possessionGateMarkers {
					pkg, ok := sel.X.(*ast.Ident)
					if ok && pkg.Name == "authn" && sel.Sel.Name == strings.TrimPrefix(m, "authn.") {
						marker = m
						return false
					}
				}
				return true
			})
			if marker != "" {
				owners = append(owners, filepath.Base(filename)+":"+fn.Name.Name)
			}
		}
	}
	sort.Strings(owners)
	return owners
}
