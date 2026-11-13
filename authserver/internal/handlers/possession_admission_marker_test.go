package handlers

// possession_admission_marker_test.go — the per-tab admission-recovery
// contract's wire marker (r4): every 401 that refused a request at the
// DPoP/token-binding ADMISSION layer carries the machine-readable problem code
// threat.DPoPAdmissionCode, and every APPLICATION-level 401 — one whose
// evaluated failure has already been committed server-side — carries none.
// The webmail client replays a proof-signed request after its
// GET /auth/session/token recovery ONLY on the marked shape; an unmarked 401
// (the TOTP-removal invalid-code refusal, whose increment counts toward the
// factor lockout) must execute exactly once.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"setjoin.com/shared/threat"
)

// problemCodeOf decodes the `code` member of a problem+json body.
func problemCodeOf(t *testing.T, body string) string {
	t.Helper()
	var p struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal([]byte(body), &p); err != nil {
		t.Fatalf("decode problem body %s: %v", body, err)
	}
	return p.Code
}

// TestAdmissionRefusalsCarryTheMarker pins the marked shape on BOTH admission
// surfaces the client's recovery rides:
//   - the possession endpoints' T1 self-admission (mounted WITHOUT
//     requireAuth; the handler writes the 401 itself), and
//   - (the middleware half — RequireAuth's ErrTokenBinding arm — is pinned in
//     authserver/internal/middleware's auth_test.go).
func TestAdmissionRefusalsCarryTheMarker(t *testing.T) {
	h := newPossessionHarness(t)

	// Nothing presented at the self-admitting begin: the uniform T1 401.
	rr := postPossession(h, "/auth/mfa/possession/webauthn/begin",
		map[string]any{"operation": "recovery.regenerate"}, nil, nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("begin admission status = %d body %s, want 401", rr.Code, rr.Body.String())
	}
	if code := problemCodeOf(t, rr.Body.String()); code != threat.DPoPAdmissionCode {
		t.Fatalf("begin admission problem code = %q, want %q — an unmarked admission 401 can never be distinguished from a committed application refusal, so the per-tab recovery is unusable", code, threat.DPoPAdmissionCode)
	}

	// Same contract at the finish's admission.
	fr := postPossession(h, "/auth/mfa/possession/webauthn/finish",
		map[string]any{"operation": "recovery.regenerate", "mfa_token": "not-a-token"}, nil, nil)
	if fr.Code != http.StatusUnauthorized {
		t.Fatalf("finish admission status = %d body %s, want 401", fr.Code, fr.Body.String())
	}
	if code := problemCodeOf(t, fr.Body.String()); code != threat.DPoPAdmissionCode {
		t.Fatalf("finish admission problem code = %q, want %q", code, threat.DPoPAdmissionCode)
	}
}

// TestApplicationRemoval401StaysUnmarked pins the negative half: the
// TOTP-removal begin's invalid-code 401 is an EVALUATED failure whose
// bookkeeping already committed toward the five-attempt lock. It must NEVER
// carry the admission marker — a client replay would re-evaluate the same
// wrong code and double-count toward lockout.
func TestApplicationRemoval401StaysUnmarked(t *testing.T) {
	h := newPossessionHarness(t)
	userID, claims := newPossessionUserWithEmail(t, h, "marker-unmarked", false)
	seedEnabledTOTP(t, h, userID)
	if _, err := h.pool.Exec(context.Background(),
		`UPDATE users SET password_hash = $2 WHERE id = $1`, userID, mustHash(t, "correct-horse-battery"),
	); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRequest(http.MethodPost, "/auth/totp/removal/begin",
		strings.NewReader(`{"password":"correct-horse-battery","code":"000000"}`))
	rr.Header.Set("Content-Type", "application/json")
	rr = rr.WithContext(ContextWithUser(rr.Context(), claims))
	w := httptest.NewRecorder()
	h.TOTPRemovalBegin(w, rr)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("invalid-code removal status = %d body %s, want 401", w.Code, w.Body.String())
	}
	if code := problemCodeOf(t, w.Body.String()); code == threat.DPoPAdmissionCode {
		t.Fatal("the evaluated invalid-code 401 carries the admission marker — a replay here would double-count toward the factor lockout")
	}
}
