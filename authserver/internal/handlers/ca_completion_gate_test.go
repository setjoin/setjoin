package handlers

// G4: tests for the login-time conditional-access gate on the factor-completion
// paths (TOTP/backup/push/WebAuthn/device). Reuses the ca_recorder_test.go
// scaffolding (newBlockEngine, captureRecorder, staticPolicyStore, discardLogger).
// No DB: fetchUserGroups runs against a closed pool (→ nil, no panic), geoipDB is
// nil (→ ""), deviceResolver is nil (→ skipped).

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/threat"
	"setjoin.com/shared/toggle"
)

// pectxRecorder captures the PolicyEvalContext the gate builds, to assert the
// AuthMethod mapping (decision 1) reaches CA evaluation / the audit row.
type pectxRecorder struct {
	called bool
	pectx  threat.PolicyEvalContext
}

func (p *pectxRecorder) Record(_ context.Context, pectx threat.PolicyEvalContext, _ threat.PolicyResult) {
	p.called = true
	p.pectx = pectx
}

func allowEngine() *threat.PolicyEngine {
	return threat.NewPolicyEngine(
		&staticPolicyStore{rows: nil}, // no policies → default allow
		toggle.NewStatic(map[string]bool{toggle.FeatureConditionalAccess: true}),
		nil, nil, discardLogger(), false,
	)
}

// (c) decision 1: AuthMethod derives from the COMPLETED (last-appended) factor,
// not factors[0] (the password first factor).
func TestAuthMethodFromCompletedFactors(t *testing.T) {
	cases := []struct {
		name    string
		factors []string
		want    string
	}{
		{"totp: pwd+otp", []string{token.AMRPassword, token.AMROTP}, "totp"},
		{"backup collapses to totp", []string{token.AMRPassword, token.AMROTP}, "totp"},
		{"push: pwd+swk+user", []string{token.AMRPassword, token.AMRSoftwareKey, token.AMRUserPresence}, "push"},
		{"device collapses to push", []string{token.AMRSoftwareKey, token.AMRUserPresence}, "push"},
		{"webauthn passwordless: hwk", []string{token.AMRHardwareKey}, "webauthn"},
		{"passkey-first then totp → completed is totp", []string{token.AMRHardwareKey, token.AMROTP}, "totp"},
		{"password only", []string{token.AMRPassword}, "password"},
		{"empty → password", nil, "password"},
	}
	for _, c := range cases {
		if got := authMethodFromCompletedFactors(c.factors); got != c.want {
			t.Errorf("%s: authMethodFromCompletedFactors(%v) = %q, want %q", c.name, c.factors, got, c.want)
		}
	}
}

// (a) the gate calls CA eval + records when policyEngine is set, and a FRESH
// passwordless/device login (enforceTerminal=true) honors a hard block terminally.
func TestCompletionGate_FreshLogin_EnforcesBlock(t *testing.T) {
	rec := &captureRecorder{}
	d := &deps{
		policyEngine:   newBlockEngine(),
		signInRecorder: rec,
		logger:         discardLogger(),
		pool:           createClosedPool(t),
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/webauthn/login/finish", nil)

	stop, _ := d.evaluateCompletionConditionalAccess(w, r, &userRow{ID: 42, Email: "u@example.com"},
		CompletionRequest{Factors: []string{token.AMRHardwareKey}})

	if !stop {
		t.Fatal("fresh login with a block policy must stop issuance (return true)")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("fresh-login block must 403, got %d", w.Code)
	}
	if !rec.called {
		t.Fatal("gate must record the CA evaluation (ca_signin_log audit row)")
	}
}

// (b) DECISION 2 (corrected scope — ER5 occ_b855024): a step-up-in-progress
// completion (completing the exact factor the server demanded) must not be
// blocked by a REMEDIABLE decision (require_terms / a re-issued step-up — the
// deadlock concern), but a FRESH HARD BLOCK (block with no remediation hint) IS
// terminal: the policy just refused the session this leg is about to mint, and
// with feature.cae_runtime off there is no runtime gate to defer the refusal to.
// The audit row is written either way. (The old pin — "hard block must never
// stop a step-up completion" — encoded the bypass this gate now closes and was
// replaced, not weakened.)
func TestCompletionGate_StepUpInProgress_HardBlockIsTerminal(t *testing.T) {
	rec := &captureRecorder{}
	d := &deps{
		policyEngine:   newBlockEngine(), // hard block: no remediation hint
		signInRecorder: rec,
		logger:         discardLogger(),
		pool:           createClosedPool(t),
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/totp/verify", nil)

	stop, _ := d.evaluateCompletionConditionalAccess(w, r, &userRow{ID: 42, Email: "u@example.com"},
		CompletionRequest{
			Factors:  []string{token.AMRPassword, token.AMROTP},
			Metadata: CompletionMetadata{ConditionalAccess: CompletionConditionalAccess{StepUpInProgress: true}},
		})

	if !stop {
		t.Fatal("step-up-in-progress completion under a fresh HARD block must stop issuance")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("hard-blocked step-up completion must 403, got %d", w.Code)
	}
	if !rec.called {
		t.Fatal("audit row must still be written for the hard-blocked completion")
	}
}

// (b2) the deadlock contract survives, correctly scoped: a REMEDIABLE block
// (require_terms) mid-step-up does NOT strand the completion — the runtime gate
// owns the remediation journey after tokens are issued.
func TestCompletionGate_StepUpInProgress_RemediableBlockContinues(t *testing.T) {
	rec := &captureRecorder{}
	remediable := threat.NewPolicyEngine(
		&staticPolicyStore{rows: []threat.PolicyRow{
			{ID: 3, Name: "terms-all", State: "on", ScopeType: "global",
				Conditions: map[string]interface{}{},
				Actions:    map[string]interface{}{"action": "require_terms"}},
		}},
		toggle.NewStatic(map[string]bool{toggle.FeatureConditionalAccess: true}),
		nil, nil, discardLogger(), false,
	)
	d := &deps{
		policyEngine:   remediable,
		signInRecorder: rec,
		logger:         discardLogger(),
		pool:           createClosedPool(t),
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/totp/verify", nil)

	stop, policyID := d.evaluateCompletionConditionalAccess(w, r, &userRow{ID: 42, Email: "u@example.com"},
		CompletionRequest{
			Factors:  []string{token.AMRPassword, token.AMROTP},
			Metadata: CompletionMetadata{ConditionalAccess: CompletionConditionalAccess{StepUpInProgress: true}},
		})

	if stop {
		t.Fatal("remediable block must not strand a step-up completion (deadlock)")
	}
	if w.Code == http.StatusForbidden {
		t.Fatalf("remediable block must not 403 a step-up completion; got %d", w.Code)
	}
	if policyID != 3 {
		t.Fatalf("matched policy id = %d, want 3 (feeds the sif session-control read)", policyID)
	}
	if !rec.called {
		t.Fatal("audit row must still be written for a remediable-block completion")
	}
}

// (b3) a step-up-in-progress completion under a step-up decision is never
// re-challenged mid-completion (the original deadlock concern), audit only.
func TestCompletionGate_StepUpInProgress_StepUpNotReChallenged(t *testing.T) {
	rec := &captureRecorder{}
	d := &deps{
		policyEngine:   newStepUpEngine(),
		signInRecorder: rec,
		logger:         discardLogger(),
		pool:           createClosedPool(t),
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/totp/verify", nil)

	stop, _ := d.evaluateCompletionConditionalAccess(w, r, &userRow{ID: 42, Email: "u@example.com"},
		CompletionRequest{
			Factors:  []string{token.AMRPassword, token.AMROTP},
			Metadata: CompletionMetadata{ConditionalAccess: CompletionConditionalAccess{StepUpInProgress: true}},
		})

	if stop {
		t.Fatal("step-up decision must not stop a step-up completion (would strand)")
	}
	if w.Code == http.StatusForbidden || w.Code == http.StatusAccepted {
		t.Fatalf("step-up decision must not write a terminal response; got %d", w.Code)
	}
	if !rec.called {
		t.Fatal("audit row must be written")
	}
}

// (c) the AuthMethod passed to CA evaluation / audit is the completed factor.
func TestCompletionGate_RecordsCompletedAuthMethod(t *testing.T) {
	rec := &pectxRecorder{}
	d := &deps{
		policyEngine:   allowEngine(),
		signInRecorder: rec,
		logger:         discardLogger(),
		pool:           createClosedPool(t),
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/totp/verify", nil)

	// password first factor + TOTP completed → the leg's auth_method is "totp".
	stop, _ := d.evaluateCompletionConditionalAccess(w, r, &userRow{ID: 42, Email: "u@example.com"},
		CompletionRequest{
			Factors:  []string{token.AMRPassword, token.AMROTP},
			Metadata: CompletionMetadata{ConditionalAccess: CompletionConditionalAccess{StepUpInProgress: true}},
		})

	if stop {
		t.Fatal("allow policy must not stop issuance")
	}
	if !rec.called {
		t.Fatal("recorder must be called")
	}
	if rec.pectx.AuthMethod != "totp" {
		t.Fatalf("recorded AuthMethod = %q, want \"totp\" (the completed factor, not the password first factor)", rec.pectx.AuthMethod)
	}
}

// nil policy engine → no-op, no panic, no pool touched.
func TestCompletionGate_NilEngine_NoOp(t *testing.T) {
	d := &deps{logger: discardLogger()}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/totp/verify", nil)
	if stop, _ := d.evaluateCompletionConditionalAccess(w, r, &userRow{ID: 1}, CompletionRequest{Factors: []string{token.AMROTP}}); stop {
		t.Fatal("nil policy engine must be a no-op (return false)")
	}
}

// (d) fail-closed guest-scope lookup at the completion leg: a resolver error
// stops issuance with 503 BEFORE any policy evaluation or audit row — the CA
// context is unavailable, so the gate cannot prove the completion admissible
// (mirrors the SSO leg's populateGuestCAScope fail-closed contract; even a
// default-allow policy store must not be reached).
func TestCompletionGate_GuestScopeLookupFailure_StopsIssuance(t *testing.T) {
	rec := &captureRecorder{}
	d := &deps{
		policyEngine:   allowEngine(), // default-allow: only the lookup failure may stop this
		signInRecorder: rec,
		logger:         discardLogger(),
		pool:           createClosedPool(t),
		guestScopeResolver: func(_ context.Context, _ int64) (bool, error) {
			return false, errors.New("database unavailable")
		},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/totp/verify", nil)

	stop, policyID := d.evaluateCompletionConditionalAccess(w, r, &userRow{ID: 42, Email: "u@example.com"},
		CompletionRequest{Factors: []string{token.AMRPassword, token.AMROTP}})

	if !stop {
		t.Fatal("guest-scope lookup failure must stop issuance (return true)")
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("guest-scope lookup failure must respond 503, got %d", w.Code)
	}
	if policyID != 0 {
		t.Fatalf("policy id = %d, want 0 (no policy evaluated)", policyID)
	}
	if rec.called {
		t.Fatal("audit row must not be written when the CA context is unavailable")
	}
}
