package handlers

// ER5 er5-s08 occurrence test (missing-security-control.mfa-sign-in-frequency):
// an MFA-completed session must carry the conditional-access sign-in-frequency
// control the matched policy mandates. Password login embedded the policy's
// sif; every completion path (TOTP verify / push poll / backup codes /
// enrollment confirm) historically minted sessions WITHOUT it — the policy's
// max-session-age silently did not apply to MFA sessions.
//
// The e2e leg drives the REAL enrollment-confirm completion under a CA policy
// whose DB row (policy_session_view) carries session_control.sign_in_frequency,
// and asserts the minted access token carries the sif. The gate→policyID leg
// (evaluateCompletionConditionalAccess returning the matched policy's ID) is
// unit-pinned by TestCompletionGate_StepUpInProgress_RemediableBlockContinues.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"setjoin.com/shared/threat"
	"setjoin.com/shared/toggle"
)

// sifPolicyID is the conditional_access_policies row this test seeds with a
// 4-hour sign-in-frequency session control.
const sifPolicyID int64 = 51008

func TestMFACompletionCarriesSignInFrequencyFromMatchedPolicy(t *testing.T) {
	pool := enrollmentHandlerPool(t)
	ensureEnrollmentLocalDomain(t, pool)
	userID := seedLocalUser(t, pool, "totp-sif-completion@example.com")

	// Seed the policy row the completion's sif read consults. priority 9999
	// (evaluated last) so a leaked row can never shadow a real policy — a
	// leaked priority-0 ALLOW row here poisoned the admin CA-simulate tests
	// downstream (nightly-15 CI). Cleanup deletes by id AND name and surfaces
	// failures: a silently-leaked global policy is a cross-lane test hazard.
	if _, err := pool.Exec(t.Context(),
		`INSERT INTO conditional_access_policies (id, name, enabled, state, priority, session_control)
		 VALUES ($1, 'er5s08-sif-e2e', TRUE, 'on', 9999,
		         '{"sign_in_frequency": {"value": 4, "unit": "hours"}}'::jsonb)
		 ON CONFLICT (id) DO UPDATE SET session_control = EXCLUDED.session_control, state = 'on', priority = 9999`,
		sifPolicyID,
	); err != nil {
		t.Fatalf("seed session-control policy: %v", err)
	}
	t.Cleanup(func() {
		t.Helper()
		// t.Context() is already canceled by cleanup time — the DELETE must
		// run on a live context or the seeded global policy leaks and poisons
		// every later CA-policy consumer on the shared test database.
		if _, err := pool.Exec(context.Background(),
			`DELETE FROM conditional_access_policies WHERE id = $1 OR name = 'er5s08-sif-e2e'`,
			sifPolicyID); err != nil {
			t.Errorf("cleanup: delete seeded CA policy: %v", err)
		}
	})

	recorder := &captureRecorder{}
	h := NewAuthHandler(AuthHandlerConfig{
		Pool:           pool,
		JWT:            newTestJWT(),
		Logger:         discardLogger(),
		PolicyEngine:   newAllowEngineWithID(sifPolicyID),
		SignInRecorder: recorder,
		Toggles: toggle.NewTestFlags(map[string]bool{
			toggle.FeatureTokenBinding: true,
		}),
	})
	mfaToken, err := h.jwt.IssueMFAPending(userID, "totp-sif-completion@example.com")
	if err != nil {
		t.Fatalf("issue MFA-pending token: %v", err)
	}

	seedBootstrapGrant(t, pool, h.jwt, mfaToken)
	setup := postEnrollmentJSON(t, "/auth/totp/enroll/setup", map[string]any{
		"mfa_token": mfaToken,
	}, h.TOTPEnrollmentSetup)
	if setup.Code != http.StatusOK {
		t.Fatalf("enrollment setup: got %d, want 200: %s", setup.Code, setup.Body.String())
	}
	enrollmentID := enrollmentIDFromBody(t, setup.Body.Bytes())
	var setupBody struct {
		ProvisioningURI string `json:"provisioning_uri"`
	}
	if err := json.Unmarshal(setup.Body.Bytes(), &setupBody); err != nil {
		t.Fatalf("decode enrollment setup: %v", err)
	}
	key, err := otp.NewKeyFromURL(setupBody.ProvisioningURI)
	if err != nil {
		t.Fatalf("parse provisioning URI: %v", err)
	}
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("generate confirmation code: %v", err)
	}

	confirm := postEnrollmentJSON(t, "/auth/totp/enroll/confirm", map[string]any{
		"mfa_token":     mfaToken,
		"code":          code,
		"enrollment_id": enrollmentID,
	}, h.TOTPEnrollmentConfirm)
	if confirm.Code != http.StatusOK {
		t.Fatalf("enrollment confirm: got %d, want 200: %s", confirm.Code, confirm.Body.String())
	}
	claims, err := h.jwt.Validate(accessTokenFromBody(t, confirm))
	if err != nil {
		t.Fatalf("validate minted access token: %v", err)
	}

	// THE OCCURRENCE: the MFA-completed session must carry the matched policy's
	// sign-in-frequency control (4 hours = 14400s).
	if claims.SignInFreq == nil {
		t.Fatal("MFA-completed session minted WITHOUT the policy's sign-in-frequency control — conditional access session controls skip MFA sessions")
	}
	if *claims.SignInFreq != 4*3600 {
		t.Fatalf("sif = %ds, want 14400s (the seeded policy's 4-hour max session age)", *claims.SignInFreq)
	}
	// SessionAuthTime is stamped together with sif (issueAndStore compatibility
	// for sif-bearing tokens depends on the pair).
	if claims.SessionAuthTime == nil {
		t.Fatal("sif-bearing token minted without an auth_time anchor — the timer could never be evaluated")
	}
}

// newAllowEngineWithID builds an engine whose single policy (state on, global,
// allow) carries the given ID, so the completion gate surfaces it as the
// matched policy and the sif read hits the seeded DB row.
func newAllowEngineWithID(id int64) *threat.PolicyEngine {
	return threat.NewPolicyEngine(
		&staticPolicyStore{rows: []threat.PolicyRow{
			{ID: id, Name: "er5s08-sif-allow", State: "on", ScopeType: "global",
				Conditions: map[string]interface{}{},
				Actions:    map[string]interface{}{"action": "allow"}},
		}},
		toggle.NewStatic(map[string]bool{toggle.FeatureConditionalAccess: true}),
		nil, nil, discardLogger(), false,
	)
}
