package handlers

// SSO conditional-access enforcement (#1: SSO bypasses CA).
//
// SAML ACS + OIDC RP callback issued tokens WITHOUT calling PolicyEngine.Evaluate,
// so federated logins bypassed every CA control (block / step-up / geo / device).
// The fix routes all three SSO paths through settleSSOMappingsThenIssue, which now
// runs evaluateSSOConditionalAccess (mirroring the password Login gate) before
// minting a session. These tests prove the gate denies a blocking policy and yields
// MFA-pending (not a full session) on a step-up policy — no DB needed (the block/
// step-up engines match globally), reusing the ca_recorder_test fakes.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/threat"
)

// TestSSOConditionalAccess_BlockDeniesLogin: a blocking CA policy must deny an SSO
// login — evaluateSSOConditionalAccess returns true (issuance stops) and writes 403.
func TestSSOConditionalAccess_BlockDeniesLogin(t *testing.T) {
	d := &deps{
		policyEngine:   newBlockEngine(),
		signInRecorder: threat.NoopSignInRecorder{},
		logger:         discardLogger(),
		pool:           createClosedPool(t), // fetchUserGroups → nil on closed pool (no panic)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/saml/corp/acs", nil)

	stop := d.evaluateSSOConditionalAccess(w, r, &userRow{ID: 42, Email: "u@example.com"}, "saml", CompletionRequest{Factors: []string{token.AMRPassword}})
	if !stop {
		t.Fatal("blocking CA policy must stop SSO issuance (return true)")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("blocked SSO login must 403, got %d", w.Code)
	}
}

// TestSSOConditionalAccess_StepUpYieldsMFAPending: a step-up CA policy must NOT mint
// a full session — it returns true and writes an mfa_required body with an mfa_token
// (the MFA-pending exchange), exactly like the password Login step-up path.
func TestSSOConditionalAccess_StepUpYieldsMFAPending(t *testing.T) {
	d := &deps{
		policyEngine:   newStepUpEngine(),
		signInRecorder: threat.NoopSignInRecorder{},
		logger:         discardLogger(),
		jwt:            newTestJWT(), // step-up mints an MFA-pending token
		pool:           createClosedPool(t),
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback", nil)

	fenceUser := &userRow{
		ID:                       42,
		Email:                    "u@example.com",
		IdentitySourceID:         101,
		IdentitySourceGeneration: 7,
		IdentityLinkID:           202,
		IdentityLinkGeneration:   9,
	}
	stop := d.evaluateSSOConditionalAccess(w, r, fenceUser, "oidc", CompletionRequest{
		Factors: []string{token.AMRPassword},
		Metadata: CompletionMetadata{IdentityFence: &jwtutil.IdentityFenceClaim{
			SourceID: fenceUser.IdentitySourceID, SourceGeneration: fenceUser.IdentitySourceGeneration,
			LinkID: fenceUser.IdentityLinkID, LinkGeneration: fenceUser.IdentityLinkGeneration,
		}},
	})
	if !stop {
		t.Fatal("step-up CA policy must stop SSO issuance (return true)")
	}
	if w.Code != http.StatusAccepted {
		t.Fatalf("step-up SSO login must respond 202 (the client dispatches MFA on 202), got %d", w.Code)
	}
	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode step-up body: %v", err)
	}
	if body["mfa_required"] != true {
		t.Errorf("step-up SSO login must return mfa_required=true, got %v", body["mfa_required"])
	}
	tok, _ := body["mfa_token"].(string)
	if tok == "" {
		t.Error("step-up SSO login must return an mfa_token (MFA-pending, not a full session)")
	} else {
		claims, err := d.jwt.Validate(tok)
		if err != nil {
			t.Fatalf("validate SSO MFA-pending token: %v", err)
		}
		if claims.IdentityFence == nil ||
			claims.IdentityFence.SourceID != fenceUser.IdentitySourceID ||
			claims.IdentityFence.SourceGeneration != fenceUser.IdentitySourceGeneration ||
			claims.IdentityFence.LinkID != fenceUser.IdentityLinkID ||
			claims.IdentityFence.LinkGeneration != fenceUser.IdentityLinkGeneration {
			t.Fatalf("SSO MFA-pending identity fence=%+v want source/link generations from %+v",
				claims.IdentityFence, fenceUser)
		}
	}
	if _, ok := body["access_token"]; ok {
		t.Error("step-up must NOT mint a full session access_token")
	}
}

// TestSSOConditionalAccess_NilEngineAllows: with no policy engine wired (CA off /
// unconfigured), the gate is a pure pass-through so SSO issuance proceeds.
func TestSSOConditionalAccess_NilEngineAllows(t *testing.T) {
	d := &deps{policyEngine: nil, logger: discardLogger()}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/saml/corp/acs", nil)
	if d.evaluateSSOConditionalAccess(w, r, &userRow{ID: 1, Email: "u@example.com"}, "saml", CompletionRequest{Factors: []string{token.AMRPassword}}) {
		t.Fatal("nil policy engine must not stop issuance (pass-through)")
	}
}

// TestSettleSSO_EnforcesCABeforeMint_StaticGuard pins the wiring at the source level
// (no DB): settleSSOMappingsThenIssue must run applyGroupMappings → re-derive
// (lookupUser) → evaluateSSOConditionalAccess → issueTokens, so CA is enforced on
// every SSO path BEFORE a session is minted.
func TestSettleSSO_EnforcesCABeforeMint_StaticGuard(t *testing.T) {
	helper := funcSrc(t, "auth.go", "settleSSOMappingsThenIssue")
	requireOrder(t, helper, "settleSSOMappingsThenIssue CA ordering",
		"applyGroupMappings",           // 1. settle this login's groups (CA reads them)
		"lookupUser",                   // 2. re-derive is_admin
		"evaluateSSOConditionalAccess", // 3. CA gate (block / step-up) BEFORE mint
		"issueTokens",                  // 4. THEN mint
	)
}
