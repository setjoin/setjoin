package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/threat"
	"setjoin.com/shared/toggle"
)

func TestCompletionRequestCarriesMFAPendingFencesExplicitly(t *testing.T) {
	h := &deps{jwt: newTestJWT()}
	wantIdentity := &jwtutil.IdentityFenceClaim{
		SourceID: 11, SourceGeneration: 12,
		LinkID: 21, LinkGeneration: 22,
	}
	wantCredential := "credential-version-proof"
	completion := CompletionRequest{
		Factors: []string{token.AMRHardwareKey},
		Metadata: CompletionMetadata{
			IdentityFence:   wantIdentity,
			CredentialFence: wantCredential,
		},
	}

	raw, err := h.issueMFAPending(
		context.Background(), 42, "typed-completion@example.com", completion,
	)
	if err != nil {
		t.Fatalf("issue typed MFA-pending token: %v", err)
	}
	claims, err := h.jwt.Validate(raw)
	if err != nil {
		t.Fatalf("validate typed MFA-pending token: %v", err)
	}
	if claims.CredentialFence != wantCredential {
		t.Fatalf("credential fence=%q, want %q", claims.CredentialFence, wantCredential)
	}
	if claims.IdentityFence == nil || *claims.IdentityFence != *wantIdentity {
		t.Fatalf("identity fence=%+v, want %+v", claims.IdentityFence, wantIdentity)
	}
	if len(claims.AMR) != 1 || claims.AMR[0] != token.AMRHardwareKey {
		t.Fatalf("AMR=%v, want [%s]", claims.AMR, token.AMRHardwareKey)
	}
}

type completionCARecorder struct{ calls int }

func (r *completionCARecorder) Record(
	context.Context, threat.PolicyEvalContext, threat.PolicyResult,
) {
	r.calls++
}

func TestCompletionRequestSevenLoginShapesPreserveClaimsAndFamily(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	userID := seedSSOTestActorDB(t, pool, ctx, "completion-seven-shapes")
	defer cleanSSOActor(t, pool, ctx, userID)
	var email string
	if err := pool.QueryRow(ctx, `SELECT email FROM users WHERE id=$1`, userID).
		Scan(&email); err != nil {
		t.Fatalf("read completion actor: %v", err)
	}

	recorder := &completionCARecorder{}
	provider := newTestJWT()
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: provider, Logger: discardLogger(),
		PolicyEngine: allowEngine(), SignInRecorder: recorder,
		Toggles: toggle.NewTestFlags(map[string]bool{
			toggle.FeatureTokenBinding: true,
		}),
	})
	sif := int64(3600)
	wantJKT, err := threat.JKTFromJWK(fakeDPoPJWK)
	if err != nil {
		t.Fatalf("derive DPoP thumbprint: %v", err)
	}
	tests := []struct {
		name         string
		factors      []string
		caEvaluated  bool
		stepUp       bool
		wantACR      string
		wantCARecord int
		wantDPoP     bool
		wantSIF      bool
	}{
		{"password", []string{token.AMRPassword}, true, false, jwtutil.ACRAAL1, 0, true, true},
		{"sso", []string{token.AMRPassword}, true, false, jwtutil.ACRAAL1, 0, false, false},
		{"totp", []string{token.AMRPassword, token.AMROTP}, false, true, jwtutil.ACRAAL2, 1, true, false},
		{"backup-code", []string{token.AMRPassword, token.AMROTP}, false, true, jwtutil.ACRAAL2, 1, true, false},
		{"device-approve", []string{token.AMRSoftwareKey, token.AMRUserPresence}, false, false, jwtutil.ACRAAL1, 1, true, false},
		{"webauthn", []string{token.AMRHardwareKey}, false, false, jwtutil.ACRAAL1, 1, true, false},
		{"push", []string{token.AMRPassword, token.AMRSoftwareKey, token.AMRUserPresence}, false, true, jwtutil.ACRAAL2, 1, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			beforeCA := recorder.calls
			req := httptest.NewRequest(http.MethodPost, "/auth/"+tt.name, nil)
			response := httptest.NewRecorder()
			metadata := CompletionMetadata{
				ConditionalAccess: CompletionConditionalAccess{
					Evaluated: tt.caEvaluated, StepUpInProgress: tt.stepUp,
				},
			}
			switch tt.name {
			case "password":
				metadata.Session = &CompletionSessionMetadata{
					Confirmation:    &jwtutil.ConfirmationClaim{JKT: wantJKT},
					SignInFrequency: &sif, PersistentSession: "never",
				}
			case "sso":
				// Federated callbacks have no DPoP/session-control request today;
				// nil preserves their established token and cookie shape.
			default:
				metadata = h.completionMetadataForDPoP(fakeDPoPJWK, tt.stepUp)
				metadata.ConditionalAccess.Evaluated = tt.caEvaluated
			}
			h.issueTokensWithFactors(response, req, &userRow{ID: userID, Email: email}, CompletionRequest{
				Factors:  tt.factors,
				Metadata: metadata,
			})
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if delta := recorder.calls - beforeCA; delta != tt.wantCARecord {
				t.Fatalf("CA records=%d want %d (evaluated=%v)",
					delta, tt.wantCARecord, tt.caEvaluated)
			}

			var body struct {
				AccessToken  string `json:"access_token"`
				RefreshToken string `json:"refresh_token"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode token response: %v", err)
			}
			access, err := provider.Validate(body.AccessToken)
			if err != nil {
				t.Fatalf("validate access token: %v", err)
			}
			refresh, err := provider.Validate(body.RefreshToken)
			if err != nil {
				t.Fatalf("validate refresh token: %v", err)
			}
			if access.ACR != tt.wantACR || access.FamilyID == "" ||
				access.FamilyID != refresh.FamilyID {
				t.Fatalf("access context/family=%q/%q refresh family=%q want ACR=%q",
					access.ACR, access.FamilyID, refresh.FamilyID, tt.wantACR)
			}
			for label, claims := range map[string]*token.Claims{
				"access": access, "refresh": refresh,
			} {
				if tt.wantDPoP && (claims.Cnf == nil || claims.Cnf.JKT != wantJKT) {
					t.Fatalf("%s DPoP claim=%+v want jkt %q", label, claims.Cnf, wantJKT)
				}
				if !tt.wantDPoP && claims.Cnf != nil {
					t.Fatalf("%s unexpectedly bound SSO token: %+v", label, claims.Cnf)
				}
				if tt.wantSIF && (claims.SignInFreq == nil || *claims.SignInFreq != sif ||
					claims.SessionAuthTime == nil) {
					t.Fatalf("%s session claims=%+v", label, claims)
				}
				if !tt.wantSIF && (claims.SignInFreq != nil || claims.SessionAuthTime != nil) {
					t.Fatalf("%s unexpectedly gained SIF claims: %+v", label, claims)
				}
			}
			var anchors int
			if err := pool.QueryRow(ctx,
				`SELECT count(*) FROM oauth_tokens WHERE user_id=$1 AND family_id=$2::uuid`,
				userID, access.FamilyID,
			).Scan(&anchors); err != nil {
				t.Fatalf("count family anchor: %v", err)
			}
			if anchors != 1 {
				t.Fatalf("family anchors=%d want 1", anchors)
			}
			accessCookieMaxAge := -1
			for _, cookie := range response.Result().Cookies() {
				if cookie.Name == "access_token" {
					accessCookieMaxAge = cookie.MaxAge
				}
			}
			if tt.name == "password" && accessCookieMaxAge != 0 {
				t.Fatalf("typed session-only cookie MaxAge=%d want 0", accessCookieMaxAge)
			}
			if tt.name != "password" && accessCookieMaxAge <= 0 {
				t.Fatalf("legacy completion cookie MaxAge=%d want positive TTL", accessCookieMaxAge)
			}
		})
	}
}
