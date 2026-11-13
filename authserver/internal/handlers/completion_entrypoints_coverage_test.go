package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/authserver/internal/authn"
	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/threat"
	"setjoin.com/shared/toggle"
)

type fixedCredentialStore struct {
	credentials UserCredentials
}

func (s fixedCredentialStore) CredentialsFor(_ context.Context, userID int64) (UserCredentials, error) {
	c := s.credentials
	c.UserID = userID
	return c, nil
}

func (s fixedCredentialStore) CredentialsByEmail(_ context.Context, email string) (UserCredentials, error) {
	c := s.credentials
	c.Email = email
	return c, nil
}

type successfulPasskeyProvider struct {
	finishedBody map[string]any
}

func (*successfulPasskeyProvider) BeginRegistration(context.Context, int64) ([]byte, []byte, error) {
	return nil, nil, errors.New("not used")
}

func (*successfulPasskeyProvider) FinishRegistration(context.Context, int64, []byte, *http.Request) error {
	return errors.New("not used")
}

func (*successfulPasskeyProvider) BeginLogin(context.Context, string) (int64, []byte, []byte, error) {
	return 0, nil, nil, errors.New("not used")
}

func (p *successfulPasskeyProvider) FinishLogin(_ context.Context, _ int64, _ []byte, r *http.Request) error {
	return json.NewDecoder(r.Body).Decode(&p.finishedBody)
}

func (*successfulPasskeyProvider) NameCredential(context.Context, []byte, int64, string) error {
	return errors.New("not used")
}

func (*successfulPasskeyProvider) RevokeCredential(context.Context, []byte, int64) error {
	return errors.New("not used")
}

type successfulPushProvider struct{}

func (successfulPushProvider) Name() string                          { return "push" }
func (successfulPushProvider) Available(context.Context, int64) bool { return true }
func (successfulPushProvider) GenerateChallenge(context.Context, int64, string) (*authn.ChallengeResponse, error) {
	return &authn.ChallengeResponse{Method: "push", Nonce: "coverage-nonce", TTLSeconds: 60}, nil
}
func (successfulPushProvider) VerifyChallenge(context.Context, int64, string, string) error {
	return nil
}

func seedCompletionEntryUser(t *testing.T, pool *pgxpool.Pool, email, password string, pushEnabled bool) int64 {
	t.Helper()
	ensureEnrollmentLocalDomain(t, pool)
	hash, err := bcryptHashForTest(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	var userID int64
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO users (
			username, email, display_name, domain_id, sync_source, enabled,
			password_hash, must_change_password, mfa_exempt, push_mfa_enabled
		)
		SELECT $1, $1, 'Completion entrypoint coverage', id, 'local', TRUE,
		       $2, FALSE, TRUE, $3
		  FROM domains WHERE is_local = TRUE ORDER BY id LIMIT 1
		RETURNING id`, email, hash, pushEnabled).Scan(&userID); err != nil {
		t.Fatalf("seed completion user: %v", err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = pool.Exec(ctx, `DELETE FROM sessions WHERE user_id=$1`, userID)
		_, _ = pool.Exec(ctx, `DELETE FROM oauth_tokens WHERE user_id=$1`, userID)
		_, _ = pool.Exec(ctx, `DELETE FROM login_events WHERE user_id=$1`, userID)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, userID)
	})
	return userID
}

func TestLoginCompletionEntrypointsPreserveSecurityMetadata(t *testing.T) {
	pool := openHandlerPool(t)
	const password = "Completion-Coverage-1!"

	t.Run("direct password completion", func(t *testing.T) {
		email := "completion-direct-coverage@example.com"
		userID := seedCompletionEntryUser(t, pool, email, password, false)
		recorder := &captureRecorder{}
		h := NewAuthHandler(AuthHandlerConfig{
			Pool: pool, JWT: newTestJWT(), Logger: discardLogger(),
			PolicyEngine: allowEngine(), SignInRecorder: recorder,
			Toggles: toggle.NewTestFlags(map[string]bool{toggle.FeatureTokenBinding: true}),
		})
		body, _ := json.Marshal(map[string]any{
			"email": email, "password": password, "dpop_jwk": fakeDPoPJWK,
			"stay_signed_in": true,
		})
		req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		h.Login(response, req)
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		if !recorder.called {
			t.Fatal("password entrypoint did not evaluate and record conditional access")
		}
		claims, err := h.jwt.Validate(accessTokenFromBody(t, response))
		if err != nil {
			t.Fatalf("validate access token: %v", err)
		}
		wantJKT, _ := threat.JKTFromJWK(fakeDPoPJWK)
		if claims.Cnf == nil || claims.Cnf.JKT != wantJKT {
			t.Fatalf("claims lost completion metadata: %+v", claims)
		}
		if len(claims.AMR) != 1 || claims.AMR[0] != token.AMRPassword {
			t.Fatalf("AMR=%v, want password", claims.AMR)
		}
		var anchors int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM oauth_tokens WHERE user_id=$1 AND family_id=$2::uuid`,
			userID, claims.FamilyID).Scan(&anchors); err != nil || anchors != 1 {
			t.Fatalf("family anchor count=%d err=%v", anchors, err)
		}
	})

	t.Run("password to push challenge", func(t *testing.T) {
		email := "completion-push-coverage@example.com"
		seedCompletionEntryUser(t, pool, email, password, true)
		h := NewAuthHandler(AuthHandlerConfig{
			Pool: pool, JWT: newTestJWT(), Logger: discardLogger(), PushMFA: successfulPushProvider{},
		})
		body, _ := json.Marshal(map[string]string{"email": email, "password": password})
		req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
		response := httptest.NewRecorder()
		h.Login(response, req)
		if response.Code != http.StatusAccepted {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		var result struct {
			Method   string   `json:"mfa_method"`
			Token    string   `json:"mfa_token"`
			Nonce    string   `json:"nonce"`
			Fallback []string `json:"fallback"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		claims, err := h.jwt.Validate(result.Token)
		if err != nil {
			t.Fatalf("validate pending token: %v", err)
		}
		if result.Method != "push" || result.Nonce == "" || claims.CredentialFence == "" ||
			len(claims.AMR) != 1 || claims.AMR[0] != token.AMRPassword {
			t.Fatalf("push challenge=%+v claims=%+v", result, claims)
		}
	})
}

func TestWebAuthnLoginFinishDrivesCompletionFunnel(t *testing.T) {
	pool := openHandlerPool(t)
	const (
		email    = "completion-webauthn-coverage@example.com"
		password = "unused-WebAuthn-Coverage-1!"
	)
	userID := seedCompletionEntryUser(t, pool, email, password, false)
	cookieKey := []byte("0123456789abcdef0123456789abcdef")

	for _, tc := range []struct {
		name        string
		credentials UserCredentials
		wantMFA     bool
	}{
		{name: "passkey then TOTP", credentials: UserCredentials{TOTPEnrolled: true}, wantMFA: true},
		{name: "passkey direct completion", wantMFA: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			passkey := &successfulPasskeyProvider{}
			recorder := &captureRecorder{}
			h := NewAuthHandler(AuthHandlerConfig{
				Pool: pool, JWT: newTestJWT(), CookieKey: cookieKey, Logger: discardLogger(),
				Credentials:  fixedCredentialStore{credentials: tc.credentials},
				PolicyEngine: allowEngine(), SignInRecorder: recorder,
				Toggles: toggle.NewTestFlags(map[string]bool{toggle.FeatureTokenBinding: true}),
			})
			h.deps.passkey = passkey
			sessionCookie, err := h.encryptCookieValue([]byte(`{"challenge":"session"}`))
			if err != nil {
				t.Fatal(err)
			}
			uidCookie, err := h.encryptCookieValue([]byte(strconv.FormatInt(userID, 10)))
			if err != nil {
				t.Fatal(err)
			}
			body, _ := json.Marshal(map[string]any{
				"id": "credential", "type": "public-key", "dpop_jwk": fakeDPoPJWK,
			})
			req := httptest.NewRequest(http.MethodPost, "/auth/webauthn/login/finish", bytes.NewReader(body))
			req.AddCookie(&http.Cookie{Name: "wa_login_sess", Value: sessionCookie})
			req.AddCookie(&http.Cookie{Name: "wa_login_uid", Value: uidCookie})
			response := httptest.NewRecorder()
			h.WebAuthnLoginFinish(response, req)
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if !recorder.called || passkey.finishedBody["id"] != "credential" {
				t.Fatalf("completion did not run CA/passkey: recorder=%v body=%v", recorder.called, passkey.finishedBody)
			}
			if tc.wantMFA {
				var result struct {
					Required bool   `json:"mfa_required"`
					Method   string `json:"mfa_method"`
					Token    string `json:"mfa_token"`
				}
				if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				claims, err := h.jwt.Validate(result.Token)
				if err != nil || !result.Required || result.Method != "totp" ||
					len(claims.AMR) != 1 || claims.AMR[0] != token.AMRHardwareKey {
					t.Fatalf("MFA result=%+v claims=%+v err=%v", result, claims, err)
				}
				return
			}
			claims, err := h.jwt.Validate(accessTokenFromBody(t, response))
			if err != nil {
				t.Fatal(err)
			}
			wantJKT, _ := threat.JKTFromJWK(fakeDPoPJWK)
			if len(claims.AMR) != 1 || claims.AMR[0] != token.AMRHardwareKey ||
				claims.Cnf == nil || claims.Cnf.JKT != wantJKT {
				t.Fatalf("direct passkey claims=%+v", claims)
			}
		})
	}
}
