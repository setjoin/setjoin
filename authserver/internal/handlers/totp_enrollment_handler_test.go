package handlers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/threat"
	"setjoin.com/shared/toggle"
)

const enrollmentHandlerTestKey = "test-totp-encryption-key-32chars"

// seedBootstrapGrant inserts the mfa_pending bootstrap grant the login flow
// commits atomically with the mfa_token (possession scheme v7 §1.5.1 step 5).
// The enrollment handler tests mint tokens directly, so this fixture supplies
// the grant half of that pair — the enroll/setup + confirm arms peek/consume
// it (REVISED per v7 §4: the arms are grant-gated, no bare-token enrollment).
func seedBootstrapGrant(t *testing.T, pool *pgxpool.Pool, jwt *token.JWTProvider, mfaToken string) {
	t.Helper()
	claims, err := jwt.Validate(mfaToken)
	if err != nil {
		t.Fatalf("validate fixture mfa_token: %v", err)
	}
	sum := sha256.Sum256([]byte(mfaToken))
	if _, err := pool.Exec(context.Background(),
		`DELETE FROM mfa_reauth_step_ups WHERE user_id = $1`, claims.UserID); err != nil {
		t.Fatalf("seed bootstrap grant cleanup: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO mfa_reauth_step_ups
		   (token_hash, user_id, session_jti, operation, target_ref,
		    proof_method, proving_factor_id, bound_factor_generation,
		    token_scope, refresh_family_id, expires_at)
		 VALUES ($1, $2, $3, 'bootstrap.totp.enroll', NULL,
		         'password', NULL,
		         (SELECT factor_generation FROM users WHERE id = $2),
		         'mfa_pending', NULL, now() + interval '5 minutes')`,
		hex.EncodeToString(sum[:]), claims.UserID, claims.JTI,
	); err != nil {
		t.Fatalf("seed bootstrap grant: %v", err)
	}
}

// enrollmentIDFromBody extracts the setup-issued enrollment_id (v7 §1.6).
func enrollmentIDFromBody(t *testing.T, body []byte) string {
	t.Helper()
	var parsed struct {
		EnrollmentID string `json:"enrollment_id"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || parsed.EnrollmentID == "" {
		t.Fatalf("setup body %s carries no enrollment_id (%v)", body, err)
	}
	return parsed.EnrollmentID
}

func enrollmentHandlerPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxutil.OpenPool(context.Background(), liveDSN(t), 5, enrollmentHandlerTestKey, "")
	if err != nil {
		t.Fatalf("open enrollment handler pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func ensureEnrollmentLocalDomain(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	name := fmt.Sprintf("totp-enrollment-handler-%d.test", time.Now().UnixNano())
	var domainID int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, name).Scan(&domainID); err != nil {
		t.Fatalf("create local enrollment-test domain: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM domains WHERE id = $1`, domainID)
	})
}

func postEnrollmentJSON(t *testing.T, path string, payload map[string]any, handler http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	return postEnrollmentJSONContext(t, context.Background(), path, payload, handler)
}

func postEnrollmentJSONContext(
	t *testing.T,
	ctx context.Context,
	path string,
	payload map[string]any,
	handler http.HandlerFunc,
) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal %s payload: %v", path, err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler(rr, req)
	return rr
}

// TestTOTPEnrollmentConfirm_PreservesDPoPAndCompletionCA proves the new HTTP
// completion endpoint carries both context stashes into the real issuance
// funnel. The step-up policy would write a terminal step-up response if the
// step-up marker were lost (evaluateAndRespond re-challenging mid-completion);
// the minted access token would lack cnf.jkt if the CA-login stash were lost.
// (ER5 occ_b855024: the audit-only mid-step-up carve-out is now scoped to
// remediable/step-up decisions — a fresh HARD block at completion is terminal,
// pinned by TestCompletionGate_StepUpInProgress_HardBlockIsTerminal — so this
// test uses a step-up policy to keep proving marker propagation.)
func TestTOTPEnrollmentConfirm_PreservesDPoPAndCompletionCA(t *testing.T) {
	pool := enrollmentHandlerPool(t)
	ensureEnrollmentLocalDomain(t, pool)
	userID := seedLocalUser(t, pool, "totp-enrollment-handler@example.com")
	recorder := &captureRecorder{}
	h := NewAuthHandler(AuthHandlerConfig{
		Pool:           pool,
		JWT:            newTestJWT(),
		Logger:         discardLogger(),
		PolicyEngine:   newStepUpEngine(),
		SignInRecorder: recorder,
		Toggles: toggle.NewTestFlags(map[string]bool{
			toggle.FeatureTokenBinding: true,
		}),
	})
	mfaToken, err := h.jwt.IssueMFAPending(userID, "totp-enrollment-handler@example.com")
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
		"dpop_jwk":      fakeDPoPJWK,
	}, h.TOTPEnrollmentConfirm)
	if confirm.Code != http.StatusOK {
		t.Fatalf("enrollment confirm: got %d, want 200: %s", confirm.Code, confirm.Body.String())
	}
	claims, err := h.jwt.Validate(accessTokenFromBody(t, confirm))
	if err != nil {
		t.Fatalf("validate minted access token: %v", err)
	}
	wantJKT, err := threat.JKTFromJWK(fakeDPoPJWK)
	if err != nil {
		t.Fatalf("derive expected JWK thumbprint: %v", err)
	}
	if claims.Cnf == nil || claims.Cnf.JKT != wantJKT {
		t.Fatalf("enrollment completion cnf = %+v, want jkt %q", claims.Cnf, wantJKT)
	}
	if !recorder.called {
		t.Fatal("completion must still record the Conditional Access evaluation")
	}
}

func TestTOTPEnrollmentHandlers_StatusMappings(t *testing.T) {
	pool := enrollmentHandlerPool(t)
	ensureEnrollmentLocalDomain(t, pool)
	h := NewAuthHandler(AuthHandlerConfig{
		Pool:   pool,
		JWT:    newTestJWT(),
		Logger: discardLogger(),
	})

	for _, endpoint := range []struct {
		path    string
		handler http.HandlerFunc
	}{
		{"/auth/totp/enroll/setup", h.TOTPEnrollmentSetup},
		{"/auth/totp/enroll/confirm", h.TOTPEnrollmentConfirm},
	} {
		rr := postEnrollmentJSON(t, endpoint.path, map[string]any{
			"mfa_token": "not-a-valid-token",
			"code":      "000000",
		}, endpoint.handler)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("%s invalid token: got %d, want 401", endpoint.path, rr.Code)
		}
	}

	activeID := seedLocalUser(t, pool, "totp-enrollment-active@example.com")
	if _, err := pool.Exec(context.Background(), `UPDATE users SET totp_enabled = TRUE WHERE id = $1`, activeID); err != nil {
		t.Fatalf("mark active factor: %v", err)
	}
	activeToken, err := h.jwt.IssueMFAPending(activeID, "totp-enrollment-active@example.com")
	if err != nil {
		t.Fatalf("issue active-user MFA token: %v", err)
	}
	for _, endpoint := range []struct {
		path    string
		handler http.HandlerFunc
	}{
		{"/auth/totp/enroll/setup", h.TOTPEnrollmentSetup},
		{"/auth/totp/enroll/confirm", h.TOTPEnrollmentConfirm},
	} {
		rr := postEnrollmentJSON(t, endpoint.path, map[string]any{
			"mfa_token":     activeToken,
			"code":          "000000",
			"enrollment_id": "00000000-0000-0000-0000-000000000000",
		}, endpoint.handler)
		if rr.Code != http.StatusConflict {
			t.Errorf("%s changed state: got %d, want 409: %s", endpoint.path, rr.Code, rr.Body.String())
		}
	}

	lockedID := seedLocalUser(t, pool, "totp-enrollment-locked@example.com")
	lockedToken, err := h.jwt.IssueMFAPending(lockedID, "totp-enrollment-locked@example.com")
	if err != nil {
		t.Fatalf("issue lockout-user MFA token: %v", err)
	}
	seedBootstrapGrant(t, pool, h.jwt, lockedToken)
	setup := postEnrollmentJSON(t, "/auth/totp/enroll/setup", map[string]any{
		"mfa_token": lockedToken,
	}, h.TOTPEnrollmentSetup)
	if setup.Code != http.StatusOK {
		t.Fatalf("lockout fixture setup: got %d, want 200: %s", setup.Code, setup.Body.String())
	}
	lockedEnrollmentID := enrollmentIDFromBody(t, setup.Body.Bytes())
	if _, err := pool.Exec(context.Background(),
		`UPDATE users SET totp_failed_attempts = 4 WHERE id = $1`, lockedID); err != nil {
		t.Fatalf("seed four failed attempts: %v", err)
	}
	locked := postEnrollmentJSON(t, "/auth/totp/enroll/confirm", map[string]any{
		"mfa_token":     lockedToken,
		"code":          "not-a-code",
		"enrollment_id": lockedEnrollmentID,
	}, h.TOTPEnrollmentConfirm)
	if locked.Code != http.StatusTooManyRequests {
		t.Fatalf("enrollment lockout threshold: got %d, want 429: %s", locked.Code, locked.Body.String())
	}
}

func TestFencedTOTPEnrollmentFailsClosedAtStoreAndFenceBoundaries(t *testing.T) {
	jwt := newTestJWT()
	issue := func(t *testing.T, userID int64, fence *jwtutil.IdentityFenceClaim) string {
		t.Helper()
		raw, err := jwt.IssueMFAPendingWithIdentityFence(
			userID, "fenced-boundary@example.com", fence, token.AMRPassword,
		)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	validShape := &jwtutil.IdentityFenceClaim{
		SourceID: 1, SourceGeneration: 1, LinkID: 1, LinkGeneration: 1,
	}

	closed := NewAuthHandler(AuthHandlerConfig{
		Pool: createClosedPool(t), JWT: jwt, Logger: discardLogger(),
	})
	setup := postEnrollmentJSON(t, "/auth/totp/enroll/setup", map[string]any{
		"mfa_token": issue(t, 42, validShape),
	}, closed.TOTPEnrollmentSetup)
	if setup.Code != http.StatusServiceUnavailable {
		t.Fatalf("closed setup status=%d, want 503: %s",
			setup.Code, setup.Body.String())
	}

	pool := enrollmentHandlerPool(t)
	ensureEnrollmentLocalDomain(t, pool)
	userID := seedLocalUser(t, pool, "fenced-boundary@example.com")
	live := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: jwt, Logger: discardLogger(),
	})
	invalid := &jwtutil.IdentityFenceClaim{}
	setup = postEnrollmentJSON(t, "/auth/totp/enroll/setup", map[string]any{
		"mfa_token": issue(t, userID, invalid),
	}, live.TOTPEnrollmentSetup)
	if setup.Code != http.StatusConflict {
		t.Fatalf("invalid setup fence status=%d, want 409: %s",
			setup.Code, setup.Body.String())
	}
	confirm := postEnrollmentJSON(t, "/auth/totp/enroll/confirm", map[string]any{
		"mfa_token":     issue(t, userID, invalid),
		"code":          "000000",
		"enrollment_id": "00000000-0000-0000-0000-000000000000",
	}, live.TOTPEnrollmentConfirm)
	if confirm.Code != http.StatusConflict {
		t.Fatalf("invalid confirm fence status=%d, want 409: %s",
			confirm.Code, confirm.Body.String())
	}
	missing := postEnrollmentJSON(t, "/auth/totp/enroll/confirm", map[string]any{
		"mfa_token":     issue(t, 9_223_372_036_854_000_000, validShape),
		"code":          "000000",
		"enrollment_id": "00000000-0000-0000-0000-000000000000",
	}, live.TOTPEnrollmentConfirm)
	if missing.Code != http.StatusUnauthorized {
		t.Fatalf("missing fenced user status=%d, want 401: %s",
			missing.Code, missing.Body.String())
	}
}

func TestTOTPEnrollmentCredentialFenceRejectsStalePasswordBeforeWrites(t *testing.T) {
	pool := enrollmentHandlerPool(t)
	ensureEnrollmentLocalDomain(t, pool)
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(),
	})

	issuePasswordPending := func(t *testing.T, userID int64, email string) string {
		t.Helper()
		var passwordHash string
		if err := pool.QueryRow(context.Background(),
			`SELECT password_hash FROM users WHERE id=$1`, userID,
		).Scan(&passwordHash); err != nil {
			t.Fatalf("read password hash: %v", err)
		}
		raw, err := h.jwt.IssueMFAPendingWithFences(
			userID, email, nil, credentialFenceForPasswordHash(passwordHash),
			token.AMRPassword,
		)
		if err != nil {
			t.Fatalf("issue credential-fenced MFA token: %v", err)
		}
		return raw
	}
	rotatePassword := func(t *testing.T, userID int64) {
		t.Helper()
		if _, err := pool.Exec(context.Background(),
			`UPDATE users SET password_hash=password_hash || '-rotated' WHERE id=$1`,
			userID,
		); err != nil {
			t.Fatalf("rotate password fixture: %v", err)
		}
	}

	t.Run("setup", func(t *testing.T) {
		email := "totp-stale-setup@example.com"
		userID := seedLocalUser(t, pool, email)
		pending := issuePasswordPending(t, userID, email)
		rotatePassword(t, userID)

		response := postEnrollmentJSON(t, "/auth/totp/enroll/setup", map[string]any{
			"mfa_token": pending,
		}, h.TOTPEnrollmentSetup)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("stale setup status=%d want 401: %s", response.Code, response.Body.String())
		}
		var hasSecret bool
		if err := pool.QueryRow(context.Background(),
			`SELECT totp_secret_enc IS NOT NULL FROM users WHERE id=$1`, userID,
		).Scan(&hasSecret); err != nil {
			t.Fatalf("read setup state: %v", err)
		}
		if hasSecret {
			t.Fatal("stale password proof persisted a pending TOTP secret")
		}
	})

	t.Run("confirm", func(t *testing.T) {
		email := "totp-stale-confirm@example.com"
		userID := seedLocalUser(t, pool, email)
		pending := issuePasswordPending(t, userID, email)
		seedBootstrapGrant(t, pool, h.jwt, pending)
		setup := postEnrollmentJSON(t, "/auth/totp/enroll/setup", map[string]any{
			"mfa_token": pending,
		}, h.TOTPEnrollmentSetup)
		if setup.Code != http.StatusOK {
			t.Fatalf("setup status=%d: %s", setup.Code, setup.Body.String())
		}
		enrollmentID := enrollmentIDFromBody(t, setup.Body.Bytes())
		var setupBody struct {
			ProvisioningURI string `json:"provisioning_uri"`
		}
		if err := json.Unmarshal(setup.Body.Bytes(), &setupBody); err != nil {
			t.Fatalf("decode provisioning URI: %v", err)
		}
		key, err := otp.NewKeyFromURL(setupBody.ProvisioningURI)
		if err != nil {
			t.Fatalf("parse provisioning URI: %v", err)
		}
		code, err := totp.GenerateCode(key.Secret(), time.Now())
		if err != nil {
			t.Fatalf("generate confirmation code: %v", err)
		}
		rotatePassword(t, userID)

		var anchorsBefore int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM oauth_tokens WHERE user_id=$1`, userID,
		).Scan(&anchorsBefore); err != nil {
			t.Fatalf("count anchors before confirm: %v", err)
		}
		response := postEnrollmentJSON(t, "/auth/totp/enroll/confirm", map[string]any{
			"mfa_token":     pending,
			"code":          code,
			"enrollment_id": enrollmentID,
		}, h.TOTPEnrollmentConfirm)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("stale confirm status=%d want 401: %s", response.Code, response.Body.String())
		}
		if response.Header().Get("Set-Cookie") != "" ||
			strings.Contains(response.Body.String(), "access_token") {
			t.Fatalf("stale confirm leaked session: headers=%v body=%s",
				response.Header(), response.Body.String())
		}
		var enabled bool
		var anchorsAfter int
		if err := pool.QueryRow(context.Background(),
			`SELECT COALESCE(totp_enabled,FALSE) FROM users WHERE id=$1`, userID,
		).Scan(&enabled); err != nil {
			t.Fatalf("read TOTP state after confirm: %v", err)
		}
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM oauth_tokens WHERE user_id=$1`, userID,
		).Scan(&anchorsAfter); err != nil {
			t.Fatalf("count anchors after confirm: %v", err)
		}
		if enabled || anchorsAfter != anchorsBefore {
			t.Fatalf("stale confirm committed state: enabled=%v anchors=%d want %d",
				enabled, anchorsAfter, anchorsBefore)
		}
	})

	t.Run("identity-and-stale-credential", func(t *testing.T) {
		email := "totp-stale-both@example.com"
		userID := seedLocalUser(t, pool, email)
		var mailboxID int64
		if err := pool.QueryRow(context.Background(), `
			INSERT INTO mailboxes(
				user_id,domain_id,email,display_name,type,is_primary
			)
			SELECT id,domain_id,email,display_name,'personal',TRUE
			  FROM users WHERE id=$1
			RETURNING id`,
			userID,
		).Scan(&mailboxID); err != nil {
			t.Fatalf("seed dual-fence primary mailbox: %v", err)
		}
		defer func() {
			tx, err := pool.Begin(context.Background())
			if err != nil {
				return
			}
			defer tx.Rollback(context.Background()) //nolint:errcheck
			_, _ = tx.Exec(context.Background(), `SET LOCAL session_replication_role=replica`)
			_, _ = tx.Exec(context.Background(), `DELETE FROM mailboxes WHERE id=$1`, mailboxID)
			_ = tx.Commit(context.Background())
		}()
		sourceKey := fmt.Sprintf("oidc:totp-stale-both-%d", time.Now().UnixNano())
		var sourceID, sourceGeneration int64
		if err := pool.QueryRow(context.Background(), `
			INSERT INTO identity_sources(
				source_key,display_name,kind,capabilities,state
			) VALUES(
				$1,'TOTP dual fence','oidc',
				'{"authenticate":true,"stable_immutable_subject":true}'::jsonb,
				'active'
			) RETURNING id,generation`,
			sourceKey,
		).Scan(&sourceID, &sourceGeneration); err != nil {
			t.Fatalf("seed identity source: %v", err)
		}
		var linkID, linkGeneration int64
		if err := pool.QueryRow(context.Background(), `
			INSERT INTO user_identity_links(
				user_id,source_id,external_subject,purposes,state,link_method
			) VALUES($1,$2,$3,ARRAY['authenticate'],'active','jit')
			RETURNING id,generation`,
			userID, sourceID, "subject-"+sourceKey,
		).Scan(&linkID, &linkGeneration); err != nil {
			t.Fatalf("seed identity link: %v", err)
		}
		defer func() {
			_, _ = pool.Exec(context.Background(),
				`DELETE FROM user_identity_links WHERE id=$1`, linkID)
			_, _ = pool.Exec(context.Background(),
				`DELETE FROM identity_sources WHERE id=$1`, sourceID)
		}()
		var passwordHash string
		if err := pool.QueryRow(context.Background(),
			`SELECT password_hash FROM users WHERE id=$1`, userID,
		).Scan(&passwordHash); err != nil {
			t.Fatalf("read password hash: %v", err)
		}
		pending, err := h.jwt.IssueMFAPendingWithFences(
			userID, email,
			&jwtutil.IdentityFenceClaim{
				SourceID: sourceID, SourceGeneration: sourceGeneration,
				LinkID: linkID, LinkGeneration: linkGeneration,
			},
			credentialFenceForPasswordHash(passwordHash), token.AMRPassword,
		)
		if err != nil {
			t.Fatalf("issue dual-fenced MFA token: %v", err)
		}
		rotatePassword(t, userID)
		response := postEnrollmentJSON(t, "/auth/totp/enroll/setup", map[string]any{
			"mfa_token": pending,
		}, h.TOTPEnrollmentSetup)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("dual-fence stale setup status=%d want 401: %s",
				response.Code, response.Body.String())
		}
		var hasSecret bool
		if err := pool.QueryRow(context.Background(),
			`SELECT totp_secret_enc IS NOT NULL FROM users WHERE id=$1`, userID,
		).Scan(&hasSecret); err != nil {
			t.Fatalf("read dual-fence setup state: %v", err)
		}
		if hasSecret {
			t.Fatal("dual-fence stale proof persisted a pending TOTP secret")
		}
	})
}

func TestTOTPEnrollmentConfirmCommitFailureRollsBackCredentialAndFamily(t *testing.T) {
	pool := enrollmentHandlerPool(t)
	ensureEnrollmentLocalDomain(t, pool)
	email := "totp-confirm-commit-failure@example.com"
	userID := seedLocalUser(t, pool, email)
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(),
	})
	var passwordHash string
	if err := pool.QueryRow(context.Background(),
		`SELECT password_hash FROM users WHERE id=$1`, userID,
	).Scan(&passwordHash); err != nil {
		t.Fatalf("read password hash: %v", err)
	}
	pending, err := h.jwt.IssueMFAPendingWithFences(
		userID, email, nil, credentialFenceForPasswordHash(passwordHash),
		token.AMRPassword,
	)
	if err != nil {
		t.Fatalf("issue credential-fenced MFA token: %v", err)
	}
	seedBootstrapGrant(t, pool, h.jwt, pending)
	setup := postEnrollmentJSON(t, "/auth/totp/enroll/setup", map[string]any{
		"mfa_token": pending,
	}, h.TOTPEnrollmentSetup)
	if setup.Code != http.StatusOK {
		t.Fatalf("setup status=%d: %s", setup.Code, setup.Body.String())
	}
	enrollmentID := enrollmentIDFromBody(t, setup.Body.Bytes())
	var setupBody struct {
		ProvisioningURI string `json:"provisioning_uri"`
	}
	if err := json.Unmarshal(setup.Body.Bytes(), &setupBody); err != nil {
		t.Fatalf("decode setup: %v", err)
	}
	key, err := otp.NewKeyFromURL(setupBody.ProvisioningURI)
	if err != nil {
		t.Fatalf("parse provisioning URI: %v", err)
	}
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("generate confirmation code: %v", err)
	}
	var pendingSecretBefore []byte
	if err := pool.QueryRow(context.Background(),
		`SELECT totp_secret_enc FROM users WHERE id=$1`, userID,
	).Scan(&pendingSecretBefore); err != nil {
		t.Fatalf("read pending secret before confirm: %v", err)
	}

	suffix := randSuffix()
	functionName := "test_totp_commit_fail_" + suffix
	triggerName := "test_totp_commit_fail_trigger_" + suffix
	if _, err := pool.Exec(context.Background(), fmt.Sprintf(`
		CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $fn$
		BEGIN
			IF NEW.user_id = %d THEN
				RAISE EXCEPTION 'injected deferred TOTP commit failure' USING ERRCODE='40001';
			END IF;
			RETURN NEW;
		END
		$fn$;
		CREATE CONSTRAINT TRIGGER %s
		AFTER INSERT ON oauth_tokens
		DEFERRABLE INITIALLY DEFERRED
		FOR EACH ROW EXECUTE FUNCTION %s()`,
		functionName, userID, triggerName, functionName,
	)); err != nil {
		t.Fatalf("install deferred commit failure: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), fmt.Sprintf(
			`DROP TRIGGER IF EXISTS %s ON oauth_tokens; DROP FUNCTION IF EXISTS %s()`,
			triggerName, functionName,
		))
	})

	response := postEnrollmentJSON(t, "/auth/totp/enroll/confirm", map[string]any{
		"mfa_token":     pending,
		"code":          code,
		"enrollment_id": enrollmentID,
	}, h.TOTPEnrollmentConfirm)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("commit-failed confirm status=%d want 503: %s",
			response.Code, response.Body.String())
	}
	if response.Header().Get("Set-Cookie") != "" ||
		strings.Contains(response.Body.String(), "access_token") ||
		strings.Contains(response.Body.String(), "refresh_token") {
		t.Fatalf("commit-failed confirm leaked session: headers=%v body=%s",
			response.Header(), response.Body.String())
	}
	var (
		enabled            bool
		pendingSecretAfter []byte
		anchors            int
	)
	if err := pool.QueryRow(context.Background(),
		`SELECT COALESCE(totp_enabled,FALSE),totp_secret_enc FROM users WHERE id=$1`,
		userID,
	).Scan(&enabled, &pendingSecretAfter); err != nil {
		t.Fatalf("read TOTP state after commit failure: %v", err)
	}
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM oauth_tokens WHERE user_id=$1`, userID,
	).Scan(&anchors); err != nil {
		t.Fatalf("count anchors after commit failure: %v", err)
	}
	if enabled || !bytes.Equal(pendingSecretAfter, pendingSecretBefore) || anchors != 0 {
		t.Fatalf("commit failure changed durable state: enabled=%v secret_changed=%v anchors=%d",
			enabled, !bytes.Equal(pendingSecretAfter, pendingSecretBefore), anchors)
	}
}

func TestNormalizedSSOEnrollmentFencesCredentialWrites(t *testing.T) {
	pool := enrollmentHandlerPool(t)
	ensureEnrollmentLocalDomain(t, pool)
	email := "totp-enrollment-fence@example.com"
	userID := seedLocalUser(t, pool, email)
	var mailboxID int64
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO mailboxes(
			user_id,domain_id,email,display_name,type,is_primary
		)
		SELECT id,domain_id,email,display_name,'personal',TRUE
		  FROM users WHERE id=$1
		RETURNING id`,
		userID,
	).Scan(&mailboxID); err != nil {
		t.Fatalf("seed normalized primary mailbox: %v", err)
	}
	t.Cleanup(func() {
		tx, err := pool.Begin(context.Background())
		if err != nil {
			return
		}
		defer tx.Rollback(context.Background()) //nolint:errcheck
		_, _ = tx.Exec(context.Background(),
			`SET LOCAL session_replication_role=replica`)
		_, _ = tx.Exec(context.Background(),
			`DELETE FROM mailboxes WHERE id=$1`, mailboxID)
		_ = tx.Commit(context.Background())
	})
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(),
	})

	sourceKey := fmt.Sprintf("oidc:totp-enrollment-fence-%d", time.Now().UnixNano())
	var sourceID, sourceGeneration int64
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO identity_sources(
			source_key,display_name,kind,capabilities,state
		) VALUES(
			$1,'TOTP enrollment fence','oidc',
			'{"authenticate":true,"stable_immutable_subject":true}'::jsonb,
			'active'
		) RETURNING id,generation`,
		sourceKey,
	).Scan(&sourceID, &sourceGeneration); err != nil {
		t.Fatalf("seed normalized source: %v", err)
	}
	var linkID, linkGeneration int64
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO user_identity_links(
			user_id,source_id,external_subject,purposes,state,link_method
		) VALUES($1,$2,$3,ARRAY['authenticate'],'active','jit')
		RETURNING id,generation`,
		userID, sourceID, "subject-"+sourceKey,
	).Scan(&linkID, &linkGeneration); err != nil {
		t.Fatalf("seed normalized link: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM user_identity_links WHERE id=$1`, linkID)
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM identity_sources WHERE id=$1`, sourceID)
	})

	issuePending := func(generation int64) string {
		t.Helper()
		value, err := h.jwt.IssueMFAPendingWithIdentityFence(
			userID,
			email,
			&jwtutil.IdentityFenceClaim{
				SourceID:         sourceID,
				SourceGeneration: generation,
				LinkID:           linkID,
				LinkGeneration:   linkGeneration,
			},
			token.AMRPassword,
		)
		if err != nil {
			t.Fatalf("issue identity-fenced MFA token: %v", err)
		}
		return value
	}

	if err := pool.QueryRow(context.Background(),
		`UPDATE identity_sources SET state='paused' WHERE id=$1 RETURNING generation`,
		sourceID,
	).Scan(&sourceGeneration); err != nil {
		t.Fatalf("pause source before setup: %v", err)
	}
	rejectedSetup := postEnrollmentJSON(t, "/auth/totp/enroll/setup", map[string]any{
		"mfa_token": issuePending(sourceGeneration),
	}, h.TOTPEnrollmentSetup)
	if rejectedSetup.Code == http.StatusOK {
		t.Fatalf("paused source setup unexpectedly succeeded: %s", rejectedSetup.Body.String())
	}
	var hasSecret bool
	if err := pool.QueryRow(context.Background(),
		`SELECT totp_secret_enc IS NOT NULL FROM users WHERE id=$1`, userID,
	).Scan(&hasSecret); err != nil {
		t.Fatalf("read pending secret state: %v", err)
	}
	if hasSecret {
		t.Fatal("rejected normalized setup persisted a pending TOTP secret")
	}

	if err := pool.QueryRow(context.Background(),
		`UPDATE identity_sources SET state='active' WHERE id=$1 RETURNING generation`,
		sourceID,
	).Scan(&sourceGeneration); err != nil {
		t.Fatalf("reactivate source for setup: %v", err)
	}
	activeToken := issuePending(sourceGeneration)
	seedBootstrapGrant(t, pool, h.jwt, activeToken)
	setup := postEnrollmentJSON(t, "/auth/totp/enroll/setup", map[string]any{
		"mfa_token": activeToken,
	}, h.TOTPEnrollmentSetup)
	if setup.Code != http.StatusOK {
		t.Fatalf("active normalized setup status=%d body=%s",
			setup.Code, setup.Body.String())
	}
	activeEnrollmentID := enrollmentIDFromBody(t, setup.Body.Bytes())
	var setupBody struct {
		ProvisioningURI string `json:"provisioning_uri"`
	}
	if err := json.Unmarshal(setup.Body.Bytes(), &setupBody); err != nil {
		t.Fatalf("decode active setup: %v", err)
	}
	key, err := otp.NewKeyFromURL(setupBody.ProvisioningURI)
	if err != nil {
		t.Fatalf("parse active provisioning URI: %v", err)
	}
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("generate active enrollment code: %v", err)
	}
	wrongKeyPool, err := pgxutil.OpenPool(
		context.Background(), liveDSN(t), 2,
		"wrong-totp-encryption-key-32ch", "",
	)
	if err != nil {
		t.Fatalf("open wrong-key enrollment pool: %v", err)
	}
	t.Cleanup(wrongKeyPool.Close)
	wrongKeyHandler := NewAuthHandler(AuthHandlerConfig{
		Pool: wrongKeyPool, JWT: h.jwt, Logger: discardLogger(),
	})
	decryptFailure := postEnrollmentJSON(t, "/auth/totp/enroll/confirm", map[string]any{
		"mfa_token":     activeToken,
		"code":          code,
		"enrollment_id": activeEnrollmentID,
	}, wrongKeyHandler.TOTPEnrollmentConfirm)
	if decryptFailure.Code != http.StatusInternalServerError {
		t.Fatalf("wrong-key fenced confirm status=%d, want 500: %s",
			decryptFailure.Code, decryptFailure.Body.String())
	}
	invalid := postEnrollmentJSON(t, "/auth/totp/enroll/confirm", map[string]any{
		"mfa_token":     activeToken,
		"code":          "not-a-code",
		"enrollment_id": activeEnrollmentID,
	}, h.TOTPEnrollmentConfirm)
	if invalid.Code != http.StatusUnauthorized {
		t.Fatalf("invalid fenced confirm status=%d, want 401: %s",
			invalid.Code, invalid.Body.String())
	}
	if _, err := pool.Exec(context.Background(),
		`UPDATE users SET totp_failed_attempts=4,totp_locked_until=NULL WHERE id=$1`,
		userID,
	); err != nil {
		t.Fatalf("seed fenced lockout threshold: %v", err)
	}
	locked := postEnrollmentJSON(t, "/auth/totp/enroll/confirm", map[string]any{
		"mfa_token":     activeToken,
		"code":          "not-a-code",
		"enrollment_id": activeEnrollmentID,
	}, h.TOTPEnrollmentConfirm)
	if locked.Code != http.StatusTooManyRequests {
		t.Fatalf("locked fenced confirm status=%d, want 429: %s",
			locked.Code, locked.Body.String())
	}
	if _, err := pool.Exec(context.Background(),
		`UPDATE users SET totp_failed_attempts=0,totp_locked_until=NULL WHERE id=$1`,
		userID,
	); err != nil {
		t.Fatalf("reset fenced lockout fixture: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`UPDATE identity_sources SET state='paused' WHERE id=$1`, sourceID,
	); err != nil {
		t.Fatalf("pause source before confirm: %v", err)
	}
	rejectedConfirm := postEnrollmentJSON(t, "/auth/totp/enroll/confirm", map[string]any{
		"mfa_token":     activeToken,
		"code":          code,
		"enrollment_id": activeEnrollmentID,
	}, h.TOTPEnrollmentConfirm)
	if rejectedConfirm.Code == http.StatusOK {
		t.Fatalf("paused source confirm unexpectedly succeeded: %s",
			rejectedConfirm.Body.String())
	}
	var enabled bool
	if err := pool.QueryRow(context.Background(),
		`SELECT COALESCE(totp_enabled,FALSE) FROM users WHERE id=$1`, userID,
	).Scan(&enabled); err != nil {
		t.Fatalf("read TOTP enabled state: %v", err)
	}
	if enabled {
		t.Fatal("rejected normalized confirm installed a durable TOTP credential")
	}

	if err := pool.QueryRow(context.Background(),
		`UPDATE identity_sources SET state='active' WHERE id=$1 RETURNING generation`,
		sourceID,
	).Scan(&sourceGeneration); err != nil {
		t.Fatalf("reactivate source for successful confirm: %v", err)
	}
	// The success confirm presents a FRESH grant+enrollment pair (v7 §1.6):
	// the new token's grant is fixture-seeded and a new setup binds it to a
	// new staged enrollment, replacing the abandoned one.
	successToken := issuePending(sourceGeneration)
	seedBootstrapGrant(t, pool, h.jwt, successToken)
	successSetup := postEnrollmentJSON(t, "/auth/totp/enroll/setup", map[string]any{
		"mfa_token": successToken,
	}, h.TOTPEnrollmentSetup)
	if successSetup.Code != http.StatusOK {
		t.Fatalf("success setup status=%d body=%s", successSetup.Code, successSetup.Body.String())
	}
	successEnrollmentID := enrollmentIDFromBody(t, successSetup.Body.Bytes())
	// v7 §1.6: the re-stage mints a NEW pending secret — derive the
	// confirmation code from the FRESH provisioning URI, not the abandoned one.
	var successSetupBody struct {
		ProvisioningURI string `json:"provisioning_uri"`
	}
	if err := json.Unmarshal(successSetup.Body.Bytes(), &successSetupBody); err != nil {
		t.Fatalf("decode success setup: %v", err)
	}
	successKey, err := otp.NewKeyFromURL(successSetupBody.ProvisioningURI)
	if err != nil {
		t.Fatalf("parse success provisioning URI: %v", err)
	}
	code, err = totp.GenerateCode(successKey.Secret(), time.Now())
	if err != nil {
		t.Fatalf("generate success enrollment code: %v", err)
	}
	successCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	success := postEnrollmentJSONContext(
		t,
		successCtx,
		"/auth/totp/enroll/confirm",
		map[string]any{
			"mfa_token":     successToken,
			"code":          code,
			"enrollment_id": successEnrollmentID,
		},
		h.TOTPEnrollmentConfirm,
	)
	if success.Code != http.StatusOK {
		t.Fatalf("active normalized confirm status=%d body=%s",
			success.Code, success.Body.String())
	}
	if err := pool.QueryRow(context.Background(),
		`SELECT COALESCE(totp_enabled,FALSE) FROM users WHERE id=$1`, userID,
	).Scan(&enabled); err != nil {
		t.Fatalf("read successful TOTP state: %v", err)
	}
	if !enabled {
		t.Fatal("successful normalized confirm did not install the TOTP credential")
	}
	if _, err := pool.Exec(context.Background(),
		`UPDATE users SET last_totp_used_at=NULL WHERE id=$1`, userID,
	); err != nil {
		t.Fatalf("reset replay marker for TOTP verify: %v", err)
	}
	// A fresh code from the CURRENT secret, minted close to the verify call
	// so the RFC 6238 window cannot lapse under a loaded parallel suite.
	code, err = totp.GenerateCode(successKey.Secret(), time.Now())
	if err != nil {
		t.Fatalf("generate verify code: %v", err)
	}
	verify := postEnrollmentJSON(t, "/auth/totp/verify", map[string]any{
		"mfa_token": issuePending(sourceGeneration),
		"code":      code,
	}, h.TOTPVerify)
	if verify.Code != http.StatusOK {
		// Diagnose the cycle verdict from durable state (which leg refused).
		var diag struct {
			Attempts   int
			Locked     bool
			ReplayNULL bool
			Decrypts   bool
		}
		_ = pool.QueryRow(context.Background(), `
			SELECT COALESCE(totp_failed_attempts,-1),
			       totp_locked_until IS NOT NULL,
			       last_totp_used_at IS NULL,
			       totp_secret_enc IS NOT NULL`,
			userID).Scan(&diag.Attempts, &diag.Locked, &diag.ReplayNULL, &diag.Decrypts)
		t.Fatalf("active normalized TOTP verify status=%d, want 200: %s | diag=%+v code=%s",
			verify.Code, verify.Body.String(), diag, code)
	}
	alreadyActive := postEnrollmentJSON(t, "/auth/totp/enroll/confirm", map[string]any{
		"mfa_token":     issuePending(sourceGeneration),
		"code":          code,
		"enrollment_id": "00000000-0000-0000-0000-000000000000",
	}, h.TOTPEnrollmentConfirm)
	if alreadyActive.Code != http.StatusConflict {
		t.Fatalf("already-active fenced confirm status=%d, want 409: %s",
			alreadyActive.Code, alreadyActive.Body.String())
	}
}
