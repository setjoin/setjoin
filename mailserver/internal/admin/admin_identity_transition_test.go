package admin

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

func TestIdentityTransitionApprovalIDPreservesExactDecimalStrings(t *testing.T) {
	t.Parallel()
	large := strconv.FormatInt(math.MaxInt64, 10)
	tests := []struct {
		name string
		raw  *string
		want int64
		ok   bool
	}{
		{"absent", nil, 0, true},
		{"ordinary", ptr("17"), 17, true},
		{"above javascript safe integer", ptr("9007199254740993"), 9007199254740993, true},
		{"max int64", &large, math.MaxInt64, true},
		{"zero", ptr("0"), 0, false},
		{"leading zero", ptr("01"), 0, false},
		{"negative", ptr("-1"), 0, false},
		{"fraction", ptr("1.0"), 0, false},
		{"overflow", ptr("9223372036854775808"), 0, false},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, ok := identityTransitionApprovalID(test.raw)
			if ok != test.ok {
				t.Fatalf("ok=%v, want %v", ok, test.ok)
			}
			if test.raw == nil {
				if got != nil {
					t.Fatalf("absent id=%v, want nil", got)
				}
				return
			}
			if test.ok && (got == nil || *got != test.want) {
				t.Fatalf("id=%v, want %d", got, test.want)
			}
		})
	}
}

func ptr(value string) *string { return &value }

func TestIdentityTransitionStepUpBindingsRequireFreshTwoFactorSession(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	transitionID := uuid.MustParse("10000000-0000-4000-8000-000000000001")
	challengeID := uuid.MustParse("20000000-0000-4000-8000-000000000002")
	digest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	valid := &jwtutil.Claims{
		UserID: 42,
		JTI:    "verified-session-jti",
		ACR:    jwtutil.ACRAAL2,
		AMR: []string{
			jwtutil.AMRMultiFactor,
			jwtutil.AMROTP,
			jwtutil.AMRPassword,
		},
	}
	valid.IssuedAt = jwtutil.NewNumericDate(now.Add(-time.Minute))

	session, factors, amr, ok := identityTransitionStepUpBindings(
		valid, transitionID, challengeID, digest, now,
	)
	if !ok {
		t.Fatal("fresh two-factor AAL2 session was rejected")
	}
	if session == ([32]byte{}) || factors == ([32]byte{}) {
		t.Fatal("step-up bindings must be non-zero digests")
	}
	if len(amr) != 3 || amr[0] != jwtutil.AMRMultiFactor ||
		amr[1] != jwtutil.AMROTP || amr[2] != jwtutil.AMRPassword {
		t.Fatalf("canonical AMR = %v", amr)
	}

	tests := []struct {
		name   string
		mutate func(*jwtutil.Claims)
	}{
		{"missing jti", func(c *jwtutil.Claims) { c.JTI = "" }},
		{"aal1", func(c *jwtutil.Claims) { c.ACR = jwtutil.ACRAAL1 }},
		{"one factor", func(c *jwtutil.Claims) {
			c.AMR = []string{jwtutil.AMRMultiFactor, jwtutil.AMRPassword}
		}},
		{"missing mfa marker", func(c *jwtutil.Claims) {
			c.AMR = []string{jwtutil.AMRPassword, jwtutil.AMROTP}
		}},
		{"stale session", func(c *jwtutil.Claims) {
			c.IssuedAt = jwtutil.NewNumericDate(now.Add(-jwtutil.CurrentFreshAAL2MaxAge - time.Second))
		}},
		{"future session", func(c *jwtutil.Claims) {
			c.IssuedAt = jwtutil.NewNumericDate(now.Add(time.Minute))
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			copyClaims := *valid
			copyClaims.AMR = append([]string(nil), valid.AMR...)
			test.mutate(&copyClaims)
			if _, _, _, accepted := identityTransitionStepUpBindings(
				&copyClaims, transitionID, challengeID, digest, now,
			); accepted {
				t.Fatalf("%s step-up was accepted", test.name)
			}
		})
	}
}

func TestIdentityTransitionStepUpBindingsAreScopeBoundAndDeterministic(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	claims := &jwtutil.Claims{
		UserID: 7,
		JTI:    "jti-7",
		ACR:    jwtutil.ACRAAL2,
		AMR: []string{
			jwtutil.AMRPassword,
			jwtutil.AMRMultiFactor,
			jwtutil.AMROTP,
			jwtutil.AMROTP,
		},
	}
	claims.IssuedAt = jwtutil.NewNumericDate(now.Add(-time.Minute))
	transitionID := uuid.MustParse("30000000-0000-4000-8000-000000000003")
	challengeID := uuid.MustParse("40000000-0000-4000-8000-000000000004")
	digest := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	session1, factors1, amr1, ok := identityTransitionStepUpBindings(
		claims, transitionID, challengeID, digest, now,
	)
	if !ok {
		t.Fatal("valid step-up was rejected")
	}
	reordered := *claims
	reordered.AMR = []string{
		jwtutil.AMROTP,
		jwtutil.AMRPassword,
		jwtutil.AMRMultiFactor,
	}
	session2, factors2, amr2, ok := identityTransitionStepUpBindings(
		&reordered, transitionID, challengeID, digest, now,
	)
	if !ok || session1 != session2 || factors1 != factors2 {
		t.Fatalf("canonicalized bindings differ: amr %v vs %v", amr1, amr2)
	}
	_, differentFactors, _, ok := identityTransitionStepUpBindings(
		claims, transitionID, uuid.New(), digest, now,
	)
	if !ok || differentFactors == factors1 {
		t.Fatal("factor digest must be challenge-bound")
	}
}

func TestIdentityTransitionHTTPFencesFailClosedBeforeDatabase(t *testing.T) {
	h := NewIdentityHandler(nil, nil, testsupport.TestLogger())
	transitionID := uuid.NewString()
	digest := strings.Repeat("a", 64)
	reason := "identity transition HTTP fence test"
	elevationID := uuid.NewString()
	key := uuid.NewString()
	request := func(method, path, body string) *http.Request {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.SetPathValue("id", transitionID)
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
			UserID:            42,
			IsAdmin:           true,
			Permissions:       permissions.AllPermissions,
			GlobalPermissions: permissions.AllPermissions,
		}))
		req.Header.Set("X-Audit-Reason", reason)
		return req
	}
	call := func(
		handler func(http.ResponseWriter, *http.Request),
		req *http.Request,
		want int,
	) {
		t.Helper()
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Code != want {
			t.Fatalf("%s %s: status=%d want=%d body=%s",
				req.Method, req.URL.Path, rec.Code, want, rec.Body.String())
		}
	}

	badID := request(http.MethodGet, "/admin/identity/v2/transitions/bad", "")
	badID.SetPathValue("id", "bad")
	call(h.IdentityTransition, badID, http.StatusBadRequest)

	read := request(http.MethodGet,
		"/admin/identity/v2/transitions/"+transitionID, "")
	call(h.IdentityTransition, read, http.StatusServiceUnavailable)

	challenge := request(http.MethodPost,
		"/admin/identity/v2/transitions/"+transitionID+"/challenge",
		`{"previewDigest":"bad","idempotencyKey":"`+key+`"}`)
	call(h.TransitionChallengeIssue, challenge, http.StatusBadRequest)

	complete := request(http.MethodPost,
		"/admin/identity/v2/transitions/"+transitionID+"/challenge:complete",
		`{"challengeId":"bad","previewDigest":"`+digest+
			`","idempotencyKey":"`+key+`"}`)
	complete.Header.Set("If-Match", `"`+digest+`"`)
	call(h.TransitionChallengeComplete, complete, http.StatusBadRequest)

	for name, handler := range map[string]func(http.ResponseWriter, *http.Request){
		"request":  h.TransitionRequest,
		"approve":  h.TransitionApprove,
		"deny":     h.TransitionDeny,
		"execute":  h.TransitionExecuteAuthorized,
		"rollback": h.TransitionRollback,
	} {
		t.Run(name, func(t *testing.T) {
			body := `{"previewDigest":"` + digest +
				`","elevationId":"bad","reason":"` + reason +
				`","idempotencyKey":"` + key + `"}`
			req := request(http.MethodPost,
				"/admin/identity/v2/transitions/"+transitionID+":"+name, body)
			req.Header.Set("If-Match", `"`+digest+`"`)
			call(handler, req, http.StatusBadRequest)
		})
	}
	rollbackWithoutApproval := request(http.MethodPost,
		"/admin/identity/v2/transitions/"+transitionID+":rollback",
		`{"previewDigest":"`+digest+`","elevationId":"`+elevationID+
			`","reason":"`+reason+`","idempotencyKey":"`+key+`"}`)
	rollbackWithoutApproval.Header.Set("If-Match", `"`+digest+`"`)
	call(h.TransitionRollback, rollbackWithoutApproval, http.StatusBadRequest)

	for name, handler := range map[string]func(http.ResponseWriter, *http.Request){
		"cancel":           h.TransitionCancel,
		"rollback-preview": h.TransitionRollbackPreview,
	} {
		t.Run(name, func(t *testing.T) {
			req := request(http.MethodPost,
				"/admin/identity/v2/transitions/"+transitionID+":"+name,
				`{"expectedGeneration":"1","reason":"`+reason+
					`","idempotencyKey":"`+key+`"}`)
			req.Header.Set("Idempotency-Key", key)
			call(handler, req, http.StatusPreconditionFailed)
		})
	}

	retry := request(http.MethodPost,
		"/admin/identity/v2/transitions/"+transitionID+"/effects/bad:retry",
		`{"expectedGeneration":"1","reason":"`+reason+
			`","idempotencyKey":"`+key+`"}`)
	retry.SetPathValue("effectId", "bad")
	call(h.TransitionRetry, retry, http.StatusBadRequest)

	mutationReq := request(http.MethodPost, "/", "")
	mutationReq.Header.Set("Idempotency-Key", key)
	mutationRec := httptest.NewRecorder()
	if got, ok := identityTransitionMutationKey(mutationRec, mutationReq, key); !ok || got.String() != key {
		t.Fatalf("valid transition mutation key rejected: %v %v", got, ok)
	}
	generationReq := request(http.MethodPost, "/", "")
	generationReq.Header.Set("If-Match", `"7"`)
	generationRec := httptest.NewRecorder()
	if got, ok := identityTransitionGenerationFence(
		generationRec, generationReq, "7",
	); !ok || got != 7 {
		t.Fatalf("valid transition generation rejected: %d %v", got, ok)
	}
	digestReq := request(http.MethodPost, "/", "")
	digestReq.Header.Set("If-Match", `"`+digest+`"`)
	digestRec := httptest.NewRecorder()
	if !identityTransitionDigestFence(digestRec, digestReq, digest) {
		t.Fatalf("valid transition digest rejected: %s", digestRec.Body.String())
	}

	validResult := httptest.NewRecorder()
	writeIdentityTransitionResult(validResult, request(http.MethodPost, "/", ""),
		http.StatusAccepted, json.RawMessage(`{"transitionGeneration":"3"}`))
	if validResult.Code != http.StatusAccepted ||
		validResult.Header().Get("ETag") != `"3"` {
		t.Fatalf("valid transition result: status=%d etag=%q body=%s",
			validResult.Code, validResult.Header().Get("ETag"), validResult.Body.String())
	}
	for name, raw := range map[string]string{
		"invalid JSON":       `{`,
		"invalid generation": `{"transitionGeneration":"0"}`,
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeIdentityTransitionResult(rec, request(http.MethodPost, "/", ""),
				http.StatusOK, json.RawMessage(raw))
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("invalid transition result status=%d body=%s",
					rec.Code, rec.Body.String())
			}
		})
	}
	notFound := httptest.NewRecorder()
	writeIdentityTransitionReducerError(notFound, request(http.MethodPost, "/", ""),
		pgx.ErrNoRows, "transition failed")
	if notFound.Code != http.StatusNotFound {
		t.Fatalf("missing transition status=%d body=%s",
			notFound.Code, notFound.Body.String())
	}
	internal := httptest.NewRecorder()
	writeIdentityTransitionReducerError(internal, request(http.MethodPost, "/", ""),
		errors.New("unclassified"), "transition failed")
	if internal.Code != http.StatusInternalServerError {
		t.Fatalf("unclassified transition status=%d body=%s",
			internal.Code, internal.Body.String())
	}
}

func TestIdentityTransitionLocalAuthorizationAndFenceMatrix(t *testing.T) {
	h := NewIdentityHandler(nil, nil, testsupport.TestLogger())
	transitionID := uuid.NewString()
	effectID := uuid.NewString()

	for name, handler := range map[string]func(http.ResponseWriter, *http.Request){
		"read":             h.IdentityTransition,
		"challenge issue":  h.TransitionChallengeIssue,
		"challenge finish": h.TransitionChallengeComplete,
		"request":          h.TransitionRequest,
		"approve":          h.TransitionApprove,
		"deny":             h.TransitionDeny,
		"execute":          h.TransitionExecuteAuthorized,
		"rollback":         h.TransitionRollback,
		"cancel":           h.TransitionCancel,
		"rollback preview": h.TransitionRollbackPreview,
		"retry":            h.TransitionRetry,
	} {
		t.Run(name+" unauthenticated", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
			req.SetPathValue("id", transitionID)
			req.SetPathValue("effectId", effectID)
			rec := httptest.NewRecorder()
			handler(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}

	mutationReq := httptest.NewRequest(http.MethodPost, "/", nil)
	mutationReq.Header.Set("Idempotency-Key", "bad")
	mutationRec := httptest.NewRecorder()
	if _, ok := identityTransitionMutationKey(mutationRec, mutationReq, "bad"); ok ||
		mutationRec.Code != http.StatusBadRequest {
		t.Fatalf("invalid mutation UUID status=%d body=%s",
			mutationRec.Code, mutationRec.Body.String())
	}
	for name, req := range map[string]*http.Request{
		"missing header": httptest.NewRequest(http.MethodPost, "/", nil),
		"mismatched header": func() *http.Request {
			request := httptest.NewRequest(http.MethodPost, "/", nil)
			request.Header.Set("Idempotency-Key", uuid.NewString())
			return request
		}(),
	} {
		t.Run("mutation key "+name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			if _, ok := identityTransitionMutationKey(
				rec, req, uuid.NewString(),
			); ok || rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}

	digest := strings.Repeat("b", 64)
	badDigestRec := httptest.NewRecorder()
	if identityTransitionDigestFence(badDigestRec,
		httptest.NewRequest(http.MethodPost, "/", nil), "bad") ||
		badDigestRec.Code != http.StatusBadRequest {
		t.Fatalf("invalid digest status=%d body=%s",
			badDigestRec.Code, badDigestRec.Body.String())
	}
	staleDigestReq := httptest.NewRequest(http.MethodPost, "/", nil)
	staleDigestReq.Header.Set("If-Match", `"`+strings.Repeat("c", 64)+`"`)
	staleDigestRec := httptest.NewRecorder()
	if identityTransitionDigestFence(staleDigestRec, staleDigestReq, digest) ||
		staleDigestRec.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale digest status=%d body=%s",
			staleDigestRec.Code, staleDigestRec.Body.String())
	}

	invalidGenerationRec := httptest.NewRecorder()
	if _, ok := identityTransitionGenerationFence(invalidGenerationRec,
		httptest.NewRequest(http.MethodPost, "/", nil), "0"); ok ||
		invalidGenerationRec.Code != http.StatusBadRequest {
		t.Fatalf("invalid generation status=%d body=%s",
			invalidGenerationRec.Code, invalidGenerationRec.Body.String())
	}

	pool := testsupport.OpenTestPool(t)
	dbHandler := NewIdentityHandler(pool, pool, testsupport.TestLogger())
	missing := identityV2RequestWithActor(http.MethodGet, "/transitions/"+transitionID, "")
	missing.SetPathValue("id", transitionID)
	missingRec := httptest.NewRecorder()
	dbHandler.IdentityTransition(missingRec, missing)
	if missingRec.Code != http.StatusNotFound {
		t.Fatalf("missing transition status=%d body=%s",
			missingRec.Code, missingRec.Body.String())
	}

	for name, handler := range map[string]func(http.ResponseWriter, *http.Request){
		"read":             dbHandler.IdentityTransition,
		"challenge issue":  dbHandler.TransitionChallengeIssue,
		"challenge finish": dbHandler.TransitionChallengeComplete,
		"request":          dbHandler.TransitionRequest,
		"cancel":           dbHandler.TransitionCancel,
		"retry":            dbHandler.TransitionRetry,
	} {
		t.Run(name+" invalid authenticated path", func(t *testing.T) {
			req := identityV2RequestWithActor(http.MethodPost, "/", `{}`)
			req.SetPathValue("id", "bad")
			req.SetPathValue("effectId", uuid.NewString())
			rec := httptest.NewRecorder()
			handler(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}

	now := time.Now()
	claims := &jwtutil.Claims{
		UserID: 42, JTI: "step-up-with-empty-method",
		ACR: jwtutil.ACRAAL2,
		AMR: []string{
			"", jwtutil.AMRMultiFactor, jwtutil.AMRPassword, jwtutil.AMROTP,
		},
	}
	claims.IssuedAt = jwtutil.NewNumericDate(now.Add(-time.Minute))
	if _, _, amr, ok := identityTransitionStepUpBindings(
		claims, uuid.New(), uuid.New(), strings.Repeat("a", 64), now,
	); !ok || len(amr) != 3 {
		t.Fatalf("valid step-up with ignored empty method rejected: ok=%v amr=%v",
			ok, amr)
	}
}

func TestIdentityTransitionProtocolHandlersWithReducers(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	suffix := strings.ToLower(uuid.NewString()[:8])

	var actorMailbox, targetMailbox, actorID, targetID int64
	if err := pool.QueryRow(ctx, `SELECT mk_account($1)`,
		"identity-transition-actor-"+suffix).Scan(&actorMailbox); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT mk_account($1)`,
		"identity-transition-target-"+suffix).Scan(&targetMailbox); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT user_id FROM mailboxes WHERE id=$1`, actorMailbox,
	).Scan(&actorID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT user_id FROM mailboxes WHERE id=$1`, targetMailbox,
	).Scan(&targetID); err != nil {
		t.Fatal(err)
	}
	var roleID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO admin_role_groups(name,permissions)
		VALUES($1,ARRAY['users.read','identity.write','audit.export','system.upgrade'])
		RETURNING id
	`, "identity-transition-"+suffix).Scan(&roleID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by)
		VALUES($1,$2,$1)
	`, actorID, roleID); err != nil {
		t.Fatal(err)
	}
	var sourceID, linkID int64
	sourceKey := "transition-" + suffix
	if err := pool.QueryRow(ctx, `
		INSERT INTO identity_sources(
			source_key,display_name,kind,capabilities,state,generation
		) VALUES (
			$1,$2,'ldap',
			'{"authenticate":false,"provision_lifecycle":true,"stable_immutable_subject":true}'::jsonb,
			'active',1
		) RETURNING id
	`, sourceKey, "Transition "+suffix).Scan(&sourceID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO user_identity_links(
			user_id,source_id,external_subject,purposes,state,link_method,evidence
		) VALUES (
			$1,$2,$3,ARRAY['provision']::text[],'active','hard_anchor','{}'::jsonb
		) RETURNING id
	`, targetID, sourceID, "subject-"+suffix).Scan(&linkID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE user_lifecycle_authorities
		   SET authority_kind='source',link_id=$2,generation=generation+1,
		       established_by=$3,updated_at=statement_timestamp()
		 WHERE user_id=$1
	`, targetID, linkID, actorID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE users SET password_hash='identity-transition-recovery-proof'
		 WHERE id=$1
	`, targetID); err != nil {
		t.Fatal(err)
	}
	toggleKeys := []string{
		"feature.identity_model_v2",
		"feature.identity_transitions",
		"feature.cae_runtime",
	}
	toggleState := make(map[string]bool, len(toggleKeys))
	rows, err := pool.Query(ctx,
		`SELECT key,enabled FROM feature_toggles WHERE key=ANY($1::text[])`,
		toggleKeys)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var key string
		var enabled bool
		if err := rows.Scan(&key, &enabled); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		toggleState[key] = enabled
	}
	rows.Close()
	if _, err := pool.Exec(ctx,
		`UPDATE feature_toggles SET enabled=true WHERE key=ANY($1::text[])`,
		toggleKeys); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for key, enabled := range toggleState {
			_, _ = pool.Exec(context.Background(),
				`UPDATE feature_toggles SET enabled=$2 WHERE key=$1`,
				key, enabled)
		}
	})

	type transitionFixture struct {
		ID         uuid.UUID
		Digest     string
		Generation string
	}
	createTransition := func(state, label string) transitionFixture {
		t.Helper()
		var fixture transitionFixture
		if err := pool.QueryRow(ctx, `
			INSERT INTO identity_transitions(
				user_id,kind,state,source_id,link_id,source_generation,
				link_generation,lifecycle_generation,preview_digest,
				preview_snapshot,preview_expires_at,actor_user_id,reason,
				idempotency_key,request_digest,protected
			) VALUES (
				$1,'directory_to_local',$2,$3,$4,1,1,1,
				digest($5,'sha256'),jsonb_build_object('fixture',$5),
				statement_timestamp()+interval '15 minutes',
				$6,$7,gen_random_uuid(),digest($7,'sha256'),false
			)
			RETURNING id,encode(preview_digest,'hex'),transition_generation::text
		`, targetID, state, sourceID, linkID, label, actorID,
			"transition protocol handler test").Scan(
			&fixture.ID, &fixture.Digest, &fixture.Generation,
		); err != nil {
			t.Fatalf("create %s transition: %v", label, err)
		}
		return fixture
	}
	authorized := createTransition("previewed", "authorized-"+suffix)
	retryable := createTransition("failed_recoverable", "retry-"+suffix)
	rollback := createTransition("failed_recoverable", "rollback-"+suffix)
	var effectID uuid.UUID
	if err := pool.QueryRow(ctx, `
		INSERT INTO identity_transition_effects(
			transition_id,effect_kind,state,attempt_count,last_error_code
		) VALUES($1,'auth_sessions','failed',1,'fixture_failure')
		RETURNING effect_id
	`, retryable.ID).Scan(&effectID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE identity_transitions
		   SET authority_before='{"authorityKind":"source"}'::jsonb,
		       committed_at=statement_timestamp(),
		       committed_lifecycle_generation=1,
		       committed_link_generation=1
		 WHERE id=$1
	`, rollback.ID); err != nil {
		t.Fatal(err)
	}

	transitionIDs := []uuid.UUID{authorized.ID, retryable.ID, rollback.ID}
	t.Cleanup(func() {
		cleanup := context.Background()
		tx, err := pool.Begin(cleanup)
		if err != nil {
			t.Errorf("begin transition fixture cleanup: %v", err)
			return
		}
		defer func() { _ = tx.Rollback(cleanup) }()
		if _, err := tx.Exec(cleanup,
			`SET LOCAL session_replication_role = replica`); err != nil {
			t.Errorf("isolate transition fixture cleanup: %v", err)
			return
		}
		for _, query := range []string{
			`DELETE FROM identity_transition_effect_targets WHERE transition_id=ANY($1::uuid[])`,
			`DELETE FROM identity_transition_effects WHERE transition_id=ANY($1::uuid[])`,
			`DELETE FROM identity_transition_idempotency WHERE transition_id=ANY($1::uuid[])`,
			`DELETE FROM identity_transition_challenges WHERE transition_id=ANY($1::uuid[])`,
			`DELETE FROM identity_transition_elevations WHERE transition_id=ANY($1::uuid[])`,
			`DELETE FROM identity_transition_steps WHERE transition_id=ANY($1::uuid[])`,
			`DELETE FROM identity_jobs WHERE transition_id=ANY($1::uuid[])`,
			`DELETE FROM identity_link_events WHERE transition_id=ANY($1::uuid[]) OR source_id=$2`,
			`DELETE FROM identity_transitions WHERE id=ANY($1::uuid[])`,
		} {
			args := []any{transitionIDs}
			if strings.Contains(query, "$2") {
				args = append(args, sourceID)
			}
			if _, err := tx.Exec(cleanup, query, args...); err != nil {
				t.Errorf("delete transition fixture: %v", err)
				return
			}
		}
		for _, query := range []struct {
			sql  string
			args []any
		}{
			{`DELETE FROM admin_role_assignments WHERE user_id=$1 AND role_group_id=$2`,
				[]any{actorID, roleID}},
			{`DELETE FROM admin_role_groups WHERE id=$1`, []any{roleID}},
			{`DELETE FROM user_lifecycle_authorities WHERE user_id=$1`,
				[]any{targetID}},
			{`DELETE FROM user_identity_links WHERE id=$1`, []any{linkID}},
			{`DELETE FROM identity_sources WHERE id=$1`, []any{sourceID}},
			{`DELETE FROM mailboxes WHERE id=ANY($1::bigint[])`,
				[]any{[]int64{actorMailbox, targetMailbox}}},
			{`DELETE FROM users WHERE id=ANY($1::bigint[])`,
				[]any{[]int64{actorID, targetID}}},
		} {
			if _, err := tx.Exec(cleanup, query.sql, query.args...); err != nil {
				t.Errorf("delete transition supporting fixture: %v", err)
				return
			}
		}
		if err := tx.Commit(cleanup); err != nil {
			t.Errorf("commit transition fixture cleanup: %v", err)
		}
	})

	h := NewIdentityHandler(pool, pool, testsupport.TestLogger())
	request := func(method, target, body string) *http.Request {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		claims := &auth.Claims{
			UserID:            actorID,
			IsAdmin:           true,
			Permissions:       permissions.AllPermissions,
			GlobalPermissions: permissions.AllPermissions,
			JTI:               "transition-session-" + suffix,
			ACR:               jwtutil.ACRAAL2,
			AMR: []string{
				jwtutil.AMRMultiFactor,
				jwtutil.AMROTP,
				jwtutil.AMRPassword,
			},
		}
		claims.IssuedAt = jwtutil.NewNumericDate(time.Now().Add(-time.Minute))
		return req.WithContext(auth.ContextWithUser(req.Context(), claims))
	}
	call := func(
		handler func(http.ResponseWriter, *http.Request),
		req *http.Request,
		want int,
	) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Code != want {
			t.Fatalf("%s %s: status=%d want=%d body=%s",
				req.Method, req.URL.String(), rec.Code, want, rec.Body.String())
		}
		return rec
	}
	bindTransition := func(req *http.Request, fixture transitionFixture) {
		req.SetPathValue("id", fixture.ID.String())
	}

	previewKey := uuid.NewString()
	previewReq := request(http.MethodPost,
		"/admin/identity/v2/transitions/preview",
		`{"userId":"`+strconv.FormatInt(targetID, 10)+
			`","reason":"transition protocol handler preview",`+
			`"idempotencyKey":"`+previewKey+`"}`)
	previewReq.Header.Set("Idempotency-Key", previewKey)
	previewReq.Header.Set("X-Audit-Reason",
		"transition protocol handler preview")
	previewRec := call(h.TransitionPreview, previewReq, http.StatusOK)
	var previewResult struct {
		TransitionID  string `json:"transitionId"`
		PreviewDigest string `json:"previewDigest"`
	}
	if err := json.Unmarshal(previewRec.Body.Bytes(), &previewResult); err != nil ||
		previewResult.TransitionID == "" ||
		!validIdentityDigest(previewResult.PreviewDigest) {
		t.Fatalf("decode handler transition preview: %v body=%s",
			err, previewRec.Body.String())
	}
	previewTransitionID, err := uuid.Parse(previewResult.TransitionID)
	if err != nil {
		t.Fatal(err)
	}
	transitionIDs = append(transitionIDs, previewTransitionID)

	unsupportedKey := uuid.NewString()
	unsupportedAuthorized := request(http.MethodPost, "/", `{
		"previewDigest":"`+authorized.Digest+`",
		"elevationId":"`+uuid.NewString()+`",
		"reason":"transition protocol unsupported command",
		"idempotencyKey":"`+unsupportedKey+`"
	}`)
	bindTransition(unsupportedAuthorized, authorized)
	unsupportedAuthorized.Header.Set("If-Match", `"`+authorized.Digest+`"`)
	unsupportedAuthorized.Header.Set("Idempotency-Key", unsupportedKey)
	unsupportedAuthorized.Header.Set("X-Audit-Reason",
		"transition protocol unsupported command")
	call(func(w http.ResponseWriter, r *http.Request) {
		h.transitionAuthorizedMutation(w, r, "unknown")
	}, unsupportedAuthorized, http.StatusInternalServerError)

	unsupportedGenerationKey := uuid.NewString()
	unsupportedGeneration := request(http.MethodPost, "/", `{
		"expectedGeneration":"`+retryable.Generation+`",
		"reason":"transition protocol unsupported generation command",
		"idempotencyKey":"`+unsupportedGenerationKey+`"
	}`)
	bindTransition(unsupportedGeneration, retryable)
	unsupportedGeneration.Header.Set("If-Match", `"`+retryable.Generation+`"`)
	unsupportedGeneration.Header.Set("Idempotency-Key", unsupportedGenerationKey)
	unsupportedGeneration.Header.Set("X-Audit-Reason",
		"transition protocol unsupported generation command")
	call(func(w http.ResponseWriter, r *http.Request) {
		h.transitionGenerationMutation(w, r, "unknown")
	}, unsupportedGeneration, http.StatusInternalServerError)

	list := call(h.IdentityTransitions,
		request(http.MethodGet,
			"/admin/identity/v2/transitions?source="+sourceKey, ""),
		http.StatusOK)
	if !strings.Contains(list.Body.String(), authorized.ID.String()) {
		t.Fatalf("transition list omitted fixture: %s", list.Body.String())
	}
	firstPage := call(h.IdentityTransitions,
		request(http.MethodGet,
			"/admin/identity/v2/transitions?source="+sourceKey+"&limit=1", ""),
		http.StatusOK)
	var transitionPage struct {
		NextCursor string `json:"nextCursor"`
	}
	if err := json.Unmarshal(firstPage.Body.Bytes(), &transitionPage); err != nil ||
		transitionPage.NextCursor == "" {
		t.Fatalf("transition first page cursor: %v body=%s",
			err, firstPage.Body.String())
	}
	call(h.IdentityTransitions,
		request(http.MethodGet,
			"/admin/identity/v2/transitions?source="+sourceKey+
				"&limit=1&cursor="+transitionPage.NextCursor, ""),
		http.StatusOK)
	read := request(http.MethodGet,
		"/admin/identity/v2/transitions/"+authorized.ID.String(), "")
	bindTransition(read, authorized)
	call(h.IdentityTransition, read, http.StatusOK)
	report := request(http.MethodGet,
		"/admin/identity/v2/transitions/"+authorized.ID.String()+"/report", "")
	bindTransition(report, authorized)
	call(h.IdentityTransitionReport, report, http.StatusOK)

	challengeKey := uuid.NewString()
	challengeReq := request(http.MethodPost,
		"/admin/identity/v2/transitions/"+authorized.ID.String()+"/challenge",
		`{"previewDigest":"`+authorized.Digest+
			`","idempotencyKey":"`+challengeKey+`"}`)
	bindTransition(challengeReq, authorized)
	challengeReq.Header.Set("If-Match", `"`+authorized.Digest+`"`)
	challengeReq.Header.Set("Idempotency-Key", challengeKey)
	challengeRec := call(h.TransitionChallengeIssue, challengeReq, http.StatusOK)
	var challenge struct {
		ChallengeID string `json:"challengeId"`
	}
	if err := json.Unmarshal(challengeRec.Body.Bytes(), &challenge); err != nil ||
		challenge.ChallengeID == "" {
		t.Fatalf("decode transition challenge: %v body=%s",
			err, challengeRec.Body.String())
	}

	completeKey := uuid.NewString()
	completeReq := request(http.MethodPost,
		"/admin/identity/v2/transitions/"+authorized.ID.String()+"/challenge:complete",
		`{"challengeId":"`+challenge.ChallengeID+
			`","previewDigest":"`+authorized.Digest+
			`","idempotencyKey":"`+completeKey+`"}`)
	bindTransition(completeReq, authorized)
	completeReq.Header.Set("If-Match", `"`+authorized.Digest+`"`)
	completeReq.Header.Set("Idempotency-Key", completeKey)
	completeRec := call(h.TransitionChallengeComplete, completeReq, http.StatusOK)
	var elevation struct {
		ElevationID string `json:"elevationId"`
	}
	if err := json.Unmarshal(completeRec.Body.Bytes(), &elevation); err != nil ||
		elevation.ElevationID == "" {
		t.Fatalf("decode transition elevation: %v body=%s",
			err, completeRec.Body.String())
	}

	requestKey := uuid.NewString()
	requestReq := request(http.MethodPost,
		"/admin/identity/v2/transitions/"+authorized.ID.String()+":request",
		`{"previewDigest":"`+authorized.Digest+
			`","elevationId":"`+elevation.ElevationID+
			`","reason":"transition protocol handler test",`+
			`"idempotencyKey":"`+requestKey+`"}`)
	bindTransition(requestReq, authorized)
	requestReq.Header.Set("If-Match", `"`+authorized.Digest+`"`)
	requestReq.Header.Set("Idempotency-Key", requestKey)
	requestReq.Header.Set("X-Audit-Reason", "transition protocol handler test")
	requestRec := call(h.TransitionRequest, requestReq, http.StatusAccepted)
	var requested struct {
		Generation string `json:"transitionGeneration"`
		State      string `json:"state"`
	}
	if err := json.Unmarshal(requestRec.Body.Bytes(), &requested); err != nil ||
		requested.Generation == "" || requested.State != "authorized" {
		t.Fatalf("decode requested transition: %v body=%s",
			err, requestRec.Body.String())
	}

	cancelKey := uuid.NewString()
	cancelReq := request(http.MethodPost,
		"/admin/identity/v2/transitions/"+authorized.ID.String()+":cancel",
		`{"expectedGeneration":"`+requested.Generation+
			`","reason":"transition protocol handler test",`+
			`"idempotencyKey":"`+cancelKey+`"}`)
	bindTransition(cancelReq, authorized)
	cancelReq.Header.Set("If-Match", `"`+requested.Generation+`"`)
	cancelReq.Header.Set("Idempotency-Key", cancelKey)
	cancelReq.Header.Set("X-Audit-Reason", "transition protocol handler test")
	call(h.TransitionCancel, cancelReq, http.StatusOK)

	replayedChallengeKey := uuid.NewString()
	replayedChallenge := request(http.MethodPost,
		"/admin/identity/v2/transitions/"+authorized.ID.String()+"/challenge",
		`{"previewDigest":"`+authorized.Digest+
			`","idempotencyKey":"`+replayedChallengeKey+`"}`)
	bindTransition(replayedChallenge, authorized)
	replayedChallenge.Header.Set("If-Match", `"`+authorized.Digest+`"`)
	replayedChallenge.Header.Set("Idempotency-Key", replayedChallengeKey)
	replayedChallengeRec := httptest.NewRecorder()
	h.TransitionChallengeIssue(replayedChallengeRec, replayedChallenge)
	if replayedChallengeRec.Code < http.StatusBadRequest {
		t.Fatalf("cancelled transition challenge unexpectedly succeeded: %d %s",
			replayedChallengeRec.Code, replayedChallengeRec.Body.String())
	}

	replayedCompleteKey := uuid.NewString()
	replayedComplete := request(http.MethodPost,
		"/admin/identity/v2/transitions/"+authorized.ID.String()+"/challenge:complete",
		`{"challengeId":"`+challenge.ChallengeID+
			`","previewDigest":"`+authorized.Digest+
			`","idempotencyKey":"`+replayedCompleteKey+`"}`)
	bindTransition(replayedComplete, authorized)
	replayedComplete.Header.Set("If-Match", `"`+authorized.Digest+`"`)
	replayedComplete.Header.Set("Idempotency-Key", replayedCompleteKey)
	replayedCompleteRec := httptest.NewRecorder()
	h.TransitionChallengeComplete(replayedCompleteRec, replayedComplete)
	if replayedCompleteRec.Code < http.StatusBadRequest {
		t.Fatalf("consumed challenge unexpectedly completed twice: %d %s",
			replayedCompleteRec.Code, replayedCompleteRec.Body.String())
	}

	for _, tc := range []struct {
		name     string
		handler  func(http.ResponseWriter, *http.Request)
		approval bool
	}{
		{"request", h.TransitionRequest, false},
		{"approve", h.TransitionApprove, false},
		{"deny", h.TransitionDeny, false},
		{"execute", h.TransitionExecuteAuthorized, false},
		{"rollback", h.TransitionRollback, true},
		{"unsupported", func(w http.ResponseWriter, r *http.Request) {
			h.transitionAuthorizedMutation(w, r, "unsupported")
		}, false},
	} {
		key := uuid.NewString()
		approval := ""
		if tc.approval {
			approval = `,"approvalRequestId":"42"`
		}
		body := `{"previewDigest":"` + authorized.Digest +
			`","elevationId":"` + elevation.ElevationID +
			`","reason":"transition protocol handler test",` +
			`"idempotencyKey":"` + key + `"` + approval + `}`
		req := request(http.MethodPost,
			"/admin/identity/v2/transitions/"+authorized.ID.String()+
				":"+tc.name, body)
		bindTransition(req, authorized)
		req.Header.Set("If-Match", `"`+authorized.Digest+`"`)
		req.Header.Set("Idempotency-Key", key)
		req.Header.Set("X-Audit-Reason", "transition protocol handler test")
		rec := httptest.NewRecorder()
		tc.handler(rec, req)
		if rec.Code < http.StatusBadRequest {
			t.Fatalf("cancelled transition %s unexpectedly succeeded: status=%d body=%s",
				tc.name, rec.Code, rec.Body.String())
		}
	}

	retryKey := uuid.NewString()
	retryReq := request(http.MethodPost,
		"/admin/identity/v2/transitions/"+retryable.ID.String()+
			"/effects/"+effectID.String()+":retry",
		`{"expectedGeneration":"`+retryable.Generation+
			`","reason":"transition protocol handler test",`+
			`"idempotencyKey":"`+retryKey+`"}`)
	bindTransition(retryReq, retryable)
	retryReq.SetPathValue("effectId", effectID.String())
	retryReq.Header.Set("If-Match", `"`+retryable.Generation+`"`)
	retryReq.Header.Set("Idempotency-Key", retryKey)
	retryReq.Header.Set("X-Audit-Reason", "transition protocol handler test")
	call(h.TransitionRetry, retryReq, http.StatusAccepted)

	staleCancelKey := uuid.NewString()
	staleCancel := request(http.MethodPost,
		"/admin/identity/v2/transitions/"+authorized.ID.String()+":cancel",
		`{"expectedGeneration":"`+requested.Generation+
			`","reason":"transition protocol handler test",`+
			`"idempotencyKey":"`+staleCancelKey+`"}`)
	bindTransition(staleCancel, authorized)
	staleCancel.Header.Set("If-Match", `"`+requested.Generation+`"`)
	staleCancel.Header.Set("Idempotency-Key", staleCancelKey)
	staleCancel.Header.Set("X-Audit-Reason", "transition protocol handler test")
	staleCancelRec := httptest.NewRecorder()
	h.TransitionCancel(staleCancelRec, staleCancel)
	if staleCancelRec.Code < http.StatusBadRequest {
		t.Fatalf("stale cancel unexpectedly succeeded: %d %s",
			staleCancelRec.Code, staleCancelRec.Body.String())
	}

	rollbackKey := uuid.NewString()
	rollbackReq := request(http.MethodPost,
		"/admin/identity/v2/transitions/"+rollback.ID.String()+":rollback-preview",
		`{"expectedGeneration":"`+rollback.Generation+
			`","reason":"transition protocol handler test",`+
			`"idempotencyKey":"`+rollbackKey+`"}`)
	bindTransition(rollbackReq, rollback)
	rollbackReq.Header.Set("If-Match", `"`+rollback.Generation+`"`)
	rollbackReq.Header.Set("Idempotency-Key", rollbackKey)
	rollbackReq.Header.Set("X-Audit-Reason", "transition protocol handler test")
	call(h.TransitionRollbackPreview, rollbackReq, http.StatusOK)
}

func TestIdentityTransitionResponseHelpersFailClosedOnMalformedReducerOutput(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/transition", nil)
	for name, raw := range map[string]json.RawMessage{
		"malformed": json.RawMessage(`{`),
		"missing generation": json.RawMessage(
			`{"transitionGeneration":""}`),
		"zero generation": json.RawMessage(
			`{"transitionGeneration":"0"}`),
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeIdentityTransitionResult(rec, req, http.StatusOK, raw)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
	notFound := httptest.NewRecorder()
	writeIdentityTransitionReducerError(notFound, req, pgx.ErrNoRows, "failed")
	if notFound.Code != http.StatusNotFound {
		t.Fatalf("no rows status=%d body=%s", notFound.Code, notFound.Body.String())
	}
	generic := httptest.NewRecorder()
	writeIdentityTransitionReducerError(generic, req, errors.New("boom"), "failed")
	if generic.Code != http.StatusInternalServerError {
		t.Fatalf("generic status=%d body=%s", generic.Code, generic.Body.String())
	}
}
