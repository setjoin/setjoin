package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/jwtutil"

	"setjoin.com/mailserver/internal/middleware"
)

type upgradeJSONRow struct {
	raw json.RawMessage
	err error
}

func (row upgradeJSONRow) Scan(dest ...any) error {
	if row.err != nil {
		return row.err
	}
	*(dest[0].(*json.RawMessage)) = append(json.RawMessage(nil), row.raw...)
	return nil
}

type upgradeQueryRecorder struct {
	query string
	args  []any
	err   error
}

func (db *upgradeQueryRecorder) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	db.query = query
	db.args = append([]any(nil), args...)
	return upgradeJSONRow{raw: json.RawMessage(`{"installationId":"11111111-1111-4111-8111-111111111111","timelineId":"22222222-2222-4222-8222-222222222222","schemaVersion":179,"counts":{"users":2,"mailboxes":2,"blobs":1,"blobBytes":4},"representativeIds":["user:1"]}`), err: db.err}
}

func upgradeTestClaims() *jwtutil.Claims {
	claims := &jwtutil.Claims{
		UserID: 7, JTI: "upgrade-test-session", ACR: jwtutil.ACRAAL2,
		AMR: []string{jwtutil.AMRPassword, jwtutil.AMROTP, jwtutil.AMRMultiFactor},
	}
	claims.IssuedAt = jwtutil.NewNumericDate(time.Now().Add(-time.Minute))
	return claims
}

func upgradeRequest(method, target, body string, claims *jwtutil.Claims) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if claims != nil {
		req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	}
	return req
}

func TestUpgradeRequestDecoderRejectsUnknownTrailingAndOversizedBodies(t *testing.T) {
	for _, body := range []string{
		`{"releaseId":"release-1","reason":"planned maintenance","unknown":true}`,
		`{"releaseId":"release-1","reason":"planned maintenance"}{}`,
		`{"releaseId":"release-1","reason":"` + string(bytes.Repeat([]byte{'x'}, maxUpgradeBodyBytes)) + `"}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/admin/system/upgrades/preview", strings.NewReader(body))
		req.Header.Set("X-Audit-Reason", "planned maintenance")
		req = req.WithContext(auth.ContextWithUser(req.Context(), &jwtutil.Claims{UserID: 1}))
		recorder := httptest.NewRecorder()
		NewUpgradeHandler(nil).Preview(recorder, req)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("body accepted with status %d", recorder.Code)
		}
	}
}

func TestUpgradeStepUpBindingsRequireFreshTwoFactorAAL2AndBindChallenge(t *testing.T) {
	now := time.Now().UTC()
	claims := &jwtutil.Claims{
		UserID: 7, JTI: "session-1", ACR: jwtutil.ACRAAL2,
		AMR: []string{jwtutil.AMRPassword, jwtutil.AMROTP, jwtutil.AMRMultiFactor},
	}
	claims.IssuedAt = jwtutil.NewNumericDate(now.Add(-time.Minute))
	challenge := uuid.New()
	session, factor, amr, ok := upgradeStepUpBindings(claims, challenge, now)
	if !ok || session == ([32]byte{}) || factor == ([32]byte{}) || len(amr) != 3 {
		t.Fatalf("fresh AAL2 rejected: ok=%v amr=%v", ok, amr)
	}
	_, changedFactor, _, ok := upgradeStepUpBindings(claims, uuid.New(), now)
	if !ok || changedFactor == factor {
		t.Fatal("factor binding does not cover the challenge")
	}
	stale := *claims
	stale.IssuedAt = jwtutil.NewNumericDate(now.Add(-6 * time.Minute))
	if _, _, _, ok := upgradeStepUpBindings(&stale, challenge, now); ok {
		t.Fatal("stale AAL2 accepted")
	}
}

func TestRecoveryContextUsesBoundedReducerProjection(t *testing.T) {
	db := &upgradeQueryRecorder{}
	h := NewUpgradeHandler(nil)
	h.db = db
	req := httptest.NewRequest(http.MethodGet, "/admin/system/upgrades/recovery-context", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &jwtutil.Claims{UserID: 7}))
	recorder := httptest.NewRecorder()
	h.RecoveryContext(recorder, req)
	if recorder.Code != http.StatusOK || !strings.Contains(db.query, "upgrade_recovery_context_read") {
		t.Fatalf("status=%d query=%q body=%s", recorder.Code, db.query, recorder.Body.String())
	}
	for _, forbidden := range []string{"dsn", "token", "password", "configuration", "objectKey", "email", "mime"} {
		if strings.Contains(strings.ToLower(recorder.Body.String()), strings.ToLower(forbidden)) {
			t.Fatalf("recovery context exposed forbidden field %q: %s", forbidden, recorder.Body.String())
		}
	}
}

func TestLegacyUpgradeMutationsReturnGoneBeforeParsingInput(t *testing.T) {
	h := NewUpgradeHandler(nil)
	tests := []struct {
		name    string
		target  string
		handler http.HandlerFunc
	}{
		{name: "check", target: "/admin/system/upgrade/check", handler: h.CheckUpgrade},
		{name: "apply", target: "/admin/system/upgrade/apply", handler: h.ApplyUpgrade},
		{name: "rollback", target: "/admin/system/upgrade/rollback", handler: h.Rollback},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Invalid JSON deliberately proves the safety interlock runs before the
			// retired handlers decode input or attempt any filesystem/DB work.
			req := httptest.NewRequest(http.MethodPost, tt.target, strings.NewReader("{"))
			rr := httptest.NewRecorder()

			tt.handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusGone {
				t.Fatalf("status = %d, want %d", rr.Code, http.StatusGone)
			}
			if got := rr.Header().Get("Content-Type"); got != "application/problem+json" {
				t.Fatalf("Content-Type = %q", got)
			}
			var problem httputil.Problem
			if err := json.Unmarshal(rr.Body.Bytes(), &problem); err != nil {
				t.Fatalf("decode problem: %v", err)
			}
			if problem.Type != legacyUpgradeRetiredType || problem.Instance != tt.target {
				t.Fatalf("problem = %#v", problem)
			}
			if !strings.Contains(problem.Remediation, "/admin/updates/server") ||
				!strings.Contains(problem.Remediation, "UPGRADE.md") {
				t.Fatalf("remediation does not name the transactional console and runbook: %q", problem.Remediation)
			}
		})
	}
}

func TestUpgradeControlHandlersUseBoundedReducerSurface(t *testing.T) {
	const (
		reason      = "planned transactional upgrade"
		idempotency = "44444444-4444-4444-8444-444444444444"
		challenge   = "55555555-5555-4555-8555-555555555555"
		elevation   = "66666666-6666-4666-8666-666666666666"
		setID       = "77777777-7777-4777-8777-777777777777"
		timelineID  = "88888888-8888-4888-8888-888888888888"
		proofID     = "99999999-9999-4999-8999-999999999999"
	)
	digest := strings.Repeat("a", 64)
	now := time.Now().UTC().Truncate(time.Second)
	tests := []struct {
		name, method, target, body, query string
		status                            int
		path                              map[string]string
		idempotency                       bool
		handler                           func(*UpgradeHandler, http.ResponseWriter, *http.Request)
	}{
		{name: "console", method: http.MethodGet, target: "/admin/system/upgrades", query: "upgrade_console_read", status: http.StatusOK, handler: (*UpgradeHandler).Console},
		{name: "preview", method: http.MethodPost, target: "/admin/system/upgrades/preview", body: `{"releaseId":"release-179","reason":"` + reason + `"}`, query: "upgrade_intent_preview", status: http.StatusOK, handler: (*UpgradeHandler).Preview},
		{name: "challenge issue", method: http.MethodPost, target: "/admin/system/upgrades/challenges", body: `{"releaseId":"release-179","reason":"` + reason + `","previewDigest":"` + digest + `","idempotencyKey":"` + idempotency + `"}`, query: "upgrade_challenge_issue", status: http.StatusOK, idempotency: true, handler: (*UpgradeHandler).ChallengeIssue},
		{name: "challenge complete", method: http.MethodPost, target: "/admin/system/upgrades/challenges/complete", body: `{"challengeId":"` + challenge + `"}`, query: "upgrade_challenge_complete", status: http.StatusOK, handler: (*UpgradeHandler).ChallengeComplete},
		{name: "request intent", method: http.MethodPost, target: "/admin/system/upgrades/intents", body: `{"releaseId":"release-179","reason":"` + reason + `","previewDigest":"` + digest + `","elevationId":"` + elevation + `","idempotencyKey":"` + idempotency + `"}`, query: "upgrade_intent_request", status: http.StatusAccepted, idempotency: true, handler: (*UpgradeHandler).RequestIntent},
		{name: "intent", method: http.MethodGet, target: "/admin/system/upgrades/intents/17", query: "upgrade_intent_read", status: http.StatusOK, path: map[string]string{"id": "17"}, handler: (*UpgradeHandler).Intent},
		{name: "diagnostics", method: http.MethodGet, target: "/admin/system/upgrades/intents/17/diagnostics", query: "upgrade_intent_diagnostics", status: http.StatusOK, path: map[string]string{"id": "17"}, handler: (*UpgradeHandler).Diagnostics},
		{name: "cancel", method: http.MethodPost, target: "/admin/system/upgrades/intents/17/cancel", body: `{"expectedGeneration":"3","reason":"` + reason + `"}`, query: "upgrade_intent_cancel", status: http.StatusOK, path: map[string]string{"id": "17"}, handler: (*UpgradeHandler).CancelIntent},
		{name: "record recovery set", method: http.MethodPost, target: "/admin/system/upgrades/recovery-sets", body: `{"recoverySetId":"` + setID + `","timelineId":"` + timelineID + `","sourceReleaseId":"release-178","schemaVersion":178,"manifestDigest":"` + digest + `","checks":{"database":true},"createdAt":"` + now.Format(time.RFC3339) + `","expiresAt":"` + now.Add(time.Hour).Format(time.RFC3339) + `","reason":"` + reason + `"}`, query: "upgrade_recovery_set_record", status: http.StatusCreated, handler: (*UpgradeHandler).RecordRecoverySet},
		{name: "recovery context", method: http.MethodGet, target: "/admin/system/upgrades/recovery-context", query: "upgrade_recovery_context_read", status: http.StatusOK, handler: (*UpgradeHandler).RecoveryContext},
		{name: "restore proof", method: http.MethodPost, target: "/admin/system/upgrades/restore-proofs", body: `{"proofId":"` + proofID + `","recoverySetId":"` + setID + `","targetId":"isolated-restore-1","checks":{"login":true},"provedAt":"` + now.Format(time.RFC3339) + `","reason":"` + reason + `"}`, query: "upgrade_restore_proof_record", status: http.StatusCreated, handler: (*UpgradeHandler).RecordRestoreProof},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := &upgradeQueryRecorder{}
			h := NewUpgradeHandler(nil)
			h.db = db
			req := upgradeRequest(tt.method, tt.target, tt.body, upgradeTestClaims())
			if strings.Contains(tt.body, `"reason"`) {
				req.Header.Set("X-Audit-Reason", reason)
			}
			if tt.idempotency {
				req.Header.Set("Idempotency-Key", idempotency)
			}
			for key, value := range tt.path {
				req.SetPathValue(key, value)
			}
			rr := httptest.NewRecorder()
			// WP2: Cache-Control is middleware-owned — assert the no-store
			// posture through the assembled chain.
			middleware.CacheControl(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tt.handler(h, w, r)
			})).ServeHTTP(rr, req)
			if rr.Code != tt.status || !strings.Contains(db.query, tt.query) || rr.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("status=%d query=%q cache=%q body=%s", rr.Code, db.query, rr.Header().Get("Cache-Control"), rr.Body.String())
			}
			if len(db.args) == 0 {
				t.Fatal("reducer query received no authority arguments")
			}
		})
	}
}

func TestUpgradeControlHandlersRejectUnauthenticatedBeforeParsing(t *testing.T) {
	h := NewUpgradeHandler(nil)
	handlers := []func(*UpgradeHandler, http.ResponseWriter, *http.Request){
		(*UpgradeHandler).Console, (*UpgradeHandler).Preview, (*UpgradeHandler).ChallengeIssue,
		(*UpgradeHandler).ChallengeComplete, (*UpgradeHandler).RequestIntent, (*UpgradeHandler).Intent,
		(*UpgradeHandler).Diagnostics, (*UpgradeHandler).CancelIntent, (*UpgradeHandler).RecordRecoverySet,
		(*UpgradeHandler).RecoveryContext, (*UpgradeHandler).RecordRestoreProof,
	}
	for index, handler := range handlers {
		req := upgradeRequest(http.MethodPost, "/admin/system/upgrades", "{", nil)
		rr := httptest.NewRecorder()
		handler(h, rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("handler %d status=%d", index, rr.Code)
		}
	}
}

func TestUpgradeControlValidationAndDatabaseFailuresAreTyped(t *testing.T) {
	const reason = "planned transactional upgrade"
	digest := strings.Repeat("a", 64)
	tests := []struct {
		name, body string
		path       map[string]string
		headers    map[string]string
		handler    func(*UpgradeHandler, http.ResponseWriter, *http.Request)
	}{
		{name: "preview reason mismatch", body: `{"releaseId":"r","reason":"` + reason + `"}`, handler: (*UpgradeHandler).Preview},
		{name: "challenge digest", body: `{"releaseId":"r","reason":"` + reason + `","previewDigest":"bad","idempotencyKey":"44444444-4444-4444-8444-444444444444"}`, headers: map[string]string{"X-Audit-Reason": reason, "Idempotency-Key": "44444444-4444-4444-8444-444444444444"}, handler: (*UpgradeHandler).ChallengeIssue},
		{name: "challenge idempotency", body: `{"releaseId":"r","reason":"` + reason + `","previewDigest":"` + digest + `","idempotencyKey":"bad"}`, headers: map[string]string{"X-Audit-Reason": reason, "Idempotency-Key": "bad"}, handler: (*UpgradeHandler).ChallengeIssue},
		{name: "challenge identity", body: `{"challengeId":"bad"}`, handler: (*UpgradeHandler).ChallengeComplete},
		{name: "intent digest", body: `{"releaseId":"r","reason":"` + reason + `","previewDigest":"bad","elevationId":"66666666-6666-4666-8666-666666666666","idempotencyKey":"44444444-4444-4444-8444-444444444444"}`, headers: map[string]string{"X-Audit-Reason": reason}, handler: (*UpgradeHandler).RequestIntent},
		{name: "intent elevation", body: `{"releaseId":"r","reason":"` + reason + `","previewDigest":"` + digest + `","elevationId":"bad","idempotencyKey":"44444444-4444-4444-8444-444444444444"}`, headers: map[string]string{"X-Audit-Reason": reason}, handler: (*UpgradeHandler).RequestIntent},
		{name: "intent idempotency mismatch", body: `{"releaseId":"r","reason":"` + reason + `","previewDigest":"` + digest + `","elevationId":"66666666-6666-4666-8666-666666666666","idempotencyKey":"44444444-4444-4444-8444-444444444444"}`, headers: map[string]string{"X-Audit-Reason": reason, "Idempotency-Key": "55555555-5555-4555-8555-555555555555"}, handler: (*UpgradeHandler).RequestIntent},
		{name: "read intent id", path: map[string]string{"id": "01"}, handler: (*UpgradeHandler).Intent},
		{name: "diagnostic id", path: map[string]string{"id": "-1"}, handler: (*UpgradeHandler).Diagnostics},
		{name: "cancel generation", path: map[string]string{"id": "17"}, body: `{"expectedGeneration":"0","reason":"` + reason + `"}`, headers: map[string]string{"X-Audit-Reason": reason}, handler: (*UpgradeHandler).CancelIntent},
		{name: "recovery digest", body: `{"manifestDigest":"bad","reason":"` + reason + `"}`, headers: map[string]string{"X-Audit-Reason": reason}, handler: (*UpgradeHandler).RecordRecoverySet},
		{name: "recovery identity", body: `{"recoverySetId":"bad","timelineId":"bad","manifestDigest":"` + digest + `","reason":"` + reason + `"}`, headers: map[string]string{"X-Audit-Reason": reason}, handler: (*UpgradeHandler).RecordRecoverySet},
		{name: "restore identity", body: `{"proofId":"bad","recoverySetId":"bad","reason":"` + reason + `"}`, headers: map[string]string{"X-Audit-Reason": reason}, handler: (*UpgradeHandler).RecordRestoreProof},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewUpgradeHandler(nil)
			req := upgradeRequest(http.MethodPost, "/admin/system/upgrades", tt.body, upgradeTestClaims())
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}
			for key, value := range tt.path {
				req.SetPathValue(key, value)
			}
			rr := httptest.NewRecorder()
			tt.handler(h, rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
		})
	}

	for name, h := range map[string]*UpgradeHandler{
		"missing": NewUpgradeHandler(nil),
		"failed":  {db: &upgradeQueryRecorder{err: errors.New("database unavailable")}},
	} {
		req := upgradeRequest(http.MethodGet, "/admin/system/upgrades", "", upgradeTestClaims())
		rr := httptest.NewRecorder()
		h.Console(rr, req)
		if rr.Code != http.StatusServiceUnavailable && rr.Code != http.StatusInternalServerError {
			t.Fatalf("%s status=%d body=%s", name, rr.Code, rr.Body.String())
		}
	}
}

func TestChallengeCompletionRejectsNonStepUpSession(t *testing.T) {
	h := NewUpgradeHandler(nil)
	h.db = &upgradeQueryRecorder{}
	req := upgradeRequest(http.MethodPost, "/admin/system/upgrades/challenges/complete", `{"challengeId":"55555555-5555-4555-8555-555555555555"}`, &jwtutil.Claims{UserID: 7})
	rr := httptest.NewRecorder()
	h.ChallengeComplete(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestUpgradeHandlerValidationReturnsAreCoveredPerMutation(t *testing.T) {
	if handler := NewUpgradeHandler(&pgxpool.Pool{}); handler.db == nil {
		t.Fatal("non-nil pool was not wired")
	}
	h := NewUpgradeHandler(nil)
	h.db = &upgradeQueryRecorder{}
	for name, handler := range map[string]func(*UpgradeHandler, http.ResponseWriter, *http.Request){
		"challenge": (*UpgradeHandler).ChallengeIssue,
		"complete":  (*UpgradeHandler).ChallengeComplete,
		"request":   (*UpgradeHandler).RequestIntent,
		"cancel":    (*UpgradeHandler).CancelIntent,
		"recovery":  (*UpgradeHandler).RecordRecoverySet,
		"proof":     (*UpgradeHandler).RecordRestoreProof,
	} {
		t.Run(name, func(t *testing.T) {
			req := upgradeRequest(http.MethodPost, "/admin/system/upgrades", "{", upgradeTestClaims())
			if name == "cancel" {
				req.SetPathValue("id", "17")
			}
			rr := httptest.NewRecorder()
			handler(h, rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
		})
	}

	for _, id := range []string{"", "-1", "01"} {
		req := upgradeRequest(http.MethodPost, "/admin/system/upgrades/intents/"+id+"/cancel", `{}`, upgradeTestClaims())
		req.SetPathValue("id", id)
		rr := httptest.NewRecorder()
		h.CancelIntent(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("id=%q status=%d", id, rr.Code)
		}
	}
}

func TestUpgradeStepUpBindingsIgnoreEmptyAndDuplicateMethodsAndBoundCardinality(t *testing.T) {
	claims := upgradeTestClaims()
	claims.AMR = []string{"", jwtutil.AMRPassword, jwtutil.AMRPassword, jwtutil.AMROTP, jwtutil.AMRMultiFactor}
	if _, _, amr, ok := upgradeStepUpBindings(claims, uuid.New(), time.Now()); !ok || len(amr) != 3 {
		t.Fatalf("duplicate/empty normalization failed: ok=%v amr=%v", ok, amr)
	}
	claims.AMR = []string{jwtutil.AMRPassword, jwtutil.AMRMultiFactor}
	if _, _, _, ok := upgradeStepUpBindings(claims, uuid.New(), time.Now()); ok {
		t.Fatal("one verified factor accepted")
	}
	claims.AMR = []string{jwtutil.AMRPassword, jwtutil.AMROTP, jwtutil.AMRMultiFactor}
	for i := 0; i < 17; i++ {
		claims.AMR = append(claims.AMR, "extension-"+strconv.Itoa(i))
	}
	if _, _, _, ok := upgradeStepUpBindings(claims, uuid.New(), time.Now()); ok {
		t.Fatal("unbounded AMR set accepted")
	}
}
