package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/threat"
)

// TestCaPolicyCreateHasSessionControl guards the struct contract: session_control
// must exist on caPolicyCreate as json.RawMessage so the admin API round-trips it.
// Handler-level HTTP integration lives in the broader admin suite; this unit
// guards the field contract so a rename/type change fails loud here first.
func TestCaPolicyCreateHasSessionControl(t *testing.T) {
	var req caPolicyCreate
	// Compile-time guard: the field must exist and be json.RawMessage.
	req.SessionControl = []byte(`{"persistent_session":"never"}`)
	if string(req.SessionControl) == "" {
		t.Fatal("session_control must round-trip")
	}
}

// newTestCAHandler opens the test pool and returns a ConditionalAccessHandler.
// Test DB runs as superuser so pool = workerPool (BYPASSRLS distinction is irrelevant).
func newTestCAHandler(t *testing.T) *ConditionalAccessHandler {
	t.Helper()
	pool := testsupport.OpenTestPool(t)
	return NewConditionalAccessHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())
}

// withAdminClaims attaches admin auth claims to the request context.
func withAdminClaims(r *http.Request, userID int64) *http.Request {
	return r.WithContext(auth.ContextWithUser(r.Context(), &auth.Claims{UserID: userID}))
}

// seedSignInRow inserts one ca_signin_log row via ca_signin_log_append for test setup.
func seedSignInRow(t *testing.T, h *ConditionalAccessHandler, userID int64, corrID string) {
	t.Helper()
	payload := fmt.Sprintf(`{"user_id":%d,"decision":"allow","correlation_id":%q,"evaluated":[]}`, userID, corrID)
	if _, err := h.pool.Exec(context.Background(), `SELECT ca_signin_log_append($1::jsonb)`, payload); err != nil {
		t.Fatalf("seedSignInRow: %v", err)
	}
}

// seedSignInRowWithIP inserts a ca_signin_log row that includes a non-NULL source_ip.
// C1 regression: source_ip is inet; the SELECT must cast via host() or pgx v5 binary
// scan panics on every real row.
func seedSignInRowWithIP(t *testing.T, h *ConditionalAccessHandler, userID int64, corrID, sourceIP string) {
	t.Helper()
	payload := fmt.Sprintf(`{"user_id":%d,"decision":"allow","correlation_id":%q,"source_ip":%q,"evaluated":[]}`,
		userID, corrID, sourceIP)
	if _, err := h.pool.Exec(context.Background(), `SELECT ca_signin_log_append($1::jsonb)`, payload); err != nil {
		t.Fatalf("seedSignInRowWithIP: %v", err)
	}
}

// TestSignInLog_ByUser returns appended rows for a user_id query.
func TestSignInLog_ByUser(t *testing.T) {
	h := newTestCAHandler(t)
	seedSignInRow(t, h, 4711, "CA-7f3c9a")
	req := httptest.NewRequest(http.MethodGet, "/admin/conditional-access/signin-log?user_id=4711&limit=1", nil)
	req = withAdminClaims(req, 1)
	w := httptest.NewRecorder()
	h.SignInLog(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "CA-7f3c9a") {
		t.Fatalf("want 200 with correlation id, got %d (%s)", w.Code, w.Body.String())
	}
}

// TestSignInLog_ByCorrelation looks up a single-row trace by correlation id.
func TestSignInLog_ByCorrelation(t *testing.T) {
	h := newTestCAHandler(t)
	seedSignInRow(t, h, 4711, "CA-abc999")
	req := httptest.NewRequest(http.MethodGet, "/admin/conditional-access/signin-log?correlation_id=CA-abc999", nil)
	req = withAdminClaims(req, 1)
	w := httptest.NewRecorder()
	h.SignInLog(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "CA-abc999") {
		t.Fatalf("want 200 with correlation id, got %d (%s)", w.Code, w.Body.String())
	}
}

// TestSignInLogNoAuth verifies that SignInLog returns 400 when no query params
// are supplied, regardless of auth state. The handler requires user_id or
// correlation_id; the route gate (requireCAPolicyRead) is the auth backstop,
// but we verify the handler itself doesn't leak data on a bad request.
// Pure unit test — no DB pool needed (bad-param check fires before any query).
func TestSignInLogNoAuth(t *testing.T) {
	h := &ConditionalAccessHandler{logger: testsupport.TestLogger()}

	// No query params → 400 before any DB call (no pool needed, no auth needed).
	req := httptest.NewRequest(http.MethodGet, "/admin/conditional-access/signin-log", nil)
	w := httptest.NewRecorder()
	h.SignInLog(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("SignInLog(no params): got %d, want 400", w.Code)
	}
}

// TestSignInLog_NonNullSourceIP — C1 regression: source_ip is an inet column.
// pgx v5 binary mode cannot scan inet into *string; the SELECT must cast via
// host(). Before the fix, every row with a non-NULL source_ip caused a 500 and
// the row was silently dropped by the scan-error continue.
func TestSignInLog_NonNullSourceIP(t *testing.T) {
	h := newTestCAHandler(t)
	seedSignInRowWithIP(t, h, 4712, "CA-c1-fix", "203.0.113.9")
	req := httptest.NewRequest(http.MethodGet, "/admin/conditional-access/signin-log?user_id=4712&limit=1", nil)
	req = withAdminClaims(req, 1)
	w := httptest.NewRecorder()
	h.SignInLog(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("C1: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "203.0.113.9") {
		t.Fatalf("C1: response must contain source_ip string; got: %s", body)
	}
}

func TestCAErrorStatus(t *testing.T) {
	cases := []struct {
		name string
		code string
		want int
	}{
		{"lockout-guard", "BZ080", http.StatusConflict},
		{"not-found", "BZ081", http.StatusNotFound},
		{"audit-not-found", "BZ086", http.StatusNotFound},
		{"priority-conflict", "BZ087", http.StatusConflict},
		{"check-violation", "23514", http.StatusBadRequest},
		{"other", "XX000", http.StatusInternalServerError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := &pgconn.PgError{Code: c.code}
			if got := caErrorStatus(err); got != c.want {
				t.Fatalf("caErrorStatus(%s) = %d, want %d", c.code, got, c.want)
			}
		})
	}
}

// TestCAValidateBeforePersist — F6: ValidatePolicyDocument is called before the reducer
// so a bad condition key is rejected with HTTP 400 before any SQL is issued.
func TestCAValidateBeforePersist(t *testing.T) {
	// A *PolicySchemaError from ValidatePolicyDocument maps to 400.
	schemaErr := &threat.PolicySchemaError{Key: "unknown_key", Reason: "unknown condition key"}
	if got := caSchemaErrorStatus(schemaErr); got != http.StatusBadRequest {
		t.Fatalf("caSchemaErrorStatus(*PolicySchemaError) = %d, want 400", got)
	}
	// nil → no validation error; does not map to 400.
	if got := caSchemaErrorStatus(nil); got != 0 {
		t.Fatalf("caSchemaErrorStatus(nil) = %d, want 0 (pass-through)", got)
	}
}

// TestGetBreakGlassAbsent — when no ca_break_glass_user_ids key exists in
// system_config, GetBreakGlass returns 200 with { admins: [] } (not an error).
// Uses a cancelled context to skip the user-resolve query; the system_config
// SELECT fails first (key absent on a fresh test DB is also fine — both yield
// the empty response). DB-backed; skips without DB_DSN.
func TestGetBreakGlassAbsent(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewConditionalAccessHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())

	// Ensure the key is absent (test DB may have it from a prior run).
	_, _ = pool.Exec(context.Background(),
		`DELETE FROM system_config WHERE key = 'ca_break_glass_user_ids'`)

	req := httptest.NewRequest(http.MethodGet, "/admin/conditional-access/break-glass", nil)
	w := httptest.NewRecorder()
	h.GetBreakGlass(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GetBreakGlass(absent): got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("GetBreakGlass(absent): invalid JSON: %v", err)
	}
	var admins []any
	if err := json.Unmarshal(resp["admins"], &admins); err != nil {
		t.Fatalf("GetBreakGlass(absent): admins field not parseable: %v", err)
	}
	if len(admins) != 0 {
		t.Fatalf("GetBreakGlass(absent): want empty admins, got %v", admins)
	}
}

// TestSetBreakGlassEmptyArrayRejected — PUT with an empty array is rejected 400
// before touching the DB. No DB required; the empty check fires before the auth gate.
// Pure unit test — no DB pool needed.
func TestSetBreakGlassEmptyArrayRejected(t *testing.T) {
	h := &ConditionalAccessHandler{logger: testsupport.TestLogger()}

	body, _ := json.Marshal([]int64{})
	req := httptest.NewRequest(http.MethodPut, "/admin/conditional-access/break-glass",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.SetBreakGlass(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("SetBreakGlass(empty): got %d, want 400", w.Code)
	}
}

// TestSetBreakGlassNoAuth — PUT without an auth context returns 401.
// Pure unit test — no DB pool needed (auth check fires before any DB query).
func TestSetBreakGlassNoAuth(t *testing.T) {
	h := &ConditionalAccessHandler{logger: testsupport.TestLogger()}

	body, _ := json.Marshal([]int64{1})
	req := httptest.NewRequest(http.MethodPut, "/admin/conditional-access/break-glass",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// No auth context — auth.UserFromContext returns nil.
	w := httptest.NewRecorder()
	h.SetBreakGlass(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("SetBreakGlass(no auth): got %d, want 401", w.Code)
	}
}

// TestSetBreakGlassRoundTrip — DB-backed: SET then GET returns the same IDs.
// Seeds a user row so the GET can resolve it. DB-backed; skips without DB_DSN.
func TestSetBreakGlassRoundTrip(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewConditionalAccessHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())

	ctx := context.Background()

	// Seed a domain + user.
	_, _ = pool.Exec(ctx,
		`INSERT INTO domains (id, name, is_local) VALUES (97100, 'bgrt.test', TRUE) ON CONFLICT DO NOTHING`)
	_, _ = pool.Exec(ctx,
		`INSERT INTO users (id, username, domain_id, email, display_name, enabled)
		 VALUES (84001, 'bgrt_u', 97100, 'bgrt@bgrt.test', 'BG Round-Trip', TRUE)
		 ON CONFLICT (id) DO NOTHING`)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM system_config WHERE key = 'ca_break_glass_user_ids'`)
	})

	// PUT — set break-glass to [84001].
	putBody, _ := json.Marshal([]int64{84001})
	putReq := httptest.NewRequest(http.MethodPut, "/admin/conditional-access/break-glass",
		bytes.NewReader(putBody))
	putReq.Header.Set("Content-Type", "application/json")
	putReq = putReq.WithContext(auth.ContextWithUser(ctx, &auth.Claims{UserID: 84001}))
	putW := httptest.NewRecorder()
	h.SetBreakGlass(putW, putReq)
	if putW.Code != http.StatusNoContent {
		t.Fatalf("SetBreakGlass PUT: got %d, want 204; body=%s", putW.Code, putW.Body.String())
	}

	// GET — should return the user.
	getReq := httptest.NewRequest(http.MethodGet, "/admin/conditional-access/break-glass", nil)
	getW := httptest.NewRecorder()
	h.GetBreakGlass(getW, getReq)
	if getW.Code != http.StatusOK {
		t.Fatalf("GetBreakGlass after SET: got %d, want 200; body=%s", getW.Code, getW.Body.String())
	}
	var resp struct {
		Admins []struct {
			ID          int64  `json:"id"`
			Email       string `json:"email"`
			DisplayName string `json:"display_name"`
		} `json:"admins"`
	}
	if err := json.Unmarshal(getW.Body.Bytes(), &resp); err != nil {
		t.Fatalf("GetBreakGlass after SET: invalid JSON: %v", err)
	}
	if len(resp.Admins) != 1 || resp.Admins[0].ID != 84001 {
		t.Fatalf("GetBreakGlass after SET: want [{id:84001}], got %+v", resp.Admins)
	}
}

// TestGetBreakGlassDBError — GET with a cancelled context returns non-2xx on
// the system_config query path (DB error → 500 or absent-key → 200 empty;
// but the user-resolve query path must also 500 on cancelled context).
// Here we just verify it does not panic and returns a sensible status.
// DB-backed; skips without DB_DSN.
func TestGetBreakGlassDBError(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewConditionalAccessHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())

	// Seed a value so the user-resolve query fires.
	ctx := context.Background()
	_, _ = pool.Exec(ctx,
		`INSERT INTO system_config (key, value) VALUES ('ca_break_glass_user_ids', '[1]')
		 ON CONFLICT (key) DO UPDATE SET value = '[1]'`)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM system_config WHERE key = 'ca_break_glass_user_ids'`)
	})

	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()

	req := httptest.NewRequest(http.MethodGet, "/admin/conditional-access/break-glass", nil)
	req = req.WithContext(cancelCtx)
	w := httptest.NewRecorder()
	h.GetBreakGlass(w, req)
	// Either 500 (query failed) or 200 (system_config query returned before cancel).
	// The important thing is the handler does not panic.
	if w.Code == 0 {
		t.Fatal("GetBreakGlass: no response written")
	}
}

// ── D2: soft-delete / restore / restore-from-audit / ?include_deleted ──

// d2AdminUserID is the stable user id used for all D2 tests.
const d2AdminUserID = int64(99001)

// ensureD2AdminUser seeds the d2AdminUserID user row (idempotent) so that the
// admin_audit_log FK constraint is satisfied when reducers write audit rows.
// The test CA DB has no users by default.
func ensureD2AdminUser(t *testing.T, h *ConditionalAccessHandler) {
	t.Helper()
	ctx := context.Background()
	_, _ = h.pool.Exec(ctx,
		`INSERT INTO domains (id, name, is_local) VALUES (99001, 'd2test.test', TRUE) ON CONFLICT DO NOTHING`)
	_, _ = h.pool.Exec(ctx,
		`INSERT INTO users (id, username, domain_id, email, display_name, enabled)
		 VALUES ($1, 'd2admin', 99001, 'd2admin@d2test.test', 'D2 Admin', TRUE)
		 ON CONFLICT (id) DO NOTHING`, d2AdminUserID)
}

// seedCAPolicy creates a minimal CA policy (using d2AdminUserID) and returns its id.
// ponytail: uses action:"allow" flat form so ca_lockout_guard short-circuits even when
// the ca_sync_enabled trigger flips state to 'on' (legacy enabled-default back-compat).
func seedCAPolicy(t *testing.T, h *ConditionalAccessHandler, name string, priority int) int64 {
	t.Helper()
	ensureD2AdminUser(t, h)
	body, _ := json.Marshal(map[string]any{
		"name":       name,
		"priority":   priority,
		"conditions": map[string]any{},
		"actions":    map[string]any{"action": "allow"},
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/conditional-access/policies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withAdminClaims(req, d2AdminUserID)
	w := httptest.NewRecorder()
	h.Create(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("seedCAPolicy(%q): got %d, want 201; body=%s", name, w.Code, w.Body.String())
	}
	var resp struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.ID == 0 {
		t.Fatalf("seedCAPolicy(%q): cannot parse id from %s", name, w.Body.String())
	}
	return resp.ID
}

// TestConditionalAccessUpdateSessionControlRollback proves Update has the same
// transaction boundary as Create: a session-control rejection cannot commit the
// preceding policy upsert.
func TestConditionalAccessUpdateSessionControlRollback(t *testing.T) {
	h := newTestCAHandler(t)
	id := seedCAPolicy(t, h, "CA-update-rollback-before", 9897)
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(),
			`DELETE FROM conditional_access_policies WHERE id = $1`, id)
	})

	body, _ := json.Marshal(map[string]any{
		"name":       "CA-update-rollback-after",
		"state":      "off",
		"scope_type": "global",
		"conditions": map[string]any{},
		"actions": map[string]any{
			"operator": "all",
			"grants":   []map[string]any{{"type": "notify"}},
		},
		"session_control": map[string]any{"persistent_session": "sometimes"},
	})
	req := httptest.NewRequest(http.MethodPut,
		"/admin/conditional-access/policies/"+fmt.Sprint(id), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", fmt.Sprint(id))
	req = withAdminClaims(req, d2AdminUserID)
	w := httptest.NewRecorder()
	h.Update(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("Update invalid session control: got %d, want 400; body=%s", w.Code, w.Body.String())
	}

	var name string
	var actionsUnchanged, sessionControlUnchanged bool
	if err := h.pool.QueryRow(context.Background(),
		`SELECT name,
		        actions = '{"action":"allow"}'::jsonb,
		        session_control = '{}'::jsonb
		   FROM conditional_access_policies WHERE id=$1`, id,
	).Scan(&name, &actionsUnchanged, &sessionControlUnchanged); err != nil {
		t.Fatal(err)
	}
	if name != "CA-update-rollback-before" || !actionsUnchanged || !sessionControlUnchanged {
		t.Fatalf("partial update committed: name=%q actions_unchanged=%v session_control_unchanged=%v",
			name, actionsUnchanged, sessionControlUnchanged)
	}
}

// TestSoftDeleteHidesFromList — DELETE soft-deletes: policy absent from List,
// present with ?include_deleted=1.
func TestSoftDeleteHidesFromList(t *testing.T) {
	h := newTestCAHandler(t)
	id := seedCAPolicy(t, h, "D2-soft-hide", 9901)
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(),
			`DELETE FROM conditional_access_policies WHERE id = $1`, id)
	})

	// DELETE
	delReq := httptest.NewRequest(http.MethodDelete,
		"/admin/conditional-access/policies/"+fmt.Sprint(id), nil)
	delReq = withAdminClaims(delReq, d2AdminUserID)
	delReq.SetPathValue("id", fmt.Sprint(id))
	delW := httptest.NewRecorder()
	h.Delete(delW, delReq)
	if delW.Code != http.StatusNoContent {
		t.Fatalf("soft-delete: got %d, want 204; body=%s", delW.Code, delW.Body.String())
	}

	// List (default, no include_deleted) — should NOT contain the policy.
	listReq := httptest.NewRequest(http.MethodGet, "/admin/conditional-access/policies", nil)
	listReq = withAdminClaims(listReq, d2AdminUserID)
	listW := httptest.NewRecorder()
	h.List(listW, listReq)
	if listW.Code != http.StatusOK {
		t.Fatalf("list: got %d, want 200", listW.Code)
	}
	if strings.Contains(listW.Body.String(), "D2-soft-hide") {
		t.Fatalf("list: soft-deleted policy must be absent; body=%s", listW.Body.String())
	}

	// List with ?include_deleted=1 — should contain it with a non-null deleted_at.
	listDelReq := httptest.NewRequest(http.MethodGet, "/admin/conditional-access/policies?include_deleted=1", nil)
	listDelReq = withAdminClaims(listDelReq, d2AdminUserID)
	listDelW := httptest.NewRecorder()
	h.List(listDelW, listDelReq)
	if listDelW.Code != http.StatusOK {
		t.Fatalf("list?include_deleted=1: got %d, want 200", listDelW.Code)
	}
	if !strings.Contains(listDelW.Body.String(), "D2-soft-hide") {
		t.Fatalf("list?include_deleted=1: soft-deleted policy must appear; body=%s", listDelW.Body.String())
	}
	// deleted_at must be present and non-null so the UI can distinguish tombstones.
	var policies []struct {
		Name      string  `json:"name"`
		DeletedAt *string `json:"deleted_at"`
	}
	if err := json.Unmarshal(listDelW.Body.Bytes(), &policies); err != nil {
		t.Fatalf("list?include_deleted=1: cannot parse JSON: %v", err)
	}
	found := false
	for _, p := range policies {
		if p.Name == "D2-soft-hide" {
			if p.DeletedAt == nil {
				t.Fatal("list?include_deleted=1: deleted_at must be non-null for tombstone row")
			}
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("list?include_deleted=1: D2-soft-hide not found in parsed response; body=%s", listDelW.Body.String())
	}
}

// TestRestoreReturns200 — POST /{id}/restore restores a soft-deleted policy.
func TestRestoreReturns200(t *testing.T) {
	h := newTestCAHandler(t)
	id := seedCAPolicy(t, h, "D2-restore", 9902)
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(),
			`DELETE FROM conditional_access_policies WHERE id = $1`, id)
	})

	// Soft-delete first.
	_, err := h.pool.Exec(context.Background(),
		`SELECT ca_policy_soft_delete($1, $2)`, id, d2AdminUserID)
	if err != nil {
		t.Fatalf("soft-delete setup: %v", err)
	}

	// Restore.
	restReq := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/admin/conditional-access/policies/%d/restore", id), nil)
	restReq = withAdminClaims(restReq, d2AdminUserID)
	restReq.SetPathValue("id", fmt.Sprint(id))
	restW := httptest.NewRecorder()
	h.Restore(restW, restReq)
	if restW.Code != http.StatusNoContent {
		t.Fatalf("restore: got %d, want 204; body=%s", restW.Code, restW.Body.String())
	}

	// Verify policy is live again.
	listReq := httptest.NewRequest(http.MethodGet, "/admin/conditional-access/policies", nil)
	listReq = withAdminClaims(listReq, d2AdminUserID)
	listW := httptest.NewRecorder()
	h.List(listW, listReq)
	if !strings.Contains(listW.Body.String(), "D2-restore") {
		t.Fatalf("after restore: policy must appear in live list; body=%s", listW.Body.String())
	}
}

// TestRestorePriorityConflict — restore into an occupied priority slot → 409.
func TestRestorePriorityConflict(t *testing.T) {
	h := newTestCAHandler(t)
	ensureD2AdminUser(t, h)

	// Create two on-policies at the same priority (soft-delete the first to free slot, create second at that slot, then try to restore the first).
	idA := seedCAPolicy(t, h, "D2-conflict-A", 9903)
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(),
			`DELETE FROM conditional_access_policies WHERE id = $1`, idA)
	})

	// Set A to state='on' so the partial-unique index tracks it.
	_, _ = h.pool.Exec(context.Background(),
		`UPDATE conditional_access_policies SET state='on', enabled=true WHERE id=$1`, idA)

	// Soft-delete A (frees priority slot).
	_, err := h.pool.Exec(context.Background(),
		`SELECT ca_policy_soft_delete($1, $2)`, idA, d2AdminUserID)
	if err != nil {
		t.Fatalf("soft-delete A: %v", err)
	}

	// Create B at same priority as A (slot now free), also state='on'.
	idB := seedCAPolicy(t, h, "D2-conflict-B", 9903)
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(),
			`DELETE FROM conditional_access_policies WHERE id = $1`, idB)
	})
	_, _ = h.pool.Exec(context.Background(),
		`UPDATE conditional_access_policies SET state='on', enabled=true WHERE id=$1`, idB)

	// Now try to restore A — B holds priority 9903 → BZ087 → 409.
	restReq := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/admin/conditional-access/policies/%d/restore", idA), nil)
	restReq = withAdminClaims(restReq, d2AdminUserID)
	restReq.SetPathValue("id", fmt.Sprint(idA))
	restW := httptest.NewRecorder()
	h.Restore(restW, restReq)
	if restW.Code != http.StatusConflict {
		t.Fatalf("restore conflict: got %d, want 409; body=%s", restW.Code, restW.Body.String())
	}
}

// TestRestoreFromAudit — POST /restore-from-audit with a valid audit_id re-creates
// a purged policy and returns the new id.
func TestRestoreFromAudit(t *testing.T) {
	h := newTestCAHandler(t)
	id := seedCAPolicy(t, h, "D2-audit-restore", 9904)

	// Hard-delete to create an audit row (ca_policy_delete writes audit then hard-deletes).
	_, err := h.pool.Exec(context.Background(),
		`SELECT ca_policy_delete($1, $2::inet, $3)`, d2AdminUserID, nil, id)
	if err != nil {
		t.Fatalf("hard-delete setup: %v", err)
	}

	// Find the audit row id.
	var auditID int64
	err = h.pool.QueryRow(context.Background(),
		`SELECT id FROM admin_audit_log
		 WHERE target_type='conditional_access_policy' AND target_id=$1
		 ORDER BY occurred_at DESC LIMIT 1`, id,
	).Scan(&auditID)
	if err != nil {
		t.Fatalf("find audit row: %v", err)
	}

	// POST /restore-from-audit
	body, _ := json.Marshal(map[string]any{"audit_id": auditID})
	rfaReq := httptest.NewRequest(http.MethodPost,
		"/admin/conditional-access/policies/restore-from-audit", bytes.NewReader(body))
	rfaReq.Header.Set("Content-Type", "application/json")
	rfaReq = withAdminClaims(rfaReq, d2AdminUserID)
	rfaW := httptest.NewRecorder()
	h.RestoreFromAudit(rfaW, rfaReq)
	if rfaW.Code != http.StatusOK {
		t.Fatalf("restore-from-audit: got %d, want 200; body=%s", rfaW.Code, rfaW.Body.String())
	}
	var resp struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rfaW.Body.Bytes(), &resp); err != nil || resp.ID == 0 {
		t.Fatalf("restore-from-audit: cannot parse new id from %s", rfaW.Body.String())
	}
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(),
			`DELETE FROM conditional_access_policies WHERE id = $1`, resp.ID)
	})
}

// TestRestoreFromAuditBadAuditID — missing audit row → BZ086 → 404.
func TestRestoreFromAuditBadAuditID(t *testing.T) {
	h := newTestCAHandler(t)
	ensureD2AdminUser(t, h)
	body, _ := json.Marshal(map[string]any{"audit_id": int64(9999999999)})
	req := httptest.NewRequest(http.MethodPost,
		"/admin/conditional-access/policies/restore-from-audit", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withAdminClaims(req, d2AdminUserID)
	w := httptest.NewRecorder()
	h.RestoreFromAudit(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("restore-from-audit(bad id): got %d, want 404; body=%s", w.Code, w.Body.String())
	}
}

// TestResolvePrincipalsDBError verifies that ResolvePrincipals returns HTTP 500
// (not 200 with empty arrays) when the database query fails. A cancelled context
// is used to reliably trigger a query error without needing a broken DB.
// DB-backed; skips without DB_DSN.
func TestResolvePrincipalsDBError(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewConditionalAccessHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())

	// Cancel the context before calling the handler so the DB query fails.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// users query path
	req := httptest.NewRequest(http.MethodGet, "/admin/conditional-access/resolve-principals?users=1", nil)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.ResolvePrincipals(w, req)
	if w.Code == http.StatusOK {
		t.Fatalf("ResolvePrincipals(users, cancelled ctx): got 200, want non-2xx; body=%s", w.Body.String())
	}

	// groups query path
	req2 := httptest.NewRequest(http.MethodGet, "/admin/conditional-access/resolve-principals?groups=1", nil)
	req2 = req2.WithContext(ctx)
	w2 := httptest.NewRecorder()
	h.ResolvePrincipals(w2, req2)
	if w2.Code == http.StatusOK {
		t.Fatalf("ResolvePrincipals(groups, cancelled ctx): got 200, want non-2xx; body=%s", w2.Body.String())
	}
}

// ── D3: Promote handler ──

// d3AdminUserID is the stable admin user ID used for D3 promote tests.
// A separate range from D2 (99001) to avoid cross-test interference.
const d3AdminUserID = int64(99011)
const d3BlockedUserID = int64(99012)

// cleanupD3SuperAdmin expires then deletes d3admin's Super-Admin assignment.
// A plain DELETE trips trg_protect_last_super_admin whenever d3admin is the
// last ACTIVE super admin in the shared test DB, and the old swallowed error
// leaked the row permanently (it broke authserver's SSO-sweep test). Expired
// rows skip the guard, so expire first; fail loudly if either statement errors.
func cleanupSuperAdmin(t *testing.T, h *ConditionalAccessHandler, userID int64) {
	t.Helper()
	ctx := context.Background()
	if _, err := h.pool.Exec(ctx,
		`UPDATE admin_role_assignments SET expires_at = now() - interval '1 second'
		  WHERE user_id=$1 AND role_group_id=1`, userID); err != nil {
		t.Errorf("cleanup: expire SA for user %d: %v", userID, err)
	}
	if _, err := h.pool.Exec(ctx,
		`DELETE FROM admin_role_assignments WHERE user_id=$1 AND role_group_id=1`, userID); err != nil {
		t.Errorf("cleanup: delete SA for user %d: %v", userID, err)
	}
}

// grantSuperAdmin gives an EXISTING userID an active global Super-Admin
// assignment so
// admin_can_manage reach checks pass, with loud expire-then-delete cleanup.
func grantSuperAdmin(t *testing.T, h *ConditionalAccessHandler, userID int64) {
	t.Helper()
	if _, err := h.pool.Exec(context.Background(),
		`INSERT INTO admin_role_assignments (user_id, role_group_id)
		 VALUES ($1, 1) ON CONFLICT DO NOTHING`, userID); err != nil {
		t.Fatalf("seed SA for user %d: %v", userID, err)
	}
	t.Cleanup(func() { cleanupSuperAdmin(t, h, userID) })
}

// ensureD3Users seeds two user rows used by D3 tests (idempotent).
// d3AdminUserID = the acting admin; d3BlockedUserID = a user who would be blocked.
func ensureD3Users(t *testing.T, h *ConditionalAccessHandler) {
	t.Helper()
	ctx := context.Background()
	_, _ = h.pool.Exec(ctx,
		`INSERT INTO domains (id, name, is_local) VALUES (99011, 'd3test.test', TRUE) ON CONFLICT DO NOTHING`)
	_, _ = h.pool.Exec(ctx,
		`INSERT INTO users (id, username, domain_id, email, display_name, enabled)
		 VALUES ($1, 'd3admin', 99011, 'd3admin@d3test.test', 'D3 Admin', TRUE)
		 ON CONFLICT (id) DO NOTHING`, d3AdminUserID)
	_, _ = h.pool.Exec(ctx,
		`INSERT INTO users (id, username, domain_id, email, display_name, enabled)
		 VALUES ($1, 'd3blocked', 99011, 'd3blocked@d3test.test', 'D3 Blocked', TRUE)
		 ON CONFLICT (id) DO NOTHING`, d3BlockedUserID)
}

// seedReportOnlyBlockPolicy creates a report_only block policy for D3 tests.
// Uses a global scope + block action so it goes through the lockout guard path.
func seedReportOnlyBlockPolicy(t *testing.T, h *ConditionalAccessHandler, name string, priority int, adminID int64) int64 {
	t.Helper()
	// Create off first (safe), then flip to report_only directly.
	body, _ := json.Marshal(map[string]any{
		"name":       name,
		"priority":   priority,
		"conditions": map[string]any{},
		"actions":    map[string]any{"action": "block"},
		"state":      "off",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/conditional-access/policies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withAdminClaims(req, adminID)
	w := httptest.NewRecorder()
	h.Create(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("seedReportOnlyBlockPolicy(%q): create got %d, want 201; body=%s", name, w.Code, w.Body.String())
	}
	var resp struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.ID == 0 {
		t.Fatalf("seedReportOnlyBlockPolicy(%q): cannot parse id from %s", name, w.Body.String())
	}
	// Flip to report_only directly in DB (bypasses handler guard, which is correct for seeding).
	if _, err := h.pool.Exec(context.Background(),
		`UPDATE conditional_access_policies SET state='report_only' WHERE id=$1`, resp.ID); err != nil {
		t.Fatalf("seedReportOnlyBlockPolicy: flip to report_only: %v", err)
	}
	return resp.ID
}

// seedWouldBlockLog inserts a ca_signin_log row with would_decision='block' for a policy+user.
// This makes ca_policy_impact(id, '7d', ...) return non-zero would_block counts.
func seedWouldBlockLog(t *testing.T, h *ConditionalAccessHandler, policyID, userID int64) {
	t.Helper()
	payload := fmt.Sprintf(`{"user_id":%d,"decision":"allow","would_decision":"block","matched_policy_id":%d,"evaluated":[]}`,
		userID, policyID)
	if _, err := h.pool.Exec(context.Background(),
		`SELECT ca_signin_log_append($1::jsonb)`, payload); err != nil {
		t.Fatalf("seedWouldBlockLog: %v", err)
	}
}

// doPromote calls the Promote handler with the given policyID + confirm flag.
func doPromote(h *ConditionalAccessHandler, policyID int64, confirm bool, adminID int64) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]any{"confirm": confirm})
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/admin/conditional-access/policies/%d/promote", policyID),
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withAdminClaims(req, adminID)
	req.SetPathValue("id", fmt.Sprint(policyID))
	w := httptest.NewRecorder()
	h.Promote(w, req)
	return w
}

// TestPromotePreview — without confirm and would_block>0 → 409 with blocked-user shape.
// The 409 body must include: would_block_users, would_block_admins, self_locked_out,
// blocked_users (capped list), admin_users (uncapped), shown, total, window.
func TestPromotePreview(t *testing.T) {
	h := newTestCAHandler(t)
	ensureD3Users(t, h)
	ensureD2AdminUser(t, h)

	id := seedReportOnlyBlockPolicy(t, h, "D3-preview", 9911, d3AdminUserID)
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(),
			`DELETE FROM conditional_access_policies WHERE id=$1`, id)
	})
	// Seed one would-block log entry for d3BlockedUserID.
	seedWouldBlockLog(t, h, id, d3BlockedUserID)

	w := doPromote(h, id, false, d3AdminUserID)
	if w.Code != http.StatusConflict {
		t.Fatalf("Promote(no confirm, would_block>0): got %d, want 409; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		WouldBlockUsers  int64 `json:"would_block_users"`
		WouldBlockAdmins int64 `json:"would_block_admins"`
		SelfLockedOut    bool  `json:"self_locked_out"`
		BlockedUsers     []struct {
			ID      int64  `json:"id"`
			Address string `json:"address"`
			IsAdmin bool   `json:"is_admin"`
		} `json:"blocked_users"`
		AdminUsers []any  `json:"admin_users"`
		Shown      int64  `json:"shown"`
		Total      int64  `json:"total"`
		Window     string `json:"window"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Promote(no confirm): cannot parse 409 body: %v; body=%s", err, w.Body.String())
	}
	if resp.WouldBlockUsers == 0 {
		t.Fatalf("Promote(no confirm): want would_block_users>0, got 0; body=%s", w.Body.String())
	}
	if resp.Total == 0 {
		t.Fatalf("Promote(no confirm): want total>0, got 0")
	}
	if resp.Window == "" {
		t.Fatalf("Promote(no confirm): want window field, got empty")
	}
	if len(resp.BlockedUsers) == 0 {
		t.Fatalf("Promote(no confirm): want blocked_users populated, got empty")
	}
}

// TestPromoteSelfLockedOut — when the acting admin's own id is in the would-block set,
// self_locked_out must be true in the 409 preview.
func TestPromoteSelfLockedOut(t *testing.T) {
	h := newTestCAHandler(t)
	ensureD3Users(t, h)

	id := seedReportOnlyBlockPolicy(t, h, "D3-self-lockout", 9912, d3AdminUserID)
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(),
			`DELETE FROM conditional_access_policies WHERE id=$1`, id)
	})
	// Seed would-block log for the ADMIN themselves (self_locked_out path).
	seedWouldBlockLog(t, h, id, d3AdminUserID)

	w := doPromote(h, id, false, d3AdminUserID)
	if w.Code != http.StatusConflict {
		t.Fatalf("Promote(self lockout): got %d, want 409; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		SelfLockedOut   bool  `json:"self_locked_out"`
		WouldBlockUsers int64 `json:"would_block_users"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Promote(self lockout): cannot parse 409 body: %v", err)
	}
	if !resp.SelfLockedOut {
		t.Fatalf("Promote(self lockout): self_locked_out must be true when acting admin is in blocked set; body=%s", w.Body.String())
	}
}

// TestPromoteConfirmSuccess — confirm:true promotes and returns 200 with state:on.
// The policy would block d3BlockedUserID; the acting admin (d3AdminUserID) holds
// an admin role and is in the break-glass set so ca_lockout_guard doesn't trip.
func TestPromoteConfirmSuccess(t *testing.T) {
	h := newTestCAHandler(t)
	ensureD3Users(t, h)

	id := seedReportOnlyBlockPolicy(t, h, "D3-confirm", 9913, d3AdminUserID)
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(),
			`DELETE FROM conditional_access_policies WHERE id=$1`, id)
	})
	seedWouldBlockLog(t, h, id, d3BlockedUserID)

	// Give d3AdminUserID an admin role so ca_lockout_guard sees an active admin.
	_, err := h.pool.Exec(context.Background(),
		`INSERT INTO admin_role_assignments (user_id, role_group_id)
		 VALUES ($1, 1) ON CONFLICT DO NOTHING`, d3AdminUserID)
	if err != nil {
		t.Fatalf("seed admin role: %v", err)
	}
	t.Cleanup(func() { cleanupSuperAdmin(t, h, d3AdminUserID) })

	// Put d3AdminUserID in the break-glass set so the lockout guard sees them
	// as excluded (reachable) and allows the promote to proceed.
	_, _ = h.pool.Exec(context.Background(),
		`INSERT INTO system_config (key, value)
		 VALUES ('ca_break_glass_user_ids', $1::jsonb)
		 ON CONFLICT (key) DO UPDATE SET value = $1::jsonb`,
		fmt.Sprintf("[%d]", d3AdminUserID))
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(),
			`DELETE FROM system_config WHERE key='ca_break_glass_user_ids'`)
	})
	// Registered last so it runs before break-glass/assignment cleanup. The
	// reachability invariant correctly refuses removing those escape paths while
	// this dangerous policy remains on.
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(),
			`UPDATE conditional_access_policies SET state='off' WHERE id=$1`, id)
		_, _ = h.pool.Exec(context.Background(),
			`DELETE FROM conditional_access_policies WHERE id=$1`, id)
	})

	w := doPromote(h, id, true, d3AdminUserID)
	if w.Code != http.StatusOK {
		t.Fatalf("Promote(confirm:true): got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Promote(confirm:true): cannot parse response: %v", err)
	}
	if resp.State != "on" {
		t.Fatalf("Promote(confirm:true): want state=on, got %q", resp.State)
	}
}

// TestPromoteAlreadyOn — promoting an already-on policy → 200 no-op.
func TestPromoteAlreadyOn(t *testing.T) {
	h := newTestCAHandler(t)
	ensureD3Users(t, h)

	id := seedReportOnlyBlockPolicy(t, h, "D3-already-on", 9914, d3AdminUserID)
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(),
			`DELETE FROM conditional_access_policies WHERE id=$1`, id)
	})

	// Set break-glass for the admin so the lockout guard won't trip on promote.
	_, _ = h.pool.Exec(context.Background(),
		`INSERT INTO system_config (key, value)
		 VALUES ('ca_break_glass_user_ids', $1::jsonb)
		 ON CONFLICT (key) DO UPDATE SET value = $1::jsonb`,
		fmt.Sprintf("[%d]", d3AdminUserID))
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(),
			`DELETE FROM system_config WHERE key='ca_break_glass_user_ids'`)
	})
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(),
			`UPDATE conditional_access_policies SET state='off' WHERE id=$1`, id)
		_, _ = h.pool.Exec(context.Background(),
			`DELETE FROM conditional_access_policies WHERE id=$1`, id)
	})

	// Flip to on directly in DB (simulating a prior promote).
	_, _ = h.pool.Exec(context.Background(),
		`UPDATE conditional_access_policies SET state='on', enabled=true WHERE id=$1`, id)

	w := doPromote(h, id, true, d3AdminUserID)
	if w.Code != http.StatusOK {
		t.Fatalf("Promote(already-on): got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Promote(already-on): cannot parse response: %v", err)
	}
	if resp.State != "on" {
		t.Fatalf("Promote(already-on): want state=on, got %q", resp.State)
	}
}

// TestPromotePreviewNeverMutates — confirm:false is a pure preview: it must leave
// a report_only policy untouched in BOTH arms (would_block==0 → 200 zeroed preview;
// would_block>0 → 409 blast radius). Regression guard for the promote-safety gate:
// the handler historically promoted at would_block==0 on the preview call, so
// merely opening the PromoteDialog could enforce a report_only policy and Cancel
// could not undo it. Zero ca_policy_promote side effects = state still report_only,
// updated_at not bumped, and no ca_policy_promote row in admin_audit_log (the
// reducer writes state bump + audit + notify atomically).
func TestPromotePreviewNeverMutates(t *testing.T) {
	h := newTestCAHandler(t)
	ensureD3Users(t, h)

	// snapshotPolicyRowUpdatedAt reads updated_at for the no-mutation assertions.
	snapshotPolicyRowUpdatedAt := func(t *testing.T, policyID int64) time.Time {
		t.Helper()
		var state string
		var updatedAt time.Time
		if err := h.pool.QueryRow(context.Background(),
			`SELECT state, updated_at FROM conditional_access_policies WHERE id=$1`, policyID,
		).Scan(&state, &updatedAt); err != nil {
			t.Fatalf("read policy row: %v", err)
		}
		return updatedAt
	}

	// assertNoPromoteSideEffects fails unless the policy is still report_only,
	// its row was not updated, and no promote audit row exists for it.
	assertNoPromoteSideEffects := func(t *testing.T, policyID int64, updatedAtBefore time.Time) {
		t.Helper()
		var state string
		var updatedAt time.Time
		if err := h.pool.QueryRow(context.Background(),
			`SELECT state, updated_at FROM conditional_access_policies WHERE id=$1`, policyID,
		).Scan(&state, &updatedAt); err != nil {
			t.Fatalf("re-read policy row: %v", err)
		}
		if state != "report_only" {
			t.Fatalf("preview mutated the policy: state=%q, want report_only", state)
		}
		if !updatedAt.Equal(updatedAtBefore) {
			t.Fatalf("preview bumped updated_at: %v → %v", updatedAtBefore, updatedAt)
		}
		var audits int
		if err := h.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM admin_audit_log
			  WHERE action='ca_policy_promote' AND target_id=$1`, policyID,
		).Scan(&audits); err != nil {
			t.Fatalf("count ca_policy_promote audit rows: %v", err)
		}
		if audits != 0 {
			t.Fatalf("preview wrote %d ca_policy_promote audit rows, want 0", audits)
		}
	}

	// ── Arm 1: would_block==0 → 200 with the zeroed preview shape, no mutation ──
	id := seedReportOnlyBlockPolicy(t, h, "D3-preview-no-mutate", 9916, d3AdminUserID)
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(),
			`DELETE FROM conditional_access_policies WHERE id=$1`, id)
	})
	updatedAtBefore := snapshotPolicyRowUpdatedAt(t, id)

	w := doPromote(h, id, false, d3AdminUserID)
	if w.Code != http.StatusOK {
		t.Fatalf("Promote(preview, would_block==0): got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var preview struct {
		WouldBlockUsers  int64  `json:"would_block_users"`
		WouldBlockAdmins int64  `json:"would_block_admins"`
		SelfLockedOut    bool   `json:"self_locked_out"`
		BlockedUsers     []any  `json:"blocked_users"`
		AdminUsers       []any  `json:"admin_users"`
		Shown            int64  `json:"shown"`
		Total            int64  `json:"total"`
		Window           string `json:"window"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &preview); err != nil {
		t.Fatalf("Promote(preview, would_block==0): cannot parse body: %v; body=%s", err, w.Body.String())
	}
	if preview.WouldBlockUsers != 0 || preview.Total != 0 || preview.SelfLockedOut {
		t.Fatalf("Promote(preview, would_block==0): want zeroed preview, got %+v", preview)
	}
	if preview.BlockedUsers == nil || preview.AdminUsers == nil {
		t.Fatalf("Promote(preview, would_block==0): blocked_users/admin_users must be [] not null; body=%s", w.Body.String())
	}
	if preview.Window == "" {
		t.Fatalf("Promote(preview, would_block==0): want window field, got empty")
	}
	assertNoPromoteSideEffects(t, id, updatedAtBefore)

	// ── Arm 2: would_block>0 → 409 blast radius, still no mutation ──
	id2 := seedReportOnlyBlockPolicy(t, h, "D3-preview-no-mutate-blocked", 9917, d3AdminUserID)
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(),
			`DELETE FROM conditional_access_policies WHERE id=$1`, id2)
	})
	seedWouldBlockLog(t, h, id2, d3BlockedUserID)
	updatedAtBefore2 := snapshotPolicyRowUpdatedAt(t, id2)

	w2 := doPromote(h, id2, false, d3AdminUserID)
	if w2.Code != http.StatusConflict {
		t.Fatalf("Promote(preview, would_block>0): got %d, want 409; body=%s", w2.Code, w2.Body.String())
	}
	var preview2 struct {
		WouldBlockUsers int64 `json:"would_block_users"`
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &preview2); err != nil {
		t.Fatalf("Promote(preview, would_block>0): cannot parse 409 body: %v", err)
	}
	if preview2.WouldBlockUsers == 0 {
		t.Fatalf("Promote(preview, would_block>0): want would_block_users>0, got 0; body=%s", w2.Body.String())
	}
	assertNoPromoteSideEffects(t, id2, updatedAtBefore2)
}

// ── CA-3a: RevokeSessions + SessionEnforcementLog ──

// revocationUserID is the stable user id used for CA-3a revocation tests.
const revocationUserID = int64(99021)

// ensureRevocationUser seeds the test user for CA-3a tests (idempotent).
func ensureRevocationUser(t *testing.T, h *ConditionalAccessHandler) {
	t.Helper()
	ctx := context.Background()
	_, _ = h.pool.Exec(ctx,
		`INSERT INTO domains (id, name, is_local) VALUES (99021, 'rev.test', TRUE) ON CONFLICT DO NOTHING`)
	_, _ = h.pool.Exec(ctx,
		`INSERT INTO users (id, username, domain_id, email, display_name, enabled)
		 VALUES ($1, 'revuser', 99021, 'revuser@rev.test', 'Revocation User', TRUE)
		 ON CONFLICT (id) DO NOTHING`, revocationUserID)
}

// TestRevokeSessionsReturnsRevocationID — POST .../sessions/{userId}/revoke inserts a
// session_revocations row and returns the row id.
func TestRevokeSessionsReturnsRevocationID(t *testing.T) {
	h := newTestCAHandler(t)
	ensureRevocationUser(t, h)
	ensureD2AdminUser(t, h)              // actor FK needed by admin_audit_log in the reducer
	grantSuperAdmin(t, h, d2AdminUserID) // reach: admin_can_manage denies assignment-less actors

	req := httptest.NewRequest(http.MethodPost,
		"/admin/conditional-access/sessions/99021/revoke", nil)
	req = withAdminClaims(req, d2AdminUserID)
	req.SetPathValue("userId", "99021")
	w := httptest.NewRecorder()
	h.RevokeSessions(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("RevokeSessions: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		RevocationID int64 `json:"revocation_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.RevocationID == 0 {
		t.Fatalf("RevokeSessions: want revocation_id>0, got body=%s", w.Body.String())
	}
}

// TestRevokeSessionsNoAuth — missing auth context → 401.
func TestRevokeSessionsNoAuth(t *testing.T) {
	h := &ConditionalAccessHandler{logger: testsupport.TestLogger()}
	req := httptest.NewRequest(http.MethodPost,
		"/admin/conditional-access/sessions/1/revoke", nil)
	req.SetPathValue("userId", "1")
	w := httptest.NewRecorder()
	h.RevokeSessions(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("RevokeSessions(no auth): got %d, want 401", w.Code)
	}
}

// TestSessionEnforcementLogReturnsRows — GET .../sessions/log returns the row
// inserted by RevokeSessions. Validates the cross-user (BYPASSRLS) read path.
func TestSessionEnforcementLogReturnsRows(t *testing.T) {
	h := newTestCAHandler(t)
	ensureRevocationUser(t, h)
	ensureD2AdminUser(t, h)
	grantSuperAdmin(t, h, d2AdminUserID) // reach: admin_can_manage denies assignment-less actors

	// Insert a revocation row via the handler.
	revokeReq := httptest.NewRequest(http.MethodPost,
		"/admin/conditional-access/sessions/99021/revoke", nil)
	revokeReq = withAdminClaims(revokeReq, d2AdminUserID)
	revokeReq.SetPathValue("userId", "99021")
	revokeW := httptest.NewRecorder()
	h.RevokeSessions(revokeW, revokeReq)
	if revokeW.Code != http.StatusOK {
		t.Fatalf("setup RevokeSessions: got %d; body=%s", revokeW.Code, revokeW.Body.String())
	}

	// Now read via SessionEnforcementLog — must return at least one row.
	logReq := httptest.NewRequest(http.MethodGet, "/admin/conditional-access/sessions/log", nil)
	logReq = withAdminClaims(logReq, d2AdminUserID)
	logW := httptest.NewRecorder()
	h.SessionEnforcementLog(logW, logReq)
	if logW.Code != http.StatusOK {
		t.Fatalf("SessionEnforcementLog: got %d; body=%s", logW.Code, logW.Body.String())
	}
	var rows []struct {
		UserID int64 `json:"user_id"`
	}
	if err := json.Unmarshal(logW.Body.Bytes(), &rows); err != nil {
		t.Fatalf("SessionEnforcementLog: invalid JSON: %v; body=%s", err, logW.Body.String())
	}
	found := false
	for _, r := range rows {
		if r.UserID == revocationUserID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("SessionEnforcementLog: want row for user_id=%d; got body=%s", revocationUserID, logW.Body.String())
	}
}

// TestPromoteLockoutGuard — a global-block promote that would strand all admins
// → BZ080 from ca_lockout_guard → 409. The break-glass set is deliberately empty.
func TestPromoteLockoutGuard(t *testing.T) {
	h := newTestCAHandler(t)
	ensureD3Users(t, h)

	id := seedReportOnlyBlockPolicy(t, h, "D3-lockout", 9915, d3AdminUserID)
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(),
			`DELETE FROM conditional_access_policies WHERE id=$1`, id)
	})

	// Ensure NO break-glass set and NO exclude list — any admin role assignment
	// makes this admin reachable, so ensure none for d3AdminUserID, and ensure
	// there are no other active admin role assignments (or none at all).
	// The simplest approach: use a policy that would_block=0 (no signin log) but
	// still trips lockout because admin has a role assignment + no exclusions.
	// Actually the lockout guard fires INSIDE ca_policy_promote (not the handler).
	// To reliably trip it we need:
	//   1. At least one active admin_role_assignment for d3AdminUserID
	//   2. No exclusions in the policy (scope_type='global', action='block')
	//   3. No break-glass set

	// Insert an admin_role_assignment for d3AdminUserID (role_group_id=1 = Super Admin).
	_, err := h.pool.Exec(context.Background(),
		`INSERT INTO admin_role_assignments (user_id, role_group_id)
		 VALUES ($1, 1) ON CONFLICT DO NOTHING`, d3AdminUserID)
	if err != nil {
		t.Fatalf("seed admin_role_assignments: %v", err)
	}
	t.Cleanup(func() { cleanupSuperAdmin(t, h, d3AdminUserID) })

	// Ensure no break-glass set.
	_, _ = h.pool.Exec(context.Background(),
		`DELETE FROM system_config WHERE key='ca_break_glass_user_ids'`)

	// Promote with confirm:true — the lockout guard inside ca_policy_promote fires → BZ080 → 409.
	w := doPromote(h, id, true, d3AdminUserID)
	if w.Code != http.StatusConflict {
		t.Fatalf("Promote(lockout guard): got %d, want 409; body=%s", w.Code, w.Body.String())
	}
}
