package admin

// Coverage suite for the changed retention handler lines the ownership suite
// does not reach: the unauthenticated 401 arms, transaction-begin failures,
// ATOMIC-commit failures (F-002: a failed commit must leave NO policy row),
// audit-write failures, the pre-image read error branch, and the untouched
// log-retention/RunPrune handlers.
//
// Failure injection follows the package's shadow-schema pattern
// (openMAMListFixturePool): planted deferred-trigger commit failures and a
// planted failing audit_write — never production edits.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"setjoin.com/shared/testsupport"
)

// retentionCovFixtureSQL is the shadow retention_policies table with the full
// projection shape. __TRIGGER__ may carry the deferred commit-failure trigger.
const retentionCovFixtureSQL = `
	CREATE TABLE __SCHEMA__.retention_policies(
		id bigserial PRIMARY KEY,
		name text NOT NULL,
		description text NOT NULL DEFAULT '',
		retain_days int,
		action text NOT NULL DEFAULT 'delete',
		is_default boolean NOT NULL DEFAULT false,
		domain_id bigint,
		created_at timestamptz NOT NULL DEFAULT now());`

// retentionCovCommitFailTrigger is appended AFTER the seed rows are inserted,
// so the seeding transactions commit before the deferred trigger exists.
const retentionCovCommitFailTrigger = `
	CREATE FUNCTION __SCHEMA__.retention_commit_fail() RETURNS trigger
	LANGUAGE plpgsql AS $fn$ BEGIN
	  RAISE EXCEPTION 'planted deferred commit failure';
	END $fn$;
	CREATE CONSTRAINT TRIGGER retention_commit_fail_trg
	AFTER INSERT OR UPDATE OR DELETE ON __SCHEMA__.retention_policies
	DEFERRABLE INITIALLY DEFERRED
	FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.retention_commit_fail();`

// retentionCovAuditFailFn plants a failing audit_write: audit.Write's
// unqualified SELECT audit_write(...) resolves shadow-first.
const retentionCovAuditFailFn = `
	CREATE FUNCTION __SCHEMA__.audit_write(
		p_actor bigint, p_action text, p_target_type text, p_target_id bigint,
		p_before jsonb, p_after jsonb, p_ip inet, p_notes text, p_tier text
	) RETURNS void LANGUAGE plpgsql AS $fn$ BEGIN
	  RAISE EXCEPTION 'planted audit failure';
	END $fn$;`

// TestRetentionWrites_Unauthenticated_401 proves the RequireUser arms on all
// three policy mutators: no claims in context → 401 problem, no DB work.
func TestRetentionWrites_Unauthenticated_401(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRetentionHandler(pool, testsupport.TestLogger())

	// Requests WITHOUT auth claims (plain context, no ContextWithUser).
	req := httptest.NewRequest(http.MethodPost, "/admin/retention/policies", stringReader(`{"name":"x"}`))
	rec := httptest.NewRecorder()
	h.CreatePolicy(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("create without claims: want 401, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPut, "/admin/retention/policies/1", stringReader(`{"name":"x"}`))
	req.SetPathValue("id", "1")
	rec = httptest.NewRecorder()
	h.UpdatePolicy(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("update without claims: want 401, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodDelete, "/admin/retention/policies/1", nil)
	req.SetPathValue("id", "1")
	rec = httptest.NewRecorder()
	h.DeletePolicy(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("delete without claims: want 401, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestRetentionWrites_TxBeginFailure_500 proves the Begin arms: a closed pool
// fails the transaction before any statement and every mutator answers 5xx.
func TestRetentionWrites_TxBeginFailure_500(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRetentionHandler(pool, testsupport.TestLogger())
	pool.Close() // Begin must fail; the handler maps it to a DB-error problem.

	actor := int64(96412)
	req := newRetentionRequest(t, http.MethodPost, "/admin/retention/policies", "", `{"name":"retown-cov-begin"}`, actor, 0)
	rec := httptest.NewRecorder()
	h.CreatePolicy(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("create begin failure: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	req = newRetentionRequest(t, http.MethodPut, "/admin/retention/policies/1", "1", `{"name":"retown-cov-begin"}`, actor, 0)
	rec = httptest.NewRecorder()
	h.UpdatePolicy(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("update begin failure: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	req = newRetentionRequest(t, http.MethodDelete, "/admin/retention/policies/1", "1", "", actor, 0)
	rec = httptest.NewRecorder()
	h.DeletePolicy(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("delete begin failure: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestRetentionWrites_CommitFailure_500 proves the commit arms of the ATOMIC
// mutation+audit contract (F-002): a deferred trigger that raises at COMMIT
// fails all three mutators AFTER their statements ran — every response is a
// 5xx and the shadow table keeps ZERO rows (the whole transaction rolled
// back, audit row included).
func TestRetentionWrites_CommitFailure_500(t *testing.T) {
	actor := retCovSeedActorPool(t)
	shadowPool := openMAMListFixturePool(t, retentionCovFixtureSQL+`
		INSERT INTO __SCHEMA__.retention_policies (id, name, description, retain_days, action)
		VALUES (424242, 'retown-cov-commit', '', 30, 'delete');`+retentionCovCommitFailTrigger)
	h := NewRetentionHandler(shadowPool, testsupport.TestLogger())

	// Create: INSERT runs, audit_write (real, public) runs, COMMIT raises.
	req := newRetentionRequest(t, http.MethodPost, "/admin/retention/policies", "",
		`{"name":"retown-cov-commit-create","retainDays":7}`, actor, 0)
	rec := httptest.NewRecorder()
	h.CreatePolicy(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("create commit failure: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	// Update: pre-image read + UPDATE + audit run, COMMIT raises.
	req = newRetentionRequest(t, http.MethodPut, "/admin/retention/policies/424242", "424242",
		`{"name":"retown-cov-commit-update"}`, actor, 0)
	rec = httptest.NewRecorder()
	h.UpdatePolicy(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("update commit failure: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	// Delete: DELETE RETURNING + audit run, COMMIT raises.
	req = newRetentionRequest(t, http.MethodDelete, "/admin/retention/policies/424242", "424242", "", actor, 0)
	rec = httptest.NewRecorder()
	h.DeletePolicy(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("delete commit failure: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	// Nothing persisted anywhere: every mutation (and its audit row) rolled back.
	var n int
	if err := shadowPool.QueryRow(context.Background(),
		`SELECT count(*) FROM retention_policies`).Scan(&n); err != nil {
		t.Fatalf("count shadow policies: %v", err)
	}
	if n != 1 { // only the seeded row 424242 survives
		t.Fatalf("shadow policy rows after commit failures = %d, want 1 (seed only)", n)
	}
}

// TestRetentionWrites_AuditFailure_500 proves the audit arms: a planted
// failing audit_write rolls the mutation back (deferred tx.Rollback) and the
// mutator answers 5xx — no unaudited policy row.
func TestRetentionWrites_AuditFailure_500(t *testing.T) {
	shadowPool := openMAMListFixturePool(t, retentionCovFixtureSQL+`
		INSERT INTO __SCHEMA__.retention_policies (id, name, description, retain_days, action)
		VALUES (424243, 'retown-cov-audit', '', 30, 'delete');`+retentionCovAuditFailFn)
	h := NewRetentionHandler(shadowPool, testsupport.TestLogger())
	actor := int64(96412)

	req := newRetentionRequest(t, http.MethodPost, "/admin/retention/policies", "",
		`{"name":"retown-cov-audit-create"}`, actor, 0)
	rec := httptest.NewRecorder()
	h.CreatePolicy(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("create audit failure: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	req = newRetentionRequest(t, http.MethodPut, "/admin/retention/policies/424243", "424243",
		`{"name":"retown-cov-audit-update"}`, actor, 0)
	rec = httptest.NewRecorder()
	h.UpdatePolicy(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("update audit failure: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	req = newRetentionRequest(t, http.MethodDelete, "/admin/retention/policies/424243", "424243", "", actor, 0)
	rec = httptest.NewRecorder()
	h.DeletePolicy(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("delete audit failure: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	// Every rolled-back mutation left the shadow rows untouched.
	var names []string
	rows, err := shadowPool.Query(context.Background(), `SELECT name FROM retention_policies`)
	if err != nil {
		t.Fatalf("list shadow policies: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		names = append(names, name)
	}
	if len(names) != 1 || names[0] != "retown-cov-audit" {
		t.Fatalf("shadow policies after audit failures = %v, want [retown-cov-audit] (seed only)", names)
	}
}

// TestRetentionUpdatePolicy_PreImageFailure_500 proves the pre-image read's
// non-ErrNoRows arm: a shadow table missing the projected action column fails
// the locked pre-image SELECT and the handler answers 5xx (never a bare 404
// over an infrastructure error).
func TestRetentionUpdatePolicy_PreImageFailure_500(t *testing.T) {
	shadowPool := openMAMListFixturePool(t, `
		CREATE TABLE __SCHEMA__.retention_policies(
			id bigserial PRIMARY KEY, name text NOT NULL, description text DEFAULT '',
			retain_days int, is_default boolean DEFAULT false, domain_id bigint,
			created_at timestamptz DEFAULT now());
		INSERT INTO __SCHEMA__.retention_policies (id, name) VALUES (424244, 'retown-cov-preimage');`)
	h := NewRetentionHandler(shadowPool, testsupport.TestLogger())

	req := newRetentionRequest(t, http.MethodPut, "/admin/retention/policies/424244", "424244",
		`{"name":"retown-cov-preimage-2"}`, 96412, 0)
	rec := httptest.NewRecorder()
	h.UpdatePolicy(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("pre-image failure: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestRetentionLogRetention_GetSet_RoundTrip covers GetLogRetention and
// SetLogRetention end to end: the four system_config keys are written ("0" =
// forever) and read back with the >0 projection (0/invalid → nil).
func TestRetentionLogRetention_GetSet_RoundTrip(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRetentionHandler(pool, testsupport.TestLogger())
	ctx := context.Background()

	keys := []string{
		"log_retention_message_trace_days",
		"log_retention_mailbox_audit_days",
		"log_retention_auth_event_days",
		"log_retention_webhook_delivery_days",
	}
	prior := make(map[string]*string)
	for _, k := range keys {
		var raw []byte
		if err := pool.QueryRow(ctx, `SELECT value FROM system_config WHERE key = $1`, k).Scan(&raw); err == nil {
			v := string(raw)
			prior[k] = &v
		}
	}
	t.Cleanup(func() {
		c := context.Background()
		for _, k := range keys {
			if v := prior[k]; v != nil {
				_, _ = pool.Exec(c, `UPDATE system_config SET value = $2, updated_at = now() WHERE key = $1`, k, *v)
			} else {
				_, _ = pool.Exec(c, `DELETE FROM system_config WHERE key = $1`, k)
			}
		}
	})

	// Set: 45 / 0 (forever) / omitted (forever) / 12.
	setReq := httptest.NewRequest(http.MethodPut, "/admin/retention/logs",
		stringReader(`{"messageTraceDays":45,"mailboxAuditLogDays":0,"webhookDeliveryDays":12}`))
	setRec := httptest.NewRecorder()
	h.SetLogRetention(setRec, setReq)
	if setRec.Code != http.StatusNoContent {
		t.Fatalf("SetLogRetention: want 204, got %d (body=%s)", setRec.Code, setRec.Body.String())
	}

	// Invalid JSON → 400.
	badReq := httptest.NewRequest(http.MethodPut, "/admin/retention/logs", stringReader(`{`))
	badRec := httptest.NewRecorder()
	h.SetLogRetention(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("SetLogRetention invalid JSON: want 400, got %d", badRec.Code)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/admin/retention/logs", nil)
	getRec := httptest.NewRecorder()
	h.GetLogRetention(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GetLogRetention: want 200, got %d (body=%s)", getRec.Code, getRec.Body.String())
	}
	var got struct {
		MessageTraceDays    *int `json:"messageTraceDays"`
		MailboxAuditLogDays *int `json:"mailboxAuditLogDays"`
		AuthEventDays       *int `json:"authEventDays"`
		WebhookDeliveryDays *int `json:"webhookDeliveryDays"`
	}
	if err := json.Unmarshal(getRec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode log retention: %v", err)
	}
	if got.MessageTraceDays == nil || *got.MessageTraceDays != 45 {
		t.Errorf("messageTraceDays = %v, want 45", got.MessageTraceDays)
	}
	if got.MailboxAuditLogDays != nil {
		t.Errorf("mailboxAuditLogDays = %v, want nil (0 = forever)", got.MailboxAuditLogDays)
	}
	if got.AuthEventDays != nil {
		t.Errorf("authEventDays = %v, want nil (never set)", got.AuthEventDays)
	}
	if got.WebhookDeliveryDays == nil || *got.WebhookDeliveryDays != 12 {
		t.Errorf("webhookDeliveryDays = %v, want 12", got.WebhookDeliveryDays)
	}
}

// TestRetentionRunPrune_ReturnsTables covers RunPrune against the real
// prune_log_tables() read: 200 with a JSON array of {table, deleted} rows.
func TestRetentionRunPrune_ReturnsTables(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRetentionHandler(pool, testsupport.TestLogger())

	req := httptest.NewRequest(http.MethodPost, "/admin/retention/prune", nil)
	rec := httptest.NewRecorder()
	h.RunPrune(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("RunPrune: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var out []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode prune results: %v", err)
	}
	if len(out) == 0 {
		t.Fatalf("prune results empty: %s", rec.Body.String())
	}
	if _, ok := out[0]["table"]; !ok {
		t.Errorf("prune row missing table key: %v", out[0])
	}
	if _, ok := out[0]["deleted"]; !ok {
		t.Errorf("prune row missing deleted key: %v", out[0])
	}
}

// retCovSeedActorPool seeds one real actor user for audit-FK validity and
// returns its id (distinct range: 9642x).
func retCovSeedActorPool(t *testing.T) int64 {
	t.Helper()
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	domainID := int64(96420)
	actorID := int64(96421)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	if _, err := pool.Exec(ctx,
		`INSERT INTO domains (id, name, is_local) VALUES ($1, $2, TRUE)
		 ON CONFLICT (id) DO NOTHING`, domainID, "retcov.test"); err != nil {
		t.Fatalf("seed retcov domain: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO users (id, username, domain_id, email, display_name, enabled)
		 VALUES ($1, $2, $3, $4, 'R', TRUE)
		 ON CONFLICT (id) DO NOTHING`,
		actorID, "retcov_"+suffix, domainID, "retcov@retcov.test"); err != nil {
		t.Fatalf("seed retcov actor: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM admin_audit_log WHERE user_id = $1`, actorID)
		_, _ = pool.Exec(c, `DELETE FROM users WHERE id = $1`, actorID)
	})
	return actorID
}
