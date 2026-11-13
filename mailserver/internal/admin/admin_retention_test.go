package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/testsupport"
)

func TestRetentionListPoliciesScansTimestampAndScopesDomains(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRetentionHandler(pool, testsupport.TestLogger())
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	var domainA, domainB int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ($1) RETURNING id`, "retention-a-"+suffix+".test").Scan(&domainA); err != nil {
		t.Fatalf("seed domain A: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ($1) RETURNING id`, "retention-b-"+suffix+".test").Scan(&domainB); err != nil {
		t.Fatalf("seed domain B: %v", err)
	}
	policyA := "retention-a-" + suffix
	policyB := "retention-b-" + suffix
	if _, err := pool.Exec(ctx, `
		INSERT INTO retention_policies (name, description, retain_days, action, domain_id)
		VALUES ($1, '', 30, 'delete', $2), ($3, '', 60, 'hold', $4)`,
		policyA, domainA, policyB, domainB); err != nil {
		t.Fatalf("seed policies: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM domains WHERE id IN ($1, $2)`, domainA, domainB)
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/retention/policies", nil)
	req = req.WithContext(middleware.ContextWithDomainScope(req.Context(), domainA))
	rec := httptest.NewRecorder()
	h.ListPolicies(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ListPolicies: got %d body=%s, want 200", rec.Code, rec.Body.String())
	}

	var policies []struct {
		Name      string    `json:"name"`
		CreatedAt time.Time `json:"createdAt"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &policies); err != nil {
		t.Fatalf("decode policies: %v", err)
	}
	foundA := false
	for _, policy := range policies {
		if policy.Name == policyB {
			t.Fatalf("domain A response leaked domain B policy: %+v", policy)
		}
		if policy.Name == policyA {
			foundA = true
			if policy.CreatedAt.IsZero() {
				t.Fatalf("createdAt was not projected: %+v", policy)
			}
		}
	}
	if !foundA {
		t.Fatalf("domain A policy missing from response: %+v", policies)
	}
}

func TestRetentionPolicyJSON(t *testing.T) {
	v := 30
	createdAt := time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)
	p := retentionPolicy{
		ID:          1,
		Name:        "Test",
		Description: "desc",
		RetainDays:  &v,
		Action:      "delete",
		IsDefault:   true,
		CreatedAt:   createdAt,
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if parsed["name"] != "Test" || parsed["retainDays"] != float64(30) || parsed["action"] != "delete" {
		t.Fatalf("unexpected policy projection: %+v", parsed)
	}
	if parsed["createdAt"] != createdAt.Format(time.RFC3339) {
		t.Fatalf("createdAt=%v, want %s", parsed["createdAt"], createdAt.Format(time.RFC3339))
	}
}

func TestRetentionPolicyNullDays(t *testing.T) {
	p := retentionPolicy{ID: 2, Name: "Forever", RetainDays: nil, Action: "hold"}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if parsed["retainDays"] != nil {
		t.Fatalf("retainDays should be nil for forever, got %v", parsed["retainDays"])
	}
}

func TestLogRetentionSettingsJSON(t *testing.T) {
	v := 30
	settings := logRetentionSettings{MessageTraceDays: &v, MailboxAuditLogDays: nil}
	b, err := json.Marshal(settings)
	if err != nil {
		t.Fatalf("marshal settings: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("unmarshal settings: %v", err)
	}
	if parsed["messageTraceDays"] != float64(30) || parsed["mailboxAuditLogDays"] != nil {
		t.Fatalf("unexpected settings projection: %+v", parsed)
	}
}

func TestLogRetentionSettingsRoundTrip(t *testing.T) {
	v1, v2 := 30, 90
	want := logRetentionSettings{MessageTraceDays: &v1, MailboxAuditLogDays: &v2}
	b, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal settings: %v", err)
	}
	var got logRetentionSettings
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal settings: %v", err)
	}
	if got.MessageTraceDays == nil || *got.MessageTraceDays != 30 || got.MailboxAuditLogDays == nil || *got.MailboxAuditLogDays != 90 {
		t.Fatalf("settings mismatch after round-trip: %+v", got)
	}
}

// ── med-shard3-007 F-002 (Astra waves34 HOLD 4): retention mutations and
// their audit rows commit atomically, with accurate images and rollback on
// audit failure. ─────────────────────────────────────────────────────────────

// retentionAuditPoisonedRequest builds a request whose ClientIP fails the
// audit_write inet cast, so audit.Write returns an error deterministically —
// the rollback path's trigger — without touching any shared DB state.
func retentionAuditPoisonedRequest(method, target, body string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.RemoteAddr = "not-an-ip:9999" // → ClientIP "not-an-ip" → $7::inet cast error
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID: 1, IsAdmin: true,
	}))
	return req
}

// TestRetentionPolicyCreateRollsBackWhenAuditFails proves the create is
// atomic with its audit: when the audit row cannot be persisted the INSERT
// rolls back, the API answers 500, and no unaudited policy row survives.
func TestRetentionPolicyCreateRollsBackWhenAuditFails(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRetentionHandler(pool, testsupport.TestLogger())
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	policyName := "retention-atomic-create-" + suffix

	req := retentionAuditPoisonedRequest(http.MethodPost, "/admin/retention/policies",
		`{"name":"`+policyName+`","retainDays":30,"action":"delete"}`)
	rec := httptest.NewRecorder()
	h.CreatePolicy(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("create with failing audit: got %d body=%s, want 500", rec.Code, rec.Body.String())
	}
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM retention_policies WHERE name = $1`, policyName).Scan(&n); err != nil {
		t.Fatalf("count policies: %v", err)
	}
	if n != 0 {
		t.Fatalf("unaudited policy creation survived the audit failure: %d row(s)", n)
	}
	// And the failed audit left no audit row either (the whole tx rolled back).
	var a int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_audit_log WHERE action = 'retention_policy_create'
		  AND after_state->>'name' = $1`, policyName).Scan(&a); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	if a != 0 {
		t.Fatalf("failed audit wrote a partial audit row: %d", a)
	}
}

// TestRetentionPolicyDeleteRollsBackWhenAuditFails proves the delete is
// atomic with its audit: when the audit row cannot be persisted the DELETE
// rolls back and the policy row survives.
func TestRetentionPolicyDeleteRollsBackWhenAuditFails(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRetentionHandler(pool, testsupport.TestLogger())
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	policyName := "retention-atomic-delete-" + suffix

	var policyID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO retention_policies (name, description, retain_days, action)
		 VALUES ($1, '', 30, 'delete') RETURNING id`, policyName).Scan(&policyID); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM retention_policies WHERE id = $1`, policyID) //nolint:errcheck
	})

	req := retentionAuditPoisonedRequest(http.MethodDelete,
		fmt.Sprintf("/admin/retention/policies/%d", policyID), "")
	req.SetPathValue("id", fmt.Sprintf("%d", policyID))
	rec := httptest.NewRecorder()
	h.DeletePolicy(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("delete with failing audit: got %d body=%s, want 500", rec.Code, rec.Body.String())
	}
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM retention_policies WHERE id = $1`, policyID).Scan(&n); err != nil {
		t.Fatalf("count policies: %v", err)
	}
	if n != 1 {
		t.Fatalf("unaudited policy deletion survived the audit failure: policy row is gone")
	}
}

// TestRetentionPolicyUpdateAuditsAccurateBeforeAndAfterImages proves the
// update audit carries BOTH images fed from the row itself — before from the
// locked pre-row (retainDays 30), after from the patch's RETURNING (90) —
// and that the whole transition commits with its audit row.
func TestRetentionPolicyUpdateAuditsAccurateBeforeAndAfterImages(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRetentionHandler(pool, testsupport.TestLogger())
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	policyName := "retention-atomic-update-" + suffix

	var policyID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO retention_policies (name, description, retain_days, action)
		 VALUES ($1, '', 30, 'delete') RETURNING id`, policyName).Scan(&policyID); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM retention_policies WHERE id = $1`, policyID) //nolint:errcheck
	})

	req := httptest.NewRequest(http.MethodPatch,
		fmt.Sprintf("/admin/retention/policies/%d", policyID),
		strings.NewReader(`{"retainDays":90}`))
	req.SetPathValue("id", fmt.Sprintf("%d", policyID))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 1, IsAdmin: true}))
	rec := httptest.NewRecorder()
	h.UpdatePolicy(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("update: got %d body=%s, want 204", rec.Code, rec.Body.String())
	}

	var beforeDays, afterDays string
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT before_state->>'retainDays', after_state->>'retainDays', count(*) OVER ()
		   FROM admin_audit_log
		  WHERE action = 'retention_policy_update' AND target_id = $1
		  ORDER BY id DESC LIMIT 1`, policyID).Scan(&beforeDays, &afterDays, &n); err != nil {
		t.Fatalf("read update audit row: %v", err)
	}
	if beforeDays != "30" || afterDays != "90" {
		t.Fatalf("update audit images inaccurate: before retainDays=%s (want 30), after=%s (want 90)",
			beforeDays, afterDays)
	}
}
