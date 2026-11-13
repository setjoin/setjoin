package user

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/pgxutil"
)

// WP3 moved the four /admin/rules writes into rule_config_* reducers; these
// tests drive the handlers end-to-end against the loaded disposable DB and
// prove both the preserved API outcomes and the audit rows the reducers now
// write. They need DB_DSN (testsupport.OpenTestPool fail-closes under CI's
// REQUIRE_DB=1, skips cleanly for plain local runs without a server).

func TestRulesHandlers_WriteThroughReducers(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	h := NewRulesHandler(pgxutil.WorkerPool{Pool: pool}, testLogger())

	// Fixture: domain + user + owned mailbox (distinct range; ON CONFLICT keeps
	// reruns idempotent).
	const (
		domainID  = 96200
		userID    = 6201
		mailboxID = 962001
		otherID   = 6202
	)
	mustExec := func(t *testing.T, sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed (%s): %v", sql[:40], err)
		}
	}
	mustExec(t, `INSERT INTO domains (id, name, is_local) VALUES ($1, 'rules-handler.test', TRUE)
		ON CONFLICT (id) DO NOTHING`, domainID)
	mustExec(t, `INSERT INTO users (id, username, domain_id, email, display_name, enabled)
		VALUES ($1, 'rh', $2, 'rh@rules-handler.test', 'Rules Handler', TRUE)
		ON CONFLICT (id) DO NOTHING`, userID, domainID)
	mustExec(t, `INSERT INTO mailboxes (id, user_id, domain_id, email, display_name, is_primary)
		VALUES ($1, $2, $3, 'rh@rules-handler.test', 'RH', TRUE)
		ON CONFLICT (id) DO NOTHING`, mailboxID, userID, domainID)
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM admin_audit_log
			WHERE action LIKE 'rule_config_%'
			  AND target_id IN (SELECT id FROM rules WHERE mailbox_id = $1)`, mailboxID)
		pool.Exec(c, `DELETE FROM admin_audit_log
			WHERE action LIKE 'rule_config_%'
			  AND target_id NOT IN (SELECT id FROM rules)`, mailboxID)
		pool.Exec(c, `DELETE FROM rules WHERE mailbox_id = $1`, mailboxID)
		pool.Exec(c, `DELETE FROM mailboxes WHERE id = $1`, mailboxID)
		pool.Exec(c, `DELETE FROM users WHERE id = $1`, userID)
		pool.Exec(c, `DELETE FROM domains WHERE id = $1`, domainID)
	})

	auditCount := func(t *testing.T, action string) int64 {
		t.Helper()
		var n int64
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM admin_audit_log WHERE action = $1 AND target_type = 'rule'`,
			action).Scan(&n); err != nil {
			t.Fatalf("audit count: %v", err)
		}
		return n
	}

	call := func(t *testing.T, actorID int64, method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		var req *http.Request
		if body == "" {
			req = httptest.NewRequest(method, path, nil)
		} else {
			req = httptest.NewRequest(method, path, strings.NewReader(body))
		}
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: actorID}))
		rec := httptest.NewRecorder()
		switch {
		case method == http.MethodPost && strings.HasSuffix(path, "/admin/rules"):
			h.Create(rec, req)
		case method == http.MethodPut:
			h.Update(rec, req)
		case method == http.MethodDelete:
			h.Delete(rec, req)
		default:
			t.Fatalf("unrouted call: %s %s", method, path)
		}
		return rec
	}

	id := func(t *testing.T) int64 {
		t.Helper()
		var n int64
		if err := pool.QueryRow(ctx,
			`SELECT id FROM rules WHERE name = 'wp3-handler-rule'`).Scan(&n); err != nil {
			t.Fatalf("locate created rule: %v", err)
		}
		return n
	}

	// ── Create: 201 {id} + audited ──────────────────────────────────────────
	before := auditCount(t, "rule_config_create")
	rec := call(t, userID, http.MethodPost, "/admin/rules",
		`{"name":"wp3-handler-rule","enabled":true,"priority":3,"runOn":"server",`+
			`"mailboxId":`+strconv.FormatInt(mailboxID, 10)+`,`+
			`"isTransportRule":false,"conditions":{},"actions":[],"stopProcessing":false}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}
	if after := auditCount(t, "rule_config_create"); after != before+1 {
		t.Fatalf("create did not land a rule_config_create audit row (%d → %d)", before, after)
	}

	// ── Update: wrong actor 404 without a row; owner 204 with one ───────────
	ruleID := strconv.FormatInt(id(t), 10)
	beforeU := auditCount(t, "rule_config_update")
	if rec := call(t, otherID, http.MethodPut, "/admin/rules/"+ruleID,
		`{"enabled":false}`); rec.Code != http.StatusNotFound {
		t.Fatalf("wrong-actor update = %d, want 404", rec.Code)
	}
	if after := auditCount(t, "rule_config_update"); after != beforeU {
		t.Fatal("refused update wrote an audit row")
	}
	if rec := call(t, userID, http.MethodPut, "/admin/rules/"+ruleID,
		`{"enabled":false}`); rec.Code != http.StatusNoContent {
		t.Fatalf("owner update = %d: %s", rec.Code, rec.Body.String())
	}
	if after := auditCount(t, "rule_config_update"); after != beforeU+1 {
		t.Fatal("owner update did not land a rule_config_update audit row")
	}

	// ── Delete by the owner: 204 + audited ──────────────────────────────────
	beforeD := auditCount(t, "rule_config_delete")
	if rec := call(t, userID, http.MethodDelete, "/admin/rules/"+ruleID, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("owner delete = %d: %s", rec.Code, rec.Body.String())
	}
	if after := auditCount(t, "rule_config_delete"); after != beforeD+1 {
		t.Fatal("owner delete did not land a rule_config_delete audit row")
	}
}
