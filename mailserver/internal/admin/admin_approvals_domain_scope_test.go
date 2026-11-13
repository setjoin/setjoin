package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

// TestApprovalAudit_DomainScope is the TODOS.md "approval_requests.domain_id"
// follow-up proof: GET /admin/approval-requests/audit must scope to the
// caller's domain (middleware.DomainScopeFromContext), mirroring admin_users.go
// — an admin scoped to domain A must not see domain B's approval requests, but
// an unscoped (global) admin still sees both. RLS is unchanged (an admin with
// approvals.view still passes the row-visibility policy for every domain); the
// domain restriction is an additional application-layer WHERE, same posture as
// admin_users.go's ListUsers.
func TestApprovalAudit_DomainScope(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewApprovalsHandler(pool, testsupport.TestLogger())
	ctx := context.Background()

	domA := ensureScopeTestDomain(t, pool, "approval-audit-scopea.example")
	domB := ensureScopeTestDomain(t, pool, "approval-audit-scopeb.example")

	// The actor: a real Super Admin assignment (role_group_id=1) so the RLS
	// admin_is_super branch grants row visibility across every domain — the
	// domain restriction under test is purely the Go-layer WHERE clause.
	actorID := createScopeTestUser(t, pool, domA, "approval-audit-scopea.example")
	if _, err := pool.Exec(ctx,
		`INSERT INTO admin_role_assignments (user_id, role_group_id) VALUES ($1, 1)`, actorID,
	); err != nil {
		t.Fatalf("assign super admin: %v", err)
	}
	t.Cleanup(func() {
		// Expire the synthetic assignment before deleting it. Otherwise this
		// fixture can become the database's last active Super Admin and the
		// production BZ064 guard correctly refuses cleanup, leaking the actor
		// into later packages that share mailserver_test.
		_, _ = pool.Exec(ctx, `
			UPDATE admin_role_assignments
			   SET expires_at = statement_timestamp() - interval '1 second'
			 WHERE user_id = $1 AND role_group_id = 1`, actorID)
		_, _ = pool.Exec(ctx,
			`DELETE FROM admin_role_assignments WHERE user_id = $1`, actorID)
	})

	subjectA := "domain-scope-audit-A"
	subjectB := "domain-scope-audit-B"
	insertAuditRequest := func(subject string, domainID int64) int64 {
		var id int64
		if err := pool.QueryRow(ctx, `
			INSERT INTO approval_requests
			  (consumer_type, requester_user_id, subject, payload, approver_kind, approver_ref, expires_at, domain_id)
			VALUES ('mail.external_send', $1, $2, '{}'::jsonb, 'user', $1, now()+interval '1h', $3)
			RETURNING id`,
			actorID, subject, domainID,
		).Scan(&id); err != nil {
			t.Fatalf("insert request %q: %v", subject, err)
		}
		t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM approval_requests WHERE id = $1`, id) }) //nolint:errcheck
		return id
	}
	insertAuditRequest(subjectA, domA)
	insertAuditRequest(subjectB, domB)

	doList := func(domainScope int64) []approvalRequestAuditRow {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/admin/approval-requests/audit?limit=500", nil)
		reqCtx := auth.ContextWithUser(req.Context(), &auth.Claims{
			UserID: actorID, IsAdmin: true, Permissions: permissions.AllPermissions,
		})
		if domainScope > 0 {
			reqCtx = middleware.ContextWithDomainScope(reqCtx, domainScope)
		}
		req = req.WithContext(reqCtx)
		w := httptest.NewRecorder()
		h.ListAudit(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("ListAudit: want 200, got %d — %s", w.Code, w.Body.String())
		}
		var out []approvalRequestAuditRow
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return out
	}

	hasSubject := func(rows []approvalRequestAuditRow, subject string) bool {
		for _, r := range rows {
			if r.Subject == subject {
				return true
			}
		}
		return false
	}

	// Scoped to domain A: sees A's request, NOT B's.
	scopedA := doList(domA)
	if !hasSubject(scopedA, subjectA) {
		t.Error("domain-A-scoped admin: missing domain A's own request")
	}
	if hasSubject(scopedA, subjectB) {
		t.Error("domain-A-scoped admin: leaked domain B's request")
	}

	// Unscoped (global) admin: sees both.
	unscoped := doList(0)
	if !hasSubject(unscoped, subjectA) || !hasSubject(unscoped, subjectB) {
		t.Error("unscoped admin: expected to see both domain A and domain B requests")
	}
}
