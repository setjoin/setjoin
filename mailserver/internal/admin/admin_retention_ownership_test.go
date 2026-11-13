package admin

// med-shard3-007 (F-002): R3 domain-ownership predicates plus audit rows on
// retention policy writes. A domain-scoped compliance.write holder must not
// be able to create/retarget/delete another domain's policy via sequential
// ids, the request's domainId must never be inserted verbatim (ownership
// comes from the auth-context domain scope), and every successful write must
// emit an admin_audit_log row.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

// Fixed fixture ids (distinct range: 9641x, not used by any other fixture in
// this package). Real users rows are required — admin_audit_log.user_id is
// FK'd to users(id) and the audit rows are the assertion target.
const (
	retOwnDomainA = int64(96410)
	retOwnDomainB = int64(96411)
	retOwnActorA  = int64(96412)
	retOwnActorB  = int64(96413)
	retOwnActorG  = int64(96414)
)

// seedRetOwnFixtures seeds two domains and three actor users. Cleanup deletes
// in FK-safe dependency order (policies → users → domains).
func seedRetOwnFixtures(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seedRetOwnFixtures: %v: %v", sql, err)
		}
	}
	exec(`INSERT INTO domains (id, name, is_local) VALUES ($1, 'retown-a.test', TRUE)
	      ON CONFLICT (id) DO NOTHING`, retOwnDomainA)
	exec(`INSERT INTO domains (id, name, is_local) VALUES ($1, 'retown-b.test', TRUE)
	      ON CONFLICT (id) DO NOTHING`, retOwnDomainB)
	exec(`INSERT INTO users (id, username, domain_id, email, display_name, enabled)
	      VALUES ($1, 'retown_a', $4, 'retown_a@retown-a.test', 'A', TRUE),
	             ($2, 'retown_b', $5, 'retown_b@retown-b.test', 'B', TRUE),
	             ($3, 'retown_g', $4, 'retown_g@retown-a.test', 'G', TRUE)
	      ON CONFLICT (id) DO NOTHING`,
		retOwnActorA, retOwnActorB, retOwnActorG, retOwnDomainA, retOwnDomainB)
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM retention_policies WHERE domain_id IN ($1, $2) OR domain_id IS NULL AND name LIKE 'retown-%'`, retOwnDomainA, retOwnDomainB) //nolint:errcheck
		pool.Exec(c, `DELETE FROM users WHERE id IN ($1, $2, $3)`, retOwnActorA, retOwnActorB, retOwnActorG)                                                   //nolint:errcheck
		pool.Exec(c, `DELETE FROM domains WHERE id IN ($1, $2)`, retOwnDomainA, retOwnDomainB)                                                                 //nolint:errcheck
	})
}

// retentionScopeClaims returns admin claims carrying compliance.write.
func retentionScopeClaims(userID int64) *auth.Claims {
	return &auth.Claims{
		UserID:      userID,
		IsAdmin:     true,
		Permissions: []string{permissions.PermComplianceWrite},
	}
}

// newRetentionRequest builds a request with a JSON body, compliance.write
// claims, and the given auth-context domain scope. pathID populates the {id}
// path value (httptest.NewRequest never parses path values itself).
func newRetentionRequest(t *testing.T, method, target, pathID, body string, actorID, scope int64) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, target, bytes.NewReader([]byte(body)))
	if pathID != "" {
		req.SetPathValue("id", pathID)
	}
	req = req.WithContext(auth.ContextWithUser(
		middleware.ContextWithDomainScope(req.Context(), scope),
		retentionScopeClaims(actorID),
	))
	return req
}

// retentionAuditCount counts audit rows for one (target_id, action, actor).
// Target ids are freshly-minted serials per run, so counts are exact.
func retentionAuditCount(t *testing.T, pool *pgxpool.Pool, targetID int64, action string, actor int64) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM admin_audit_log WHERE target_id = $1 AND action = $2 AND user_id = $3`,
		targetID, action, actor).Scan(&n); err != nil {
		t.Fatalf("audit count %s: %v", action, err)
	}
	return n
}

// TestRetentionPolicy_ScopedCreate_RejectsForeignDomainAndForcesScope proves
// R2 on CreatePolicy: a domain-scoped compliance.write holder (1) cannot
// inject another domain's id via the request body (403, no row created
// there), and (2) gets the policy stamped with their OWN auth-context scope —
// including when the body omits domainId entirely (a scoped actor must not be
// able to mint a NULL-domain/global policy either).
func TestRetentionPolicy_ScopedCreate_RejectsForeignDomainAndForcesScope(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedRetOwnFixtures(t, pool)
	h := NewRetentionHandler(pool, testsupport.TestLogger())
	ctx := context.Background()

	// (1) verbatim-DomainID injection: actor scoped to domain A posts
	// domainId=<domain B> → 403 and no policy row in domain B.
	req := newRetentionRequest(t, http.MethodPost, "/admin/retention/policies", "",
		fmt.Sprintf(`{"name":"retown-inject","domainId":%d}`, retOwnDomainB), retOwnActorA, retOwnDomainA)
	rec := httptest.NewRecorder()
	h.CreatePolicy(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-domain create: got %d body=%s, want 403", rec.Code, rec.Body.String())
	}
	var injected int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM retention_policies WHERE name = 'retown-inject' AND domain_id = $1`,
		retOwnDomainB).Scan(&injected); err != nil {
		t.Fatalf("count injected: %v", err)
	}
	if injected != 0 {
		t.Fatalf("request domainId was inserted verbatim: %d policy row(s) created in domain B", injected)
	}

	// (2) body names the actor's own domain → 201, and the stored domain_id is
	// the auth-context scope.
	req = newRetentionRequest(t, http.MethodPost, "/admin/retention/policies", "",
		fmt.Sprintf(`{"name":"retown-owned","domainId":%d}`, retOwnDomainA), retOwnActorA, retOwnDomainA)
	rec = httptest.NewRecorder()
	h.CreatePolicy(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("own-domain create: got %d body=%s, want 201", rec.Code, rec.Body.String())
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.ID == 0 {
		t.Fatalf("decode create response: %v (%s)", err, rec.Body.String())
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM retention_policies WHERE id = $1`, created.ID) //nolint:errcheck
	})
	var gotDomain int64
	if err := pool.QueryRow(ctx,
		`SELECT domain_id FROM retention_policies WHERE id = $1`, created.ID).Scan(&gotDomain); err != nil {
		t.Fatalf("reload created policy: %v", err)
	}
	if gotDomain != retOwnDomainA {
		t.Fatalf("created policy domain_id = %d, want auth-context scope %d", gotDomain, retOwnDomainA)
	}

	// (3) body omits domainId → still stamped with the auth-context scope,
	// never NULL (a scoped actor cannot mint a global policy).
	req = newRetentionRequest(t, http.MethodPost, "/admin/retention/policies", "",
		`{"name":"retown-nodom"}`, retOwnActorA, retOwnDomainA)
	rec = httptest.NewRecorder()
	h.CreatePolicy(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("no-domain create: got %d body=%s, want 201", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.ID == 0 {
		t.Fatalf("decode second create response: %v (%s)", err, rec.Body.String())
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM retention_policies WHERE id = $1`, created.ID) //nolint:errcheck
	})
	if err := pool.QueryRow(ctx,
		`SELECT domain_id FROM retention_policies WHERE id = $1`, created.ID).Scan(&gotDomain); err != nil {
		t.Fatalf("reload second created policy: %v", err)
	}
	if gotDomain != retOwnDomainA {
		t.Fatalf("no-domain create domain_id = %d, want scope %d (NULL = global is out of a scoped actor's reach)", gotDomain, retOwnDomainA)
	}

	// Audit rows on every successful create.
	if n := retentionAuditCount(t, pool, created.ID, "retention_policy_create", retOwnActorA); n != 1 {
		t.Fatalf("retention_policy_create audit rows = %d, want 1", n)
	}
}

// TestRetentionPolicy_ScopedUpdateDelete_ConfinedToOwnDomain proves R3 on
// UpdatePolicy/DeletePolicy: a domain-scoped compliance.write holder cannot
// retarget, patch, or delete another domain's policy (or a global NULL-domain
// one) via sequential ids — each is not-found — while their own domain's
// policy patches and deletes fine; a retarget to a foreign domain in the body
// is rejected outright.
func TestRetentionPolicy_ScopedUpdateDelete_ConfinedToOwnDomain(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedRetOwnFixtures(t, pool)
	h := NewRetentionHandler(pool, testsupport.TestLogger())
	ctx := context.Background()

	// Sequential ids: policyA (domain A), policyB (domain B), policyGlobal
	// (NULL domain = org-wide).
	var policyA, policyB, policyGlobal int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO retention_policies (name, description, retain_days, action, domain_id)
		 VALUES ('retown-pol-a', '', 30, 'delete', $1) RETURNING id`, retOwnDomainA).Scan(&policyA); err != nil {
		t.Fatalf("seed policyA: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO retention_policies (name, description, retain_days, action, domain_id)
		 VALUES ('retown-pol-b', '', 30, 'delete', $1) RETURNING id`, retOwnDomainB).Scan(&policyB); err != nil {
		t.Fatalf("seed policyB: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO retention_policies (name, description, retain_days, action, domain_id)
		 VALUES ('retown-pol-global', '', 30, 'delete', NULL) RETURNING id`).Scan(&policyGlobal); err != nil {
		t.Fatalf("seed policyGlobal: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(),
			`DELETE FROM retention_policies WHERE id IN ($1, $2, $3)`, policyA, policyB, policyGlobal) //nolint:errcheck
	})

	// Actor scoped to domain B: patching domain A's policy is not-found.
	req := newRetentionRequest(t, http.MethodPut, fmt.Sprintf("/admin/retention/policies/%d", policyA),
		fmt.Sprintf("%d", policyA), `{"name":"hijacked"}`, retOwnActorB, retOwnDomainB)
	rec := httptest.NewRecorder()
	h.UpdatePolicy(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("update foreign policy: got %d body=%s, want 404", rec.Code, rec.Body.String())
	}
	// ...so is patching the global NULL-domain policy.
	req = newRetentionRequest(t, http.MethodPut, fmt.Sprintf("/admin/retention/policies/%d", policyGlobal),
		fmt.Sprintf("%d", policyGlobal), `{"name":"hijacked"}`, retOwnActorB, retOwnDomainB)
	rec = httptest.NewRecorder()
	h.UpdatePolicy(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("update global policy: got %d body=%s, want 404", rec.Code, rec.Body.String())
	}
	// ...and so is deleting either.
	for _, target := range []int64{policyA, policyGlobal} {
		req = newRetentionRequest(t, http.MethodDelete, fmt.Sprintf("/admin/retention/policies/%d", target),
			fmt.Sprintf("%d", target), "", retOwnActorB, retOwnDomainB)
		rec = httptest.NewRecorder()
		h.DeletePolicy(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("delete policy %d: got %d body=%s, want 404", target, rec.Code, rec.Body.String())
		}
	}
	// The untouched rows really are untouched.
	var nameA, nameGlobal string
	if err := pool.QueryRow(ctx, `SELECT name FROM retention_policies WHERE id = $1`, policyA).Scan(&nameA); err != nil || nameA != "retown-pol-a" {
		t.Fatalf("policyA mutated by foreign actor: name=%q err=%v", nameA, err)
	}
	if err := pool.QueryRow(ctx, `SELECT name FROM retention_policies WHERE id = $1`, policyGlobal).Scan(&nameGlobal); err != nil || nameGlobal != "retown-pol-global" {
		t.Fatalf("policyGlobal mutated by foreign actor: name=%q err=%v", nameGlobal, err)
	}

	// Retargeting the actor's OWN policy to a foreign domain is rejected.
	req = newRetentionRequest(t, http.MethodPut, fmt.Sprintf("/admin/retention/policies/%d", policyB),
		fmt.Sprintf("%d", policyB), fmt.Sprintf(`{"domainId":%d}`, retOwnDomainA), retOwnActorB, retOwnDomainB)
	rec = httptest.NewRecorder()
	h.UpdatePolicy(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("retarget own policy to foreign domain: got %d body=%s, want 403", rec.Code, rec.Body.String())
	}
	var gotDomain int64
	if err := pool.QueryRow(ctx, `SELECT domain_id FROM retention_policies WHERE id = $1`, policyB).Scan(&gotDomain); err != nil || gotDomain != retOwnDomainB {
		t.Fatalf("policyB retargeted despite 403: domain_id=%d err=%v", gotDomain, err)
	}

	// Own-domain patch and delete succeed, and each writes its audit row.
	req = newRetentionRequest(t, http.MethodPut, fmt.Sprintf("/admin/retention/policies/%d", policyB),
		fmt.Sprintf("%d", policyB), `{"name":"retown-pol-b2"}`, retOwnActorB, retOwnDomainB)
	rec = httptest.NewRecorder()
	h.UpdatePolicy(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("own-domain update: got %d body=%s, want 204", rec.Code, rec.Body.String())
	}
	if n := retentionAuditCount(t, pool, policyB, "retention_policy_update", retOwnActorB); n != 1 {
		t.Fatalf("retention_policy_update audit rows = %d, want 1", n)
	}

	req = newRetentionRequest(t, http.MethodDelete, fmt.Sprintf("/admin/retention/policies/%d", policyB),
		fmt.Sprintf("%d", policyB), "", retOwnActorB, retOwnDomainB)
	rec = httptest.NewRecorder()
	h.DeletePolicy(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("own-domain delete: got %d body=%s, want 204", rec.Code, rec.Body.String())
	}
	if n := retentionAuditCount(t, pool, policyB, "retention_policy_delete", retOwnActorB); n != 1 {
		t.Fatalf("retention_policy_delete audit rows = %d, want 1", n)
	}
	var remaining int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM retention_policies WHERE id = $1`, policyB).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("own-domain delete did not remove the row: count=%d err=%v", remaining, err)
	}
}

// TestRetentionPolicy_UnscopedWrites_Audited proves the global arm: an
// unscoped (global) compliance.write holder may still target any domain
// (including NULL = the legitimately global policy tier), and every write —
// create, update, delete — emits its audit row.
func TestRetentionPolicy_UnscopedWrites_Audited(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedRetOwnFixtures(t, pool)
	h := NewRetentionHandler(pool, testsupport.TestLogger())
	ctx := context.Background()

	// Create in a named domain (global admins may target domains) and a NULL
	// global one.
	var inDomain, globalOne int64
	req := newRetentionRequest(t, http.MethodPost, "/admin/retention/policies", "",
		fmt.Sprintf(`{"name":"retown-g-dom","domainId":%d}`, retOwnDomainA), retOwnActorG, 0)
	rec := httptest.NewRecorder()
	h.CreatePolicy(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("unscoped domain-targeted create: got %d body=%s, want 201", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &struct {
		ID *int64 `json:"id"`
	}{&inDomain}); err != nil || inDomain == 0 {
		t.Fatalf("decode create response: %v (%s)", err, rec.Body.String())
	}
	var gotDomain int64
	if err := pool.QueryRow(ctx, `SELECT domain_id FROM retention_policies WHERE id = $1`, inDomain).Scan(&gotDomain); err != nil || gotDomain != retOwnDomainA {
		t.Fatalf("unscoped targeted create domain_id = %d err=%v, want %d", gotDomain, err, retOwnDomainA)
	}

	req = newRetentionRequest(t, http.MethodPost, "/admin/retention/policies", "",
		`{"name":"retown-g-global"}`, retOwnActorG, 0)
	rec = httptest.NewRecorder()
	h.CreatePolicy(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("unscoped global create: got %d body=%s, want 201", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &struct {
		ID *int64 `json:"id"`
	}{&globalOne}); err != nil || globalOne == 0 {
		t.Fatalf("decode global create response: %v (%s)", err, rec.Body.String())
	}
	var isNULL bool
	if err := pool.QueryRow(ctx, `SELECT domain_id IS NULL FROM retention_policies WHERE id = $1`, globalOne).Scan(&isNULL); err != nil || !isNULL {
		t.Fatalf("unscoped global create domain_id not NULL: err=%v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM retention_policies WHERE id IN ($1, $2)`, inDomain, globalOne) //nolint:errcheck
	})

	if n := retentionAuditCount(t, pool, inDomain, "retention_policy_create", retOwnActorG); n != 1 {
		t.Fatalf("targeted create audit rows = %d, want 1", n)
	}
	if n := retentionAuditCount(t, pool, globalOne, "retention_policy_create", retOwnActorG); n != 1 {
		t.Fatalf("global create audit rows = %d, want 1", n)
	}

	// Update + delete, each audited.
	req = newRetentionRequest(t, http.MethodPut, fmt.Sprintf("/admin/retention/policies/%d", inDomain),
		fmt.Sprintf("%d", inDomain), `{"name":"retown-g-dom2"}`, retOwnActorG, 0)
	rec = httptest.NewRecorder()
	h.UpdatePolicy(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("unscoped update: got %d body=%s, want 204", rec.Code, rec.Body.String())
	}
	if n := retentionAuditCount(t, pool, inDomain, "retention_policy_update", retOwnActorG); n != 1 {
		t.Fatalf("update audit rows = %d, want 1", n)
	}

	req = newRetentionRequest(t, http.MethodDelete, fmt.Sprintf("/admin/retention/policies/%d", globalOne),
		fmt.Sprintf("%d", globalOne), "", retOwnActorG, 0)
	rec = httptest.NewRecorder()
	h.DeletePolicy(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("unscoped delete: got %d body=%s, want 204", rec.Code, rec.Body.String())
	}
	if n := retentionAuditCount(t, pool, globalOne, "retention_policy_delete", retOwnActorG); n != 1 {
		t.Fatalf("delete audit rows = %d, want 1", n)
	}
}
