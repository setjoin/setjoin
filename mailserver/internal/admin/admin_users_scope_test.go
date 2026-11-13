package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/pgxutil"
)

// ── domain-scope IDOR regression suite ──────────────────────────────────────
//
// A domain-scoped admin (claims.DomainScope) must NOT be able to read or mutate
// users in a DIFFERENT domain. These tests seed two domains (A and B), each with
// a user, inject a request context scoped to domain A, and assert that the
// domain-A admin cannot touch the domain-B user (404 — indistinguishable from
// missing) while still being able to act on the domain-A user. All seeded rows
// are cleaned up in t.Cleanup.

// ensureScopeTestDomain creates (or finds) a named test domain and returns its ID.
func ensureScopeTestDomain(t *testing.T, pool *pgxpool.Pool, name string) int64 {
	t.Helper()
	ctx := context.Background()
	var id int64
	err := pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ($1)
		 ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
		 RETURNING id`, name,
	).Scan(&id)
	if err != nil {
		t.Fatalf("ensureScopeTestDomain(%s): %v", name, err)
	}
	return id
}

// createScopeTestUser inserts a user + primary mailbox in the given domain and
// returns the user ID. Cleanup removes the mailbox (triggers disabled) + user.
func createScopeTestUser(t *testing.T, pool *pgxpool.Pool, domainID int64, domainName string) int64 {
	t.Helper()
	ctx := context.Background()
	suffix := mailboxRandomSuffix(t)
	email := "scopetest-" + suffix + "@" + domainName
	var userID int64
	err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, password_hash, domain_id)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		"scopetest-"+suffix, email, "Scope Test", "$2a$10$placeholder", domainID,
	).Scan(&userID)
	if err != nil {
		t.Fatalf("createScopeTestUser: %v", err)
	}
	// Primary mailbox (so quota/alias paths have something to resolve).
	mboxEmail := "scopembox-" + suffix + "@" + domainName
	_, err = pool.Exec(ctx,
		`INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary)
		 VALUES ($1, $2, $3, $4, 'personal', TRUE)`,
		userID, domainID, mboxEmail, "Scope Mbox",
	)
	if err != nil {
		t.Fatalf("createScopeTestUser (mailbox): %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `ALTER TABLE mailboxes DISABLE TRIGGER ALL`)
		pool.Exec(c, `DELETE FROM mailboxes WHERE user_id = $1`, userID)
		pool.Exec(c, `ALTER TABLE mailboxes ENABLE TRIGGER ALL`)
		pool.Exec(c, `DELETE FROM users WHERE id = $1`, userID)
	})
	return userID
}

// scopedReq builds a GET/DELETE/etc request with the "id" path value set and a
// context carrying the given domain scope AND an authenticated actor.
//
// The mutating handlers (Update/Delete/ResetPassword) now require auth claims
// (claims.UserID feeds admin_protection_check) and 401 if absent. The cross-domain
// scope/ownership 404 (the IDOR property these tests assert) fires BEFORE the
// protection check in every one of those handlers, so a minimal authed actor —
// distinct id, IsAdmin — is enough to reach the asserted 404 without perturbing it.
// (Actor id is fixed and never equals a seeded target user, so no self-protection.)
func scopedReq(method string, id, scope int64, body string) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, "/admin/users", stringReader(body))
	} else {
		r = httptest.NewRequest(method, "/admin/users", nil)
	}
	r.SetPathValue("id", fmt.Sprintf("%d", id))
	ctx := auth.ContextWithUser(r.Context(), &auth.Claims{UserID: -1, IsAdmin: true})
	ctx = middleware.ContextWithDomainScope(ctx, scope)
	r = r.WithContext(ctx)
	return r
}

func stringReader(s string) *stringReadCloser { return &stringReadCloser{s: s} }

type stringReadCloser struct {
	s string
	i int
}

func (r *stringReadCloser) Read(p []byte) (int, error) {
	if r.i >= len(r.s) {
		return 0, fmt.Errorf("EOF")
	}
	n := copy(p, r.s[r.i:])
	r.i += n
	return n, nil
}

// TestUsers_DomainScope_Get verifies a domain-A admin cannot Get a domain-B user
// (404) but can Get a domain-A user (200).
func TestUsers_DomainScope_Get(t *testing.T) {
	pool := mailboxTestPool(t)
	logger := mailboxTestLogger()
	h := NewUsersHandler(pool, pgxutil.WorkerPool{Pool: pool}, logger, nil, "", "")

	domA := ensureScopeTestDomain(t, pool, "scopea.example")
	domB := ensureScopeTestDomain(t, pool, "scopeb.example")
	userA := createScopeTestUser(t, pool, domA, "scopea.example")
	userB := createScopeTestUser(t, pool, domB, "scopeb.example")

	// Domain-A admin → domain-B user: must be 404.
	rec := httptest.NewRecorder()
	h.Get(rec, scopedReq(http.MethodGet, userB, domA, ""))
	if rec.Code != http.StatusNotFound {
		t.Errorf("Get cross-domain user: want 404, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	// Domain-A admin → domain-A user: must be 200.
	rec = httptest.NewRecorder()
	h.Get(rec, scopedReq(http.MethodGet, userA, domA, ""))
	if rec.Code != http.StatusOK {
		t.Errorf("Get same-domain user: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestUsers_DomainScope_List verifies List returns only domain-A users for a
// domain-A admin.
func TestUsers_DomainScope_List(t *testing.T) {
	pool := mailboxTestPool(t)
	logger := mailboxTestLogger()
	h := NewUsersHandler(pool, pgxutil.WorkerPool{Pool: pool}, logger, nil, "", "")

	domA := ensureScopeTestDomain(t, pool, "scopea.example")
	domB := ensureScopeTestDomain(t, pool, "scopeb.example")
	userA := createScopeTestUser(t, pool, domA, "scopea.example")
	userB := createScopeTestUser(t, pool, domB, "scopeb.example")

	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	req = req.WithContext(middleware.ContextWithDomainScope(req.Context(), domA))
	rec := httptest.NewRecorder()
	h.List(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("List: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var out []UserResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	sawA, sawB := false, false
	for _, u := range out {
		if u.ID == userA {
			sawA = true
		}
		if u.ID == userB {
			sawB = true
		}
	}
	if !sawA {
		t.Error("List for domain-A admin omitted the domain-A user")
	}
	if sawB {
		t.Error("List for domain-A admin leaked a domain-B user (IDOR)")
	}
}

// TestUsers_List_QueryFilter verifies the ?q= server-side filter: it matches by
// email substring, excludes non-matching users, and still enforces the caller's
// domain scope (a scoped admin cannot use q to fish users out of another domain).
func TestUsers_List_QueryFilter(t *testing.T) {
	pool := mailboxTestPool(t)
	logger := mailboxTestLogger()
	h := NewUsersHandler(pool, pgxutil.WorkerPool{Pool: pool}, logger, nil, "", "")

	domA := ensureScopeTestDomain(t, pool, "scopea.example")
	domB := ensureScopeTestDomain(t, pool, "scopeb.example")
	userA := createScopeTestUser(t, pool, domA, "scopea.example")
	userB := createScopeTestUser(t, pool, domB, "scopeb.example")

	ctx := context.Background()
	var emailA, emailB string
	if err := pool.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, userA).Scan(&emailA); err != nil {
		t.Fatalf("read emailA: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, userB).Scan(&emailB); err != nil {
		t.Fatalf("read emailB: %v", err)
	}

	list := func(q string, scope int64) []UserResponse {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/admin/users?q="+q, nil)
		if scope > 0 {
			req = req.WithContext(middleware.ContextWithDomainScope(req.Context(), scope))
		}
		rec := httptest.NewRecorder()
		h.List(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("List(q=%q, scope=%d): want 200, got %d (body=%s)", q, scope, rec.Code, rec.Body.String())
		}
		var out []UserResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode list: %v", err)
		}
		return out
	}
	has := func(out []UserResponse, id int64) bool {
		for _, u := range out {
			if u.ID == id {
				return true
			}
		}
		return false
	}

	// Matching: unscoped admin filtering by userA's exact email sees userA only.
	out := list(emailA, 0)
	if !has(out, userA) {
		t.Errorf("List(q=emailA) omitted the matching user")
	}
	if has(out, userB) {
		t.Errorf("List(q=emailA) returned a non-matching user")
	}

	// Non-matching: a query that matches nothing returns neither.
	out = list("no-such-user-zzz@nowhere.example", 0)
	if has(out, userA) || has(out, userB) {
		t.Errorf("List(q=non-matching) returned a user")
	}

	// Scope still enforced under q: a domain-A admin filtering by the domain-B
	// user's exact email must NOT see it (IDOR via search).
	out = list(emailB, domA)
	if has(out, userB) {
		t.Error("List(q=emailB, scope=domA) leaked a domain-B user (IDOR via q)")
	}
	// ...while the same scoped admin still finds their own domain's user.
	out = list(emailA, domA)
	if !has(out, userA) {
		t.Error("List(q=emailA, scope=domA) omitted the in-scope matching user")
	}
}

// TestUsers_DomainScope_ResetPassword verifies a domain-A admin cannot reset the
// password of a domain-B user (404, row unchanged).
func TestUsers_DomainScope_ResetPassword(t *testing.T) {
	pool := mailboxTestPool(t)
	logger := mailboxTestLogger()
	h := NewUsersHandler(pool, pgxutil.WorkerPool{Pool: pool}, logger, nil, "", "")

	domA := ensureScopeTestDomain(t, pool, "scopea.example")
	domB := ensureScopeTestDomain(t, pool, "scopeb.example")
	createScopeTestUser(t, pool, domA, "scopea.example")
	userB := createScopeTestUser(t, pool, domB, "scopeb.example")

	ctx := context.Background()
	var before string
	if err := pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE id = $1`, userB).Scan(&before); err != nil {
		t.Fatalf("read before hash: %v", err)
	}

	body := `{"password":"Sup3r-Str0ng-Pw!"}`
	rec := httptest.NewRecorder()
	h.ResetPassword(rec, scopedReq(http.MethodPost, userB, domA, body))
	if rec.Code != http.StatusNotFound {
		t.Errorf("ResetPassword cross-domain: want 404, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	var after string
	if err := pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE id = $1`, userB).Scan(&after); err != nil {
		t.Fatalf("read after hash: %v", err)
	}
	if before != after {
		t.Error("ResetPassword cross-domain mutated the domain-B user's password hash (IDOR)")
	}
}

// TestUsers_DomainScope_Update verifies a domain-A admin cannot update a
// domain-B user (404, row unchanged).
func TestUsers_DomainScope_Update(t *testing.T) {
	pool := mailboxTestPool(t)
	logger := mailboxTestLogger()
	h := NewUsersHandler(pool, pgxutil.WorkerPool{Pool: pool}, logger, nil, "", "")

	domA := ensureScopeTestDomain(t, pool, "scopea.example")
	domB := ensureScopeTestDomain(t, pool, "scopeb.example")
	createScopeTestUser(t, pool, domA, "scopea.example")
	userB := createScopeTestUser(t, pool, domB, "scopeb.example")

	ctx := context.Background()
	var before string
	if err := pool.QueryRow(ctx, `SELECT display_name FROM users WHERE id = $1`, userB).Scan(&before); err != nil {
		t.Fatalf("read before name: %v", err)
	}

	body := `{"displayName":"HACKED"}`
	rec := httptest.NewRecorder()
	h.Update(rec, scopedReq(http.MethodPatch, userB, domA, body))
	if rec.Code != http.StatusNotFound {
		t.Errorf("Update cross-domain: want 404, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	var after string
	if err := pool.QueryRow(ctx, `SELECT display_name FROM users WHERE id = $1`, userB).Scan(&after); err != nil {
		t.Fatalf("read after name: %v", err)
	}
	if after != before {
		t.Errorf("Update cross-domain mutated domain-B user (IDOR): %q -> %q", before, after)
	}
}

// TestUsers_DomainScope_Delete verifies a domain-A admin cannot delete a
// domain-B user (404, user still present).
func TestUsers_DomainScope_Delete(t *testing.T) {
	pool := mailboxTestPool(t)
	logger := mailboxTestLogger()
	h := NewUsersHandler(pool, pgxutil.WorkerPool{Pool: pool}, logger, nil, "", "")

	domA := ensureScopeTestDomain(t, pool, "scopea.example")
	domB := ensureScopeTestDomain(t, pool, "scopeb.example")
	createScopeTestUser(t, pool, domA, "scopea.example")
	userB := createScopeTestUser(t, pool, domB, "scopeb.example")

	rec := httptest.NewRecorder()
	h.Delete(rec, scopedReq(http.MethodDelete, userB, domA, ""))
	if rec.Code != http.StatusNotFound {
		t.Errorf("Delete cross-domain: want 404, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	ctx := context.Background()
	var stillThere int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE id = $1`, userB).Scan(&stillThere); err != nil {
		t.Fatalf("count after delete: %v", err)
	}
	if stillThere != 1 {
		t.Error("Delete cross-domain removed the domain-B user (IDOR / mail destruction)")
	}
}
