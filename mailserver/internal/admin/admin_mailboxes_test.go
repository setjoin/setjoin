package admin

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// mailboxTestPool returns a pool connected to the test database.
// Skips the test if DB_DSN is not set.
func mailboxTestPool(t *testing.T) *pgxpool.Pool {
	return testsupport.OpenTestPool(t)
}

func mailboxTestLogger() *slog.Logger {
	return testsupport.TestLogger()
}

func mailboxRandomSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return fmt.Sprintf("%x", b)
}

// ensureMailboxTestDomain creates (or finds) a test domain and returns its ID.
func ensureMailboxTestDomain(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	ctx := context.Background()
	var id int64
	err := pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ('mbtest.example')
		 ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
		 RETURNING id`,
	).Scan(&id)
	if err != nil {
		t.Fatalf("ensureMailboxTestDomain: %v", err)
	}
	return id
}

// createMailboxTestUser inserts a test user and returns the user ID. Cleanup
// is registered after the creation succeeds and its error is verified.
func createMailboxTestUser(t *testing.T, pool *pgxpool.Pool, domainID int64) int64 {
	t.Helper()
	ctx := context.Background()
	suffix := mailboxRandomSuffix(t)
	email := "mbtest-" + suffix + "@mbtest.example"
	var userID int64
	err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, password_hash, domain_id)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		"mbtest-"+suffix, email, "MB Test", "$2a$10$placeholder", domainID,
	).Scan(&userID)
	if err != nil {
		t.Fatalf("createMailboxTestUser: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID); err != nil {
			t.Errorf("cleanup mailbox test user %d: %v", userID, err)
		}
	})
	return userID
}

// createPersonalMailbox inserts a personal mailbox for a user as the primary
// mailbox (the trigger requires every user to have exactly one primary).
//
// Teardown deletes the mailbox and the owning user in ONE transaction —
// mailboxes before users, the BZ013-safe pattern proven by the ad fixture:
// deleting a user's primary mailbox alone trips the primary-mailbox guard (and
// the former ALTER TABLE ... DISABLE TRIGGER ALL hack silently failed without
// table ownership while locking trigger state table-wide for concurrent runs).
// At commit the user is gone, so the deferred primary-mailbox check passes.
func createPersonalMailbox(t *testing.T, pool *pgxpool.Pool, userID, domainID int64) int64 {
	t.Helper()
	ctx := context.Background()
	suffix := mailboxRandomSuffix(t)
	email := "mbtest-" + suffix + "@mbtest.example"
	var mbID int64
	err := pool.QueryRow(ctx,
		`INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary)
		 VALUES ($1, $2, $3, $4, 'personal', TRUE) RETURNING id`,
		userID, domainID, email, "Test Mailbox",
	).Scan(&mbID)
	if err != nil {
		t.Fatalf("createPersonalMailbox: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		tx, err := pool.Begin(c)
		if err != nil {
			t.Errorf("cleanup personal mailbox %d: begin teardown tx: %v", mbID, err)
			return
		}
		// Dependent rows first, in the FK order the schema enforces: messages
		// (their tags/attachments cascade), the mailbox-address-claims
		// substrate and lifecycle rows (both RESTRICT — lifecycle rows bind
		// the owner via bound_user_id), then the mailbox, then the user. At
		// commit the user is gone, so the deferred primary-mailbox check
		// passes.
		teardown := [...]struct {
			what  string
			query string
			args  []any
		}{
			{"messages", `DELETE FROM messages WHERE mailbox_id = $1`, []any{mbID}},
			{"mailbox address claims", `DELETE FROM mailbox_address_claims WHERE mailbox_id = $1`, []any{mbID}},
			{"mailbox lifecycle", `DELETE FROM mailbox_lifecycle WHERE mailbox_id = $1 OR bound_user_id = $2`, []any{mbID, userID}},
		}
		for _, stmt := range teardown {
			if _, err := tx.Exec(c, stmt.query, stmt.args...); err != nil {
				t.Errorf("cleanup personal mailbox %d: delete %s: %v", mbID, stmt.what, err)
				_ = tx.Rollback(c)
				return
			}
		}
		if _, err := tx.Exec(c, `DELETE FROM mailboxes WHERE id = $1`, mbID); err != nil {
			t.Errorf("cleanup personal mailbox %d: delete mailbox: %v", mbID, err)
			_ = tx.Rollback(c)
			return
		}
		if _, err := tx.Exec(c, `DELETE FROM users WHERE id = $1`, userID); err != nil {
			t.Errorf("cleanup personal mailbox %d: delete user %d: %v", mbID, userID, err)
			_ = tx.Rollback(c)
			return
		}
		if err := tx.Commit(c); err != nil {
			t.Errorf("cleanup personal mailbox %d: commit teardown: %v", mbID, err)
		}
	})
	return mbID
}

// createDistributionMailbox inserts a personal mailbox and a distribution_groups satellite row.
func createDistributionMailbox(t *testing.T, pool *pgxpool.Pool, domainID int64) int64 {
	t.Helper()
	ctx := context.Background()
	suffix := mailboxRandomSuffix(t)
	email := "distmb-" + suffix + "@mbtest.example"
	var mbID int64
	err := pool.QueryRow(ctx,
		`INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary)
		 VALUES (NULL, $1, $2, $3, 'personal', FALSE) RETURNING id`,
		domainID, email, "Dist Mailbox",
	).Scan(&mbID)
	if err != nil {
		t.Fatalf("createDistributionMailbox (mailbox): %v", err)
	}
	// Round 2 (Astra): the helper owns TWO rows, so its cleanup is registered
	// IMMEDIATELY after the FIRST creation succeeds — not after the second
	// insert. A failed distribution_groups INSERT used to t.Fatalf with the
	// mailbox row already landed and no cleanup registered, stranding it in
	// the shared test database. The cleanup tolerates the absent satellite
	// row (the DELETE matches zero rows) when the group insert never ran.
	// Imported messages are deleted BEFORE the mailbox (the FK order
	// createPersonalMailbox uses): import/export fixtures park messages on
	// the owner-less mailbox, and a bare mailbox delete FK-fails on them.
	t.Cleanup(func() {
		c := context.Background()
		if _, err := pool.Exec(c, `DELETE FROM messages WHERE mailbox_id = $1`, mbID); err != nil {
			t.Errorf("cleanup distribution mailbox %d: delete messages: %v", mbID, err)
		}
		if _, err := pool.Exec(c, `DELETE FROM distribution_groups WHERE mailbox_id = $1`, mbID); err != nil {
			t.Errorf("cleanup distribution mailbox %d: delete distribution group: %v", mbID, err)
		}
		if _, err := pool.Exec(c, `DELETE FROM mailboxes WHERE id = $1`, mbID); err != nil {
			t.Errorf("cleanup distribution mailbox %d: delete mailbox: %v", mbID, err)
		}
	})
	_, err = pool.Exec(ctx,
		`INSERT INTO distribution_groups (mailbox_id) VALUES ($1)`,
		mbID,
	)
	if err != nil {
		t.Fatalf("createDistributionMailbox (distribution_groups): %v", err)
	}
	return mbID
}

func TestMailboxDeleteRefusesLifecycleEnabled(t *testing.T) {
	pool := mailboxTestPool(t)
	h := NewMailboxesHandler(pool, pgxutil.WorkerPool{Pool: pool}, mailboxTestLogger())
	ctx := context.Background()
	domainID := ensureMailboxTestDomain(t, pool)
	userID := createMailboxTestUser(t, pool, domainID)
	mailboxID := createPersonalMailbox(t, pool, userID, domainID)

	var previous bool
	if err := pool.QueryRow(ctx,
		`SELECT enabled FROM feature_toggles WHERE key='feature.mailbox_lifecycle_retention'`,
	).Scan(&previous); err != nil {
		t.Fatalf("read mailbox lifecycle toggle: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE feature_toggles SET enabled=TRUE WHERE key='feature.mailbox_lifecycle_retention'`,
	); err != nil {
		t.Fatalf("enable mailbox lifecycle toggle: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`UPDATE feature_toggles SET enabled=$1 WHERE key='feature.mailbox_lifecycle_retention'`, previous)
	})

	req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/admin/mailboxes/%d", mailboxID), nil)
	req.SetPathValue("id", fmt.Sprintf("%d", mailboxID))
	w := httptest.NewRecorder()
	h.Delete(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("Delete returned %d, want 409; body=%s", w.Code, w.Body.String())
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM mailboxes WHERE id=$1`, mailboxID).Scan(&count); err != nil {
		t.Fatalf("re-read protected mailbox: %v", err)
	}
	if count != 1 {
		t.Fatalf("lifecycle-enabled delete removed mailbox: count=%d", count)
	}
}

// TestMailboxEffectiveType_List verifies that the List handler returns the
// correct effective_type derived from satellite tables, not the raw
// mailboxes.type column (which is now always 'personal').
func TestMailboxEffectiveType_List(t *testing.T) {
	pool := mailboxTestPool(t)
	logger := mailboxTestLogger()
	h := NewMailboxesHandler(pool, pgxutil.WorkerPool{Pool: pool}, logger)

	domainID := ensureMailboxTestDomain(t, pool)
	userID := createMailboxTestUser(t, pool, domainID)
	personalID := createPersonalMailbox(t, pool, userID, domainID)
	distID := createDistributionMailbox(t, pool, domainID)

	req := httptest.NewRequest("GET", "/admin/mailboxes", nil)
	// Domain-scope the request to this test's own fixture domain (the real
	// production shape for a domain-scoped admin — DomainScopeFromContext
	// returns 0/unscoped otherwise). Unscoped + the handler's default
	// ORDER BY id DESC LIMIT 50 otherwise starves this test's own
	// plain-sequence-id mailbox out of the page whenever the shared test DB
	// already holds 50+ higher-id fixture rows from other suites (e.g. every
	// chat DB-gated test's mk_account helper, whose reserved id range sorts
	// above the mailboxes table's native serial) — a test-isolation gap, not
	// a List bug: a real domain-scoped admin never sees cross-domain rows.
	req = req.WithContext(middleware.ContextWithDomainScope(req.Context(), domainID))
	w := httptest.NewRecorder()
	h.List(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("List returned %d, body: %s", w.Code, w.Body.String())
	}

	var items []adminMailboxResponse
	if err := json.NewDecoder(w.Body).Decode(&items); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	byID := make(map[int64]adminMailboxResponse)
	for _, m := range items {
		byID[m.ID] = m
	}

	// Personal mailbox
	pers, ok := byID[personalID]
	if !ok {
		t.Fatalf("personal mailbox %d not found in List response", personalID)
	}
	if pers.Type != "personal" {
		t.Errorf("personal mailbox: expected type=personal, got %q", pers.Type)
	}

	// Distribution mailbox
	dist, ok := byID[distID]
	if !ok {
		t.Fatalf("distribution mailbox %d not found in List response", distID)
	}
	if dist.Type != "distribution" {
		t.Errorf("distribution mailbox: expected type=distribution, got %q", dist.Type)
	}
}

// TestMailboxEffectiveType_Get verifies that the Get handler returns the
// effective_type from satellite tables.
func TestMailboxEffectiveType_Get(t *testing.T) {
	pool := mailboxTestPool(t)
	logger := mailboxTestLogger()
	h := NewMailboxesHandler(pool, pgxutil.WorkerPool{Pool: pool}, logger)

	domainID := ensureMailboxTestDomain(t, pool)
	userID := createMailboxTestUser(t, pool, domainID)
	personalID := createPersonalMailbox(t, pool, userID, domainID)
	distID := createDistributionMailbox(t, pool, domainID)

	t.Run("personal", func(t *testing.T) {
		req := httptest.NewRequest("GET", fmt.Sprintf("/admin/mailboxes/%d", personalID), nil)
		req.SetPathValue("id", fmt.Sprintf("%d", personalID))
		w := httptest.NewRecorder()
		h.Get(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("Get personal returned %d, body: %s", w.Code, w.Body.String())
		}
		var m adminMailboxResponse
		if err := json.NewDecoder(w.Body).Decode(&m); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if m.Type != "personal" {
			t.Errorf("expected personal, got %q", m.Type)
		}
	})

	t.Run("distribution", func(t *testing.T) {
		req := httptest.NewRequest("GET", fmt.Sprintf("/admin/mailboxes/%d", distID), nil)
		req.SetPathValue("id", fmt.Sprintf("%d", distID))
		w := httptest.NewRecorder()
		h.Get(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("Get distribution returned %d, body: %s", w.Code, w.Body.String())
		}
		var m adminMailboxResponse
		if err := json.NewDecoder(w.Body).Decode(&m); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if m.Type != "distribution" {
			t.Errorf("expected distribution, got %q", m.Type)
		}
	})
}

// TestMailboxCreate_RejectsNonPersonalType verifies that the Create handler
// rejects any type other than "personal" with 400.
// TestMailboxesCreate_CrossUserRequiresUsersWrite proves the object-level
// cross-user gate (census #21) now keys off the permission registry
// (users.write), not hard-coded AdminRole strings. The caller is an admin for
// THIS console but lacks users.write and is creating a mailbox for a DIFFERENT
// user (999 != 1) — must be 403. This branch fires before any DB call.
func TestMailboxesCreate_CrossUserRequiresUsersWrite(t *testing.T) {
	h := NewMailboxesHandler(nil, pgxutil.WorkerPool{}, mailboxTestLogger())
	body := `{"email":"x@d.test","userId":999,"type":"personal"}`
	req := httptest.NewRequest("POST", "/admin/mailboxes", strings.NewReader(body))
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID: 1, Permissions: []string{permissions.PermDomainsRead},
	})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	h.Create(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-user create without users.write: want 403, got %d", rec.Code)
	}
}

// TestMailboxesCreate_CrossUserAllowedWithUsersCreate proves the positive side:
// a caller holding users.create may create a mailbox for a different user — the
// cross-user gate passes and execution proceeds past it (nil pool then yields a
// downstream error, NOT a 403).
func TestMailboxesCreate_CrossUserAllowedWithUsersCreate(t *testing.T) {
	h := NewMailboxesHandler(nil, pgxutil.WorkerPool{}, mailboxTestLogger())
	body := `{"email":"x@d.test","userId":999,"type":"personal"}`
	req := httptest.NewRequest("POST", "/admin/mailboxes", strings.NewReader(body))
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID: 1, Permissions: []string{permissions.PermUsersCreate},
	})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	defer func() { _ = recover() }() // nil pool QueryRow panics after the gate passes
	h.Create(rec, req)
	if rec.Code == http.StatusForbidden {
		t.Fatalf("cross-user create WITH users.create must pass the gate, got 403")
	}
}

func TestMailboxCreate_RejectsNonPersonalType(t *testing.T) {
	// This test does not need a real DB pool because the type validation
	// check fires before any DB call.
	h := NewMailboxesHandler(nil, pgxutil.WorkerPool{}, mailboxTestLogger())

	nonPersonalTypes := []string{"distribution", "shared", "room", "equipment"}
	for _, typ := range nonPersonalTypes {
		t.Run(typ, func(t *testing.T) {
			body := fmt.Sprintf(`{"userId":1,"email":"test@example.com","displayName":"Test","type":%q}`, typ)
			req := httptest.NewRequest("POST", "/admin/mailboxes", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.Create(w, req)
			if w.Code != http.StatusBadRequest {
				t.Errorf("type=%q: expected 400, got %d (body: %s)", typ, w.Code, w.Body.String())
			}
		})
	}
}
