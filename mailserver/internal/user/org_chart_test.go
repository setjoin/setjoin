package user

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/permissions"
)

func TestOrgChartCrossDomainForbidden(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set; skipping database-dependent test")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("failed to connect to test DB: %v", err)
	}
	// Registered FIRST so t.Cleanup LIFO closes the pool LAST — after every
	// fixture cleanup below has run (a defer would close it before them).
	t.Cleanup(pool.Close)

	// Unique-per-run identifiers (random-suffix domains, the shared-DB minting
	// convention): the former fixed domain-a/b.test rows and orgchart-user-*@
	// domain-* emails collided across runs, machines and leftover un-cleaned
	// rows on the shared test DB. Every created row registers its cleanup
	// immediately after its own creation succeeds, and each cleanup verifies
	// its error; t.Cleanup LIFO deletes the users before their domains.
	suffix := randomSuffix(t)
	domainA := "orgchart-a-" + suffix + ".test"
	domainB := "orgchart-b-" + suffix + ".test"

	createDomain := func(name string) int64 {
		t.Helper()
		var id int64
		if err := pool.QueryRow(ctx,
			`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, name,
		).Scan(&id); err != nil {
			t.Fatalf("failed to create domain %s: %v", name, err)
		}
		t.Cleanup(func() {
			if _, err := pool.Exec(context.Background(), `DELETE FROM domains WHERE id = $1`, id); err != nil {
				t.Errorf("cleanup domain %s: %v", name, err)
			}
		})
		return id
	}
	domainAID := createDomain(domainA)
	domainBID := createDomain(domainB)

	createUser := func(username, domain, display string, domainID int64) int64 {
		t.Helper()
		email := username + "@" + domain
		var id int64
		if err := pool.QueryRow(ctx, `
			INSERT INTO users (username, domain_id, email, display_name)
			VALUES ($1, $2, $3, $4)
			RETURNING id
		`, username, domainID, email, display).Scan(&id); err != nil {
			t.Fatalf("failed to create user %s: %v", email, err)
		}
		t.Cleanup(func() {
			if _, err := pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, id); err != nil {
				t.Errorf("cleanup user %s: %v", email, err)
			}
		})
		return id
	}

	userAID := createUser("orgchart-user-a", domainA, "Org Chart User A", domainAID)
	userBID := createUser("orgchart-user-b", domainB, "Org Chart User B", domainBID)
	userAEmail := "orgchart-user-a@" + domainA

	handler := NewOrgChartHandler(pool)

	t.Run("cross-domain access returns 403", func(t *testing.T) {
		// Authenticate as user from domain A with users.read, request org chart for user in domain B.
		// The domain-scoping check (not the perm check) is what fires here.
		req := httptest.NewRequest(http.MethodGet, "/directory/org-chart?userId="+formatInt64(userBID), nil)
		claims := &auth.Claims{
			UserID:      userAID,
			Email:       userAEmail,
			IsAdmin:     true,
			Permissions: []string{permissions.PermUsersRead},
			Type:        auth.TypeAccess,
		}
		req = req.WithContext(auth.ContextWithUser(req.Context(), claims))

		rec := httptest.NewRecorder()
		handler.GetOrgChart(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for cross-domain org chart access, got %d. body: %s",
				rec.Code, rec.Body.String())
		}
	})

	t.Run("no users.read permission returns 403", func(t *testing.T) {
		// is_admin=true but no users.read permission — must be denied (perm model, not role).
		req := httptest.NewRequest(http.MethodGet, "/directory/org-chart?userId="+formatInt64(userBID), nil)
		claims := &auth.Claims{
			UserID:      userAID,
			Email:       userAEmail,
			IsAdmin:     true,
			Permissions: []string{}, // no users.read
			Type:        auth.TypeAccess,
		}
		req = req.WithContext(auth.ContextWithUser(req.Context(), claims))

		rec := httptest.NewRecorder()
		handler.GetOrgChart(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for admin without users.read, got %d. body: %s",
				rec.Code, rec.Body.String())
		}
	})

	t.Run("same-domain access succeeds", func(t *testing.T) {
		// Create a second user in domain A to test same-domain access.
		// (Cleanup registers on the subtest, so this user is removed before
		// the parent's domain teardown.)
		userA2ID := createUser("orgchart-user-a2", domainA, "Org Chart User A2", domainAID)

		req := httptest.NewRequest(http.MethodGet, "/directory/org-chart?userId="+formatInt64(userA2ID), nil)
		claims := &auth.Claims{
			UserID:      userAID,
			Email:       userAEmail,
			IsAdmin:     true,
			Permissions: []string{permissions.PermUsersRead},
			Type:        auth.TypeAccess,
		}
		req = req.WithContext(auth.ContextWithUser(req.Context(), claims))

		rec := httptest.NewRecorder()
		handler.GetOrgChart(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 OK for same-domain org chart access, got %d. body: %s",
				rec.Code, rec.Body.String())
		}
	})
}

func formatInt64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
