package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/pgxutil"
)

// TestUserListManageableFlags exercises the manageable + is_self flags emitted
// by the List endpoint. Requires DB_DSN (skipped when unset via mailboxTestPool).
//
// Scenarios:
//   - plain user (no admin role) → manageable=true (actor has no restricted perms,
//     target has no restricted perms; <@ nil ⊆ nil is true), is_self=false
//   - actor's own row → is_self=true
//   - Super-Admin target vs a low-authority actor → manageable=false
//     (Super Admin has a non-empty perm set the actor cannot cover)
func TestUserListManageableFlags(t *testing.T) {
	pool := mailboxTestPool(t) // skips if DB_DSN unset
	ctx := context.Background()
	prefix := fmt.Sprintf("mgt-%d", time.Now().UnixNano())

	// Create a local domain.
	var domID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ('mgtflags.example')
		 ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id`,
	).Scan(&domID); err != nil {
		t.Fatalf("ensure domain: %v", err)
	}

	// createUser inserts a bare user (no role assignments) and returns its ID.
	createUser := func(suffix string) int64 {
		var id int64
		username := prefix + "-" + suffix
		email := username + "@mgtflags.example"
		if err := pool.QueryRow(ctx,
			`INSERT INTO users (username, email, display_name, password_hash, domain_id)
			 VALUES ($1, $2, $3, '$2a$10$placeholder', $4) RETURNING id`,
			username, email, "Mgt "+suffix, domID,
		).Scan(&id); err != nil {
			t.Fatalf("createUser(%s): %v", suffix, err)
		}
		// Minimal primary mailbox so the page renders.
		if _, err := pool.Exec(ctx,
			`INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary)
			 VALUES ($1, $2, $3, $4, 'personal', TRUE)`,
			id, domID, email, "Mgt "+suffix,
		); err != nil {
			t.Fatalf("createUser mailbox(%s): %v", suffix, err)
		}
		t.Cleanup(func() {
			c := context.Background()
			pool.Exec(c, `ALTER TABLE mailboxes DISABLE TRIGGER ALL`)
			pool.Exec(c, `DELETE FROM mailboxes WHERE user_id = $1`, id)
			pool.Exec(c, `ALTER TABLE mailboxes ENABLE TRIGGER ALL`)
			_, _ = pool.Exec(c, `
				UPDATE admin_role_assignments
				   SET expires_at = statement_timestamp() - interval '1 second'
				 WHERE user_id = $1 AND role_group_id = 1`, id)
			pool.Exec(c, `DELETE FROM admin_role_assignments WHERE user_id = $1`, id)
			pool.Exec(c, `DELETE FROM users WHERE id = $1`, id)
		})
		return id
	}

	actorID := createUser("actor")
	plainID := createUser("plain")
	superID := createUser("super")

	// Promote superID to Super Admin (role_group_id=1).
	if _, err := pool.Exec(ctx,
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by)
		 VALUES ($1, 1, $1)
		 ON CONFLICT DO NOTHING`,
		superID,
	); err != nil {
		t.Fatalf("assign super admin to superID: %v", err)
	}

	h := NewUsersHandler(pool, pgxutil.WorkerPool{Pool: pool}, mailboxTestLogger(), nil, "", "")

	// Build a scoped request as actorID (no domain scope — global view).
	req := httptest.NewRequest(http.MethodGet, "/admin/users?q="+prefix, nil)
	req = req.WithContext(auth.ContextWithUser(
		middleware.ContextWithDomainScope(req.Context(), domID),
		&auth.Claims{UserID: actorID},
	))
	rec := httptest.NewRecorder()
	h.List(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("List: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var out []UserResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode list: %v", err)
	}

	// Index by ID.
	byID := make(map[int64]UserResponse, len(out))
	for _, u := range out {
		byID[u.ID] = u
	}

	// actor's own row must have is_self=true.
	if u, ok := byID[actorID]; !ok {
		t.Error("actor's own row missing from list")
	} else if !u.IsSelf {
		t.Errorf("actor row: isSelf=%v, want true", u.IsSelf)
	}

	// plain user (no roles) must be manageable by the actor (also no roles).
	if u, ok := byID[plainID]; !ok {
		t.Error("plain user row missing from list")
	} else {
		if !u.Manageable {
			t.Errorf("plain user row: manageable=%v, want true (actor covers empty perm set)", u.Manageable)
		}
		if u.IsSelf {
			t.Errorf("plain user row: isSelf=%v, want false", u.IsSelf)
		}
	}

	// Super Admin target must NOT be manageable by the low-authority actor.
	if u, ok := byID[superID]; !ok {
		t.Error("super user row missing from list")
	} else {
		if u.Manageable {
			t.Errorf("super user row: manageable=%v, want false (actor cannot cover super's perm set)", u.Manageable)
		}
		if u.IsSelf {
			t.Errorf("super user row: isSelf=%v, want false", u.IsSelf)
		}
	}
}
