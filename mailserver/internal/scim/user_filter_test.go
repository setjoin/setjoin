package scim

import (
	"context"
	"net/http/httptest"
	"testing"

	"setjoin.com/shared/pgxutil"
)

// TestGetUsersFilter_UserNameEq is a DB-integration regression test for C6-scim:
// the COUNT query in queryUsersFilter used "FROM users WHERE u.col=..." (no alias),
// causing every filtered GET /scim/v2/Users to 500. The fix adds the "u" alias.
// This test FAILS without the fix (pgx returns "column u.username does not exist").
func TestGetUsersFilter_UserNameEq(t *testing.T) {
	pool := scimTestPool(t) // skips when DB_DSN unset
	s := NewServer(pool, pgxutil.WorkerPool{Pool: pool}, scimTestLogger(), "", "")

	userID, _ := createSCIMTestUser(t, pool)
	var sourceID int64
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO identity_sources(
		    source_key,display_name,kind,capabilities,state
		) VALUES($1,$2,'scim','{"provision_lifecycle":true}'::jsonb,'active')
		RETURNING id`,
		"scim:filter-"+scimRandomSuffix(t), "SCIM filter test",
	).Scan(&sourceID); err != nil {
		t.Fatalf("create source: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO user_identity_links(
		    user_id,source_id,external_subject,purposes,state,link_method
		) VALUES($1,$2,$3,ARRAY['provision']::text[],'active','hard_anchor')`,
		userID, sourceID, "filter-subject",
	); err != nil {
		t.Fatalf("create source link: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM user_identity_links WHERE source_id=$1`, sourceID)
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM identity_sources WHERE id=$1`, sourceID)
	})

	// Look up the username we just inserted so we can filter on it.
	var username string
	if err := pool.QueryRow(context.Background(),
		`SELECT username FROM users WHERE id = $1`, userID).Scan(&username); err != nil {
		t.Fatalf("read username: %v", err)
	}

	filter := `userName eq "` + username + `"`
	// queryUsersFilter only uses r.Context(); keep the URL simple.
	req := httptest.NewRequest("GET", "/scim/v2/Users", nil).
		WithContext(normalizedSCIMContext(sourceID, 1, ""))

	rows, total, err := s.queryUsersFilter(req, filter, 1, 100)
	if err != nil {
		t.Fatalf("queryUsersFilter returned error (was C6-scim alias bug?): %v", err)
	}

	users, n, _ := s.scanUsers(rows, total, false, sourceID)
	if n != 1 {
		t.Fatalf("totalResults = %d, want 1", n)
	}
	if len(users) != 1 {
		t.Fatalf("returned %d users, want 1", len(users))
	}
	if users[0].UserName != username {
		t.Fatalf("userName = %q, want %q", users[0].UserName, username)
	}
}
