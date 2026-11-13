package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// Cov-gap constants for the cap-vs-uncapped promote preview fixture. The ids
// live in the same reserved 99xxx block the D3 tests use; the actor id is the
// LARGEST so the 200-entry capped blocked_users list cannot contain it while
// the uncapped admin_users list must.
const (
	covGapBlockerBase   = int64(99101) // 200 blocker users: 99101..99300
	covGapBlockerCount  = 200
	covGapScopedAdminID = int64(99500)
)

// TestPromoteSelfLockedOut_AdminBeyondTheUserCap pins why admin_users is
// UNCAPPED while blocked_users stops at 200: an admin whose would-block entry
// sorts past the cap is invisible in blocked_users yet must still flip
// self_locked_out — otherwise opening the promote dialog lies to the one
// person about to lock themselves out.
//
// Fixture: 200 distinct blocker users with smaller ids (they fill the capped
// list) plus an admin with an unexpired role assignment whose block entry is
// the 201st distinct user. The 409 preview must report total=201, shown=200,
// the admin absent from blocked_users, present in admin_users, and
// self_locked_out=true.
func TestPromoteSelfLockedOut_AdminBeyondTheUserCap(t *testing.T) {
	h := newTestCAHandler(t)
	ctx := context.Background()

	// Domain 99011 is the shared D3 fixture domain (idempotent).
	if _, err := h.pool.Exec(ctx,
		`INSERT INTO domains (id, name, is_local) VALUES (99011, 'd3test.test', TRUE)
		 ON CONFLICT DO NOTHING`); err != nil {
		t.Fatalf("ensure fixture domain: %v", err)
	}

	// 200 blocker users with ids strictly below the admin's.
	if _, err := h.pool.Exec(ctx,
		`INSERT INTO users (id, username, domain_id, email, display_name, enabled)
		 SELECT i, 'covgap-blk-' || i, 99011, 'covgap-blk-' || i || '@d3test.test', 'Cov Gap Blocker', TRUE
		   FROM generate_series($1::bigint, $2::bigint) AS i
		 ON CONFLICT (id) DO NOTHING`,
		covGapBlockerBase, covGapBlockerBase+covGapBlockerCount-1); err != nil {
		t.Fatalf("seed blocker users: %v", err)
	}
	// The scoped admin: a real users row + unexpired role assignment (the
	// assignment is what admin_users requires).
	if _, err := h.pool.Exec(ctx,
		`INSERT INTO users (id, username, domain_id, email, display_name, enabled)
		 VALUES ($1, 'covgap-admin', 99011, 'covgap-admin@d3test.test', 'Cov Gap Scoped Admin', TRUE)
		 ON CONFLICT (id) DO NOTHING`, covGapScopedAdminID); err != nil {
		t.Fatalf("seed admin user: %v", err)
	}
	if _, err := h.pool.Exec(ctx,
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by)
		 VALUES ($1, 2, $1)
		 ON CONFLICT (user_id, role_group_id) DO NOTHING`, covGapScopedAdminID); err != nil {
		t.Fatalf("seed admin assignment: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		h.pool.Exec(c, `DELETE FROM admin_role_assignments WHERE user_id = $1`, covGapScopedAdminID) //nolint:errcheck
		h.pool.Exec(c, `DELETE FROM users WHERE id BETWEEN $1 AND $2`,
			covGapBlockerBase, covGapBlockerBase+covGapBlockerCount-1) //nolint:errcheck
		h.pool.Exec(c, `DELETE FROM users WHERE id = $1`, covGapScopedAdminID) //nolint:errcheck
	})

	// Report-only block policy owned by the scoped admin.
	id := seedReportOnlyBlockPolicy(t, h, "covgap-cap-selflock", 9961, covGapScopedAdminID)
	t.Cleanup(func() {
		h.pool.Exec(context.Background(),
			`DELETE FROM conditional_access_policies WHERE id = $1`, id) //nolint:errcheck
	})

	// 201 would-block entries: the 200 small users + the admin last.
	for i := int64(0); i < covGapBlockerCount; i++ {
		seedWouldBlockLog(t, h, id, covGapBlockerBase+i)
	}
	seedWouldBlockLog(t, h, id, covGapScopedAdminID)

	w := doPromote(h, id, false, covGapScopedAdminID)
	if w.Code != http.StatusConflict {
		t.Fatalf("Promote preview: want 409, got %d (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		WouldBlockUsers  int64 `json:"would_block_users"`
		WouldBlockAdmins int64 `json:"would_block_admins"`
		SelfLockedOut    bool  `json:"self_locked_out"`
		BlockedUsers     []struct {
			ID      int64 `json:"id"`
			IsAdmin bool  `json:"is_admin"`
		} `json:"blocked_users"`
		AdminUsers []struct {
			ID int64 `json:"id"`
		} `json:"admin_users"`
		Shown  int64  `json:"shown"`
		Total  int64  `json:"total"`
		Window string `json:"window"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode 409 preview: %v (body=%s)", err, w.Body.String())
	}
	if resp.WouldBlockUsers != covGapBlockerCount+1 || resp.Total != covGapBlockerCount+1 {
		t.Fatalf("would_block_users/total = %d/%d, want %d (every distinct blocked user counts)",
			resp.WouldBlockUsers, resp.Total, covGapBlockerCount+1)
	}
	if resp.Shown != covGapBlockerCount || len(resp.BlockedUsers) != covGapBlockerCount {
		t.Fatalf("shown/len(blocked_users) = %d/%d, want the 200 cap", resp.Shown, len(resp.BlockedUsers))
	}
	for _, u := range resp.BlockedUsers {
		if u.ID == covGapScopedAdminID {
			t.Fatal("the admin appears in the capped blocked_users list; fixture ordering broken")
		}
	}
	var adminInAdminUsers bool
	for _, au := range resp.AdminUsers {
		if au.ID == covGapScopedAdminID {
			adminInAdminUsers = true
		}
	}
	if !adminInAdminUsers {
		t.Fatalf("admin missing from the uncapped admin_users list: %+v", resp.AdminUsers)
	}
	if !resp.SelfLockedOut {
		t.Fatal("self_locked_out = false: the uncapped admin_users scan missed the acting admin")
	}
	if resp.Window != "7d" {
		t.Fatalf("window = %q, want 7d", resp.Window)
	}
}
