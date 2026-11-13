package admin

import (
	"context"
	"errors"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

// TestCanReachMailbox_GlobalArmOwnerlessMailbox is a SELF-CONTAINED drive of
// the owner-less global-authority arm of canReachMailbox: an actor holding a
// NULL-scope (truly global) assignment reaches an owner-less distribution
// mailbox in a FOREIGN domain, with NO domain scope in the request context.
// The round2 fixture covers the same arm; this drive is fixture-independent.
func TestCanReachMailbox_GlobalArmOwnerlessMailbox(t *testing.T) {
	pool := testsupport.OpenTestPool(t)

	inDomain := seedScopeFixDomain(t, pool, "globalarm-in.example.test")
	outDomain := seedScopeFixDomain(t, pool, "globalarm-out.example.test")

	actor := createMailboxTestUser(t, pool, inDomain)
	helpDeskID := builtinRoleID(t, pool, "Help Desk")
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by)
		 VALUES ($1, $2, $1)`, actor, helpDeskID); err != nil {
		t.Fatalf("seed global assignment: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM admin_role_assignments WHERE user_id = $1`, actor) //nolint:errcheck
		pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, actor)                       //nolint:errcheck
	})

	distMailbox := createDistributionMailbox(t, pool, outDomain)
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM mailboxes WHERE id = $1`, distMailbox) //nolint:errcheck
	})

	// NO domain scope in the context: the global arm is the only admission.
	ctx := auth.ContextWithUser(context.Background(), &auth.Claims{
		UserID: actor, IsAdmin: true, Permissions: permissions.AllPermissions,
	})
	if err := canReachMailbox(ctx, pool, distMailbox); err != nil {
		t.Fatalf("global actor, owner-less foreign mailbox: want nil, got %v", err)
	}

	// A missing mailbox fails closed with the not-found sentinel (no
	// existence oracle through the scope decision).
	if err := canReachMailbox(ctx, pool, 999999999); !errors.Is(err, errMailboxNotFound) {
		t.Fatalf("missing mailbox: err=%v, want errMailboxNotFound", err)
	}
}

// TestCanReachMailbox_ClosedPoolFailsClosed pins the closed-pool variant: the
// first query fails and maps to the generic scope error — fail-closed.
func TestCanReachMailbox_ClosedPoolFailsClosed(t *testing.T) {
	closed := testsupport.OpenTestPool(t)
	closed.Close()
	ctx := auth.ContextWithUser(context.Background(), &auth.Claims{
		UserID: 1, IsAdmin: true, Permissions: permissions.AllPermissions,
	})
	if err := canReachMailbox(ctx, closed, 1); err == nil {
		t.Fatal("closed pool must fail closed")
	}
}
