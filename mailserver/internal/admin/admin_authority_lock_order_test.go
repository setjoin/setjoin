package admin

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"setjoin.com/shared/testsupport"
)

// TestAdminAuthorityHandlerPrelockVsAssignmentInsert models the handler's
// advisory-first role prelock while a second session inserts an assignment for
// that same role. The assignment trigger must wait on the advisory fence before
// reaching its FK/role-row work; both transactions then complete without 40P01.
func TestAdminAuthorityHandlerPrelockVsAssignmentInsert(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := t.Context()

	const (
		domainID = int64(99401)
		userID   = int64(99402)
		roleID   = int64(99403)
	)

	if _, err := pool.Exec(ctx,
		`INSERT INTO domains(id,name,is_local) VALUES($1,'admin-lock-order.test',true)
		 ON CONFLICT(id) DO NOTHING`, domainID); err != nil {
		t.Fatalf("seed domain: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO users(id,username,domain_id,email,display_name,enabled)
		 VALUES($1,'admin_lock_order_user',$2,'user@admin-lock-order.test','Admin Lock Order User',true)
		 ON CONFLICT(id) DO NOTHING`, userID, domainID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO admin_role_groups(id,name) VALUES($1,'Admin handler lock-order role')
		 ON CONFLICT(id) DO NOTHING`, roleID); err != nil {
		t.Fatalf("seed role: %v", err)
	}

	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		tx, err := pool.Begin(cleanupCtx)
		if err != nil {
			t.Errorf("cleanup begin: %v", err)
			return
		}
		defer func() { _ = tx.Rollback(cleanupCtx) }()
		_, _ = tx.Exec(cleanupCtx, `DELETE FROM admin_role_assignments WHERE user_id=$1 AND role_group_id=$2`, userID, roleID)
		_, _ = tx.Exec(cleanupCtx, `DELETE FROM admin_role_groups WHERE id=$1`, roleID)
		_, _ = tx.Exec(cleanupCtx, `DELETE FROM users WHERE id=$1`, userID)
		_, _ = tx.Exec(cleanupCtx, `DELETE FROM domains WHERE id=$1`, domainID)
		if err := tx.Commit(cleanupCtx); err != nil {
			t.Errorf("cleanup commit: %v", err)
		}
	})

	handlerConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire handler connection: %v", err)
	}
	defer handlerConn.Release()
	assignmentConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire assignment connection: %v", err)
	}
	defer assignmentConn.Release()

	handlerTx, err := handlerConn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin handler transaction: %v", err)
	}
	defer func() { _ = handlerTx.Rollback(context.Background()) }()
	if err := acquireAdminAuthorityFence(ctx, handlerTx); err != nil {
		t.Fatalf("acquire handler authority fence: %v", err)
	}
	var lockedRoleID int64
	if err := handlerTx.QueryRow(ctx,
		`SELECT id FROM admin_role_groups WHERE id=$1 FOR UPDATE`, roleID).Scan(&lockedRoleID); err != nil {
		t.Fatalf("handler role prelock: %v", err)
	}

	var assignmentPID int
	if err := assignmentConn.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&assignmentPID); err != nil {
		t.Fatalf("read assignment backend pid: %v", err)
	}
	assignmentDone := make(chan error, 1)
	go func() {
		_, execErr := assignmentConn.Exec(context.Background(),
			`INSERT INTO admin_role_assignments(user_id,role_group_id,expires_at,eligible)
			 VALUES($1,$2,NULL,false)`, userID, roleID)
		assignmentDone <- execErr
	}()

	waitCtx, cancelWait := context.WithTimeout(ctx, 5*time.Second)
	defer cancelWait()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	blocked := false
	for !blocked {
		select {
		case assignmentErr := <-assignmentDone:
			_ = handlerTx.Rollback(ctx)
			t.Fatalf("assignment completed before handler fence released: %v", assignmentErr)
		case <-ticker.C:
			if err := handlerTx.QueryRow(ctx,
				`SELECT EXISTS(SELECT 1 FROM pg_stat_activity
				 WHERE pid=$1 AND wait_event_type='Lock' AND wait_event='advisory')`,
				assignmentPID).Scan(&blocked); err != nil {
				_ = handlerTx.Rollback(ctx)
				assignmentErr := <-assignmentDone
				t.Fatalf("inspect blocked assignment (result %v): %v", assignmentErr, err)
			}
		case <-waitCtx.Done():
			_ = handlerTx.Rollback(ctx)
			assignmentErr := <-assignmentDone
			t.Fatalf("assignment did not wait on advisory fence (result %v): %v", assignmentErr, waitCtx.Err())
		}
	}

	if err := handlerTx.Commit(ctx); err != nil {
		t.Fatalf("commit handler transaction: %v", err)
	}

	var assignmentErr error
	select {
	case assignmentErr = <-assignmentDone:
	case <-time.After(5 * time.Second):
		t.Fatal("assignment did not resume after handler commit")
	}
	if assignmentErr != nil {
		var pgErr *pgconn.PgError
		if errors.As(assignmentErr, &pgErr) && pgErr.Code == "40P01" {
			t.Fatalf("authority writers deadlocked despite advisory-first order: %v", assignmentErr)
		}
		t.Fatalf("assignment insert after handler prelock: %v", assignmentErr)
	}

	var exists bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM admin_role_assignments WHERE user_id=$1 AND role_group_id=$2)`,
		userID, roleID).Scan(&exists); err != nil {
		t.Fatalf("verify assignment: %v", err)
	}
	if !exists {
		t.Fatal("assignment did not persist after serialized transactions")
	}
}

// TestAdminAuthorityGuestStatusVsReprovisionLockOrder models the guest-status
// handler exactly: fence first, guest-row prelock, then guest_set_status. A
// concurrent reprovision of that guest must wait on the advisory fence before
// it can reach the same user/guest rows, and both transactions complete in
// advisory->row order without 40P01.
func TestAdminAuthorityGuestStatusVsReprovisionLockOrder(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := t.Context()

	const (
		domainID = int64(99411)
		adminID  = int64(99412)
		guestID  = int64(99413)
		roleID   = int64(99414)
	)
	const guestEmail = "guest@admin-guest-lock-order.test"

	if _, err := pool.Exec(ctx, `INSERT INTO domains(id,name,is_local) VALUES($1,'admin-guest-lock-order.test',true)`, domainID); err != nil {
		t.Fatalf("seed domain: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,username,domain_id,email,display_name,enabled) VALUES
		($1,'admin_guest_lock_order_admin',$3,'admin@admin-guest-lock-order.test','Guest Manager',true),
		($2,$4,(SELECT id FROM domains WHERE name='guest.invalid'),$4,'Lock Order Guest',true)`, adminID, guestID, domainID, guestEmail); err != nil {
		t.Fatalf("seed users: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO guest_accounts(user_id,invited_email,invited_by,invited_by_email,sponsor_user_id,host_domain_id,status)
		VALUES($1,$2,$3,'admin@admin-guest-lock-order.test',$3,$4,'active')`, guestID, guestEmail, adminID, domainID); err != nil {
		t.Fatalf("seed guest: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO admin_role_groups(id,name,permissions,domain_scope)
		VALUES($1,'Guest handler lock-order role',ARRAY['guests.manage'],$2)`, roleID, domainID); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by,eligible)
		VALUES($1,$2,$1,false)`, adminID, roleID); err != nil {
		t.Fatalf("seed assignment: %v", err)
	}

	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = pool.Exec(cleanupCtx, `DELETE FROM admin_role_assignments WHERE user_id=$1 AND role_group_id=$2`, adminID, roleID)
		_, _ = pool.Exec(cleanupCtx, `DELETE FROM admin_role_groups WHERE id=$1`, roleID)
		_, _ = pool.Exec(cleanupCtx, `DELETE FROM guest_accounts WHERE user_id=$1`, guestID)
		_, _ = pool.Exec(cleanupCtx, `DELETE FROM users WHERE id IN ($1,$2)`, adminID, guestID)
		_, _ = pool.Exec(cleanupCtx, `DELETE FROM domains WHERE id=$1`, domainID)
	})

	handlerConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire handler connection: %v", err)
	}
	defer handlerConn.Release()
	reprovisionConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire reprovision connection: %v", err)
	}
	defer reprovisionConn.Release()

	handlerTx, err := handlerConn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin handler transaction: %v", err)
	}
	defer func() { _ = handlerTx.Rollback(context.Background()) }()
	if err := acquireAdminAuthorityFence(ctx, handlerTx); err != nil {
		t.Fatalf("acquire handler authority fence: %v", err)
	}
	var lockedGuestID int64
	if err := handlerTx.QueryRow(ctx, `SELECT g.user_id FROM guest_accounts g
		WHERE g.user_id=$2 AND guest_admin_can_reach_with_permission($1,g.user_id,'guests.manage')
		FOR UPDATE`, adminID, guestID).Scan(&lockedGuestID); err != nil {
		t.Fatalf("handler guest prelock: %v", err)
	}
	if _, err := handlerTx.Exec(ctx, `SELECT guest_set_status($1,$2,'disable',NULL)`, adminID, guestID); err != nil {
		t.Fatalf("handler guest disable: %v", err)
	}

	var reprovisionPID int
	if err := reprovisionConn.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&reprovisionPID); err != nil {
		t.Fatalf("read reprovision backend pid: %v", err)
	}
	reprovisionDone := make(chan error, 1)
	go func() {
		_, execErr := reprovisionConn.Exec(context.Background(), `SELECT provision_account(
			p_email=>$1,p_guest=>true,p_invited_by=>$2)`, guestEmail, adminID)
		reprovisionDone <- execErr
	}()

	waitCtx, cancelWait := context.WithTimeout(ctx, 5*time.Second)
	defer cancelWait()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	blocked := false
	for !blocked {
		select {
		case reprovisionErr := <-reprovisionDone:
			_ = handlerTx.Rollback(ctx)
			t.Fatalf("reprovision completed before guest-status fence released: %v", reprovisionErr)
		case <-ticker.C:
			if err := handlerTx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity
				WHERE pid=$1 AND wait_event_type='Lock' AND wait_event='advisory')`, reprovisionPID).Scan(&blocked); err != nil {
				t.Fatalf("inspect blocked reprovision: %v", err)
			}
		case <-waitCtx.Done():
			_ = handlerTx.Rollback(ctx)
			reprovisionErr := <-reprovisionDone
			t.Fatalf("reprovision did not wait on advisory fence (result %v): %v", reprovisionErr, waitCtx.Err())
		}
	}

	if err := handlerTx.Commit(ctx); err != nil {
		t.Fatalf("commit guest-status transaction: %v", err)
	}
	select {
	case err := <-reprovisionDone:
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "40P01" {
				t.Fatalf("guest authority writers deadlocked: %v", err)
			}
			t.Fatalf("reprovision after guest status: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reprovision did not resume after guest-status commit")
	}

	var status string
	var enabled bool
	if err := pool.QueryRow(ctx, `SELECT g.status,u.enabled FROM guest_accounts g JOIN users u ON u.id=g.user_id WHERE g.user_id=$1`, guestID).Scan(&status, &enabled); err != nil {
		t.Fatalf("read serialized guest state: %v", err)
	}
	if status != "disabled" || enabled {
		t.Fatalf("serialized guest state status=%q enabled=%v, want disabled/false", status, enabled)
	}
}
