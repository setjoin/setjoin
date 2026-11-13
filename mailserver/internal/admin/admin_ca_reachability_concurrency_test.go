package admin

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"setjoin.com/shared/testsupport"
)

// TestCAReachabilitySerializationPolicyVsBreakGlass proves the cross-table
// invariant with two real sessions. A policy promotion holds the shared
// reachability fence; a concurrent break-glass replacement must wait, then see
// the committed policy and fail BZ080 rather than commit an all-admin lockout.
func TestCAReachabilitySerializationPolicyVsBreakGlass(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := t.Context()

	const (
		domainID   = int64(99321)
		adminID    = int64(99322)
		nonAdminID = int64(99323)
		roleID     = int64(99324)
		priority   = 99321
	)

	if _, err := pool.Exec(ctx,
		`INSERT INTO domains(id,name,is_local) VALUES($1,'ca-concurrency.test',true)
		 ON CONFLICT(id) DO NOTHING`, domainID); err != nil {
		t.Fatalf("seed domain: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO users(id,username,domain_id,email,display_name,enabled) VALUES
		 ($1,'ca_concurrent_admin',$3,'admin@ca-concurrency.test','CA Concurrent Admin',true),
		 ($2,'ca_concurrent_nonadmin',$3,'nonadmin@ca-concurrency.test','CA Concurrent Nonadmin',true)
		 ON CONFLICT(id) DO NOTHING`, adminID, nonAdminID, domainID); err != nil {
		t.Fatalf("seed users: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO admin_role_groups(id,name) VALUES($1,'CA concurrency role')
		 ON CONFLICT(id) DO NOTHING`, roleID); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO admin_role_assignments(user_id,role_group_id,expires_at,eligible)
		 VALUES($1,$2,NULL,false) ON CONFLICT(user_id,role_group_id) DO UPDATE
		 SET expires_at=NULL,eligible=false,activated_until=NULL`, adminID, roleID); err != nil {
		t.Fatalf("seed assignment: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO system_config(key,value) VALUES('ca_break_glass_user_ids',$1::jsonb)
		 ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value`, fmt.Sprintf("[%d]", adminID)); err != nil {
		t.Fatalf("seed break-glass: %v", err)
	}

	var policyID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO conditional_access_policies
		 (priority,name,state,scope_type,conditions,actions,exclude_users,exclude_groups)
		 VALUES($1,'CA reachability concurrency','report_only','global','{}',
		        '{"action":"block"}','[]','[]') RETURNING id`, priority).Scan(&policyID); err != nil {
		t.Fatalf("seed report-only policy: %v", err)
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
		_, _ = tx.Exec(cleanupCtx, `UPDATE conditional_access_policies SET state='off' WHERE id=$1`, policyID)
		_, _ = tx.Exec(cleanupCtx, `DELETE FROM conditional_access_policies WHERE id=$1`, policyID)
		_, _ = tx.Exec(cleanupCtx, `UPDATE system_config SET value='[]'::jsonb WHERE key='ca_break_glass_user_ids'`)
		_, _ = tx.Exec(cleanupCtx, `DELETE FROM admin_role_assignments WHERE user_id=$1 AND role_group_id=$2`, adminID, roleID)
		_, _ = tx.Exec(cleanupCtx, `DELETE FROM admin_role_groups WHERE id=$1`, roleID)
		_, _ = tx.Exec(cleanupCtx, `DELETE FROM users WHERE id IN ($1,$2)`, adminID, nonAdminID)
		_, _ = tx.Exec(cleanupCtx, `DELETE FROM domains WHERE id=$1`, domainID)
		if err := tx.Commit(cleanupCtx); err != nil {
			t.Errorf("cleanup commit: %v", err)
		}
	})

	policyConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire policy connection: %v", err)
	}
	defer policyConn.Release()
	mutationConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire mutation connection: %v", err)
	}
	defer mutationConn.Release()

	policyTx, err := policyConn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin policy transaction: %v", err)
	}
	defer func() { _ = policyTx.Rollback(context.Background()) }()

	policyDoc := fmt.Sprintf(
		`{"priority":%d,"name":"CA reachability concurrency","state":"on",`+
			`"scope_type":"global","conditions":{},"actions":{"action":"block"},`+
			`"exclude_users":[],"exclude_groups":[]}`, priority)
	var promoted []byte
	if err := policyTx.QueryRow(ctx,
		`SELECT ca_policy_upsert($1,'203.0.113.223'::inet,$2,$3::jsonb)`,
		adminID, policyID, policyDoc).Scan(&promoted); err != nil {
		t.Fatalf("promote policy in transaction: %v", err)
	}

	var mutationPID int
	if err := mutationConn.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&mutationPID); err != nil {
		t.Fatalf("read mutation backend pid: %v", err)
	}
	mutationDone := make(chan error, 1)
	go func() {
		_, execErr := mutationConn.Exec(context.Background(),
			`SELECT ca_break_glass_set($1,'203.0.113.224'::inet,$2::bigint[])`,
			adminID, []int64{nonAdminID})
		mutationDone <- execErr
	}()

	waitCtx, cancelWait := context.WithTimeout(ctx, 5*time.Second)
	defer cancelWait()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	blocked := false
	for !blocked {
		select {
		case mutationErr := <-mutationDone:
			_ = policyTx.Rollback(ctx)
			t.Fatalf("break-glass mutation completed before policy fence released: %v", mutationErr)
		case <-ticker.C:
			if err := policyTx.QueryRow(ctx,
				`SELECT EXISTS(SELECT 1 FROM pg_stat_activity
				 WHERE pid=$1 AND wait_event_type='Lock' AND wait_event='advisory')`,
				mutationPID).Scan(&blocked); err != nil {
				_ = policyTx.Rollback(ctx)
				mutationErr := <-mutationDone
				t.Fatalf("inspect blocked mutation (mutation result %v): %v", mutationErr, err)
			}
		case <-waitCtx.Done():
			_ = policyTx.Rollback(ctx)
			mutationErr := <-mutationDone
			t.Fatalf("break-glass mutation did not block on advisory fence (result %v): %v", mutationErr, waitCtx.Err())
		}
	}

	if err := policyTx.Commit(ctx); err != nil {
		t.Fatalf("commit policy promotion: %v", err)
	}

	var mutationErr error
	select {
	case mutationErr = <-mutationDone:
	case <-time.After(5 * time.Second):
		t.Fatal("break-glass mutation did not resume after policy commit")
	}
	var pgErr *pgconn.PgError
	if !errors.As(mutationErr, &pgErr) || pgErr.Code != "BZ080" {
		t.Fatalf("break-glass mutation error=%v, want PostgreSQL BZ080", mutationErr)
	}

	var state string
	var breakGlass string
	if err := pool.QueryRow(ctx,
		`SELECT p.state, c.value::text
		 FROM conditional_access_policies p
		 JOIN system_config c ON c.key='ca_break_glass_user_ids'
		 WHERE p.id=$1`, policyID).Scan(&state, &breakGlass); err != nil {
		t.Fatalf("read final serialized state: %v", err)
	}
	if state != "on" || breakGlass != fmt.Sprintf("[%d]", adminID) {
		t.Fatalf("final state policy=%q breakGlass=%s, want on and [%d]", state, breakGlass, adminID)
	}
}

// TestCAReachabilitySerializationImportVsUpsertLockOrder proves every policy
// writer uses advisory-fence -> policy-row order. Upsert holds both locks on a
// policy while import of that same policy waits specifically on the advisory
// fence; after the upsert commits, import completes second without 40P01.
func TestCAReachabilitySerializationImportVsUpsertLockOrder(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := t.Context()

	const (
		domainID = int64(99331)
		adminID  = int64(99332)
		roleID   = int64(99334)
		priority = 99331
		name     = "CA import-upsert lock order"
	)

	if _, err := pool.Exec(ctx,
		`INSERT INTO domains(id,name,is_local) VALUES($1,'ca-lock-order.test',true)
		 ON CONFLICT(id) DO NOTHING`, domainID); err != nil {
		t.Fatalf("seed domain: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO users(id,username,domain_id,email,display_name,enabled)
		 VALUES($1,'ca_lock_order_admin',$2,'admin@ca-lock-order.test','CA Lock Order Admin',true)
		 ON CONFLICT(id) DO NOTHING`, adminID, domainID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO admin_role_groups(id,name) VALUES($1,'CA lock-order role')
		 ON CONFLICT(id) DO NOTHING`, roleID); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO admin_role_assignments(user_id,role_group_id,expires_at,eligible)
		 VALUES($1,$2,NULL,false) ON CONFLICT(user_id,role_group_id) DO UPDATE
		 SET expires_at=NULL,eligible=false,activated_until=NULL`, adminID, roleID); err != nil {
		t.Fatalf("seed assignment: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO system_config(key,value) VALUES('ca_break_glass_user_ids',$1::jsonb)
		 ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value`, fmt.Sprintf("[%d]", adminID)); err != nil {
		t.Fatalf("seed break-glass: %v", err)
	}

	var policyID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO conditional_access_policies
		 (priority,name,description,state,scope_type,conditions,actions,exclude_users,exclude_groups)
		 VALUES($1,$2,'seed','report_only','global','{}','{"action":"allow"}','[]','[]')
		 RETURNING id`, priority, name).Scan(&policyID); err != nil {
		t.Fatalf("seed policy: %v", err)
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
		_, _ = tx.Exec(cleanupCtx, `UPDATE conditional_access_policies SET state='off' WHERE id=$1`, policyID)
		_, _ = tx.Exec(cleanupCtx, `DELETE FROM conditional_access_policies WHERE id=$1`, policyID)
		_, _ = tx.Exec(cleanupCtx, `UPDATE system_config SET value='[]'::jsonb WHERE key='ca_break_glass_user_ids'`)
		_, _ = tx.Exec(cleanupCtx, `DELETE FROM admin_role_assignments WHERE user_id=$1 AND role_group_id=$2`, adminID, roleID)
		_, _ = tx.Exec(cleanupCtx, `DELETE FROM admin_role_groups WHERE id=$1`, roleID)
		_, _ = tx.Exec(cleanupCtx, `DELETE FROM users WHERE id=$1`, adminID)
		_, _ = tx.Exec(cleanupCtx, `DELETE FROM domains WHERE id=$1`, domainID)
		if err := tx.Commit(cleanupCtx); err != nil {
			t.Errorf("cleanup commit: %v", err)
		}
	})

	upsertConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire upsert connection: %v", err)
	}
	defer upsertConn.Release()
	importConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire import connection: %v", err)
	}
	defer importConn.Release()

	upsertTx, err := upsertConn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin upsert transaction: %v", err)
	}
	defer func() { _ = upsertTx.Rollback(context.Background()) }()

	upsertDoc := fmt.Sprintf(
		`{"priority":%d,"name":%q,"description":"upsert-first","state":"report_only",`+
			`"scope_type":"global","conditions":{},"actions":{"action":"allow"},`+
			`"exclude_users":[],"exclude_groups":[]}`, priority, name)
	var upserted []byte
	if err := upsertTx.QueryRow(ctx,
		`SELECT ca_policy_upsert($1,'203.0.113.225'::inet,$2,$3::jsonb)`,
		adminID, policyID, upsertDoc).Scan(&upserted); err != nil {
		t.Fatalf("upsert policy in transaction: %v", err)
	}

	var importPID int
	if err := importConn.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&importPID); err != nil {
		t.Fatalf("read import backend pid: %v", err)
	}
	importDoc := fmt.Sprintf(
		`{"schemaVersion":1,"policies":[{"priority":%d,"name":%q,`+
			`"description":"import-second","scope_type":"global","scope_target":"",`+
			`"conditions":{},"actions":{"action":"allow"},`+
			`"exclude_users":[],"exclude_groups":[]}]}`, priority, name)
	importDone := make(chan error, 1)
	go func() {
		var summary []byte
		importDone <- importConn.QueryRow(context.Background(),
			`SELECT ca_policy_import($1::jsonb,$2,'merge')`, importDoc, adminID).Scan(&summary)
	}()

	waitCtx, cancelWait := context.WithTimeout(ctx, 5*time.Second)
	defer cancelWait()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	blocked := false
	for !blocked {
		select {
		case importErr := <-importDone:
			_ = upsertTx.Rollback(ctx)
			t.Fatalf("import completed before upsert fence released: %v", importErr)
		case <-ticker.C:
			if err := upsertTx.QueryRow(ctx,
				`SELECT EXISTS(SELECT 1 FROM pg_stat_activity
				 WHERE pid=$1 AND wait_event_type='Lock' AND wait_event='advisory')`,
				importPID).Scan(&blocked); err != nil {
				_ = upsertTx.Rollback(ctx)
				importErr := <-importDone
				t.Fatalf("inspect blocked import (import result %v): %v", importErr, err)
			}
		case <-waitCtx.Done():
			_ = upsertTx.Rollback(ctx)
			importErr := <-importDone
			t.Fatalf("import did not block on advisory fence (result %v): %v", importErr, waitCtx.Err())
		}
	}

	if err := upsertTx.Commit(ctx); err != nil {
		t.Fatalf("commit first upsert: %v", err)
	}

	var importErr error
	select {
	case importErr = <-importDone:
	case <-time.After(5 * time.Second):
		t.Fatal("import did not resume after upsert commit")
	}
	if importErr != nil {
		var pgErr *pgconn.PgError
		if errors.As(importErr, &pgErr) && pgErr.Code == "40P01" {
			t.Fatalf("policy writers deadlocked despite universal advisory-first order: %v", importErr)
		}
		t.Fatalf("import after upsert: %v", importErr)
	}

	var description string
	if err := pool.QueryRow(ctx,
		`SELECT description FROM conditional_access_policies WHERE id=$1`, policyID).Scan(&description); err != nil {
		t.Fatalf("read final policy: %v", err)
	}
	if description != "import-second" {
		t.Fatalf("final description=%q, want import-second", description)
	}
}

// TestCAReachabilitySerializationPromoteVsSessionControl proves promotion
// guards a fenced, row-locked current tuple. A concurrent unsafe action update
// waits on the advisory fence; after promotion commits it must observe state=on
// and fail BZ080 instead of leaving an active blocking policy with no escape.
func TestCAReachabilitySerializationPromoteVsSessionControl(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := t.Context()

	const (
		domainID = int64(99341)
		adminID  = int64(99342)
		roleID   = int64(99344)
		priority = 99341
	)

	if _, err := pool.Exec(ctx,
		`INSERT INTO domains(id,name,is_local) VALUES($1,'ca-promote-race.test',true)
		 ON CONFLICT(id) DO NOTHING`, domainID); err != nil {
		t.Fatalf("seed domain: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO users(id,username,domain_id,email,display_name,enabled)
		 VALUES($1,'ca_promote_race_admin',$2,'admin@ca-promote-race.test','CA Promote Race Admin',true)
		 ON CONFLICT(id) DO NOTHING`, adminID, domainID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO admin_role_groups(id,name) VALUES($1,'CA promotion race role')
		 ON CONFLICT(id) DO NOTHING`, roleID); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO admin_role_assignments(user_id,role_group_id,expires_at,eligible)
		 VALUES($1,$2,NULL,false) ON CONFLICT(user_id,role_group_id) DO UPDATE
		 SET expires_at=NULL,eligible=false,activated_until=NULL`, adminID, roleID); err != nil {
		t.Fatalf("seed assignment: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO system_config(key,value) VALUES('ca_break_glass_user_ids','[]'::jsonb)
		 ON CONFLICT(key) DO UPDATE SET value='[]'::jsonb`); err != nil {
		t.Fatalf("clear break-glass: %v", err)
	}

	var policyID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO conditional_access_policies
		 (priority,name,state,scope_type,conditions,actions,exclude_users,exclude_groups)
		 VALUES($1,'CA promotion-session race','report_only','global','{}',
		        '{"action":"allow"}','[]','[]') RETURNING id`, priority).Scan(&policyID); err != nil {
		t.Fatalf("seed report-only policy: %v", err)
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
		_, _ = tx.Exec(cleanupCtx, `UPDATE conditional_access_policies SET state='off' WHERE id=$1`, policyID)
		_, _ = tx.Exec(cleanupCtx, `DELETE FROM conditional_access_policies WHERE id=$1`, policyID)
		_, _ = tx.Exec(cleanupCtx, `UPDATE system_config SET value='[]'::jsonb WHERE key='ca_break_glass_user_ids'`)
		_, _ = tx.Exec(cleanupCtx, `DELETE FROM admin_role_assignments WHERE user_id=$1 AND role_group_id=$2`, adminID, roleID)
		_, _ = tx.Exec(cleanupCtx, `DELETE FROM admin_role_groups WHERE id=$1`, roleID)
		_, _ = tx.Exec(cleanupCtx, `DELETE FROM users WHERE id=$1`, adminID)
		_, _ = tx.Exec(cleanupCtx, `DELETE FROM domains WHERE id=$1`, domainID)
		if err := tx.Commit(cleanupCtx); err != nil {
			t.Errorf("cleanup commit: %v", err)
		}
	})

	promoteConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire promotion connection: %v", err)
	}
	defer promoteConn.Release()
	sessionConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire session-control connection: %v", err)
	}
	defer sessionConn.Release()

	promoteTx, err := promoteConn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin promotion transaction: %v", err)
	}
	defer func() { _ = promoteTx.Rollback(context.Background()) }()
	var promoted []byte
	if err := promoteTx.QueryRow(ctx,
		`SELECT ca_policy_promote($1,$2)`, policyID, adminID).Scan(&promoted); err != nil {
		t.Fatalf("promote policy in transaction: %v", err)
	}

	var sessionPID int
	if err := sessionConn.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&sessionPID); err != nil {
		t.Fatalf("read session-control backend pid: %v", err)
	}
	sessionDone := make(chan error, 1)
	go func() {
		_, execErr := sessionConn.Exec(context.Background(),
			`SELECT set_session_control($1,$2::jsonb,'{}'::jsonb,$3,'203.0.113.226'::inet)`,
			policyID, `{"operator":"all","grants":[{"type":"block"}]}`, adminID)
		sessionDone <- execErr
	}()

	waitCtx, cancelWait := context.WithTimeout(ctx, 5*time.Second)
	defer cancelWait()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	blocked := false
	for !blocked {
		select {
		case sessionErr := <-sessionDone:
			_ = promoteTx.Rollback(ctx)
			t.Fatalf("session-control update completed before promotion fence released: %v", sessionErr)
		case <-ticker.C:
			if err := promoteTx.QueryRow(ctx,
				`SELECT EXISTS(SELECT 1 FROM pg_stat_activity
				 WHERE pid=$1 AND wait_event_type='Lock' AND wait_event='advisory')`,
				sessionPID).Scan(&blocked); err != nil {
				_ = promoteTx.Rollback(ctx)
				sessionErr := <-sessionDone
				t.Fatalf("inspect blocked session-control update (result %v): %v", sessionErr, err)
			}
		case <-waitCtx.Done():
			_ = promoteTx.Rollback(ctx)
			sessionErr := <-sessionDone
			t.Fatalf("session-control update did not block on advisory fence (result %v): %v", sessionErr, waitCtx.Err())
		}
	}

	if err := promoteTx.Commit(ctx); err != nil {
		t.Fatalf("commit promotion: %v", err)
	}

	var sessionErr error
	select {
	case sessionErr = <-sessionDone:
	case <-time.After(5 * time.Second):
		t.Fatal("session-control update did not resume after promotion commit")
	}
	var pgErr *pgconn.PgError
	if !errors.As(sessionErr, &pgErr) || pgErr.Code != "BZ080" {
		t.Fatalf("session-control update error=%v, want PostgreSQL BZ080", sessionErr)
	}

	var state string
	var action string
	if err := pool.QueryRow(ctx,
		`SELECT state,actions->>'action' FROM conditional_access_policies WHERE id=$1`,
		policyID).Scan(&state, &action); err != nil {
		t.Fatalf("read final policy: %v", err)
	}
	if state != "on" || action != "allow" {
		t.Fatalf("final state=%q action=%q, want on with allow action", state, action)
	}
}
