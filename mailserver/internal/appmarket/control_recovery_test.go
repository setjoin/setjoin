package appmarket

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

// TestPGControlPlaneRecoveryMatrix drives the state/recovery acceptance matrix
// against the real reducers: crash-in-rollback-window reclaim completion,
// terminal non-reclaim across updater restarts, and the admin-authorized
// ROLLBACK_FAILED cleanup retry that never silently clears the ownership fence.
func TestPGControlPlaneRecoveryMatrix(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := t.Context()
	testsupport.SetFeatureToggleForTest(t, pool, "feature.office_managed_delivery", true)

	var adminMailbox int64
	if err := pool.QueryRow(ctx, `SELECT mk_account('app-recovery-admin')`).Scan(&adminMailbox); err != nil {
		t.Fatal(err)
	}
	var admin int64
	if err := pool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id=$1`, adminMailbox).Scan(&admin); err != nil {
		t.Fatal(err)
	}
	// A dedicated role group carrying exactly apps.manage drives
	// drive_has_admin_perm, and avoids the last-super-admin guard entirely.
	var roleID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO admin_role_groups(name,permissions) VALUES($1,$2) RETURNING id`,
		fmt.Sprintf("app-recovery-role-%d", time.Now().UnixNano()),
		[]string{permissions.PermAppsManage}).Scan(&roleID); err != nil {
		t.Fatal(err)
	}
	var outsiderMailbox int64
	if err := pool.QueryRow(ctx, `SELECT mk_account('app-recovery-outsider')`).Scan(&outsiderMailbox); err != nil {
		t.Fatal(err)
	}
	var outsider int64
	if err := pool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id=$1`, outsiderMailbox).Scan(&outsider); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)`,
		admin, roleID); err != nil {
		t.Fatal(err)
	}
	// admin_audit_log is append-only (trg_audit_append_only): recovery audits
	// written by this test are immutable evidence and are intentionally left.
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM office_app_operations WHERE requested_by IN ($1,$2)`, admin, outsider)
		_, _ = pool.Exec(c, `DELETE FROM admin_role_assignments WHERE role_group_id=$1`, roleID)
		_, _ = pool.Exec(c, `DELETE FROM admin_role_groups WHERE id=$1`, roleID)
		_, _ = pool.Exec(c, `DELETE FROM mailbox_lifecycle WHERE bound_user_id IN ($1,$2)`, admin, outsider)
		_, _ = pool.Exec(c, `ALTER TABLE mailboxes DISABLE TRIGGER ALL`)
		_, _ = pool.Exec(c, `DELETE FROM mailboxes WHERE user_id IN ($1,$2)`, admin, outsider)
		_, _ = pool.Exec(c, `ALTER TABLE mailboxes ENABLE TRIGGER ALL`)
		_, _ = pool.Exec(c, `DELETE FROM users WHERE id IN ($1,$2)`, admin, outsider)
	})

	// insertOp plants an operation in an arbitrary lifecycle state with an
	// expired lease (in-flight shapes) or retained executor identity
	// (terminals). An empty errorCode stores NULL error.
	insertOp := func(state, errorCode string) (uuid.UUID, int64) {
		t.Helper()
		var errorJSON any
		if errorCode != "" {
			errorJSON = json.RawMessage(`{"code":"` + errorCode + `","detail":"injected"}`)
		}
		var id uuid.UUID
		var generation int64
		stmt := `INSERT INTO office_app_operations(
			app_id,kind,state,state_generation,requested_by,reason,idempotency_key,
			request_digest,request,executor_id,lease_id,phase,error,
			last_heartbeat_at,lease_expires_at)
			VALUES('collabora-code','install',$1,6,$2,'recovery matrix test',$3,$4,$5,
			CASE WHEN $1='requested' THEN NULL ELSE 'crashed-runner' END,
			CASE WHEN $1='requested' THEN NULL ELSE gen_random_uuid() END,
			CASE WHEN $1='requested' THEN 'requested' ELSE 'rollback_runtime' END,$6,
			CASE WHEN $1='requested' THEN NULL ELSE statement_timestamp()-interval '60 seconds' END,
			CASE WHEN $1='requested' THEN NULL ELSE statement_timestamp()-interval '30 seconds' END)
			RETURNING id,state_generation`
		if err := pool.QueryRow(ctx, stmt, state, admin, uuid.New(), strings.Repeat("a", 64),
			`{"providerId":"collabora-managed"}`, errorJSON).Scan(&id, &generation); err != nil {
			t.Fatal(err)
		}
		return id, generation
	}
	deleteOps := func() {
		t.Helper()
		if _, err := pool.Exec(ctx, `DELETE FROM office_app_operations WHERE requested_by=$1`, admin); err != nil {
			t.Fatal(err)
		}
	}
	expectCode := func(err error, code string) {
		t.Helper()
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != code {
			t.Fatalf("error=%v, want %s", err, code)
		}
	}

	acquired, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer acquired.Release()
	control := &PGControlPlane{conn: acquired.Conn()}

	// Matrix (a): the crash-in-rollback-window reclaim completes through the
	// reducer-authorized arm (rolling_back stays reclaimable and advancable to
	// rolled_back) — RECOVERY_STATE_UNKNOWN has no reducer-side basis.
	rollbackID, _ := insertOp("rolling_back", "RUNTIME_STEP_FAILED")
	op, err := control.Claim(ctx, "recovery-executor", uuid.New())
	if err != nil || op == nil {
		t.Fatalf("claim=%+v err=%v", op, err)
	}
	if op.OperationID != rollbackID || !op.Reclaimed || op.State != "rolling_back" {
		t.Fatalf("reclaimed op=%+v", op)
	}
	if err := control.Advance(ctx, op, "rolled_back", "rollback_complete",
		map[string]any{"providerRoutingChanged": false},
		map[string]any{"code": "RUNTIME_STEP_FAILED", "detail": "reclaim completion"}); err != nil {
		t.Fatalf("complete reclaimed rollback: %v", err)
	}
	if op.State != "rolled_back" {
		t.Fatalf("completion state=%s", op.State)
	}
	deleteOps()

	// Matrix (c): failed_terminal and rolled_back are never re-claimed.
	if _, gen := insertOp("failed_terminal", "ROLLBACK_FAILED"); gen != 6 {
		t.Fatalf("fixture generation=%d", gen)
	}
	insertOp("rolled_back", "")
	if op, err := control.Claim(ctx, "sweeper", uuid.New()); err != nil || op != nil {
		t.Fatalf("terminal rows re-claimed: op=%+v err=%v", op, err)
	}
	deleteOps()

	// Matrix (b): the admin-authorized recover path re-arms a ROLLBACK_FAILED
	// cleanup retry; a retry that fails again lands failed_terminal and stays
	// admin-recoverable (idempotent across updater restarts).
	ftID, ftGen := insertOp("failed_terminal", "ROLLBACK_FAILED")
	for attempt := 0; attempt < 2; attempt++ {
		var raw []byte
		if err := pool.QueryRow(ctx,
			`SELECT office_app_operation_recover_request($1,$2,$3,$4)`,
			admin, ftID, ftGen, "retry fence-checked cleanup").Scan(&raw); err != nil {
			t.Fatalf("recover attempt %d: %v", attempt, err)
		}
		var recovered struct {
			State string `json:"state"`
			Phase string `json:"phase"`
		}
		if err := json.Unmarshal(raw, &recovered); err != nil {
			t.Fatal(err)
		}
		if recovered.State != "rolling_back" || recovered.Phase != "recovery_requested" {
			t.Fatalf("recover attempt %d returned %+v", attempt, recovered)
		}
		op, err = control.Claim(ctx, "cleanup-executor", uuid.New())
		if err != nil || op == nil || op.OperationID != ftID || op.State != "rolling_back" || !op.Reclaimed {
			t.Fatalf("cleanup reclaim attempt %d: op=%+v err=%v", attempt, op, err)
		}
		next := "rolled_back"
		if attempt == 0 {
			next = "failed_terminal" // the cleanup retry fails once more
		}
		failure := map[string]any{"code": "ROLLBACK_FAILED", "detail": "cleanup retry failed"}
		if err := control.Advance(ctx, op, next, "rollback_complete",
			map[string]any{}, failure); err != nil {
			t.Fatalf("cleanup attempt %d advance %s: %v", attempt, next, err)
		}
		if op.State != next {
			t.Fatalf("cleanup attempt %d state=%s want=%s", attempt, op.State, next)
		}
		ftGen = op.StateGeneration
	}
	// The ownership fence is never silently cleared: the nonterminal retry
	// window always re-enters through reclaim, terminals stay non-reclaimable.
	if op, err := control.Claim(ctx, "sweeper", uuid.New()); err != nil || op != nil {
		t.Fatalf("post-recovery claim=%+v err=%v", op, err)
	}
	deleteOps()

	// Matrix (b), negative arms: stale generation, non-admin caller, and
	// non-cleanup terminal failures are all refused.
	negID, negGen := insertOp("failed_terminal", "RUNTIME_STEP_FAILED")
	expectCode(func() error {
		var raw []byte
		return pool.QueryRow(ctx, `SELECT office_app_operation_recover_request($1,$2,$3,$4)`,
			admin, negID, 999, "stale generation").Scan(&raw)
	}(), "BZ324")
	expectCode(func() error {
		var raw []byte
		return pool.QueryRow(ctx, `SELECT office_app_operation_recover_request($1,$2,$3,$4)`,
			outsider, negID, negGen, "not an admin").Scan(&raw)
	}(), "BZ323")
	expectCode(func() error {
		var raw []byte
		return pool.QueryRow(ctx, `SELECT office_app_operation_recover_request($1,$2,$3,$4)`,
			admin, negID, negGen, "not a cleanup failure").Scan(&raw)
	}(), "BZ324")
	deleteOps()

	// Matrix (e): the pulling pause arm and its bounded recovery —
	// pulling -> paused_recoverable (nonterminal, no completed_at), admin
	// recover_request on the already-paused row, reclaim, resume via preflight.
	insertOp("requested", "")
	op, err = control.Claim(ctx, "pull-executor", uuid.New())
	if err != nil || op == nil || op.Reclaimed {
		t.Fatalf("fresh claim=%+v err=%v", op, err)
	}
	for _, next := range []string{"preflight", "pulling"} {
		if err := control.Advance(ctx, op, next, next, map[string]any{}, nil); err != nil {
			t.Fatalf("advance %s: %v", next, err)
		}
	}
	if err := control.Heartbeat(ctx, op, worstCaseStepLeaseSeconds); err != nil {
		t.Fatalf("step-aware heartbeat: %v", err)
	}
	if err := control.Advance(ctx, op, "paused_recoverable", "lease_budget_paused",
		map[string]any{"pausedDuring": "artifact_pull"},
		map[string]any{"code": "LEASE_BUDGET_EXHAUSTED"}); err != nil {
		t.Fatalf("pull pause: %v", err)
	}
	var completedAt *bool
	if err := pool.QueryRow(ctx,
		`SELECT completed_at IS NULL FROM office_app_operations WHERE id=$1`,
		op.OperationID).Scan(&completedAt); err != nil || !*completedAt {
		t.Fatalf("paused row completed_at=%v err=%v", completedAt, err)
	}
	var raw []byte
	if err := pool.QueryRow(ctx,
		`SELECT office_app_operation_recover_request($1,$2,$3,$4)`,
		admin, op.OperationID, op.StateGeneration, "resume the paused pull").Scan(&raw); err != nil {
		t.Fatalf("paused recovery request: %v", err)
	}
	op, err = control.Claim(ctx, "resume-executor", uuid.New())
	if err != nil || op == nil || !op.Reclaimed || op.State != "paused_recoverable" {
		t.Fatalf("paused reclaim=%+v err=%v", op, err)
	}
	if err := control.Advance(ctx, op, "preflight", "runtime_preflight",
		map[string]any{}, nil); err != nil {
		t.Fatalf("resume preflight: %v", err)
	}
}
