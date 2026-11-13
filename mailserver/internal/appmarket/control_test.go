package appmarket

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"setjoin.com/shared/testsupport"
)

func TestPGControlPlaneClaimAdvanceHeartbeatAndCommit(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := t.Context()
	testsupport.SetFeatureToggleForTest(t, pool, "feature.office_managed_delivery", true)
	var mailboxID, actor int64
	if err := pool.QueryRow(ctx, `SELECT mk_account('app-control')`).Scan(&mailboxID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id=$1`, mailboxID).Scan(&actor); err != nil {
		t.Fatal(err)
	}
	provider := "control-provider"
	if _, err := pool.Exec(ctx, `INSERT INTO office_provider_policies(
		provider_id,enabled,entitlement_state,build_id,config,route_state)
		VALUES($1,false,'evaluation','control','{}','connected_inactive')`, provider); err != nil {
		t.Fatal(err)
	}
	operationID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO office_app_operations(
		id,app_id,kind,state,requested_by,reason,idempotency_key,request_digest,request)
		VALUES($1,'collabora-code','install','requested',$2,'control test',$3,$4,$5)`,
		operationID, actor, uuid.New(), strings.Repeat("a", 64), `{"providerId":"`+provider+`"}`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `UPDATE office_app_operations SET app_revision_id=NULL WHERE id=$1`, operationID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM office_app_revisions WHERE created_by_operation_id=$1`, operationID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM office_app_operations WHERE id=$1`, operationID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM office_provider_policies WHERE provider_id=$1`, provider)
	})
	acquired, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer acquired.Release()
	control := &PGControlPlane{conn: acquired.Conn()}
	installationID, err := control.InstallationID(ctx)
	if err != nil || installationID == "" {
		t.Fatalf("installation=%q err=%v", installationID, err)
	}
	leaseID := uuid.New()
	op, err := control.Claim(ctx, "control-executor", leaseID)
	if err != nil || op == nil || op.OperationID != operationID {
		t.Fatalf("claim=%+v err=%v", op, err)
	}
	if err := control.Heartbeat(ctx, op, 30); err != nil {
		t.Fatal(err)
	}
	for _, next := range []string{"preflight", "pulling", "verifying", "staging", "starting", "qualifying"} {
		if err := control.Advance(ctx, op, next, next, map[string]any{"step": next}, nil); err != nil {
			t.Fatalf("advance %s: %v", next, err)
		}
	}
	manifest := testManifest().WithExecution(installationID, operationID.String())
	if err := control.CommitInstall(ctx, op, manifest); err != nil {
		t.Fatal(err)
	}
	if op.State != "connected_inactive" {
		t.Fatalf("commit state=%s", op.State)
	}
	if claimed, err := control.Claim(ctx, "control-executor", uuid.New()); err != nil || claimed != nil {
		t.Fatalf("empty claim=%+v err=%v", claimed, err)
	}
}

func TestPGControlPlaneConnectionAndClosedConnectionFailures(t *testing.T) {
	ctx := t.Context()
	if _, err := OpenPGControlPlane(ctx, "postgres://127.0.0.1:1/nope?connect_timeout=1"); err == nil || !strings.Contains(err.Error(), "open managed app control plane") {
		t.Fatalf("bad connection=%v", err)
	}
	pool := testsupport.OpenTestPool(t)
	acquired, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	control := &PGControlPlane{conn: acquired.Conn()}
	if err := control.Close(ctx); err != nil {
		t.Fatal(err)
	}
	acquired.Release()
	op := &Operation{OperationID: uuid.New(), LeaseID: uuid.New(), ExecutorID: "closed", Kind: "install"}
	if _, err := control.InstallationID(ctx); err == nil {
		t.Fatal("InstallationID accepted closed connection")
	}
	if _, err := control.Claim(ctx, "closed", uuid.New()); err == nil {
		t.Fatal("Claim accepted closed connection")
	}
	if err := control.Heartbeat(ctx, op, 30); err == nil {
		t.Fatal("Heartbeat accepted closed connection")
	}
	if err := control.Advance(ctx, op, "preflight", "test", map[string]any{}, map[string]any{"code": "x"}); err == nil {
		t.Fatal("Advance accepted closed connection")
	}
	if err := control.CommitInstall(ctx, op, testManifest().WithExecution("i", op.OperationID.String())); err == nil {
		t.Fatal("Commit accepted closed connection")
	}
	if err := control.CommitInstall(ctx, op, Manifest{}); err == nil {
		t.Fatal("Commit accepted invalid manifest")
	}
}
