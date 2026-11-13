package backup

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/testsupport"
)

func backupTestPool(t *testing.T) *pgxpool.Pool {
	return testsupport.OpenTestPool(t)
}

// TestClaimRun_CASClaimsPendingOnce: claimRun is a compare-and-swap on
// status='pending' — the first claim succeeds, a second of the same id fails
// (already running), so a redelivered/duplicate NOTIFY can't double-process.
func TestClaimRun_CASClaimsPendingOnce(t *testing.T) {
	pool := backupTestPool(t)
	ctx := context.Background()
	e := NewEngine(pool, nil, nil, testLogger(), ctx)

	var id int64
	if err := pool.QueryRow(ctx, `INSERT INTO backup_runs (status) VALUES ('pending') RETURNING id`).Scan(&id); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM backup_runs WHERE id = $1`, id) })

	claimed, err := e.claimRun(ctx, fmt.Sprint(id))
	if err != nil {
		t.Fatalf("claimRun: %v", err)
	}
	if !claimed {
		t.Fatal("first claim of a pending run should succeed")
	}

	claimed2, err := e.claimRun(ctx, fmt.Sprint(id))
	if err != nil {
		t.Fatalf("claimRun (2nd): %v", err)
	}
	if claimed2 {
		t.Error("a second claim of an already-running run must fail (single-flight)")
	}
}

// TestClaimRun_CompletedNotReclaimable: a completed run cannot be flipped back to
// running by a stray redelivered NOTIFY.
func TestClaimRun_CompletedNotReclaimable(t *testing.T) {
	pool := backupTestPool(t)
	ctx := context.Background()
	e := NewEngine(pool, nil, nil, testLogger(), ctx)

	var id int64
	if err := pool.QueryRow(ctx, `INSERT INTO backup_runs (status, completed_at) VALUES ('completed', now()) RETURNING id`).Scan(&id); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM backup_runs WHERE id = $1`, id) })

	claimed, err := e.claimRun(ctx, fmt.Sprint(id))
	if err != nil {
		t.Fatalf("claimRun: %v", err)
	}
	if claimed {
		t.Error("a completed run must not be re-claimable")
	}
}

// TestPendingRunIDs_ReturnsOnlyPending: the startup drain query returns pending
// runs (the backstop for a dropped NOTIFY / a restart) and excludes finished ones.
func TestPendingRunIDs_ReturnsOnlyPending(t *testing.T) {
	pool := backupTestPool(t)
	ctx := context.Background()
	e := NewEngine(pool, nil, nil, testLogger(), ctx)

	var pendingID, doneID int64
	_ = pool.QueryRow(ctx, `INSERT INTO backup_runs (status) VALUES ('pending') RETURNING id`).Scan(&pendingID)
	_ = pool.QueryRow(ctx, `INSERT INTO backup_runs (status, completed_at) VALUES ('completed', now()) RETURNING id`).Scan(&doneID)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM backup_runs WHERE id = ANY($1)`, []int64{pendingID, doneID})
	})

	ids, err := e.pendingRunIDs(ctx)
	if err != nil {
		t.Fatalf("pendingRunIDs: %v", err)
	}
	var sawPending, sawDone bool
	for _, id := range ids {
		if id == pendingID {
			sawPending = true
		}
		if id == doneID {
			sawDone = true
		}
	}
	if !sawPending {
		t.Error("a pending run must be returned by the drain query")
	}
	if sawDone {
		t.Error("a completed run must NOT be returned by the drain query")
	}
}

// TestReclaimStaleRunning_RequeuesOnlyRunning pins the startup crash-recovery
// reclaim (D-MAILSERVER-INTERNAL-BACKUP-F-004): a 'running' row stranded by a
// crash mid-run is flipped back to 'pending' (so the drain re-processes it),
// while 'pending'/'completed'/'failed' rows are untouched.
func TestReclaimStaleRunning_RequeuesOnlyRunning(t *testing.T) {
	pool := backupTestPool(t)
	ctx := context.Background()
	e := NewEngine(pool, nil, nil, testLogger(), ctx)

	var runningID, pendingID, completedID int64
	if err := pool.QueryRow(ctx, `INSERT INTO backup_runs (status, started_at) VALUES ('running', now()) RETURNING id`).Scan(&runningID); err != nil {
		t.Fatalf("seed running: %v", err)
	}
	_ = pool.QueryRow(ctx, `INSERT INTO backup_runs (status) VALUES ('pending') RETURNING id`).Scan(&pendingID)
	_ = pool.QueryRow(ctx, `INSERT INTO backup_runs (status, completed_at) VALUES ('completed', now()) RETURNING id`).Scan(&completedID)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM backup_runs WHERE id = ANY($1)`, []int64{runningID, pendingID, completedID})
	})

	if err := e.reclaimStaleRunning(ctx); err != nil {
		t.Fatalf("reclaimStaleRunning: %v", err)
	}

	var status string
	if err := pool.QueryRow(ctx, `SELECT status FROM backup_runs WHERE id = $1`, runningID).Scan(&status); err != nil {
		t.Fatalf("read running row: %v", err)
	}
	if status != "pending" {
		t.Errorf("stranded 'running' row must be requeued to 'pending', got %q", status)
	}

	for id, want := range map[int64]string{pendingID: "pending", completedID: "completed"} {
		if err := pool.QueryRow(ctx, `SELECT status FROM backup_runs WHERE id = $1`, id).Scan(&status); err != nil {
			t.Fatalf("read row %d: %v", id, err)
		}
		if status != want {
			t.Errorf("row %d status = %q, want %q (reclaim must only touch 'running' rows)", id, status, want)
		}
	}

	// The requeued row must now be claimable — closing the loop back into
	// claimRun's CAS.
	claimed, err := e.claimRun(ctx, fmt.Sprint(runningID))
	if err != nil || !claimed {
		t.Errorf("requeued row must be claimable via CAS, claimed=%v err=%v", claimed, err)
	}
}

// TestApplyRetention_KeepsRowWhenIndexDeleteFails pins the retention ordering
// (D-MAILSERVER-INTERNAL-BACKUP-F-003): the backup_runs row is the only
// bookkeeping for a pruned run, so when an index-object delete fails the row
// must stay (next pass retries) — never deleted while its config export
// survives orphaned in the store.
func TestApplyRetention_KeepsRowWhenIndexDeleteFails(t *testing.T) {
	pool := backupTestPool(t)
	ctx := context.Background()
	_, _ = pool.Exec(ctx, `DELETE FROM backup_runs WHERE status='completed' AND manifest_timestamp IS NOT NULL`)

	store := newMemStore()
	e := NewEngine(pool, nil, store, testLogger(), ctx)

	tss := []string{"20200101T000004Z", "20200101T000005Z"}
	var ids []int64
	for _, ts := range tss {
		var id int64
		if err := pool.QueryRow(ctx,
			`INSERT INTO backup_runs (status, completed_at, manifest_timestamp) VALUES ('completed', now(), $1) RETURNING id`, ts).Scan(&id); err != nil {
			t.Fatalf("seed: %v", err)
		}
		ids = append(ids, id)
		store.objs["backup-manifest-"+ts+".json"] = []byte("{}")
		store.objs["manifests/incr-"+ts+".json"] = []byte("{}")
		store.objs["config-"+ts+".json"] = []byte("{}")
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM backup_runs WHERE id = ANY($1)`, ids) })

	// The oldest run's config object refuses to delete; the newest deletes fine.
	store.deleteErr["config-"+tss[0]+".json"] = errors.New("s3 delete unavailable")

	pruned, err := e.ApplyRetention(ctx, RetentionPolicy{GFSScheme: "1d0w0m"}) // keep 1
	if err != nil {
		t.Fatalf("ApplyRetention: %v", err)
	}
	if pruned != 0 {
		t.Fatalf("pruned = %d, want 0 — the failing run's row must be kept", pruned)
	}

	var n int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM backup_runs WHERE id = $1`, ids[0]).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Error("run row must be retained when its index-object delete fails (retry next pass)")
	}
	if _, ok := store.get("config-" + tss[0] + ".json"); !ok {
		t.Error("surviving config object must still be present")
	}
	if _, ok := store.get("backup-manifest-" + tss[0] + ".json"); !ok {
		t.Error("the run's manifest object must be untouched when any delete of that run failed")
	}
}

// TestApplyRetention_PrunesOldestBeyondGFS: end-to-end deletion path — old runs'
// index objects + backup_runs rows are pruned, the newest survives. Isolation-safe:
// it clears only completed-with-manifest rows (admin tests use 'pending' rows,
// which completedRuns excludes), and backup-package tests run sequentially.
func TestApplyRetention_PrunesOldestBeyondGFS(t *testing.T) {
	pool := backupTestPool(t)
	ctx := context.Background()
	_, _ = pool.Exec(ctx, `DELETE FROM backup_runs WHERE status='completed' AND manifest_timestamp IS NOT NULL`)

	store := newMemStore()
	e := NewEngine(pool, nil, store, testLogger(), ctx)

	tss := []string{"20200101T000001Z", "20200101T000002Z", "20200101T000003Z"}
	var ids []int64
	for _, ts := range tss {
		var id int64
		if err := pool.QueryRow(ctx,
			`INSERT INTO backup_runs (status, completed_at, manifest_timestamp) VALUES ('completed', now(), $1) RETURNING id`, ts).Scan(&id); err != nil {
			t.Fatalf("seed: %v", err)
		}
		ids = append(ids, id)
		store.objs["backup-manifest-"+ts+".json"] = []byte("{}")
		store.objs["manifests/incr-"+ts+".json"] = []byte("{}")
		store.objs["config-"+ts+".json"] = []byte("{}")
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM backup_runs WHERE id = ANY($1)`, ids) })

	pruned, err := e.ApplyRetention(ctx, RetentionPolicy{GFSScheme: "1d0w0m"}) // keep 1
	if err != nil {
		t.Fatalf("ApplyRetention: %v", err)
	}
	if pruned != 2 {
		t.Fatalf("pruned = %d, want 2 (3 runs, keep 1)", pruned)
	}
	if _, ok := store.get("backup-manifest-" + tss[2] + ".json"); !ok {
		t.Error("newest manifest must survive")
	}
	for _, ts := range tss[:2] {
		if _, ok := store.get("backup-manifest-" + ts + ".json"); ok {
			t.Errorf("manifest %s should be pruned from the store", ts)
		}
		if _, ok := store.get("config-" + ts + ".json"); ok {
			t.Errorf("config %s should be pruned from the store", ts)
		}
	}
	var n int
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM backup_runs WHERE id = ANY($1)`, ids[:2]).Scan(&n)
	if n != 0 {
		t.Errorf("oldest backup_runs rows should be deleted, %d remain", n)
	}
}
