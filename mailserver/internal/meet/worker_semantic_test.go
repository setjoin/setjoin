package meet

import (
	"context"
	"fmt"
	"testing"

	"setjoin.com/mailserver/internal/meet/presentation"
)

// M4 slice 1 worker tests — the two semantic drain legs
// (worker_semantic.go) against the real reducers. DB-gated: the legs are
// pool-only, but their subject matter is the reducer contract.

// The tests drive the REAL reducers via plain SQL on the test pool (the
// fake-free tier) and assert the worker's drain legs converge through them.

func TestWorkerSemanticSweepDeletesPackage(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	ctx := context.Background()

	host := meetTestUser(t, pool, "semworkerhost")
	var meetingID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO meetings (title, owner_user_id, state) VALUES ('sem-sweep', $1, 'live') RETURNING id`,
		host).Scan(&meetingID); err != nil {
		t.Fatalf("meeting: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `SELECT meeting_end($1, $2)`, host, meetingID) })
	if _, err := pool.Exec(ctx,
		`INSERT INTO meeting_participants (meeting_id, user_id, identity, role, joined_at)
		 VALUES ($1, $2::bigint, 'u:' || $2::text, 'host', now())`, meetingID, host); err != nil {
		t.Fatalf("participant: %v", err)
	}

	var recID int64
	if err := pool.QueryRow(ctx,
		`SELECT meeting_semantic_recording_start($1, $2, 'server_audio', NULL)`,
		host, meetingID).Scan(&recID); err != nil {
		t.Fatalf("start: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT meeting_semantic_recording_stop($1, $2)`, host, meetingID); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT meeting_semantic_package_mark_delete($1, $2, $3)`,
		host, meetingID, recID); err != nil {
		t.Fatalf("mark_delete: %v", err)
	}
	var generation int64
	if err := pool.QueryRow(ctx,
		`SELECT deletion_generation FROM meeting_semantic_recordings WHERE id = $1`, recID).Scan(&generation); err != nil {
		t.Fatalf("generation: %v", err)
	}

	w := meetWorker(pool, true, configuredCfg, newFakeRooms())
	w.sweepSemanticPackages(ctx)

	var state string
	var released, total int
	if err := pool.QueryRow(ctx, `
		SELECT r.package_state,
		       (SELECT count(*)::int FROM meeting_semantic_children c WHERE c.recording_id = r.id AND c.released),
		       (SELECT count(*)::int FROM meeting_semantic_children c WHERE c.recording_id = r.id)
		  FROM meeting_semantic_recordings r WHERE r.id = $1`, recID).
		Scan(&state, &released, &total); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if state != "DELETED" {
		t.Fatalf("the sweep finalizes the package through the reducers: got %s (%d/%d released)", state, released, total)
	}
	if released != total {
		t.Fatalf("every expected child was released: %d/%d", released, total)
	}

	// Idempotence: a second sweep over a DELETED package is a no-op.
	w.sweepSemanticPackages(ctx)
	if err := pool.QueryRow(ctx,
		`SELECT package_state FROM meeting_semantic_recordings WHERE id = $1`, recID).Scan(&state); err != nil {
		t.Fatalf("read back 2: %v", err)
	}
	if state != "DELETED" {
		t.Fatalf("the deleted package never resurrects: %s", state)
	}
}

func TestWorkerSemanticSweepHoldFences(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	ctx := context.Background()

	host := meetTestUser(t, pool, "semworkerhold")
	var meetingID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO meetings (title, owner_user_id, state) VALUES ('sem-hold', $1, 'live') RETURNING id`,
		host).Scan(&meetingID); err != nil {
		t.Fatalf("meeting: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `SELECT meeting_end($1, $2)`, host, meetingID) })
	if _, err := pool.Exec(ctx,
		`INSERT INTO meeting_participants (meeting_id, user_id, identity, role, joined_at)
		 VALUES ($1, $2::bigint, 'u:' || $2::text, 'host', now())`, meetingID, host); err != nil {
		t.Fatalf("participant: %v", err)
	}

	var recID int64
	if err := pool.QueryRow(ctx,
		`SELECT meeting_semantic_recording_start($1, $2, 'server_audio', NULL)`,
		host, meetingID).Scan(&recID); err != nil {
		t.Fatalf("start: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT meeting_semantic_recording_stop($1, $2)`, host, meetingID); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT meeting_semantic_package_mark_delete($1, $2, $3)`,
		host, meetingID, recID); err != nil {
		t.Fatalf("mark_delete: %v", err)
	}
	// The hold lands AFTER the mark: zero required releases → HELD_COMPLETE,
	// and the sweep must converge to nothing (fenced, not crashed).
	if _, err := pool.Exec(ctx, `SELECT meeting_semantic_package_hold($1, $2, $3, true)`,
		host, meetingID, recID); err != nil {
		t.Fatalf("hold: %v", err)
	}

	w := meetWorker(pool, true, configuredCfg, newFakeRooms())
	w.sweepSemanticPackages(ctx)

	var state string
	if err := pool.QueryRow(ctx,
		`SELECT package_state FROM meeting_semantic_recordings WHERE id = $1`, recID).Scan(&state); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if state != "HELD_COMPLETE" {
		t.Fatalf("a held package suspends the sweep: got %s", state)
	}
}

func TestWorkerSemanticExportNilComposerFailsClosed(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	ctx := context.Background()

	host := meetTestUser(t, pool, "semworkerexport")
	var meetingID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO meetings (title, owner_user_id, state) VALUES ('sem-export', $1, 'live') RETURNING id`,
		host).Scan(&meetingID); err != nil {
		t.Fatalf("meeting: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `SELECT meeting_end($1, $2)`, host, meetingID) })
	if _, err := pool.Exec(ctx,
		`INSERT INTO meeting_participants (meeting_id, user_id, identity, role, joined_at)
		 VALUES ($1, $2::bigint, 'u:' || $2::text, 'host', now())`, meetingID, host); err != nil {
		t.Fatalf("participant: %v", err)
	}

	var recID int64
	if err := pool.QueryRow(ctx,
		`SELECT meeting_semantic_recording_start($1, $2, 'server_audio', NULL)`,
		host, meetingID).Scan(&recID); err != nil {
		t.Fatalf("start: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`SELECT meeting_semantic_segment_ingest($1, 1, 'verified', repeat('ab', 32), 100,
		       'audio/webm', 'opus', 'webm', 0, 1000, 1, 2, NULL)`, recID); err != nil {
		t.Fatalf("segment ingest: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT meeting_semantic_recording_stop($1, $2)`, host, meetingID); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT meeting_semantic_export_request($1, $2, $3, NULL, NULL)`,
		host, meetingID, recID); err != nil {
		t.Fatalf("export request: %v", err)
	}

	// The production state: NO composer is wired (the audio path is
	// evidence-gated). The queue must settle the receipt FAILED with the
	// named reason — never re-queue forever, never fabricate a video.
	w := meetWorker(pool, true, configuredCfg, newFakeRooms())
	w.drainSemanticExports(ctx)

	var state, errText string
	if err := pool.QueryRow(ctx,
		`SELECT state, COALESCE(error, '') FROM meeting_semantic_exports WHERE recording_id = $1`,
		recID).Scan(&state, &errText); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if state != "failed" {
		t.Fatalf("the export completes failed with no qualified composer: got %s", state)
	}
	if errText == "" {
		t.Fatal("the failure names its cause")
	}
	// Idempotence + no-duplication: repeated ticks never mint more receipts
	// or flip the settled state.
	w.drainSemanticExports(ctx)
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*)::int FROM meeting_semantic_exports WHERE recording_id = $1 AND state = 'ready'`,
		recID).Scan(&n); err != nil {
		t.Fatalf("ready count: %v", err)
	}
	if n != 0 {
		t.Fatal("no ready export can exist while composition is fail-closed")
	}
}

type fakeComposer struct {
	calls int
}

func (f *fakeComposer) Compose(ctx context.Context, plan *presentation.ComposePlan) (int64, int64, string, error) {
	f.calls++
	return 0, 0, "", fmt.Errorf("simulated composition fault")
}

func TestWorkerSemanticExportComposerFaultRetainsSource(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	ctx := context.Background()

	host := meetTestUser(t, pool, "semworkerfault")
	var meetingID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO meetings (title, owner_user_id, state) VALUES ('sem-fault', $1, 'live') RETURNING id`,
		host).Scan(&meetingID); err != nil {
		t.Fatalf("meeting: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `SELECT meeting_end($1, $2)`, host, meetingID) })
	if _, err := pool.Exec(ctx,
		`INSERT INTO meeting_participants (meeting_id, user_id, identity, role, joined_at)
		 VALUES ($1, $2::bigint, 'u:' || $2::text, 'host', now())`, meetingID, host); err != nil {
		t.Fatalf("participant: %v", err)
	}

	var recID int64
	if err := pool.QueryRow(ctx,
		`SELECT meeting_semantic_recording_start($1, $2, 'server_audio', NULL)`,
		host, meetingID).Scan(&recID); err != nil {
		t.Fatalf("start: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`SELECT meeting_semantic_segment_ingest($1, 1, 'verified', repeat('ab', 32), 100,
		       'audio/webm', 'opus', 'webm', 0, 1000, 1, 2, NULL)`, recID); err != nil {
		t.Fatalf("segment ingest: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT meeting_semantic_recording_stop($1, $2)`, host, meetingID); err != nil {
		t.Fatalf("stop: %v", err)
	}
	// The bounds are the CONFIRMED windows the Go request path computes via
	// PlanExport from the verified coverage — here [0,1000), no exclusions.
	if _, err := pool.Exec(ctx,
		`SELECT meeting_semantic_export_request($1, $2, $3, '[{"startMs":0,"endMs":1000}]'::jsonb, '[]'::jsonb)`,
		host, meetingID, recID); err != nil {
		t.Fatalf("export request: %v", err)
	}

	composer := &fakeComposer{}
	w := meetWorker(pool, true, configuredCfg, newFakeRooms())
	w.composer = composer
	w.drainSemanticExports(ctx)

	if composer.calls != 1 {
		t.Fatalf("the composer ran exactly once for the claim: %d", composer.calls)
	}
	var state, errText string
	var segs int
	if err := pool.QueryRow(ctx, `
		SELECT e.state, COALESCE(e.error, ''),
		       (SELECT count(*)::int FROM meeting_semantic_segments WHERE recording_id = $1 AND state = 'verified')
		  FROM meeting_semantic_exports e WHERE e.recording_id = $1`,
		recID).Scan(&state, &errText, &segs); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if state != "failed" || errText == "" {
		t.Fatalf("a composer fault settles failed with its reason: %s/%q", state, errText)
	}
	if segs != 1 {
		t.Fatalf("the semantic source is retained untouched by every export arm: %d verified segments", segs)
	}
}

type capturingComposer struct {
	plan *presentation.ComposePlan
}

func (c *capturingComposer) Compose(ctx context.Context, plan *presentation.ComposePlan) (int64, int64, string, error) {
	c.plan = plan
	return 421, 422, "audio/mp4", nil
}

// A NULL-bounds receipt defers to the worker's coverage computation (the
// reducer contract): the composer must receive the merged verified runs as
// the confirmed bounds and the export must complete — not be refused by a
// synthesized empty bound.
func TestWorkerSemanticExportDeferredBoundsCompose(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	ctx := context.Background()

	host := meetTestUser(t, pool, "semdeferred")
	var meetingID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO meetings (title, owner_user_id, state) VALUES ('sem-deferred', $1, 'live') RETURNING id`,
		host).Scan(&meetingID); err != nil {
		t.Fatalf("meeting: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `SELECT meeting_end($1, $2)`, host, meetingID) })
	if _, err := pool.Exec(ctx,
		`INSERT INTO meeting_participants (meeting_id, user_id, identity, role, joined_at)
		 VALUES ($1, $2::bigint, 'u:' || $2::text, 'host', now())`, meetingID, host); err != nil {
		t.Fatalf("participant: %v", err)
	}

	var recID int64
	if err := pool.QueryRow(ctx,
		`SELECT meeting_semantic_recording_start($1, $2, 'server_audio', NULL)`,
		host, meetingID).Scan(&recID); err != nil {
		t.Fatalf("start: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`SELECT meeting_semantic_segment_ingest($1, 1, 'verified', repeat('ab', 32), 100,
		       'audio/webm', 'opus', 'webm', 0, 500, 1, 2, NULL)`, recID); err != nil {
		t.Fatalf("segment ingest 1: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`SELECT meeting_semantic_segment_ingest($1, 2, 'verified', repeat('cd', 32), 100,
		       'audio/webm', 'opus', 'webm', 500, 1000, 2, 3, NULL)`, recID); err != nil {
		t.Fatalf("segment ingest 2: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT meeting_semantic_recording_stop($1, $2)`, host, meetingID); err != nil {
		t.Fatalf("stop: %v", err)
	}
	// The DEFAULT request pins NO confirmed bounds — the reducer contract
	// defers them to this worker's coverage computation.
	if _, err := pool.Exec(ctx,
		`SELECT meeting_semantic_export_request($1, $2, $3)`,
		host, meetingID, recID); err != nil {
		t.Fatalf("export request: %v", err)
	}

	composer := &capturingComposer{}
	w := meetWorker(pool, true, configuredCfg, newFakeRooms())
	w.composer = composer
	w.drainSemanticExports(ctx)

	if composer.plan == nil {
		t.Fatal("the deferred-bounds export reached the composer")
	}
	if len(composer.plan.Bounds) != 1 || composer.plan.Bounds[0] != (presentation.MediaInterval{StartMs: 0, EndMs: 1000}) {
		t.Fatalf("deferred bounds are the merged verified coverage: %+v", composer.plan.Bounds)
	}
	var state string
	if err := pool.QueryRow(ctx,
		`SELECT e.state FROM meeting_semantic_exports e WHERE e.recording_id = $1`,
		recID).Scan(&state); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if state != "ready" {
		t.Fatalf("the deferred-bounds export composes to ready: %s", state)
	}
}

// A closed pool makes every query fail with pgxpool.ErrClosed — the honest
// way to drive the drain legs' fault arms (each must log and return, never
// panic, and leave nothing half-mutated).
func TestWorkerSemanticLegsSurviveDBFault(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	w := meetWorker(pool, true, configuredCfg, newFakeRooms())
	pool.Close()

	ctx := context.Background()
	w.sweepSemanticPackages(ctx) // delete-pending query fails
	w.sweepOnePackage(ctx, 1, 1) // children query fails
	w.drainSemanticExports(ctx)  // export query fails
	w.exportOne(ctx, 1, 1)       // claim fails
	w.completeExport(ctx, 1, 1, true, 1, 2, "")
	if _, err := w.buildComposePlan(ctx, 1, 1); err == nil {
		t.Fatal("plan build against a dead DB must surface the lookup failure")
	}
}
