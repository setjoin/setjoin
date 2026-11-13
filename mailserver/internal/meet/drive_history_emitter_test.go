// drive_history_emitter_test.go — the MEET Drive-History worker leg
// (drive_history_emitter.go) against the real DRIVE-side ingest reducer
// (drive_meet_history_emit + V269). DB-gated (the worker_semantic_test.go
// genre: DB_DSN skip-if-absent, raw SQL fixtures, the real reducers).
//
// The test drives the three frozen lifecycle points through real reducers,
// runs the leg, and pins the emitter's contract (hermetically: the leg's
// candidate SELECTs are global sweeps in production, so the test scopes its
// candidate selection to the ids it seeded — see the emitSeededFacts note):
//   - each committed fact lands exactly ONE chain entry (drive_audit_log)
//     through the owning Drive authority, with the receipt in V269;
//   - a stopped package with NO ready export receipts 'absent' and mints no
//     chain entry (non-Drive authority is never synthesized);
//   - a second leg run is a full replay: no new chain entries, no new
//     receipts (the idempotency belt holds across ticks);
//   - the space chain still verifies end to end (the §9.3 discipline the
//     emitter rides, never reimplements).
package meet

import (
	"context"
	"fmt"
	"testing"
)

func TestWorkerDriveHistoryEmitsLifecycleEvents(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	ctx := context.Background()

	host := meetTestUser(t, pool, "dh-host")

	// The meeting + its host participant.
	var meetingID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO meetings (title, owner_user_id, state) VALUES ('dh-worker', $1, 'live') RETURNING id`,
		host).Scan(&meetingID); err != nil {
		t.Fatalf("meeting: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `SELECT meeting_end($1, $2)`, host, meetingID) })
	if _, err := pool.Exec(ctx,
		`INSERT INTO meeting_participants (meeting_id, user_id, identity, role, joined_at)
		 VALUES ($1, $2::bigint, 'u:' || $2::text, 'host', now())`, meetingID, host); err != nil {
		t.Fatalf("participant: %v", err)
	}

	// Drive: the presented source (node/ver) + the rendition output
	// (rnode/rver) in one host-owned space.
	var spaceID, nodeID, verID, rnodeID, rverID int64
	if err := pool.QueryRow(ctx,
		`SELECT drive_space_create($1, 'dh-worker-space', 'regular')`, host).Scan(&spaceID); err != nil {
		t.Fatalf("space: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT drive_node_create($1, $2, NULL, 'file', 'deck.pdf')`, host, spaceID).Scan(&nodeID); err != nil {
		t.Fatalf("node: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO drive_file_versions (file_node_id, space_id, content_sha256, size_bytes, author_user_id)
		 VALUES ($1, $2, repeat('ab', 32), 1, $3) RETURNING id`, nodeID, spaceID, host).Scan(&verID); err != nil {
		t.Fatalf("version: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT drive_node_create($1, $2, NULL, 'file', 'rendition.mp4')`, host, spaceID).Scan(&rnodeID); err != nil {
		t.Fatalf("rnode: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO drive_file_versions (file_node_id, space_id, content_sha256, size_bytes, author_user_id)
		 VALUES ($1, $2, repeat('cd', 32), 1, $3) RETURNING id`, rnodeID, spaceID, host).Scan(&rverID); err != nil {
		t.Fatalf("rversion: %v", err)
	}

	// Lifecycle point 3 (presentation.pinned): prepare → ready → start.
	var presID int64
	if err := pool.QueryRow(ctx,
		`SELECT meeting_presentation_prepare($1, $2, $3, $4, repeat('ef', 32))`,
		host, meetingID, nodeID, verID).Scan(&presID); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`SELECT meeting_presentation_ready($1, $2, $3, NULL)`, host, meetingID, presID); err != nil {
		t.Fatalf("ready: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`SELECT meeting_presentation_start($1, $2, $3, 1)`, host, meetingID, presID); err != nil {
		t.Fatalf("start: %v", err)
	}

	// Lifecycle point 2 (annotation.committed): the real commit path. The
	// byte size derives from the exact snapshot bytes (never a literal).
	if _, err := pool.Exec(ctx,
		`SELECT meeting_presentation_annotation_commit($1, $2, $3, 1, 2, false,
		    '{"worker":true}', octet_length(convert_to('{"worker":true}', 'UTF8')))`,
		host, meetingID, presID); err != nil {
		t.Fatalf("annotation commit: %v", err)
	}
	var annID int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM meeting_presentation_annotations WHERE presentation_id = $1`, presID).Scan(&annID); err != nil {
		t.Fatalf("annotation lookup: %v", err)
	}

	// Lifecycle point 1 (recording.stopped): start → verified segment →
	// stop → export request → claim → complete ready onto rnode/rver —
	// plus rec2, stopped but NEVER exported (the absent arm).
	semanticRecording := func(label string) int64 {
		t.Helper()
		var recID int64
		if err := pool.QueryRow(ctx,
			`SELECT meeting_semantic_recording_start($1, $2, 'server_audio', NULL)`,
			host, meetingID).Scan(&recID); err != nil {
			t.Fatalf("%s start: %v", label, err)
		}
		return recID
	}
	recID := semanticRecording("exported")
	if _, err := pool.Exec(ctx,
		`SELECT meeting_semantic_segment_ingest($1, 1, 'verified', repeat('12', 32), 48210,
		                                        'audio/webm', 'opus', 'webm', 0, 1000, 1000, 2000, NULL)`,
		recID); err != nil {
		t.Fatalf("segment ingest: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`SELECT meeting_semantic_recording_stop($1, $2)`, host, meetingID); err != nil {
		t.Fatalf("stop: %v", err)
	}
	var generation int64
	if err := pool.QueryRow(ctx,
		`SELECT (meeting_semantic_export_request($1, $2, $3, NULL, NULL)->>'generation')::bigint`,
		host, meetingID, recID).Scan(&generation); err != nil {
		t.Fatalf("export request: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`SELECT meeting_semantic_export_claim($1, $2)`, recID, generation); err != nil {
		t.Fatalf("export claim: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`SELECT meeting_semantic_export_complete($1, $2, true, $3, $4, NULL)`,
		recID, generation, rnodeID, rverID); err != nil {
		t.Fatalf("export complete: %v", err)
	}
	rec2ID := semanticRecording("absent")
	if _, err := pool.Exec(ctx,
		`SELECT meeting_semantic_recording_stop($1, $2)`, host, meetingID); err != nil {
		t.Fatalf("stop2: %v", err)
	}

	w := meetWorker(pool, true, configuredCfg, newFakeRooms())

	// The production drains (emitMeetDriveHistory) are GLOBAL sweeps — every
	// committed meet fact on the database, one bounded batch per tick — so
	// driving them raw would make this test an oracle on foreign state: a
	// shared DB's un-emitted facts could fill the batch ahead of this test's
	// ids (starving them) or mutate shared state mid-run. Hermeticity
	// therefore comes from the candidate SELECTs, not from skipping: the leg
	// runs through the SAME emit entry point (emitDriveHistoryKind →
	// drive_meet_history_emit → receipt ledger + §9.3 chain), with the
	// candidate scope narrowed to the ids THIS test seeded (its own
	// generated int64s — never request input — inlined the same way the
	// fault-arms genre crafts candidate queries). Everything downstream of
	// candidate selection is production end to end.
	emitSeededFacts := func() {
		t.Helper()
		w.emitDriveHistoryKind(ctx, "recording.stopped", fmt.Sprintf(`
			SELECT r.id
			  FROM meeting_semantic_recordings r
			 WHERE r.id IN (%d, %d)
			   AND NOT EXISTS (SELECT 1 FROM drive_meet_history_events h
			                    WHERE h.source_kind = 'recording.stopped'
			                      AND h.source_id = r.id)
			 ORDER BY r.id
			 LIMIT $1`, recID, rec2ID))
		w.emitDriveHistoryKind(ctx, "annotation.committed", fmt.Sprintf(`
			SELECT a.id
			  FROM meeting_presentation_annotations a
			 WHERE a.id = %d
			   AND NOT EXISTS (SELECT 1 FROM drive_meet_history_events h
			                    WHERE h.source_kind = 'annotation.committed'
			                      AND h.source_id = a.id)
			 ORDER BY a.id
			 LIMIT $1`, annID))
		w.emitDriveHistoryKind(ctx, "presentation.pinned", fmt.Sprintf(`
			SELECT p.id
			  FROM meeting_presentations p
			 WHERE p.id = %d
			   AND NOT EXISTS (SELECT 1 FROM drive_meet_history_events h
			                    WHERE h.source_kind = 'presentation.pinned'
			                      AND h.source_id = p.id)
			 ORDER BY p.id
			 LIMIT $1`, presID))
	}
	emitSeededFacts()

	// Exactly one receipt per fact THIS test seeded — read back by the
	// specific recording/annotation/presentation ids, never a meeting-wide
	// or global aggregate: 3 Drive-attached emits (exported stop, annotation
	// commit, pin) + the unexported stop's 'absent'. The annotation and pin
	// attach to the presented node, the stop to the rendition node.
	var emitted, absent, spaceAuditEntries int64
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE state = 'emitted'),
		        count(*) FILTER (WHERE state = 'absent')
		   FROM drive_meet_history_events
		  WHERE (source_kind, source_id) IN
		        (('recording.stopped', $1), ('recording.stopped', $2),
		         ('annotation.committed', $3), ('presentation.pinned', $4))`,
		recID, rec2ID, annID, presID).Scan(&emitted, &absent); err != nil {
		t.Fatalf("receipt count: %v", err)
	}
	if emitted != 3 || absent != 1 {
		t.Fatalf("receipts: got emitted=%d absent=%d, want 3/1 (pin, annotation, exported stop; unexported stop absent)", emitted, absent)
	}
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM drive_audit_log
		  WHERE space_id = $1 AND action LIKE 'meet.%'`, spaceID).Scan(&spaceAuditEntries); err != nil {
		t.Fatalf("audit count: %v", err)
	}
	if spaceAuditEntries != 3 {
		t.Fatalf("chain entries: got %d, want 3 (one per lifecycle point)", spaceAuditEntries)
	}

	// The stop entry attaches to the rendition output node; the pin and
	// annotation entries attach to the presented node (target_type='node'
	// is what drive_file_history_query keys on).
	var rnodeEntries, nodeEntries int64
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM drive_audit_log
		  WHERE space_id = $1 AND action = 'meet.recording.stopped'
		    AND target_type = 'node' AND target_id = $2`, spaceID, rnodeID).Scan(&rnodeEntries); err != nil {
		t.Fatalf("rnode entries: %v", err)
	}
	if rnodeEntries != 1 {
		t.Fatalf("rendition node entries: got %d, want 1", rnodeEntries)
	}
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM drive_audit_log
		  WHERE space_id = $1 AND action IN ('meet.annotation.committed','meet.presentation.pinned')
		    AND target_type = 'node' AND target_id = $2`, spaceID, nodeID).Scan(&nodeEntries); err != nil {
		t.Fatalf("node entries: %v", err)
	}
	if nodeEntries != 2 {
		t.Fatalf("presented node entries: got %d, want 2", nodeEntries)
	}

	// The absent arm: receipted, never synthesized into the chain — exactly
	// ONE stop entry exists in the space (the exported package's).
	var absentState string
	if err := pool.QueryRow(ctx,
		`SELECT state FROM drive_meet_history_events
		  WHERE source_kind = 'recording.stopped' AND source_id = $1`, rec2ID).Scan(&absentState); err != nil {
		t.Fatalf("absent receipt: %v", err)
	}
	var stopEntries int64
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM drive_audit_log
		  WHERE space_id = $1 AND action = 'meet.recording.stopped'`, spaceID).Scan(&stopEntries); err != nil {
		t.Fatalf("stop entry count: %v", err)
	}
	if absentState != "absent" || stopEntries != 1 {
		t.Fatalf("absent arm: receipt state %q, stop chain entries %d (want absent/1)", absentState, stopEntries)
	}

	// The chain the emitter rode still verifies end to end.
	var chainValid bool
	if err := pool.QueryRow(ctx,
		`SELECT bool_and(valid) FROM verify_drive_audit_chain($1)`, spaceID).Scan(&chainValid); err != nil {
		t.Fatalf("chain verify: %v", err)
	}
	if !chainValid {
		t.Fatal("the space audit chain does not verify after emission")
	}

	// A second leg run is a full replay: every seeded fact now carries its
	// receipt, so the drains' NOT EXISTS belt re-selects nothing — no new
	// chain entries, no new receipts. The receipt ledger's UNIQUE
	// (source_kind, source_id) is the across-tick belt (a retry re-enters
	// the committed receipt, never double-appends).
	emitSeededFacts()
	var replayed, spaceAuditAfter int64
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM drive_meet_history_events
		  WHERE (source_kind, source_id) IN
		        (('recording.stopped', $1), ('recording.stopped', $2),
		         ('annotation.committed', $3), ('presentation.pinned', $4))`,
		recID, rec2ID, annID, presID).Scan(&replayed); err != nil {
		t.Fatalf("receipt recount: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM drive_audit_log
		  WHERE space_id = $1 AND action LIKE 'meet.%'`, spaceID).Scan(&spaceAuditAfter); err != nil {
		t.Fatalf("audit recount: %v", err)
	}
	if replayed != 4 || spaceAuditAfter != 3 {
		t.Fatalf("replay: receipts %d chain entries %d, want 4/3 (retries re-enter, never double-append)", replayed, spaceAuditAfter)
	}
}

// TestWorkerDriveHistoryFaultArms pins the leg's log-and-continue contract:
// a candidate-query failure, a bad scan shape, and a REFUSED emit each end
// this tick's attempt without panicking or wedging — the next tick retries
// through the receipt's idempotency. These arms are reached with crafted
// leg inputs (a nonexistent table, a non-id column, a kind/id mismatch);
// production inputs are the frozen queries above.
func TestWorkerDriveHistoryFaultArms(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	ctx := context.Background()
	w := meetWorker(pool, true, configuredCfg, newFakeRooms())

	// A candidate query that cannot run: the leg logs and returns.
	w.emitDriveHistoryKind(ctx, "recording.stopped", `
		SELECT id FROM no_such_drive_history_table WHERE package_state = 'x' LIMIT $1`)

	// A candidate row that is not an id: the leg logs and returns.
	w.emitDriveHistoryKind(ctx, "annotation.committed", `
		SELECT meeting_id::text FROM meeting_semantic_recordings LIMIT $1`)

	// A fact the ingest refuses (a meeting id is not an annotation id):
	// the emit fails, the leg logs and CONTINUES to the next candidate.
	if _, err := pool.Exec(ctx,
		`INSERT INTO meetings (title, owner_user_id, state) VALUES ('dh-fault', (SELECT max(owner_user_id) FROM meetings), 'live')`); err != nil {
		t.Fatalf("meeting: %v", err)
	}
	w.emitDriveHistoryKind(ctx, "annotation.committed", `
		SELECT id FROM meetings WHERE title = 'dh-fault' ORDER BY id DESC LIMIT $1`)
}
