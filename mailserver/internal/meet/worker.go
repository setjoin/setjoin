// worker.go — Task 12 (B1): the Meet reconcile sweep, and the Worker type
// every arm below attaches to. Spike §2 finding 2 is why this exists:
// LiveKit webhooks are retried, sequenced, but NOT guaranteed delivered, so
// meeting lifecycle GC cannot depend on them arriving. This worker is the
// backstop that converges state even when every webhook for a given meeting
// is lost — the drive.NewWorker posture (started unconditionally in
// main.go, Task 13; each tick is inert unless feature.meet is ON and the
// LiveKit sidecar is configured).
//
// This file owns the Worker type, its constructor/Run/tick dispatcher, and
// the ORIGINAL Task-12 lifecycle arm (lobby expiry, the ended-but-live
// DeleteRoom retry, the lost-webhook GC). Three later programs extended the
// SAME Worker with their own arms, split into sibling files (route-file-split
// shape, arch #4): worker_recordings.go (B2), worker_breakouts.go (B3a),
// worker_captions.go (B3b). Pure file move — same package, same methods, no
// worker-arm abstraction (five arms, five real shapes; a common interface
// would erase the very asymmetry documented below).
//
// ── THE TWO GATING POSTURES (verbatim-critical — read before touching tick) ──
//
//  1. B2's recording drains (reconcileRecordings/ingestRecordings/reapStaging,
//     worker_recordings.go) run BEFORE and OUTSIDE the
//     `feature.meet && Configured()` gate below, gated only on their OWN
//     runtime deps (an Egress/S3-store binding) existing — NEVER on
//     feature.meet or feature.meet_recording. This is the D11
//     unconditional-drain posture: a toggle gates new intent, never the
//     draining of already-committed state — a recording started before
//     feature.meet_recording flips OFF must still stop, upload, and ingest.
//
//  2. B3's breakout/captions healers (reconcileBreakouts/reconcileCaptions,
//     worker_breakouts.go/worker_captions.go) run INSIDE the SAME
//     `feature.meet && Configured()` gate as the original Task-12 lifecycle
//     legs (they need liveSet/RoomController the same way
//     deleteEndedButLiveRooms does) — but are NEVER gated on
//     feature.meet_breakouts/feature.meet_captions themselves. A toggle flip
//     must never strand anyone in a breakout room nobody can close or leave,
//     nor strand a crashed or orphaned captions session.
//
// Do not "simplify" either posture into the other — they are deliberately
// different gates for deliberately different reasons (drain-what's-committed
// vs. heal-what's-live-under-the-parent-gate).
package meet

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
)

// workerInterval is the plan's locked 60s reconcile cadence.
const workerInterval = 60 * time.Second

// staleWindow: how long a 'live' meeting must show zero open participants
// AND no create/join/leave activity before the lost-webhook GC leg (below)
// treats it as abandoned — the plan's locked predicate.
const staleWindow = 10 * time.Minute

// Worker runs the Task 12 reconcile sweep every tick: lobby expiry
// (meeting_requests_expire), the ended-but-still-on-the-SFU DeleteRoom
// retry (the Task 10 kick/end 502 backstop), and the lost-webhook GC (a
// live meeting with zero open participants, no SFU room, and no activity
// for staleWindow gets a synthetic room_finished fact) — plus (B2 Task 7)
// the recording ingest/reconcile/reaper legs (worker_recordings.go), (B3a)
// the breakout GC/presence-heal legs (worker_breakouts.go), and (B3b Task 14)
// the captions healer (worker_captions.go).
type Worker struct {
	pool     pgxutil.WorkerPool
	flags    *toggle.FeatureFlags
	cfg      Config
	rooms    RoomController
	egress   EgressController // B2 Task 7; nil-safe — reconcileRecordings skipped when nil
	store    stagingStore     // B2 Task 7; nil-safe — ingestRecordings/reapStaging skipped when nil
	bucket   string
	captions CaptionsController // B3 Task 14; nil-safe — reconcileCaptions skipped when nil
	// composer is the M4 bounded MP4 composition seam (worker_semantic.go);
	// deliberately nil in slice 1 — the audio path is evidence-gated, so
	// every claimed export completes failed with exportCompositionFailed
	// and the semantic source is retained. Qualification lands as an
	// implementation of ExportComposer, never as a flag flip.
	composer ExportComposer // M4; nil-safe — exports complete failed while nil
	logger   *slog.Logger

	// ingestFaultBeforeFinalize is a test-only hook (nil in production,
	// zero cost): when set, ingestOne calls it right after
	// drive_file_put_version succeeds and returns its error instead of
	// proceeding to meeting_recording_ingested — the fakeEgress.startHook
	// genre, used to prove a mid-transaction crash leaves no orphan node
	// (the whole txn rolls back) and a retry converges. (worker_recordings.go)
	ingestFaultBeforeFinalize func() error

	// absentSince is the B3 Task 5 delta-8 grace map (reconcileBreakoutPresence,
	// worker_breakouts.go): key = "meetingID/identity", value = the
	// meeting/identity that entry belongs to (so the sweep can settle it
	// without re-parsing the key string). In-memory only — ponytail: a
	// worker restart extends the grace, never fires it early; move to a DB
	// column if multi-instance workers ever exist.
	//
	// eng retro finding #4: every entry is settled (stamped or dropped) the
	// FIRST tick its meeting falls out of the candidate set (sweepStale
	// AbsentEntries, called from reconcileBreakoutPresence) — an entry never
	// lingers past that tick. This closes three bugs at once: unbounded
	// growth (a meeting that leaves the candidate set for good used to keep
	// its entries forever), destructive-early stamps on a LATER breakout
	// session that reuses the same meetingID/identity key (a stale entry
	// used to still read as "seen last tick"), and the phantom-participant
	// hole (an assignee who left from a non-assigned room — leave suppressed
	// by the §4.1 mismatch rule — whose host closed breakouts before the
	// grace's second tick used to never get left_at stamped at all, blocking
	// gcLostWebhooks' NOT EXISTS(open participants) predicate forever).
	absentSince map[string]absentEntry
}

// NewWorker builds the reconcile worker. store/bucket may be zero-valued on
// a box with no S3 configured — the ingest/reaper legs then no-op (w.store
// nil-checked in tick). captions may be nil on a box with no ASR sidecar
// configured — reconcileCaptions then no-ops (w.captions nil-checked).
func NewWorker(pool pgxutil.WorkerPool, flags *toggle.FeatureFlags, cfg Config,
	rooms RoomController, egress EgressController, store stagingStore, bucket string,
	captions CaptionsController, logger *slog.Logger) *Worker {
	return &Worker{pool: pool, flags: flags, cfg: cfg, rooms: rooms,
		egress: egress, store: store, bucket: bucket, captions: captions, logger: logger,
		absentSince: map[string]absentEntry{}}
}

// Run starts the ticker loop; exits cleanly when ctx is cancelled (the
// drive.Worker.Run / chat unfurl Worker.Run precedent).
func (w *Worker) Run(ctx context.Context) {
	w.logger.Info("meet reconcile worker started", "interval", workerInterval)
	ticker := time.NewTicker(workerInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			w.logger.Info("meet reconcile worker stopped")
			return
		case <-ticker.C:
			w.tick(ctx)
		}
	}
}

// tick is inert unless feature.meet is ON and the sidecar is configured —
// the worker goroutine always runs (drive.NewWorker's posture); the toggle
// gates what a tick actually does, never whether the goroutine exists.
//
// See the file-header "TWO GATING POSTURES" block above — this function IS
// the two gates: the B2 recording drains run first and unconditionally,
// then everything below the feature.meet && Configured() check runs inside
// that one gate (never gated a second time on feature.meet_breakouts /
// feature.meet_captions).
func (w *Worker) tick(ctx context.Context) {
	// F5: reconcileRecordings' DB-only legs (ended-residue flip, wedge-4
	// sweep, stale-requested grace) need only the pool, never the Egress
	// API — they run unconditionally inside it (never gated on w.egress),
	// or every row they'd otherwise converge wedges forever the moment the
	// sidecar is deconfigured with recordings still in flight.
	w.reconcileRecordings(ctx)
	if w.store != nil {
		w.ingestRecordings(ctx)
		w.reapStaging(ctx)
	}
	// M4 (worker_semantic.go): the semantic package-delete sweep and the
	// bounded export queue share the B2 drain posture — pool-only, outside
	// every feature gate, never gated on feature.meet_semantic_recording.
	w.sweepSemanticPackages(ctx)
	w.drainSemanticExports(ctx)
	// M4/M1 follow-up (drive_history_emitter.go): the Drive-History leg
	// rides the SAME drain posture — it drives the three frozen lifecycle
	// points through the DRIVE-side ingest reducer; observational, never a
	// second coordinator, no backfill.
	w.emitMeetDriveHistory(ctx)
	// M5: the local-capture lease expirer rides the SAME drain posture —
	// a lease is committed state (it exists only because the capture
	// started), so a tick converges expired leases even after
	// feature.meet_local_recording flips OFF; the flag gates new intent,
	// never the drain.
	w.expireLocalCaptureLeases(ctx)

	if !w.flags.IsEnabled(toggle.FeatureMeet) || !w.cfg.Configured() {
		return
	}
	if err := w.expireLobby(ctx); err != nil {
		w.logger.Warn("meet worker: lobby expiry failed", "error", err)
	}

	liveRooms, err := w.rooms.ListRooms(ctx)
	if err != nil {
		w.logger.Warn("meet worker: ListRooms failed", "error", err)
		return // both remaining legs need the live-room set; nothing more to do this tick
	}
	liveSet := make(map[string]bool, len(liveRooms))
	for _, r := range liveRooms {
		liveSet[r] = true
	}
	w.deleteEndedButLiveRooms(ctx, liveSet)
	w.reconcileBreakouts(ctx, liveSet)
	w.gcLostWebhooks(ctx, liveSet)
	w.reconcileCaptions(ctx)
}

func (w *Worker) expireLobby(ctx context.Context) error {
	_, err := w.pool.Exec(ctx, `SELECT meeting_requests_expire()`)
	return err
}

// expireLocalCaptureLeases is the M5 local-capture arm of the sweep
// (meeting_local_capture.sql's meeting_local_capture_lease_expire — the
// WORKER-plane SECURITY DEFINER drain): every live lease past its TTL flips
// 'expired' and its still-active recording stops truthfully. Bounded by the
// expirer's own limit (50/tick, the sweep-leg genre) and logs-and-continues
// on a DB error — the heartbeat lazy arm still converges any lease this tick
// missed, so a transient failure never strands state permanently.
func (w *Worker) expireLocalCaptureLeases(ctx context.Context) {
	var expired int
	if err := w.pool.QueryRow(ctx, `SELECT meeting_local_capture_lease_expire(50)`).Scan(&expired); err != nil {
		w.logger.Warn("meet worker: local-capture lease expiry failed", "error", err)
		return
	}
	if expired > 0 {
		w.logger.Info("meet worker: expired local-capture leases", "count", expired)
	}
}

// retryDeleteForRooms is the shared shape behind deleteEndedButLiveRooms
// (below) and (worker_breakouts.go's) gcClosedBreakoutRooms: run query
// (which must SELECT exactly one uuid room_name column), drain it fully,
// then retry DeleteRoom for every returned room still listed in liveSet.
// logPrefix names the caller in every warning this helper logs.
func (w *Worker) retryDeleteForRooms(ctx context.Context, liveSet map[string]bool, logPrefix, query string) {
	rows, err := w.pool.Query(ctx, query)
	if err != nil {
		w.logger.Warn(logPrefix+" query failed", "error", err)
		return
	}
	var rooms []uuid.UUID
	for rows.Next() {
		var room uuid.UUID
		if err := rows.Scan(&room); err != nil {
			rows.Close()
			w.logger.Warn(logPrefix+" scan failed", "error", err)
			return
		}
		rooms = append(rooms, room)
	}
	if err := rows.Err(); err != nil {
		w.logger.Warn(logPrefix+" rows error", "error", err)
		return
	}
	for _, room := range rooms {
		name := room.String()
		if !liveSet[name] {
			continue // already gone from the SFU — nothing to retry
		}
		if err := w.rooms.DeleteRoom(ctx, name); err != nil {
			w.logger.Warn(logPrefix+" DeleteRoom retry failed", "room", name, "error", err)
		}
	}
}

// deleteEndedButLiveRooms retries the Task 10 end/kick 502 case: a meeting
// this DB already marked 'ended' whose room the SFU still lists (the
// original DeleteRoom call failed and the host got a 502-retry response).
// Bounded to the last 24h (meeting_list.sql's own "declutter old huddles"
// window) — an ended meeting's room should disappear from the SFU within
// minutes; there is no reason to keep re-checking a months-old row forever.
func (w *Worker) deleteEndedButLiveRooms(ctx context.Context, liveSet map[string]bool) {
	w.retryDeleteForRooms(ctx, liveSet, "meet worker: ended-room", `
		SELECT room_name FROM meetings
		 WHERE state = 'ended' AND ended_at > now() - interval '24 hours'`)
}

// gcLostWebhooks implements the plan's locked predicate: a meeting still
// 'live' in our DB, with zero currently-open participants, whose last
// activity (creation, or any participant join/leave) is older than
// staleWindow, AND whose room the SFU no longer lists — that combination
// means every webhook telling us this meeting ended was lost (spike §2
// finding 2: delivery is not guaranteed), so this synthesizes the
// room_finished fact the SFU should have sent.
//
// Deviation from the plan's literal SQL (an allowance the plan's own Task
// 12 section documents): the plan's single LEFT JOIN filtered to open
// participants (p.left_at IS NULL) in the join condition itself, which
// makes max(p.left_at) inside that join always NULL — it can never see a
// CLOSED participant's left_at, so a meeting whose last participant left 2
// minutes ago would already read as "stale since creation" and GC
// immediately. This rewrite keeps the identical contract (live + zero open
// participants + no SFU room + no activity for staleWindow) but computes
// the activity high-water mark from ALL participants, open or closed, via
// a NOT EXISTS guard plus two scalar subqueries instead of one filtered
// join.
func (w *Worker) gcLostWebhooks(ctx context.Context, liveSet map[string]bool) {
	rows, err := w.pool.Query(ctx, `
		SELECT m.id, m.room_name FROM meetings m
		 WHERE m.state = 'live'
		   AND NOT EXISTS (
		     SELECT 1 FROM meeting_participants p
		      WHERE p.meeting_id = m.id AND p.left_at IS NULL
		   )
		   AND GREATEST(
		         m.created_at,
		         COALESCE((SELECT max(joined_at) FROM meeting_participants WHERE meeting_id = m.id), '-infinity'),
		         COALESCE((SELECT max(left_at) FROM meeting_participants WHERE meeting_id = m.id), '-infinity')
		       ) < $1`, time.Now().Add(-staleWindow))
	if err != nil {
		w.logger.Warn("meet worker: lost-webhook query failed", "error", err)
		return
	}
	type staleMeeting struct {
		id       int64
		roomName uuid.UUID
	}
	var stale []staleMeeting
	for rows.Next() {
		var m staleMeeting
		if err := rows.Scan(&m.id, &m.roomName); err != nil {
			rows.Close()
			w.logger.Warn("meet worker: lost-webhook scan failed", "error", err)
			return
		}
		stale = append(stale, m)
	}
	if err := rows.Err(); err != nil {
		w.logger.Warn("meet worker: lost-webhook rows error", "error", err)
		return
	}
	for _, m := range stale {
		name := m.roomName.String()
		if liveSet[name] {
			continue // the SFU still lists this room — not lost, just quiet; a real webhook may still arrive
		}
		if _, err := w.pool.Exec(ctx, `SELECT meeting_participant_event($1, 'room_finished')`, m.roomName); err != nil {
			w.logger.Warn("meet worker: room_finished ingest failed", "meeting_id", m.id, "room", name, "error", err)
		}
	}
}
