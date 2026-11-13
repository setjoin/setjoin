// worker_recordings.go — B2 Task 7: the three unconditional recording drain
// legs (reconcileRecordings, ingestRecordings, reapStaging) on the shared
// Worker (worker.go). D11 posture (see worker.go's file-header "TWO GATING
// POSTURES" block): these run BEFORE and OUTSIDE the
// `feature.meet && Configured()` gate, gated only on their own runtime deps
// (an EgressController/S3-store binding) existing — never on feature.meet or
// feature.meet_recording. A toggle gates new intent (the start route), never
// the draining of already-committed state.
package meet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/minio/minio-go/v7"

	"setjoin.com/mailserver/internal/drive"
)

// requestedGrace: §6.4 — a 'requested' recording row with no egress bound
// for longer than this means Go crashed between the reducer call and
// StartRoomComposite; the worker fails it directly rather than wait forever.
const requestedGrace = 2 * time.Minute

// maxIngestAttempts: §6.4 bounded retry — a pending_ingest row that has
// failed this many times is marked failed (never a wedge, the drive-worker
// FK lesson). ingest_attempts is durable (V129 plan delta 9): an in-memory
// counter would reset on worker restart and retry forever.
const maxIngestAttempts = 5

// stagingKeepFailed: §6.4 leg 3 — a 'failed' recording's staging object is
// kept for diagnosis this long before the reaper deletes it (the
// AbortStaleMultiparts genre); an orphan meet-egress/ object (no registry
// row at all) gets the same grace.
const stagingKeepFailed = 7 * 24 * time.Hour

// stagingStore is the meet package's own narrow S3 seam (the RoomController
// per-package-seam precedent). drive.MinioStore satisfies it structurally
// (StatObject/ListObjects/RemoveObject promoted from the embedded client;
// GetObject via its io.ReadCloser adapter) — and it is a superset of
// drive.ChunkPromoter, so w.store passes straight into Drive's shared staged
// chunk commit path.
type stagingStore interface {
	GetObject(ctx context.Context, bucket, object string, opts minio.GetObjectOptions) (io.ReadCloser, error)
	PutObject(ctx context.Context, bucket, object string, reader io.Reader, size int64, opts minio.PutObjectOptions) (minio.UploadInfo, error)
	CopyObject(ctx context.Context, dst minio.CopyDestOptions, src minio.CopySrcOptions) (minio.UploadInfo, error)
	StatObject(ctx context.Context, bucket, object string, opts minio.StatObjectOptions) (minio.ObjectInfo, error)
	RemoveObject(ctx context.Context, bucket, object string, opts minio.RemoveObjectOptions) error
	ListObjects(ctx context.Context, bucket string, opts minio.ListObjectsOptions) <-chan minio.ObjectInfo
}

// reconcileRecordingsDBOnly runs the three §6.4 legs that need only the
// pool, never the Egress API (F5): the ended-residue flip, the wedge-4
// sweep, and the stale-requested grace. Hoisted out of tick's w.egress !=
// nil gate — these rows must still converge (never wedge forever) even on a
// box where the LiveKit Egress sidecar has been deconfigured with
// recordings already in flight; only the ListEgress-keyed remainder
// (reconcileRecordingsEgress) genuinely needs EgressController.
func (w *Worker) reconcileRecordingsDBOnly(ctx context.Context) {
	// ended-meeting residue first (the room_finished mirror's sweep half).
	// E-F2 restriction: only a BOUND row may enter 'stopping' — an unbound
	// 'requested' row on an ended meeting converges via the stale-requested
	// grace leg below (bind_egress p_ok=false, which also pushes banner-off).
	if _, err := w.pool.Exec(ctx, `
		UPDATE meeting_recordings r SET state = 'stopping'
		  FROM meetings m
		 WHERE m.id = r.meeting_id AND m.state = 'ended'
		   AND (r.state = 'active' OR (r.state = 'requested' AND r.egress_id IS NOT NULL))`); err != nil {
		w.logger.Warn("meet worker: ended-residue flip failed", "error", err)
	}
	// wedge 4 (belt — plan delta 11): a 'stopping' row with no egress binding
	// is invisible to every ListEgress-keyed leg below. Task 2's origin fix
	// keeps meeting_end/room_finished from minting these; this sweep kills
	// any that exist anyway (pre-fix rows, manual UPDATEs).
	if _, err := w.pool.Exec(ctx, `
		UPDATE meeting_recordings
		   SET state = 'failed', stopped_at = COALESCE(stopped_at, now()),
		       error = COALESCE(error, 'stopping with no egress binding (wedge-4 sweep)')
		 WHERE state = 'stopping' AND egress_id IS NULL`); err != nil {
		w.logger.Warn("meet worker: wedge-4 sweep failed", "error", err)
	}
	// stale 'requested' → failed (banner-off push rides bind_egress). Drain
	// the id set FULLY before the per-id reducer calls (pgx: one conn, one
	// active query — the A4b review-F2 rule; the deleteEndedButLiveRooms shape).
	var staleIDs []int64
	rows, err := w.pool.Query(ctx, `
		SELECT id FROM meeting_recordings
		 WHERE state = 'requested' AND egress_id IS NULL AND started_at < $1`,
		time.Now().Add(-requestedGrace))
	if err != nil {
		w.logger.Warn("meet worker: stale-requested query failed", "error", err)
		return
	}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			w.logger.Warn("meet worker: stale-requested scan failed", "error", err)
			return
		}
		staleIDs = append(staleIDs, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		w.logger.Warn("meet worker: stale-requested rows error", "error", err)
		return
	}
	for _, id := range staleIDs {
		if _, err := w.pool.Exec(ctx, `SELECT meeting_recording_bind_egress($1, NULL, NULL, false,
			'egress start never bound (gateway crash before StartRoomComposite)')`, id); err != nil {
			w.logger.Warn("meet worker: stale-requested fail-mark failed", "recording_id", id, "error", err)
		}
	}
}

// reconcileRecordings is the §6.4 sweep's single entry point (tick() and
// every direct test caller): the DB-only legs run FIRST and
// UNCONDITIONALLY (F5 — they must converge their rows even when w.egress
// is nil), then the ListEgress-keyed remainder runs only when an
// EgressController exists.
func (w *Worker) reconcileRecordings(ctx context.Context) {
	w.reconcileRecordingsDBOnly(ctx)
	if w.egress != nil {
		w.reconcileRecordingsEgress(ctx)
	}
}

// reconcileRecordingsEgress is the ListEgress-keyed remainder of the §6.4
// sweep: wedge 2 (a 'stopping' row still active at the SFU → retry
// StopEgress), wedge 3 (an active/bound row absent from ListEgress → a
// synthetic egress_ended, F1 age-guarded below), and the belt (an SFU-active
// egress with no known registry row, F1 age-guarded below).
func (w *Worker) reconcileRecordingsEgress(ctx context.Context) {
	live, err := w.egress.ListEgress(ctx)
	if err != nil {
		w.logger.Warn("meet worker: ListEgress failed", "error", err)
		return // the remaining legs need the live set
	}
	activeByID := map[string]bool{}
	for _, e := range live {
		if e.Active {
			activeByID[e.EgressID] = true
		}
	}

	// registry side — drained into a slice before ANY follow-up call (F2).
	type recRow struct {
		id         int64
		state      string
		egressID   string
		stagingKey *string
		roomName   uuid.UUID
	}
	// F1: age-guarded against the ListEgress-vs-registry-read race — this
	// query runs AFTER ListEgress above, so a recording bound in that window
	// would otherwise look absent from `live` and wedge 3 would synthesize a
	// failure on a healthy, just-started egress. A row younger than
	// requestedGrace is excluded here entirely (wedge 2's retry is merely
	// deferred a tick for such a row — never destructive; wedge 3's
	// synthetic-fail is the leg this guard actually protects).
	var recs []recRow
	rows, err := w.pool.Query(ctx, `
		SELECT r.id, r.state, r.egress_id, r.staging_key, m.room_name
		  FROM meeting_recordings r JOIN meetings m ON m.id = r.meeting_id
		 WHERE r.state IN ('active', 'stopping') AND r.egress_id IS NOT NULL
		   AND r.started_at < $1`, time.Now().Add(-requestedGrace))
	if err != nil {
		w.logger.Warn("meet worker: reconcile query failed", "error", err)
		return
	}
	for rows.Next() {
		var rec recRow
		if err := rows.Scan(&rec.id, &rec.state, &rec.egressID, &rec.stagingKey, &rec.roomName); err != nil {
			rows.Close()
			w.logger.Warn("meet worker: reconcile scan failed", "error", err)
			return
		}
		recs = append(recs, rec)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		w.logger.Warn("meet worker: reconcile rows error", "error", err)
		return
	}

	knownEgress := map[string]bool{}
	for _, rec := range recs {
		knownEgress[rec.egressID] = true
		switch {
		case rec.state == "stopping" && activeByID[rec.egressID]:
			// wedge 2: the stop call was lost — retry it (law 1).
			if err := w.egress.StopEgress(ctx, rec.egressID); err != nil {
				w.logger.Warn("meet worker: retry StopEgress failed", "egress_id", rec.egressID, "error", err)
			}
		case !activeByID[rec.egressID]:
			// wedge 3: gone from the SFU with no egress_ended fact — the
			// synthetic end. staging_key is OURS (persisted at bind): HEAD it.
			if rec.stagingKey == nil {
				continue // active-with-no-staging-key cannot exist post-bind; skip defensively
			}
			stat, statErr := w.store.StatObject(ctx, w.bucket, *rec.stagingKey, minio.StatObjectOptions{})
			var infoJSON string
			if statErr == nil {
				infoJSON = fmt.Sprintf(`{"status":"EGRESS_COMPLETE","fileResults":[{"size":"%d"}]}`, stat.Size)
			} else {
				infoJSON = `{"status":"EGRESS_FAILED","error":"egress vanished from ListEgress; no staging object found"}`
			}
			if _, err := w.pool.Exec(ctx, `SELECT meeting_recording_event($1, $2, 'egress_ended', $3::jsonb)`,
				rec.roomName, rec.egressID, infoJSON); err != nil {
				w.logger.Warn("meet worker: synthetic egress_ended failed", "recording_id", rec.id, "error", err)
			}
		}
	}
	// belt: an SFU-active egress whose registry row is terminal or unknown —
	// stop it (law 1's belt; TestEveryRecordingStopPathStopsEgress case 7).
	// A 'requested' row's egress is deliberately "unknown" here: pre-bind it
	// exists only inside one in-flight HTTP request (sub-second), and a
	// WEDGED bind (DB fault after StartRoomComposite) is exactly the state
	// this belt + the 2-minute grace exist to kill (the Task-5 route comment).
	//
	// F1 mirror: an egress that IS active but not yet in `knownEgress` can
	// also be the same ListEgress-vs-registry-read race in reverse — the
	// bind commits AFTER this tick's ListEgress snapshot, so the registry
	// query above never saw it either. Age-guard by the egress's OWN
	// StartedAt (not the registry's started_at, which this belt has no row
	// for): a young unregistered egress is left alone this tick.
	for _, e := range live {
		if !e.Active || knownEgress[e.EgressID] {
			continue
		}
		if !e.StartedAt.IsZero() && time.Since(e.StartedAt) < requestedGrace {
			continue
		}
		if err := w.egress.StopEgress(ctx, e.EgressID); err != nil {
			w.logger.Warn("meet worker: belt StopEgress failed", "egress_id", e.EgressID, "error", err)
		}
	}
}

// pendingRecording is a drained pending_ingest row — the recRow shape,
// gathered fully before any per-row work starts (F2).
type pendingRecording struct {
	id         int64
	meetingID  int64
	ownerID    int64 // meetings.owner_user_id — the ingest's write identity (plan delta 10)
	stagingKey string
	attempts   int
	title      string
	startedAt  time.Time
}

// drainPendingIngest fully drains the pending_ingest candidate set before any
// per-row reducer/storage call — the F2 discipline (one conn, one active
// query at a time; the reconcileRecordings recRow shape, verbatim). Returns
// ([]T, error) — the drainOpenBreakoutRooms/drainBreakoutAssignments shape
// (arch #4 signature normalization): the caller's nil-slice-on-error
// behavior is unchanged (ranging over a nil pending slice is already a
// no-op), this only lets ingestRecordings short-circuit on the same error
// its own Warn already logged, instead of silently ranging zero times.
func (w *Worker) drainPendingIngest(ctx context.Context) ([]pendingRecording, error) {
	rows, err := w.pool.Query(ctx, `
		SELECT r.id, r.meeting_id, m.owner_user_id, r.staging_key, r.ingest_attempts,
		       m.title, r.started_at
		  FROM meeting_recordings r JOIN meetings m ON m.id = r.meeting_id
		 WHERE r.state = 'pending_ingest' AND r.staging_key IS NOT NULL`)
	if err != nil {
		w.logger.Warn("meet worker: ingest-candidate query failed", "error", err)
		return nil, err
	}
	var pending []pendingRecording
	for rows.Next() {
		var rec pendingRecording
		if err := rows.Scan(&rec.id, &rec.meetingID, &rec.ownerID, &rec.stagingKey, &rec.attempts,
			&rec.title, &rec.startedAt); err != nil {
			rows.Close()
			w.logger.Warn("meet worker: ingest-candidate scan failed", "error", err)
			return nil, err
		}
		pending = append(pending, rec)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		w.logger.Warn("meet worker: ingest-candidate rows error", "error", err)
		return nil, err
	}
	return pending, nil
}

// ingestRecordings drains pending_ingest rows and runs each through the
// §3.4 pipeline, serially. Bounded retry (§6.4): a row is only marked
// failed on the pass AFTER it has already exhausted maxIngestAttempts — the
// attempt that hits the cap still gets its normal try first.
func (w *Worker) ingestRecordings(ctx context.Context) {
	pending, err := w.drainPendingIngest(ctx)
	if err != nil {
		return // already logged inside drainPendingIngest
	}
	for _, rec := range pending {
		if rec.attempts >= maxIngestAttempts {
			// exhausted → failed + error, never a wedge (§6.4)
			if _, err := w.pool.Exec(ctx, `UPDATE meeting_recordings SET state='failed',
				error = 'ingest failed after '||ingest_attempts||' attempts: '||COALESCE(error,'')
				WHERE id = $1 AND state = 'pending_ingest'`, rec.id); err != nil {
				w.logger.Warn("meet worker: ingest exhaustion mark-failed failed", "recording_id", rec.id, "error", err)
			}
			continue
		}
		if _, err := w.pool.Exec(ctx,
			`UPDATE meeting_recordings SET ingest_attempts = ingest_attempts + 1 WHERE id = $1`, rec.id); err != nil {
			w.logger.Warn("meet worker: ingest attempt-count bump failed", "recording_id", rec.id, "error", err)
			continue
		}
		if err := w.ingestOne(ctx, rec); err != nil {
			w.logger.Warn("meet worker: ingest failed", "recording_id", rec.id, "error", err)
			if _, uerr := w.pool.Exec(ctx, `UPDATE meeting_recordings SET error = $2 WHERE id = $1`,
				rec.id, err.Error()); uerr != nil {
				w.logger.Warn("meet worker: ingest error-record failed", "recording_id", rec.id, "error", uerr)
			}
		}
	}
}

// ingestOne runs the §3.4 pipeline for one recording: exactly a user upload
// (whole-file + per-chunk SHA-256 in one streaming pass, each chunk through
// the SAME stage→locked-promote→register path as a real Drive upload), then
// node+version+finalize in one transaction. Each chunk uses its own short DB
// transaction, matching ordinary client uploads; a concurrent classification
// upgrade makes the final version reducer fail closed and the durable ingest
// retry converges on the new scope. A crash can leave claimed, unreferenced
// chunks, which the existing seven-day claim sweep/GC rail owns.
func (w *Worker) ingestOne(ctx context.Context, rec pendingRecording) error {
	var spaceID int64
	if err := w.pool.QueryRow(ctx, `SELECT meeting_space_ensure($1)`, rec.meetingID).Scan(&spaceID); err != nil {
		return err
	}
	obj, err := w.store.GetObject(ctx, w.bucket, rec.stagingKey, minio.GetObjectOptions{})
	if err != nil {
		return err
	}
	defer obj.Close()
	whole := sha256.New()
	tee := io.TeeReader(obj, whole)
	buf := make([]byte, 4*1024*1024)
	type mchunk struct {
		Sha256 string `json:"sha256"`
		Size   int64  `json:"size"`
	}
	var manifest []mchunk
	var total int64
	// Write identity = meetings.owner_user_id, NOT started_by (plan delta 10,
	// eng E-F7). A kicked cohost-starter can disappear from the meeting role
	// arm; the owner is the stable authority anchor. Keep one chunk lock and
	// one bounded CopyObject per transaction rather than holding thousands of
	// advisory locks for a long recording.
	for {
		n, rerr := io.ReadFull(tee, buf)
		if n > 0 {
			sum := sha256.Sum256(buf[:n])
			sha := hex.EncodeToString(sum[:])
			staged, perr := drive.StageChunk(ctx, w.store, w.bucket, sha,
				bytes.NewReader(buf[:n]), int64(n))
			if perr != nil {
				return perr
			}
			commitErr := func() error {
				tx, err := w.pool.Begin(ctx)
				if err != nil {
					return err
				}
				defer tx.Rollback(ctx) //nolint:errcheck
				if err := drive.CommitStagedChunk(ctx, tx, w.store, w.bucket,
					rec.ownerID, spaceID, staged); err != nil {
					return err
				}
				return tx.Commit(ctx)
			}()
			staged.Cleanup(ctx, w.store, w.bucket)
			if commitErr != nil {
				return commitErr
			}
			manifest = append(manifest, mchunk{Sha256: sha, Size: int64(n)})
			total += int64(n)
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	// F2: the recording id is load-bearing, not decorative — a stop+restart
	// inside the same minute produces two rows with an otherwise IDENTICAL
	// name ("Recording — {title} — {minute}.mp4"), which collides at
	// BZ147 in drive_node_create and reaps the second recording's bytes on
	// the failed retry. The id makes every row's name unique regardless of
	// timing.
	name := fmt.Sprintf("Recording — %s — %s (#%d).mp4", rec.title, rec.startedAt.Format("2006-01-02 15:04"), rec.id)

	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var nodeID int64
	if err := tx.QueryRow(ctx, `SELECT drive_node_create($1, $2, NULL, 'file', $3, 'video/mp4')`,
		rec.ownerID, spaceID, name).Scan(&nodeID); err != nil {
		return err
	}
	var put struct {
		VersionID int64 `json:"versionId"`
	}
	var raw []byte
	if err := tx.QueryRow(ctx, `SELECT drive_file_put_version($1, $2, $3, $4, 'video/mp4', NULL, $5::jsonb, 'meeting recording ingest', 'meet-egress')`,
		rec.ownerID, nodeID, hex.EncodeToString(whole.Sum(nil)), total, string(manifestJSON)).Scan(&raw); err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &put); err != nil {
		return err
	}
	if w.ingestFaultBeforeFinalize != nil {
		if err := w.ingestFaultBeforeFinalize(); err != nil {
			return err // rolls back via the deferred tx.Rollback — node/version never commit
		}
	}
	if _, err := tx.Exec(ctx, `SELECT meeting_recording_ingested($1, $2, $3)`,
		rec.id, nodeID, put.VersionID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	// staging delete AFTER commit (§3.4/§6.4: 'ready' owns its own cleanup;
	// a failed delete leaves an orphan the reaper's ready-leg removes).
	if err := w.store.RemoveObject(ctx, w.bucket, rec.stagingKey, minio.RemoveObjectOptions{}); err != nil {
		w.logger.Warn("meet worker: staging delete failed (reaper will retry)", "key", rec.stagingKey, "error", err)
	}
	return nil
}

// reapStaging — §6.4 leg 3, explicit semantics (the AbortStaleMultiparts
// genre): 'ready' → the staging object should already be gone (ingestOne's
// post-commit delete); a leftover means that delete failed once, so remove
// it now. 'failed' → kept stagingKeepFailed for diagnosis, then deleted. No
// registry row at all (orphan) → same grace, then deleted. Every other
// state (requested/active/stopping/pending_ingest) is the live pipeline —
// never touched here.
func (w *Worker) reapStaging(ctx context.Context) {
	for obj := range w.store.ListObjects(ctx, w.bucket, minio.ListObjectsOptions{Prefix: "meet-egress/"}) {
		if obj.Err != nil {
			w.logger.Warn("meet worker: staging list failed", "error", obj.Err)
			return
		}
		var state string
		err := w.pool.QueryRow(ctx, `SELECT state FROM meeting_recordings WHERE staging_key = $1`,
			obj.Key).Scan(&state)
		switch {
		case errors.Is(err, pgx.ErrNoRows): // orphan: no registry row at all
			if time.Since(obj.LastModified) > stagingKeepFailed {
				w.removeStaging(ctx, obj.Key)
			}
		case err != nil:
			w.logger.Warn("meet worker: staging lookup failed", "key", obj.Key, "error", err)
		case state == "ready": // ingest completed; the post-commit delete failed once
			w.removeStaging(ctx, obj.Key)
		case state == "failed": // kept 7 days for diagnosis (§6.4), then deleted
			if time.Since(obj.LastModified) > stagingKeepFailed {
				w.removeStaging(ctx, obj.Key)
			}
		}
		// requested/active/stopping/pending_ingest: live pipeline — never touched.
	}
}

func (w *Worker) removeStaging(ctx context.Context, key string) {
	if err := w.store.RemoveObject(ctx, w.bucket, key, minio.RemoveObjectOptions{}); err != nil {
		w.logger.Warn("meet worker: staging reap failed", "key", key, "error", err)
	}
}
