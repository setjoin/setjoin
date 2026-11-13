// Package-level maintenance worker for setjoin Drive (spec §3.5, G8): the
// journal/claims sweep, zero-ref chunk GC, bounded canonical-object inventory,
// and tmp/upload/ reaper. Started once at startup on workerPool (BYPASSRLS —
// every step here is cross-tenant by design, the same posture as eapjobs/
// pushjobs/approvaljobs), exits on ctx cancel.
package drive

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"

	"setjoin.com/mailserver/internal/storage"
	"setjoin.com/shared/pgxutil"
)

const workerInterval = 5 * time.Minute

// gcAction is gcDecide's verdict for one drive_chunk_gc_queue row.
type gcAction int

const (
	gcDelete  gcAction = iota // zero-ref, unlocked → delete the storage object + row
	gcDequeue                 // re-referenced since queueing → drop the queue row only
	gcSkip                    // WORM-retained (retain_until in the future) → leave for a later tick
)

// gcDecide is pure — no I/O — so the three branches are unit-testable
// without a database or object store.
func gcDecide(refCount int64, retainUntil *time.Time, now time.Time) gcAction {
	if refCount > 0 {
		return gcDequeue
	}
	if retainUntil != nil && retainUntil.After(now) {
		return gcSkip
	}
	return gcDelete
}

// tmpReapWindow (G8) is the grace period an orphaned tmp/upload/ object must
// survive before the reaper deletes it — long enough that a genuinely
// in-flight chunk/blob upload is never caught mid-write.
const tmpReapWindow = 24 * time.Hour

// canonicalOrphanReapWindow gives every successful promote ample time to
// register before an inventory pass considers its bytes abandoned. The
// advisory-lock protocol is the correctness boundary; this window avoids
// churning on recent failures and matches the existing tmp-object policy.
const canonicalOrphanReapWindow = 24 * time.Hour

const canonicalInventoryBatchSize = 200

func tmpIsStale(lastModified, now time.Time) bool {
	return !lastModified.IsZero() && now.Sub(lastModified) > tmpReapWindow
}

func canonicalOrphanIsStale(lastModified, now time.Time) bool {
	return !lastModified.IsZero() && now.Sub(lastModified) > canonicalOrphanReapWindow
}

// parseCanonicalChunkKey accepts only keys the Drive chunk writer itself can
// produce. Unknown/malformed keys are never deletion candidates.
func parseCanonicalChunkKey(key string) (scope, sha string, ok bool) {
	parts := strings.Split(key, "/")
	if len(parts) != 3 || parts[0] != "drive" || !chunkShaRe.MatchString(parts[2]) {
		return "", "", false
	}
	scope = parts[1]
	if scope == "g" {
		return scope, parts[2], true
	}
	if len(scope) < 2 || scope[0] != 's' || scope[1] == '0' {
		return "", "", false
	}
	spaceID, err := strconv.ParseInt(scope[1:], 10, 64)
	if err != nil || spaceID <= 0 {
		return "", "", false
	}
	return scope, parts[2], true
}

// Worker runs the P1 maintenance sweep.
type Worker struct {
	pool      pgxutil.WorkerPool
	store     objectStore
	bucket    string
	retention storage.Retention // P5 G1: WORM retry; nil-safe — wired post-construction via SetRetention
	logger    *slog.Logger

	// afterGCCommitHook is a test-only seam (nil in production): called in
	// gcDeleteOne right after the DB transaction commits and before the
	// re-reference recheck + RemoveObject, so a test can deterministically
	// land a "concurrent re-upload" inside the B2 race window instead of
	// racing real goroutines against wall-clock timing.
	afterGCCommitHook func()

	// afterGCRemoveCheckHook is the narrower final-race seam: it runs while
	// the removal transaction holds the per-key advisory lock, after row
	// absence is confirmed and immediately before storage deletion.
	afterGCRemoveCheckHook func()

	// canonicalScanAfter is a process-local pagination cursor. Without it, a
	// fixed-size scan would revisit the lexicographically first live objects
	// forever and starve later orphan keys.
	canonicalScanAfter string

	// afterCanonicalCheckHook is a test-only seam (nil in production): called
	// while the per-key advisory lock is held, after the authoritative row
	// absence check and before RemoveObject.
	afterCanonicalCheckHook func()
}

// NewWorker builds the maintenance worker. store/bucket are the SAME
// object-storage seam the chunk/content handlers use (production: drive.MinioStore{minioClient}).
func NewWorker(pool pgxutil.WorkerPool, store objectStore, bucket string, logger *slog.Logger) *Worker {
	return &Worker{pool: pool, store: store, bucket: bucket, logger: logger}
}

// SetRetention wires the storage backend's WORM/Object-Lock capability (the
// Handler.SetRetention idiom, worm.go) — a post-construction setter so a nil
// value (no Retention capability configured) is the honest default until
// main.go wires a real one.
func (w *Worker) SetRetention(r storage.Retention) { w.retention = r }

// Run starts the ticker loop; exits cleanly when ctx is cancelled.
func (w *Worker) Run(ctx context.Context) {
	w.logger.Info("drive maintenance worker started", "interval", workerInterval)
	ticker := time.NewTicker(workerInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			w.logger.Info("drive maintenance worker stopped")
			return
		case <-ticker.C:
			w.tick(ctx)
		}
	}
}

// tick runs each maintenance step, error-isolated (a failure in one step
// logs and does not block the others — same posture as every other cron/
// worker loop in this gateway).
func (w *Worker) tick(ctx context.Context) {
	if err := w.sweep(ctx); err != nil {
		w.logger.Warn("drive worker: sweep failed", "error", err)
	}
	if err := w.gcChunks(ctx); err != nil {
		w.logger.Warn("drive worker: chunk GC failed", "error", err)
	}
	if err := w.reapCanonicalOrphans(ctx); err != nil {
		w.logger.Warn("drive worker: canonical orphan reaper failed", "error", err)
	}
	if err := w.reapTmp(ctx); err != nil {
		w.logger.Warn("drive worker: tmp reaper failed", "error", err)
	}
	w.retryPendingWormLocks(ctx) // P5 G1 — error-isolated internally, never blocks the other steps
	// Version prune (drive_version_prune) is deliberately NOT called in P1 —
	// no user-facing retention-count policy knob exists yet to drive p_keep
	// (spec §13, deferred to a later phase).
}

func (w *Worker) sweep(ctx context.Context) error {
	var out []byte
	if err := w.pool.QueryRow(ctx, `SELECT drive_maintenance_sweep()`).Scan(&out); err != nil {
		return err
	}
	w.logger.Info("drive maintenance sweep", "result", string(out))
	return nil
}

// gcBatchSize caps how many gc_queue rows one tick processes.
// ponytail: 200-row GC batch per tick; raise if the queue ever backs up.
const gcBatchSize = 200

type gcRow struct {
	scope, sha, storageRef string
	refCount               int64
	retainUntil            *time.Time
}

func (w *Worker) gcChunks(ctx context.Context) error {
	rows, err := w.pool.Query(ctx, `
		SELECT q.scope_key, q.sha256, c.ref_count, c.retain_until, c.storage_ref
		  FROM drive_chunk_gc_queue q JOIN drive_chunks c USING (scope_key, sha256)
		 LIMIT $1`, gcBatchSize)
	if err != nil {
		return err
	}
	var batch []gcRow
	for rows.Next() {
		var r gcRow
		if err := rows.Scan(&r.scope, &r.sha, &r.refCount, &r.retainUntil, &r.storageRef); err != nil {
			rows.Close()
			return err
		}
		batch = append(batch, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	now := time.Now()
	for _, r := range batch {
		switch gcDecide(r.refCount, r.retainUntil, now) {
		case gcDelete:
			w.gcDeleteOne(ctx, r)
		case gcDequeue:
			if _, err := w.pool.Exec(ctx, `DELETE FROM drive_chunk_gc_queue WHERE scope_key=$1 AND sha256=$2`, r.scope, r.sha); err != nil {
				w.logger.Warn("drive worker: gc dequeue failed", "scope", r.scope, "sha256", r.sha, "error", err)
			}
		case gcSkip:
			// leave queued; retry next tick (P5 also maps storage ErrObjectLocked here)
		}
	}
	return nil
}

// gcDeleteOne deletes the DB row (re-checking ref_count=0 atomically — closes
// the requeue race a batch-read-then-act loop opens) BEFORE the storage
// object, never the reverse: if the row survives (a concurrent manifest
// re-referenced it since the batch read), the storage object must NOT be
// touched — deleting bytes a live version still points to is a correctness
// bug, whereas the opposite failure mode (DB row gone, storage object
// orphaned on a crash between the two steps) is merely wasted space.
//
// The DB commit and storage delete cannot be atomic. The second transaction
// below therefore acquires the same advisory key as every producer, rechecks
// row absence, and keeps that lock through RemoveObject. A re-upload either
// completes first (the row survives and storage stays) or waits and promotes
// fresh bytes after the old object is removed. Registration also deletes a
// stale gc_queue row, and this first transaction requires that queue verdict
// to still exist before it can delete the chunk row.
func (w *Worker) gcDeleteOne(ctx context.Context, r gcRow) {
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		w.logger.Warn("drive worker: gc begin failed", "scope", r.scope, "sha256", r.sha, "error", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful Commit

	if err := lockChunkTx(ctx, tx, r.scope, r.sha); err != nil {
		w.logger.Warn("drive worker: gc chunk lock failed", "scope", r.scope, "sha256", r.sha, "error", err)
		return
	}
	tag, err := tx.Exec(ctx, `
		DELETE FROM drive_chunks c
		 WHERE c.scope_key=$1 AND c.sha256=$2 AND c.ref_count=0
		   AND EXISTS (SELECT 1 FROM drive_chunk_gc_queue q
		                WHERE q.scope_key=c.scope_key AND q.sha256=c.sha256)`, r.scope, r.sha)
	if err != nil {
		w.logger.Warn("drive worker: gc chunk delete failed", "scope", r.scope, "sha256", r.sha, "error", err)
		return
	}
	raced := tag.RowsAffected() == 0
	if _, err := tx.Exec(ctx, `DELETE FROM drive_chunk_gc_queue WHERE scope_key=$1 AND sha256=$2`, r.scope, r.sha); err != nil {
		w.logger.Warn("drive worker: gc dequeue failed", "scope", r.scope, "sha256", r.sha, "error", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		w.logger.Warn("drive worker: gc commit failed", "scope", r.scope, "sha256", r.sha, "error", err)
		return
	}
	if raced {
		return // re-referenced since the batch read — storage object stays live
	}
	if w.afterGCCommitHook != nil {
		w.afterGCCommitHook() // test-only seam: inject a concurrent re-upload into the gap below
	}

	// The row deletion must commit before touching storage: a storage delete
	// followed by a failed DB commit would restore a row pointing at missing
	// bytes. A second transaction closes the non-transactional gap. Holding the
	// same advisory lock from the final row check through RemoveObject means a
	// producer can only promote either before this check or after this delete.
	removeTx, err := w.pool.Begin(ctx)
	if err != nil {
		w.logger.Warn("drive worker: gc remove begin failed", "scope", r.scope, "sha256", r.sha, "error", err)
		return
	}
	defer func() { _ = removeTx.Rollback(ctx) }()
	if err := lockChunkTx(ctx, removeTx, r.scope, r.sha); err != nil {
		w.logger.Warn("drive worker: gc remove lock failed", "scope", r.scope, "sha256", r.sha, "error", err)
		return
	}
	var reRegistered bool
	if err := removeTx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM drive_chunks WHERE scope_key=$1 AND sha256=$2)`, r.scope, r.sha).
		Scan(&reRegistered); err != nil {
		w.logger.Warn("drive worker: gc re-reference recheck failed — leaving storage object alone", "scope", r.scope, "sha256", r.sha, "error", err)
		return
	}
	if reRegistered {
		w.logger.Info("drive worker: gc skip — chunk re-registered since commit (race averted)", "scope", r.scope, "sha256", r.sha)
		return
	}
	if w.afterGCRemoveCheckHook != nil {
		w.afterGCRemoveCheckHook()
	}
	if err := w.store.RemoveObject(ctx, w.bucket, r.storageRef, minio.RemoveObjectOptions{}); err != nil {
		if errors.Is(err, storage.ErrObjectLocked) {
			// P5 (spec §3.5): a WORM-locked object whose DB row we just deleted
			// (ref_count reached 0, retain_until had already passed by DB's
			// clock but storage's own clock/lock hasn't released it yet) — a
			// benign gcSkip, not an orphan-object bug: storage releases the
			// lock on its own schedule, no requeue needed (nothing still
			// references this key, so a future GC cycle never revisits it —
			// the object is simply orphaned-but-safe until storage's own
			// retention expiry permits deletion out-of-band).
			// ponytail: objectStore (minio-go against SeaweedFS's S3 API) does
			// not currently translate a locked-object delete into this
			// sentinel — reachable once the chunk store is Retention-aware;
			// the check is forward-compatible and costs nothing today.
			w.logger.Info("drive worker: gc skip — object still WORM-locked in storage", "key", r.storageRef)
			return
		}
		w.logger.Warn("drive worker: gc storage remove failed (DB row already gone — orphaned object)", "key", r.storageRef, "error", err)
		return
	}
	if err := removeTx.Commit(ctx); err != nil {
		// Read-only commit failure cannot resurrect a drive_chunks row; the
		// storage deletion was authorized while the advisory lock was held.
		w.logger.Warn("drive worker: gc remove transaction close failed", "key", r.storageRef, "error", err)
	}
}

// reapCanonicalOrphans inventories the canonical Drive prefix for objects
// left behind when promotion succeeds but registration rolls back/fails. It
// never infers ownership from storage alone: exact key grammar, age, an
// authoritative DB absence check, and the shared advisory lock are all
// required before deletion.
func (w *Worker) reapCanonicalOrphans(ctx context.Context) error {
	listCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	listed := 0
	completedPage := true
	lastKey := w.canonicalScanAfter
	now := time.Now()
	objects := w.store.ListObjects(listCtx, w.bucket, minio.ListObjectsOptions{
		Prefix:     "drive/",
		Recursive:  true,
		StartAfter: w.canonicalScanAfter,
		MaxKeys:    canonicalInventoryBatchSize,
	})
	for obj := range objects {
		if listed >= canonicalInventoryBatchSize {
			completedPage = false
			cancel()
			break
		}
		listed++
		if obj.Err != nil {
			w.logger.Warn("drive worker: canonical inventory list error", "error", obj.Err)
			continue
		}
		lastKey = obj.Key
		scope, sha, ok := parseCanonicalChunkKey(obj.Key)
		if !ok || !canonicalOrphanIsStale(obj.LastModified, now) {
			continue
		}
		w.reapCanonicalOrphan(ctx, scope, sha, obj.Key)
	}
	if completedPage {
		// The channel closed naturally, including the empty-prefix and exact-
		// batch-size cases: the scan reached the end, so wrap next tick.
		w.canonicalScanAfter = ""
	} else if lastKey != "" {
		w.canonicalScanAfter = lastKey
	}
	return nil
}

func (w *Worker) reapCanonicalOrphan(ctx context.Context, scope, sha, key string) {
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		w.logger.Warn("drive worker: canonical orphan begin failed", "key", key, "error", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockChunkTx(ctx, tx, scope, sha); err != nil {
		w.logger.Warn("drive worker: canonical orphan lock failed", "key", key, "error", err)
		return
	}
	var registered bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM drive_chunks WHERE scope_key=$1 AND sha256=$2)`, scope, sha).Scan(&registered); err != nil {
		w.logger.Warn("drive worker: canonical orphan DB check failed — leaving storage object alone", "key", key, "error", err)
		return
	}
	if registered {
		return
	}
	if w.afterCanonicalCheckHook != nil {
		w.afterCanonicalCheckHook()
	}
	if err := w.store.RemoveObject(ctx, w.bucket, key, minio.RemoveObjectOptions{}); err != nil {
		if errors.Is(err, storage.ErrObjectLocked) {
			w.logger.Info("drive worker: canonical orphan still WORM-locked — will retry", "key", key)
			return
		}
		w.logger.Warn("drive worker: canonical orphan remove failed — will retry", "key", key, "error", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		w.logger.Warn("drive worker: canonical orphan transaction close failed", "key", key, "error", err)
	}
}

// retryPendingWormLocks re-applies Object-Lock for chunks whose apply failed
// (G1). Reads drive_chunks.worm_pending, a STORED generated column derived
// from retain_until vs worm_applied_until (V116/V118 C3) — nothing to
// enqueue, nothing to lose on crash: a chunk stays pending until this tick
// (or a later one) succeeds. Nil-safe: no Retention capability configured
// means every gxp chunk stays worm-pending forever — correct fail-closed,
// surfaced via the admin drive_worm_pending count (spec §12-22 fallback),
// never silently treated as applied.
func (w *Worker) retryPendingWormLocks(ctx context.Context) {
	if w.retention == nil {
		return
	}
	rows, err := w.pool.Query(ctx, `
		SELECT c.scope_key, c.sha256, c.retain_until, s.worm_mode
		  FROM drive_chunks c
		  JOIN drive_spaces s ON s.id = substring(c.scope_key from 2)::bigint
		 WHERE c.scope_key LIKE 's%' AND c.worm_pending
		 LIMIT $1`, wormRetryBatchSize)
	if err != nil {
		w.logger.Warn("drive worker: worm-pending query failed", "error", err)
		return
	}
	type pendingChunk struct {
		scope, sha string
		until      time.Time
		mode       *string
	}
	var batch []pendingChunk
	for rows.Next() {
		var c pendingChunk
		if err := rows.Scan(&c.scope, &c.sha, &c.until, &c.mode); err != nil {
			rows.Close()
			w.logger.Warn("drive worker: worm-pending scan failed", "error", err)
			return
		}
		batch = append(batch, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		w.logger.Warn("drive worker: worm-pending iterate failed", "error", err)
		return
	}

	for _, c := range batch {
		mode := "governance"
		if c.mode != nil && *c.mode != "" {
			mode = *c.mode
		}
		key := "drive/" + c.scope + "/" + c.sha
		if err := w.retention.PutObjectRetention(ctx, key, mode, c.until); err != nil {
			w.logger.Warn("drive worker: worm retry apply failed — will retry next tick", "key", key, "error", err)
			continue
		}
		if _, err := w.pool.Exec(ctx, `
			UPDATE drive_chunks
			   SET worm_applied_until = GREATEST(coalesce(worm_applied_until, '-infinity'), $3)
			 WHERE scope_key = $1 AND sha256 = $2`, c.scope, c.sha, c.until); err != nil {
			w.logger.Warn("drive worker: worm mark-applied failed", "key", key, "error", err)
		}
	}
}

// wormRetryBatchSize caps how many worm-pending chunks one tick retries.
// ponytail: 200-row batch per tick, matches gcBatchSize; raise if the
// pending set ever backs up.
const wormRetryBatchSize = 200

func (w *Worker) reapTmp(ctx context.Context) error {
	now := time.Now()
	for obj := range w.store.ListObjects(ctx, w.bucket, minio.ListObjectsOptions{Prefix: "tmp/upload/", Recursive: true}) {
		if obj.Err != nil {
			w.logger.Warn("drive worker: tmp list error", "error", obj.Err)
			continue
		}
		if !tmpIsStale(obj.LastModified, now) {
			continue
		}
		if err := w.store.RemoveObject(ctx, w.bucket, obj.Key, minio.RemoveObjectOptions{}); err != nil {
			w.logger.Warn("drive worker: tmp reap failed", "key", obj.Key, "error", err)
		}
	}
	return nil
}
