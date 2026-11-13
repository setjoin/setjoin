package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// blobMover is the narrow storage contract the migration orchestrator needs:
// existence check, read, write, best-effort delete, and a provider label for
// the migration record. Consumer-defined (ISP): even this in-package consumer
// no longer depends on the fat Driver. The concrete drivers satisfy it
// structurally; NewDriver(...) results are assignable with no caller edit.
// DeleteObject exists so a failed post-copy integrity check can remove the
// corrupt partial object instead of leaving it on the target.
type blobMover interface {
	ProviderName() string
	HeadObject(ctx context.Context, key string) (*ObjectInfo, error)
	GetObject(ctx context.Context, key string) (io.ReadCloser, error)
	PutObject(ctx context.Context, key string, data io.Reader, size int64) error
	DeleteObject(ctx context.Context, key string) error
}

// backfillRows is the row-cursor surface backfill consumes (satisfied by
// pgx.Rows). It exists so the per-object copy/integrity/reconciliation logic
// is unit-testable without a database.
type backfillRows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}

// scanCursor is the loader seam's return type: a backfillRows cursor that must
// also be closed (pgx.Rows requires Close to release the connection).
// copyRows keeps consuming the narrower backfillRows surface.
type scanCursor interface {
	backfillRows
	Close()
}

// MigrationStatus tracks the state of a cross-driver blob migration.
type MigrationStatus string

const (
	MigDualWrite MigrationStatus = "dual_write"
	MigBackfill  MigrationStatus = "backfill"
	MigCutover   MigrationStatus = "cutover"
	MigCompleted MigrationStatus = "completed"
	MigFailed    MigrationStatus = "failed"
	MigCancelled MigrationStatus = "cancelled"
)

// Migration orchestrates a blob migration between two storage drivers.
// Phase 1 — Dual-write: NOT implemented. The design intends new uploads to go to
//
//	both source and target during backfill, but there is NO dual-write code path
//	here or in any caller — the orchestrator records the dual_write status and
//	immediately advances to backfill. Blobs written after Start but before cutover
//	land only on the source; the backfill query (ref_count > 0) does pick up blobs
//	created during the run, but only if they appear before the cursor passes their
//	sha256 ordering position. Treat this as a maintenance-window / quiescent-writes
//	migration, NOT zero-downtime, until a real dual-write path exists.
//
// Phase 2 — Backfill: existing blobs are copied from source to target.
// Phase 3 — Cutover: reads switch to target, source kept as read-only fallback.
type Migration struct {
	pool   *pgxpool.Pool
	source blobMover
	target blobMover
	logger *slog.Logger

	// statusDB is the persistence surface for the terminal status write
	// (setStatus). nil falls back to pool; it exists so the detached write's
	// timeout and error handling are unit-testable without a database.
	statusDB statusStore

	// blobRows loads the backfill cursor (the blobs SELECT). nil falls back to
	// pool; it exists so a whole run is unit-testable without a database.
	blobRows func(ctx context.Context) (scanCursor, error)

	mu sync.Mutex
	// lastStatus mirrors the row status for from/to transition logging; owned
	// by the run goroutine (the only status writer) via setStatus.
	lastStatus MigrationStatus
	cancelFn   context.CancelFunc

	// cancelRequested records an admin cancel handshake (Migrator.Cancel). The
	// run consults it after observing context cancellation to publish the
	// correct terminal status (cancelled vs failed) through the detached
	// setStatus path.
	cancelRequested atomic.Bool
}

// NewMigration creates a migration orchestrator.
//
// Prefer the process-lifetime Migrator: per-request instances cannot reach a
// worker spawned from a different instance, which is why this constructor's
// Start/Cancel/Status remain only until the admin handler is rewired to the
// Migrator (AR-01).
func NewMigration(pool *pgxpool.Pool, source, target blobMover, logger *slog.Logger) *Migration {
	m := &Migration{pool: pool, source: source, target: target, logger: logger}
	m.blobRows = func(ctx context.Context) (scanCursor, error) {
		if pool == nil {
			return nil, errors.New("migration: no database pool configured")
		}
		return pool.Query(ctx,
			`SELECT sha256, size_bytes FROM blobs WHERE ref_count > 0 ORDER BY sha256`)
	}
	return m
}

// Start begins the migration. Returns immediately; progress tracked in storage_migrations table.
//
// Legacy per-instance path (pending handler rewire to Migrator): the run
// context derives from the CALLER's context here, so a request returning can
// cancel the worker — exactly the defect Migrator.Start fixes by deriving run
// contexts from the service lifecycle.
func (m *Migration) Start(ctx context.Context) (int64, error) {
	var id int64
	err := m.pool.QueryRow(ctx,
		`INSERT INTO storage_migrations (source_driver, target_driver, status)
		 VALUES ($1, $2, 'dual_write') RETURNING id`,
		m.source.ProviderName(), m.target.ProviderName(),
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("migration: record start: %w", err)
	}

	m.logger.Info("migration: started", "id", id, "source", m.source.ProviderName(), "target", m.target.ProviderName())

	ctx, cancel := context.WithCancel(ctx)
	m.cancelFn = cancel
	go m.run(ctx, id)
	return id, nil
}

// Cancel stops a running migration.
//
// Legacy per-instance path (pending handler rewire to Migrator): this DB-only
// flip cannot reach a worker goroutine spawned from a different Migration
// instance — Migrator.Cancel is the bounded handshake that can. What is kept
// from the integrity contract: terminal rows (completed/failed/cancelled) and
// rows resting at cutover are refused with the row unchanged, never
// unconditionally overwritten.
func (m *Migration) Cancel(id int64) error {
	m.mu.Lock()
	cancelFn := m.cancelFn
	m.mu.Unlock()
	if cancelFn != nil {
		cancelFn()
	}
	var status string
	if err := m.pool.QueryRow(context.Background(),
		`SELECT status FROM storage_migrations WHERE id = $1`, id).Scan(&status); err != nil {
		return err
	}
	switch MigrationStatus(status) {
	case MigCompleted, MigFailed, MigCancelled, MigCutover:
		return fmt.Errorf("%w: migration %d is %q", ErrNotCancellable, id, status)
	}
	_, err := m.pool.Exec(context.Background(),
		`UPDATE storage_migrations SET status = 'cancelled', completed_at = now() WHERE id = $1`, id)
	return err
}

// Status returns the current migration state from the database.
func (m *Migration) Status(ctx context.Context, id int64) (map[string]any, error) {
	var status string
	var total, migrated int64
	var lastKey *string
	var started time.Time
	var completed *time.Time
	err := m.pool.QueryRow(ctx,
		`SELECT status, COALESCE(total_blobs, 0), COALESCE(migrated, 0), last_key, started_at, completed_at
		 FROM storage_migrations WHERE id = $1`, id,
	).Scan(&status, &total, &migrated, &lastKey, &started, &completed)
	if err != nil {
		return nil, err
	}
	result := map[string]any{
		"id": id, "status": status, "total": total, "migrated": migrated,
		"started": started,
	}
	if lastKey != nil {
		result["last_key"] = *lastKey
	}
	if completed != nil {
		result["completed"] = *completed
	}
	if total > 0 {
		result["progress_pct"] = float64(migrated) * 100 / float64(total)
	}
	return result, nil
}

// run executes the backfill phase in a background goroutine.
func (m *Migration) run(ctx context.Context, id int64) {
	// Phase 1: dual-write is a no-op — no dual-write path exists in any caller
	// (see the Migration type doc). We record the status and advance straight to
	// backfill; concurrent writes during the run are NOT mirrored to the target.
	m.setStatus(ctx, id, MigBackfill)

	// Phase 2: backfill
	count, failed, err := m.backfill(ctx, id)

	// Reconcile the stop signal BEFORE publishing any backfill outcome (Astra
	// AR01 finding 3): the copy loop checks cancellation only at row
	// boundaries, so a stop delivered during the FINAL copy returns a nil
	// error here once the blocked driver call succeeds and the cursor
	// exhausts. Publishing `cutover` on that path would make Cancel return
	// success on a drained handshake while the DB claimed a finished backfill.
	// The outcome is therefore atomic with the stop signal the run observed:
	// `cancelled` when an admin cancel was requested, `failed` on a
	// service-shutdown stop — never a forward state.
	//
	// The re-check also covers a handshake that stored cancelRequested after
	// the backfill returned but before this decision point (Astra impl-r2 r3
	// finding 2): cancelRequested is stored before the run context is
	// cancelled, so observing it here means the handshake arrived before the
	// run committed to cutover and the cancelled outcome must win. A request
	// landing after this check races the detached cutover write and is
	// resolved by Migrator.Cancel's post-join outcome refusal.
	if ctx.Err() != nil || m.cancelRequested.Load() {
		// The run stopped on cancellation, not on a data error. Cancel is
		// a handshake: the RUN performs its own terminal write through the
		// detached setStatus path — `cancelled` when an admin cancel was
		// requested, `failed` on a service-shutdown stop — so the DB
		// terminal status implies the worker has stopped copying.
		if m.cancelRequested.Load() {
			m.logger.Warn("migration: backfill stopped by cancel request",
				"id", id, "migrated_before_stop", count)
			m.setStatus(ctx, id, MigCancelled)
			return
		}
		m.logger.Warn("migration: backfill stopped by service shutdown",
			"id", id, "migrated_before_stop", count)
		m.setStatus(ctx, id, MigFailed)
		return
	}
	if err != nil {
		m.logger.Error("migration: backfill failed", "id", id, "error", err, "migrated_before_failure", count)
		m.setStatus(ctx, id, MigFailed)
		return
	}
	if len(failed) > 0 {
		// Reconciliation contract (D-MAILSERVER-INTERNAL-STORAGE-F-001): a
		// backfill with objects that could not be transferred or failed
		// integrity verification is NOT cutover-ready. The failed keys are
		// enumerated for per-object reconciliation — never a convergence claim.
		m.logger.Error("migration: backfill finished with unreconciled objects — cutover withheld",
			"id", id, "migrated", count, "failed_count", len(failed),
			"failed_keys_first", boundedKeys(failed, 20))
		m.setStatus(ctx, id, MigFailed)
		return
	}

	m.logger.Info("migration: backfill complete", "id", id, "total", count)
	m.setStatus(ctx, id, MigCutover)
	// Phase 3: cutover has no consumer — there is no POST /admin/storage/cutover
	// route in the mailserverd route table, so the row legitimately rests at
	// cutover. The STORE plan (E5–E8) owns the transactionally authorized
	// cutover operation; do not assume an endpoint here.
}

// boundedKeys returns at most n keys for structured-log enumeration.
func boundedKeys(keys []string, n int) []string {
	if len(keys) <= n {
		return keys
	}
	return keys[:n]
}

// backfill copies all blobs with ref_count > 0 from source to target.
func (m *Migration) backfill(ctx context.Context, id int64) (int64, []string, error) {
	rows, err := m.blobRows(ctx)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()

	migrated, failed, err := m.copyRows(ctx, rows, id)
	if err != nil {
		return migrated, failed, err
	}

	if m.pool != nil {
		m.pool.Exec(ctx, //nolint:errcheck
			`UPDATE storage_migrations SET migrated = $1, total_blobs = $2 WHERE id = $3`,
			migrated, migrated, id)
	}
	return migrated, failed, nil
}

// copyRows is the DB-free core of the backfill loop. Per object it applies the
// reconciliation contract from D-MAILSERVER-INTERNAL-STORAGE-F-001:
//
//   - an existing target object is skipped ONLY when both size AND content
//     (sha256 read-back against the content-addressed key) verify — the old
//     HeadObject existence-only skip left truncated partial objects in place;
//   - every copy is hashed while streaming (source corruption detected) and
//     read back from the target afterwards (truncated/mangled writes detected);
//     a failed verification deletes the target object best-effort;
//   - transfer/verification failures do NOT abort the run — they are counted
//     and ENUMERATED in the returned failed list for per-object reconciliation;
//   - cancellation is checked per row (accepted work stops promptly).
//
// id is the storage_migrations row for periodic progress updates (only touched
// when m.pool is non-nil; unit tests pass a pool-free Migration).
func (m *Migration) copyRows(ctx context.Context, rows backfillRows, id int64) (migrated int64, failed []string, err error) {
	for rows.Next() {
		select {
		case <-ctx.Done():
			return migrated, failed, ctx.Err()
		default:
		}

		var sha string
		var size int64
		if err := rows.Scan(&sha, &size); err != nil {
			continue
		}

		// Skip only on verified integrity (size + sha256 read-back), not on
		// existence. Any mismatch (partial object from an interrupted earlier
		// run) falls through to a re-copy, which overwrites the target.
		if err := verifyBlob(ctx, m.target, sha, size); err == nil {
			migrated++
			continue
		}

		rc, err := m.source.GetObject(ctx, sha)
		if err != nil {
			m.logger.Warn("migration: source read failed", "sha", sha, "error", err)
			failed = append(failed, sha)
			continue
		}

		// Hash the source bytes while streaming to the target so a corrupted
		// or short source read is caught against the content-addressed key.
		hash := sha256.New()
		var copied int64
		counting := &countingHashWriter{hash: hash, n: &copied}
		putErr := m.target.PutObject(ctx, sha, io.TeeReader(rc, counting), size)
		rc.Close()
		if putErr != nil {
			m.logger.Warn("migration: target write failed", "sha", sha, "error", putErr)
			failed = append(failed, sha)
			continue
		}
		if copied != size || !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), sha) {
			m.logger.Error("migration: copied object failed source integrity check — deleting target copy",
				"sha", sha, "expected_size", size, "copied_size", copied)
			m.discardPartial(ctx, sha)
			failed = append(failed, sha)
			continue
		}

		// Post-copy read-back: verify what actually LANDED on the target.
		if err := verifyBlob(ctx, m.target, sha, size); err != nil {
			m.logger.Error("migration: post-copy integrity verification failed — deleting target copy",
				"sha", sha, "error", err)
			m.discardPartial(ctx, sha)
			failed = append(failed, sha)
			continue
		}

		migrated++
		if migrated%1000 == 0 && m.pool != nil {
			m.pool.Exec(ctx, //nolint:errcheck
				`UPDATE storage_migrations SET migrated = $1, last_key = $2 WHERE id = $3`,
				migrated, sha, id)
		}
	}

	if err := rows.Err(); err != nil {
		return migrated, failed, fmt.Errorf("migration: cursor error: %w", err)
	}
	return migrated, failed, nil
}

// discardPartial removes a target object that failed integrity verification so
// reconciliation cannot mistake it for a completed transfer.
func (m *Migration) discardPartial(ctx context.Context, sha string) {
	if err := m.target.DeleteObject(ctx, sha); err != nil {
		m.logger.Error("migration: failed to delete unverified target object", "sha", sha, "error", err)
	}
}

// verifyBlob reads the object back and compares BOTH size and content hash
// against the content-addressed key. Existence alone is never accepted.
func verifyBlob(ctx context.Context, d blobMover, key string, wantSize int64) error {
	rc, err := d.GetObject(ctx, key)
	if err != nil {
		return err
	}
	defer rc.Close()

	hash := sha256.New()
	n, err := io.Copy(hash, rc)
	if err != nil {
		return err
	}
	if n != wantSize {
		return fmt.Errorf("size mismatch: target has %d bytes, want %d", n, wantSize)
	}
	got := hex.EncodeToString(hash.Sum(nil))
	if !strings.EqualFold(got, key) {
		return fmt.Errorf("content hash %s does not match content-addressed key", got)
	}
	return nil
}

// countingHashWriter hashes the streamed bytes and counts them.
type countingHashWriter struct {
	hash io.Writer
	n    *int64
}

func (w *countingHashWriter) Write(p []byte) (int, error) {
	n, err := w.hash.Write(p)
	*w.n += int64(n)
	return n, err
}

// statusWriteTimeout bounds the detached terminal status write. WithoutCancel
// strips deadlines along with cancellation, so without its own timeout an
// unbounded write against a stalled database would hang the migration worker
// forever. A var (not const) so tests can pin bounded termination with a short
// deadline.
var statusWriteTimeout = 10 * time.Second

// statusStore is the narrow persistence surface the terminal status write
// needs, satisfied structurally by *pgxpool.Pool. Consumer-defined (ISP), so
// the detached write's timeout and error handling are unit-testable without a
// database.
type statusStore interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// outcome returns the status the run last published through setStatus — its
// selected forward/terminal outcome at exit. lastStatus is owned by the run
// goroutine; Migrator.Cancel reads it only after the run's exit was observed
// (done closed), so the value is final (Astra impl-r2 r3 finding 2).
func (m *Migration) outcome() MigrationStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastStatus
}

func (m *Migration) setStatus(ctx context.Context, id int64, status MigrationStatus) {
	// Detach from the request-derived context: without this, the cancellation
	// that stops the backfill also silently swallowed the terminal
	// failed/cancelled status write, stranding the migration row in a
	// transitional status (the "stranded rows" reconciliation finding).
	// WithoutCancel drops deadlines too, so the detached write is bounded by
	// its own timeout — a stalled database must not strand the WORKER either.
	detached, cancel := context.WithTimeout(context.WithoutCancel(ctx), statusWriteTimeout)
	defer cancel()

	store := m.statusDB
	if store == nil {
		store = m.pool
	}

	// Transition observability (acceptance): every transition logs id and the
	// from/to statuses. lastStatus is owned by the run goroutine — the only
	// status writer.
	m.mu.Lock()
	from := m.lastStatus
	m.lastStatus = status
	m.mu.Unlock()
	m.logger.Info("migration: status", "id", id, "from", string(from), "to", string(status))

	if _, err := store.Exec(detached, migrationStatusSQL(status),
		string(status), id); err != nil {
		// A failed terminal write still strands the ROW in a transitional
		// status with no reconciliation evidence; surface the migration ID and
		// the intended status so the row can be reconciled manually instead of
		// the error being silently ignored.
		m.logger.Error("migration: status write failed — row may be stranded in a transitional status; reconcile manually",
			"id", id, "intended_status", string(status), "error", err)
	}
}

// migrationStatusSQL returns the row update for a status write. Terminal
// writes (failed/cancelled; `completed` has no production writer today) also
// stamp completed_at — repairing the historical asymmetry where only the old
// DB-only cancel flip set completed_at while the run's terminal writes never
// did. Cutover is NOT terminal (phase 3 remains owned by E5–E8), so its write
// leaves completed_at empty.
func migrationStatusSQL(status MigrationStatus) string {
	switch status {
	case MigFailed, MigCancelled, MigCompleted:
		return `UPDATE storage_migrations SET status = $1, completed_at = now() WHERE id = $2`
	}
	return `UPDATE storage_migrations SET status = $1 WHERE id = $2`
}
