package mdm

// Device-registry legacy secret backfill (D6 / DBSCHEMA-005; Astra D6
// impl-r2 finding 2). V260 adds device_registry.device_secret_enc /
// device_secret_key_id, but the archived MAM check-in column
// device_registry.device_secret has NO live reader — shared/device verifies
// through devices.hmac_secret (V247) and shared/threat inserts registry rows
// without a device_secret — so the webhook loader's lazy-migration pattern
// can never fire for it. Without an active path any pre-archival plaintext
// value would sit in the column indefinitely.
//
// This backfill IS the migration path: at startup the process seals every
// legacy plaintext value into the same family AES-256-GCM EK01 envelope
// (shared/device SecretCodec over the RAW master secret) and NULLs the
// plaintext, one row at a time with the R3 predicate pinning the exact value
// that was just read (a concurrent change makes the UPDATE a no-op instead
// of sealing a value this call never saw). Each batch is fully collected and
// its rows closed BEFORE any UPDATE runs — an open result set holds its pool
// connection, and updating through the same pool then needs a second
// connection, which starves on the supported DB_MAX_CONNS=1 floor. The run is
// idempotent — only rows
// with plaintext and no envelope are selected — so a failed or interrupted
// run is simply retried by the next boot.
//
// Credential: device_registry is a FORCE-RLS Posture A table (V254), and this
// is cross-tenant maintenance, so production passes the WORKER pool
// (BYPASSRLS), never the request pool. Failure is non-fatal at the startup
// call site (logged; retried next boot) — the envelope columns are additive
// and no behavior depends on completion.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/device"
)

const (
	// registryBackfillBatch bounds each SELECT so a large legacy table cannot
	// hold one result set (or one seal loop) indefinitely.
	registryBackfillBatch = 500
	// registryBackfillTimeout bounds the whole drain; the next boot retries.
	registryBackfillTimeout = 30 * time.Second
)

// BackfillRegistryDeviceSecrets seals every legacy plaintext
// device_registry.device_secret into device_secret_enc and NULLs the
// plaintext. It returns the number of rows it migrated. codec is REQUIRED
// (nil fails closed — silently leaving plaintext in place would defeat the
// control it exists to complete).
func BackfillRegistryDeviceSecrets(ctx context.Context, pool *pgxpool.Pool, codec *device.SecretCodec, logger *slog.Logger) (int, error) {
	if codec == nil {
		return 0, errors.New("mdm: device secret codec not configured")
	}
	if pool == nil {
		return 0, errors.New("mdm: device secret backfill requires a pool")
	}
	bctx, cancel := context.WithTimeout(ctx, registryBackfillTimeout)
	defer cancel()

	total := 0
	for {
		rows, err := pool.Query(bctx,
			`SELECT id, device_secret FROM device_registry
			  WHERE device_secret IS NOT NULL AND device_secret_enc IS NULL
			  LIMIT $1`, registryBackfillBatch)
		if err != nil {
			return total, fmt.Errorf("mdm: device secret backfill select: %w", err)
		}
		// Collect the whole bounded batch BEFORE any update: open rows hold
		// their pool connection, and a pool.Exec issued while they are live
		// needs a SECOND connection — on the supported DB_MAX_CONNS=1 floor
		// that UPDATE would wait for its own SELECT's connection until the
		// drain timeout expired and no row would ever migrate (Astra D6
		// impl-r2 HOLD). Two-phase discipline: collect, close/check the rows,
		// then update.
		type pendingSeal struct {
			id        int64
			plaintext string
		}
		batch := make([]pendingSeal, 0, registryBackfillBatch)
		for rows.Next() {
			var row pendingSeal
			if err := rows.Scan(&row.id, &row.plaintext); err != nil {
				rows.Close()
				return total, fmt.Errorf("mdm: device secret backfill scan: %w", err)
			}
			batch = append(batch, row)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return total, fmt.Errorf("mdm: device secret backfill rows: %w", err)
		}
		// rows is closed and checked: the SELECT connection is back in the
		// pool, so the updates below cannot starve against it.
		for _, row := range batch {
			sealed, err := codec.Seal(row.plaintext)
			if err != nil {
				return total, fmt.Errorf("mdm: device secret backfill seal (device %d): %w", row.id, err)
			}
			tag, err := pool.Exec(bctx,
				`UPDATE device_registry
				    SET device_secret_enc = $2,
				        device_secret_key_id = $3,
				        device_secret = NULL
				  WHERE id = $1
				    AND device_secret = $4
				    AND device_secret_enc IS NULL`,
				row.id, sealed, codec.ActiveKeyID(), row.plaintext)
			if err != nil {
				return total, fmt.Errorf("mdm: device secret backfill update (device %d): %w", row.id, err)
			}
			if tag.RowsAffected() == 1 {
				total++
			}
			// RowsAffected 0 ⇒ the plaintext changed under us (or another
			// worker drained the row): leave it for the next pass instead of
			// sealing a value this call never saw.
		}
		if len(batch) < registryBackfillBatch {
			return total, nil
		}
	}
}
