package pgxutil

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MaxRetries is the number of connection attempts before giving up.
const MaxRetries = 3

// WorkerPool is the BYPASSRLS (cross-tenant) connection pool — the
// `setjoin_worker` credential that skips row-level security so cron, inbound
// delivery, and journaling can read across mailboxes. It is a DISTINCT Go type
// from the RLS-enforced app pool (`*pgxpool.Pool`) purely so the compiler
// enforces the split: a constructor that must run cross-tenant declares a
// `WorkerPool` parameter, and a plain app `*pgxpool.Pool` can no longer be passed
// to it (nor a WorkerPool silently used where an RLS pool is expected). Until the
// native-RLS DSN flip the two are the same underlying pool, so this is inert
// today — but it makes the escalation boundary legible and un-mis-wireable BEFORE
// the flip turns a confusion into a cross-tenant data leak. See
// retired-docs:superpowers/plans/archive/2026-06-18-native-rls-backstop.md.
//
// The embedded *pgxpool.Pool promotes Query/Exec/Begin/QueryRow, so worker code
// uses it transparently; unwrap via `.Pool` only when handing it to a callee that
// legitimately takes a plain *pgxpool.Pool.
type WorkerPool struct{ *pgxpool.Pool }

// OpenPool creates a connection pool with retry logic (exponential backoff).
// On transient failures (network, DNS, DB starting up), it retries up to
// MaxRetries times with backoff of 1s, 2s, 4s.
//
// auditHMACKey (AUDIT_HMAC_KEY) keys the admin_audit_log hash chain (V087):
// set as the app.audit_hmac_key GUC per connection, same mechanics as
// app.encryption_key below. Empty = audit rows fall back to unkeyed V2 sha256.
func OpenPool(ctx context.Context, dsn string, maxConns int, encryptionKey, auditHMACKey string) (*pgxpool.Pool, error) {
	if dsn == "" {
		return nil, fmt.Errorf("DSN is required")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("invalid DSN: %w", err)
	}
	if maxConns <= 0 {
		maxConns = 20
	}
	cfg.MaxConns = int32(maxConns)
	cfg.MinConns = int32(maxConns / 4)
	if cfg.MinConns < 1 {
		cfg.MinConns = 1
	}
	cfg.MaxConnLifetime = time.Hour
	cfg.MaxConnIdleTime = 30 * time.Minute
	cfg.HealthCheckPeriod = time.Minute

	if encryptionKey != "" || auditHMACKey != "" {
		// AfterConnect sets app.encryption_key / app.audit_hmac_key as
		// session-level GUCs on each new backend connection. In PgBouncer
		// transaction mode this only holds for the one backend that handled
		// AfterConnect; subsequent transactions may land on a different
		// backend. The pgbouncer.ini must include:
		//   track_extra_parameters = app.encryption_key,app.audit_hmac_key
		// to pin the GUCs to the logical client connection across hops.
		cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
			if encryptionKey != "" {
				if _, err := conn.Exec(ctx, "SELECT set_config('app.encryption_key', $1, false)", encryptionKey); err != nil {
					return err
				}
			}
			if auditHMACKey != "" {
				if _, err := conn.Exec(ctx, "SELECT set_config('app.audit_hmac_key', $1, false)", auditHMACKey); err != nil {
					return err
				}
			}
			return nil
		}
	}

	var pool *pgxpool.Pool
	var lastErr error
	for attempt := 0; attempt < MaxRetries; attempt++ {
		pool, err = pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			lastErr = fmt.Errorf("failed to create pool: %w", err)
			slog.Warn("pgxutil: pool creation failed, retrying", "attempt", attempt+1, "error", err)
			time.Sleep(time.Duration(1<<attempt) * time.Second)
			continue
		}
		if err := pool.Ping(ctx); err != nil {
			pool.Close()
			lastErr = fmt.Errorf("failed to ping database: %w", err)
			slog.Warn("pgxutil: ping failed, retrying", "attempt", attempt+1, "error", err)
			time.Sleep(time.Duration(1<<attempt) * time.Second)
			continue
		}
		if encryptionKey != "" || auditHMACKey != "" {
			if err := verifySessionGUCCarry(ctx, pool, encryptionKey, auditHMACKey); err != nil {
				// A deterministic deployment precondition, not a transient:
				// retrying cannot fix a pooler that drops the GUCs, so the
				// pool is closed and the failure surfaces loudly instead of
				// every decrypt/audit write failing later at request time.
				pool.Close()
				return nil, fmt.Errorf("pgxutil: session GUC deployment precondition failed: %w", err)
			}
		}
		return pool, nil
	}
	return nil, fmt.Errorf("pgxutil: failed after %d attempts: %w", MaxRetries, lastErr)
}

// verifySessionGUCCarry is the startup canary for the deployment precondition
// the AfterConnect hook depends on: the session-level app.* GUCs it sets must
// be readable from pool connections at transaction time. Direct PostgreSQL
// satisfies this structurally (one backend per pool connection); PgBouncer in
// transaction mode satisfies it only when track_extra_parameters carries the
// GUCs across backend hops. The canary reads the GUCs on TWO separate pool
// acquisitions — two transactions that may land on different backends — and
// refuses the pool if either leg cannot see the configured values (the
// missing-GUC mode fails closed at decrypt time, so refusing at startup is
// the honest loud variant of the same outcome).
func verifySessionGUCCarry(ctx context.Context, pool *pgxpool.Pool, encryptionKey, auditHMACKey string) error {
	for leg := 1; leg <= 2; leg++ {
		conn, err := pool.Acquire(ctx)
		if err != nil {
			return fmt.Errorf("canary leg %d: acquire: %w", leg, err)
		}
		if encryptionKey != "" {
			var got string
			// coalesce: a missing GUC reads as NULL, which cannot scan into a
			// string — the empty string IS the failure signal here.
			if err := conn.QueryRow(ctx, `SELECT coalesce(current_setting('app.encryption_key', true), '')`).Scan(&got); err != nil {
				conn.Release()
				return fmt.Errorf("canary leg %d: read app.encryption_key: %w", leg, err)
			}
			if got != encryptionKey {
				conn.Release()
				return fmt.Errorf("canary leg %d: app.encryption_key did not survive to the transaction backend (PgBouncer needs track_extra_parameters = app.encryption_key,app.audit_hmac_key): got %d bytes, want %d", leg, len(got), len(encryptionKey))
			}
		}
		if auditHMACKey != "" {
			var got string
			if err := conn.QueryRow(ctx, `SELECT coalesce(current_setting('app.audit_hmac_key', true), '')`).Scan(&got); err != nil {
				conn.Release()
				return fmt.Errorf("canary leg %d: read app.audit_hmac_key: %w", leg, err)
			}
			if got != auditHMACKey {
				conn.Release()
				return fmt.Errorf("canary leg %d: app.audit_hmac_key did not survive to the transaction backend (PgBouncer needs track_extra_parameters = app.encryption_key,app.audit_hmac_key)", leg)
			}
		}
		conn.Release()
	}
	return nil
}

// auditKeyActivationFloor is the minimum AUDIT_HMAC_KEY length EnforceAuditCutover
// accepts for a FIRST activation of audit V3. ValidateBase's profile-aware floor
// is 32 (standard/hybrid) or 16 (smx); the cutover gate runs without the crypto
// profile, so it fail-closes to the strictest floor — audit V3 is never
// permanently activated under a key that is weak under ANY profile. Installations
// that already activated are governed by the compatibility branch (same-key
// verification), not by this floor.
const auditKeyActivationFloor = 32

// auditKeyVerifyRows bounds the boot-time activation-key verification to the
// rows at the cutover boundary: a supplied key that differs from the activation
// key fails the FIRST v3: row, so a bounded window is sufficient proof of key
// identity while keeping startup cost O(window) instead of O(history).
// Full-history verification remains the operator's verify_audit_chain call.
const auditKeyVerifyRows = 256

// EnforceAuditCutover enforces the approved pre/post-cutover AUDIT_HMAC_KEY
// compatibility matrix (med-audit-key-validation-b1r2-013), keyed off the
// audit_chain_cutover singleton:
//
//	key        | pre-cutover                        | post-cutover (activated)
//	-----------+------------------------------------+----------------------------------------
//	empty      | supported unkeyed V2 state         | refuse startup ("AUDIT_HMAC_KEY is
//	           | (V2 writes and verify continue)    | required after audit V3 cutover")
//	weak       | REFUSE before activation — V3 is   | boot on the deployed key with a
//	(< floor)  | never permanently activated under  | persistent operator-visible warning;
//	           | a weak key                         | same-key verification still applies
//	adequate   | activate V3 idempotently           | verify the activation key; refuse an
//	           |                                    | unmanaged replacement loudly — audit
//	           |                                    | history is never rewritten
func EnforceAuditCutover(ctx context.Context, pool *pgxpool.Pool, auditHMACKey string) error {
	var active bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM audit_chain_cutover WHERE singleton)`).Scan(&active); err != nil {
		return fmt.Errorf("inspect audit HMAC cutover: %w", err)
	}
	if auditHMACKey == "" {
		// Empty pre-cutover stays a supported V2 state; post-cutover it would
		// silently downgrade new rows to unkeyed hashes, so startup refuses.
		if active {
			return fmt.Errorf("AUDIT_HMAC_KEY is required after audit V3 cutover")
		}
		return nil
	}
	if !active {
		if len(auditHMACKey) < auditKeyActivationFloor {
			return fmt.Errorf("AUDIT_HMAC_KEY must be at least %d characters to activate audit V3 cutover", auditKeyActivationFloor)
		}
		if _, err := pool.Exec(ctx, `SELECT audit_chain_activate_v3()`); err != nil {
			return fmt.Errorf("activate audit HMAC cutover: %w", err)
		}
		return nil
	}
	// Activated install with a key present. An already-deployed weak key keeps
	// operating — its historical v3: rows only verify under that key, so rejecting
	// it would brick every upgrade from a pre-floor install, and silently swapping
	// it would invalidate history. The weakness surfaces as this persistent
	// (every-boot) operator-visible warning instead.
	if len(auditHMACKey) < auditKeyActivationFloor {
		slog.Warn("AUDIT_HMAC_KEY is below the activation floor but this install already activated audit V3 under it; continuing so historical V3 rows keep verifying",
			"floor", auditKeyActivationFloor,
			"length", len(auditHMACKey))
	}
	return verifyAuditActivationKey(ctx, pool)
}

// verifyAuditActivationKey refuses an unmanaged AUDIT_HMAC_KEY replacement on an
// activated install. verify_audit_chain recomputes each v3: row under the
// CURRENT session key (set per connection by OpenPool's AfterConnect hook), so
// any row failing under the supplied key proves that key is not the one the
// chain was activated with — and since no audit row is ever re-hashed, starting
// with a different key would mark the whole historical V3 segment invalid.
func verifyAuditActivationKey(ctx context.Context, pool *pgxpool.Pool) error {
	var firstV3ID int64
	if err := pool.QueryRow(ctx, `SELECT first_v3_id FROM audit_chain_cutover WHERE singleton`).Scan(&firstV3ID); err != nil {
		return fmt.Errorf("inspect audit HMAC cutover: %w", err)
	}
	rows, err := pool.Query(ctx,
		`SELECT valid FROM verify_audit_chain($1, $2)`,
		firstV3ID, firstV3ID+int64(auditKeyVerifyRows)-1)
	if err != nil {
		return fmt.Errorf("verify audit HMAC cutover key: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var valid bool
		if err := rows.Scan(&valid); err != nil {
			return fmt.Errorf("verify audit HMAC cutover key: %w", err)
		}
		if !valid {
			return fmt.Errorf("AUDIT_HMAC_KEY does not match the key this install activated audit V3 with: refusing startup because replacing the audit key would invalidate historical V3 verification (audit history is never rewritten) — restore the original AUDIT_HMAC_KEY or use the documented operator rotation path")
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("verify audit HMAC cutover key: %w", err)
	}
	return nil
}

func OpenDirectPool(ctx context.Context, directDSN, poolDSN string) (*pgxpool.Pool, error) {
	dsn := directDSN
	if dsn == "" {
		dsn = poolDSN
	}
	return OpenPool(ctx, dsn, 1, "", "")
}

func OpenDirectConn(ctx context.Context, directDSN, poolDSN string) (*pgx.Conn, error) {
	dsn := directDSN
	if dsn == "" {
		dsn = poolDSN
	}
	return pgx.Connect(ctx, dsn)
}
