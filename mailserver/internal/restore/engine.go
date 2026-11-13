package restore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"sort"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/backup"
)

// blobHashRe matches a canonical lowercase hex SHA-256 — the only shape a blob
// store key may take. Manifest hashes are attacker-controlled (a malicious backup
// could carry a path-traversal payload like "../../etc/passwd"), and the POSIX
// driver's filepath.Join collapses "..", so any non-canonical hash MUST be
// rejected before it is concatenated into a "blobs/"+hash key.
var blobHashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

const maxRestoreMetadataBytes = 64 << 20

func isValidBlobHash(h string) bool { return blobHashRe.MatchString(h) }

// DetectMode returns the gateway operating mode based on database state.
// "setup" = no users (first boot or bare-metal restore needed)
// "restore_resume" = users exist but restore was interrupted
// "normal" = normal operation
func DetectMode(userCount, pendingRestores int) string {
	if pendingRestores > 0 {
		return "restore_resume"
	}
	if userCount == 0 {
		return "setup"
	}
	return "normal"
}

// Engine manages restore operations: config, pg_dump, blob restore.
// Its storage dependencies are the narrow consumer-defined RestoreStore (ISP),
// not the fat storage.Driver — restore only needs Head/Get/Put.
type Engine struct {
	pool    *pgxpool.Pool
	primary RestoreStore // SeaweedFS (target)
	backup  RestoreStore // S3/OSS/B2 (source)
	logger  *slog.Logger
}

// NewEngine creates a new restore engine.
func NewEngine(pool *pgxpool.Pool, primary, backup RestoreStore, logger *slog.Logger) *Engine {
	return &Engine{pool: pool, primary: primary, backup: backup, logger: logger}
}

// DownloadManifest fetches and parses backup-manifest.json — the latest backup
// index the worker's writeManifests commits last, and restore's entry point.
func (e *Engine) DownloadManifest(ctx context.Context) (*backup.BackupManifest, error) {
	r, err := e.backup.GetObject(ctx, "backup-manifest.json")
	if err != nil {
		return nil, fmt.Errorf("download backup-manifest.json: %w", err)
	}
	data, err := readBoundedAndClose(r, maxRestoreMetadataBytes)
	if err != nil {
		return nil, fmt.Errorf("read backup-manifest.json: %w", err)
	}
	var m backup.BackupManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse backup-manifest.json: %w", err)
	}
	if err := backup.VerifyEmbeddedManifest(m); err != nil {
		return nil, fmt.Errorf("verify backup-manifest.json: %w", err)
	}
	return &m, nil
}

// RestoreConfig reads config.json (the system_config export) from the backup
// store and applies only reducer-classified safe configuration. Operator-approved,
// encrypted, rotate, quarantine and unknown rows remain isolated. The embedded
// manifest proves integrity, not source trust; a future independently verified
// trust-pack flow must expose a separate proof-carrying API rather than a boolean.
// Returns the number of safe keys restored.
func (e *Engine) RestoreConfig(ctx context.Context) (int, error) {
	r, err := e.backup.GetObject(ctx, "config.json")
	if err != nil {
		return 0, fmt.Errorf("download config.json: %w", err)
	}
	data, err := readBoundedAndClose(r, maxRestoreMetadataBytes)
	if err != nil {
		return 0, fmt.Errorf("read config.json: %w", err)
	}
	var cfg map[string]backup.ConfigEntry
	if err := json.Unmarshal(data, &cfg); err != nil {
		return 0, fmt.Errorf("parse config.json: %w", err)
	}
	// ER5 occ_902b7cb54c44c587c54a129d (backup-integrity.config-manifest-downgrade):
	// the manifest lookup IS the verification gate, so a lookup ERROR can never be
	// a reason to skip verification. The previous HeadObject probe treated every
	// error — transient storage outage, throttling, permission failure — exactly
	// like "no manifest", silently restoring config.json with no integrity check
	// at all. Absence is not a legacy shape either: writeManifests commits
	// backup-manifest.json as the LAST artifact of every complete backup run (the
	// run's commit point), so a backup whose config.json lacks its manifest is an
	// incomplete or tampered artifact. DownloadManifest is therefore unconditional
	// and every outcome except a verified manifest bound to these exact bytes
	// fails closed before the first database write (the mailctl argv-hygiene
	// precedent: detection is fail-closed, never best-effort).
	manifest, err := e.DownloadManifest(ctx)
	if err != nil {
		return 0, fmt.Errorf("config restore requires a verifiable backup manifest: %w", err)
	}
	digest := sha256.Sum256(data)
	if manifest.ConfigSize != int64(len(data)) || manifest.ConfigSHA256 != hex.EncodeToString(digest[:]) {
		return 0, errors.New("config.json does not match the signed backup manifest")
	}
	tx, err := e.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin config restore: %w", err)
	}
	defer tx.Rollback(ctx)
	keys := make([]string, 0, len(cfg))
	for key := range cfg {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	applied := 0
	for _, k := range keys {
		entry := cfg[k]
		var disposition string
		if err := tx.QueryRow(ctx,
			`SELECT restore_config_apply($1,$2::jsonb,$3,$4)`,
			k, entry.Value, entry.Encrypted, false).Scan(&disposition); err != nil {
			return 0, fmt.Errorf("restore config key %q: %w", k, err)
		}
		if disposition == "safe" {
			applied++
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit config restore: %w", err)
	}
	return applied, nil
}

func readBoundedAndClose(r io.ReadCloser, limit int64) ([]byte, error) {
	data, readErr := io.ReadAll(io.LimitReader(r, limit+1))
	closeErr := r.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("object exceeds %d-byte metadata limit", limit)
	}
	return data, nil
}

// IntegrityReport describes the result of a blob integrity check.
type IntegrityReport struct {
	Total   int
	Present int
	Missing []string // SHA-256 hashes
	Corrupt []string // present but wrong size or content digest
}

type integrityRows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}

func scanIntegrityRefs(rows integrityRows) ([]backup.BlobRef, error) {
	var refs []backup.BlobRef
	for rows.Next() {
		var ref backup.BlobRef
		if err := rows.Scan(&ref.Hash, &ref.Size); err != nil {
			return nil, fmt.Errorf("scan integrity blob: %w", err)
		}
		if !isValidBlobHash(ref.Hash) || ref.Size < 0 {
			return nil, fmt.Errorf("invalid blob inventory metadata for %q", ref.Hash)
		}
		refs = append(refs, ref)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate integrity blobs: %w", err)
	}
	return refs, nil
}

// VerifyIntegrity checks that every blob referenced in the database
// actually exists in primary storage.
func (e *Engine) VerifyIntegrity(ctx context.Context) (*IntegrityReport, error) {
	rows, err := e.pool.Query(ctx,
		`SELECT sha256, size_bytes FROM blobs WHERE ref_count > 0`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	refs, err := scanIntegrityRefs(rows)
	if err != nil {
		return nil, err
	}
	var report IntegrityReport
	for _, ref := range refs {
		report.Total++
		head, err := e.primary.HeadObject(ctx, "blobs/"+ref.Hash)
		if err != nil {
			report.Missing = append(report.Missing, ref.Hash)
			continue
		}
		if head.Size != ref.Size {
			report.Corrupt = append(report.Corrupt, ref.Hash)
			continue
		}
		if err := verifyBlobDigest(ctx, e.primary, ref.Hash, ref.Size); err != nil {
			report.Corrupt = append(report.Corrupt, ref.Hash)
			continue
		}
		report.Present++
	}
	return &report, nil
}

// restoreAdvisoryLockKey is the application-defined key for the restore
// single-flight advisory lock (the ASCII of "REST" — an arbitrary stable value).
const restoreAdvisoryLockKey int64 = 0x5245_5354

// StartRestoreJob claims the single restore slot: it inserts a 'running'
// restore_jobs row only if no other restore is pending/running, serialized by a
// transaction-scoped advisory lock so two concurrent callers can't both claim
// (the "lock" in mailctl-restore-lock-replication). Returns the new job id, or an
// error if a restore is already in progress.
func (e *Engine) StartRestoreJob(ctx context.Context, restoreType string) (int64, error) {
	tx, err := e.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx)

	// Serialize concurrent claimants — the lock releases at tx end.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, restoreAdvisoryLockKey); err != nil {
		return 0, fmt.Errorf("acquire restore lock: %w", err)
	}

	var inProgress bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM restore_jobs WHERE status IN ('pending', 'running'))`,
	).Scan(&inProgress); err != nil {
		return 0, fmt.Errorf("check in-progress: %w", err)
	}
	if inProgress {
		return 0, fmt.Errorf("a restore is already in progress")
	}

	var id int64
	if err := tx.QueryRow(ctx,
		`INSERT INTO restore_jobs (status, restore_type, started_at)
		 VALUES ('running', $1, now()) RETURNING id`, restoreType,
	).Scan(&id); err != nil {
		return 0, fmt.Errorf("insert restore_jobs: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return id, nil
}

// FinishRestoreJob closes out a restore_jobs row — 'completed' when restoreErr is
// nil, otherwise 'failed' with the message recorded in error_log — and thereby
// releases the single-flight slot StartRestoreJob claimed.
func (e *Engine) FinishRestoreJob(ctx context.Context, id int64, restoreErr error) error {
	if restoreErr != nil {
		errJSON, _ := json.Marshal([]string{restoreErr.Error()})
		_, err := e.pool.Exec(ctx,
			`UPDATE restore_jobs SET status = 'failed', completed_at = now(), error_log = $1 WHERE id = $2`,
			errJSON, id)
		return err
	}
	_, err := e.pool.Exec(ctx,
		`UPDATE restore_jobs SET status = 'completed', completed_at = now() WHERE id = $1`, id)
	return err
}

// RestoreFromManifest restores the manifest's blobs that are absent from primary
// storage (HEAD-skip the present ones), each SHA-256-verified on fetch. Use after
// the DB is in place; the manifest's hash set is the authoritative blob inventory.
func (e *Engine) RestoreFromManifest(ctx context.Context, manifest *backup.BackupManifest) (restored int, errs []error) {
	if manifest == nil {
		return 0, []error{fmt.Errorf("backup manifest is required")}
	}
	if manifest.BlobManifest.Count != len(manifest.BlobManifest.Hashes) || manifest.BlobCount != len(manifest.BlobManifest.Hashes) {
		return 0, []error{fmt.Errorf("backup manifest blob counts do not match the hash inventory")}
	}
	var missing []string
	seen := make(map[string]struct{}, len(manifest.BlobManifest.Hashes))
	for _, h := range manifest.BlobManifest.Hashes {
		if !isValidBlobHash(h) {
			errs = append(errs, fmt.Errorf("blob %q: not a canonical sha-256 hash — rejected", h))
			continue
		}
		if _, exists := seen[h]; exists {
			errs = append(errs, fmt.Errorf("blob %s: duplicate manifest entry", h))
			continue
		}
		seen[h] = struct{}{}
		head, err := e.primary.HeadObject(ctx, "blobs/"+h)
		if err != nil || head == nil || verifyBlobDigest(ctx, e.primary, h, head.Size) != nil {
			missing = append(missing, h)
		}
	}
	r, rerrs := e.RestoreMissingBlobs(ctx, missing)
	return r, append(errs, rerrs...)
}

// RestoreMissingBlobs fetches specific blob hashes from backup and writes to primary.
func (e *Engine) RestoreMissingBlobs(ctx context.Context, hashes []string) (restored int, errs []error) {
	for _, hash := range hashes {
		// Defense-in-depth: reject any non-canonical hash before it reaches a
		// store key (RestoreFromManifest also pre-filters, but this method is a
		// public entry point — e.g. mailctl restore --hashes).
		if !isValidBlobHash(hash) {
			errs = append(errs, fmt.Errorf("blob %q: not a canonical sha-256 hash — rejected", hash))
			continue
		}
		head, err := e.backup.HeadObject(ctx, "blobs/"+hash)
		if err != nil {
			errs = append(errs, fmt.Errorf("blob %s: backup head: %w", hash, err))
			continue
		}
		if head == nil || head.Size < 0 {
			errs = append(errs, fmt.Errorf("blob %s: backup returned invalid metadata", hash))
			continue
		}
		// Authenticate the source before writing a byte into the primary store.
		// A second streaming read performs the copy; this avoids buffering a large
		// blob while preserving the no-partial-corrupt-write boundary.
		if err := verifyBlobDigest(ctx, e.backup, hash, head.Size); err != nil {
			errs = append(errs, fmt.Errorf("blob %s: backup verification: %w", hash, err))
			continue
		}
		r, err := e.backup.GetObject(ctx, "blobs/"+hash)
		if err != nil {
			errs = append(errs, fmt.Errorf("blob %s: backup get: %w", hash, err))
			continue
		}
		counter := &countingReader{reader: r}
		putErr := e.primary.PutObject(ctx, "blobs/"+hash, counter, head.Size)
		closeErr := r.Close()
		if err := errors.Join(putErr, closeErr); err != nil {
			errs = append(errs, fmt.Errorf("blob %s: primary put/read close: %w", hash, err))
			continue
		}
		if counter.count != head.Size {
			errs = append(errs, fmt.Errorf("blob %s: backup size mismatch (expected %d, read %d)", hash, head.Size, counter.count))
			continue
		}
		if err := verifyBlobDigest(ctx, e.primary, hash, head.Size); err != nil {
			errs = append(errs, fmt.Errorf("blob %s: post-write verification: %w", hash, err))
			continue
		}
		restored++
	}
	return restored, errs
}

type countingReader struct {
	reader io.Reader
	count  int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.count += int64(n)
	return n, err
}

func verifyBlobDigest(ctx context.Context, store RestoreStore, hash string, size int64) error {
	if !isValidBlobHash(hash) || size < 0 {
		return fmt.Errorf("invalid blob metadata")
	}
	r, err := store.GetObject(ctx, "blobs/"+hash)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, readErr := io.Copy(h, r)
	closeErr := r.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return err
	}
	if n != size {
		return fmt.Errorf("size mismatch (expected %d, got %d)", size, n)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != hash {
		return fmt.Errorf("sha-256 mismatch (got %s)", got)
	}
	return nil
}
