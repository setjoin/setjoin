package backup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var canonicalBlobHash = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Engine manages backup operations: snapshot, blob copy, manifest management.
// Its storage dependencies are the narrow consumer-defined BackupStore (ISP),
// not the fat storage.Driver — backup only needs Head/Get/Put/ProviderName plus
// the WORM retention ops it may apply.
type Engine struct {
	pool         *pgxpool.Pool
	primary      BackupStore // SeaweedFS (where blobs live)
	backup       BackupStore // S3/OSS/B2 (backup target)
	replica      BackupStore // optional cross-region replica. nil = disabled.
	logger       *slog.Logger
	ctx          context.Context // lifecycle context for background DB/MinIO operations
	signingKey   ed25519.PrivateKey
	signingKeyID string
}

// NewEngine creates a new backup engine.
func NewEngine(pool *pgxpool.Pool, primary, backup BackupStore, logger *slog.Logger, ctx context.Context) *Engine {
	return &Engine{pool: pool, primary: primary, backup: backup, logger: logger, ctx: ctx}
}

// NewEngineWithReplica creates a backup engine with a cross-region replica.
func NewEngineWithReplica(pool *pgxpool.Pool, primary, backup, replica BackupStore, logger *slog.Logger, ctx context.Context) *Engine {
	return &Engine{pool: pool, primary: primary, backup: backup, replica: replica, logger: logger, ctx: ctx}
}

// hasReplica returns true if a replica driver is configured.
func (e *Engine) hasReplica() bool {
	return e.replica != nil
}

// BackupResult holds the result of a backup run.
type BackupResult struct {
	Timestamp     string
	ConfigSize    int64
	BlobCount     int
	BlobTotalSize int64
	BlobsCopied   int
	BlobsSkipped  int
}

// BackupManifest indexes the artifacts of a backup run.
type BackupManifest struct {
	SchemaVersion    int      `json:"schema_version"`
	Timestamp        string   `json:"timestamp"`
	ConfigSize       int64    `json:"config_size_bytes"`
	ConfigSHA256     string   `json:"config_sha256"`
	BlobManifest     Manifest `json:"blob_manifest"`
	BlobCount        int      `json:"blob_count"`
	BlobTotalSize    int64    `json:"blob_total_size_bytes"`
	SigningKeyID     string   `json:"signing_key_id,omitempty"`
	SigningPublicKey string   `json:"signing_public_key,omitempty"`
	Signature        string   `json:"signature,omitempty"`
}

// VerifyEmbeddedManifest verifies self-contained recovery integrity. An
// external trust pack may additionally pin SigningKeyID, but changing either
// the manifest or its embedded key without recomputing a valid signature is
// always detected here.
func VerifyEmbeddedManifest(index BackupManifest) error {
	if index.SchemaVersion == 0 && index.Signature == "" {
		return nil // legacy backup; restore applies only reducer-classified safe config
	}
	if index.SchemaVersion != 1 || index.Signature == "" || index.SigningPublicKey == "" || index.SigningKeyID == "" {
		return errors.New("backup manifest signature metadata is incomplete")
	}
	pub, err := base64.RawStdEncoding.DecodeString(index.SigningPublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("backup manifest public key is invalid")
	}
	digest := sha256.Sum256(pub)
	if index.SigningKeyID != hex.EncodeToString(digest[:]) {
		return errors.New("backup manifest signing key ID mismatch")
	}
	signature, err := base64.RawStdEncoding.DecodeString(index.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("backup manifest signature encoding is invalid")
	}
	index.Signature = ""
	canonical, err := json.Marshal(index)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), canonical, signature) {
		return errors.New("backup manifest signature verification failed")
	}
	return nil
}

// ConfigureSigningKey loads a root-readable hex Ed25519 seed. Production
// backup workers must call this before they subscribe to jobs; the public key
// is embedded for standalone recovery while an optional external trust pack
// may pin the same key ID independently.
func (e *Engine) ConfigureSigningKey(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("BACKUP_SIGNING_KEY_FILE is required when backups are enabled")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("backup signing key must be a regular non-symlink 0600 file")
	}
	raw, err := os.ReadFile(path) //nolint:gosec // validated root-configured secret path
	if err != nil {
		return err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return errors.New("backup signing key must contain one 32-byte hex Ed25519 seed")
	}
	e.signingKey = ed25519.NewKeyFromSeed(seed)
	pub := e.signingKey.Public().(ed25519.PublicKey)
	digest := sha256.Sum256(pub)
	e.signingKeyID = hex.EncodeToString(digest[:])
	return nil
}

// BlobRef is a lightweight blob reference from the database.
type BlobRef struct {
	Hash string
	Size int64
}

// ConfigEntry is one system_config row in a backup: the jsonb value (as text) and
// the encrypted flag — the flag MUST round-trip, since the read path keys
// decryption off it (a lost flag corrupts encrypted credentials on restore).
type ConfigEntry struct {
	Value     string `json:"value"`
	Encrypted bool   `json:"encrypted"`
}

// rowScanner is the minimal cursor surface the scan helpers need (satisfied by
// pgx.Rows). It exists so the scan-error / cursor-error paths are testable with a
// fake — the bug a silent `continue` + a missing rows.Err() hid was a truncated
// backup inventory that still reported success.
type rowScanner interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}

// scanBlobRefs collects every blob row. A per-row Scan error is FATAL (a dropped
// blob is undetectable data loss), and rows.Err() is checked so a mid-iteration
// cursor error never masquerades as a clean, complete snapshot.
func scanBlobRefs(rows rowScanner) ([]BlobRef, error) {
	var blobs []BlobRef
	for rows.Next() {
		var ref BlobRef
		if err := rows.Scan(&ref.Hash, &ref.Size); err != nil {
			return nil, fmt.Errorf("scan blob: %w", err)
		}
		blobs = append(blobs, ref)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate blobs: %w", err)
	}
	return blobs, nil
}

// scanConfigEntries collects every system_config row (key → value+encrypted),
// with the same fatal-on-scan-error + rows.Err() discipline as scanBlobRefs.
func scanConfigEntries(rows rowScanner) (map[string]ConfigEntry, error) {
	config := make(map[string]ConfigEntry)
	for rows.Next() {
		var k, v string
		var enc bool
		if err := rows.Scan(&k, &v, &enc); err != nil {
			return nil, fmt.Errorf("scan config: %w", err)
		}
		config[k] = ConfigEntry{Value: v, Encrypted: enc}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate config: %w", err)
	}
	return config, nil
}

// SnapshotBlobs returns all live blobs (ref_count > 0) from the database.
func (e *Engine) SnapshotBlobs(ctx context.Context) ([]BlobRef, error) {
	rows, err := e.pool.Query(ctx,
		`SELECT b.sha256, b.size_bytes FROM blobs b WHERE b.ref_count > 0`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanBlobRefs(rows)
}

// CopyNewBlobs copies blobs from primary to backup, skipping those
// that already exist (idempotent via HeadObject check).
func (e *Engine) CopyNewBlobs(ctx context.Context, blobs []BlobRef) (copied, skipped int, errs []error) {
	for _, b := range blobs {
		if !canonicalBlobHash.MatchString(b.Hash) || b.Size < 0 {
			errs = append(errs, fmt.Errorf("blob %q has invalid inventory metadata", b.Hash))
			continue
		}
		// Skip only when the backup already holds a SAME-SIZE object — a present
		// object is still read and hashed before it is trusted. This repairs legacy
		// same-size corruption left by the pre-U3 size-only check.
		if head, herr := e.backup.HeadObject(ctx, "blobs/"+b.Hash); herr == nil && head.Size == b.Size {
			if verr := verifyStoredBlob(ctx, e.backup, b); verr == nil {
				skipped++
				continue
			}
		}
		r, gerr := e.primary.GetObject(ctx, "blobs/"+b.Hash)
		if gerr != nil {
			errs = append(errs, fmt.Errorf("blob %s: %w", b.Hash, gerr))
			continue
		}
		perr := e.backup.PutObject(ctx, "blobs/"+b.Hash, r, b.Size)
		cerr := r.Close()
		if err := errors.Join(perr, cerr); err != nil {
			errs = append(errs, fmt.Errorf("blob %s: copy/close: %w", b.Hash, err))
			continue
		}

		// The object name is a content hash, so a same-size write is not sufficient
		// evidence. Re-read the committed destination and verify both byte count and
		// digest before the manifest commit point can reference it.
		if err := verifyStoredBlob(ctx, e.backup, b); err != nil {
			errs = append(errs, fmt.Errorf("backup integrity check failed for %s: %w", b.Hash, err))
			continue
		}

		copied++
	}
	return copied, skipped, errs
}

func verifyStoredBlob(ctx context.Context, store BackupStore, blob BlobRef) error {
	head, err := store.HeadObject(ctx, "blobs/"+blob.Hash)
	if err != nil {
		return fmt.Errorf("head object: %w", err)
	}
	if head.Size != blob.Size {
		return fmt.Errorf("size mismatch (expected %d, got %d)", blob.Size, head.Size)
	}
	r, err := store.GetObject(ctx, "blobs/"+blob.Hash)
	if err != nil {
		return fmt.Errorf("read object: %w", err)
	}
	h := sha256.New()
	n, readErr := io.Copy(h, r)
	closeErr := r.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return fmt.Errorf("read/close object: %w", err)
	}
	if n != blob.Size {
		return fmt.Errorf("read size mismatch (expected %d, got %d)", blob.Size, n)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != blob.Hash {
		return fmt.Errorf("sha-256 mismatch (got %s)", got)
	}
	return nil
}

// ExportConfig exports system_config as JSON: a map of key → {value, encrypted}.
// The encrypted flag is included so restore can re-apply it — the read path keys
// decryption off it, so dropping it would corrupt encrypted credentials on a DR
// restore.
func (e *Engine) ExportConfig(ctx context.Context) ([]byte, error) {
	rows, err := e.pool.Query(ctx,
		`SELECT key, value, encrypted FROM system_config ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	config, err := scanConfigEntries(rows)
	if err != nil {
		return nil, err
	}
	return json.Marshal(config)
}

// BuildBlobManifest constructs the incremental blob manifest from a snapshot:
// the SHA-256 hash set, the count, and the total byte size. Pure (no I/O) so the
// manifest contract is unit-testable without a store.
func BuildBlobManifest(blobs []BlobRef, timestamp string) Manifest {
	m := Manifest{
		Timestamp: timestamp,
		Type:      "incr",
		Count:     len(blobs),
		Hashes:    make([]string, 0, len(blobs)),
	}
	for _, b := range blobs {
		m.Hashes = append(m.Hashes, b.Hash)
		m.TotalSize += b.Size
	}
	return m
}

// putJSON marshals already-encoded bytes to the backup store at key.
func (e *Engine) putJSON(ctx context.Context, key string, data []byte) error {
	return e.backup.PutObject(ctx, key, bytes.NewReader(data), int64(len(data)))
}

// writeManifests writes a backup run's index artifacts to the backup store:
//
//	manifests/incr-<ts>.json   — the incremental blob manifest (hash set)
//	config-<ts>.json           — the system_config export (full each run)
//	config.json                — latest-config pointer (overwritten)
//	backup-manifest-<ts>.json  — the immutable run index
//	backup-manifest.json       — latest-index pointer (the restore entry point)
//
// configJSON is the caller's system_config export (passed in, not fetched, so
// this method is pure-store and unit-testable without a DB). The fixed
// backup-manifest.json is written LAST, as the commit point: if the run dies
// earlier, restore still reads the previous complete backup (design §2.6 — an
// incomplete index is never committed). Returns the run's sizes for the
// backup_runs bookkeeping.
func (e *Engine) writeManifests(ctx context.Context, blobs []BlobRef, configJSON []byte, timestamp string) (BackupResult, error) {
	blobManifest := BuildBlobManifest(blobs, timestamp)
	bm, err := json.Marshal(blobManifest)
	if err != nil {
		return BackupResult{}, fmt.Errorf("marshal blob manifest: %w", err)
	}
	if err := e.putJSON(ctx, "manifests/incr-"+timestamp+".json", bm); err != nil {
		return BackupResult{}, fmt.Errorf("write blob manifest: %w", err)
	}

	if err := e.putJSON(ctx, "config-"+timestamp+".json", configJSON); err != nil {
		return BackupResult{}, fmt.Errorf("write config: %w", err)
	}
	if err := e.putJSON(ctx, "config.json", configJSON); err != nil {
		return BackupResult{}, fmt.Errorf("write latest config: %w", err)
	}

	configDigest := sha256.Sum256(configJSON)
	index := BackupManifest{
		SchemaVersion: 1,
		Timestamp:     timestamp,
		ConfigSize:    int64(len(configJSON)),
		ConfigSHA256:  hex.EncodeToString(configDigest[:]),
		BlobManifest:  blobManifest,
		BlobCount:     blobManifest.Count,
		BlobTotalSize: blobManifest.TotalSize,
	}
	if len(e.signingKey) == ed25519.PrivateKeySize {
		pub := e.signingKey.Public().(ed25519.PublicKey)
		index.SigningKeyID = e.signingKeyID
		index.SigningPublicKey = base64.RawStdEncoding.EncodeToString(pub)
		canonical, marshalErr := json.Marshal(index)
		if marshalErr != nil {
			return BackupResult{}, fmt.Errorf("marshal unsigned index: %w", marshalErr)
		}
		index.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(e.signingKey, canonical))
	}
	idx, err := json.Marshal(index)
	if err != nil {
		return BackupResult{}, fmt.Errorf("marshal index: %w", err)
	}
	if err := e.putJSON(ctx, "backup-manifest-"+timestamp+".json", idx); err != nil {
		return BackupResult{}, fmt.Errorf("write index: %w", err)
	}
	// Commit point — written last so a partial run never advertises itself.
	if err := e.putJSON(ctx, "backup-manifest.json", idx); err != nil {
		return BackupResult{}, fmt.Errorf("write latest index: %w", err)
	}

	return BackupResult{
		Timestamp:     timestamp,
		ConfigSize:    index.ConfigSize,
		BlobCount:     index.BlobCount,
		BlobTotalSize: index.BlobTotalSize,
	}, nil
}

// replicateToBackup mirrors a completed backup run to the cross-region replica:
// best-effort and non-fatal — a replica error is logged, never fails the primary
// run, and self-heals on the next run (blobs are content-addressed + HEAD-skip;
// manifests are re-copied each run since the latest pointer changes). Intended to
// run in its own goroutine off the worker's hot path.
func (e *Engine) replicateToBackup(blobs []BlobRef, result BackupResult) {
	if e.replica == nil {
		return
	}
	ts := result.Timestamp

	// Blobs: content-addressed, so HEAD-skip the ones already on the replica and
	// stream the rest backup→replica (no full-buffer; the size is known).
	var copied, failed int
	for _, b := range blobs {
		// A same-size replica object is still read and hashed before it is trusted
		// — the same verify-before-skip discipline CopyNewBlobs applies to the
		// backup store. A same-size corrupt/truncated-then-padded mirror is
		// re-copied instead of being skipped as parity (D-MAILSERVER-INTERNAL-
		// BACKUP-F-002); only a digest-verified mirror self-heals by skip.
		if head, err := e.replica.HeadObject(e.ctx, "blobs/"+b.Hash); err == nil && head.Size == b.Size {
			if verr := verifyStoredBlob(e.ctx, e.replica, b); verr == nil {
				continue
			}
			e.logger.Warn("replica: same-size blob failed digest verification — re-copying", "hash", b.Hash)
		}
		r, err := e.backup.GetObject(e.ctx, "blobs/"+b.Hash)
		if err != nil {
			e.logger.Warn("replica: blob fetch failed", "hash", b.Hash, "error", err)
			failed++
			continue
		}
		putErr := e.replica.PutObject(e.ctx, "blobs/"+b.Hash, r, b.Size)
		closeErr := r.Close()
		if err := errors.Join(putErr, closeErr); err != nil {
			e.logger.Warn("replica: blob write failed", "hash", b.Hash, "error", err)
			failed++
		} else if err := verifyStoredBlob(e.ctx, e.replica, b); err != nil {
			e.logger.Warn("replica: blob integrity check failed", "hash", b.Hash, "error", err)
			failed++
		} else {
			copied++
		}
	}

	// Manifests change every run (the latest pointer moves), so always re-copy.
	for _, key := range []string{
		"manifests/incr-" + ts + ".json",
		"config-" + ts + ".json",
		"config.json",
		"backup-manifest-" + ts + ".json",
		"backup-manifest.json",
	} {
		if err := e.copyObject(key); err != nil {
			e.logger.Warn("replica: manifest copy failed", "key", key, "error", err)
			failed++
		}
	}

	e.logger.Info("replica: mirror complete", "blobs_copied", copied, "failures", failed, "timestamp", ts)
}

// copyObject reads a (small) object from the backup store and writes it to the
// replica. Used for manifests/config only — blobs stream directly (size known).
func (e *Engine) copyObject(key string) error {
	r, err := e.backup.GetObject(e.ctx, key)
	if err != nil {
		return err
	}
	defer r.Close()
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return e.replica.PutObject(e.ctx, key, bytes.NewReader(data), int64(len(data)))
}

// claimRun atomically claims a pending run via a compare-and-swap on
// status='pending'. Returns false if the run was already claimed or finished — so
// a redelivered/duplicate backup_run NOTIFY, or a second worker (HA deploy),
// cannot double-process the same id.
func (e *Engine) claimRun(ctx context.Context, idStr string) (bool, error) {
	tag, err := e.pool.Exec(ctx,
		`UPDATE backup_runs SET status = 'running', started_at = now()
		 WHERE id = $1::bigint AND status = 'pending'`, idStr)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// pendingRunIDs returns the ids of runs still 'pending' — the startup-drain
// backstop for a NOTIFY dropped by the lossy fanout (or a row enqueued while the
// worker was down). The CAS claim makes draining safe against a racing NOTIFY.
func (e *Engine) pendingRunIDs(ctx context.Context) ([]int64, error) {
	rows, err := e.pool.Query(ctx, `SELECT id FROM backup_runs WHERE status = 'pending' ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan pending id: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// failRun marks a run failed with the given messages + counts. The terminal
// UPDATE's error is checked and logged loudly: a silently swallowed failure
// would strand the row in 'running' with no operator-visible trace
// (D-MAILSERVER-INTERNAL-BACKUP-F-004).
func (e *Engine) failRun(idStr string, msgs []string, blobCount, copied, skipped int) {
	if _, err := e.pool.Exec(e.ctx,
		`UPDATE backup_runs SET status = 'failed', completed_at = now(),
		 blob_count = $1, blobs_copied = $2, blobs_skipped = $3, error_log = $4 WHERE id = $5::bigint`,
		blobCount, copied, skipped, jsonMarshal(msgs), idStr); err != nil {
		e.logger.Error("backup job: terminal failed-UPDATE failed — run row left 'running'", "job_id", idStr, "error", err)
	}
}

// processRun executes one backup run. It first CAS-claims the row (skipping if a
// duplicate/redelivered NOTIFY or another worker already took it), then snapshots
// → copies → emits manifests → replicates, failing the run loudly at any step.
func (e *Engine) processRun(idStr string) {
	claimed, err := e.claimRun(e.ctx, idStr)
	if err != nil {
		e.logger.Error("backup job: claim failed", "job_id", idStr, "error", err)
		return
	}
	if !claimed {
		e.logger.Info("backup job: already claimed/finished — skipping", "job_id", idStr)
		return
	}

	blobs, err := e.SnapshotBlobs(e.ctx)
	if err != nil {
		e.logger.Error("backup job: blob snapshot failed", "job_id", idStr, "error", err)
		e.failRun(idStr, []string{err.Error()}, 0, 0, 0)
		return
	}

	copied, skipped, errs := e.CopyNewBlobs(e.ctx, blobs)
	if len(errs) > 0 {
		// An incomplete copy must NOT advertise a manifest restore would trust (it
		// would reference blobs absent from the backup). Fail the run; the next run
		// retries the missing blobs (HEAD-skip skips the good ones).
		msgs := make([]string, len(errs))
		for i, er := range errs {
			msgs[i] = er.Error()
		}
		e.logger.Error("backup job: blob copy errors — backup incomplete, marking failed",
			"job_id", idStr, "error_count", len(errs))
		e.failRun(idStr, msgs, len(blobs), copied, skipped)
		return
	}

	// Every snapshot blob is now in the backup — emit the manifests.
	ts := time.Now().UTC().Format("20060102T150405Z")
	configJSON, cerr := e.ExportConfig(e.ctx)
	if cerr != nil {
		e.logger.Error("backup job: config export failed", "job_id", idStr, "error", cerr)
		e.failRun(idStr, []string{cerr.Error()}, len(blobs), copied, skipped)
		return
	}
	result, merr := e.writeManifests(e.ctx, blobs, configJSON, ts)
	if merr != nil {
		e.logger.Error("backup job: manifest write failed", "job_id", idStr, "error", merr)
		e.failRun(idStr, []string{merr.Error()}, len(blobs), copied, skipped)
		return
	}

	if _, err := e.pool.Exec(e.ctx,
		`UPDATE backup_runs SET status = 'completed', completed_at = now(),
		 blob_count = $1, blobs_copied = $2, blobs_skipped = $3,
		 config_size = $4, blob_total_size = $5, manifest_timestamp = $6 WHERE id = $7::bigint`,
		len(blobs), copied, skipped, result.ConfigSize, result.BlobTotalSize, ts, idStr); err != nil {
		e.logger.Error("backup job: terminal completed-UPDATE failed — run row left 'running' though objects are committed",
			"job_id", idStr, "error", err)
	}

	e.logger.Info("backup worker: job completed", "job_id", idStr,
		"blobs_total", len(blobs), "copied", copied, "skipped", skipped,
		"manifest", "backup-manifest-"+ts+".json")

	// Cross-region replica: async + best-effort, off the worker hot path.
	// A replica failure never affects the (already-committed) primary run.
	if e.hasReplica() {
		go e.replicateToBackup(blobs, result)
	}

	// GFS retention: prune index objects + rows for runs beyond the keep-count.
	// Best-effort — a retention error never fails the (committed) backup.
	if _, rerr := e.ApplyRetention(e.ctx, e.getRetentionPolicy(e.ctx)); rerr != nil {
		e.logger.Warn("retention: apply failed", "error", rerr)
	}
}

// completedRuns returns completed backup runs that have a manifest, newest-first —
// the manifest history GFS retention prunes.
func (e *Engine) completedRuns(ctx context.Context) ([]retentionRun, error) {
	rows, err := e.pool.Query(ctx,
		`SELECT id, manifest_timestamp FROM backup_runs
		 WHERE status = 'completed' AND manifest_timestamp IS NOT NULL
		 ORDER BY created_at DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var runs []retentionRun
	for rows.Next() {
		var r retentionRun
		if err := rows.Scan(&r.ID, &r.Timestamp); err != nil {
			return nil, fmt.Errorf("scan retention run: %w", err)
		}
		runs = append(runs, r)
	}
	return runs, rows.Err()
}

// ApplyRetention prunes backup runs beyond what the GFS policy keeps. Each
// backup-manifest-<ts>.json is a self-contained restore point, so this deletes the
// oldest runs' INDEX objects (backup-manifest / incr-manifest / config) + their
// backup_runs rows — NEVER blobs (blob GC is ref_count-driven + separate). A pruned
// run loses its restore point; no blob a kept manifest references is touched.
func (e *Engine) ApplyRetention(ctx context.Context, policy RetentionPolicy) (pruned int, err error) {
	runs, err := e.completedRuns(ctx)
	if err != nil {
		return 0, err
	}
	for _, r := range runsToPrune(runs, policy) {
		// The backup_runs row is the only bookkeeping for a pruned run, so it is
		// deleted ONLY after every index object of that run is confirmed gone
		// (D-MAILSERVER-INTERNAL-BACKUP-F-003). A failed object delete leaves the
		// row in place: the next retention pass retries the run instead of the row
		// (and its restore-point ledger) disappearing while a config export
		// survives orphaned beyond the GFS window.
		//
		// Secondary artifacts (incr index copy, config export) are deleted first
		// and the authoritative self-contained restore-point index
		// (backup-manifest-<ts>.json) LAST; the run's remaining deletes are
		// abandoned at the first failure. An interrupted prune must never have
		// already destroyed the run's index while secondary objects survive —
		// the retained row re-drives the missing deletes on the next pass.
		allDeleted := true
		for _, key := range []string{
			"manifests/incr-" + r.Timestamp + ".json",
			"config-" + r.Timestamp + ".json",
			"backup-manifest-" + r.Timestamp + ".json",
		} {
			if derr := e.backup.DeleteObject(ctx, key); derr != nil {
				e.logger.Warn("retention: index delete failed — row kept for retry", "key", key, "id", r.ID, "error", derr)
				allDeleted = false
				break
			}
		}
		if !allDeleted {
			continue
		}
		if _, derr := e.pool.Exec(ctx, `DELETE FROM backup_runs WHERE id = $1`, r.ID); derr != nil {
			e.logger.Warn("retention: backup_runs delete failed", "id", r.ID, "error", derr)
			continue
		}
		pruned++
	}
	if pruned > 0 {
		e.logger.Info("retention: pruned old backup runs", "pruned", pruned, "kept", len(runs)-pruned)
	}
	return pruned, nil
}

// getRetentionPolicy loads the GFS scheme from system_config
// (key backup.retention_policy = {"gfs":"7d4w12m"}), defaulting to 7d4w12m.
func (e *Engine) getRetentionPolicy(ctx context.Context) RetentionPolicy {
	policy := RetentionPolicy{GFSScheme: "7d4w12m"}
	var raw string
	if err := e.pool.QueryRow(ctx,
		`SELECT value FROM system_config WHERE key = 'backup.retention_policy'`).Scan(&raw); err != nil {
		return policy // not configured → default
	}
	var cfg struct {
		GFS string `json:"gfs"`
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err == nil && cfg.GFS != "" {
		policy.GFSScheme = cfg.GFS
	}
	return policy
}

// reclaimStaleRunning flips 'running' rows back to 'pending' at worker startup,
// mirroring bulkroles' reclaim: a crash mid-run strands the row in 'running'
// where neither claimRun (CAS on 'pending') nor the pending-drain would ever
// touch it again — silent bookkeeping death (D-MAILSERVER-INTERNAL-BACKUP-F-004).
// Safe at startup because a single worker services runs; any surviving
// 'running' row predates this process. Content-addressed HEAD-skip makes a
// re-run of a partially copied run idempotent.
func (e *Engine) reclaimStaleRunning(ctx context.Context) error {
	tag, err := e.pool.Exec(ctx,
		`UPDATE backup_runs SET status = 'pending', started_at = NULL WHERE status = 'running'`)
	if err != nil {
		return err
	}
	if n := tag.RowsAffected(); n > 0 {
		e.logger.Warn("backup worker: reclaimed stranded 'running' rows from a previous process", "requeued", n)
	}
	return nil
}

// Worker drains any pending runs (the backstop for a dropped NOTIFY or a restart),
// then services backup_run notifications. Run as a goroutine at startup.
func (e *Engine) Worker(ctx context.Context, ch <-chan string) {
	e.logger.Info("backup worker: started")

	// Startup reclaim: stranded 'running' rows (crash mid-run) go back to
	// 'pending' so the drain below re-processes them instead of skipping.
	if rerr := e.reclaimStaleRunning(e.ctx); rerr != nil {
		e.logger.Error("backup worker: stale-running reclaim failed", "error", rerr)
	}

	// Startup drain: a NOTIFY can be dropped by the lossy fanout, or a row can be
	// enqueued while the worker was down — process any leftover 'pending' rows so
	// no enqueued backup is silently stranded. The CAS claim in processRun makes
	// this safe against a NOTIFY racing the drain for the same id.
	if ids, derr := e.pendingRunIDs(e.ctx); derr != nil {
		e.logger.Error("backup worker: pending-drain query failed", "error", derr)
	} else {
		for _, id := range ids {
			e.processRun(fmt.Sprint(id))
		}
	}

	for {
		select {
		case <-ctx.Done():
			e.logger.Info("backup worker: shutting down")
			return
		case jobIDStr, ok := <-ch:
			if !ok {
				return
			}
			e.logger.Info("backup worker: job received", "job_id", jobIDStr)
			e.processRun(jobIDStr)
		}
	}
}

func jsonMarshal(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}
