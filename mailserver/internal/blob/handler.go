package blob

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/config"
	"setjoin.com/mailserver/internal/storage"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/reducererr"
)

// Handler proxies attachment reads and writes between clients and MinIO.
// Clients never talk to MinIO directly; all access is mediated here after JWT auth.
//
// URL scheme:
//
//	GET  /blobs/{sha256}  — download attachment by content hash
//	PUT  /blobs/{sha256}  — upload a new attachment (used during compose)
//
// The sha256 path param is the content-addressed key used in the blobs table.
// MinIO stores the raw bytes; PostgreSQL stores only the MinIO path (raw_ref).
type Handler struct {
	minio objectStore
	pool  *pgxpool.Pool
	// workerPool is the setjoin_worker (BYPASSRLS) pool. The blob-ownership check
	// (Get) keys on mb.user_id ACROSS all of the user's mailboxes — a content-
	// addressed blob can be attached to a message in ANY of them — so it does NOT
	// fit ONE app.current_mailbox_id GUC. Under the W6/V004 FORCE flip an app-pool
	// GUC=one-mailbox would hide the user's own blobs attached in their other
	// mailboxes (false 404). The read is R1-scoped (mb.user_id = claims.UserID) and
	// structurally cross-mailbox-for-one-user, so it runs on the bypass pool — the
	// admin-case treatment the native-RLS plan prescribes for multi-mailbox reads.
	// workerPool aliases pool until DB_WORKER_DSN is set (W1b), so this is INERT.
	workerPool        *pgxpool.Pool
	bucket            string
	logger            *slog.Logger
	retentionRegistry RetentionRegistry // optional; nil if WORM/retention is disabled
	// Reclamation/accounting policy (D-MAILSERVER-INTERNAL-BLOB-002); set once
	// at startup via SetReclamationPolicy. Zero values are safe: the default
	// grace window applies and per-user enforcement stays OFF (accounting is
	// still recorded).
	reclaimGraceMinutes int
	userQuotaBytes      int64

	cacheMu    sync.Mutex
	cache      map[string]cachedBlob
	cacheBytes int64

	// retryMu guards the bounded in-memory retry ledgers below. Both exist so a
	// TRANSIENT failure can never strand work permanently (the cleanup goroutine
	// retries them on its existing 5-minute tick):
	//
	//   - reapRetries: blobs whose guarded row delete succeeded but whose MinIO
	//     RemoveObject failed (D-MAILSERVER-INTERNAL-BLOB-005). Without the
	//     retry, the bytes are orphaned forever — no blobs row, no queue row
	//     (FK CASCADE dropped it), no sweeper.
	//   - retentionRetries: uploaded blobs whose WORM ApplyAll failed
	//     (D-MAILSERVER-INTERNAL-BLOB-006) — the upload stays non-fatal (the
	//     documented design), but the lock application is retried instead of
	//     being silently forgotten, mirroring the drive plane's worm-pending
	//     retry loop (in memory rather than via a schema column).
	//
	// Both are bounded: a crash loses the in-memory ledger (durable reconciliation
	// is the recorded owner follow-up), and an overflow keeps the oldest failures
	// visible in logs while dropping the ledger entry.
	retryMu          sync.Mutex
	reapRetries      map[string]struct{}
	retentionRetries map[string]struct{}
}

// RetentionRegistry is the interface for applying retention policies after blob writes.
// This avoids a circular import between blob and storage packages.
type RetentionRegistry interface {
	ApplyAll(ctx context.Context, key string) error
}

// objectStore is the consumer-defined subset of *minio.Client the blob handler
// uses. It exists so Put's stream-to-temp-then-copy safety property can be unit-
// tested with a fake store (no live MinIO). *minio.Client satisfies it directly.
// ponytail: one production impl (*minio.Client) — this is the test seam, not
// abstraction for its own sake; widen only if a second backend lands.
type objectStore interface {
	PutObject(ctx context.Context, bucket, object string, reader io.Reader, size int64, opts minio.PutObjectOptions) (minio.UploadInfo, error)
	GetObject(ctx context.Context, bucket, object string, opts minio.GetObjectOptions) (*minio.Object, error)
	CopyObject(ctx context.Context, dst minio.CopyDestOptions, src minio.CopySrcOptions) (minio.UploadInfo, error)
	RemoveObject(ctx context.Context, bucket, object string, opts minio.RemoveObjectOptions) error
}

// blobHashRe matches a lowercase hex SHA-256 — the only valid content-addressed
// key. Anything else is rejected before any storage call.
var blobHashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

const (
	maxCacheBytes = 512 << 20 // 512 MiB
	maxCacheTTL   = 10 * time.Minute
	maxCacheSize  = 10 << 20 // only cache files < 10 MiB

	// maxRetryLedger bounds each in-memory retry ledger (see the Handler field
	// doc). Far above any plausible transient-failure backlog; an overflow is
	// logged loudly rather than growing without bound.
	maxRetryLedger = 1024
)

type cachedBlob struct {
	data        []byte
	contentType string
	expiresAt   time.Time
}

// NewMinIOClient creates a MinIO client from config.
// Called by main so the same client instance can be shared with startup checks.
//
// TLS posture (D-MAILSERVER-INTERNAL-STORAGE-F-001): the endpoint is resolved
// through storage.ResolveEndpointTLS with the S3_SECURE value as an explicit
// assertion — https:// endpoints force TLS (S3_SECURE=false is a rejected
// conflict), scheme-less non-loopback endpoints are rejected fail-closed
// (they historically defaulted to plaintext), and explicit loopback HTTP
// remains the supported local compatibility case. The scheme-stripped host is
// handed to minio-go, which builds the URL scheme from the resolved Secure —
// previously a scheme-ful S3_ENDPOINT was mangled into the URL here.
func NewMinIOClient(cfg *config.Config) (*minio.Client, error) {
	hostPort, useTLS, err := storage.ResolveEndpointTLS(cfg.S3Endpoint, &cfg.S3Secure)
	if err != nil {
		return nil, fmt.Errorf("minio client: %w", err)
	}
	if hostPort == "" {
		return nil, fmt.Errorf("minio client: S3 endpoint is required")
	}
	mc, err := minio.New(hostPort, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.S3AccessKey, cfg.S3SecretKey, ""),
		Secure: useTLS,
	})
	if err != nil {
		return nil, fmt.Errorf("minio client: %w", err)
	}
	return mc, nil
}

// NewHandler wraps an existing MinIO client for request handling.
func NewHandler(mc *minio.Client, pool *pgxpool.Pool, workerPool pgxutil.WorkerPool, bucket string, logger *slog.Logger) *Handler {
	return &Handler{
		minio:      mc,
		pool:       pool,
		workerPool: workerPool.Pool,
		bucket:     bucket,
		logger:     logger,
		cache:      make(map[string]cachedBlob),
	}
}

// SetRetentionRegistry sets the retention policy registry for WORM enforcement.
// When set, ApplyAll is called after every successful PutObject.
func (h *Handler) SetRetentionRegistry(r RetentionRegistry) {
	h.retentionRegistry = r
}

// DefaultReclaimGraceMinutes is the PUT-time reclamation grace window used when
// no explicit policy is configured: an uploaded-but-never-attached blob stays
// in blob_cleanup_queue this long before the sweeper may reclaim it. Long
// enough for compose-draft-then-send flows; the zero-trigger detach path keeps
// whatever delay the row already carries (longer retention, never less safe).
const DefaultReclaimGraceMinutes = 1440 // 24h

// SetReclamationPolicy configures PUT-time reclamation arming and per-user
// blob storage enforcement (D-MAILSERVER-INTERNAL-BLOB-002). Arming at PUT is
// always on once deployed — that is the remediation; graceMinutes (a product/
// ops setting) only selects the window, with values <= 0 meaning "use
// DefaultReclaimGraceMinutes". quotaBytes is the per-user charged-bytes bound;
// values <= 0 leave enforcement OFF (accounting is still recorded). The bound
// check runs inside the blob_upload_account reducer under a per-user row lock
// (blob_user_usage FOR UPDATE), so simultaneous uploads can never exceed it.
// Called once from main; zero-value Handlers (unit tests) get the default
// grace and no enforcement.
func (h *Handler) SetReclamationPolicy(graceMinutes int, quotaBytes int64) {
	h.reclaimGraceMinutes = graceMinutes
	h.userQuotaBytes = quotaBytes
}

// reclaimGrace resolves the effective PUT-time reclamation grace window.
func (h *Handler) reclaimGrace() int {
	if h.reclaimGraceMinutes > 0 {
		return h.reclaimGraceMinutes
	}
	return DefaultReclaimGraceMinutes
}

// byteCounter counts the bytes actually streamed through a PUT body, so
// unknown-length (chunked) uploads are charged their measured size rather than
// the ContentLength zero-size fallback.
type byteCounter struct{ n int64 }

func (c *byteCounter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

// StartCleanup runs a background goroutine that processes the deferred blob
// cleanup queue. Blobs scheduled for deletion >5 minutes ago and whose ref_count
// is still 0 are permanently removed from MinIO and the database. The same tick
// retries the bounded in-memory failure ledgers (reap + retention) so a
// transient MinIO failure cannot strand bytes or a WORM lock permanently.
func (h *Handler) StartCleanup(ctx context.Context) {
	// Server-lifetime goroutine — uses server-level shutdown context.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				h.processCleanupQueue(ctx)
				h.processOrphanedBlobs(ctx)
				h.retryFailedReaps(ctx)
				h.retryFailedRetention(ctx)
			case <-ctx.Done():
				return
			}
		}
	}()
}

// noteRetry records key in the bounded in-memory retry ledger pointed to by
// ledger, lazily initializing it and evicting an arbitrary entry when the
// ledger is full (the overflow stays visible only in the error logs — durable
// reconciliation is the recorded owner follow-up). Shared by the reap and
// retention ledgers, which differ only in which map they arm.
func (h *Handler) noteRetry(ledger *map[string]struct{}, key string) {
	h.retryMu.Lock()
	defer h.retryMu.Unlock()
	if *ledger == nil {
		*ledger = make(map[string]struct{})
	}
	if len(*ledger) >= maxRetryLedger {
		for k := range *ledger {
			delete(*ledger, k)
			break
		}
	}
	(*ledger)[key] = struct{}{}
}

// noteReapRetry records a sha256 whose storage removal failed after the guarded
// blobs-row delete, bounded by maxRetryLedger (oldest entries are dropped and
// stay visible only in the error logs — durable reconciliation is the recorded
// owner follow-up).
func (h *Handler) noteReapRetry(sha256 string) {
	h.noteRetry(&h.reapRetries, sha256)
}

// noteRetentionRetry records a blob key whose WORM ApplyAll failed after a
// successful upload (bounded like noteReapRetry).
func (h *Handler) noteRetentionRetry(key string) {
	h.noteRetry(&h.retentionRetries, key)
}

// retryFailedReaps re-runs MinIO removal for blobs whose guarded row delete
// already committed but whose RemoveObject failed on a previous tick. The
// blobs row is already gone at this point, so the storage removal is
// unconditional — the row's absence IS the B3 guard.
func (h *Handler) retryFailedReaps(ctx context.Context) {
	h.retryMu.Lock()
	pending := make([]string, 0, len(h.reapRetries))
	for sha := range h.reapRetries {
		pending = append(pending, sha)
	}
	h.retryMu.Unlock()

	for _, sha := range pending {
		// Re-check the live table: if the blob somehow exists again (re-upload of
		// the same content), the object is live again — drop the ledger entry and
		// let the normal ref_count-driven lifecycle own it.
		var gone bool
		if err := h.workerPool.QueryRow(ctx,
			`SELECT NOT EXISTS (SELECT 1 FROM blobs WHERE sha256 = $1)`, sha,
		).Scan(&gone); err != nil || !gone {
			if err != nil {
				h.logger.Warn("blob cleanup retry: existence re-check failed — will retry next tick", "sha256", sha, "error", err)
				continue
			}
			h.retryMu.Lock()
			delete(h.reapRetries, sha)
			h.retryMu.Unlock()
			continue
		}
		if err := h.minio.RemoveObject(ctx, h.bucket, sha, minio.RemoveObjectOptions{}); err != nil {
			h.logger.Warn("blob cleanup retry: minio remove still failing", "sha256", sha, "error", err)
			continue
		}
		h.retryMu.Lock()
		delete(h.reapRetries, sha)
		h.retryMu.Unlock()
		h.logger.Info("blob cleanup retry: removed previously orphaned blob", "sha256", sha)
	}
}

// retryFailedRetention re-applies WORM policies for uploads whose ApplyAll
// failed when they were written (the drive plane's worm-pending retry, in
// memory — the blob plane has no worm_pending column to piggyback on).
func (h *Handler) retryFailedRetention(ctx context.Context) {
	if h.retentionRegistry == nil {
		return
	}
	h.retryMu.Lock()
	pending := make([]string, 0, len(h.retentionRetries))
	for key := range h.retentionRetries {
		pending = append(pending, key)
	}
	h.retryMu.Unlock()

	for _, key := range pending {
		if err := h.retentionRegistry.ApplyAll(ctx, key); err != nil {
			h.logger.Warn("blob retention retry: apply still failing", "key", key, "error", err)
			continue
		}
		h.retryMu.Lock()
		delete(h.retentionRetries, key)
		h.retryMu.Unlock()
		h.logger.Info("blob retention retry: WORM policy applied on retry", "key", key)
	}
}

func (h *Handler) processCleanupQueue(ctx context.Context) {
	for _, sha256 := range h.cleanupCandidates(ctx) {
		h.reapCleanupCandidate(ctx, sha256)
	}
}

// cleanupCandidates snapshots the due, apparently-unreferenced blobs. This is
// only a snapshot: an attach (message_attachments INSERT → the V075 AFTER
// INSERT trigger) can bump a candidate's ref_count 0→1 any time after this
// scan returns. reapCleanupCandidate re-checks atomically before touching
// anything, so a stale candidate here is harmless.
func (h *Handler) cleanupCandidates(ctx context.Context) []string {
	rows, err := h.pool.Query(ctx,
		`SELECT q.blob_sha256 FROM blob_cleanup_queue q
		 JOIN blobs b ON b.sha256 = q.blob_sha256
		 WHERE q.scheduled_at + make_interval(mins => q.delay_minutes) < now()
		   AND b.ref_count = 0`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var sha256 string
		if err := rows.Scan(&sha256); err != nil {
			continue
		}
		out = append(out, sha256)
	}
	return out
}

// reapCleanupCandidate is the atomic re-check + delete: DELETE ... WHERE
// ref_count = 0 gates the row delete AND the MinIO removal on the SAME
// up-to-the-instant read, closing the race cleanupCandidates' snapshot can't
// (B3: an attach committing between the candidate scan and here used to lose
// the file — RemoveObject ran unconditionally on a stale ref_count=0 read,
// and the blobs row was never deleted either).
//
// message_attachments.blob_sha256 FKs to blobs(sha256), so an in-flight
// attach's FK check holds a row lock this DELETE contends with: whichever
// commits first wins, and the loser either finds RowsAffected()==0 (attach
// won — ref_count is no longer 0, nothing to do here) or its own FK check
// fails loudly (this DELETE won — no silent data loss either way).
//
// blob_cleanup_queue's FK to blobs is ON DELETE CASCADE, so a successful
// delete here also drops the queue row; a lost race leaves the queue row in
// place, which is correct — trg_blob_refcount_zero re-arms it (bumps
// scheduled_at) the next time ref_count actually reaches 0.
func (h *Handler) reapCleanupCandidate(ctx context.Context, sha256 string) {
	tag, err := h.pool.Exec(ctx, `DELETE FROM blobs WHERE sha256 = $1 AND ref_count = 0`, sha256)
	if err != nil {
		h.logger.Error("blob cleanup: row delete failed", "sha256", sha256, "error", err)
		return
	}
	if tag.RowsAffected() == 0 {
		// Raced: something attached this blob since the candidate scan. Still
		// referenced — leave the bytes and the row alone.
		return
	}
	if err := h.minio.RemoveObject(ctx, h.bucket, sha256, minio.RemoveObjectOptions{}); err != nil {
		h.logger.Error("blob cleanup: minio remove failed", "sha256", sha256, "error", err)
		// The guarded row delete already committed (and CASCADEd the queue row),
		// so a plain return would orphan the bytes forever. Record the key for
		// the cleanup tick's bounded retry (D-MAILSERVER-INTERNAL-BLOB-005).
		h.noteReapRetry(sha256)
		return
	}
	h.logger.Info("blob cleanup: removed orphaned blob", "sha256", sha256)
}

// processOrphanedBlobs drains orphaned_message_blobs — the sibling queue to
// blob_cleanup_queue for message RAW BODIES. Every purge path (IMAP
// EXPUNGE/CLOSE via jmap_email_purge, JMAP Email/purge, the purge_deleted_
// messages cron, the S/MIME re-sign swap in jmap_email_submission.sql) queues
// an unshared messages.raw_ref here, but nothing used to read the table: rows
// piled up forever and the SeaweedFS objects they named were never reclaimed.
// Runs on the same 5-minute ticker as processCleanupQueue — no new goroutine,
// no new schedule (see StartCleanup).
//
// raw_ref is NOT a uniform content-addressed key the way blob_cleanup_queue's
// blob_sha256 is: reducer-built drafts pass the INLINE RFC 5322 message text
// (always contains a line break) straight into this table, and that must NEVER
// reach RemoveObject. IsInlineMessage is the one discriminator every raw_ref
// consumer routes through — skip those rows for storage purposes, just drop
// the (harmless, non-leaking) queue row. Real keys ("inbound/<sha>",
// "blobs/<sha>", bare sha256, sentinels like "system:welcome:<uid>", …) are
// deleted by the exact raw_ref string, which IS the MinIO object key for that
// family — unlike attachment blobs, always keyed by bare sha256.
//
// Double-delete safety: some producers content-address raw_ref by SHA-256, so
// a brand-new message can legitimately recreate a key that is sitting in this
// queue from an older, already-hard-deleted message (the insert-time dedup
// check in each purge path only sees the world as of that transaction). Mirror
// processCleanupQueue's guard (a check against the live table at drain time,
// not a held row lock — the same tolerance already accepted for
// blob_cleanup_queue's ref_count race): re-verify no messages row still
// references it before touching storage. If one does, the entry is no longer
// orphaned — drop the queue row and leave the object alone.
func (h *Handler) processOrphanedBlobs(ctx context.Context) {
	rows, err := h.workerPool.Query(ctx, `SELECT raw_ref FROM orphaned_message_blobs`)
	if err != nil {
		return
	}
	var refs []string
	for rows.Next() {
		var ref string
		if err := rows.Scan(&ref); err != nil {
			continue
		}
		refs = append(refs, ref)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return
	}

	for _, ref := range refs {
		if !IsInlineMessage(ref) {
			var stillOrphaned bool
			if err := h.workerPool.QueryRow(ctx,
				`SELECT NOT EXISTS (SELECT 1 FROM messages WHERE raw_ref = $1)`, ref,
			).Scan(&stillOrphaned); err != nil {
				continue // leave the row queued; retry next tick
			}
			if stillOrphaned {
				if err := h.minio.RemoveObject(ctx, h.bucket, ref, minio.RemoveObjectOptions{}); err != nil {
					h.logger.Warn("orphaned blob cleanup: remove failed", "raw_ref", ref, "error", err)
					continue
				}
				h.logger.Info("orphaned blob cleanup: removed raw message blob", "raw_ref", ref)
			}
			// else: a new message re-created this key — no leak, nothing to delete.
		}
		// Inline refs were never a real object; either way the row is done.
		if _, err := h.workerPool.Exec(ctx, `DELETE FROM orphaned_message_blobs WHERE raw_ref = $1`, ref); err != nil {
			h.logger.Warn("orphaned blob cleanup: dequeue failed", "raw_ref", ref, "error", err)
		}
	}
}

// Get streams an attachment from MinIO to the client.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	blobHash := r.PathValue("sha256")
	if blobHash == "" {
		http.Error(w, "missing blob ID", http.StatusBadRequest)
		return
	}

	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var owned bool
	// native-RLS: cross-mailbox-for-one-user ownership check on the BYPASSRLS
	// worker pool (see the workerPool field doc). R1-scoped by mb.user_id.
	//
	// C5: HR expense-receipt evidence blobs are NOT message_attachments rows —
	// NewHrRequestDialog.svelte PUTs the receipt straight to /blobs during the
	// expense form, never attaching it to any message — so the first EXISTS
	// alone 404s the download for every caller, including the assigned
	// approver reviewing HrEvidence.svelte's evidence link and the requester
	// who submitted it. The second EXISTS mirrors approval_requests_row_
	// visibility (V070's RLS policy on approval_requests): the requester, the
	// resolved single-user approver, an active role-group approver member, or
	// an ACTIVE SUPER ADMIN (the policy's inline admin_is_super third branch:
	// role_group_id=1, non-expired, admin_assignment_active) may fetch a
	// receipt blob linked to their request via hr_expense_receipts. The Super
	// Admin branch was previously missing here — a Go-side drift from the
	// policy that 404'd exactly the callers the RLS policy admits
	// (D-MAILSERVER-INTERNAL-BLOB-003); keep the two predicates in lockstep.
	if err := h.workerPool.QueryRow(r.Context(),
		`SELECT EXISTS (
			SELECT 1 FROM message_attachments ma
			JOIN messages m ON m.id = ma.message_id AND m.received_at = ma.received_at
			JOIN mailboxes mb ON mb.id = m.mailbox_id
			WHERE ma.blob_sha256 = $1 AND mb.user_id = $2
		) OR EXISTS (
			SELECT 1 FROM hr_expense_receipts her
			JOIN approval_requests ar ON ar.id = her.approval_request_id
			WHERE her.blob_sha256 = $1
			  AND (
				ar.requester_user_id = $2
				OR (ar.approver_kind = 'user' AND ar.approver_ref = $2)
				OR (ar.approver_kind = 'role_group' AND EXISTS (
					SELECT 1 FROM admin_role_assignments ara
					 WHERE ara.role_group_id = ar.approver_ref
					   AND ara.user_id = $2
					   AND (ara.expires_at IS NULL OR ara.expires_at > now())
					   AND admin_assignment_active(ara.eligible, ara.activated_until)
				))
				OR EXISTS (
					SELECT 1 FROM admin_role_assignments sa
					 WHERE sa.role_group_id = 1
					   AND sa.user_id = $2
					   AND (sa.expires_at IS NULL OR sa.expires_at > now())
					   AND admin_assignment_active(sa.eligible, sa.activated_until)
				)
			  )
		)`, blobHash, claims.UserID,
	).Scan(&owned); err != nil {
		h.logger.Error("blob ownership check failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !owned {
		http.Error(w, "blob not found", http.StatusNotFound)
		return
	}

	h.cacheMu.Lock()
	if cached, ok := h.cache[blobHash]; ok && time.Now().Before(cached.expiresAt) {
		h.cacheMu.Unlock()
		w.Header().Set("Content-Type", cached.contentType)
		// G705: blob bytes + their stored Content-Type are attacker-supplied at
		// upload; nosniff + a sandbox CSP stop a correctly-typed text/html/svg
		// blob from executing as a top-level document in the app origin.
		httputil.SetUntrustedBlobHeaders(w)
		// http.ServeContent (not a flat w.Write) so a cache-hit honors Range the
		// same way the cache-miss path below does — see writeBlobContent.
		http.ServeContent(w, r, blobHash, time.Time{}, bytes.NewReader(cached.data))
		return
	}
	h.cacheMu.Unlock()

	// Always fetch unranged. writeBlobContent (below) honors any client Range
	// itself via http.ServeContent, which Seeks the *minio.Object to the
	// requested offset — that re-issues a ranged GetObject to MinIO under the
	// hood. Forwarding the Range header here too (the pre-fix behavior) made
	// info.Size reflect only the partial length and left the response to the
	// client at the default 200 with no Content-Range, corrupting resuming
	// downloads (review B4).
	obj, err := h.minio.GetObject(r.Context(), h.bucket, blobHash, minio.GetObjectOptions{})
	if err != nil {
		h.logger.Error("minio get failed", "key", blobHash, "error", err)
		http.Error(w, "blob not found", http.StatusNotFound)
		return
	}
	defer func() { _ = obj.Close() }()

	info, err := obj.Stat()
	if err != nil {
		http.Error(w, "blob not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", info.ContentType)
	// G705: see cache-hit path — nosniff + a sandbox CSP keep the attacker-
	// supplied blob bytes/Content-Type from executing as active content (sniffed
	// or correctly-typed as a top-level document) in the app origin.
	httputil.SetUntrustedBlobHeaders(w)

	h.writeBlobContent(w, r, blobHash, obj, info)
}

// writeBlobContent streams the blob body to w. A small, non-ranged object is
// buffered once and cached (see the in-memory cache above the caller); every
// other request — including any byte-range request — streams via
// http.ServeContent, which parses the Range header itself and replies with
// 206 + Content-Range (or 200 whole-file) and the matching Content-Length.
// obj must be an io.ReadSeeker; *minio.Object satisfies this by re-issuing a
// ranged GetObject to MinIO on Seek, so a range request never buffers the
// whole object in memory.
func (h *Handler) writeBlobContent(w http.ResponseWriter, r *http.Request, blobHash string, obj io.ReadSeeker, info minio.ObjectInfo) {
	if r.Header.Get("Range") == "" && info.Size > 0 && info.Size < maxCacheSize {
		buf := make([]byte, info.Size)
		if n, err := io.ReadFull(obj, buf); err == nil && int64(n) == info.Size {
			h.cacheMu.Lock()
			for h.cacheBytes+info.Size > maxCacheBytes && len(h.cache) > 0 {
				var oldestK string
				var oldestT time.Time
				for k, v := range h.cache {
					if oldestK == "" || v.expiresAt.Before(oldestT) {
						oldestK = k
						oldestT = v.expiresAt
					}
				}
				h.cacheBytes -= int64(len(h.cache[oldestK].data))
				delete(h.cache, oldestK)
			}
			h.cache[blobHash] = cachedBlob{
				data:        buf,
				contentType: info.ContentType,
				expiresAt:   time.Now().Add(maxCacheTTL),
			}
			h.cacheBytes += info.Size
			h.cacheMu.Unlock()
			w.Header().Set("Content-Length", strconv.FormatInt(info.Size, 10))
			w.Write(buf) //nolint:gosec // G705: nosniff set by the caller; blob is content-addressed bytes served with its stored Content-Type
			return
		}
	}

	http.ServeContent(w, r, blobHash, info.LastModified, obj)
}

// Put stores an uploaded attachment in MinIO under its SHA-256 key.
// The caller must have computed the SHA-256 of the content and set it in the URL.
// Content deduplication is automatic: the canonical key holds identical bytes.
//
// SECURITY: the request body is streamed to a RANDOM temp key while hashing,
// verified, then promoted to the canonical (client-supplied) key via CopyObject.
// We never PutObject/RemoveObject the canonical key directly — otherwise any
// authenticated user could destroy another tenant's content-addressed (cross-
// tenant deduped) blob just by PUTting a mismatched body under its known SHA.
//
// Ordering (D-MAILSERVER-INTERNAL-BLOB-002): the DB bookkeeping — blob row,
// PUT-time reclamation arming (grace window), per-user byte accounting and its
// bound enforcement — commits BEFORE the canonical promote, so a rejected or
// failed upload never persists bytes; see the transaction comment below.
func (h *Handler) Put(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	blobHash := r.PathValue("sha256")
	if !blobHashRe.MatchString(blobHash) {
		http.Error(w, "invalid blob ID", http.StatusBadRequest)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 100<<20) // 100 MiB

	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	hasher := sha256.New()
	// counted streams the same bytes into the hash AND the measured-size
	// counter: r.ContentLength is negative for chunked uploads, so accounting
	// must charge what was actually read, not a zero-size fallback
	// (D-MAILSERVER-INTERNAL-BLOB-002).
	counter := &byteCounter{}
	body := io.TeeReader(r.Body, io.MultiWriter(hasher, counter))

	tempKey := "tmp/upload/" + randomHex(16)
	if _, err := h.minio.PutObject(
		r.Context(), h.bucket, tempKey, body, r.ContentLength,
		minio.PutObjectOptions{ContentType: contentType},
	); err != nil {
		h.logger.Error("minio put failed", "key", tempKey, "error", err)
		http.Error(w, "upload failed", http.StatusInternalServerError)
		return
	}

	computed := hex.EncodeToString(hasher.Sum(nil))
	if computed != blobHash {
		_ = h.minio.RemoveObject(r.Context(), h.bucket, tempKey, minio.RemoveObjectOptions{})
		h.logger.Warn("blob hash mismatch", "expected", blobHash, "computed", computed)
		http.Error(w, "sha256 mismatch", http.StatusBadRequest)
		return
	}

	// DB bookkeeping (blob row + reclamation arming + per-user accounting) runs
	// as ONE transaction, BEFORE the temp→canonical promote below: a rejected
	// or failed upload must never leave bytes at the canonical key, and the
	// canonical key itself must never be removed here — it is shared
	// deduplicated content (see the SECURITY note above). A promote that fails
	// after this commit leaves a ref_count=0 row that the reclamation entry
	// armed in this same transaction heals after the grace window.
	//
	// The transition itself is REDUCER-OWNED (med-blob-reclamation-001): Go is
	// the protocol translator — it binds p_user_id from the authenticated
	// claims (R2, never a request-owned field), the measured byte count from
	// the streamed body, and the configured policy — while the admission
	// decision, charge insertion, quota bound, and reclamation arming all
	// happen inside blob_upload_account (mailserver/sql/reducers/) in this one
	// transaction. Over-bound admission raises BZ001 (HINT over_quota), which
	// rolls the whole transaction back: no blobs row, no charge, no arming.
	measured := counter.n
	if err := dbscope.RunUserScoped(r.Context(), h.pool, user.UserID, func(tx pgx.Tx) error {
		var accounted string
		return tx.QueryRow(r.Context(),
			`SELECT blob_upload_account($1, $2, $3, $4, $5, $6, $7)`,
			user.UserID, blobHash, h.bucket+"/"+blobHash, measured, contentType,
			h.reclaimGrace(), h.userQuotaBytes,
		).Scan(&accounted)
	}); err != nil {
		_ = h.minio.RemoveObject(r.Context(), h.bucket, tempKey, minio.RemoveObjectOptions{})
		if reducererr.IsCode(err, "BZ001") {
			h.logger.Warn("blob upload rejected: per-user storage bound exceeded",
				"sha256", blobHash, "user_id", user.UserID, "bytes", measured)
			http.Error(w, "storage quota exceeded", http.StatusRequestEntityTooLarge)
			return
		}
		h.logger.Error("blob row insert failed", "sha256", blobHash, "error", err)
		http.Error(w, "upload failed", http.StatusInternalServerError)
		return
	}

	// Promote temp → canonical key (dedup-safe: overwriting with identical bytes
	// is a no-op if the canonical blob already exists), then drop the temp key.
	src := minio.CopySrcOptions{Bucket: h.bucket, Object: tempKey}
	dst := minio.CopyDestOptions{Bucket: h.bucket, Object: blobHash}
	if _, err := h.minio.CopyObject(r.Context(), dst, src); err != nil {
		_ = h.minio.RemoveObject(r.Context(), h.bucket, tempKey, minio.RemoveObjectOptions{})
		h.logger.Error("minio copy to hash key failed", "key", blobHash, "error", err)
		http.Error(w, "upload failed", http.StatusInternalServerError)
		return
	}
	if err := h.minio.RemoveObject(r.Context(), h.bucket, tempKey, minio.RemoveObjectOptions{}); err != nil {
		h.logger.Warn("temporary blob cleanup failed", "key", tempKey, "error", err)
	}

	// Apply retention policies (WORM immutability) after successful write.
	if h.retentionRegistry != nil {
		if err := h.retentionRegistry.ApplyAll(r.Context(), blobHash); err != nil {
			h.logger.Error("retention policy apply failed", "key", blobHash, "error", err)
			// Non-fatal: the blob is stored but retention was not applied.
			// The object can be re-locked by the admin or via the verify-worm.sh script.
			// Queue the key for the cleanup tick's bounded retry so the failure is
			// not silently permanent (D-MAILSERVER-INTERNAL-BLOB-006).
			h.noteRetentionRetry(blobHash)
		}
	}

	w.WriteHeader(http.StatusCreated)
}

// randomHex returns 2n lowercase hex chars from crypto/rand for temp-key names.
func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b) //nolint:errcheck // crypto/rand.Read never returns a short read/error on these platforms
	return hex.EncodeToString(b)
}
