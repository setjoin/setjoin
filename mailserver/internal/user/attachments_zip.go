package user

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/pgxutil"
)

// blobGetter fetches a blob's bytes by content-addressed key. In production it
// wraps minioClient.GetObject (whose *minio.Object is an io.ReadCloser); the
// test injects a fake returning canned bytes. It is a func seam rather than an
// interface returning *minio.Object because minio.Object has no public
// constructor — an interface with that return type cannot be faked with real
// bytes, so the zip-contents path could never be unit-tested through it.
type blobGetter func(ctx context.Context, key string) (io.ReadCloser, error)

// AttachmentsZipHandler streams a zip of all non-inline attachments on a message
// the authenticated user owns: GET /messages/{id}/attachments.zip.
type AttachmentsZipHandler struct {
	// getBlob resolves a blob key to its bytes (production: MinIO/SeaweedFS).
	getBlob blobGetter
	// workerPool is the setjoin_worker (BYPASSRLS) pool. The ownership read keys
	// on mb.user_id ACROSS all the user's mailboxes (the message may live in any
	// of them), the admin-case treatment for a cross-mailbox-for-one-user read
	// (R1-scoped by mb.user_id). workerPool aliases pool until DB_WORKER_DSN is
	// set (W1b), so this is INERT.
	workerPool *pgxpool.Pool
	logger     *slog.Logger
}

// NewAttachmentsZipHandler wires the handler to a live MinIO client. The bucket
// is captured in the getBlob closure.
func NewAttachmentsZipHandler(m *minio.Client, workerPool pgxutil.WorkerPool, bucket string, logger *slog.Logger) *AttachmentsZipHandler {
	return &AttachmentsZipHandler{
		getBlob: func(ctx context.Context, key string) (io.ReadCloser, error) {
			return m.GetObject(ctx, bucket, key, minio.GetObjectOptions{})
		},
		workerPool: workerPool.Pool,
		logger:     logger,
	}
}

// DownloadAll streams a zip of the message's non-inline attachments. Ownership
// (R1/R4) and the attachment list come from a single bound read; mailbox_id and
// ownership are never taken from the request.
func (h *AttachmentsZipHandler) DownloadAll(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	msgID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || msgID <= 0 {
		httputil.WriteError(w, http.StatusBadRequest, "invalid message id")
		return
	}

	// Bound ownership read (R1/R4): the non-inline attachment list + the owning
	// subject in one statement, pinned to a mailbox the authenticated user owns.
	// message_attachments' FK into the partitioned messages table is
	// (message_id, received_at), so the join keys on BOTH id and received_at.
	rows, err := h.workerPool.Query(r.Context(),
		`SELECT ma.blob_sha256, COALESCE(ma.filename, 'attachment'), m.subject
		   FROM message_attachments ma
		   JOIN messages m   ON m.id = ma.message_id AND m.received_at = ma.received_at
		   JOIN mailboxes mb ON mb.id = m.mailbox_id
		  WHERE m.id = $1 AND mb.user_id = $2 AND ma.disposition <> 'inline'
		  ORDER BY ma.id`,
		msgID, u.UserID,
	)
	if err != nil {
		h.logger.Error("attachments zip ownership query failed", "message_id", msgID, "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	type attachment struct {
		sha  string
		name string
	}
	var atts []attachment
	var subject string
	first := true
	for rows.Next() {
		var a attachment
		var subj *string
		if err := rows.Scan(&a.sha, &a.name, &subj); err != nil {
			h.logger.Error("attachments zip scan failed", "message_id", msgID, "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "database error")
			return
		}
		if first {
			if subj != nil {
				subject = *subj
			}
			first = false
		}
		atts = append(atts, a)
	}
	if err := rows.Err(); err != nil {
		h.logger.Error("attachments zip row iteration failed", "message_id", msgID, "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	// Zero rows → not owned OR nothing to zip. Safely indistinguishable: a 404
	// leaks nothing about whether the message exists in another user's mailbox.
	if len(atts) == 0 {
		httputil.WriteError(w, http.StatusNotFound, "no attachments")
		return
	}

	// Commit to 200 + stream: a streamed zip has no Content-Length.
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-attachments.zip"`, sanitizeFilename(subject)))
	w.Header().Set("X-Content-Type-Options", "nosniff")

	zw := zip.NewWriter(w)
	defer zw.Close()

	seen := map[string]int{}
	for _, a := range atts {
		// sanitizeFilename neutralises path separators / traversal in the
		// sender-controlled filename before it becomes a zip entry name (zip-slip
		// hygiene); dedupe disambiguates two attachments sharing a name.
		name := dedupeZipName(seen, sanitizeFilename(a.name))
		fw, err := zw.Create(name)
		if err != nil {
			h.logger.Warn("attachments zip create entry failed", "message_id", msgID, "name", name, "error", err)
			continue
		}
		obj, err := h.getBlob(r.Context(), a.sha)
		if err != nil {
			// Skip a missing blob rather than abort the whole zip (mirror the admin
			// export). The zip still delivers every attachment that resolves.
			h.logger.Warn("attachments zip blob fetch failed", "message_id", msgID, "sha", a.sha, "error", err)
			continue
		}
		if _, err := io.Copy(fw, obj); err != nil {
			h.logger.Warn("attachments zip stream interrupted", "message_id", msgID, "sha", a.sha, "error", err)
		}
		obj.Close()
	}
}

// dedupeZipName returns a zip-entry name unique within seen, inserting -2/-3/…
// before the extension on collision (two attachments can share a filename).
func dedupeZipName(seen map[string]int, name string) string {
	n := seen[name]
	seen[name] = n + 1
	if n == 0 {
		return name
	}
	ext := path.Ext(name)
	return fmt.Sprintf("%s-%d%s", name[:len(name)-len(ext)], n+1, ext)
}
