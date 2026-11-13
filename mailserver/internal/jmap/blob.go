package jmap

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/minio/minio-go/v7"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/identity"
	"setjoin.com/shared/reducererr"
)

// Blob JMAP methods (RFC 9404)

// blobGet returns metadata for blobs by id.
func (h *JMAPHandler) blobGet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID  string   `json:"accountId"`
		Ids        []string `json:"ids"`
		Properties []string `json:"properties,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", "")
	}
	if len(req.Ids) == 0 {
		// The accountId is client-controlled: JSON-encode it via mustMarshal
		// instead of concatenating it into a raw literal, which would let a
		// crafted value inject JSON structure into the method response.
		return "Blob/get", mustMarshal(map[string]any{
			"list":      []any{},
			"notFound":  []any{},
			"accountId": req.AccountID,
		})
	}
	if len(req.Ids) > 256 {
		return "Blob/get", mustMarshal(map[string]any{
			"list":      []any{},
			"notFound":  []any{},
			"accountId": req.AccountID,
		})
	}

	// Ownership check: only return blobs attached to a message in a mailbox
	// owned by this user. Orphan blobs (uploaded but not yet attached to any
	// message) are invisible here — they have no ownership link.
	//
	// native-RLS (W7): this keys on mb.user_id ACROSS all the user's mailboxes (a
	// content-addressed blob may be attached in ANY of them), so it does NOT fit
	// one app.current_mailbox_id GUC. It runs on the BYPASSRLS worker pool — the
	// admin-case treatment for a cross-mailbox-for-one-user read; R1-scoped by
	// mb.user_id. workerPool aliases pool until DB_WORKER_DSN is set (INERT).
	rows, err := h.workerPool.Query(ctx,
		`SELECT DISTINCT b.sha256, b.size_bytes, b.content_type
		 FROM blobs b
		 INNER JOIN message_attachments ma ON ma.blob_sha256 = b.sha256
		 INNER JOIN messages m ON m.id = ma.message_id
		 INNER JOIN mailboxes mb ON mb.id = m.mailbox_id
		 WHERE b.sha256 = ANY($1)
		   AND mb.user_id = $2`,
		req.Ids, user.UserID,
	)
	if err != nil {
		h.logger.Error("blobGet query failed", "error", err)
		return methodError("serverFail", "")
	}
	defer rows.Close()

	type blobInfo struct {
		ID          string `json:"id"`
		BlobID      string `json:"blobId"`
		Size        int64  `json:"size"`
		ContentType string `json:"contentType"`
		AccountID   string `json:"accountId"`
	}
	found := map[string]blobInfo{}
	for rows.Next() {
		var id string
		var size int64
		var ct *string
		contentType := "application/octet-stream"
		if err := rows.Scan(&id, &size, &ct); err != nil {
			continue
		}
		if ct != nil && *ct != "" {
			contentType = *ct
		}
		found[id] = blobInfo{
			ID:          id,
			BlobID:      id,
			Size:        size,
			ContentType: contentType,
			AccountID:   req.AccountID,
		}
	}

	list := make([]blobInfo, 0, len(found))
	notFound := make([]string, 0)
	for _, id := range req.Ids {
		if b, ok := found[id]; ok {
			list = append(list, b)
		} else {
			notFound = append(notFound, id)
		}
	}

	result := map[string]interface{}{
		"accountId": req.AccountID,
		"state":     encodeStateToken(0), // blobs are immutable: state never advances
		"list":      list,
		"notFound":  notFound,
	}
	return "Blob/get", mustMarshal(result)
}

// blobCopy copies blobs between accounts. Since blobs are content-addressed and
// immutable, this is essentially an existence check — no data is transferred.
func (h *JMAPHandler) blobCopy(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		FromAccountID string   `json:"fromAccountId"`
		ToAccountID   string   `json:"toAccountId"`
		Ids           []string `json:"ids"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", "")
	}
	if len(req.Ids) == 0 || len(req.Ids) > 256 {
		return "Blob/copy", mustMarshal(map[string]interface{}{
			"fromAccountId": req.FromAccountID,
			"toAccountId":   req.ToAccountID,
			"list":          []interface{}{},
			"notCopied":     []interface{}{},
		})
	}

	// Ownership check: only copy blobs the user already owns (attached to a
	// message in a mailbox they own). Orphan blobs are not copyable.
	// native-RLS (W7): cross-mailbox-for-one-user read on the BYPASSRLS worker
	// pool (see blobGet); R1-scoped by mb.user_id.
	rows, err := h.workerPool.Query(ctx,
		`SELECT DISTINCT b.sha256
		 FROM blobs b
		 INNER JOIN message_attachments ma ON ma.blob_sha256 = b.sha256
		 INNER JOIN messages m ON m.id = ma.message_id
		 INNER JOIN mailboxes mb ON mb.id = m.mailbox_id
		 WHERE b.sha256 = ANY($1)
		   AND mb.user_id = $2`,
		req.Ids, user.UserID,
	)
	if err != nil {
		h.logger.Error("blobCopy query failed", "error", err)
		return methodError("serverFail", "")
	}
	defer rows.Close()

	existing := map[string]bool{}
	for rows.Next() {
		var id string
		rows.Scan(&id)
		existing[id] = true
	}

	list := make([]map[string]string, 0, len(existing))
	notCopied := make([]map[string]interface{}, 0)
	for _, id := range req.Ids {
		if existing[id] {
			list = append(list, map[string]string{"id": id, "blobId": id, "type": "application/octet-stream"})
		} else {
			notCopied = append(notCopied, map[string]interface{}{
				"id":          id,
				"type":        "blobNotFound",
				"description": "blob not found",
			})
		}
	}

	result := map[string]interface{}{
		"fromAccountId": req.FromAccountID,
		"toAccountId":   req.ToAccountID,
		"list":          list,
		"notCopied":     notCopied,
	}
	return "Blob/copy", mustMarshal(result)
}

// blobLookup maps per-type content hashes to blob IDs.
func (h *JMAPHandler) blobLookup(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string   `json:"accountId"`
		TypeNames []string `json:"typeNames,omitempty"`
		Hashes    []string `json:"hashes,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", "")
	}

	if len(req.Hashes) > 0 {
		// Ownership check: only resolve hashes for blobs attached to a
		// message in a mailbox owned by this user. Orphan blobs are not visible.
		// native-RLS (W7): cross-mailbox-for-one-user read on the BYPASSRLS worker
		// pool (see blobGet); R1-scoped by mb.user_id.
		rows, err := h.workerPool.Query(ctx,
			`SELECT DISTINCT b.sha256, b.content_type
			 FROM blobs b
			 INNER JOIN message_attachments ma ON ma.blob_sha256 = b.sha256
			 INNER JOIN messages m ON m.id = ma.message_id
			 INNER JOIN mailboxes mb ON mb.id = m.mailbox_id
			 WHERE b.sha256 = ANY($1)
			   AND mb.user_id = $2`,
			req.Hashes, user.UserID,
		)
		if err != nil {
			h.logger.Error("blobLookup query failed", "error", err)
			return methodError("serverFail", "")
		}
		defer rows.Close()

		matched := map[string]string{}
		for rows.Next() {
			var id string
			var ct *string
			rows.Scan(&id, &ct)
			matched[id] = id
		}

		listed := make([]map[string]interface{}, 0, len(matched))
		for _, h := range req.Hashes {
			if blobID, ok := matched[h]; ok {
				listed = append(listed, map[string]interface{}{
					"hash":   h,
					"blobId": blobID,
				})
			}
		}

		result := map[string]interface{}{
			"accountId": req.AccountID,
			"list":      listed,
		}
		return "Blob/lookup", mustMarshal(result)
	}

	return "Blob/lookup", mustMarshal(map[string]interface{}{
		"accountId": req.AccountID,
		"list":      []interface{}{},
	})
}

// jmapUploadBodyCap resolves the upload admission cap: the configured JMAP
// maxSizeUpload when wired, else the legacy 100 MiB ceiling (zero-value
// Handlers — unit tests). Every upload body is bounded BEFORE streaming.
func jmapUploadBodyCap(maxUploadSize int) int64 {
	if maxUploadSize > 0 {
		return int64(maxUploadSize)
	}
	return 100 << 20
}

// uploadByteCounter counts the bytes actually streamed through an upload body,
// so accounting charges the measured size rather than a request-asserted or
// zero-size fallback (the blob gateway's measured-bytes rule, D-...-BLOB-002).
type uploadByteCounter struct{ n int64 }

func (c *uploadByteCounter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

// accountUpload runs the upload's DB bookkeeping through the shared
// blob_upload_account reducer (med-blob-reclamation-001) in ONE transaction:
// admission (blobs row at ref_count=0 — an upload is NOT yet a reference),
// the per-user byte charge (blob_user_charges → blob_user_usage; this is also
// the upload-ownership evidence Email/set's attachment gate keys on), the
// per-user quota bound (enforced once main wires SetReclamationPolicy —
// er6 residual rollup on occ_2ee199; zero-value Handlers keep it OFF), and
// reclamation arming (blob_cleanup_queue)
// so an uploaded-but-never-attached blob is reclaimed after the grace window
// instead of persisting forever (er5-s11, sealed anchor
// jmap-uploads-create-permanent-positive-blob-references...). p_user_id is
// bound from the authenticated claims (R2), never a request field; the
// previously-inlined INSERT (ref_count=1 + ON CONFLICT bump) was both an
// unearned permanent reference and an uncharged unowned write.
func (h *JMAPHandler) accountUpload(ctx context.Context, userID int64, blobID string, measured int64, contentType string) error {
	var accounted string
	return dbscope.RunUserScoped(ctx, h.pool, userID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT blob_upload_account($1, $2, $3, $4, $5, $6, $7)`,
			userID, blobID, h.bucket+"/"+blobID, measured, contentType,
			h.reclaimGrace(), h.userQuotaBytes,
		).Scan(&accounted)
	})
}

// Upload handles POST /jmap/upload/{accountId} (RFC 9404 §5).
// Accepts blobs by file and returns the blobId (SHA-256).
func (h *JMAPHandler) Upload(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		WriteProblem(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}

	accountIDStr := r.PathValue("accountId")
	if accountIDStr == "" {
		WriteProblem(w, http.StatusBadRequest, "invalidArguments", "missing accountId")
		return
	}
	accountID, err := strconv.ParseInt(accountIDStr, 10, 64)
	if err != nil || accountID <= 0 {
		WriteProblem(w, http.StatusBadRequest, "accountNotFound", "invalid accountId")
		return
	}

	// The upload accountId must be the caller's PRIMARY mailbox id (ARCH-003)
	// or a MAIL-delegated shared mailbox (#13 — compose-in-shared-context
	// attachments upload under the shared accountId). Uploading only stores a
	// content-addressed blob; attaching it to mail is gated per-method.
	own, grants, err := identity.ValidateAccountID(r.Context(), h.pool, accountID, user.UserID, h.delegateGrants)
	if err != nil || (!own && !gateRead.allows(grants)) {
		WriteProblem(w, http.StatusForbidden, "accountNotFound", "account not found")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, jmapUploadBodyCap(h.maxUploadSize))

	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	// Stream to temp key while computing SHA-256 AND the measured byte count,
	// then move to the final key.
	hasher := sha256.New()
	counter := &uploadByteCounter{}
	tee := io.TeeReader(r.Body, io.MultiWriter(hasher, counter))

	tempKey := "tmp/upload/" + genRandomHex(16)
	_, err = h.minio.PutObject(
		r.Context(), h.bucket, tempKey,
		tee, r.ContentLength,
		minio.PutObjectOptions{ContentType: contentType},
	)
	if err != nil {
		h.logger.Error("jmap upload failed", "error", err)
		WriteProblem(w, http.StatusInternalServerError, "serverFail", "upload failed")
		return
	}

	blobID := hex.EncodeToString(hasher.Sum(nil))
	measured := counter.n

	// DB bookkeeping commits BEFORE the temp→canonical promote (the blob
	// gateway's ordering): a rejected or failed upload must never persist
	// bytes, and a failed promote leaves a ref_count=0 row the reclamation
	// arming written in the same transaction heals after the grace window.
	// Over-quota admission raises BZ001 → 413, nothing stored.
	if err := h.accountUpload(r.Context(), user.UserID, blobID, measured, contentType); err != nil {
		_ = h.minio.RemoveObject(r.Context(), h.bucket, tempKey, minio.RemoveObjectOptions{})
		if reducererr.IsCode(err, "BZ001") {
			h.logger.Warn("jmap upload rejected: per-user storage bound exceeded",
				"blob_id", blobID, "user_id", user.UserID, "bytes", measured)
			WriteProblem(w, http.StatusRequestEntityTooLarge, "overQuota", "storage quota exceeded")
			return
		}
		h.logger.Error("jmap blob accounting failed", "blob_id", blobID, "error", err)
		WriteProblem(w, http.StatusInternalServerError, "serverFail", "upload failed")
		return
	}

	// Move from temp key to content-hash key (dedup-safe: no-op if exists).
	src := minio.CopySrcOptions{Bucket: h.bucket, Object: tempKey}
	dst := minio.CopyDestOptions{Bucket: h.bucket, Object: blobID}
	if _, err := h.minio.CopyObject(r.Context(), dst, src); err != nil {
		h.logger.Error("jmap copy to hash key failed", "error", err)
		h.minio.RemoveObject(r.Context(), h.bucket, tempKey, minio.RemoveObjectOptions{})
		WriteProblem(w, http.StatusInternalServerError, "serverFail", "upload failed")
		return
	}
	h.minio.RemoveObject(r.Context(), h.bucket, tempKey, minio.RemoveObjectOptions{})

	resp := map[string]interface{}{
		"accountId": accountIDStr,
		"blobId":    blobID,
		"type":      contentType,
		"size":      measured,
	}
	httputil.WriteJSON(w, http.StatusCreated, resp)
}

// blobDownloadAuthorized reports whether userID may download blobID: either
// they own a message referencing it (any of their own mailboxes — mirrors
// blobGet's cross-mailbox-for-one-user shape), OR (#13 shared-mailbox
// use-surface) accountIDStr names a mailbox they hold a MAIL delegate grant
// on (any grant level admits download — read|send_as|send_on_behalf|
// full_access — mirroring the gateRead check Upload already applies, a33c315c)
// and the blob is attached to a message IN THAT mailbox. An absent/invalid/
// own-primary accountId degrades to the own-mailbox-only check (delegatedMailboxID
// stays 0, which never matches a real mailboxes.id).
//
// Runs the ownership EXISTS check on the BYPASSRLS worker pool (native-RLS W7,
// same as blobGet); the delegate GRANT lookup itself still runs RLS-scoped via
// h.delegateGrants (dbscope.RunUserScoped) — the FORCE-RLS trap identity.go
// documents.
func (h *JMAPHandler) blobDownloadAuthorized(ctx context.Context, accountIDStr, blobID string, userID int64) bool {
	var delegatedMailboxID int64
	if accountID, err := strconv.ParseInt(accountIDStr, 10, 64); err == nil && accountID > 0 {
		own, grants, err := identity.ValidateAccountID(ctx, h.pool, accountID, userID, h.delegateGrants)
		if err == nil && !own && gateRead.allows(grants) {
			delegatedMailboxID = accountID
		}
	}

	var authorized bool
	h.workerPool.QueryRow(ctx,
		`SELECT EXISTS(
			SELECT 1 FROM message_attachments ma
			JOIN messages m ON m.id = ma.message_id
			JOIN mailboxes mb ON mb.id = m.mailbox_id
			WHERE ma.blob_sha256 = $1 AND (mb.user_id = $2 OR mb.id = $3)
		)`, blobID, userID, delegatedMailboxID,
	).Scan(&authorized)
	return authorized
}

// Download handles GET /jmap/download/{accountId}/{blobId}/{name}?type={type} (RFC 9404 §5.4).
func (h *JMAPHandler) Download(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		WriteProblem(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}

	blobID := r.PathValue("blobId")
	if blobID == "" {
		WriteProblem(w, http.StatusBadRequest, "invalidArguments", "missing blobId")
		return
	}

	var size int64
	var ct string
	err := h.pool.QueryRow(r.Context(),
		`SELECT size_bytes, COALESCE(content_type, 'application/octet-stream') FROM blobs WHERE sha256 = $1`,
		blobID,
	).Scan(&size, &ct)
	if err != nil {
		WriteProblem(w, http.StatusNotFound, "blobNotFound", "blob not found")
		return
	}

	if !h.blobDownloadAuthorized(r.Context(), r.PathValue("accountId"), blobID, user.UserID) {
		WriteProblem(w, http.StatusForbidden, "forbidden", "access denied")
		return
	}

	obj, err := h.minio.GetObject(r.Context(), h.bucket, blobID, minio.GetObjectOptions{})
	if err != nil {
		WriteProblem(w, http.StatusNotFound, "blobNotFound", "blob not found")
		return
	}
	defer obj.Close()
	info, err := obj.Stat()
	if err != nil || info.Size != size {
		WriteProblem(w, http.StatusNotFound, "blobNotFound", "blob not found")
		return
	}

	name := sanitizeFilename(r.PathValue("name"))
	disp := "inline"
	reqType := r.URL.Query().Get("type")
	if reqType == "application/octet-stream" {
		disp = "attachment"
	}

	serveImmutableBlob(w, r, obj, name, ct, disp, blobID)
}

func genRandomHex(n int) string {
	var buf [16]byte
	rand.Read(buf[:])
	return hex.EncodeToString(buf[:])[:n]
}

func mustMarshal(v interface{}) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}

// sanitizeFilename strips characters that could break a quoted-string in an
// HTTP header (double quotes, backslashes) and caps the length at 255 bytes.
func sanitizeFilename(name string) string {
	b := []byte(name)
	n := 0
	for i := 0; i < len(b); i++ {
		c := b[i]
		// Strip characters unsafe in a quoted-string per RFC 7230 section 3.2.6.
		if c == '"' || c == '\\' || c < 32 || c == 127 {
			continue
		}
		b[n] = c
		n++
	}
	if n > 255 {
		n = 255
	}
	return string(b[:n])
}
