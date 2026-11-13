package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/validate"
)

// MailboxesHandler provides admin CRUD for mailboxes and folders.
type MailboxesHandler struct {
	pool *pgxpool.Pool
	// workerPool is the setjoin_worker (BYPASSRLS) pool. Delete() fans out a
	// cross-tenant wipe of ANOTHER mailbox's messages / message_attachments
	// (DELETE … WHERE mailbox_id = $1) in a PLAIN tx with NO app.current_mailbox_id
	// — under the W6/V004 FORCE flip the app role's policy would deny/orphan those
	// deletes — so that tx runs on workerPool. workerPool aliases pool until
	// DB_WORKER_DSN is set (W1b), so this is INERT.
	workerPool *pgxpool.Pool
	logger     *slog.Logger
}

// NewMailboxesHandler creates an admin mailboxes handler.
func NewMailboxesHandler(pool *pgxpool.Pool, workerPool pgxutil.WorkerPool, logger *slog.Logger) *MailboxesHandler {
	return &MailboxesHandler{pool: pool, workerPool: workerPool.Pool, logger: logger}
}

type adminMailboxResponse struct {
	ID          int64     `json:"id"`
	UserID      *int64    `json:"userId"`
	UserEmail   string    `json:"userEmail"`
	Email       string    `json:"email"`
	DisplayName string    `json:"displayName"`
	Type        string    `json:"type"`
	IsPrimary   bool      `json:"isPrimary"`
	QuotaBytes  int64     `json:"quotaBytes"`
	UsedBytes   int64     `json:"usedBytes"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"createdAt"`
	DomainName  string    `json:"domainName"`
}

type adminFolderResponse struct {
	ID          int64  `json:"id"`
	MailboxID   int64  `json:"mailboxId"`
	Name        string `json:"name"`
	Role        string `json:"role"`
	Path        string `json:"path"`
	TotalCount  int64  `json:"totalCount"`
	UnreadCount int64  `json:"unreadCount"`
}

// List returns a paginated list of mailboxes (scoped to the admin's domain if applicable).
func (h *MailboxesHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query().Get("q")
	userIDStr := r.URL.Query().Get("user_id")
	limit, offset := httputil.ParseLimitOffset(r, 50, 100)

	domainScope := middleware.DomainScopeFromContext(ctx)
	selectCols := `SELECT m.id, m.user_id, COALESCE(u.email, ''), m.email, m.display_name, mailbox_effective_type(m.id), m.is_primary, m.quota_bytes, m.used_bytes, m.enabled, m.created_at, d.name
			 FROM mailboxes m LEFT JOIN users u ON u.id = m.user_id
			 JOIN domains d ON d.id = m.domain_id`

	var rows pgx.Rows
	var err error
	switch {
	case userIDStr != "":
		userID, _ := strconv.ParseInt(userIDStr, 10, 64)
		if domainScope > 0 {
			rows, err = h.pool.Query(ctx,
				selectCols+` WHERE m.user_id = $1 AND d.id = $2
				 ORDER BY m.id DESC LIMIT $3 OFFSET $4`,
				userID, domainScope, limit, offset)
		} else {
			rows, err = h.pool.Query(ctx,
				selectCols+` WHERE m.user_id = $1
				 ORDER BY m.id DESC LIMIT $2 OFFSET $3`,
				userID, limit, offset)
		}
	case q != "":
		pattern := "%" + q + "%"
		if domainScope > 0 {
			rows, err = h.pool.Query(ctx,
				selectCols+` WHERE (u.email ILIKE $1 OR m.display_name ILIKE $1 OR m.email ILIKE $1) AND d.id = $2
				 ORDER BY m.id DESC LIMIT $3 OFFSET $4`,
				pattern, domainScope, limit, offset)
		} else {
			rows, err = h.pool.Query(ctx,
				selectCols+` WHERE u.email ILIKE $1 OR m.display_name ILIKE $1 OR m.email ILIKE $1
				 ORDER BY m.id DESC LIMIT $2 OFFSET $3`,
				pattern, limit, offset)
		}
	default:
		if domainScope > 0 {
			rows, err = h.pool.Query(ctx,
				selectCols+` WHERE d.id = $1
				 ORDER BY m.id DESC LIMIT $2 OFFSET $3`,
				domainScope, limit, offset)
		} else {
			rows, err = h.pool.Query(ctx,
				selectCols+` ORDER BY m.id DESC LIMIT $1 OFFSET $2`,
				limit, offset)
		}
	}
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "admin mailboxes list failed", err)
		return
	}
	defer rows.Close()

	out := []adminMailboxResponse{}
	for rows.Next() {
		var m adminMailboxResponse
		if err := rows.Scan(&m.ID, &m.UserID, &m.UserEmail, &m.Email, &m.DisplayName, &m.Type, &m.IsPrimary, &m.QuotaBytes, &m.UsedBytes, &m.Enabled, &m.CreatedAt, &m.DomainName); err != nil {
			h.logger.Error("admin mailbox scan failed", "error", err)
			continue
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "admin mailboxes list rows error", err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, out)
}

// Get returns a single mailbox by ID (scoped to the admin's domain if applicable).
func (h *MailboxesHandler) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid mailbox id"})
		return
	}

	domainScope := middleware.DomainScopeFromContext(ctx)
	var m adminMailboxResponse
	if domainScope > 0 {
		err = h.pool.QueryRow(ctx,
			`SELECT m.id, m.user_id, COALESCE(u.email, ''), m.email, m.display_name, mailbox_effective_type(m.id), m.is_primary, m.quota_bytes, m.used_bytes, m.enabled, m.created_at, d.name
			 FROM mailboxes m LEFT JOIN users u ON u.id = m.user_id
			 JOIN domains d ON d.id = m.domain_id
			 WHERE m.id = $1 AND d.id = $2`, id, domainScope,
		).Scan(&m.ID, &m.UserID, &m.UserEmail, &m.Email, &m.DisplayName, &m.Type, &m.IsPrimary, &m.QuotaBytes, &m.UsedBytes, &m.Enabled, &m.CreatedAt, &m.DomainName)
	} else {
		err = h.pool.QueryRow(ctx,
			`SELECT m.id, m.user_id, COALESCE(u.email, ''), m.email, m.display_name, mailbox_effective_type(m.id), m.is_primary, m.quota_bytes, m.used_bytes, m.enabled, m.created_at, d.name
			 FROM mailboxes m LEFT JOIN users u ON u.id = m.user_id
			 JOIN domains d ON d.id = m.domain_id
			 WHERE m.id = $1`, id,
		).Scan(&m.ID, &m.UserID, &m.UserEmail, &m.Email, &m.DisplayName, &m.Type, &m.IsPrimary, &m.QuotaBytes, &m.UsedBytes, &m.Enabled, &m.CreatedAt, &m.DomainName)
	}
	if err != nil {
		if err == pgx.ErrNoRows {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "mailbox not found"})
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "admin mailbox get failed", err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, m)
}

// Create creates a new mailbox for an existing user.
func (h *MailboxesHandler) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req struct {
		UserID      int64  `json:"userId"`
		Email       string `json:"email"`
		DisplayName string `json:"displayName"`
		Type        string `json:"type"`
		QuotaBytes  *int64 `json:"quotaBytes,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if req.UserID <= 0 || req.Email == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "userId and email required"})
		return
	}
	// Validate AND capture the canonical value in one step: the persisted
	// mailboxes.email is the RFC 5322 canonical address the validation accepted
	// (display-name/comment/whitespace decoration stripped), never the raw
	// request string — the error-only ValidateEmail call validated a value the
	// INSERT below then discarded in favor of the unmodified input.
	canonicalEmail, err := validate.CanonicalEmail(req.Email)
	if err != nil {
		if ve, ok := err.(*validate.ValidationError); ok {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: ve.ToFieldError().Message})
		} else {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: err.Error()})
		}
		return
	}
	if req.DisplayName == "" {
		req.DisplayName = canonicalEmail
	}
	if req.Type == "" {
		req.Type = "personal"
	}
	if req.Type != "personal" {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusBadRequest,
			Detail: "mailbox type must be personal; groups, shared, and resource mailboxes are created via their own endpoints",
		})
		return
	}

	// Enforce DATABASE_SECURITY.md R2: user_id must be authorized from auth context.
	claims := auth.UserFromContext(ctx)
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "authentication required")
		return
	}
	// Object-level authorization: the route-level mail permission is already
	// enforced+audited by requireMailPerm in main.go. This is the additional,
	// request-data-dependent gate ("may this admin create a mailbox for a
	// *different* user?") that a route guard cannot express. It keys off the
	// permission registry (PermUsersCreate) rather than hard-coded role strings,
	// so it composes with custom RBAC roles, not just the two built-in admins.
	if req.UserID != claims.UserID && !claims.HasPermission(permissions.PermUsersCreate) {
		httputil.WriteProblemStatus(w, http.StatusForbidden, "cannot create mailbox for another user")
		return
	}

	// C-2: refuse a guest target with a friendly 409 before the INSERT hits
	// the V143 guest_mailbox_guard trigger (which would raise BZ221 as a raw
	// 500) — a guest is mailbox-less by design, full stop.
	if adminRefuseGuestTarget(ctx, h.pool, h.logger, w, r, req.UserID) {
		return
	}

	// Look up user's domain_id
	var domainID int64
	if err = h.pool.QueryRow(ctx, `SELECT domain_id FROM users WHERE id = $1`, req.UserID).Scan(&domainID); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "user not found"})
		return
	}

	// Enforce domain scope: the user being assigned a mailbox must belong to
	// the admin's scoped domain.
	domainScope := middleware.DomainScopeFromContext(ctx)
	if domainScope > 0 && domainID != domainScope {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "user is not in your domain scope"})
		return
	}

	var mbID int64
	var quotaVal *int64
	if req.QuotaBytes != nil && *req.QuotaBytes > 0 {
		quotaVal = req.QuotaBytes
	}
	err = h.pool.QueryRow(ctx,
		`INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary, quota_bytes)
		 VALUES ($1, $2, $3, $4, $5, FALSE, $6)
		 RETURNING id`,
		req.UserID, domainID, canonicalEmail, req.DisplayName, req.Type, quotaVal,
	).Scan(&mbID)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "admin mailbox create failed", err)
		return
	}
	httputil.WriteJSON(w, http.StatusCreated, map[string]int64{"id": mbID})
}

// Update patches a mailbox's fields (scoped to the admin's domain if applicable).
func (h *MailboxesHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid mailbox id"})
		return
	}

	var req struct {
		DisplayName      *string `json:"displayName,omitempty"`
		QuotaBytes       *int64  `json:"quotaBytes,omitempty"`
		Enabled          *bool   `json:"enabled,omitempty"`
		LitigationHold   *bool   `json:"litigationHold,omitempty"`
		DeletedPurgeDays *int    `json:"deletedPurgeDays,omitempty"`
		SpamPurgeDays    *int    `json:"spamPurgeDays,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}

	domainScope := middleware.DomainScopeFromContext(ctx)
	var tag pgconn.CommandTag
	if domainScope > 0 {
		tag, err = h.pool.Exec(ctx,
			`UPDATE mailboxes SET
			   display_name = COALESCE($3, display_name),
			   quota_bytes = COALESCE($4, quota_bytes),
			   enabled = COALESCE($5, enabled),
			   litigation_hold = COALESCE($6, litigation_hold),
			   deleted_purge_days = $7,
			   spam_purge_days = $8,
			   updated_at = now()
			 WHERE id = $1 AND domain_id = $2`,
			id, domainScope, req.DisplayName, req.QuotaBytes, req.Enabled, req.LitigationHold,
			req.DeletedPurgeDays, req.SpamPurgeDays,
		)
	} else {
		tag, err = h.pool.Exec(ctx,
			`UPDATE mailboxes SET
			   display_name = COALESCE($2, display_name),
			   quota_bytes = COALESCE($3, quota_bytes),
			   enabled = COALESCE($4, enabled),
			   litigation_hold = COALESCE($5, litigation_hold),
			   deleted_purge_days = $6,
			   spam_purge_days = $7,
			   updated_at = now()
			 WHERE id = $1`,
			id, req.DisplayName, req.QuotaBytes, req.Enabled, req.LitigationHold,
			req.DeletedPurgeDays, req.SpamPurgeDays,
		)
	}
	if err != nil {
		h.logger.Error("mailbox update failed", "error", err, "id", id)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "database error"})
		return
	}
	if tag.RowsAffected() == 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "mailbox not found"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Delete removes a mailbox and all its contents (scoped to the admin's domain if applicable).
func (h *MailboxesHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid mailbox id"})
		return
	}
	var lifecycleEnabled bool
	if err := h.workerPool.QueryRow(ctx, `SELECT mailbox_lifecycle_enabled()`).Scan(&lifecycleEnabled); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "mailbox lifecycle gate failed", err)
		return
	}
	if lifecycleEnabled {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusConflict,
			Detail: "direct mailbox deletion is disabled; detach and retain the mailbox, then use the independently approved purge workflow"})
		return
	}

	// Verify the mailbox belongs to the admin's domain scope before deletion.
	domainScope := middleware.DomainScopeFromContext(ctx)
	if domainScope > 0 {
		var mbDomainID int64
		err := h.pool.QueryRow(ctx, `SELECT domain_id FROM mailboxes WHERE id = $1`, id).Scan(&mbDomainID)
		if err != nil {
			if err == pgx.ErrNoRows {
				httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "mailbox not found"})
				return
			}
			httputil.WriteDBErr(w, r, h.logger, "mailbox delete lookup failed", err)
			return
		}
		if mbDomainID != domainScope {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "access denied: mailbox not in domain scope"})
			return
		}
	}

	// native-RLS W7: cross-tenant admin delete fan-out on the BYPASSRLS pool
	// (see the workerPool field doc).
	tx, err := h.workerPool.Begin(ctx)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "mailbox delete tx begin failed", err)
		return
	}
	defer tx.Rollback(ctx)

	// Delete aliases referencing this mailbox
	_, err = tx.Exec(ctx, `DELETE FROM aliases WHERE mailbox_id = $1`, id)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "mailbox delete aliases failed", err)
		return
	}

	// Delete message attachments for messages in this mailbox
	_, err = tx.Exec(ctx, `
		DELETE FROM message_attachments WHERE message_id IN (
			SELECT id FROM messages WHERE mailbox_id = $1
		)
	`, id)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "mailbox delete attachments failed", err)
		return
	}

	// Delete messages
	_, err = tx.Exec(ctx, `DELETE FROM messages WHERE mailbox_id = $1`, id)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "mailbox delete messages failed", err)
		return
	}

	// Delete folders
	_, err = tx.Exec(ctx, `DELETE FROM folders WHERE mailbox_id = $1`, id)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "mailbox delete folders failed", err)
		return
	}

	// Delete mailbox
	_, err = tx.Exec(ctx, `DELETE FROM mailboxes WHERE id = $1`, id)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "mailbox delete failed", err)
		return
	}

	if err := tx.Commit(ctx); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "mailbox delete tx commit failed", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// inDomainScope verifies the target mailbox belongs to the admin's domain scope
// (when scoped). Returns true when the caller may proceed; otherwise it has
// already written the HTTP problem (404 unknown mailbox, 403 out of scope, 500
// on DB error). A global admin (scope 0) always passes. Mirrors the Delete
// handler's lookup so the folder sub-handlers can't be addressed across domains.
func (h *MailboxesHandler) inDomainScope(w http.ResponseWriter, r *http.Request, mbID int64) bool {
	domainScope := middleware.DomainScopeFromContext(r.Context())
	if domainScope == 0 {
		return true
	}
	var mbDomainID int64
	err := h.pool.QueryRow(r.Context(), `SELECT domain_id FROM mailboxes WHERE id = $1`, mbID).Scan(&mbDomainID)
	if err != nil {
		if err == pgx.ErrNoRows {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "mailbox not found"})
			return false
		}
		httputil.WriteDBErr(w, r, h.logger, "mailbox domain scope lookup failed", err)
		return false
	}
	if mbDomainID != domainScope {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "access denied: mailbox not in domain scope"})
		return false
	}
	return true
}

// ListFolders returns folders for a mailbox.
func (h *MailboxesHandler) ListFolders(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	mbIDStr := r.PathValue("id")
	mbID, _ := strconv.ParseInt(mbIDStr, 10, 64)
	if mbID <= 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid mailbox id"})
		return
	}
	if !h.inDomainScope(w, r, mbID) {
		return
	}

	// V077 dropped folders.total_count/unread_count (the live counts moved to tags.*_count
	// under the Phase-17 tag model). Source them from the matching tag (folder.name ↔
	// tag.name within the mailbox); a folder with no matching tag reports 0.
	rows, err := h.pool.Query(ctx,
		`SELECT f.id, f.mailbox_id, f.name, f.role, f.path,
		        COALESCE(t.total_count, 0), COALESCE(t.unread_count, 0)
		 FROM folders f
		 LEFT JOIN tags t ON t.mailbox_id = f.mailbox_id AND t.name = f.name
		 WHERE f.mailbox_id = $1 ORDER BY f.path`, mbID)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "list folders failed", err)
		return
	}
	defer rows.Close()

	out := []adminFolderResponse{}
	for rows.Next() {
		var f adminFolderResponse
		if err := rows.Scan(&f.ID, &f.MailboxID, &f.Name, &f.Role, &f.Path, &f.TotalCount, &f.UnreadCount); err == nil {
			out = append(out, f)
		}
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

// CreateFolder adds a folder to a mailbox.
func (h *MailboxesHandler) CreateFolder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	mbIDStr := r.PathValue("id")
	mbID, _ := strconv.ParseInt(mbIDStr, 10, 64)
	if mbID <= 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid mailbox id"})
		return
	}
	if !h.inDomainScope(w, r, mbID) {
		return
	}

	var req struct {
		Name     string `json:"name"`
		ParentID *int64 `json:"parentId,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if req.Name == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "name required"})
		return
	}

	var parentPath string
	if req.ParentID != nil && *req.ParentID > 0 {
		err := h.pool.QueryRow(ctx, `SELECT path FROM folders WHERE id = $1 AND mailbox_id = $2`, *req.ParentID, mbID).Scan(&parentPath)
		if err != nil {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "parent folder not found"})
			return
		}
	}

	path := req.Name
	if parentPath != "" {
		path = parentPath + "/" + req.Name
	}

	var folderID int64
	err := h.pool.QueryRow(ctx,
		`INSERT INTO folders (mailbox_id, parent_id, name, path)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id`,
		mbID, req.ParentID, req.Name, path,
	).Scan(&folderID)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "create folder failed", err)
		return
	}

	// Also create a corresponding tag for JMAP/webmail visibility
	_, err = h.pool.Exec(ctx,
		`INSERT INTO tags (mailbox_id, parent_id, name, tag_type, sort_order, imap_expose)
		 VALUES ($1, $2, $3, 'user', 100, TRUE)
		 ON CONFLICT (mailbox_id, name) DO NOTHING`,
		mbID, req.ParentID, req.Name,
	)
	if err != nil {
		h.logger.Warn("create tag sync failed", "error", err)
	}

	httputil.WriteJSON(w, http.StatusCreated, map[string]int64{"id": folderID})
}

// UpdateFolder renames a folder.
func (h *MailboxesHandler) UpdateFolder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	mbIDStr := r.PathValue("id")
	mbID, _ := strconv.ParseInt(mbIDStr, 10, 64)
	folderIDStr := r.PathValue("folderId")
	folderID, _ := strconv.ParseInt(folderIDStr, 10, 64)
	if mbID <= 0 || folderID <= 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid id"})
		return
	}
	if !h.inDomainScope(w, r, mbID) {
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if req.Name == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "name required"})
		return
	}

	// Rename the paired tag FIRST: its correlated subquery reads folders.name
	// while it still holds the OLD name, so `tags.name = <old name>` matches.
	// Renaming the folder before this would make the subquery return the NEW
	// name, match no tag, and leave folders.name / tags.name silently diverged.
	// ponytail: two Execs, not one tx — matches CreateFolder/DeleteFolder.
	if _, err := h.pool.Exec(ctx,
		`UPDATE tags SET name = $1 WHERE mailbox_id = $2 AND name = (
		  SELECT name FROM folders WHERE id = $3 AND mailbox_id = $2
		 )`,
		req.Name, mbID, folderID,
	); err != nil {
		h.logger.Warn("update tag sync failed", "error", err)
	}

	if _, err := h.pool.Exec(ctx,
		`UPDATE folders SET name = $1,
			  path = regexp_replace(path, '[^/]+$', $1)
			 WHERE id = $2 AND mailbox_id = $3`,
		req.Name, folderID, mbID); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "update folder failed", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// DeleteFolder removes a folder.
func (h *MailboxesHandler) DeleteFolder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	mbIDStr := r.PathValue("id")
	mbID, _ := strconv.ParseInt(mbIDStr, 10, 64)
	folderIDStr := r.PathValue("folderId")
	folderID, _ := strconv.ParseInt(folderIDStr, 10, 64)
	if mbID <= 0 || folderID <= 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid id"})
		return
	}
	if !h.inDomainScope(w, r, mbID) {
		return
	}

	// Delete corresponding tag first
	_, _ = h.pool.Exec(ctx,
		`DELETE FROM tags WHERE mailbox_id = $1 AND name = (
		  SELECT name FROM folders WHERE id = $2 AND mailbox_id = $1
		 )`,
		mbID, folderID,
	)

	_, err := h.pool.Exec(ctx, `DELETE FROM folders WHERE id = $1 AND mailbox_id = $2`, folderID, mbID)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "delete folder failed", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
