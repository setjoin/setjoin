package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/audit"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
)

// ediscoveryCase represents an eDiscovery case that groups related searches.
type ediscoveryCase struct {
	ID          int64   `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description,omitempty"`
	Status      string  `json:"status"`
	CreatedBy   int64   `json:"createdBy"`
	ClosedAt    *string `json:"closedAt,omitempty"`
	ClosedBy    *int64  `json:"closedBy,omitempty"`
	SearchCount int     `json:"searchCount"`
	CreatedAt   string  `json:"createdAt"`
	UpdatedAt   string  `json:"updatedAt"`
}

// EDiscoveryCaseHandler provides CRUD for eDiscovery cases.
type EDiscoveryCaseHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewEDiscoveryCaseHandler creates a case handler.
func NewEDiscoveryCaseHandler(pool *pgxpool.Pool, logger *slog.Logger) *EDiscoveryCaseHandler {
	return &EDiscoveryCaseHandler{pool: pool, logger: logger}
}

// ListCases returns all eDiscovery cases, most recent first.
func (h *EDiscoveryCaseHandler) ListCases(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rows, err := h.pool.Query(ctx, `
		SELECT c.id, c.name, c.description, c.status, c.created_by,
		       c.closed_at, c.closed_by, c.created_at, c.updated_at,
		       (SELECT COUNT(*) FROM ediscovery_searches s WHERE s.case_id = c.id)
		FROM ediscovery_cases c
		ORDER BY c.created_at DESC
	`)
	if err != nil {
		h.logger.Error("ediscovery cases list failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	out := make([]ediscoveryCase, 0)
	for rows.Next() {
		var c ediscoveryCase
		var closedAt *time.Time
		var createdAt, updatedAt time.Time
		if err := rows.Scan(&c.ID, &c.Name, &c.Description, &c.Status, &c.CreatedBy,
			&closedAt, &c.ClosedBy, &createdAt, &updatedAt, &c.SearchCount); err != nil {
			continue
		}
		if closedAt != nil {
			s := closedAt.Format(time.RFC3339)
			c.ClosedAt = &s
		}
		c.CreatedAt = createdAt.Format(time.RFC3339)
		c.UpdatedAt = updatedAt.Format(time.RFC3339)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		h.logger.Error("ediscovery cases rows error", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, out)
}

// CreateCase creates a new eDiscovery case.
func (h *EDiscoveryCaseHandler) CreateCase(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := auth.UserFromContext(ctx)

	var req struct {
		Name        string `json:"name"`
		Description string `json:"description,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Name == "" {
		httputil.WriteError(w, http.StatusBadRequest, "name is required")
		return
	}

	var id int64
	err := h.pool.QueryRow(ctx, `
		INSERT INTO ediscovery_cases (name, description, created_by)
		VALUES ($1, $2, $3) RETURNING id
	`, req.Name, req.Description, user.UserID).Scan(&id)
	if err != nil {
		h.logger.Error("ediscovery case create failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	httputil.WriteJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

// GetCase returns a single eDiscovery case with its associated searches.
func (h *EDiscoveryCaseHandler) GetCase(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		httputil.WriteError(w, http.StatusBadRequest, "invalid case id")
		return
	}

	var c ediscoveryCase
	var closedAt *time.Time
	var createdAt, updatedAt time.Time
	err = h.pool.QueryRow(ctx, `
		SELECT c.id, c.name, c.description, c.status, c.created_by,
		       c.closed_at, c.closed_by, c.created_at, c.updated_at,
		       (SELECT COUNT(*) FROM ediscovery_searches s WHERE s.case_id = c.id)
		FROM ediscovery_cases c WHERE c.id = $1
	`, id).Scan(&c.ID, &c.Name, &c.Description, &c.Status, &c.CreatedBy,
		&closedAt, &c.ClosedBy, &createdAt, &updatedAt, &c.SearchCount)
	if err != nil {
		httputil.WriteError(w, http.StatusNotFound, "case not found")
		return
	}
	if closedAt != nil {
		s := closedAt.Format(time.RFC3339)
		c.ClosedAt = &s
	}
	c.CreatedAt = createdAt.Format(time.RFC3339)
	c.UpdatedAt = updatedAt.Format(time.RFC3339)

	// Fetch associated searches
	type searchInfo struct {
		ID          int64  `json:"id"`
		Name        string `json:"name"`
		Status      string `json:"status"`
		ResultCount *int   `json:"resultCount,omitempty"`
		CreatedAt   string `json:"createdAt"`
	}
	searches := make([]searchInfo, 0)
	srows, err := h.pool.Query(ctx, `
		SELECT id, name, status, result_count, created_at
		FROM ediscovery_searches WHERE case_id = $1 ORDER BY created_at DESC
	`, id)
	if err == nil {
		defer srows.Close()
		for srows.Next() {
			var s searchInfo
			var sca time.Time
			if srows.Scan(&s.ID, &s.Name, &s.Status, &s.ResultCount, &sca) == nil {
				s.CreatedAt = sca.Format(time.RFC3339)
				searches = append(searches, s)
			}
		}
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"case":     c,
		"searches": searches,
	})
}

// CloseCase closes an eDiscovery case.
func (h *EDiscoveryCaseHandler) CloseCase(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := auth.UserFromContext(ctx)
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		httputil.WriteError(w, http.StatusBadRequest, "invalid case id")
		return
	}

	var req struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	tag, err := h.pool.Exec(ctx, `
		UPDATE ediscovery_cases
		SET status = 'closed', closed_at = now(), closed_by = $1, updated_at = now()
		WHERE id = $2 AND status = 'active'
	`, user.UserID, id)
	if err != nil {
		h.logger.Error("ediscovery case close failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if tag.RowsAffected() == 0 {
		httputil.WriteError(w, http.StatusNotFound, "case not found or already closed")
		return
	}

	// Audit log
	reasonJSON, _ := json.Marshal(map[string]string{"reason": req.Reason})
	_ = audit.Write(ctx, h.pool, audit.Entry{
		Actor: user.UserID, Action: "ediscovery_case_close", TargetType: "ediscovery_case", TargetID: &id,
		Before: reasonJSON, IP: httputil.ClientIP(r), Tier: "core",
	})

	w.WriteHeader(http.StatusNoContent)
}

// UpdateCase updates an eDiscovery case name or description.
func (h *EDiscoveryCaseHandler) UpdateCase(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		httputil.WriteError(w, http.StatusBadRequest, "invalid case id")
		return
	}

	var req struct {
		Name        *string `json:"name,omitempty"`
		Description *string `json:"description,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if (req.Name == nil || *req.Name == "") && req.Description == nil {
		httputil.WriteError(w, http.StatusBadRequest, "no fields to update")
		return
	}

	var sets []string
	var args []any
	argIdx := 1

	if req.Name != nil && *req.Name != "" {
		sets = append(sets, "name = $"+strconv.Itoa(argIdx))
		args = append(args, *req.Name)
		argIdx++
	}
	if req.Description != nil {
		sets = append(sets, "description = $"+strconv.Itoa(argIdx))
		args = append(args, *req.Description)
		argIdx++
	}
	sets = append(sets, "updated_at = now()")

	args = append(args, id)
	query := "UPDATE ediscovery_cases SET " + strings.Join(sets, ", ") + " WHERE id = $" + strconv.Itoa(argIdx)
	tag, err := h.pool.Exec(ctx, query, args...)
	if err != nil {
		h.logger.Error("ediscovery case update failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if tag.RowsAffected() == 0 {
		httputil.WriteError(w, http.StatusNotFound, "case not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// DeleteCase deletes an eDiscovery case (only if it has no searches).
func (h *EDiscoveryCaseHandler) DeleteCase(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		httputil.WriteError(w, http.StatusBadRequest, "invalid case id")
		return
	}

	tag, err := h.pool.Exec(ctx, `
		DELETE FROM ediscovery_cases
		WHERE id = $1
		  AND NOT EXISTS (SELECT 1 FROM ediscovery_searches WHERE case_id = $1)
	`, id)
	if err != nil {
		h.logger.Error("ediscovery case delete failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if tag.RowsAffected() == 0 {
		httputil.WriteError(w, http.StatusConflict, "case not found or has associated searches")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// AssociateSearch links a search to a case.
func (h *EDiscoveryCaseHandler) AssociateSearch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		SearchID int64 `json:"searchId"`
		CaseID   int64 `json:"caseId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.SearchID <= 0 || req.CaseID <= 0 {
		httputil.WriteError(w, http.StatusBadRequest, "searchId and caseId required")
		return
	}

	tag, err := h.pool.Exec(ctx, `
		UPDATE ediscovery_searches SET case_id = $1 WHERE id = $2 AND case_id IS NULL
	`, req.CaseID, req.SearchID)
	if err != nil {
		h.logger.Error("ediscovery search association failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if tag.RowsAffected() == 0 {
		httputil.WriteError(w, http.StatusNotFound, "search not found or already associated with a case")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
