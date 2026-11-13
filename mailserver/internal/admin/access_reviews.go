package admin

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/reducererr"
)

// AccessReviewsHandler is a thin translator over the access_review_* reducers.
type AccessReviewsHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewAccessReviewsHandler creates an access-reviews admin handler.
func NewAccessReviewsHandler(pool *pgxpool.Pool, logger *slog.Logger) *AccessReviewsHandler {
	return &AccessReviewsHandler{pool: pool, logger: logger}
}

// mapReducerErr maps a reducer BZ0xx pgError to an HTTP problem via the single
// shared reducererr.WriteClassified (arch #A1; was a hand-rolled Classify/
// Detail pair before, and before THAT a private hand-switch that duplicated
// the mapping entirely — the divergent 4th classifier arch A1 originally
// flagged). Anything unclassified stays "database error" — reducer internals
// never leak.
func (h *AccessReviewsHandler) mapReducerErr(w http.ResponseWriter, r *http.Request, err error) {
	h.logger.Log(r.Context(), reducererr.Classify(err).LogLevel(), "access review reducer failed", "error", err)
	if !reducererr.WriteClassified(w, r, err) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "database error"})
	}
}

// actorScope pulls (userID, domainScope) from the request context, or writes 401.
func (h *AccessReviewsHandler) actorScope(w http.ResponseWriter, r *http.Request) (int64, int64, bool) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblem(w, r, httputil.NewUnauthorizedProblem("authentication required"))
		return 0, 0, false
	}
	return claims.UserID, middleware.DomainScopeFromContext(r.Context()), true
}

type campaignRow struct {
	ID        int64   `json:"id"`
	Name      string  `json:"name"`
	Status    string  `json:"status"`
	Reviewed  int     `json:"reviewed"`
	Total     int     `json:"total"`
	CreatedBy string  `json:"createdBy"`
	CreatedAt string  `json:"createdAt"`
	ClosedBy  *string `json:"closedBy,omitempty"`
	ClosedAt  *string `json:"closedAt,omitempty"`
}

// List returns the caller's in-scope campaigns (scoped admin sees only domain_scope=scope).
func (h *AccessReviewsHandler) List(w http.ResponseWriter, r *http.Request) {
	_, scope, ok := h.actorScope(w, r)
	if !ok {
		return
	}
	rows, err := h.pool.Query(r.Context(), `
		SELECT c.id, c.name, c.status,
		       COUNT(i.id) FILTER (WHERE i.decision <> 'undecided')::int,
		       COUNT(i.id)::int,
		       u.email, c.created_at::text,
		       cu.email, c.closed_at::text
		  FROM access_review_campaigns c
		  JOIN users u ON u.id = c.created_by
		  LEFT JOIN users cu ON cu.id = c.closed_by
		  LEFT JOIN access_review_items i ON i.campaign_id = c.id
		 WHERE $1 <= 0 OR c.domain_scope = $1
		 GROUP BY c.id, u.email, cu.email
		 ORDER BY (c.status='open') DESC, c.created_at DESC`, scope)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "list access reviews failed", err)
		return
	}
	defer rows.Close()
	out := []campaignRow{}
	for rows.Next() {
		var c campaignRow
		if err := rows.Scan(&c.ID, &c.Name, &c.Status, &c.Reviewed, &c.Total,
			&c.CreatedBy, &c.CreatedAt, &c.ClosedBy, &c.ClosedAt); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "scan campaign failed", err)
			return
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "list access reviews rows error", err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

type itemRow struct {
	ID        int64   `json:"id"`
	UserEmail string  `json:"userEmail"`
	RoleName  string  `json:"roleName"`
	Scope     *int64  `json:"scope"` // effective scope (NULL = global)
	GrantedAt *string `json:"grantedAt"`
	GrantedBy *string `json:"grantedBy,omitempty"` // admin email; nil = SSO
	IsSSO     bool    `json:"isSso"`
	IsSelf    bool    `json:"isSelf"`
	Decision  string  `json:"decision"`
	AppliedAt *string `json:"appliedAt"`
}

// Get returns one campaign + its items, scope-checked (404 on missing or out-of-scope).
func (h *AccessReviewsHandler) Get(w http.ResponseWriter, r *http.Request) {
	actor, scope, ok := h.actorScope(w, r)
	if !ok {
		return
	}
	id, ok := httputil.ParseIDPath(w, r, "id", "invalid id")
	if !ok {
		return
	}
	var c campaignRow
	err := h.pool.QueryRow(r.Context(), `
		SELECT c.id, c.name, c.status, u.email, c.created_at::text, cu.email, c.closed_at::text
		  FROM access_review_campaigns c
		  JOIN users u ON u.id = c.created_by
		  LEFT JOIN users cu ON cu.id = c.closed_by
		 WHERE c.id = $1 AND ($2 <= 0 OR c.domain_scope = $2)`, id, scope).
		Scan(&c.ID, &c.Name, &c.Status, &c.CreatedBy, &c.CreatedAt, &c.ClosedBy, &c.ClosedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "no such campaign"})
		return
	} else if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "get access review failed", err)
		return
	}
	rows, err := h.pool.Query(r.Context(), `
		SELECT i.id, u.email, rg.name, COALESCE(i.domain_override, rg.domain_scope),
		       i.granted_at::text, gb.email, i.is_sso, (i.user_id = $2), i.decision, i.applied_at::text
		  FROM access_review_items i
		  LEFT JOIN users u ON u.id = i.user_id
		  LEFT JOIN admin_role_groups rg ON rg.id = i.role_group_id
		  LEFT JOIN users gb ON gb.id = i.granted_by
		 WHERE i.campaign_id = $1
		 ORDER BY (i.decision='undecided') DESC, u.email`, id, actor)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "get items failed", err)
		return
	}
	defer rows.Close()
	items := []itemRow{}
	for rows.Next() {
		var it itemRow
		if err := rows.Scan(&it.ID, &it.UserEmail, &it.RoleName, &it.Scope, &it.GrantedAt,
			&it.GrantedBy, &it.IsSSO, &it.IsSelf, &it.Decision, &it.AppliedAt); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "scan item failed", err)
			return
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "read items rows error", err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{"campaign": c, "items": items})
}

// Start creates a campaign (POST /admin/access-reviews, body {name}).
func (h *AccessReviewsHandler) Start(w http.ResponseWriter, r *http.Request) {
	actor, scope, ok := h.actorScope(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "name required"})
		return
	}
	var id int64
	if err := h.pool.QueryRow(r.Context(),
		`SELECT access_review_start($1, $2, $3)`, actor, req.Name, scope).Scan(&id); err != nil {
		h.mapReducerErr(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

var validDecision = map[string]bool{"keep": true, "revoke": true}

// Decide records one decision (PUT /admin/access-reviews/{id}/items/{itemId}).
func (h *AccessReviewsHandler) Decide(w http.ResponseWriter, r *http.Request) {
	actor, scope, ok := h.actorScope(w, r)
	if !ok {
		return
	}
	cid, ok := httputil.ParseIDPath(w, r, "id", "invalid id")
	if !ok {
		return
	}
	iid, ok := httputil.ParseIDPath(w, r, "itemId", "invalid id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	var req struct {
		Decision string  `json:"decision"`
		Note     *string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !validDecision[req.Decision] {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "decision must be keep or revoke"})
		return
	}
	if _, err := h.pool.Exec(r.Context(),
		`SELECT access_review_decide($1,$2,$3,$4,$5,$6)`, actor, cid, iid, req.Decision, req.Note, scope); err != nil {
		h.mapReducerErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// DecideBulk applies one decision to many items (PUT /admin/access-reviews/{id}/items).
func (h *AccessReviewsHandler) DecideBulk(w http.ResponseWriter, r *http.Request) {
	actor, scope, ok := h.actorScope(w, r)
	if !ok {
		return
	}
	cid, ok := httputil.ParseIDPath(w, r, "id", "invalid id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		ItemIDs  []int64 `json:"itemIds"`
		Decision string  `json:"decision"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !validDecision[req.Decision] || len(req.ItemIDs) == 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "itemIds + keep/revoke required"})
		return
	}
	var result []byte
	if err := h.pool.QueryRow(r.Context(),
		`SELECT access_review_decide_bulk($1,$2,$3,$4,$5)`, actor, cid, req.ItemIDs, req.Decision, scope).Scan(&result); err != nil {
		h.mapReducerErr(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(result) // reducer returns {applied, skipped} JSON
}

// Close finalizes a campaign (POST /admin/access-reviews/{id}/close).
func (h *AccessReviewsHandler) Close(w http.ResponseWriter, r *http.Request) {
	actor, scope, ok := h.actorScope(w, r)
	if !ok {
		return
	}
	cid, ok := httputil.ParseIDPath(w, r, "id", "invalid id")
	if !ok {
		return
	}
	if _, err := h.pool.Exec(r.Context(),
		`SELECT access_review_close($1,$2,$3,$4)`, actor, cid, httputil.ClientIP(r), scope); err != nil {
		h.mapReducerErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
