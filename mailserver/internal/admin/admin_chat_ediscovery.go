// admin_chat_ediscovery.go — Chat A4b Task 5: durable case/custodian holds
// (the chat_case_hold_set/chat_case_hold_release admin surface) and a thin
// case-registry read. Task 6 adds the chat.ediscovery-gated search/reader/
// export routes to this same handler.
//
// Split from admin_chat_compliance.go (the A4a boolean legal_hold surface,
// untouched) the same way admin_ediscovery.go and admin_ediscovery_cases.go
// are split for mail — one handler struct per authority plane, sharing
// nothing but the genre (gate/requireManageClaims/requireViewClaims/mapErr
// copied verbatim from admin_chat_compliance.go:70-118; `ponytail:` extract
// a shared helper only when a third handler clones them).
//
// workerPool carve-out (spec §9, contract #5): chat_case_holds and
// chat_case_hold_channels are FORCE-RLS deny-all (V127 — zero policies, the
// chat_audit_log precedent). Every read of them runs on workerPool
// (BYPASSRLS) — the A4a Task 11a/11b carve-out template, replicated here.
// Holds and reader activity stay invisible to custodians (no end-user
// projection, ever — the A4a tipping-off rule): there is no member-facing
// route anywhere in this file.
//
// Authorization is route-declared (chat.compliance_manage/chat.
// compliance_view via main.go's requireChatComplianceManage/View
// middlewares) AND re-checked in-handler (requireManageClaims/
// requireViewClaims below) — the belt-and-braces posture every admin
// handler in this package follows.
package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"

	"setjoin.com/mailserver/internal/audit"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/chat"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/reducererr"
	"setjoin.com/shared/toggle"
)

// ChatEDiscoveryHandler serves the chat A4b oversight admin surface: durable
// case/custodian holds (this task) and, from Task 6, the chat.ediscovery
// search/read/export routes. s3/s3Bucket are unused until Task 7's export —
// wired now so main.go's construction site is touched exactly once.
type ChatEDiscoveryHandler struct {
	pool       *pgxpool.Pool
	workerPool *pgxpool.Pool
	flags      *toggle.FeatureFlags
	logger     *slog.Logger
	s3         *minio.Client
	s3Bucket   string
}

// NewChatEDiscoveryHandler creates a ChatEDiscoveryHandler.
func NewChatEDiscoveryHandler(pool, workerPool *pgxpool.Pool, flags *toggle.FeatureFlags, logger *slog.Logger, s3 *minio.Client, s3Bucket string) *ChatEDiscoveryHandler {
	return &ChatEDiscoveryHandler{pool: pool, workerPool: workerPool, flags: flags, logger: logger, s3: s3, s3Bucket: s3Bucket}
}

// gate 404s the route when feature.chat_compliance is OFF (checked live on
// every request, never cached — the ChatComplianceHandler.gate shape). A4b
// makes the toggle shippable; it does not flip it (Global Constraints).
func (h *ChatEDiscoveryHandler) gate(w http.ResponseWriter, r *http.Request) bool {
	if !h.flags.IsEnabled(toggle.FeatureChatCompliance) {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return false
	}
	return true
}

// requireManageClaims returns claims if the caller holds chat.compliance_manage.
func (h *ChatEDiscoveryHandler) requireManageClaims(w http.ResponseWriter, r *http.Request) (*auth.Claims, bool) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblem(w, r, httputil.NewUnauthorizedProblem("authentication required"))
		return nil, false
	}
	if !claims.HasPermission(permissions.PermChatComplianceManage) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "chat.compliance_manage required"})
		return nil, false
	}
	return claims, true
}

// requireViewClaims returns claims if the caller holds chat.compliance_view
// or chat.compliance_manage.
func (h *ChatEDiscoveryHandler) requireViewClaims(w http.ResponseWriter, r *http.Request) (*auth.Claims, bool) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblem(w, r, httputil.NewUnauthorizedProblem("authentication required"))
		return nil, false
	}
	if !claims.HasPermission(permissions.PermChatComplianceView) && !claims.HasPermission(permissions.PermChatComplianceManage) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "chat.compliance_view or chat.compliance_manage required"})
		return nil, false
	}
	return claims, true
}

// mapErr classifies a V127 reducer business error (BZ197/198) via the shared
// reducererr.WriteClassified (arch #A1): returns true if handled (a Problem
// was written), false if the caller must fall back to WriteDBErr for an
// unclassified error.
func (h *ChatEDiscoveryHandler) mapErr(w http.ResponseWriter, r *http.Request, err error) bool {
	return reducererr.WriteClassified(w, r, err)
}

// ── durable case/custodian holds ────────────────────────────────────────────

type setCaseHoldRequest struct {
	CaseID          int64  `json:"caseId"`
	CustodianUserID *int64 `json:"custodianUserId,omitempty"`
	ChannelID       *int64 `json:"channelId,omitempty"`
	Reason          string `json:"reason"`
}

// SetCaseHold implements POST /admin/chat-ediscovery/holds. manage only.
// Custodian-scoped holds are OU/domain-scoped via admin_can_reach (the A4a
// custodian-hold fix, commit 6267355c — spec §9): a domain-scoped admin
// cannot place a hold on a custodian outside their administrative scope.
// Channel-scoped holds have no single target user to scope by.
func (h *ChatEDiscoveryHandler) SetCaseHold(w http.ResponseWriter, r *http.Request) {
	if !h.gate(w, r) {
		return
	}
	claims, ok := h.requireManageClaims(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	var req setCaseHoldRequest
	if err := httputil.DecodeJSON(w, r, &req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if req.CustodianUserID != nil {
		var canReach bool
		if err := h.pool.QueryRow(ctx, `SELECT admin_can_reach($1, $2)`, claims.UserID, *req.CustodianUserID).Scan(&canReach); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "case hold reach check failed", err)
			return
		}
		if !canReach {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "target user is outside your administrative scope"})
			return
		}
	}
	var holdID int64
	err := h.pool.QueryRow(ctx, `SELECT chat_case_hold_set($1, $2, $3, $4, $5)`,
		claims.UserID, req.CaseID, req.CustodianUserID, req.ChannelID, req.Reason).Scan(&holdID)
	if err != nil {
		if h.mapErr(w, r, err) {
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "chat_case_hold_set failed", err)
		return
	}
	_ = audit.Write(ctx, h.pool, audit.Entry{
		Actor: claims.UserID, Action: "chat_case_hold_set", TargetType: "chat_case_hold", TargetID: &holdID,
		IP: httputil.ClientIP(r), Tier: "core",
	})
	httputil.WriteJSON(w, http.StatusCreated, map[string]any{"holdId": holdID})
}

type releaseCaseHoldRequest struct {
	Reason string `json:"reason"`
}

// ReleaseCaseHold implements POST /admin/chat-ediscovery/holds/{id}/release.
// manage only. Case-scoped by construction (chat_case_hold_release.sql) — a
// hold row belongs to one case, so releasing it can never drop another
// case's coverage. A second release of the same hold raises BZ197 (spec
// §6.1, resolved ambiguity 1): cleanly, no state change, no duplicate act.
func (h *ChatEDiscoveryHandler) ReleaseCaseHold(w http.ResponseWriter, r *http.Request) {
	if !h.gate(w, r) {
		return
	}
	claims, ok := h.requireManageClaims(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	holdID, ok := httputil.ParseIDPath(w, r, "id", "invalid hold id")
	if !ok {
		return
	}
	var req releaseCaseHoldRequest
	if err := httputil.DecodeJSON(w, r, &req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if _, err := h.pool.Exec(ctx, `SELECT chat_case_hold_release($1, $2, $3)`, claims.UserID, holdID, req.Reason); err != nil {
		if h.mapErr(w, r, err) {
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "chat_case_hold_release failed", err)
		return
	}
	_ = audit.Write(ctx, h.pool, audit.Entry{
		Actor: claims.UserID, Action: "chat_case_hold_release", TargetType: "chat_case_hold", TargetID: &holdID,
		IP: httputil.ClientIP(r), Tier: "core",
	})
	w.WriteHeader(http.StatusNoContent)
}

// listCaseHoldsSQL runs on workerPool: chat_case_holds/chat_case_hold_channels
// are FORCE-RLS deny-all (V127 — zero policies, tables invisible even to the
// row's own custodian), so an invoker-rights query would see zero rows.
// channels is the covered-channel count, not the hold's raw scope — the
// operator wants "how much did this actually cover", which for a custodian
// hold can exceed 1 (snapshot + join growth).
const listCaseHoldsSQL = `
SELECT h.id, h.case_id, h.custodian_user_id, h.channel_id, h.reason,
       h.created_by, h.created_at, h.released_at, h.released_by,
       (SELECT count(*) FROM chat_case_hold_channels hc WHERE hc.hold_id = h.id) AS channels
  FROM chat_case_holds h
 WHERE h.case_id = $1
 ORDER BY h.id DESC`

type caseHoldRow struct {
	ID              int64      `json:"id"`
	CaseID          int64      `json:"caseId"`
	CustodianUserID *int64     `json:"custodianUserId,omitempty"`
	ChannelID       *int64     `json:"channelId,omitempty"`
	Reason          string     `json:"reason"`
	CreatedBy       int64      `json:"createdBy"`
	CreatedAt       time.Time  `json:"createdAt"`
	ReleasedAt      *time.Time `json:"releasedAt,omitempty"`
	ReleasedBy      *int64     `json:"releasedBy,omitempty"`
	Channels        int        `json:"channels"`
}

// ListCaseHolds implements GET /admin/chat-ediscovery/holds?caseId=. view or
// manage. caseId is required (400 if absent — a full-table dump of every
// case's holds is not a control an operator should be one fat-fingered
// request away from). An AUDITED read (the ListChannels/GetAudit CEO-#11
// posture): browsing which custodians/channels are under a case hold is
// itself surveillance-relevant metadata.
func (h *ChatEDiscoveryHandler) ListCaseHolds(w http.ResponseWriter, r *http.Request) {
	if !h.gate(w, r) {
		return
	}
	claims, ok := h.requireViewClaims(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	caseIDStr := r.URL.Query().Get("caseId")
	if caseIDStr == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "caseId is required"})
		return
	}
	caseID, err := strconv.ParseInt(caseIDStr, 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid caseId"})
		return
	}
	rows, err := h.workerPool.Query(ctx, listCaseHoldsSQL, caseID)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "list case holds failed", err)
		return
	}
	defer rows.Close()
	out := []caseHoldRow{}
	for rows.Next() {
		var row caseHoldRow
		if err := rows.Scan(&row.ID, &row.CaseID, &row.CustodianUserID, &row.ChannelID, &row.Reason,
			&row.CreatedBy, &row.CreatedAt, &row.ReleasedAt, &row.ReleasedBy, &row.Channels); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "scan case hold row failed", err)
			return
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "list case holds failed", err)
		return
	}
	_ = audit.Write(ctx, h.pool, audit.Entry{
		Actor: claims.UserID, Action: "chat_case_hold_list", TargetType: "ediscovery_case", TargetID: &caseID,
		IP: httputil.ClientIP(r), Tier: "core",
	})
	httputil.WriteJSON(w, http.StatusOK, out)
}

// ── case registry read (review F3) ──────────────────────────────────────────

type ediscoveryCaseRow struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// ListCases implements GET /admin/chat-ediscovery/cases. view or manage. A
// thin SELECT on h.pool — ediscovery_cases carries no RLS (the mail
// console's own GET /admin/ediscovery/cases precedent, admin_ediscovery_
// cases.go:43-83). This route exists SOLELY because that mail-console route
// is requireMailPerm-gated (main.go:3302), which a chat-compliance/
// eDiscovery officer holding only Access-console perms does not hold —
// without it the Task 9 case picker 403s for exactly its target persona
// (review F3). D-H still holds: one case registry, two permission-gated
// projections of it.
func (h *ChatEDiscoveryHandler) ListCases(w http.ResponseWriter, r *http.Request) {
	if !h.gate(w, r) {
		return
	}
	if _, ok := h.requireViewClaims(w, r); !ok {
		return
	}
	ctx := r.Context()
	rows, err := h.pool.Query(ctx, `SELECT id, name, status FROM ediscovery_cases ORDER BY status, name`)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "list ediscovery cases failed", err)
		return
	}
	defer rows.Close()
	out := []ediscoveryCaseRow{}
	for rows.Next() {
		var c ediscoveryCaseRow
		if err := rows.Scan(&c.ID, &c.Name, &c.Status); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "scan ediscovery case row failed", err)
			return
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "list ediscovery cases failed", err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

// ── search + reader (chat.ediscovery-gated, Task 6) ─────────────────────────
//
// D-A / spec §6.3: chat.ediscovery is the SoD-separate permission that gates
// these two routes — deliberately NOT satisfiable by chat.compliance_manage
// (holding authority to destroy chat content, e.g. purge/hold, does not
// grant authority to read every employee's chat content; the reverse
// composition is exactly the tipping-off/over-collection risk the split
// exists to prevent). requireEDiscoveryClaims below is the belt-and-braces
// in-handler re-check alongside main.go's route-declared
// requireChatEDiscovery middleware.

// parseEDiscoveryDate accepts RFC3339 or a bare date (the console's <input
// type="date"> shape) — review F7: chat_ediscovery_search casts
// p_query->>'dateFrom'/'dateTo' straight to timestamptz, so junk here would
// otherwise surface as an unclassified reducer cast error (500), not a
// caller-fixable 400.
func parseEDiscoveryDate(s string) bool {
	if _, err := time.Parse(time.RFC3339, s); err == nil {
		return true
	}
	_, err := time.Parse("2006-01-02", s)
	return err == nil
}

// requireEDiscoveryClaims returns claims if the caller holds chat.ediscovery.
func (h *ChatEDiscoveryHandler) requireEDiscoveryClaims(w http.ResponseWriter, r *http.Request) (*auth.Claims, bool) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblem(w, r, httputil.NewUnauthorizedProblem("authentication required"))
		return nil, false
	}
	if !claims.HasPermission(permissions.PermChatEDiscovery) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "chat.ediscovery required"})
		return nil, false
	}
	return claims, true
}

// searchRequest is the named-field wire shape (R2: the handler builds
// p_query itself — a raw body pass-through into a reducer JSONB argument
// would let a caller smuggle unexpected keys into the persisted
// chat_ediscovery_searches.query row).
type searchRequest struct {
	CaseID     int64   `json:"caseId"`
	Terms      string  `json:"terms"`
	ChannelIDs []int64 `json:"channelIds,omitempty"`
	AuthorID   *int64  `json:"authorId,omitempty"`
	DateFrom   *string `json:"dateFrom,omitempty"`
	DateTo     *string `json:"dateTo,omitempty"`
	BeforeID   *int64  `json:"beforeId,omitempty"`
	Limit      *int    `json:"limit,omitempty"`
}

// Search implements POST /admin/chat-ediscovery/search. chat.ediscovery
// only. Routes p_use_trgm on chat.HasHanRune(terms) — the exact
// Han-detection table the member chat/search.go route uses (review F10:
// its one in-package caller), not a copy-pasted table. Runs on workerPool
// (spec §9: chat_ediscovery_searches is FORCE-RLS deny-all; the reducer is
// SECURITY DEFINER so any pool would work, but reads of the result tables
// stay worker-plane for consistency with the rest of this file). Writes
// the reducer's JSON straight through verbatim
// ({searchId, hits, scheduledHits, resultCount}) — this route does zero
// result-shaping of its own.
func (h *ChatEDiscoveryHandler) Search(w http.ResponseWriter, r *http.Request) {
	if !h.gate(w, r) {
		return
	}
	claims, ok := h.requireEDiscoveryClaims(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	var req searchRequest
	if err := httputil.DecodeJSON(w, r, &req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if strings.TrimSpace(req.Terms) == "" {
		// fast-path 400 (the reducer's BZ197 for empty terms is the belt).
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "terms is required"})
		return
	}
	query := map[string]any{"terms": req.Terms}
	if len(req.ChannelIDs) > 0 {
		query["channelIds"] = req.ChannelIDs
	}
	if req.AuthorID != nil {
		query["authorId"] = *req.AuthorID
	}
	if req.DateFrom != nil {
		if !parseEDiscoveryDate(*req.DateFrom) {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid dateFrom (want RFC3339 or YYYY-MM-DD)"})
			return
		}
		query["dateFrom"] = *req.DateFrom
	}
	if req.DateTo != nil {
		if !parseEDiscoveryDate(*req.DateTo) {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid dateTo (want RFC3339 or YYYY-MM-DD)"})
			return
		}
		query["dateTo"] = *req.DateTo
	}
	queryJSON, err := json.Marshal(query)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "marshal ediscovery search query failed", err)
		return
	}
	limit := 50
	if req.Limit != nil {
		limit = *req.Limit
	}
	var raw []byte
	err = h.workerPool.QueryRow(ctx, `SELECT chat_ediscovery_search($1, $2, $3, $4, $5, $6)`,
		claims.UserID, req.CaseID, queryJSON, req.BeforeID, chat.HasHanRune(req.Terms), limit).Scan(&raw)
	if err != nil {
		if h.mapErr(w, r, err) {
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "chat_ediscovery_search failed", err)
		return
	}
	_ = audit.Write(ctx, h.pool, audit.Entry{
		Actor: claims.UserID, Action: "chat_ediscovery_search", TargetType: "ediscovery_case", TargetID: &req.CaseID,
		IP: httputil.ClientIP(r), Tier: "core",
	})
	httputil.WriteJSON(w, http.StatusOK, json.RawMessage(raw))
}

// ReadMessages implements GET /admin/chat-ediscovery/channels/{id}/messages.
// chat.ediscovery only. caseId is a required query param (the reducer
// stamps every read against a case for the record — spec §6.1);
// beforeId/limit are optional keyset/page params. Writes the reducer's JSON
// straight through verbatim ({channelId, lastPurgedSeq, purgeActs,
// scheduledRows, messages}).
func (h *ChatEDiscoveryHandler) ReadMessages(w http.ResponseWriter, r *http.Request) {
	if !h.gate(w, r) {
		return
	}
	claims, ok := h.requireEDiscoveryClaims(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	channelID, ok := httputil.ParseIDPath(w, r, "id", "invalid channel id")
	if !ok {
		return
	}
	caseIDStr := r.URL.Query().Get("caseId")
	if caseIDStr == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "caseId is required"})
		return
	}
	caseID, err := strconv.ParseInt(caseIDStr, 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid caseId"})
		return
	}
	var beforeID *int64
	if v := r.URL.Query().Get("beforeId"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid beforeId"})
			return
		}
		beforeID = &id
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid limit"})
			return
		}
		limit = n
	}
	var raw []byte
	err = h.workerPool.QueryRow(ctx, `SELECT chat_ediscovery_read($1, $2, $3, $4, $5)`,
		claims.UserID, caseID, channelID, beforeID, limit).Scan(&raw)
	if err != nil {
		if h.mapErr(w, r, err) {
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "chat_ediscovery_read failed", err)
		return
	}
	_ = audit.Write(ctx, h.pool, audit.Entry{
		Actor: claims.UserID, Action: "chat_ediscovery_read", TargetType: "channel", TargetID: &channelID,
		IP: httputil.ClientIP(r), Tier: "core",
	})
	httputil.WriteJSON(w, http.StatusOK, json.RawMessage(raw))
}
