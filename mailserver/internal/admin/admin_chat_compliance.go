// admin_chat_compliance.go — Chat A4a Task 11a: the admin MUTATION surface
// (org retention-policy CRUD with the 7-day effective-at grace + FIX 3's
// effective-retention-exposure guard, the participant-projecting channel
// list, channel/custodian legal hold, and the gxp/WORM classification +
// per-channel retention override). Task 11 was split (verify C3); Task 11b
// (preview/overview/audit/verify/CSV) is a separate file sharing this
// handler struct and its middlewares.
//
// Shape verbatim from admin_approvals.go:106-482 (view/manage perm split,
// RFC7807 errors, direct SQL, audit.Write to the GLOBAL admin_audit_log for
// org-config CRUD — a policy has no single channel to hang a chain act on).
// Per-channel mutations (hold/retention/classification) call the SECURITY
// DEFINER V126 reducers, which write their own chat_access_audit chain act
// (chat_channels has no UPDATE policy under FORCE RLS — Global Constraints —
// so this handler never issues a raw UPDATE on chat_channels itself except
// the classification route's retention/worm pre-set, which must run on
// workerPool for the same FORCE-RLS reason).
package admin

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/audit"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/reducererr"
	"setjoin.com/shared/toggle"
)

// ChatComplianceHandler serves the chat A4a compliance admin surface.
type ChatComplianceHandler struct {
	// pool is the app pool: chat_retention_policies carries no RLS (org
	// config, the org_default_channels/V122 posture), and every chat_channels
	// mutation here goes through a SECURITY DEFINER reducer (works on any
	// pool/role by construction).
	pool *pgxpool.Pool
	// workerPool (BYPASSRLS) is required for any raw SELECT/UPDATE against
	// chat_channels or a join through chat_channel_members: chat_channels'
	// FORCE-RLS SELECT policy only admits a caller's OWN channels, and it
	// carries no UPDATE policy at all (V126 §A comment) — an invoker-rights
	// query would see zero rows for every channel the admin does not belong
	// to, which for a compliance console is every channel that matters.
	workerPool *pgxpool.Pool
	flags      *toggle.FeatureFlags
	logger     *slog.Logger
}

// NewChatComplianceHandler creates a ChatComplianceHandler.
func NewChatComplianceHandler(pool, workerPool *pgxpool.Pool, flags *toggle.FeatureFlags, logger *slog.Logger) *ChatComplianceHandler {
	return &ChatComplianceHandler{pool: pool, workerPool: workerPool, flags: flags, logger: logger}
}

// gate 404s the route when feature.chat_compliance is OFF (checked live on
// every request, never cached — the chat.Handler.ServeHTTP G5 shape) and
// returns false when the caller must stop. Ship posture: the toggle stays
// OFF at merge (plan §"Ship posture") — this is what makes that true for the
// admin surface, not just the end-user one.
func (h *ChatComplianceHandler) gate(w http.ResponseWriter, r *http.Request) bool {
	if !h.flags.IsEnabled(toggle.FeatureChatCompliance) {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return false
	}
	return true
}

// requireManageClaims returns claims if the caller holds chat.compliance_manage.
func (h *ChatComplianceHandler) requireManageClaims(w http.ResponseWriter, r *http.Request) (*auth.Claims, bool) {
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
func (h *ChatComplianceHandler) requireViewClaims(w http.ResponseWriter, r *http.Request) (*auth.Claims, bool) {
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

// mapErr classifies a V126 reducer business error (BZ192-196) via the shared
// reducererr.WriteClassified (arch #A1): returns true if handled (a Problem
// was written), false if the caller must fall back to WriteDBErr for an
// unclassified error.
func (h *ChatComplianceHandler) mapErr(w http.ResponseWriter, r *http.Request, err error) bool {
	return reducererr.WriteClassified(w, r, err)
}

// ── retention policies ───────────────────────────────────────────────────────

var validAppliesTo = map[string]bool{"channel": true, "dm": true, "group_dm": true, "all": true}

type retentionPolicyResponse struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	AppliesTo    string `json:"appliesTo"`
	DurationDays int    `json:"durationDays"`
	Enabled      bool   `json:"enabled"`
	EffectiveAt  string `json:"effectiveAt"`
	CreatedAt    string `json:"createdAt"`
	UpdatedAt    string `json:"updatedAt"`
}

// ListPolicies implements GET /admin/chat-retention-policies. view or manage.
func (h *ChatComplianceHandler) ListPolicies(w http.ResponseWriter, r *http.Request) {
	if !h.gate(w, r) {
		return
	}
	if _, ok := h.requireViewClaims(w, r); !ok {
		return
	}
	ctx := r.Context()

	rows, err := h.pool.Query(ctx, `
		SELECT id, name, applies_to, duration_days, enabled,
		       effective_at::TEXT, created_at::TEXT, updated_at::TEXT
		  FROM chat_retention_policies ORDER BY id`)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "list chat retention policies failed", err)
		return
	}
	defer rows.Close()
	out := []retentionPolicyResponse{}
	for rows.Next() {
		var p retentionPolicyResponse
		if err := rows.Scan(&p.ID, &p.Name, &p.AppliesTo, &p.DurationDays, &p.Enabled,
			&p.EffectiveAt, &p.CreatedAt, &p.UpdatedAt); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "scan chat retention policy failed", err)
			return
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "list chat retention policies failed", err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

type createRetentionPolicyRequest struct {
	Name         string `json:"name"`
	AppliesTo    string `json:"appliesTo"`
	DurationDays int    `json:"durationDays"`
	Enabled      bool   `json:"enabled"`
}

// CreatePolicy implements POST /admin/chat-retention-policies. manage only.
func (h *ChatComplianceHandler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	if !h.gate(w, r) {
		return
	}
	claims, ok := h.requireManageClaims(w, r)
	if !ok {
		return
	}
	ctx := r.Context()

	var req createRetentionPolicyRequest
	if err := httputil.DecodeJSON(w, r, &req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if !validAppliesTo[req.AppliesTo] {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnprocessableEntity, Detail: "appliesTo must be one of channel, dm, group_dm, all"})
		return
	}
	if req.DurationDays <= 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnprocessableEntity, Detail: "durationDays must be a positive integer"})
		return
	}
	if req.Name == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnprocessableEntity, Detail: "name is required"})
		return
	}

	var id int64
	var effectiveAt string
	err := h.pool.QueryRow(ctx, `
		INSERT INTO chat_retention_policies (name, applies_to, duration_days, enabled)
		VALUES ($1, $2, $3, $4) RETURNING id, effective_at::TEXT`,
		req.Name, req.AppliesTo, req.DurationDays, req.Enabled).Scan(&id, &effectiveAt)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "create chat retention policy failed", err)
		return
	}

	afterJSON, _ := json.Marshal(map[string]any{"id": id, "name": req.Name, "appliesTo": req.AppliesTo, "durationDays": req.DurationDays, "enabled": req.Enabled})
	_ = audit.Write(ctx, h.pool, audit.Entry{
		Actor: claims.UserID, Action: "chat_retention_policy_create", TargetType: "chat_retention_policy", TargetID: &id,
		After: afterJSON, IP: httputil.ClientIP(r), Tier: "core",
	})

	httputil.WriteJSON(w, http.StatusCreated, map[string]any{"id": id, "effectiveAt": effectiveAt})
}

type updateRetentionPolicyRequest struct {
	Name         string `json:"name"`
	AppliesTo    string `json:"appliesTo"`
	DurationDays int    `json:"durationDays"`
	Enabled      bool   `json:"enabled"`
}

type currentPolicyRow struct {
	Name         string
	AppliesTo    string
	DurationDays int
	Enabled      bool
}

// UpdatePolicy implements PUT /admin/chat-retention-policies/{id}. manage
// only. Re-arms the 7-day effective-at grace whenever the edit can only GROW
// the destroyed set (verify N4/FIX 3 — see the plan's "UpdatePolicy MUST
// RE-ARM effective_at" section, binding).
func (h *ChatComplianceHandler) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	if !h.gate(w, r) {
		return
	}
	claims, ok := h.requireManageClaims(w, r)
	if !ok {
		return
	}
	ctx := r.Context()

	id, ok := httputil.ParseIDPath(w, r, "id", "invalid policy id")
	if !ok {
		return
	}

	var req updateRetentionPolicyRequest
	if err := httputil.DecodeJSON(w, r, &req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if !validAppliesTo[req.AppliesTo] {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnprocessableEntity, Detail: "appliesTo must be one of channel, dm, group_dm, all"})
		return
	}
	if req.DurationDays <= 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnprocessableEntity, Detail: "durationDays must be a positive integer"})
		return
	}

	var cur currentPolicyRow
	if err := h.pool.QueryRow(ctx, `SELECT name, applies_to, duration_days, enabled FROM chat_retention_policies WHERE id = $1`, id).
		Scan(&cur.Name, &cur.AppliesTo, &cur.DurationDays, &cur.Enabled); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "policy not found"})
		return
	}

	// FIX 3: does this edit SHORTEN any channel's effective retention? The
	// per-policy terms below are cheap early-outs; exposesAnyChannel is the
	// backstop that also catches shielding-weakening edits the per-policy
	// terms read as benign (disabling/narrowing a long kind-specific policy
	// that shields a class from a shorter 'all' ceiling).
	exposed, err := h.exposedChannelCount(ctx, id, req.AppliesTo, req.DurationDays, req.Enabled)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "compute retention exposure failed", err)
		return
	}
	// N4: the 7-day grace is a rail, not a UI confirm. A policy edit that can
	// only GROW the destroyed set re-arms the window; a shrinking edit does
	// not (an admin lengthening retention should not wait a week to make the
	// system LESS destructive).
	moreDestructive := req.DurationDays < cur.DurationDays ||
		(req.Enabled && !cur.Enabled) ||
		req.AppliesTo != cur.AppliesTo ||
		exposed > 0

	var effectiveAt string
	err = h.pool.QueryRow(ctx, `
		UPDATE chat_retention_policies
		   SET name = $2, applies_to = $3, duration_days = $4, enabled = $5,
		       effective_at = CASE WHEN $6
		                           THEN GREATEST(effective_at, now() + interval '7 days')
		                           ELSE effective_at END,
		       updated_at = now()
		 WHERE id = $1
		RETURNING effective_at::TEXT`,
		id, req.Name, req.AppliesTo, req.DurationDays, req.Enabled, moreDestructive).Scan(&effectiveAt)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "update chat retention policy failed", err)
		return
	}

	afterJSON, _ := json.Marshal(map[string]any{"id": id, "name": req.Name, "appliesTo": req.AppliesTo, "durationDays": req.DurationDays, "enabled": req.Enabled, "moreDestructive": moreDestructive})
	_ = audit.Write(ctx, h.pool, audit.Entry{
		Actor: claims.UserID, Action: "chat_retention_policy_update", TargetType: "chat_retention_policy", TargetID: &id,
		After: afterJSON, IP: httputil.ClientIP(r), Tier: "core",
	})

	// The (possibly re-armed) effective_at is returned so the caller shows
	// "takes effect on «date»" AFTER the save, never the pre-save value.
	httputil.WriteJSON(w, http.StatusOK, map[string]any{"effectiveAt": effectiveAt})
}

// DeletePolicy implements DELETE /admin/chat-retention-policies/{id}?confirm=DESTROY.
// manage only. Refuses (409) when the delete would shorten any channel's
// effective retention, unless confirm=DESTROY (verify FIX 3 — a hard delete
// has no effective_at to arm, so the confirm IS the rail).
func (h *ChatComplianceHandler) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	if !h.gate(w, r) {
		return
	}
	claims, ok := h.requireManageClaims(w, r)
	if !ok {
		return
	}
	ctx := r.Context()

	id, ok := httputil.ParseIDPath(w, r, "id", "invalid policy id")
	if !ok {
		return
	}

	exposed, err := h.exposedChannelCount(ctx, id, "", 0, false)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "compute retention exposure failed", err)
		return
	}
	if exposed > 0 && r.URL.Query().Get("confirm") != "DESTROY" {
		httputil.WriteJSON(w, http.StatusConflict, map[string]any{"code": "exposure", "exposedChannels": exposed})
		return
	}

	tag, err := h.pool.Exec(ctx, `DELETE FROM chat_retention_policies WHERE id = $1`, id)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "delete chat retention policy failed", err)
		return
	}
	if tag.RowsAffected() == 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "policy not found"})
		return
	}

	_ = audit.Write(ctx, h.pool, audit.Entry{
		Actor: claims.UserID, Action: "chat_retention_policy_delete", TargetType: "chat_retention_policy", TargetID: &id,
		IP: httputil.ClientIP(r), Tier: "core",
	})

	w.WriteHeader(http.StatusNoContent)
}

// exposedChannelCountSQL is the FIX 3 effective-retention-exposure check
// (plan text, verbatim): counts channels whose effective retention SHORTENS
// under the policy set with $1 excluded and, when $4 is true, a proposed
// (applies_to=$2, duration_days=$3) row unioned in — DeletePolicy calls with
// $4=false (no replacement row); UpdatePolicy calls with $4=req.Enabled (a
// proposed-but-disabled edit adds nothing back, which is exactly how a
// disable-the-shield edit is caught as exposure). Runs on workerPool: chat_
// channels' FORCE RLS would otherwise hide every channel the caller is not a
// member of.
const exposedChannelCountSQL = `
WITH before_pol AS (
  SELECT applies_to, duration_days FROM chat_retention_policies
   WHERE enabled AND effective_at <= now()
), after_pol AS (
  SELECT applies_to, duration_days FROM chat_retention_policies
   WHERE id <> $1 AND enabled AND effective_at <= now()
  UNION ALL
  SELECT $2::text, $3::int WHERE $4::boolean
)
SELECT count(*) FROM chat_channels c
WHERE COALESCE(c.retention_days,
        (SELECT min(duration_days) FROM after_pol p WHERE p.applies_to = c.kind),
        (SELECT min(duration_days) FROM after_pol p WHERE p.applies_to = 'all'),
        2147483647)
    < COALESCE(c.retention_days,
        (SELECT min(duration_days) FROM before_pol p WHERE p.applies_to = c.kind),
        (SELECT min(duration_days) FROM before_pol p WHERE p.applies_to = 'all'),
        2147483647)`

func (h *ChatComplianceHandler) exposedChannelCount(ctx context.Context, excludeID int64, proposedAppliesTo string, proposedDurationDays int, includeProposed bool) (int, error) {
	var n int
	err := h.workerPool.QueryRow(ctx, exposedChannelCountSQL, excludeID, proposedAppliesTo, proposedDurationDays, includeProposed).Scan(&n)
	return n, err
}

// ── channels ─────────────────────────────────────────────────────────────────

// listChannelsSQL projects participants (plan verify C3): chat_channels.name
// is NULL for dm/group_dm (V119:10), so without this a DM row is
// unidentifiable to the operator who must hold/override/classify it. Capped
// at 8 participants; member_count carries the true size.
const listChannelsSQL = `
SELECT c.id, c.kind, c.name,
       c.classification, c.retention_days, c.worm_mode,
       chat_hold_active(c.id) AS legal_hold,   -- REPOINTED (A4b spec §2.3): predicate truth, never the raw boolean
       c.legal_hold_reason, c.last_purged_seq,
       chat_effective_retention(c.id) AS effective_retention_days,
       (SELECT count(*) FROM chat_channel_members m WHERE m.channel_id = c.id) AS member_count,
       (SELECT count(*) FROM chat_case_hold_channels hc
          JOIN chat_case_holds h ON h.id = hc.hold_id AND h.released_at IS NULL
         WHERE hc.channel_id = c.id) AS case_hold_count,
       COALESCE((
         SELECT jsonb_agg(jsonb_build_object('userId', u.id,
                                             'displayName', u.display_name,
                                             'email', u.email)
                          ORDER BY u.display_name)
           FROM (SELECT m2.user_id FROM chat_channel_members m2
                  WHERE m2.channel_id = c.id ORDER BY m2.user_id LIMIT 8) lim
           JOIN users u ON u.id = lim.user_id
       ), '[]'::jsonb) AS participants
  FROM chat_channels c
 WHERE ($1::bigint IS NULL OR EXISTS (SELECT 1 FROM chat_channel_members m3
                                       WHERE m3.channel_id = c.id AND m3.user_id = $1))
   AND ($2::text IS NULL OR c.name ILIKE '%'||$2||'%'
        OR EXISTS (SELECT 1 FROM chat_channel_members m4 JOIN users u2 ON u2.id = m4.user_id
                    WHERE m4.channel_id = c.id
                      AND (u2.email ILIKE '%'||$2||'%' OR u2.display_name ILIKE '%'||$2||'%')))
 ORDER BY c.id
 LIMIT $3 OFFSET $4`

type channelListRow struct {
	ID                     int64   `json:"id"`
	Kind                   string  `json:"kind"`
	Name                   *string `json:"name,omitempty"`
	Classification         string  `json:"classification"`
	RetentionDays          *int    `json:"retentionDays,omitempty"`
	WormMode               *string `json:"wormMode,omitempty"`
	LegalHold              bool    `json:"legalHold"`
	LegalHoldReason        *string `json:"legalHoldReason,omitempty"`
	LastPurgedSeq          int64   `json:"lastPurgedSeq"`
	EffectiveRetentionDays *int    `json:"effectiveRetentionDays,omitempty"`
	MemberCount            int     `json:"memberCount"`
	CaseHoldCount          int     `json:"caseHoldCount"`
	Participants           []byte  `json:"-"`
}

// ListChannels implements GET /admin/chat-channels?q=&userId=&limit=&offset=.
// view or manage. Runs on workerPool (BYPASSRLS carve-out — chat FORCE-RLS
// hides every channel the admin caller is not a member of).
//
// This is an AUDITED read (CEO review #11): browsing every DM in the org by
// name with participants is itself surveillance-relevant metadata a DE/
// works-council deployment expects logged.
func (h *ChatComplianceHandler) ListChannels(w http.ResponseWriter, r *http.Request) {
	if !h.gate(w, r) {
		return
	}
	claims, ok := h.requireViewClaims(w, r)
	if !ok {
		return
	}
	ctx := r.Context()

	var userID *int64
	if v := r.URL.Query().Get("userId"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid userId"})
			return
		}
		userID = &id
	}
	var q *string
	if v := r.URL.Query().Get("q"); v != "" {
		q = &v
	}
	limit, offset := httputil.ParseLimitOffset(r, 50, 500)

	rows, err := h.workerPool.Query(ctx, listChannelsSQL, userID, q, limit, offset)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "list chat channels failed", err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var row channelListRow
		if err := rows.Scan(&row.ID, &row.Kind, &row.Name,
			&row.Classification, &row.RetentionDays, &row.WormMode,
			&row.LegalHold, &row.LegalHoldReason, &row.LastPurgedSeq,
			&row.EffectiveRetentionDays, &row.MemberCount, &row.CaseHoldCount, &row.Participants); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "scan chat channel failed", err)
			return
		}
		out = append(out, channelRowToJSON(row))
	}
	if err := rows.Err(); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "list chat channels failed", err)
		return
	}

	_ = audit.Write(ctx, h.pool, audit.Entry{
		Actor: claims.UserID, Action: "chat_channel_admin_list", TargetType: "chat_channel",
		IP: httputil.ClientIP(r), Tier: "core",
	})

	httputil.WriteJSON(w, http.StatusOK, out)
}

// channelRowToJSON assembles the wire map with participants embedded as raw
// JSON (already jsonb from Postgres — no need to round-trip through a typed
// Go slice just to re-marshal the identical bytes).
func channelRowToJSON(row channelListRow) map[string]any {
	m := map[string]any{
		"id":             row.ID,
		"kind":           row.Kind,
		"classification": row.Classification,
		"legalHold":      row.LegalHold,
		"lastPurgedSeq":  row.LastPurgedSeq,
		"memberCount":    row.MemberCount,
		"caseHoldCount":  row.CaseHoldCount,
		"participants":   json.RawMessage(row.Participants),
	}
	if row.Name != nil {
		m["name"] = *row.Name
	}
	if row.RetentionDays != nil {
		m["retentionDays"] = *row.RetentionDays
	}
	if row.WormMode != nil {
		m["wormMode"] = *row.WormMode
	}
	if row.LegalHoldReason != nil {
		m["legalHoldReason"] = *row.LegalHoldReason
	}
	if row.EffectiveRetentionDays != nil {
		m["effectiveRetentionDays"] = *row.EffectiveRetentionDays
	}
	return m
}

// ── holds ────────────────────────────────────────────────────────────────────

type setHoldRequest struct {
	On     bool    `json:"on"`
	Reason *string `json:"reason,omitempty"`
}

// SetHold implements POST /admin/chat-channels/{id}/hold. manage only.
func (h *ChatComplianceHandler) SetHold(w http.ResponseWriter, r *http.Request) {
	if !h.gate(w, r) {
		return
	}
	claims, ok := h.requireManageClaims(w, r)
	if !ok {
		return
	}
	ctx := r.Context()

	channelID, ok := httputil.ParseIDPath(w, r, "id", "invalid channel id")
	if !ok {
		return
	}
	var req setHoldRequest
	if err := httputil.DecodeJSON(w, r, &req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}

	_, err := h.pool.Exec(ctx, `SELECT chat_channel_set_hold($1, $2, $3, $4)`, claims.UserID, channelID, req.On, req.Reason)
	if err != nil {
		if h.mapErr(w, r, err) {
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "chat_channel_set_hold failed", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── classification & per-channel retention ──────────────────────────────────

var validWormMode = map[string]bool{"governance": true, "compliance": true}

type setClassificationRequest struct {
	Classification string `json:"classification"`
	RetentionDays  int    `json:"retentionDays"`
	WormMode       string `json:"wormMode"`
}

// SetClassification implements POST /admin/chat-channels/{id}/classification.
// manage only. Sets retention_days/worm_mode first (a raw UPDATE on
// workerPool — chat_channels has no UPDATE policy under FORCE RLS, so this
// must bypass), THEN calls chat_channel_set_classification, matching drive's
// own ordering (drive_space_set_classification.sql:28-31): the reducer
// requires both knobs already set before it will allow the gxp transition.
func (h *ChatComplianceHandler) SetClassification(w http.ResponseWriter, r *http.Request) {
	if !h.gate(w, r) {
		return
	}
	claims, ok := h.requireManageClaims(w, r)
	if !ok {
		return
	}
	ctx := r.Context()

	channelID, ok := httputil.ParseIDPath(w, r, "id", "invalid channel id")
	if !ok {
		return
	}
	var req setClassificationRequest
	if err := httputil.DecodeJSON(w, r, &req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if req.Classification != "gxp" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "classification must be gxp (the only reducer-valid transition)"})
		return
	}
	if req.RetentionDays <= 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "retentionDays must be a positive integer"})
		return
	}
	if !validWormMode[req.WormMode] {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "wormMode must be governance or compliance"})
		return
	}

	if _, err := h.workerPool.Exec(ctx,
		`UPDATE chat_channels SET retention_days = $1, worm_mode = $2 WHERE id = $3`,
		req.RetentionDays, req.WormMode, channelID); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "set channel retention/worm knobs failed", err)
		return
	}

	_, err := h.pool.Exec(ctx, `SELECT chat_channel_set_classification($1, $2, $3)`, claims.UserID, channelID, req.Classification)
	if err != nil {
		if h.mapErr(w, r, err) {
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "chat_channel_set_classification failed", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type setChannelRetentionRequest struct {
	RetentionDays *int `json:"retentionDays"`
}

// SetRetention implements PUT /admin/chat-channels/{id}/retention. manage
// only. Immediate-by-design (plan FIX 3 / §Goal) — no grace, unlike the org
// policy path: single channel, chat.compliance_manage-scoped, no org blast
// radius. A null retentionDays clears the override.
func (h *ChatComplianceHandler) SetRetention(w http.ResponseWriter, r *http.Request) {
	if !h.gate(w, r) {
		return
	}
	claims, ok := h.requireManageClaims(w, r)
	if !ok {
		return
	}
	ctx := r.Context()

	channelID, ok := httputil.ParseIDPath(w, r, "id", "invalid channel id")
	if !ok {
		return
	}
	var req setChannelRetentionRequest
	if err := httputil.DecodeJSON(w, r, &req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}

	_, err := h.pool.Exec(ctx, `SELECT chat_channel_set_retention($1, $2, $3)`, claims.UserID, channelID, req.RetentionDays)
	if err != nil {
		if h.mapErr(w, r, err) {
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "chat_channel_set_retention failed", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── Task 11b: the evidence surface (preview · overview · audit · verify) ────

// PreviewPurge implements GET /admin/chat-purge/preview. view or manage.
// Dry-runs chat_purge_expired (Task 6) on workerPool: the reducer's own
// per-channel scan (classification -> hold -> retention) must be authoritative
// for what would be destroyed — re-deriving that selection in Go would drift.
func (h *ChatComplianceHandler) PreviewPurge(w http.ResponseWriter, r *http.Request) {
	if !h.gate(w, r) {
		return
	}
	if _, ok := h.requireViewClaims(w, r); !ok {
		return
	}
	ctx := r.Context()

	rows, err := h.workerPool.Query(ctx,
		`SELECT channel_id, purged_count, id_from, id_to, retention_days FROM chat_purge_expired(100000, TRUE)`)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "preview chat purge failed", err)
		return
	}
	defer rows.Close()
	type previewRow struct {
		ChannelID     int64 `json:"channelId"`
		PurgedCount   int   `json:"purgedCount"`
		IDFrom        int64 `json:"idFrom"`
		IDTo          int64 `json:"idTo"`
		RetentionDays int   `json:"retentionDays"`
	}
	out := []previewRow{}
	var totalMessages int
	for rows.Next() {
		var p previewRow
		if err := rows.Scan(&p.ChannelID, &p.PurgedCount, &p.IDFrom, &p.IDTo, &p.RetentionDays); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "scan chat purge preview row failed", err)
			return
		}
		totalMessages += p.PurgedCount
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "preview chat purge failed", err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"channels":      out,
		"totalChannels": len(out),
		"totalMessages": totalMessages,
	})
}

// overviewChannelsSQL is a single workerPool round-trip (chat_channels' FORCE
// RLS otherwise hides every channel the caller is not a member of): three
// jsonb-agg'd arrays — channels under hold (with the boolean arm's matter
// from legal_hold_reason AND its case-hold coverage), gxp channels, and
// channels carrying a per-channel retention override.
const overviewChannelsSQL = `
SELECT
  COALESCE((SELECT jsonb_agg(jsonb_build_object('id', ch.id, 'kind', ch.kind, 'name', ch.name,
              'legalHoldReason', ch.legal_hold_reason, 'caseHolds', ch.case_holds) ORDER BY ch.id)
    FROM (
      SELECT c.id, c.kind, c.name, c.legal_hold_reason,
             (SELECT jsonb_agg(jsonb_build_object('caseId', h.case_id, 'holdId', h.id))
                FROM chat_case_hold_channels hc
                JOIN chat_case_holds h ON h.id = hc.hold_id AND h.released_at IS NULL
               WHERE hc.channel_id = c.id) AS case_holds
        FROM chat_channels c
       WHERE chat_hold_active(c.id)          -- REPOINTED (A4b spec §2.3)
       -- ponytail: chat_hold_active(c.id) per row over all channels — a
       -- per-row DEFINER call at admin-console frequency; inline the
       -- two-arm predicate as a set query if a 100k-channel org ever drags.
    ) ch), '[]'::jsonb),
  COALESCE((SELECT jsonb_agg(jsonb_build_object('id', id, 'kind', kind, 'name', name, 'retentionDays', retention_days, 'wormMode', worm_mode) ORDER BY id)
              FROM chat_channels WHERE classification = 'gxp'), '[]'::jsonb),
  COALESCE((SELECT jsonb_agg(jsonb_build_object('id', id, 'kind', kind, 'name', name, 'retentionDays', retention_days) ORDER BY id)
              FROM chat_channels WHERE retention_days IS NOT NULL AND classification = 'regular'), '[]'::jsonb)`

// nextChatPurgeRunAt computes the next occurrence of the chat-purge-expired
// cron ("50 2 * * *", internal/cron/tasks.go). ponytail: the schedule is one
// fixed daily time, not a general cron expression — hardcoding 02:50 is
// simpler than pulling in the cron package's Task/Due machinery for a single
// display field. If the schedule ever needs a real 5-field parse, share
// internal/cron's instead of duplicating one here.
func nextChatPurgeRunAt() time.Time {
	now := time.Now()
	next := time.Date(now.Year(), now.Month(), now.Day(), 2, 50, 0, 0, now.Location())
	if !next.After(now) {
		next = next.Add(24 * time.Hour)
	}
	return next
}

// Overview implements GET /admin/chat-compliance/overview. view or manage.
func (h *ChatComplianceHandler) Overview(w http.ResponseWriter, r *http.Request) {
	if !h.gate(w, r) {
		return
	}
	if _, ok := h.requireViewClaims(w, r); !ok {
		return
	}
	ctx := r.Context()

	var holds, gxp, overrides []byte
	if err := h.workerPool.QueryRow(ctx, overviewChannelsSQL).Scan(&holds, &gxp, &overrides); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "chat compliance overview channels query failed", err)
		return
	}

	// The last chat.purge_run admin_audit_log row (Task 6's chat_purge_run):
	// totals + timestamp + drained. A missing row (no run has ever happened)
	// is a nil lastPurgeRun, not an error — the console renders that as
	// "never run" rather than a stale date.
	var lastPurgeRun any
	var runChannels, runMessages int
	var runDrained bool
	var runAt time.Time
	err := h.workerPool.QueryRow(ctx, `
		SELECT (after_state->>'channels')::int, (after_state->>'messages')::int,
		       (after_state->>'drained')::boolean, occurred_at
		  FROM admin_audit_log WHERE action = 'chat.purge_run' ORDER BY id DESC LIMIT 1`).
		Scan(&runChannels, &runMessages, &runDrained, &runAt)
	switch {
	case err == nil:
		lastPurgeRun = map[string]any{
			"channels":   runChannels,
			"messages":   runMessages,
			"drained":    runDrained,
			"occurredAt": runAt.Format(time.RFC3339),
		}
	case errors.Is(err, pgx.ErrNoRows):
		lastPurgeRun = nil
	default:
		httputil.WriteDBErr(w, r, h.logger, "chat compliance overview last-run query failed", err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"channelsUnderHold":     json.RawMessage(holds),
		"gxpChannels":           json.RawMessage(gxp),
		"channelsWithOverrides": json.RawMessage(overrides),
		"lastPurgeRun":          lastPurgeRun,
		"nextRunAt":             nextChatPurgeRunAt().Format(time.RFC3339),
	})
}

type chatAuditActRow struct {
	ID          int64           `json:"id"`
	OccurredAt  string          `json:"occurredAt"`
	UserID      *int64          `json:"userId,omitempty"`
	IP          string          `json:"ip,omitempty"`
	Action      string          `json:"action"`
	TargetType  *string         `json:"targetType,omitempty"`
	TargetID    *int64          `json:"targetId,omitempty"`
	BeforeState json.RawMessage `json:"beforeState,omitempty"`
	AfterState  json.RawMessage `json:"afterState,omitempty"`
	Notes       *string         `json:"notes,omitempty"`
}

// GetAudit implements GET /admin/chat-channels/{id}/audit?limit=&beforeId=&format=.
// view or manage. workerPool: chat_audit_log is deny-all under FORCE RLS
// (Task 2 — zero policies, the chat_link_previews precedent), so this only
// ever returns rows through the BYPASSRLS admin path. Newest-first,
// keyset-paginated on id (an admin paging through a long chain should not
// re-scan already-seen rows on every page, unlike an offset scheme).
//
// This is an AUDITED read (CEO review #11, ListChannels' own reasoning):
// browsing a channel's compliance acts — hold placements, the matter a
// custodian hold was set under — is itself surveillance-relevant metadata a
// DE/works-council deployment expects logged.
func (h *ChatComplianceHandler) GetAudit(w http.ResponseWriter, r *http.Request) {
	if !h.gate(w, r) {
		return
	}
	claims, ok := h.requireViewClaims(w, r)
	if !ok {
		return
	}
	ctx := r.Context()

	channelID, ok := httputil.ParseIDPath(w, r, "id", "invalid channel id")
	if !ok {
		return
	}
	limit, _ := httputil.ParseLimitOffset(r, 100, 1000)
	var beforeID *int64
	if v := r.URL.Query().Get("beforeId"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid beforeId"})
			return
		}
		beforeID = &id
	}

	rows, err := h.workerPool.Query(ctx, `
		SELECT id, occurred_at, user_id, COALESCE(ip::text, ''), action, target_type, target_id,
		       before_state, after_state, notes
		  FROM chat_audit_log
		 WHERE channel_id = $1 AND ($2::bigint IS NULL OR id < $2)
		 ORDER BY id DESC
		 LIMIT $3`, channelID, beforeID, limit)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "get chat channel audit failed", err)
		return
	}
	defer rows.Close()
	out := []chatAuditActRow{}
	for rows.Next() {
		var a chatAuditActRow
		var occurredAt time.Time
		var ip string
		if err := rows.Scan(&a.ID, &occurredAt, &a.UserID, &ip, &a.Action, &a.TargetType, &a.TargetID,
			&a.BeforeState, &a.AfterState, &a.Notes); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "scan chat channel audit row failed", err)
			return
		}
		a.OccurredAt = occurredAt.Format(time.RFC3339)
		a.IP = ip
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "get chat channel audit failed", err)
		return
	}

	_ = audit.Write(ctx, h.pool, audit.Entry{
		Actor: claims.UserID, Action: "chat_channel_audit_read", TargetType: "chat_channel", TargetID: &channelID,
		IP: httputil.ClientIP(r), Tier: "core",
	})

	if r.URL.Query().Get("format") == "csv" {
		h.writeAuditCSV(ctx, w, channelID, out)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

// writeAuditCSV streams the channel's audit acts as a downloadable CSV with a
// verification header — the chain's validity/keyVersion an auditor keeps as
// the artifact of record alongside the rows (plan: "the acts + the
// verification header as the artifact an auditor actually keeps").
func (h *ChatComplianceHandler) writeAuditCSV(ctx context.Context, w http.ResponseWriter, channelID int64, acts []chatAuditActRow) {
	summary, err := h.chainSummary(ctx, channelID)

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=chat-audit-%d-%s.csv", channelID, time.Now().Format("20060102")))
	w.WriteHeader(http.StatusOK)
	cw := csv.NewWriter(w)
	if err != nil {
		cw.Write([]string{"# verification", "error computing chain validity"}) //nolint:errcheck
	} else {
		cw.Write([]string{ //nolint:errcheck
			"# chain verification",
			fmt.Sprintf("valid=%t", summary.Valid),
			fmt.Sprintf("checked=%d", summary.Checked),
			fmt.Sprintf("keyVersion=%s", summary.KeyVersion),
			fmt.Sprintf("verifiedAt=%s", time.Now().Format(time.RFC3339)),
		})
	}
	cw.Write([]string{"ID", "Occurred At", "User ID", "IP", "Action", "Target Type", "Target ID", "Notes"}) //nolint:errcheck
	for _, a := range acts {
		var userID, targetID, targetType, notes string
		if a.UserID != nil {
			userID = strconv.FormatInt(*a.UserID, 10)
		}
		if a.TargetID != nil {
			targetID = strconv.FormatInt(*a.TargetID, 10)
		}
		if a.TargetType != nil {
			targetType = *a.TargetType
		}
		if a.Notes != nil {
			notes = *a.Notes
		}
		// Formula-injection guard: IP and free-text notes are data-derived —
		// neutralize at the writer seam (admin_csv.go, migration.EscapeCSVCell)
		// before serialization. The two fixed metadata rows above are
		// server-generated constants, not data, and stay literal.
		cw.Write(escapeCSVCells([]string{strconv.FormatInt(a.ID, 10), a.OccurredAt, userID, a.IP, a.Action, targetType, targetID, notes})) //nolint:errcheck
	}
	cw.Flush()
}

// chainSummaryResult is the "can this session verify this chain, and does it"
// summary both GetAudit's CSV header and VerifyAudit's stage-2 check need.
type chainSummaryResult struct {
	Checked      int
	Valid        bool
	FromID       *int64
	ToID         *int64
	FirstInvalid *int64
	KeyVersion   string
}

// chainSummary runs verify_chat_audit_chain (Task 2) over a channel's full
// chain. keyVersion mirrors audit_row_hash_v's own branch (V087): 'v3' when
// the session carries app.audit_hmac_key, 'v2' otherwise.
func (h *ChatComplianceHandler) chainSummary(ctx context.Context, channelID int64) (chainSummaryResult, error) {
	res := chainSummaryResult{Valid: true}
	rows, err := h.workerPool.Query(ctx, `SELECT row_id, valid FROM verify_chat_audit_chain($1)`, channelID)
	if err != nil {
		return res, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var v bool
		if err := rows.Scan(&id, &v); err != nil {
			return res, err
		}
		res.Checked++
		if res.FromID == nil {
			res.FromID = &id
		}
		res.ToID = &id
		if !v {
			res.Valid = false
			if res.FirstInvalid == nil {
				res.FirstInvalid = &id
			}
		}
	}
	if err := rows.Err(); err != nil {
		return res, err
	}
	var hasKey bool
	if err := h.workerPool.QueryRow(ctx,
		`SELECT coalesce(current_setting('app.audit_hmac_key', TRUE), '') <> ''`).Scan(&hasKey); err != nil {
		return res, err
	}
	res.KeyVersion = "v2"
	if hasKey {
		res.KeyVersion = "v3"
	}
	return res, nil
}

type chatAuditHead struct {
	ID       int64  `json:"id"`
	Checksum string `json:"checksum"`
}

// VerifyAudit implements GET /admin/chat-channels/{id}/audit/verify. view or
// manage. THE ORDERED three-stage check (plan, binding — FIX 1): (1) the
// chain-head notary truncation cross-check; (2) verify_chat_audit_chain for a
// mid-chain break; (3) chat_chain_anchor_verify. A truncation or a break
// SHORT-CIRCUITS stage 3 — the anchor verdicts are computed from inputs that
// ride the broken/truncated chain (the purge acts' destroyedElems among them)
// and must not be offered as if they meant anything.
func (h *ChatComplianceHandler) VerifyAudit(w http.ResponseWriter, r *http.Request) {
	if !h.gate(w, r) {
		return
	}
	if _, ok := h.requireViewClaims(w, r); !ok {
		return
	}
	ctx := r.Context()

	channelID, ok := httputil.ParseIDPath(w, r, "id", "invalid channel id")
	if !ok {
		return
	}

	// Stage 1 — the notary truncation cross-check: the last chat.chain_notary
	// admin_audit_log row's head for this channel vs. the LIVE chat_audit_log
	// head. A channel absent from the notary map (never anchored) has no
	// floor to check.
	var notarizedHead *chatAuditHead
	var headJSON []byte
	err := h.workerPool.QueryRow(ctx, `
		SELECT after_state->'heads'->$1::text
		  FROM admin_audit_log
		 WHERE action = 'chat.chain_notary'
		 ORDER BY id DESC LIMIT 1`, strconv.FormatInt(channelID, 10)).Scan(&headJSON)
	switch {
	case err == nil && len(headJSON) > 0 && string(headJSON) != "null":
		var head chatAuditHead
		if jsonErr := json.Unmarshal(headJSON, &head); jsonErr == nil && head.Checksum != "" {
			notarizedHead = &head
		}
	case err != nil && !errors.Is(err, pgx.ErrNoRows):
		httputil.WriteDBErr(w, r, h.logger, "chat audit notary lookup failed", err)
		return
	}

	var liveHead *chatAuditHead
	var liveID int64
	var liveChecksum string
	err = h.workerPool.QueryRow(ctx, `
		SELECT id, after_state->>'_checksum' FROM chat_audit_log
		 WHERE channel_id = $1 ORDER BY id DESC LIMIT 1`, channelID).Scan(&liveID, &liveChecksum)
	switch {
	case err == nil:
		liveHead = &chatAuditHead{ID: liveID, Checksum: liveChecksum}
	case errors.Is(err, pgx.ErrNoRows):
		liveHead = nil
	default:
		httputil.WriteDBErr(w, r, h.logger, "chat audit live-head lookup failed", err)
		return
	}

	truncationDetected := false
	if notarizedHead != nil {
		if liveHead == nil || liveHead.ID < notarizedHead.ID {
			truncationDetected = true
		} else {
			var csAtNotarized *string
			qErr := h.workerPool.QueryRow(ctx, `
				SELECT after_state->>'_checksum' FROM chat_audit_log
				 WHERE channel_id = $1 AND id = $2`, channelID, notarizedHead.ID).Scan(&csAtNotarized)
			if qErr != nil && !errors.Is(qErr, pgx.ErrNoRows) {
				httputil.WriteDBErr(w, r, h.logger, "chat audit notarized-row lookup failed", qErr)
				return
			}
			if csAtNotarized == nil || *csAtNotarized != notarizedHead.Checksum {
				truncationDetected = true
			}
		}
	}

	// Stage 2 — the mid-chain break check.
	summary, err := h.chainSummary(ctx, channelID)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "verify chat audit chain failed", err)
		return
	}

	resp := map[string]any{
		"channelId":          channelID,
		"checked":            summary.Checked,
		"fromId":             summary.FromID,
		"toId":               summary.ToID,
		"chainValid":         summary.Valid,
		"firstInvalid":       summary.FirstInvalid,
		"verifiedAt":         time.Now().Format(time.RFC3339),
		"keyVersion":         summary.KeyVersion,
		"truncationDetected": truncationDetected,
	}
	if notarizedHead != nil {
		resp["notarizedHead"] = notarizedHead
	}
	if liveHead != nil {
		resp["liveHead"] = liveHead
	}

	if truncationDetected || !summary.Valid {
		httputil.WriteJSON(w, http.StatusOK, resp)
		return
	}

	// Stage 3 — anchor reconciliation (chat_chain_anchor_verify, Task 9).
	rows, err := h.workerPool.Query(ctx, `
		SELECT anchor_id, id_from, id_to, valid, reconciled_from_purge, revisions_unchained
		  FROM chat_chain_anchor_verify($1)`, channelID)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "chat chain anchor verify failed", err)
		return
	}
	defer rows.Close()
	type anchorVerdict struct {
		AnchorID            int64 `json:"anchorId"`
		IDFrom              int64 `json:"idFrom"`
		IDTo                int64 `json:"idTo"`
		Valid               bool  `json:"valid"`
		ReconciledFromPurge int   `json:"reconciledFromPurge"`
		RevisionsUnchained  int   `json:"revisionsUnchained"`
	}
	anchors := []anchorVerdict{}
	for rows.Next() {
		var a anchorVerdict
		if err := rows.Scan(&a.AnchorID, &a.IDFrom, &a.IDTo, &a.Valid, &a.ReconciledFromPurge, &a.RevisionsUnchained); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "scan chat chain anchor verdict failed", err)
			return
		}
		anchors = append(anchors, a)
	}
	if err := rows.Err(); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "chat chain anchor verify failed", err)
		return
	}
	resp["anchors"] = anchors

	httputil.WriteJSON(w, http.StatusOK, resp)
}
