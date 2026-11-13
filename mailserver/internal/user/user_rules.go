package user

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/identity"
)

// UserRulesHandler is the END-USER surface for mail rules (mounted at /settings/rules
// behind requireAuth). It is the security-scoped counterpart to the admin RulesHandler:
// EVERY query is constrained to the caller's OWN mailboxes and to NON-transport rules,
// so a user can never read/edit/delete another tenant's rules nor create/modify an
// org-wide transport rule. The admin RulesHandler's List/Get/Create are intentionally
// unscoped (cross-tenant admin management, admin-perm-gated) and must NOT back a user
// route — hence this dedicated handler with its own scoped SQL. The rules engine
// (apply_rules + eval_conditions/apply_action) is reused unchanged. Uses the app pool:
// a user only ever touches their own rows, so no BYPASSRLS carve-out is needed.
type UserRulesHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

func NewUserRulesHandler(pool *pgxpool.Pool, logger *slog.Logger) *UserRulesHandler {
	return &UserRulesHandler{pool: pool, logger: logger}
}

// ER5 occ_ad8a413b31c65399a5a6abeb (unbounded-rule-evaluation-delivery) and
// occ_0cd0f2f744230e79abc58690 (unbounded-forward-actions): the user rule
// program is size-bounded and ORGANIZE-ONLY. The rules engine evaluates every
// server-side rule per delivered message on the shared PostgreSQL cluster, so
// an unbounded count × unbounded program size is a delivery-path resource
// exhaust; and send-time actions (forward_to/redirect/bcc queue outbound mail;
// add_header/append_footer mutate outbound MIME) would turn a client-authored
// rule into an unbounded outbound amplifier — the same send-time set the
// engine's organize-only retro guard refuses (rule_engine.sql p_organize_only).
const (
	// maxRuleBodyBytes bounds the whole request body (mirrors the repo's
	// http.MaxBytesReader precedents: telemetry ingest 64KB, signatures 128KB).
	maxRuleBodyBytes = 64 << 10 // 64 KB
	// maxRuleProgramBytes bounds the stored conditions or actions JSON of one rule.
	maxRuleProgramBytes = 16 << 10 // 16 KB
	// maxRuleNameLen bounds one rule name.
	maxRuleNameLen = 200
	// maxRuleConditions / maxRuleActions bound the per-rule program entry
	// counts the delivery engine evaluates per message.
	maxRuleConditions = 20
	maxRuleActions    = 20
	// maxRulesPerMailbox bounds how many rules ONE mailbox can stack — the
	// delivery engine runs every enabled rule against every delivered message,
	// so the per-mailbox rule count is the amplification multiplier.
	maxRulesPerMailbox = 100
)

// maxRetroBodyBytes bounds the apply-retro request body (a single window enum).
const maxRetroBodyBytes = 4 << 10

// maxRetroSweepsInFlight caps concurrent (pending/processing) rules_retro
// sweeps per mailbox. Each sweep pages historical mail through the shared
// scheduled_actions dispatcher (occ_9e336c84f2d3596e2e86941d): one sweep per
// rule is deduped by the reducer, but a mailbox with many rules could still
// enqueue unbounded heavy sweeps and starve every other tenant's scheduled
// work. The reducer's per-(mailbox,rule) dedup is necessary but not
// sufficient; this is the per-mailbox concurrency admission bound.
const maxRetroSweepsInFlight = 3

// sendTimeRuleActions is the engine's send-time action vocabulary (the exact
// set rule_engine.sql refuses under p_organize_only). These never pass the
// user surface: a client-authored rule must not queue or mutate outbound mail.
var sendTimeRuleActions = map[string]struct{}{
	"forward_to":    {},
	"redirect":      {},
	"bcc":           {},
	"append_footer": {},
	"add_header":    {},
}

// validateRuleProgram bounds one persisted rule-program field (conditions or
// actions): practical byte size, array shape, and entry count. For actions it
// additionally refuses the engine's send-time vocabulary — the user surface is
// organize-only. A returned error text names the offending field (the 400
// contract used by this package's bounds).
func validateRuleProgram(field string, raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil // treated as "no change"/empty by the SQL COALESCE paths
	}
	if len(raw) > maxRuleProgramBytes {
		return fmt.Errorf("%s is too long", field)
	}
	var entries []struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return fmt.Errorf("%s must be a JSON array", field)
	}
	limit := maxRuleConditions
	if field == "actions" {
		limit = maxRuleActions
	}
	if len(entries) > limit {
		return fmt.Errorf("%s has too many entries", field)
	}
	if field == "actions" {
		for _, e := range entries {
			if _, blocked := sendTimeRuleActions[e.Type]; blocked {
				return fmt.Errorf("action type %q is not allowed on personal rules (organize-only)", e.Type)
			}
		}
	}
	return nil
}

// List returns the caller's own (non-transport) rules.
func (h *UserRulesHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := auth.UserFromContext(ctx)
	if user == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	rows, err := h.pool.Query(ctx,
		`SELECT id, mailbox_id, name, enabled, priority, run_on, is_transport_rule,
		        conditions, actions, stop_processing, created_at, updated_at
		 FROM rules
		 WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = $1)
		   AND is_transport_rule = FALSE
		 ORDER BY priority, id`, user.UserID)
	if err != nil {
		h.logger.Error("user rules list failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	out := make([]ruleResponse, 0)
	for rows.Next() {
		var rr ruleResponse
		var mbID *int64
		if err := rows.Scan(&rr.ID, &mbID, &rr.Name, &rr.Enabled, &rr.Priority, &rr.RunOn,
			&rr.IsTransportRule, &rr.Conditions, &rr.Actions, &rr.StopProcessing,
			&rr.CreatedAt, &rr.UpdatedAt); err != nil {
			continue
		}
		rr.MailboxID = mbID
		out = append(out, rr)
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

// Create adds a rule scoped to the caller's PRIMARY mailbox. The client cannot choose a
// mailbox (never another user's) nor make a transport rule — both are forced server-side.
func (h *UserRulesHandler) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := auth.UserFromContext(ctx)
	if user == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// Bound the decoded body before json.Decode can buffer it (the
	// MaxBytesReader surfaces an oversized body as a decode error → 400).
	r.Body = http.MaxBytesReader(w, r.Body, maxRuleBodyBytes)

	var req ruleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Name == "" {
		httputil.WriteError(w, http.StatusBadRequest, "name is required")
		return
	}
	if len(req.Name) > maxRuleNameLen {
		httputil.WriteError(w, http.StatusBadRequest, "name is too long")
		return
	}
	if err := validateRuleProgram("conditions", req.Conditions); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateRuleProgram("actions", req.Actions); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	runOn, ok := normalizeRunOn(req.RunOn)
	if !ok {
		httputil.WriteError(w, http.StatusBadRequest, "runOn must be server, client, or both")
		return
	}

	// R2: the mailbox comes from the auth context, never the request body.
	mbID, err := identity.ResolvePrimaryMailbox(ctx, h.pool, user.UserID)
	if err != nil {
		h.logger.Error("user rule create: resolve mailbox failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "mailbox not found")
		return
	}

	// Per-mailbox rule-count admission: the delivery engine evaluates every
	// enabled rule per message, so the stored rule count is the amplification
	// multiplier against the shared PostgreSQL cluster.
	var ruleCount int
	if err := h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM rules WHERE mailbox_id = $1`, mbID,
	).Scan(&ruleCount); err != nil {
		h.logger.Error("user rule create: count rules failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if ruleCount >= maxRulesPerMailbox {
		httputil.WriteError(w, http.StatusBadRequest, "rule limit reached for this mailbox")
		return
	}

	var id int64
	err = h.pool.QueryRow(ctx,
		`INSERT INTO rules (mailbox_id, name, enabled, priority, run_on, is_transport_rule,
		                    conditions, actions, stop_processing)
		 VALUES ($1, $2, $3, $4, $5, FALSE, $6, $7, $8)
		 RETURNING id`,
		mbID, req.Name, req.Enabled, req.Priority, runOn,
		req.Conditions, req.Actions, req.StopProcessing,
	).Scan(&id)
	if err != nil {
		h.logger.Error("user rule create failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	httputil.WriteJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

// Update edits one of the caller's own rules. mailbox_id and is_transport_rule are NOT
// client-settable (no reassigning a rule to another mailbox, no promoting it to a
// transport rule); the ownership + non-transport predicate scopes the write.
func (h *UserRulesHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := auth.UserFromContext(ctx)
	if user == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid rule id")
		return
	}

	// Same bounds as Create: the stored program stays size-capped and
	// organize-only no matter which handler wrote it.
	r.Body = http.MaxBytesReader(w, r.Body, maxRuleBodyBytes)
	var req ruleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if len(req.Name) > maxRuleNameLen {
		httputil.WriteError(w, http.StatusBadRequest, "name is too long")
		return
	}
	if err := validateRuleProgram("conditions", req.Conditions); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateRuleProgram("actions", req.Actions); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	runOn, ok := normalizeRunOn(req.RunOn)
	if !ok {
		httputil.WriteError(w, http.StatusBadRequest, "runOn must be server, client, or both")
		return
	}

	ct, err := h.pool.Exec(ctx,
		`UPDATE rules SET
			name = COALESCE(NULLIF($3,''), name),
			enabled = $4,
			priority = $5,
			run_on = $6,
			conditions = COALESCE($7, conditions),
			actions = COALESCE($8, actions),
			stop_processing = $9,
			updated_at = now()
		 WHERE id = $1
		   AND mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = $2)
		   AND is_transport_rule = FALSE`,
		id, user.UserID, req.Name, req.Enabled, req.Priority, runOn,
		req.Conditions, req.Actions, req.StopProcessing)
	if err != nil {
		h.logger.Error("user rule update failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if ct.RowsAffected() == 0 {
		httputil.WriteError(w, http.StatusNotFound, "rule not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Delete removes one of the caller's own (non-transport) rules.
func (h *UserRulesHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := auth.UserFromContext(ctx)
	if user == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid rule id")
		return
	}
	ct, err := h.pool.Exec(ctx,
		`DELETE FROM rules WHERE id = $1
		   AND mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = $2)
		   AND is_transport_rule = FALSE`, id, user.UserID)
	if err != nil {
		h.logger.Error("user rule delete failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if ct.RowsAffected() == 0 {
		httputil.WriteError(w, http.StatusNotFound, "rule not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// applyRetroRequest is the POST body for retroactively applying a rule to existing mail.
type applyRetroRequest struct {
	Window string `json:"window"` // 90d | 1y | all
}

// ApplyRetro enqueues an async sweep that applies ONE of the caller's own rules to
// their existing mail (POST /settings/rules/{id}/apply, body {window}). It returns
// 202 + the scheduled-action id immediately; the heavy work runs in the
// scheduled_actions dispatcher (`rules_retro` handler) with organize-only semantics
// so no historical mail is ever re-sent. Rule ownership + window validity are
// enforced in the reducer (R1). RFC 7807 problem responses.
func (h *UserRulesHandler) ApplyRetro(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := auth.UserFromContext(ctx)
	if user == nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnauthorized, Type: httputil.TypeUnauthorized, Detail: "authentication required"})
		return
	}
	ruleID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Type: httputil.TypeValidationFailed, Detail: "invalid rule id"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRetroBodyBytes)
	var req applyRetroRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Type: httputil.TypeInvalidJSON, Detail: "invalid JSON"})
		return
	}
	if req.Window == "" {
		req.Window = "90d"
	}
	if req.Window != "90d" && req.Window != "1y" && req.Window != "all" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Type: httputil.TypeValidationFailed, Detail: "window must be 90d, 1y, or all"})
		return
	}

	// R2: mailbox from auth, never the request. The reducer re-checks that the rule
	// belongs to this mailbox (R1) before enqueueing.
	mbID, err := identity.ResolvePrimaryMailbox(ctx, h.pool, user.UserID)
	if err != nil {
		h.logger.Error("rule apply-retro: resolve mailbox failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Type: httputil.TypeInternalError, Detail: "mailbox not found"})
		return
	}

	// Per-mailbox concurrency admission for the shared dispatcher: the reducer
	// dedups per (mailbox, rule), but a mailbox with many rules could still
	// stack unbounded heavy sweeps and starve every other tenant's scheduled
	// work. Refuse the enqueue (429) once the mailbox already holds the cap of
	// pending/processing sweeps.
	var inFlight int
	if err := h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM scheduled_actions
		  WHERE mailbox_id = $1
		    AND action_kind = 'rules_retro'
		    AND status IN ('pending','processing')`, mbID,
	).Scan(&inFlight); err != nil {
		h.logger.Error("rule apply-retro: count in-flight failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Type: httputil.TypeInternalError, Detail: "database error"})
		return
	}
	if inFlight >= maxRetroSweepsInFlight {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusTooManyRequests, Type: httputil.TypeRateLimited,
			Title:  "Too many active rule sweeps",
			Detail: "this mailbox already has the maximum number of rule sweeps in progress; wait for one to finish",
		})
		return
	}

	var actionID string
	err = h.pool.QueryRow(ctx,
		`SELECT rules_apply_retroactive($1, $2, $3)::TEXT`, mbID, ruleID, req.Window,
	).Scan(&actionID)
	if err != nil {
		status := reducerErrorStatus(err)
		if status == http.StatusInternalServerError {
			h.logger.Error("rule apply-retro failed", "error", err)
		}
		problemType := httputil.TypeInternalError
		detail := "database error"
		switch status {
		case http.StatusNotFound:
			problemType, detail = httputil.TypeNotFound, "rule not found"
		case http.StatusBadRequest:
			problemType, detail = httputil.TypeValidationFailed, "invalid request"
		}
		httputil.WriteProblem(w, r, &httputil.Problem{Status: status, Type: problemType, Detail: detail})
		return
	}

	httputil.WriteJSON(w, http.StatusAccepted, map[string]string{"actionId": actionID, "status": "queued"})
}

// ApplyStatus reports the progress of a retro-apply sweep by its action id
// (GET /settings/rules/apply/{actionId}). Scoped to the caller's own mailbox (R1):
// {status: pending|processing|done|failed, processed, truncated}. processed/
// truncated are populated by the handler once the sweep completes.
func (h *UserRulesHandler) ApplyStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := auth.UserFromContext(ctx)
	if user == nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnauthorized, Type: httputil.TypeUnauthorized, Detail: "authentication required"})
		return
	}
	actionID := r.PathValue("actionId")
	if actionID == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Type: httputil.TypeValidationFailed, Detail: "invalid action id"})
		return
	}

	var status string
	var processed *int64
	var truncated *bool
	err := h.pool.QueryRow(ctx,
		`SELECT status,
		        (payload->>'processed')::BIGINT,
		        (payload->>'truncated')::BOOLEAN
		 FROM scheduled_actions
		 WHERE id = $1::UUID
		   AND action_kind = 'rules_retro'
		   AND mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = $2)`,
		actionID, user.UserID,
	).Scan(&status, &processed, &truncated)
	if err != nil {
		// Unknown id, foreign mailbox, or malformed UUID all read as "not found" —
		// no cross-tenant existence oracle.
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Type: httputil.TypeNotFound, Detail: "apply job not found"})
		return
	}

	out := map[string]any{"status": status}
	if processed != nil {
		out["processed"] = *processed
	}
	if truncated != nil {
		out["truncated"] = *truncated
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

// normalizeRunOn defaults an empty value to "server" and rejects anything outside the
// engine's vocabulary (server | client | both).
func normalizeRunOn(v string) (string, bool) {
	switch v {
	case "", "server":
		return "server", true
	case "client", "both":
		return v, true
	default:
		return "", false
	}
}
