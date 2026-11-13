package user

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/identity"
	"setjoin.com/shared/pgxutil"
)

// RulesHandler provides admin CRUD for mail rules (mounted under /admin/rules,
// requireAuth + RequirePermAudited(mail.pipeline)).
//
// native-RLS (W7): Test() runs a candidate rule against recent messages, and a
// rule's mailbox_id may be NULL (an org-wide transport rule), in which case the
// COALESCE($1, t.mailbox_id) predicate matches EVERY mailbox's messages — a
// deliberately CROSS-TENANT admin read. So the handler runs on the setjoin_worker
// (BYPASSRLS) pool; under the W6 FORCE flip a tenant GUC would deny the
// cross-mailbox rows. pool aliases the app pool until DB_WORKER_DSN is set, INERT.
type RulesHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewRulesHandler takes the BYPASSRLS worker pool (cross-tenant admin; see type doc).
func NewRulesHandler(workerPool pgxutil.WorkerPool, logger *slog.Logger) *RulesHandler {
	return &RulesHandler{pool: workerPool.Pool, logger: logger}
}

type ruleRequest struct {
	MailboxID       *int64          `json:"mailboxId,omitempty"`
	Name            string          `json:"name"`
	Enabled         bool            `json:"enabled"`
	Priority        int             `json:"priority"`
	RunOn           string          `json:"runOn"` // server, client, both
	IsTransportRule bool            `json:"isTransportRule"`
	Conditions      json.RawMessage `json:"conditions"`
	Actions         json.RawMessage `json:"actions"`
	StopProcessing  bool            `json:"stopProcessing"`
}

type ruleResponse struct {
	ID              int64           `json:"id"`
	MailboxID       *int64          `json:"mailboxId,omitempty"`
	Name            string          `json:"name"`
	Enabled         bool            `json:"enabled"`
	Priority        int             `json:"priority"`
	RunOn           string          `json:"runOn"`
	IsTransportRule bool            `json:"isTransportRule"`
	Conditions      json.RawMessage `json:"conditions"`
	Actions         json.RawMessage `json:"actions"`
	StopProcessing  bool            `json:"stopProcessing"`
	CreatedAt       time.Time       `json:"createdAt"`
	UpdatedAt       time.Time       `json:"updatedAt"`
}

// List returns all rules, optionally filtered by mailbox_id.
func (h *RulesHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	mailboxID := r.URL.Query().Get("mailboxId")

	var rows pgx.Rows
	var err error
	if mailboxID != "" {
		id, _ := strconv.ParseInt(mailboxID, 10, 64)
		rows, err = h.pool.Query(ctx,
			`SELECT id, mailbox_id, name, enabled, priority, run_on, is_transport_rule,
			        conditions, actions, stop_processing, created_at, updated_at
			 FROM rules WHERE mailbox_id = $1 ORDER BY priority, id`, id)
	} else {
		rows, err = h.pool.Query(ctx,
			`SELECT id, mailbox_id, name, enabled, priority, run_on, is_transport_rule,
			        conditions, actions, stop_processing, created_at, updated_at
			 FROM rules ORDER BY is_transport_rule DESC, priority, id`)
	}
	if err != nil {
		h.logger.Error("rules list failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	out := make([]ruleResponse, 0)
	for rows.Next() {
		var r ruleResponse
		var mbID *int64
		err := rows.Scan(&r.ID, &mbID, &r.Name, &r.Enabled, &r.Priority, &r.RunOn,
			&r.IsTransportRule, &r.Conditions, &r.Actions, &r.StopProcessing,
			&r.CreatedAt, &r.UpdatedAt)
		if err != nil {
			continue
		}
		r.MailboxID = mbID
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		h.logger.Error("rules list rows error", "error", err)
	}

	httputil.WriteJSON(w, http.StatusOK, out)
}

// Get returns a single rule by ID.
func (h *RulesHandler) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := strings.TrimPrefix(r.URL.Path, "/admin/rules/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid rule id")
		return
	}

	var resp ruleResponse
	var mbID *int64
	err = h.pool.QueryRow(ctx,
		`SELECT id, mailbox_id, name, enabled, priority, run_on, is_transport_rule,
		        conditions, actions, stop_processing, created_at, updated_at
		 FROM rules WHERE id = $1`, id,
	).Scan(&resp.ID, &mbID, &resp.Name, &resp.Enabled, &resp.Priority, &resp.RunOn,
		&resp.IsTransportRule, &resp.Conditions, &resp.Actions, &resp.StopProcessing,
		&resp.CreatedAt, &resp.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			httputil.WriteError(w, http.StatusNotFound, "rule not found")
			return
		}
		h.logger.Error("rule get failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	resp.MailboxID = mbID

	httputil.WriteJSON(w, http.StatusOK, resp)
}

// Create adds a new rule. Supports template-based creation via ?from_template=<id>.
func (h *RulesHandler) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Check for template-based creation
	if templateIDStr := r.URL.Query().Get("from_template"); templateIDStr != "" {
		h.createFromTemplate(w, r, templateIDStr)
		return
	}

	var req ruleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if req.Name == "" {
		httputil.WriteError(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.RunOn == "" {
		req.RunOn = "server"
	}

	// Transport rules have no mailbox (mailbox_id IS NULL). Only check mailbox
	// existence when a mailbox_id is provided; when absent, require isTransportRule.
	if req.MailboxID != nil {
		var mailboxExists bool
		if err := h.pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM mailboxes WHERE id = $1)`,
			*req.MailboxID,
		).Scan(&mailboxExists); err != nil || !mailboxExists {
			httputil.WriteError(w, http.StatusBadRequest, "mailbox not found")
			return
		}
	} else if !req.IsTransportRule {
		httputil.WriteError(w, http.StatusBadRequest, "mailbox_id required for non-transport rules")
		return
	}

	// WP3: the write is reducer-owned (rule_config_create) so configuration
	// changes land an admin_audit_log row; containment/validation moved with it.
	actor := auth.UserFromContext(ctx)
	if actor == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var id int64
	err := h.pool.QueryRow(ctx,
		`SELECT rule_config_create($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		actor.UserID, req.MailboxID, req.Name, req.Enabled, req.Priority, req.RunOn,
		req.IsTransportRule, req.Conditions, req.Actions, req.StopProcessing,
	).Scan(&id)
	if err != nil {
		h.logger.Error("rule create failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	httputil.WriteJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

// Update modifies an existing rule.
func (h *RulesHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := strings.TrimPrefix(r.URL.Path, "/admin/rules/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid rule id")
		return
	}

	var req ruleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	user := auth.UserFromContext(ctx)
	if user == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// WP3: reducer-owned write with the actor-containment predicate inside the
	// mutation; FALSE = no such rule for this actor (→ 404, API outcome kept).
	var updated bool
	err = h.pool.QueryRow(ctx,
		`SELECT rule_config_update($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		user.UserID, id, req.MailboxID, req.Name, req.Enabled, req.Priority, req.RunOn,
		req.IsTransportRule, req.Conditions, req.Actions, req.StopProcessing,
	).Scan(&updated)
	if err != nil {
		h.logger.Error("rule update failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if !updated {
		httputil.WriteError(w, http.StatusNotFound, "rule not found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Delete removes a rule.
func (h *RulesHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := strings.TrimPrefix(r.URL.Path, "/admin/rules/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid rule id")
		return
	}

	user := auth.UserFromContext(ctx)
	if user == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// WP3: reducer-owned delete with in-mutation containment; FALSE → 404.
	var deleted bool
	err = h.pool.QueryRow(ctx,
		`SELECT rule_config_delete($1, $2)`, user.UserID, id,
	).Scan(&deleted)
	if err != nil {
		h.logger.Error("rule delete failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if !deleted {
		httputil.WriteError(w, http.StatusNotFound, "rule not found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Test runs a dry-run of a rule against the most recent messages.
func (h *RulesHandler) Test(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := strings.TrimPrefix(r.URL.Path, "/admin/rules/")
	idStr = strings.TrimSuffix(idStr, "/test")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid rule id")
		return
	}

	// Fetch the rule
	var conds, acts json.RawMessage
	var mbID *int64
	err = h.pool.QueryRow(ctx,
		`SELECT mailbox_id, conditions, actions FROM rules WHERE id = $1`, id,
	).Scan(&mbID, &conds, &acts)
	if err != nil {
		if err == pgx.ErrNoRows {
			httputil.WriteError(w, http.StatusNotFound, "rule not found")
			return
		}
		h.logger.Error("rule test fetch failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	// Run the rule against last 20 messages in the mailbox (sandboxed: only last 7 days).
	var results []map[string]interface{}
	rows, err := h.pool.Query(ctx,
		`SET LOCAL statement_timeout = '5s';
		 SELECT DISTINCT m.id, m.received_at, m.message_id, m.from_addr, m.subject
		 FROM messages m
		 JOIN message_tags mt ON mt.message_id = m.id AND mt.received_at = m.received_at
		 JOIN tags t ON t.id = mt.tag_id
		 WHERE t.mailbox_id = COALESCE($1, t.mailbox_id)
		   AND m.received_at > now() - interval '7 days'
		 ORDER BY m.received_at DESC
		 LIMIT 20`, mbID)
	if err != nil {
		h.logger.Error("rule test query failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	for rows.Next() {
		var msgID int64
		var receivedAt time.Time
		var msgIDStr, fromAddr, subject string
		if err := rows.Scan(&msgID, &receivedAt, &msgIDStr, &fromAddr, &subject); err != nil {
			continue
		}
		results = append(results, map[string]interface{}{
			"messageId":  msgID,
			"receivedAt": receivedAt,
			"fromAddr":   fromAddr,
			"subject":    subject,
			"wouldMatch": h.evalRuleConditions(ctx, int(id), msgID, receivedAt, conds),
		})
	}
	if err := rows.Err(); err != nil {
		h.logger.Error("rule test rows error", "error", err)
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"ruleId":     id,
		"conditions": conds,
		"actions":    acts,
		"matches":    results,
	})
}

func (h *RulesHandler) evalRuleConditions(ctx context.Context, ruleID int, msgID int64, receivedAt time.Time, conditions []byte) bool {
	var matched bool
	err := h.pool.QueryRow(ctx,
		`SELECT eval_conditions(
			(SELECT row_to_json(m)::JSONB FROM messages m WHERE id = $1 AND received_at = $2),
			$3::JSONB
		)`,
		msgID, receivedAt, conditions,
	).Scan(&matched)
	return err == nil && matched
}

func (h *RulesHandler) createFromTemplate(w http.ResponseWriter, r *http.Request, templateIDStr string) {
	ctx := r.Context()
	templateID, err := strconv.ParseInt(templateIDStr, 10, 64)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid template id")
		return
	}

	// Load template
	var name, category string
	var conditions, actions, parameters []byte
	err = h.pool.QueryRow(ctx,
		`SELECT name, category, conditions, actions, parameters FROM rule_templates WHERE id = $1 AND enabled = TRUE`,
		templateID,
	).Scan(&name, &category, &conditions, &actions, &parameters)
	if err != nil {
		httputil.WriteError(w, http.StatusNotFound, "template not found")
		return
	}

	// Parse user-provided parameter values
	var params map[string]string
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid parameters JSON")
		return
	}

	// Resolve placeholders in conditions and actions
	resolvedActions := json.RawMessage(resolvePlaceholders(actions, params))
	resolvedConditions := json.RawMessage(resolvePlaceholders(conditions, params))

	// Resolve the user's primary mailbox_id for scoping the rule
	user := auth.UserFromContext(ctx)
	var mailboxID *int64
	if user != nil {
		if mbID, err := identity.ResolvePrimaryMailbox(ctx, h.pool, user.UserID); err == nil {
			mailboxID = &mbID
		}
	}

	// Create the rule — WP3: reducer-owned write with its audit row. The actor
	// is the authenticated user (nil → system context as before); the mailbox
	// was resolved server-side above, never from the request.
	var id int64
	var actorID *int64
	if user != nil {
		idCopy := user.UserID
		actorID = &idCopy
	}
	err = h.pool.QueryRow(ctx,
		`SELECT rule_config_template_create($1, $2, $3, $4, $5)`,
		actorID, mailboxID, name, resolvedConditions, resolvedActions,
	).Scan(&id)
	if err != nil {
		h.logger.Error("template rule create failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	httputil.WriteJSON(w, http.StatusCreated, map[string]interface{}{
		"id":       id,
		"name":     name,
		"category": category,
	})
}

func resolvePlaceholders(data []byte, params map[string]string) string {
	s := string(data)
	for key, val := range params {
		escaped, _ := json.Marshal(val)
		placeholder := fmt.Sprintf(`"{{%s}}"`, key)
		s = strings.ReplaceAll(s, placeholder, string(escaped))
	}
	return s
}
