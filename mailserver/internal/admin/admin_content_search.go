package admin

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/kql"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/pgxutil"
)

// maxContentSearchBodyBytes bounds the decoded request body of both content
// search handlers (telemetry 64KB MaxBytesReader precedent). KQL queries are
// separately capped at kql.MaxQueryLength runes; the body cap keeps the DECODE
// itself off the attacker's memory budget (an unbounded json.Decoder would
// buffer the whole request before the length caps could fire) and bounds the
// legacy keyword path the KQL cap does not reach.
const maxContentSearchBodyBytes = 64 << 10

// ContentSearchHandler provides cross-mailbox FTS search with mass-delete.
type ContentSearchHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

func NewContentSearchHandler(workerPool pgxutil.WorkerPool, logger *slog.Logger) *ContentSearchHandler {
	return &ContentSearchHandler{pool: workerPool.Pool, logger: logger}
}

// Search runs a synchronous cross-mailbox FTS search (max 500 results).
// Supports both legacy keyword-based search and KQL Boolean search.
func (h *ContentSearchHandler) Search(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Keywords   string  `json:"keywords"`
		KQL        string  `json:"kql,omitempty"`
		FromAddr   string  `json:"fromAddr,omitempty"`
		DateFrom   string  `json:"dateFrom,omitempty"`
		DateTo     string  `json:"dateTo,omitempty"`
		MailboxIDs []int64 `json:"mailboxIds,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxContentSearchBodyBytes)).Decode(&req); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid request")
		return
	}

	var sql string
	var args []interface{}

	if req.KQL != "" {
		// KQL Boolean search — enforce the resource-bound length cap at the
		// handler boundary so a hostile query from a compliance.write
		// principal is rejected with a bounded 400 before any parse work.
		// The nesting-depth and term-count caps are enforced inside
		// kql.Parse on every application and surface as its bounded error
		// below — never a fatal abort.
		if len([]rune(strings.TrimSpace(req.KQL))) > kql.MaxQueryLength {
			httputil.WriteProblemStatus(w, http.StatusBadRequest,
				fmt.Sprintf("invalid KQL query: query exceeds maximum length of %d characters", kql.MaxQueryLength))
			return
		}
		// Parse and build SQL from AST
		ast, err := kql.Parse(req.KQL)
		if err != nil {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid KQL query: "+err.Error())
			return
		}
		whereSQL, kqlArgs := kql.BuildSQL(ast)
		sql = fmt.Sprintf(`SELECT m.id, m.subject, m.from_addr, m.received_at, mb.email as mailbox
		 FROM messages m JOIN mailboxes mb ON mb.id = m.mailbox_id
		 WHERE %s`, whereSQL)
		args = kqlArgs
	} else {
		// Legacy keyword-based search
		if req.Keywords == "" && req.FromAddr == "" {
			httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "keywords, fromAddr, or kql required"})
			return
		}

		// Plain GIN/tsquery (2026-07-04 queue-B #2 revert): ParadeDB is never
		// installed, so the prior @@@/paradedb.parse syntax threw here on every
		// deployment.
		sql = `SELECT m.id, m.subject, m.from_addr, m.received_at, mb.email as mailbox
		 FROM messages m JOIN mailboxes mb ON mb.id = m.mailbox_id
		 WHERE (m.body_tsv @@ websearch_to_tsquery('simple', $1)
		    OR m.subject_tsv @@ websearch_to_tsquery('simple', $1)
		    OR m.from_tsv @@ websearch_to_tsquery('simple', $1))`
		args = []interface{}{req.Keywords}
		argIdx := 2

		if req.FromAddr != "" {
			sql += fmt.Sprintf(" AND m.from_addr ILIKE '%%' || $%d || '%%'", argIdx)
			args = append(args, req.FromAddr)
			argIdx++
		}
		if req.DateFrom != "" {
			sql += fmt.Sprintf(" AND m.received_at >= $%d", argIdx)
			args = append(args, req.DateFrom)
			argIdx++
		}
		if req.DateTo != "" {
			sql += fmt.Sprintf(" AND m.received_at <= $%d", argIdx)
			args = append(args, req.DateTo)
			argIdx++
		}
		if len(req.MailboxIDs) > 0 {
			sql += fmt.Sprintf(" AND m.mailbox_id = ANY($%d::bigint[])", argIdx)
			args = append(args, req.MailboxIDs)
		}
	}
	sql += " ORDER BY m.received_at DESC LIMIT 500"

	rows, err := h.pool.Query(r.Context(), sql, args...)
	if err != nil {
		h.logger.Error("content search failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "search failed")
		return
	}
	defer rows.Close()

	results := make([]map[string]interface{}, 0)
	for rows.Next() {
		var msgID int64
		var subj, from, mb string
		var recv time.Time
		if rows.Scan(&msgID, &subj, &from, &recv, &mb) == nil {
			results = append(results, map[string]interface{}{
				"id": msgID, "subject": subj, "from": from,
				"receivedAt": recv.Format(time.RFC3339), "mailbox": mb,
			})
		}
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{"results": results, "total": len(results)})
}

// DeleteSelected hard-deletes selected messages across mailboxes.
func (h *ContentSearchHandler) DeleteSelected(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	var req struct {
		IDs    []int64 `json:"ids"`
		Reason string  `json:"reason"`
	}
	// Same decode-time body cap as Search: the ids/reason shape checks below
	// only fire AFTER the request has been buffered, so the cap is the bound
	// that keeps the decode itself off the attacker's memory budget.
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxContentSearchBodyBytes)).Decode(&req); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid request")
		return
	}
	if len(req.IDs) == 0 || len(req.IDs) > 500 {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "1-500 ids required")
		return
	}
	if len(req.Reason) < 10 {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "reason required (min 10 chars)")
		return
	}

	var deleted, held, notFound int
	err := h.pool.QueryRow(r.Context(),
		`SELECT deleted_count, held_count, not_found_count
		 FROM content_purge_messages($1, $2, $3, $4)`,
		req.IDs, user.Email, req.Reason, user.UserID,
	).Scan(&deleted, &held, &notFound)
	if err != nil {
		h.logger.Error("content purge failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "purge failed")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"deleted":  deleted,
		"held":     held,
		"notFound": notFound,
	})
}
