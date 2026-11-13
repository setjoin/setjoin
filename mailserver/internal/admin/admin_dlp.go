package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/httputil"
)

// DLPHandler serves admin DLP pattern management endpoints.
type DLPHandler struct {
	pool *pgxpool.Pool
}

// NewDLPHandler creates a DLP handler.
func NewDLPHandler(pool *pgxpool.Pool) *DLPHandler {
	return &DLPHandler{pool: pool}
}

// dlpPatternRow is the wire format shared with the webmail admin UI.
// severity maps to/from the dlp_policies.action column.
type dlpPatternRow struct {
	ID       int64  `json:"id,omitempty"`
	Name     string `json:"name"`
	Regex    string `json:"regex"`
	Severity string `json:"severity"` // critical|high|medium|low
	Enabled  bool   `json:"enabled"`
}

func actionToSeverity(action string) string {
	switch action {
	case "block":
		return "critical"
	case "quarantine":
		return "high"
	case "notify_admin":
		return "medium"
	default:
		return "low"
	}
}

func severityToAction(severity string) string {
	switch severity {
	case "critical":
		return "block"
	case "high":
		return "quarantine"
	case "medium":
		return "notify_admin"
	default:
		return "warn"
	}
}

// GetPatterns returns DLP pattern rows from dlp_policies (scoped to the
// admin's domain if applicable; global patterns are always visible).
func (h *DLPHandler) GetPatterns(w http.ResponseWriter, r *http.Request) {
	domainScope := middleware.DomainScopeFromContext(r.Context())
	var rows pgx.Rows
	var err error
	if domainScope > 0 {
		rows, err = h.pool.Query(r.Context(),
			`SELECT id, name, COALESCE(regex_patterns[1], ''), action, enabled
			 FROM dlp_policies
			 WHERE is_pattern = TRUE
			   AND (domain_id IS NULL OR domain_id = $1)
			 ORDER BY priority, id`, domainScope,
		)
	} else {
		rows, err = h.pool.Query(r.Context(),
			`SELECT id, name, COALESCE(regex_patterns[1], ''), action, enabled
			 FROM dlp_policies
			 WHERE is_pattern = TRUE
			 ORDER BY priority, id`,
		)
	}
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to load patterns")
		return
	}
	defer rows.Close()

	patterns := make([]dlpPatternRow, 0)
	for rows.Next() {
		var p dlpPatternRow
		var action string
		if err := rows.Scan(&p.ID, &p.Name, &p.Regex, &action, &p.Enabled); err != nil {
			continue
		}
		p.Severity = actionToSeverity(action)
		patterns = append(patterns, p)
	}

	httputil.WriteJSON(w, http.StatusOK, patterns)
}

// UpdatePatterns replaces all DLP pattern rows with the submitted array.
// Scoped admins cannot use this endpoint since it replaces global configuration.
func (h *DLPHandler) UpdatePatterns(w http.ResponseWriter, r *http.Request) {
	domainScope := middleware.DomainScopeFromContext(r.Context())
	if domainScope > 0 {
		httputil.WriteError(w, http.StatusForbidden, "scoped admins cannot modify global DLP patterns")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var patterns []dlpPatternRow
	if err := json.NewDecoder(r.Body).Decode(&patterns); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "transaction failed")
		return
	}
	defer tx.Rollback(r.Context())

	if _, err := tx.Exec(r.Context(), `DELETE FROM dlp_policies WHERE is_pattern = TRUE`); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to clear patterns")
		return
	}

	if len(patterns) > 0 {
		valueRows := make([]string, len(patterns))
		args := make([]any, 0, len(patterns)*5)
		for i, p := range patterns {
			base := i * 5
			valueRows[i] = fmt.Sprintf("($%d,$%d,$%d,$%d,ARRAY[$%d],TRUE,TRUE)", base+1, base+2, base+3, base+4, base+5)
			args = append(args, p.Name, p.Enabled, i, severityToAction(p.Severity), p.Regex)
		}
		_, err := tx.Exec(r.Context(),
			`INSERT INTO dlp_policies (name, enabled, priority, action, regex_patterns, applies_to_all, is_pattern) VALUES `+strings.Join(valueRows, ","),
			args...,
		)
		if err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, "failed to save patterns")
			return
		}
	}

	if err := tx.Commit(r.Context()); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "commit failed")
		return
	}

	w.WriteHeader(http.StatusOK)
}
