// Admin API: CA doctor health check endpoint (CA-1 G1).
//
// Routes (registered in main.go):
//
//	GET /admin/conditional-access/doctor
//
// Aggregates read-only checks into a health score + per-gap next-actions.
// Also surfaces policy-hygiene (stale report_only) and time-to-first-policy.
// Read-only — no audit / no notify. Gated: requireCAPolicyRead at the route.
package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/httputil"
)

// CADoctorHandler provides the CA health-check endpoint.
type CADoctorHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewCADoctorHandler creates a CADoctorHandler.
func NewCADoctorHandler(pool *pgxpool.Pool, logger *slog.Logger) *CADoctorHandler {
	return &CADoctorHandler{pool: pool, logger: logger}
}

// doctorCheck is a single health-check result.
type doctorCheck struct {
	Name       string `json:"name"`
	Passed     bool   `json:"passed"`
	NextAction string `json:"next_action,omitempty"`
}

// hygienePolicy is a policy flagged by the hygiene scan.
type hygienePolicy struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	State     string `json:"state"`
	DaysSince int64  `json:"days_since_created,omitempty"`
}

// doctorResponse is the shape returned by GET /admin/conditional-access/doctor.
type doctorResponse struct {
	Score                int           `json:"score"`
	Total                int           `json:"total"`
	Checks               []doctorCheck `json:"checks"`
	Hygiene              doctorHygiene `json:"hygiene"`
	TimeToFirstPolicySec *int64        `json:"time_to_first_policy_sec"`
}

// doctorHygiene holds policy-hygiene findings.
type doctorHygiene struct {
	StaleReportOnly []hygienePolicy `json:"stale_report_only"` // report_only > 30 days
}

// Doctor runs health checks and returns a score + next-actions.
// All queries are read-only; no audit / no notify.
func (h *CADoctorHandler) Doctor(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// ponytail: four scalar reads + one ca_coverage_report() call; inline SQL is
	// fine here — all are short, read-only projections, not business logic.

	// ── check 1: feature toggle on ───────────────────────────────────────────
	var featureOn bool
	if err := h.pool.QueryRow(ctx,
		`SELECT COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'feature.conditional_access'), false)`,
	).Scan(&featureOn); err != nil {
		h.logger.Error("ca doctor: feature toggle read failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	// ── check 2: break-glass configured ──────────────────────────────────────
	var breakGlassSet bool
	if err := h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM system_config WHERE key = 'ca_break_glass_user_ids'
		                AND jsonb_array_length(value) > 0)`,
	).Scan(&breakGlassSet); err != nil {
		h.logger.Error("ca doctor: break-glass read failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	// ── check 3: ≥1 report_only policy (graduated testing before enforce) ────
	var hasReportOnly bool
	if err := h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM conditional_access_policies
		                WHERE state = 'report_only' AND deleted_at IS NULL)`,
	).Scan(&hasReportOnly); err != nil {
		h.logger.Error("ca doctor: report_only read failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	// ── check 4: no coverage gaps ─────────────────────────────────────────────
	var coverageRaw []byte
	if err := h.pool.QueryRow(ctx, `SELECT ca_coverage_report()`).Scan(&coverageRaw); err != nil {
		h.logger.Error("ca doctor: ca_coverage_report failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	var coverage struct {
		Gaps []json.RawMessage `json:"gaps"`
	}
	if err := json.Unmarshal(coverageRaw, &coverage); err != nil {
		h.logger.Error("ca doctor: parse coverage failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	noGaps := len(coverage.Gaps) == 0

	// ── assemble checks ───────────────────────────────────────────────────────
	checks := []doctorCheck{
		{
			Name:       "feature_on",
			Passed:     featureOn,
			NextAction: "Enable feature.conditional_access in feature toggles",
		},
		{
			Name:       "break_glass_configured",
			Passed:     breakGlassSet,
			NextAction: "Set break-glass users via `mailctl ca` or the admin console to prevent lockout",
		},
		{
			Name:       "has_report_only_policy",
			Passed:     hasReportOnly,
			NextAction: "Create at least one report_only policy to test coverage before enforcing",
		},
		{
			Name:       "no_coverage_gaps",
			Passed:     noGaps,
			NextAction: "Run `mailctl ca coverage` to see gaps; create policies to cover flagged protocols",
		},
	}
	// Clear next_action for passed checks (cleaner output).
	score := 0
	for i := range checks {
		if checks[i].Passed {
			checks[i].NextAction = ""
			score++
		}
	}

	// ── policy hygiene: stale report_only > 30 days ───────────────────────────
	hygieneRows, err := h.pool.Query(ctx, `
		SELECT id, name, state,
		       EXTRACT(DAY FROM now() - created_at)::bigint AS days_since
		FROM conditional_access_policies
		WHERE state = 'report_only'
		  AND deleted_at IS NULL
		  AND created_at < now() - INTERVAL '30 days'
		ORDER BY created_at`)
	if err != nil {
		h.logger.Error("ca doctor: hygiene query failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer hygieneRows.Close()

	var staleReportOnly []hygienePolicy
	for hygieneRows.Next() {
		var p hygienePolicy
		if err := hygieneRows.Scan(&p.ID, &p.Name, &p.State, &p.DaysSince); err != nil {
			h.logger.Error("ca doctor: hygiene row scan failed", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "database error")
			return
		}
		staleReportOnly = append(staleReportOnly, p)
	}
	if err := hygieneRows.Err(); err != nil {
		h.logger.Error("ca doctor: hygiene rows error", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if staleReportOnly == nil {
		staleReportOnly = []hygienePolicy{} // never null in JSON
	}

	// ── time-to-first-policy: first ca_policy_create → first ca_policy_promote ─
	// ponytail: reads admin_audit_log directly; no reducer needed for a 2-row read.
	var ttfpSec *int64
	var firstCreate, firstPromote *time.Time
	if err := h.pool.QueryRow(ctx,
		`SELECT MIN(occurred_at) FROM admin_audit_log WHERE action = 'ca_policy_create'`,
	).Scan(&firstCreate); err != nil {
		h.logger.Error("ca doctor: first-create read failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if err := h.pool.QueryRow(ctx,
		`SELECT MIN(occurred_at) FROM admin_audit_log WHERE action = 'ca_policy_promote'`,
	).Scan(&firstPromote); err != nil {
		h.logger.Error("ca doctor: first-promote read failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if firstCreate != nil && firstPromote != nil && firstPromote.After(*firstCreate) {
		d := int64(firstPromote.Sub(*firstCreate).Seconds())
		ttfpSec = &d
	}

	resp := doctorResponse{
		Score:  score,
		Total:  len(checks),
		Checks: checks,
		Hygiene: doctorHygiene{
			StaleReportOnly: staleReportOnly,
		},
		TimeToFirstPolicySec: ttfpSec,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
}
