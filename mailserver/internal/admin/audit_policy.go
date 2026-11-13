package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/audit"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
)

// AuditPolicyHandler serves GET/PUT /admin/audit/policy.
type AuditPolicyHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

func NewAuditPolicyHandler(pool *pgxpool.Pool, logger *slog.Logger) *AuditPolicyHandler {
	return &AuditPolicyHandler{pool: pool, logger: logger}
}

type auditPolicyRow struct {
	Level               string   `json:"level"`
	ReasonRequiredAreas []string `json:"reasonRequiredAreas"`
}

// Get returns the singleton audit_policy row.
func (h *AuditPolicyHandler) Get(w http.ResponseWriter, r *http.Request) {
	var p auditPolicyRow
	err := h.pool.QueryRow(r.Context(),
		`SELECT level, reason_required_areas FROM audit_policy WHERE id=1`,
	).Scan(&p.Level, &p.ReasonRequiredAreas)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	if p.ReasonRequiredAreas == nil {
		p.ReasonRequiredAreas = []string{}
	}
	httputil.WriteJSON(w, http.StatusOK, p)
}

// Put validates, updates, and self-audits a policy change.
func (h *AuditPolicyHandler) Put(w http.ResponseWriter, r *http.Request) {
	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}

	var req struct {
		Level               string   `json:"level"`
		ReasonRequiredAreas []string `json:"reasonRequiredAreas"`
		Reason              string   `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// A policy change is always a sensitive, audited act — reason required.
	if req.Reason == "" {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "reason_required")
		return
	}
	if req.Level != "lean" && req.Level != "full" {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "level must be 'lean' or 'full'")
		return
	}
	if req.ReasonRequiredAreas == nil {
		req.ReasonRequiredAreas = []string{}
	}

	ctx := r.Context()

	// Read old policy before update (for before/after audit).
	var oldPolicy auditPolicyRow
	if err := h.pool.QueryRow(ctx,
		`SELECT level, reason_required_areas FROM audit_policy WHERE id=1`,
	).Scan(&oldPolicy.Level, &oldPolicy.ReasonRequiredAreas); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	if oldPolicy.ReasonRequiredAreas == nil {
		oldPolicy.ReasonRequiredAreas = []string{}
	}

	// Apply the update — actor from claims, never from body.
	if _, err := h.pool.Exec(ctx,
		`UPDATE audit_policy SET level=$1, reason_required_areas=$2, updated_at=now(), updated_by=$3 WHERE id=1`,
		req.Level, req.ReasonRequiredAreas, claims.UserID,
	); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}

	// Marshal before/after for the audit entry.
	beforeJSON, _ := json.Marshal(oldPolicy)
	afterJSON, _ := json.Marshal(auditPolicyRow{
		Level:               req.Level,
		ReasonRequiredAreas: req.ReasonRequiredAreas,
	})

	// Write core audit entry — a policy change always produces a core row.
	_ = audit.Write(ctx, h.pool, audit.Entry{
		Actor:  claims.UserID,
		Action: "audit_policy_change",
		Before: beforeJSON,
		After:  afterJSON,
		IP:     httputil.ClientIP(r),
		Notes:  req.Reason,
		Tier:   "core",
	})

	httputil.WriteJSON(w, http.StatusOK, auditPolicyRow{
		Level:               req.Level,
		ReasonRequiredAreas: req.ReasonRequiredAreas,
	})
}
