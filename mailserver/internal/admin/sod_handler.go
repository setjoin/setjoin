// Package admin — sod_handler.go
//
// SodModeHandler is the dedicated, gated enablement endpoint for 等保三级 SoD
// mode (PUT /admin/dengbao/sod-mode). It is the ONLY path that may flip the
// dengbao.sod_mode toggle — the generic feature endpoint refuses the key
// (admin_features.go) so every flip runs through the precheck gate here.
//
// The route is gated on security.write (RequirePermAudited), NOT on an enum role —
// under SoD, super_admin is decomposed, so the gate must be permission-based.
//
// Turning ON runs admin_sod_precheck() AND the toggle UPDATE in ONE transaction.
// If the precheck returns ANY rows, the tx ROLLS BACK and the toggle stays OFF
// (closing the precheck→flip TOCTOU). On a clean precheck it commits and writes
// an admin_audit_log row. Turning OFF is unconditional and audited.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5"
	"setjoin.com/mailserver/internal/audit"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
)

// sodTxBeginner is the minimal transactional surface the handler needs. Both
// *pgxpool.Pool and pgx.Tx satisfy it: Pool.Begin opens a real transaction;
// Tx.Begin opens a SAVEPOINT (nested), which lets tests drive the handler
// inside an outer tx they roll back.
type sodTxBeginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// SodModeHandler serves PUT /admin/dengbao/sod-mode.
type SodModeHandler struct {
	db     sodTxBeginner
	logger *slog.Logger
}

// NewSodModeHandler constructs the handler. db is typically the *pgxpool.Pool.
func NewSodModeHandler(db sodTxBeginner, logger *slog.Logger) *SodModeHandler {
	return &SodModeHandler{db: db, logger: logger}
}

type sodModeSetRequest struct {
	Enabled bool `json:"enabled"`
}

type sodViolation struct {
	ViolationType string `json:"violationType"`
	Subject       string `json:"subject"`
	Detail        string `json:"detail"`
}

// Set handles PUT /admin/dengbao/sod-mode.
func (h *SodModeHandler) Set(w http.ResponseWriter, r *http.Request) {
	var req sodModeSetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusBadRequest,
			Detail: "request body must be JSON with an 'enabled' boolean",
		})
		return
	}

	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}

	if h.db == nil {
		httputil.WriteProblem(w, r, httputil.NewInternalProblem())
		return
	}

	ctx := r.Context()
	tx, err := h.db.Begin(ctx)
	if err != nil {
		h.logError("sod_mode begin tx", err)
		httputil.WriteProblem(w, r, httputil.NewInternalProblem())
		return
	}
	// Rollback is a no-op once the tx is committed; safe to always defer.
	defer tx.Rollback(ctx)

	if req.Enabled {
		// ── Turning ON: precheck + flip in ONE transaction. ──────────────────
		violations, err := h.runPrecheck(ctx, tx)
		if err != nil {
			h.logError("sod_mode precheck", err)
			httputil.WriteProblem(w, r, httputil.NewInternalProblem())
			return
		}
		if len(violations) > 0 {
			// Any violation ⇒ ROLL BACK (deferred), toggle stays OFF. Return the
			// list so the operator can fix them and retry.
			httputil.WriteJSON(w, http.StatusConflict, map[string]any{
				"error":      "等保三级 SoD mode cannot be enabled: unresolved separation-of-duties violations",
				"violations": violations,
			})
			return
		}
		if err := h.flip(ctx, tx, true); err != nil {
			h.logError("sod_mode enable flip", err)
			httputil.WriteProblem(w, r, httputil.NewInternalProblem())
			return
		}
		if err := h.audit(ctx, tx, claims.UserID, httputil.ClientIP(r), "sod_mode_enable"); err != nil {
			h.logError("sod_mode enable audit", err)
			httputil.WriteProblem(w, r, httputil.NewInternalProblem())
			return
		}
	} else {
		// ── Turning OFF: unconditional, audited. ─────────────────────────────
		if err := h.flip(ctx, tx, false); err != nil {
			h.logError("sod_mode disable flip", err)
			httputil.WriteProblem(w, r, httputil.NewInternalProblem())
			return
		}
		if err := h.audit(ctx, tx, claims.UserID, httputil.ClientIP(r), "sod_mode_disable"); err != nil {
			h.logError("sod_mode disable audit", err)
			httputil.WriteProblem(w, r, httputil.NewInternalProblem())
			return
		}
	}

	if err := tx.Commit(ctx); err != nil {
		h.logError("sod_mode commit", err)
		httputil.WriteProblem(w, r, httputil.NewInternalProblem())
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{"enabled": req.Enabled})
}

// Get handles GET /admin/dengbao/sod-mode — read-only precheck status.
// Runs admin_sod_precheck() in a read-only transaction and returns the current
// toggle state and any violations. Does NOT mutate any state.
func (h *SodModeHandler) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tx, err := h.db.Begin(ctx)
	if err != nil {
		h.logError("sod_mode_get begin tx", err)
		httputil.WriteProblem(w, r, httputil.NewInternalProblem())
		return
	}
	defer tx.Rollback(ctx) // always rollback — this handler is read-only

	var enabled bool
	if err := tx.QueryRow(ctx,
		`SELECT enabled FROM feature_toggles WHERE key = $1`,
		SodModeToggleKey).Scan(&enabled); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		h.logError("sod_mode_get read toggle", err)
		httputil.WriteProblem(w, r, httputil.NewInternalProblem())
		return
	}

	violations, err := h.runPrecheck(ctx, tx)
	if err != nil {
		h.logError("sod_mode_get precheck", err)
		httputil.WriteProblem(w, r, httputil.NewInternalProblem())
		return
	}

	if violations == nil {
		violations = []sodViolation{} // never null in JSON
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"enabled":    enabled,
		"violations": violations,
	})
}

// runPrecheck runs admin_sod_precheck() inside the transaction and returns the
// reported violations.
func (h *SodModeHandler) runPrecheck(ctx context.Context, tx pgx.Tx) ([]sodViolation, error) {
	rows, err := tx.Query(ctx,
		`SELECT violation_type, subject, detail FROM admin_sod_precheck()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []sodViolation
	for rows.Next() {
		var v sodViolation
		if err := rows.Scan(&v.ViolationType, &v.Subject, &v.Detail); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// flip upserts the dengbao.sod_mode toggle row inside the transaction.
func (h *SodModeHandler) flip(ctx context.Context, tx pgx.Tx, enabled bool) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO feature_toggles (key, enabled, updated_at)
		 VALUES ($1, $2, now())
		 ON CONFLICT (key) DO UPDATE SET enabled = $2, updated_at = now()`,
		SodModeToggleKey, enabled)
	return err
}

// audit writes the admin_audit_log row inside the transaction. Unlike the
// best-effort audit elsewhere, this one is part of the gated tx — a failed
// audit write must abort the flip (the audit trail is load-bearing here).
func (h *SodModeHandler) audit(ctx context.Context, tx pgx.Tx, userID int64, ip, action string) error {
	afterJSON, _ := json.Marshal(map[string]string{"key": SodModeToggleKey})
	return audit.Write(ctx, tx, audit.Entry{
		Actor: userID, Action: action, TargetType: "feature_toggle",
		After: afterJSON, IP: ip, Tier: "core",
	})
}

func (h *SodModeHandler) logError(msg string, err error) {
	if h.logger != nil {
		h.logger.Error(msg, "error", err)
	}
}
