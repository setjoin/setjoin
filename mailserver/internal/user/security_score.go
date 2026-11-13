package user

import (
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
)

// SecurityScoreHandler provides a user-facing security posture score.
type SecurityScoreHandler struct {
	pool *pgxpool.Pool
}

// NewSecurityScoreHandler creates a security score handler.
func NewSecurityScoreHandler(pool *pgxpool.Pool) *SecurityScoreHandler {
	return &SecurityScoreHandler{pool: pool}
}

// GetScore handles GET /user/security-score.
// Computes a 0-100 score based on: TOTP enabled, backup codes available,
// recent failed logins, and trusted device count.
func (h *SecurityScoreHandler) GetScore(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "authentication required")
		return
	}

	ctx := r.Context()
	score := 50 // baseline
	var checks []map[string]interface{}

	// +20 for TOTP enabled
	var hasTOTP bool
	err := h.pool.QueryRow(ctx,
		`SELECT totp_enabled FROM users WHERE id = $1`, claims.UserID,
	).Scan(&hasTOTP)
	if err == nil && hasTOTP {
		score += 20
		checks = append(checks, map[string]interface{}{
			"name": "TOTP enabled", "pass": true, "points": 20,
		})
	} else {
		checks = append(checks, map[string]interface{}{
			"name":   "TOTP enabled",
			"pass":   false,
			"points": 0,
			"action": "Enable two-factor authentication",
		})
	}

	// +15 for having backup codes (totp_backup_codes_enc TEXT[] column from authserver)
	var backupCount int
	err = h.pool.QueryRow(ctx,
		`SELECT COALESCE(array_length(totp_backup_codes_enc, 1), 0) FROM users WHERE id = $1`,
		claims.UserID,
	).Scan(&backupCount)
	if err != nil {
		backupCount = 0 // column may not exist yet (authserver extension not applied)
	}
	if backupCount > 0 {
		score += 15
		checks = append(checks, map[string]interface{}{
			"name": "Backup codes", "pass": true, "points": 15, "remaining": backupCount,
		})
	} else {
		checks = append(checks, map[string]interface{}{
			"name":   "Backup codes",
			"pass":   false,
			"points": 0,
			"action": "Generate backup codes",
		})
	}

	// +10 for no failed logins in 7 days
	// RunUserScoped sets app.current_user_id for V028 FORCE RLS at the W6 flip.
	var recentFails int
	if scopeErr := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT COUNT(*) FROM login_events
			 WHERE user_id = $1 AND success = false AND occurred_at > now() - INTERVAL '7 days'`,
			claims.UserID,
		).Scan(&recentFails)
	}); scopeErr != nil {
		recentFails = 0 // table may not exist yet
	}
	if recentFails == 0 {
		score += 10
		checks = append(checks, map[string]interface{}{
			"name": "No recent failed logins", "pass": true, "points": 10,
		})
	} else {
		checks = append(checks, map[string]interface{}{
			"name": "No recent failed logins", "pass": false, "points": 0,
			"recent_fails": recentFails,
		})
	}

	// +5 for having <= 5 trusted devices.
	//
	// V254 FORCE-RLS pairing (L2-C2 r1 item 2b): device_registry is Posture A
	// (self keyed on app.current_user_id) — the COUNT runs inside
	// dbscope.RunUserScoped so the actor GUC admits the self arm; the
	// in-statement `WHERE user_id = $1` predicate (R1 primary) is unchanged.
	var deviceCount int
	if scoreErr := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT COUNT(*) FROM device_registry WHERE user_id = $1`,
			claims.UserID,
		).Scan(&deviceCount)
	}); scoreErr != nil {
		deviceCount = 0 // table may not exist yet
	}
	if deviceCount <= 5 {
		score += 5
		checks = append(checks, map[string]interface{}{
			"name": "Device count <= 5", "pass": true, "points": 5,
			"device_count": deviceCount,
		})
	} else {
		checks = append(checks, map[string]interface{}{
			"name": "Device count <= 5", "pass": false, "points": 0,
			"device_count": deviceCount,
			"action":       "Review and remove unused devices",
		})
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"score":  score,
		"checks": checks,
	})
}
