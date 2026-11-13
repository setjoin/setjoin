package admin

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/audit"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/reducererr"
)

// mapProtectionErr maps admin_protection_check BZ06x errors to HTTP responses.
// Returns true if the error was one of the known BZ064/BZ065/BZ066 protection
// codes (in which case the appropriate problem was written to w and an audit
// row was emitted on pool in autocommit — surviving any rolled-back mutation tx).
// Returns false for all other errors, leaving the caller to handle them.
//
// The membership check stays an IsCode branch (only the three protection codes
// trigger the denial AUDIT side-effect); the status (BZ064→409 ClassConflict,
// BZ065/BZ066→403 ClassForbidden) and message-passthrough detail come from the
// shared reducererr projection (c6).
//
// pool may be nil (e.g. unit tests) — the audit write is skipped in that case.
// actorID and targetID are included in the audit row for attribution.
func mapProtectionErr(pool *pgxpool.Pool, logger *slog.Logger, w http.ResponseWriter, r *http.Request, err error, actorID, targetID int64) bool {
	if !reducererr.IsCode(err, "BZ064", "BZ065", "BZ066") {
		return false
	}
	var pgErr *pgconn.PgError
	_ = errors.As(err, &pgErr) // guaranteed by IsCode; code kept only for audit attribution

	// Emit an audit row on the shared pool (autocommit — this write survives the
	// mutation tx's rollback). Skipped when pool is nil (unit-test path). A failed
	// audit write must not be silent — it drops a security-denial record.
	if pool != nil {
		afterJSON, _ := json.Marshal(map[string]any{
			"code": pgErr.Code, "actor_id": actorID, "target_id": targetID,
		})
		if auditErr := audit.WriteAutonomous(r.Context(), pool, audit.Entry{
			Actor:      actorID,
			Action:     "admin_protection.denied",
			TargetType: "user",
			TargetID:   &targetID,
			After:      afterJSON,
			IP:         httputil.ClientIP(r),
			Tier:       "core",
		}); auditErr != nil && logger != nil {
			logger.Warn("admin_protection denial audit write failed",
				"error", auditErr, "actor_id", actorID, "target_id", targetID, "code", pgErr.Code)
		}
	}

	// err is guaranteed classified here (IsCode matched BZ064/065/066 above),
	// so WriteClassified always writes and returns true — arch #A1.
	reducererr.WriteClassified(w, r, err)
	return true
}
