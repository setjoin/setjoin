// P5 WORM/Object-Lock (spec §3.4, G1) + the audit-chain verify route
// (AUTOPLAN correction #2: P1 shipped verify_drive_audit_chain with no
// route/UI; this file adds the route, Task 10 adds the button).
package drive

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/storage"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
)

// registerWormRoutes wires the P5 compliance-read routes.
func (h *Handler) registerWormRoutes(mux router) {
	mux.HandleFunc("GET /drive/spaces/{id}/audit/verify", h.handleVerifyAuditChain)
}

// SetRetention wires the storage backend's WORM/Object-Lock capability — a
// post-construction setter (the SetJWTProvider idiom, native_token.go)
// rather than growing NewHandler's signature for a dependency most tests
// never exercise. nil is safe and semantically meaningful: no Retention
// capability configured (a non-Linux POSIX deployment, or Aliyun OSS —
// storage/driver.go's RetentionOf commentary) means every gxp chunk stays
// worm-pending forever — correct fail-closed, surfaced via drive_worm_pending
// (admin count), never silently treated as applied.
func (h *Handler) SetRetention(r storage.Retention) { h.retention = r }

// dbExecer is the minimal seam applyWormLocks needs for the WORM-applied
// mark-bookkeeping — satisfied by *pgxpool.Pool (Handler.workerPool) and
// pgxutil.WorkerPool (Worker.pool, worker.go).
type dbExecer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// applyWormLocks applies per-chunk Object-Lock retention after a gxp
// put-version commits (spec §3.4). NEVER fails the caller: any per-chunk
// failure (storage error, or no Retention capability at all) leaves that
// chunk's worm_pending generated column (drive_chunks, C3) true and
// returns pending=true — the caller answers 2xx
// {"wormPending":true} (G1) and the worker retries until clean.
// Bookkeeping (worm_applied_until) runs on workerPool: drive_chunks has no
// user UPDATE policy (G7 — ref_count moves via DEFINER triggers only), and
// this is infrastructure state, not user data.
func applyWormLocks(ctx context.Context, ret storage.Retention, workerPool dbExecer,
	logger *slog.Logger, scopeKey, mode string, until time.Time, shas []string) (pending bool) {
	if ret == nil {
		if len(shas) > 0 {
			logger.Warn("drive: no Retention capability configured — gxp chunks stay worm-pending (spec §12-22 fallback)",
				"scope", scopeKey)
		}
		return len(shas) > 0
	}
	for _, sha := range shas {
		key := "drive/" + scopeKey + "/" + sha
		if err := ret.PutObjectRetention(ctx, key, mode, until); err != nil {
			logger.Warn("drive: WORM apply failed — pending, worker will retry", "key", key, "error", err)
			pending = true
			continue
		}
		if workerPool == nil {
			pending = true
			continue
		}
		if _, err := workerPool.Exec(ctx, `
			UPDATE drive_chunks
			   SET worm_applied_until = GREATEST(coalesce(worm_applied_until, '-infinity'), $3)
			 WHERE scope_key = $1 AND sha256 = $2`, scopeKey, sha, until); err != nil {
			logger.Warn("drive: WORM mark-applied failed", "key", key, "error", err)
			pending = true
		}
	}
	return pending
}

// applyGxpWormIfNeeded, when the target file's space is gxp, applies the
// real storage Object-Lock for every chunk in manifest and returns the
// derived pending state. ok=false for a non-gxp space (or a lookup failure —
// logged, never surfaced as a save error: the version is already committed;
// the reducer's own wormPending:false stays the answer for a non-gxp space).
func (h *Handler) applyGxpWormIfNeeded(ctx context.Context, userID, nodeID int64, manifest []byte) (pending, ok bool) {
	var scopeKey, wormMode string
	var retentionDays int
	err := dbscope.RunUserScoped(ctx, h.pool, userID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT CASE WHEN s.classification = 'regular' THEN 'g' ELSE 's' || s.id END,
			       COALESCE(s.worm_mode, 'governance'), COALESCE(s.retention_days, 0)
			  FROM drive_nodes n JOIN drive_spaces s ON s.id = n.space_id
			 WHERE n.id = $1 AND s.classification = 'gxp'`, nodeID,
		).Scan(&scopeKey, &wormMode, &retentionDays)
	})
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			h.logger.Warn("drive: gxp WORM lookup failed after put_version commit", "node", nodeID, "error", err)
		}
		return false, false // not gxp, or lookup failed — leave the reducer's wormPending:false as-is
	}

	var mc []struct {
		Sha256 string `json:"sha256"`
	}
	if err := json.Unmarshal(manifest, &mc); err != nil || len(mc) == 0 {
		return false, false
	}
	shas := make([]string, len(mc))
	for i, c := range mc {
		shas[i] = c.Sha256
	}
	until := time.Now().Add(time.Duration(retentionDays) * 24 * time.Hour)
	return applyWormLocks(ctx, h.retention, h.workerPool, h.logger, scopeKey, wormMode, until, shas), true
}

// ── audit-chain verify (AUTOPLAN correction #2) ─────────────────────────────

var errVerifyForbidden = errors.New("drive: drive.view required")

// handleVerifyAuditChain is GET /api/drive/spaces/{id}/audit/verify.
// drive.view-gated (the same admin permission listSpacesAdmin checks) — an
// admin verifying a tamper-evident chain need not be a space member.
func (h *Handler) handleVerifyAuditChain(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	spaceID, ok := httputil.ParseIDPath(w, r, "id", "invalid space id")
	if !ok {
		return
	}
	ctx := r.Context()
	var checked int
	var broken []int64
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		var hasPerm bool
		if err := tx.QueryRow(ctx, `SELECT drive_has_admin_perm($1, 'drive.view')`, claims.UserID).Scan(&hasPerm); err != nil {
			return err
		}
		if !hasPerm {
			return errVerifyForbidden
		}
		rows, err := tx.Query(ctx, `SELECT row_id, valid FROM verify_drive_audit_chain($1)`, spaceID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id int64
			var valid bool
			if err := rows.Scan(&id, &valid); err != nil {
				return err
			}
			checked++
			if !valid {
				broken = append(broken, id)
			}
		}
		return rows.Err()
	})
	if err != nil {
		if errors.Is(err, errVerifyForbidden) {
			httputil.WriteProblem(w, r, httputil.NewForbiddenProblem("drive.view required"))
			return
		}
		writeDriveProblem(w, r, err)
		return
	}
	if broken == nil {
		broken = []int64{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"checked": checked, "broken": broken})
}
