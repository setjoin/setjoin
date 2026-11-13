// trash.go — P6 Task 9: admin tier-2 trash (the "admin bin"). Tier 1 (member
// trash) is unchanged and already has its own P1 route
// (GET /drive/spaces/{id}/tree?deleted=1); this file is drive.manage-only
// surfaces backed by the SECURITY DEFINER pair (drive_trash_admin_list /
// drive_node_purge_restore, V117 + Task 3) — the reducer re-checks the
// permission itself (BZ140), the handler's job is routing + RFC 7807
// mapping, not authorization. feature.drive is already gated once, centrally,
// in Handler.ServeHTTP (G5) — no per-handler re-check needed here.
package drive

import (
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
)

// registerTrashRoutes registers the P6 admin tier-2 trash routes on h.mux.
func (h *Handler) registerTrashRoutes(mux router) {
	mux.HandleFunc("GET /drive/spaces/{id}/trash", h.adminTrashList)
	mux.HandleFunc("POST /drive/nodes/{id}/purge-restore", h.purgeRestore)
}

// adminTrashList handles GET /api/drive/spaces/{id}/trash?tier=2 — the
// tier-2 admin bin (drive_trash_admin_list). Tier 1 already has its own P1
// route (GET .../tree?deleted=1) — this endpoint is tier-2 ONLY; ponytail:
// any other (or absent) ?tier value is a 400 naming that route instead of
// re-implementing a listing that already exists elsewhere.
func (h *Handler) adminTrashList(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	spaceID, ok := httputil.ParseIDPath(w, r, "id", "invalid space id")
	if !ok {
		return
	}
	if r.URL.Query().Get("tier") != "2" {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusBadRequest,
			Detail: "tier=2 required (tier-1 member trash is GET .../tree?deleted=1)",
		})
		return
	}
	ctx := r.Context()
	var out []byte
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT drive_trash_admin_list($1, $2)`, claims.UserID, spaceID).Scan(&out)
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	// drive_trash_admin_list returns a bare (never-null) jsonb array — wrap it
	// the same way Task 10's search endpoint does.
	writeJSON(w, http.StatusOK, map[string]json.RawMessage{"items": out})
}

// purgeRestore handles POST /api/drive/nodes/{id}/purge-restore — a
// drive.manage admin restores a tier-2 subtree to its original path (G4
// collision suffix on a live-name clash).
func (h *Handler) purgeRestore(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	nodeID, ok := httputil.ParseIDPath(w, r, "id", "invalid node id")
	if !ok {
		return
	}
	ctx := r.Context()
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT drive_node_purge_restore($1, $2)`, claims.UserID, nodeID)
		return err
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
