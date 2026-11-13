// asof.go — P6 Task 12: the "space as of T" time-point view + the watch
// list. Watch CREATE/DELETE (PUT/DELETE .../nodes/{id}/watch, ops body
// included) already shipped in P4 (locks.go) — this file only adds the read
// side the P6 subscription-manager UI needs.
package drive

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
)

// registerAsOfRoutes registers the P6 as-of-view + watch-list routes on h.mux.
func (h *Handler) registerAsOfRoutes(mux router) {
	mux.HandleFunc("GET /drive/spaces/{id}/asof", h.spaceAsOf)
	mux.HandleFunc("GET /drive/watches", h.listWatches)
}

// spaceAsOf handles GET /api/drive/spaces/{id}/asof?at=<RFC3339> — the
// metadata-only time-point view (drive_space_as_of; three honest ceilings
// documented on the reducer itself).
func (h *Handler) spaceAsOf(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	spaceID, ok := httputil.ParseIDPath(w, r, "id", "invalid space id")
	if !ok {
		return
	}
	at, err := time.Parse(time.RFC3339, r.URL.Query().Get("at"))
	if err != nil {
		httputil.WriteProblem(w, r, httputil.NewValidationProblem("at must be an RFC3339 timestamp", nil))
		return
	}

	ctx := r.Context()
	var out []byte
	err = dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT drive_space_as_of($1, $2, $3)`, claims.UserID, spaceID, at).Scan(&out)
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	// drive_space_as_of returns a bare (never-null) jsonb array.
	writeJSON(w, http.StatusOK, map[string]json.RawMessage{"items": out})
}

type watchOut struct {
	NodeID   int64    `json:"nodeId"`
	NodeName string   `json:"nodeName"`
	Kind     string   `json:"kind"`
	Ops      []string `json:"ops"` // nil (JSON null) = watching all ops — same convention drive_watches.ops uses
}

// listWatches handles GET /api/drive/watches — the caller's own change
// subscriptions (the P6 subscription-manager list). AUTOPLAN batch-3
// BLOCKER #1: scoped by an explicit "WHERE w.user_id = $1", never left to
// RLS — RLS is inert on the pre-flip/owner-role pool this runtime still
// connects through (dbscope.go).
func (h *Handler) listWatches(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	ctx := r.Context()
	var out []watchOut
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT w.node_id, n.name, n.kind, w.ops
			  FROM drive_watches w
			  JOIN drive_nodes n ON n.id = w.node_id
			 WHERE w.user_id = $1
			 ORDER BY w.created_at DESC`, claims.UserID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var wo watchOut
			if err := rows.Scan(&wo.NodeID, &wo.NodeName, &wo.Kind, &wo.Ops); err != nil {
				return err
			}
			out = append(out, wo)
		}
		return rows.Err()
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	writeJSONList(w, out)
}
