// search.go — P6 Task 10: name search (spec §6.4). Thin wrapper over
// drive_search_nodes, which does its own R1 membership scoping — this
// handler is routing + response-shaping only.
package drive

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
)

// registerSearchRoutes registers the P6 name-search route on h.mux.
func (h *Handler) registerSearchRoutes(mux router) {
	mux.HandleFunc("GET /drive/search", h.searchNodes)
}

// searchNodes handles GET /api/drive/search?q=&space=&max=. space and max
// are optional (absent space searches every space the caller is a member
// of); an empty/missing q is rejected by the reducer itself (BZ141 -> 422).
func (h *Handler) searchNodes(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	q := r.URL.Query().Get("q")
	spaceID, ok := parseOptionalInt64Query(w, r, "space")
	if !ok {
		return
	}
	var max *int
	if m := r.URL.Query().Get("max"); m != "" {
		v, err := strconv.Atoi(m)
		if err != nil {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid max"})
			return
		}
		max = &v
	}

	ctx := r.Context()
	var out []byte
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT drive_search_nodes($1, $2, $3, $4)`,
			claims.UserID, spaceID, q, max).Scan(&out)
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	// drive_search_nodes returns a bare (never-null) jsonb array.
	writeJSON(w, http.StatusOK, map[string]json.RawMessage{"items": out})
}
