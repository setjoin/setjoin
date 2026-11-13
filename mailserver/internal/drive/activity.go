// activity.go — Go route for the P4 activity feed (plan Task 11, LR-1/LR-2).
// Thin passthrough to drive_activity_feed, the read reducer over the
// actor-bearing audit chain (drive_changes has no actor column).
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

// registerActivityRoutes registers the activity-feed route on h.mux.
func (h *Handler) registerActivityRoutes(mux router) {
	mux.HandleFunc("GET /drive/spaces/{id}/activity", h.activity)
}

// activity serves GET /drive/spaces/{id}/activity?node=&beforeId=&max= — a
// per-space (or, with ?node=, per-file) activity feed. All three query params
// are optional; a malformed one is a client 400 (never reaches the reducer).
func (h *Handler) activity(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	spaceID, ok := httputil.ParseIDPath(w, r, "id", "invalid space id")
	if !ok {
		return
	}
	nodeID, ok := parseOptionalInt64Query(w, r, "node")
	if !ok {
		return
	}
	beforeID, ok := parseOptionalInt64Query(w, r, "beforeId")
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
	var out json.RawMessage
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT drive_activity_feed($1, $2, $3, $4, $5)`,
			claims.UserID, spaceID, nodeID, max, beforeID).Scan(&out)
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

// parseOptionalInt64Query parses an optional int64 query param. Absent ->
// (nil, true). A present-but-malformed value writes a 400 and returns ok=false.
func parseOptionalInt64Query(w http.ResponseWriter, r *http.Request, name string) (*int64, bool) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return nil, true
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid " + name})
		return nil, false
	}
	return &v, true
}
