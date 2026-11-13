// threads.go — Pillar A3 QoL Task 11: the My-Threads inbox. Thin route over
// chat_my_threads (chat_threads.sql) — a pure query, no membership error to
// map (same IN-SQL scope posture as search.go): a thread from a channel the
// caller isn't CURRENTLY a member of never surfaces, and there is no BZ
// code to raise here.
package chat

import (
	"net/http"

	"setjoin.com/mailserver/internal/auth"
)

// registerThreadsRoutes registers the My-Threads route on h.mux.
func (h *Handler) registerThreadsRoutes(mux router) {
	mux.HandleFunc("GET /chat/my-threads", h.listMyThreads)
}

// listMyThreads serves GET /chat/my-threads?limit=. limit is optional
// (chat_my_threads defaults/clamps it itself, same shape as chat_search's
// p_limit); a malformed limit 400s before touching the DB.
func (h *Handler) listMyThreads(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	limit, ok := parseOptionalIntQuery(w, r, "limit")
	if !ok {
		return
	}
	h.queryChatJSON(w, r, claims.UserID, `SELECT chat_my_threads($1, $2)`, claims.UserID, limit)
}
