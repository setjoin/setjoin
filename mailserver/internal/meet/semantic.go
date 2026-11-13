// semantic.go — MEET plan M4 completion gates: the semantic recording read
// routes (the M4 named gap — "replay read routes"). Two GETs, both reading
// through the owning reducers (the checkpoint-read genre: jsonb
// projections, HISTORICAL-attendee scoped, indistinguishable not-found):
//
//   - GET /meet/{id}/semantic/{rid}/package — the `.sjrec` package
//     manifest facts + truthful segment/coverage state + receipt ledger via
//     the EXISTING meeting_semantic_package_read reducer (wave 4 slice 1).
//   - GET /meet/{id}/semantic/{rid}/replay — the deterministic replay feed
//     the webmail replay model consumes
//     (meeting_semantic_replay_read: the package projection composed with
//     the presentation version links, committed annotation references and
//     the wall/media-aligned fact rail; captions project as an explicitly
//     empty list until their binding producer lands — named absence, never
//     a fabricated track).
//
// Flag posture (the M2 split): both are committed-state reads — NOT
// flag-gated (DisableDrain; a post-end replay read converges regardless of
// feature.meet_semantic_recording's state). Routes may exist while the
// feature flag gates the user-facing surface; the reducers are the
// authority once a route is reached.
package meet

import (
	"net/http"

	"setjoin.com/mailserver/internal/auth"
)

func (h *Handler) registerSemanticRoutes(mux router) {
	mux.HandleFunc("GET /meet/{id}/semantic/{rid}/package", h.readSemanticPackage)
	mux.HandleFunc("GET /meet/{id}/semantic/{rid}/replay", h.readSemanticReplay)
}

// parseSemanticPath parses the meeting id and the semantic recording id (the
// two-segment read routes' shared skeleton).
func (h *Handler) parseSemanticPath(w http.ResponseWriter, r *http.Request) (int64, int64, bool) {
	return parseTwoIDPath(w, r, "rid", "invalid semantic recording id")
}

// readSemanticJSON is the two semantic reads' shared skeleton: caller claims
// → the semantic path parse → queryMeetJSON through the owning reducer (the
// checkpoint-read genre: jsonb projections, HISTORICAL-attendee scoped,
// indistinguishable not-found). The reducer SQL is the per-read difference;
// the scope binding (the caller's id as both the reader argument and the
// query argument) and the response path are identical.
func (h *Handler) readSemanticJSON(w http.ResponseWriter, r *http.Request, sql string) {
	claims := auth.UserFromContext(r.Context())
	id, rid, ok := h.parseSemanticPath(w, r)
	if !ok {
		return
	}
	h.queryMeetJSON(w, r, claims.UserID, sql, claims.UserID, id, rid)
}

// readSemanticPackage serves GET …/package — the authorized package
// projection (reducer-owned gate: meeting_attendee_role; absent caller =
// the indistinguishable BZ278).
func (h *Handler) readSemanticPackage(w http.ResponseWriter, r *http.Request) {
	h.readSemanticJSON(w, r, `SELECT meeting_semantic_package_read($1, $2, $3)`)
}

// readSemanticReplay serves GET …/replay — the deterministic replay feed.
func (h *Handler) readSemanticReplay(w http.ResponseWriter, r *http.Request) {
	h.readSemanticJSON(w, r, `SELECT meeting_semantic_replay_read($1, $2, $3)`)
}
