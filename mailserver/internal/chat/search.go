// search.go — Pillar A3 QoL Task 10: CJK-capable full-text search. Thin
// route over chat_search (chat_search.sql) — membership scope is IN-SQL
// (R1) inside the reducer, so this handler does zero membership logic of
// its own, same posture as translate.go/poll.go.
package chat

import (
	"net/http"
	"unicode"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
)

// registerSearchRoutes registers the search route on h.mux.
func (h *Handler) registerSearchRoutes(mux router) {
	mux.HandleFunc("GET /chat/search", h.searchMessages)
}

// HasHanRune reports whether q contains at least one CJK Han-script rune.
// The 'simple' tsquery config cannot tokenize a Han run into words
// (chat_messages.search_tsv, V119, is latin-only in practice), so a
// Han-containing query must route to the pg_trgm-backed ILIKE substring leg
// (chat_messages_body_trgm_idx, V122) instead of
// search_tsv @@ plainto_tsquery('simple', q) — without this routing, zh
// search returns nothing for the target market (plan's CN-critical
// differentiator). Exported (A4b Task 6, review F10): the admin eDiscovery
// search route reuses this exact Han-detection table rather than
// copy-pasting it.
func HasHanRune(q string) bool {
	for _, r := range q {
		if unicode.Is(unicode.Han, r) {
			return true
		}
	}
	return false
}

// searchMessages serves GET /chat/search?q=&in=&from=&before=&has=. q is
// required (an empty/whitespace-only query would otherwise ILIKE-match
// every message the caller can see, which is not a search). in/from/before
// are optional int64 filters; has is an opaque string passed straight
// through to chat_search (today only 'attachment' is recognized there; any
// other value degrades to "no results", never a 500).
func (h *Handler) searchMessages(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	q := r.URL.Query().Get("q")
	if q == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "q is required"})
		return
	}
	channelID, ok := parseOptionalInt64Query(w, r, "in")
	if !ok {
		return
	}
	fromUser, ok := parseOptionalInt64Query(w, r, "from")
	if !ok {
		return
	}
	beforeID, ok := parseOptionalInt64Query(w, r, "before")
	if !ok {
		return
	}
	var has *string
	if v := r.URL.Query().Get("has"); v != "" {
		has = &v
	}
	h.queryChatJSON(w, r, claims.UserID, `SELECT chat_search($1, $2, $3, $4, $5, $6, $7)`,
		claims.UserID, q, channelID, fromUser, beforeID, has, HasHanRune(q))
}
