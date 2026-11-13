// roster.go — Task 11: channel roster + @mention search. Both reducers are
// membership-gated (BZ163) — a non-member gets the same 403 as reading
// messages. Feeds Task 12+'s DM title resolution (client resolves memberIds
// -> names) and MessageRow author names/avatars, plus the Composer's mention
// autocomplete popup.
package chat

import (
	"net/http"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
)

// registerRosterRoutes registers the member-list and mention-search routes on
// h.mux.
func (h *Handler) registerRosterRoutes(mux router) {
	mux.HandleFunc("GET /chat/channels/{id}/members", h.channelRoster)
	mux.HandleFunc("GET /chat/channels/{id}/members/search", h.mentionSearch)
}

// channelRoster serves GET /chat/channels/{id}/members. chat_channel_roster
// raises BZ163 for a non-member — a channel's roster is membership-private,
// same posture as its messages.
func (h *Handler) channelRoster(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	channelID, ok := httputil.ParseIDPath(w, r, "id", "invalid channel id")
	if !ok {
		return
	}
	h.queryChatJSON(w, r, claims.UserID, `SELECT chat_channel_roster($1, $2)`, claims.UserID, channelID)
}

// mentionSearch serves GET /chat/channels/{id}/members/search?q=. Matches on
// THIS channel's members only (F4 — never an org-wide directory search); an
// absent/empty q returns the whole (capped) roster.
func (h *Handler) mentionSearch(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	channelID, ok := httputil.ParseIDPath(w, r, "id", "invalid channel id")
	if !ok {
		return
	}
	q := r.URL.Query().Get("q")
	h.queryChatJSON(w, r, claims.UserID, `SELECT chat_mention_search($1, $2, $3)`, claims.UserID, channelID, q)
}
