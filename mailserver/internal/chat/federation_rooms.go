// federation_rooms.go — Pillar C2 Task 7: the room-federation Go surface.
// Thin protocol translator over the Task 2 room-lifecycle reducers
// (federation_room_create/invite/remove) plus this task's own
// federation_room_roster read — the same shape every other file in this
// package uses (claims -> parse body -> dbscope.RunUserScoped ->
// writeChatProblem). Role authority (owner/admin for create/invite/remove;
// any member for the roster read) lives entirely in the reducers (R1); these
// handlers are thin callers, never a second authorization decision.
//
// Every route here is toggle-gated 404 while feature.federation is OFF — the
// openFederatedDM (channels.go) pattern, extended: the create route ALSO
// 404s when this box has no federationLocalDomain configured (the static-gate
// posture federation.Service and admin.FederationHandler already use for the
// same underlying config.Config.FederationLocalDomain — a reducer cannot see
// process config, so an unconfigured box must refuse before ever calling
// federation_room_create with an empty string).
package chat

import (
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/toggle"
)

// SetFederationLocalDomain wires config.Config.FederationLocalDomain
// (main.go, the admin.NewFederationHandler/federation.Config precedent) —
// the drive.SetJWTProvider/chat.SetUnfurl post-construction setter idiom, so
// NewHandler's signature stays untouched. Empty (the default zero value)
// means this box has no federation local domain configured; bindFederation
// 404s rather than calling federation_room_create with an empty string.
func (h *Handler) SetFederationLocalDomain(domain string) {
	h.federationLocalDomain = strings.ToLower(strings.TrimSpace(domain))
}

func (h *Handler) registerFederationRoomRoutes(mux router) {
	mux.HandleFunc("POST /chat/channels/{id}/federation", h.bindFederation)
	mux.HandleFunc("POST /chat/channels/{id}/federation/invite", h.inviteFederationMember)
	mux.HandleFunc("POST /chat/channels/{id}/federation/remove", h.removeFederationMember)
	mux.HandleFunc("GET /chat/channels/{id}/federation", h.federationRoster)
}

// bindFederation serves POST /chat/channels/{id}/federation -> {roomId}.
// federation_room_create proves owner/admin (BZ163/BZ209) and every
// bind-eligibility refusal (BZ209/BZ210) itself; this handler's only job
// beyond the toggle/local-domain gates is passing p_local_domain through
// (never trusting a request-body value for it — a reducer can't see process
// config, and letting the client name its own "local" domain would let any
// room's minted roomId claim to be hub-owned by an arbitrary domain).
func (h *Handler) bindFederation(w http.ResponseWriter, r *http.Request) {
	if !h.flags.IsEnabled(toggle.FeatureFederation) {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	if h.federationLocalDomain == "" {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	claims := auth.UserFromContext(r.Context())
	channelID, ok := httputil.ParseIDPath(w, r, "id", "invalid channel id")
	if !ok {
		return
	}
	ctx := r.Context()
	var roomID string
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT federation_room_create($1, $2, $3)`,
			claims.UserID, channelID, h.federationLocalDomain).Scan(&roomID)
	})
	if err != nil {
		writeChatProblem(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"roomId": roomID})
}

type inviteFederationBody struct {
	MemberDomain string `json:"memberDomain"`
	ContactAddr  string `json:"contactAddr"`
}

// inviteFederationMember serves POST /chat/channels/{id}/federation/invite
// {memberDomain, contactAddr} -> 204. federation_room_invite IS re-admit
// (Q9) — the same route re-admits a parked/revoked/removed member, no
// separate endpoint.
func (h *Handler) inviteFederationMember(w http.ResponseWriter, r *http.Request) {
	if !h.flags.IsEnabled(toggle.FeatureFederation) {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	claims := auth.UserFromContext(r.Context())
	channelID, body, ok := chatIDBody[inviteFederationBody](w, r, "id")
	if !ok {
		return
	}
	h.execChat(w, r, claims.UserID, `SELECT federation_room_invite($1, $2, $3, $4)`,
		claims.UserID, channelID, body.MemberDomain, body.ContactAddr)
}

type removeFederationBody struct {
	MemberDomain string `json:"memberDomain"`
}

// removeFederationMember serves POST /chat/channels/{id}/federation/remove
// {memberDomain} -> 204 (the kick lever, Q3).
func (h *Handler) removeFederationMember(w http.ResponseWriter, r *http.Request) {
	if !h.flags.IsEnabled(toggle.FeatureFederation) {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	claims := auth.UserFromContext(r.Context())
	channelID, body, ok := chatIDBody[removeFederationBody](w, r, "id")
	if !ok {
		return
	}
	h.execChat(w, r, claims.UserID, `SELECT federation_room_remove($1, $2, $3)`,
		claims.UserID, channelID, body.MemberDomain)
}

// federationRoster serves GET /chat/channels/{id}/federation -> the roster
// envelope (roomId/hubDomain/isHub/removedAt/members[]). Any channel member
// may read (federation_room_roster's own R1 chat_require_role proof, no
// min-role restriction) — only the mutating routes above are owner/admin
// gated.
func (h *Handler) federationRoster(w http.ResponseWriter, r *http.Request) {
	if !h.flags.IsEnabled(toggle.FeatureFederation) {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	claims := auth.UserFromContext(r.Context())
	channelID, ok := httputil.ParseIDPath(w, r, "id", "invalid channel id")
	if !ok {
		return
	}
	h.queryChatJSON(w, r, claims.UserID, `SELECT federation_room_roster($1, $2)`, claims.UserID, channelID)
}
