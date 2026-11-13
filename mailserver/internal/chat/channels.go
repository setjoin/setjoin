// channels.go — Task 9 tracer routes: create channel, open DM, list
// conversations. Every handler follows the plan's fixed shape: claims →
// parse body → pool.QueryRow("SELECT chat_*($1,...)", claims.UserID, ...) →
// map error. claims.UserID is the ONLY source of p_user_id (R1/R2) — never a
// request-body field.
package chat

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/toggle"
)

// registerChannelRoutes registers the create/dm/conversations routes plus
// Task 10's discovery/lifecycle/membership routes on h.mux. Roster/mention-
// search (Task 11) live in roster.go instead. Chat A2 Task 5 adds the
// per-channel Drive-space-ensure route.
func (h *Handler) registerChannelRoutes(mux router) {
	mux.HandleFunc("GET /chat/conversations", h.listConversations)
	mux.HandleFunc("POST /chat/channels", h.createChannel)
	mux.HandleFunc("POST /chat/dm", h.openDM)
	mux.HandleFunc("POST /chat/dm/federated", h.openFederatedDM)
	mux.HandleFunc("GET /chat/channels/browse", h.browseChannels)
	mux.HandleFunc("POST /chat/channels/{id}/join", h.joinChannel)
	mux.HandleFunc("PATCH /chat/channels/{id}", h.updateChannel)
	mux.HandleFunc("POST /chat/channels/{id}/members", h.addMember)
	mux.HandleFunc("POST /chat/channels/{id}/members/guest-preview", h.previewGuestMember)
	mux.HandleFunc("DELETE /chat/channels/{id}/members/{userId}", h.removeMember)
	mux.HandleFunc("POST /chat/channels/{id}/space", h.ensureSpace)
	mux.HandleFunc("PUT /chat/channels/{id}/notif", h.setChannelNotif)
}

type createChannelBody struct {
	Name       string `json:"name"`
	Topic      string `json:"topic"`
	Visibility string `json:"visibility"`
}

// createChannel serves POST /chat/channels. An empty topic is sent to the
// reducer as SQL NULL (chat_channel_create's p_topic DEFAULT NULL) rather
// than an empty string, so a channel created without a topic reads back NULL
// like one created before this field existed.
func (h *Handler) createChannel(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	var body createChannelBody
	if err := httputil.DecodeJSON(w, r, &body); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	var topic *string
	if body.Topic != "" {
		topic = &body.Topic
	}
	visibility := body.Visibility
	if visibility == "" {
		visibility = "public"
	}
	ctx := r.Context()
	var id int64
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT chat_channel_create($1, $2, $3, $4)`,
			claims.UserID, body.Name, topic, visibility).Scan(&id)
	})
	if err != nil {
		writeChatProblem(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusCreated, map[string]int64{"channelId": id})
}

type openDMBody struct {
	UserIDs []int64 `json:"userIds"`
}

// openDM serves POST /chat/dm. chat_dm_open folds the caller into the member
// set itself and DB-enforces dedup via member_key's partial UNIQUE index
// (H3/F5) — this handler never looks up an existing DM first.
func (h *Handler) openDM(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	var body openDMBody
	if err := httputil.DecodeJSON(w, r, &body); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	ctx := r.Context()
	var id int64
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT chat_dm_open($1, $2)`, claims.UserID, body.UserIDs).Scan(&id)
	})
	if err != nil {
		writeChatProblem(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]int64{"channelId": id})
}

type openFederatedDMBody struct {
	RemoteAddr string `json:"remoteAddr"`
}

// openFederatedDM serves POST /chat/dm/federated {remoteAddr} -> {channelId}.
// Pillar C1 Task 3: the ONLY user path that starts a federated DM (the plan's
// own words) — toggle-gated 404 while feature.federation is OFF, the same
// route-layer defense shape ensureSpace uses for feature.drive above.
// federation_dm_ensure (Task 2) does the real work: upserts the federated
// channel on its dedup key and raises BZ204 when the peer domain isn't
// locally allow-listed+enabled, which writeChatProblem surfaces as a 403.
func (h *Handler) openFederatedDM(w http.ResponseWriter, r *http.Request) {
	if !h.flags.IsEnabled(toggle.FeatureFederation) {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	claims := auth.UserFromContext(r.Context())
	var body openFederatedDMBody
	if err := httputil.DecodeJSON(w, r, &body); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if strings.TrimSpace(body.RemoteAddr) == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "remoteAddr is required"})
		return
	}
	ctx := r.Context()
	var id int64
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT federation_dm_ensure($1, $2)`, claims.UserID, body.RemoteAddr).Scan(&id)
	})
	if err != nil {
		writeChatProblem(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]int64{"channelId": id})
}

// listConversations serves GET /chat/conversations. chat_conversation_list is
// already COALESCE(...,'[]'::jsonb) — no null-list guard needed here. Chat A2
// Task 5: the response gains a top-level `attachmentsEnabled` capability
// (chatToggle && driveToggle && !guest — chat is always true here, the ServeHTTP gate
// already proved it, but the formula is written out in full to match the
// plan's contract literally) so the composer knows to hide the attach
// surface entirely when feature.drive is off, and each conversation's own
// `spaceId` (nullable — chat_read.sql's own addition) rides straight through
// unmodified as part of the array.
func (h *Handler) listConversations(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	ctx := r.Context()
	var out json.RawMessage
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT chat_conversation_list($1)`, claims.UserID).Scan(&out)
	})
	if err != nil {
		writeChatProblem(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"conversations":      out,
		"attachmentsEnabled": !claims.IsGuest() && h.flags.IsEnabled(toggle.FeatureChat) && h.flags.IsEnabled(toggle.FeatureDrive),
	})
}

// ensureSpace serves POST /chat/channels/{id}/space -> {spaceId}. The
// composer calls this before the chunk-upload rail so it has a space to
// upload into; chat_space_ensure lazily provisions (or returns the existing)
// org-governed Drive space bound to the channel, membership-gated (BZ163).
// This IS an attachment surface (Task 5's "the two attachment surfaces"),
// so it 404s while feature.drive is off — plain messaging is unaffected,
// only this route and an attachments-bearing send (messages.go) gate on it.
func (h *Handler) ensureSpace(w http.ResponseWriter, r *http.Request) {
	if !h.flags.IsEnabled(toggle.FeatureDrive) {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	claims := auth.UserFromContext(r.Context())
	channelID, ok := httputil.ParseIDPath(w, r, "id", "invalid channel id")
	if !ok {
		return
	}
	ctx := r.Context()
	var spaceID int64
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT chat_space_ensure($1, $2)`, claims.UserID, channelID).Scan(&spaceID)
	})
	if err != nil {
		writeChatProblem(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]int64{"spaceId": spaceID})
}

// browseChannels serves GET /chat/channels/browse. chat_browse_channels
// lists public non-archived channels only — private channels never appear
// (grill Q1: visibility controls discovery, never content access).
func (h *Handler) browseChannels(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	h.queryChatJSON(w, r, claims.UserID, `SELECT chat_browse_channels($1)`, claims.UserID)
}

// joinChannel serves POST /chat/channels/{id}/join. chat_channel_join is the
// anti-oracle leg (BZ170): a private, archived, or nonexistent channel id
// all read identically — joining must never reveal a private channel exists.
func (h *Handler) joinChannel(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	channelID, ok := httputil.ParseIDPath(w, r, "id", "invalid channel id")
	if !ok {
		return
	}
	h.execChat(w, r, claims.UserID, `SELECT chat_channel_join($1, $2)`, claims.UserID, channelID)
}

type updateChannelBody struct {
	Name                *string `json:"name"`
	Topic               *string `json:"topic"`
	Archived            *bool   `json:"archived"`
	PostPermission      *string `json:"postPermission"`
	BroadcastPermission *string `json:"broadcastPermission"`
}

// updateChannel serves PATCH /chat/channels/{id} (rename/topic/archive/
// post-permission/broadcast-permission — the last two, Pillar A3 QoL Task 8).
// Owner/admin only (BZ161); absent fields are left unchanged by
// chat_channel_update's own COALESCE — this handler never fills in defaults.
func (h *Handler) updateChannel(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	channelID, body, ok := chatIDBody[updateChannelBody](w, r, "id")
	if !ok {
		return
	}
	h.execChat(w, r, claims.UserID, `SELECT chat_channel_update($1, $2, $3, $4, $5, $6, $7)`,
		claims.UserID, channelID, body.Name, body.Topic, body.Archived,
		body.PostPermission, body.BroadcastPermission)
}

type memberBody struct {
	UserID int64 `json:"userId"`
}

type guestPreviewBody struct {
	Email string `json:"email"`
}

// previewGuestMember serves the exact-email, non-enumerable guest preview.
// chat_guest_preview runs channel owner/admin authority before touching the
// target identity and returns one of two frozen JSON shapes.
func (h *Handler) previewGuestMember(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	channelID, ok := httputil.ParseIDPath(w, r, "id", "invalid channel id")
	if !ok {
		return
	}
	var body guestPreviewBody
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if strings.TrimSpace(body.Email) == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusBadRequest,
			Type:   "https://setjoin.com/problems/chat/invalid-arguments",
			Detail: "email is required",
		})
		return
	}
	h.queryChatJSON(w, r, claims.UserID, `SELECT chat_guest_preview($1, $2, $3)`,
		claims.UserID, channelID, body.Email)
}

// addMember serves POST /chat/channels/{id}/members {userId}. Owner/admin
// only (BZ161); never on dm/group_dm (BZ162) — chat_member_add enforces
// both and is silently idempotent for an existing member (F9).
func (h *Handler) addMember(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	channelID, body, ok := chatIDBody[memberBody](w, r, "id")
	if !ok {
		return
	}
	h.execChat(w, r, claims.UserID, `SELECT chat_member_add($1, $2, $3)`, claims.UserID, channelID, body.UserID)
}

// removeMember serves DELETE /chat/channels/{id}/members/{userId}. Self-leave
// always allowed; otherwise owner/admin (BZ161) — chat_member_remove also
// runs owner-succession (grill Q7) in the same txn when the departing member
// was the last owner.
func (h *Handler) removeMember(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	channelID, ok := httputil.ParseIDPath(w, r, "id", "invalid channel id")
	if !ok {
		return
	}
	removeID, ok := httputil.ParseIDPath(w, r, "userId", "invalid user id")
	if !ok {
		return
	}
	h.execChat(w, r, claims.UserID, `SELECT chat_member_remove($1, $2, $3)`, claims.UserID, channelID, removeID)
}

type setNotifBody struct {
	Level string `json:"level"`
}

// setChannelNotif serves PUT /chat/channels/{id}/notif {level} -> 204. A3 QoL
// Task 7: the caller's OWN per-channel mute/DND preference
// ('all'|'mentions'|'none') — chat_member_set_notif validates the value
// (BZ162) and the membership scope (BZ163) in one statement. Purely a
// client-decision surface: no notify fan-out (self-only state), and the WS
// relay is never filtered by this value (Global Constraints).
func (h *Handler) setChannelNotif(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	channelID, body, ok := chatIDBody[setNotifBody](w, r, "id")
	if !ok {
		return
	}
	h.execChat(w, r, claims.UserID, `SELECT chat_member_set_notif($1, $2, $3)`, claims.UserID, channelID, body.Level)
}
