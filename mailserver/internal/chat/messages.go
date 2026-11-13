// messages.go — Task 9 tracer routes (send/list/since) plus Task 10's
// message-level breadth routes (edit/delete/react). Read/typing/presence
// live in presence.go; membership/browse/join/update live in channels.go.
package chat

import (
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/toggle"
)

const chatReplayCursorHeader = "X-Setjoin-Chat-Cursor"

// ── Detached-unfurl admission bound (er5-s15, sealed anchor chat-unfurl-can-
// launch-unbounded-detached-fetch-and-storage-work) ──
//
// Every URL-bearing send kicks a detached goroutine (fetch + storage + DB).
// Each unit is bounded (unfurl.go: 15s total timeout, 2MiB page / 5MiB image
// caps, 3 redirect hops, per-URL claim dedup, TTL reaper), but the SPAWN RATE
// was unbounded: one identity posting distinct URLs mints unbounded detached
// work. admitDetachedUnfurl is the per-sender fixed-window admission cap at
// the trigger seam: a sender beyond their window budget skips their unfurl
// (best-effort enrichment by contract — the send itself is unaffected).
// Per-sender (not process-global) so one spammer cannot starve everyone
// else's enrichment. Sends are already body-capped by httputil.DecodeJSON's
// 1MiB MaxBytesReader.
const (
	// maxUnfurlTriggersPerWindow is one sender's detached-unfurl budget per
	// unfurlAdmissionWindow. Sized above any realistic link-sharing rate;
	// exhaustion degrades preview enrichment, never chat itself.
	maxUnfurlTriggersPerWindow = 30
	// unfurlAdmissionWindow is the fixed admission window.
	unfurlAdmissionWindow = time.Minute
)

// unfurlAdmission holds one sender's fixed-window counter. Entries live in a
// package-level map keyed by the authenticated user id (real tenants only);
// an entry resets lazily when its window elapses.
type unfurlAdmission struct {
	mu      sync.Mutex
	started time.Time
	count   int
}

// allow admits one detached unfurl trigger for userID, counting against the
// sender's current fixed window. now is injectable for deterministic tests.
func (a *unfurlAdmission) allow(now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.started.IsZero() || now.Sub(a.started) >= unfurlAdmissionWindow {
		a.started = now
		a.count = 0
	}
	if a.count >= maxUnfurlTriggersPerWindow {
		return false
	}
	a.count++
	return true
}

// detachedUnfurlAdmission is the per-sender limiter table. Var (not value) so
// tests can swap a fresh limiter without touching other tests' counters.
var detachedUnfurlAdmission = map[int64]*unfurlAdmission{}

// admitDetachedUnfurl is the send-seam admission check for one sender.
func admitDetachedUnfurl(userID int64, now time.Time) bool {
	detachedUnfurlAdmissionMu.Lock()
	a := detachedUnfurlAdmission[userID]
	if a == nil {
		a = &unfurlAdmission{}
		detachedUnfurlAdmission[userID] = a
	}
	detachedUnfurlAdmissionMu.Unlock()
	return a.allow(now)
}

var detachedUnfurlAdmissionMu sync.Mutex

// registerMessageRoutes registers the send/list/since routes on h.mux.

func (h *Handler) registerMessageRoutes(mux router) {
	mux.HandleFunc("POST /chat/channels/{id}/messages", h.sendMessage)
	mux.HandleFunc("GET /chat/channels/{id}/messages", h.listMessages)
	mux.HandleFunc("GET /chat/channels/{id}/messages/since", h.sinceMessages)
	mux.HandleFunc("PATCH /chat/messages/{id}", h.editMessage)
	mux.HandleFunc("DELETE /chat/messages/{id}", h.deleteMessage)
	mux.HandleFunc("POST /chat/messages/{id}/reactions", h.toggleReaction)
	mux.HandleFunc("GET /chat/messages/{id}/thread", h.threadMessages)
	// A3 QoL Task 3: pin (channel curation act, BZ176-gated) + save
	// (personal bookmark, self-scoped, no permission gate beyond membership).
	mux.HandleFunc("POST /chat/messages/{id}/pin", h.togglePin)
	mux.HandleFunc("GET /chat/channels/{id}/pins", h.listPins)
	mux.HandleFunc("POST /chat/messages/{id}/save", h.toggleSave)
	mux.HandleFunc("GET /chat/saves", h.listSaves)
}

type sendMessageBody struct {
	Body        string          `json:"body"`
	ParentID    *int64          `json:"parentId"`
	Mentions    []int64         `json:"mentions"`
	Broadcast   *string         `json:"broadcast"`
	Attachments json.RawMessage `json:"attachments"`
	// A3 QoL Task 15: the client-facing half of Task 6's msg_type/payload
	// send seam — chat_message_send has taken p_msg_type/p_payload since
	// Task 6, but no route ever threaded them through from a plain send
	// (only poll.go's chat_poll_create, a separate seam, set msg_type
	// server-side). Voice needs one; "poll" stays exclusive to that other
	// route (see the allowlist below) so a client can't post a bare
	// msg_type='poll' row with no chat_polls/chat_poll_options behind it.
	MsgType *string         `json:"msgType"`
	Payload json.RawMessage `json:"payload"`
}

// sendMessage serves POST /chat/channels/{id}/messages. channelID comes from
// the path, never the body — the reducer's own membership check (BZ163) is
// the authorization, this handler only routes the call. Chat A2 Task 5:
// attachments[] passes straight through to chat_message_send's p_attachments
// (the reducer owns every decision — space provisioning, node/version
// creation, claims/quota/dedup via drive_file_put_version, the 8-cap/BZ172
// shape check); this handler's only added job is the route-layer drive gate
// below — an attachments-bearing send IS one of "the two attachment
// surfaces" (with ensureSpace) that 404 while feature.drive is off, so a
// disabled deployment gets an opaque 404 instead of the reducer's deeper
// BZ173. A plain (no-attachments) send is completely unaffected either way.
func (h *Handler) sendMessage(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	channelID, ok := httputil.ParseIDPath(w, r, "id", "invalid channel id")
	if !ok {
		return
	}
	var body sendMessageBody
	if err := httputil.DecodeJSON(w, r, &body); err != nil {
		// DecodeJSON already binds the 1MiB MaxBytesReader; classify the
		// failure so a body-cap violation is a 413, everything else 400.
		httputil.WriteDecodeError(w, r, err)
		return
	}
	mentions := body.Mentions
	if mentions == nil {
		mentions = []int64{}
	}
	// Normalize an absent field, JSON null, and an explicit empty array to
	// "no attachments" BEFORE the drive gate — json.RawMessage captures the
	// literal bytes `null` (len 4) and `[]` (len 2), neither of which is
	// caught by a bare len==0 check, so either one used to be misread as
	// attachments-bearing: a plain message 404ed with feature.drive off, and
	// with it on the literal string "null" reached chat_message_send and blew
	// up jsonb_array_length on a scalar. Any other shape (a real array with
	// items, or malformed JSON) is left for chat_message_send to validate.
	attachments := body.Attachments
	if len(attachments) == 0 || string(attachments) == "null" {
		attachments = json.RawMessage(`[]`)
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(attachments, &arr); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid attachments"})
		return
	}
	if len(arr) > 0 && !h.flags.IsEnabled(toggle.FeatureDrive) {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	// A3 QoL Task 15: msgType is a client-facing allowlist of exactly the
	// kinds this route may originate — "text" (the default), "voice", and
	// "question" (B3 Q&A — a question IS a chat message: membership, rate
	// limit, retention, audit, eDiscovery, purge all apply for free).
	// "poll" is deliberately excluded: only chat_poll_create posts one,
	// atomically alongside the chat_polls/chat_poll_options rows a bare
	// send here would never create, which would leave chat_poll_results
	// looking up a payload.pollId that points nowhere.
	msgType := "text"
	if body.MsgType != nil && *body.MsgType != "" {
		if *body.MsgType != "text" && *body.MsgType != "voice" && *body.MsgType != "question" {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid msgType"})
			return
		}
		msgType = *body.MsgType
	}
	var payloadArg *string
	if len(body.Payload) > 0 && string(body.Payload) != "null" {
		s := string(body.Payload)
		payloadArg = &s
	}
	ctx := r.Context()
	var out json.RawMessage
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT chat_message_send($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			claims.UserID, channelID, body.Body, body.ParentID, mentions, body.Broadcast, string(attachments), msgType, payloadArg).Scan(&out)
	})
	if err != nil {
		writeChatProblem(w, r, err)
		return
	}
	// A3 QoL Task 13: best-effort, fully async link unfurl — never affects
	// this response either way (unfurl.go's triggerUnfurl no-ops when the
	// chat.unfurl toggle is off or no store is wired via SetUnfurl). The
	// trigger is admitted under the sender's fixed-window cap so one identity
	// minting URL-bearing sends cannot launch unbounded detached fetch+
	// storage work; over-budget sends skip enrichment silently.
	if admitDetachedUnfurl(claims.UserID, time.Now()) {
		h.triggerUnfurl(r.Context(), out, body.Body)
	}
	httputil.WriteJSON(w, http.StatusCreated, out)
}

// listMessages serves GET /chat/channels/{id}/messages?beforeSeq=&limit=&aroundSeq= —
// newest-first keyset pagination on seq (chat_messages_list), OR, when
// aroundSeq is given, the A3 QoL Task 10 jump-to-message window (limit
// becomes "N per side" in that mode — see chat_messages_list's own comment).
// aroundSeq is the click-through substrate for search hits/pins/saves/
// My-Threads (Task 14's openChannelAt).
func (h *Handler) listMessages(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	channelID, ok := httputil.ParseIDPath(w, r, "id", "invalid channel id")
	if !ok {
		return
	}
	beforeSeq, ok := parseOptionalInt64Query(w, r, "beforeSeq")
	if !ok {
		return
	}
	limit, ok := parseOptionalIntQuery(w, r, "limit")
	if !ok {
		return
	}
	aroundSeq, ok := parseOptionalInt64Query(w, r, "aroundSeq")
	if !ok {
		return
	}
	ctx := r.Context()
	var out json.RawMessage
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT chat_messages_list($1, $2, $3, $4, $5)`,
			claims.UserID, channelID, beforeSeq, limit, aroundSeq).Scan(&out)
	})
	if err != nil {
		writeChatProblem(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

// sinceMessages serves GET /chat/channels/{id}/messages/since?seq= — the
// reconnect replay path (H2). An absent/empty seq means "since the beginning"
// (chat_messages_since treats NULL as 0 via COALESCE).
func (h *Handler) sinceMessages(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	channelID, ok := httputil.ParseIDPath(w, r, "id", "invalid channel id")
	if !ok {
		return
	}
	sinceSeq, ok := parseOptionalInt64Query(w, r, "seq")
	if !ok {
		return
	}
	ctx := r.Context()
	var out json.RawMessage
	var cursor int64
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		// One SQL statement gives the array and channel high-water mark the same
		// MVCC snapshot. A hidden pre-floor edit/delete can legitimately advance
		// change_seq without yielding a safe message row; the additive header lets
		// clients advance past it without exposing message id/content/type.
		return tx.QueryRow(ctx, `
			SELECT chat_messages_since($1, $2, $3),
			       COALESCE((SELECT change_seq FROM chat_channels WHERE id = $2), 0)`,
			claims.UserID, channelID, sinceSeq).Scan(&out, &cursor)
	})
	if err != nil {
		writeChatProblem(w, r, err)
		return
	}
	w.Header().Set(chatReplayCursorHeader, strconv.FormatInt(cursor, 10))
	httputil.WriteJSON(w, http.StatusOK, out)
}

// threadMessages serves GET /chat/messages/{id}/thread — root + replies
// ascending (chat_thread_list), {id} is the ROOT message id. ThreadPane's
// only read path (Task 15). Membership is resolved off the parent's own
// channel inside the reducer, so no channel id travels on this route.
func (h *Handler) threadMessages(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	parentID, ok := httputil.ParseIDPath(w, r, "id", "invalid message id")
	if !ok {
		return
	}
	h.queryChatJSON(w, r, claims.UserID, `SELECT chat_thread_list($1, $2)`, claims.UserID, parentID)
}

type editMessageBody struct {
	Body string `json:"body"`
}

// editMessage serves PATCH /chat/messages/{id} {body}. Author-only (BZ167);
// chat_message_edit captures the prior body into chat_message_revisions
// before overwriting and returns the new seq.
func (h *Handler) editMessage(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	messageID, body, ok := chatIDBody[editMessageBody](w, r, "id")
	if !ok {
		return
	}
	ctx := r.Context()
	var seq int64
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT chat_message_edit($1, $2, $3)`,
			claims.UserID, messageID, body.Body).Scan(&seq)
	})
	if err != nil {
		writeChatProblem(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]int64{"seq": seq})
}

// deleteMessage serves DELETE /chat/messages/{id}. Author or channel
// owner/admin (BZ167); chat_message_delete retains body (compliance, C1) and
// returns the new seq — this handler never touches body directly.
func (h *Handler) deleteMessage(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	messageID, ok := httputil.ParseIDPath(w, r, "id", "invalid message id")
	if !ok {
		return
	}
	ctx := r.Context()
	var seq int64
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT chat_message_delete($1, $2)`,
			claims.UserID, messageID).Scan(&seq)
	})
	if err != nil {
		writeChatProblem(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]int64{"seq": seq})
}

type reactionBody struct {
	Emoji string `json:"emoji"`
}

// toggleReaction serves POST /chat/messages/{id}/reactions {emoji} ->
// {present}. chat_reaction_toggle distinguishes "not a member" (BZ163) from
// "message gone/deleted" (BZ169, F9) — this handler just relays whichever.
func (h *Handler) toggleReaction(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	messageID, body, ok := chatIDBody[reactionBody](w, r, "id")
	if !ok {
		return
	}
	ctx := r.Context()
	var present bool
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT chat_reaction_toggle($1, $2, $3)`,
			claims.UserID, messageID, body.Emoji).Scan(&present)
	})
	if err != nil {
		writeChatProblem(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]bool{"present": present})
}

// togglePin serves POST /chat/messages/{id}/pin -> {pinned}. chat_pin_toggle
// gates on owner/admin in a channel (BZ176) but any member in a DM/group-DM;
// unpin is collective (any authorized member, not just the original pinner).
func (h *Handler) togglePin(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	messageID, ok := httputil.ParseIDPath(w, r, "id", "invalid message id")
	if !ok {
		return
	}
	ctx := r.Context()
	var pinned bool
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT chat_pin_toggle($1, $2)`,
			claims.UserID, messageID).Scan(&pinned)
	})
	if err != nil {
		writeChatProblem(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]bool{"pinned": pinned})
}

// listPins serves GET /chat/channels/{id}/pins. chat_pins_list is
// membership-gated (BZ163); already COALESCEd to '[]'::jsonb.
func (h *Handler) listPins(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	channelID, ok := httputil.ParseIDPath(w, r, "id", "invalid channel id")
	if !ok {
		return
	}
	h.queryChatJSON(w, r, claims.UserID, `SELECT chat_pins_list($1, $2)`, claims.UserID, channelID)
}

// toggleSave serves POST /chat/messages/{id}/save -> {saved}. Personal
// bookmark, self-scoped — membership is checked at save time only
// (chat_save_toggle), never fans out a notify (self-only state).
func (h *Handler) toggleSave(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	messageID, ok := httputil.ParseIDPath(w, r, "id", "invalid message id")
	if !ok {
		return
	}
	ctx := r.Context()
	var saved bool
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT chat_save_toggle($1, $2)`,
			claims.UserID, messageID).Scan(&saved)
	})
	if err != nil {
		writeChatProblem(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]bool{"saved": saved})
}

// listSaves serves GET /chat/saves. chat_saves_list hides (never deletes) a
// save whose channel the caller has since left — R1 via an in-SQL
// membership join, not a stored flag.
func (h *Handler) listSaves(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	h.queryChatJSON(w, r, claims.UserID, `SELECT chat_saves_list($1)`, claims.UserID)
}

// parseOptionalInt64Query parses an optional int64 query param. Absent ->
// (nil, true). A malformed value writes a 400 and returns ok=false.
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

// parseOptionalIntQuery is parseOptionalInt64Query's int-width twin, for the
// "limit" query param (chat_messages_list's p_limit is a plain int).
func parseOptionalIntQuery(w http.ResponseWriter, r *http.Request, name string) (*int, bool) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return nil, true
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid " + name})
		return nil, false
	}
	return &v, true
}
