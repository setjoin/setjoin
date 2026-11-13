// poll.go — Chat A3 QoL Task 9: poll create/vote/close/results routes over
// chat_poll.sql. A pure translator (R1/R2): claims.UserID is the only source
// of p_user_id, channel/poll/option ids come from the path or an already-
// validated body field, never trusted from a caller-asserted identity field.
// Every permission/state decision (membership, poll-closed, wrong-actor
// close, bad option) lives in the reducer — this file maps BZ163/BZ177/BZ161
// to their wire status via the shared writeChatProblem/execChat/queryChatJSON
// helpers, same as every other route in this package.
package chat

import (
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
)

// registerPollRoutes registers the Task 9 poll routes on h.mux.
func (h *Handler) registerPollRoutes(mux router) {
	mux.HandleFunc("POST /chat/channels/{id}/polls", h.createPoll)
	mux.HandleFunc("POST /chat/polls/{id}/vote", h.votePoll)
	mux.HandleFunc("POST /chat/polls/{id}/close", h.closePoll)
	mux.HandleFunc("GET /chat/polls/{id}/results", h.pollResults)
}

type createPollBody struct {
	Question string   `json:"question"`
	Options  []string `json:"options"`
	Multi    bool     `json:"multi"`
	ClosesAt *string  `json:"closesAt"`
}

// createPoll serves POST /chat/channels/{id}/polls -> {messageId, pollId,
// seq}. chat_poll_create posts the poll THROUGH chat_message_send (Task 6's
// seam) so it rides the same membership/post-permission/archive gate as any
// other message — this handler adds no gating of its own.
func (h *Handler) createPoll(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	channelID, ok := httputil.ParseIDPath(w, r, "id", "invalid channel id")
	if !ok {
		return
	}
	var body createPollBody
	if err := httputil.DecodeJSON(w, r, &body); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	ctx := r.Context()
	var out json.RawMessage
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT chat_poll_create($1, $2, $3, $4, $5, $6)`,
			claims.UserID, channelID, body.Question, body.Options, body.Multi, body.ClosesAt).Scan(&out)
	})
	if err != nil {
		writeChatProblem(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusCreated, out)
}

type votePollBody struct {
	OptionID int64 `json:"optionId"`
}

// votePoll serves POST /chat/polls/{id}/vote {optionId} -> 204.
// chat_poll_vote handles single-vote (delete-prior-then-insert) vs multi
// (accumulate) internally based on the poll's own multi flag.
func (h *Handler) votePoll(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	pollID, body, ok := chatIDBody[votePollBody](w, r, "id")
	if !ok {
		return
	}
	h.execChat(w, r, claims.UserID, `SELECT chat_poll_vote($1, $2, $3)`, claims.UserID, pollID, body.OptionID)
}

// closePoll serves POST /chat/polls/{id}/close -> 204. Creator or channel
// owner/admin (BZ161 otherwise); a poll is never re-opened.
func (h *Handler) closePoll(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	pollID, ok := httputil.ParseIDPath(w, r, "id", "invalid poll id")
	if !ok {
		return
	}
	h.execChat(w, r, claims.UserID, `SELECT chat_poll_close($1, $2)`, claims.UserID, pollID)
}

// pollResults serves GET /chat/polls/{id}/results. chat_poll_results is
// membership-gated (BZ163) and non-anonymous — per-option voter lists ride
// along, not just counts (gate-approved: vote rows are member-readable under
// RLS regardless, so hiding voters would be a curtain, not a guarantee).
func (h *Handler) pollResults(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	pollID, ok := httputil.ParseIDPath(w, r, "id", "invalid poll id")
	if !ok {
		return
	}
	h.queryChatJSON(w, r, claims.UserID, `SELECT chat_poll_results($1, $2)`, claims.UserID, pollID)
}
