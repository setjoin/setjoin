// scheduled.go — Chat A3 QoL Task 2: scheduled-send routes over the
// ScheduledAction rail (chat_schedule.sql's chat-owned reducer trio).
// scheduled_actions has NO RLS and a nullable mailbox_id — chat rows carry
// mailbox_id=NULL, so this handler never reuses the generic
// enqueue_scheduled_action/cancel_scheduled_action front door; it calls
// chat_schedule_message/chat_scheduled_list/chat_scheduled_cancel instead
// (ownership lives in payload->>'userId', R1/R2/R3 all folded into those
// reducers' own statements — this handler is a pure translator, same
// posture as every other chat route in this package).
package chat

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
)

// registerScheduledRoutes registers the scheduled-send routes on h.mux.
func (h *Handler) registerScheduledRoutes(mux router) {
	mux.HandleFunc("POST /chat/channels/{id}/messages/schedule", h.scheduleMessage)
	mux.HandleFunc("GET /chat/scheduled", h.listScheduled)
	mux.HandleFunc("DELETE /chat/scheduled/{actionId}", h.cancelScheduled)
}

type scheduleMessageBody struct {
	Body      string     `json:"body"`
	ParentID  *int64     `json:"parentId"`
	Mentions  []int64    `json:"mentions"`
	Broadcast *string    `json:"broadcast"`
	FireAt    *time.Time `json:"fireAt"`
}

// scheduleMessage serves POST /chat/channels/{id}/messages/schedule ->
// {actionId}. channelID comes from the path, never the body (R2);
// chat_schedule_message re-checks membership at ENQUEUE time (BZ163) and
// validates fireAt (BZ179) — this handler only routes the call. The fire-time
// handler (scheduled_action_chat_send) re-checks membership/permission AGAIN
// at fire time (TOCTOU) — not this route's concern.
func (h *Handler) scheduleMessage(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	channelID, ok := httputil.ParseIDPath(w, r, "id", "invalid channel id")
	if !ok {
		return
	}
	var body scheduleMessageBody
	if err := httputil.DecodeJSON(w, r, &body); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	mentions := body.Mentions
	if mentions == nil {
		mentions = []int64{}
	}
	ctx := r.Context()
	var actionID uuid.UUID
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT chat_schedule_message($1, $2, $3, $4, $5, $6, $7)`,
			claims.UserID, channelID, body.Body, body.ParentID, mentions, body.Broadcast, body.FireAt).Scan(&actionID)
	})
	if err != nil {
		writeChatProblem(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusCreated, map[string]string{"actionId": actionID.String()})
}

// listScheduled serves GET /chat/scheduled. chat_scheduled_list is
// self-scoped (payload->>'userId' = the caller), already COALESCEd to
// '[]'::jsonb — carries the caller's own pending AND failed chat_send rows
// (failed rows stay visible: silent content loss is the wrong brand for a
// compliance product; Dismiss = cancelScheduled on a failed row).
func (h *Handler) listScheduled(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	h.queryChatJSON(w, r, claims.UserID, `SELECT chat_scheduled_list($1)`, claims.UserID)
}

// cancelScheduled serves DELETE /chat/scheduled/{actionId}. Works on a
// pending OR failed row (dismiss); chat_scheduled_cancel folds ownership + id
// + status into ONE statement (BZ179 anti-oracle — see chat_schedule.sql).
func (h *Handler) cancelScheduled(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	actionID, err := uuid.Parse(r.PathValue("actionId"))
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid actionId"})
		return
	}
	h.execChat(w, r, claims.UserID, `SELECT chat_scheduled_cancel($1, $2)`, claims.UserID, actionID)
}
