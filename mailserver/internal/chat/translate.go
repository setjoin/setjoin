// translate.go — POST /chat/messages/{id}/translate (Pillar A3 QoL Task 5).
//
// Reuses shared/assist's Provider (the same OpenAI-compatible client
// internal/assist's /assist/complete route already drives) with a
// translate-shaped prompt, instead of inventing a chat-specific AI
// integration. Membership + the message body come from chat_thread_list
// (BZ163 not-a-member, BZ165 not-found/other-channel/soft-deleted) — the
// same reducer messages.go's threadMessages route already calls — rather
// than a new reducer: the plan's Task 5 Files list names only this Go file.
package chat

import (
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5"

	iassist "setjoin.com/mailserver/internal/assist"
	"setjoin.com/mailserver/internal/auth"
	sharedassist "setjoin.com/shared/assist"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/toggle"
)

// registerTranslateRoutes registers the Task 5 translate route on h.mux.
func (h *Handler) registerTranslateRoutes(mux router) {
	mux.HandleFunc("POST /chat/messages/{id}/translate", h.translateMessage)
}

// translateRequestBody is the inbound envelope for the translate route.
type translateRequestBody struct {
	TargetLocale string `json:"targetLocale"`
}

// threadMessageBody is the subset of chat_message_to_json's fields this
// route needs out of chat_thread_list's jsonb array.
type threadMessageBody struct {
	MessageID int64  `json:"messageId"`
	ChannelID int64  `json:"channelId"`
	Body      string `json:"body"`
}

// translateMessage serves POST /chat/messages/{id}/translate {targetLocale}
// -> {translated}.
//
//   - 422 if targetLocale is missing
//   - 503 if feature.assist is disabled, or the AI provider is not configured
//   - 403/404 mapped from chat_thread_list's own membership/existence check
//     (BZ163/BZ165) — this route adds no membership logic of its own
//   - 502 if the upstream provider errors
//   - 200 {"translated": "..."} on success
//
// Egress observability (plan Task 5): chat content leaves the DB through an
// external AI provider here, so a structured audit line (userId, messageId,
// targetLocale, provider) is emitted on every successful translation — A4's
// audit chain inherits this line.
func (h *Handler) translateMessage(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	messageID, body, ok := chatIDBody[translateRequestBody](w, r, "id")
	if !ok {
		return
	}
	if body.TargetLocale == "" {
		httputil.WriteProblem(w, r, httputil.NewValidationProblem("targetLocale is required.", nil))
		return
	}

	if !h.flags.IsEnabled(toggle.FeatureAssist) {
		httputil.WriteProblem(w, r, httputil.NewServiceUnavailableProblem("AI assist is not enabled."))
		return
	}

	ctx := r.Context()
	var raw json.RawMessage
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT chat_thread_list($1, $2)`, claims.UserID, messageID).Scan(&raw)
	})
	if err != nil {
		writeChatProblem(w, r, err)
		return
	}
	var msgs []threadMessageBody
	if err := json.Unmarshal(raw, &msgs); err != nil {
		h.logger.Error("chat: translate decode thread", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	}
	var msgBody string
	var channelID int64
	found := false
	for _, m := range msgs {
		if m.MessageID == messageID {
			msgBody, channelID, found = m.Body, m.ChannelID, true
			break
		}
	}
	if !found {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "message not found"})
		return
	}

	reader := iassist.NewPoolConfigReader(h.pool)
	if h.configSecrets != nil {
		// ER5 occ_130c4ed3dfc8ef275164387e: the startup upgrade encrypts a
		// legacy plaintext assist.api_key into a setjoin-config-secret
		// envelope; the reader needs the same codec to keep translate
		// available (without it an envelope value fails closed as 503).
		reader = iassist.NewPoolConfigReaderWithSecrets(h.pool, h.configSecrets)
	}
	cfg, err := iassist.LoadConfig(r.Context(), reader)
	if err != nil {
		httputil.WriteProblem(w, r, httputil.NewServiceUnavailableProblem("AI assist is not configured."))
		return
	}

	// A4a Task 3: the ACT records intent-to-egress, written BEFORE the
	// provider call (CEO review #10) — writing it after would mean a
	// chain-write failure 500s a request whose text has already left the
	// building, and a client retry would egress the text twice. A
	// chain-write failure here fails the request before any egress happens.
	// Inert (zero rows) while feature.chat_compliance is OFF.
	if h.flags.IsEnabled(toggle.FeatureChatCompliance) {
		after, _ := json.Marshal(map[string]string{"targetLocale": body.TargetLocale, "provider": cfg.Model})
		auditErr := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx,
				`SELECT chat_access_audit($1, $2, 'translate.egress', 'message', $3, NULL, $4, NULL, NULL)`,
				claims.UserID, channelID, messageID, after)
			return err
		})
		if auditErr != nil {
			writeChatProblem(w, r, auditErr)
			return
		}
	}

	provider := sharedassist.NewOpenAICompatible(cfg)
	resp, err := provider.Complete(r.Context(), sharedassist.Request{
		Messages: []sharedassist.Message{{Role: "user", Content: msgBody}},
		Context:  "Translate the following chat message. Respond with ONLY the translated text, no commentary.",
		Locale:   body.TargetLocale,
	})
	if err != nil {
		h.logger.Warn("chat: translate upstream error", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadGateway, Detail: "The AI assist provider returned an error. Please try again."})
		return
	}

	h.logger.Info("chat: message translated",
		"userId", claims.UserID, "messageId", messageID,
		"targetLocale", body.TargetLocale, "provider", cfg.Model)

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"translated": resp.Content})
}
