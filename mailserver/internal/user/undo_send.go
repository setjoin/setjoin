package user

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/identity"
)

// UndoSendDefaultDelaySeconds is the factory default for undo send delay.
const UndoSendDefaultDelaySeconds = 5

// UndoSendMinDelaySeconds is the minimum allowed undo send delay.
const UndoSendMinDelaySeconds = 5

// UndoSendMaxDelaySeconds is the maximum allowed undo send delay.
const UndoSendMaxDelaySeconds = 30

// UndoSendHandler handles undo-send (POST /messages/{id}/undo) and the
// per-user undo-send delay setting (GET/PUT /settings/undo-send).
type UndoSendHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewUndoSendHandler creates an UndoSendHandler.
func NewUndoSendHandler(pool *pgxpool.Pool, logger *slog.Logger) *UndoSendHandler {
	return &UndoSendHandler{pool: pool, logger: logger}
}

// Undo handles POST /messages/{id}/undo — cancels a pending send if within
// the undo delay window. Moves the message from Sent back to Drafts and
// deletes any outbound queue entries that have not yet been dispatched.
func (h *UndoSendHandler) Undo(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Extract message ID from path: /messages/{id}/undo
	messageIDStr := r.PathValue("id")
	if messageIDStr == "" {
		httputil.WriteError(w, http.StatusBadRequest, "missing message id")
		return
	}

	messageID, err := strconv.ParseInt(messageIDStr, 10, 64)
	if err != nil || messageID <= 0 {
		httputil.WriteError(w, http.StatusBadRequest, "invalid message id")
		return
	}

	// Look up the user's primary mailbox (account ID).
	accountID, err := identity.ResolvePrimaryMailbox(r.Context(), h.pool, u.UserID)
	if err != nil {
		h.logger.Error("undo send: primary mailbox lookup failed", "user_id", u.UserID, "error", err)
		httputil.WriteError(w, http.StatusNotFound, "mailbox not found")
		return
	}

	var result json.RawMessage
	err = h.pool.QueryRow(r.Context(),
		`SELECT undo_send($1, $2)`,
		accountID, messageID,
	).Scan(&result)
	if err != nil {
		msg := err.Error()
		h.logger.Error("undo send failed", "message_id", messageID, "error", err)

		// Distinguish known error codes from internal failures. BZ021/BZ022 are
		// undo-specific codes outside the shared reducererr vocabulary, so they
		// keep their bespoke string-match mapping (404 / 410).
		if strings.Contains(msg, "BZ021") {
			httputil.WriteError(w, http.StatusNotFound, "message not found")
			return
		}
		if strings.Contains(msg, "BZ022") {
			httputil.WriteError(w, http.StatusGone, "undo window has expired")
			return
		}
		// Classify any other reducer BZ business error (over-quota / forbidden /
		// not-found / conflict) so it surfaces as 507 / 403 / 404 / 409 instead of
		// a blanket 500; an unrecognized error keeps the 500 fallback.
		httputil.WriteError(w, reducerErrorStatus(err), "undo failed")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, result)
}

// GetDelay handles GET /settings/undo-send — returns the user's current
// undo send delay in seconds.
func (h *UndoSendHandler) GetDelay(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var prefs []byte
	err := h.pool.QueryRow(r.Context(),
		`SELECT view_prefs FROM users WHERE id = $1`, u.UserID,
	).Scan(&prefs)

	delay := UndoSendDefaultDelaySeconds
	if err == nil && len(prefs) > 0 && string(prefs) != "null" {
		var m map[string]interface{}
		if json.Unmarshal(prefs, &m) == nil {
			if v, ok := m["undoSendDelay"]; ok {
				switch d := v.(type) {
				case float64:
					delay = int(d)
				case int:
					delay = d
				}
			}
		}
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"undoSendDelay": delay,
	})
}

// PutDelay handles PUT /settings/undo-send — updates the user's undo send
// delay in seconds. Values outside [5, 30] are clamped.
func (h *UndoSendHandler) PutDelay(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req struct {
		UndoSendDelay int `json:"undoSendDelay"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}

	delay := req.UndoSendDelay
	if delay < UndoSendMinDelaySeconds {
		delay = UndoSendMinDelaySeconds
	}
	if delay > UndoSendMaxDelaySeconds {
		delay = UndoSendMaxDelaySeconds
	}

	// Merge with existing preferences so other keys are preserved.
	var existing map[string]interface{}
	var prefs []byte
	err := h.pool.QueryRow(r.Context(),
		`SELECT view_prefs FROM users WHERE id = $1`, u.UserID,
	).Scan(&prefs)
	if err == nil && len(prefs) > 0 && string(prefs) != "null" {
		json.Unmarshal(prefs, &existing)
	}
	if existing == nil {
		existing = make(map[string]interface{})
	}
	existing["undoSendDelay"] = delay

	prefsJSON, _ := json.Marshal(existing)
	_, err = h.pool.Exec(r.Context(),
		`UPDATE users SET view_prefs = $2 WHERE id = $1`,
		u.UserID, prefsJSON,
	)
	if err != nil {
		h.logger.Error("undo send delay put failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"undoSendDelay": delay,
	})
}
