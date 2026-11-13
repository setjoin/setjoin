package user

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/ssrf"
	wh "setjoin.com/shared/webhook"
)

// UserWebhooksHandler provides self-service CRUD for webhook subscriptions.
type UserWebhooksHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
	// codec seals webhook signing secrets at rest
	// (webhook_subscriptions.secret_enc; D6/DBSCHEMA-005, the V247 device
	// pattern). Nil fails closed at Create — the handler never persists
	// plaintext secrets.
	codec *wh.SecretCodec
}

func NewUserWebhooksHandler(pool *pgxpool.Pool, logger *slog.Logger, codec *wh.SecretCodec) *UserWebhooksHandler {
	return &UserWebhooksHandler{pool: pool, logger: logger, codec: codec}
}

// List returns the authenticated user's webhooks.
func (h *UserWebhooksHandler) List(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	rows, err := h.pool.Query(r.Context(),
		`SELECT id, url, event_types, scope, is_active, created_at, updated_at
		 FROM webhook_subscriptions WHERE user_id = $1 ORDER BY created_at DESC`, user.UserID)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	type sub struct {
		ID         int64     `json:"id"`
		URL        string    `json:"url"`
		EventTypes []string  `json:"eventTypes"`
		Scope      string    `json:"scope"`
		IsActive   bool      `json:"isActive"`
		CreatedAt  time.Time `json:"createdAt"`
		UpdatedAt  time.Time `json:"updatedAt"`
	}
	out := make([]sub, 0)
	for rows.Next() {
		var s sub
		var types []byte
		if rows.Scan(&s.ID, &s.URL, &types, &s.Scope, &s.IsActive, &s.CreatedAt, &s.UpdatedAt) == nil {
			json.Unmarshal(types, &s.EventTypes)
			out = append(out, s)
		}
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

// Create creates a new webhook subscription for the authenticated user.
func (h *UserWebhooksHandler) Create(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	var req struct {
		URL        string   `json:"url"`
		EventTypes []string `json:"eventTypes"`
		Scope      string   `json:"scope"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.URL == "" || len(req.EventTypes) == 0 {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "url and eventTypes required")
		return
	}
	if req.Scope != "" && req.Scope != "self" {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "self-service webhooks require self scope")
		return
	}
	seen := make(map[string]struct{}, len(req.EventTypes))
	for _, eventType := range req.EventTypes {
		if !wh.IsKnownEventType(eventType) {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "unknown event type")
			return
		}
		if _, duplicate := seen[eventType]; duplicate {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "duplicate event type")
			return
		}
		seen[eventType] = struct{}{}
	}

	// SSRF guard: reject obviously unsafe destinations (bad scheme, literal
	// internal IP) before storing. The dispatcher's dialer enforces the same
	// policy at delivery time for hostnames that resolve internally.
	if err := ssrf.ValidateURL(req.URL); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "webhook URL must be http(s) and point to a public host")
		return
	}

	secret := generateUserWebhookSecret()
	// At rest the secret is stored ONLY as the family's AES-256-GCM envelope
	// (secret_enc + key id; D6/DBSCHEMA-005): the generated plaintext is
	// returned to the caller exactly once and sealed for storage — the row
	// itself never holds it. A nil codec fails closed here.
	sealed, err := h.codec.Seal(secret)
	if err != nil {
		if h.logger != nil {
			h.logger.Error("webhook secret sealing failed", "error", err)
		}
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "secret sealing failed")
		return
	}
	typesJSON, _ := json.Marshal(req.EventTypes)

	var id int64
	err = h.pool.QueryRow(r.Context(),
		`INSERT INTO webhook_subscriptions (user_id, url, secret_enc, secret_key_id, event_types, scope) VALUES ($1, $2, $3, $4, $5, 'self') RETURNING id`,
		user.UserID, req.URL, sealed, h.codec.ActiveKeyID(), string(typesJSON)).Scan(&id)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "create failed")
		return
	}
	httputil.WriteJSON(w, http.StatusCreated, map[string]interface{}{
		"id": id, "secret": secret, "url": req.URL, "scope": "self",
	})
}

// Delete deletes a webhook subscription owned by the authenticated user.
func (h *UserWebhooksHandler) Delete(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	tag, _ := h.pool.Exec(r.Context(),
		`DELETE FROM webhook_subscriptions WHERE id = $1 AND user_id = $2`, id, user.UserID)
	if tag.RowsAffected() == 0 {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func generateUserWebhookSecret() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}
