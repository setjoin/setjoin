package admin

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	wh "setjoin.com/shared/webhook"
)

// WebhooksHandler provides admin CRUD for webhook subscriptions.
type WebhooksHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
	// codec seals webhook signing secrets at rest
	// (webhook_subscriptions.secret_enc / prev_secret_enc; D6/DBSCHEMA-005,
	// the V247 device pattern). Nil fails closed at Create/RotateSecret — the
	// handler never persists plaintext secrets.
	codec *wh.SecretCodec
}

func NewWebhooksHandler(pool *pgxpool.Pool, logger *slog.Logger, codec *wh.SecretCodec) *WebhooksHandler {
	return &WebhooksHandler{pool: pool, logger: logger, codec: codec}
}

// List returns all webhook subscriptions.
func (h *WebhooksHandler) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.pool.Query(r.Context(),
		`SELECT id, user_id, url, event_types, scope, is_active, created_at, updated_at
         FROM webhook_subscriptions ORDER BY created_at DESC`)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	type sub struct {
		ID         int64     `json:"id"`
		UserID     *int64    `json:"userId,omitempty"`
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
		if rows.Scan(&s.ID, &s.UserID, &s.URL, &types, &s.Scope, &s.IsActive, &s.CreatedAt, &s.UpdatedAt) == nil {
			json.Unmarshal(types, &s.EventTypes)
			out = append(out, s)
		}
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

// Create creates a new webhook subscription.
func (h *WebhooksHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL        string   `json:"url"`
		EventTypes []string `json:"eventTypes"`
		Scope      string   `json:"scope"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.URL == "" || len(req.EventTypes) == 0 {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "url and eventTypes required")
		return
	}
	if req.Scope == "" {
		req.Scope = "self"
	}
	if req.Scope != "self" && req.Scope != "organization" {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "scope must be self or organization")
		return
	}
	if len(req.EventTypes) > len(wh.EventCatalog()) {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "eventTypes exceeds the catalog")
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

	secret, err := generateWebhookSecret()
	if err != nil {
		h.logger.Error("generate webhook secret failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "secret generation failed")
		return
	}
	// At rest the secret is stored ONLY as the family's AES-256-GCM envelope
	// (secret_enc + key id; D6/DBSCHEMA-005): the generated plaintext is
	// returned to the caller exactly once and sealed for storage — the row
	// itself never holds it. A nil codec fails closed here.
	sealed, err := h.codec.Seal(secret)
	if err != nil {
		h.logger.Error("webhook secret sealing failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "secret sealing failed")
		return
	}
	typesJSON, _ := json.Marshal(req.EventTypes)

	user := auth.UserFromContext(r.Context())
	var id int64
	err = h.pool.QueryRow(r.Context(),
		`INSERT INTO webhook_subscriptions (user_id, url, secret_enc, secret_key_id, event_types, scope)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		user.UserID, req.URL, sealed, h.codec.ActiveKeyID(), string(typesJSON), req.Scope).Scan(&id)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "create failed")
		return
	}
	httputil.WriteJSON(w, http.StatusCreated, map[string]interface{}{
		"id": id, "secret": secret, "url": req.URL, "scope": req.Scope,
	})
}

// Delete deletes a webhook subscription.
func (h *WebhooksHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	user := auth.UserFromContext(r.Context())
	tag, err := h.pool.Exec(r.Context(),
		`DELETE FROM webhook_subscriptions WHERE id = $1 AND user_id = $2`, id, user.UserID)
	if err != nil {
		h.logger.Error("webhook delete failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	if tag.RowsAffected() == 0 {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RotateSecret rotates the signing secret for a webhook.
//
// At-rest contract (D6/DBSCHEMA-005): the previous value is re-sealed into
// the prev_* envelope columns and the new value is installed as an envelope —
// a rotated row ends ciphertext-only in all four secret cells (legacy
// plaintext rows drain here too). The row is locked FOR UPDATE inside one
// transaction with the ownership predicate (id + user_id) in BOTH statements,
// so a concurrent rotation serializes instead of racing (no check-then-mutate).
// A previous envelope stamped with an unknown key version fails the rotation
// closed — the operator re-rotates after fixing key configuration; no
// undecryptable secret is ever silently copied or dropped.
func (h *WebhooksHandler) RotateSecret(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	newSecret, err := generateWebhookSecret()
	if err != nil {
		h.logger.Error("generate webhook secret failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "secret generation failed")
		return
	}
	user := auth.UserFromContext(r.Context())
	ctx := r.Context()

	// Seal both values before touching the row: a nil/broken codec fails
	// closed without leaving the subscription in a half-rotated state.
	sealedNew, err := h.codec.Seal(newSecret)
	if err != nil {
		h.logger.Error("webhook secret sealing failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "secret sealing failed")
		return
	}

	tx, err := h.pool.Begin(ctx)
	if err != nil {
		h.logger.Error("webhook secret rotation failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	// Rollback is the no-op-after-commit safety net; surface a real failure
	// instead of silently dropping it.
	defer func() {
		if rerr := tx.Rollback(ctx); rerr != nil && !errors.Is(rerr, pgx.ErrTxClosed) {
			h.logger.Error("webhook secret rotation rollback failed", "error", rerr)
		}
	}()

	var legacy *string
	var envelope []byte
	var keyID *string
	err = tx.QueryRow(ctx,
		`SELECT secret, secret_enc, secret_key_id FROM webhook_subscriptions
          WHERE id = $1 AND user_id = $2 FOR UPDATE`,
		id, user.UserID).Scan(&legacy, &envelope, &keyID)
	if errors.Is(err, pgx.ErrNoRows) {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		h.logger.Error("webhook secret rotation failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}

	var sealedPrev []byte
	switch {
	case envelope != nil:
		if keyID == nil {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "stored secret has no key id")
			return
		}
		prev, err := h.codec.Open(envelope, *keyID)
		if err != nil {
			// Unknown key id / undecryptable envelope: fail closed, roll back.
			h.logger.Error("webhook secret rotation refused", "error", err)
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "previous secret cannot be opened")
			return
		}
		sealedPrev, err = h.codec.Seal(prev)
		if err != nil {
			h.logger.Error("webhook secret sealing failed", "error", err)
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "secret sealing failed")
			return
		}
	case legacy != nil:
		// Legacy plaintext row: re-seal the issued value into the prev
		// envelope and drain the plaintext (compatibility leg).
		sealedPrev, err = h.codec.Seal(*legacy)
		if err != nil {
			h.logger.Error("webhook secret sealing failed", "error", err)
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "secret sealing failed")
			return
		}
	default:
		// Malformed row (no previous secret in either form): install the new
		// secret with an empty prev — rotation is the recovery path.
		sealedPrev = nil
	}

	tag, err := tx.Exec(ctx,
		`UPDATE webhook_subscriptions
		    SET prev_secret = NULL, prev_secret_enc = $1, prev_secret_key_id = $2,
		        secret = NULL, secret_enc = $3, secret_key_id = $4
		  WHERE id = $5 AND user_id = $6`,
		sealedPrev, h.codec.ActiveKeyID(), sealedNew, h.codec.ActiveKeyID(), id, user.UserID)
	if err != nil {
		h.logger.Error("webhook secret rotation failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	if tag.RowsAffected() == 0 {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		h.logger.Error("webhook secret rotation failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"secret": newSecret})
}

// EventCatalog returns the machine-readable event type catalog.
func (h *WebhooksHandler) EventCatalog(w http.ResponseWriter, r *http.Request) {
	httputil.WriteJSON(w, http.StatusOK, wh.EventCatalog())
}

// Deliveries returns the delivery log for a webhook.
func (h *WebhooksHandler) Deliveries(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	rows, err := h.pool.Query(r.Context(),
		`SELECT id, event_id, event_type, response_code, latency_ms, attempt, status, error_message, created_at
         FROM webhook_deliveries WHERE subscription_id = $1 ORDER BY created_at DESC LIMIT 200`, id)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	type delivery struct {
		ID           int64     `json:"id"`
		EventID      string    `json:"eventId"`
		EventType    string    `json:"eventType"`
		ResponseCode *int      `json:"responseCode,omitempty"`
		LatencyMS    *int      `json:"latencyMs,omitempty"`
		Attempt      int       `json:"attempt"`
		Status       string    `json:"status"`
		ErrorMessage *string   `json:"errorMessage,omitempty"`
		CreatedAt    time.Time `json:"createdAt"`
	}
	out := make([]delivery, 0)
	for rows.Next() {
		var d delivery
		if rows.Scan(&d.ID, &d.EventID, &d.EventType, &d.ResponseCode, &d.LatencyMS, &d.Attempt, &d.Status, &d.ErrorMessage, &d.CreatedAt) == nil {
			out = append(out, d)
		}
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

func generateWebhookSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
