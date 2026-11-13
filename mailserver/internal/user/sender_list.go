package user

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/reducererr"
	"setjoin.com/shared/toggle"
)

type senderControlFeatureGate interface{ IsEnabled(string) bool }

// SenderListHandler provides GET/PUT /settings/senders — per-user safe/blocked sender lists.
type SenderListHandler struct {
	pool     *pgxpool.Pool
	logger   *slog.Logger
	worker   pgxutil.WorkerPool
	features senderControlFeatureGate
}

func (h *SenderListHandler) SetSenderControl(worker pgxutil.WorkerPool, features senderControlFeatureGate) {
	h.worker, h.features = worker, features
}

func (h *SenderListHandler) senderControlOn() bool {
	return h.features != nil && h.features.IsEnabled(toggle.FeatureSenderControlCenter)
}

// NewSenderListHandler creates a SenderListHandler.
func NewSenderListHandler(pool *pgxpool.Pool, logger *slog.Logger) *SenderListHandler {
	return &SenderListHandler{pool: pool, logger: logger}
}

// Get returns the current user's safe and blocked sender lists.
func (h *SenderListHandler) Get(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if h.senderControlOn() {
		var raw json.RawMessage
		if err := h.worker.QueryRow(r.Context(), `SELECT sender_list_read($1)`, u.UserID).Scan(&raw); err != nil {
			if !reducererr.WriteClassified(w, r, err) {
				httputil.WriteProblemStatus(w, http.StatusInternalServerError, "sender list read failed")
			}
			return
		}
		var meta struct {
			Generation string `json:"generation"`
		}
		_ = json.Unmarshal(raw, &meta)
		w.Header().Set("ETag", `"`+meta.Generation+`"`)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
		return
	}

	rows, err := h.pool.Query(r.Context(),
		`SELECT sender, list_type FROM user_sender_list WHERE user_id = $1 ORDER BY list_type, sender`,
		u.UserID,
	)
	if err != nil {
		h.logger.Error("sender list query failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	safe := make([]string, 0)
	blocked := make([]string, 0)
	for rows.Next() {
		var sender, listType string
		if err := rows.Scan(&sender, &listType); err != nil {
			continue
		}
		if listType == "safe" {
			safe = append(safe, sender)
		} else {
			blocked = append(blocked, sender)
		}
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"safe":    safe,
		"blocked": blocked,
	})
}

// Put replaces the user's entire sender list atomically.
func (h *SenderListHandler) Put(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req struct {
		Safe               []string `json:"safe"`
		Blocked            []string `json:"blocked"`
		ExpectedGeneration string   `json:"expectedGeneration,omitempty"`
		OperationID        string   `json:"operationId,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if h.senderControlOn() {
		operationID, parseErr := uuid.Parse(req.OperationID)
		generation, genErr := strconv.ParseInt(req.ExpectedGeneration, 10, 64)
		if parseErr != nil || operationID == uuid.Nil || genErr != nil || generation <= 0 ||
			strings.TrimSpace(r.Header.Get("Idempotency-Key")) != req.OperationID || r.Header.Get("If-Match") != `"`+req.ExpectedGeneration+`"` {
			httputil.WriteProblemStatus(w, http.StatusPreconditionRequired, "operationId/Idempotency-Key and expectedGeneration/If-Match are required")
			return
		}
		encoded, _ := json.Marshal(req)
		sum := sha256.Sum256(encoded)
		digest := hex.EncodeToString(sum[:])
		var raw json.RawMessage
		if err := h.worker.QueryRow(r.Context(), `SELECT sender_list_replace($1,$2,$3,$4,$5,$6)`,
			u.UserID, operationID, generation, digest, req.Safe, req.Blocked).Scan(&raw); err != nil {
			if !reducererr.WriteClassified(w, r, err) {
				httputil.WriteProblemStatus(w, http.StatusInternalServerError, "sender list replacement failed")
			}
			return
		}
		var meta struct {
			Generation string `json:"generation"`
		}
		_ = json.Unmarshal(raw, &meta)
		w.Header().Set("ETag", `"`+meta.Generation+`"`)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
		return
	}

	// Replace the full list atomically: delete all, re-insert.
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "tx error")
		return
	}
	defer tx.Rollback(r.Context())

	if _, err := tx.Exec(r.Context(),
		`DELETE FROM user_sender_list WHERE user_id = $1`, u.UserID,
	); err != nil {
		h.logger.Error("sender list delete failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	for _, s := range req.Safe {
		if _, err := tx.Exec(r.Context(),
			`INSERT INTO user_sender_list (user_id, sender, list_type) VALUES ($1, $2, 'safe')`,
			u.UserID, s,
		); err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, "database error")
			return
		}
	}
	for _, s := range req.Blocked {
		if _, err := tx.Exec(r.Context(),
			`INSERT INTO user_sender_list (user_id, sender, list_type) VALUES ($1, $2, 'blocked')`,
			u.UserID, s,
		); err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, "database error")
			return
		}
	}

	if err := tx.Commit(r.Context()); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "commit error")
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// NeverBlock moves a sender from the blocked list to the safe list.
// POST /settings/senders/never-block
func (h *SenderListHandler) NeverBlock(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if h.senderControlOn() {
		httputil.WriteProblemStatus(w, http.StatusConflict, "use the message-bound sender control action")
		return
	}

	var req struct {
		Sender string `json:"sender"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.Sender == "" {
		httputil.WriteError(w, http.StatusBadRequest, "sender is required")
		return
	}

	// Upsert: add to safe list, remove from blocked if present.
	_, err := h.pool.Exec(r.Context(),
		`DELETE FROM user_sender_list WHERE user_id = $1 AND sender = $2 AND list_type = 'blocked'`,
		u.UserID, req.Sender,
	)
	if err != nil {
		h.logger.Error("never-block delete blocked failed", "error", err)
	}
	_, err = h.pool.Exec(r.Context(),
		`INSERT INTO user_sender_list (user_id, sender, list_type)
		 VALUES ($1, $2, 'safe')
		 ON CONFLICT (user_id, sender, list_type) DO NOTHING`,
		u.UserID, req.Sender,
	)
	if err != nil {
		h.logger.Error("never-block insert safe failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "sender": req.Sender, "list": "safe"})
}
