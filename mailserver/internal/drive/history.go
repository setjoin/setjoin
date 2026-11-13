package drive

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/toggle"
)

const maxHistoryLimit = 100

type historyCursor struct {
	OccurredAt string `json:"occurredAt"`
	SourceRank int    `json:"sourceRank"`
	SourceID   int64  `json:"sourceId"`
}

type historyEnvelope struct {
	Items       json.RawMessage `json:"items"`
	HasMore     bool            `json:"hasMore"`
	Next        *historyCursor  `json:"next"`
	Coverage    json.RawMessage `json:"coverage"`
	GeneratedAt string          `json:"generatedAt"`
}

func (h *Handler) registerHistoryRoutes(mux router) {
	mux.HandleFunc("GET /drive/files/{id}/history", h.fileHistory)
}

func (h *Handler) signHistoryCursor(c historyCursor) (string, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, h.historyCursorKey[:])
	_, _ = mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (h *Handler) parseHistoryCursor(raw string) (historyCursor, error) {
	var c historyCursor
	parts := strings.Split(raw, ".")
	if len(parts) != 2 {
		return c, errors.New("invalid cursor")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return c, errors.New("invalid cursor")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return c, errors.New("invalid cursor")
	}
	mac := hmac.New(sha256.New, h.historyCursorKey[:])
	_, _ = mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return c, errors.New("invalid cursor")
	}
	if err := json.Unmarshal(payload, &c); err != nil || c.SourceRank < 0 || c.SourceID < 1 {
		return historyCursor{}, errors.New("invalid cursor")
	}
	if _, err := time.Parse(time.RFC3339Nano, c.OccurredAt); err != nil {
		return historyCursor{}, errors.New("invalid cursor")
	}
	return c, nil
}

func (h *Handler) fileHistory(w http.ResponseWriter, r *http.Request) {
	if !h.flags.IsEnabled(toggle.FeatureDriveHistory) {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	claims := auth.UserFromContext(r.Context())
	nodeID, ok := httputil.ParseIDPath(w, r, "id", "invalid file id")
	if !ok {
		return
	}
	limit := maxHistoryLimit
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > maxHistoryLimit {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnprocessableEntity,
				Type: "https://setjoin.com/problems/drive/invalid-arguments", Detail: "limit must be between 1 and 100", Code: "BZ141"})
			return
		}
		limit = parsed
	}
	var cursor *historyCursor
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		parsed, err := h.parseHistoryCursor(raw)
		if err != nil {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest,
				Type: "https://setjoin.com/problems/drive/invalid-cursor", Detail: "history cursor is invalid or expired", Code: "BZ141"})
			return
		}
		cursor = &parsed
	}

	var beforeAt *time.Time
	var beforeRank *int
	var beforeID *int64
	if cursor != nil {
		at, _ := time.Parse(time.RFC3339Nano, cursor.OccurredAt)
		beforeAt, beforeRank, beforeID = &at, &cursor.SourceRank, &cursor.SourceID
	}
	var raw json.RawMessage
	err := dbscope.RunUserScoped(r.Context(), h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `SELECT drive_file_history_query($1,$2,$3,$4,$5,$6)`,
			claims.UserID, nodeID, limit, beforeAt, beforeRank, beforeID).Scan(&raw)
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	var envelope historyEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		h.logger.Error("decode drive history reducer envelope", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "history unavailable")
		return
	}
	var nextCursor *string
	if envelope.HasMore && envelope.Next != nil {
		signed, err := h.signHistoryCursor(*envelope.Next)
		if err != nil {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "history unavailable")
			return
		}
		nextCursor = &signed
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": envelope.Items, "hasMore": envelope.HasMore,
		"nextCursor": nextCursor, "coverage": envelope.Coverage,
		"generatedAt": envelope.GeneratedAt,
	})
}
