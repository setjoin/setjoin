package user

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
)

// defaultViewPrefs is the set of keys returned when the user has never saved preferences.
var defaultViewPrefs = map[string]interface{}{
	"defaultView":      "conversation",
	"readingPane":      "right",
	"senderImages":     true,
	"extSenderWarning": true,
	"smartMute":        false,
	"undoSendDelay":    5,
	"offlineWindow":    "30d",
}

// validOfflineWindow mirrors lib/offline/window.ts OFFLINE_WINDOWS (review C2:
// single-sourced enum, validated server-side). Bounds the NATIVE cache only.
// ponytail: switch is the minimal form; extend when the TS enum grows.
func validOfflineWindow(v string) bool {
	switch v {
	case "7d", "30d", "90d", "180d", "365d", "all":
		return true
	}
	return false
}

type ViewPrefsHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

func NewViewPrefsHandler(pool *pgxpool.Pool, logger *slog.Logger) *ViewPrefsHandler {
	return &ViewPrefsHandler{pool: pool, logger: logger}
}

func (h *ViewPrefsHandler) Get(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var prefs []byte
	err := h.pool.QueryRow(r.Context(),
		`SELECT view_prefs FROM users WHERE id = $1`, u.UserID,
	).Scan(&prefs)
	if err != nil || len(prefs) == 0 || string(prefs) == "null" {
		httputil.WriteJSON(w, http.StatusOK, defaultViewPrefs)
		return
	}

	var stored map[string]interface{}
	if err := json.Unmarshal(prefs, &stored); err != nil {
		httputil.WriteJSON(w, http.StatusOK, defaultViewPrefs)
		return
	}

	// ponytail: merge stored over defaults so keys added after the user first
	// saved prefs (e.g. offlineWindow) are back-filled. O(n) copy, n≤10 keys.
	result := make(map[string]interface{}, len(defaultViewPrefs))
	for k, v := range defaultViewPrefs {
		result[k] = v
	}
	for k, v := range stored {
		result[k] = v
	}
	httputil.WriteJSON(w, http.StatusOK, result)
}

func (h *ViewPrefsHandler) Put(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}

	if val, ok := req["offlineWindow"]; ok {
		s, isStr := val.(string)
		if !isStr || !validOfflineWindow(s) {
			httputil.WriteError(w, http.StatusBadRequest, "invalid offlineWindow")
			return
		}
	}

	prefsJSON, _ := json.Marshal(req)
	_, err := h.pool.Exec(r.Context(),
		`UPDATE users SET view_prefs = $2 WHERE id = $1`,
		u.UserID, prefsJSON,
	)
	if err != nil {
		h.logger.Error("view prefs put failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
