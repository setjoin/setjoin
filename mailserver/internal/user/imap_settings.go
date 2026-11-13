package user

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
)

type UserIMAPSettingsHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

func NewUserIMAPSettingsHandler(pool *pgxpool.Pool, logger *slog.Logger) *UserIMAPSettingsHandler {
	return &UserIMAPSettingsHandler{pool: pool, logger: logger}
}

func (h *UserIMAPSettingsHandler) Get(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var exposeAll, subOnly bool
	var exposedIDs []int64
	var separator string
	err := h.pool.QueryRow(r.Context(),
		`SELECT COALESCE(expose_all, FALSE), COALESCE(show_subscribed_only, TRUE),
		        COALESCE(exposed_tag_ids, '{}'), COALESCE(folder_separator, '/')
		 FROM user_imap_settings WHERE user_id = $1`,
		user.UserID,
	).Scan(&exposeAll, &subOnly, &exposedIDs, &separator)
	if err != nil {
		// No settings yet — return defaults
		httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{
			"exposeAll":          false,
			"showSubscribedOnly": true,
			"exposedTagIds":      []int64{},
			"folderSeparator":    "/",
		})
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"exposeAll":          exposeAll,
		"showSubscribedOnly": subOnly,
		"exposedTagIds":      exposedIDs,
		"folderSeparator":    separator,
	})
}

func (h *UserIMAPSettingsHandler) Put(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req struct {
		ExposeAll          *bool   `json:"exposeAll"`
		ShowSubscribedOnly *bool   `json:"showSubscribedOnly"`
		ExposedTagIds      []int64 `json:"exposedTagIds"`
		FolderSeparator    *string `json:"folderSeparator"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}

	_, err := h.pool.Exec(r.Context(),
		`INSERT INTO user_imap_settings (user_id, expose_all, show_subscribed_only, exposed_tag_ids, folder_separator)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (user_id) DO UPDATE SET
		   expose_all = COALESCE($2, user_imap_settings.expose_all),
		   show_subscribed_only = COALESCE($3, user_imap_settings.show_subscribed_only),
		   exposed_tag_ids = CASE WHEN $4::BIGINT[] IS NOT NULL THEN $4 ELSE user_imap_settings.exposed_tag_ids END,
		   folder_separator = COALESCE($5, user_imap_settings.folder_separator)`,
		user.UserID,
		req.ExposeAll,
		req.ShowSubscribedOnly,
		req.ExposedTagIds,
		req.FolderSeparator,
	)
	if err != nil {
		h.logger.Error("imap settings put failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
