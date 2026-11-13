package user

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
)

// NewsletterBundlesResponse is the shape returned by GET /settings/newsletter-bundles.
type NewsletterBundlesResponse struct {
	// BundleNewsletters controls whether newsletters from the same mailing list
	// are collapsed into a bundle view. Defaults to true (bundles on).
	BundleNewsletters bool `json:"bundleNewsletters"`
	// OptedOutLists is the list of list_ids whose messages are shown individually
	// rather than collapsed into a bundle (per-list opt-out).
	OptedOutLists []string `json:"optedOutLists"`
}

// newsletterBundlesRequest is the body accepted by PUT /settings/newsletter-bundles.
type newsletterBundlesRequest struct {
	BundleNewsletters *bool    `json:"bundleNewsletters"`
	OptedOutLists     []string `json:"optedOutLists"`
}

// NewsletterBundlesHandler manages the per-user newsletter bundling preference
// stored in users.view_prefs (keys: "bundleNewsletters" bool, "newsletterOptouts" []string).
type NewsletterBundlesHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewNewsletterBundlesHandler creates a NewsletterBundlesHandler.
func NewNewsletterBundlesHandler(pool *pgxpool.Pool, logger *slog.Logger) *NewsletterBundlesHandler {
	return &NewsletterBundlesHandler{pool: pool, logger: logger}
}

// Get handles GET /settings/newsletter-bundles.
// Returns the current bundleNewsletters flag and optedOutLists from view_prefs.
func (h *NewsletterBundlesHandler) Get(w http.ResponseWriter, r *http.Request) {
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
		httputil.WriteJSON(w, http.StatusOK, NewsletterBundlesResponse{
			BundleNewsletters: true,
			OptedOutLists:     []string{},
		})
		return
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(prefs, &raw); err != nil {
		httputil.WriteJSON(w, http.StatusOK, NewsletterBundlesResponse{
			BundleNewsletters: true,
			OptedOutLists:     []string{},
		})
		return
	}

	resp := h.buildResponse(raw)
	httputil.WriteJSON(w, http.StatusOK, resp)
}

// buildResponse extracts newsletter bundle prefs from a raw view_prefs map.
func (h *NewsletterBundlesHandler) buildResponse(raw map[string]json.RawMessage) NewsletterBundlesResponse {
	resp := NewsletterBundlesResponse{
		BundleNewsletters: true,
		OptedOutLists:     []string{},
	}

	if v, ok := raw["bundleNewsletters"]; ok {
		var b bool
		if err := json.Unmarshal(v, &b); err == nil {
			resp.BundleNewsletters = b
		}
	}

	if v, ok := raw["newsletterOptouts"]; ok {
		var list []string
		if err := json.Unmarshal(v, &list); err == nil && list != nil {
			resp.OptedOutLists = list
		}
	}

	return resp
}

// Put handles PUT /settings/newsletter-bundles.
// Merges bundleNewsletters and optedOutLists into the existing view_prefs JSONB column.
// Returns 400 on malformed body.
func (h *NewsletterBundlesHandler) Put(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req newsletterBundlesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}

	// Merge into existing view_prefs using PostgreSQL JSONB concatenation so other
	// prefs keys (defaultView, readingPane, etc.) are preserved.
	// Build a patch object containing only the newsletter-related keys.
	patch := map[string]interface{}{}
	if req.BundleNewsletters != nil {
		patch["bundleNewsletters"] = *req.BundleNewsletters
	}
	if req.OptedOutLists != nil {
		patch["newsletterOptouts"] = req.OptedOutLists
	}

	patchJSON, err := json.Marshal(patch)
	if err != nil {
		h.logger.Error("newsletter bundles marshal patch failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Merge the patch into view_prefs: existing value || patch (patch wins on conflict).
	_, err = h.pool.Exec(r.Context(),
		`UPDATE users
		    SET view_prefs = COALESCE(view_prefs, '{}'::jsonb) || $2::jsonb
		  WHERE id = $1`,
		u.UserID, string(patchJSON),
	)
	if err != nil {
		h.logger.Error("newsletter bundles update failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"}) //nolint:errcheck
}
