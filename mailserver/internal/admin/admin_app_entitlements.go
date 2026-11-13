package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/reducererr"
)

// appEntitlementOrder is the authoritative member-app catalog and response
// order. Every app may be explicitly blocked per user; check_user_app_entitlement
// also intersects the six feature-backed apps with their program toggles.
var appEntitlementOrder = []string{"mail", "calendar", "contacts", "tasks", "chat", "drive", "meet"}

var validGatedApps = func() map[string]bool {
	apps := make(map[string]bool, len(appEntitlementOrder))
	for _, app := range appEntitlementOrder {
		apps[app] = true
	}
	return apps
}()

// AppEntitlementHandler manages per-user app entitlements for admin operators.
type AppEntitlementHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewAppEntitlementHandler creates a new AppEntitlementHandler.
func NewAppEntitlementHandler(pool *pgxpool.Pool, logger *slog.Logger) *AppEntitlementHandler {
	return &AppEntitlementHandler{pool: pool, logger: logger}
}

// appEntitlementRow is the wire shape returned by List.
type appEntitlementRow struct {
	App     string `json:"app"`
	Enabled bool   `json:"enabled"` // stored value, or the target account type's missing-row default
}

// List handles GET /admin/users/{id}/app-access.
// Returns all seven apps with their per-user entitlement value. Missing rows
// default allow for members and deny for guests, matching the reducer authority.
func (h *AppEntitlementHandler) List(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Type:   httputil.TypeValidationFailed,
			Title:  "Bad Request",
			Status: http.StatusBadRequest,
			Detail: "invalid user id",
		})
		return
	}

	// Resolve the missing-row default behind the same domain predicate as the
	// entitlement rows below. An out-of-scope or missing target therefore retains
	// the historical member-shaped default-allow response; it does not reveal that
	// an out-of-scope id belongs to a guest.
	domainScope := middleware.DomainScopeFromContext(r.Context())
	var isGuest bool
	if domainScope > 0 {
		err = h.pool.QueryRow(r.Context(),
			`SELECT COALESCE((
				SELECT is_guest_account(u.id)
				  FROM users u
				 WHERE u.id = $1
				   AND COALESCE(guest_account_host_domain(u.id), u.domain_id) = $2
			), FALSE)`, userID, domainScope).Scan(&isGuest)
	} else {
		err = h.pool.QueryRow(r.Context(),
			`SELECT COALESCE((
				SELECT is_guest_account(u.id)
				  FROM users u
				 WHERE u.id = $1
			), FALSE)`, userID).Scan(&isGuest)
	}
	if err != nil {
		if h.logger != nil {
			h.logger.Error("admin app entitlement target classification failed", "user_id", userID, "error", err)
		}
		httputil.WriteProblem(w, r, httputil.NewInternalProblem())
		return
	}

	// Query any explicit entitlement rows for this user. Domain-scoped admins fold
	// their domain into the SAME resolving SELECT (R1): user_app_entitlements has
	// no domain_id, so the predicate routes through users (user_id IN the scoped
	// user). An out-of-scope user yields no explicit rows → all seven apps
	// fall back to the default-allow (enabled=true), the same shape a user with no
	// entitlement rows returns — indistinguishable. domainScope == 0 (global
	// admin) → no extra predicate.
	var rows pgx.Rows
	if domainScope > 0 {
		rows, err = h.pool.Query(r.Context(),
			`SELECT app, enabled FROM user_app_entitlements
			 WHERE user_id = $1
			   AND user_id IN (
			       SELECT u.id FROM users u
			        WHERE u.id = $1
			          AND COALESCE(guest_account_host_domain(u.id), u.domain_id) = $2
			   )`,
			userID, domainScope)
	} else {
		rows, err = h.pool.Query(r.Context(),
			`SELECT app, enabled FROM user_app_entitlements WHERE user_id = $1`, userID)
	}
	if err != nil {
		if h.logger != nil {
			h.logger.Error("admin app entitlement list failed", "user_id", userID, "error", err)
		}
		httputil.WriteProblem(w, r, httputil.NewInternalProblem())
		return
	}
	defer rows.Close()

	// Build a map of explicit rows; the missing-row default is account-type aware.
	explicit := make(map[string]bool)
	for rows.Next() {
		var app string
		var enabled bool
		if scanErr := rows.Scan(&app, &enabled); scanErr == nil {
			explicit[app] = enabled
		}
	}
	if err := rows.Err(); err != nil {
		if h.logger != nil {
			h.logger.Error("admin app entitlement list rows error", "user_id", userID, "error", err)
		}
		httputil.WriteProblem(w, r, httputil.NewInternalProblem())
		return
	}

	// Emit one entry per app in the authoritative deterministic order.
	out := make([]appEntitlementRow, 0, len(appEntitlementOrder))
	for _, app := range appEntitlementOrder {
		enabled := !isGuest
		if val, ok := explicit[app]; ok {
			enabled = val
		}
		out = append(out, appEntitlementRow{App: app, Enabled: enabled})
	}

	httputil.WriteJSON(w, http.StatusOK, out)
}

// setAppEntitlementBody is the request body for Set.
type setAppEntitlementBody struct {
	Enabled bool `json:"enabled"`
}

// Set handles PUT /admin/users/{id}/app-access/{app}.
// Decodes {enabled bool}, validates the app name, then calls the set_app_entitlement reducer.
func (h *AppEntitlementHandler) Set(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Type:   httputil.TypeValidationFailed,
			Title:  "Validation Failed",
			Status: http.StatusBadRequest,
			Detail: "invalid user id",
		})
		return
	}

	app := r.PathValue("app")
	if !validGatedApps[app] {
		httputil.WriteProblem(w, r, httputil.NewValidationProblem(
			"unknown app; must be one of mail, calendar, contacts, tasks, chat, drive, meet",
			[]httputil.FieldError{{Field: "app", Message: "unknown app"}},
		))
		return
	}

	var body setAppEntitlementBody
	if decodeErr := json.NewDecoder(r.Body).Decode(&body); decodeErr != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Type:   httputil.TypeValidationFailed,
			Title:  "Bad Request",
			Status: http.StatusBadRequest,
			Detail: "request body must be JSON with an 'enabled' boolean",
		})
		return
	}

	// h.pool is nil in unit tests that exercise only the decode/validation path.
	if h.pool == nil {
		httputil.WriteProblem(w, r, httputil.NewInternalProblem())
		return
	}

	adminUser := auth.UserFromContext(r.Context())

	// Domain-scoped admins may only toggle entitlements for users in their own
	// domain. user_app_entitlements has no domain_id and the mutation runs inside
	// the set_app_entitlement reducer, so we fold the domain predicate into a
	// scoped existence check that runs in the SAME transaction as the reducer call
	// (no TOCTOU — mirrors admin_users.go Delete): an out-of-scope (or missing)
	// user matches 0 rows → 404, indistinguishable from missing, and the reducer
	// never runs. domainScope == 0 (global admin) → the reducer call is unchanged.
	domainScope := middleware.DomainScopeFromContext(r.Context())
	if domainScope > 0 {
		tx, txErr := h.pool.Begin(r.Context())
		if txErr != nil {
			if h.logger != nil {
				h.logger.Error("admin set_app_entitlement tx begin failed",
					"user_id", userID, "app", app, "error", txErr)
			}
			httputil.WriteProblem(w, r, httputil.NewInternalProblem())
			return
		}
		defer tx.Rollback(r.Context())

		var scopedID int64
		scopeErr := tx.QueryRow(r.Context(),
			`SELECT u.id FROM users u
			  WHERE u.id = $1
			    AND COALESCE(guest_account_host_domain(u.id), u.domain_id) = $2`,
			userID, domainScope).Scan(&scopedID)
		if scopeErr != nil {
			if scopeErr == pgx.ErrNoRows {
				httputil.WriteProblem(w, r, &httputil.Problem{
					Type:   httputil.TypeNotFound,
					Title:  "Not Found",
					Status: http.StatusNotFound,
					Detail: "user not found",
				})
				return
			}
			if h.logger != nil {
				h.logger.Error("admin set_app_entitlement scope check failed",
					"user_id", userID, "app", app, "error", scopeErr)
			}
			httputil.WriteProblem(w, r, httputil.NewInternalProblem())
			return
		}

		if _, dbErr := tx.Exec(r.Context(),
			`SELECT set_app_entitlement($1, $2, $3, $4)`,
			userID, app, body.Enabled, adminUser.UserID); dbErr != nil {
			if reducererr.WriteClassified(w, r, dbErr) {
				return
			}
			if h.logger != nil {
				h.logger.Error("admin set_app_entitlement failed",
					"user_id", userID, "app", app, "error", dbErr)
			}
			httputil.WriteProblem(w, r, httputil.NewInternalProblem())
			return
		}

		if commitErr := tx.Commit(r.Context()); commitErr != nil {
			if h.logger != nil {
				h.logger.Error("admin set_app_entitlement tx commit failed",
					"user_id", userID, "app", app, "error", commitErr)
			}
			httputil.WriteProblem(w, r, httputil.NewInternalProblem())
			return
		}

		w.WriteHeader(http.StatusNoContent)
		return
	}

	_, dbErr := h.pool.Exec(r.Context(),
		`SELECT set_app_entitlement($1, $2, $3, $4)`,
		userID, app, body.Enabled, adminUser.UserID)
	if dbErr != nil {
		if reducererr.WriteClassified(w, r, dbErr) {
			return
		}
		if h.logger != nil {
			h.logger.Error("admin set_app_entitlement failed",
				"user_id", userID, "app", app, "error", dbErr)
		}
		httputil.WriteProblem(w, r, httputil.NewInternalProblem())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
