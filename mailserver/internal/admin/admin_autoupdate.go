package admin

import (
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/httputil"
)

// AutoUpdateHandler preserves the authenticated compatibility routes while
// keeping server-update authority in the transactional updater control plane.
// The constructor retains its historical signature so route wiring does not
// accidentally bypass the existing authorization middleware.
type AutoUpdateHandler struct{}

func NewAutoUpdateHandler(_ *pgxpool.Pool, _ *slog.Logger) *AutoUpdateHandler {
	return &AutoUpdateHandler{}
}

const legacyAutoUpdateRetiredType = "https://setjoin.com/errors/legacy-auto-update-retired"

func writeLegacyAutoUpdateRetired(w http.ResponseWriter, r *http.Request) {
	httputil.WriteProblem(w, r, &httputil.Problem{
		Type:   legacyAutoUpdateRetiredType,
		Title:  "Legacy auto-update configuration retired",
		Status: http.StatusGone,
		Detail: "Path-based auto-update and its separate maintenance-window configuration are retired because they bypass signed releases, application recovery points, and transactional rollback.",
		Remediation: "Open /admin/updates/server to preview or schedule a signed release. " +
			"Use mailctl upgrade status --json for read-only host status and follow docs/guides/UPGRADE.md for operator recovery.",
	})
}

func (h *AutoUpdateHandler) GetAutoUpdateConfig(w http.ResponseWriter, r *http.Request) {
	writeLegacyAutoUpdateRetired(w, r)
}

func (h *AutoUpdateHandler) SaveAutoUpdateConfig(w http.ResponseWriter, r *http.Request) {
	writeLegacyAutoUpdateRetired(w, r)
}

func (h *AutoUpdateHandler) GetMaintenanceWindow(w http.ResponseWriter, r *http.Request) {
	writeLegacyAutoUpdateRetired(w, r)
}

func (h *AutoUpdateHandler) SaveMaintenanceWindow(w http.ResponseWriter, r *http.Request) {
	writeLegacyAutoUpdateRetired(w, r)
}
