package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"setjoin.com/mailserver/internal/deploy"
	"setjoin.com/shared/httputil"
)

// DeployHandler serves the HA deployment wizard API endpoints.
type DeployHandler struct {
	wizard *deploy.Wizard
	logger *slog.Logger
}

// NewDeployHandler creates a deploy handler.
func NewDeployHandler(wizard *deploy.Wizard, logger *slog.Logger) *DeployHandler {
	return &DeployHandler{wizard: wizard, logger: logger}
}

// GetStatus returns the current deployment state as a secret-free projection:
// booleans/paths only — inline SSH private-key bodies and node passwords are
// never rendered (D-MAILSERVER-INTERNAL-DEPLOY-R-001). Inline-key input stays
// supported and is marked via has_inline_key with the body unrendered.
func (h *DeployHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	httputil.WriteJSON(w, http.StatusOK, h.wizard.StatusState())
}

// StartDeploy begins the automated deployment.
func (h *DeployHandler) StartDeploy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Nodes []deploy.NodeConfig `json:"nodes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(req.Nodes) != 3 {
		httputil.WriteError(w, http.StatusBadRequest, "exactly 3 nodes required for HA deployment")
		return
	}
	h.wizard.Reset()
	if err := h.wizard.Begin(r.Context(), req.Nodes); err != nil {
		h.logger.Error("deploy begin failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "Deploy failed. Check the server logs for details.")
		return
	}
	httputil.WriteJSON(w, http.StatusAccepted, map[string]string{"status": "deploying"})
}

// CancelDeploy cancels an in-progress deployment.
func (h *DeployHandler) CancelDeploy(w http.ResponseWriter, r *http.Request) {
	h.wizard.Reset()
	w.WriteHeader(http.StatusNoContent)
}
