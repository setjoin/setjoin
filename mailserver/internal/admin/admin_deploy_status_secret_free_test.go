package admin

// Secret-free status projection tests for the HA deploy wizard read surface
// (D-MAILSERVER-INTERNAL-DEPLOY-R-001, package deploy-wizard-secret-echo).
//
// GetStatus must serve the deploy.StatusState projection — the response body
// contains no SSH private-key bodies or node passwords even when NodeConfig
// holds them — and the route is pinned to system.upgrade holders in
// cmd/mailserverd (route_inventory golden + TestRouteInventory_LoadBearingChains),
// replacing the former any-of-four System-console scopes.

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/deploy"
)

const (
	deployTestInlineKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAAVkJcU2VjcmV0S2V5Qm9keQ==\n-----END OPENSSH PRIVATE KEY-----"
	deployTestKeyPath   = "/etc/setjoin/deploy_ed25519"
	deployTestNodePass  = "s3cret-node-password"
)

func TestGetStatus_BodyContainsNoSecretMaterialEvenWhenNodeConfigHoldsIt(t *testing.T) {
	wizard := deploy.NewWizardWithState(&deploy.DeploymentState{
		Profile: deploy.Profile3Node,
		Nodes: []deploy.NodeConfig{
			{Host: "10.0.0.11", Role: "primary", SSHUser: "root", SSHKey: deployTestInlineKey, Password: deployTestNodePass},
			{Host: "10.0.0.12", Role: "standby", SSHUser: "root", SSHKey: deployTestKeyPath, Password: deployTestNodePass},
		},
		Steps: []deploy.DeploymentStep{{Name: "ssh_check", Status: "ok"}},
	})
	h := NewDeployHandler(wizard, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/admin/deploy/status", nil)
	w := httptest.NewRecorder()

	h.GetStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	for _, secret := range []string{
		deployTestInlineKey,
		"b3BlbnNzaC1rZXktdjEAAAAAVkJcU2VjcmV0S2V5Qm9keQ==",
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		deployTestNodePass,
	} {
		if strings.Contains(body, secret) {
			t.Errorf("status body leaked secret material %q", secret)
		}
	}
	if strings.Contains(body, `"ssh_key"`) || strings.Contains(body, `"password"`) {
		t.Errorf("status body serializes secret-bearing fields: %s", body)
	}

	var parsed struct {
		Nodes []struct {
			Host         string `json:"host"`
			KeyPath      string `json:"key_path"`
			HasInlineKey bool   `json:"has_inline_key"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("decode status body: %v", err)
	}
	if len(parsed.Nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(parsed.Nodes))
	}
	if !parsed.Nodes[0].HasInlineKey || parsed.Nodes[0].KeyPath != "" {
		t.Errorf("inline-key node must render as has_inline_key with no key_path, got %+v", parsed.Nodes[0])
	}
	if parsed.Nodes[1].HasInlineKey || parsed.Nodes[1].KeyPath != deployTestKeyPath {
		t.Errorf("path-key node must render key_path only, got %+v", parsed.Nodes[1])
	}
}

// TestDeployResetCallers_PinnedBySource pins proposedTest acceptance naming
// BOTH Reset callers: StartDeploy and CancelDeploy each invoke
// h.wizard.Reset() (shared-state replacement). A source-level guard keeps the
// handler-level Reset contract durable without executing a deployment.
func TestDeployResetCallers_PinnedBySource(t *testing.T) {
	src, err := os.ReadFile("admin_deploy.go")
	if err != nil {
		t.Fatalf("read admin_deploy.go: %v", err)
	}
	for _, fn := range []string{
		"func (h *DeployHandler) StartDeploy(",
		"func (h *DeployHandler) CancelDeploy(",
	} {
		start := strings.Index(string(src), fn)
		if start < 0 {
			t.Fatalf("handler %q not found in admin_deploy.go", fn)
		}
		body := string(src[start:])
		if end := strings.Index(body, "\nfunc "); end >= 0 {
			body = body[:end]
		}
		if !strings.Contains(body, "h.wizard.Reset()") {
			t.Errorf("%s must call h.wizard.Reset() (shared-state replacement)", fn)
		}
	}
}
