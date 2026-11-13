package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/config"
)

// The shipped SeaweedFS S3 identity config (deploy/seaweedfs-s3.json) is the
// -s3.config mounted by deploy/seaweedfs-master.service.template on the HA /
// copy-paste track. It must fail closed: it ships the identity scaffold only,
// with zero credential material, so no deterministic identity exists until S3
// credentials are provisioned at install time (generated into the deployment's
// secret handling, like the single-node config.env path). Shipping a
// well-known pair (e.g. minioadmin/minioadmin) would let any network peer
// reaching :9000 authenticate as full admin.
//
// Contract enforced here (D-MAILSERVER-DEPLOY-001):
//   - the file is strict JSON with a non-empty identities scaffold;
//   - no shipped identity carries any credential (credentials stay empty);
//   - no well-known/default/placeholder credential string appears anywhere;
//   - no "anonymous" identity is shipped (unsigned requests must not match);
//   - the shipped unit template still mounts this exact config, so this guard
//     keeps covering the path a deployment actually loads.
const shippedSeaweedfsS3ConfigPath = "../../deploy/seaweedfs-s3.json"

const shippedSeaweedfsMasterUnitPath = "../../deploy/seaweedfs-master.service.template"

// wellKnownS3CredentialSubstrings (the vendor-default and placeholder marker
// list) is owned by seaweedfs.go and shared with ValidateS3IdentitiesConfig,
// the deployment-time rejection gate — both the shipped-artifact guard below
// and the deployed-config validator must reject the SAME marker set.

type shippedS3Identity struct {
	Name        string `json:"name"`
	Credentials []struct {
		AccessKey string `json:"accessKey"`
		SecretKey string `json:"secretKey"`
	} `json:"credentials"`
	Actions []string `json:"actions"`
}

type shippedS3Config struct {
	Identities []shippedS3Identity `json:"identities"`
}

// checkShippedSeaweedfsS3Config enforces the fail-closed shipped-artifact
// contract against raw config bytes.
func checkShippedSeaweedfsS3Config(raw []byte) error {
	lower := strings.ToLower(string(raw))
	for _, marker := range wellKnownS3CredentialSubstrings {
		if strings.Contains(lower, marker) {
			return fmt.Errorf("shipped S3 config contains well-known/placeholder credential marker %q; S3 identities must be generated at install time, never shipped", marker)
		}
	}

	var cfg shippedS3Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("shipped S3 config is not valid JSON: %v", err)
	}
	if len(cfg.Identities) == 0 {
		return fmt.Errorf("shipped S3 config defines no identities; the identities scaffold is what keeps the S3 API in authenticated mode")
	}
	for i, ident := range cfg.Identities {
		if strings.TrimSpace(ident.Name) == "" {
			return fmt.Errorf("shipped S3 config identity[%d] has an empty name", i)
		}
		if strings.EqualFold(ident.Name, "anonymous") {
			return fmt.Errorf("shipped S3 config must not define an anonymous identity; unsigned requests must not match anything")
		}
		if len(ident.Actions) == 0 {
			return fmt.Errorf("shipped S3 config identity %q grants no actions; scaffold must document the action set install-time provisioning grants", ident.Name)
		}
		if len(ident.Credentials) > 0 {
			return fmt.Errorf("shipped S3 config identity %q carries %d credential(s); the shipped artifact must fail closed with zero credentials (generate S3 identities at install time instead)", ident.Name, len(ident.Credentials))
		}
	}
	return nil
}

// TestShippedSeaweedfsS3Config_FailsClosed pins the fail-closed contract on the
// artifact a deployment actually loads.
func TestShippedSeaweedfsS3Config_FailsClosed(t *testing.T) {
	raw, err := os.ReadFile(shippedSeaweedfsS3ConfigPath)
	if err != nil {
		t.Fatalf("read %s: %v", shippedSeaweedfsS3ConfigPath, err)
	}
	if err := checkShippedSeaweedfsS3Config(raw); err != nil {
		t.Fatalf("shipped %s must fail closed: %v", shippedSeaweedfsS3ConfigPath, err)
	}
}

// TestShippedSeaweedfsS3Config_RejectsWellKnownPairs proves the guard rejects
// the exact states the finding forbids, so the contract cannot silently rot.
func TestShippedSeaweedfsS3Config_RejectsWellKnownPairs(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{
			name: "vendor default minioadmin pair",
			raw: `{
  "identities": [
    {
      "name": "admin",
      "credentials": [{"accessKey": "minioadmin", "secretKey": "minioadmin"}],
      "actions": ["Admin", "Read", "Write", "List", "Tagging"]
    }
  ]
}`,
		},
		{
			name: "placeholder credential pair",
			raw: `{
  "identities": [
    {
      "name": "admin",
      "credentials": [{"accessKey": "<generated-at-install>", "secretKey": "<generated-at-install>"}],
      "actions": ["Admin"]
    }
  ]
}`,
		},
		{
			name: "empty-string credential pair",
			raw: `{
  "identities": [
    {
      "name": "admin",
      "credentials": [{"accessKey": "", "secretKey": ""}],
      "actions": ["Admin"]
    }
  ]
}`,
		},
		{
			name: "anonymous identity shipped",
			raw: `{
  "identities": [
    {
      "name": "anonymous",
      "actions": ["Read"]
    }
  ]
}`,
		},
		{
			name: "no identities at all",
			raw:  `{"identities": []}`,
		},
		{
			name: "not JSON",
			raw:  "not json at all",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if err := checkShippedSeaweedfsS3Config([]byte(tc.raw)); err == nil {
				t.Fatalf("guard accepted a forbidden shipped S3 config state (%s)", tc.name)
			}
		})
	}
}

// TestShippedSeaweedfsMasterUnitMountsS3Config keeps this guard attached to the
// deployment path: the shipped unit template must keep loading this config via
// -s3.config, otherwise the artifact above is not what deployments run.
func TestShippedSeaweedfsMasterUnitMountsS3Config(t *testing.T) {
	raw, err := os.ReadFile(shippedSeaweedfsMasterUnitPath)
	if err != nil {
		t.Fatalf("read %s: %v", shippedSeaweedfsMasterUnitPath, err)
	}
	unit := string(raw)
	if !strings.Contains(unit, "-s3.config=") {
		t.Fatalf("shipped unit template no longer mounts an -s3.config; update the shipped S3 config guard to the deployed identity path")
	}
	if !strings.Contains(unit, "seaweedfs-s3.json") {
		t.Fatalf("shipped unit template no longer references seaweedfs-s3.json; update the shipped S3 config guard to the deployed identity path")
	}
}

// ── Deployment-time identity wiring (r2 integration, D-MAILSERVER-DEPLOY-001) ──
//
// The shipped artifact fails closed above; the DEPLOYED runtime config is its
// inverse: the wizard HA path (configureSeaweedFS) and install.sh must deploy
// a generated admin identity through -s3.config, and the config-load path
// must reject well-known/empty-credential artifacts loud before a node can
// load them.

func TestGenerateSystemdUnit_MountsDeployedS3Config(t *testing.T) {
	unit := GenerateSystemdUnit(SeaweedFSNodeConfig{
		Peers:  []string{"node1:9333", "node2:9333", "node3:9333"},
		S3Port: 9000,
	})
	if !strings.Contains(unit, "-s3.config="+SeaweedfsS3ConfigPath) {
		t.Fatalf("wizard-generated unit no longer loads the deployed S3 identity config via -s3.config:\n%s", unit)
	}
	if !strings.Contains(unit, SeaweedfsS3ConfigPath) {
		t.Fatalf("unit does not reference the deployed identity path %s:\n%s", SeaweedfsS3ConfigPath, unit)
	}
}

func TestRenderSeaweedfsS3Config_GeneratedIdentityPassesDeploymentGate(t *testing.T) {
	raw, err := RenderSeaweedfsS3Config("ak-generated-32chars-hex", "sk-generated-48chars-hex-value")
	if err != nil {
		t.Fatalf("RenderSeaweedfsS3Config with generated material: %v", err)
	}
	if err := ValidateS3IdentitiesConfig([]byte(raw)); err != nil {
		t.Fatalf("rendered deployed config must pass the deployment gate: %v\n%s", err, raw)
	}
	var cfg deployedS3Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("rendered config is not JSON: %v", err)
	}
	if len(cfg.Identities) != 1 || cfg.Identities[0].Name != "admin" {
		t.Fatalf("rendered config must carry exactly the generated admin identity: %+v", cfg)
	}
	if len(cfg.Identities[0].Credentials) != 1 ||
		cfg.Identities[0].Credentials[0].AccessKey == "" ||
		cfg.Identities[0].Credentials[0].SecretKey == "" {
		t.Fatalf("generated admin identity must carry exactly one non-empty credential pair: %+v", cfg.Identities[0])
	}
}

func TestRenderSeaweedfsS3Config_RefusesEmptyMaterial(t *testing.T) {
	for _, tc := range []struct{ access, secret string }{
		{"", ""},
		{"access", ""},
		{"", "secret"},
		{"   ", "secret"},
	} {
		if raw, err := RenderSeaweedfsS3Config(tc.access, tc.secret); err == nil {
			t.Fatalf("render accepted empty credential material (%q, %q): %s", tc.access, tc.secret, raw)
		}
	}
}

func TestValidateS3IdentitiesConfig_RejectsDeploymentForbiddenStates(t *testing.T) {
	valid := func(body string) string {
		return fmt.Sprintf(`{"identities":[{"name":"admin","credentials":[%s],"actions":["Admin"]}]}`, body)
	}
	cases := []struct {
		name string
		raw  string
	}{
		{"vendor default minioadmin pair", valid(`{"accessKey":"minioadmin","secretKey":"minioadmin"}`)},
		{"minioadmin only in the secret", valid(`{"accessKey":"randomak","secretKey":"MINIOADMIN"}`)},
		{"empty access key", valid(`{"accessKey":"","secretKey":"somecret"}`)},
		{"empty secret key", valid(`{"accessKey":"someak","secretKey":""}`)},
		{"whitespace-only credential", valid(`{"accessKey":"  ","secretKey":"somecret"}`)},
		{"placeholder marker", valid(`{"accessKey":"<generated-at-install>","secretKey":"x"}`)},
		{"identity without credentials", `{"identities":[{"name":"admin","actions":["Admin"]}]}`},
		{"no identities", `{"identities": []}`},
		{"anonymous identity", `{"identities":[{"name":"anonymous","credentials":[{"accessKey":"a","secretKey":"b"}],"actions":["Read"]}]}`},
		{"empty name identity", `{"identities":[{"name":"","credentials":[{"accessKey":"a","secretKey":"b"}],"actions":["Read"]}]}`},
		{"identity without actions", `{"identities":[{"name":"admin","credentials":[{"accessKey":"a","secretKey":"b"}]}]}`},
		{"not JSON", "not json at all"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateS3IdentitiesConfig([]byte(tc.raw)); err == nil {
				t.Fatalf("deployment gate accepted a forbidden S3 identity config state (%s)", tc.name)
			}
		})
	}
}

// TestConfigureSeaweedFS_DeploysGatewayS3Identity drives the wizard's HA
// SeaweedFS step against the fake SSH peer and proves the deployed identity
// IS the gateway's configured S3 client pair (the credential-handoff lockstep,
// med-deploy-s3-credentials-b1r2-001): every node's command renders the config
// JSON carrying exactly that pair, mounts it via the unit's -s3.config, pins
// it root:mail 0640, and aborts before the restart on any failed install step.
// randomHex is pinned to the vendor-default marker: if the wizard still
// generated the identity per run, the rendered config would carry the marker
// and fail the deployment gate — the generator must be out of the identity
// path entirely.
func TestConfigureSeaweedFS_DeploysGatewayS3Identity(t *testing.T) {
	const (
		gatewayAccess = "gateway-access-key-fixture"
		gatewaySecret = "gateway-secret-key-fixture-48-chars-long!!"
	)
	restoreGatewayCreds := gatewayS3Credentials
	gatewayS3Credentials = func() (string, string, bool) { return gatewayAccess, gatewaySecret, true }
	t.Cleanup(func() { gatewayS3Credentials = restoreGatewayCreds })
	restoreRandomHex := randomHex
	randomHex = func(int) string { return "minioadmin" }
	t.Cleanup(func() { randomHex = restoreRandomHex })

	srv, addr, hostPub, clientPEM := newFakeSSHServerEcho(t, "ok\n")
	_ = srv
	w, _ := wizardWithPeerNodes(t, addr, clientPEM)
	w.hostKey = hostPub

	if err := w.configureSeaweedFS(context.Background()); err != nil {
		t.Fatalf("configureSeaweedFS: %v", err)
	}

	commands := srv.recorded()
	if len(commands) == 0 {
		t.Fatal("fake peer recorded no commands")
	}
	sawUnit := 0
	for _, cmd := range commands {
		// Assert only the per-node config+unit provisioning commands; the
		// post-deploy weed shell/curl commands are recorded too.
		if !strings.Contains(cmd, "cat > "+seaweedfsSystemdUnitPath) {
			continue
		}
		sawUnit++
		if !strings.Contains(cmd, SeaweedfsS3ConfigPath) {
			t.Errorf("seaweedfs deployment command missing the identity config path %s:\n%s", SeaweedfsS3ConfigPath, cmd)
		}
		if !strings.Contains(cmd, "-s3.config="+SeaweedfsS3ConfigPath) {
			t.Errorf("deployed unit does not load the identity config via -s3.config:\n%s", cmd)
		}
		if !strings.Contains(cmd, "chmod 0640") || !strings.Contains(cmd, "chown root:"+SeaweedfsS3ConfigGroup) {
			t.Errorf("deployed identity config is not pinned root:%s 0640:\n%s", SeaweedfsS3ConfigGroup, cmd)
		}
		// The GATEWAY's credential pair must reach the node's config — not a
		// per-run generated pair.
		if !strings.Contains(cmd, `"accessKey": "`+gatewayAccess+`"`) ||
			!strings.Contains(cmd, `"secretKey": "`+gatewaySecret+`"`) {
			t.Errorf("deployed config does not carry the gateway's configured credential pair:\n%s", cmd)
		}
		if strings.Contains(cmd, "minioadmin") {
			t.Errorf("deployed config carries a generated (pinned-to-marker) pair; the wizard must deploy the gateway's pair, not regenerate:\n%s", cmd)
		}
		// The rendered body must pass the deployment gate: cut the heredoc
		// body out of the command and validate it.
		body := extractHeredocBody(t, cmd, "<< 'ENDOFS3CONFIG'", "ENDOFS3CONFIG")
		if err := ValidateS3IdentitiesConfig([]byte(body)); err != nil {
			t.Errorf("deployed S3 config body fails the deployment gate: %v\n%s", err, body)
		}
		// Failure ordering: any failed install step must abort before the
		// restart of the unit that loads this config.
		if err := checkRemoteInstallFailureOrdering(cmd, "systemctl restart seaweedfs"); err != nil {
			t.Errorf("deployed install command violates the failure-ordering contract: %v\n%s", err, cmd)
		}
	}
	if sawUnit != 3 {
		t.Errorf("expected the unit+config step on all 3 nodes, saw %d", sawUnit)
	}
}

// TestConfigureSeaweedFS_ReusesGatewayIdentityAcrossRuns pins the reuse side
// of the credential handoff: re-running the deployment deploys the IDENTICAL
// gateway pair again — a wizard re-run must never rotate the S3 identity out
// from under an existing gateway (the r2 HOLD's server-only regeneration).
func TestConfigureSeaweedFS_ReusesGatewayIdentityAcrossRuns(t *testing.T) {
	const (
		gatewayAccess = "gateway-access-key-fixture"
		gatewaySecret = "gateway-secret-key-fixture-48-chars-long!!"
	)
	restoreGatewayCreds := gatewayS3Credentials
	gatewayS3Credentials = func() (string, string, bool) { return gatewayAccess, gatewaySecret, true }
	t.Cleanup(func() { gatewayS3Credentials = restoreGatewayCreds })

	srv, addr, hostPub, clientPEM := newFakeSSHServerEcho(t, "ok\n")
	_ = srv

	deployed := make([]string, 0, 2)
	for run := 1; run <= 2; run++ {
		before := len(srv.recorded()) // recorded() is cumulative across runs
		w, _ := wizardWithPeerNodes(t, addr, clientPEM)
		w.hostKey = hostPub
		if err := w.configureSeaweedFS(context.Background()); err != nil {
			t.Fatalf("configureSeaweedFS run %d: %v", run, err)
		}
		for _, cmd := range srv.recorded()[before:] {
			if !strings.Contains(cmd, "<< 'ENDOFS3CONFIG'") {
				continue
			}
			deployed = append(deployed, extractHeredocBody(t, cmd, "<< 'ENDOFS3CONFIG'", "ENDOFS3CONFIG"))
		}
	}
	if len(deployed) != 6 { // 3 nodes x 2 runs
		t.Fatalf("expected the identity config deployed on 3 nodes across 2 runs, saw %d", len(deployed))
	}
	for i, body := range deployed {
		if body != deployed[0] {
			t.Errorf("run %d deployed a DIFFERENT identity config than run 1 — a re-run must not rotate the gateway's S3 identity:\n--- first ---\n%s\n--- run %d ---\n%s", i/3+1, deployed[0], i/3+1, body)
		}
		if !strings.Contains(body, gatewayAccess) || !strings.Contains(body, gatewaySecret) {
			t.Errorf("deployed identity does not carry the gateway's pair:\n%s", body)
		}
	}
}

// TestConfigureSeaweedFS_RefusesWithoutGatewayCredentials: with the gateway
// carrying NO S3 client credentials there is no pair to keep in lockstep, and
// deploying a freshly generated node-only identity would strand the gateway
// (the exact r2 HOLD). The step must refuse before any node is contacted.
func TestConfigureSeaweedFS_RefusesWithoutGatewayCredentials(t *testing.T) {
	restoreGatewayCreds := gatewayS3Credentials
	gatewayS3Credentials = func() (string, string, bool) { return "", "", false }
	t.Cleanup(func() { gatewayS3Credentials = restoreGatewayCreds })

	srv, addr, hostPub, clientPEM := newFakeSSHServerEcho(t, "ok\n")
	_ = srv
	w, _ := wizardWithPeerNodes(t, addr, clientPEM)
	w.hostKey = hostPub

	err := w.configureSeaweedFS(context.Background())
	if err == nil {
		t.Fatal("configureSeaweedFS must refuse to deploy when the gateway has no S3 credentials configured")
	}
	if !strings.Contains(err.Error(), "S3_ACCESS_KEY") || !strings.Contains(err.Error(), "config.env") {
		t.Fatalf("refusal must name the gateway config surface, got: %v", err)
	}
	if recorded := srv.recorded(); len(recorded) != 0 {
		t.Fatalf("no node may be contacted when no gateway credential pair exists; recorded: %v", recorded)
	}
}

// TestConfigureSeaweedFS_S3IdentityFailureAbortsBeforeUpload pins the
// deployment-time rejection ordering: a gateway pair that is a well-known
// credential marker fails ValidateS3IdentitiesConfig and aborts the step
// BEFORE any node is contacted.
func TestConfigureSeaweedFS_S3IdentityFailureAbortsBeforeUpload(t *testing.T) {
	restoreGatewayCreds := gatewayS3Credentials
	gatewayS3Credentials = func() (string, string, bool) { return "minioadmin", "minioadmin", true }
	t.Cleanup(func() { gatewayS3Credentials = restoreGatewayCreds })

	srv, addr, hostPub, clientPEM := newFakeSSHServerEcho(t, "ok\n")
	_ = srv
	w, _ := wizardWithPeerNodes(t, addr, clientPEM)
	w.hostKey = hostPub

	err := w.configureSeaweedFS(context.Background())
	if err == nil {
		t.Fatal("configureSeaweedFS must fail loud when the gateway's pair is a well-known credential artifact")
	}
	if !strings.Contains(err.Error(), "minioadmin") {
		t.Fatalf("failure must name the rejected credential marker, got: %v", err)
	}
	if recorded := srv.recorded(); len(recorded) != 0 {
		t.Fatalf("no node may be contacted after the identity gate fails; recorded: %v", recorded)
	}
}

// TestSeaweedFSInstallCmd_FailureAbortsBeforeRestart executes the generated
// per-node provisioning command through a REAL local shell with the node tool
// namespace shimmed, proving the failure ordering by execution rather than
// string matching: an intermediate install failure must exit nonzero and the
// systemctl restart must never be recorded. (The pre-fix plain-newline
// command let a failed identity install be masked by a successful restart of
// a pre-existing unit.)
func TestSeaweedFSInstallCmd_FailureAbortsBeforeRestart(t *testing.T) {
	dir := t.TempDir()
	body, err := RenderSeaweedfsS3Config("ak-fixture-32-chars-long-hex-value!", "sk-fixture-48-chars-long-hex-value-for-tests!")
	if err != nil {
		t.Fatalf("render fixture config: %v", err)
	}
	cmd := buildSeaweedFSNodeInstallCmd(
		filepath.Join(dir, "seaweedfs-s3.json"),
		strings.TrimRight(body, "\n"),
		SeaweedfsS3ConfigGroup,
		filepath.Join(dir, "seaweedfs.service"),
		GenerateSystemdUnit(SeaweedFSNodeConfig{}),
	)

	// Happy path: every step succeeds, the restart runs, and the identity
	// config the unit loads was actually written by the same command.
	exitErr, calls := runRemoteInstallCmd(t, cmd, "", "")
	if exitErr != nil {
		t.Fatalf("clean environment: command failed: %v", exitErr)
	}
	if len(calls) != 3 || calls[0] != "daemon-reload" || calls[1] != "enable seaweedfs" || calls[2] != "restart seaweedfs" {
		t.Fatalf("clean environment systemctl calls = %v, want [daemon-reload enable seaweedfs restart seaweedfs]", calls)
	}
	written, err := os.ReadFile(filepath.Join(dir, "seaweedfs-s3.json"))
	if err != nil {
		t.Fatalf("identity config not written by the command: %v", err)
	}
	if !strings.Contains(string(written), "ak-fixture-32-chars-long-hex-value!") {
		t.Errorf("written identity config does not carry the fixture pair:\n%s", written)
	}

	// A failed chown (the 0640 root:mail pin) aborts before the restart: the
	// identity file would not be loadable by the mail user, so booting the
	// unit must never happen.
	exitErr, calls = runRemoteInstallCmd(t, cmd, "chown", "")
	if exitErr == nil {
		t.Fatal("failed chown must abort the install command")
	}
	if len(calls) != 0 {
		t.Fatalf("failed chown must abort BEFORE any systemctl call (restart masking), got %v", calls)
	}

	// A failed chmod likewise aborts before the restart.
	exitErr, calls = runRemoteInstallCmd(t, cmd, "chmod", "")
	if exitErr == nil || len(calls) != 0 {
		t.Fatalf("failed chmod must abort before the restart (err=%v, calls=%v)", exitErr, calls)
	}

	// A failed daemon-reload aborts before the restart too.
	exitErr, calls = runRemoteInstallCmd(t, cmd, "systemctl", "daemon-reload")
	if exitErr == nil {
		t.Fatal("failed daemon-reload must abort the install command")
	}
	if len(calls) != 1 || calls[0] != "daemon-reload" {
		t.Fatalf("failed daemon-reload must record only itself, got %v", calls)
	}
}

// ── Gateway credential RESOLUTION (r4 HOLD, med-deploy-s3-credentials-b1r2-001) ──
//
// The gateway resolves its S3 client pair through internal/config: a merge of
// defaults → SETJOIN_CONFIG YAML → environment, after which the legacy
// MINIO_* pair is consulted only when the merged value is empty (config.go).
// The pre-r4 wizard read the process environment alone, so with YAML pair A +
// legacy MINIO_* pair B + no S3_* env the gateway authenticated with A while
// the wizard deployed B — an incomplete handoff. The tests below pin the
// wizard's resolution to the gateway's own loader behavior and drive the
// exact mismatch scenario end to end through configureSeaweedFS.

// unsetEnvForTest unsets key for the duration of the test and restores its
// prior state at cleanup. t.Setenv can only set, never unset — and the merge
// scenarios require the ABSENCE of a variable, because an empty-but-present
// S3_* variable still overrides the YAML layer in the koanf env merge.
func unsetEnvForTest(t *testing.T, key string) {
	t.Helper()
	if old, had := os.LookupEnv(key); had {
		t.Cleanup(func() { _ = os.Setenv(key, old) })
	} else {
		t.Cleanup(func() { _ = os.Unsetenv(key) })
	}
	_ = os.Unsetenv(key)
}

// sandboxGatewayConfigEnv pins the base environment internal/config's loader
// validates (DB_DSN, JWT_SECRET, TLS_CERT+TLS_KEY — the loader refuses IMAP
// beyond loopback without both, the gateway's normal posture) and clears
// every other ambient variable its validation rules could trip over, so the
// gateway-side comparison in the tests below exercises the S3 merge contract
// only, independent of the host shell the suite runs in.
func sandboxGatewayConfigEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DB_DSN", "postgres://gateway-config-pinning-fixture/snap0")
	t.Setenv("JWT_SECRET", "gateway-config-pinning-jwt-secret-48-chars-long!!")
	t.Setenv("TLS_CERT", "/tmp/setjoin-test-cert.pem")
	t.Setenv("TLS_KEY", "/tmp/setjoin-test-key.pem")
	for _, key := range []string{
		"CRYPTO_ALGORITHM_PROFILE",
		"DB_ENCRYPTION_KEY",
		"SMTP_INBOUND_ADDR",
		"SMTP_SUBMISSION_ADDR",
		"IMAP_ADDR",
		"JWT_MAIL_ATTACHMENT_SECRET",
		"JWT_MAIL_ATTACHMENT_PREVIOUS_SECRET",
	} {
		unsetEnvForTest(t, key)
	}
}

// writeGatewayConfigYAML writes a SETJOIN_CONFIG fixture with the s3 access
// and/or secret key pinned, returning its path.
func writeGatewayConfigYAML(t *testing.T, access, secret string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := "s3:\n"
	if access != "" {
		body += "  access_key: " + access + "\n"
	}
	if secret != "" {
		body += "  secret_key: " + secret + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture yaml: %v", err)
	}
	return path
}

// TestResolveGatewayS3Credentials_MatchesGatewayConfigLoader pins the wizard's
// S3 credential resolution against the GATEWAY's own loader (internal/config
// Load → S3AccessKey/S3SecretKey) for every precedence combination of the
// three sources the merge contract defines: the SETJOIN_CONFIG YAML file, the
// S3_* environment pair, and the legacy MINIO_* pair (consulted only when the
// merged value is empty, per field). The first case is the r4 HOLD scenario:
// YAML A + legacy MINIO_* B + no S3_* env — the gateway authenticates with A,
// so that is exactly what the wizard must resolve (the pre-r4 env-only read
// deployed B).
func TestResolveGatewayS3Credentials_MatchesGatewayConfigLoader(t *testing.T) {
	const (
		yamlAccess  = "yaml-a-access-fixture"
		yamlSecret  = "yaml-a-secret-fixture-48-chars-long!!"
		minioAccess = "legacy-minio-b-access-fixture"
		minioSecret = "legacy-minio-b-secret-fixture-48-chars!!"
		envAccess   = "s3-env-access-fixture"
		envSecret   = "s3-env-secret-fixture-48-chars!!"
	)
	cases := []struct {
		name       string
		yaml       func(t *testing.T) string // nil = SETJOIN_CONFIG unset
		s3Set      bool
		s3Empty    bool // present but empty — still overrides the YAML layer
		minioSet   bool
		wantAccess string
		wantSecret string
	}{
		{
			name:       "yaml pair A over legacy MINIO pair B with no S3_* env (r4 HOLD scenario)",
			yaml:       func(t *testing.T) string { return writeGatewayConfigYAML(t, yamlAccess, yamlSecret) },
			minioSet:   true,
			wantAccess: yamlAccess,
			wantSecret: yamlSecret,
		},
		{
			name:       "S3_* env over YAML A and MINIO B",
			yaml:       func(t *testing.T) string { return writeGatewayConfigYAML(t, yamlAccess, yamlSecret) },
			s3Set:      true,
			minioSet:   true,
			wantAccess: envAccess,
			wantSecret: envSecret,
		},
		{
			name:       "S3_* env over MINIO B without a config file",
			s3Set:      true,
			minioSet:   true,
			wantAccess: envAccess,
			wantSecret: envSecret,
		},
		{
			name:       "legacy MINIO B fallback without YAML or S3_* env",
			minioSet:   true,
			wantAccess: minioAccess,
			wantSecret: minioSecret,
		},
		{
			name:       "YAML pair A alone",
			yaml:       func(t *testing.T) string { return writeGatewayConfigYAML(t, yamlAccess, yamlSecret) },
			wantAccess: yamlAccess,
			wantSecret: yamlSecret,
		},
		{
			name:       "per-field fallback: YAML access key with MINIO secret key",
			yaml:       func(t *testing.T) string { return writeGatewayConfigYAML(t, yamlAccess, "") },
			minioSet:   true,
			wantAccess: yamlAccess,
			wantSecret: minioSecret,
		},
		{
			name:       "empty-but-present S3_* env overrides YAML, then MINIO fallback",
			yaml:       func(t *testing.T) string { return writeGatewayConfigYAML(t, yamlAccess, yamlSecret) },
			s3Set:      true,
			s3Empty:    true,
			minioSet:   true,
			wantAccess: minioAccess,
			wantSecret: minioSecret,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			sandboxGatewayConfigEnv(t)
			if tc.yaml != nil {
				t.Setenv("SETJOIN_CONFIG", tc.yaml(t))
			} else {
				unsetEnvForTest(t, "SETJOIN_CONFIG")
			}
			if tc.s3Set {
				if tc.s3Empty {
					t.Setenv("S3_ACCESS_KEY", "")
					t.Setenv("S3_SECRET_KEY", "")
				} else {
					t.Setenv("S3_ACCESS_KEY", envAccess)
					t.Setenv("S3_SECRET_KEY", envSecret)
				}
			} else {
				unsetEnvForTest(t, "S3_ACCESS_KEY")
				unsetEnvForTest(t, "S3_SECRET_KEY")
			}
			if tc.minioSet {
				t.Setenv("MINIO_ACCESS_KEY", minioAccess)
				t.Setenv("MINIO_SECRET_KEY", minioSecret)
			} else {
				unsetEnvForTest(t, "MINIO_ACCESS_KEY")
				unsetEnvForTest(t, "MINIO_SECRET_KEY")
			}

			gotAccess, gotSecret := resolveGatewayS3Credentials()
			if gotAccess != tc.wantAccess || gotSecret != tc.wantSecret {
				t.Fatalf("wizard resolution = (%q, %q), want (%q, %q)", gotAccess, gotSecret, tc.wantAccess, tc.wantSecret)
			}

			// Pin against the gateway's own loader: the pair the gateway
			// authenticates with must be byte-identical to what the wizard
			// resolved, in the same environment.
			gatewayCfg, err := config.Load()
			if err != nil {
				t.Fatalf("gateway loader refused the same environment: %v", err)
			}
			if gatewayCfg.S3AccessKey != gotAccess || gatewayCfg.S3SecretKey != gotSecret {
				t.Fatalf("gateway resolved (%q, %q) but the wizard resolved (%q, %q) — the deployed pair would not be the pair the gateway authenticates with",
					gatewayCfg.S3AccessKey, gatewayCfg.S3SecretKey, gotAccess, gotSecret)
			}
		})
	}

	// Fail-consistency: a SETJOIN_CONFIG file the loader cannot read refuses
	// the gateway's own boot too, so the wizard must resolve NO pair (fail
	// closed) rather than fall back to ambient credential sources.
	t.Run("unreadable SETJOIN_CONFIG resolves no pair like the gateway loader", func(t *testing.T) {
		sandboxGatewayConfigEnv(t)
		t.Setenv("SETJOIN_CONFIG", filepath.Join(t.TempDir(), "does-not-exist.yaml"))
		gotAccess, gotSecret := resolveGatewayS3Credentials()
		if gotAccess != "" || gotSecret != "" {
			t.Fatalf("unresolvable gateway config must resolve no pair, got (%q, %q)", gotAccess, gotSecret)
		}
		if _, err := config.Load(); err == nil {
			t.Fatal("gateway loader unexpectedly accepted a missing config file; update the wizard's fail-closed expectation")
		}
	})
}

// TestConfigureSeaweedFS_DeploysResolvedGatewayPairOverLegacyMinioEnv drives
// the r4 HOLD scenario END TO END through the REAL credential resolution (no
// seam substitution — the seam-replacing tests above cannot detect the
// mismatch): the gateway's SETJOIN_CONFIG YAML pins pair A, the legacy
// MINIO_* environment pair is B, and no S3_* env exists. The gateway
// authenticates with A (its merged configuration keeps the YAML value over
// the MINIO_* fallback), so every node's deployed identity must carry
// exactly A — byte-identical to the gateway's resolved pair — never B.
func TestConfigureSeaweedFS_DeploysResolvedGatewayPairOverLegacyMinioEnv(t *testing.T) {
	const (
		yamlAccess  = "yaml-a-access-fixture"
		yamlSecret  = "yaml-a-secret-fixture-48-chars-long!!"
		minioAccess = "legacy-minio-b-access-fixture"
		minioSecret = "legacy-minio-b-secret-fixture-48-chars!!"
	)
	sandboxGatewayConfigEnv(t)
	unsetEnvForTest(t, "S3_ACCESS_KEY")
	unsetEnvForTest(t, "S3_SECRET_KEY")
	t.Setenv("MINIO_ACCESS_KEY", minioAccess)
	t.Setenv("MINIO_SECRET_KEY", minioSecret)
	t.Setenv("SETJOIN_CONFIG", writeGatewayConfigYAML(t, yamlAccess, yamlSecret))

	// The gateway side of the handoff, resolved through the gateway's own
	// loader in the same environment: the pair its blob client authenticates
	// with.
	gatewayCfg, err := config.Load()
	if err != nil {
		t.Fatalf("gateway loader refused the scenario environment: %v", err)
	}
	if gatewayCfg.S3AccessKey != yamlAccess || gatewayCfg.S3SecretKey != yamlSecret {
		t.Fatalf("fixture drift: gateway resolved (%q, %q), want the YAML pair", gatewayCfg.S3AccessKey, gatewayCfg.S3SecretKey)
	}

	srv, addr, hostPub, clientPEM := newFakeSSHServerEcho(t, "ok\n")
	_ = srv
	w, _ := wizardWithPeerNodes(t, addr, clientPEM)
	w.hostKey = hostPub

	if err := w.configureSeaweedFS(context.Background()); err != nil {
		t.Fatalf("configureSeaweedFS: %v", err)
	}

	sawIdentity := 0
	for _, cmd := range srv.recorded() {
		if !strings.Contains(cmd, "<< 'ENDOFS3CONFIG'") {
			continue
		}
		sawIdentity++
		body := extractHeredocBody(t, cmd, "<< 'ENDOFS3CONFIG'", "ENDOFS3CONFIG")
		var cfg deployedS3Config
		if err := json.Unmarshal([]byte(body), &cfg); err != nil {
			t.Fatalf("deployed config is not JSON: %v\n%s", err, body)
		}
		if len(cfg.Identities) != 1 || len(cfg.Identities[0].Credentials) != 1 {
			t.Fatalf("deployed config does not carry exactly one admin credential:\n%s", body)
		}
		cred := cfg.Identities[0].Credentials[0]
		// Byte-identical handoff: the deployed credential pair must equal the
		// pair the gateway's blob client authenticates with (the YAML pair),
		// not the legacy MINIO_* pair the pre-r4 env-only read deployed.
		if cred.AccessKey != gatewayCfg.S3AccessKey || cred.SecretKey != gatewayCfg.S3SecretKey {
			t.Fatalf("deployed credential pair (%q, %q) is not the gateway's resolved pair (%q, %q):\n%s",
				cred.AccessKey, cred.SecretKey, gatewayCfg.S3AccessKey, gatewayCfg.S3SecretKey, body)
		}
		if strings.Contains(body, minioAccess) || strings.Contains(body, minioSecret) {
			t.Fatalf("deployed config carries the legacy MINIO_* pair the gateway does not use:\n%s", body)
		}
		if err := ValidateS3IdentitiesConfig([]byte(body)); err != nil {
			t.Errorf("deployed S3 config body fails the deployment gate: %v\n%s", err, body)
		}
	}
	if sawIdentity != 3 {
		t.Errorf("expected the identity config deployed on all 3 nodes, saw %d", sawIdentity)
	}
}
