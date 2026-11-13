package deploy

// Secret-redaction and lifecycle tests for the deploy wizard status surface
// (D-MAILSERVER-INTERNAL-DEPLOY-R-001, package deploy-wizard-secret-echo).
//
// Covered contract:
//   - the status projection (StatusState) never renders SSH private-key bodies
//     or node passwords, even when NodeConfig holds them; inline-key input
//     stays supported and is marked has_inline_key with the body unrendered;
//   - raw remote output carrying key material never reaches step errors, log
//     lines, or persisted deployment_steps rows unredacted: sshRun snapshots
//     ALL wizard-held secrets (inline key bodies, node passwords) under the
//     lock and redacts them before truncation/return, so successful
//     verification output logged without failStep's scrub is clean too;
//   - the SSH ERROR text is scrubbed with the SAME COMPLETE secret set
//     (caller extras like the generated pgpool health-check password, inline
//     key bodies, node passwords): an exit-signal reason ("Reason was: ...")
//     is remote-controlled and can echo a caller extra back, and upstream
//     failStep knows only the node secrets (r2 HOLD, wizard.go);
//   - structural redaction runs BEFORE exact-secret replacement, and
//     overlapping exact secrets are replaced in one union-of-intervals pass;
//   - steps restored from persisted rows have their free-form Output/Error
//     WITHHELD (a pre-redaction row's bare secrets cannot be exact-matched at
//     restore — restart/status cannot disclose them), retaining step/status
//     metadata;
//   - the lifecycle matrix is characterized per case: Reset is invoked by BOTH
//     handler callers (StartDeploy and CancelDeploy, admin package), bare
//     request-context cancellation does NOT reset or halt the run (the run's
//     lifetime is owned by the wizard), and process restart clears in-memory
//     NodeConfig while persisted step rows survive — restored withheld, never
//     assumed gone.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"setjoin.com/shared/testsupport"
)

const (
	testInlineKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAAVkJcU2VjcmV0S2V5Qm9keQ==\n-----END OPENSSH PRIVATE KEY-----"
	testKeyPath   = "/etc/setjoin/deploy_ed25519"
	testNodePass  = "s3cret-node-password"
	testPgpPass   = "e2d1fa4c9b0a7d6e5c4b3a2918f0e1d2"
	// The gateway's configured S3 client pair (med-deploy-s3-credentials-b1r2-001):
	// the full-run tests point the gatewayS3Credentials env surface at it.
	testGatewayS3Access = "gateway-s3-access-fixture"
	testGatewayS3Secret = "gateway-s3-secret-fixture-48-chars-long!!"
)

// dirtyRemoteOutput is remote output that echoes secret material back: an
// inline private-key block, the generated pgpool health-check password inside
// an echoed heredoc, and an exact caller secret.
func dirtyRemoteOutput() string {
	return fmt.Sprintf("cat > /etc/pgpool2/pgpool.conf << 'ENDOFCONFIG'\n"+
		"health_check_password = '%s'\n"+
		"ENDOFCONFIG\n"+
		"%s\n"+
		"token=%s done", testPgpPass, testInlineKey, testNodePass)
}

// dirtyRestoreRowOutput is a pre-fix persisted row body: structural key
// material only. After a restart the wizard holds no node credentials
// (NodeConfig is never persisted), so even structural-only rows cannot be
// proven secret-free at restore time — the free-form body is withheld
// wholesale (see redactDeploymentStep), and the bare-password restore case is
// pinned by TestRestart_WithholdsLegacyBarePasswordRows.
func dirtyRestoreRowOutput() string {
	return fmt.Sprintf("cat > /etc/pgpool2/pgpool.conf << 'ENDOFCONFIG'\n"+
		"health_check_password = '%s'\n"+
		"ENDOFCONFIG\n%s", testPgpPass, testInlineKey)
}

func assertNoSecretMaterial(t *testing.T, surface, body string) {
	t.Helper()
	for _, secret := range []string{
		testInlineKey,
		"b3BlbnNzaC1rZXktdjEAAAAAVkJcU2VjcmV0S2V5Qm9keQ==",
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		testNodePass,
		testPgpPass,
	} {
		if strings.Contains(body, secret) {
			t.Errorf("%s: leaked secret material %q", surface, secret)
		}
	}
}

// assertNoSecretFragments fails when any fragment (>= 6 chars) of secret
// survives in body — the truncation-boundary check: redaction must run BEFORE
// truncation so a secret crossing the cut cannot survive as a fragment. Six
// chars is the floor where windows become distinctive ("pass" would false-positive
// on ordinary words like "passed" in wizard-generated log lines).
func assertNoSecretFragments(t *testing.T, surface, body, secret string) {
	t.Helper()
	const minFrag = 6
	for n := minFrag; n <= len(secret); n++ {
		for i := 0; i+n <= len(secret); i++ {
			if strings.Contains(body, secret[i:i+n]) {
				t.Errorf("%s: leaked fragment %q of secret %q", surface, secret[i:i+n], secret)
				return
			}
		}
	}
}

// assertNoStructuralKeyMaterial checks the restore-time envelope: PEM key
// blocks and pgpool health-check password lines must never survive.
func assertNoStructuralKeyMaterial(t *testing.T, surface, body string) {
	t.Helper()
	for _, secret := range []string{
		testInlineKey,
		"b3BlbnNzaC1rZXktdjEAAAAAVkJcU2VjcmV0S2V5Qm9keQ==",
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		testPgpPass,
	} {
		if strings.Contains(body, secret) {
			t.Errorf("%s: leaked secret material %q", surface, secret)
		}
	}
}

// ── RedactOutput (the sshRun choke point) ───────────────────────────────────

func TestRedactOutput_ScrubsKeyMaterialAndExtraSecrets(t *testing.T) {
	out := RedactOutput(dirtyRemoteOutput(), testPgpPass)
	// testPgpPass is passed as an exact caller secret and must be scrubbed
	// everywhere it occurs, including outside the pgpool line structure.
	assertNoStructuralKeyMaterial(t, "RedactOutput", out)
	if !strings.Contains(out, "[REDACTED]") {
		t.Errorf("expected [REDACTED] sentinel in %q", out)
	}
	// Structure around the scrubbed pgpool password is preserved.
	if !strings.Contains(out, "health_check_password = '[REDACTED]'") {
		t.Errorf("expected pgpool password line scrubbed in place, got %q", out)
	}
	// The node password is NOT passed here: exact caller-secret scrubbing is
	// the caller's contract (the wizard-known-secret carriers are pinned by
	// TestFailStep_* and TestPersistStep_*).
	if !strings.Contains(out, testNodePass) {
		t.Errorf("unexpected scrub of a secret the caller did not pass: %q", out)
	}
}

func TestRedactOutput_BoundsRetainedOutput(t *testing.T) {
	long := strings.Repeat("x", maxRedactedOutput+1000)
	got := RedactOutput(long)
	if len(got) > maxRedactedOutput+len("\n...[truncated]") {
		t.Errorf("redacted output not bounded: %d bytes", len(got))
	}
}

func TestRedactOutput_UnterminatedKeyBlock(t *testing.T) {
	// A remote host that dies mid-echo must not leave a partial key body.
	out := RedactOutput("prefix -----BEGIN RSA PRIVATE KEY-----\nMIImidblockdata")
	if strings.Contains(out, "MIImidblockdata") {
		t.Errorf("unterminated key block body survived: %q", out)
	}
}

// TestRedactOutput_StructuralRedactionPrecedesExactReplacement is the
// delimiter-destruction regression: with exact replacement applied first, an
// extra secret equal to "PRIVATE" rewrites the PEM header so
// privateKeyBlockRe no longer matches and the whole key body survives. The
// structural pass must run first.
func TestRedactOutput_StructuralRedactionPrecedesExactReplacement(t *testing.T) {
	pemKey := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAAVkJcU2VjcmV0S2V5Qm9keQ==\n-----END OPENSSH PRIVATE KEY-----"
	out := RedactOutput("host echoed: "+pemKey+" end", "PRIVATE")
	if strings.Contains(out, "-----BEGIN") ||
		strings.Contains(out, "PRIVATE KEY") ||
		strings.Contains(out, "b3BlbnNzaC1rZXktdjEAAAAAVkJcU2VjcmV0S2V5Qm9keQ==") {
		t.Errorf("exact secret %q destroyed PEM delimiters; key block survived: %q", "PRIVATE", out)
	}
	if !strings.Contains(out, redactionSentinel) {
		t.Errorf("expected %s sentinel in %q", redactionSentinel, out)
	}
}

// TestRedactOutput_OverlappingExactSecretsLeaveNoSuffixes: overlapping exact
// secrets are replaced in a single longest-first pass. Sequential
// replacement lets a shorter secret fire first and fragment a longer one,
// leaving recognizable suffixes behind.
func TestRedactOutput_OverlappingExactSecretsLeaveNoSuffixes(t *testing.T) {
	out := RedactOutput("token=SECRETKEYVALUE tail", "SECRET", "KEYVALUE", "SECRETKEYVALUE")
	if strings.Count(out, redactionSentinel) != 1 {
		t.Errorf("want exactly one sentinel for one overlapping match region, got %d in %q", strings.Count(out, redactionSentinel), out)
	}
	for _, frag := range []string{"SECRET", "KEYVALUE"} {
		if strings.Contains(out, frag) {
			t.Errorf("overlapping secret fragment %q survived: %q", frag, out)
		}
	}
	// A secret equal to a prefix of the output text with a longer secret
	// overlapping it must not leave the shorter secret's tail region intact.
	out = RedactOutput("aSECRETKEYVALUEb", "SECRET", "SECRETKEY")
	if strings.Contains(out, "SECRET") || strings.Contains(out, "ETKEY") {
		t.Errorf("overlap left a suffix behind: %q", out)
	}
	// Empty secrets are skipped, not matched everywhere.
	if got := RedactOutput("unchanged", ""); got != "unchanged" {
		t.Errorf("empty extra secret mutated output: %q", got)
	}
}

// TestRedactOutput_SecretStraddlingTruncationBoundary: redaction happens
// BEFORE truncation, so a secret crossing the cut cannot survive as a
// fragment (the sentinel text itself may be cut — that is harmless).
func TestRedactOutput_SecretStraddlingTruncationBoundary(t *testing.T) {
	out := RedactOutput(strings.Repeat("x", maxRedactedOutput-6)+testNodePass+" tail after the boundary", testNodePass)
	assertNoSecretFragments(t, "truncation-boundary output", out, testNodePass)
	if !strings.HasSuffix(out, "\n...[truncated]") {
		t.Errorf("output not truncated: %q", out)
	}
}

// ── StatusState projection (the /admin/deploy/status body) ──────────────────

func TestStatusState_NoSecretMaterialEvenWhenNodeConfigHoldsIt(t *testing.T) {
	w := NewWizardWithState(&DeploymentState{
		Profile: Profile3Node,
		Nodes: []NodeConfig{
			{Host: "10.0.0.11", Role: "primary", SSHUser: "root", SSHKey: testInlineKey, Password: testNodePass},
			{Host: "10.0.0.12", Role: "standby", SSHUser: "root", SSHKey: testKeyPath, Password: testNodePass},
		},
		Steps:     []DeploymentStep{{Name: "ssh_check", Status: "ok"}},
		Status:    "deploying",
		StartedAt: time.Now(),
	})
	body, err := json.Marshal(w.StatusState())
	if err != nil {
		t.Fatalf("marshal StatusState: %v", err)
	}
	assertNoSecretMaterial(t, "StatusState JSON", string(body))
	// The secret-bearing fields must not exist on the projection at all.
	if strings.Contains(string(body), `"ssh_key"`) || strings.Contains(string(body), `"password"`) {
		t.Errorf("projection serializes secret-bearing fields: %s", body)
	}
}

func TestStatusState_InlineKeyMarkedUnrenderedPathKeyRenderedAsPath(t *testing.T) {
	w := NewWizardWithState(&DeploymentState{
		Nodes: []NodeConfig{
			{Host: "10.0.0.11", Role: "primary", SSHUser: "root", SSHKey: testInlineKey, Password: testNodePass},
			{Host: "10.0.0.12", Role: "standby", SSHUser: "root", SSHKey: testKeyPath, Password: testNodePass},
		},
		Status: "config",
	})
	st := w.StatusState()
	if len(st.Nodes) != 2 {
		t.Fatalf("expected 2 projected nodes, got %d", len(st.Nodes))
	}
	inline, path := st.Nodes[0], st.Nodes[1]
	if !inline.HasInlineKey || inline.KeyPath != "" {
		t.Errorf("inline-key node: want HasInlineKey=true and empty KeyPath, got %+v", inline)
	}
	if path.HasInlineKey || path.KeyPath != testKeyPath {
		t.Errorf("path-key node: want KeyPath=%q and HasInlineKey=false, got %+v", testKeyPath, path)
	}
	if path.Host != "10.0.0.12" || path.SSHUser != "root" {
		t.Errorf("path-key node lost non-secret fields: %+v", path)
	}
}

// ── Inline-key input stays supported ────────────────────────────────────────

func TestInlineKeyInput_Supported(t *testing.T) {
	if !isInlineKeyMaterial(testInlineKey) {
		t.Fatal("inline PEM key not recognized as inline material")
	}
	if isInlineKeyMaterial(testKeyPath) {
		t.Fatal("key path misclassified as inline material")
	}
	key, err := readPrivateKey(testInlineKey)
	if err != nil {
		t.Fatalf("readPrivateKey(inline): %v", err)
	}
	if string(key) != testInlineKey {
		t.Error("readPrivateKey did not return the inline key body verbatim")
	}
}

// ── Error/log/persistence carriers ──────────────────────────────────────────

func TestFailStep_RedactsKeyMaterialFromStepErrorAndLog(t *testing.T) {
	w := &Wizard{state: &DeploymentState{
		// Production shape: during a run the wizard holds the node credentials
		// it deployed with, so failStep must scrub them from every carrier.
		Nodes: []NodeConfig{
			{Host: "10.0.0.11", Role: "primary", SSHUser: "root", SSHKey: testInlineKey, Password: testNodePass},
		},
		Steps: make([]DeploymentStep, 0),
	}}
	w.logStep("verify", "Verify cluster health")
	w.failStep("verify", fmt.Errorf("verify replication on primary 10.0.0.11: exit 1 — output: %s", dirtyRemoteOutput()))

	var failed *DeploymentStep
	for i := range w.state.Steps {
		if w.state.Steps[i].Name == "verify" {
			failed = &w.state.Steps[i]
		}
	}
	if failed == nil || failed.Status != "failed" {
		t.Fatalf("verify step not marked failed: %+v", w.state.Steps)
	}
	assertNoSecretMaterial(t, "step.Error", failed.Error)
	if len(w.state.Log) == 0 {
		t.Fatal("no log line recorded")
	}
	assertNoSecretMaterial(t, "state.Log", w.state.Log[len(w.state.Log)-1])
}

func TestRedactDeploymentStep_ScrubsOutputAndError(t *testing.T) {
	got := redactDeploymentStep(DeploymentStep{
		Name: "configure_pgpool", Status: "failed",
		Output: dirtyRestoreRowOutput(),
		Error:  "pgpool config upload: exit 1 (output: " + dirtyRestoreRowOutput() + ")",
	})
	// Restored free-form bodies are WITHHELD entirely, not merely structurally
	// scrubbed: at restore the wizard holds no node credentials, so bare
	// secrets in pre-redaction rows cannot be exact-matched. Step/status
	// metadata is retained.
	if got.Output != withheldRestoreNote {
		t.Errorf("restored Output = %q, want withheld note %q", got.Output, withheldRestoreNote)
	}
	if got.Error != withheldRestoreNote {
		t.Errorf("restored Error = %q, want withheld note %q", got.Error, withheldRestoreNote)
	}
	if got.Name != "configure_pgpool" || got.Status != "failed" {
		t.Errorf("restore must retain step/status metadata, got name=%q status=%q", got.Name, got.Status)
	}
	assertNoStructuralKeyMaterial(t, "step.Output", got.Output)
	assertNoStructuralKeyMaterial(t, "step.Error", got.Error)
}

// TestPersistStep_ScrubsSecretMaterialInPersistedRow is the real-persistence
// leg of "persisted deployment steps are scrubbed": the row written to
// deployment_steps carries no secret material — neither structurally
// patterned key material nor the node credentials the wizard holds — even
// when the caller passes a step whose Output/Error hold them. Requires
// DB_DSN (skips otherwise, fail-closed in CI via REQUIRE_DB).
func TestPersistStep_ScrubsSecretMaterialInPersistedRow(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	const stepName = "sec_probe_step"
	cleanup := func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM deployment_steps WHERE step_name = $1`, stepName)
	}
	cleanup()
	t.Cleanup(cleanup)

	w := &Wizard{pool: pool, logger: slog.Default(), state: &DeploymentState{
		Nodes: []NodeConfig{
			{Host: "10.0.0.11", Role: "primary", SSHUser: "root", SSHKey: testInlineKey, Password: testNodePass},
		},
		Steps: make([]DeploymentStep, 0),
	}}
	w.persistStep(context.Background(), DeploymentStep{
		Name: stepName, Status: "failed",
		Output: dirtyRemoteOutput(),
		Error:  "pgpool config upload to 10.0.0.11: exit 1 (output: " + dirtyRemoteOutput() + ")",
	})

	var output, storedErr string
	if err := pool.QueryRow(context.Background(),
		`SELECT COALESCE(output,''), COALESCE(error,'') FROM deployment_steps WHERE step_name = $1`, stepName,
	).Scan(&output, &storedErr); err != nil {
		t.Fatalf("persisted row missing: %v", err)
	}
	assertNoSecretMaterial(t, "persisted output", output)
	assertNoSecretMaterial(t, "persisted error", storedErr)
}

// TestRestart_RestoresScrubbedStepsWithoutNodeConfig characterizes the restart
// case: in-memory NodeConfig (inline keys, passwords) is never persisted, so a
// fresh wizard holds no node material, while previously persisted step rows DO
// survive and are restored — their free-form bodies WITHHELD (unverifiable at
// restore), so pre-fix dirty rows cannot re-expose secrets on the read
// surface. Requires DB_DSN (skips otherwise).
func TestRestart_RestoresScrubbedStepsWithoutNodeConfig(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	const stepName = "sec_restore_probe"
	cleanup := func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM deployment_steps WHERE step_name = $1`, stepName)
	}
	cleanup()
	t.Cleanup(cleanup)
	// Seed a PRE-FIX row whose error still carries raw key material.
	dirty := "start services on 10.0.0.11: exit 1\n" + dirtyRestoreRowOutput()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO deployment_steps (step_name, status, output, error, started_at)
		 VALUES ($1, 'failed', $2, $2, now())`, stepName, dirty); err != nil {
		t.Fatalf("seed dirty row: %v", err)
	}

	w := NewWizard(pool, slog.Default())
	st := w.StatusState()
	if len(st.Nodes) != 0 {
		t.Errorf("restart must not restore in-memory NodeConfig, got %+v", st.Nodes)
	}
	var restored *DeploymentStep
	for i := range w.state.Steps {
		if w.state.Steps[i].Name == stepName {
			restored = &w.state.Steps[i]
		}
	}
	if restored == nil {
		t.Fatal("persisted step row was not restored on restart")
	}
	assertNoStructuralKeyMaterial(t, "restored step output", restored.Output)
	assertNoStructuralKeyMaterial(t, "restored step error", restored.Error)
	if st.Status != "resumed" {
		t.Errorf("expected resumed status after restoring steps, got %q", st.Status)
	}
}

// TestRestart_WithholdsLegacyBarePasswordRows is the DB-seeded
// legacy-password proof: a row written before redaction landed carrying ONLY a
// bare node password (no structural pattern to scrub) must not be disclosed
// after a restart — the wizard holds no node credentials at restore, so the
// free-form body cannot be exact-matched and is withheld, with step/status
// metadata retained. Requires DB_DSN (skips otherwise).
func TestRestart_WithholdsLegacyBarePasswordRows(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	const stepName = "sec_legacy_bare_pass"
	cleanup := func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM deployment_steps WHERE step_name = $1`, stepName)
	}
	cleanup()
	t.Cleanup(cleanup)
	// Seed a PRE-FIX row whose body carries only a bare password.
	dirty := "start services on 10.0.0.11: exit 1\nnode auth rejected password " + testNodePass
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO deployment_steps (step_name, status, output, error, started_at)
		 VALUES ($1, 'failed', $2, $2, now())`, stepName, dirty); err != nil {
		t.Fatalf("seed legacy bare-password row: %v", err)
	}

	// Restart: NewWizard restores from the table.
	w := NewWizard(pool, slog.Default())
	st := w.StatusState()
	var restored *DeploymentStep
	for i := range w.state.Steps {
		if w.state.Steps[i].Name == stepName {
			restored = &w.state.Steps[i]
		}
	}
	if restored == nil {
		t.Fatal("persisted step row was not restored on restart")
	}
	// Step/status metadata is retained...
	if restored.Status != "failed" {
		t.Errorf("restored step status = %q, want failed (metadata retained)", restored.Status)
	}
	// ...but the unverifiable free-form body is withheld: restart/status
	// cannot disclose the bare password.
	if restored.Output != withheldRestoreNote {
		t.Errorf("restored Output = %q, want withheld note %q", restored.Output, withheldRestoreNote)
	}
	if restored.Error != withheldRestoreNote {
		t.Errorf("restored Error = %q, want withheld note %q", restored.Error, withheldRestoreNote)
	}
	body, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal StatusState: %v", err)
	}
	assertNoSecretMaterial(t, "StatusState JSON after restart", string(body))
}

// ── sshRun: all wizard-held secrets redacted at the choke point ─────────────

// boundaryEchoOutput is remote output whose bare node password straddles the
// truncation boundary: redaction must run before truncation so no fragment
// survives the cut.
func boundaryEchoOutput() string {
	return strings.Repeat("x", maxRedactedOutput-6) + testNodePass + "\n# tail after the truncation boundary"
}

// wizardWithPeerNodes returns a wizard holding node credentials for the fake
// peer (inline key body + bare node passwords) and a logger capturing every
// record — the wizard.go verification-output log lines have no failStep
// scrub, so the captured log is the assertion surface.
func wizardWithPeerNodes(t *testing.T, addr, clientPEM string) (*Wizard, *bytes.Buffer) {
	t.Helper()
	var logBuf bytes.Buffer
	w := NewWizardWithState(&DeploymentState{
		Profile: Profile3Node,
		Nodes: []NodeConfig{
			{Host: addr, Role: "primary", SSHUser: "root", SSHKey: clientPEM, Password: testNodePass},
			{Host: addr, Role: "standby", SSHUser: "root", SSHKey: clientPEM, Password: testNodePass},
			{Host: addr, Role: "standby", SSHUser: "root", SSHKey: clientPEM, Password: testNodePass},
		},
		Steps: make([]DeploymentStep, 0),
	})
	w.logger = slog.New(slog.NewTextHandler(&logBuf, nil))
	return w, &logBuf
}

// TestSSHRun_RedactsNodePasswordsInReturnedOutput: a bare node password echoed
// back in successful remote output must not survive sshRun's return value —
// including when it straddles the truncation boundary (the [REDACTED] sentinel
// itself may be cut; the secret must not).
func TestSSHRun_RedactsNodePasswordsInReturnedOutput(t *testing.T) {
	// Boundary-straddling echo: the password crosses the truncation cut.
	srv, addr, hostPub, clientPEM := newFakeSSHServerEcho(t, boundaryEchoOutput())
	_ = srv // peer held only via t.Cleanup; addr and keys carry the assertions
	w, _ := wizardWithPeerNodes(t, addr, clientPEM)
	w.hostKey = hostPub

	out, err := w.sshRun(context.Background(), addr, "root", clientPEM, "echo ok")
	if err != nil {
		t.Fatalf("sshRun: %v", err)
	}
	assertNoSecretMaterial(t, "sshRun returned output", out)
	assertNoSecretFragments(t, "sshRun returned output", out, testNodePass)
	if !strings.HasSuffix(out, "\n...[truncated]") {
		t.Errorf("returned output not truncated: %q", out)
	}

	// Mid-stream echo: the replacement sentinel must be visible in the
	// returned output.
	srv2, addr2, hostPub2, clientPEM2 := newFakeSSHServerEcho(t, "prefix "+testNodePass+" suffix\n")
	_ = srv2
	w2, _ := wizardWithPeerNodes(t, addr2, clientPEM2)
	w2.hostKey = hostPub2

	out2, err := w2.sshRun(context.Background(), addr2, "root", clientPEM2, "echo ok")
	if err != nil {
		t.Fatalf("sshRun (mid-stream): %v", err)
	}
	assertNoSecretMaterial(t, "sshRun mid-stream output", out2)
	if !strings.Contains(out2, redactionSentinel) {
		t.Errorf("expected %s sentinel in returned output %q", redactionSentinel, out2)
	}
}

// TestVerificationLog_RedactsNodePasswords drives a full deployment (all steps
// succeed against the echoing peer) whose verification output is logged at
// wizard.go's verifyCluster WITHOUT failStep's additional scrub: every log
// record and every in-memory step/log surface must be free of the node
// passwords the wizard holds. The gateway's S3 credential pair is configured
// (the deployment contract: configureSeaweedFS deploys the gateway's pair),
// so the run reaches the SeaweedFS step and completes.
func TestVerificationLog_RedactsNodePasswords(t *testing.T) {
	srv, addr, hostPub, clientPEM := newFakeSSHServerEcho(t, boundaryEchoOutput())
	_ = srv // peer held only via t.Cleanup; addr and keys carry the assertions
	t.Setenv(seaweedfsChecksumEnv, strings.Repeat("ab", 32))
	t.Setenv("S3_ACCESS_KEY", testGatewayS3Access)
	t.Setenv("S3_SECRET_KEY", testGatewayS3Secret)
	w, logBuf := wizardWithPeerNodes(t, addr, clientPEM)
	w.hostKey = hostPub

	if err := w.Begin(context.Background(), w.State().Nodes); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if status := waitForTerminalStatus(t, w); status != "done" {
		t.Fatalf("run status = %q, want done", status)
	}
	waitDrained(t, w)

	assertNoSecretMaterial(t, "captured deploy logs", logBuf.String())
	assertNoSecretFragments(t, "captured deploy logs", logBuf.String(), testNodePass)
	st := w.StatusState()
	stepsJSON, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	assertNoSecretMaterial(t, "status steps JSON", string(stepsJSON))
	for _, line := range st.Log {
		assertNoSecretMaterial(t, "state.Log", line)
	}
}

// ── sshRun: the SSH error text is scrubbed with the SAME COMPLETE secret set ──

// TestSSHRun_ScrubsExitSignalReasonInReturnedError is the r2 P1 regression at
// the choke point: an SSH exit-signal reason is remote-controlled text that
// can carry a secret the target host has seen (e.g. the generated pgpool
// health-check password echoed back in the dying process's output). The
// password is a CALLER extra here — failStep only knows the node secrets — so
// sshRun itself must scrub the error before it leaves the SSH layer, while
// retaining the non-secret verdict context.
func TestSSHRun_ScrubsExitSignalReasonInReturnedError(t *testing.T) {
	srv, addr, hostPub, clientPEM := newFakeSSHServerExitSignal(t, "ENDOFCONFIG", "health check failed: "+testPgpPass)
	_ = srv // peer held only via t.Cleanup; addr and keys carry the assertions
	w, _ := wizardWithPeerNodes(t, addr, clientPEM)
	w.hostKey = hostPub

	out, err := w.sshRun(context.Background(), addr, "root", clientPEM,
		"cat > /etc/pgpool2/pgpool.conf << 'ENDOFCONFIG'\nhealth_check_password = 'x'\nENDOFCONFIG",
		testPgpPass)
	if err == nil {
		t.Fatal("exit-signaled command: want error, got nil")
	}
	assertNoSecretMaterial(t, "sshRun error", err.Error())
	assertNoSecretFragments(t, "sshRun error", err.Error(), testPgpPass)
	assertNoSecretFragments(t, "sshRun error", err.Error(), testNodePass)
	// The non-secret verdict context survives the scrub (signal name/status),
	// proving the signal path (not a fabricated error) produced it.
	if !strings.Contains(err.Error(), "signal") {
		t.Errorf("expected the remote signal verdict to survive scrubbing, got %q", err)
	}
	assertNoSecretMaterial(t, "sshRun returned output", out)
}

// exitSignalScrubTestWizard builds the run-level exit-signal fixture: the
// generated pgpool health-check password is pinned to testPgpPass (randomHex
// var seam) so the fake peer's remote-controlled exit-signal reason echoes
// back EXACTLY the caller extra configurePgpool hands to sshRun — the real
// leak shape, since failStep and persistStep know only the node secrets.
func exitSignalScrubTestWizard(t *testing.T, addr, clientPEM string, hostPub ssh.PublicKey) (*Wizard, *bytes.Buffer) {
	t.Helper()
	restoreRandomHex := randomHex
	randomHex = func(int) string { return testPgpPass }
	t.Cleanup(func() { randomHex = restoreRandomHex })

	t.Setenv(seaweedfsChecksumEnv, strings.Repeat("ab", 32))
	w, logBuf := wizardWithPeerNodes(t, addr, clientPEM)
	w.hostKey = hostPub
	return w, logBuf
}

// TestExitSignalReason_ScrubbedThroughRunStatus drives a full deployment whose
// pgpool step is terminated by an exit-signal whose reason text carries the
// generated pgpool password: the failure flows through failStep (which knows
// only node secrets) into the in-memory steps, the state log, and the status
// JSON — none of which may retain the caller extra.
func TestExitSignalReason_ScrubbedThroughRunStatus(t *testing.T) {
	srv, addr, hostPub, clientPEM := newFakeSSHServerExitSignal(t, "ENDOFCONFIG", "health check failed: "+testPgpPass)
	_ = srv // peer held only via t.Cleanup; addr and keys carry the assertions
	w, logBuf := exitSignalScrubTestWizard(t, addr, clientPEM, hostPub)

	if err := w.Begin(context.Background(), w.State().Nodes); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if status := waitForTerminalStatus(t, w); status != "failed" {
		t.Fatalf("run status = %q, want failed at the pgpool exit-signal", status)
	}
	waitDrained(t, w)

	var pgpool *DeploymentStep
	for i := range w.state.Steps {
		if w.state.Steps[i].Name == "configure_pgpool" {
			pgpool = &w.state.Steps[i]
		}
	}
	if pgpool == nil || pgpool.Status != "failed" {
		t.Fatalf("configure_pgpool step not failed: %+v", w.state.Steps)
	}
	assertNoSecretMaterial(t, "configure_pgpool step error", pgpool.Error)
	assertNoSecretFragments(t, "configure_pgpool step error", pgpool.Error, testPgpPass)
	if !strings.Contains(pgpool.Error, "signal") {
		t.Errorf("expected the remote signal verdict in the step error, got %q", pgpool.Error)
	}
	assertNoSecretMaterial(t, "captured deploy logs", logBuf.String())
	body, err := json.Marshal(w.StatusState())
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	assertNoSecretMaterial(t, "status JSON after exit-signal failure", string(body))
	for _, line := range w.StatusState().Log {
		assertNoSecretMaterial(t, "state.Log", line)
	}
}

// TestExitSignalReason_ScrubbedInPersistedRow is the DB leg of the same run:
// the persisted deployment_steps row for the exit-signaled pgpool step must be
// free of the caller extra, since persistStep cannot exact-match it (the
// generated password is not a wizard-held node secret). Requires DB_DSN
// (skips otherwise, fail-closed in CI via REQUIRE_DB).
func TestExitSignalReason_ScrubbedInPersistedRow(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	stepNames := []string{"ssh_check", "install_packages", "configure_replication", "configure_pgpool"}
	cleanup := func() {
		for _, name := range stepNames {
			_, _ = pool.Exec(context.Background(), `DELETE FROM deployment_steps WHERE step_name = $1`, name)
		}
	}
	cleanup()
	t.Cleanup(cleanup)

	srv, addr, hostPub, clientPEM := newFakeSSHServerExitSignal(t, "ENDOFCONFIG", "health check failed: "+testPgpPass)
	_ = srv // peer held only via t.Cleanup; addr and keys carry the assertions
	w, _ := exitSignalScrubTestWizard(t, addr, clientPEM, hostPub)
	w.pool = pool

	if err := w.Begin(context.Background(), w.State().Nodes); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if status := waitForTerminalStatus(t, w); status != "failed" {
		t.Fatalf("run status = %q, want failed at the pgpool exit-signal", status)
	}
	waitDrained(t, w)

	var output, storedErr string
	if err := pool.QueryRow(context.Background(),
		`SELECT COALESCE(output,''), COALESCE(error,'') FROM deployment_steps WHERE step_name = 'configure_pgpool'`,
	).Scan(&output, &storedErr); err != nil {
		t.Fatalf("persisted configure_pgpool row missing: %v", err)
	}
	assertNoSecretMaterial(t, "persisted output", output)
	assertNoSecretMaterial(t, "persisted error", storedErr)
	assertNoSecretFragments(t, "persisted error", storedErr, testPgpPass)
	assertNoSecretFragments(t, "persisted error", storedErr, testNodePass)
}

// ── lifecycle matrix ────────────────────────────────────────────────────────

// TestLifecycle_ResetCancelContextRestartMatrix pins the four-case lifecycle:
//
//  1. Reset — invoked by BOTH API callers: StartDeploy (admin_deploy.go
//     calls h.wizard.Reset() before Begin) and CancelDeploy (calls
//     h.wizard.Reset()). Both replace the shared state; node secrets vanish.
//  2. Bare request-context cancellation — does NOT reset state and does NOT
//     halt the local deployment goroutine (sshRun does not consume its ctx):
//     the run below completes on its own and the state stays well-formed.
//  3. Process termination/restart — ends the local goroutine and drops
//     in-memory NodeConfig; persisted step rows survive and are restored
//     scrubbed (TestRestart_RestoresScrubbedStepsWithoutNodeConfig).
//  4. Already-issued remote actions — outcomes are NOT rolled back by any of
//     the above; they must be characterized/reconciled on the target hosts.
//     This case needs a live SSH peer and is deliberately not asserted here.
func TestLifecycle_ResetCancelContextRestartMatrix(t *testing.T) {
	t.Run("StartDeploy_Reset_replaces_state", func(t *testing.T) {
		w := seededWizardWithSecrets(t)
		w.Reset() // StartDeploy path: Reset before Begin
		assertStateCleared(t, w.StatusState())
	})
	t.Run("CancelDeploy_Reset_replaces_state", func(t *testing.T) {
		w := seededWizardWithSecrets(t)
		w.Reset() // CancelDeploy path
		assertStateCleared(t, w.StatusState())
	})
	t.Run("request_context_cancellation_does_not_reset_or_halt", func(t *testing.T) {
		// The run's lifetime is owned by the wizard (context.WithoutCancel):
		// a bare request-context cancellation neither resets state nor halts
		// the local deployment goroutine. Only Reset (the CancelDeploy path)
		// or Close cancels a run; the run below completes on its own and the
		// state stays well-formed.
		w := &Wizard{state: &DeploymentState{Steps: make([]DeploymentStep, 0)}}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := w.Begin(ctx, nil); err != nil { // zero nodes: no network egress
			t.Fatalf("Begin: %v", err)
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			st := w.StatusState()
			if st.Status == "failed" { // verifyCluster fails on zero nodes
				if len(st.Nodes) != 0 {
					t.Errorf("unexpected nodes after run: %+v", st.Nodes)
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("runDeployment did not reach a terminal state after request-context cancellation; status=%q", st.Status)
			}
			time.Sleep(5 * time.Millisecond)
		}
	})
	t.Run("restart_clears_in_memory_state", func(t *testing.T) {
		seededWizardWithSecrets(t) // secrets live only in the old wizard value
		fresh := NewWizard(nil, slog.Default())
		assertStateCleared(t, fresh.StatusState())
	})
}

func seededWizardWithSecrets(t *testing.T) *Wizard {
	t.Helper()
	return NewWizardWithState(&DeploymentState{
		Profile: Profile3Node,
		Nodes: []NodeConfig{
			{Host: "10.0.0.11", Role: "primary", SSHUser: "root", SSHKey: testInlineKey, Password: testNodePass},
		},
		Steps:     []DeploymentStep{{Name: "ssh_check", Status: "running"}},
		Status:    "deploying",
		StartedAt: time.Now(),
	})
}

func assertStateCleared(t *testing.T, st *StatusState) {
	t.Helper()
	if len(st.Nodes) != 0 {
		t.Errorf("state not cleared: nodes %+v", st.Nodes)
	}
	if len(st.Steps) != 0 {
		t.Errorf("state not cleared: steps %+v", st.Steps)
	}
	// Reset and restart both leave the zero-value state; nothing sets the
	// nominal "config" status until Begin replaces the state.
	if st.Status != "" {
		t.Errorf("state not cleared: status %q, want empty zero value", st.Status)
	}
	body, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	assertNoSecretMaterial(t, "cleared state", string(body))
}
