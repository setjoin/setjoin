package deploy

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestStateSnapshotNoRace runs State() (which the HTTP handler marshals outside
// the lock) concurrently with okStep (which mutates Steps[i] in place under the
// lock). With the pre-fix shallow copy the returned snapshot shared the Steps
// backing array, so `go test -race` flagged a data race here; the deep copy in
// State() makes the snapshot independent.
func TestStateSnapshotNoRace(t *testing.T) {
	w := &Wizard{state: &DeploymentState{}}
	for i := 0; i < 50; i++ {
		w.state.Steps = append(w.state.Steps, DeploymentStep{Name: fmt.Sprintf("s%d", i), Status: "running"})
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_, _ = json.Marshal(w.State())
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			w.okStep(fmt.Sprintf("s%d", i))
		}
	}()
	wg.Wait()
}

func TestBuildReplicationCommands(t *testing.T) {
	cmds := buildReplicationCommands("pg-primary", []string{"pg-standby1", "pg-standby2"})
	if len(cmds) == 0 {
		t.Fatal("should have replication commands")
	}
	if !strings.Contains(cmds[0], "systemctl stop postgresql") {
		t.Errorf("first command should stop postgresql, got %q", cmds[0])
	}
	hasBasebackup := false
	hasStandbySignal := false
	hasConninfo := false
	for _, c := range cmds {
		if strings.Contains(c, "pg_basebackup") {
			hasBasebackup = true
		}
		if strings.Contains(c, "standby.signal") {
			hasStandbySignal = true
		}
		if strings.Contains(c, "primary_conninfo") {
			hasConninfo = true
		}
	}
	if !hasBasebackup {
		t.Error("should include pg_basebackup")
	}
	if !hasStandbySignal {
		t.Error("should create standby.signal")
	}
	if !hasConninfo {
		t.Error("should configure primary_conninfo")
	}
	if len(cmds) != 12 {
		t.Errorf("expected 12 commands for 2 standbys, got %d", len(cmds))
	}
}

func TestBuildReplicationCommands_SingleStandby(t *testing.T) {
	cmds := buildReplicationCommands("primary", []string{"standby1"})
	if len(cmds) != 6 {
		t.Errorf("expected 6 commands for 1 standby, got %d", len(cmds))
	}
}

func TestBuildReplicationCommands_NoStandbys(t *testing.T) {
	cmds := buildReplicationCommands("primary", nil)
	if len(cmds) != 0 {
		t.Errorf("expected 0 commands for no standbys, got %d", len(cmds))
	}
}

func TestBuildVerifyCommands(t *testing.T) {
	cmds := buildVerifyCommands("pg-primary", []string{"pg-standby1"})
	if len(cmds) == 0 {
		t.Fatal("should have verify commands")
	}
	if !strings.Contains(cmds[0], "pg_stat_replication") {
		t.Errorf("first command should check replication status, got %q", cmds[0])
	}
	hasRecovery := false
	for _, c := range cmds {
		if strings.Contains(c, "pg_is_in_recovery") {
			hasRecovery = true
		}
	}
	if !hasRecovery {
		t.Error("should check pg_is_in_recovery on standby")
	}
}

func TestGeneratePgpoolSystemdUnit(t *testing.T) {
	unit := GeneratePgpoolSystemdUnit(PgpoolConfig{
		Backends:   []string{"10.0.1.11:5432", "10.0.1.12:5432"},
		ListenPort: 9999,
	})
	if !strings.Contains(unit, "[Unit]") {
		t.Error("missing [Unit] section")
	}
	if !strings.Contains(unit, "[Service]") {
		t.Error("missing [Service] section")
	}
	if !strings.Contains(unit, "[Install]") {
		t.Error("missing [Install] section")
	}
	if !strings.Contains(unit, "pgpool") {
		t.Error("should reference pgpool")
	}
	if !strings.Contains(unit, "9999") {
		t.Error("should include listen port 9999")
	}
	if !strings.Contains(unit, "10.0.1.11:5432") {
		t.Error("should include backend 1")
	}
}

func TestGeneratePgpoolSystemdUnit_DefaultPort(t *testing.T) {
	unit := GeneratePgpoolSystemdUnit(PgpoolConfig{
		Backends: []string{"10.0.1.11:5432"},
	})
	if !strings.Contains(unit, "9999") {
		t.Error("should default to port 9999")
	}
}

// ── local shell execution of generated remote install commands ───────────────
//
// The wizard's remote provisioning commands run as root on a Debian node, but
// their failure-ordering contract (set -e + one simple command per
// pre-activation step, activation last) is plain POSIX shell. These helpers
// execute a generated command through a REAL local shell with the node tool
// namespace (install, chown, chmod, systemctl) shimmed on PATH, so a failing
// step's behavior is observed by execution, not by string matching alone:
// an intermediate failure must produce a nonzero exit and NEVER reach the
// recorded systemctl restart.

// writeRemoteInstallShims builds the PATH-shim directory. Each shim exits
// nonzero only when FAIL_TOOL names it (and, when FAIL_TOOL_ARG is set, only
// when its arguments contain that substring); systemctl additionally records
// every invocation into $SYSTEMCTL_LOG (one line of joined args per call) so
// tests can observe whether the restart ran at all.
func writeRemoteInstallShims(t *testing.T) (shimDir, systemctlLog string) {
	t.Helper()
	shimDir = t.TempDir()
	systemctlLog = filepath.Join(t.TempDir(), "systemctl.log")

	shim := func(name, body string) {
		t.Helper()
		path := filepath.Join(shimDir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0755); err != nil {
			t.Fatalf("write shim %s: %v", name, err)
		}
	}
	failGuard := func(name string) string {
		return "if [ \"$FAIL_TOOL\" = \"" + name + "\" ]; then\n" +
			"  if [ -z \"$FAIL_TOOL_ARG\" ] || printf '%s' \"$*\" | grep -q -- \"$FAIL_TOOL_ARG\"; then\n" +
			"    echo \"" + name + ": simulated failure\" >&2\n" +
			"    exit 3\n" +
			"  fi\n" +
			"fi\n"
	}
	// install shim: the wizard only uses `install -d ... DIR`; honor it with
	// mkdir -p of the final argument (owner/mode flags are irrelevant here).
	shim("install", "last=\"\"\nfor a in \"$@\"; do last=\"$a\"; done\nmkdir -p \"$last\" || exit 1\nexit 0\n")
	shim("chown", failGuard("chown")+"exit 0\n")
	shim("chmod", failGuard("chmod")+"exit 0\n")
	shim("systemctl", "printf '%s\\n' \"$*\" >> \"$SYSTEMCTL_LOG\"\n"+failGuard("systemctl")+"exit 0\n")
	return shimDir, systemctlLog
}

// runRemoteInstallCmd executes a generated provisioning command through the
// local shell with the node tool namespace shimmed. It returns the command
// error (nil on a clean exit) and the systemctl invocations recorded, in
// order.
func runRemoteInstallCmd(t *testing.T, cmd, failTool, failToolArg string) (exitErr error, systemctlCalls []string) {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no local shell: cannot execute generated install commands")
	}
	shimDir, systemctlLog := writeRemoteInstallShims(t)

	execCmd := exec.Command("sh", "-c", cmd)
	execCmd.Env = append(os.Environ(),
		"PATH="+shimDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAIL_TOOL="+failTool,
		"FAIL_TOOL_ARG="+failToolArg,
		"SYSTEMCTL_LOG="+systemctlLog,
	)
	exitErr = execCmd.Run()

	raw, err := os.ReadFile(systemctlLog)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("read systemctl log: %v", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) != "" {
			systemctlCalls = append(systemctlCalls, line)
		}
	}
	return exitErr, systemctlCalls
}

// TestRemoteInstallCommands_FailureOrderingGate is the command-text gate for
// the failure-ordering contract (med-deploy-s3-credentials-b1r2-001 item b,
// med-deploy-ssh-host-identity-b1r2-002): the wizard's generated provisioning
// commands must abort before the restart when any install step fails. The
// production commands must pass, and the PRE-FIX command shapes — plain
// newline-separated steps with `chown x && chmod x`, no set -e — must be
// REJECTED, so the defect class this fixes cannot silently rot back in.
func TestRemoteInstallCommands_FailureOrderingGate(t *testing.T) {
	production := []struct {
		name, cmd, marker string
	}{
		{
			name:   "seaweedfs per-node install command",
			cmd:    buildSeaweedFSNodeInstallCmd(SeaweedfsS3ConfigPath, "{\"identities\":[]}", SeaweedfsS3ConfigGroup, seaweedfsSystemdUnitPath, "unit-body"),
			marker: "systemctl restart seaweedfs",
		},
		{
			name:   "pgpool per-node install command",
			cmd:    buildPgpoolNodeInstallCmd(pgpoolFailoverScriptPath, wizardFailoverScript, pgpoolKnownHostsPath, "host key\n", pgpoolConfPath, "conf\n"),
			marker: "systemctl restart pgpool2",
		},
	}
	for _, tc := range production {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if err := checkRemoteInstallFailureOrdering(tc.cmd, tc.marker); err != nil {
				t.Fatalf("production command must pass the failure-ordering gate: %v\n%s", err, tc.cmd)
			}
		})
	}

	// The pre-fix seaweedfs command shape (plain-newline separated steps,
	// chown&&chmod, &&-chained activation, no set -e) must be rejected.
	preFixSeaweed := "install -d -o root -g mail -m 0750 /etc/mail\n" +
		"cat > " + SeaweedfsS3ConfigPath + " << 'ENDOFS3CONFIG'\n{}\nENDOFS3CONFIG\n" +
		"chown root:mail " + SeaweedfsS3ConfigPath + " && chmod 0640 " + SeaweedfsS3ConfigPath + "\n" +
		"cat > " + seaweedfsSystemdUnitPath + " << 'ENDOFUNIT'\nunit\nENDOFUNIT\n" +
		"systemctl daemon-reload && systemctl enable seaweedfs && systemctl restart seaweedfs"
	// The pre-fix pgpool command shape likewise.
	preFixPgpool := "install -d -o root -g root -m 0755 /etc/pgpool2\n" +
		"cat > " + pgpoolFailoverScriptPath + " << 'ENDOFFAILOVER'\nscript\nENDOFFAILOVER\n" +
		"chown root:root " + pgpoolFailoverScriptPath + " && chmod 0700 " + pgpoolFailoverScriptPath + "\n" +
		"cat > " + pgpoolKnownHostsPath + " << 'ENDOFKNOWNHOSTS'\nhost key\nENDOFKNOWNHOSTS\n" +
		"chown root:root " + pgpoolKnownHostsPath + " && chmod 0644 " + pgpoolKnownHostsPath + "\n" +
		"cat > " + pgpoolConfPath + " << 'ENDOFCONFIG'\nconf\nENDOFCONFIG\n" +
		"systemctl restart pgpool2 2>/dev/null || systemctl restart pgpool 2>/dev/null"

	mutations := []struct {
		name, cmd, marker string
	}{
		{
			name:   "pre-fix seaweedfs command (no set -e, plain newlines)",
			cmd:    preFixSeaweed,
			marker: "systemctl restart seaweedfs",
		},
		{
			name:   "pre-fix pgpool command (no set -e, plain newlines)",
			cmd:    preFixPgpool,
			marker: "systemctl restart pgpool2",
		},
		{
			// Isolates the AND-OR exemption: set -e alone does NOT abort on a
			// failing non-final command of a && list, so the pre-fix
			// `chown x && chmod x` line would continue into the restart.
			name: "set -e but mid-script AND-OR list",
			cmd: "set -e\n" +
				"install -d -o root -g mail -m 0750 /etc/mail\n" +
				"chown root:mail " + SeaweedfsS3ConfigPath + " && chmod 0640 " + SeaweedfsS3ConfigPath + "\n" +
				"systemctl restart seaweedfs",
			marker: "systemctl restart seaweedfs",
		},
		{
			// set -e + simple commands, but the restart is not the last
			// executable step: a later failure can no longer abort it.
			name: "executable step after the restart",
			cmd: "set -e\n" +
				"chown root:mail " + SeaweedfsS3ConfigPath + "\n" +
				"systemctl restart seaweedfs\n" +
				"systemctl enable seaweedfs",
			marker: "systemctl restart seaweedfs",
		},
		{
			name: "no restart at all",
			cmd: "set -e\n" +
				"chown root:mail " + SeaweedfsS3ConfigPath + "\n",
			marker: "systemctl restart seaweedfs",
		},
	}
	for _, tc := range mutations {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if err := checkRemoteInstallFailureOrdering(tc.cmd, tc.marker); err == nil {
				t.Fatalf("failure-ordering gate accepted a forbidden command shape (%s):\n%s", tc.name, tc.cmd)
			}
		})
	}
}
