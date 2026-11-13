package deploy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Host-identity policy for the Pgpool-II failover path
// (D-MAILSERVER-DEPLOY-002, med-deploy-ssh-host-identity-b1r2-002).
//
// deploy/failover.sh.template runs as root on an unattended control channel:
// pgpool invokes it at failover time with %H (the new primary hostname) and
// the script SSHes to that host to run `pg_ctl promote`. The SSH client must
// therefore fail closed:
//   - StrictHostKeyChecking=yes — unknown or substituted host keys are
//     refused; TOFU/accept-new is deliberately rejected because it accepts
//     previously unknown keys;
//   - UserKnownHostsFile AND GlobalKnownHostsFile pinned to
//     /etc/pgpool2/known_hosts — the only trust anchor is the peer keys
//     pre-provisioned at provisioning time. Provisioning is implemented on
//     both tracks (r2 integration): the wizard's configurePgpool installs the
//     anchor from the operator-pinned deployment host key, and install.sh's
//     opt-in HA leg installs it from operator-verified host keys; both are
//     fail-closed on unverified input (pinned by the wizard provisioning
//     tests below and by deploy/scripts/test-install-provision-render.sh);
//   - BatchMode=yes — no interactive prompt can hang the unattended failover;
//   - ConnectTimeout=5 retained;
//   - a refused/failed remote promote is logged and returns nonzero to pgpool.
//
// The wizard-embedded pgpool config (pgpoolConfigTemplate) enforces the
// identical policy by delegating failover to the same /etc/pgpool2/failover.sh
// script; it must never inline its own ssh command with a weaker policy.
const shippedFailoverScriptPath = "../../deploy/failover.sh.template"

// failoverKnownHostsAnchor is the pre-provisioned trust anchor path the
// failover SSH must pin both known-hosts stores to.
const failoverKnownHostsAnchor = `/etc/pgpool2/known_hosts`

// requiredFailoverSSHOptions must appear on executable (non-comment) lines of
// the shipped failover script.
var requiredFailoverSSHOptions = []string{
	"StrictHostKeyChecking=yes",
	"BatchMode=yes",
	"ConnectTimeout=5",
	`UserKnownHostsFile="$KNOWN_HOSTS"`,
	`GlobalKnownHostsFile="$KNOWN_HOSTS"`,
	`KNOWN_HOSTS="` + failoverKnownHostsAnchor + `"`,
	`"root@$NEW_HOST"`,
	`"$PGCTL promote -D $PGDATA"`,
}

// forbiddenFailoverSSHOptions must never appear on executable lines of the
// shipped failover script.
var forbiddenFailoverSSHOptions = []string{
	"StrictHostKeyChecking=no",
	"accept-new",
}

// stripFailoverComments drops comment lines so a policy mentioned in the
// header documentation cannot satisfy the executable-line checks.
func stripFailoverComments(script string) string {
	var kept []string
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// checkFailoverHostIdentity enforces the fail-closed host-identity contract
// against raw failover-script text.
func checkFailoverHostIdentity(script string) error {
	executable := stripFailoverComments(script)
	if strings.TrimSpace(executable) == "" {
		return &failoverPolicyError{what: "script has no executable lines"}
	}
	for _, forbidden := range forbiddenFailoverSSHOptions {
		if strings.Contains(executable, forbidden) {
			return &failoverPolicyError{what: "forbidden option " + forbidden}
		}
	}
	for _, required := range requiredFailoverSSHOptions {
		if !strings.Contains(executable, required) {
			return &failoverPolicyError{what: "missing required option " + required}
		}
	}
	// Both promote branches must log failure and exit nonzero, so a refused
	// host key is recorded and pgpool does not treat the failover as done.
	for _, marker := range []string{"Promote FAILED", "Remote promote FAILED"} {
		if !strings.Contains(executable, marker) {
			return &failoverPolicyError{what: "failure path not logged: " + marker}
		}
	}
	if strings.Count(executable, "exit 1") < 2 {
		return &failoverPolicyError{what: "both promote branches must exit nonzero"}
	}
	return nil
}

type failoverPolicyError struct{ what string }

func (e *failoverPolicyError) Error() string {
	return "failover script violates strict host-identity policy: " + e.what
}

// strictFailoverFixture is a minimal guard-clean failover script with the same
// branch structure as the shipped template.
const strictFailoverFixture = `LOG="/var/log/pgpool/failover.log"
KNOWN_HOSTS="/etc/pgpool2/known_hosts"
if [ "$NEW_HOST" = "localhost" ]; then
    if pg_ctl promote; then
        exit 0
    else
        echo "Promote FAILED" >> "$LOG"
        exit 1
    fi
else
    if ssh -o StrictHostKeyChecking=yes \
        -o UserKnownHostsFile="$KNOWN_HOSTS" \
        -o GlobalKnownHostsFile="$KNOWN_HOSTS" \
        -o BatchMode=yes \
        -o ConnectTimeout=5 \
        "root@$NEW_HOST" \
        "$PGCTL promote -D $PGDATA" >> "$LOG" 2>&1; then
        exit 0
    else
        echo "Remote promote FAILED" >> "$LOG"
        exit 1
    fi
fi
`

// TestShippedFailoverScript_StrictHostIdentity pins the fail-closed contract
// on the shipped script a pgpool deployment installs.
func TestShippedFailoverScript_StrictHostIdentity(t *testing.T) {
	raw, err := os.ReadFile(shippedFailoverScriptPath)
	if err != nil {
		t.Fatalf("read %s: %v", shippedFailoverScriptPath, err)
	}
	if err := checkFailoverHostIdentity(string(raw)); err != nil {
		t.Fatalf("shipped %s must fail closed: %v", shippedFailoverScriptPath, err)
	}
}

// TestFailoverHostIdentity_RejectsWeakerPolicies proves the guard rejects the
// exact states the finding forbids (and accepts the strict baseline), so the
// contract cannot silently rot.
func TestFailoverHostIdentity_RejectsWeakerPolicies(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(string) string
		wantErr bool
	}{
		{"unmodified strict policy is accepted", func(s string) string { return s }, false},
		{"host key checking disabled", func(s string) string {
			return strings.ReplaceAll(s, "StrictHostKeyChecking=yes", "StrictHostKeyChecking=no")
		}, true},
		{"accept-new TOFU policy", func(s string) string {
			return strings.ReplaceAll(s, "StrictHostKeyChecking=yes", "StrictHostKeyChecking=accept-new")
		}, true},
		{"strict policy only in a comment", func(s string) string {
			stripped := strings.ReplaceAll(s, "-o StrictHostKeyChecking=yes \\\n        ", "")
			return "# policy: StrictHostKeyChecking=yes\n" + stripped
		}, true},
		{"interactive prompting allowed", func(s string) string {
			return strings.ReplaceAll(s, "-o BatchMode=yes \\\n        ", "")
		}, true},
		{"user known_hosts left at root default", func(s string) string {
			return strings.ReplaceAll(s, `UserKnownHostsFile="$KNOWN_HOSTS"`, "UserKnownHostsFile=/root/.ssh/known_hosts")
		}, true},
		{"global known_hosts left at system default", func(s string) string {
			return strings.ReplaceAll(s, `GlobalKnownHostsFile="$KNOWN_HOSTS"`, "GlobalKnownHostsFile=/etc/ssh/ssh_known_hosts")
		}, true},
		{"remote failure reported as success to pgpool", func(s string) string {
			return strings.Replace(s, `echo "Remote promote FAILED" >> "$LOG"`+"\n        exit 1",
				`echo "Remote promote FAILED" >> "$LOG"`+"\n        exit 0", 1)
		}, true},
		{"remote failure not logged", func(s string) string {
			return strings.ReplaceAll(s, `        echo "Remote promote FAILED" >> "$LOG"`+"\n", "")
		}, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := checkFailoverHostIdentity(tc.mutate(strictFailoverFixture))
			if tc.wantErr && err == nil {
				t.Fatalf("guard accepted a forbidden failover policy state (%s)", tc.name)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("guard rejected the strict baseline: %v", err)
			}
		})
	}
}

// TestPgpoolConfigTemplate_DelegatesFailoverToStrictScript keeps the
// wizard-embedded pgpool config on the identical policy: it must delegate
// failover to /etc/pgpool2/failover.sh — the script whose strict host-identity
// contract is pinned above — and never inline an ssh command of its own.
func TestPgpoolConfigTemplate_DelegatesFailoverToStrictScript(t *testing.T) {
	const delegatedCommand = "failover_command = '/etc/pgpool2/failover.sh %d %P %H %R'"
	if !strings.Contains(pgpoolConfigTemplate, delegatedCommand) {
		t.Fatalf("pgpoolConfigTemplate failover_command no longer delegates to the strict failover script; want %q in:\n%s", delegatedCommand, pgpoolConfigTemplate)
	}
	for _, banned := range []string{"ssh ", "StrictHostKeyChecking"} {
		if strings.Contains(pgpoolConfigTemplate, banned) {
			t.Fatalf("pgpoolConfigTemplate must not embed %q; host-identity policy lives in /etc/pgpool2/failover.sh:\n%s", banned, pgpoolConfigTemplate)
		}
	}
}

// ── Wizard failover provisioning (r2 integration, D-MAILSERVER-DEPLOY-002) ──
//
// The strict script and its trust anchor must actually BE installed: the
// wizard's configurePgpool provisions /etc/pgpool2/failover.sh (0700,
// root-owned) and /etc/pgpool2/known_hosts (0644, root-owned) on every node
// in the same step that rewrites pgpool.conf, and the known_hosts entries are
// derived ONLY from the operator-pinned deployment host key — the key every
// node connection has already authenticated against — never from unverified
// input.

// TestWizardFailoverScript_MatchesShippedTemplate pins the wizard-embedded
// failover script to the reviewed shipped template byte-for-byte, so the
// installed script and the documented/render-tested script can never diverge.
func TestWizardFailoverScript_MatchesShippedTemplate(t *testing.T) {
	shipped, err := os.ReadFile(shippedFailoverScriptPath)
	if err != nil {
		t.Fatalf("read %s: %v", shippedFailoverScriptPath, err)
	}
	if wizardFailoverScript != string(shipped) {
		t.Fatalf("wizardFailoverScript diverges from %s — the wizard must install the exact reviewed script (update BOTH together):\n--- shipped ---\n%s\n--- embedded ---\n%s",
			shippedFailoverScriptPath, string(shipped), wizardFailoverScript)
	}
}

// extractHeredocBody pulls the body between a heredoc's start and end markers
// from a recorded remote command.
func extractHeredocBody(t *testing.T, cmd, startMarker, endMarker string) string {
	t.Helper()
	start := strings.Index(cmd, startMarker+"\n")
	if start == -1 {
		t.Fatalf("command missing heredoc start marker %s:\n%s", startMarker, cmd)
	}
	start += len(startMarker) + 1
	end := strings.Index(cmd[start:], "\n"+endMarker)
	if end == -1 {
		t.Fatalf("command missing heredoc end marker %s:\n%s", endMarker, cmd)
	}
	return cmd[start : start+end]
}

// TestConfigurePgpool_InstallsFailoverScriptAndKnownHosts drives the wizard's
// pgpool step against the fake SSH peer and proves every node receives:
//   - /etc/pgpool2/failover.sh with the reviewed strict script, 0700 root:root;
//   - /etc/pgpool2/known_hosts pinning the pinned deployment host key for
//     every node host, 0644 root:root;
//   - the pgpool.conf rewrite, still in the same step;
//   - a command whose install steps all abort before the pgpool restart, so a
//     failed script/anchor install can never be masked by a restart of a
//     pre-existing pgpool.conf (med-deploy-ssh-host-identity-b1r2-002).
func TestConfigurePgpool_InstallsFailoverScriptAndKnownHosts(t *testing.T) {
	srv, addr, hostPub, clientPEM := newFakeSSHServerEcho(t, "ok\n")
	_ = srv
	w, _ := wizardWithPeerNodes(t, addr, clientPEM)
	w.hostKey = hostPub

	if err := w.configurePgpool(context.Background()); err != nil {
		t.Fatalf("configurePgpool: %v", err)
	}

	commands := srv.recorded()
	if len(commands) != 3 {
		t.Fatalf("expected one provisioning command per node (3), got %d", len(commands))
	}
	pinnedLine := addr + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostPub)))
	sawKnownHosts, sawFailover := 0, 0
	for _, cmd := range commands {
		if !strings.Contains(cmd, "install -d -o root -g root -m 0755 /etc/pgpool2") {
			t.Errorf("provisioning command does not create /etc/pgpool2 with strict modes:\n%s", cmd)
		}
		if !strings.Contains(cmd, "chown root:root "+pgpoolFailoverScriptPath+"\nchmod 0700 "+pgpoolFailoverScriptPath+"\n") {
			t.Errorf("failover.sh is not pinned 0700 root-owned as its own abortable step:\n%s", cmd)
		}
		if !strings.Contains(cmd, "chown root:root "+pgpoolKnownHostsPath+"\nchmod 0644 "+pgpoolKnownHostsPath+"\n") {
			t.Errorf("known_hosts is not pinned 0644 root-owned as its own abortable step:\n%s", cmd)
		}
		if !strings.Contains(cmd, "cat > "+pgpoolConfPath) {
			t.Errorf("provisioning step no longer rewrites pgpool.conf:\n%s", cmd)
		}
		// Failure ordering: any failed install step must abort before the
		// pgpool restart (set -e discipline; med-deploy-ssh-host-identity-b1r2-002).
		if err := checkRemoteInstallFailureOrdering(cmd, "systemctl restart pgpool2"); err != nil {
			t.Errorf("pgpool provisioning command violates the failure-ordering contract: %v\n%s", err, cmd)
		}
		if strings.Contains(cmd, "cat > "+pgpoolFailoverScriptPath) {
			sawFailover++
			script := extractHeredocBody(t, cmd, "<< 'ENDOFFAILOVER'", "ENDOFFAILOVER")
			if script != wizardFailoverScript {
				t.Errorf("uploaded failover script diverges from the embedded shipped script")
			}
			if err := checkFailoverHostIdentity(script); err != nil {
				t.Errorf("uploaded failover script violates the strict host-identity policy: %v", err)
			}
		}
		if strings.Contains(cmd, "cat > "+pgpoolKnownHostsPath) {
			sawKnownHosts++
			kh := extractHeredocBody(t, cmd, "<< 'ENDOFKNOWNHOSTS'", "ENDOFKNOWNHOSTS")
			if !strings.Contains(kh, pinnedLine) {
				t.Errorf("known_hosts does not pin the deployment host key for node host %s; got:\n%s", addr, kh)
			}
			for _, host := range []string{addr} {
				if !strings.Contains(kh, host+" ") {
					t.Errorf("known_hosts missing an entry for node host %s:\n%s", host, kh)
				}
			}
		}
	}
	if sawFailover != 3 || sawKnownHosts != 3 {
		t.Errorf("expected failover.sh + known_hosts provisioning on all 3 nodes (failover=%d known_hosts=%d)", sawFailover, sawKnownHosts)
	}
}

// TestPgpoolInstallCmd_FailureAbortsBeforeRestart executes the generated
// per-node pgpool provisioning command through a REAL local shell with the
// node tool namespace shimmed, proving the failure ordering by execution: a
// failed failover.sh/known_hosts install exits nonzero and the systemctl
// restart is never recorded — provisioning cannot report success while a node
// would run a pgpool.conf delegating to a missing or stale artifact
// (med-deploy-ssh-host-identity-b1r2-002). The pgpool2→pgpool unit-name
// fallback and the both-units-failing abort are exercised too.
func TestPgpoolInstallCmd_FailureAbortsBeforeRestart(t *testing.T) {
	dir := t.TempDir()
	cmd := buildPgpoolNodeInstallCmd(
		filepath.Join(dir, "failover.sh"),
		wizardFailoverScript,
		filepath.Join(dir, "known_hosts"),
		"node1.example ssh-ed25519 AAAAfixture1\nnode2.example ssh-ed25519 AAAAfixture2\n",
		filepath.Join(dir, "pgpool.conf"),
		"listen_addresses = '*'\n",
	)

	// Happy path: the pgpool2 restart runs (fallback not taken).
	exitErr, calls := runRemoteInstallCmd(t, cmd, "", "")
	if exitErr != nil {
		t.Fatalf("clean environment: command failed: %v", exitErr)
	}
	if len(calls) != 1 || calls[0] != "restart pgpool2" {
		t.Fatalf("clean environment systemctl calls = %v, want [restart pgpool2]", calls)
	}

	// A failed chown on the failover script aborts before the restart.
	exitErr, calls = runRemoteInstallCmd(t, cmd, "chown", "")
	if exitErr == nil || len(calls) != 0 {
		t.Fatalf("failed chown must abort before the restart (err=%v, calls=%v)", exitErr, calls)
	}

	// A failed chmod on known_hosts aborts before the restart.
	exitErr, calls = runRemoteInstallCmd(t, cmd, "chmod", "")
	if exitErr == nil || len(calls) != 0 {
		t.Fatalf("failed chmod must abort before the restart (err=%v, calls=%v)", exitErr, calls)
	}

	// Unit-name fallback: a failing pgpool2 unit falls back to the pgpool unit.
	exitErr, calls = runRemoteInstallCmd(t, cmd, "systemctl", "pgpool2")
	if exitErr != nil {
		t.Fatalf("pgpool2 failure must fall back to the pgpool unit, got: %v", exitErr)
	}
	if len(calls) != 2 || calls[0] != "restart pgpool2" || calls[1] != "restart pgpool" {
		t.Fatalf("fallback sequence = %v, want [restart pgpool2 restart pgpool]", calls)
	}

	// Both unit names failing terminates the command nonzero (the fallback's
	// final command is the last restart attempt — set -e applies to it).
	exitErr, calls = runRemoteInstallCmd(t, cmd, "systemctl", "")
	if exitErr == nil {
		t.Fatal("both unit restarts failing must abort the install command")
	}
	if len(calls) != 2 {
		t.Fatalf("both-failing restart sequence = %v, want both attempts recorded", calls)
	}
}

// TestConfigurePgpool_RefusesUnpinnedHostKey keeps the trust anchor fail
// closed: with no pinned deployment host key there is no verified input to
// provision from, so the step must refuse BEFORE any node is contacted.
func TestConfigurePgpool_RefusesUnpinnedHostKey(t *testing.T) {
	srv, addr, _, clientPEM := newFakeSSHServerEcho(t, "ok\n")
	_ = srv
	w, _ := wizardWithPeerNodes(t, addr, clientPEM)
	w.hostKey = nil

	err := w.configurePgpool(context.Background())
	if err == nil {
		t.Fatal("configurePgpool must refuse to provision without a pinned deployment host key")
	}
	if !strings.Contains(err.Error(), "unverified input") {
		t.Fatalf("refusal must name the unverified-input contract, got: %v", err)
	}
	if recorded := srv.recorded(); len(recorded) != 0 {
		t.Fatalf("no node may be contacted when the trust anchor is unprovisionable; recorded: %v", recorded)
	}
}
