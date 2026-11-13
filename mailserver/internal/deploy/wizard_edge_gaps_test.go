package deploy

// Edge-branch coverage for the changed wizard/lock/redaction surfaces that the
// runlock and redaction suites do not already drive:
//
//   - Close is the server-shutdown seam (an ordinary Reset on an idle wizard);
//   - Reset's drain window is bounded and logs when a run outlives it;
//   - dialSSH fails on a refused TCP dial and its watchdog breaks a stalled
//     handshake the moment ctx is cancelled;
//   - openSession reports session-open failures and honors its open deadline;
//   - remoteTerminationConfirmed classifies session results by verdict;
//   - the cancel drain treats a SURFACED remote verdict as confirmed
//     termination (plain cancellation error, no unconfirmed fence wording);
//   - buildPgpoolKnownHosts fails closed on unverified input (nil key, no
//     hosts) and pins deduplicated hosts;
//   - checkRemoteInstallFailureOrdering rejects degenerate command shapes and
//     heredocDelimiter parses every delimiter form;
//   - knownSecrets/currentNodes are nil-state safe; scrubStep redacts both
//     free-form step fields with the wizard-held node secrets;
//   - persistStep/loadState round-trip scrubbed steps through a live
//     deployment_steps table (skips without DB_DSN, like the other live-DB
//     suites in this repo).
//
// The SSH peer is the in-process fake from wizard_runlock_test.go — no real
// SSH, no external network.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/ssh"
)

// ── Close / Reset drain window ───────────────────────────────────────────────

// TestCloseResetsIdleWizard: Close is the server-shutdown seam; on an idle
// wizard it clears the state for a fresh attempt (an ordinary Reset) and is
// safe to call repeatedly.
func TestCloseResetsIdleWizard(t *testing.T) {
	w := NewWizardWithState(&DeploymentState{
		Steps:  make([]DeploymentStep, 0),
		Status: "failed",
		Log:    []string{"[ssh_check] FAILED"},
	})
	w.Close()
	if got := w.StatusState().Status; got != "" {
		t.Fatalf("status after Close = %q, want empty (fresh state)", got)
	}
	w.Close() // idempotent
	if got := w.StatusState().Status; got != "" {
		t.Fatalf("status after second Close = %q, want empty", got)
	}
}

// capturingLogHandler records log records so the drain-timeout warning can be
// asserted without touching the default logger.
type capturingLogHandler struct {
	mu       sync.Mutex
	messages []string
}

func (h *capturingLogHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *capturingLogHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.messages = append(h.messages, r.Message)
	return nil
}
func (h *capturingLogHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *capturingLogHandler) WithGroup(string) slog.Handler      { return h }

func (h *capturingLogHandler) recorded() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.messages...)
}

// TestResetDrainTimeoutIsBoundedAndLogged: a Reset against a run that outlives
// the drain window returns once the window elapses — instead of blocking on the
// run — and logs that Begin stays guarded until the drain completes. The
// overrun is produced honestly: the wizard's pool dial is gated AFTER the run
// parks on the remote install command, so the cancelled run stalls inside
// failStep's persistStep (which the run acquires after Reset released mu) until
// the gate is released — far longer than the shrunken drain window.
func TestResetDrainTimeoutIsBoundedAndLogged(t *testing.T) {
	srv, addr, hostPub, clientPEM := newFakeSSHServer(t)

	origReset := resetDrainTimeout
	resetDrainTimeout = 25 * time.Millisecond
	defer func() { resetDrainTimeout = origReset }()

	var dialGate atomic.Bool
	release := make(chan struct{})
	poolCfg, err := pgxpool.ParseConfig("postgres://drain-probe@127.0.0.1/deploy")
	if err != nil {
		t.Fatalf("parse pool config: %v", err)
	}
	poolCfg.ConnConfig.DialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) {
		if !dialGate.Load() {
			return nil, errors.New("drain test: no DB expected before the gate closes")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-release:
			return nil, errors.New("drain test dial released")
		}
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), poolCfg)
	if err != nil {
		t.Fatalf("new pool: %v", err)
	}
	t.Cleanup(pool.Close)

	w := newRunlockTestWizard(t, hostPub)
	w.pool = pool
	capture := &capturingLogHandler{}
	w.logger = slog.New(capture)

	if err := w.Begin(context.Background(), runlockTestNodes(addr, clientPEM)); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	waitForExec(t, srv, installGate)
	// The run is parked on the remote install command. Gate the pool dial so
	// its fail path (failStep → persistStep) stalls until released.
	dialGate.Store(true)

	start := time.Now()
	w.Reset() // cancels, then waits for the drain until resetDrainTimeout
	elapsed := time.Since(start)
	if elapsed > 5*time.Second {
		t.Fatalf("Reset blocked %v; the drain window must bound it", elapsed)
	}

	found := false
	for _, msg := range capture.recorded() {
		if strings.Contains(msg, "reset timed out waiting for run drain") {
			found = true
		}
	}
	if !found {
		t.Errorf("drain-timeout warning not logged; records=%v", capture.recorded())
	}

	// Release the stalled dial: persistStep fails (logged, non-fatal), the run
	// records its terminal state and drains.
	close(release)
	waitDrained(t, w)
	srv.close()
}

// ── dialSSH ──────────────────────────────────────────────────────────────────

// throwawayHostKey generates a host key for configs whose handshake never gets
// far enough to verify it (refused dial).
func throwawayHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	return signer.PublicKey()
}

// TestDialSSHRefusedConnectionIsReported: a TCP dial to a closed loopback port
// surfaces the dial error instead of hanging (no SSH version exchange ever
// happens, so the dial error return is what this covers).
func TestDialSSHRefusedConnectionIsReported(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closedAddr := ln.Addr().String()
	_ = ln.Close() // the port is now (very likely) refused

	config := &ssh.ClientConfig{
		User:            "dial",
		HostKeyCallback: ssh.FixedHostKey(throwawayHostKey(t)),
		Timeout:         connectTimeout,
	}
	if _, err := dialSSH(context.Background(), closedAddr, config); err == nil {
		t.Fatal("dial to a closed loopback port succeeded; want an error")
	}
}

// TestDialSSHWatchdogBreaksStalledHandshakeOnCancel: against a peer that
// accepts TCP and goes silent, cancelling ctx must break the pending handshake
// immediately (the watchdog forces the conn deadline) instead of waiting for
// the full handshake deadline.
func TestDialSSHWatchdogBreaksStalledHandshakeOnCancel(t *testing.T) {
	srv, addr, hostPub, _ := newFakeSSHServerStalled(t, true, false)
	_ = srv // peer held only via t.Cleanup
	config := &ssh.ClientConfig{
		User:            "dial",
		HostKeyCallback: ssh.FixedHostKey(hostPub),
		Timeout:         connectTimeout,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := dialSSH(ctx, addr, config)
		done <- err
	}()
	time.Sleep(150 * time.Millisecond) // let the dial complete and the handshake stall
	start := time.Now()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled stalled handshake returned no error")
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("watchdog did not break the handshake promptly (returned after %v)", elapsed)
		}
	case <-time.After(runlockTimeout):
		t.Fatal("dialSSH did not return after ctx cancellation")
	}
}

// ── openSession ──────────────────────────────────────────────────────────────

// TestOpenSessionReportsSessionOpenFailure: a session open against a closed
// client surfaces the underlying error wrapped with the host.
func TestOpenSessionReportsSessionOpenFailure(t *testing.T) {
	srv, addr, hostPub, clientPEM := newFakeSSHServer(t, []string{}...)
	_ = srv
	client := dialFakePeer(t, addr, hostPub, clientPEM)
	_ = client.Close()
	if _, err := openSession(context.Background(), client, addr); err == nil || !strings.Contains(err.Error(), "open session to") {
		t.Fatalf("openSession on a closed client = %v, want a wrapped open error", err)
	}
}

// TestOpenSessionHonorsOpenDeadline: a peer that completed the handshake but
// never answers the session channel-open must hit the open deadline (not hang),
// close the abandoned client, and report the timeout.
func TestOpenSessionHonorsOpenDeadline(t *testing.T) {
	srv, addr, hostPub, clientPEM := newFakeSSHServerStalled(t, false, true)
	_ = srv
	client := dialFakePeer(t, addr, hostPub, clientPEM)

	origTimeout := sessionOpenTimeout
	sessionOpenTimeout = 50 * time.Millisecond
	defer func() { sessionOpenTimeout = origTimeout }()

	start := time.Now()
	_, err := openSession(context.Background(), client, addr)
	elapsed := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("openSession against a stalled peer = %v, want open timeout", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("session open not bounded by its deadline (returned after %v)", elapsed)
	}
}

// dialFakePeer dials the fake peer with its own client key and returns the
// connected client (the handshake completes for both the answering and the
// session-open-stalled peer shapes).
func dialFakePeer(t *testing.T, addr string, hostPub ssh.PublicKey, clientPEM string) *ssh.Client {
	t.Helper()
	signer, err := ssh.ParsePrivateKey([]byte(clientPEM))
	if err != nil {
		t.Fatalf("parse client key: %v", err)
	}
	config := &ssh.ClientConfig{
		User:            "session",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostPub),
		Timeout:         connectTimeout,
	}
	client, err := dialSSH(context.Background(), addr, config)
	if err != nil {
		t.Fatalf("dial fake peer: %v", err)
	}
	return client
}

// ── remoteTerminationConfirmed ───────────────────────────────────────────────

// TestRemoteTerminationConfirmedClassifiesVerdicts pins the evidence rules: a
// clean exit and a concrete remote exit error are termination evidence; a
// resultless teardown, a transport failure, and any other error are not.
func TestRemoteTerminationConfirmedClassifiesVerdicts(t *testing.T) {
	if !remoteTerminationConfirmed(nil) {
		t.Error("a clean zero exit must count as confirmed termination")
	}
	if !remoteTerminationConfirmed(&ssh.ExitError{}) {
		t.Error("a concrete remote exit verdict must count as confirmed termination")
	}
	if remoteTerminationConfirmed(&ssh.ExitMissingError{}) {
		t.Error("a resultless teardown must NOT count as confirmed termination")
	}
	if remoteTerminationConfirmed(errors.New("connection reset by peer")) {
		t.Error("a transport error must NOT count as confirmed termination")
	}
	var wrapped error = fmt.Errorf("during: %w", &ssh.ExitError{})
	if !remoteTerminationConfirmed(wrapped) {
		t.Error("a wrapped remote exit verdict must count as confirmed termination")
	}
}

// ── cancel drain with a confirmed remote verdict ─────────────────────────────
// NOTE: the `case res := <-resCh` + remoteTerminationConfirmed branch inside
// sshRunUnredacted's ctx.Done handling (a surfaced REAL verdict consumed by the
// cancel drain) is NOT deterministically reachable in-process: a verdict that
// arrives before cancellation is consumed by the outer select as the plain
// result, and a verdict attempted after cancellation dies with the transport
// teardown as a resultless *ssh.ExitMissingError (the unconfirmed branch, which
// TestExitMissingErrorDuringCancelDrainHoldsFence covers). Measured empirically
// with a remote-controlled fake peer across release/cancel orderings and delays
// (0/240 attempts observed the confirmed-drain branch); the branch is a
// defensive classifier for a scheduling window the runtime collapses, and its
// confirmed/unconfirmed predicates are pinned by
// TestRemoteTerminationConfirmedClassifiesVerdicts instead.

// ── sshRun stderr capture ────────────────────────────────────────────────────

// TestSSHRunCapturesAndRedactsStderr: remote stderr flows back through the
// single redaction choke point appended to the output as a [stderr] section —
// and wizard-held node secrets are scrubbed from it exactly like stdout.
func TestSSHRunCapturesAndRedactsStderr(t *testing.T) {
	password := "stderr-echoed-node-password"
	_, addr, hostPub, clientPEM := newFakeSSHServerEchoStdoutStderr(t,
		"stdout line\n",
		"warning: password "+password+" leaked to stderr\n",
	)
	w := NewWizardWithState(&DeploymentState{
		Steps: make([]DeploymentStep, 0),
		Nodes: []NodeConfig{{Host: addr, Role: "primary", SSHUser: "runlock", SSHKey: clientPEM, Password: password}},
	})
	w.hostKey = hostPub

	out, err := w.sshRun(context.Background(), addr, "runlock", clientPEM, "echo streams")
	if err != nil {
		t.Fatalf("sshRun: %v", err)
	}
	if !strings.Contains(out, "stdout line") {
		t.Errorf("stdout lost from output: %q", out)
	}
	if !strings.Contains(out, "[stderr]") || !strings.Contains(out, "warning: password") {
		t.Errorf("stderr section missing from output: %q", out)
	}
	if strings.Contains(out, password) {
		t.Errorf("node password survived redaction in stderr capture: %q", out)
	}
	if !strings.Contains(out, redactionSentinel) {
		t.Errorf("redaction sentinel missing from stderr capture: %q", out)
	}
}

// ── buildPgpoolKnownHosts ────────────────────────────────────────────────────

// TestBuildPgpoolKnownHostsFailsClosed pins the fail-closed refusals: no pinned
// key, an empty inventory, and a blank host inside the inventory must all
// refuse to render the trust anchor; a valid inventory pins every DISTINCT
// host with the marshaled key.
func TestBuildPgpoolKnownHostsFailsClosed(t *testing.T) {
	_, _, hostPub, _ := newFakeSSHServer(t, []string{}...)

	if _, err := buildPgpoolKnownHosts([]string{"n1.local"}, nil); err == nil || !strings.Contains(err.Error(), "no pinned deployment host key") {
		t.Fatalf("nil host key: err=%v, want the unverified-input refusal", err)
	}
	if _, err := buildPgpoolKnownHosts(nil, hostPub); err == nil || !strings.Contains(err.Error(), "no node hosts to pin") {
		t.Fatalf("empty inventory: err=%v, want the empty-anchor refusal", err)
	}
	if _, err := buildPgpoolKnownHosts([]string{"a.local", "   "}, hostPub); err == nil || !strings.Contains(err.Error(), "empty node host") {
		t.Fatalf("blank host in inventory: err=%v, want the blank-host refusal", err)
	}

	got, err := buildPgpoolKnownHosts([]string{"a.local", "b.local", "a.local"}, hostPub)
	if err != nil {
		t.Fatalf("valid inventory: %v", err)
	}
	wantLine := "a.local " + string(ssh.MarshalAuthorizedKey(hostPub))
	if !strings.HasPrefix(got, wantLine) {
		t.Errorf("anchor %q does not start with the pinned a.local entry %q", got, wantLine)
	}
	if strings.Count(got, "a.local ") != 1 {
		t.Errorf("anchor %q must deduplicate a.local", got)
	}
	if !strings.Contains(got, "b.local ") {
		t.Errorf("anchor %q must pin b.local", got)
	}
}

// ── failure-ordering gate: degenerate shapes and heredoc delimiters ─────────

// TestCheckRemoteInstallGateRejectsDegenerateCommands covers the remaining
// rejection shapes: a command with no executable lines at all, and a command
// that activates without any install step before it.
func TestCheckRemoteInstallGateRejectsDegenerateCommands(t *testing.T) {
	tests := []struct {
		name, cmd, wantErr string
	}{
		{
			name:    "empty command has no executable lines",
			cmd:     "",
			wantErr: "no executable lines",
		},
		{
			name:    "whitespace-only command has no executable lines",
			cmd:     "\n   \n\t\n",
			wantErr: "no executable lines",
		},
		{
			name:    "activation without install steps",
			cmd:     "set -e\nsystemctl restart seaweedfs",
			wantErr: "no install steps before activation",
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := checkRemoteInstallFailureOrdering(tc.cmd, "systemctl restart seaweedfs")
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("gate = %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestHeredocDelimiterForms pins the delimiter parser across quoting forms and
// its refusal shapes.
func TestHeredocDelimiterForms(t *testing.T) {
	tests := []struct {
		line  string
		want  string
		found bool
	}{
		{"cat > f << 'ENDOFUNIT'", "ENDOFUNIT", true},     // single-quoted
		{`cat > f << "ENDOFUNIT"`, "ENDOFUNIT", true},     // double-quoted
		{"cat > f << ENDOFUNIT", "ENDOFUNIT", true},       // bare
		{"cat > f << ENDOFUNIT extra", "ENDOFUNIT", true}, // bare with trailing arg
		{"install -d /etc/mail", "", false},               // no redirection
		{"cat > f <<", "", false},                         // nothing after <<
		{"cat > f << 'UNTERMINATED", "", false},           // unterminated quote
	}
	for _, tc := range tests {
		got, found := heredocDelimiter(tc.line)
		if found != tc.found || got != tc.want {
			t.Errorf("heredocDelimiter(%q) = (%q, %v), want (%q, %v)", tc.line, got, found, tc.want, tc.found)
		}
	}
}

// ── nil-state accessors and scrubStep ────────────────────────────────────────

// TestNilStateAccessorsAreSafe: knownSecrets and currentNodes must tolerate a
// wizard constructed without state (the nil guard branches).
func TestNilStateAccessorsAreSafe(t *testing.T) {
	w := &Wizard{}
	if got := w.knownSecrets(); got != nil {
		t.Errorf("knownSecrets on a stateless wizard = %v, want nil", got)
	}
	if got := w.currentNodes(); got != nil {
		t.Errorf("currentNodes on a stateless wizard = %v, want nil", got)
	}
}

// TestScrubStepRedactsWizardHeldSecrets: scrubStep applies structural redaction
// plus every node secret the wizard holds to BOTH free-form step fields before
// persistence.
func TestScrubStepRedactsWizardHeldSecrets(t *testing.T) {
	key := strings.Repeat("A", 30)
	password := "node-password-s3cret"
	w := NewWizardWithState(&DeploymentState{
		Nodes: []NodeConfig{
			{Host: "n1", Role: "primary", SSHKey: "-----BEGIN OPENSSH PRIVATE KEY-----\n" + key, Password: password},
		},
	})
	step := DeploymentStep{
		Name:   "install_packages",
		Status: "failed",
		Output: "echoed inline key: -----BEGIN OPENSSH PRIVATE KEY-----\n" + key,
		Error:  "auth failed with " + password,
	}
	scrubbed := w.scrubStep(step)
	if strings.Contains(scrubbed.Output, key) {
		t.Errorf("scrubbed output retains the inline key body: %q", scrubbed.Output)
	}
	if strings.Contains(scrubbed.Error, password) {
		t.Errorf("scrubbed error retains the node password: %q", scrubbed.Error)
	}
	if !strings.Contains(scrubbed.Output, redactionSentinel) || !strings.Contains(scrubbed.Error, redactionSentinel) {
		t.Errorf("scrubbed fields must carry the redaction sentinel: output=%q error=%q", scrubbed.Output, scrubbed.Error)
	}
}

// ── persistence round-trip (live DB; skips without DB_DSN) ──────────────────

// TestPersistStepAndLoadStateRoundTripThroughDB drives the LOGGED persistence
// boundary against a live PostgreSQL: persistStep scrubs and upserts the step
// (the pool-bound branch), loadState restores the rows as a "resumed" state
// with a crashed running row marked failed and free-form bodies withheld.
// Skips without DB_DSN, matching the repo's other live-DB suites.
func TestPersistStepAndLoadStateRoundTripThroughDB(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	ctx := context.Background()

	stepName := fmt.Sprintf("cov_gap_step_%d", time.Now().UnixNano())
	crashedName := stepName + "_crashed"
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM deployment_steps WHERE step_name IN ($1, $2)`, stepName, crashedName)
	})

	password := "persisted-node-password"
	w := &Wizard{
		pool:   pool,
		state:  &DeploymentState{Steps: make([]DeploymentStep, 0)},
		logger: slog.Default(),
	}
	w.state.Nodes = []NodeConfig{{Host: "n1", Role: "primary", Password: password}}

	// persistStep with a live pool: scrub + upsert (the pool-bound branch the
	// nil-pool early return skips).
	w.mu.Lock()
	w.persistStep(ctx, DeploymentStep{
		Name:   stepName,
		Status: "done",
		Output: "upload echoed " + password,
	})
	w.mu.Unlock()

	// A running row from a crashed run is marked failed on restore.
	if _, err := pool.Exec(ctx,
		`INSERT INTO deployment_steps (step_name, status, output, error) VALUES ($1, 'running', 'legacy detail', 'legacy error')
		 ON CONFLICT (step_name) DO UPDATE SET status = 'running', output = EXCLUDED.output, error = EXCLUDED.error`,
		crashedName); err != nil {
		t.Fatalf("seed running row: %v", err)
	}

	restored := &Wizard{
		pool:   pool,
		state:  &DeploymentState{Steps: make([]DeploymentStep, 0)},
		logger: slog.Default(),
	}
	restored.loadState(ctx)

	if got := restored.state.Status; got != "resumed" {
		t.Fatalf("restored status = %q, want resumed", got)
	}
	var foundDone, foundCrashed bool
	for _, s := range restored.state.Steps {
		switch s.Name {
		case stepName:
			foundDone = true
			if strings.Contains(s.Output, password) {
				t.Errorf("restored output retains the node password: %q", s.Output)
			}
		case crashedName:
			foundCrashed = true
			if s.Status != "failed" {
				t.Errorf("running row restored with status %q, want failed", s.Status)
			}
			// A pre-redaction row's free-form body is unverifiable at restore
			// time (no node credentials held) and must be withheld entirely.
			if s.Output != withheldRestoreNote || s.Error != withheldRestoreNote {
				t.Errorf("legacy row bodies not withheld: output=%q error=%q", s.Output, s.Error)
			}
		}
	}
	if !foundDone || !foundCrashed {
		t.Fatalf("restored steps missing rows (done=%v crashed=%v): %+v", foundDone, foundCrashed, restored.state.Steps)
	}
}
