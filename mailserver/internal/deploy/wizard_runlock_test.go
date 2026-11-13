package deploy

// Run-serialization, owned-lifetime, run-fence and real-cancellation tests for
// the deploy wizard (D-MAILSERVER-INTERNAL-DEPLOY-R-002, package
// med-deploy-wizard-serialization-b1r2-007; r2 review delta).
//
// Covered contract:
//   - the run's lifetime is OWNED by the wizard (context.WithoutCancel):
//     completing the HTTP response (caller-context cancellation) leaves the
//     run running; only Reset/Close cancel it;
//   - Begin while a deployment run is in flight is rejected
//     (ErrDeployInProgress) and NEVER cancels the active run — a rejected
//     start preserves it; the handler's Reset;Begin start sequence works
//     because Reset drains the cancelled run before returning;
//   - while the run fence is held (prior run cancelled mid-command with no
//     ACTUAL remote termination evidence — no verdict at all, a resultless
//     *ssh.ExitMissingError teardown, or any other transport error — remote
//     termination is unconfirmed), Begin refuses with ErrDeployUnreconciled so
//     no subsequent run overlaps surviving remote work; the fence is cleared
//     ONLY by the explicit AcknowledgeReconciled operator acknowledgment:
//     ordinary Reset calls and start retries preserve it;
//   - a session result surfaced during the cancel drain counts as confirmed
//     termination only when it carries a real remote verdict (concrete exit
//     status or exit signal, or a clean exit) — the confirmed-termination
//     test drives a fake that ACTUALLY terminates the command over the live
//     transport, not one left parked while the client kills the transport;
//   - connection establishment and session opening are bounded: stalled
//     handshake and stalled session-open peers return within the ctx
//     deadline instead of blocking the run indefinitely;
//   - cancellation is REAL: Reset halts destructive remote steps — the fake
//     SSH peer never observes the later replication commands, and the
//     in-flight command is interrupted by sshRun's transport teardown;
//   - step functions read nodes only through the locked currentNodes
//     accessor, so Begin/Reset swapping the state pointer is race-free
//     (TestDeploymentStateAccessRaceFree; `go test -race` is the assertion).
//
// The SSH peer is an in-process x/crypto/ssh server on a 127.0.0.1 listener —
// no real SSH, no external network. Runs in the race-churn test fail fast
// (nonexistent key, closed loopback port) before any dial.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	// installGate is the substring identifying the install_packages command;
	// fake-peer sessions running it hold until released.
	installGate = "apt-get update"
	// runlockTimeout bounds every wait in these tests.
	runlockTimeout = 10 * time.Second
)

// fakeSSHServer is an in-process SSH peer. Sessions whose command contains a
// gate substring are held open until the server is closed (release), letting
// tests park a deployment run at a known destructive step.
type fakeSSHServer struct {
	ln     net.Listener
	config *ssh.ServerConfig

	mu       sync.Mutex
	executed []string

	release chan struct{}
	// releaseOnce and closeLnOnce are separate: releaseGate() unblocks gated
	// sessions WITHOUT closing the listener, so a released command delivers
	// its exit status over the still-open transport (actual remote
	// termination evidence). close() does both.
	releaseOnce sync.Once
	closeLnOnce sync.Once

	// gates lists command substrings whose sessions are held until release;
	// empty means the default {installGate, "hang"}.
	gates []string
	// stallHandshake accepts TCP connections but never sends the SSH server
	// version — the client handshake blocks until its deadline.
	stallHandshake bool
	// stallSessionOpen completes the SSH handshake but never answers a
	// session channel-open request — client NewSession blocks until its
	// deadline.
	stallSessionOpen bool
	// echoAll, when non-empty, is written as command output for every exec
	// instead of the default "ok\n".
	echoAll string
	// echoStderr, when non-empty, is written as command STDERR for every exec
	// — the remote stderr shape the sshRun stderr-capture coverage drives.
	echoStderr string
	// exitSignalSubstring, when non-empty, makes sessions whose command
	// contains it terminate with an SSH exit-signal request whose Errmsg
	// carries exitSignalMessage — the remote-controlled "Reason was: ..."
	// text the error-scrub tests ride on (a real sshd builds that text from
	// the remote process's dying output, so it can echo secrets back).
	exitSignalSubstring string
	exitSignalMessage   string
}

func newFakeSSHServer(t *testing.T, gateSubstrings ...string) (*fakeSSHServer, string, ssh.PublicKey, string) {
	t.Helper()
	return newFakeSSHServerOpts(t, fakeSSHServerOpts{gates: gateSubstrings})
}

// newFakeSSHServerStalled returns a peer that completes the TCP accept and,
// per flags, either never performs the SSH handshake or never answers session
// channel opens — the two indefinite-block shapes pinned by
// TestSSHRunStalledHandshakeIsBounded / TestSSHRunStalledSessionOpenIsBounded.
func newFakeSSHServerStalled(t *testing.T, stallHandshake, stallSessionOpen bool) (*fakeSSHServer, string, ssh.PublicKey, string) {
	t.Helper()
	return newFakeSSHServerOpts(t, fakeSSHServerOpts{stallHandshake: stallHandshake, stallSessionOpen: stallSessionOpen})
}

// newFakeSSHServerEcho returns a non-gated peer that echoes echoAll as the
// output of every exec — the remote-echo shape the secret-redaction tests
// scrub out of returned output and logs.
func newFakeSSHServerEcho(t *testing.T, echoAll string) (*fakeSSHServer, string, ssh.PublicKey, string) {
	t.Helper()
	return newFakeSSHServerOpts(t, fakeSSHServerOpts{gates: []string{}, echoAll: echoAll})
}

// newFakeSSHServerEchoStdoutStderr returns a non-gated peer that echoes both a
// stdout and a stderr stream for every exec — the shape the sshRun
// stderr-capture branch drives.
func newFakeSSHServerEchoStdoutStderr(t *testing.T, stdout, stderr string) (*fakeSSHServer, string, ssh.PublicKey, string) {
	t.Helper()
	return newFakeSSHServerOpts(t, fakeSSHServerOpts{gates: []string{}, echoAll: stdout, echoStderr: stderr})
}

// newFakeSSHServerExitSignal returns a non-gated peer whose commands containing
// cmdSubstring terminate with an SSH exit-signal request carrying msg — the
// remote verdict shape the error-scrub tests drive through sshRun, failStep,
// persistence, and the status surface.
func newFakeSSHServerExitSignal(t *testing.T, cmdSubstring, msg string) (*fakeSSHServer, string, ssh.PublicKey, string) {
	t.Helper()
	return newFakeSSHServerOpts(t, fakeSSHServerOpts{
		gates:               []string{},
		exitSignalSubstring: cmdSubstring,
		exitSignalMessage:   msg,
	})
}

type fakeSSHServerOpts struct {
	gates            []string
	stallHandshake   bool
	stallSessionOpen bool
	echoAll          string
	// echoStderr: stderr written for every exec (see fakeSSHServer's
	// same-named field).
	echoStderr string
	// exitSignalSubstring/exitSignalMessage: sessions whose command contains
	// the substring terminate with an SSH exit-signal whose Errmsg carries the
	// message (see fakeSSHServer's same-named fields).
	exitSignalSubstring string
	exitSignalMessage   string
}

func newFakeSSHServerOpts(t *testing.T, opts fakeSSHServerOpts) (*fakeSSHServer, string, ssh.PublicKey, string) {
	t.Helper()

	hostPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	clientPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	clientSigner, err := ssh.NewSignerFromKey(clientPriv)
	if err != nil {
		t.Fatalf("client signer: %v", err)
	}
	authLine := string(ssh.MarshalAuthorizedKey(clientSigner.PublicKey()))
	pemBlock, err := ssh.MarshalPrivateKey(clientPriv, "deploy-runlock-test")
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}
	clientPEM := string(pem.EncodeToMemory(pemBlock))

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(ssh.MarshalAuthorizedKey(key)) != authLine {
				return nil, errors.New("unknown client key")
			}
			return &ssh.Permissions{}, nil
		},
	}
	config.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &fakeSSHServer{
		ln:                  ln,
		config:              config,
		release:             make(chan struct{}),
		gates:               opts.gates,
		stallHandshake:      opts.stallHandshake,
		stallSessionOpen:    opts.stallSessionOpen,
		echoAll:             opts.echoAll,
		echoStderr:          opts.echoStderr,
		exitSignalSubstring: opts.exitSignalSubstring,
		exitSignalMessage:   opts.exitSignalMessage,
	}
	// A nil gates slice means the caller did not care: default to the parked
	// install/hang gates. An explicit empty slice (echo servers) gates
	// nothing.
	if opts.gates == nil {
		srv.gates = []string{installGate, "hang"}
	}
	go srv.acceptLoop()
	t.Cleanup(srv.close)
	return srv, ln.Addr().String(), hostSigner.PublicKey(), clientPEM
}

func (s *fakeSSHServer) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *fakeSSHServer) handleConn(conn net.Conn) {
	if s.stallHandshake {
		// Accept TCP, then go silent: never send the server version, so the
		// client's handshake blocks until its deadline.
		<-s.release
		_ = conn.Close()
		return
	}
	sconn, chans, reqs, err := ssh.NewServerConn(conn, s.config)
	if err != nil {
		_ = conn.Close()
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		if s.stallSessionOpen {
			// Complete the handshake, then never answer the channel-open:
			// the client's NewSession blocks until its deadline.
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			continue
		}
		go s.handleSession(ch, chReqs)
	}
}

func (s *fakeSSHServer) handleSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for req := range reqs {
		if req.Type != "exec" {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			continue
		}
		var payload struct{ Command string }
		if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			continue
		}
		s.mu.Lock()
		s.executed = append(s.executed, payload.Command)
		s.mu.Unlock()
		if req.WantReply {
			_ = req.Reply(true, nil)
		}
		if s.gated(payload.Command) {
			<-s.release
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1}))
			return
		}
		if s.exitSignalSubstring != "" && strings.Contains(payload.Command, s.exitSignalSubstring) {
			// Terminate with an SSH exit-signal: the remote-controlled
			// reason text flows into *ssh.ExitError.Error() ("Process exited
			// with status N from signal TERM. Reason was: ...") on the client.
			payload := ssh.Marshal(struct {
				Signal     string
				CoreDumped bool
				Errmsg     string
				Lang       string
			}{Signal: "TERM", CoreDumped: false, Errmsg: s.exitSignalMessage, Lang: "en"})
			_, _ = ch.SendRequest("exit-signal", false, payload)
			return
		}
		out := []byte("ok\n")
		if s.echoAll != "" {
			out = []byte(s.echoAll)
		}
		_, _ = ch.Write(out)
		if s.echoStderr != "" {
			_, _ = ch.Stderr().Write([]byte(s.echoStderr))
		}
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		return
	}
}

func (s *fakeSSHServer) gated(cmd string) bool {
	for _, gate := range s.gates {
		if strings.Contains(cmd, gate) {
			return true
		}
	}
	return false
}

// releaseGate unblocks every gated/stalled session without closing the
// listener: parked session handlers proceed and deliver their exit status over
// the still-open transport — the "fake actually terminates" shape the
// confirmed-termination test requires.
func (s *fakeSSHServer) releaseGate() {
	s.releaseOnce.Do(func() { close(s.release) })
}

func (s *fakeSSHServer) close() {
	s.releaseOnce.Do(func() { close(s.release) })
	s.closeLnOnce.Do(func() { _ = s.ln.Close() })
}

func (s *fakeSSHServer) recorded() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.executed...)
}

// ── wait helpers ─────────────────────────────────────────────────────────────

func waitForExec(t *testing.T, s *fakeSSHServer, substr string) {
	t.Helper()
	deadline := time.Now().Add(runlockTimeout)
	for {
		for _, cmd := range s.recorded() {
			if strings.Contains(cmd, substr) {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("fake ssh peer never saw command containing %q; executed=%v", substr, s.recorded())
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func waitForTerminalStatus(t *testing.T, w *Wizard) string {
	t.Helper()
	deadline := time.Now().Add(runlockTimeout)
	for {
		st := w.StatusState().Status
		if st == "failed" || st == "done" {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("run did not reach a terminal status; last=%q", st)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func waitDrained(t *testing.T, w *Wizard) {
	t.Helper()
	deadline := time.Now().Add(runlockTimeout)
	for {
		w.mu.Lock()
		run := w.run
		w.mu.Unlock()
		if run == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("deployment run did not drain")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// ── fixtures ─────────────────────────────────────────────────────────────────

func newRunlockTestWizard(t *testing.T, hostPub ssh.PublicKey) *Wizard {
	t.Helper()
	// installPackages fails closed without a pinned artifact digest
	// (D-MAILSERVER-INTERNAL-DEPLOY-R-003), before any remote command. These
	// tests need the run to reach the remote steps, so record a well-formed
	// digest via the operator seam; the fake peer records but never executes
	// the install command, so nothing is ever downloaded.
	t.Setenv(seaweedfsChecksumEnv, strings.Repeat("ab", 32))
	w := NewWizardWithState(&DeploymentState{Steps: make([]DeploymentStep, 0)})
	w.hostKey = hostPub
	return w
}

func runlockTestNodes(addr, clientPEM string) []NodeConfig {
	return []NodeConfig{{Host: addr, Role: "standby", SSHUser: "runlock", SSHKey: clientPEM}}
}

// ── Begin guard ──────────────────────────────────────────────────────────────

func TestBeginRejectedWhileDeploymentInFlight(t *testing.T) {
	srv, addr, hostPub, clientPEM := newFakeSSHServer(t)
	w := newRunlockTestWizard(t, hostPub)

	if err := w.Begin(context.Background(), runlockTestNodes(addr, clientPEM)); err != nil {
		t.Fatalf("first Begin: %v", err)
	}
	// The run is genuinely in flight once the peer is executing the install
	// command (held open by the fake peer's gate).
	waitForExec(t, srv, installGate)

	if err := w.Begin(context.Background(), runlockTestNodes(addr, clientPEM)); !errors.Is(err, ErrDeployInProgress) {
		t.Fatalf("second Begin during in-flight run: got %v, want ErrDeployInProgress", err)
	}

	// Release the held command with a failing exit status; the run must reach
	// its terminal state and drain, after which Begin is accepted again.
	srv.close()
	waitDrained(t, w)

	if err := w.Begin(context.Background(), runlockTestNodes(addr, clientPEM)); err != nil {
		t.Fatalf("Begin after drain: %v", err)
	}
	// Leave no run behind: Reset cancels the replacement run (listener already
	// closed, so it fails fast either way).
	w.Reset()
	waitDrained(t, w)
}

// ── owned run lifetime ───────────────────────────────────────────────────────

// TestCallerContextCancellationLeavesRunRunning pins the owned-lifetime
// contract: the run's context is derived with context.WithoutCancel, so
// completing the HTTP response (the accepted caller's request context being
// cancelled) must NOT cancel the deployment. Only Reset/Close cancel a run.
func TestCallerContextCancellationLeavesRunRunning(t *testing.T) {
	srv, addr, hostPub, clientPEM := newFakeSSHServer(t)
	w := newRunlockTestWizard(t, hostPub)

	// Simulate the HTTP request lifetime: Begin with a request context.
	ctx, cancel := context.WithCancel(context.Background())
	if err := w.Begin(ctx, runlockTestNodes(addr, clientPEM)); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	waitForExec(t, srv, installGate)

	// "Response complete": the caller's context dies while the run is parked
	// on the peer's held install command.
	cancel()
	time.Sleep(100 * time.Millisecond)

	w.mu.Lock()
	stillTracked := w.run != nil
	w.mu.Unlock()
	if !stillTracked {
		t.Fatal("run was cancelled when the caller's (request) context was cancelled; the run lifetime must be owned by the wizard")
	}
	if st := w.StatusState().Status; st != "deploying" {
		t.Fatalf("status after caller-context cancellation = %q, want deploying", st)
	}

	// The run can still make progress on its own: releasing the peer lets it
	// reach a terminal state without any further caller involvement.
	srv.close()
	if status := waitForTerminalStatus(t, w); status != "failed" {
		t.Fatalf("run status = %q, want failed (peer exit-status after release)", status)
	}
	waitDrained(t, w)
}

// ── rejected starts preserve the active run ──────────────────────────────────

// TestRejectedStartPreservesActiveRun: Begin while a run is in flight rejects
// with ErrDeployInProgress and must NOT cancel the active run — Begin never
// cancels; Reset is the only cancellation path.
func TestRejectedStartPreservesActiveRun(t *testing.T) {
	srv, addr, hostPub, clientPEM := newFakeSSHServer(t)
	w := newRunlockTestWizard(t, hostPub)

	if err := w.Begin(context.Background(), runlockTestNodes(addr, clientPEM)); err != nil {
		t.Fatalf("first Begin: %v", err)
	}
	waitForExec(t, srv, installGate)

	if err := w.Begin(context.Background(), runlockTestNodes(addr, clientPEM)); !errors.Is(err, ErrDeployInProgress) {
		t.Fatalf("second Begin during in-flight run: got %v, want ErrDeployInProgress", err)
	}

	// The active run is untouched: still parked on the peer's gate, and its
	// eventual terminal state is driven by the peer's exit status — NOT by a
	// deployment cancellation.
	srv.close()
	if status := waitForTerminalStatus(t, w); status != "failed" {
		t.Fatalf("run status = %q, want failed", status)
	}
	waitDrained(t, w)
	for _, step := range w.StatusState().Steps {
		if step.Name == "install_packages" && strings.Contains(step.Error, "deployment cancelled") {
			t.Errorf("rejected start cancelled the active run: install_packages error = %q", step.Error)
		}
	}
	for _, cmd := range srv.recorded() {
		if strings.Contains(cmd, "pg_basebackup") {
			t.Errorf("destructive replication command executed after rejected start: %q", cmd)
		}
	}
}

// TestResetDrainLetsStartSequenceReplaceRun pins the reconciled handler start
// path: StartDeploy calls Reset() then Begin() — Reset cancels the in-flight
// run AND drains it before returning, so the subsequent Begin observes an idle
// wizard (ErrDeployInProgress is gone). The cancelled run's remote outcome was
// unconfirmed (the parked command delivered no verdict), so the drain ALSO
// installed the run fence: the replacement start is then refused with
// ErrDeployUnreconciled until the explicit AcknowledgeReconciled — a retry
// must not clear a drained run's fence merely by restarting.
func TestResetDrainLetsStartSequenceReplaceRun(t *testing.T) {
	srv, addr, hostPub, clientPEM := newFakeSSHServer(t)
	w := newRunlockTestWizard(t, hostPub)

	if err := w.Begin(context.Background(), runlockTestNodes(addr, clientPEM)); err != nil {
		t.Fatalf("first Begin: %v", err)
	}
	waitForExec(t, srv, installGate)

	// Handler StartDeploy path against an in-flight run.
	w.Reset()
	waitDrained(t, w)

	// Idle (drained): the refusal is the FENCE, not an in-flight conflict.
	if err := w.Begin(context.Background(), runlockTestNodes(addr, clientPEM)); !errors.Is(err, ErrDeployUnreconciled) {
		t.Fatalf("Begin after Reset-drain: got %v, want ErrDeployUnreconciled", err)
	}
	// Explicit acknowledgment admits the replacement run.
	if err := w.AcknowledgeReconciled(); err != nil {
		t.Fatalf("AcknowledgeReconciled: %v", err)
	}
	if err := w.Begin(context.Background(), runlockTestNodes(addr, clientPEM)); err != nil {
		t.Fatalf("Begin after acknowledgment: %v, want replacement run accepted", err)
	}
	w.Reset()
	waitDrained(t, w)
}

// ── real cancellation (Reset is the only cancel path) ────────────────────────

func TestResetCancelsInFlightDeployment(t *testing.T) {
	srv, addr, hostPub, clientPEM := newFakeSSHServer(t)
	w := newRunlockTestWizard(t, hostPub)

	if err := w.Begin(context.Background(), runlockTestNodes(addr, clientPEM)); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	waitForExec(t, srv, installGate)

	// Reset is the handler's CancelDeploy path: it must hard-cancel the run
	// (real cancellation), not merely replace the status struct while the old
	// goroutine keeps issuing remote commands.
	w.Reset()
	if status := waitForTerminalStatus(t, w); status != "failed" {
		t.Fatalf("Reset-cancelled run status = %q, want failed", status)
	}
	waitDrained(t, w)
	// The destructive replication steps must never have been issued. (The
	// install command itself legitimately embeds `rm -rf` of its own staging
	// dir, so match the replication-specific signatures.)
	for _, cmd := range srv.recorded() {
		if strings.Contains(cmd, "pg_basebackup") ||
			strings.Contains(cmd, "/var/lib/postgresql") ||
			strings.Contains(cmd, "systemctl stop postgresql") {
			t.Errorf("destructive replication command executed after Reset: %q", cmd)
		}
	}
	// The failing step surfaced as cancellation, not a plain command error.
	for _, step := range w.StatusState().Steps {
		if step.Name == "install_packages" && !strings.Contains(step.Error, "deployment cancelled") {
			t.Errorf("install_packages error = %q, want cancellation error", step.Error)
		}
	}

	// The parked command never delivered a remote verdict before the transport
	// died, so the cancelled run's remote outcome is unconfirmed: the drained
	// wizard holds the run fence and Begin refuses until the explicit
	// acknowledgment. (Before the r2 fix this drain surfaced a resultless
	// *ssh.ExitMissingError that was consumed without examining res.err and
	// mistaken for confirmed termination.)
	if err := w.Begin(context.Background(), runlockTestNodes(addr, clientPEM)); !errors.Is(err, ErrDeployUnreconciled) {
		t.Fatalf("Begin after Reset-cancel drain: got %v, want ErrDeployUnreconciled", err)
	}
	if err := w.AcknowledgeReconciled(); err != nil {
		t.Fatalf("AcknowledgeReconciled: %v", err)
	}

	// The acknowledged wizard accepts a fresh run again; leave nothing in
	// flight.
	if err := w.Begin(context.Background(), runlockTestNodes(addr, clientPEM)); err != nil {
		t.Fatalf("Begin after acknowledgment: %v", err)
	}
	w.Reset()
	waitDrained(t, w)
}

func TestSSHRunCancellationHaltsRemoteCommand(t *testing.T) {
	srv, addr, hostPub, clientPEM := newFakeSSHServer(t)
	w := newRunlockTestWizard(t, hostPub)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := w.sshRun(ctx, addr, "runlock", clientPEM, "hang forever")
		done <- err
	}()
	waitForExec(t, srv, "hang")
	cancel()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "deployment cancelled") {
			t.Fatalf("sshRun after cancellation: got %v, want deployment cancelled error", err)
		}
	case <-time.After(runlockTimeout):
		t.Fatal("sshRun did not return after context cancellation")
	}

	// A pre-cancelled context refuses the next command outright; the peer must
	// not see it.
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	before := len(srv.recorded())
	if _, err := w.sshRun(ctx2, addr, "runlock", clientPEM, "echo ok && hostname"); err == nil || !strings.Contains(err.Error(), "deployment cancelled") {
		t.Fatalf("sshRun with pre-cancelled ctx: got %v, want deployment cancelled error", err)
	}
	if got := len(srv.recorded()); got != before {
		t.Errorf("pre-cancelled sshRun reached the remote peer (%d new commands)", got-before)
	}
}

// ── run fence on unconfirmed remote termination ──────────────────────────────

// fenceWithUnconfirmedTermination drives a wizard into the fenced state: a run
// is cancelled mid-command while the fake peer holds the session open, with
// the drain timer forced to fire immediately, so no session result surfaces —
// the remote outcome stays unconfirmed and the run fence is installed on
// drain.
func fenceWithUnconfirmedTermination(t *testing.T, srv *fakeSSHServer, w *Wizard, addr, clientPEM string) {
	t.Helper()
	origTimer := sshCancelDrainTimer
	sshCancelDrainTimer = func() <-chan time.Time {
		ch := make(chan time.Time)
		close(ch)
		return ch
	}
	defer func() { sshCancelDrainTimer = origTimer }()

	if err := w.Begin(context.Background(), runlockTestNodes(addr, clientPEM)); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	waitForExec(t, srv, installGate)

	// CancelDeploy: Reset cancels mid-command and drains. Remote termination
	// stays unconfirmed, so the fence must be held when the drain completes.
	w.Reset()
	waitDrained(t, w)
}

// TestUnconfirmedRemoteTerminationHoldsFence: when Reset cancels a run while
// a destructive remote command is in flight and the transport teardown never
// surfaces a session result, the remote process's termination is unconfirmed.
// The run fence must then be held on drain: Begin refuses with
// ErrDeployUnreconciled (no subsequent run may overlap surviving remote work)
// until AcknowledgeReconciled — the explicit operator acknowledgment — clears
// it. Ordinary Reset calls and start retries must NOT clear the fence.
func TestUnconfirmedRemoteTerminationHoldsFence(t *testing.T) {
	srv, addr, hostPub, clientPEM := newFakeSSHServer(t)
	w := newRunlockTestWizard(t, hostPub)

	fenceWithUnconfirmedTermination(t, srv, w, addr, clientPEM)

	if err := w.Begin(context.Background(), runlockTestNodes(addr, clientPEM)); !errors.Is(err, ErrDeployUnreconciled) {
		t.Fatalf("Begin while fenced: got %v, want ErrDeployUnreconciled", err)
	}
	if st := w.StatusState().Status; st != "failed" {
		t.Errorf("fenced run status = %q, want failed (terminal state recorded)", st)
	}

	// Ordinary Reset (the StartDeploy pre-Begin reset AND the CancelDeploy
	// path) is cancellation/state reset, NOT reconciliation: the drained run's
	// fence survives it.
	w.Reset()
	if err := w.Begin(context.Background(), runlockTestNodes(addr, clientPEM)); !errors.Is(err, ErrDeployUnreconciled) {
		t.Fatalf("Begin after ordinary Reset: got %v, want ErrDeployUnreconciled (Reset must not acknowledge)", err)
	}

	// Concurrent Reset callers cannot acknowledge after the drain either.
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.Reset()
		}()
	}
	wg.Wait()
	if err := w.Begin(context.Background(), runlockTestNodes(addr, clientPEM)); !errors.Is(err, ErrDeployUnreconciled) {
		t.Fatalf("Begin after concurrent Resets: got %v, want ErrDeployUnreconciled", err)
	}

	// The explicit acknowledgment is the only fence-clearing path; Begin is
	// accepted again afterwards.
	if err := w.AcknowledgeReconciled(); err != nil {
		t.Fatalf("AcknowledgeReconciled: %v", err)
	}
	if err := w.Begin(context.Background(), runlockTestNodes(addr, clientPEM)); err != nil {
		t.Fatalf("Begin after AcknowledgeReconciled: %v, want accepted", err)
	}
	w.Reset()
	waitDrained(t, w)
}

// TestStartDeployResetBeginPreservesUnreconciledFence pins the documented r2
// HOLD: the StartDeploy → Reset → Begin sequence on a fenced wizard must keep
// refusing with ErrDeployUnreconciled — an ordinary start retry clears nothing.
func TestStartDeployResetBeginPreservesUnreconciledFence(t *testing.T) {
	srv, addr, hostPub, clientPEM := newFakeSSHServer(t)
	w := newRunlockTestWizard(t, hostPub)

	fenceWithUnconfirmedTermination(t, srv, w, addr, clientPEM)

	// The handler's exact StartDeploy sequence against the fence.
	w.Reset()
	if err := w.Begin(context.Background(), runlockTestNodes(addr, clientPEM)); !errors.Is(err, ErrDeployUnreconciled) {
		t.Fatalf("StartDeploy Reset;Begin over the fence: got %v, want ErrDeployUnreconciled", err)
	}
}

// TestAcknowledgeReconciledRefusedWhileRunActive: reconciliation is meaningful
// only once the run has drained — the explicit acknowledgment must refuse an
// active run instead of clearing anything mid-flight.
func TestAcknowledgeReconciledRefusedWhileRunActive(t *testing.T) {
	srv, addr, hostPub, clientPEM := newFakeSSHServer(t)
	w := newRunlockTestWizard(t, hostPub)

	if err := w.Begin(context.Background(), runlockTestNodes(addr, clientPEM)); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	waitForExec(t, srv, installGate)

	if err := w.AcknowledgeReconciled(); !errors.Is(err, ErrDeployInProgress) {
		t.Fatalf("AcknowledgeReconciled during active run: got %v, want ErrDeployInProgress", err)
	}

	w.Reset()
	waitDrained(t, w)
}

// TestExitMissingErrorDuringCancelDrainHoldsFence is the r2 P1 regression: a
// cancelled client transport surfaces *ssh.ExitMissingError ("remote command
// exited without exit status or exit signal") just as promptly as a genuine
// completion delivers its exit status. The pre-fix drain consumed the result
// without examining res.err, so the resultless teardown was mistaken for
// CONFIRMED remote termination while the parked remote command had delivered
// no verdict at all. The outcome must be marked unknown and the fence held.
func TestExitMissingErrorDuringCancelDrainHoldsFence(t *testing.T) {
	srv, addr, hostPub, clientPEM := newFakeSSHServer(t)
	w := newRunlockTestWizard(t, hostPub)

	// Real (default) drain window: the transport teardown surfaces the
	// resultless session error well within it — the pre-fix code treated
	// exactly this surfacing as confirmation.
	if err := w.Begin(context.Background(), runlockTestNodes(addr, clientPEM)); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	waitForExec(t, srv, installGate)

	w.Reset()
	waitDrained(t, w)

	if !w.unknownInterrupt.Load() {
		t.Fatal("resultless teardown (ExitMissingError) did not mark the remote outcome unknown")
	}
	if err := w.Begin(context.Background(), runlockTestNodes(addr, clientPEM)); !errors.Is(err, ErrDeployUnreconciled) {
		t.Fatalf("Begin after ExitMissingError teardown: got %v, want ErrDeployUnreconciled", err)
	}
	// The step error names the unconfirmed outcome, not a plain command error.
	for _, step := range w.StatusState().Steps {
		if step.Name == "install_packages" && !strings.Contains(step.Error, "unconfirmed remote termination") {
			t.Errorf("install_packages error = %q, want unconfirmed-termination cancellation error", step.Error)
		}
	}

	if err := w.AcknowledgeReconciled(); err != nil {
		t.Fatalf("AcknowledgeReconciled: %v", err)
	}
	if err := w.Begin(context.Background(), runlockTestNodes(addr, clientPEM)); err != nil {
		t.Fatalf("Begin after acknowledgment: %v, want accepted", err)
	}
	w.Reset()
	waitDrained(t, w)
}

// TestConfirmedRemoteTerminationDoesNotFence pins the CONFIRMED side of the
// fence contract. The fake must ACTUALLY TERMINATE the in-flight command: the
// gate is released while the transport is still open, so the parked session
// delivers a real exit-status verdict and the run records it and drains
// WITHOUT cancellation — no fence, no acknowledgment needed. (The pre-fix
// version of this test left the command parked on the release channel and let
// the client's transport teardown surface a resultless *ssh.ExitMissingError,
// which the drain consumed without examining res.err — mistaking a dead
// connection for a dead remote process.)
func TestConfirmedRemoteTerminationDoesNotFence(t *testing.T) {
	// Gate ONLY the install command: releasing it lets the parked session
	// terminate with its verdict and the run fail fast on its own result.
	srv, addr, hostPub, clientPEM := newFakeSSHServer(t, installGate)
	w := newRunlockTestWizard(t, hostPub)

	if err := w.Begin(context.Background(), runlockTestNodes(addr, clientPEM)); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	waitForExec(t, srv, installGate)

	// Actual remote termination: exit-status delivered over the LIVE transport.
	srv.releaseGate()

	if status := waitForTerminalStatus(t, w); status != "failed" {
		t.Fatalf("run status = %q, want failed (remote verdict: install exit status)", status)
	}
	waitDrained(t, w)

	if w.unknownInterrupt.Load() {
		t.Error("a delivered remote verdict was flagged as an unknown outcome")
	}
	for _, step := range w.StatusState().Steps {
		if step.Name != "install_packages" {
			continue
		}
		if strings.Contains(step.Error, "deployment cancelled") {
			t.Errorf("confirmed termination recorded as cancellation: %q", step.Error)
		}
		if !strings.Contains(step.Error, "exited with status") {
			t.Errorf("install_packages error = %q, want the remote exit verdict", step.Error)
		}
	}

	// No fence: the wizard accepts a fresh run WITHOUT any acknowledgment.
	if err := w.Begin(context.Background(), runlockTestNodes(addr, clientPEM)); err != nil {
		t.Fatalf("Begin after confirmed termination: %v, want accepted without acknowledgment", err)
	}
	w.Reset()
	waitDrained(t, w)
}

// ── bounded connection establishment ─────────────────────────────────────────

// TestSSHRunStalledHandshakeIsBounded: a peer that accepts TCP but never
// performs the SSH handshake (no version exchange) must not block sshRun
// indefinitely — connection establishment returns within the ctx deadline.
func TestSSHRunStalledHandshakeIsBounded(t *testing.T) {
	srv, addr, hostPub, clientPEM := newFakeSSHServerStalled(t, true, false)
	_ = srv // peer held only via t.Cleanup; addr and keys carry the assertions
	w := newRunlockTestWizard(t, hostPub)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := w.sshRun(ctx, addr, "runlock", clientPEM, "echo ok")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("stalled handshake peer: want an error, got none")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("handshake not bounded by ctx deadline: returned after %v", elapsed)
	}
	if !strings.Contains(err.Error(), "dial "+addr) {
		t.Errorf("stalled handshake error = %v, want dial/handshake failure", err)
	}
}

// TestSSHRunStalledSessionOpenIsBounded: a peer that completes the handshake
// but never answers the session channel-open must not block sshRun
// indefinitely — session opening returns within the ctx deadline.
func TestSSHRunStalledSessionOpenIsBounded(t *testing.T) {
	srv, addr, hostPub, clientPEM := newFakeSSHServerStalled(t, false, true)
	_ = srv // peer held only via t.Cleanup; addr and keys carry the assertions
	w := newRunlockTestWizard(t, hostPub)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := w.sshRun(ctx, addr, "runlock", clientPEM, "echo ok")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("stalled session-open peer: want an error, got none")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("session open not bounded by ctx deadline: returned after %v", elapsed)
	}
	if !strings.Contains(err.Error(), "opening session") {
		t.Errorf("stalled session-open error = %v, want session-open failure", err)
	}
}

// ── locked state access ──────────────────────────────────────────────────────

// TestDeploymentStateAccessRaceFree churns Begin/Reset/State/StatusState
// concurrently while short-lived runs swap the state pointer. With the pre-fix
// unlocked w.state.Nodes reads in the step functions the swap raced the
// readers — `go test -race` is the assertion. The nodes fail fast (nonexistent
// key, closed loopback port) before any dial, so no network is involved.
func TestDeploymentStateAccessRaceFree(t *testing.T) {
	w := NewWizardWithState(&DeploymentState{Steps: make([]DeploymentStep, 0)})
	nodes := []NodeConfig{{Host: "127.0.0.1:1", Role: "standby", SSHUser: "x", SSHKey: "/nonexistent/id_ed25519"}}

	const workers = 4
	const iters = 50
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := range workers {
		go func(role int) {
			defer wg.Done()
			for range iters {
				switch role % 4 {
				case 0:
					_ = w.Begin(context.Background(), nodes) // nil or ErrDeployInProgress — both legal under churn
				case 1:
					w.Reset()
				case 2:
					_ = w.State()
				case 3:
					_ = w.StatusState()
				}
			}
		}(i)
	}
	wg.Wait()

	waitDrained(t, w)
	switch st := w.StatusState().Status; st {
	case "", "config", "deploying", "verifying", "done", "failed", "resumed":
	default:
		t.Errorf("final status %q is not a known deployment state", st)
	}
}
