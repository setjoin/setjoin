// Package deploy provides SSH-based auto-deployment of the 3-node HA mail server.
// Provisioning: PostgreSQL 18, Pgpool-II, SeaweedFS on remote nodes.
package deploy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"text/template"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/ssh"
	sharedcfg "setjoin.com/shared/config"
)

// Profile describes a deployment target.
type Profile int

const (
	Profile3Node Profile = iota
)

// DeploymentStep tracks the progress of a single deployment operation.
type DeploymentStep struct {
	Name   string `json:"name"`
	Status string `json:"status"` // "pending","running","ok","failed"
	Output string `json:"output,omitempty"`
	Error  string `json:"error,omitempty"`
}

// DeploymentState tracks the overall wizard progress.
// Concurrent access is guarded by Wizard.mu (this struct carries no lock of its own).
type DeploymentState struct {
	Profile   Profile          `json:"profile"`
	Nodes     []NodeConfig     `json:"nodes"`
	Steps     []DeploymentStep `json:"steps"`
	Status    string           `json:"status"` // "config","deploying","verifying","done","failed"
	Log       []string         `json:"log"`
	StartedAt time.Time        `json:"started_at"`
}

// NodeConfig holds connection info for a remote node.
type NodeConfig struct {
	Host     string `json:"host"`
	Role     string `json:"role"` // "primary","standby"
	SSHUser  string `json:"ssh_user"`
	SSHKey   string `json:"ssh_key"`  // path or inline
	Password string `json:"password"` // placeholder for future password auth
}

// Wizard orchestrates the HA deployment across remote nodes.
type Wizard struct {
	pool    *pgxpool.Pool
	state   *DeploymentState
	logger  *slog.Logger
	mu      sync.Mutex
	hostKey ssh.PublicKey
	// run tracks the single in-flight deployment run (Begin guard + real
	// cancellation); guarded by mu. Owned by runlock.go.
	run *deployRun
	// fenced holds the run fence after a run drained with an unconfirmed
	// remote outcome (cancelled mid-command, no session result during the
	// drain window): destructive remote work may have survived the transport
	// teardown, so Begin refuses until AcknowledgeReconciled — the EXPLICIT
	// operator acknowledgment — clears it. Ordinary Reset calls and start
	// retries never touch it (guarded by mu).
	fenced bool
	// unknownInterrupt is set by sshRun when a cancelled command's session
	// produced no result within the drain window. Begin clears it when
	// installing a run and runs are serialized, so the run goroutine can
	// attribute a set flag to its own run. Atomic: written deep inside sshRun
	// without holding mu.
	unknownInterrupt atomic.Bool
}

func NewWizard(pool *pgxpool.Pool, logger *slog.Logger) *Wizard {
	w := &Wizard{
		pool:   pool,
		state:  &DeploymentState{Steps: make([]DeploymentStep, 0)},
		logger: logger,
	}
	if keyStr := os.Getenv("DEPLOY_HOST_KEY"); keyStr != "" {
		if key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keyStr)); err == nil {
			w.hostKey = key
		}
	}
	w.loadState(context.Background())
	return w
}

// NewWizardWithState returns a Wizard seeded with an explicit DeploymentState.
// Test seam: handler-level tests use it to drive the status read surface with
// NodeConfig secret material (inline SSH keys, node passwords) without
// executing a deployment. Production startup uses NewWizard only.
func NewWizardWithState(state *DeploymentState) *Wizard {
	if state.Steps == nil {
		state.Steps = make([]DeploymentStep, 0)
	}
	return &Wizard{state: state, logger: slog.Default()}
}

func (w *Wizard) State() *DeploymentState {
	w.mu.Lock()
	defer w.mu.Unlock()
	// Deep-copy the mutated slices so the HTTP handler can json.Marshal the
	// snapshot OUTSIDE the lock. A shallow struct copy would share the
	// Steps/Log/Nodes backing arrays, and okStep/failStep mutate Steps[i] IN
	// PLACE under the lock — marshalling the shared array concurrently is a data
	// race. Element types (DeploymentStep/NodeConfig/string) are flat, so a
	// per-slice copy yields a fully independent snapshot.
	//
	// Internal accessor: the returned snapshot still carries NodeConfig secret
	// material (inline SSH keys, node passwords). The HTTP read surface must go
	// through StatusState, never through this method.
	s := *w.state
	s.Steps = append([]DeploymentStep(nil), w.state.Steps...)
	s.Log = append([]string(nil), w.state.Log...)
	s.Nodes = append([]NodeConfig(nil), w.state.Nodes...)
	return &s
}

// NodeStatus is the secret-free per-node projection served by the
// /admin/deploy/status read surface. An inline SSH key is reported only as
// HasInlineKey=true (body unrendered); a path-based key renders as KeyPath.
// SSH private-key bodies and node passwords are never serialized.
type NodeStatus struct {
	Host         string `json:"host"`
	Role         string `json:"role"`
	SSHUser      string `json:"ssh_user"`
	KeyPath      string `json:"key_path,omitempty"`
	HasInlineKey bool   `json:"has_inline_key,omitempty"`
}

// StatusState is the secret-free projection of DeploymentState for the status
// read surface: booleans/paths only — never private-key bodies or passwords.
// Step Output/Error are redacted at the sshRun source and again at the
// persistence boundary; steps restored from persisted rows have their
// free-form Output/Error withheld entirely (redactDeploymentStep), because a
// pre-redaction row's bare secrets cannot be verified at restore time.
type StatusState struct {
	Profile   Profile          `json:"profile"`
	Nodes     []NodeStatus     `json:"nodes"`
	Steps     []DeploymentStep `json:"steps"`
	Status    string           `json:"status"` // "config","deploying","verifying","done","failed","resumed"
	Log       []string         `json:"log"`
	StartedAt time.Time        `json:"started_at"`
}

// StatusState returns the secret-free projection of the current deployment
// state. Inline-key input stays supported (marked via HasInlineKey with the
// body unrendered); path-based keys render as paths only.
func (w *Wizard) StatusState() *StatusState {
	s := w.State()
	nodes := make([]NodeStatus, 0, len(s.Nodes))
	for _, n := range s.Nodes {
		ns := NodeStatus{Host: n.Host, Role: n.Role, SSHUser: n.SSHUser}
		if isInlineKeyMaterial(n.SSHKey) {
			ns.HasInlineKey = true
		} else {
			ns.KeyPath = n.SSHKey
		}
		nodes = append(nodes, ns)
	}
	return &StatusState{
		Profile:   s.Profile,
		Nodes:     nodes,
		Steps:     s.Steps,
		Status:    s.Status,
		Log:       s.Log,
		StartedAt: s.StartedAt,
	}
}

// persistStep saves a deployment step to the LOGGED table for crash-safe resumability.
// The step is scrubbed at the persistence boundary — pattern-based redaction
// plus every secret the wizard currently holds for its nodes — so no secret
// material is written to deployment_steps even if a caller failed to redact
// upstream. Called with w.mu held (okStep/failStep) or with exclusive access.
func (w *Wizard) persistStep(ctx context.Context, step DeploymentStep) {
	if w.pool == nil {
		return
	}
	step = w.scrubStep(step)
	_, err := w.pool.Exec(ctx,
		`INSERT INTO deployment_steps (step_name, status, output, error, started_at, completed_at)
		 VALUES ($1, $2, $3, $4, now(), CASE WHEN $2 IN ('done','failed') THEN now() END)
		 ON CONFLICT (step_name) DO UPDATE SET
		   status = EXCLUDED.status, output = EXCLUDED.output, error = EXCLUDED.error,
		   started_at = COALESCE(deployment_steps.started_at, EXCLUDED.started_at),
		   completed_at = CASE WHEN EXCLUDED.status IN ('done','failed') THEN now() ELSE deployment_steps.completed_at END`,
		step.Name, step.Status, step.Output, step.Error)
	if err != nil {
		w.logger.Warn("deploy: failed to persist step", "step", step.Name, "error", err)
	}
}

// loadState restores deployment state from the LOGGED table on startup.
func (w *Wizard) loadState(ctx context.Context) {
	if w.pool == nil {
		return
	}
	rows, err := w.pool.Query(ctx,
		`SELECT step_name, status, COALESCE(output,''), COALESCE(error,'') FROM deployment_steps ORDER BY step_name`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var s DeploymentStep
		if err := rows.Scan(&s.Name, &s.Status, &s.Output, &s.Error); err != nil {
			continue
		}
		// Mark any in-progress steps as failed (crashed mid-step)
		if s.Status == "running" {
			s.Status = "failed"
		}
		// Rows written before redaction landed may still carry secret material;
		// scrub at restore and WITHHOLD the unverifiable free-form body — the
		// wizard holds no node credentials here (NodeConfig is never
		// persisted), so a bare password cannot be exact-matched. Step
		// name/status metadata is retained.
		w.state.Steps = append(w.state.Steps, redactDeploymentStep(s))
	}
	if len(w.state.Steps) > 0 {
		w.state.Status = "resumed"
	}
}

// Reset clears the deployment state for a new attempt, and is the real
// cancellation path for an in-flight run (both admin callers — StartDeploy's
// pre-Begin reset and CancelDeploy — invoke it): instead of only replacing the
// status struct while the old goroutine kept issuing remote commands, it
// cancels the run context so sshRun interrupts the destructive remote step in
// flight.
//
// Semantics (reconciled start/reset/cancel contract):
//   - Reset on an ACTIVE run cancels it and DRAINS it before returning, so the
//     StartDeploy caller's Reset;Begin sequence observes an idle wizard — a
//     second start can no longer cancel the first run and then reject against
//     its own drain. The run records its terminal state and holds the run
//     fence itself when its remote outcome was unconfirmed; Reset does not
//     swap the state out from under a live run.
//   - Reset on an IDLE wizard clears the state for a fresh attempt but NEVER
//     the run fence: cancellation/reset and reconciliation acknowledgment are
//     separate concerns, so a drained run's fence survives ordinary resets
//     (the StartDeploy Reset;Begin retry sequence keeps refusing with
//     ErrDeployUnreconciled instead of clearing the fence by retrying Start,
//     and a concurrent Reset caller cannot acknowledge after the drain).
//     AcknowledgeReconciled is the only fence-clearing path.
//
// Begin never cancels anything, so a rejected start always preserves the
// active run.
func (w *Wizard) Reset() {
	w.mu.Lock()
	if !w.cancelRunLocked() {
		// Idle: clear the state for a fresh attempt. The run fence is
		// deliberately PRESERVED — clearing it requires the explicit
		// AcknowledgeReconciled acknowledgment (runlock.go).
		w.state = &DeploymentState{Steps: make([]DeploymentStep, 0)}
		w.mu.Unlock()
		return
	}
	// Active run: real cancellation issued; drain it before returning.
	run := w.run
	w.mu.Unlock()
	select {
	case <-run.done:
	case <-time.After(resetDrainTimeout):
		if w.logger != nil {
			w.logger.Warn("deploy: reset timed out waiting for run drain; Begin stays guarded until the run completes")
		}
	}
}

// Begin starts the automated deployment process. Runs are serialized: while a
// deployment is in flight, Begin returns ErrDeployInProgress and NEVER cancels
// the active run — a rejected start must preserve it (Reset is the only
// cancellation path, and it drains before returning). While the run fence is
// held (the previous run ended with unconfirmed remote termination), Begin
// returns ErrDeployUnreconciled so no subsequent run can overlap surviving
// remote work; the fence survives ordinary resets and start retries and is
// cleared only by the explicit AcknowledgeReconciled operator acknowledgment.
//
// The run's lifetime is explicitly OWNED, not borrowed from the caller: the
// ctx argument contributes only request values (context.WithoutCancel), never
// cancellation or deadlines — completing the accepted HTTP response must not
// cancel the deployment. Cancellation is real but explicit: Reset (the
// CancelDeploy path) or Close (server shutdown) halts destructive remote
// steps through the cancellation supervision in sshRun.
func (w *Wizard) Begin(ctx context.Context, nodes []NodeConfig) error {
	w.mu.Lock()
	if w.fenced {
		w.mu.Unlock()
		return ErrDeployUnreconciled
	}
	if w.inFlightLocked() {
		w.mu.Unlock()
		return ErrDeployInProgress
	}
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	run := &deployRun{cancel: cancel, done: make(chan struct{})}
	w.state = &DeploymentState{
		Profile:   Profile3Node,
		Nodes:     append([]NodeConfig(nil), nodes...),
		Steps:     make([]DeploymentStep, 0),
		Status:    "deploying",
		StartedAt: time.Now(),
	}
	w.unknownInterrupt.Store(false)
	w.run = run
	w.mu.Unlock()

	go func() {
		defer func() {
			w.mu.Lock()
			if w.run == run {
				w.run = nil
			}
			w.mu.Unlock()
			close(run.done)
		}()
		w.runDeployment(runCtx)
		// Run fence: a cancelled run whose in-flight command produced no
		// result during sshRun's drain window has an unconfirmed remote
		// outcome — destructive remote work may have survived the transport
		// teardown. Hold the fence on drain so no subsequent run overlaps it;
		// Reset is the operator acknowledgment. Runs are serialized and Begin
		// cleared unknownInterrupt when installing this run, so a set flag is
		// attributable to this run. The fence is published before run.done
		// closes (the tracker-clear defer runs last), so a drainer observes
		// it as soon as the drain completes.
		if runCtx.Err() != nil && w.unknownInterrupt.Load() {
			w.mu.Lock()
			w.fenced = true
			w.mu.Unlock()
		}
	}()
	return nil
}

// Close is the server-shutdown seam. The run's lifetime is owned by the
// wizard — never the HTTP request — so an explicit shutdown path is required
// to cancel an active run and wait for it to drain. Idempotent; a no-op on an
// idle wizard besides clearing state.
func (w *Wizard) Close() {
	w.Reset()
}

func (w *Wizard) runDeployment(ctx context.Context) {
	w.logStep("ssh_check", "SSH connectivity check")
	if err := w.checkSSH(ctx); err != nil {
		w.failStep("ssh_check", err)
		w.setStatus("failed")
		return
	}
	w.okStep("ssh_check")

	w.logStep("install_packages", "Install PostgreSQL + Pgpool-II + SeaweedFS")
	if err := w.installPackages(ctx); err != nil {
		w.failStep("install_packages", err)
		w.setStatus("failed")
		return
	}
	w.okStep("install_packages")

	w.logStep("configure_replication", "Configure streaming replication")
	if err := w.configureReplication(ctx); err != nil {
		w.failStep("configure_replication", err)
		w.setStatus("failed")
		return
	}
	w.okStep("configure_replication")

	w.logStep("configure_pgpool", "Configure Pgpool-II + watchdog")
	if err := w.configurePgpool(ctx); err != nil {
		w.failStep("configure_pgpool", err)
		w.setStatus("failed")
		return
	}
	w.okStep("configure_pgpool")

	w.logStep("configure_seaweedfs", "Configure SeaweedFS 3-node Raft")
	if err := w.configureSeaweedFS(ctx); err != nil {
		w.failStep("configure_seaweedfs", err)
		w.setStatus("failed")
		return
	}
	w.okStep("configure_seaweedfs")

	w.logStep("start_services", "Start all services")
	if err := w.startServices(ctx); err != nil {
		w.failStep("start_services", err)
		w.setStatus("failed")
		return
	}
	w.okStep("start_services")

	w.logStep("verify", "Verify cluster health")
	if err := w.verifyCluster(ctx); err != nil {
		w.failStep("verify", err)
		w.setStatus("failed")
		return
	}
	w.okStep("verify")

	w.setStatus("done")
}

// ── SSH helpers ──

const (
	// connectTimeout bounds the TCP dial and the SSH handshake when the run
	// context carries no earlier deadline.
	connectTimeout = 10 * time.Second
)

var (
	// sessionOpenTimeout bounds the session channel-open round trip when the
	// run context carries no earlier deadline. Vars (not consts) as a test
	// seam for stalled-peer tests.
	sessionOpenTimeout = 10 * time.Second
	// sshCancelDrainWait bounds how long a cancelled sshRun waits for the
	// interrupted session's result before declaring the remote outcome
	// unknown (which holds the run fence on drain).
	sshCancelDrainWait = 5 * time.Second
	// sshCancelDrainTimer is the drain deadline channel. Var seam: the
	// unknown-outcome tests substitute a channel that never fires so the
	// branch is exercised deterministically against a peer holding the
	// session open.
	sshCancelDrainTimer = func() <-chan time.Time { return time.After(sshCancelDrainWait) }
	// resetDrainTimeout bounds how long Reset waits for a cancelled run to
	// drain before giving up (the tracker stays set, so Begin remains
	// guarded until the drain completes).
	resetDrainTimeout = 10 * time.Second
)

// dialSSH establishes the SSH connection under ctx supervision. x/crypto's
// ssh.Dial bounds only the TCP dial; the SSH handshake (version and key
// exchange) would block indefinitely against a peer that accepts TCP and goes
// silent. Here the TCP dial honors ctx directly (net.Dialer.DialContext), the
// handshake is bounded by a conn deadline derived from the ctx deadline (or
// connectTimeout), and a watchdog forces the deadline the moment ctx is
// cancelled — connection establishment can no longer block the run
// indefinitely.
func dialSSH(ctx context.Context, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	bound := connectTimeout
	if dl, ok := ctx.Deadline(); ok {
		if until := time.Until(dl); until < bound {
			bound = until
		}
	}
	dialer := &net.Dialer{Timeout: bound}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	// Bound the handshake phase x/crypto leaves to the caller.
	_ = conn.SetDeadline(time.Now().Add(bound))
	handshakeDone := make(chan struct{})
	defer close(handshakeDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now()) // break pending handshake I/O now
		case <-handshakeDone:
		}
	}()
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		return nil, err
	}
	// Handshake complete: long-running sessions must not inherit the connect
	// deadline. (conn is the net.Conn this function dialed; NewClientConn
	// wrapped, not replaced, it.)
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
}

// openSession opens the SSH session channel under ctx supervision with a
// deadline: a peer that completes the handshake but never answers the
// channel-open request must not block the run indefinitely. The client is
// closed on abandonment so the pending open cannot leak.
func openSession(ctx context.Context, client *ssh.Client, host string) (*ssh.Session, error) {
	type opened struct {
		session *ssh.Session
		err     error
	}
	ch := make(chan opened, 1)
	go func() {
		s, err := client.NewSession()
		ch <- opened{session: s, err: err}
	}()
	select {
	case res := <-ch:
		if res.err != nil {
			return nil, fmt.Errorf("open session to %s: %w", host, res.err)
		}
		return res.session, nil
	case <-ctx.Done():
		_ = client.Close()
		return nil, fmt.Errorf("deployment cancelled opening session to %s: %w", host, ctx.Err())
	case <-time.After(sessionOpenTimeout):
		_ = client.Close()
		return nil, fmt.Errorf("opening session to %s timed out", host)
	}
}

// sshRun runs cmd on the remote host and returns its output. The returned
// output is ALWAYS redacted (private-key blocks, caller-supplied extra secrets,
// echoed pgpool health-check passwords, every secret the wizard holds for its
// nodes — inline key bodies and node passwords —, length-bounded): this is the
// single choke point through which remote output reaches errors, logs, and
// persisted step rows, and successful verification output is logged by callers
// WITHOUT failStep's additional scrub, so the wizard-held secrets are
// snapshotted under the lock here and redacted before truncation/return.
// extraSecrets are exact secret strings known to the caller (e.g. the
// generated pgpool health-check password) and are scrubbed wherever they
// occur in the output.
//
// The returned error is scrubbed with the SAME COMPLETE secret set (caller
// extras, inline key body, wizard-held node credentials): SSH error text is
// remote-influenced — an exit-signal reason ("Reason was: ...") or an sshd
// message can echo back material the target host has seen, e.g. the generated
// pgpool health-check password — and upstream failStep knows only the node
// secrets, not the caller extras. The redacted text replaces the error value
// (errors.New): no in-package consumer unwraps x/crypto error identity, and
// keeping the raw error in the wrap chain would re-disclose the secret.
//
// Connection establishment (TCP dial, SSH handshake, session open) and the
// command itself are all under ctx supervision with deadlines — no phase can
// block indefinitely against a stalled peer (D-MAILSERVER-INTERNAL-DEPLOY-R-002).
//
// Cancellation: ctx is consumed (D-MAILSERVER-INTERNAL-DEPLOY-R-002). A
// cancelled context refuses the next remote command outright and interrupts
// the command already executing by closing the SSH client transport — the
// session dies with the connection, so destructive remote steps halt instead
// of running to completion. An interrupted command's outcome is only fully
// known on the target host: if the transport teardown surfaces the session
// result within sshCancelDrainWait, the remote process's termination counts as
// confirmed ONLY when the result carries an actual remote verdict (a concrete
// exit status or exit signal — *ssh.ExitError — or a clean zero exit); a
// resultless teardown (*ssh.ExitMissingError) or a transport error says the
// CONNECTION died, not that the remote process did. Missing-exit/transport
// outcomes mark the outcome unknown — as does no surfaced result at all — and
// the run holds the run fence on drain (Begin refuses until
// AcknowledgeReconciled acknowledges reconciliation) so a subsequent run
// cannot overlap surviving remote work.
func (w *Wizard) sshRun(ctx context.Context, host, user, keyPath, cmd string, extraSecrets ...string) (string, error) {
	// Snapshot the COMPLETE secret set once, before any remote contact: the
	// caller's exact extras (e.g. the generated pgpool health-check password),
	// the inline key body this call may hold, and a fresh snapshot of the
	// wizard's node credentials (inline key bodies, node passwords) taken under
	// the lock. The SAME COMPLETE set scrubs both the output and the error —
	// failStep only knows node secrets, so a caller extra could survive in an
	// unredacted error. Redaction happens inside RedactOutput BEFORE
	// truncation, so a secret crossing the truncation boundary cannot survive
	// as a fragment.
	if isInlineKeyMaterial(keyPath) {
		extraSecrets = append(append([]string(nil), extraSecrets...), strings.TrimSpace(keyPath))
	}
	w.mu.Lock()
	extraSecrets = append(extraSecrets, w.knownSecrets()...)
	w.mu.Unlock()
	output, err := w.sshRunUnredacted(ctx, host, user, keyPath, cmd)
	if err != nil {
		err = errors.New(RedactOutput(err.Error(), extraSecrets...))
	}
	return RedactOutput(output, extraSecrets...), err
}

// remoteTerminationConfirmed reports whether err carries ACTUAL remote
// termination evidence for a session result surfaced during the cancel-drain
// window. A clean zero exit (nil) and *ssh.ExitError (the remote sshd
// delivered a concrete exit status or exit signal — the process ended, by
// completion or by signal) are evidence. *ssh.ExitMissingError — exactly what
// a client transport teardown surfaces when the command was still running —
// and transport/IO errors are NOT: they prove the connection died, nothing
// about the remote process.
func remoteTerminationConfirmed(err error) bool {
	if err == nil {
		return true
	}
	var exitErr *ssh.ExitError
	return errors.As(err, &exitErr)
}

// sshRunUnredacted is the raw SSH execution body: it returns UNREDACTED
// output and error — sshRun is the only caller and owns the redaction
// boundary. Cancellation supervision and the drain-window termination
// evidence check live here (D-MAILSERVER-INTERNAL-DEPLOY-R-002).
func (w *Wizard) sshRunUnredacted(ctx context.Context, host, user, keyPath, cmd string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("deployment cancelled before %s: %w", host, err)
	}
	key, err := readPrivateKey(keyPath)
	if err != nil {
		return "", fmt.Errorf("read key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("parse key: %w", err)
	}
	if w.hostKey == nil {
		return "", fmt.Errorf("no DEPLOY_HOST_KEY configured — refusing to connect without SSH host key")
	}
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(w.hostKey),
		Timeout:         connectTimeout,
	}
	addr := host + ":22"
	if strings.Contains(host, ":") {
		addr = host
	}
	client, err := dialSSH(ctx, addr, config)
	if err != nil {
		return "", fmt.Errorf("dial %s: %w", host, err)
	}
	defer func() { _ = client.Close() }()

	session, err := openSession(ctx, client, host)
	if err != nil {
		return "", err
	}
	defer func() { _ = session.Close() }()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	// Run the command under ctx supervision. The buffers belong to the runner
	// goroutine alone until its result is delivered on the channel, so a
	// cancelled caller never races a still-running session on them.
	type sshResult struct {
		output string
		err    error
	}
	resCh := make(chan sshResult, 1)
	go func() {
		runErr := session.Run(cmd)
		out := stdout.String()
		if stderr.Len() > 0 {
			out += "\n[stderr]\n" + stderr.String()
		}
		resCh <- sshResult{output: out, err: runErr}
	}()

	var output string
	select {
	case res := <-resCh:
		err = res.err
		output = res.output
	case <-ctx.Done():
		// Real cancellation: closing the client tears down the transport,
		// which interrupts the remote command already executing.
		_ = client.Close()
		select {
		case res := <-resCh:
			output = res.output
			// A surfaced result is termination evidence ONLY when it
			// carries an actual remote verdict. Closing the client while
			// the command was still running surfaces *ssh.ExitMissingError
			// just as promptly as a genuinely completed session delivers
			// its exit status — consuming the result without examining
			// res.err would mistake a dead transport for a dead remote
			// process. Missing-exit/transport outcomes stay unconfirmed:
			// mark them so the run holds the fence on drain.
			if !remoteTerminationConfirmed(res.err) {
				w.unknownInterrupt.Store(true)
				err = fmt.Errorf("deployment cancelled during %s with unconfirmed remote termination (%v): %w", host, res.err, ctx.Err())
				break
			}
			err = fmt.Errorf("deployment cancelled during %s: %w", host, ctx.Err())
		case <-sshCancelDrainTimer():
			// Transport teardown did not surface a session result: whether
			// the remote destructive process terminated is unknown from this
			// host. Mark it so the run holds the fence on drain.
			w.unknownInterrupt.Store(true)
			err = fmt.Errorf("deployment cancelled during %s with unconfirmed remote termination: %w", host, ctx.Err())
			return "", err
		}
	}
	return output, err
}

func readPrivateKey(path string) ([]byte, error) {
	// Accept inline keys (starting with "-----BEGIN") or file paths
	if isInlineKeyMaterial(path) {
		return []byte(path), nil
	}
	return sshKeyBytes(path), nil // simplified: assume path reads correctly
}

func sshKeyBytes(path string) []byte {
	//nolint:gosec // G304: path is the admin-configured SSH key path from NodeConfig (deploy wizard target), not user/request input
	b, err := os.ReadFile(path)
	if err != nil {
		return []byte{}
	}
	return b
}

// randomHex generates n hex characters of cryptographic randomness. Var seam:
// the exit-signal error-scrub tests pin the generated pgpool health-check
// password to a known fixture so the fake SSH peer can echo it back through
// the remote-controlled exit-signal reason.
var randomHex = func(n int) string {
	b := make([]byte, n/2)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand.Read failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// ── Deployment steps ──

func (w *Wizard) checkSSH(ctx context.Context) error {
	for _, n := range w.currentNodes() {
		if n.Role == "primary" && n.Host == "localhost" {
			continue // skip self
		}
		out, err := w.sshRun(ctx, n.Host, n.SSHUser, n.SSHKey, "echo ok && hostname")
		if err != nil {
			return fmt.Errorf("SSH %s: %w — output: %s", n.Host, err, out)
		}
		w.logger.Info("SSH OK", "host", n.Host)
	}
	return nil
}

func (w *Wizard) installPackages(ctx context.Context) error {
	// Resolve the pinned, checksum-verified SeaweedFS artifact once, before any
	// node is contacted: an unresolvable pin refuses the whole install step
	// before any remote root execution (D-MAILSERVER-INTERNAL-DEPLOY-R-003).
	weedInstall, err := buildSeaweedFSInstallCommand()
	if err != nil {
		return fmt.Errorf("seaweedfs artifact pin: %w", err)
	}
	for _, n := range w.currentNodes() {
		if n.Role == "primary" && n.Host == "localhost" {
			continue
		}
		cmd := "apt-get update && apt-get install -y postgresql-18 pgpool2 && " + weedInstall
		out, err := w.sshRun(ctx, n.Host, n.SSHUser, n.SSHKey, cmd)
		if err != nil {
			return fmt.Errorf("install %s: %w\n%s", n.Host, err, out)
		}
		w.logger.Info("packages installed", "host", n.Host)
	}
	return nil
}

// buildReplicationCommands returns shell commands to set up streaming replication
// on each standby node. Commands are executed sequentially via sshRun.
func buildReplicationCommands(primaryHost string, standbyHosts []string) []string {
	var cmds []string
	for range standbyHosts {
		cmds = append(cmds,
			fmt.Sprintf("systemctl stop postgresql"),
			fmt.Sprintf("rm -rf /var/lib/postgresql/18/main"),
			fmt.Sprintf("pg_basebackup -h %s -D /var/lib/postgresql/18/main -U replicator -P -X stream", primaryHost),
			fmt.Sprintf("touch /var/lib/postgresql/18/main/standby.signal"),
			fmt.Sprintf("echo 'primary_conninfo = host=%s port=5432 user=replicator' >> /var/lib/postgresql/18/main/postgresql.auto.conf", primaryHost),
			fmt.Sprintf("systemctl start postgresql"),
		)
	}
	return cmds
}

func (w *Wizard) configureReplication(ctx context.Context) error {
	nodes := w.currentNodes()
	var primary string
	var standbys []string
	for _, n := range nodes {
		if n.Role == "primary" {
			primary = n.Host
		} else {
			standbys = append(standbys, n.Host)
		}
	}
	if primary == "" {
		return fmt.Errorf("no primary node found")
	}
	if len(standbys) == 0 {
		w.logger.Info("no standbys to configure, skipping replication")
		return nil
	}

	cmds := buildReplicationCommands(primary, standbys)
	for i, standby := range standbys {
		base := i * 6
		for j, cmd := range cmds[base : base+6] {
			out, err := w.sshRun(ctx, standby, nodes[0].SSHUser, nodes[0].SSHKey, cmd)
			if err != nil {
				return fmt.Errorf("replication step %d on %s: %w\n%s", j, standby, err, out)
			}
			w.logger.Info("replication", "standby", standby, "step", j, "output", out)
		}
	}
	return nil
}

// wizardFailoverScript mirrors mailserver/deploy/failover.sh.template
// byte-for-byte (pinned by TestWizardFailoverScript_MatchesShippedTemplate in
// failover_host_identity_test.go): the wizard installs the SAME reviewed
// script the template documents, never a divergent copy. Host-identity policy
// lives in this script (strict known_hosts pinning, BatchMode) — the
// wizard-embedded pgpool config only delegates to it.
const wizardFailoverScript = `#!/bin/bash
# Pgpool-II failover script — promotes a standby to primary.
# Called by Pgpool-II when the primary backend fails.
# Arguments from Pgpool-II:
#   %d = failed backend node id
#   %P = old primary node id
#   %H = new primary hostname
#   %R = old primary port
#
# Host-identity policy (fail closed, D-MAILSERVER-DEPLOY-002): the SSH client
# trusts ONLY peer host keys pre-provisioned in /etc/pgpool2/known_hosts.
# StrictHostKeyChecking=yes refuses unknown or substituted keys instead of
# accepting them (TOFU/accept-new is deliberately rejected), and BatchMode=yes
# disables every interactive prompt, so an unattended failover toward an
# unauthenticated or spoofed host fails, is logged, and returns nonzero to
# pgpool instead of hanging or silently promoting an impostor. The wizard
# provisions /etc/pgpool2/known_hosts in this same deployment step from the
# operator-pinned deployment host key (see buildPgpoolKnownHosts); the
# install.sh HA leg provisions it from operator-verified host keys instead.

FAILED_NODE=$1
OLD_PRIMARY=$2
NEW_HOST=$3
# shellcheck disable=SC2034  # OLD_PORT documents pgpool's %R argument position
OLD_PORT=$4

LOG="/var/log/pgpool/failover.log"
PGCTL="/usr/lib/postgresql/18/bin/pg_ctl"
PGDATA="/var/lib/postgresql/18/main"
KNOWN_HOSTS="/etc/pgpool2/known_hosts"

echo "$(date): Failover triggered — failed=$FAILED_NODE old=$OLD_PRIMARY new=$NEW_HOST" >> "$LOG"

# Promote the new primary
if [ "$NEW_HOST" = "$(hostname -f)" ] || [ "$NEW_HOST" = "$(hostname)" ] || [ "$NEW_HOST" = "localhost" ]; then
    echo "$(date): Promoting local PostgreSQL to primary" >> "$LOG"
    if "$PGCTL" promote -D "$PGDATA" >> "$LOG" 2>&1; then
        echo "$(date): Promote successful" >> "$LOG"
        exit 0
    else
        echo "$(date): Promote FAILED" >> "$LOG"
        exit 1
    fi
else
    echo "$(date): Promoting remote PostgreSQL on $NEW_HOST" >> "$LOG"
    if ssh -o StrictHostKeyChecking=yes \
           -o UserKnownHostsFile="$KNOWN_HOSTS" \
           -o GlobalKnownHostsFile="$KNOWN_HOSTS" \
           -o BatchMode=yes \
           -o ConnectTimeout=5 \
           "root@$NEW_HOST" \
           "$PGCTL promote -D $PGDATA" >> "$LOG" 2>&1; then
        echo "$(date): Remote promote successful" >> "$LOG"
        exit 0
    else
        echo "$(date): Remote promote FAILED" >> "$LOG"
        exit 1
    fi
fi
`

// buildPgpoolKnownHosts renders the /etc/pgpool2/known_hosts trust anchor for
// the failover script's SSH client: one entry per node host, carrying the
// pinned deployment host key the operator supplied (DEPLOY_HOST_KEY). This is
// VERIFIED input by construction — every node connection this deployment
// makes authenticates against exactly that key (sshRun's FixedHostKey), so a
// deployment that reached the pgpool step has proven each node presents it.
// The builder fails closed: no pinned key or an empty host list refuses to
// write an anchor from unverified input.
func buildPgpoolKnownHosts(hosts []string, key ssh.PublicKey) (string, error) {
	if key == nil {
		return "", fmt.Errorf("no pinned deployment host key — refusing to write /etc/pgpool2/known_hosts from unverified input")
	}
	seen := make(map[string]bool, len(hosts))
	var b strings.Builder
	for _, h := range hosts {
		host := strings.TrimSpace(h)
		if host == "" {
			return "", fmt.Errorf("empty node host in deployment inventory — refusing to write /etc/pgpool2/known_hosts")
		}
		if seen[host] {
			continue
		}
		seen[host] = true
		b.WriteString(host)
		b.WriteString(" ")
		b.WriteString(string(ssh.MarshalAuthorizedKey(key)))
	}
	if b.Len() == 0 {
		return "", fmt.Errorf("no node hosts to pin — refusing to write an empty /etc/pgpool2/known_hosts")
	}
	return b.String(), nil
}

// pgpoolNodePaths are the per-node paths configurePgpool provisions. The
// wizard and the shipped templates install the same artifacts at the same
// paths on both deployment tracks.
const (
	pgpoolFailoverScriptPath = "/etc/pgpool2/failover.sh"
	pgpoolKnownHostsPath     = "/etc/pgpool2/known_hosts"
	pgpoolConfPath           = "/etc/pgpool2/pgpool.conf"
)

func (w *Wizard) configurePgpool(ctx context.Context) error {
	nodes := w.currentNodes()
	tmpl, err := template.New("pgpool").Parse(pgpoolConfigTemplate)
	if err != nil {
		return fmt.Errorf("pgpool template parse: %w", err)
	}

	// Provision the failover trust anchor from the pinned deployment host key
	// BEFORE any node is contacted (fail closed on unverified input). Entries
	// cover every node host (the pgpool %H argument is one of them), so the
	// failover script's strict SSH client always has the peer it may promote.
	nodeHosts := make([]string, 0, len(nodes))
	for _, n := range nodes {
		nodeHosts = append(nodeHosts, n.Host)
	}
	knownHosts, err := buildPgpoolKnownHosts(nodeHosts, w.hostKey)
	if err != nil {
		return fmt.Errorf("pgpool failover provisioning: %w", err)
	}

	// Generate one shared password for all nodes. Every pgpool.conf must use the
	// same health_check_password so that they can authenticate the 'pgpool' PG
	// user created on the primary during provisioning.
	pgpoolPass := randomHex(32)

	for i, n := range nodes {
		peers := make([]string, 0, 2)
		for j, p := range nodes {
			if j != i {
				peers = append(peers, p.Host)
			}
		}
		data := map[string]string{
			"MyHost":     n.Host,
			"Node1":      nodes[0].Host,
			"Node2":      nodes[1].Host,
			"Node3":      nodes[2].Host,
			"Peer1":      peers[0],
			"Peer2":      peers[1],
			"PgpoolPass": pgpoolPass,
		}
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, data); err != nil {
			return fmt.Errorf("pgpool template exec for %s: %w", n.Host, err)
		}

		// Upload config via SSH heredoc, then restart pgpool. The reviewed
		// failover script (0700 root-owned) and its known_hosts trust anchor
		// (0644 root-owned, operator-pinned host keys only) are installed in
		// the SAME step, before pgpool restarts with a failover_command that
		// delegates to the script (D-MAILSERVER-DEPLOY-002 provisioning); any
		// failed install step aborts before the restart
		// (buildPgpoolNodeInstallCmd, med-deploy-ssh-host-identity-b1r2-002).
		// pgpoolPass is passed as an exact extra secret so an echo of the
		// heredoc payload in the remote output can never retain the generated
		// password.
		cmd := buildPgpoolNodeInstallCmd(
			pgpoolFailoverScriptPath,
			wizardFailoverScript,
			pgpoolKnownHostsPath,
			knownHosts,
			pgpoolConfPath,
			buf.String(),
		)
		// Live command-text gate: the uploaded command must abort before the
		// restart on any failed install step (fail closed on a builder
		// regression, before this node's restart can mask an install failure).
		if err := checkRemoteInstallFailureOrdering(cmd, "systemctl restart pgpool2"); err != nil {
			return fmt.Errorf("pgpool install command failure-ordering gate for %s: %w", n.Host, err)
		}
		out, err := w.sshRun(ctx, n.Host, n.SSHUser, n.SSHKey, cmd, pgpoolPass)
		if err != nil {
			return fmt.Errorf("pgpool config upload to %s: %w (output: %s)", n.Host, err, out)
		}
		w.logger.Info("pgpool config deployed", "host", n.Host, "size", buf.Len())
	}
	return nil
}

// gatewayS3Credentials reads the S3 client credential pair the GATEWAY (the
// process hosting this wizard) is configured with — the pair the gateway's
// blob client actually authenticates with. The gateway resolves its S3
// credentials through internal/config (config.go): a koanf merge of
// defaults → SETJOIN_CONFIG YAML → environment, after which the legacy
// MINIO_ACCESS_KEY/MINIO_SECRET_KEY variables are consulted only when the
// merged value is empty. Reading the process environment alone (the pre-r4
// behavior) deploys a DIFFERENT pair than the gateway authenticates with
// whenever the YAML file pins one pair while legacy MINIO_* carries another
// (the r4 HOLD scenario: YAML A + MINIO_* B + no S3_* env → gateway uses A,
// wizard deploys B). Var seam: tests substitute the pair.
var gatewayS3Credentials = func() (accessKey, secretKey string, ok bool) {
	accessKey, secretKey = resolveGatewayS3Credentials()
	return accessKey, secretKey, accessKey != "" && secretKey != ""
}

// resolveGatewayS3Credentials resolves the pair through the SAME merge
// contract the gateway's loader applies. internal/config is importable from
// this package without a cycle, but its Load runs the gateway's full
// configuration validation (DB_DSN, JWT_SECRET, ...), which is not part of
// the credential handoff and would couple this step to unrelated
// prerequisites. The merge itself, however, is delegated by internal/config
// to shared/config.Load (config.go:406) — so the resolution below runs that
// same engine over the same file path (SETJOIN_CONFIG), the same delimiter,
// and the same s3.access_key/s3.secret_key defaults (both "" in the gateway's
// defaults map), then mirrors config.go's MINIO_* fallback verbatim. The
// precedence-matrix test in seaweedfs_s3_config_test.go pins the result
// against internal/config.Load's resolved S3AccessKey/S3SecretKey for every
// layering combination, so any divergence between this slice and the
// gateway's loader fails a test. Read-only: no config state is mutated.
//
// A SETJOIN_CONFIG file that cannot be read or parsed fails the gateway's own
// boot too, so no resolved pair exists to hand off — both keys resolve empty
// and the caller refuses the deployment before any node is contacted.
func resolveGatewayS3Credentials() (accessKey, secretKey string) {
	k, err := sharedcfg.Load(map[string]interface{}{
		"s3.access_key": "",
		"s3.secret_key": "",
	}, sharedcfg.Options{
		FilePath:  os.Getenv("SETJOIN_CONFIG"),
		EnvPrefix: "",
		Delimiter: ".",
	})
	if err != nil {
		return "", ""
	}
	// Legacy MINIO_* fallback in the exact precedence internal/config applies
	// (config.go): consulted only when the merged value is empty, per field.
	accessKey = k.String("s3.access_key")
	if v := os.Getenv("MINIO_ACCESS_KEY"); accessKey == "" && v != "" {
		accessKey = v
	}
	secretKey = k.String("s3.secret_key")
	if v := os.Getenv("MINIO_SECRET_KEY"); secretKey == "" && v != "" {
		secretKey = v
	}
	return accessKey, secretKey
}

// configureSeaweedFS provisions the 3-node SeaweedFS raft WITH its S3
// identity config (D-MAILSERVER-DEPLOY-001): each node gets the GATEWAY'S S3
// client identity rendered to SeaweedfsS3ConfigPath (root:mail 0640 — the
// unit runs weed as User=mail) and a systemd unit that loads it via
// -s3.config. The gateway's pair backs every node's config so any node's S3
// gateway accepts the credential the gateway's blob client actually
// authenticates with.
//
// Credential handoff (med-deploy-s3-credentials-b1r2-001): the deployed
// identity IS the gateway's configured S3 client pair, resolved through the
// gateway's own merge contract (internal/config: defaults → SETJOIN_CONFIG
// YAML → environment, legacy MINIO_* only when the merged value is empty —
// see gatewayS3Credentials) — lockstep by construction, in the same run.
// The wizard NEVER regenerates the pair: re-running a deployment reuses
// the same identity, so an existing gateway keeps working across runs without
// any cross-process coordination (server-only regeneration was the r2 HOLD:
// it stranded the gateway with a stale credential). Rotation is EXPLICIT and
// lives on the gateway config surface: rotate S3_ACCESS_KEY/S3_SECRET_KEY in
// config.env (install.sh --force does exactly this), restart the gateway, and
// re-run the deployment — the next run deploys the new pair to every node.
// Refusals, both before any node is contacted: a gateway with NO S3
// credentials configured (deploying a node-only identity no consumer shares
// would recreate the dual-identity defect), and a well-known/empty gateway
// pair (RenderSeaweedfsS3Config → ValidateS3IdentitiesConfig deployment-time
// rejection). Unlike pgpoolPass — generated per run because its consumers are
// only the configs written in the same run — the S3 pair has an EXTERNAL
// consumer (the gateway), which is exactly why it must not be regenerated
// here.
func (w *Wizard) configureSeaweedFS(ctx context.Context) error {
	nodes := w.currentNodes()
	nodeIPs := make([]string, len(nodes))
	for i, n := range nodes {
		nodeIPs[i] = n.Host
	}

	// The gateway's configured S3 client identity. The pair is passed to every
	// sshRun as an exact extra secret so an echo of the heredoc payload in
	// remote output can never retain it.
	s3AccessKey, s3SecretKey, ok := gatewayS3Credentials()
	if !ok {
		return fmt.Errorf("seaweedfs s3 identity (no node contacted): the gateway has no S3 client credentials configured (S3_ACCESS_KEY/S3_SECRET_KEY in its config.env, or s3.access_key/s3.secret_key in its SETJOIN_CONFIG YAML) — refusing to deploy a node-only identity no consumer shares; configure the gateway's S3 credentials first, then re-run the deployment")
	}
	s3Config, err := RenderSeaweedfsS3Config(s3AccessKey, s3SecretKey)
	if err != nil {
		return fmt.Errorf("seaweedfs s3 identity (no node contacted): %w", err)
	}

	plan := HaPlan{
		Nodes:           nodeIPs,
		ReplicationMode: "001",
		VolumePath:      "/data/seaweedfs",
		S3Port:          9000,
		MasterPort:      9333,
		MaxVolumes:      100,
		Rack:            "rack1",
	}
	configs := BuildHaConfig(plan)

	for i, cfg := range configs {
		unit := GenerateSystemdUnit(cfg)
		n := nodes[i]

		// Upload the S3 identity config and the systemd unit in one SSH step:
		// the unit restarts only after the config it -s3.config-loads is in
		// place, and any failed install step aborts before the restart (see
		// buildSeaweedFSNodeInstallCmd). The heredoc delimiter is quoted, so
		// the JSON's $-free body is not shell-expanded.
		cmd := buildSeaweedFSNodeInstallCmd(
			SeaweedfsS3ConfigPath,
			strings.TrimRight(s3Config, "\n"),
			SeaweedfsS3ConfigGroup,
			seaweedfsSystemdUnitPath,
			unit,
		)
		// Live command-text gate: the uploaded command must abort before the
		// restart on any failed install step (fail closed on a builder
		// regression, before any node is contacted).
		if err := checkRemoteInstallFailureOrdering(cmd, "systemctl restart seaweedfs"); err != nil {
			return fmt.Errorf("seaweedfs install command failure-ordering gate (no node contacted): %w", err)
		}
		out, err := w.sshRun(ctx, n.Host, n.SSHUser, n.SSHKey, cmd, s3AccessKey, s3SecretKey)
		if err != nil {
			return fmt.Errorf("seaweedfs config upload to %s: %w (output: %s)", n.Host, err, out)
		}
		w.logger.Info("seaweedfs config deployed", "host", n.Host)
	}

	// Run post-deploy commands on the first master node
	masterHost := nodes[0]
	for _, shellCmd := range BuildPostDeployCommands(plan) {
		out, err := w.sshRun(ctx, masterHost.Host, masterHost.SSHUser, masterHost.SSHKey, shellCmd)
		if err != nil {
			w.logger.Warn("post-deploy command failed (non-fatal)", "cmd", shellCmd, "error", err, "output", out)
		}
	}

	return nil
}

// seaweedfsSystemdUnitPath is the per-node path the wizard installs the
// SeaweedFS systemd unit to.
const seaweedfsSystemdUnitPath = "/etc/systemd/system/seaweedfs.service"

// buildSeaweedFSNodeInstallCmd renders the per-node SeaweedFS provisioning
// command: create the config directory, install the S3 identity config
// (root:group 0640) and the systemd unit, then activate the service.
//
// Failure ordering (med-deploy-s3-credentials-b1r2-001 item b): the script
// runs under set -e and every pre-activation step is a SINGLE SIMPLE COMMAND
// on its own line, so any failed install step aborts the command before the
// restart — a failed identity-file install can never be masked by a
// successful restart of a pre-existing unit. AND-OR lists are deliberately
// not used mid-script: under set -e only the FINAL command of a && / ||
// list terminates the script on failure, so a failing `chown x && chmod x`
// would silently continue into the restart — the exact pre-fix defect.
func buildSeaweedFSNodeInstallCmd(s3ConfigPath, s3ConfigBody, group, unitPath, unit string) string {
	return "set -e\n" +
		"install -d -o root -g " + group + " -m 0750 " + filepath.Dir(s3ConfigPath) + "\n" +
		"cat > " + s3ConfigPath + " << 'ENDOFS3CONFIG'\n" + s3ConfigBody + "\nENDOFS3CONFIG\n" +
		"chown root:" + group + " " + s3ConfigPath + "\n" +
		"chmod 0640 " + s3ConfigPath + "\n" +
		"cat > " + unitPath + " << 'ENDOFUNIT'\n" + unit + "\nENDOFUNIT\n" +
		"systemctl daemon-reload\n" +
		"systemctl enable seaweedfs\n" +
		"systemctl restart seaweedfs"
}

// buildPgpoolNodeInstallCmd renders the per-node pgpool provisioning command:
// create /etc/pgpool2, install the reviewed failover script (0700 root:root)
// and the known_hosts trust anchor (0644 root:root), rewrite pgpool.conf
// (root:postgres 0640 — no longer world-readable; it carries the generated
// health_check_password, D-MAILSERVER-INTERNAL-DEPLOY-R-004), then restart
// pgpool.
//
// Failure ordering (med-deploy-ssh-host-identity-b1r2-002): identical
// set -e / single-simple-command discipline as
// buildSeaweedFSNodeInstallCmd — a failed failover.sh or known_hosts install
// aborts the command before the restart, so provisioning can never report
// success while a node runs a pgpool.conf delegating to a missing or stale
// artifact. The restart line's unit-name fallback (pgpool2 || pgpool) is the
// one deliberate AND-OR list: its FINAL command is the last restart attempt,
// so only both-failing terminates the script — the fallback survives.
func buildPgpoolNodeInstallCmd(failoverPath, failoverScript, knownHostsPath, knownHosts, pgpoolConfPath, pgpoolConf string) string {
	return "set -e\n" +
		"install -d -o root -g root -m 0755 " + filepath.Dir(failoverPath) + "\n" +
		"cat > " + failoverPath + " << 'ENDOFFAILOVER'\n" + failoverScript + "\nENDOFFAILOVER\n" +
		"chown root:root " + failoverPath + "\n" +
		"chmod 0700 " + failoverPath + "\n" +
		"cat > " + knownHostsPath + " << 'ENDOFKNOWNHOSTS'\n" + knownHosts + "ENDOFKNOWNHOSTS\n" +
		"chown root:root " + knownHostsPath + "\n" +
		"chmod 0644 " + knownHostsPath + "\n" +
		"cat > " + pgpoolConfPath + " << 'ENDOFCONFIG'\n" + pgpoolConf + "\nENDOFCONFIG\n" +
		"chown root:postgres " + pgpoolConfPath + "\n" +
		"chmod 0640 " + pgpoolConfPath + "\n" +
		"systemctl restart pgpool2 2>/dev/null || systemctl restart pgpool 2>/dev/null"
}

// checkRemoteInstallFailureOrdering is the command-text gate for the wizard's
// remote provisioning commands (med-deploy-s3-credentials-b1r2-001 item b,
// med-deploy-ssh-host-identity-b1r2-002): a provisioning command that
// installs artifacts and then restarts a service must abort before the
// restart when any install step fails. It enforces on the generated text:
//   - the first executable line is exactly "set -e" (any failed step aborts);
//   - every pre-activation executable line is a SINGLE simple command — no
//     "&&", "||" or ";" — because under set -e only the final command of an
//     AND-OR list terminates the script, so a failing `chown x && chmod x`
//     would silently continue into the restart (the pre-fix defect);
//   - exactly one activation line (activationMarker), and it is the LAST
//     executable line — nothing may run after the restart that a late
//     failure could no longer prevent.
//
// Heredoc bodies (the uploaded artifact content) are skipped: only command
// structure is inspected.
func checkRemoteInstallFailureOrdering(cmd, activationMarker string) error {
	lines := strings.Split(cmd, "\n")
	first := true
	inHeredoc := ""
	sawActivation := false
	steps := 0
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if inHeredoc != "" {
			if trimmed == inHeredoc {
				inHeredoc = ""
			}
			continue
		}
		if trimmed == "" {
			continue
		}
		if first {
			if trimmed != "set -e" {
				return fmt.Errorf("remote install command must begin with set -e so any failed step aborts; first line is %q", trimmed)
			}
			first = false
			continue
		}
		if marker, ok := heredocDelimiter(trimmed); ok {
			inHeredoc = marker
			steps++
			continue
		}
		if strings.Contains(line, activationMarker) {
			if sawActivation {
				return fmt.Errorf("activation step %q appears more than once", trimmed)
			}
			sawActivation = true
			for _, rest := range lines[i+1:] {
				if strings.TrimSpace(rest) != "" {
					return fmt.Errorf("executable line %q follows the activation step; a failure there could no longer abort the restart", rest)
				}
			}
			continue
		}
		if strings.Contains(line, "&&") || strings.Contains(line, "||") || strings.Contains(line, ";") {
			return fmt.Errorf("pre-activation step %q must be a single simple command: AND-OR lists are exempt from set -e for non-final commands, so a failure would not abort before the restart", trimmed)
		}
		steps++
	}
	if first {
		return errors.New("remote install command has no executable lines")
	}
	if !sawActivation {
		return fmt.Errorf("remote install command never activates the service (%q absent)", activationMarker)
	}
	if steps == 0 {
		return errors.New("remote install command has no install steps before activation")
	}
	return nil
}

// heredocDelimiter extracts the delimiter word from a "<< 'MARKER'"
// redirection on a command line.
func heredocDelimiter(line string) (string, bool) {
	i := strings.Index(line, "<<")
	if i == -1 {
		return "", false
	}
	rest := strings.TrimSpace(line[i+2:])
	if rest == "" {
		return "", false
	}
	if rest[0] == '\'' || rest[0] == '"' {
		end := strings.IndexByte(rest[1:], rest[0])
		if end == -1 {
			return "", false
		}
		return rest[1 : 1+end], true
	}
	if j := strings.IndexAny(rest, " \t"); j != -1 {
		return rest[:j], true
	}
	return rest, true
}

func (w *Wizard) startServices(ctx context.Context) error {
	for _, n := range w.currentNodes() {
		if n.Role == "primary" && n.Host == "localhost" {
			continue
		}
		out, err := w.sshRun(ctx, n.Host, n.SSHUser, n.SSHKey,
			"systemctl start postgresql && systemctl start pgpool2 && systemctl start seaweedfs-master")
		if err != nil {
			return fmt.Errorf("start services on %s: %w\n%s", n.Host, err, out)
		}
	}
	return nil
}

// buildVerifyCommands returns shell commands to verify cluster health.
func buildVerifyCommands(primaryHost string, standbyHosts []string) []string {
	cmds := []string{
		fmt.Sprintf("psql -U mail -d mailserver -c \"SELECT usename, application_name, state, sync_state, sync_priority FROM pg_stat_replication;\""),
	}
	for range standbyHosts {
		cmds = append(cmds,
			fmt.Sprintf("psql -U mail -d mailserver -c \"SELECT pg_is_in_recovery();\""),
		)
	}
	return cmds
}

func (w *Wizard) verifyCluster(ctx context.Context) error {
	nodes := w.currentNodes()
	var primary string
	var standbys []string
	for _, n := range nodes {
		if n.Role == "primary" {
			primary = n.Host
		} else {
			standbys = append(standbys, n.Host)
		}
	}
	if primary == "" && len(standbys) == 0 {
		return fmt.Errorf("no nodes to verify")
	}

	cmds := buildVerifyCommands(primary, standbys)

	if primary != "" {
		out, err := w.sshRun(ctx, primary, nodes[0].SSHUser, nodes[0].SSHKey, cmds[0])
		if err != nil {
			return fmt.Errorf("verify replication on primary %s: %w\n%s", primary, err, out)
		}
		w.logger.Info("primary replication status", "output", out)
	}

	for i, standby := range standbys {
		out, err := w.sshRun(ctx, standby, nodes[0].SSHUser, nodes[0].SSHKey, cmds[i+1])
		if err != nil {
			return fmt.Errorf("verify recovery on standby %s: %w\n%s", standby, err, out)
		}
		w.logger.Info("standby recovery status", "standby", standby, "output", out)
	}

	w.logger.Info("cluster verification passed")
	return nil
}

// ── State helpers ──

func (w *Wizard) logStep(name, desc string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.state.Steps = append(w.state.Steps, DeploymentStep{Name: name, Status: "running"})
	w.state.Log = append(w.state.Log, fmt.Sprintf("[%s] %s", name, desc))
}

func (w *Wizard) okStep(name string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for i := range w.state.Steps {
		if w.state.Steps[i].Name == name && w.state.Steps[i].Status == "running" {
			w.state.Steps[i].Status = "ok"
			w.persistStep(context.Background(), w.state.Steps[i])
			break
		}
	}
	w.state.Log = append(w.state.Log, fmt.Sprintf("[%s] OK", name))
}

func (w *Wizard) failStep(name string, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	// Redact once, up front, under the lock: the error text may embed raw
	// remote output (e.g. "SSH host: ... — output: ...") plus any secret the
	// wizard holds for its nodes, and the same redacted string feeds the
	// in-memory step, the persisted deployment_steps row, and the log line.
	redacted := RedactOutput(err.Error(), w.knownSecrets()...)
	for i := range w.state.Steps {
		if w.state.Steps[i].Name == name && w.state.Steps[i].Status == "running" {
			w.state.Steps[i].Status = "failed"
			w.state.Steps[i].Error = redacted
			w.persistStep(context.Background(), w.state.Steps[i])
			break
		}
	}
	w.state.Log = append(w.state.Log, fmt.Sprintf("[%s] FAILED: %s", name, redacted))
}

func (w *Wizard) setStatus(s string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.state.Status = s
}

// Template embedded for convenience; production could load from file.
var pgpoolConfigTemplate = `# Auto-generated by HA Deploy Wizard
backend_hostname0 = '{{.Node1}}'
backend_port0 = 5432
backend_weight0 = 1
backend_flag0 = 'ALWAYS_PRIMARY|DISALLOW_TO_FAILOVER'
backend_hostname1 = '{{.Node2}}'
backend_port1 = 5432
backend_weight1 = 1
backend_hostname2 = '{{.Node3}}'
backend_port2 = 5432
backend_weight2 = 1
listen_addresses = '*'
port = 9999
num_init_children = 32
max_pool = 4
health_check_period = 3
health_check_user = 'pgpool'
health_check_password = '{{.PgpoolPass}}'
failover_command = '/etc/pgpool2/failover.sh %d %P %H %R'
fail_over_on_backend_error = on
load_balance_mode = on
use_watchdog = on
wd_hostname = '{{.MyHost}}'
wd_port = 9000
wd_priority = 1
wd_lifecheck_method = 'heartbeat'
wd_heartbeat_keepalive = 2
wd_heartbeat_deadtime = 30
other_pgpool_hostname0 = '{{.Peer1}}'
other_pgpool_port0 = 9999
other_pgpool_wd_port0 = 9000
other_pgpool_hostname1 = '{{.Peer2}}'
other_pgpool_port1 = 9999
other_pgpool_wd_port1 = 9000
`
