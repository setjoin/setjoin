// runlock.go — deployment run serialization and real cancellation
// (D-MAILSERVER-INTERNAL-DEPLOY-R-002).
//
// Begin previously swapped w.state and spawned runDeployment with no in-flight
// guard, so two concurrent deployments could each drive re-initialization
// (systemctl stop / rm -rf / pg_basebackup) against the same live cluster, and
// the only cancellation surface (Reset, invoked by CancelDeploy) merely
// replaced the status struct while the old goroutine kept issuing remote
// commands. This file owns the run lifecycle: exactly one deployment at a
// time, node-list access through a locked accessor, and a cancel path whose
// context reaches sshRun so an in-flight destructive remote command is
// interrupted by tearing down the SSH transport.
package deploy

import (
	"context"
	"errors"
)

// ErrDeployInProgress is returned by Begin when a deployment run is already
// active. Begin never cancels the active run: a rejected start must preserve
// it. The in-flight run must be cancelled (Reset, which drains before
// returning) before a new Begin is accepted; callers can map this sentinel to
// a conflict response.
var ErrDeployInProgress = errors.New("deployment already in progress")

// ErrDeployUnreconciled is returned by Begin while the run fence is held: the
// previous run was cancelled while a remote command was in flight and its
// termination on the target host could not be confirmed, so destructive
// remote work may have survived the SSH transport teardown. A subsequent run
// must not overlap surviving remote work. The fence is NOT cleared by ordinary
// Reset calls (a drained run's fence survives the StartDeploy Reset;Begin
// retry sequence, and a concurrent Reset cannot acknowledge after the drain):
// only AcknowledgeReconciled — the explicit operator acknowledgment that the
// target hosts were reconciled — clears it before a new run is accepted.
// Callers can map this sentinel to a conflict response.
var ErrDeployUnreconciled = errors.New("previous deployment ended with unconfirmed remote termination — reconcile the target hosts, then AcknowledgeReconciled before starting again")

// deployRun tracks one in-flight runDeployment execution.
// Guarded by Wizard.mu (the wizard's single lock; no second lock).
type deployRun struct {
	// cancel aborts the run context; sshRun reacts by fast-failing before the
	// next remote command and by closing the SSH client transport around the
	// command currently executing.
	cancel context.CancelFunc
	// done is closed by the run goroutine after it has drained (terminal
	// state recorded, tracker cleared).
	done chan struct{}
}

// inFlightLocked reports whether a deployment run is active. Caller holds w.mu.
func (w *Wizard) inFlightLocked() bool {
	return w.run != nil
}

// AcknowledgeReconciled is the EXPLICIT operator acknowledgment that the
// target hosts were reconciled after an unconfirmed prior remote termination:
// it is the only path that clears the run fence. Ordinary Reset calls never
// touch the fence — cancellation/reset and reconciliation acknowledgment are
// separate concerns, so the StartDeploy Reset;Begin retry sequence keeps
// refusing with ErrDeployUnreconciled instead of clearing a drained run's
// fence merely by retrying Start, and a concurrent Reset caller cannot
// acknowledge after the drain. Refuses with ErrDeployInProgress while a run is
// active: reconciliation is meaningful only once the run has drained.
func (w *Wizard) AcknowledgeReconciled() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.inFlightLocked() {
		return ErrDeployInProgress
	}
	w.fenced = false
	return nil
}

// cancelRunLocked hard-cancels the active run, if any, and reports whether one
// was cancelled. Cancellation is the destructive-remote-step halt: the run
// context reaches sshRun, which interrupts the command in flight. The caller
// (Reset) drains the run afterwards by waiting on run.done. Caller holds
// w.mu.
func (w *Wizard) cancelRunLocked() bool {
	if w.run == nil {
		return false
	}
	w.run.cancel()
	return true
}

// currentNodes returns a copy of the active deployment's node list. Step
// functions MUST read nodes through this locked accessor instead of touching
// w.state directly: Begin and Reset swap the state pointer under w.mu, so an
// unlocked w.state.Nodes read races the pointer swap and can observe a torn or
// foreign node set (the read surface flagged by D-...-R-002).
func (w *Wizard) currentNodes() []NodeConfig {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.state == nil {
		return nil
	}
	return append([]NodeConfig(nil), w.state.Nodes...)
}
