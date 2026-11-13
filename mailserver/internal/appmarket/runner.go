package appmarket

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ErrOperationFailedRecorded marks a per-operation outcome that was fully
// recorded in the control plane (failed_terminal / rolled_back) — the reducer
// state machine is correct and the journal carries the intent. It is a
// RECORDED OUTCOME, not a worker fault: Poll continues polling (the operation's
// failure is visible to the admin in the operation state, with its remedy),
// while control-plane/DB/journal faults (which do NOT wrap this sentinel)
// remain terminal for the shared updater process
// (D-MAILSERVER-INTERNAL-APPMARKET-003). One-shot (--once / E2E) callers keep
// their fail-fast contract: RunOnce returns the sentinel to them too.
var ErrOperationFailedRecorded = errors.New("managed CODE operation failed (recorded)")

const (
	// defaultStepLeaseSeconds renews the lease across bounded local steps
	// (preflight, verify, stage, start) whose worst case is a slow Docker
	// daemon round-trip.
	defaultStepLeaseSeconds = 60
	// worstCaseStepLeaseSeconds is the reducer heartbeat ceiling (10..300).
	// It is the step-aware lease for the two steps with the widest duration
	// spread: the pinned multi-arch image pull and the bounded discovery
	// health retry loop (30 attempts x (5s timeout + 2s delay) ~= 210s), so
	// the post-step heartbeat can never raise BZ324 on a merely slow step.
	worstCaseStepLeaseSeconds = 300
	// defaultPullBudget bounds one pull attempt BELOW its lease so the
	// reducer-authorized pulling->paused_recoverable pause (the only
	// reachable pause arm) stays available while the lease is still valid.
	defaultPullBudget = 240 * time.Second
)

type Runner struct {
	Control                    ControlPlane
	Runtime                    Runtime
	Manifest                   Manifest
	ExecutorID                 string
	InstallationID             string
	Journal                    *AppJournal
	AllowInsecureTestTransport bool
	// PullBudget overrides the artifact-pull execution budget in tests; zero
	// uses defaultPullBudget.
	PullBudget time.Duration
}

// runnerStep is one reducer state the executor drives. leaseSeconds is the
// step-aware heartbeat TTL covering this step's worst-case duration; budget
// (when non-zero) bounds one execution attempt below that lease; pausable
// marks the only state the reducer admits into paused_recoverable.
type runnerStep struct {
	state        string
	phase        string
	run          func(context.Context, Manifest) error
	leaseSeconds int
	budget       time.Duration
	pausable     bool
}

func (r *Runner) manifestForOperation(op *Operation) (Manifest, error) {
	var request struct {
		WOPIPublicBaseURL string `json:"wopiPublicBaseUrl"`
	}
	if err := json.Unmarshal(op.Request, &request); err != nil {
		return Manifest{}, fmt.Errorf("decode managed Office operation request: %w", err)
	}
	if strings.TrimSpace(request.WOPIPublicBaseURL) == "" {
		return Manifest{}, errors.New("managed Office operation lacks reducer-bound WOPI origin")
	}
	manifest := r.Manifest.WithExecution(r.InstallationID, op.OperationID.String()).
		WithProvider(request.WOPIPublicBaseURL, r.AllowInsecureTestTransport)
	if _, err := CompileRuntimePlan(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func (r *Runner) Poll(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		return errors.New("managed app poll interval must be positive")
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		worked, err := r.RunOnce(ctx)
		if errors.Is(err, ErrOperationFailedRecorded) {
			// Recorded operation outcome — never a process-lifecycle event.
			// Terminating the shared updater here let any apps.manage holder
			// (or one registry hiccup) stop release/migration polling too.
			// Wait out the tick like an idle cycle so a queue of poisoned
			// operations drains at poll cadence, and honor cancellation.
			slog.Warn("managed app operation failed; outcome recorded, continuing to poll", "error", err)
			worked = false
		} else if err != nil {
			return err
		}
		if worked {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (r *Runner) RunOnce(ctx context.Context) (bool, error) {
	lease := uuid.New()
	op, err := r.Control.Claim(ctx, r.ExecutorID, lease)
	if err != nil || op == nil {
		return false, err
	}
	if op.Kind != "install" {
		return true, r.fail(ctx, op, "UNSUPPORTED_OPERATION", "only install is available in the first managed CODE slice")
	}
	manifest, err := r.manifestForOperation(op)
	if err != nil {
		return true, r.fail(ctx, op, "INVALID_RUNTIME_PLAN", err.Error())
	}
	if r.Journal != nil {
		lock, err := r.Journal.AcquireLock()
		if err != nil {
			return true, fmt.Errorf("acquire managed app journal lock: %w", err)
		}
		defer func() { _ = lock.Close() }()
	}
	steps := []runnerStep{
		{state: "preflight", phase: "runtime_preflight", run: r.Runtime.Preflight,
			leaseSeconds: defaultStepLeaseSeconds},
		{state: "pulling", phase: "artifact_pull", run: r.Runtime.Pull,
			leaseSeconds: worstCaseStepLeaseSeconds, budget: r.pullBudget(), pausable: true},
		{state: "verifying", phase: "artifact_digest", run: r.Runtime.Verify,
			leaseSeconds: defaultStepLeaseSeconds},
		{state: "staging", phase: "runtime_staging", run: r.Runtime.Stage,
			leaseSeconds: defaultStepLeaseSeconds},
		{state: "starting", phase: "runtime_start", run: r.Runtime.Start,
			leaseSeconds: defaultStepLeaseSeconds},
		{state: "qualifying", phase: "discovery_health", run: r.Runtime.Healthy,
			leaseSeconds: worstCaseStepLeaseSeconds},
	}
	totalSteps := len(steps) + 1
	start := 0
	if op.Reclaimed && op.State != "claimed" {
		if op.State == "rolling_back" {
			return true, r.completeReclaimedRollback(ctx, op, manifest)
		}
		start = -1
		if op.State == "paused_recoverable" {
			start = 0
		}
		for index, step := range steps {
			if step.state == op.State {
				start = index
				break
			}
		}
		if start < 0 {
			return true, r.fail(ctx, op, "RECOVERY_STATE_UNKNOWN", "claimed operation state cannot be reconciled")
		}
	}
	for index := start; index < len(steps); index++ {
		step := steps[index]
		progress := map[string]any{"step": index + 1, "steps": totalSteps}
		if op.State != step.state {
			if err := r.Control.Advance(ctx, op, step.state, step.phase, progress, nil); err != nil {
				return true, err
			}
		}
		if err := r.Control.Heartbeat(ctx, op, step.leaseSeconds); err != nil {
			return true, fmt.Errorf("heartbeat managed CODE operation: %w", err)
		}
		if r.Journal != nil {
			if err := r.Journal.Append(op, step.phase+":intent", progress); err != nil {
				return true, fmt.Errorf("record managed app step intent: %w", err)
			}
		}
		stepCtx := ctx
		if step.budget > 0 {
			var cancel context.CancelFunc
			stepCtx, cancel = context.WithTimeout(ctx, step.budget)
			defer cancel()
		}
		stepErr := step.run(stepCtx, manifest)
		if stepErr != nil && step.pausable && ctx.Err() == nil &&
			errors.Is(stepCtx.Err(), context.DeadlineExceeded) {
			// Renewal could not cover the pull and the budget fired while the
			// lease is still valid: park the operation in the reducer's
			// nonterminal paused_recoverable arm instead of letting the
			// post-expiry heartbeat raise BZ324 and kill the updater.
			if pauseErr := r.pauseForRecovery(ctx, op, step.phase); pauseErr != nil {
				return true, pauseErr
			}
			return true, nil
		}
		if stepErr != nil {
			if index >= 3 {
				return true, r.rollback(ctx, op, stepErr)
			}
			return true, r.fail(ctx, op, "RUNTIME_STEP_FAILED", stepErr.Error())
		}
		if err := r.Control.Heartbeat(ctx, op, step.leaseSeconds); err != nil {
			return true, fmt.Errorf("heartbeat managed CODE operation after %s: %w", step.phase, err)
		}
		if r.Journal != nil {
			if err := r.Journal.Append(op, step.phase+":complete", progress); err != nil {
				return true, fmt.Errorf("record managed app step completion: %w", err)
			}
		}
	}
	if err := r.Control.CommitInstall(ctx, op, manifest); err != nil {
		return true, fmt.Errorf("commit managed CODE install: %w", err)
	}
	return true, nil
}

// recordedFailure wraps an operation-outcome error that was fully recorded in
// the control plane with ErrOperationFailedRecorded, so Poll can distinguish
// "outcome recorded" from "worker unhealthy" via errors.Is alone.
func recordedFailure(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrOperationFailedRecorded, err.Error())
}

func (r *Runner) pullBudget() time.Duration {
	if r.PullBudget > 0 {
		return r.PullBudget
	}
	return defaultPullBudget
}

// pauseForRecovery parks a lease-budget-exhausted pull in the reducer's
// nonterminal paused_recoverable arm. Recovery is bounded and explicit:
// office_app_operation_recover_request (admin-gated) re-arms the lease for
// reclaim, the resumed run advances paused_recoverable -> preflight, and the
// operation reaches a separately named terminal outcome — never an ambiguous
// perpetual pause and never a terminal pause.
func (r *Runner) pauseForRecovery(ctx context.Context, op *Operation, phase string) error {
	detail := fmt.Sprintf("%s exceeded its lease budget; operation paused for bounded admin recovery", phase)
	pause := map[string]any{"code": "LEASE_BUDGET_EXHAUSTED", "detail": detail,
		"owner": "setjoin-admin", "effect": "provider routing unchanged",
		"remedy": "approve recovery to resume the install"}
	if err := r.Control.Advance(ctx, op, "paused_recoverable", "lease_budget_paused",
		map[string]any{"pausedDuring": phase}, pause); err != nil {
		return fmt.Errorf("pause managed CODE operation after %s: %w", phase, err)
	}
	return nil
}

// completeReclaimedRollback finishes the rollback window a crashed executor
// left behind: the reclaimed rolling_back operation re-runs the fence-checked
// Rollback (DockerRuntime.Rollback -> RemoveTestRuntime), advances
// rolling_back -> rolled_back — releasing the one-active install fence — and
// never reaches RECOVERY_STATE_UNKNOWN. A rollback that still fails records
// ROLLBACK_FAILED on failed_terminal with the ownership fence intact, where
// the admin-authorized recover path can re-arm the cleanup retry.
func (r *Runner) completeReclaimedRollback(ctx context.Context, op *Operation, manifest Manifest) error {
	failure := map[string]any{"code": "RUNTIME_STEP_FAILED",
		"detail": "rollback resumed and completed by executor reclaim",
		"owner":  "setjoin-admin", "effect": "provider routing unchanged"}
	if err := r.Runtime.Rollback(ctx, manifest); err != nil {
		return r.fail(ctx, op, "ROLLBACK_FAILED",
			fmt.Sprintf("%v; rollback resumed after executor loss", err))
	}
	if err := r.Control.Advance(ctx, op, "rolled_back", "rollback_complete",
		map[string]any{"providerRoutingChanged": false, "resumedAfterReclaim": true},
		failure); err != nil {
		return fmt.Errorf("record managed CODE rollback: %w", err)
	}
	return recordedFailure(errors.New("managed CODE install failed and was rolled back after reclaim"))
}

func (r *Runner) rollback(ctx context.Context, op *Operation, original error) error {
	failure := map[string]any{"code": "RUNTIME_STEP_FAILED", "detail": original.Error(),
		"owner": "setjoin-admin", "effect": "provider routing unchanged"}
	if err := r.Control.Advance(ctx, op, "rolling_back", "rollback_runtime",
		map[string]any{"reason": "install_failed"}, failure); err != nil {
		return fmt.Errorf("begin managed CODE rollback: %w (original: %v)", err, original)
	}
	manifest, bindErr := r.manifestForOperation(op)
	if bindErr != nil {
		return r.fail(ctx, op, "ROLLBACK_BINDING_INVALID", bindErr.Error())
	}
	if err := r.Runtime.Rollback(ctx, manifest); err != nil {
		return r.fail(ctx, op, "ROLLBACK_FAILED", fmt.Sprintf("%v; original failure: %v", err, original))
	}
	if err := r.Control.Advance(ctx, op, "rolled_back", "rollback_complete",
		map[string]any{"providerRoutingChanged": false}, failure); err != nil {
		return fmt.Errorf("record managed CODE rollback: %w (original: %v)", err, original)
	}
	return recordedFailure(fmt.Errorf("managed CODE install failed and was rolled back: %w", original))
}

func (r *Runner) fail(ctx context.Context, op *Operation, code, detail string) error {
	failure := map[string]any{"code": code, "detail": detail, "owner": "setjoin-admin",
		"effect": "provider routing unchanged", "remedy": "inspect diagnostics and retry with a new operation"}
	if err := r.Control.Advance(ctx, op, "failed_terminal", "failed", map[string]any{}, failure); err != nil {
		// Control-plane fault while RECORDING — genuinely unhealthy worker:
		// deliberately NOT wrapped in ErrOperationFailedRecorded, so Poll
		// treats this as terminal.
		return fmt.Errorf("record managed CODE failure: %w (original: %s)", err, detail)
	}
	return recordedFailure(fmt.Errorf("managed CODE operation failed: %s", detail))
}
