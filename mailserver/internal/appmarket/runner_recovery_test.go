package appmarket

import (
	"context"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
)

func reclaimedOp(state string) *Operation {
	return &Operation{OperationID: uuid.New(), Kind: "install", State: state,
		StateGeneration: 7, ExecutorID: "crashed-runner", LeaseID: uuid.New(),
		Reclaimed: true}
}

func recoveryRunner(control *fakeControl, runtime Runtime) *Runner {
	return &Runner{Control: control, Runtime: runtime, Manifest: testManifest(),
		ExecutorID: "reclaimer", InstallationID: "test-installation"}
}

// Matrix (a): a crash in the rollback window reclaims rolling_back, completes
// the fence-checked Rollback, lands rolled_back with the fence released, and a
// subsequent install succeeds against the ownership fence.
func TestRunnerReclaimedRollingBackCompletesRollbackAndReleasesFence(t *testing.T) {
	control := &fakeControl{op: reclaimedOp("rolling_back")}
	runtime := &fakeRuntime{}
	worked, err := recoveryRunner(control, runtime).RunOnce(context.Background())
	if err == nil || !worked {
		t.Fatalf("RunOnce=(%v,%v)", worked, err)
	}
	if want := []string{"rolled_back"}; !reflect.DeepEqual(control.states, want) {
		t.Fatalf("states=%v want=%v", control.states, want)
	}
	if got := runtime.calls; len(got) != 1 || got[0] != "rollback" {
		t.Fatalf("runtime calls=%v, want exactly the reclaim Rollback", got)
	}
	// A subsequent install succeeds: no stranded active row, no
	// RECOVERY_STATE_UNKNOWN for the fence release.
	control.op = &Operation{OperationID: uuid.New(), Kind: "install", StateGeneration: 2}
	control.states, control.lastFailure = nil, nil
	runtime.calls = nil
	if _, err := recoveryRunner(control, runtime).RunOnce(context.Background()); err != nil {
		t.Fatalf("subsequent install: %v", err)
	}
	want := []string{"preflight", "pulling", "verifying", "staging", "starting",
		"qualifying", "connected_inactive"}
	if !reflect.DeepEqual(control.states, want) {
		t.Fatalf("install states=%v want=%v", control.states, want)
	}
}

// Matrix (a), unknown-state guard: genuinely unreconcilable reclaimed states
// still fail RECOVERY_STATE_UNKNOWN; rolling_back is no longer one of them.
func TestRunnerReclaimedUnknownStateStillFails(t *testing.T) {
	control := &fakeControl{op: reclaimedOp("disabling_launches")}
	if _, err := recoveryRunner(control, &fakeRuntime{}).RunOnce(context.Background()); err == nil ||
		!slices.Contains(control.states, "failed_terminal") {
		t.Fatalf("unknown state=(%v,%v)", control.states, err)
	}
}

// Matrix (b): a Rollback that still fails after reclaim records ROLLBACK_FAILED
// on failed_terminal with the failure retained for the admin recover path.
func TestRunnerReclaimedRollbackFailureRecordsRollbackFailed(t *testing.T) {
	control := &fakeControl{op: reclaimedOp("rolling_back")}
	runtime := &fakeRuntime{failAt: "rollback"}
	worked, err := recoveryRunner(control, runtime).RunOnce(context.Background())
	if err == nil || !worked {
		t.Fatalf("RunOnce=(%v,%v)", worked, err)
	}
	if got := control.states[len(control.states)-1]; got != "failed_terminal" {
		t.Fatalf("terminal state=%q", got)
	}
	if got := control.lastFailure["code"]; got != "ROLLBACK_FAILED" {
		t.Fatalf("failure code=%v, want ROLLBACK_FAILED", got)
	}
	if got := runtime.calls[len(runtime.calls)-1]; got != "rollback" {
		t.Fatalf("last runtime call=%q", got)
	}
}

// slowPullRuntime blocks in Pull past any injected budget.
type slowPullRuntime struct {
	*fakeRuntime
	delay time.Duration
}

func (f *slowPullRuntime) Pull(ctx context.Context, m Manifest) error {
	f.calls = append(f.calls, "pull")
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(f.delay):
		return nil
	}
}

// Matrix (e), pull branch: when lease renewal cannot cover the pull, the
// budget fires while the lease is still valid and the runner advances
// pulling -> paused_recoverable with the updater alive (no error return).
func TestRunnerPullBudgetExhaustionPausesWithUpdaterAlive(t *testing.T) {
	control := &fakeControl{op: &Operation{OperationID: uuid.New(), Kind: "install",
		StateGeneration: 2}}
	runner := recoveryRunner(control, &slowPullRuntime{fakeRuntime: &fakeRuntime{}, delay: 50 * time.Millisecond})
	runner.PullBudget = 10 * time.Millisecond
	worked, err := runner.RunOnce(context.Background())
	if err != nil || !worked {
		t.Fatalf("pause must keep the updater alive: RunOnce=(%v,%v)", worked, err)
	}
	want := []string{"preflight", "pulling", "paused_recoverable"}
	if !reflect.DeepEqual(control.states, want) {
		t.Fatalf("states=%v want=%v", control.states, want)
	}
	if got := control.lastFailure["code"]; got != "LEASE_BUDGET_EXHAUSTED" {
		t.Fatalf("pause code=%v", got)
	}
	if !slices.Contains(control.heartbeats, worstCaseStepLeaseSeconds) {
		t.Fatalf("pull step heartbeats=%v, want a %ds step-aware renewal", control.heartbeats, worstCaseStepLeaseSeconds)
	}
}

// Matrix (e), bounded recovery from a paused pull row: the reclaim resumes at
// preflight and reaches a separately named terminal outcome.
func TestRunnerPausedPullRecoveryReachesNamedTerminalOutcome(t *testing.T) {
	control := &fakeControl{op: reclaimedOp("paused_recoverable")}
	runtime := &fakeRuntime{failAt: "pull"}
	worked, err := recoveryRunner(control, runtime).RunOnce(context.Background())
	if err == nil || !worked {
		t.Fatalf("RunOnce=(%v,%v)", worked, err)
	}
	want := []string{"preflight", "pulling", "failed_terminal"}
	if !reflect.DeepEqual(control.states, want) {
		t.Fatalf("states=%v want=%v", control.states, want)
	}
}

// Matrix (e), qualifying branch: the health step renews its lease across the
// worst-case window and, on failure, follows the bounded reducer-authorized
// outcome rolling_back -> rolled_back with NO health-to-pause transition.
func TestRunnerQualifyingFailureFollowsBoundedRollbackWithoutPause(t *testing.T) {
	control := &fakeControl{op: &Operation{OperationID: uuid.New(), Kind: "install",
		StateGeneration: 2}}
	runtime := &fakeRuntime{failAt: "healthy"}
	worked, err := recoveryRunner(control, runtime).RunOnce(context.Background())
	if err == nil || !worked {
		t.Fatalf("RunOnce=(%v,%v)", worked, err)
	}
	want := []string{"preflight", "pulling", "verifying", "staging", "starting",
		"qualifying", "rolling_back", "rolled_back"}
	if !reflect.DeepEqual(control.states, want) {
		t.Fatalf("states=%v want=%v", control.states, want)
	}
	if slices.Contains(control.states, "paused_recoverable") {
		t.Fatal("qualifying attempted a health-to-pause transition")
	}
	if !slices.Contains(control.heartbeats, worstCaseStepLeaseSeconds) {
		t.Fatalf("qualifying heartbeats=%v, want a %ds step-aware renewal", control.heartbeats, worstCaseStepLeaseSeconds)
	}
	if got := runtime.calls[len(runtime.calls)-1]; got != "rollback" {
		t.Fatalf("last runtime call=%q", got)
	}
}

// Matrix (e), step-aware TTL: every bounded step renews with its own TTL and
// no step renews below the previously hard-coded 30s global lease.
func TestRunnerStepAwareLeaseSeconds(t *testing.T) {
	control := &fakeControl{op: &Operation{OperationID: uuid.New(), Kind: "install",
		StateGeneration: 2}}
	if _, err := recoveryRunner(control, &fakeRuntime{}).RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Two heartbeats per step, each carrying that step's worst-case TTL.
	want := []int{defaultStepLeaseSeconds, defaultStepLeaseSeconds,
		worstCaseStepLeaseSeconds, worstCaseStepLeaseSeconds,
		defaultStepLeaseSeconds, defaultStepLeaseSeconds,
		defaultStepLeaseSeconds, defaultStepLeaseSeconds,
		defaultStepLeaseSeconds, defaultStepLeaseSeconds,
		worstCaseStepLeaseSeconds, worstCaseStepLeaseSeconds}
	if !reflect.DeepEqual(control.heartbeats, want) {
		t.Fatalf("heartbeats=%v want=%v", control.heartbeats, want)
	}
}
