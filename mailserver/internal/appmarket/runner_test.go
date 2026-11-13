package appmarket

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

type fakeControl struct {
	op           *Operation
	states       []string
	heartbeats   []int
	lastFailure  map[string]any
	claimErr     error
	advanceErrAt string
	heartbeatErr error
	commitErr    error
}

func (f *fakeControl) Claim(context.Context, string, uuid.UUID) (*Operation, error) {
	if f.op != nil && len(f.op.Request) == 0 {
		f.op.Request = []byte(`{"wopiPublicBaseUrl":"https://setjoin.example"}`)
	}
	return f.op, f.claimErr
}
func (f *fakeControl) Advance(_ context.Context, op *Operation, next, _ string, _ map[string]any, failure map[string]any) error {
	if next == f.advanceErrAt {
		return errors.New("advance failed")
	}
	f.states = append(f.states, next)
	f.lastFailure = failure
	op.State, op.StateGeneration = next, op.StateGeneration+1
	return nil
}
func (f *fakeControl) Heartbeat(_ context.Context, op *Operation, leaseSeconds int) error {
	if f.heartbeatErr == nil {
		f.heartbeats = append(f.heartbeats, leaseSeconds)
	}
	return f.heartbeatErr
}
func (f *fakeControl) CommitInstall(_ context.Context, op *Operation, _ Manifest) error {
	if f.commitErr != nil {
		return f.commitErr
	}
	f.states = append(f.states, "connected_inactive")
	op.State, op.StateGeneration = "connected_inactive", op.StateGeneration+1
	return nil
}

type fakeRuntime struct {
	failAt string
	calls  []string
}

func (f *fakeRuntime) run(name string) error {
	f.calls = append(f.calls, name)
	if name == f.failAt {
		return errors.New("injected failure")
	}
	return nil
}
func (f *fakeRuntime) Preflight(context.Context, Manifest) error { return f.run("preflight") }
func (f *fakeRuntime) Pull(context.Context, Manifest) error      { return f.run("pull") }
func (f *fakeRuntime) Verify(context.Context, Manifest) error    { return f.run("verify") }
func (f *fakeRuntime) Stage(context.Context, Manifest) error     { return f.run("stage") }
func (f *fakeRuntime) Start(context.Context, Manifest) error     { return f.run("start") }
func (f *fakeRuntime) Healthy(context.Context, Manifest) error   { return f.run("healthy") }
func (f *fakeRuntime) Rollback(context.Context, Manifest) error  { return f.run("rollback") }

func TestRunnerInstallLifecycle(t *testing.T) {
	control := &fakeControl{op: &Operation{OperationID: uuid.New(), Kind: "install", StateGeneration: 2}}
	runtime := &fakeRuntime{}
	runner := Runner{Control: control, Runtime: runtime, Manifest: testManifest(), ExecutorID: "test", InstallationID: "test-installation"}
	worked, err := runner.RunOnce(context.Background())
	if err != nil || !worked {
		t.Fatalf("RunOnce=(%v,%v)", worked, err)
	}
	want := []string{"preflight", "pulling", "verifying", "staging", "starting", "qualifying", "connected_inactive"}
	if !reflect.DeepEqual(control.states, want) {
		t.Fatalf("states=%v want=%v", control.states, want)
	}
}

func TestRunnerFailureIsTerminal(t *testing.T) {
	control := &fakeControl{op: &Operation{OperationID: uuid.New(), Kind: "install", StateGeneration: 2}}
	runner := Runner{Control: control, Runtime: &fakeRuntime{failAt: "verify"}, Manifest: testManifest(), ExecutorID: "test", InstallationID: "test-installation"}
	if _, err := runner.RunOnce(context.Background()); err == nil {
		t.Fatal("expected failure")
	}
	if got := control.states[len(control.states)-1]; got != "failed_terminal" {
		t.Fatalf("terminal state=%q", got)
	}
}

// claimOnceControl drains the queue after one claim, so Poll has idle cycles.
type claimOnceControl struct {
	fakeControl
	claimed bool
}

func (f *claimOnceControl) Claim(ctx context.Context, id string, lease uuid.UUID) (*Operation, error) {
	if f.claimed {
		return nil, nil
	}
	f.claimed = true
	return f.fakeControl.Claim(ctx, id, lease)
}

// TestPollContinuesAfterRecordedOperationFailure pins the
// D-MAILSERVER-INTERNAL-APPMARKET-003 distinction: an operation whose failure
// was fully RECORDED (failed_terminal) is an outcome, not a worker fault —
// Poll keeps polling (observing ctx) instead of terminating the shared
// updater; RunOnce still surfaces the sentinel to one-shot (--once/E2E)
// callers for fail-fast.
func TestPollContinuesAfterRecordedOperationFailure(t *testing.T) {
	control := &claimOnceControl{fakeControl: fakeControl{
		op: &Operation{OperationID: uuid.New(), Kind: "install", StateGeneration: 2},
	}}
	runner := Runner{Control: control, Runtime: &fakeRuntime{failAt: "verify"},
		Manifest: testManifest(), ExecutorID: "test", InstallationID: "test-installation"}

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if err := runner.Poll(ctx, time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Poll returned %v; want it to keep polling until ctx expiry", err)
	}
	if got := control.states[len(control.states)-1]; got != "failed_terminal" {
		t.Fatalf("terminal state=%q; failure must be recorded in the control plane", got)
	}

	// One-shot callers keep fail-fast: RunOnce returns the recorded-failure
	// sentinel (non-nil) so --once exits non-zero.
	fresh := &fakeControl{op: &Operation{OperationID: uuid.New(), Kind: "install", StateGeneration: 2}}
	once := Runner{Control: fresh, Runtime: &fakeRuntime{failAt: "verify"},
		Manifest: testManifest(), ExecutorID: "test", InstallationID: "test-installation"}
	if _, err := once.RunOnce(context.Background()); !errors.Is(err, ErrOperationFailedRecorded) {
		t.Fatalf("RunOnce err=%v; want ErrOperationFailedRecorded sentinel", err)
	}
}

// TestPollStillExitsOnControlPlaneFault pins the other half: an Advance fault
// while RECORDING the failure is a worker fault and stays terminal.
func TestPollStillExitsOnControlPlaneFault(t *testing.T) {
	control := &claimOnceControl{fakeControl: fakeControl{
		op:           &Operation{OperationID: uuid.New(), Kind: "install", StateGeneration: 2},
		advanceErrAt: "failed_terminal",
	}}
	runner := Runner{Control: control, Runtime: &fakeRuntime{failAt: "verify"},
		Manifest: testManifest(), ExecutorID: "test", InstallationID: "test-installation"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := runner.Poll(ctx, time.Millisecond)
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Poll returned %v; control-plane fault must terminate the worker", err)
	}
}

func TestRunnerFailureAfterStagingRollsBack(t *testing.T) {
	control := &fakeControl{op: &Operation{OperationID: uuid.New(), Kind: "install", StateGeneration: 2}}
	runtime := &fakeRuntime{failAt: "start"}
	runner := Runner{Control: control, Runtime: runtime, Manifest: testManifest(), ExecutorID: "test", InstallationID: "test-installation"}
	if _, err := runner.RunOnce(context.Background()); err == nil {
		t.Fatal("expected failure")
	}
	wantStates := []string{"preflight", "pulling", "verifying", "staging", "starting", "rolling_back", "rolled_back"}
	if !reflect.DeepEqual(control.states, wantStates) {
		t.Fatalf("states=%v want=%v", control.states, wantStates)
	}
	if got := runtime.calls[len(runtime.calls)-1]; got != "rollback" {
		t.Fatalf("last runtime call=%q", got)
	}
}

func TestRunnerRollbackFailureIsTerminal(t *testing.T) {
	control := &fakeControl{op: &Operation{OperationID: uuid.New(), Kind: "install", StateGeneration: 2}}
	runtime := &fakeRuntime{failAt: "rollback"}
	runtimeWithTwoFailures := &twoFailureRuntime{fakeRuntime: runtime}
	runner := Runner{Control: control, Runtime: runtimeWithTwoFailures, Manifest: testManifest(), ExecutorID: "test", InstallationID: "test-installation"}
	if _, err := runner.RunOnce(context.Background()); err == nil {
		t.Fatal("expected failure")
	}
	if got := control.states[len(control.states)-1]; got != "failed_terminal" {
		t.Fatalf("terminal state=%q", got)
	}
}

type twoFailureRuntime struct{ *fakeRuntime }

func (f *twoFailureRuntime) Start(context.Context, Manifest) error {
	f.calls = append(f.calls, "start")
	return errors.New("injected start failure")
}

func TestRunnerNoWorkClaimErrorAndUnsupportedOperation(t *testing.T) {
	runtime := &fakeRuntime{}
	for _, control := range []*fakeControl{{}, {claimErr: errors.New("offline")}} {
		worked, err := (&Runner{Control: control, Runtime: runtime}).RunOnce(context.Background())
		if worked {
			t.Fatal("empty/error claim reported work")
		}
		if control.claimErr != nil && !errors.Is(err, control.claimErr) {
			t.Fatalf("claim error=%v", err)
		}
	}
	control := &fakeControl{op: &Operation{OperationID: uuid.New(), Kind: "upgrade"}}
	worked, err := (&Runner{Control: control, Runtime: runtime, Manifest: testManifest()}).RunOnce(context.Background())
	if !worked || err == nil || control.states[len(control.states)-1] != "failed_terminal" {
		t.Fatalf("unsupported=(%v,%v,%v)", worked, err, control.states)
	}
}

func TestRunnerInvalidPlanRecoveryAndControlFailures(t *testing.T) {
	invalidControl := &fakeControl{op: &Operation{OperationID: uuid.New(), Kind: "install"}}
	if _, err := (&Runner{Control: invalidControl, Runtime: &fakeRuntime{}, Manifest: Manifest{}}).RunOnce(context.Background()); err == nil || invalidControl.states[len(invalidControl.states)-1] != "failed_terminal" {
		t.Fatalf("invalid plan=%v states=%v", err, invalidControl.states)
	}
	for _, state := range []string{"paused_recoverable", "pulling"} {
		control := &fakeControl{op: &Operation{OperationID: uuid.New(), Kind: "install", State: state, Reclaimed: true}}
		runtime := &fakeRuntime{}
		if _, err := (&Runner{Control: control, Runtime: runtime, Manifest: testManifest(), InstallationID: "i"}).RunOnce(context.Background()); err != nil {
			t.Fatalf("recover %s: %v", state, err)
		}
		if state == "pulling" && len(runtime.calls) > 0 && runtime.calls[0] != "pull" {
			t.Fatalf("resume calls=%v", runtime.calls)
		}
	}
	unknown := &fakeControl{op: &Operation{OperationID: uuid.New(), Kind: "install", State: "mystery", Reclaimed: true}}
	if _, err := (&Runner{Control: unknown, Runtime: &fakeRuntime{}, Manifest: testManifest(), InstallationID: "i"}).RunOnce(context.Background()); err == nil {
		t.Fatal("unknown recovery accepted")
	}

	for _, tc := range []struct {
		name    string
		control *fakeControl
		want    string
	}{
		{"advance", &fakeControl{op: &Operation{OperationID: uuid.New(), Kind: "install"}, advanceErrAt: "preflight"}, "advance failed"},
		{"heartbeat", &fakeControl{op: &Operation{OperationID: uuid.New(), Kind: "install"}, heartbeatErr: errors.New("heartbeat failed")}, "heartbeat managed"},
		{"commit", &fakeControl{op: &Operation{OperationID: uuid.New(), Kind: "install"}, commitErr: errors.New("commit failed")}, "commit managed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := (&Runner{Control: tc.control, Runtime: &fakeRuntime{}, Manifest: testManifest(), InstallationID: "i"}).RunOnce(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestRunnerRollbackAndFailureRecordingErrors(t *testing.T) {
	op := func() *Operation { return &Operation{OperationID: uuid.New(), Kind: "install"} }
	rollbackAdvance := &fakeControl{op: op(), advanceErrAt: "rolling_back"}
	if _, err := (&Runner{Control: rollbackAdvance, Runtime: &fakeRuntime{failAt: "start"}, Manifest: testManifest(), InstallationID: "i"}).RunOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "begin managed CODE rollback") {
		t.Fatalf("rollback advance=%v", err)
	}
	rolledBackAdvance := &fakeControl{op: op(), advanceErrAt: "rolled_back"}
	if _, err := (&Runner{Control: rolledBackAdvance, Runtime: &fakeRuntime{failAt: "start"}, Manifest: testManifest(), InstallationID: "i"}).RunOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "record managed CODE rollback") {
		t.Fatalf("rolled back advance=%v", err)
	}
	failAdvance := &fakeControl{op: &Operation{OperationID: uuid.New(), Kind: "upgrade"}, advanceErrAt: "failed_terminal"}
	if _, err := (&Runner{Control: failAdvance, Runtime: &fakeRuntime{}, Manifest: testManifest()}).RunOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "record managed CODE failure") {
		t.Fatalf("failure record=%v", err)
	}
}

func TestRunnerPollValidationCancellationAndError(t *testing.T) {
	if err := (&Runner{}).Poll(context.Background(), 0); err == nil {
		t.Fatal("zero poll accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (&Runner{Control: &fakeControl{}}).Poll(ctx, time.Millisecond); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled poll=%v", err)
	}
	claimErr := errors.New("offline")
	if err := (&Runner{Control: &fakeControl{claimErr: claimErr}}).Poll(context.Background(), time.Millisecond); !errors.Is(err, claimErr) {
		t.Fatalf("error poll=%v", err)
	}
}
