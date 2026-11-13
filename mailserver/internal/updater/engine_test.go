package updater

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"setjoin.com/shared/release"
)

type fakeControlPlane struct {
	intent               Intent
	lease                string
	evidence             map[State]string
	failClaimResponse    bool
	failProgressBefore   State
	loseProgressResponse State
	loseCompleteResponse bool
	progressCalls        map[State]int
	completeCalls        int
	lockErr              error
	readErr              error
	nilIntent            bool
	claimErr             error
	completeErr          error
}

func newFakeControlPlane(releaseID, digest string) *fakeControlPlane {
	return &fakeControlPlane{
		intent: Intent{ID: "42", ReleaseID: releaseID, ManifestDigest: digest,
			State: StateApproved, StateGeneration: 1},
		evidence: map[State]string{}, progressCalls: map[State]int{},
	}
}

func (fake *fakeControlPlane) TryInstallationLock(context.Context) error { return fake.lockErr }

func (fake *fakeControlPlane) ReadLatest(context.Context) (*Intent, error) {
	if fake.readErr != nil {
		return nil, fake.readErr
	}
	if fake.nilIntent {
		return nil, nil
	}
	copy := fake.intent
	return &copy, nil
}

func (fake *fakeControlPlane) Claim(_ context.Context, intent *Intent, executorID, leaseID string) (*Intent, error) {
	if fake.claimErr != nil {
		return nil, fake.claimErr
	}
	if fake.intent.State == StateClaimed && fake.lease == leaseID {
		copy := fake.intent
		copy.ExecutorID, copy.LeaseID = executorID, leaseID
		return &copy, nil
	}
	if fake.intent.State != intent.State || fake.intent.StateGeneration != intent.StateGeneration {
		return nil, errors.New("stale claim")
	}
	fake.intent.State = StateClaimed
	fake.intent.StateGeneration++
	fake.intent.ExecutorID, fake.intent.LeaseID, fake.lease = executorID, leaseID, leaseID
	copy := fake.intent
	if fake.failClaimResponse {
		fake.failClaimResponse = false
		return nil, ErrControlPlaneUnavailable
	}
	return &copy, nil
}

func (fake *fakeControlPlane) Progress(_ context.Context, event Event, target State, _ json.RawMessage) (int64, bool, error) {
	fake.progressCalls[target]++
	if fake.failProgressBefore == target {
		fake.failProgressBefore = ""
		return 0, false, ErrControlPlaneUnavailable
	}
	if fake.intent.State == target && fake.intent.StateGeneration == int64(event.StateGeneration) {
		if fake.evidence[target] != event.Hash {
			return 0, false, errors.New("changed replay evidence")
		}
		return fake.intent.StateGeneration, true, nil
	}
	if int64(event.StateGeneration) != fake.intent.StateGeneration+1 {
		return 0, false, errors.New("out-of-order progress")
	}
	if err := ValidateTransition(fake.intent.State, target); err != nil {
		return 0, false, err
	}
	fake.intent.State, fake.intent.StateGeneration = target, int64(event.StateGeneration)
	fake.evidence[target] = event.Hash
	if fake.loseProgressResponse == target {
		fake.loseProgressResponse = ""
		return 0, false, ErrControlPlaneUnavailable
	}
	return fake.intent.StateGeneration, false, nil
}

func (fake *fakeControlPlane) Complete(_ context.Context, event Event, target State, _ json.RawMessage) (int64, bool, error) {
	fake.completeCalls++
	if fake.completeErr != nil {
		return 0, false, fake.completeErr
	}
	if fake.intent.State == target && fake.intent.StateGeneration == int64(event.StateGeneration) {
		if fake.evidence[target] != event.Hash {
			return 0, false, errors.New("changed terminal evidence")
		}
		return fake.intent.StateGeneration, true, nil
	}
	if int64(event.StateGeneration) != fake.intent.StateGeneration+1 {
		return 0, false, errors.New("out-of-order completion")
	}
	fake.intent.State, fake.intent.StateGeneration = target, int64(event.StateGeneration)
	fake.evidence[target] = event.Hash
	if fake.loseCompleteResponse {
		fake.loseCompleteResponse = false
		return 0, false, ErrControlPlaneUnavailable
	}
	return fake.intent.StateGeneration, false, nil
}

func TestEngineResumesClaimAndProgressResponseLossWithoutRepeatingStep(t *testing.T) {
	t.Parallel()
	engine, fake, counts := newEngineFixture(t)
	fake.failClaimResponse = true
	if err := engine.RunOnce(context.Background()); !errors.Is(err, ErrControlPlaneUnavailable) {
		t.Fatalf("claim loss: got %v", err)
	}
	fake.loseProgressResponse = StateRecoveryPoint
	if err := engine.RunOnce(context.Background()); !errors.Is(err, ErrControlPlaneUnavailable) {
		t.Fatalf("progress loss: got %v", err)
	}
	if counts[StateRecoveryPoint] != 1 {
		t.Fatalf("recovery point ran %d times", counts[StateRecoveryPoint])
	}
	if err := engine.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fake.intent.State != StateVerified {
		t.Fatalf("got state %s", fake.intent.State)
	}
	if counts[StateRecoveryPoint] != 1 {
		t.Fatalf("durable step reran after response loss: %d", counts[StateRecoveryPoint])
	}
	state, err := engine.Journal.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !state.Reconciled || len(state.Events) != 1 || state.Events[0].State != StateVerified {
		t.Fatalf("unexpected compacted journal: %#v", state)
	}
}

func TestEnginePausesWhenDBFailsBeforeProgressThenResumes(t *testing.T) {
	t.Parallel()
	engine, fake, counts := newEngineFixture(t)
	fake.failProgressBefore = StateStaged
	if err := engine.RunOnce(context.Background()); !errors.Is(err, ErrControlPlaneUnavailable) {
		t.Fatalf("got %v", err)
	}
	if counts[StateStaged] != 1 || fake.intent.State != StateRecoveryPoint {
		t.Fatalf("unexpected pause: count=%d state=%s", counts[StateStaged], fake.intent.State)
	}
	if err := engine.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if counts[StateStaged] != 1 || fake.intent.State != StateVerified {
		t.Fatalf("resume reran step or did not finish: count=%d state=%s", counts[StateStaged], fake.intent.State)
	}
}

func TestEngineResumesLostTerminalResponse(t *testing.T) {
	t.Parallel()
	engine, fake, _ := newEngineFixture(t)
	fake.loseCompleteResponse = true
	if err := engine.RunOnce(context.Background()); !errors.Is(err, ErrControlPlaneUnavailable) {
		t.Fatalf("got %v", err)
	}
	if fake.intent.State != StateVerified {
		t.Fatalf("DB completion did not land: %s", fake.intent.State)
	}
	if err := engine.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fake.completeCalls != 2 {
		t.Fatalf("expected exact completion replay, calls=%d", fake.completeCalls)
	}
}

func TestEngineStartsNextApprovedIntentAfterReconciledTerminal(t *testing.T) {
	engine, fake, counts := newEngineFixture(t)
	if err := engine.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fake.intent.State != StateVerified {
		t.Fatalf("first state=%s", fake.intent.State)
	}
	fake.intent = Intent{ID: "43", ReleaseID: fake.intent.ReleaseID,
		ManifestDigest: fake.intent.ManifestDigest, State: StateApproved, StateGeneration: 1}
	fake.lease = ""
	fake.evidence = map[State]string{}
	if err := engine.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fake.intent.State != StateVerified || counts[StateCommitted] != 2 {
		t.Fatalf("second state=%s committedRuns=%d", fake.intent.State, counts[StateCommitted])
	}
	archive, err := readBounded(filepath.Join(engine.Journal.dir, terminalArchiveFileName), maxJournalRecord)
	if err != nil || !bytes.Contains(archive, []byte(`"intent_id":"42"`)) {
		t.Fatalf("previous terminal archive=%q err=%v", archive, err)
	}
}

func TestEngineFailsClosedBeforeClaimWhenReleaseTreeMissing(t *testing.T) {
	t.Parallel()
	engine, fake, _ := newEngineFixture(t)
	fake.intent.ReleaseID = "missing"
	if err := engine.RunOnce(context.Background()); !errors.Is(err, ErrReleaseUnavailable) {
		t.Fatalf("got %v", err)
	}
	if fake.intent.State != StateApproved {
		t.Fatalf("missing release was claimed: %s", fake.intent.State)
	}
}

func TestEngineClassifiesPreAndPostMaintenanceFailure(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		fail State
		want State
	}{
		{name: "preflight", fail: StateRecoveryPoint, want: StateFailed},
		{name: "post-maintenance", fail: StateMigrations, want: StateRecoveryRequired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine, fake, _ := newEngineFixture(t)
			engine.Rollback = func(context.Context, Transaction, Event, Step, error) (json.RawMessage, error) {
				return nil, errors.New("injected rollback failure")
			}
			for index := range engine.Steps {
				if engine.Steps[index].To == tc.fail {
					engine.Steps[index].Run = func(context.Context, Transaction) (json.RawMessage, error) {
						return nil, errors.New("injected adapter failure")
					}
				}
			}
			if err := engine.RunOnce(context.Background()); err == nil {
				t.Fatal("step failure was hidden")
			}
			if fake.intent.State != tc.want {
				t.Fatalf("got %s, want %s", fake.intent.State, tc.want)
			}
		})
	}
}

func TestEngineRunsFixedRollbackAndEscalatesSecondFailure(t *testing.T) {
	for _, tc := range []struct {
		name        string
		rollbackErr error
		want        State
	}{
		{name: "rollback verified", want: StateRolledBack},
		{name: "rollback failed", rollbackErr: errors.New("restart failed"), want: StateRecoveryRequired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine, fake, _ := newEngineFixture(t)
			for index := range engine.Steps {
				if engine.Steps[index].To == StateReadiness {
					engine.Steps[index].Run = func(context.Context, Transaction) (json.RawMessage, error) {
						return nil, errors.New("readiness failed")
					}
				}
			}
			rollbackCalls := 0
			engine.Rollback = func(context.Context, Transaction, Event, Step, error) (json.RawMessage, error) {
				rollbackCalls++
				return json.RawMessage(`{"rollback":"verified"}`), tc.rollbackErr
			}
			if err := engine.RunOnce(context.Background()); err == nil {
				t.Fatal("upgrade failure was hidden")
			}
			if rollbackCalls != 1 || fake.intent.State != tc.want || fake.progressCalls[StateRollingBack] != 1 {
				t.Fatalf("rollbackCalls=%d state=%s rolling=%d", rollbackCalls, fake.intent.State, fake.progressCalls[StateRollingBack])
			}
		})
	}
}

func TestEngineValidationAndObserverBoundaries(t *testing.T) {
	t.Parallel()
	if err := (&Engine{}).validate(); err == nil {
		t.Fatal("empty engine accepted")
	}
	engine, fake, _ := newEngineFixture(t)
	for _, id := range []string{"", "bad/id"} {
		copy := *engine
		copy.ExecutorID = id
		if err := copy.validate(); err == nil {
			t.Fatalf("executor %q accepted", id)
		}
	}
	for name, steps := range map[string][]Step{
		"bad name":   {{Name: "bad/name", To: StatePreflight, Run: func(context.Context, Transaction) (json.RawMessage, error) { return json.RawMessage(`{}`), nil }}},
		"nil run":    {{Name: "step", To: StatePreflight}},
		"duplicate":  {{Name: "step", To: StatePreflight, Run: func(context.Context, Transaction) (json.RawMessage, error) { return json.RawMessage(`{}`), nil }}, {Name: "step", To: StateRecoveryPoint, Run: func(context.Context, Transaction) (json.RawMessage, error) { return json.RawMessage(`{}`), nil }}},
		"transition": {{Name: "step", To: StateSwitched, Run: func(context.Context, Transaction) (json.RawMessage, error) { return json.RawMessage(`{}`), nil }}},
	} {
		copy := *engine
		copy.Steps = steps
		if err := copy.validate(); err == nil {
			t.Fatalf("%s catalog accepted", name)
		}
	}
	copy := *engine
	copy.Steps = engine.Steps[:1]
	if err := copy.validate(); err == nil {
		t.Fatal("claim-enabled partial catalog accepted")
	}
	copy = *engine
	copy.Rollback = nil
	if err := copy.validate(); err == nil {
		t.Fatal("claim-enabled maintenance catalog without rollback accepted")
	}

	engine.AllowNewClaims = false
	if err := engine.RunOnce(context.Background()); !errors.Is(err, ErrExecutionDisabled) {
		t.Fatalf("observer error=%v", err)
	}
	engine.AllowNewClaims = true
	fake.nilIntent = true
	if err := engine.RunOnce(context.Background()); !errors.Is(err, ErrNoClaimableIntent) {
		t.Fatalf("nil intent error=%v", err)
	}
	fake.nilIntent = false
	fake.intent.State = StatePreflight
	if err := engine.RunOnce(context.Background()); !errors.Is(err, ErrNoClaimableIntent) {
		t.Fatalf("nonclaimable error=%v", err)
	}
	fake.intent.State = StateApproved
	fake.lockErr = ErrInstallationLocked
	if err := engine.RunOnce(context.Background()); !errors.Is(err, ErrInstallationLocked) {
		t.Fatalf("lock error=%v", err)
	}
}

func TestEngineCancellationIsJournaledBeforeNextHostStep(t *testing.T) {
	t.Parallel()
	engine, fake, counts := newEngineFixture(t)
	lease := "11111111-1111-4111-8111-111111111111"
	prepared, err := engine.Journal.Append(Event{IntentID: fake.intent.ID, ReleaseID: fake.intent.ReleaseID,
		ManifestDigest: fake.intent.ManifestDigest, LeaseID: lease, ExecutorID: engine.ExecutorID,
		StateGeneration: 1, State: StateApproved, Step: "claim_prepared", Evidence: json.RawMessage(`{"prepared":true}`)})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := engine.Journal.Append(nextEvent(prepared, StateClaimed, "claimed", json.RawMessage(`{"claimed":true}`)))
	if err != nil {
		t.Fatal(err)
	}
	fake.intent.State, fake.intent.StateGeneration = StateCancelRequested, int64(claimed.StateGeneration)+1
	fake.intent.ExecutorID, fake.intent.LeaseID, fake.lease = engine.ExecutorID, lease, lease
	if err := engine.RunOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("cancel result=%v", err)
	}
	if fake.intent.State != StateCancelled || fake.completeCalls != 1 {
		t.Fatalf("state=%s completes=%d", fake.intent.State, fake.completeCalls)
	}
	for state, count := range counts {
		if count != 0 {
			t.Fatalf("host step %s ran %d times", state, count)
		}
	}
	state, err := engine.Journal.Load()
	if err != nil || !state.Reconciled {
		t.Fatalf("journal=%#v err=%v", state, err)
	}
}

func TestEngineEvidenceAndHelperBoundaries(t *testing.T) {
	t.Parallel()
	for _, evidence := range []json.RawMessage{nil, []byte(`null`), []byte(`[]`), []byte(`{`), bytes.Repeat([]byte("x"), (64<<10)+1)} {
		if err := validateEvidence(evidence); err == nil {
			t.Fatalf("invalid evidence %.20q accepted", evidence)
		}
	}
	if err := validateEvidence(json.RawMessage(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}
	if got := boundedError(nil); got != "unknown failure" {
		t.Fatalf("nil error=%q", got)
	}
	long := boundedError(errors.New(strings.Repeat("x", 600)))
	if len(long) != 512 {
		t.Fatalf("bounded error length=%d", len(long))
	}
	if !atOrAfterMaintenance(StateMaintenance) || atOrAfterMaintenance(StateStaged) {
		t.Fatal("maintenance classifier drift")
	}
	event := Event{IntentID: "1", ReleaseID: "release", ManifestDigest: strings.Repeat("a", 64), LeaseID: "lease", ExecutorID: "executor", StateGeneration: 3}
	next := nextEvent(event, StatePreflight, "preflight", json.RawMessage(`{}`))
	if next.StateGeneration != 4 || transactionFromEvent(next).IntentID != "1" {
		t.Fatalf("next=%#v", next)
	}
	if !stepCompleted([]Event{next}, Step{Name: "preflight", To: StatePreflight}) || stepCompleted([]Event{next}, Step{Name: "other", To: StatePreflight}) {
		t.Fatal("step completion classifier drift")
	}
}

func TestEngineInvalidStepEvidenceFailsBeforeMaintenance(t *testing.T) {
	t.Parallel()
	for _, evidence := range []json.RawMessage{nil, json.RawMessage(`[]`)} {
		engine, fake, _ := newEngineFixture(t)
		engine.Steps[0].Run = func(context.Context, Transaction) (json.RawMessage, error) { return evidence, nil }
		if err := engine.RunOnce(context.Background()); err == nil {
			t.Fatal("invalid evidence hidden")
		}
		if fake.intent.State != StateFailed {
			t.Fatalf("state=%s", fake.intent.State)
		}
	}
}

func TestEngineReconcileDetectsDivergenceAndPollCancellation(t *testing.T) {
	t.Parallel()
	engine, fake, _ := newEngineFixture(t)
	if err := engine.Poll(context.Background(), time.Millisecond); err == nil {
		t.Fatal("short poll accepted")
	}
	if err := engine.Poll(context.Background(), 16*time.Minute); err == nil {
		t.Fatal("long poll accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := engine.Poll(ctx, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("poll cancel=%v", err)
	}
	engine, fake, _ = newEngineFixture(t)
	prepared, err := engine.Journal.Append(Event{IntentID: fake.intent.ID, ReleaseID: fake.intent.ReleaseID,
		ManifestDigest: fake.intent.ManifestDigest, LeaseID: "11111111-1111-4111-8111-111111111111", ExecutorID: engine.ExecutorID,
		StateGeneration: 1, State: StateApproved, Step: "claim_prepared", Evidence: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	fake.intent.ID = "other"
	if err := engine.reconcileProgress(context.Background()); err == nil {
		t.Fatal("intent divergence accepted")
	}
	fake.intent.ID = prepared.IntentID
	fake.intent.State, fake.intent.StateGeneration = StatePreflight, 3
	if err := engine.reconcileProgress(context.Background()); err == nil {
		t.Fatal("ahead generation accepted")
	}
	fake.intent.State, fake.intent.StateGeneration = StateScheduled, 1
	if err := engine.reconcileProgress(context.Background()); err == nil {
		t.Fatal("same-generation state drift accepted")
	}
	fake.readErr = ErrControlPlaneUnavailable
	if err := engine.reconcileProgress(context.Background()); !errors.Is(err, ErrControlPlaneUnavailable) {
		t.Fatalf("read error=%v", err)
	}
}

func newEngineFixture(t *testing.T) (*Engine, *fakeControlPlane, map[State]int) {
	t.Helper()
	base := t.TempDir()
	stateDir := filepath.Join(base, "state")
	journal, err := OpenJournal(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	storeRoot := filepath.Join(base, "releases")
	if err := os.Mkdir(storeRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	releaseDir := filepath.Join(storeRoot, "release-1")
	if err := os.Mkdir(releaseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(minimalManifest())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(releaseDir, "manifest.json"), data, 0o444); err != nil {
		t.Fatal(err)
	}
	canonical, err := release.CanonicalManifest(minimalManifest())
	if err != nil {
		t.Fatal(err)
	}
	digestBytes := sha256.Sum256(canonical)
	digest := hex.EncodeToString(digestBytes[:])
	store, err := OpenReleaseStore(storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	fake := newFakeControlPlane("release-1", digest)
	counts := map[State]int{}
	states := []State{StatePreflight, StateRecoveryPoint, StateStaged, StateMaintenance,
		StateMigrations, StateSwitched, StateReadiness, StateCommitted}
	steps := make([]Step, 0, len(states))
	for _, target := range states {
		target := target
		steps = append(steps, Step{Name: "step_" + string(target), To: target,
			Run: func(context.Context, Transaction) (json.RawMessage, error) {
				counts[target]++
				return json.RawMessage(`{"ok":true}`), nil
			}})
	}
	return &Engine{Journal: journal, Store: store, Control: fake,
		ExecutorID: "updater-test", Steps: steps, AllowNewClaims: true,
		Rollback: func(context.Context, Transaction, Event, Step, error) (json.RawMessage, error) {
			return json.RawMessage(`{"rollback":"verified"}`), nil
		}}, fake, counts
}

func TestReadCredentialFileIsBoundedPrivateAndSingleLine(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "dsn")
	if err := os.WriteFile(path, []byte("postgres://setjoin_updater:secret@127.0.0.1/mailserver\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadCredentialFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "postgres://setjoin_updater:") {
		t.Fatalf("unexpected credential result")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCredentialFile(path); err == nil {
		t.Fatal("world-readable credential accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("one\ntwo"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCredentialFile(path); err == nil {
		t.Fatal("multi-line credential accepted")
	}
}

func TestReadPrivateKeyFilePreservesExactBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "recovery.key")
	want := []byte(strings.Repeat("a", 32) + "\n")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadPrivateKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("private key bytes changed: got=%q want=%q", got, want)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivateKeyFile(path); err == nil {
		t.Fatal("group-readable private key accepted")
	}
}

func TestEngineRunOnceSurfacesEveryDurableBoundaryFailure(t *testing.T) {
	t.Run("validation", func(t *testing.T) {
		engine, _, _ := newEngineFixture(t)
		engine.ExecutorID = "bad/id"
		if err := engine.RunOnce(context.Background()); err == nil {
			t.Fatal("invalid engine ran")
		}
	})
	t.Run("local lock", func(t *testing.T) {
		engine, _, _ := newEngineFixture(t)
		lock, err := AcquireLocalLock(engine.Journal.dir)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		if err := engine.RunOnce(context.Background()); !errors.Is(err, ErrUpdaterAlreadyRunning) {
			t.Fatalf("lock error=%v", err)
		}
	})
	t.Run("journal load", func(t *testing.T) {
		engine, _, _ := newEngineFixture(t)
		if err := os.WriteFile(filepath.Join(engine.Journal.dir, journalFileName), []byte("{"), journalFileMode); err != nil {
			t.Fatal(err)
		}
		if err := engine.RunOnce(context.Background()); err == nil {
			t.Fatal("corrupt journal was accepted")
		}
	})
	t.Run("reconciled terminal", func(t *testing.T) {
		engine, fake, _ := newEngineFixture(t)
		terminal, err := engine.Journal.Append(testEvent(StateFailed, "failed"))
		if err != nil {
			t.Fatal(err)
		}
		if err := engine.Journal.Compact(true); err != nil {
			t.Fatal(err)
		}
		fake.intent.State, fake.intent.StateGeneration = terminal.State, int64(terminal.StateGeneration)
		if err := engine.RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("terminal reconciliation", func(t *testing.T) {
		engine, fake, _ := newEngineFixture(t)
		if _, err := engine.Journal.Append(testEvent(StateFailed, "failed")); err != nil {
			t.Fatal(err)
		}
		fake.completeErr = errors.New("complete failed")
		if err := engine.RunOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "complete failed") {
			t.Fatalf("terminal reconciliation error=%v", err)
		}
	})
	t.Run("initial read", func(t *testing.T) {
		engine, fake, _ := newEngineFixture(t)
		fake.readErr = errors.New("read failed")
		if err := engine.RunOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "read failed") {
			t.Fatalf("initial read error=%v", err)
		}
	})
	t.Run("claim prepared append", func(t *testing.T) {
		engine, _, _ := newEngineFixture(t)
		engine.Journal.syncFile = func(*os.File) error { return errors.New("prepared fsync") }
		if err := engine.RunOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "prepared fsync") {
			t.Fatalf("prepared append error=%v", err)
		}
	})
	t.Run("claim request", func(t *testing.T) {
		engine, fake, _ := newEngineFixture(t)
		fake.claimErr = errors.New("claim failed")
		if err := engine.RunOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "claim failed") {
			t.Fatalf("claim error=%v", err)
		}
	})
	t.Run("claimed append", func(t *testing.T) {
		engine, _, _ := newEngineFixture(t)
		calls := 0
		engine.Journal.syncFile = func(file *os.File) error {
			calls++
			if calls == 2 {
				return errors.New("claimed fsync")
			}
			return file.Sync()
		}
		if err := engine.RunOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "claimed fsync") {
			t.Fatalf("claimed append error=%v", err)
		}
	})
	t.Run("post-claim release verification", func(t *testing.T) {
		engine, fake, _ := newEngineFixture(t)
		event := testEvent(StateClaimed, "claimed")
		event.ReleaseID = "missing"
		if _, err := engine.Journal.Append(event); err != nil {
			t.Fatal(err)
		}
		fake.intent.ID, fake.intent.ReleaseID, fake.intent.ManifestDigest = event.IntentID, event.ReleaseID, event.ManifestDigest
		fake.intent.State, fake.intent.StateGeneration = StateClaimed, int64(event.StateGeneration)
		if err := engine.RunOnce(context.Background()); !errors.Is(err, ErrReleaseUnavailable) {
			t.Fatalf("release verification error=%v", err)
		}
	})
	t.Run("runtime transition", func(t *testing.T) {
		engine, fake, _ := newEngineFixture(t)
		event := testEvent(StatePreflight, "different_preflight")
		event.IntentID, event.ReleaseID, event.ManifestDigest = fake.intent.ID, fake.intent.ReleaseID, fake.intent.ManifestDigest
		if _, err := engine.Journal.Append(event); err != nil {
			t.Fatal(err)
		}
		fake.intent.State, fake.intent.StateGeneration = StatePreflight, int64(event.StateGeneration)
		if err := engine.RunOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "illegal upgrade transition") {
			t.Fatalf("transition error=%v", err)
		}
	})
	t.Run("catalog stops before commit", func(t *testing.T) {
		engine, fake, _ := newEngineFixture(t)
		event := testEvent(StateClaimed, "claimed")
		event.IntentID, event.ReleaseID, event.ManifestDigest = fake.intent.ID, fake.intent.ReleaseID, fake.intent.ManifestDigest
		if _, err := engine.Journal.Append(event); err != nil {
			t.Fatal(err)
		}
		fake.intent.State, fake.intent.StateGeneration = StateClaimed, int64(event.StateGeneration)
		engine.AllowNewClaims = false
		engine.Steps = engine.Steps[:1]
		if err := engine.RunOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "stopped") {
			t.Fatalf("catalog error=%v", err)
		}
	})
	t.Run("terminal append", func(t *testing.T) {
		engine, fake, _ := newEngineFixture(t)
		event := testEvent(StateClaimed, "claimed")
		event.IntentID, event.ReleaseID, event.ManifestDigest = fake.intent.ID, fake.intent.ReleaseID, fake.intent.ManifestDigest
		if _, err := engine.Journal.Append(event); err != nil {
			t.Fatal(err)
		}
		fake.intent.State, fake.intent.StateGeneration = StateClaimed, int64(event.StateGeneration)
		calls := 0
		engine.Journal.syncFile = func(file *os.File) error {
			calls++
			if calls == len(engine.Steps)+1 {
				return errors.New("terminal fsync")
			}
			return file.Sync()
		}
		if err := engine.RunOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "terminal fsync") {
			t.Fatalf("terminal append error=%v calls=%d", err, calls)
		}
	})
}

func TestEngineReconciliationAndFailureAdaptersPreserveErrors(t *testing.T) {
	engine, fake, _ := newEngineFixture(t)
	local := testEvent(StateClaimed, "claimed")
	fake.readErr = errors.New("confirm read failed")
	if err := engine.confirmContinue(context.Background(), local); err == nil || !strings.Contains(err.Error(), "confirm read failed") {
		t.Fatalf("confirm read error=%v", err)
	}
	fake.readErr, fake.nilIntent = nil, true
	if err := engine.confirmContinue(context.Background(), local); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("confirm identity error=%v", err)
	}

	engine, fake, _ = newEngineFixture(t)
	if _, err := engine.Journal.Append(local); err != nil {
		t.Fatal(err)
	}
	fake.completeErr = errors.New("terminal write failed")
	if err := engine.failStep(context.Background(), local, engine.Steps[0], errors.New("adapter failed")); err == nil || !strings.Contains(err.Error(), "terminal write failed") {
		t.Fatalf("fail-step completion error=%v", err)
	}

	engine, fake, _ = newEngineFixture(t)
	maintenance := testEvent(StateMaintenance, "maintenance")
	if _, err := engine.Journal.Append(maintenance); err != nil {
		t.Fatal(err)
	}
	fake.intent.ID, fake.intent.ReleaseID, fake.intent.ManifestDigest = maintenance.IntentID, maintenance.ReleaseID, maintenance.ManifestDigest
	fake.intent.State, fake.intent.StateGeneration = StateMaintenance, int64(maintenance.StateGeneration)
	fake.failProgressBefore = StateRollingBack
	if err := engine.rollbackAfterFailure(context.Background(), maintenance, Step{Name: "switch", To: StateSwitched}, errors.New("switch failed"), json.RawMessage(`{"failed":true}`)); err == nil || !errors.Is(err, ErrControlPlaneUnavailable) {
		t.Fatalf("rollback progress error=%v", err)
	}

	engine, fake, _ = newEngineFixture(t)
	if _, err := engine.Journal.Append(maintenance); err != nil {
		t.Fatal(err)
	}
	fake.intent.ID, fake.intent.ReleaseID, fake.intent.ManifestDigest = maintenance.IntentID, maintenance.ReleaseID, maintenance.ManifestDigest
	fake.intent.State, fake.intent.StateGeneration = StateMaintenance, int64(maintenance.StateGeneration)
	engine.Rollback = func(context.Context, Transaction, Event, Step, error) (json.RawMessage, error) {
		return json.RawMessage(`[]`), nil
	}
	if err := engine.rollbackAfterFailure(context.Background(), maintenance, Step{Name: "switch", To: StateSwitched}, errors.New("switch failed"), json.RawMessage(`{"failed":true}`)); err == nil {
		t.Fatal("invalid rollback evidence was hidden")
	}
	if fake.intent.State != StateRecoveryRequired {
		t.Fatalf("rollback target=%s", fake.intent.State)
	}
}

func TestEngineJournalAndTerminalFailureReturnsRemainVisible(t *testing.T) {
	seed := func(t *testing.T, state State, step string) (*Engine, *fakeControlPlane, Event) {
		t.Helper()
		engine, fake, _ := newEngineFixture(t)
		event := testEvent(state, step)
		event.IntentID, event.ReleaseID, event.ManifestDigest = fake.intent.ID, fake.intent.ReleaseID, fake.intent.ManifestDigest
		persisted, err := engine.Journal.Append(event)
		if err != nil {
			t.Fatal(err)
		}
		fake.intent.State, fake.intent.StateGeneration = state, int64(persisted.StateGeneration)
		return engine, fake, persisted
	}
	t.Run("run reconciliation", func(t *testing.T) {
		engine, fake, _ := seed(t, StateClaimed, "claimed")
		fake.intent.ID = "other"
		if err := engine.RunOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "differ") {
			t.Fatalf("reconciliation error=%v", err)
		}
	})
	t.Run("second journal load", func(t *testing.T) {
		engine, _, _ := newEngineFixture(t)
		if err := os.WriteFile(filepath.Join(engine.Journal.dir, journalFileName), []byte("{"), journalFileMode); err != nil {
			t.Fatal(err)
		}
		if err := engine.reconcileProgress(context.Background()); err == nil {
			t.Fatal("corrupt journal reconciled")
		}
	})
	t.Run("step append", func(t *testing.T) {
		engine, _, _ := seed(t, StateClaimed, "claimed")
		engine.Journal.syncFile = func(*os.File) error { return errors.New("step fsync") }
		if err := engine.RunOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "step fsync") {
			t.Fatalf("step append error=%v", err)
		}
	})
	t.Run("cancel completion", func(t *testing.T) {
		engine, fake, local := seed(t, StateClaimed, "claimed")
		fake.intent.State, fake.intent.StateGeneration = StateCancelRequested, int64(local.StateGeneration)+1
		fake.completeErr = errors.New("cancel completion failed")
		if err := engine.confirmContinue(context.Background(), local); err == nil || !strings.Contains(err.Error(), "cancel completion failed") {
			t.Fatalf("cancel completion error=%v", err)
		}
	})
	t.Run("fail-step append", func(t *testing.T) {
		engine, _, local := seed(t, StateClaimed, "claimed")
		engine.Journal.syncFile = func(*os.File) error { return errors.New("failure fsync") }
		if err := engine.failStep(context.Background(), local, engine.Steps[0], errors.New("adapter failed")); err == nil || !strings.Contains(err.Error(), "failure fsync") {
			t.Fatalf("fail-step append error=%v", err)
		}
	})
	t.Run("fail-step compaction", func(t *testing.T) {
		engine, _, local := seed(t, StateClaimed, "claimed")
		engine.Journal.syncDir = func(string) error { return errors.New("compact directory fsync") }
		if err := engine.failStep(context.Background(), local, engine.Steps[0], errors.New("adapter failed")); err == nil || !strings.Contains(err.Error(), "compact directory fsync") {
			t.Fatalf("fail-step compact error=%v", err)
		}
	})
	t.Run("rollback append", func(t *testing.T) {
		engine, _, local := seed(t, StateMaintenance, "maintenance")
		engine.Journal.syncFile = func(*os.File) error { return errors.New("rolling fsync") }
		if err := engine.rollbackAfterFailure(context.Background(), local, Step{Name: "switch", To: StateSwitched}, errors.New("switch failed"), json.RawMessage(`{"failed":true}`)); err == nil || !strings.Contains(err.Error(), "rolling fsync") {
			t.Fatalf("rollback append error=%v", err)
		}
	})
	t.Run("rollback terminal append", func(t *testing.T) {
		engine, _, local := seed(t, StateMaintenance, "maintenance")
		calls := 0
		engine.Journal.syncFile = func(file *os.File) error {
			calls++
			if calls == 2 {
				return errors.New("rollback terminal fsync")
			}
			return file.Sync()
		}
		engine.Rollback = func(context.Context, Transaction, Event, Step, error) (json.RawMessage, error) {
			return json.RawMessage(`{"rollback":"verified"}`), nil
		}
		if err := engine.rollbackAfterFailure(context.Background(), local, Step{Name: "switch", To: StateSwitched}, errors.New("switch failed"), json.RawMessage(`{"failed":true}`)); err == nil || !strings.Contains(err.Error(), "rollback terminal fsync") {
			t.Fatalf("rollback terminal append error=%v", err)
		}
	})
	t.Run("rollback completion", func(t *testing.T) {
		engine, fake, local := seed(t, StateMaintenance, "maintenance")
		engine.Rollback = func(context.Context, Transaction, Event, Step, error) (json.RawMessage, error) {
			return json.RawMessage(`{"rollback":"verified"}`), nil
		}
		fake.completeErr = errors.New("rollback completion failed")
		if err := engine.rollbackAfterFailure(context.Background(), local, Step{Name: "switch", To: StateSwitched}, errors.New("switch failed"), json.RawMessage(`{"failed":true}`)); err == nil || !strings.Contains(err.Error(), "rollback completion failed") {
			t.Fatalf("rollback completion error=%v", err)
		}
	})
	t.Run("rollback compaction", func(t *testing.T) {
		engine, _, local := seed(t, StateMaintenance, "maintenance")
		engine.Rollback = func(context.Context, Transaction, Event, Step, error) (json.RawMessage, error) {
			return json.RawMessage(`{"rollback":"verified"}`), nil
		}
		engine.Journal.syncDir = func(string) error { return errors.New("rollback compact fsync") }
		if err := engine.rollbackAfterFailure(context.Background(), local, Step{Name: "switch", To: StateSwitched}, errors.New("switch failed"), json.RawMessage(`{"failed":true}`)); err == nil || !strings.Contains(err.Error(), "rollback compact fsync") {
			t.Fatalf("rollback compact error=%v", err)
		}
	})
}
