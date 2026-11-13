package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/google/uuid"
)

var (
	ErrNoClaimableIntent = errors.New("no claimable upgrade intent")
	ErrExecutionDisabled = errors.New("updater execution adapters are not installed")
)

type Transaction struct {
	IntentID          string
	ReleaseID         string
	ManifestDigest    string
	RecoverySetID     string
	RecoverySetDigest string
	LeaseID           string
	ExecutorID        string
}

// Step is one bounded, retry-safe host action. Run must be idempotent for the
// same transaction and return a bounded JSON object containing no secrets.
type Step struct {
	Name string
	To   State
	Run  func(context.Context, Transaction) (json.RawMessage, error)
}

type Engine struct {
	Journal    *Journal
	Store      *ReleaseStore
	Control    ControlPlane
	ExecutorID string
	Steps      []Step
	// Rollback is the one fixed, idempotent host rollback adapter installed by
	// U2. It is never populated by the observer-only U1 production command.
	Rollback       func(context.Context, Transaction, Event, Step, error) (json.RawMessage, error)
	AllowNewClaims bool
	Logger         *slog.Logger
}

// RunOnce resumes the one local transaction or, when explicitly enabled,
// claims one approved transaction. It never accepts a release path or command.
func (engine *Engine) RunOnce(ctx context.Context) error {
	if err := engine.validate(); err != nil {
		return err
	}
	lock, err := AcquireLocalLock(engine.Journal.dir)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	if err := engine.Control.TryInstallationLock(ctx); err != nil {
		return err
	}

	journalState, err := engine.Journal.Load()
	if err != nil {
		return err
	}
	last, exists := journalState.Last()
	if exists && last.State.Terminal() {
		if !journalState.Reconciled {
			if err := engine.reconcileTerminal(ctx, last); err != nil {
				return err
			}
			return engine.Journal.Compact(true)
		}
		if !engine.AllowNewClaims {
			return nil
		}
		remote, err := engine.Control.ReadLatest(ctx)
		if err != nil {
			return err
		}
		if remote == nil || remote.ID == last.IntentID {
			return nil
		}
		if remote.State != StateApproved && remote.State != StateScheduled {
			return fmt.Errorf("new database intent %q is not claimable from reconciled terminal journal", remote.ID)
		}
		if err := engine.Journal.ArchiveReconciledTerminal(); err != nil {
			return err
		}
		journalState = JournalState{}
		exists = false
	}

	if !exists {
		if !engine.AllowNewClaims {
			return ErrExecutionDisabled
		}
		intent, err := engine.Control.ReadLatest(ctx)
		if err != nil {
			return err
		}
		if intent == nil || (intent.State != StateApproved && intent.State != StateScheduled) {
			return ErrNoClaimableIntent
		}
		if _, err := engine.Store.VerifyTree(intent.ReleaseID, intent.ManifestDigest); err != nil {
			return err
		}
		generation, err := generationFromDatabase(intent.StateGeneration)
		if err != nil {
			return err
		}
		lease := uuid.NewString()
		prepared, err := engine.Journal.Append(Event{
			IntentID: intent.ID, ReleaseID: intent.ReleaseID,
			ManifestDigest: intent.ManifestDigest, LeaseID: lease,
			RecoverySetID: intent.RecoverySetID, RecoverySetDigest: intent.RecoverySetDigest,
			ExecutorID: engine.ExecutorID, StateGeneration: generation,
			State: intent.State, Step: "claim_prepared",
			Evidence: json.RawMessage(`{"prepared":true}`),
		})
		if err != nil {
			return err
		}
		last = prepared
	}

	if last.State == StateApproved || last.State == StateScheduled {
		generation, err := generationForDatabase(last.StateGeneration)
		if err != nil {
			return err
		}
		intent := &Intent{ID: last.IntentID, ReleaseID: last.ReleaseID,
			ManifestDigest: last.ManifestDigest, State: last.State,
			RecoverySetID: last.RecoverySetID, RecoverySetDigest: last.RecoverySetDigest,
			StateGeneration: generation}
		claimed, err := engine.Control.Claim(ctx, intent, last.ExecutorID, last.LeaseID)
		if err != nil {
			return err
		}
		claimedGeneration, err := generationFromDatabase(claimed.StateGeneration)
		if err != nil {
			return err
		}
		claimedEvent, err := engine.Journal.Append(Event{
			IntentID: last.IntentID, ReleaseID: last.ReleaseID,
			ManifestDigest: last.ManifestDigest, LeaseID: last.LeaseID,
			RecoverySetID: last.RecoverySetID, RecoverySetDigest: last.RecoverySetDigest,
			ExecutorID: last.ExecutorID, StateGeneration: claimedGeneration,
			State: StateClaimed, Step: "claimed",
			Evidence: json.RawMessage(`{"claimed":true}`),
		})
		if err != nil {
			return err
		}
		last = claimedEvent
	}

	if _, err := engine.Store.VerifyTree(last.ReleaseID, last.ManifestDigest); err != nil {
		return err
	}
	if err := engine.reconcileProgress(ctx); err != nil {
		return err
	}
	journalState, err = engine.Journal.Load()
	if err != nil {
		return err
	}
	last, _ = journalState.Last()
	transaction := transactionFromEvent(last)

	for _, step := range engine.Steps {
		if stepCompleted(journalState.Events, step) {
			continue
		}
		if err := ValidateTransition(last.State, step.To); err != nil {
			return err
		}
		if err := engine.confirmContinue(ctx, last); err != nil {
			return err
		}
		evidence, runErr := step.Run(ctx, transaction)
		if runErr != nil {
			return engine.failStep(ctx, last, step, runErr)
		}
		if err := validateEvidence(evidence); err != nil {
			return engine.failStep(ctx, last, step, err)
		}
		next, err := engine.Journal.Append(nextEvent(last, step.To, step.Name, evidence))
		if err != nil {
			return err
		}
		if _, _, err := engine.Control.Progress(ctx, next, step.To, evidence); err != nil {
			return err
		}
		last = next
		journalState.Events = append(journalState.Events, next)
	}
	if last.State != StateCommitted {
		return fmt.Errorf("step catalog stopped at %q, want committed", last.State)
	}
	result := json.RawMessage(`{"verified":true}`)
	terminal, err := engine.Journal.Append(nextEvent(last, StateVerified, "verified", result))
	if err != nil {
		return err
	}
	if _, _, err := engine.Control.Complete(ctx, terminal, StateVerified, result); err != nil {
		return err
	}
	return engine.Journal.Compact(true)
}

func (engine *Engine) validate() error {
	if engine.Journal == nil || engine.Store == nil || engine.Control == nil {
		return fmt.Errorf("updater engine dependencies are incomplete")
	}
	if !journalIdentifierExpr.MatchString(engine.ExecutorID) {
		return fmt.Errorf("invalid executor ID")
	}
	if engine.Logger == nil {
		engine.Logger = slog.Default()
	}
	state := StateClaimed
	seenNames := map[string]bool{}
	crossesMaintenance := false
	for _, step := range engine.Steps {
		if !journalIdentifierExpr.MatchString(step.Name) || seenNames[step.Name] || step.Run == nil {
			return fmt.Errorf("invalid or duplicate updater step %q", step.Name)
		}
		seenNames[step.Name] = true
		if err := ValidateTransition(state, step.To); err != nil {
			return err
		}
		crossesMaintenance = crossesMaintenance || atOrAfterMaintenance(step.To)
		state = step.To
	}
	if engine.AllowNewClaims && state != StateCommitted {
		return fmt.Errorf("claim-enabled step catalog must end at committed")
	}
	if engine.AllowNewClaims && crossesMaintenance && engine.Rollback == nil {
		return fmt.Errorf("claim-enabled step catalog crosses maintenance without a rollback adapter")
	}
	return nil
}

func (engine *Engine) reconcileProgress(ctx context.Context) error {
	state, err := engine.Journal.Load()
	if err != nil {
		return err
	}
	remote, err := engine.Control.ReadLatest(ctx)
	if err != nil {
		return err
	}
	last, ok := state.Last()
	if !ok || remote == nil || remote.ID != last.IntentID {
		return fmt.Errorf("local and database upgrade transactions differ")
	}
	lastGeneration, err := generationForDatabase(last.StateGeneration)
	if err != nil {
		return err
	}
	if remote.StateGeneration > lastGeneration {
		if remote.State == StateCancelRequested && remote.StateGeneration == lastGeneration+1 {
			return nil
		}
		return fmt.Errorf("database upgrade generation %d is ahead of local journal %d",
			remote.StateGeneration, last.StateGeneration)
	}
	for _, event := range state.Events {
		eventGeneration, err := generationForDatabase(event.StateGeneration)
		if err != nil {
			return err
		}
		if eventGeneration < remote.StateGeneration {
			continue
		}
		if eventGeneration == remote.StateGeneration {
			if event.State != remote.State {
				return fmt.Errorf("database state %q differs from journal state %q at generation %d",
					remote.State, event.State, event.StateGeneration)
			}
			continue
		}
		switch event.State {
		case StateApproved, StateScheduled, StateClaimed, StateCancelRequested:
			continue
		case StateVerified, StateRolledBack, StateFailed, StateRecoveryRequired, StateCancelled:
			if err := engine.reconcileTerminal(ctx, event); err != nil {
				return err
			}
		default:
			if _, _, err := engine.Control.Progress(ctx, event, event.State, event.Evidence); err != nil {
				return err
			}
		}
		remote.State = event.State
		remote.StateGeneration = eventGeneration
	}
	return nil
}

func (engine *Engine) reconcileTerminal(ctx context.Context, event Event) error {
	_, _, err := engine.Control.Complete(ctx, event, event.State, event.Evidence)
	return err
}

func (engine *Engine) confirmContinue(ctx context.Context, local Event) error {
	remote, err := engine.Control.ReadLatest(ctx)
	if err != nil {
		return err
	}
	if remote == nil || remote.ID != local.IntentID {
		return fmt.Errorf("active upgrade intent changed while executing")
	}
	if remote.State == StateCancelRequested {
		observed, err := engine.Journal.Append(nextEvent(local, StateCancelRequested,
			"cancel_observed", json.RawMessage(`{"cancel_requested":true}`)))
		if err != nil {
			return err
		}
		cancelled := nextEvent(observed, StateCancelled, "cancelled", json.RawMessage(`{"cancelled":true}`))
		persisted, err := engine.Journal.Append(cancelled)
		if err != nil {
			return err
		}
		if _, _, err := engine.Control.Complete(ctx, persisted, StateCancelled, persisted.Evidence); err != nil {
			return err
		}
		if err := engine.Journal.Compact(true); err != nil {
			return err
		}
		return fmt.Errorf("upgrade cancelled before step execution")
	}
	return nil
}

func (engine *Engine) failStep(ctx context.Context, last Event, step Step, cause error) error {
	evidence, _ := json.Marshal(map[string]any{
		"category": "step_failed", "step": step.Name,
		"summary": boundedError(cause),
	})
	if atOrAfterMaintenance(last.State) || atOrAfterMaintenance(step.To) {
		return engine.rollbackAfterFailure(ctx, last, step, cause, evidence)
	}
	target := StateFailed
	terminal, err := engine.Journal.Append(nextEvent(last, target, string(target), evidence))
	if err != nil {
		return errors.Join(cause, err)
	}
	if _, _, completeErr := engine.Control.Complete(ctx, terminal, target, evidence); completeErr != nil {
		return errors.Join(cause, completeErr)
	}
	if compactErr := engine.Journal.Compact(true); compactErr != nil {
		return errors.Join(cause, compactErr)
	}
	return cause
}

func (engine *Engine) rollbackAfterFailure(ctx context.Context, last Event, step Step, cause error, failureEvidence json.RawMessage) error {
	rolling, err := engine.Journal.Append(nextEvent(last, StateRollingBack, "rolling_back", failureEvidence))
	if err != nil {
		return errors.Join(cause, err)
	}
	if _, _, err := engine.Control.Progress(ctx, rolling, StateRollingBack, failureEvidence); err != nil {
		return errors.Join(cause, err)
	}
	rollbackEvidence := json.RawMessage(`{"rollback":"unavailable"}`)
	rollbackErr := errors.New("rollback adapter is not installed")
	if engine.Rollback != nil {
		rollbackEvidence, rollbackErr = engine.Rollback(ctx, transactionFromEvent(rolling), rolling, step, cause)
		if evidenceErr := validateEvidence(rollbackEvidence); evidenceErr != nil {
			rollbackErr = errors.Join(rollbackErr, evidenceErr)
		}
	}
	target := StateRolledBack
	if rollbackErr != nil {
		target = StateRecoveryRequired
		rollbackEvidence, _ = json.Marshal(map[string]any{
			"category": "rollback_failed", "failed_step": step.Name,
			"upgrade_error": boundedError(cause), "rollback_error": boundedError(rollbackErr),
		})
	}
	terminal, err := engine.Journal.Append(nextEvent(rolling, target, string(target), rollbackEvidence))
	if err != nil {
		return errors.Join(cause, rollbackErr, err)
	}
	if _, _, err := engine.Control.Complete(ctx, terminal, target, rollbackEvidence); err != nil {
		return errors.Join(cause, rollbackErr, err)
	}
	if err := engine.Journal.Compact(true); err != nil {
		return errors.Join(cause, rollbackErr, err)
	}
	return errors.Join(cause, rollbackErr)
}

func nextEvent(previous Event, state State, step string, evidence json.RawMessage) Event {
	return Event{
		IntentID: previous.IntentID, ReleaseID: previous.ReleaseID,
		ManifestDigest: previous.ManifestDigest, LeaseID: previous.LeaseID,
		RecoverySetID: previous.RecoverySetID, RecoverySetDigest: previous.RecoverySetDigest,
		ExecutorID: previous.ExecutorID, StateGeneration: previous.StateGeneration + 1,
		State: state, Step: step, Evidence: evidence,
	}
}

func transactionFromEvent(event Event) Transaction {
	return Transaction{IntentID: event.IntentID, ReleaseID: event.ReleaseID,
		ManifestDigest: event.ManifestDigest, LeaseID: event.LeaseID,
		RecoverySetID: event.RecoverySetID, RecoverySetDigest: event.RecoverySetDigest,
		ExecutorID: event.ExecutorID}
}

func stepCompleted(events []Event, step Step) bool {
	return slices.ContainsFunc(events, func(event Event) bool { return event.Step == step.Name && event.State == step.To })
}

func validateEvidence(evidence json.RawMessage) error {
	if len(evidence) == 0 || len(evidence) > 64<<10 || !json.Valid(evidence) {
		return fmt.Errorf("step evidence is empty, invalid, or exceeds 64 KiB")
	}
	var object map[string]any
	if err := json.Unmarshal(evidence, &object); err != nil || object == nil {
		return fmt.Errorf("step evidence must be a JSON object")
	}
	return nil
}

func atOrAfterMaintenance(state State) bool {
	return slices.Contains([]State{StateMaintenance, StateMigrations, StateSwitched,
		StateReadiness, StateCommitted, StateRollingBack}, state)
}

func boundedError(err error) string {
	if err == nil {
		return "unknown failure"
	}
	value := err.Error()
	if len(value) > 512 {
		value = value[:512]
	}
	return value
}

// Poll runs bounded one-shot attempts. It intentionally has no network
// listener and never spins on a broken control plane.
func (engine *Engine) Poll(ctx context.Context, interval time.Duration) error {
	if interval < time.Second || interval > 15*time.Minute {
		return fmt.Errorf("poll interval must be between 1 second and 15 minutes")
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			err := engine.RunOnce(ctx)
			if err != nil && !errors.Is(err, ErrNoClaimableIntent) && !errors.Is(err, ErrExecutionDisabled) {
				engine.Logger.Error("updater iteration paused", "error", err)
			}
			timer.Reset(interval)
		}
	}
}
