package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"setjoin.com/mailserver/internal/deploycatalog"
)

var ErrRecoveryUnauthorized = errors.New("break-glass recovery is not authorized")

type RecoveryHost interface {
	StopCore(context.Context) error
	StartCore(context.Context) error
	Readiness(context.Context) error
	StopUpdater(context.Context) error
	StartUpdater(context.Context) error
}

type RecoveryOptions struct {
	InstallRoot string
	EvidenceDir string
	Journal     *Journal
	Control     RecoveryControlPlane
	Host        RecoveryHost
	Now         func() time.Time
}

type RecoveryStatus struct {
	Current                        string `json:"current"`
	Previous                       string `json:"previous,omitempty"`
	IntentID                       string `json:"intent_id,omitempty"`
	IntentState                    State  `json:"intent_state,omitempty"`
	RecoveryRequired               bool   `json:"recovery_required"`
	DatabaseReconciliationRequired bool   `json:"database_reconciliation_required"`
	JournalHash                    string `json:"journal_hash,omitempty"`
}

type RecoveryEvidence struct {
	SchemaVersion int               `json:"schema_version"`
	RecordedAt    string            `json:"recorded_at"`
	Phase         string            `json:"phase"`
	Reason        string            `json:"reason"`
	Forced        bool              `json:"forced"`
	Status        RecoveryStatus    `json:"status"`
	Units         map[string]string `json:"units"`
}

func (options RecoveryOptions) Status() (*RecoveryStatus, error) {
	if !filepath.IsAbs(options.InstallRoot) || options.Journal == nil {
		return nil, fmt.Errorf("recovery status paths are invalid")
	}
	current, err := activeReleaseID(options.InstallRoot, "current")
	if err != nil {
		return nil, err
	}
	status := &RecoveryStatus{Current: current}
	if previous, err := activeReleaseID(options.InstallRoot, "previous"); err == nil {
		status.Previous = previous
	} else if !errors.Is(errorCause(err), os.ErrNotExist) {
		return nil, err
	}
	state, err := options.Journal.Load()
	if err != nil {
		return nil, err
	}
	if last, ok := state.Last(); ok {
		status.IntentID, status.IntentState, status.JournalHash = last.IntentID, last.State, last.Hash
		status.RecoveryRequired = last.State == StateRecoveryRequired
		status.DatabaseReconciliationRequired = last.State == StateRolledBack && last.Step == "break_glass_reconciled" && !state.Reconciled
	}
	return status, nil
}

func (options RecoveryOptions) Snapshot(ctx context.Context, reason string) (string, error) {
	if err := validateRecoveryReason(reason); err != nil {
		return "", err
	}
	if !filepath.IsAbs(options.EvidenceDir) {
		return "", fmt.Errorf("recovery evidence directory is invalid")
	}
	if err := ensureSecureDirectory(options.EvidenceDir, 0o700); err != nil {
		return "", err
	}
	status, err := options.Status()
	if err != nil {
		return "", err
	}
	return options.writeEvidence(ctx, "operator_snapshot", reason, false, *status)
}

func (options RecoveryOptions) Recover(ctx context.Context, reason string, force, tty bool) (evidencePath string, returnErr error) {
	if options.Host == nil || !filepath.IsAbs(options.EvidenceDir) {
		return "", fmt.Errorf("recovery dependencies are incomplete")
	}
	if err := validateRecoveryReason(reason); err != nil {
		return "", err
	}
	status, err := options.Status()
	if err != nil {
		return "", err
	}
	if status.IntentState == StateRolledBack && !status.DatabaseReconciliationRequired {
		state, loadErr := options.Journal.Load()
		if loadErr == nil {
			if last, ok := state.Last(); ok && last.Step == "break_glass_reconciled" {
				var prior struct {
					EvidenceFile string `json:"evidence_file"`
				}
				if json.Unmarshal(last.Evidence, &prior) == nil && filepath.Base(prior.EvidenceFile) == prior.EvidenceFile {
					path := filepath.Join(options.EvidenceDir, prior.EvidenceFile)
					if info, statErr := os.Lstat(path); statErr == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o077 == 0 {
						if err := startUpdaterBounded(options.Host); err != nil {
							return path, fmt.Errorf("recovery is reconciled but updater restart failed: %w", err)
						}
						return path, nil
					}
				}
			}
		}
	}
	if !status.RecoveryRequired && !status.DatabaseReconciliationRequired && !(force && tty) {
		return "", ErrRecoveryUnauthorized
	}
	var authoredLast Event
	if status.RecoveryRequired {
		state, loadErr := options.Journal.Load()
		if loadErr != nil {
			return "", loadErr
		}
		authoredLast, _ = state.Last()
	}
	failedReleaseNeverActivated := status.RecoveryRequired && status.Current != authoredLast.ReleaseID
	if !status.DatabaseReconciliationRequired && !failedReleaseNeverActivated && (status.Previous == "" || status.Previous == status.Current) {
		return "", fmt.Errorf("no distinct complete previous release is available")
	}
	if err := ensureSecureDirectory(options.EvidenceDir, 0o700); err != nil {
		return "", err
	}
	preEvidence, err := options.writeEvidence(ctx, "before", reason, force, *status)
	if err != nil {
		return "", err
	}
	if err := options.Host.StopUpdater(ctx); err != nil {
		return preEvidence, err
	}
	updaterStopped := true
	defer func() {
		if updaterStopped {
			if err := startUpdaterBounded(options.Host); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("restart updater after recovery attempt: %w", err))
			}
		}
	}()
	lock, err := AcquireLocalLock(options.Journal.dir)
	if err != nil {
		return preEvidence, err
	}
	defer func() {
		if err := lock.Close(); err != nil {
			returnErr = errors.Join(returnErr, err)
		}
	}()
	lockedStatus, err := options.Status()
	if err != nil {
		return preEvidence, err
	}
	if *lockedStatus != *status {
		return preEvidence, fmt.Errorf("recovery state changed while acquiring the execution boundary")
	}

	var last Event
	if status.RecoveryRequired || status.DatabaseReconciliationRequired {
		state, err := options.Journal.Load()
		if err != nil {
			return preEvidence, err
		}
		last, _ = state.Last()
		if options.Control == nil {
			return preEvidence, fmt.Errorf("recovery-required transaction needs its updater control plane")
		}
		if err := options.Control.TryInstallationLock(ctx); err != nil {
			return preEvidence, err
		}
		remote, err := options.Control.ReadLatest(ctx)
		if err != nil {
			return preEvidence, err
		}
		if remote == nil || remote.ID != last.IntentID {
			return preEvidence, fmt.Errorf("database and local recovery transaction differ")
		}
		lastGeneration, generationErr := generationForDatabase(last.StateGeneration)
		if generationErr != nil {
			return preEvidence, generationErr
		}
		if status.RecoveryRequired && (remote.State != StateRecoveryRequired || remote.StateGeneration != lastGeneration) {
			return preEvidence, fmt.Errorf("database and local recovery transaction differ")
		}
		if status.DatabaseReconciliationRequired {
			if _, _, err := options.Control.Recover(ctx, last, last.Evidence); err != nil {
				return preEvidence, err
			}
			if err := options.Journal.Compact(true); err != nil {
				return preEvidence, err
			}
			reconciled, err := options.Status()
			if err != nil {
				return preEvidence, err
			}
			return options.writeEvidence(ctx, "database_reconciled", reason, force, *reconciled)
		}
	}
	failedRelease := status.Current
	if status.RecoveryRequired {
		failedRelease = last.ReleaseID
	}
	if err := options.Host.StopCore(ctx); err != nil {
		return preEvidence, err
	}
	if status.Current == failedRelease {
		if err := ActivatePrevious(options.InstallRoot, failedRelease); err != nil {
			return preEvidence, err
		}
	}
	if err := options.Host.StartCore(ctx); err != nil {
		return preEvidence, err
	}
	if err := options.Host.Readiness(ctx); err != nil {
		return preEvidence, err
	}
	postStatus, err := options.Status()
	if err != nil {
		return preEvidence, err
	}
	postEvidence, err := options.writeEvidence(ctx, "verified_previous", reason, force, *postStatus)
	if err != nil {
		return preEvidence, err
	}
	if status.RecoveryRequired {
		result, _ := json.Marshal(map[string]string{
			"rollback": "verified", "reason": reason,
			"previous_release": postStatus.Current, "evidence_file": filepath.Base(postEvidence),
		})
		recovered, err := options.Journal.Append(nextEvent(last, StateRolledBack, "break_glass_reconciled", result))
		if err != nil {
			return postEvidence, err
		}
		if _, _, err := options.Control.Recover(ctx, recovered, result); err != nil {
			return postEvidence, err
		}
		if err := options.Journal.Compact(true); err != nil {
			return postEvidence, err
		}
	}
	return postEvidence, nil
}

func startUpdaterBounded(host RecoveryHost) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return host.StartUpdater(ctx)
}

func (options RecoveryOptions) writeEvidence(ctx context.Context, phase, reason string, forced bool, status RecoveryStatus) (string, error) {
	now := time.Now().UTC().Truncate(time.Second)
	if options.Now != nil {
		now = options.Now().UTC().Truncate(time.Second)
	}
	evidence := RecoveryEvidence{SchemaVersion: 1, RecordedAt: now.Format(time.RFC3339),
		Phase: phase, Reason: reason, Forced: forced, Status: status, Units: fixedUnitStates(ctx)}
	raw, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return "", err
	}
	raw = append(raw, '\n')
	sum := sha256.Sum256(raw)
	name := fmt.Sprintf("recovery-%s-%s-%s.json", now.Format("20060102T150405Z"), phase, hex.EncodeToString(sum[:6]))
	path := filepath.Join(options.EvidenceDir, name)
	// EvidenceDir is a validated private root; name contains only fixed phase,
	// normalized UTC time, and a hex digest, while O_EXCL prevents replacement.
	//nolint:gosec // G304: no request-controlled filesystem path is opened.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		//nolint:gosec // G304: path is the same bounded evidence filename described above.
		existing, readErr := os.ReadFile(path)
		if readErr == nil && string(existing) == string(raw) {
			return path, nil
		}
	}
	if err != nil {
		return "", err
	}
	if _, err := file.Write(raw); err != nil {
		file.Close()
		return "", err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	if err := syncDirectory(options.EvidenceDir); err != nil {
		return "", err
	}
	return path, nil
}

func validateRecoveryReason(reason string) error {
	if len(reason) < 8 || len(reason) > 1024 || strings.TrimSpace(reason) != reason {
		return fmt.Errorf("recovery reason must be 8..1024 trimmed bytes")
	}
	for _, character := range reason {
		if unicode.IsControl(character) {
			return fmt.Errorf("recovery reason contains control characters")
		}
	}
	return nil
}

func fixedUnitStates(ctx context.Context) map[string]string {
	states := map[string]string{}
	for _, unit := range deploycatalog.RecoveryObserved() {
		command := execCommandContext(ctx, "systemctl", "is-active", unit.Name)
		command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
		output, err := command.Output()
		state := strings.TrimSpace(string(output))
		if err != nil || len(state) == 0 || len(state) > 32 {
			state = "unknown"
		}
		states[unit.Name] = state
	}
	return states
}
