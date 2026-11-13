package updater

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

type fakeRecoveryControl struct {
	intent       Intent
	recoverCalls int
	recoverError error
	lockError    error
	readError    error
	nilIntent    bool
}

func (control *fakeRecoveryControl) TryInstallationLock(context.Context) error {
	return control.lockError
}
func (control *fakeRecoveryControl) ReadLatest(context.Context) (*Intent, error) {
	if control.readError != nil {
		return nil, control.readError
	}
	if control.nilIntent {
		return nil, nil
	}
	copy := control.intent
	return &copy, nil
}
func (control *fakeRecoveryControl) Recover(_ context.Context, event Event, result json.RawMessage) (int64, bool, error) {
	control.recoverCalls++
	if control.recoverError != nil {
		return 0, false, control.recoverError
	}
	if control.intent.State == StateRolledBack && control.intent.StateGeneration == int64(event.StateGeneration) {
		return control.intent.StateGeneration, true, nil
	}
	if control.intent.State != StateRecoveryRequired || control.intent.StateGeneration+1 != int64(event.StateGeneration) || !json.Valid(result) {
		return 0, false, errors.New("recovery identity differs")
	}
	control.intent.State = StateRolledBack
	control.intent.StateGeneration = int64(event.StateGeneration)
	return control.intent.StateGeneration, false, nil
}

func TestRecoveryResumesAfterDatabaseResponseFailure(t *testing.T) {
	options, control, baseline, failed := recoveryFixture(t)
	control.recoverError = errors.New("database response lost")
	firstEvidence, err := options.Recover(context.Background(), "operator verified rollback", false, false)
	if err == nil || firstEvidence == "" {
		t.Fatalf("first recovery evidence=%q err=%v", firstEvidence, err)
	}
	current, _ := activeReleaseID(options.InstallRoot, "current")
	previous, _ := activeReleaseID(options.InstallRoot, "previous")
	if current != baseline || previous != failed {
		t.Fatalf("completed local rollback current=%q previous=%q", current, previous)
	}
	status, statusErr := options.Status()
	if statusErr != nil || !status.DatabaseReconciliationRequired {
		t.Fatalf("status=%#v err=%v", status, statusErr)
	}
	control.recoverError = nil
	secondEvidence, err := options.Recover(context.Background(), "operator verified rollback", false, false)
	if err != nil || secondEvidence == "" || control.intent.State != StateRolledBack {
		t.Fatalf("resumed recovery evidence=%q err=%v state=%s", secondEvidence, err, control.intent.State)
	}
}

func recoveryFixture(t *testing.T) (RecoveryOptions, *fakeRecoveryControl, string, string) {
	t.Helper()
	adoption := flatFixture(t)
	baseline, err := AdoptCurrentLayout(adoption)
	if err != nil {
		t.Fatal(err)
	}
	archive := webmailArchive(t, webmailEntry{name: "index.html", typeflag: '0', data: "ok"})
	storeRoot, releaseID, digest, _ := writeStageFixture(t, archive)
	store, _ := OpenReleaseStore(storeRoot)
	if _, err := store.StageRelease(context.Background(), adoption.InstallRoot, releaseID, digest,
		StagePolicy{Platform: "linux", Architecture: "amd64", FreeBytes: func(string) (uint64, error) { return 1 << 40, nil }}); err != nil {
		t.Fatal(err)
	}
	if err := ActivateRelease(adoption.InstallRoot, releaseID); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenJournal(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	lease := uuid.NewString()
	last, err := journal.Append(Event{IntentID: "42", ReleaseID: releaseID, ManifestDigest: digest,
		LeaseID: lease, ExecutorID: "setjoin-updater", StateGeneration: 9,
		State: StateRecoveryRequired, Step: "recovery_required", Evidence: json.RawMessage(`{"category":"rollback_failed"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Compact(true); err != nil {
		t.Fatal(err)
	}
	control := &fakeRecoveryControl{intent: Intent{ID: "42", ReleaseID: releaseID, ManifestDigest: digest,
		State: StateRecoveryRequired, StateGeneration: int64(last.StateGeneration), ExecutorID: "setjoin-updater", LeaseID: lease}}
	options := RecoveryOptions{InstallRoot: adoption.InstallRoot, EvidenceDir: filepath.Join(t.TempDir(), "evidence"),
		Journal: journal, Control: control, Host: &fakeHostOperations{}}
	return options, control, baseline.ReleaseID, releaseID
}

func TestRecoveryReconcilesVerifiedPreviousAndIsIdempotent(t *testing.T) {
	options, control, baseline, failed := recoveryFixture(t)
	evidencePath, err := options.Recover(context.Background(), "operator verified rollback", false, false)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(evidencePath) != options.EvidenceDir {
		t.Fatalf("evidence escaped fixed directory: %s", evidencePath)
	}
	current, _ := activeReleaseID(options.InstallRoot, "current")
	previous, _ := activeReleaseID(options.InstallRoot, "previous")
	if current != baseline || previous != failed || control.intent.State != StateRolledBack || control.recoverCalls != 1 {
		t.Fatalf("current=%q previous=%q state=%s recoverCalls=%d", current, previous, control.intent.State, control.recoverCalls)
	}
	state, err := options.Journal.Load()
	if err != nil {
		t.Fatal(err)
	}
	last, _ := state.Last()
	if !state.Reconciled || last.State != StateRolledBack {
		t.Fatalf("journal=%#v", state)
	}
	again, err := options.Recover(context.Background(), "operator verified rollback", false, false)
	if err != nil || again != evidencePath || control.recoverCalls != 1 {
		t.Fatalf("recovery replay path=%q err=%v calls=%d", again, err, control.recoverCalls)
	}
	raw, err := os.ReadFile(evidencePath)
	if err != nil || !json.Valid(raw) {
		t.Fatalf("evidence invalid: %v", err)
	}
}

func TestRecoveryReconcilesFailureBeforeReleaseActivationWithoutPrevious(t *testing.T) {
	adoption := flatFixture(t)
	baseline, err := AdoptCurrentLayout(adoption)
	if err != nil {
		t.Fatal(err)
	}
	journal := testJournal(t)
	lease := uuid.NewString()
	last, err := journal.Append(Event{IntentID: "43", ReleaseID: "failed-before-switch",
		ManifestDigest: strings.Repeat("b", 64), LeaseID: lease, ExecutorID: "setjoin-updater",
		StateGeneration: 8, State: StateRecoveryRequired, Step: "recovery_required",
		Evidence: json.RawMessage(`{"category":"rollback_failed"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Compact(true); err != nil {
		t.Fatal(err)
	}
	control := &fakeRecoveryControl{intent: Intent{ID: "43", ReleaseID: last.ReleaseID,
		ManifestDigest: last.ManifestDigest, State: StateRecoveryRequired,
		StateGeneration: int64(last.StateGeneration), ExecutorID: last.ExecutorID, LeaseID: lease}}
	host := &fakeHostOperations{}
	options := RecoveryOptions{InstallRoot: adoption.InstallRoot,
		EvidenceDir: filepath.Join(t.TempDir(), "evidence"), Journal: journal, Control: control, Host: host}
	evidence, err := options.Recover(context.Background(), "reconcile pre-switch failure", false, false)
	if err != nil || evidence == "" {
		t.Fatalf("pre-switch recovery evidence=%q err=%v", evidence, err)
	}
	current, _ := activeReleaseID(adoption.InstallRoot, "current")
	if current != baseline.ReleaseID || control.intent.State != StateRolledBack {
		t.Fatalf("current=%q state=%s", current, control.intent.State)
	}
	if previous, err := activeReleaseID(adoption.InstallRoot, "previous"); err == nil || previous != "" {
		t.Fatalf("pre-switch recovery invented previous=%q err=%v", previous, err)
	}
	if strings.Join(host.calls, ",") != "stop_updater,stop,start,readiness,start_updater" {
		t.Fatalf("host calls=%v", host.calls)
	}
}

func TestRecoveryRequiresAuthoredStateOrExplicitTTYForce(t *testing.T) {
	options, _, _, _ := recoveryFixture(t)
	state, _ := options.Journal.Load()
	last, _ := state.Last()
	// Replace the compacted state with a non-recovery terminal fixture.
	journal, err := OpenJournal(filepath.Join(t.TempDir(), "other-journal"))
	if err != nil {
		t.Fatal(err)
	}
	last.State, last.Step, last.StateGeneration = StateFailed, "failed", 1
	last.Sequence, last.PreviousHash, last.Hash, last.Version, last.OccurredAt = 0, "", "", 0, ""
	if _, err := journal.Append(last); err != nil {
		t.Fatal(err)
	}
	if err := journal.Compact(true); err != nil {
		t.Fatal(err)
	}
	options.Journal = journal
	if _, err := options.Recover(context.Background(), "manual safe rollback", false, false); !errors.Is(err, ErrRecoveryUnauthorized) {
		t.Fatalf("unauthorized recovery error=%v", err)
	}
	if _, err := options.Recover(context.Background(), "short", true, true); err == nil {
		t.Fatal("short recovery reason accepted")
	}
}

func TestRecoveryUsesLocalExecutorLockAndSurfacesUpdaterRestartFailure(t *testing.T) {
	options, _, _, _ := recoveryFixture(t)
	lock, err := AcquireLocalLock(options.Journal.dir)
	if err != nil {
		t.Fatal(err)
	}
	host := options.Host.(*fakeHostOperations)
	if _, err := options.Recover(context.Background(), "operator verified rollback", false, false); !errors.Is(err, ErrUpdaterAlreadyRunning) {
		t.Fatalf("locked recovery error=%v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	host.startUpdaterErr = errors.New("systemd unavailable")
	if _, err := options.Recover(context.Background(), "operator verified rollback", false, false); err == nil || !strings.Contains(err.Error(), "restart updater") {
		t.Fatalf("restart failure error=%v", err)
	}
}

func TestRecoveryStatusAndSnapshotRejectInvalidState(t *testing.T) {
	if _, err := (RecoveryOptions{}).Status(); err == nil {
		t.Fatal("empty status options accepted")
	}
	journal := testJournal(t)
	options := RecoveryOptions{InstallRoot: t.TempDir(), Journal: journal, EvidenceDir: "relative"}
	if _, err := options.Status(); err == nil {
		t.Fatal("missing current pointer accepted")
	}
	if _, err := options.Snapshot(context.Background(), "short"); err == nil {
		t.Fatal("short snapshot reason accepted")
	}
	options, _, _, _ = recoveryFixture(t)
	options.EvidenceDir = "relative"
	if _, err := options.Snapshot(context.Background(), "operator snapshot"); err == nil {
		t.Fatal("relative evidence directory accepted")
	}
	options, _, _, _ = recoveryFixture(t)
	if err := os.Mkdir(options.EvidenceDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(options.EvidenceDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := options.Snapshot(context.Background(), "operator snapshot"); err == nil {
		t.Fatal("insecure evidence directory accepted")
	}
}

func TestRecoveryControlPlaneAndHostFailuresAreFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure func(*RecoveryOptions, *fakeRecoveryControl)
	}{
		{"missing control", func(o *RecoveryOptions, _ *fakeRecoveryControl) { o.Control = nil }},
		{"installation lock", func(_ *RecoveryOptions, c *fakeRecoveryControl) { c.lockError = errors.New("lock failed") }},
		{"read remote", func(_ *RecoveryOptions, c *fakeRecoveryControl) { c.readError = errors.New("read failed") }},
		{"nil remote", func(_ *RecoveryOptions, c *fakeRecoveryControl) { c.nilIntent = true }},
		{"wrong remote", func(_ *RecoveryOptions, c *fakeRecoveryControl) { c.intent.ID = "other" }},
		{"wrong state", func(_ *RecoveryOptions, c *fakeRecoveryControl) { c.intent.State = StateFailed }},
		{"stop updater", func(o *RecoveryOptions, _ *fakeRecoveryControl) {
			o.Host.(*fakeHostOperations).errors = map[string]error{"stop_updater": errors.New("stop updater failed")}
		}},
		{"stop core", func(o *RecoveryOptions, _ *fakeRecoveryControl) {
			o.Host.(*fakeHostOperations).errors = map[string]error{"stop": errors.New("stop core failed")}
		}},
		{"start core", func(o *RecoveryOptions, _ *fakeRecoveryControl) {
			o.Host.(*fakeHostOperations).errors = map[string]error{"start": errors.New("start core failed")}
		}},
		{"readiness", func(o *RecoveryOptions, _ *fakeRecoveryControl) {
			o.Host.(*fakeHostOperations).errors = map[string]error{"readiness": errors.New("readiness failed")}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options, control, _, _ := recoveryFixture(t)
			tc.configure(&options, control)
			if _, err := options.Recover(context.Background(), "operator verified rollback", false, false); err == nil {
				t.Fatal("injected failure hidden")
			}
		})
	}
}

func TestRecoveryForcedLocalRollbackAndEvidenceReplay(t *testing.T) {
	options, _, baseline, failed := recoveryFixture(t)
	state, err := options.Journal.Load()
	if err != nil {
		t.Fatal(err)
	}
	last, _ := state.Last()
	journal := testJournal(t)
	last.State, last.Step, last.StateGeneration = StateFailed, "failed", 1
	last.Sequence, last.PreviousHash, last.Hash, last.Version, last.OccurredAt = 0, "", "", 0, ""
	if _, err := journal.Append(last); err != nil {
		t.Fatal(err)
	}
	if err := journal.Compact(true); err != nil {
		t.Fatal(err)
	}
	options.Journal, options.Control = journal, nil
	options.Now = func() time.Time { return time.Date(2026, 8, 1, 1, 2, 3, 0, time.UTC) }
	path, err := options.Recover(context.Background(), "manual safe rollback", true, true)
	if err != nil {
		t.Fatal(err)
	}
	current, _ := activeReleaseID(options.InstallRoot, "current")
	previous, _ := activeReleaseID(options.InstallRoot, "previous")
	if current != baseline || previous != failed {
		t.Fatalf("current=%s previous=%s", current, previous)
	}
	status, err := options.Status()
	if err != nil || status.RecoveryRequired {
		t.Fatalf("status=%#v err=%v", status, err)
	}
	if _, err := options.writeEvidence(context.Background(), "verified_previous", "manual safe rollback", true, *status); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryReasonAndUnitStateBounds(t *testing.T) {
	for _, reason := range []string{" short reason", "short", strings.Repeat("x", 1025), "valid reason\n", "valid\treason"} {
		if err := validateRecoveryReason(reason); err == nil {
			t.Fatalf("reason %q accepted", reason)
		}
	}
	if err := validateRecoveryReason("valid recovery reason"); err != nil {
		t.Fatal(err)
	}
	prior := execCommandContext
	t.Cleanup(func() { execCommandContext = prior })
	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if args[len(args)-1] == "setjoin" {
			return exec.CommandContext(ctx, "/bin/sh", "-c", "printf active")
		}
		if args[len(args)-1] == "setjoin-auth" {
			return exec.CommandContext(ctx, "/bin/sh", "-c", "printf '%040d' 1")
		}
		return exec.CommandContext(ctx, "/bin/false")
	}
	states := fixedUnitStates(context.Background())
	if states["setjoin"] != "active" || states["setjoin-auth"] != "unknown" || states["setjoin-updater"] != "unknown" {
		t.Fatalf("states=%v", states)
	}
}

func TestRecoveryStatusSnapshotAndForceRejectCorruptLocalAuthority(t *testing.T) {
	t.Run("unsafe previous pointer", func(t *testing.T) {
		options, _, _, _ := recoveryFixture(t)
		if err := os.Remove(filepath.Join(options.InstallRoot, "previous")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/tmp", filepath.Join(options.InstallRoot, "previous")); err != nil {
			t.Fatal(err)
		}
		if _, err := options.Status(); err == nil {
			t.Fatal("unsafe previous pointer was accepted")
		}
	})
	t.Run("corrupt journal", func(t *testing.T) {
		options, _, _, _ := recoveryFixture(t)
		path := filepath.Join(options.Journal.dir, snapshotFileName)
		if err := os.WriteFile(path, []byte("{"), journalFileMode); err != nil {
			t.Fatal(err)
		}
		if _, err := options.Status(); err == nil {
			t.Fatal("corrupt recovery journal was accepted")
		}
	})
	t.Run("snapshot status", func(t *testing.T) {
		options := RecoveryOptions{InstallRoot: filepath.Join(t.TempDir(), "missing"), EvidenceDir: filepath.Join(t.TempDir(), "evidence"), Journal: testJournal(t)}
		if _, err := options.Snapshot(context.Background(), "operator snapshot"); err == nil {
			t.Fatal("snapshot without current release succeeded")
		}
	})
	for name, options := range map[string]RecoveryOptions{
		"missing host":      {InstallRoot: t.TempDir(), EvidenceDir: t.TempDir(), Journal: testJournal(t)},
		"relative evidence": {InstallRoot: t.TempDir(), EvidenceDir: "relative", Journal: testJournal(t), Host: &fakeHostOperations{}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := options.Recover(context.Background(), "operator recovery", true, true); err == nil {
				t.Fatal("incomplete recovery dependencies were accepted")
			}
		})
	}
	t.Run("recover status", func(t *testing.T) {
		options := RecoveryOptions{InstallRoot: filepath.Join(t.TempDir(), "missing"), EvidenceDir: filepath.Join(t.TempDir(), "evidence"), Journal: testJournal(t), Host: &fakeHostOperations{}}
		if _, err := options.Recover(context.Background(), "operator recovery", true, true); err == nil {
			t.Fatal("recovery without current release succeeded")
		}
	})
	t.Run("no previous", func(t *testing.T) {
		adoption := flatFixture(t)
		if _, err := AdoptCurrentLayout(adoption); err != nil {
			t.Fatal(err)
		}
		options := RecoveryOptions{InstallRoot: adoption.InstallRoot, EvidenceDir: filepath.Join(t.TempDir(), "evidence"), Journal: testJournal(t), Host: &fakeHostOperations{}}
		if _, err := options.Recover(context.Background(), "operator recovery", true, true); err == nil || !strings.Contains(err.Error(), "no distinct") {
			t.Fatalf("no-previous error=%v", err)
		}
	})
}

func TestRecoveryEvidenceAndReconciliationFailuresRemainActionable(t *testing.T) {
	t.Run("insecure evidence directory", func(t *testing.T) {
		options, _, _, _ := recoveryFixture(t)
		if err := os.Mkdir(options.EvidenceDir, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(options.EvidenceDir, 0o777); err != nil {
			t.Fatal(err)
		}
		if _, err := options.Recover(context.Background(), "operator verified rollback", false, false); err == nil {
			t.Fatal("insecure recovery evidence directory accepted")
		}
	})
	t.Run("evidence collision", func(t *testing.T) {
		options, _, _, _ := recoveryFixture(t)
		options.Now = func() time.Time { return time.Date(2026, 8, 1, 2, 3, 4, 0, time.UTC) }
		if err := ensureSecureDirectory(options.EvidenceDir, 0o700); err != nil {
			t.Fatal(err)
		}
		status, err := options.Status()
		if err != nil {
			t.Fatal(err)
		}
		path, err := options.writeEvidence(context.Background(), "before", "operator verified rollback", false, *status)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("different"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := options.Recover(context.Background(), "operator verified rollback", false, false); err == nil || !errors.Is(errorCause(err), os.ErrExist) {
			t.Fatalf("evidence collision error=%v", err)
		}
	})
	t.Run("reconciled updater restart", func(t *testing.T) {
		options, _, _, _ := recoveryFixture(t)
		path, err := options.Recover(context.Background(), "operator verified rollback", false, false)
		if err != nil {
			t.Fatal(err)
		}
		options.Host.(*fakeHostOperations).startUpdaterErr = errors.New("updater restart failed")
		got, err := options.Recover(context.Background(), "operator verified rollback", false, false)
		if got != path || err == nil || !strings.Contains(err.Error(), "reconciled") {
			t.Fatalf("reconciled restart path=%q err=%v", got, err)
		}
	})
	t.Run("database reconciliation", func(t *testing.T) {
		options, control, _, _ := recoveryFixture(t)
		control.recoverError = errors.New("database response unavailable")
		if _, err := options.Recover(context.Background(), "operator verified rollback", false, false); err == nil {
			t.Fatal("initial database response failure hidden")
		}
		if _, err := options.Recover(context.Background(), "operator verified rollback", false, false); err == nil || !strings.Contains(err.Error(), "database response unavailable") {
			t.Fatalf("database reconciliation error=%v", err)
		}
	})
}
