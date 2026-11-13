// publish_edge_test.go — the atomic publisher's refusal and crash-injection
// edges the commit-path suites never reach: argument validation (nil change
// set, missing ledger path, unsafe run id, unreadable ledger), stage
// failures that leave a retained journal or a committed-but-unreported
// publication, Recover's hostile-directory and corrupt-entry arms, and the
// atomicWrite failure ladders reached through replay targets that cannot be
// materialized (paths under a regular file, rename onto a directory).
package securityprogram

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// journalFixtureBytes renders a hand-built journal document the way
// Publish's marshal stage would (two-space indent) so replay tests can plant
// exact, parseable crash locks.
func journalFixtureBytes(t *testing.T, doc map[string]any) []byte {
	t.Helper()
	out, err := json.MarshalIndent(doc, "", " ")
	if err != nil {
		t.Fatalf("journal marshal: %v", err)
	}
	return out
}

// skipAsRoot keeps the permission-driven failure injections honest: a root
// process ignores file modes, so the injected EACCS never fires and the
// assertion would lie.
func skipAsRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("permission-based failure injection requires a non-root tester")
	}
}

func startedChangeSet(t *testing.T, ctx context.Context, ledgerPath string) *ChangeSet {
	t.Helper()
	raw, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatalf("fixture read: %v", err)
	}
	svc, err := serviceFromBytes(t, raw)
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	cs, err := svc.Start(ctx, StartRequest{Request: authedReq(testOcc)})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	return cs
}

func TestPublishArgumentRefusals(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	ledgerPath, _ := writeTestLedger(t, dir)
	cs := startedChangeSet(t, ctx, ledgerPath)
	pub := NewFilePublisher()

	// A nil change set is a caller bug, not a publication.
	if err := pub.Publish(ctx, nil, ledgerPath); !IsCode(err, CodeUsage) {
		t.Fatalf("nil change set = %v", err)
	}
	// The ledger path is a required argument.
	if err := pub.Publish(ctx, cs, ""); !IsCode(err, CodeUsage) {
		t.Fatalf("empty ledger path = %v", err)
	}
	// A run id that could not name a journal file safely never reaches the
	// filesystem.
	badRun := *cs
	badRun.Transition.RunID = "../evil"
	if err := pub.Publish(ctx, &badRun, ledgerPath); !IsCode(err, CodeUsage) {
		t.Fatalf("unsafe run id = %v", err)
	}
	// An unreadable ledger cannot be hash-checked against the change set.
	if err := pub.Publish(ctx, cs, filepath.Join(dir, "absent.json")); !IsCode(err, CodeEvidenceInvalid) {
		t.Fatalf("unreadable ledger = %v", err)
	}
}

func TestPublishEmptyEvidencePathIsUsage(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	ledgerPath, _ := writeTestLedger(t, dir)
	cs := stageCompleteOnDiskFixture(t, ledgerPath)
	cs.Evidence = &EvidenceFile{Path: "", Body: cs.Evidence.Body}
	if err := NewFilePublisher().Publish(ctx, cs, ledgerPath); !IsCode(err, CodeUsage) {
		t.Fatalf("empty evidence path = %v", err)
	}
}

func TestPublishSingleTargetWriteFailure(t *testing.T) {
	skipAsRoot(t)
	ctx := context.Background()
	dir := t.TempDir()
	ledgerPath, beforeHash := writeTestLedger(t, dir)
	cs := startedChangeSet(t, ctx, ledgerPath)
	// A read-only ledger directory accepts the hash check but not the write.
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	defer func() { _ = os.Chmod(dir, 0o755) }()
	err := NewFilePublisher().Publish(ctx, cs, ledgerPath)
	if !IsCode(err, CodeInternal) || !strings.Contains(err.Error(), "ledger publication failed") {
		t.Fatalf("single-target write failure = %v", err)
	}
	if raw, readErr := os.ReadFile(ledgerPath); readErr != nil || SHA256Hex(raw) != beforeHash {
		t.Fatalf("failed publication must leave the ledger byte-identical")
	}
}

func TestPublishJournalWriteFailureOnFileOccupiedLockName(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	ledgerPath, _ := writeTestLedger(t, dir)
	cs := stageCompleteOnDiskFixture(t, ledgerPath)
	resolved := filepath.Join(dir, cs.Evidence.Path)
	// The on-disk state the failing publication would have moved from.
	onDisk, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatalf("ledger read: %v", err)
	}
	onDiskHash := SHA256Hex(onDisk)
	// The crash-lock directory name is occupied by a regular file, so the
	// journal's atomic write cannot create its directory.
	if err := os.WriteFile(filepath.Join(dir, journalDirName), []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("occupy: %v", err)
	}
	twoTarget := &ChangeSet{
		Transition:         cs.Transition,
		LedgerAfter:        cs.LedgerAfter,
		LedgerBeforeSHA256: cs.LedgerBeforeSHA256,
		Evidence:           &EvidenceFile{Path: resolved, Body: cs.Evidence.Body},
	}
	err = NewFilePublisher().Publish(ctx, twoTarget, ledgerPath)
	if !IsCode(err, CodeInternal) || !strings.Contains(err.Error(), "crash-lock journal write failed") {
		t.Fatalf("journal write failure = %v", err)
	}
	if raw, readErr := os.ReadFile(ledgerPath); readErr != nil || SHA256Hex(raw) != onDiskHash {
		t.Fatalf("no target may move when the journal cannot be written")
	}
}

func TestPublishEvidenceWriteFailureRetainsJournal(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	ledgerPath, _ := writeTestLedger(t, dir)
	cs := stageCompleteOnDiskFixture(t, ledgerPath)
	// The on-disk state the failing publication would have moved from.
	onDisk, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatalf("ledger read: %v", err)
	}
	onDiskHash := SHA256Hex(onDisk)
	// The evidence target sits under a regular file, so its atomic write
	// cannot create the parent directories.
	cs.Evidence = &EvidenceFile{
		Path: filepath.Join(dir, "blocker", "manifest.json"),
		Body: cs.Evidence.Body,
	}
	if err := os.WriteFile(filepath.Join(dir, "blocker"), []byte("file"), 0o644); err != nil {
		t.Fatalf("blocker: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Join(dir, "blocker")) })
	twoTarget := &ChangeSet{
		Transition:         cs.Transition,
		LedgerAfter:        cs.LedgerAfter,
		LedgerBeforeSHA256: cs.LedgerBeforeSHA256,
		Evidence:           cs.Evidence,
	}
	err = NewFilePublisher().Publish(ctx, twoTarget, ledgerPath)
	if !IsCode(err, CodeInternal) || !strings.Contains(err.Error(), "evidence publication failed") {
		t.Fatalf("evidence write failure = %v", err)
	}
	// The journal stays behind as the crash lock; the ledger has not moved.
	if _, statErr := os.Stat(filepath.Join(dir, journalDirName, cs.Transition.RunID+".journal.json")); statErr != nil {
		t.Fatalf("failed publication must retain its crash-lock journal")
	}
	if raw, readErr := os.ReadFile(ledgerPath); readErr != nil || SHA256Hex(raw) != onDiskHash {
		t.Fatalf("failed publication must leave the ledger untouched")
	}
	// Recovery after clearing the blocker deterministically completes it.
	if err := os.Remove(filepath.Join(dir, "blocker")); err != nil {
		t.Fatalf("unblock: %v", err)
	}
	reports, err := NewFilePublisher().Recover(ctx, dir)
	if err != nil || len(reports) != 1 || !reports[0].Resolved {
		t.Fatalf("recover after unblock = %v/%+v", err, reports)
	}
}

func TestPublishLedgerStageFailureRetainsRecoverableJournal(t *testing.T) {
	skipAsRoot(t)
	ctx := context.Background()
	dir := t.TempDir()
	ledgerPath, _ := writeTestLedger(t, dir)
	cs := stageCompleteOnDiskFixture(t, ledgerPath)
	resolved := filepath.Join(dir, cs.Evidence.Path)
	// The evidence stage succeeds, then the directory goes read-only so the
	// ledger rename fails with the journal already retained.
	pub := &FilePublisher{failAfter: func(stage string) error {
		if stage == "evidence" {
			_ = os.Chmod(dir, 0o555) // publication continues into the failing ledger write
		}
		return nil
	}}
	defer func() { _ = os.Chmod(dir, 0o755) }()
	err := pub.Publish(ctx, &ChangeSet{
		Transition:         cs.Transition,
		LedgerAfter:        cs.LedgerAfter,
		LedgerBeforeSHA256: cs.LedgerBeforeSHA256,
		Evidence:           &EvidenceFile{Path: resolved, Body: cs.Evidence.Body},
	}, ledgerPath)
	if !IsCode(err, CodeInternal) || !strings.Contains(err.Error(), "ledger publication failed") {
		t.Fatalf("ledger stage failure = %v", err)
	}
	if _, statErr := os.Stat(resolved); statErr != nil {
		t.Fatalf("evidence committed before the failure must persist")
	}
	// Clearing the permission lets Recover complete the staged publication.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("unblock: %v", err)
	}
	ledgerBody, err := func() ([]byte, error) {
		reports, err := NewFilePublisher().Recover(ctx, dir)
		if err != nil || len(reports) != 1 || !reports[0].Resolved {
			return nil, err
		}
		return os.ReadFile(ledgerPath)
	}()
	if err != nil || !bytes.Equal(ledgerBody, cs.LedgerAfter) {
		t.Fatalf("recovery did not complete the staged ledger: %v", err)
	}
}

func TestPublishJournalRemovalFailureReportsCommitted(t *testing.T) {
	skipAsRoot(t)
	ctx := context.Background()
	dir := t.TempDir()
	ledgerPath, _ := writeTestLedger(t, dir)
	cs := stageCompleteOnDiskFixture(t, ledgerPath)
	resolved := filepath.Join(dir, cs.Evidence.Path)
	journalDir := filepath.Join(dir, journalDirName)
	// Once both targets are committed, the journal directory goes read-only
	// so its removal fails: the publication is COMPLETE but unreported — the
	// error must say so and point at Recover.
	pub := &FilePublisher{failAfter: func(stage string) error {
		if stage == "ledger" {
			_ = os.Chmod(journalDir, 0o555) // both targets committed; removal now fails
		}
		return nil
	}}
	defer func() { _ = os.Chmod(journalDir, 0o755) }()
	err := pub.Publish(ctx, &ChangeSet{
		Transition:         cs.Transition,
		LedgerAfter:        cs.LedgerAfter,
		LedgerBeforeSHA256: cs.LedgerBeforeSHA256,
		Evidence:           &EvidenceFile{Path: resolved, Body: cs.Evidence.Body},
	}, ledgerPath)
	if !IsCode(err, CodeInternal) || !strings.Contains(err.Error(), "publication is complete") {
		t.Fatalf("journal removal failure = %v", err)
	}
	// Both targets carry the staged bytes; Recover then clears the lock.
	ledgerBody, _ := os.ReadFile(ledgerPath)
	if !bytes.Equal(ledgerBody, cs.LedgerAfter) {
		t.Fatalf("committed publication must carry the staged ledger bytes")
	}
	_ = os.Chmod(journalDir, 0o755)
	if reports, err := NewFilePublisher().Recover(ctx, dir); err != nil || len(reports) != 1 {
		t.Fatalf("recover must clear the committed publication's journal: %v", err)
	}
}

func TestPublishCommitStageFailureStillCommitted(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	ledgerPath, _ := writeTestLedger(t, dir)
	cs := stageCompleteOnDiskFixture(t, ledgerPath)
	resolved := filepath.Join(dir, cs.Evidence.Path)
	// A failure reported at the commit stage cannot uncommit anything: the
	// caller learns the publication succeeded on disk but its receipt of
	// that fact was lost.
	pub := &FilePublisher{failAfter: func(stage string) error {
		if stage == "commit" {
			return errCrashInjected
		}
		return nil
	}}
	err := pub.Publish(ctx, &ChangeSet{
		Transition:         cs.Transition,
		LedgerAfter:        cs.LedgerAfter,
		LedgerBeforeSHA256: cs.LedgerBeforeSHA256,
		Evidence:           &EvidenceFile{Path: resolved, Body: cs.Evidence.Body},
	}, ledgerPath)
	if err != errCrashInjected {
		t.Fatalf("commit-stage failure = %v", err)
	}
	ledgerBody, _ := os.ReadFile(ledgerPath)
	evBody, _ := os.ReadFile(resolved)
	if !bytes.Equal(ledgerBody, cs.LedgerAfter) || !bytes.Equal(evBody, cs.Evidence.Body) {
		t.Fatalf("commit-stage failure must leave both targets committed")
	}
	if _, statErr := os.Stat(filepath.Join(dir, journalDirName)); !os.IsNotExist(statErr) {
		t.Fatalf("committed publication must still have cleared its journal")
	}
}

func TestRecoverAbsentAndHostileJournalDirectories(t *testing.T) {
	ctx := context.Background()
	// A directory with no crash lock at all recovers nothing, silently.
	reports, err := NewFilePublisher().Recover(ctx, t.TempDir())
	if err != nil || len(reports) != 0 {
		t.Fatalf("recover without a journal dir = %v/%+v", err, reports)
	}
	// A crash-lock name occupied by a regular file is unreadable as a
	// directory — an internal fault, never a silent success.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, journalDirName), []byte("x"), 0o644); err != nil {
		t.Fatalf("occupy: %v", err)
	}
	_, err = NewFilePublisher().Recover(ctx, dir)
	if !IsCode(err, CodeInternal) || !strings.Contains(err.Error(), "journal directory unreadable") {
		t.Fatalf("file-occupied journal dir = %v", err)
	}
}

// TestRecoverSkipsNonJournalEntriesAndNilEvidence drives the entry filter
// (directories and non-.json files are never replayed) and the ledger-only
// journal shape (no evidence target — the nil arm) whose targets already
// match their pins: replay removes the journal without rewriting anything.
func TestRecoverSkipsNonJournalEntriesAndNilEvidence(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	ledgerPath, ledgerHash := writeTestLedger(t, dir)
	journalDir := filepath.Join(dir, journalDirName)
	if err := os.MkdirAll(journalDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	keep := filepath.Join(journalDir, "keep")
	if err := os.MkdirAll(keep, 0o755); err != nil {
		t.Fatalf("subdir: %v", err)
	}
	notes := filepath.Join(journalDir, "notes.txt")
	if err := os.WriteFile(notes, []byte("operator notes"), 0o644); err != nil {
		t.Fatalf("notes: %v", err)
	}
	ledgerRaw, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatalf("ledger read: %v", err)
	}
	journal := map[string]any{
		"schema":   journalSchema,
		"contract": ContractVersion,
		"runId":    testRunID,
		"ledger":   journalFile{Path: ledgerPath, SHA256: ledgerHash, Body: string(ledgerRaw)},
	}
	journalBytes := journalFixtureBytes(t, journal)
	if err := os.WriteFile(filepath.Join(journalDir, testRunID+".journal.json"), journalBytes, 0o644); err != nil {
		t.Fatalf("journal: %v", err)
	}

	reports, err := NewFilePublisher().Recover(ctx, dir)
	if err != nil || len(reports) != 1 {
		t.Fatalf("recover = %v/%+v, want exactly the one journal replayed", err, reports)
	}
	if len(reports[0].Repaired) != 0 {
		t.Fatalf("already-committed targets must not be rewritten: %+v", reports[0].Repaired)
	}
	// The non-journal entries survive untouched.
	if _, statErr := os.Stat(keep); statErr != nil {
		t.Fatalf("directory entry must be skipped, not removed")
	}
	if _, statErr := os.Stat(notes); statErr != nil {
		t.Fatalf("non-json entry must be skipped, not removed")
	}
}

// TestRecoverBrokenJournalEntryIsAnInternalFault plants a listed-but-
// unreadable entry (a broken symlink wearing the .json suffix): the replay
// refuses with an internal code and the entry stays for reconciliation.
func TestRecoverBrokenJournalEntryIsAnInternalFault(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	journalDir := filepath.Join(dir, journalDirName)
	if err := os.MkdirAll(journalDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	broken := filepath.Join(journalDir, "broken.journal.json")
	if err := os.Symlink(filepath.Join(dir, "no-such-target"), broken); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	_, err := NewFilePublisher().Recover(ctx, dir)
	if !IsCode(err, CodeInternal) || !strings.Contains(err.Error(), "journal unreadable") {
		t.Fatalf("broken journal entry = %v", err)
	}
	if _, statErr := os.Lstat(broken); statErr != nil {
		t.Fatalf("unreadable journal entry must be quarantined in place")
	}
}

// TestRecoverReplayWriteFailureUnderRegularFile replays a journal whose
// ledger target lives under a regular file: the replay write cannot create
// its parent directories and refuses with an internal fault.
func TestRecoverReplayWriteFailureUnderRegularFile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	writeTestLedger(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "blocker"), []byte("file"), 0o644); err != nil {
		t.Fatalf("blocker: %v", err)
	}
	journalDir := filepath.Join(dir, journalDirName)
	if err := os.MkdirAll(journalDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	journal := map[string]any{
		"schema":   journalSchema,
		"contract": ContractVersion,
		"runId":    testRunID,
		"ledger": journalFile{
			Path:   filepath.Join(dir, "blocker", "sub", "ledger.json"),
			SHA256: SHA256Hex([]byte("staged")),
			Body:   "staged",
		},
	}
	journalBytes := journalFixtureBytes(t, journal)
	if err := os.WriteFile(filepath.Join(journalDir, "replay.journal.json"), journalBytes, 0o644); err != nil {
		t.Fatalf("journal: %v", err)
	}
	if _, err := NewFilePublisher().Recover(ctx, dir); !IsCode(err, CodeInternal) || !strings.Contains(err.Error(), "replay write failed") {
		t.Fatalf("replay under a regular file = %v", err)
	}
}

// TestRecoverReplayRenameFailureOntoDirectory replays a journal whose target
// is an existing directory: the temp file is written but the final rename can
// never replace a directory — the refusal surfaces as an internal fault.
func TestRecoverReplayRenameFailureOntoDirectory(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	target := filepath.Join(dir, "occupied")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("target dir: %v", err)
	}
	journalDir := filepath.Join(dir, journalDirName)
	if err := os.MkdirAll(journalDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	journal := map[string]any{
		"schema":   journalSchema,
		"contract": ContractVersion,
		"runId":    testRunID,
		"ledger":   journalFile{Path: target, SHA256: SHA256Hex([]byte("staged")), Body: "staged"},
	}
	journalBytes := journalFixtureBytes(t, journal)
	if err := os.WriteFile(filepath.Join(journalDir, "rename.journal.json"), journalBytes, 0o644); err != nil {
		t.Fatalf("journal: %v", err)
	}
	if _, err := NewFilePublisher().Recover(ctx, dir); !IsCode(err, CodeInternal) {
		t.Fatalf("replay rename onto a directory = %v", err)
	}
}
