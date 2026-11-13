package securityprogram

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// writeTestLedger materializes the fixture ledger and returns its path and
// hash so publishers can be exercised end to end on real files.
func writeTestLedger(t *testing.T, dir string) (string, string) {
	t.Helper()
	path := filepath.Join(dir, "deep-security-remediation-ledger.json")
	if err := os.WriteFile(path, testLedgerBytes(t, ""), 0o644); err != nil {
		t.Fatalf("fixture write: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("fixture read: %v", err)
	}
	return path, SHA256Hex(raw)
}

// errCrashInjected is the sentinel the failAfter hook returns to simulate a
// process death at a publication stage.
var errCrashInjected = &Error{Code: CodeInternal, Op: "publish", Detail: "crash injected by test"}

func TestPublishSingleTargetAtomic(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	ledgerPath, beforeHash := writeTestLedger(t, dir)

	svc, err := serviceFromBytes(t, testLedgerBytes(t, ""))
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	cs, err := svc.Start(ctx, StartRequest{Request: authedReq(testOcc)})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	// The staged before-hash must equal the on-disk bytes' hash.
	if cs.LedgerBeforeSHA256 != beforeHash {
		t.Fatalf("before-hash mismatch: staged %s disk %s", cs.LedgerBeforeSHA256, beforeHash)
	}
	pub := NewFilePublisher()
	if err := pub.Publish(ctx, cs, ledgerPath); err != nil {
		t.Fatalf("publish: %v", err)
	}
	raw, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(raw, cs.LedgerAfter) {
		t.Fatalf("published bytes differ from the change set")
	}
	if _, err := os.Stat(filepath.Join(dir, journalDirName)); !os.IsNotExist(err) {
		t.Fatalf("single-target publication must leave no journal directory")
	}
}

func TestPublishTwoTargetsCommitTogether(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	ledgerPath, _ := writeTestLedger(t, dir)
	evidencePath := filepath.Join("test-results", "deep-security-remediation", testRunID, "manifest.json")

	cs := stageCompleteOnDiskFixture(t, ledgerPath)
	if cs.Evidence == nil {
		t.Fatalf("complete change set must carry evidence")
	}
	// Evidence paths in change sets are repository-relative; resolve the
	// targets under the test dir as a consumer would inside the repo root.
	pub := NewFilePublisher()
	rel := func(p string) string { return filepath.Join(dir, p) }
	twoTarget := &ChangeSet{
		Transition:         cs.Transition,
		LedgerAfter:        cs.LedgerAfter,
		LedgerBeforeSHA256: cs.LedgerBeforeSHA256,
		Evidence:           &EvidenceFile{Path: rel(evidencePath), Body: cs.Evidence.Body},
	}
	if err := pub.Publish(ctx, twoTarget, ledgerPath); err != nil {
		t.Fatalf("publish: %v", err)
	}
	evBody, err := os.ReadFile(rel(evidencePath))
	if err != nil || !bytes.Equal(evBody, cs.Evidence.Body) {
		t.Fatalf("evidence artifact not committed atomically with the ledger")
	}
	ledgerBody, err := os.ReadFile(ledgerPath)
	if err != nil || !bytes.Equal(ledgerBody, cs.LedgerAfter) {
		t.Fatalf("ledger not committed")
	}
	if _, err := os.Stat(filepath.Join(dir, journalDirName)); !os.IsNotExist(err) {
		t.Fatalf("committed publication must clear its journal")
	}
}

func TestPublishBusyOnStaleLedger(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	ledgerPath, beforeHash := writeTestLedger(t, dir)
	svc, err := serviceFromBytes(t, testLedgerBytes(t, ""))
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	cs, err := svc.Start(ctx, StartRequest{Request: authedReq(testOcc)})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	_ = beforeHash
	// Someone else writes first; the staged before-hash goes stale.
	if err := os.WriteFile(ledgerPath, append([]byte("\n"), testLedgerBytes(t, "")...), 0o644); err != nil {
		t.Fatalf("interleave: %v", err)
	}
	err = NewFilePublisher().Publish(ctx, cs, ledgerPath)
	requireCode(t, err, CodePublicationBusy)
	// Nothing was written.
	raw, _ := os.ReadFile(ledgerPath)
	if bytes.Equal(raw, cs.LedgerAfter) {
		t.Fatalf("busy publication must not write")
	}
}

func TestPublishBusyOnRetainedJournal(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	ledgerPath, _ := writeTestLedger(t, dir)
	cs := stageCompleteOnDiskFixture(t, ledgerPath)
	journalDir := filepath.Join(dir, journalDirName)
	if err := os.MkdirAll(journalDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(journalDir, testRunID+".journal.json"), []byte("{}"), 0o644); err != nil {
		t.Fatalf("journal fixture: %v", err)
	}
	err := NewFilePublisher().Publish(ctx, cs, ledgerPath)
	requireCode(t, err, CodePublicationBusy)
}

// TestAtomicPublicationCrashRecovery proves the all-or-nothing contract: a
// crash at ANY stage leaves the pair recoverable to exactly the staged state,
// and Recover is idempotent.
func TestAtomicPublicationCrashRecovery(t *testing.T) {
	ctx := context.Background()
	stages := []string{"journal", "evidence", "ledger"}

	for _, stage := range stages {
		t.Run("crash after "+stage, func(t *testing.T) {
			dir := t.TempDir()
			ledgerPath, _ := writeTestLedger(t, dir)
			cs := stageCompleteOnDiskFixture(t, ledgerPath)
			// The staged before-hash pins the on-disk bytes the complete was
			// staged against — the start change set is already published.
			staged, err := os.ReadFile(ledgerPath)
			if err != nil || cs.LedgerBeforeSHA256 != SHA256Hex(staged) {
				t.Fatalf("fixture before-hash drift (start publication missing?)")
			}
			resolved := filepath.Join(dir, cs.Evidence.Path)
			twoTarget := &ChangeSet{
				Transition:         cs.Transition,
				LedgerAfter:        cs.LedgerAfter,
				LedgerBeforeSHA256: cs.LedgerBeforeSHA256,
				Evidence:           &EvidenceFile{Path: resolved, Body: cs.Evidence.Body},
			}
			pub := &FilePublisher{failAfter: func(s string) error {
				if s == stage {
					return errCrashInjected
				}
				return nil
			}}
			err = pub.Publish(ctx, twoTarget, ledgerPath)
			if err == nil {
				t.Fatalf("crash injection after %s did not abort the publication", stage)
			}

			// Deterministic recovery completes the publication exactly.
			reports, err := pub.Recover(ctx, dir)
			if err != nil {
				t.Fatalf("recover: %v", err)
			}
			if len(reports) != 1 || !reports[0].Resolved {
				t.Fatalf("expected one resolved journal, got %+v", reports)
			}
			evBody, err := os.ReadFile(resolved)
			if err != nil || !bytes.Equal(evBody, cs.Evidence.Body) {
				t.Fatalf("recovery did not restore the evidence artifact (stage %s)", stage)
			}
			ledgerBody, err := os.ReadFile(ledgerPath)
			if err != nil || !bytes.Equal(ledgerBody, cs.LedgerAfter) {
				t.Fatalf("recovery did not restore the ledger (stage %s)", stage)
			}
			if _, err := os.Stat(filepath.Join(dir, journalDirName, testRunID+".journal.json")); !os.IsNotExist(err) {
				t.Fatalf("resolved journal must be removed")
			}
			// Idempotent: a second recovery is a no-op.
			reports, err = pub.Recover(ctx, dir)
			if err != nil || len(reports) != 0 {
				t.Fatalf("second recovery must be a no-op, got %v/%v", reports, err)
			}
		})
	}
}

func TestRecoverLeavesCorruptJournalQuarantined(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	_, _ = writeTestLedger(t, dir)
	journalDir := filepath.Join(dir, journalDirName)
	if err := os.MkdirAll(journalDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	corrupt := filepath.Join(journalDir, "corrupt.journal.json")
	if err := os.WriteFile(corrupt, []byte("{not json"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := NewFilePublisher().Recover(ctx, dir)
	requireCode(t, err, CodeEvidenceInvalid)
	if _, statErr := os.Stat(corrupt); statErr != nil {
		t.Fatalf("corrupt journal must be quarantined in place, never deleted")
	}
}

func TestValidateRunID(t *testing.T) {
	for _, bad := range []string{"", "../evil", "a/b", ".hidden", string(make([]byte, 200))} {
		if err := validateRunID(bad); !IsCode(err, CodeUsage) {
			t.Fatalf("runId %q must be a usage refusal, got %v", bad, err)
		}
	}
	if err := validateRunID(testRunID); err != nil {
		t.Fatalf("legitimate runId refused: %v", err)
	}
}

// ── helpers ────────────────────────────────────────────────────────────────

func serviceFromBytes(t *testing.T, data []byte) (*Service, error) {
	t.Helper()
	doc, err := LoadLedger(data)
	if err != nil {
		return nil, err
	}
	return NewService(doc), nil
}

// stageCompleteOnDiskFixture returns a complete change set whose
// LedgerBeforeSHA256 matches the on-disk ledger bytes exactly (the evidence
// path is relative and must be resolved by the caller). The intermediate
// start change set is PUBLISHED first — the namespace's own rule is that a
// staged change set is bound to the on-disk bytes it was loaded from, so a
// consumer never stages a second transition against a file that does not yet
// carry the first one.
func stageCompleteOnDiskFixture(t *testing.T, ledgerPath string) *ChangeSet {
	t.Helper()
	raw, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatalf("fixture read: %v", err)
	}
	svc, err := serviceFromBytes(t, raw)
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	ctx := context.Background()
	start, err := svc.Start(ctx, StartRequest{Request: authedReq(testOcc)})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := NewFilePublisher().Publish(ctx, start, ledgerPath); err != nil {
		t.Fatalf("publish start: %v", err)
	}
	cs, err := svc.Complete(ctx, completeReq(testOcc, "fixed",
		filepath.Join("test-results", "deep-security-remediation", testRunID, "manifest.json")))
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	return cs
}
