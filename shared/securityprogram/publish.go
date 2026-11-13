package securityprogram

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// Atomic publication: a complete commits the ledger update and the evidence
// write as one unit (the file-artifact equivalent of a single SQL
// transaction). The commit point is an atomically-renamed journal that
// embeds BOTH target payloads and their SHA-256 pins; targets are then
// materialized by atomic rename and the journal is removed. A crash at any
// stage leaves the on-disk pair either fully at the pre-publication state or
// deterministically completable by Recover — never a half-claimed receipt.
//
// Single-target publications (start/reject: ledger only) skip the journal —
// a single atomic rename is already all-or-nothing.

// Publisher commits ChangeSets to disk atomically.
type Publisher interface {
	Publish(ctx context.Context, cs *ChangeSet, ledgerPath string) error
}

// journalDirName is the crash-lock directory created next to the ledger.
const journalDirName = ".securityprogram-publish"

// journalSchema is the versioned schema of the publication journal.
const journalSchema = "setjoin.sec.security-program-publication-journal/v1"

var runIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// FilePublisher is the file-artifact Publisher.
type FilePublisher struct {
	// failAfter, when set, is invoked after each named stage and its
	// non-nil error aborts the publication in place — the test-only crash
	// injection point. Stages: "journal", "evidence", "ledger", "commit".
	failAfter func(stage string) error
}

// NewFilePublisher returns the default file publisher.
func NewFilePublisher() *FilePublisher { return &FilePublisher{} }

type journalFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Body   string `json:"body"`
}

type journalDoc struct {
	Schema    string       `json:"schema"`
	Contract  string       `json:"contract"`
	RunID     string       `json:"runId"`
	Ledger    journalFile  `json:"ledger"`
	Evidence  *journalFile `json:"evidence,omitempty"`
	StartedAt string       `json:"startedAt"`
}

// Publish commits the change set: ledger update and evidence write happen
// atomically, or the ledger update alone for single-target change sets.
// Paths are caller-resolved; the repository-relative evidence-path boundary
// is enforced at the operation boundary (stageComplete), not here.
func (p *FilePublisher) Publish(_ context.Context, cs *ChangeSet, ledgerPath string) error {
	const op = "publish"
	if cs == nil {
		return usageErr(op, "change set is required")
	}
	if ledgerPath == "" {
		return usageErr(op, "ledger path is required")
	}
	if err := validateRunID(cs.Transition.RunID); err != nil {
		return err
	}
	current, err := os.ReadFile(ledgerPath)
	if err != nil {
		return newErr(CodeEvidenceInvalid, op, cs.Transition.OccurrenceID,
			"ledger unreadable: "+err.Error())
	}
	if SHA256Hex(current) != cs.LedgerBeforeSHA256 {
		return newErr(CodePublicationBusy, op, cs.Transition.OccurrenceID,
			"on-disk ledger no longer matches the change set's before-hash; reload and restage")
	}

	// Single-target publication: one atomic rename is already atomic.
	if cs.Evidence == nil {
		if err := atomicWrite(ledgerPath, cs.LedgerAfter); err != nil {
			return newErr(CodeInternal, op, cs.Transition.OccurrenceID,
				"ledger publication failed: "+err.Error())
		}
		return nil
	}

	if cs.Evidence.Path == "" {
		return usageErr(op, "evidence path is required")
	}
	journalDir := filepath.Join(filepath.Dir(ledgerPath), journalDirName)
	journalPath := filepath.Join(journalDir, cs.Transition.RunID+".journal.json")
	if _, err := os.Stat(journalPath); err == nil {
		return newErr(CodePublicationBusy, op, cs.Transition.OccurrenceID,
			fmt.Sprintf("retained crash lock %s owns run %s; run Recover first",
				filepath.Base(journalPath), cs.Transition.RunID))
	}
	j := journalDoc{
		Schema:    journalSchema,
		Contract:  ContractVersion,
		RunID:     cs.Transition.RunID,
		Ledger:    journalFile{Path: ledgerPath, SHA256: SHA256Hex(cs.LedgerAfter), Body: string(cs.LedgerAfter)},
		Evidence:  &journalFile{Path: cs.Evidence.Path, SHA256: SHA256Hex(cs.Evidence.Body), Body: string(cs.Evidence.Body)},
		StartedAt: RFC3339UTC(time.Now()),
	}
	jBody, err := json.MarshalIndent(j, "", " ")
	if err != nil {
		return newErr(CodeInternal, op, cs.Transition.OccurrenceID,
			"journal marshal failed: "+err.Error())
	}
	if err := atomicWrite(journalPath, jBody); err != nil {
		return newErr(CodeInternal, op, cs.Transition.OccurrenceID,
			"crash-lock journal write failed: "+err.Error())
	}
	if p.failAfter != nil {
		if err := p.failAfter("journal"); err != nil {
			return err
		}
	}
	if err := atomicWrite(cs.Evidence.Path, cs.Evidence.Body); err != nil {
		return newErr(CodeInternal, op, cs.Transition.OccurrenceID,
			"evidence publication failed: "+err.Error())
	}
	if p.failAfter != nil {
		if err := p.failAfter("evidence"); err != nil {
			return err
		}
	}
	if err := atomicWrite(ledgerPath, cs.LedgerAfter); err != nil {
		return newErr(CodeInternal, op, cs.Transition.OccurrenceID,
			"ledger publication failed: "+err.Error())
	}
	if p.failAfter != nil {
		if err := p.failAfter("ledger"); err != nil {
			return err
		}
	}
	if err := os.Remove(journalPath); err != nil && !os.IsNotExist(err) {
		return newErr(CodeInternal, op, cs.Transition.OccurrenceID,
			"crash-lock removal failed (publication is complete; run Recover to clear): "+err.Error())
	}
	// Best-effort removal of the journal directory once empty: a committed
	// publication leaves no crash-lock trace.
	_ = os.Remove(journalDir)
	_ = syncDir(journalDir)
	if p.failAfter != nil {
		if err := p.failAfter("commit"); err != nil {
			return err
		}
	}
	return nil
}

// RecoveryReport summarizes one journal replay.
type RecoveryReport struct {
	RunID       string   `json:"runId"`
	JournalPath string   `json:"journalPath"`
	Repaired    []string `json:"repaired"`
	Resolved    bool     `json:"resolved"`
}

// Recover deterministically completes or clears every retained journal under
// the given directories, replaying the embedded payloads into any target
// that is missing or does not match its pinned hash. Replay is idempotent:
// an already-committed publication only clears the journal.
func (p *FilePublisher) Recover(_ context.Context, dirs ...string) ([]RecoveryReport, error) {
	var reports []RecoveryReport
	for _, dir := range dirs {
		journalDir := filepath.Join(dir, journalDirName)
		entries, err := os.ReadDir(journalDir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return reports, newErr(CodeInternal, "recover", "", "journal directory unreadable: "+err.Error())
		}
		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
				continue
			}
			journalPath := filepath.Join(journalDir, entry.Name())
			report, err := p.replayJournal(journalPath)
			if err != nil {
				return reports, err
			}
			reports = append(reports, report)
		}
	}
	return reports, nil
}

func (p *FilePublisher) replayJournal(journalPath string) (RecoveryReport, error) {
	report := RecoveryReport{JournalPath: journalPath}
	raw, err := os.ReadFile(journalPath)
	if err != nil {
		return report, newErr(CodeInternal, "recover", "", "journal unreadable: "+err.Error())
	}
	var j journalDoc
	if err := json.Unmarshal(raw, &j); err != nil || j.Schema != journalSchema {
		// A journal that cannot be parsed is quarantined (left in place) and
		// reported; it is never silently deleted.
		return report, newErr(CodeEvidenceInvalid, "recover", "",
			fmt.Sprintf("retained journal %s is corrupt and requires operator reconciliation",
				filepath.Base(journalPath)))
	}
	report.RunID = j.RunID
	for _, target := range []*journalFile{j.Evidence, &j.Ledger} {
		if target == nil {
			continue
		}
		if fileMatchesPin(target.Path, target.SHA256) {
			continue
		}
		if err := atomicWrite(target.Path, []byte(target.Body)); err != nil {
			return report, newErr(CodeInternal, "recover", "", "replay write failed: "+err.Error())
		}
		report.Repaired = append(report.Repaired, filepath.Base(target.Path))
	}
	if err := os.Remove(journalPath); err != nil && !os.IsNotExist(err) {
		return report, newErr(CodeInternal, "recover", "", "journal removal failed: "+err.Error())
	}
	_ = syncDir(filepath.Dir(journalPath))
	report.Resolved = true
	return report, nil
}

func fileMatchesPin(path, sha string) bool {
	body, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return SHA256Hex(body) == sha
}

// validateRunID rejects unsafe run identifiers before they reach the
// filesystem (journal file names are run-id derived).
func validateRunID(runID string) error {
	if !runIDPattern.MatchString(runID) {
		return usageErr("publish", fmt.Sprintf("runId %q must match %s", runID, runIDPattern.String()))
	}
	return nil
}

// atomicWrite writes body to path via temp file, fsync, rename — the atomic
// rename is the only moment the target's identity changes.
func atomicWrite(path string, body []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".securityprogram-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return syncDir(dir)
}

// syncDir best-effort fsyncs a directory so the rename is durable.
func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
