// Package hostcontract is the fixture-only executable model of the D4
// enrollment/apply/recovery contract (wave-1 unit A4, 2026-09-23).
//
// TestOnly: every type and function here models contract states against an
// in-process memory host. Nothing in this package inspects a live system,
// performs enrollment, writes a real filesystem path, executes a shell or
// issues a network/appliance call, and production code must not import it.
// Production Plan/Apply/rollback adapters and enrollment stay unimplemented
// and owner-gated; the authoritative text is the "D4 isolated-fixture
// contract" section of
// retired-docs:superpowers/plans/2026-08-24-managed-host-package-sources.md.
package hostcontract

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// EnrollmentState is the one-way lifecycle of a D4 managed-appliance
// enrollment generation. Fixture shape of the D4.0 minimal typed fields; it is
// NOT the CP0 wire freeze, which supersedes it when it lands.
type EnrollmentState string

const (
	EnrollmentUnenrolled EnrollmentState = "unenrolled"
	EnrollmentActive     EnrollmentState = "active"
	EnrollmentRevoked    EnrollmentState = "revoked"
)

// EnrollmentRecord is the fixture shape of the D4.0 minimal typed enrollment
// fields: generation, exact host/installation/platform identity, authorizer
// identity, revocation state and issue/revoke timestamps.
type EnrollmentRecord struct {
	Generation   int
	HostIdentity string          // exact host/installation identity
	Platform     string          // e.g. linux/amd64
	Baseline     string          // e.g. ubuntu-24.04
	Authorizer   string          // authorizer identity
	State        EnrollmentState // revocation state
	IssuedAt     time.Time
	RevokedAt    time.Time
}

// Active reports whether this generation currently authorizes new desired
// changes. Revocation is one-way for the generation.
func (e EnrollmentRecord) Active() bool { return e.State == EnrollmentActive }

// Revoke returns a copy of the record permanently revoked at the given
// instant. Only already authorized safe recovery remains permitted.
func (e EnrollmentRecord) Revoke(at time.Time) EnrollmentRecord {
	if e.State == EnrollmentRevoked {
		return e
	}
	e.State = EnrollmentRevoked
	e.RevokedAt = at
	return e
}

// supportedBaselines mirrors the Managed Dependency supported baseline
// (2026-09-01-managed-dependency-coordination.md §25.7): the first-GA server
// profile is Ubuntu 24.04 x86_64 (amd64) only. A baseline change re-binds the
// profile set and the golden fixtures.
var supportedBaselines = map[string]bool{
	"ubuntu-24.04/linux/amd64": true,
}

// OperationState enumerates the exact durable operation states of the
// contract. Refusals create no durable operation state.
type OperationState string

const (
	OperationPlanned          OperationState = "planned"
	OperationApplying         OperationState = "applying"
	OperationApplied          OperationState = "applied"
	OperationRolledBack       OperationState = "rolled_back"
	OperationRecoveryRequired OperationState = "recovery_required"
	OperationRefused          OperationState = "refused"
)

// ProblemCode is the typed discriminator of refusal and recovery problems.
type ProblemCode string

const (
	ProblemEnrollmentRequired ProblemCode = "enrollment_required"
	ProblemEnrollmentRevoked  ProblemCode = "enrollment_revoked_recovery_only"
	ProblemUnsupported        ProblemCode = "unsupported_baseline"
	ProblemPreimageMissing    ProblemCode = "preimage_missing"
	ProblemSymlinkTarget      ProblemCode = "symlink_target_refused"
	ProblemPreimageDrift      ProblemCode = "preimage_drift"
	ProblemPostimageDrift     ProblemCode = "postimage_drift_restore_refused"
	ProblemRuntimeUncertain   ProblemCode = "runtime_uncertain"
	ProblemOperationInFlight  ProblemCode = "operation_in_flight"
)

// Problem is the typed refusal/recovery fact carried by receipts. It is
// secret-free by construction: callers supply only fixed classification
// strings, never inspected file contents.
type Problem struct {
	Code        ProblemCode `json:"code"`
	Detail      string      `json:"detail"`
	Remediation string      `json:"remediation"`
}

// Refusal is the error returned by every refused transition. Refusals never
// create durable operation state and leave the fixture host byte-identical.
type Refusal struct {
	Problem Problem
}

func (r *Refusal) Error() string { return r.Problem.Detail }

func refusal(code ProblemCode, detail, remediation string) *Refusal {
	return &Refusal{Problem: Problem{Code: code, Detail: detail, Remediation: remediation}}
}

// FixtureFile is one in-memory object on the fixture host. Symlink non-empty
// marks a symlink whose target is recorded but never read or followed.
type FixtureFile struct {
	Data    []byte
	Owner   string
	Mode    uint32
	Symlink string
}

func (f FixtureFile) digest() string {
	sum := sha256.Sum256(f.Data)
	return hex.EncodeToString(sum[:])
}

func (f FixtureFile) with(data []byte) FixtureFile {
	out := f
	out.Data = append([]byte(nil), data...)
	out.Symlink = ""
	return out
}

// FixtureHost is the in-process stand-in for the managed host. It holds a
// fixed map of display paths to objects; there is no filesystem behind it. It
// is not safe for concurrent use.
type FixtureHost struct {
	files map[string]FixtureFile
}

// NewFixtureHost builds a fixture host from a copy of the given objects.
func NewFixtureHost(files map[string]FixtureFile) *FixtureHost {
	out := &FixtureHost{files: make(map[string]FixtureFile, len(files))}
	for path, file := range files {
		file.Data = append([]byte(nil), file.Data...)
		out.files[path] = file
	}
	return out
}

// Get returns a copy of one object.
func (h *FixtureHost) Get(path string) (FixtureFile, bool) {
	file, ok := h.files[path]
	if ok {
		file.Data = append([]byte(nil), file.Data...)
	}
	return file, ok
}

// Snapshot returns a digest over every object; tests compare snapshots to
// prove a transition performed zero writes.
func (h *FixtureHost) Snapshot() string {
	paths := make([]string, 0, len(h.files))
	for path := range h.files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	out := sha256.New()
	for _, path := range paths {
		file := h.files[path]
		// The hash writer never errors (hash.Hash); Fprintf's return is
		// still checked to keep the errcheck surface empty by construction.
		if _, err := fmt.Fprintf(out, "%s\x00%s\x00%d\x00%s\x00", path, file.Owner, file.Mode, file.Symlink); err != nil {
			panic("fixture snapshot hash write failed: " + err.Error())
		}
		if _, err := out.Write(file.Data); err != nil {
			panic("fixture snapshot hash write failed: " + err.Error())
		}
	}
	return hex.EncodeToString(out.Sum(nil))
}

func (h *FixtureHost) replace(path string, next FixtureFile) {
	h.files[path] = next
}

// Preimage is the recorded identity of one exact object a plan may replace.
type Preimage struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Owner  string `json:"owner"`
	Mode   uint32 `json:"mode"`
}

// PlanReceipt is the deterministic output of PlanFixture. Same inputs produce
// the same PlanID; a changed generation, identity or revision produces a new
// one. In the production read-only slice MutatesHost is always false; the
// fixture's transactional model sets it true because it binds replacements
// that remain owner-gated in production.
type PlanReceipt struct {
	PlanID               string     `json:"planId"`
	EnrollmentGeneration int        `json:"enrollmentGeneration"`
	HostIdentity         string     `json:"hostIdentity"`
	PlanRevision         int        `json:"planRevision"`
	Preimages            []Preimage `json:"preimages"`
	MutatesHost          bool       `json:"mutatesHost"`
	Steps                []string   `json:"steps"`
}

// JournalEntry is one exact replacement recorded before the model advances.
type JournalEntry struct {
	Seq             int    `json:"seq"`
	Path            string `json:"path"`
	PreimageSHA256  string `json:"preimageSha256"`
	PostimageSHA256 string `json:"postimageSha256"`
	Owner           string `json:"owner"`
	Mode            uint32 `json:"mode"`
}

// RecoveryGuidance is the D4_RECOVERY_REQUIRED_SURFACED payload: the failed
// checkpoint, the retained receipt, the observed drift and the safe operator
// next step. Setjoin never overwrites drift to manufacture rollback.
type RecoveryGuidance struct {
	FailedCheckpoint int      `json:"failedCheckpoint"`
	ReceiptRef       string   `json:"receiptRef"`
	ObservedDrift    []string `json:"observedDrift"`
	SafeNextStep     string   `json:"safeNextStep"`
}

// ApplyReceipt is the operation-bound receipt. Its OperationID is unique per
// plan ID plus enrollment generation; exact replay returns the same receipt.
type ApplyReceipt struct {
	OperationID          string            `json:"operationId"`
	PlanID               string            `json:"planId"`
	EnrollmentGeneration int               `json:"enrollmentGeneration"`
	State                OperationState    `json:"state"`
	Journal              []JournalEntry    `json:"journal"`
	CompletedSteps       int               `json:"completedSteps"`
	Problem              *Problem          `json:"problem,omitempty"`
	Recovery             *RecoveryGuidance `json:"recovery,omitempty"`
	UpdatedAt            time.Time         `json:"updatedAt"`
}

// InspectFixture returns a deep copy of the fixture host facts. It never
// mutates the host; tests assert this with Snapshot comparisons, mirroring the
// production read-only inventory contract (OAR4_EXTERNAL_RESOURCE_NO_WRITE).
func InspectFixture(h *FixtureHost) map[string]FixtureFile {
	out := make(map[string]FixtureFile, len(h.files))
	for path := range h.files {
		out[path], _ = h.Get(path)
	}
	return out
}

// PlanFixture validates the exact goal against the enrollment, the supported
// baseline and the current fixture host, and returns a deterministic plan
// receipt. Refused inputs return a *Refusal and never mutate the host:
// absent enrollment (component ownership is not enrollment), revoked
// enrollment (recovery only), unsupported baseline, missing preimage and
// symlinked targets are all refused here, with zero writes.
func PlanFixture(enrollment EnrollmentRecord, h *FixtureHost, revision int, desired []string) (PlanReceipt, error) {
	if len(desired) == 0 {
		return PlanReceipt{}, refusal(ProblemPreimageMissing, "goal names no paths", "name the exact owned paths to plan")
	}
	if !enrollment.Active() {
		if enrollment.State == EnrollmentRevoked {
			return PlanReceipt{}, refusal(ProblemEnrollmentRevoked,
				"enrollment generation is revoked; only already authorized safe recovery remains",
				"use rollback of an in-flight operation or request a new enrollment through the owner gate")
		}
		return PlanReceipt{}, refusal(ProblemEnrollmentRequired,
			"no active enrollment exists for this installation; ownership labels alone do not enroll",
			"request managed-appliance enrollment through the separate product authorization gate")
	}
	if !supportedBaselines[enrollment.Baseline+"/"+enrollment.Platform] {
		return PlanReceipt{}, refusal(ProblemUnsupported,
			fmt.Sprintf("baseline %q on %q is outside the supported set", enrollment.Baseline, enrollment.Platform),
			"use the external-host operator workflow")
	}
	seen := map[string]bool{}
	preimages := make([]Preimage, 0, len(desired))
	for _, path := range desired {
		if seen[path] {
			return PlanReceipt{}, refusal(ProblemPreimageMissing, fmt.Sprintf("goal repeats path %q", path), "list each exact path once")
		}
		seen[path] = true
		file, ok := h.Get(path)
		if !ok {
			return PlanReceipt{}, refusal(ProblemPreimageMissing, fmt.Sprintf("goal path %q does not exist", path), "inspect the host and plan against existing objects")
		}
		if file.Symlink != "" {
			return PlanReceipt{}, refusal(ProblemSymlinkTarget, fmt.Sprintf("goal path %q is a symlink to %q", path, file.Symlink), "remove the symlink outside Setjoin or plan the real object")
		}
		preimages = append(preimages, Preimage{Path: path, SHA256: file.digest(), Owner: file.Owner, Mode: file.Mode})
	}
	return PlanReceipt{
		PlanID:               planID(enrollment, revision, preimages),
		EnrollmentGeneration: enrollment.Generation,
		HostIdentity:         enrollment.HostIdentity,
		PlanRevision:         revision,
		Preimages:            preimages,
		MutatesHost:          true,
		Steps:                append([]string(nil), desired...),
	}, nil
}

type retainedStep struct {
	entry     JournalEntry
	preimage  FixtureFile
	postimage FixtureFile
}

type operationRecord struct {
	plan  PlanReceipt
	steps []retainedStep
}

// FixtureJournal is the in-process operation journal. Every replacement is
// recorded here before the model advances, so a crash never re-applies a
// completed step and exact replay returns the same receipt.
type FixtureJournal struct {
	operations map[string]*operationRecord
	receipts   map[string]ApplyReceipt
}

// NewFixtureJournal builds an empty journal.
func NewFixtureJournal() *FixtureJournal {
	return &FixtureJournal{
		operations: map[string]*operationRecord{},
		receipts:   map[string]ApplyReceipt{},
	}
}

// Receipt returns the retained receipt for an operation, if any.
func (j *FixtureJournal) Receipt(operationID string) (ApplyReceipt, bool) {
	receipt, ok := j.receipts[operationID]
	return receipt, ok
}

// FailureMode selects the injected checkpoint failure of ApplyFixtureWithFailure.
type FailureMode string

const (
	// FailureCrashAfterJournal records the journal entry but drops the host
	// write: resume must redo the step from the journal.
	FailureCrashAfterJournal FailureMode = "crash_after_journal"
	// FailureCrashAfterWrite performs the host write but drops the caller's
	// return: resume must detect the postimage and skip the step.
	FailureCrashAfterWrite FailureMode = "crash_after_write"
)

// Failure names one injected checkpoint failure; AtStep is 1-based, 0 disables.
type Failure struct {
	AtStep int
	Mode   FailureMode
}

// ApplyFixture applies the closed plan against the fixture host: it
// revalidates every preimage immediately before replacement, journals each
// replacement before advancing, and terminates in OperationApplied. Drift or
// symlink substitution at apply time causes zero writes. Replaying a completed
// operation returns the retained receipt without re-applying.
func ApplyFixture(plan PlanReceipt, h *FixtureHost, j *FixtureJournal, desired map[string][]byte, now time.Time) (ApplyReceipt, error) {
	return ApplyFixtureWithFailure(plan, h, j, desired, Failure{}, now)
}

// ApplyFixtureWithFailure is ApplyFixture with one injected checkpoint failure
// for fixture tests of resume semantics. A crash after the journal entry
// leaves the step journaled but unapplied; a crash after the write leaves it
// journaled and applied; both are reconciled only by ResumeFixture.
func ApplyFixtureWithFailure(plan PlanReceipt, h *FixtureHost, j *FixtureJournal, desired map[string][]byte, fail Failure, now time.Time) (ApplyReceipt, error) {
	id := operationID(plan)
	if receipt, ok := j.receipts[id]; ok {
		if receipt.State == OperationApplied {
			return receipt, nil // exact replay: same operation identity, no duplicate effect
		}
		return ApplyReceipt{}, refusal(ProblemOperationInFlight,
			"operation is already in flight; resume from the journal",
			"call ResumeFixture instead of applying the same plan again")
	}
	// Immediate pre-replacement revalidation: any drift or symlink
	// substitution causes zero writes and a refusal receipt only.
	for _, pre := range plan.Preimages {
		if err := revalidatePreimage(h, pre); err != nil {
			return refusedReceipt(plan, err, now), err
		}
	}
	record := &operationRecord{plan: plan}
	j.operations[id] = record
	receipt := ApplyReceipt{
		OperationID:          id,
		PlanID:               plan.PlanID,
		EnrollmentGeneration: plan.EnrollmentGeneration,
		State:                OperationApplying,
		Journal:              []JournalEntry{},
		UpdatedAt:            now,
	}
	for seq, path := range plan.Steps {
		current, _ := h.Get(path)
		retained := newStep(seq+1, path, current, current.with(desired[path]))
		// Journal before advancing: the entry exists before any host effect.
		record.steps = append(record.steps, retained)
		receipt.Journal = append(receipt.Journal, retained.entry)
		receipt.CompletedSteps = retained.entry.Seq
		if fail.AtStep == retained.entry.Seq && fail.Mode == FailureCrashAfterJournal {
			j.receipts[id] = receipt
			return receipt, nil
		}
		h.replace(path, retained.postimage)
		if fail.AtStep == retained.entry.Seq && fail.Mode == FailureCrashAfterWrite {
			j.receipts[id] = receipt
			return receipt, nil
		}
	}
	receipt.State = OperationApplied
	receipt.UpdatedAt = now
	j.receipts[id] = receipt
	return receipt, nil
}

// ResumeFixture replays an in-flight operation strictly from the journal: a
// journaled step already at its postimage is skipped, one still at its
// preimage is redone, and an object matching neither is runtime-uncertain and
// enters recovery_required. Never-journaled steps are then completed in plan
// order, each journaled before advancing. A revoked enrollment stops
// continuation of new desired changes; only rollback remains permitted.
func ResumeFixture(plan PlanReceipt, h *FixtureHost, j *FixtureJournal, desired map[string][]byte, enrollment EnrollmentRecord, now time.Time) (ApplyReceipt, error) {
	id := operationID(plan)
	receipt, ok := j.receipts[id]
	if !ok {
		return ApplyReceipt{}, refusal(ProblemOperationInFlight, "no journaled operation for this plan", "apply the plan first or plan a new operation")
	}
	if receipt.State != OperationApplying {
		return receipt, nil
	}
	if !enrollment.Active() {
		return receipt, refusal(ProblemEnrollmentRevoked,
			"enrollment is revoked; continuation of new desired changes is not permitted",
			"roll back the in-flight operation; safe recovery stays authorized")
	}
	record := j.operations[id]
	for _, retained := range record.steps {
		current, exists := h.Get(retained.entry.Path)
		switch {
		case exists && current.Symlink == "" && sameIdentity(current, retained.postimage):
			// Completed step: never re-apply.
		case exists && current.Symlink == "" && sameIdentity(current, retained.preimage):
			h.replace(retained.entry.Path, retained.postimage)
		default:
			drifted := retained.entry.Path
			if !exists {
				drifted += " (missing)"
			}
			return recoverRequired(j, receipt, retained.entry.Seq, []string{drifted}, ProblemRuntimeUncertain,
				"journaled step matches neither its recorded preimage nor postimage", now), nil
		}
	}
	for seq := len(record.steps); seq < len(plan.Steps); seq++ {
		path := plan.Steps[seq]
		current, exists := h.Get(path)
		pre := plan.Preimages[seq]
		if !exists || current.Symlink != "" || current.digest() != pre.SHA256 || current.Owner != pre.Owner || current.Mode != pre.Mode {
			drifted := path
			if !exists {
				drifted += " (missing)"
			}
			return recoverRequired(j, receipt, seq+1, []string{drifted}, ProblemPreimageDrift,
				"remaining step drifted from its planned preimage during recovery", now), nil
		}
		retained := newStep(seq+1, path, current, current.with(desired[path]))
		record.steps = append(record.steps, retained)
		receipt.Journal = append(receipt.Journal, retained.entry)
		receipt.CompletedSteps = retained.entry.Seq
		h.replace(path, retained.postimage)
	}
	receipt.State = OperationApplied
	receipt.UpdatedAt = now
	j.receipts[id] = receipt
	return receipt, nil
}

// RollbackFixture restores every journaled replacement in reverse order, but
// only while the current object matches the operation's recorded postimage.
// Drifted or substituted objects are never overwritten: the operation enters
// recovery_required with surfaced guidance instead. Rollback is safe recovery
// and stays authorized after enrollment revocation.
func RollbackFixture(plan PlanReceipt, h *FixtureHost, j *FixtureJournal, now time.Time) (ApplyReceipt, error) {
	id := operationID(plan)
	receipt, ok := j.receipts[id]
	if !ok {
		return ApplyReceipt{}, refusal(ProblemOperationInFlight, "no journaled operation for this plan", "apply the plan before rolling it back")
	}
	if receipt.State == OperationRolledBack {
		return receipt, nil
	}
	record := j.operations[id]
	for index := len(record.steps) - 1; index >= 0; index-- {
		retained := record.steps[index]
		current, exists := h.Get(retained.entry.Path)
		if !exists || current.Symlink != "" || !sameIdentity(current, retained.postimage) {
			drift := retained.entry.Path
			if !exists {
				drift += " (missing)"
			}
			return recoverRequired(j, receipt, retained.entry.Seq, []string{drift}, ProblemPostimageDrift,
				"current object does not match the recorded postimage; restore refused", now), nil
		}
		h.replace(retained.entry.Path, retained.preimage)
		receipt.CompletedSteps = retained.entry.Seq - 1
	}
	receipt.State = OperationRolledBack
	receipt.UpdatedAt = now
	j.receipts[id] = receipt
	return receipt, nil
}

func newStep(seq int, path string, before, after FixtureFile) retainedStep {
	return retainedStep{
		entry: JournalEntry{
			Seq:             seq,
			Path:            path,
			PreimageSHA256:  before.digest(),
			PostimageSHA256: after.digest(),
			Owner:           after.Owner,
			Mode:            after.Mode,
		},
		preimage:  before,
		postimage: after,
	}
}

func revalidatePreimage(h *FixtureHost, pre Preimage) error {
	current, exists := h.Get(pre.Path)
	if !exists {
		return refusal(ProblemPreimageDrift, fmt.Sprintf("planned object %q disappeared before apply", pre.Path), "re-inspect and plan again")
	}
	if current.Symlink != "" {
		return refusal(ProblemPreimageDrift, fmt.Sprintf("planned object %q was replaced by a symlink to %q", pre.Path, current.Symlink), "re-inspect and plan again; Setjoin never follows the substitution")
	}
	if current.digest() != pre.SHA256 || current.Owner != pre.Owner || current.Mode != pre.Mode {
		return refusal(ProblemPreimageDrift, fmt.Sprintf("planned object %q drifted from its preimage identity", pre.Path), "re-inspect and plan again; the drift is reported, not overwritten")
	}
	return nil
}

// refusedReceipt builds the receipt-only record of a refusal. It is returned
// to the caller but deliberately not retained as durable operation state.
func refusedReceipt(plan PlanReceipt, err error, now time.Time) ApplyReceipt {
	var refused *Refusal
	errors.As(err, &refused)
	return ApplyReceipt{
		OperationID:          operationID(plan),
		PlanID:               plan.PlanID,
		EnrollmentGeneration: plan.EnrollmentGeneration,
		State:                OperationRefused,
		Journal:              []JournalEntry{},
		Problem:              &refused.Problem,
		UpdatedAt:            now,
	}
}

func recoverRequired(j *FixtureJournal, receipt ApplyReceipt, checkpoint int, drift []string, code ProblemCode, detail string, now time.Time) ApplyReceipt {
	receipt.State = OperationRecoveryRequired
	receipt.Problem = &Problem{
		Code:        code,
		Detail:      detail,
		Remediation: "resolve the drift outside Setjoin or restore the recorded bytes manually; Setjoin will not overwrite drift",
	}
	receipt.Recovery = &RecoveryGuidance{
		FailedCheckpoint: checkpoint,
		ReceiptRef:       receipt.OperationID,
		ObservedDrift:    drift,
		SafeNextStep:     "inspect the drifted object, restore it to the recorded postimage or accept it, then plan a fresh operation",
	}
	receipt.UpdatedAt = now
	j.receipts[receipt.OperationID] = receipt
	return receipt
}

func sameIdentity(current, recorded FixtureFile) bool {
	return current.digest() == recorded.digest() && current.Owner == recorded.Owner && current.Mode == recorded.Mode
}

func planID(enrollment EnrollmentRecord, revision int, preimages []Preimage) string {
	canonical := []string{
		"d4-plan-v1",
		fmt.Sprintf("gen=%d", enrollment.Generation),
		"host=" + enrollment.HostIdentity,
		"baseline=" + enrollment.Baseline,
		"platform=" + enrollment.Platform,
		fmt.Sprintf("rev=%d", revision),
	}
	for _, pre := range preimages {
		canonical = append(canonical, fmt.Sprintf("%s=%s;owner=%s;mode=%d", pre.Path, pre.SHA256, pre.Owner, pre.Mode))
	}
	sum := sha256.Sum256([]byte(strings.Join(canonical, "\x00")))
	return hex.EncodeToString(sum[:])
}

func operationID(plan PlanReceipt) string {
	sum := sha256.Sum256([]byte("d4-op-v1\x00" + plan.PlanID + "\x00" + fmt.Sprint(plan.EnrollmentGeneration)))
	return hex.EncodeToString(sum[:])
}

// OperatorInstruction renders a fixed typed template, replacing {key}
// placeholders with shell-quoted values. Inspected source strings can never
// become shell syntax (D4_OPERATOR_TEMPLATE_INJECTION).
func OperatorInstruction(template string, values map[string]string) string {
	out := template
	for key, value := range values {
		out = strings.ReplaceAll(out, "{"+key+"}", ShellQuote(value))
	}
	return out
}

// ShellQuote single-quotes value for POSIX shells, escaping embedded quotes.
func ShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}
