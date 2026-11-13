package securityprogram

import (
	"context"
	"encoding/json"
	"time"
)

// Request carries the fields every remediation-namespace operation requires:
// the contract version, the caller authority, the sealed occurrence, and the
// attempt/run identity for mutating operations.
type Request struct {
	Contract     string
	Authority    string
	Actor        string
	OccurrenceID string
	AttemptID    string
	RunID        string
}

// StartRequest is the start operation input.
type StartRequest struct{ Request }

// StatusRequest is the status operation input (read-only).
type StatusRequest struct{ Request }

// CompleteRequest is the complete operation input: the receipt-bound closure
// claim plus the evidence artifact to publish atomically with the ledger
// update.
type CompleteRequest struct {
	Request
	Outcome           string
	ClosurePatch      *ClosurePatch
	Tests             []string
	EvidenceManifest  string
	SourceFingerprint string
}

// RejectRequest is the reject operation input.
type RejectRequest struct {
	Request
	Reason string
}

// StatusResult is the read-only occurrence projection: current four-axis
// state, attempt, evidence pointer, and the operations the state admits.
type StatusResult struct {
	Contract         string        `json:"contract"`
	OccurrenceID     string        `json:"occurrenceId"`
	FindingID        string        `json:"findingId"`
	State            RowState      `json:"state"`
	Attempt          *AttemptState `json:"attempt,omitempty"`
	BlockedReason    string        `json:"blockedReason,omitempty"`
	EvidenceManifest string        `json:"evidenceManifest,omitempty"`
	Allowed          []string      `json:"allowed"`
}

// ChangeSet is the staged result of a mutating operation: the recorded
// transition, the evidence artifact (complete only), the new ledger bytes,
// and the before-hash the publisher uses for optimistic concurrency.
type ChangeSet struct {
	Transition         Transition
	Evidence           *EvidenceFile
	LedgerAfter        []byte
	LedgerBeforeSHA256 string
}

// EvidenceFile is one target of an atomic publication.
type EvidenceFile struct {
	Path string
	Body []byte
}

// Service is the remediation namespace over one loaded sealed ledger. It
// validates and applies transitions in memory; publication to disk is the
// caller's separate atomic step via Publisher. If a publication fails or
// reports busy, reload a fresh Service from the on-disk bytes rather than
// retrying against a stale document.
type Service struct{ doc *LedgerDoc }

// NewService binds the namespace to a loaded ledger document.
func NewService(doc *LedgerDoc) *Service { return &Service{doc: doc} }

// Start opens an authorized remediation attempt on a sealed occurrence. The
// ledger update is a single-target publication (atomic rename); no evidence
// artifact exists yet.
func (s *Service) Start(_ context.Context, req StartRequest) (*ChangeSet, error) {
	v, err := s.resolveTarget(OpStart, req.Request)
	if err != nil {
		return nil, err
	}
	t, err := stageStart(v, req, time.Now())
	if err != nil {
		return nil, err
	}
	att := &AttemptState{
		AttemptID: req.AttemptID,
		RunID:     req.RunID,
		State:     startRule().AttemptState,
		OpenedAt:  t.At,
	}
	return s.commit(t, "", nil, att, nil, nil)
}

// Status is the read-only occurrence projection. It performs the same
// occurrence-specific validation (version, authority, existence) but never
// records a transition or mutates anything.
func (s *Service) Status(_ context.Context, req StatusRequest) (*StatusResult, error) {
	v, err := s.resolveTarget(OpStatus, req.Request)
	if err != nil {
		return nil, err
	}
	return &StatusResult{
		Contract:         ContractVersion,
		OccurrenceID:     v.OccurrenceID,
		FindingID:        v.FindingID,
		State:            v.State,
		Attempt:          v.Attempt,
		BlockedReason:    v.BlockedReason,
		EvidenceManifest: v.Evidence.Manifest,
		Allowed:          AllowedOperations(v),
	}, nil
}

// Complete closes an active attempt with a receipt-bound closure claim. The
// returned ChangeSet carries the updated ledger bytes AND the evidence
// manifest; both must be published atomically via Publisher.Publish so the
// ledger can never claim a receipt whose evidence write did not commit.
func (s *Service) Complete(_ context.Context, req CompleteRequest) (*ChangeSet, error) {
	v, err := s.resolveTarget(OpComplete, req.Request)
	if err != nil {
		return nil, err
	}
	t, err := stageComplete(v, req, time.Now())
	if err != nil {
		return nil, err
	}
	evidence, err := buildEvidenceManifest(v, req, t)
	if err != nil {
		return nil, err
	}
	t.EvidenceSHA256 = SHA256Hex(evidence)
	att := &AttemptState{
		AttemptID: req.AttemptID,
		RunID:     req.RunID,
		State:     completeRule().AttemptState,
		OpenedAt:  v.Attempt.OpenedAt,
		ClosedAt:  t.At,
	}
	evRef := &EvidenceRef{
		SealedIndex:       v.Evidence.SealedIndex,
		Plan:              v.Evidence.Plan,
		PlanBatch:         v.Evidence.PlanBatch,
		Verification:      string(VerificationReceiptBound),
		Manifest:          req.EvidenceManifest,
		SourceFingerprint: req.SourceFingerprint,
		Verdict:           "pass",
	}
	return s.commit(t, Disposition(t.To.Disposition), evRef, att,
		&closureClaim{Patch: req.ClosurePatch, Tests: req.Tests},
		&EvidenceFile{
			Path: req.EvidenceManifest,
			Body: evidence,
		})
}

// Reject closes an active attempt with a cited reason; the occurrence returns
// to the blocked vocabulary with the reason recorded on the row.
func (s *Service) Reject(_ context.Context, req RejectRequest) (*ChangeSet, error) {
	v, err := s.resolveTarget(OpReject, req.Request)
	if err != nil {
		return nil, err
	}
	t, err := stageReject(v, req, time.Now())
	if err != nil {
		return nil, err
	}
	att := &AttemptState{
		AttemptID: req.AttemptID,
		RunID:     req.RunID,
		State:     rejectRule().AttemptState,
		OpenedAt:  v.Attempt.OpenedAt,
		ClosedAt:  t.At,
	}
	evRef := &EvidenceRef{
		SealedIndex:  v.Evidence.SealedIndex,
		Plan:         v.Evidence.Plan,
		PlanBatch:    v.Evidence.PlanBatch,
		Verification: string(VerificationNone),
		Manifest:     v.Evidence.Manifest,
		Verdict:      v.Evidence.Verdict,
	}
	return s.commit(t, DispositionBlocked, evRef, att, nil, nil)
}

// closureClaim is the completion claim written onto the row: the closure
// patch binding and the occurrence-specific tests (the checker requires
// fixed/no_change rows to carry both).
type closureClaim struct {
	Patch *ClosurePatch
	Tests []string
}

// commit applies the transition to the in-memory document, maintains the
// checker-reconciled tallies and the verification statement, and freezes the
// publication inputs. The evidence body is built BEFORE the ledger bytes so
// the appended transition record carries the evidence SHA-256 binding; the
// publisher's journal then binds the evidence hash and the ledger-after hash
// into one atomic commit.
func (s *Service) commit(t Transition, outcome Disposition, ev *EvidenceRef, att *AttemptState, claim *closureClaim, evidence *EvidenceFile) (*ChangeSet, error) {
	before, err := s.doc.Bytes()
	if err != nil {
		return nil, err
	}
	row, ok := s.doc.Find(t.OccurrenceID)
	if !ok {
		return nil, newErr(CodeInternal, t.Op, t.OccurrenceID, "target row vanished mid-operation")
	}
	// Reject records the cited reason as the row's blocked reason; complete
	// clears it (the checker constrains blockedReason only on blocked rows,
	// and a completed occurrence is no longer blocked) and records the closure
	// claim bindings the checker demands on fixed/no_change rows.
	switch t.Op {
	case OpReject:
		row["blockedReason"] = jsonRaw(t.Reason)
	case OpComplete:
		delete(row, "blockedReason")
		if claim != nil {
			if err := setOwned(row, "closurePatch", claim.Patch); err != nil {
				return nil, err
			}
			if err := setOwned(row, "tests", claim.Tests); err != nil {
				return nil, err
			}
		}
	}
	if err := writeRowState(row, t.To, ev, att); err != nil {
		return nil, err
	}
	if err := appendTransition(row, t); err != nil {
		return nil, err
	}
	if err := s.doc.bumpCounts(outcome); err != nil {
		return nil, err
	}
	if t.To.VerificationStatus == VerificationReceiptBound {
		s.doc.refreshVerificationStatement()
	}
	after, err := s.doc.Bytes()
	if err != nil {
		return nil, err
	}
	return &ChangeSet{
		Transition:         t,
		Evidence:           evidence,
		LedgerAfter:        after,
		LedgerBeforeSHA256: SHA256Hex(before),
	}, nil
}

// EvidenceManifestSchema is the versioned schema of the evidence artifact a
// complete publishes atomically with the ledger update.
const EvidenceManifestSchema = "setjoin.sec.security-program-remediation-evidence/v1"

// evidenceManifest is the serialized shape of the evidence artifact.
type evidenceManifest struct {
	Schema             string        `json:"schema"`
	Contract           string        `json:"contract"`
	Op                 string        `json:"op"`
	RunID              string        `json:"runId"`
	OccurrenceID       string        `json:"occurrenceId"`
	FindingID          string        `json:"findingId"`
	AttemptID          string        `json:"attemptId"`
	Authority          string        `json:"authority"`
	Actor              string        `json:"actor,omitempty"`
	Outcome            string        `json:"outcome"`
	From               RowState      `json:"from"`
	To                 RowState      `json:"to"`
	ClosurePatch       *ClosurePatch `json:"closurePatch"`
	Tests              []string      `json:"tests"`
	PriorBlockedReason string        `json:"priorBlockedReason,omitempty"`
	SourceFingerprint  string        `json:"sourceFingerprint,omitempty"`
	RecordedAt         string        `json:"recordedAt"`
}

func buildEvidenceManifest(v *RowView, req CompleteRequest, t Transition) ([]byte, error) {
	m := evidenceManifest{
		Schema:             EvidenceManifestSchema,
		Contract:           ContractVersion,
		Op:                 t.Op,
		RunID:              req.RunID,
		OccurrenceID:       t.OccurrenceID,
		FindingID:          v.FindingID,
		AttemptID:          req.AttemptID,
		Authority:          req.Authority,
		Actor:              req.Actor,
		Outcome:            req.Outcome,
		From:               t.From,
		To:                 t.To,
		ClosurePatch:       req.ClosurePatch,
		Tests:              req.Tests,
		PriorBlockedReason: v.BlockedReason,
		SourceFingerprint:  req.SourceFingerprint,
		RecordedAt:         t.At,
	}
	out, err := json.MarshalIndent(m, "", " ")
	if err != nil {
		return nil, newErr(CodeInternal, OpComplete, t.OccurrenceID, "evidence manifest marshal failed: "+err.Error())
	}
	return append(out, '\n'), nil
}
