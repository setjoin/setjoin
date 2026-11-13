package securityprogram

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// The frozen transition grammar. Every operation validates, for the specific
// target occurrence: the contract version, the caller authority, the
// occurrence's existence in the sealed ledger, and the occurrence's current
// state. The authoritative machine-readable form of this grammar is the
// frozen artifact (docs/verification/deep-security-remediation-transitions.json,
// generated from this package via ContractJSON); the checker enforces the same
// rules from that artifact — this code is the generator, not a second grammar.

// sealedOpenState is the required pre-state of any mutating operation on a
// not-yet-closed sealed occurrence: disposition blocked with no verification.
// Any open sealed occurrence may open an attempt (start) — the local work
// status describes progress, not eligibility.
func sealedOpenState(s RowState) bool {
	return openSealedState().matches(s)
}

// resolveTarget performs the shared occurrence-specific validation: contract
// version, authority, existence in the sealed ledger, and enum hygiene.
func (s *Service) resolveTarget(op string, req Request) (*RowView, error) {
	if req.Contract == "" {
		return nil, usageErr(op, "contract version is required (expected "+ContractVersion+")")
	}
	if req.Contract != ContractVersion {
		return nil, newErr(CodeSchemaUnsupported, op, req.OccurrenceID,
			fmt.Sprintf("contract %q unsupported (supported: %s)", req.Contract, ContractVersion))
	}
	if req.Authority != AuthorityServiceRole {
		return nil, newErr(CodeApprovalRequired, op, req.OccurrenceID,
			fmt.Sprintf("authority %q is not the required %q", req.Authority, AuthorityServiceRole))
	}
	if req.OccurrenceID == "" {
		return nil, usageErr(op, "occurrenceId is required")
	}
	row, ok := s.doc.Find(req.OccurrenceID)
	if !ok {
		return nil, newErr(CodeAttemptUnknown, op, req.OccurrenceID,
			"occurrence is not in the sealed remediation ledger; partial or invented IDs are never guessed")
	}
	return ViewRow(row)
}

// stageStart validates and stages the start transition: an active attempt is
// opened on an open, not-yet-closed sealed occurrence.
func stageStart(v *RowView, req StartRequest, at time.Time) (Transition, error) {
	const op = OpStart
	rule := startRule()
	if err := validateRequired(rule, req.Request, nil, ""); err != nil {
		return Transition{}, err
	}
	if rule.OpensAttempt && v.Attempt != nil && v.Attempt.State == AttemptActive {
		return Transition{}, newErr(CodeAttemptUnknown, op, v.OccurrenceID,
			fmt.Sprintf("active attempt %q already owns this occurrence; reject or complete it first", v.Attempt.AttemptID))
	}
	if !rule.From.matches(v.State) {
		return Transition{}, newErr(CodeEvidenceInvalid, op, v.OccurrenceID,
			fmt.Sprintf("state %s is not an open sealed state (expected blocked/*/none/*)", v.State))
	}
	to := rule.nextState(v.State, "")
	return Transition{
		Op:           OpStart,
		Contract:     ContractVersion,
		OccurrenceID: v.OccurrenceID,
		AttemptID:    req.AttemptID,
		RunID:        req.RunID,
		Authority:    req.Authority,
		Actor:        req.Actor,
		From:         v.State,
		To:           to,
		At:           RFC3339UTC(at),
	}, nil
}

// stageComplete validates and stages the complete transition: an active
// attempt is closed with a receipt-bound closure claim and its evidence
// artifact binding.
func stageComplete(v *RowView, req CompleteRequest, at time.Time) (Transition, error) {
	const op = OpComplete
	rule := completeRule()
	outcome := Disposition(req.Outcome)
	if !slices.Contains(rule.Outcomes, outcome) {
		return Transition{}, usageErr(op, fmt.Sprintf("outcome %q must be fixed or no_change", req.Outcome))
	}
	if rule.RequiresActiveAttempt && (v.Attempt == nil || v.Attempt.State != AttemptActive) {
		return Transition{}, newErr(CodeAttemptUnknown, op, v.OccurrenceID,
			"no active remediation attempt to complete; start one first")
	}
	if v.Attempt.AttemptID != req.AttemptID {
		return Transition{}, newErr(CodeAttemptUnknown, op, v.OccurrenceID,
			fmt.Sprintf("attempt %q is not the active attempt %q", req.AttemptID, v.Attempt.AttemptID))
	}
	if !rule.From.matches(v.State) {
		return Transition{}, newErr(CodeEvidenceInvalid, op, v.OccurrenceID,
			fmt.Sprintf("state %s is not an open sealed state", v.State))
	}
	if err := validateRequired(rule, req.Request, &req, ""); err != nil {
		return Transition{}, err
	}
	if constraints, ok := rule.OutcomeFrom[outcome]; ok && !constraints.matches(v.State) {
		return Transition{}, newErr(CodeEvidenceInvalid, op, v.OccurrenceID,
			fmt.Sprintf("%s outcome requires localStatus %q, found %q", outcome, constraints.LocalStatus, v.State.LocalStatus))
	}
	to := rule.nextState(v.State, outcome)
	return Transition{
		Op:               OpComplete,
		Contract:         ContractVersion,
		OccurrenceID:     v.OccurrenceID,
		AttemptID:        req.AttemptID,
		RunID:            req.RunID,
		Authority:        req.Authority,
		Actor:            req.Actor,
		From:             v.State,
		To:               to,
		At:               RFC3339UTC(at),
		EvidenceManifest: req.EvidenceManifest,
	}, nil
}

// stageReject validates and stages the reject transition: an active attempt
// is closed with a cited reason and the occurrence returns to blocked.
func stageReject(v *RowView, req RejectRequest, at time.Time) (Transition, error) {
	const op = OpReject
	rule := rejectRule()
	if err := validateRequired(rule, req.Request, nil, req.Reason); err != nil {
		return Transition{}, err
	}
	if rule.RequiresActiveAttempt && (v.Attempt == nil || v.Attempt.State != AttemptActive) {
		return Transition{}, newErr(CodeAttemptUnknown, op, v.OccurrenceID,
			"no active remediation attempt to reject")
	}
	if v.Attempt.AttemptID != req.AttemptID {
		return Transition{}, newErr(CodeAttemptUnknown, op, v.OccurrenceID,
			fmt.Sprintf("attempt %q is not the active attempt %q", req.AttemptID, v.Attempt.AttemptID))
	}
	if !rule.From.matches(v.State) {
		return Transition{}, newErr(CodeEvidenceInvalid, op, v.OccurrenceID,
			fmt.Sprintf("state %s is not an open sealed state", v.State))
	}
	to := rule.nextState(v.State, "")
	return Transition{
		Op:           OpReject,
		Contract:     ContractVersion,
		OccurrenceID: v.OccurrenceID,
		AttemptID:    req.AttemptID,
		RunID:        req.RunID,
		Authority:    req.Authority,
		Actor:        req.Actor,
		From:         v.State,
		To:           to,
		At:           RFC3339UTC(at),
		Reason:       req.Reason,
	}, nil
}

// Field semantics belong to the v2 grammar interpreter; the operation rule
// decides which fields are required. EvidenceSHA256 is minted by Complete
// after staging, not supplied by the caller.
func validateRequired(rule opSpec, req Request, complete *CompleteRequest, reason string) error {
	for _, field := range rule.Requires {
		switch field {
		case "attemptId":
			if strings.TrimSpace(req.AttemptID) == "" {
				return usageErr(rule.Op, "attemptId is required")
			}
		case "runId":
			if strings.TrimSpace(req.RunID) == "" {
				return usageErr(rule.Op, "runId is required")
			}
		case "closurePatch":
			if complete == nil || !complete.ClosurePatch.complete() {
				return newErr(CodePrerequisiteBlocked, rule.Op, req.OccurrenceID, "a closure patch binding trigger, legitimate and bypass evidence is required before completion")
			}
		case "tests":
			if complete == nil || len(complete.Tests) == 0 {
				return newErr(CodePrerequisiteBlocked, rule.Op, req.OccurrenceID, "occurrence-specific tests are required before completion")
			}
		case "evidenceManifest":
			if complete == nil {
				return newErr(CodeInternal, rule.Op, req.OccurrenceID, "completion request is required")
			}
			if err := validateEvidencePath(complete.EvidenceManifest); err != nil {
				return usageErr(rule.Op, err.Error())
			}
		case "reason":
			if strings.TrimSpace(reason) == "" {
				return usageErr(rule.Op, "a cited reason is required to reject an attempt")
			}
		default:
			return newErr(CodeInternal, rule.Op, req.OccurrenceID, "unsupported required field: "+field)
		}
	}
	return nil
}

// validateEvidencePath enforces the publication path boundary: a relative,
// repository-local path without traversal. Absolute paths and escapes are a
// usage error, never a guess.
func validateEvidencePath(p string) error {
	if strings.TrimSpace(p) == "" {
		return fmt.Errorf("evidence manifest path is required")
	}
	if filepath.IsAbs(p) || strings.Contains(p, `\`) || filepath.IsAbs(filepath.FromSlash(p)) {
		return fmt.Errorf("evidence manifest path %q must be repository-relative", p)
	}
	clean := filepath.Clean(p)
	if clean == ".." || strings.HasPrefix(clean, "../") || filepath.IsAbs(clean) {
		return fmt.Errorf("evidence manifest path %q escapes the repository", p)
	}
	return nil
}

// complete reports whether the closure patch binds all three required
// evidence legs.
func (c *ClosurePatch) complete() bool {
	return c != nil &&
		strings.TrimSpace(c.Trigger) != "" &&
		strings.TrimSpace(c.Legitimate) != "" &&
		strings.TrimSpace(c.Bypass) != ""
}

// AllowedOperations projects which operations the current state admits,
// in canonical order. Status is always allowed.
func AllowedOperations(v *RowView) []string {
	allowed := []string{OpStatus}
	if sealedOpenState(v.State) && (v.Attempt == nil || v.Attempt.State != AttemptActive) {
		allowed = append(allowed, OpStart)
	}
	if sealedOpenState(v.State) && v.Attempt != nil && v.Attempt.State == AttemptActive {
		allowed = append(allowed, OpComplete, OpReject)
	}
	return allowed
}
