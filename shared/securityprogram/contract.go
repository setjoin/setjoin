package securityprogram

import (
	"errors"
	"fmt"
)

// ContractVersion is THE version identifier every remediation-namespace
// request and recorded transition must carry. Unknown versions fail closed
// with E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED (plan DX pass 5: version every
// ledger/JSON output; unknown versions fail closed).
const ContractVersion = "setjoin.sec.security-program-remediation/v1"

// AuthorityServiceRole is the only authority accepted by the remediation
// namespace. The authority travels with the request; it is never inferred
// from the environment.
const AuthorityServiceRole = "service_role"

// Shared E_SECURITY_PROGRAM_* error codes. These are the canonical catalog
// codes from the canonical controller (scripts/security-program.mjs
// ERROR_CATALOG); the namespace allocates no new codes. The catalog triples
// below mirror that table verbatim for the codes this namespace emits.
const (
	CodeUsage               = "E_SECURITY_PROGRAM_USAGE"
	CodeApprovalRequired    = "E_SECURITY_PROGRAM_APPROVAL_REQUIRED"
	CodeAttemptUnknown      = "E_SECURITY_PROGRAM_ATTEMPT_UNKNOWN"
	CodeEvidenceInvalid     = "E_SECURITY_PROGRAM_EVIDENCE_INVALID"
	CodeSchemaUnsupported   = "E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED"
	CodePrerequisiteBlocked = "E_SECURITY_PROGRAM_PREREQUISITE_BLOCKED"
	CodePublicationBusy     = "E_SECURITY_PROGRAM_PUBLICATION_BUSY"
	CodeInternal            = "E_SECURITY_PROGRAM_INTERNAL"
)

// catalog mirrors the canonical controller's ERROR_CATALOG triples
// (problem, cause, fix) for the codes this namespace emits. guard_test.go
// asserts the emitted-code set and this table stay in lockstep, so the
// namespace can never drift from the shared error authority.
var catalog = map[string][3]string{
	CodeUsage: {
		"The command grammar is invalid",
		"Arguments do not match a supported command",
		"Run --help",
	},
	CodeApprovalRequired: {
		"The requested operation lacks explicit approval",
		"No matching immutable approval is bound to the attempt",
		"Obtain a reviewed approval before retrying",
	},
	CodeAttemptUnknown: {
		"The attempt is unavailable for this action",
		"The requested ID is not the current verified attempt in the required state",
		"Run coverage resume and use its exact next argv",
	},
	CodeEvidenceInvalid: {
		"Retained evidence failed validation",
		"A hash, binding, state transition, or envelope is inconsistent",
		"Quarantine the affected artifact and reconcile from retained authority",
	},
	CodeSchemaUnsupported: {
		"An evidence schema is unsupported",
		"The reader cannot safely interpret the retained version",
		"Run coverage migrate --check",
	},
	CodePrerequisiteBlocked: {
		"The selected resume branch has an unmet prerequisite",
		"Persisted authority is readable but not eligible to advance",
		"Run the exact read-only next command and resolve the reported prerequisite",
	},
	CodePublicationBusy: {
		"Canonical publication is already locked",
		"Another publisher or retained crash lock owns the operation",
		"Reconcile the publication lock before retrying",
	},
	CodeInternal: {
		"The control plane failed closed",
		"An unexpected internal error prevented a trustworthy result",
		"Run the offline doctor and inspect the stable diagnostic code",
	},
}

// Error is the typed remediation-namespace error. Code is always one of the
// shared E_SECURITY_PROGRAM_* constants; Detail carries the
// occurrence-specific context (target ID, expected vs actual state) without
// replacing the shared problem/cause/fix triples.
type Error struct {
	Code         string
	Op           string
	OccurrenceID string
	Detail       string
}

// Error implements the error interface. The code leads so log scanners and
// the explain surface key on the stable shared identifier.
func (e *Error) Error() string {
	switch {
	case e.Op != "" && e.OccurrenceID != "":
		return fmt.Sprintf("%s: %s %s: %s", e.Code, e.Op, e.OccurrenceID, e.Detail)
	case e.Op != "":
		return fmt.Sprintf("%s: %s: %s", e.Code, e.Op, e.Detail)
	case e.OccurrenceID != "":
		return fmt.Sprintf("%s: %s: %s", e.Code, e.OccurrenceID, e.Detail)
	default:
		return fmt.Sprintf("%s: %s", e.Code, e.Detail)
	}
}

// CodeOf extracts the shared E_SECURITY_PROGRAM_* code from err, returning
// CodeInternal for errors that are not namespace errors (fail closed, never
// reclassify an unknown failure as a caller problem).
func CodeOf(err error) string {
	var nsErr *Error
	if errors.As(err, &nsErr) {
		return nsErr.Code
	}
	return CodeInternal
}

// IsCode reports whether err carries exactly the given shared code.
func IsCode(err error, code string) bool {
	var nsErr *Error
	return errors.As(err, &nsErr) && nsErr.Code == code
}

func usageErr(op, detail string) *Error {
	return &Error{Code: CodeUsage, Op: op, Detail: detail}
}

func newErr(code, op, occurrenceID, detail string) *Error {
	return &Error{Code: code, Op: op, OccurrenceID: occurrenceID, Detail: detail}
}
