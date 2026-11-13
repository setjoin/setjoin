package securityprogram

import "fmt"

// Closed status vocabularies. These are THE ledger's own enums, byte-identical
// to the closed sets enforced by the ER1 checker
// (scripts/check-deep-security-remediation.mjs: DISPOSITIONS, LOCAL_STATUSES,
// RELEASE_STATUSES, VERIFICATION_STATUSES). The remediation namespace never
// invents a fourth vocabulary; transitions move rows only inside these sets.

// Disposition is the closure disposition of a sealed occurrence.
type Disposition string

// Supported dispositions.
const (
	DispositionFixed    Disposition = "fixed"
	DispositionNoChange Disposition = "no_change"
	DispositionBlocked  Disposition = "blocked"
)

// LocalStatus is the local remediation work state.
type LocalStatus string

// Supported local statuses.
const (
	LocalUnmapped          LocalStatus = "unmapped"
	LocalTraced            LocalStatus = "traced"
	LocalFixRequired       LocalStatus = "fix_required"
	LocalNoChangeCandidate LocalStatus = "no_change_candidate"
	LocalBlocked           LocalStatus = "blocked"
	LocalPatched           LocalStatus = "patched"
	LocalProofPatched      LocalStatus = "proof_patched"
)

// VerificationStatus is the closure-verification state.
type VerificationStatus string

// Supported verification statuses.
const (
	VerificationNone         VerificationStatus = "none"
	VerificationReceiptBound VerificationStatus = "receipt_bound"
	VerificationDerivedGreen VerificationStatus = "derived_green"
)

// ReleaseStatus is the release-readiness state.
type ReleaseStatus string

// Supported release statuses.
const (
	ReleaseNotReady             ReleaseStatus = "not_ready"
	ReleaseExternalEvidenceOpen ReleaseStatus = "external_evidence_open"
	ReleaseReady                ReleaseStatus = "release_ready"
)

func parseDisposition(s string) (Disposition, error) {
	switch Disposition(s) {
	case DispositionFixed, DispositionNoChange, DispositionBlocked:
		return Disposition(s), nil
	}
	return "", fmt.Errorf("disposition %q outside closed enum fixed|no_change|blocked", s)
}

func parseLocalStatus(s string) (LocalStatus, error) {
	switch LocalStatus(s) {
	case LocalUnmapped, LocalTraced, LocalFixRequired, LocalNoChangeCandidate,
		LocalBlocked, LocalPatched, LocalProofPatched:
		return LocalStatus(s), nil
	}
	return "", fmt.Errorf("localStatus %q outside closed enum", s)
}

func parseVerificationStatus(s string) (VerificationStatus, error) {
	switch VerificationStatus(s) {
	case VerificationNone, VerificationReceiptBound, VerificationDerivedGreen:
		return VerificationStatus(s), nil
	}
	return "", fmt.Errorf("verificationStatus %q outside closed enum", s)
}

func parseReleaseStatus(s string) (ReleaseStatus, error) {
	switch ReleaseStatus(s) {
	case ReleaseNotReady, ReleaseExternalEvidenceOpen, ReleaseReady:
		return ReleaseStatus(s), nil
	}
	return "", fmt.Errorf("releaseStatus %q outside closed enum", s)
}

// RowState is the four-axis state of a ledger row the transition grammar
// reasons over. It is embedded in every recorded Transition (from/to) so any
// consumer can audit a chain without re-deriving history.
type RowState struct {
	Disposition        Disposition        `json:"disposition"`
	LocalStatus        LocalStatus        `json:"localStatus"`
	VerificationStatus VerificationStatus `json:"verificationStatus"`
	ReleaseStatus      ReleaseStatus      `json:"releaseStatus"`
}

// Equal reports exact equality of all four axes.
func (s RowState) Equal(other RowState) bool {
	return s == other
}

// String renders the state as a stable one-line projection for errors and
// diagnostics.
func (s RowState) String() string {
	return fmt.Sprintf("%s/%s/%s/%s", s.Disposition, s.LocalStatus, s.VerificationStatus, s.ReleaseStatus)
}
