package securityprogram

import (
	"encoding/json"
)

// TransitionsSchemaV2 is the schema of the frozen grammar artifact the
// canonical checker consumes
// (docs/verification/deep-security-remediation-transitions.json). The
// artifact is generated from this package only; editing it by hand breaks
// the byte-for-byte freeze test and the checker's hash pin.
const TransitionsSchemaV2 = "setjoin.sec.deep-security-remediation-transitions/v2"

// FrozenOn is the freeze date recorded in the generated artifact.
const FrozenOn = "2026-09-22"

// CanonicalController is the sole CLI dispatcher the namespace binds to.
const CanonicalController = "scripts/verify-security-program.sh"

// TransitionsArtifactPath is the repository-relative location of the frozen
// grammar artifact.
const TransitionsArtifactPath = "docs/verification/deep-security-remediation-transitions.json"

type contractDoc struct {
	Schema              string          `json:"schema"`
	Contract            string          `json:"contract"`
	CanonicalController string          `json:"canonicalController"`
	FrozenOn            string          `json:"frozenOn"`
	Authority           authorityRule   `json:"authority"`
	Enums               enumsDoc        `json:"enums"`
	Operations          []opSpec        `json:"operations"`
	ErrorCatalog        []catalogEntry  `json:"errorCatalog"`
	LedgerBinding       ledgerBinding   `json:"ledgerBinding"`
	Publication         publicationRule `json:"publication"`
}

type authorityRule struct {
	Accepted       []string `json:"accepted"`
	ViolationCode  string   `json:"violationCode"`
	VersionHeader  string   `json:"versionHeader"`
	UnknownVersion string   `json:"unknownVersionCode"`
}

type enumsDoc struct {
	Disposition        []string `json:"disposition"`
	LocalStatus        []string `json:"localStatus"`
	VerificationStatus []string `json:"verificationStatus"`
	ReleaseStatus      []string `json:"releaseStatus"`
}

type catalogEntry struct {
	Code    string `json:"code"`
	Problem string `json:"problem"`
	Cause   string `json:"cause"`
	Fix     string `json:"fix"`
}

type ledgerBinding struct {
	OwnedRowFields        []string      `json:"ownedRowFields"`
	OwnedCounts           []string      `json:"ownedCounts"`
	VerificationStatement statementRule `json:"verificationStatement"`
}

type statementRule struct {
	ZeroReceiptsContains string `json:"zeroReceiptsContains"`
	WithReceipts         string `json:"withReceipts"`
}

type publicationRule struct {
	Mode           string `json:"mode"`
	EvidenceSchema string `json:"evidenceSchema"`
	BusyCode       string `json:"busyCode"`
	HashBinding    string `json:"hashBinding"`
}

// ContractJSON renders the frozen transition grammar. The output is
// deterministic; the committed artifact must match it byte-for-byte
// (contract_test.go enforces this, and the ER1 checker pins the artifact's
// SHA-256), so the Go grammar and the checker can never drift apart.
func ContractJSON() ([]byte, error) {
	doc := contractDoc{
		Schema:              TransitionsSchemaV2,
		Contract:            ContractVersion,
		CanonicalController: CanonicalController,
		FrozenOn:            FrozenOn,
		Authority: authorityRule{
			Accepted:       []string{AuthorityServiceRole},
			ViolationCode:  CodeApprovalRequired,
			VersionHeader:  "contract",
			UnknownVersion: CodeSchemaUnsupported,
		},
		Enums: enumsDoc{
			Disposition:        []string{"fixed", "no_change", "blocked"},
			LocalStatus:        []string{"unmapped", "traced", "fix_required", "no_change_candidate", "blocked", "patched", "proof_patched"},
			VerificationStatus: []string{"none", "receipt_bound", "derived_green"},
			ReleaseStatus:      []string{"not_ready", "external_evidence_open", "release_ready"},
		},
		Operations:   operationRules(),
		ErrorCatalog: catalogEntries(),
		LedgerBinding: ledgerBinding{
			OwnedRowFields: []string{
				"disposition", "localStatus", "verificationStatus", "releaseStatus",
				"blockedReason", "closurePatch", "tests",
				"evidence.verification", "evidence.manifest", "evidence.sourceFingerprint", "evidence.verdict",
				"remediation", "remediationTransitions",
			},
			OwnedCounts: []string{"fixed", "no_change", "blocked", "locallyRemediated"},
			VerificationStatement: statementRule{
				ZeroReceiptsContains: StatementNoReceipts,
				WithReceipts:         StatementWithReceipts,
			},
		},
		Publication: publicationRule{
			Mode:           "atomic-two-target-journal",
			EvidenceSchema: EvidenceManifestSchema,
			BusyCode:       CodePublicationBusy,
			HashBinding:    "the journal binds evidence sha256 and ledger-after sha256 into one atomic commit; Recover replays deterministically",
		},
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, newErr(CodeInternal, "contract", "", "frozen grammar marshal failed: "+err.Error())
	}
	return append(out, '\n'), nil
}

// catalogEntries returns the shared-catalog triples for exactly the codes
// this namespace emits, in stable order.
func catalogEntries() []catalogEntry {
	order := []string{
		CodeUsage,
		CodeApprovalRequired,
		CodeAttemptUnknown,
		CodeEvidenceInvalid,
		CodeSchemaUnsupported,
		CodePrerequisiteBlocked,
		CodePublicationBusy,
		CodeInternal,
	}
	entries := make([]catalogEntry, 0, len(order))
	for _, code := range order {
		triple, ok := catalog[code]
		if !ok {
			continue
		}
		entries = append(entries, catalogEntry{
			Code:    code,
			Problem: triple[0],
			Cause:   triple[1],
			Fix:     triple[2],
		})
	}
	return entries
}

// EmittedCodes returns the set of shared codes the namespace can emit.
func EmittedCodes() []string {
	order := []string{
		CodeUsage,
		CodeApprovalRequired,
		CodeAttemptUnknown,
		CodeEvidenceInvalid,
		CodeSchemaUnsupported,
		CodePrerequisiteBlocked,
		CodePublicationBusy,
		CodeInternal,
	}
	return order
}
