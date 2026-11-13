// Package securityprogram owns the Deep Security Scan Remediation ER3
// remediation namespace: the typed, versioned operation contract
// (start/status/complete/reject) over sealed deep-security occurrences, the
// occurrence-specific validation grammar, and the atomic publication engine
// that commits a ledger update and its evidence artifact together.
//
// Authority boundaries (plan
// retired-docs:superpowers/plans/2026-08-28-deep-security-scan-remediation.md ER3;
// Astra SEC r2 disposition: "Deliver occurrence-specific validation and atomic
// publication through the canonical controller's remediation namespace, with
// its shared version/error contract. The standalone guard does not establish
// this."):
//
//   - This package is a library seam, NOT a second dispatcher. The sole CLI
//     dispatcher remains scripts/verify-security-program.sh (its remediation
//     namespace). Nothing here parses argv, prints terminals, or launches
//     scans or remediation work.
//   - Error codes are the shared E_SECURITY_PROGRAM_* catalog (same codes and
//     problem/cause/fix triples as the canonical controller). No second error
//     authority is introduced; the frozen grammar artifact this package
//     generates (docs/verification/deep-security-remediation-transitions.json)
//     is the single grammar both the Go side and the ER1 checker
//     (scripts/check-deep-security-remediation.mjs) consume.
//   - The namespace operates only on the EXISTING sealed-ledger JSON
//     artifacts. It performs no scans, executes no remediation, and never
//     seals a closure without an explicit complete request bound to evidence.
//   - Every mutating operation requires the service-role authority; any other
//     caller is refused with E_SECURITY_PROGRAM_APPROVAL_REQUIRED.
package securityprogram
