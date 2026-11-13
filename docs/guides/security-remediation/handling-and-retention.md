# Security evidence handling and retention

Evidence bundles live outside worktrees under restrictive permissions. Operator
output exposes logical references, hashes, counts, and states—not credentials,
finding bodies, absolute home paths, or raw private evidence. Before C3, admitted,
failed, superseded, and quarantined evidence is retained. Archival after C3 must
keep hashes, receipts, attempt records, and observations addressable.

Predecessor G0-G4 boundary evidence resolves through
`docs/verification/security-boundary-evidence-manifest.json`: one dated immutable
pointer per named lane plus one aggregate over the eight. A single overwriteable
`latest.json` is retained run output, never completion evidence; republishing a
lane means naming its new dated generation in the manifest and updating the
aggregate, never rewriting a pointer in place. A registry lane recorded with
reopened occurrences (`security-boundary-cases.json` `reopenedOccurrenceIds[]`)
holds at exit 3 until each ID is cleared by source-keyed adjudication with
focused proof.
