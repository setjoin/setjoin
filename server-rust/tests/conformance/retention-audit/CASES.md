# Retention and audit (#290)

Public seam: front-door HTTP, with committed row/audit/state/notification
observations, as agreed in spec #251. Expectations are recorded exclusively from
frozen Go; `golden::record` refuses replacement. Native replay has no Go upstream.

The inventory's `retention-audit` slice includes 14 routes: retention policy CRUD,
log retention get/set/prune, audit list/CSV/chain verification/policy get/set,
and synchronous content search/purge. Content search belongs here despite its
path lacking a retention/audit prefix. #289 owns eDiscovery; #291 owns chat.

Each route needs success, cross-tenant/permission denial and invalid-input cases.
Global log settings deliberately accept authorized domain-scoped principals
in frozen Go; audit.read/audit.export instead carry a central org-wide-only
guard. Cases distinguish these boundaries and missing live grants; signed forged
permission claims must not admit a principal.
Retention list sees global policies plus its authenticated domain; mutations
cannot touch another domain or the global tier. Content search is org-wide-only.

Mutators additionally need repeats and committed effects. Audited retention CRUD
must roll back both data and audit on audit failure; audit-policy changes preserve
Go's best-effort audit behavior. Content purge reuses Go's existing reducer and
must preserve holds, counts, audit, state and notifications. Every route gets a
status mutant. Family effect mutants must use the normal golden comparator.
Unknown COMMIT results return an operation ID and never replay a mutation.

Record and replay with `REQUIRE_DB=1`, assigned disposable owner/app/direct DSNs,
and `cargo test --locked -p setjoin-gateway --test retention_audit_recorded --
--test-threads=1`. Recording additionally supplies `GOFREE_RECORD_GO_BINARY`,
`GOFREE_GO_SOURCE`, `GOFREE_RESOURCE_PREFIX=gofree-compl2` and a resource ledger.
Goldens retain exact response-body bytes, except declared volatile fixture IDs,
timestamps, audit checksums and export dates. Row projections come from recorded
Go observations, never from Rust.

The corpus includes scoped successful policy CRUD, global log settings with four
config_changed events, mandatory policy-audit rollback, best-effort audit-policy
failure, audit global-only denials and header/body reason gates, raw JSON ordering,
CSV iterator truncation/formula escaping, protected keyed verification, KQL and
legacy filters, body caps, and mixed held/missing/cross-mailbox purges. Native
content replay observes message/tag rows and counters, mailbox state/journal,
audit and both tag channels. Invalid dates intentionally return successful empty
searches because Go ignores Rows.Err. The legacy policies-invalid recording is
an empty GET; the genuine invalid-input floor is policies-bad-query.

The keyed verifier fixture saves/restores audit_chain_cutover: Go startup with an
HMAC key activates it persistently. Both modes start with the same protected
cutover, and cleanup restores the prior singleton, preventing subsequent keyless
Go recording or native audits from being contaminated.

Qualification adds 14 live status mutants, four real database/authority mutants,
14 before/after COMMIT wire cuts (all seven write shapes), authenticated routing
checks for both kill switches across all 14 registrations, and a local
400 for a NUL KQL (owner-approved security fix 2026-11-05, #436). Lost outcomes require 503/X-Operation-ID; receipts and
whole effects resolve each cut without replay. SQL ownership/atomicity seam:
`mailserver/sql/tests/rust_retention_audit.pg` (20 checks).
