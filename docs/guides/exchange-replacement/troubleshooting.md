# Troubleshooting and diagnostic codes

Preserve the failing artifact, its digest, the stage, and the diagnostic ID before
retrying. Diagnostics must help an operator recover without weakening security or
completeness controls.

## Current A0 diagnostic IDs — implemented

These IDs are emitted by the fixed A0 collector/report path. They are not the
V1A public taxonomy.

| ID | Meaning | Safe evidence to inspect | Remedy |
|---|---|---|---|
| `A0-COLLECT-TOPOLOGY` | Topology/build probe failed | The probe's bounded category/type/error identifier in `collector.json`; do not copy full exception prose into a portable report. | Have the approved Exchange operator resolve the read-only topology access issue, then rerun into a new output path. |
| `A0-COLLECT-DELEGATION` | Mailbox or delegation probe failed | The bounded probe detail and whether mailbox enumeration completed. | Resolve the named read-only access issue and rerun; do not infer delegation is absent. |
| `A0-MISSING-MAILBOXES` | Calendar/resource probes could not run because mailbox inventory was unavailable | `EX-A0-MAILBOX-DELEGATION` status plus the two dependent rows. | Restore a complete mailbox inventory or leave both dependent capabilities `unassessed`. |
| `A0-COLLECT-CALENDAR` | Calendar-folder visibility probe failed | Calendar row status, bounded detail, and report input/registry digests. | Resolve the read-only calendar access issue and rerun; do not convert it to observed or supported. |
| `A0-COLLECT-RESOURCE` | Resource-booking probe failed | Resource row status and bounded detail; verify the source topology label. | Resolve the read-only resource-policy access issue and rerun; preserve the blocker if it remains. |
| `A0-MISSING` | A report row was synthesized because the collector emitted no result for a registry capability | Registry digest, input digest, and the missing capability ID. | Rerun the collector or keep the row explicitly `unassessed`; never treat a missing row as success. |

The A0 Go validator also rejects malformed schema/kind/version, registry digest
mismatch, unknown or duplicate capabilities, invalid timestamps, unknown JSON
fields, oversized files/facts, and incomplete status rows. Those errors are local
validator messages, not stable public diagnostic IDs.

## V1A public diagnostic taxonomy

The following codes are the stable V1A vocabulary. Individual paths emit only
the codes applicable to their current failure boundaries; listing a code is not
evidence that its success path or external environment has been exercised.

| Code | Contract meaning | Safe evidence | Safe next action |
|---|---|---|---|
| `PKG-001` | package tampered | Compare the package's approved signature/digest and local file list | Replace it from an approved offline source; do not execute a tampered package. |
| `PKG-002` | runtime unsupported | Future `preflight --offline` result and package version | Use a version whose runtime range is explicitly admitted. |
| `CFG-001` | config invalid or contains an unknown key | The local config schema error and redacted config path | Regenerate the versioned starter and remove unknown keys; do not bypass validation. |
| `PREF-001` | Exchange RBAC insufficient | Future preflight permission verdict and required-role name | Ask the named Exchange owner for the least-privilege read role, then rerun. |
| `PREF-002` | endpoint/TLS/DNS unavailable | Future preflight endpoint result and approved local resolver/TLS evidence | Repair the approved endpoint/network path; never disable TLS or certificate checks. |
| `PREF-003` | build or topology unsupported | Future preflight support-cell tuple | Stop or record the affected scope as unassessed; do not widen the support cell by analogy. |
| `COLLECT-001` | collection throttled | Stage, retry-after metadata, checkpoint, and bounded counters | Wait for the approved retry window and resume safely. |
| `COLLECT-002` | cancelled at checkpoint | Durable checkpoint and cancellation diagnostic | Use the same-generation future `collect --resume <checkpoint>` path. |
| `COLLECT-003` | required root incomplete | Expected/emitted/missing root and terminal probe counts | Repair the missing root access and rerun the affected collection. |
| `COLLECT-004` | zero result lacks independent proof | Denominator, terminal results, and independent zero evidence | Keep the outcome unassessed; obtain the independent proof or rerun. |
| `IMPORT-001` | bundle schema incompatible | Bundle schema, server supported range, and registry/support-cell digests | Use a mutually supported artifact or follow the documented upgrade order. |
| `IMPORT-002` | digest or signature mismatch | Origin/import digest comparison and manifest/signature result | Preserve the prior valid run and obtain a matching untampered artifact. |
| `IMPORT-003` | unsafe or oversized content | Inspectable size, archive/path/format rejection, and redaction preview | Regenerate a bounded redacted bundle; never disable safety limits. |
| `IMPORT-004` | stale fencing token | Processing generation/lease diagnostic and run ID | Retry through the owning workflow; do not reuse or forge a token. |
| `MAP-001` | identity collision | Collision family, source generation, and homogeneous preview | Resolve the named collision with an authorized owner; do not guess an identity match. |
| `MAP-002` | decision generation stale | Decision generation, current run generation, and affected capability IDs | Refresh and review a new preview before deciding. |
| `EVID-001` | evidence expired or invalidated | Evidence digest, support-cell digest, expiry/invalidation reason | Rerun the named cases and regenerate the affected document. |
| `DOC-001` | document generation or translation failed | Capability ID, generator input digest, and last-valid artifact digest | Preserve the last valid artifact, correct the named input, and regenerate. |
| `PUBLISH-001` | claim gate refused publication | Claim axes, missing evidence, inclusion manifest, and refusal receipt | Keep the claim unpublished until the explicit gate is satisfied. |
| `DELETE-001` | backup expiry is pending | Object/run scope, backup disposition, and deletion receipt state | Do not claim irreversible deletion; obtain independent expiry/key-destruction proof. |

No remedy above recommends disabling TLS, version checks, signatures, redaction,
authorization, or completeness. The implementation must reject any generated
remedy that does so.

## Reading a V1A diagnostic

The problem shape contains:

```text
code
plain-language cause
affected probes/outcomes
held role versus required role
safe evidence command
copy-paste retry
next actor or escalation owner
offline documentation link
correlation ID
```

Worker fencing should be rendered as “processing ownership changed; safe retry
available.” Tokens are audit-only. A diagnostic ID joins logs and retained
evidence without exposing customer values.
