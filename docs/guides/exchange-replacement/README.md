# Exchange Replacement offline documentation

This directory is the X3 operator and maintainer documentation corpus for the
Exchange Replacement Contract. It is written so the files can be copied into an
offline package without requiring a repository checkout or an internet link.
All links in this directory are relative.

Status is frozen at **2026-08-23**:

- **Implemented / internal A0:** `mailctl exchange-a0` and the fixed
  `scripts/exchange-a0/Collect-SetjoinExchangeA0.ps1` collector. This is a
  customer-local, read-only, pre-productization lane. Its reports and receipts
  are explicitly non-importable.
- **Implemented / default OFF V1A:** `mailctl exchange assess ...`, the fixed
  31-outcome collector, strict `bundle.sja` format, canonical registry/compiler,
  reducer/API workflow, seven permissions, unified admin UI, encrypted server
  custody, signed publication/deletion receipts, redacted diagnostics and stable
  exit classes. Source-transfer bundles are integrity-bound JSON and still require
  approved media custody; the signed portable Windows release package remains a
  release gate.
- **Unassessed evidence:** no customer report, accepted handling terms, real
  decision-use event, product-owner promotion, controlled Exchange T1 evidence,
  representative Exchange T2 evidence, or live Windows PowerShell execution
  parity is asserted by this corpus. Repository implementation tests are not
  substitutes for those gates.

## Read in this order

1. [START-HERE](START-HERE.md) — choose the internal A0 path or default-OFF V1A.
2. [Quickstart](quickstart.md) — local A0 collection/report flow and the
   implemented default-OFF V1A flow.
3. [Command reference](command-reference.md) — exact A0 and V1A syntax and
   artifact boundaries.
4. [Handling and retention](handling-and-retention.md) — local custody,
   redaction, retention boundaries, and support-bundle rules.
5. [Troubleshooting](troubleshooting.md) — current A0 IDs and reserved future
   diagnostic codes with safe recovery paths.
6. [Compatibility and vocabulary](compatibility-and-vocabulary.md) — support
   cells, three-axis status, phases, and evidence tiers.
7. [Air-gapped transfer](air-gapped-transfer.md) — current local and V1A import
   custody contract.
8. [Maintainer registry workflow](maintainer-registry-workflow.md) — A0 registry
   boundaries and the implemented V1A single-source authoring workflow.
9. [Generated content and manifests](generated-content-and-manifests.md) —
   projection, inclusion-manifest, digest, and omission rules.

## Non-negotiable boundaries

`exchange-a0` never mutates Exchange, never uploads data, and never turns an
absent probe into support. Its `attest` command records an explicitly supplied
event; it does not prove that the event happened. A0 receipts have
`signatureStatus: unsigned_customer_attestation` and `importable: false`.

The V1A public contract reports business outcomes, not cmdlet parity. Unknown,
incomplete, blocked, unsupported, and excluded facts remain visible. No document,
generated comparison, UI label, or report may turn a missing implementation or
missing evidence into a `supported` claim.

For repository maintenance, the authoritative inputs are the approved plan and
`config/exchange-replacement/`; generated comparison material must not be edited
by hand. Real-customer, controlled-Exchange, signed-package, reference-scale and
retained-binary evidence remains external to this documentation corpus.
