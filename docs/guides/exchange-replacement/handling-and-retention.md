# Handling and retention

This guide describes custody and truthful evidence boundaries. A local output
directory is not automatically a retention policy, a signature, or proof that a
customer approved handling.

## Current A0 artifacts

The implemented A0 flow keeps work local and creates these artifacts:

| Artifact | Contents | Handling rule |
|---|---|---|
| `a0-registry.json` | Embedded v0 capability IDs, outcomes, and fixed `Get-*` command names | Keep with the digest that the collector used; do not edit it to expand the command allowlist. |
| `collector.json` | Versioned source metadata and aggregate probe facts | Treat as customer-local configuration evidence; do not place it in the repository or an unapproved transfer. |
| `report.json` | Registry-ordered rows, counts, statuses, facts, and digest bindings | Preserve as an immutable report input to any later receipt. |
| `report.html` | Escaped, print-ready human-readable report | The canonical A0 human view; it still says replacement readiness is not established. |
| `report.pdf` | Optional local Microsoft Edge rendering | Only created with `--pdf`; its digest is added to the A0 manifest. |
| `manifest.json` | Input, registry, row-set, and artifact SHA-256 values | Integrity binding only; it does not establish publisher identity or product support. |
| A0 receipt JSON | Explicit handling or decision-use fields and report digest | Unsigned, non-importable attestation metadata; create only after the named event. |

The collector is designed to emit aggregate counts and policy distributions rather
than message content or raw mailbox identities. The output can still contain
organization labels, build/topology metadata, and sensitive operational facts.
Apply the organization's approved local access, media, backup, and deletion rules.

The Go implementation requests restrictive file modes and refuses to overwrite
existing outputs. On Windows, POSIX mode bits are not an NTFS ACL policy: use a
directory whose NTFS ACL was restricted before running the tool. This documentation
does not claim that a Windows ACL or live execution test has been verified.

## A0 receipt semantics

`exchange-a0 attest` accepts an actor, purpose, decision, issue time, and asserted
retention period. It binds the new receipt to the exact report bytes and refuses an
invalid or importable report. It does not independently contact the organization,
verify the actor, enforce deletion, sign the receipt, or prove that a decision or
handling acceptance occurred.

The only honest receipt values in the current A0 contract are:

```text
signatureStatus = unsigned_customer_attestation
importable       = false
```

Do not create a receipt for a planned event, a test placeholder, or an invented
customer. Two comparable reports, one real decision-use receipt, accepted handling
terms, named design partners, and product-owner promotion remain external gates;
none is represented as existing here.

## V1A product retention contract — implemented active-store boundary

The V1A lifecycle is separate from A0. It inventories raw exports, normalized facts,
identity mappings, tombstones, reports, audit logs, backups, caches, fixtures, and
retained evidence. Each object must name allowed fields, storage, access roles, key
owner, retention start, deletion or irreversible-anonymization date, backup
behavior, propagation method, verification receipt, and whether pseudonyms remain
linkable.

The approved design uses these default rules as a future starting point:

- raw exports default to deletion after report acceptance or 30 days, whichever is
  earlier;
- identity mappings and tombstones use the later of project-retention and
  rollback deadlines;
- reports and retained evidence use separately approved project/release retention;
- an extension names an owner and date;
- deletion propagates through caches/backups and produces a receipt;
- deletion while backups remain restorable cannot be described as irreversible
  without independent backup-expiry or key-destruction evidence.

Deletion requests are durable and drained while the feature is OFF. Active objects
are removed and tombstoned; the signed receipt remains
`backup_expiry_pending` until independent backup-expiry or key-destruction evidence
exists. A0 supplies none of this behavior.

## V1A diagnostic support file

`mailctl exchange assess diagnose` creates an inspectable,
explicitly consented bundle containing versions, digests, stages, and redacted
diagnostics. Its default exclusion list is:

```text
raw facts, credentials, tokens, principals, customer documents
```

The operator chooses the destination. No A0 command creates this file, and no support handoff may
silently upload it. A recipient must receive only the minimum approved artifact
set and its digest/diagnostic join data.
