# Transactional release and entitlement documents

The release manifest schema and publisher use the shared Rust
`server-rust/crates/release-format` contract. Frozen Go references remain in
`shared/release/manifest.go` and `shared/release/canonical.go`; entitlements
remain in `shared/release/entitlement.go`. Unknown or exact-duplicate JSON keys
are rejected;
documents are limited to 1 MiB; all timestamps are UTC RFC 3339 seconds; all
digests are lowercase SHA-256; and signatures are Ed25519 over the canonical
document with `"signatures":null` (Go does not omit that field).

`manifest_digest` always means SHA-256 of those canonical unsigned payload
bytes, matching `VerifiedManifest.Digest`; it is not the hash of the signed JSON
file. Artifact digests still bind exact raw artifact bytes.

The CI-only Rust `setjoin-release` publisher (`server-rust/bins/release`) is the
supported authoring path; `tools/setjoin-release` remains the frozen parity
reference. Build with `cargo build --locked --release --manifest-path server-rust/Cargo.toml -p setjoin-release`:

```text
setjoin-release manifest build --draft manifest.draft.json --artifacts-dir release-root --output manifest.json
setjoin-release manifest sign --manifest manifest.json --signer-helper /protected/kms-helper --key-id release-2026-a --output manifest.signed.json
setjoin-release manifest verify --offline --manifest manifest.signed.json --artifacts-dir release-root --trust-roots release-roots.json --channel community --platform linux --arch amd64 --current-version 2.0.5
setjoin-release manifest inspect --manifest manifest.signed.json
```

Do not hand-author artifact sizes, hashes, migration hashes, SBOM/provenance
inventory, or signatures. `manifest build` derives them from fixed artifact
classes. Offline verification requires SBOM/provenance, rejects test roots and
enforces at least two release-key signatures. The signer helper chooses the key;
the publisher does not itself classify helper key IDs as production or test.

No workflow publishes releases yet, and the public repository holds no signing
material; release builds and owner-side signing are planned separately.
`scripts/sign-server-release.sh` remains the signing entry point. It takes the signer
helper, the trust-roots file and two distinct key IDs (`SETJOIN_RELEASE_SIGNER_HELPER`,
`SETJOIN_RELEASE_TRUST_ROOTS_PATH`, `SETJOIN_RELEASE_KEY_A`/`SETJOIN_RELEASE_KEY_B`)
and an unsigned inventory (`manifest.draft.json` and `artifacts/`), hashes the
inventory, signs with both helper key IDs, verifies signatures, compatibility,
freshness and every artifact, then atomically promotes the signed manifest. A failed
stage preserves an existing output. See the
[publisher contract](../../server-rust/bins/release/DOX.md) for the gate and tests.
The same script is available to existing release automation with positional
arguments documented by its usage. `SETJOIN_RELEASE_BIN` may select a prebuilt
Rust publisher; otherwise the script builds the locked Rust package itself.
The CI tool is not part of the installed server cohort.

## Release manifest v1

Top-level fields are:

| Field | Contract |
|---|---|
| `schema_version` | exactly `1` |
| `release_id`, `version` | stable identifier and strict semantic version |
| `channel` | `community` or `enterprise` |
| `published_at`, `expires_at`, `metadata_version` | freshness and anti-rollback metadata |
| `previous_version_floor` | signed executable rollback floor |
| `platforms`, `architectures` | sorted unique declared targets |
| `compatibility` | source-version, PostgreSQL, and optional minimum-client ranges |
| `schema_from`, `schema_to`, `migrations` | exact expand-only, transactional, CI-attested migration chain; no embedded SQL |
| `artifacts` | sorted unique inventory with class, fixed target, cohort, size, digest, media type, and optional core compatibility |
| `health_gates` | named preflight, readiness, data-contract, and post-commit adapters; never commands |
| `recovery` | maximum application recovery-point age and minimum free bytes |
| `notes` | bounded operator summary, downtime range, support channel, and blockers |
| `signing`, `signatures` | threshold/rotation policy and sorted signatures |

The `core` cohort, when present, contains `mailserverd`, `authserverd`,
`mailctl`, and `webmail` together. Every release contains exactly one SBOM and
one provenance artifact and exactly one recovery guide whose fixed installed
target is `share/docs/UPGRADE_RECOVERY.md`; every other fixed target is also a
singleton. Sidecars declare their compatible core range. A
migration artifact must byte-match its descriptor; v1 accepts only
transactional expand migrations with previous-binary evidence.

After extraction, the updater writes `installed.evidence.json` beside the
manifest. Its content digest covers the exact relative directory and regular-file
inventory except the evidence file itself. Activation, idempotent restaging, and
rollback recompute that digest, so a signed archive cannot silently become a
mixed or corrupted installed cohort.

## Entitlement v1

An entitlement is an offline, signed authorization for Enterprise artifact
access. It is scoped to one installation, Enterprise channel, version ranges,
valid/grace times, and optional non-production rights. Community never requires
a local entitlement. Import verifies the document before atomically replacing
`/etc/setjoin/entitlement.json`; `show` emits only sanitized identity, channel,
scope, dates, state, and digest.

Billing is an annual active-internal-human-seat contract with a 300-seat
Enterprise floor. Mailbox-less guests, shared/resource mailboxes, aliases, and
service principals are excluded. Entitlement expiry pauses new Enterprise
artifacts and support after grace; it never locks mail, data, sign-in, export,
or the running release.

The upgrade catalog stores the signed document's `grace_until` as
`entitlement_grace_until`. Preview and claim both recheck that boundary so queued
work cannot start after grace; a transaction already claimed before the boundary
continues to a safe terminal state.

## Community and Enterprise channel rules

- Community receives signed current-line releases and critical current-line
  security fixes. It is not an intentionally unsafe channel.
- Enterprise promotes the same forward-only lineage after additional validation and
  soak, and adds offline mirror support, staged deployment evidence, compatibility
  matrices, and support SLA. It is not a separate LTS or routine-backport fork.
- Both channels use the same manifest, updater, data formats, and cryptographic
  verification. Switching channels never migrates customer data or reinstalls
  the current release.
- Normal production rollout targets 14–30 days and has a 90-day maximum supported
  drift. The administrator selects the latest approved build once; the updater uses
  a direct same-epoch path or the minimum signed bridge path across contract or
  irreversible migration boundaries. It never requires every intermediate release.
- Online Enterprise repository authorization is enforced by the artifact
  service. A locally patched entitlement cannot authorize an online download.

## Artifact and startup contract

- Download and cache are per signed artifact digest. Unchanged bytes may be reused,
  but activation always references a complete, immutable, manifest-verified release.
- Activation is atomic per signed compatibility group. The core gateway, auth server,
  matching Webmail/CLI, migrations and recovery contract stay together unless exact
  mixed-version evidence admits a smaller group. Eligible sidecars/providers retain
  their own declared core and protocol ranges.
- No running executable is overwritten in place. A fully synced target is switched by
  an atomic release pointer, then the affected fixed process set is restarted or
  drained in its declared order.
- System startup may trigger or resume an approved transaction, but only the
  root-owned updater acquires locks, verifies recovery evidence and applies signed
  migrations with the separate owner credential before starting business processes.
- Business processes perform read-only schema and contract checks. A stale, future or
  incompatible schema fails startup; the process never receives DDL credentials or
  silently repairs schema.
- The durable updater journal makes restart/resume idempotent. Repeated systemd starts
  cannot create parallel migrations or bypass a recovery-required terminal state.

## Recovery evidence terminology

An application recovery point covers PostgreSQL, blobs, and protected
configuration and is the portable upgrade gate. An isolated restore proof says
that a recovery point was restored and validated elsewhere. A Proxmox/VMware/
cloud/LVM/ZFS/Btrfs snapshot is optional platform evidence and is machine-
verified only when a provider adapter can query the exact identity. The three
terms are never interchangeable.
