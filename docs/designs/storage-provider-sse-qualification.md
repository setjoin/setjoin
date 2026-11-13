# Storage E2 — provider-side encryption qualification

Date: 2026-09-08. Proposed planning contract, not implementation, provider
certification or a numerical score. Owner: Storage E2.
Meanings: [posture vocabulary](storage-posture-vocabulary.md). E1 owns host-volume
observations; E3/E4/E5 own Setjoin envelopes, custody and encoding generations.

## What this contract qualifies

Qualify a specific provider adapter/profile and bound target configuration, not
“S3-compatible” as an unrestricted guarantee. Requested SSE policy, provider
capability, observed configuration, exercised operation coverage, current access
and existing-object coverage remain independent. Provider health, TLS, checksums,
retention and a successful PUT/GET do not independently prove provider encryption.

SSE relies on the provider's enforcement and trustworthy evidence of its
configuration/operation results. Returning the original plaintext and a matching
digest proves the byte round trip, not the physical at-rest representation. State
this trust boundary in operator evidence; Setjoin cannot cryptographically prove
a remote provider's internal disk behavior through an ordinary object response.
An untrusted-provider confidentiality requirement belongs to E3's separate envelope
profile, not a stronger unsupported SSE claim.

## Current inspected implementation

`DriverConfig` has endpoint/credential/bucket and Object Lock fields, but no typed
encryption requirement. `ObjectInfo` does not expose an SSE observation. The
inspected hot-S3, backup-S3 and OSS puts/gets supply object data and ordinary
options; they do not select an encryption profile or verify one. Backup puts can
add retention settings, which are not encryption. Hot/backup copy methods also
lack an explicit encryption-policy contract in these bodies.

This is bounded source evidence, not proof that an administrator-configured
provider lacks default encryption. Existing retention methods/type assertions and
runtime unsupported errors are not an SSE-capability registry. E0 also identifies
direct MinIO consumers outside these adapters; qualifying one adapter cannot
qualify those writers by inference.

| Source | Actual read ranges | Whole-file SHA-256 |
| --- | --- | --- |
| `mailserver/internal/storage/driver.go` | complete1–174 | `e332d201a009b326581860deea74f49e2b63a555d3b029b2d6508e1584b58e36` |
| `mailserver/internal/storage/s3_hot_driver.go` | 1–145 | `f3c5d99598a47c2b83ce8f781f66b8fef09dda37ae7c529e44825bb0ea9e53d8` |
| `mailserver/internal/storage/s3_driver.go` | 68–96,130–180 | `af9f023600d85e604bc1ad993271f35fbae48cc137e14c13a650d895a275e287` |
| `mailserver/internal/storage/oss_driver.go` | 20–65 | `d5ae10e45f0219adcf88a41eee7c6ab8789eec981253f53d25d02bd861ba9d76` |

No SDK internals, live service, full constructor/caller census or tests were
qualified here. Adapter behavior and current external configuration remain
separate evidence requirements.

## Required profile and observation binding

Use the existing provider/capability registry and generated owner schemas; do not
add a second app permission registry or allow arbitrary vendor fields into Drive.
E2 must freeze typed profile variants for admitted SSE-S3, SSE-KMS and qualified
vendor/customer-managed equivalents. A key reference is not a raw encryption key;
secret-bearing customer-key protocols need explicit custody qualification, not
free-text headers supplied by an app or administrator UI.

| Binding | Required contents |
| --- | --- |
| Target | Provider registration and adapter build/profile, endpoint/transport identity, region/account/bucket or vendor equivalent, placement and configuration generation; safe display labels separate from stable identity |
| Access | Credential reference and revision, effective principal/scope evidence and key-reference revision where applicable; no credential/key values in the receipt |
| Requirement | Requested layer/profile and permitted operation set, enforcement mode (provider default versus explicit per-operation selection), required-policy revision and declared data classes |
| Observation | Qualified configuration source, safe provider response facts, probe time/freshness/invalidation, exact completed operation cases, failures and trust limitation |
| Coverage | Newly written versus inventoried historical objects, exact namespaces/generations and copy/multipart/range paths admitted; unknown coverage stays unknown |
| Operation | Qualification operation identity, approved owned resources/budget, receipt, incomplete/cleanup disposition and current admission projected by the owner |

The final registry/schema/profile must define exact serializations, validation,
safe error categories, timeout/byte/object limits and evidence maximum age.
Unknown profile/algorithm or missing required fields cannot satisfy policy. A
vendor string claiming support is not qualification.

## Qualification and activation sequence

1. Re-authorize the exact target/profile and read available configuration evidence
   through a narrow provider capability. Credential-less discovery may describe
   advertised support, but cannot alone authorize protected data access or verify
   the selected private target. Separate unsupported capability from unavailable
   inspection, denied access and malformed response.
2. Before any write, compile an owned test-resource plan: exact namespace/keys,
   count/byte limits, required operations, credentials/scope and cleanup semantics.
   Account for retention, legal hold, versioned objects and multipart remnants
   before admitting a probe. Do not call `EnsureBucket` or change bucket-wide
   defaults, lifecycle, retention, policy or keys as a side effect of discovery.
3. Use synthetic non-secret bytes only in an approved disposable namespace/target.
   Exercise each required operation through the production adapter path: write,
   full read, metadata observation, and any admitted range/multipart/copy variants.
   Verify exact bytes plus the profile's required encryption evidence. Missing
   evidence is not compensated by a successful checksum.
4. Verify policy enforcement according to the profile without writing unprotected
   bytes into a customer namespace. Negative downgrade/missing-key tests belong
   in a qualified disposable target unless the provider offers an explicitly safe
   non-mutating enforcement check. A failed negative test cannot silently widen
   the admitted operation set.
5. Reconcile every owned object/version/upload after success, failure, cancellation
   or response loss. A delete response alone is not proof that all owned retained
   versions disappeared. If cleanup is blocked, retain an exact visible obligation
   and reason; never weaken holds, delete a bucket, sweep unrelated prefixes or
   report complete cleanup. Pre-approved retention obligations remain separately
   accounted for, not hidden test residue.
6. Publish a qualification receipt binding actual covered cases and current target,
   credential, key and policy revisions. The reducer-owned admission decision must
   recheck these bindings before activation; a probe worker cannot select the
   active provider or rewrite existing handles. Incomplete required evidence keeps
   activation blocked, regardless of cosmetic health status.

Changing defaults for future objects does not establish that historical objects
were transformed. Enabling a required policy for existing data needs a complete
bound inventory and adequate current evidence for every admitted object class.
If existing objects already satisfy the requested profile, qualify that evidence
without forcing conversion. Unknown coverage stays blocked until adequate evidence
is obtained; established nonconforming data requires separately authorized provider
conversion or E5–E7 migration, independently verified with exact old/new coverage
and retained source protections. A config
toggle alone cannot advertise full historical protection or retirement eligibility.

## Rotation, outage and copy boundaries

- Credential, effective scope, endpoint identity, key reference, adapter/profile,
  required policy or relevant provider configuration changes invalidate dependent
  evidence. Requalification may reuse only unchanged, explicitly bound cases;
  failed credentials mean unavailable access, not unsupported encryption.
- Provider-held KMS unavailability does not inherit Setjoin's accepted one-hour
  in-memory grace. Only operations the provider actually authorizes and completes
  can succeed. No plaintext fallback, alternate unapproved key or weaker profile.
- A provider key rotation claim is not proof of historical-object re-encryption.
  Retain old-key dependencies required by source objects and backups until their
  owning recovery/retention obligations permit retirement. Do not retire keys as
  test cleanup or because a new credential works.
- Copy and multipart completion must establish the destination's required policy
  and exact identity. Do not assume source settings transfer, or that an old
  upload/session can complete under changed policy. Recheck current admission and
  final receipt semantics at the owning adapter/reducer boundary.
- Backup source SSE and destination SSE qualify independently. Recovery must show
  access to every required provider/key generation from the declared independent
  recovery environment; copied plaintext hashes alone do not prove key availability
  or the destination's encryption/retention posture.

## Proposed acceptance cases — none executed

| Case | Required oracle |
| --- | --- |
| E2-01 capability versus evidence | Advertised support + missing private-target evidence remains unqualified; known unsupported profile differs from access denial/timeouts |
| E2-02 byte round trip versus protection | Correct bytes without required SSE evidence cannot satisfy required policy; wrong/truncated bytes fail even with a claimed encrypted flag |
| E2-03 exact target binding | Same display endpoint with changed bucket/account/transport/config identity invalidates dependent receipt; no credential leakage |
| E2-04 safe owned probes | Unknown retention/versioning or insufficient cleanup authority blocks unplanned writes; failed cleanup reports exact owned residue without broad deletion |
| E2-05 enforcement negative | Missing/wrong key or attempted downgrade produces the profile's verified denial in a disposable target, never an unprotected customer write |
| E2-06 multipart/copy | Destination policy and final object identity verified; stale upload after policy/key change cannot yield a false admitted success |
| E2-07 old-object coverage | Full inventory/current evidence can qualify already-conforming historical objects without conversion; new-write defaults alone leave coverage unverified. Unknown objects need adequate evidence; established nonconforming objects need separately authorized verified remediation |
| E2-08 rotation and revocation | Changed credential/key scope closes stale admission; old-generation recovery dependencies remain independently tracked |
| E2-09 provider KMS outage | Truthful provider errors and safe retry; no claimed Setjoin grace, weaker key or plaintext fallback |
| E2-10 backup and restore | Independent destination/key-profile verification, exact restored bytes and explicit missing-key failure; source posture cannot certify destination |
| E2-11 cancellation and response loss | Reconcile same qualification operation, including owned versions/uploads and cleanup obligations; no duplicate uncontrolled probes |
| E2-12 surface parity | API/CLI/UI show identical current scoped posture, coverage, blockers and cleanup state; unauthorized target information is omitted |

These cases require exact adapter/profile fixtures, source/generation bindings,
executable lanes and retained verdicts in E9. They do not complete E2, activate a
provider or demonstrate compatibility with any named vendor. The source-derived
implementation map must still bind direct clients, all object operations, concrete
schema/configuration custody and existing provider-change authority. Typed schemas,
profile/fixture contracts and numerical resource bounds must freeze before
implementation. Executed qualification through the implemented production adapter
is required before activation or corresponding compatibility/protection claims;
it is not an impossible prerequisite for writing that adapter.
