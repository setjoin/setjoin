# Storage posture vocabulary — proposed semantic contract

Date: 2026-09-08. Status: documentation-only proposal; no production wire schema,
capability registration, observation, security qualification or numeric score.
Owner: Storage E0/E1/E2/E8.
Machine-readable catalog: [storage-posture-vocabulary.json](storage-posture-vocabulary.json).

## One meaning, separate authorities

The existing Provider design fixes four posture values: `enabled`, `disabled`,
`unsupported`, `unknown`. Preserve them across installer, API, CLI, UI, health and
evidence; do not add a competing global “secure” boolean. The catalog describes
their proposed meanings, not new production field names or extension capability
IDs. E1/E2/E4/E5 own the eventual schemas and evidence; E8 projects their results.

Every posture is scoped to a protection layer, storage target, relevant generation
and explicit data-class coverage. Disk, Provider SSE and Setjoin object envelopes
are independent layers. The requested policy, observed posture, evidence freshness,
implementation maturity and coverage are separate dimensions. Replication, backup,
legal retention and regulatory qualification remain separately owned facts.

| Dimension | Meaning | Forbidden inference |
| --- | --- | --- |
| Requested protection | The operator/policy's desired requirement for one layer and scope | A requested setting proves that bytes already satisfy it |
| Observed posture | Qualified observation of that layer on the bound target/generation | One enabled layer proves the other two, or all data classes, are enabled |
| Evidence freshness | Whether the observation still matches current scope/configuration and its owning validity rules | A cached historical pass is current after a relevant change |
| Data coverage | Named classes/scopes inventoried, admitted and actually evidenced | First-wave Mail/Drive coverage implies Meet or App-volume coverage |
| Implementation maturity | Missing, primitive-only, partial or integrated machinery | A tested primitive supplies a live deployment observation |
| Operational admission | Current owner-projected permission/readiness for the particular operation | A green posture badge authorizes writes, migration, activation or deletion |

## Posture projection rules

- `enabled`: current scoped evidence establishes this layer's required protection
  for the explicitly claimed coverage. A configuration toggle or provider marketing
  claim alone is insufficient. The owning profile defines the required proof.
- `disabled`: current scoped evidence establishes that this layer is not enabled.
  It is not the fallback value for a missing probe or an unavailable key.
- `unsupported`: the identified target/profile has an evidenced incompatibility
  with this layer. Missing implementation, failed credentials, lost connectivity
  or absent evidence does not prove unsupported capability.
- `unknown`: no sufficiently current, authorized evidence establishes one of the
  other outcomes. Explain the safe reason and next owner-projected action where
  permitted; never display unknown as secure or satisfy required encryption with it.

Keep a stale last-known result separately labelled rather than rewriting history.
The effective current posture becomes unknown when its required evidence expires
or loses its binding. Revoked viewing permission removes the protected observation
altogether; “unknown” must not expose a target's existence to an unauthorized user.
No UI timer renews evidence or changes the underlying authoritative state.

Object-envelope conversion needs separate source/target encoding and placement
generations and progress. “Requested enabled,” “copying” and “verified target” do
not mean the active data set has completed cutover. The active generation's proof
and permitted coverage determine its observation; retained historical generations
remain explicitly reported, not hidden behind one installation-wide label.

At-rest protection and access availability are independent. A locked runtime key
slot is not evidence that stored ciphertext became plaintext. Likewise KMS outage
grace, key revocation and final durable-commit admission are E4 decisions, not
posture calculations. Provider SSE-KMS cannot inherit Setjoin's in-memory grace.

## Required observation envelope, to bind in owning schemas

The catalog names required concepts, not current API field names:

1. Observation identity and owning verifier/profile revision.
2. Authorized installation/security scope, target/provider identity and relevant
   configuration, placement and encoding generation bindings.
3. One layer and explicit named data-class/representation coverage; unknown and
   omitted coverage stay visible to authorized administrators.
4. Observed outcome, observation time and source evidence references; validity,
   expiry and invalidation predicates come from the owning profile.
5. Requested policy and independent owner-projected action/admission result.
6. Safe reason, diagnostic correlation and next owning remedy; no keys, tokens,
   plaintext content, recovery card or unrestricted provider credentials.

The extension capability registry remains the sole capability-ID/domain-major/
schema-digest registry. This vocabulary must be mapped to its admitted contracts,
not used to register another plugin permission system. E8 must provide exact
generated OpenAPI/CLI/UI bindings and unknown-version handling before activation.

## Finite future assertions

The JSON examples are synthetic projection fixtures, not installation evidence.
For each, bind identical API/CLI/UI meaning and policy result to the owning schema:

- A missing disk probe produces unknown, even when the installer requested encryption.
- Verified disk encryption with unimplemented object envelopes does not claim live
  object encryption; maturity and current object observation remain separate.
- Verified SSE for one bucket does not attest other buckets, object envelopes,
  backup independence or regulatory compliance.
- First-wave class qualification leaves unadmitted Meet/App data explicit; no
  installation-wide envelope claim is emitted.
- Configuration/generation change invalidates dependent evidence; retained old
  observations keep their historical identity but cannot satisfy current policy.
- Explicit view denial removes protected fields and links; mutation-only denial
  preserves permitted read facts without preserving action permission.
- A locked key slot can coexist with verified at-rest ciphertext and denied content
  access. Grace expiry changes owner admission, not ciphertext into plaintext.
- An unencrypted-install acknowledgment is retained as a decision, not evidence of
  encryption or a way to suppress the continuing posture warning.

E0 remains partial until all byte classes/consumers and vocabulary mappings are
bound. E1/E2 still need concrete probe/qualification schemas; E3/E4/E5 need joint
review; these examples do not select a crypto format or operational grace clock.
