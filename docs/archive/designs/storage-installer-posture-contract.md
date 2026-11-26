# Storage E1 — installer posture and target binding

Date: 2026-09-08. Proposed specification, documentation-only. No live probe,
installer implementation, disk operation, qualification or numerical score.
Authority: Storage E1.
Shared meanings: [posture vocabulary](storage-posture-vocabulary.md).
Bootstrap/upgrade owner: Managed Dependency §§19.6 and25.7.

## Boundary

Keep the accepted native, local-first installer and administrator-selected data
directory. Observation never formats, partitions, mounts, unlocks, encrypts,
changes ownership, changes permissions or writes a probe object. Required install
mutations remain separately previewed, owned bootstrap steps. A posture probe is
not installation approval, backup verification, redundancy or object encryption.

The installer projects one owner-generated result into SSH TUI and non-interactive
JSON. Do not add a temporary public web installer or a second installation lock.
Before database/bootstrap handoff, use the existing signed bootstrap recipe and
bootstrap identity; do not fabricate an ordinary dependency intent/plan digest.
After handoff, current authenticated operation authority applies. Path selection
and posture evidence must survive that handoff without transferring an old grant.

## Observation record to bind into the owner's schema

These are required concepts, not a newly registered API schema. The existing
bootstrap/dependency schema generator must allocate and validate concrete fields;
unknown versions fail closed for execution and remain safely inspectable.

| Group | Required facts | Refusal / forbidden inference |
| --- | --- | --- |
| Provenance | Bootstrap or ordinary-operation variant, recipe/profile revision, probe implementation digest, observation identity/time, host identity and boot context | A result from another host, boot or profile is not current proof |
| Selected target | Operator-entered absolute path, canonical validated target or nearest existing ancestor plus uncreated suffix, owning mount identity and filesystem, supported backing-device chain | A path string, device display name or free-space number alone is not durable identity; unresolved aliases cannot authorize writes |
| Scope and topology | Paths the observation actually covers, shared OS/data failure-domain fact, local/native profile eligibility, any separate database/temp/config paths not covered | One data-directory result cannot certify every writable path or an independent backup location |
| Host protection | One of enabled/disabled/unsupported/unknown, unlock/accessibility fact separately, qualified chain evidence and safe reason | Merely finding an encryption-capable device, a tool or an algorithm name does not prove this target is protected |
| Capacity | Measured usable bytes/inodes where applicable, measurement scope/time, declared install/recovery headroom model and profile revision, uncertainty and admission outcome | Do not use nominal device size or another mount's free bytes; a capacity pass is not ongoing reservation |
| Permissions/ownership | Existing target status, expected service-account identity, observed access/ownership, separately planned mkdir/chown actions | Observation does not claim a nonempty foreign directory or recursively take over existing customer data |
| Policy and acknowledgement | Required-protection policy, explicit authorized acceptance of a known-unencrypted or unverified target when permitted, bound target/profile/result identity | Acknowledgement cannot bypass required encryption, unknown identity, inaccessible target, unsupported topology or failed capacity gate |
| Safe result | Blockers, warning reasons, available next action, evidence-current flag and owner-projected admission | No secrets, raw key material, unrestricted device inventory or invented success |

Disk, provider SSE and Setjoin envelope observations remain three independent
records. Database fields/search vectors, converter temporary output, runtime key
slots and backup storage need separately named coverage; they are not implicitly
included in an S3 or data-directory badge. See the
source-backed scanning/search distinction.

## Deterministic preflight and commit boundary

1. Parse the selected target without shell evaluation. Resolve identity and the
   supported backing chain using bounded read-only probes. Missing tools, denied
   inspection, partial chain, mixed/ambiguous protection or unsupported evidence
   format produce an explicit reason, never a guessed enabled result.
2. If the final directory does not yet exist, bind the nearest validated existing
   ancestor and exact suffix. The separately previewed creation step must recheck
   that binding and record the resulting target identity before data-service start.
   Reject an intervening symlink/mount/ownership substitution; do not follow it.
3. Derive protection posture only through a qualified detection profile. Report
   disabled only with affirmative scoped evidence; inaccessible encrypted media
   is not disabled merely because it cannot be read. Unknown does not mean that
   the underlying platform lacks encryption capability.
4. Evaluate hard target/topology/capacity gates separately from warnings. Under
   required disk protection, anything except current qualified enabled evidence
   blocks. Under the default optional-protection policy, disabled or unknown
   requires explicit acknowledgement of the actual risk before proceeding;
   unknown must not be relabelled disabled to reuse wording. Unsupported detection
   is shown with its precise profile limitation, not an unsupported disk claim.
5. Bind the selected path, target identity, policy, profile, observed posture and
   permitted risk acknowledgement into the owner's exact preview. Unattended
   execution requires an explicitly supplied, owner-readable policy configuration;
   absence is not consent. Never infer it from an environment default or prior
   successful installation on a different target.
6. Immediately before each target-affecting bootstrap transition, re-inspect
   identity and hard gates under the existing installation lock. A changed target,
   relevant protection/permission policy or stale/invalid evidence invalidates the
   preview. Capacity is re-evaluated, not copied from an earlier success. New hard
   failures block even if the operator acknowledged an unrelated encryption risk.
7. After a permitted install step, observe the effective data-service target and
   persist the exact committed observation/acknowledgement receipt using the
   bootstrap owner's durable journal/handoff. Lost response looks up that owner
   record. No duplicate initialization or overwrite is authorized by retry.
8. On later inspection, expose drift with the current target and independently
   retained historical receipt. Do not silently change storage roots, enable
   encryption or claim historical acknowledgement approves the new target. An
   observed loss of required protection follows the owning admission policy;
   this E1 record does not invent automatic destructive remediation.

A stale observation is still historical evidence, not current execution authority.
Reinspection is mandatory at the named boundaries regardless of wall-clock age.
The detection profile must also freeze bounded command timeouts/output sizes and
maximum evidence age before implementation; no unbounded probe or indefinite
current badge is admitted. Persisted deadlines do not restart merely on retry.

## Capacity and interruption rules

Use one source-derived capacity model shared with Managed Dependency D0/D5, not
another hardcoded minimum in the TUI. It must account for selected artifacts,
staging/rollback coexistence, data-service metadata, temporary conversion/recovery
requirements and emergency operating headroom on each actual filesystem. Show
unknown quantities explicitly and block hard-gate approval until the profile has
qualified bounds. Group by stable filesystem/mount identity, count its available
bytes/inodes once and sum distinct simultaneously live requirements. Deduplicate
only demonstrably identical shared physical allocations, not separate services'
staging, data or rollback budgets. Do not claim that an eligible separate mount is
an independent physical failure domain without evidence.

The profile freezes bytes/inodes, low-space admission and safe-stop behavior per
bootstrap phase with retained resource measurements. No numeric capacity/SLA is
invented in this packet. Concurrent consumption after a check remains possible:
disk-full during a permitted mutation must stop safely, retain diagnosable owned
state and avoid repeated destructive initialization. Existing customer files are
never the installer's emergency cleanup budget.

Before mutation, Ctrl+C exits observation without changing the host. During an
owned install operation, use the existing durable stop/resume semantics and show
its bootstrap identity; closing the TUI alone cannot misreport cancellation.
Read-only recovery/diagnostics remain distinguishable from starting data services.

## TUI, JSON and later admin projection

The storage step shows selected path, resolved mount, local-profile eligibility,
capacity estimate/confidence, independent protection facts, OS/data sharing and
blockers before confirmation. Warnings use text, not color alone. Keyboard back
navigation preserves the entered path but invalidates dependent evidence. Resize
does not erase input. Unattended JSON carries the same reasons and admission.

For an unencrypted target, offer “prepare encryption outside Setjoin and rerun”
or explicit policy-permitted continuation. Do not generate a formatting command
for an unverified device. For unknown posture, show the failed inspection and how
to obtain qualified evidence, not “encryption is off.” Acknowledgement records
the risk; it does not dismiss continuing administrator warnings. Later admin UI
uses the same scoped observation vocabulary, not a second storage-setting owner.

## Proposed acceptance matrix — not executed

| Case | Fixture/change | Required oracle |
| --- | --- | --- |
| E1-01 | Qualified encrypted and unencrypted local targets | Exact independent posture, target identity and policy result; no probe mutations |
| E1-02 | Missing tool, denied probe, malformed/oversized output, timeout, partial chain | Safe reason/unknown evidence; bounded termination; required-protection execution denied |
| E1-03 | Locked media and mixed/ambiguous chain | Accessibility separate from posture; no whole-target enabled result without qualified complete proof |
| E1-04 | Nonexistent suffix; symlink, mount or ownership swap before creation/start | Reinspection rejects stale target; no writes redirected to a replacement directory |
| E1-05 | Optional known-unencrypted/unknown target, interactive/unattended, acknowledgement absent/present/stale | Only current explicit policy-permitted risk acceptance can proceed; required-protection and hard blockers remain unbypassable |
| E1-06 | Data and OS paths share storage; separate mount with unknown physical independence | Accurate sharing/uncertainty, no redundancy or backup-independence claim |
| E1-07 | Multiple services share a filesystem; capacity falls after preview; byte/inode exhaustion during a phase | Count available pool once and sum distinct live allocations; hard-gate recheck or safe checkpoint failure; no unrelated data removal or success receipt |
| E1-08 | Reboot, profile/policy change, expired observation, response loss | Previous receipt retained as historical; changed binding forces revalidation; retry reconciles one bootstrap operation |
| E1-09 | TUI back/resize/interruption and equivalent unattended JSON | Matching scope/reasons/admission; no stale confirmation or false cancellation |
| E1-10 | Data-directory disk protected, other paths/object layer unverified | Projection identifies uncovered paths/layers; no whole-installation secure badge |
| E1-11 | Existing nonempty foreign data target | Refuse implicit adoption/recursive ownership changes; any supported adoption remains separately previewed and authorized |
| E1-12 | Revoked admin view and sanitized support export | Protected inventory omitted as required; no secrets or unrestricted host inventory in logs/exports |

Bind each case to exact source/profile fixtures, executable lane, retained result
and invariant owner in E9. Native Linux probes need a qualified native-host lane;
synthetic Mac parser/TUI cases do not prove Linux mount/encryption behavior.
No disk conversion or destructive test against existing user storage is authorized.

## Remaining freeze inputs

This packet does not complete E1. Installer source mapping must bind existing
configuration, service identity, data-root mutation and durable receipt locations.
The bounded source receipt
distinguishes today's application DATA_DIR, separate S3/SeaweedFS target and
release-adoption evidence. Their existing meanings must not be silently reused
as a common data-root or encryption attestation.
The owning schema/profile must freeze concrete fields, supported probe formats,
timeouts/age/output bounds, capacity model and operator error mappings. Review
these with the installer/Storage owners and applicable Autoplan stages before
implementation. No envelope format, provider SSE qualification or key-custody
policy is selected here; E2–E5 retain those authorities.
