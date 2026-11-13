# Architecture R2 rehearsal characterization

Date: 2026-08-03
Status: R3a complete; R3b effectful extraction held by U8 evidence

## Purpose and boundary

This record characterizes repeated mechanics in the disposable three-stack,
transactional-updater, continuity, and complete-machine rewind rehearsals. It
does not authorize a shared production deployment framework and does not move,
source, or replace any effectful code while the current scripts remain the proof
apparatus for physical-device and independent-operator U8 evidence.

R3b is eligible only when these exact rows are `CLOSED` in
`docs/verification/2026-08-02-transactional-continuity-u5-u8.md`:

- Physical iOS device
- Physical Android device
- First-use operator timing drill

`bash scripts/check-upgrade-contracts.sh --rehearsal-extraction-eligible` is the
fail-closed eligibility check. While any row is open or missing it returns
nonzero with `rehearsal_u8_hold_open` and names every blocking row. The normal
upgrade-contract lane treats that result as an expected, visible hold; it does
not pretend the deferred extraction has shipped.

## Current owners

| Owner | Scope | Current authority |
| --- | --- | --- |
| `scripts/unified-deployment-readiness.sh` | Exact A/B/C Ubuntu containers, private DNS, SMTP sink, subnet collision checks, first provisioning, guarded resume, status, exact cleanup | Resource existence, naming, subnet, and base evidence authority |
| `scripts/transactional-updater-rehearsal.sh` | U3/U4 restore proof, signed release fixtures, updater preview/challenge/intent, switch and rollback | Updater execution and terminal-OFF evidence authority |
| `scripts/transactional-upgrade-rehearsal.sh` | U5–U8 orchestration, `.pass` checkpoints, bounded delegation, hardware gate, combined cleanup | Continuity phase/resume orchestration authority |
| `scripts/transactional-continuity-rewind.sh` | Complete-machine snapshot/rewind, Egress/Podman state, later-message receipt, adversarial receipt, idempotent recovered copy | Portable rewind and private evidence authority |

## Duplication and authority matrix

| Mechanic | Unified readiness | Updater | Continuity controller | Rewind | Classification | R3b disposition |
| --- | --- | --- | --- | --- | --- | --- |
| Prefix validation | Lowercase `a-z0-9-`, non-empty, max 32 | Same plus subnet | Same prefix rule | Same plus subnet and `REWIND_ATTEMPT` | Safety authority: constrains every destructive name | Candidate pure structured helper; wrong-prefix refusal mandatory |
| Resource naming | Nine fixed names plus network | `${prefix}-a/-b` and release suffixes | Delegates; no independent resource expansion | Image, volume, builder, A/MinIO/network names | Safety authority: cleanup allowlist and collision boundary | Candidate deterministic encoder; never accept arbitrary resource templates |
| Subnet and port allocation | `/24` syntax, reserved host offsets, Docker collision scan | Inherits existing A/B stack | Pass-through to owners | Validates existing subnet and derives endpoints | Effectful environment authority | Do not centralize scans/allocations in first pilot; characterize inputs only |
| Remote execution/copy | Docker exec/cp into disposable nodes | Docker exec and bounded HTTP/JMAP calls | Delegates to owners | Docker exec/cp, systemd, Podman, tar | Effectful security boundary | No generic SSH/SCP or arbitrary-command abstraction |
| Evidence roots | `test-results/deployment-readiness/$RUN_PREFIX` | `.../updater-u3-u4` | `.../u5-u8` and atomic `.pass` checkpoints | `.../ubuntu-rewind/$REWIND_ATTEMPT` | Release evidence authority | Candidate receipt/path encoder only after exact filename parity |
| Resume markers | Exact provision PASS plus live resource verification | Terminal result and existing stack preconditions | Per-phase `.pass`; `FORCE=1` is explicit replay | Refuses existing private snapshot/resources | Behavioral authority: interruption semantics | First migrated phase must prove interrupted-resume and old/new parity |
| Receipt encoding | Plain bounded environment logs | JSON API and database evidence | Timestamped phase checkpoint | Signed receipt JSON, artifact identity, hashes, adversarial result | Security/evidence authority | Candidate structured encoder; preserve redaction and canonical filenames |
| Cleanup | Exact nine-name allowlist plus network | Delegates to exact unified cleanup | Ordered updater, unified, rewind delegation; updater failure is not masked | Exact builder/image/volume/private-file cleanup | Destructive authority | Keep owners explicit until idempotent and wrong-prefix parity is proven |
| Secrets/redaction | Test-only credentials stay in process/env; evidence is sanitized | Tokens use temp files/stdin and are not canonical evidence | Delegation adds no secret serialization | Private client evidence deleted during cleanup | Security authority | Any pilot must reject secret-bearing fields and prove sanitized output |

## Invariants that cannot be blindly shared

1. Constructors and validation run before any destructive Docker/Podman action.
2. Cleanup targets are a deterministic fixed allowlist derived from one validated
   prefix. No regex-wide or discovery-wide deletion is permitted.
3. A resume marker is not sufficient by itself; the owning script also verifies
   the exact resource/evidence preconditions for that phase.
4. Failed or partial evidence never occupies a canonical success path.
5. Updater cleanup failure remains visible; orchestration must not append
   `|| true` to that delegation.
6. Private receipt, token, and client-recovery artifacts are bounded to the
   attempt directory and deleted by exact cleanup.
7. The rewind's database, protected configuration, object store/index, updater
   journal, release links, continuity timeline, and Egress cache are one
   consistency claim; a generic file copier cannot split that authority.

## R3b migration protocol after the hold closes

The first allowed pilot is a test-only executable or non-sourced helper with
structured input/output for strict prefix validation, deterministic names, and
receipt/path encoding. It may not execute Docker, Podman, SSH, SCP, systemd,
updater, database, or network commands.

Migrate one phase only. Dual-run the old and candidate encoders against valid,
invalid, collision, redaction, interrupted-resume, cleanup, and wrong-prefix
fixtures. Require byte-identical names, evidence filenames, receipts, and resume
decisions. Then run one bounded real Ubuntu replay for that migrated phase before
retiring its old encoding path. A mismatch keeps the old authority and closes
the pilot without widening its scope.

## Deferred extraction verdict

`rehearsal_u8_hold_open` is expected today because physical iOS, physical
Android, and independent-operator timing remain open. No effectful rehearsal
code has been extracted in Architecture R2.
