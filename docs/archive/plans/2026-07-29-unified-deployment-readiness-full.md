# Unified deployment-readiness verification

**Status:** IN PROGRESS
**Date:** 2026-07-29
**Branch:** `codex/unified-deployment-readiness`
**Authority:** root `AGENTS.md`, `TODOS.md`, the Guest Accounts spec, the Identity upgrade/rollback guide, the Federation live-gate evidence, and the Native-RLS flip runbook.

## Outcome

Close the server-side deployment gates for Guest Accounts, Identity Model
Modernization, Federation, Native RLS, and disaster recovery in one reusable,
evidence-producing A/B/C test matrix on the authorized `linux-ci-host` host.

The matrix must use disposable data and environment-local private certificate
authorities. No production key, certificate, credential, customer data, DNS
zone, or production feature toggle enters the test.

## Confirmed premises

1. The implemented features are already covered by local unit, integration,
   pgTAP, protocol, and browser tests; this program proves their deployment
   composition and rollback behavior rather than rebuilding those suites.
2. One physical Ubuntu host can prove three isolated runtime environments,
   separate databases/roles, mTLS trust, private-name discovery, backup/restore,
   crash/restart, and feature-toggle rollback.
3. One physical host cannot honestly prove a real two-machine network boundary,
   public/enterprise DNS administration, legal residency approval, physical
   device behavior, or third-party credentials. Those remain named external
   gates.
4. Guest and identity toggles may be enabled only inside disposable test
   environments and must be restored to OFF before the run is considered
   complete.
5. `feature.federation` may be enabled only inside the disposable A/B/C
   environments. Each environment creates and retains its own CA private key;
   peers exchange public CA certificates only.

The user confirmed the combined scope and the A/B/C approach in the current
conversation.

## Current gaps this plan closes

- Native RLS is implemented and fresh installs use the three-role DSN shape.
  D0 corrected `mailctl backup-db` and full `restore`, which previously resolved
  `DB_DSN` before the owner connection and therefore selected constrained
  `setjoin_app` on a fresh install.
- Guest Accounts G0-G6 are complete but the Guest-specific target-deployment
  journey has not been run with the feature enabled.
- Identity I0-I7 and isolated Ubuntu rollback are complete, but the final
  source/cohort canary sequence remains an explicit deployment exercise.
- Federation has a strong three-org production-service harness, but not three
  production-shaped full stacks with installer-generated certificate material.
- Existing Ubuntu backup evidence records restored counts but not which DSN
  resolver branch selected the database credential.

## What already exists and will be reused

- `scripts/ga-fresh-install-smoke.sh` for systemd-in-container fresh-install
  rehearsal.
- `mailserver/deploy/scripts/install.sh` for three-role DSNs and per-org
  federation CA/leaf generation.
- `testharness/cmd/fedservice` and the C2 three-org evidence for transport,
  deduplication, hub/spoke, crash, backpressure, revocation, and compliance
  assertions.
- `scripts/load-test-schema.sh`, `scripts/verify-all.sh`, and the retained
  result-bound evidence contracts.
- `docs/guides/NATIVE_RLS_FLIP_RUNBOOK.md` and
  `docs/guides/IDENTITY_UPGRADE_AND_ROLLBACK.md`.
- Existing Guest E2E helpers, admin endpoints, identity CLI verbs, federation
  reducers, and authenticated browser fixtures.

## NOT in scope

- Production enablement or production certificate/key handling.
- Legal approval for federation retention/residency.
- A claim that one Ubuntu machine proves a two-machine firewall, routing, or
  failure-domain boundary.
- Public DNS changes. The run uses isolated authoritative/private DNS or a
  resolver seam scoped to the test networks.
- Apple signing, biometric hardware, native mobile devices, EWS/M365 tenants,
  or external link-protection services.
- New product functionality unrelated to closing these deployment gates.

## Topology

```text
                         authorized linux-ci-host host
  +-----------------------------------------------------------------------+
  |                                                                       |
  |  Environment A              Environment B              Environment C   |
  |  source + hub               restore target + spoke     rollback spoke  |
  |  org-a.test                 org-b.test                 org-c.test      |
  |                                                                       |
  |  app / worker / owner       app / worker / owner       app/worker/own |
  |  isolated Postgres          isolated Postgres          isolated PG    |
  |  isolated object store      isolated object store      isolated S3    |
  |  private CA A + leaf A      private CA B + leaf B      CA C + leaf C  |
  |       | public CA B,C            | public CA A              | CA A     |
  |       +------ mTLS/SRV ----------+--------------------------+          |
  |                                                                       |
  +-----------------------------------------------------------------------+
```

No container receives another environment's CA private key. Test resources use
a unique prefix and never stop, delete, or reconfigure pre-existing services.

## Data and control flow

```text
fixture data
    |
    v
A owner connection --pg_dump--> isolated backup bucket
    |                                |
    | app-role denial proof          v
    +--------------------------> B owner pg_restore
                                      |
                                      v
                              count/hash/ownership proof

A/B/C private CA generation
    |
    +--> export public CA only --> peer allow-list
                                      |
                                      v
                              SRV resolve -> mTLS -> authorize
                                      |
                     +----------------+----------------+
                     v                                 v
                Guest/Identity                     Federation
                toggle journeys                DM/room/failure legs
```

## Toggle state machine

```text
SEEDED_OFF
    |
    | disposable-environment preflight passes
    v
TEST_ENABLED
    |
    +--> journey/canary succeeds --> evidence captured
    |
    +--> failure/divergence ------> immediate rollback
    |
    v
RESTORED_OFF
    |
    v
final database assertion + restart proof
```

The run fails if a relevant toggle is ON at final inspection, even if every
functional assertion passed.

## Workstreams and tasks

### D0 - Fix the operator DSN seam

- [x] Change the shared backup/full-restore resolver to:
  explicit `--dsn` -> `DB_DIRECT_OWNER_DSN` -> `DB_OWNER_DSN` ->
  `DB_DIRECT_DSN` -> `DB_DSN`.
- [x] Rename the resolver so the owner/operator contract is obvious to both
  backup and restore callers.
- [x] Add table-driven precedence, empty-source, explicit-override, and
  Native-RLS regression tests.
- [x] Update CLI help, `mailctl/AGENTS.md`, the Native-RLS runbook, and the hot
  TODO to describe the exact operational contract.
- [x] Verify `go test ./...` in `mailctl`.

### D1 - Build a reusable A/B/C environment harness

- [x] Inventory and reuse the existing systemd-container and federation
  harness primitives.
- [x] Allocate unique networks, ports, volumes, Postgres clusters/databases,
  object-store buckets, hostnames, and evidence directories.
- [x] Parameterize the fixed resource names in
  `scripts/ga-fresh-install-smoke.sh` (or add a thin prefix-aware controller)
  so three systemd-capable containers can coexist without touching the original
  single-smoke defaults.
- [x] Add preflight checks for Docker, disk, ports, existing resource-name
  collisions, binaries, and required kernel/systemd behavior.
- [x] Put the three systemd containers on a dedicated shared federation
  network, give them stable test-only addresses, and run an isolated
  authoritative DNS service that answers real A and
  `_setjoin-im._tcp.<domain>` SRV queries through each container's default
  resolver. Do not use the injected Go resolver seam for the full-stack leg.
- [ ] Generate each org's CA and leaf locally. Assert private-key file modes,
  SAN/hostname match, expiry, public-anchor exchange, wrong-anchor refusal, and
  no private-key copies across environment boundaries.
- [ ] Generate CA material inside a mode-0700 directory owned by the
  environment. The anchor export accepts only certificate PEM blocks, rejects
  every private-key PEM label before copy, hashes the exported public
  certificate, and never mounts the source key directory into a peer. Add a
  negative signature-mismatch case proving a peer cannot impersonate another
  org with only its public CA certificate.
- [x] Treat nested Podman/Egress as a separate production-shape assertion:
  prove each environment's Egress container is owned by its own nested runtime,
  and state that all three still share the physical host kernel.
- [x] Make setup idempotent and cleanup prefix-scoped. Preserve failed
  environments when `KEEP_ON_FAIL=1`.

### D2 - Prove Native RLS plus disaster recovery

- [x] Install/provision A/B/C with separate app, worker, and owner credentials.
- [x] Assert role attributes, ownership, FORCE RLS coverage, gateway startup
  self-checks, and app-role cross-mailbox denial.
- [x] Seed A with two-mailbox data spanning messages, tags, Guest, identity,
  federation, audit, and attachment metadata.
- [x] Run `mailctl backup-db` without `--dsn`; capture a sanitized credential
  identity proof showing the owner resolver branch was selected.
- [x] Prove the same dump command fails or is incomplete under an explicit app
  DSN without treating that expected denial as a product failure.
- [x] Full-restore A into empty B without `--dsn`; compare schema version,
  counts, stable IDs, selected content hashes, ownership, grants, and toggles.
- [x] Create/verify current and next monthly partitions as owner.
- [x] Rehearse rollback to the permissive DSN shape, restart, then return to the
  three-role shape and restart again.

### D3 - Run the Guest Accounts deployment journey

- [x] Assert Guest OFF behavior first.
- [x] Enable `feature.guest_accounts` in A only, with member-initiated approval
  remaining fail-closed unless explicitly exercised.
- [x] Run admin invite, exact terminal invite lifecycle, first login, mandatory
  TOTP enrollment, constrained Mail/Chat/Drive/Meet route access, sponsor/status
  changes, session/media revocation, expiry reconciliation, recovery/re-invite,
  and stale-token eviction.
- [x] Route invite mail to an isolated SMTP sink through test DNS/MX, extract
  the real raw acceptance URL from the delivered MIME message, and use that
  browser link. Never synthesize a token or rewrite the stored digest in this
  deployment lane.
- [x] Include wrong invite, superseded invite, double accept, expired invite,
  SSO-linked recovery refusal, and cross-account access attempts.
- [x] Produce deployment evidence for accepted, superseded, revoked, expired,
  and legacy-unknown terminal reasons. Legacy-unknown comes only from an
  authorized pre-V148/fixture restore path; never manufacture it through a
  current production endpoint.
- [x] Verify browser-visible outcomes and retain screenshots/result JSON for the
  critical invite/login/revocation path.
- [x] Pin browser assertions for the acceptance disclosure, External identity
  badge, constrained app rail, route-denial recovery UI, and visible
  session-terminated state after revocation.
- [x] Disable Guest, restart, and prove existing members remain unaffected.

### D4 - Run the Identity Model canary and rollback journey

- [x] Execute preflight, backfill, shadow comparison, and source inventory.
- [x] Exercise at least one real network directory connector available in the
  isolated stack; use an existing test connector only where no production
  connector can run without external credentials, and label that boundary.
- [x] Run seven consecutive completed source syncs spanning at least 24 hours,
  exactly as the runbook requires. A fast clock/fixture test may verify reducer
  branches but does not satisfy this operational precondition. Launch the
  bounded 24-hour observation as a resumable remote timer/job with durable
  per-sync evidence. `ldap:d4-corp` passed with 117+ completed batches spanning
  28+ real hours and no nonterminal batch.
- [x] Use one Setjoin test environment as an OIDC OP for another environment's
  RP/authentication link, reusing the built-in OP instead of adding an
  unrelated IdP image. Use isolated LDAP only where a lifecycle-authority
  connector is required. A→C passed the full code/TOTP/callback/session path;
  its separate V175 authentication observation window remains in progress.
- [ ] Enable model v2, normalized reads for a bounded source/cohort, and
  transitions in the documented order.
- [ ] Prove attach, detach-to-local, reconnect-to-another IdP/source,
  concurrency/generation refusal, protected-account approval, crash/retry,
  session/SFU revocation, and stable person/mailbox/content ownership.
- [ ] Inject a critical shadow divergence, prove automatic canary pause, execute
  global rollback with immutable reason/count evidence, and verify legacy reads.
- [ ] Restore all three identity toggles OFF and restart.

### D5 - Run Federation across all three full stacks

- [x] Enable Federation only in A/B/C and configure hub/spoke allow-lists with
  exchanged public CA anchors.
- [x] Prove private-name SRV discovery, correct mTLS, wrong-anchor rejection,
  non-allow-listed B<->C refusal, and certificate rotation/reconnect.
- [ ] Run DM and room message exchange, concurrent same-numeric-ID dedup,
  delivery receipt, attribution, quarantine, and eDiscovery export.
- [ ] Run hub kill/restart queue convergence, backpressure park/recover, scope
  downgrade/re-invite, kick with straggler poison, and bilateral peer
  delete/re-add.
- [ ] Restart all three stacks in dependency order and prove no sequence gaps or
  cross-org leakage.
- [ ] Disable Federation and assert no listener/peer stream remains.

### D6 - Cross-feature composition

- [x] Invite an external Guest into an allowed collaboration surface while
  Federation and identity canary are active; prove Guest stays outside person
  lifecycle authority and cannot acquire a mailbox through sync or transition.
- [ ] Back up A in the combined enabled state, restore to B, and prove feature
  state/data integrity without automatically starting external side effects.
- [ ] On the stopped restore target, prove the restored database contains the
  expected enabled-state rows while no Guest session, identity sync, Federation
  stream, or media side effect exists. Start services only through the named
  restore verification step, then prove their documented reconcile behavior.
- [ ] Restart database, object store, auth, gateway, workers, SFU/LiveKit, and
  Egress in dependency order; verify health and resumable work.
- [ ] Keep Guest, Identity canary, and Federation enabled together during the
  24-hour identity observation and run bounded synthetic member/guest/federated
  traffic. This is the composition soak, not three isolated green checks.
- [ ] During the soak inject bounded database refusal, object-store 5xx,
  authserver outage, DNS failure, Valkey restart, and Egress kill/restart.
  Simulate clock-boundary inputs through test data/controls only; never change
  the Ubuntu host clock.
- [ ] Run authenticated browser smoke for member, guest, identity operator, and
  federation admin surfaces with console/network error assertions.

### D7 - Evidence, cleanup, and documentation

- [ ] Store sanitized commands, versions, topology, assertions, and failure
  diagnostics under a dated `docs/verification/` record.
- [ ] Retain machine-readable test results and critical screenshots in ignored
  result directories; document their paths without committing secrets.
- [ ] Assert final toggles OFF, no test policy remains, no private key left
  outside its environment, and all pre-existing Ubuntu services are unchanged.
- [ ] Snapshot every changed toggle/config/trust/allow-list row before the run
  and compare the terminal state to that snapshot. Hard-coded “known OFF”
  checks remain as defense in depth but do not replace exact restoration.
- [ ] Include a mandatory `Single-host limitations` checklist covering the
  unproved physical failure domain, adversarial independent administration,
  network-level database isolation, public/enterprise DNS administration,
  legal approval, non-Ubuntu portability, physical devices, and external
  third-party credentials.
- [ ] Update the closest DOX files, runbooks, `TODOS.md`, and active-program
  pointers based on evidence actually obtained.
- [ ] Archive this plan only after every in-scope acceptance criterion passes.

## Error and rescue registry

| Operation | Named failure | Detection | Rescue | Evidence |
|---|---|---|---|---|
| Environment create | name/port/volume collision | preflight refusal | choose unique run ID; never reuse foreign resource | collision test |
| CA/leaf generation | SAN mismatch, weak/expired cert, bad mode | OpenSSL inspection + file-mode assertion | regenerate inside owning environment | positive + negative TLS |
| Peer trust | wrong/missing anchor | mTLS handshake and audit log | install public CA only; retry | wrong-anchor refusal |
| Backup | app role selected or `pg_dump` failure | resolver identity proof + exit status | owner-first resolver or explicit owner DSN | D0 unit + D2 live |
| Upload/download | S3 unavailable/partial object | command failure + object size/hash | retry idempotently; do not restore partial object | outage injection |
| Restore | wrong role, setup guard, partial blobs, DDL failure | non-zero exit + target invariants | discard disposable B and retry from empty | live full restore |
| RLS flip | role drift/ownership violation | boot-time refusal + SQL assertions | reprovision roles; do not bypass check | negative boot |
| Guest journey | stale/superseded/expired token | exact terminal reason + user-visible refusal | issue new invite through reducer | browser/API evidence |
| Identity canary | divergence, stale generation, worker crash | source state/metrics/audit | pause source, exact retry, or global rollback | injected failure |
| Federation stream | DNS failure, TLS failure, gap, poison, backpressure | structured logs/health/audit | reconnect, park, scoped re-invite, or peer delete | chaos legs |
| Toggle cleanup | feature remains ON | final SQL assertion fails run | disable, drain, restart, reassert | terminal gate |
| Rollback action | rollback command deadlocks, crashes, or cannot evict | non-zero exit/timeout | enter MANUAL mode, preserve all prefixed environments and diagnostics, never restart-and-hope | injected rollback failure |

## Failure modes registry

| Codepath | Failure mode | Rescued? | Test? | User/operator sees | Logged? |
|---|---|---:|---:|---|---:|
| DSN resolution | app credential silently wins | planned | planned | explicit resolver proof/failure | yes |
| Backup/restore | dump is structurally incomplete | planned | planned | run fails invariant comparison | yes |
| CA exchange | private key copied to peer | planned | planned | hard policy assertion | yes |
| DNS discovery | wrong target/port | existing reconnect + planned preflight | planned | peer unhealthy | yes |
| Guest accept | replay or terminal-token ambiguity | existing | existing + live | exact refusal | yes |
| Identity canary | critical divergence | existing | existing + live injection | canary paused | yes |
| Federation apply | duplicate/gap/poison | existing | existing + live | health/audit/quarantine | yes |
| Combined restart | accepted work stranded | existing drains + planned live | planned | health/result failure | yes |
| Cleanup | test toggle or policy persists | planned | planned | run marked failed | yes |

No row may finish with no rescue, no test, and a silent outcome.

## Test coverage map

```text
CODE/OPERATOR PATHS                                  LIVE USER/ORG PATHS
[GAP -> D0] owner-first backup/restore resolver      [GAP -> D3] Guest full rollout
  + explicit --dsn                                      + invite/accept/TOTP
  + each env fallback                                   + constrained routes
  + missing DSN                                         + revoke/recover/replay

[PARTIAL -> D2] three-role runtime                   [PARTIAL -> D4] Identity canary
  + role/owner/partition assertions                     + source sync/shadow
  + cross-mailbox denial                                + cohort reads/transitions
  + dump/restore/rollback                               + divergence/rollback

[PARTIAL -> D5] three-org federation                [GAP -> D6] composition
  + transport/dedup/chaos already proven                + Guest x Identity boundary
  + full-stack install/cert/DNS missing                  + backup while enabled
  + toggle-off terminal proof missing                    + browser/restart proof
```

Unit and pgTAP lanes prove local branches. Integration lanes prove real process,
database, storage, and TLS boundaries. Browser E2E is reserved for user-visible
Guest/operator journeys. Chaos cases are bounded and run only against prefixed
disposable resources.

## Deployment sequence

```text
preflight
  -> create A/B/C isolation
  -> install with toggles OFF
  -> RLS/DR baseline
  -> enable Guest/Identity/Federation in disposable scope
  -> feature journeys + fault injection
  -> combined backup/restore/restart
  -> disable all toggles
  -> terminal assertions
  -> evidence + cleanup/retain-on-failure
```

## Rollback flow

```text
failure detected
    |
    +-- data/role/restore problem --> stop target -> discard B/C -> fix -> retry
    |
    +-- Guest problem ------------> feature.guest_accounts OFF -> revoke/drain
    |
    +-- Identity divergence ------> pause source/canary -> global rollback
    |
    +-- Federation problem --------> disable peer/toggle -> stream eviction
    |
    v
rollback succeeded? --yes--> restart -> invariant probes -> preserve diagnostics -> classify result
        |
        no
        v
MANUAL MODE -> preserve A/B/C regardless of KEEP_ON_FAIL -> exact failed step/error
            -> exit non-zero -> operator recovery only
```

## Acceptance criteria

1. D0 tests prove owner-first resolution and the live no-`--dsn` backup and
   restore select an owner-capable credential.
2. A/B/C are isolated and exchange public trust anchors without sharing private
   keys.
3. Native RLS denial, backup/restore integrity, Guest journey, identity canary
   rollback, and federation three-org chaos legs all pass.
4. Cross-feature composition proves Guests never enter member person lifecycle
   or acquire mailboxes through identity synchronization.
5. Final SQL and process probes prove Guest, Identity, and Federation toggles
   are OFF, every temporary policy/trust/allow-list row is removed or restored
   to its exact snapshot, and pre-existing Ubuntu services were not changed.
6. Every unsupported external boundary is stated as not proven; no test evidence
   is inflated into a production claim.

## Parallelization

| Lane | Work | Depends on |
|---|---|---|
| A | D0 operator DSN fix and local tests | none |
| B | D1 harness inventory and environment preflight | none |
| C | Guest/Identity/Federation journey command inventory | none |
| D | D2 -> D3 -> D4 -> D5 -> D6, strictly serial under one controller | A + B + C |
| E | D7 evidence and DOX | D |

Implementation remains in one worktree because D0 and the harness share
documentation and the live phase is stateful. Analysis can proceed in parallel,
but the controller executes D2, D3, D4, D5, and D6 in that exact order, aborts
on the first failed phase, and never restores/restarts an environment while a
later phase is active.

## Taste decisions

- Use three isolated Docker/systemd environments on the already-authorized
  Ubuntu host now, while retaining the real two-physical-host Federation smoke
  as an external gate. This maximizes immediate evidence without pretending the
  host boundary was tested.
- Keep failed environments with `KEEP_ON_FAIL=1` for diagnosis; successful runs
  clean only resources bearing their unique prefix.

## Implementation tasks

- [x] **T1 (P1)** Fix and unit-test the mailctl operator DSN resolver.
- [x] **T2 (P1)** Implement the prefix-scoped A/B/C environment controller.
- [x] **T3 (P1)** Execute Native-RLS and full disaster-recovery proof.
- [ ] **T4 (P1)** Execute Guest, Identity, and Federation live journeys.
- [ ] **T5 (P1)** Execute combined backup/restart/browser proof and terminal OFF assertions.
- [ ] **T6 (P2)** Publish sanitized evidence and update/close exact hot-queue gates.

## /autoplan review

### CEO review — selective expansion

The premise is sound: one matrix prevents five feature-specific rehearsals from
each proving only their own happy path while missing composition, credential,
certificate, restart, and cleanup failures. The accepted expansion is the
cross-feature D6 lane plus exact terminal-state snapshot comparison. A larger
multi-host lab was considered but deferred because only one Ubuntu host is
authorized; the plan must not convert a missing authorization into a false
claim.

The 12-month ideal is a reusable release-readiness runner that can target three
real hosts. This plan reaches the same application/process/database contracts on
one host and deliberately leaves physical failure-domain, real enterprise DNS,
and legal approval outside the claim.

Review findings folded into the plan:

1. **P1, 10/10 confidence:** the identity canary cannot compress its seven-sync,
   24-hour observation requirement. The plan now launches a resumable 24-hour
   job and distinguishes fixture time tests from operational evidence.
2. **P1, 9/10 confidence:** a full Guest acceptance journey needs the actual
   emailed raw token. The plan now uses an SMTP sink plus test DNS/MX and parses
   the delivered MIME instead of mutating the invite digest.
3. **P1, 9/10 confidence:** full-stack Federation must use the process default
   resolver. The plan now requires an authoritative private DNS service rather
   than the injected Go resolver used by `fedservice`.
4. **P2, 9/10 confidence:** three successful feature-specific cleanups can still
   leave a policy or trust row behind. The plan now snapshots and compares every
   changed toggle/config/trust/allow-list row.
5. **P2, 8/10 confidence:** nested Podman validates Egress packaging and service
   ownership, not a separate kernel/failure domain. The evidence must say so.
6. **P1, 9/10 confidence (Claude):** rollback can fail. The controller now
   enters a preserved MANUAL state and exits non-zero instead of restarting and
   hoping.
7. **P1, 9/10 confidence (Claude):** a post-run key scan cannot prevent an
   ephemeral private-key leak. Anchor export now accepts certificate PEM only,
   rejects key blocks before copy, and proves signature mismatch.
8. **P2, 8/10 confidence (Claude):** D2-D6 ordering was implicit. It is now
   strictly serial under a fail-fast controller.
9. **P2, 8/10 confidence (Claude):** isolated feature passes could miss
   composition defects. The 24-hour window now doubles as a bounded
   multi-feature soak with named dependency failures.

No finding challenges the user's confirmed choice to combine the tests.

### Engineering review — full review

Architecture keeps authority in existing reducers and uses existing production
services. The new code is test orchestration plus the narrow operator-DSN fix;
it does not add a parallel identity, Guest, Federation, or backup authority.
The shared-network/full-stack leg and the existing `fedservice` chaos leg are
both retained because they prove different boundaries.

The critical dependency order is:

```text
owner-DSN fix + unit proof
        |
        v
prefix-safe systemd containers -> real DNS/SMTP/private CA
        |
        v
RLS/DR baseline -> Guest -> 24h Identity canary -> Federation
        |
        v
combined restore/restart/browser -> exact terminal snapshot
```

Code-quality decision: parameterize/reuse
`scripts/ga-fresh-install-smoke.sh` primitives instead of copying its embedded
installer path. Harness helpers must take an explicit run prefix and environment
name; no global `docker rm`, broad volume prune, or unscoped service operation
is acceptable.

Performance/resource review: A/B/C may launch in parallel only after a disk,
memory, port, and image preflight. State-changing and fault-injection legs run
serially to keep evidence attributable. The existing host capacity is adequate,
but the controller must record peak container memory/disk and fail before
starving pre-existing services.

Test review:

```text
PATH                                               COVERAGE
operator DSN explicit + 4 fallbacks + empty        unit, all branches
app/worker/owner role boundaries                   SQL integration + boot negative
backup object + full restore                       live integration + hashes/counts
Guest token through MIME to browser                browser E2E + API/audit checks
Identity shadow/canary/rollback                     pgTAP + 24h live observation
Federation default DNS + mTLS                       full-stack integration
Federation dedup/crash/backpressure/revocation      existing production-service chaos
combined enabled-state backup/restart               live integration + browser smoke
terminal toggle/policy/trust restoration            exact database snapshot diff
```

There are no accepted silent failure modes. A run is failed if evidence is
missing, ambiguous, skipped, retried without a later exact pass, or the terminal
snapshot differs.

### DX review — operator platform/CLI, polish mode

**Persona:** an on-prem platform engineer operating Setjoin for a 300-10,000
user organization. They tolerate a long test run but not hidden prerequisites,
interactive secrets, ambiguous partial success, or cleanup that requires manual
forensics.

**Developer perspective:** I want one prefixed command that tells me what it
will create, refuses collisions, shows which phase is running, preserves the
failed environment, and leaves a dated evidence index. I should never need to
read shell source to learn whether a feature toggle, CA anchor, database role,
or backup was restored.

**Magical moment:** after the 24-hour canary settles, one terminal summary links
every Guest, Identity, Federation, RLS, and DR assertion to its machine-readable
evidence and proves the final environment equals its pre-run snapshot.

| Dimension | Before | Reviewed plan | What closes the gap |
|---|---:|---:|---|
| Getting started | 6/10 | 9/10 | one prefixed controller; prerequisite preflight |
| CLI contract | 7/10 | 10/10 | explicit phases, `KEEP_ON_FAIL`, stable exits |
| Errors/debugging | 7/10 | 10/10 | named failure registry and retained diagnostics |
| Documentation | 8/10 | 10/10 | dated evidence record and exact external boundaries |
| Upgrade/rollback | 8/10 | 10/10 | DSN, toggle, source, peer, and binary rollback proofs |
| Environment/tooling | 6/10 | 9/10 | real installer/systemd; one-host kernel caveat remains |
| Ecosystem fit | 9/10 | 10/10 | reuses Docker, systemd, PostgreSQL, SMTP, DNS, OpenSSL |
| Measurement | 7/10 | 10/10 | durations, snapshots, JSON/TAP/Playwright artifacts |

Overall operator DX is **9.75/10**. The only non-plan limitation is elapsed
wall-clock time: the identity canary is intentionally at least 24 hours.

### Scope decisions

| Decision | Classification | Result | Reason |
|---|---|---|---|
| Combine all server-side deployment gates | confirmed premise | accepted | exposes composition failures |
| Three isolated environments on one authorized host | taste | accepted | highest immediate evidence without new host authority |
| Claim real two-host Federation completion | mechanical | rejected | one host cannot prove that boundary |
| Simulate the 24-hour identity gate | mechanical | rejected | would create false production evidence |
| Add a new external IdP product | mechanical | rejected | reuse Setjoin's built-in OIDC OP |
| Retain failed environments | taste | accepted | materially improves diagnosis |

### Review completion

```text
CEO: 9 findings, 0 unresolved, 0 critical gaps after corrections
ENG: 9 execution paths mapped, 0 silent gaps, 5 strictly sequential live phases
DX: 9.75/10, 24h elapsed-time boundary explicit
DESIGN: skipped; no new product UI is planned
LAKE SCORE: 6/6 decisions chose the complete in-scope option
```

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|---|---|---|---:|---|---|
| CEO Review | `/plan-ceo-review` | Scope and deployment honesty | 1 | CLEAR | 9 findings folded, 0 unresolved |
| Claude Review | direct read-only second voice | Independent risk check | 1 | CLEAR_WITH_CORRECTIONS | 7 high/3 medium reviewed; applicable corrections folded |
| Eng Review | `/plan-eng-review` | Architecture, failure modes, tests | 1 | CLEAR | 9 paths mapped, 0 critical gaps |
| Design Review | `/plan-design-review` | UI/UX gaps | 0 | N/A | No UI scope |
| DX Review | `/plan-devex-review` | Operator CLI/runbook quality | 1 | CLEAR | 9.75/10; 24h gate explicit |

**CROSS-MODEL:** Both reviews agreed on owner-first DR credentials, real
24-hour identity evidence, full-stack default DNS, strict key boundaries,
terminal cleanup, and honest one-host limits. Codex rejected only Claude M2:
`TODOS.md` already explicitly permits isolated disposable verification with
all three identity flags restored OFF.

**VERDICT:** CEO + ENG + DX + CLAUDE CLEARED AFTER CORRECTIONS —
implementation may proceed.

NO UNRESOLVED DECISIONS
