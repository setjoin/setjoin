# Transactional continuity U5–U8 verification

Date: 2026-08-02

This record separates deterministic, portable-rewind, simulator, physical-device,
and operator evidence. The client-assisted recovery flags remain OFF. An OPEN
required row blocks U8 and related flag enablement, but not the already-complete
U0–U4 Transactional Updater v1 checkpoint.

| Required gate | Status | Evidence or exact missing proof |
| --- | --- | --- |
| U5 signed continuity primitives and server reducers | CLOSED | Go unit tests plus `mail_recovery_continuity.pg`; cross-scope, replay, newer timeline, and OFF defaults |
| U6 generic bounded encrypted blob bridge | CLOSED | Rust offline-core, Electron/Tauri bridge tests, TS capture/resume tests; no whole-message bridge payload |
| U7 incident, quarantine, and reducer ingestion | CLOSED | 49-case pgTAP authority/RLS/ingest/quota lane, Go MIME/inventory/range tests, strict OpenAPI route coverage |
| Desktop Electron recovery persistence and resume | CLOSED | Native binding, bounded read/write, acknowledged-offset resume, verified-item skip, cancel/abort tests |
| Recovery settings and Admin History UI | CLOSED | Component interactions plus stable English desktop and Chinese mobile Playwright baselines; no horizontal overflow; clock-only warning, bounded incident, quarantine provenance, and explicit acceptance are pinned |
| Portable complete-machine rewind on disposable Ubuntu | CLOSED | `sj-u8-rw-0802a/v182i`: DB, protected config, object data/index, updater journal, release links, continuity timeline, and Egress cache restored coherently; later witness verified, adversarial receipt rejected, one recovered copy accepted idempotently |
| iOS simulator | CLOSED | iPhone 17 / iOS 26.5: real Tauri app persisted a partial encrypted recovery blob, was terminated, resumed at byte 7 after relaunch, verified exact bytes, and rendered the production login UI |
| Android emulator | CLOSED | Android emulator: real Tauri app passed the same forced-stop/relaunch, byte-7 resume, exact read, ref/unref, DB, and visual contract |
| Physical iOS device | OPEN | Required encrypted persistence and resumable upload evidence is unavailable in this workspace |
| Physical Android device | OPEN | Required encrypted persistence and resumable upload evidence is unavailable in this workspace |
| First-use operator timing drill | OPEN | A non-implementing operator must reach first success within 45 minutes and classify injected failures within 20 minutes |
| Exact-prefix cleanup | CLOSED | `transactional-upgrade-rehearsal.sh cleanup` delegates only to the fixed U3/U4 cleanup and unified A/B resource allowlist |
| U8 full-program gate | OPEN | Blocked only by physical iOS/Android and independent-operator timing; portable rewind, simulators, browser, and deterministic evidence are CLOSED |

## Deterministic command

```bash
RUN_PREFIX=sj-continuity-$(date +%Y%m%d) \
  bash scripts/transactional-upgrade-rehearsal.sh deterministic
```

The command writes resumable `.pass` checkpoints below
`test-results/deployment-readiness/$RUN_PREFIX/u5-u8/`. Re-running skips passed
phases; set `FORCE=1` to repeat them. It writes
`physical_device_gate=OPEN` and keeps all continuity flags OFF.

Latest deterministic repeat: `RUN_PREFIX=u5u8-final2-0802 FORCE=1 bash
scripts/verify-all.sh continuity`. All five checkpoints closed: Go, a fresh
V001→V182 schema plus 705-reducer fixed point, 49 continuity pgTAP cases, 17
focused tag-counter/startup-recovery assertions, native
Rust/Tauri/Electron, Web/Svelte, and contract/context guards. OpenAPI coverage
also closed at 625 documented / 713 registered routes, and all 507 documented
path visibility labels matched the real authorization wrappers.

After V182, a fresh full pgTAP run passed **7,052/7,052 assertions across 450
files**. That run also exposed two stale catalog-count expectations left by
V181's `system.recovery` permission; their security assertions now expect the
actual 42-permission/40-Super-Admin catalog and the full lane is green.

The deterministic browser contract is
`e2e/mail-recovery.visual.spec.ts`; its three committed baselines cover the
English desktop plus separate Chinese 375×812 top-of-page and quarantine
views. The
component lane independently pins clock-only refusal, evidence scoping, and
explicit quarantine acceptance.

The final desktop assertion requires the `Access` console label and uses a
0.1% full-page pixel-difference ceiling. The former 1.5% portable default was
proven too broad when the old `System` navigation baseline differed by 1,667
pixels yet passed. The corrected English desktop and Chinese mobile baselines
then passed without snapshot-update mode. The complete Vitest lane also closed
at 407 files / 4,792 tests; `npm run check` reported zero errors and warnings,
and the production Svelte build completed.

## Portable Ubuntu rewind

The reusable action is:

```bash
RUN_PREFIX=<retained-a-b-prefix> REWIND_ATTEMPT=<new-attempt> \
  TEST_SUBNET=<same-subnet> \
  bash scripts/transactional-upgrade-rehearsal.sh rewind
```

`REWIND_ATTEMPT` creates a new evidence/snapshot namespace, so a failed rewind
can be retried without repeating successful provisioning or updater phases. The
`v182i` run restored the normalized durable DB digest
`c4361b08b546642d7b1abefaee0251a3ad597354713d46d2ffd405df6bcec63c`,
threat-feed set `e7cc93006f313128cff175bf14751e9e680c8429f9d01672b85a5ee02e3bfa94`,
and offline object set
`76f2a7ca45ebd7a9254946bd57929d3a59f004294cab547316018a4fd6cf79a6`.
It then verified a later client witness, rejected a tampered receipt, accepted
one recovered copy, replayed acceptance idempotently, and returned all three
continuity flags OFF.

Two product defects surfaced only in the real environment and now have regression
coverage. V182 makes the tag trigger maintain `size_bytes` and makes startup
quota repair count each live message once; this stops a recovery-report feedback
loop on every restart. The ClamAV client now uses newline-framed `nINSTREAM`,
`nPING`, and `nVERSION`, matching the real modern daemon instead of only mocks.
The clean installer also creates the `setjoin` group/user before its first chown.

The rehearsal snapshots nested Podman/Egress storage separately from the machine
rootfs and proves the exact image identity after restore. This is a test-fixture
boundary for a reconstructible sidecar, not a change to production ownership.

## Mobile simulator restart/resume

`bash clients/desktop/scripts/mobile-e2e.sh both` now requires two launches. The
first persists seven bytes and reports `restart-required`; the harness terminates
the app. The second must resume at the acknowledged offset, commit and re-read
the exact blob, then complete the existing database/wipe probe. Evidence is in
the ignored local artifact directories `ios-20260802T140713Z` and
`android-20260802T140955Z`; both screenshots were visually inspected for the real
login UI, pass banner, viewport fit, and clipping. Physical devices remain OPEN
by explicit scope choice.

## Security diff remediation

Codex Security scan `2df21e05-4338-4ad4-ac79-0bff3f428e69` closed all 98
in-scope files and validated three Low/P3 findings. Each was remediated before
this record was closed:

- Recovery eligibility is now a required signed receipt claim. The HTTP path
  and reducer require the request value to match the signed value exactly;
  missing, invalid, overridden, or tampered eligibility fails closed.
- Upload admission now serializes per installation and enforces cumulative
  device, mailbox, incident, and installation byte/session ceilings. Active or
  staged terminal uploads retain their reservation until exact cleanup; clean
  terminal sessions release it immediately.
- One ClamAV client serializes each complete command/write/read exchange,
  closes an expired cached connection before replacement, and invalidates the
  cache after every protocol or transport error.

Targeted evidence includes tamper/override Go tests, the 49-case pgTAP lane,
and `go test -race ./mailserver/internal/smtp`. Permission catalog counts,
`system.recovery` sensitivity/Super-only posture, Access-console placement,
and the JMAP `Continuity: MAIL` method prefix are covered by exact contract
tests. No production flag was enabled by remediation or verification.

## Claude Opus 5 second voice

Claude's earlier read-only review scored the then-current U5–U8 remediation
**9/10 with no release blockers**. Codex accepted every finding and added strict
raw-MIME/digest/expiry bounds, exact mailbox-set validation, canonical digests,
and handler-boundary tests. The historical score is retained rather than
rewritten; its named gaps are closed in the deterministic evidence above.

## Production-shaped A/B lifecycle

```bash
RUN_PREFIX=sj-continuity-$(date +%Y%m%d) \
  bash scripts/transactional-upgrade-rehearsal.sh provision

RUN_PREFIX=sj-continuity-$(date +%Y%m%d) \
  bash scripts/transactional-upgrade-rehearsal.sh updater

RUN_PREFIX=sj-continuity-$(date +%Y%m%d) REWIND_ATTEMPT=attempt-1 \
  bash scripts/transactional-upgrade-rehearsal.sh rewind

RUN_PREFIX=sj-continuity-$(date +%Y%m%d) REWIND_ATTEMPT=attempt-1 \
  bash scripts/transactional-upgrade-rehearsal.sh status

RUN_PREFIX=sj-continuity-$(date +%Y%m%d) \
  bash scripts/transactional-upgrade-rehearsal.sh cleanup
```

Provisioning owns only the exact run prefix. Failure preserves the environment
for diagnosis; `resume-provision` continues from the guarded installation
checkpoint. Cleanup cannot discover or delete unrelated containers or networks.

After every OPEN physical-device/operator row is replaced by reviewable CLOSED
evidence, the terminal one-command gate is:

```bash
RUN_PREFIX=sj-continuity-$(date +%Y%m%d) \
  bash scripts/transactional-upgrade-rehearsal.sh full
```

Today this command deliberately stops at `hardware-gate`; that failure is the
release interlock, not a reason to bypass the row or turn a feature on.
