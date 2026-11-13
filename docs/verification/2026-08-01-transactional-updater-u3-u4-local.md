# Transactional updater U3/U4 verification — 2026-08-01

Status: U3/U4 implementation and disposable-Ubuntu/browser runtime gates pass;
production execution remains OFF.

## Proven in deterministic lanes

- V179 fresh-schema load and all transactional-upgrade pgTAP assertions pass.
- The database owns the durable recovery timeline and rejects mismatched evidence.
- HMACed application recovery manifests are written last and bind an exported
  PostgreSQL snapshot, every blob/config digest, protected-key fingerprint,
  feature-toggle digest, installation UUID, and database timeline.
- `mailctl backup create|verify --pre-upgrade` uses fixed credential files,
  canonical UUIDs, stable JSON, and exit 2 for ineligible evidence.
- The Admin API/UI/CLI are reducer-authoritative and release-first. They accept no
  upload, artifact path, URL, command, unit, or generic module input.
- Playwright covers all 20 durable intent states in English desktop and Chinese
  375×812 layouts. Four materially distinct pixel baselines pin recovery-required,
  execution-OFF/rolled-back, and stale/withdrawn Enterprise states. The test blocks
  service workers so requests cannot escape the deterministic mock boundary.
- The final `scripts/test.sh`, `scripts/build.sh`, and `scripts/lint.sh` lanes pass.
  Changed Go product lines are 2091/2323 (90.01%) and critical changed lines are
  328/328 (100%), with no unattributed file.

Committed browser baselines:

- `mailserver/webmail/e2e/transactional-updater.visual.spec.ts-snapshots/`
- Live disposable-host screenshots:
  `.gstack/qa-reports/screenshots/transactional-updater-u4-en-desktop.png` and
  `.gstack/qa-reports/screenshots/transactional-updater-u4-zh-mobile.png`

## Disposable Ubuntu evidence

Run `sju4-20260801-142149` provisioned isolated A/B nodes at
`172.30.244.11/24` and `172.30.244.12/24` plus the test-only object store/DNS.
The reusable entry point was:

```bash
RUN_PREFIX=sju4-20260801-142149 \
PROVISION_ENVS="a b" \
TEST_SUBNET=172.30.244.0/24 \
bash scripts/unified-deployment-readiness.sh provision

RUN_PREFIX=sju4-20260801-142149 \
PROVISION_ENVS="a b" \
TEST_SUBNET=172.30.244.0/24 \
bash scripts/transactional-updater-rehearsal.sh
```

Terminal result:

```text
recovery_set_id=740e89ee-41b1-4862-9128-18f1ebd941bc
isolated_restore=PASS
success_intent=5:verified
rollback_intent=6:rolled_back
terminal_execution_flags=OFF
```

The same recovery-set UUID restored to B and proved schema/ownership, isolated
admin login, representative mail/blob integrity, protected configuration, and
absence of production routes. Intent 5 traversed recovery point → immutable stage
→ maintenance → migration → switch → readiness → commit → verified. Intent 6
switched to a deliberately unhealthy signed fixture, failed the fixed readiness
probe, restored the prior cohort, and terminated `rolled_back`. Independent
post-run checks saw `setjoin-updater` active, both Web endpoints HTTP 200,
`current` at the verified cohort, `previous` at the rolled-back candidate, and
both database and root-owned execution gates OFF.

After evidence capture, the exact `sju4-20260801-142149` A/B, MinIO, DNS, and
network resources were removed. The pre-existing `setjoin-egress` and
`setjoin-seaweedfs` containers remained present; no production resource was
targeted.

Sanitized raw evidence is retained below the ignored local tree
`test-results/deployment-readiness/sju4-20260801-142149/`. The durable summaries
are this record and `docs/guides/RESTORE_REHEARSAL.md`; no credential, DSN, token,
address, MIME, or private data is copied into documentation.

## Completion gates

| Gate | State | Evidence |
|---|---|---|
| Ubuntu same-set isolated restore | CLOSED | Recovery set `740e89ee-41b1-4862-9128-18f1ebd941bc` restored to the newly provisioned B cluster/blob namespace with all required checks passing. |
| Ubuntu updater switch and rollback | CLOSED | Intent 5 ended `verified`; deliberately unhealthy intent 6 ended `rolled_back`; both services remained healthy. |
| Browser dangerous-state matrix | CLOSED | Live English desktop/Chinese mobile review plus deterministic 20-state Playwright coverage and four committed pixel baselines pass. |
| Final independent review | CLOSED | Claude Opus 5 correction-only review found no residual blocker and scored the bounded U3/U4 corrections 10/10; disposition is recorded in `docs/audit/2026-08-01-transactional-updater-u3-u4-final-review.md`. |

## Runtime defects converted to regression coverage

The rehearsal found and fixed nested-systemd credential portability, installer
owner-DSN binding, release-tree traversal modes, guarded resume provisioning,
two-node rehearsal selection, Egress image transfer, recovery flag ordering,
container JSON parsing, backup-worker reconfiguration, root ownership of the
immutable namespace, auth readiness probing, pre-activation break-glass behavior,
IMAP INBOX canonicalization, release-fixture binary parity, probe backoff, and
standards-compliant ESEARCH/Message-ID probes. Unit, renderer, contract, and
rehearsal tests now cover those boundaries.

## Release posture

U0–U4 form the Transactional Updater v1 checkpoint. Shipping the code does not
enable execution: `feature.transactional_upgrades_catalog`,
`feature.transactional_upgrades_execution`, and the root-owned execution file
remain OFF until an operator makes a separate production rollout decision.
U5–U8 client-assisted continuity is not included in this checkpoint.
