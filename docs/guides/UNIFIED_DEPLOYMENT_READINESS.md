# Unified deployment-readiness rehearsal

This guide runs Setjoin's Guest Accounts, Identity Model, Federation,
Native-RLS, backup/restore, browser, and cross-feature gates against three
disposable production-shaped Ubuntu stacks. It is a release rehearsal, not a
production installer and not authorization to enable gated features in
production.

The completed execution record is
`retired-docs:superpowers/plans/archive/2026-07-29-unified-deployment-readiness.md`;
terminal evidence is
`retired-docs:verification/2026-07-29-unified-deployment-readiness.md`.

## Safety boundary

- Apply [task execution and cleanup](TASK_EXECUTION_AND_CLEANUP.md) first. Local Mac
  checks and Docker are preferred where valid; this systemd/native Linux rehearsal
  retains its dedicated Ubuntu platform requirement and is not a blanket remote default.
- Use a dedicated Ubuntu verification host with at least 12 GiB free memory,
  25 GiB free disk, four CPUs, Docker, and an unused private `/24`.
- Pick a unique lowercase RUN_PREFIX of at most 32 characters. Every
  container, network, evidence path, certificate, and cleanup action is scoped
  to that prefix.
- Never use a production subnet, DNS zone, certificate, credential, database,
  SMTP route, or private key.
- Private Federation and LDAP keys are generated inside their owning
  disposable environment. Only public CA certificates may enter the ignored
  evidence directory.
- The scripts preserve environments on failure for active diagnosis/resume. Record
  that temporary retention and its next checkpoint. On terminal success, failure or
  cancellation, the root runs the ordered cleanup below for all unneeded owned resources,
  including remote resources, retaining sanitized evidence and documented useful caches.

Example values:

```bash
export RUN_PREFIX=sj-ready-$(date -u +%Y%m%d)-1
export TEST_SUBNET=172.30.241.0/24
```

## Before the remote run

Run the local contracts first:

```bash
bash scripts/check-unified-deployment-contracts-selftest.sh
bash scripts/check-unified-deployment-contracts.sh
cd mailserver
go test ./cmd/mailserverd ./internal/federation ./internal/admin ./internal/ad ./internal/ldapsync
cd ../mailctl
go test ./...
```

The structural guard prevents recurrent rehearsal failures from regressing:

- `docker exec ... bash -s` without `-i`, which exits successfully without
  executing the heredoc;
- Federation SRV records drifting from the production port `7443`;
- journal assertions reading old successes instead of a cursor-bounded phase;
- weakening the real Identity requirement below seven completed syncs spanning
  at least 24 hours;
- replacing the authentication-only OIDC window with synthetic observations or
  a compressed timer.

## Provision A/B/C

Copy or clone the exact candidate tree onto the authorized Ubuntu host, then:

```bash
RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
  bash scripts/unified-deployment-readiness.sh preflight
RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
  bash scripts/unified-deployment-readiness.sh provision
```

The owned topology is:

| Resource | Address/purpose |
|---|---|
| `${RUN_PREFIX}-a` | full stack A, subnet `.11` |
| `${RUN_PREFIX}-b` | full stack B, subnet `.12` |
| `${RUN_PREFIX}-c` | full stack C, subnet `.13` |
| `${RUN_PREFIX}-dns` | authoritative private test DNS, subnet `.53` |
| `${RUN_PREFIX}-smtp-sink` | isolated Guest invite sink, subnet `.60` |
| `${RUN_PREFIX}-ldap` | isolated TLS LDAP directory, subnet `.61` |

`resume-provision` repairs missing owned peripherals without deleting healthy
retained A/B/C state:

```bash
RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
  bash scripts/unified-deployment-readiness.sh resume-provision
```

## Execute phases

Run phases serially because later phases intentionally compose earlier state:

```bash
# Native-RLS, database/blob backup, isolated restore and rollback posture.
RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
  bash scripts/unified-deployment-d2.sh prepare

# Guest OFF baseline, real MIME invite URL, terminal-token cases and browser.
RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
  bash scripts/unified-deployment-d3.sh prepare
# Follow the phase's browser-ready/verify/supersede actions as reported.

# Real TLS LDAP source, model-v2 shadow rail and resumable 24-hour observer.
RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
  bash scripts/unified-deployment-d4.sh prepare
RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
  bash scripts/unified-deployment-d4.sh status

# Authentication-only sources have a separate real-login observation rail.
# After D4 has configured A as RP and C as Setjoin OP, store the dedicated
# disposable C administrator login in the ignored private evidence directory,
# then start the resumable four-hour observer.
install -d -m 0700 \
  "test-results/deployment-readiness/$RUN_PREFIX/d4/oidc/private"
install -m 0600 /path/to/test-admin-email \
  "test-results/deployment-readiness/$RUN_PREFIX/d4/oidc/private/admin-email"
install -m 0600 /path/to/test-admin-password \
  "test-results/deployment-readiness/$RUN_PREFIX/d4/oidc/private/admin-password"
RUN_PREFIX="$RUN_PREFIX" \
  bash scripts/unified-deployment-d4-auth-observer.sh observe
RUN_PREFIX="$RUN_PREFIX" \
  bash scripts/unified-deployment-d4-auth-observer.sh status

# Three-stack mTLS, wrong anchor, hub/spoke DM+room, partition/dedup and rotation.
RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
  bash scripts/unified-deployment-d5.sh prepare
RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
  bash scripts/unified-deployment-d5.sh journey
RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
  bash scripts/unified-deployment-d5.sh rotate
RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
  bash scripts/unified-deployment-d5.sh adversarial
RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
  bash scripts/unified-deployment-d5.sh peer-reset
RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
  bash scripts/unified-deployment-d5.sh pressure

# Guest + Identity canary + Federation composition during the 24-hour window.
RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
  bash scripts/unified-deployment-d6.sh prepare
RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
  bash scripts/unified-deployment-d6.sh status
```

Each action is idempotent at its named checkpoint. Resume the failed action;
do not rerun provisioning or erase the evidence directory. D4's observer PID,
sync timestamps, and phase checkpoints are durable below:

```text
test-results/deployment-readiness/${RUN_PREFIX}/
```

### Transactional updater and client-assisted continuity (A/B only)

U5–U8 use the same exact-prefix Ubuntu controller but need only stacks A and B.
The dedicated wrapper preserves the already-proven provisioning, updater,
status, and cleanup behavior and adds resumable continuity checkpoints:

```bash
RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
  bash scripts/transactional-upgrade-rehearsal.sh provision
RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
  bash scripts/transactional-upgrade-rehearsal.sh updater
RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" REWIND_ATTEMPT=attempt-1 \
  bash scripts/transactional-upgrade-rehearsal.sh rewind
RUN_PREFIX="$RUN_PREFIX" FORCE=1 \
  bash scripts/transactional-upgrade-rehearsal.sh deterministic
RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
  bash scripts/transactional-upgrade-rehearsal.sh cleanup
```

Use `resume-provision` only for the guarded installer retry. If rewind fails,
preserve the successful A/B and updater state and retry with a new lowercase
`REWIND_ATTEMPT`; use that same attempt for `status` and `cleanup`. Portable
rewind and both simulator rows are now CLOSED. `full` is the terminal U8 command
after the remaining physical-device and operator rows close; until then it fails
at `hardware-gate` and every client-recovery feature remains OFF. See
[Client-assisted mail recovery](CLIENT_ASSISTED_MAIL_RECOVERY.md).

The portable snapshot covers PostgreSQL, protected config, object index/data,
updater journal, release links, and continuity state at one coherent boundary.
It preserves xattrs, ACLs, and numeric ownership. Nested Podman/Egress storage
is archived separately and its exact image identity is verified after restore;
it is reconstructible sidecar state, not business authority. Ubuntu 24.04 also
needs the split `clamdscan` package and a loopback clamd socket; the rehearsal
configures both rather than relying on a developer host.

`d4 verify-window` must not pass until the database itself proves seven
completed directory batches with no nonterminal batch and at least 24 hours
between the first and last completion. An OIDC/SAML authentication-only source
uses a distinct gate: at least seven matching real authentications spanning
24 hours, exact per-link evidence, and no open divergence. Directory elapsed
time cannot satisfy the authentication gate. Verify the latter with:

```bash
RUN_PREFIX="$RUN_PREFIX" \
  bash scripts/unified-deployment-d4-auth-observer.sh verify-window
```

The observer resets only the dedicated disposable C test administrator between
flows so mandatory first-login TOTP is exercised each time. It never alters
timestamps, inserts comparison evidence directly, or retains credentials in
committed evidence. A fixture clock or compressed timer is not accepted.

## Candidate binary upgrade order

Never replace the gateway binary and restart it against an older schema:

1. sync the exact candidate source or release artifact;
2. build and retain the new `mailctl` and `mailserverd`;
3. apply every pending migration with the owner/operator DSN;
4. verify the recorded schema version;
5. install the candidate binaries;
6. restart one stack;
7. require `/ready` before continuing to the next stack;
8. keep the previous binary until the rolling restart completes.

The gateway intentionally refuses startup on schema drift. That refusal is a
safety control, not permission to bypass the version check.

In a rehearsal container the candidate source may be mounted read-only at
`/mnt/repo-src`. Build web assets from a writable temporary copy, and run the
upgrade helper from the first existing location:
`/opt/setjoin/deploy/scripts/upgrade.sh` for an installed release or
`/mnt/repo-src/mailserver/deploy/scripts/upgrade.sh` for this retained-source
layout. Do not copy a new binary over the running installation before the
schema step merely because the installed helper is absent.

The gateway must also log `gateway stopped cleanly` during a normal restart.
A restart that waits for `TimeoutStopSec` indicates an overseer/listener
teardown regression and blocks the rehearsal.

## Evidence rules

- Use journal cursors captured immediately before a negative/positive phase.
  Do not use a broad `--since "5 minutes ago"` assertion for a state transition.
- Poll database state and cursors; do not replace convergence checks with fixed
  sleeps.
- A wrong-anchor test must first disable the peer and prove the old stream was
  actively evicted. Only then capture a new cursor and enable the wrong anchor.
- A partition test must prove unacknowledged durable outbox state, absence of a
  B-to-C bypass, post-reconnect ACK convergence, exact-once landing, and zero
  inbox sequence gaps.
- Never retain invite tokens, TOTP secrets, bind passwords, private keys, raw
  customer data, or production artifacts in evidence.

## Status and cleanup

Inspect without mutation:

```bash
RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
  bash scripts/unified-deployment-readiness.sh status
RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
  bash scripts/unified-deployment-d4.sh status
RUN_PREFIX="$RUN_PREFIX" \
  bash scripts/unified-deployment-d4-auth-observer.sh status
RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
  bash scripts/unified-deployment-d5.sh status
RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
  bash scripts/unified-deployment-d6.sh status
```

On terminal success, failure or cancellation, run feature-phase cleanup first, confirm toggles and
allow-lists match the pre-run snapshot, then delete only the exact prefix:

```bash
RUN_PREFIX="$RUN_PREFIX" \
  bash scripts/unified-deployment-d4-auth-observer.sh stop
RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
  bash scripts/unified-deployment-d6.sh cleanup
RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
  bash scripts/unified-deployment-d5.sh cleanup
RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
  bash scripts/unified-deployment-d4.sh cleanup
RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
  bash scripts/unified-deployment-d3.sh cleanup
RUN_PREFIX="$RUN_PREFIX" TEST_SUBNET="$TEST_SUBNET" \
  bash scripts/unified-deployment-readiness.sh cleanup
```

Cleanup is intentionally ordered from the most composed phase back to the
controller. The terminal probe must find no exact-prefix container, network,
locally built LDAP/OIDC image, temporary/private evidence file, observer, or
phase process. Do not remove shared caches or base images merely because they
were used by the run.

Before declaring the run complete, verify that all pre-existing host
containers/services are unchanged and record the single-host limitations:
physical failure-domain independence, adversarial independent administration,
public/enterprise DNS, external CA and credentials, non-Ubuntu portability,
legal approval, physical devices, and network-level database isolation remain
outside this rehearsal.

## Fast repeat

A later rehearsal reuses this source tree and command sequence; it does not
reuse certificates, databases, credentials, or retained containers. Choose a
fresh prefix/subnet, run `preflight`, then execute D2 through D6 serially. On a
failed phase, preserve the exact prefixed environment, repair the cause, and
use that phase's `status`/`resume` path instead of reprovisioning successful
earlier state while the run is actively being resumed. On any terminal outcome, use
the terminal cleanup order above and rerun
`preflight` to prove the namespace is reusable.

When transferring a checkout to a disposable host, exclude generated and private
state so an old build cannot turn a small source sync into a multi-gigabyte copy:

```text
.git node_modules target test-results .claude .svelte-kit coverage
/build/ /clients/desktop/src-tauri/gen/ /clients/desktop/electron/release/
/mailserver/webmail/build/ /gateway /authserver/authserverd /asrbot/asrbotd
/mailctl/mailctl
```

The installer now creates the `setjoin` group and user before the first
continuity-key chown. Do not rely on distro-specific private-group behavior;
the clean-install order guard is the regression gate.
