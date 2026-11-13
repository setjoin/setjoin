# Identity P2/P3 remediation evidence — 2026-07-28

## Scope and outcome

This record closes the two Medium findings from the latest completed Codex
Security scan `734d3580-da44-4135-a971-5de797ff3938` against the current
uncommitted Identity Model Modernization worktree:

- `csf_81035ca66b36ff3f1a400ed3` — revoked access tokens could reopen WebSocket
  and SSE push streams: **fixed**.
- `csf_b1a45ac2febee472e72ce66e` — administrator password reset used stale
  organizational reach: **fixed**.

No known P2/P3 bypass remains in the reviewed administrator-reset and
session-revocation paths. The later sections now also record the completed
Identity Model Modernization implementation-verification gates. This is not
production enablement.

## Original 16-finding scan revalidation

The first sealed Identity diff scan,
`2eb86ab1-b269-47e1-865d-8d4a0c64625f`, reported the 16 findings the operator
asked to retain through later remediation. All remain fixed:

- `csf_99e5a4d4ad4dbb5456b9c33b` and
  `csf_736a270b932a32049f9e78f1`: address evidence cannot create a durable
  authentication link, and the exact source/link generation fence runs before
  SSO profile or entitlement mutation.
- `csf_3bc55db9b17527f510b95eea` and
  `csf_bb008ecd80507dc34f84bc0f`: normalized AD and LDAP reject reusable bind
  credentials over plaintext transport.
- `csf_100e94fe57a0b1c3e5004c96` and
  `csf_7e3d663f7596c08add46add0`: database state and generation are rechecked at
  worker admission; missed notifications are reconciled, so disabled AD/LDAP
  workers cannot continue authority mutations.
- `csf_75a8591fc017aaf880bb3ab4`: manager authority is reconciled from the exact
  immutable-source page, including authoritative removal.
- `csf_da18087c74021c5b347d9e8b`,
  `csf_c25be80e24699bd7fab270d9`, and
  `csf_20db4549b57347e4cffae3e2`: SCIM profile mutations preserve lifecycle and
  department ownership semantics and inventory is isolated to the
  authenticated active provisioning source.
- `csf_8672a30c4922f9b1ed615c8a`: deployment-wide identity jobs require an
  unscoped current administrator; stale domain/OU/scope-set reach is rejected.
- `csf_f46063298f8a6a806f1a6a26`: the collector-down alert also fires when the
  metric series is absent.
- `csf_c5333cdb030c14c366aa4a47`,
  `csf_5f25245f1c05cd387f5fab72`, and
  `csf_b317796dcea31879461e25fe`: transition recovery accepts only live,
  reachable recovery, retries remain bound to the exact failed forward or
  rollback effect, and rollback approval is generation-bound.
- `csf_0f7672dbbed9e94e4d80549e`: login issuance and terminal revocation share the
  person fence, while process-wide IMAP and SMTP registries close established
  sessions.

Subsequent sealed scans deliberately searched for sibling paths rather than
treating this first set as sufficient. Their additional findings drove the
V168-V172 generation, notification, link-session, authority, and runtime
revocation controls. The latest two finding identities are listed above; no
finding was closed solely because its feature flag remains OFF.

## Security closure

- `admin_reset_password` is the authoritative transaction for current persisted
  `users.password_reset` permission, current reach, protected-target and Guest
  policy, password mutation, complete revocation, audit, and notification.
- V172 uses one fixed BIGINT advisory-lock protocol key and statement-level
  authority-fence triggers for assignment/JIT, role, department, scope-set,
  group membership, user placement, primary-mailbox, and Guest host-domain
  mutations. The shared order is authority fence, person fence, principal rows,
  then token/session rows.
- Admin create and CSV import use insert-only provisioning. Existing stable
  identities conflict before any committed account mutation.
- Initial issuance and refresh rotation stamp one exact family on the paired
  access and refresh credentials.
- Process-wide IMAP, SMTP, WebSocket, and SSE registration plus exact
  all/JTI/family matching closes established sessions and rejects reconnects.
  Missing `iat` fails closed.
- Revocation reconciliation serializes and merges concurrent NOTIFY state.
  V172 bounds enforcement retention and adds all/JTI/family/expiry indexes;
  in-memory targeted keys prune at expiry.
- Out-of-scope Guest and member targets retain 404 parity.

## Verification

- Fresh V172 schema load: 660 reducers.
- Focused reset/revocation pgTAP: 47 assertions passed.
- Full pgTAP: 447 mailserver files / 6,866 assertions and 47 authserver
  assertions passed.
- Focused database integration: complete reset revocation, create-only conflict,
  Guest oracle, assignment deletion, JIT deactivation, department reparent, and
  scope-set member removal all passed.
- Webmail: 399 files / 4,727 tests passed; 85.01% total line coverage; changed
  and critical changed lines both 100%.
- Full local Playwright: 124 passed and 59 explicitly environment-gated cases;
  strict CSP passed 1/1. Required named browser evidence rejects missing,
  skipped, failed, ambiguous, malformed, or flaky-after-retry outcomes.
- Full authserver and mailserver Go evidence passed with `REQUIRE_DB=1` and a
  real disposable PostgreSQL database. A clean-schema focused rerun passed the
  auth handlers/token/federation, admin/SCIM/AD/LDAP/source/transition,
  IMAP/SMTP/WebSocket, pgnotify, and threat packages.
- The clean-schema security pgTAP rerun passed 266 source/link/SCIM/reset/
  notification/CAE assertions plus all 59 transition-protocol assertions.
- `go test -race ./threat`, both bounded fuzz targets, runtime middleware
  revocation tests, lint, production build, context budget, and
  `git diff --check` passed.
- `govulncheck` found no reachable vulnerability in authserver, mailserver,
  shared, mailctl, or asrbot.
- The repository security lane exposed newly published transitive desktop-build
  advisories in `brace-expansion`, `postcss`, and `tar`. Exact safe-version
  overrides plus removal of stale lockfile-only packages now make all four npm
  audits report zero vulnerabilities; Electron type checking, 138 tests,
  bundling, and an unsigned directory packaging smoke pass with those
  resolutions.
- Graphify update, hook-check, and focused post-update query passed.

The branch-wide changed-Go coverage ratchet now passes after adding focused
tests for the previously uncovered LDAP configuration/error and enabled-sync
paths. The truthful aggregate is 10,992/12,164 executable changed lines
(90.37%, target 90%) and 5,288/5,564 critical changed lines (95.04%, target
95%). Every module and critical-package floor also passes.

## Ubuntu deployment, restore, rollback, and browser evidence

The authorized Ubuntu verification host ran the current source from
`<home>/setjoin-identity-20260728` under the isolated user service
`setjoin-identity-v172b.service`. It used a loopback PostgreSQL database on port
55432 and did not modify the machine's production services.

- Schema V172 loaded with four identity sources and all three identity flags
  OFF.
- The Ubuntu identity-focused suite passed `admin_reset_password.pg` plus all
  12 `identity_*.pg` files / 472 assertions. Its first run exposed one real
  test-isolation defect: the negative transition test
  inherited the E2E seed's enabled CAE runtime. The test now explicitly turns
  CAE off before proving fail-closed transition admission and turns it on only
  for the later positive path. The focused local test passed 64/64 before the
  complete remote rerun.
- A 3,371,990-byte, mode-0600 custom-format backup passed
  `pg_restore --list` and restored into the disposable
  `mailserver_identity_e2e_restore_20260728` database. Schema version,
  user/source/link/effect counts, and feature flags matched the source.
- `identity_upgrade_rollback` succeeded twice on the restored database.
  Both responses reported preserved schema, zero pending effects, four shadow
  sources, zero cohort members, and all three behavior flags OFF. The two
  commands produced two immutable source-null audit events with their exact
  reasons.
- After restarting the isolated service, HTTP health returned 200; the database
  health snapshot was 23/23 OK and MinIO connectivity supplied the 24th OK
  probe. Schema V172 and all three OFF flags persisted.
- Playwright reached the Ubuntu backend through bounded loopback tunnels.
  Identity and LDAP setup/login/journeys/teardown passed 8/8 with no retry.
  Desktop overview, source detail, and mobile screenshots were inspected and
  are retained under
  `mailserver/webmail/test-results/identity-e2e-ubuntu-evidence/`.

The exhaustive QA record is
`.gstack/qa-reports/2026-07-28-identity-modernization-final.md`.

## Independent second voice

Three policy-compliant Claude Code calls used `claude-opus-5` at `xhigh` with
only `Read`, `Grep`, and `Glob`. A full-context review produced no result after
approximately 37 minutes; a bounded reset/revocation-only retry produced no
result after 15 minutes; and the final 18-finding closure brief produced no
incremental output within its approximately two-minute bounded window. All were
terminated without file modification. Claude unavailability is non-blocking
under the repository policy, so those attempts produced no finding to accept or
reject.

A final post-evidence repository-aware review completed with the same model,
effort, and Read/Grep/Glob-only boundary. It scored the completion claim 9/10
and returned `CLEAR_WITH_DOC_CORRECTIONS`. Codex accepted all findings:

- global identity rollback discarded its mandatory reason on success, so the
  reducer now appends one immutable source-null event with exact actor/reason
  and bounded source/cohort counts, including no-op-source replays;
- the root/docs/TODO hot rails now state I0–I7 implementation completion while
  keeping production rollout and all three flags separate;
- the plan's earlier deterministic-lane figures now use the final
  90.37%/95.04%, 4,727 Vitest, and 6,866 mailserver assertion results; and
- the 472-assertion Ubuntu selector is explicitly
  `admin_reset_password.pg` plus all 12 `identity_*.pg` files.

No finding challenged a confirmed user decision. Claude then resumed the same
review context and inspected only the accepted corrections. Its final verdict
was **10/10 — CLEAR**: A1 and B1–B4 were closed in code, tests, runbook, hot
rails, and evidence records, and no correction introduced a new blocker. Its
only non-scoring note was the guide's stale V153–V167 rollback-era range; that
range now correctly includes V168–V172.

## Production boundary

The changed-Go coverage, browser evidence, and isolated Ubuntu
deployment/restore/rollback gates are now recorded. The three identity feature
flags remain OFF. Production rollout remains a separate operator decision with
the documented target-environment canary and rollback boundary.
