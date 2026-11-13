<!-- Detailed DOX reference, moved from AGENTS.md on 2026-09-11. -->
This is a task-selected reference, not an always-loaded rail. Root and local
AGENTS.md govern agent workflows. Domain contracts below remain binding for their
scope; historical status is not permission to implement or enable flags.

# e2e — Playwright suite (DOX rail)

The spec-writing contract for `mailserver/webmail/e2e/`. Parent: `webmail/AGENTS.md`. Reference implementation: `admin-crud.spec.ts` (tag routing, network ACKs, dedicated fixtures, strict API teardown — read it before writing a new spec).

## Stack

`scripts/start-test-stack.sh` builds the Webmail SPA first, then builds instance-scoped gateway/authserver/mailctl binaries below `${TMPDIR}/setjoin-e2e-<db>-<gateway-port>`, reloads `mailserver_e2e` from the collapsed baseline + forward migrations + reducers, creates the catalog-derived current/next monthly partitions **before** `fixtures/seed.sql` can place current-month rows in a DEFAULT partition, starts SeaweedFS S3, and runs the servers in the FOREGROUND under an overseer. Building before the database reset prevents stale `build/` output from testing an older product; `E2E_SKIP_WEBMAIL_BUILD=1` is allowed only when the caller already built and verified the same output, and the script refuses that override when `build/index.html` is absent. The default gateway/auth/S3 ports are `8080`/`8443`/`9000`; the disposable SMTP inbound/submission/IMAP listeners bind only `127.0.0.1` on `1025`/`1587`/`1143`, preserving the production IMAP TLS fence without exposing test authentication. Each has a matching `E2E_*_PORT` override. The reaper kills only this exact instance's binaries/Seaweed children and refuses non-E2E port owners, so isolated stacks can coexist. Pass the matching `E2E_SERVER=http://localhost:<gateway-port>` to Playwright; config, setup, helpers, and seeded `authserver.public_url` then share that browser-visible origin. Ordinary mode passes empty `LIVEKIT_*` values even if the parent shell previously ran a meeting gate; `E2E_MEET_LIVE=1` alone starts the pinned LiveKit container and wires the SFU. Poll `/health` for HTTP 200 — never a blind sleep or body-agnostic curl; child exit, degraded health, or timeout fails and cleans every sibling.

The complete front door is `bash scripts/verify-all.sh browser-complete` (or `bash scripts/e2e-browser-complete.sh`). It runs default user/admin, live CA/device, strict CSP, uninitialized onboarding, and real LiveKit phases with separate JSON reports below `test-results/browser-complete/`. `check-complete-browser-evidence.mjs` rejects failures, retry-flakes, unexpected gated skips, and any default skip not discharged by a passing real phase. The sole browser-honesty exclusion is the active native offline-mail journey. Coverage policy and the feature/dimension ledger live in `COVERAGE.md`.

`E2E_MAXIMAL_FEATURES=1` is the disposable startup-interaction diagnostic. It
enables every registered feature before authserver/gateway boot except two
deliberate policy gates: `dengbao.sod_mode`, whose dedicated reducer rejects the
seeded cross-class built-in roles, and `feature.device_lockdown`, whose purpose
is to reject an ordinary browser without an enrolled native-shell device proof.
The script verifies those exact two exceptions and that no unknown rows exist;
`device-lockdown.spec.ts` separately tests lockdown ON with its approved and
unapproved proof fixtures. This lane supplements rather than replaces
`browser-complete`: the canonical specs deliberately exercise OFF, mixed,
dependency-error, and transition states that one maximal fixture cannot.

`admin-route-matrix.spec.ts` is the catalog-derived admin shell/readiness gate:
every canonical route must render its heading and either complete all initial
requests or match one exact default-state failure with visible explanatory UI.
Keep dependency/OFF-gate exceptions endpoint- and status-specific; never turn
the matrix into a broad console-error or 404 allow-list.

`browser-complete-coverage.json` is the machine contract for those five phases.
The evidence checker runs each phase's Playwright `--list --reporter=json`
selector and compares every listed case by exact source file, source line,
project, and title with the retained result report. A non-empty narrowed report,
an extra project, or a same-title pass in another project fails closed. Every
main-phase skip has an exact gate rule in that manifest; native and
not-applicable exclusions carry an explicit reason. The live gateway browser
run sets `E2E_CSP_REQUIRE_GATEWAY_HEADER=1` so `csp.spec.ts` checks the actual
`Content-Security-Policy` response header; the standalone static CSP run checks
only the meta policy and always starts a fresh loopback server through
`scripts/playwright-supported.sh`.

The full link-protect SMTP/Safe Browsing flow is an external credential/service
gate and is intentionally absent from the default protocol `all` lane. Use
`scripts/e2e.sh link-protect` only with its explicit credentials; the local
`scripts/e2e.sh link-protect-local` lane covers the in-process token contract.

## Project routing — tags, not skips

Tag the top-level describe: `@user` runs only under `chromium` (alice storageState), `@admin` only under `admin-chromium` (admin storageState); untagged runs under BOTH (shared surfaces: smoke, a11y, csp, welcome-tour). Routing is `grepInvert` in `playwright.config.ts`. Do NOT use body-level `test.skip(project…)` — a skipped test still executes `beforeEach` (logins, psql arranges) and that concurrency corrupted shared fixtures for months.

## Seeded fixtures (fixtures/seed.sql)

alice/bob/admin (+ terms/risky for CA specs), passwords in `fixtures/test-data.ts`. The seed also carries the active, enabled, mailbox-less `e2e-drive-guest@external.test` identity used only to prove that employee directory search does not disclose guest principals. alice has 3 numbered inbound messages (`E2E seeded message 1..3` — 1 belongs to email-to-task, 2 to labels-apply, 3 to inbox-read's exact count), one HTML message, and `E2E pile probe` (focused-other's pile-move fixture). Do not repurpose another spec's message; seed your own (via the `deliver()` reducer in seed.sql) or create data through the UI/API with `Date.now()`-unique names.

## The rules that keep the suite deterministic

1. **Await the network ACK for persistence.** Optimistic UI renders before the write commits; `page.reload()` aborts in-flight POSTs and silently loses the mutation. Capture `page.waitForResponse(...Email/set|Task/set|your call...)` BEFORE the triggering click, await it after, then reload. Never `networkidle`, never `waitForTimeout` as synchronization.
2. **Dedicated users for destructive arranges.** Quota/toggle/pref mutations use a NON-alice account (send-quota uses bob) and restore in `afterEach` — alice is the shared protagonist and parallel specs read her state.
3. **Tear down through the product API, strictly.** Raw SQL teardown fights product invariants (primary-mailbox trigger, FK webs). Capture created ids from the create ACK response and `request.delete(...)` in `afterEach`, asserting 204 — a broken delete path is a product bug the spec must surface (admin-crud found three).
4. **psql for arrange/assert, not teardown.** `helpers.psql(sql)` hits the live DB synchronously — great for seeding preconditions and asserting persisted rows (remember: JMAP destroy is trash-first, then tombstone via `deleted_at`; count live rows with `deleted_at IS NULL`).
5. **Run-generated data is hygiene-cleaned per run** (`global.setup.ts` deletes `E2E %`/`e2e-%`/`dbg-%`-named reminders/events/tasks/tags/contacts, resets only `@test.local` login events, immediately restores one deterministic success + failure per seeded test user, and removes only the Alice→Bob/Admin delegation rows owned by this suite). Reminders are removed before their source events so an interrupted prior run cannot leave a fixed overlay over the next run; login-history assertions must retain their seeded failure evidence; delegation reset likewise makes an interrupted grant/revoke journey rerunnable. Name artifacts with those prefixes + `Date.now()`.
6. **Toasts pause on hover.** Playwright's cursor rests where it last clicked; a toast under it never auto-dismisses (and interrupts clicks through it). `page.mouse.move(0, 0)` before waiting a toast out.
7. **Unique per-project fixtures.** Untagged specs run in BOTH projects concurrently as the same account — include `testInfo.project.name` in generated names or tag the spec.
8. **Async jobs: poll the job-status endpoint, don't race the worker.** A background worker's tick interval (eapjobs = 3s, slower on a cold stack) beats any fixed-timeout UI assertion. Capture the enqueue ACK's job id, `expect.poll` the same status endpoint the page itself polls until the job settles, then assert the UI's done state (`email-address-policies.spec.ts` is the reference).
9. **Do not bypass append-only evidence for cosmetic cleanup.** If a product has no delete endpoint and its audit FK intentionally prevents raw space deletion, use a unique run name and retain the bounded test artifact. Drive's member-picker journey revokes the added member through the product API, but retains its empty space because `drive_audit_log` is immutable.
10. **The canonical suite is serial across files.** The user/admin projects share seeded identities and one live database; a worker-local browser context does not isolate reminders, delegations, feature toggles, or calendar state. `playwright.config.ts` therefore pins `workers: 1`. Do not raise it until every mutable fixture has a per-worker account/database namespace. A test that creates an active reminder must dismiss it through the product UI before returning.
11. **Visual baselines protect layout, not host rasterization.** `guest-invite-accept-ui.spec.ts` is the first release-gated pixel baseline. It uses the production build, self-hosted fonts, fixed locale/timezone/viewport/theme, disabled animation, and mocked pre-auth disclosure/policy responses. `playwright.config.ts` deliberately omits the host OS from the snapshot path and allows only a small antialiasing delta; do not raise that tolerance to hide real spacing, wrapping, overflow, focus, or hierarchy drift. Regenerate a baseline only after a reviewed intentional UI change, then inspect the new PNG before accepting it.
12. **Install first-document state before the first navigation.** Specs that control local/session storage for first-run behavior authenticate with `apiLogin`, register `page.addInitScript`, and then navigate once. The canonical `chromium` and `admin-chromium` feature projects block service workers so unrelated product journeys cannot race the first-install `clients.claim()` handoff. The real SW lifecycle remains mandatory in `webmail-performance.spec.ts`, whose explicit browser contexts use the browser default and prove cold/warm navigation plus the CacheStorage public-data boundary. Persistence journeys still use `page = await reloadAfterServiceWorkerControl(page)`; it preserves page-scoped routes, init scripts, viewport/emulation, cookies, origin storage, and server state and also fences the handoff when a caller deliberately enables service workers. Neither helper retries a journey or assertion.

## Helpers (helpers.ts)

`psql(sql)` · `loginAs(page, email, pw)` / `loginAsUser` / `loginAsAdmin` (cookie via real `/auth/login`; reuses a matching cookie — rate-limit friendly; installs fresh cookies against the configured `E2E_SERVER` origin, never a hard-coded hostname) · `apiToken(request, email, pw)` (Bearer for direct API calls) · `setFeature(request, adminToken, key, enabled)` (real toggle flip + hot reload; settle ~1s).

`mam-devices.spec.ts` is the minimal MAM admin smoke: on the disposable E2E
stack it arranges unique `device_registry` rows plus four authoritative
`mdm_device_state` statuses and one registry-only row, then asserts the real
list wire fields, platform/status filters, and detail projection. The MAM
surface has no product enrollment-delete endpoint, so these run-scoped rows
are retained only inside the disposable database rather than torn down with
raw SQL.

## Live-stack gated specs

`meet-live-ui.spec.ts` (Meet B1 standing gate — the full webmail-UI
authority flow: two headless Chromium members + a guest context, fake
media, against a live SFU-provisioned stack) is `MEET_LIVE_UI=1`-gated and
SKIPS in an ordinary run — the default e2e stack has no LiveKit sidecar.
It launches its own Chromium instances (fake-media flags), needs
`feature.meet` ON + seeded users + a reachable `psql`, and takes
`MEET_LIVE_UI_BASE`/`MEET_LIVE_UI_DSN`/`MEET_LIVE_UI_EVIDENCE` overrides.
The complete front door provisions `livekit/livekit-server:v1.13.5` using
`fixtures/livekit.e2e.yaml`; callers do not pre-provision an SFU.
First run 2026-07-16 (linux-ci-host) found 7 real product bugs — see
`mailserver/internal/meet/AGENTS.md`'s honesty section.

`guest-invite-lifecycle.spec.ts` is the Guest Accounts release gate over the ordinary local stack. It enables `feature.guest_accounts` only in `mailserver_e2e`, creates a uniquely allowlisted external identity through the real admin API, and proves the browser-visible Pending → Superseded replacement → exact-ID Revoked history plus invite-level audit evidence. Screenshots default to `/tmp/setjoin-guest-e2e-evidence`; the test restores the feature toggle and its temporary allowlist entry.

`drive-secure.spec.ts` includes the authenticated Drive member-picker journey. It temporarily enables `feature.drive`, creates a regular space as Alice, proves the seeded guest is absent from the real JMAP directory response/UI, proves close/reopen clears pending person + role, grants Bob as editor through the UI, asserts reducer-persisted SQL state, revokes Bob through the product API, and restores the toggle OFF.

`office-foundation.spec.ts` is the default-OFF Office/Drive History integration
gate over the ordinary local stack. It exercises OFF and mixed flag states,
web/electron choice projection, viewer denial, WOPI CheckFileInfo/GetFile/lock
conflict/save/idempotent replay, a stale-base Drive branch, signed History
pagination/tamper rejection, and provider ready/draining/removed transitions.
The same journey proves that removal fences active WOPI launches while Drive
bytes, versions, and History remain available, then restores every feature OFF.
It uses a test-only proof-disabled provider solely inside the disposable DB;
renderer fidelity remains the separately declared live Collabora/corpus gate.

`office-managed-install.spec.ts` is the gated real-install continuation. With
`E2E_MANAGED_OFFICE=1`, it configures an inactive provider, clicks the curated
Apps card, proves the reducer queue reaches the updater/Docker runner, waits via
the admin API for `connected_inactive`, checks the browser-visible terminal
state, live discovery and the manifest-bound revision digest, then restores the
toggle and removes only fixed test runtime resources. The source-bound front
door is `bash scripts/e2e-office-managed-install.sh`. An external runner may be
used through `E2E_MANAGED_OFFICE_EXTERNAL_RUNNER=1` when a supported browser is
connected to a separate Linux Docker host; that mode never runs or cleans Docker
on the browser host.

`identity-model.spec.ts` is the live-stack Identity Model release-evidence lane. It requires all three identity behavior flags to remain OFF, renders the source/person/conflict/transition/audit console from normalized shadow evidence, proves preview fails closed with actionable BZ234 remediation while admission is off, checks mobile overflow, and retains desktop/mobile screenshots. Source generation and link-count assertions must tolerate legitimate evidence retained by earlier isolated canary/rollback drills; the test may not weaken the OFF-toggle assertion or mutate a production database.

The stack defaults to PostgreSQL at `127.0.0.1:5432` as `mail`/`mail`, but
`E2E_PGHOST`, `E2E_PGPORT`, `E2E_PGUSER`, and `E2E_PGPASSWORD` may point it at
a disposable cluster. Use that isolation when a verification host already runs
a deployed Setjoin database: the E2E stack resets its database and rotates the
cluster-global `setjoin_app`/`setjoin_worker` test passwords.

## Local repeat-runs

The authserver tarpits repeated failed logins in memory (by design); the deliberate bad-login smoke test runs once per run and carries a tolerant timeout. If a local stack has absorbed many runs, restart it rather than loosening assertions.
# First-boot onboarding

The onboarding spec consumes one disposable uninitialized database in source
order. Run it only through `bash scripts/verify-all.sh onboarding`, which uses
`playwright.onboarding.config.ts` without the ordinary seeded login setup
projects. It first proves that the browser surface is read-only and every former
public setup mutation is 404, then invokes the built local `mailctl
bootstrap-admin` against the owner DSN with the password on stdin. After that
atomic local bootstrap, the instance is intentionally terminally initialized
for the rest of the login journey.
The onboarding project retries up to twice only under `CI`, matching the main
browser lane's recovery from native browser-process crashes while keeping local
failures immediate; retries never convert a failing product assertion into a
pass unless the whole assertion succeeds on a later attempt.

## Supported Linux browser runtime

`scripts/playwright-supported.sh` keeps the Playwright test process, database
helpers, and artifacts on the controller host. `auto` uses the host on macOS or
supported Ubuntu 22.04/24.04, accepts an explicit loopback-only
`PLAYWRIGHT_CONNECT_WS_ENDPOINT` for a separate supported browser host, and
fails closed on other Linux kernels. `host` and `container` are explicit
diagnostic overrides; the exact-version Noble/Jammy container binds loopback,
uses `--init`, `--ipc=host`, and host networking, and is removed on every exit,
but it shares the host kernel and is not a release-gate workaround for a kernel
compatibility crash. `verify-all.sh browser` and onboarding route through this
seam. A retry-pass on an unsupported host is not a compatibility proof; the
supported runner must pass with retries set to zero when validating a
browser-process crash.
