#!/usr/bin/env node
/**
 * CQ E6 desktop-lane client-pair launcher — CONTRACT: connectivity-e6-harness
 * (readiness item "Client-pair launch wiring" in
 * `retired-docs:verification/2026-09-19-connectivity-e6-harness.md`; profile
 * `docs/verification/connectivity-e6-profile.json`, selected
 * `e6-electron-macos-arm64-v1`).
 *
 * ---------------------------------------------------------------------------
 * What this does
 * ---------------------------------------------------------------------------
 * The E6 paired run compares a flag-OFF comparator member against an
 * execute-mode candidate member of ONE identical Electron build
 * (`feature.connectivity_aware_sync` off vs execute). This launcher:
 *   0. locates the live fixture env and re-mints both members' credentials
 *      through the fixture's own `login` subcommand (fail-closed: without the
 *      gateway origin + member sessions there is NO app to render — the
 *      2026-09-21 white-screen defect),
 *   1. builds the client once (`npm run build` in clients/desktop/electron;
 *      the harness independently verifies the `dist/main.js` sha-256),
 *   2. launches TWO instances of that one build with DISTINCT user-data dirs,
 *      the flag delta expressed through the client's harness-only rollout
 *      seam (`SETJOIN_E6_CONNECTIVITY_SYNC_MODE=off|execute`; the shipped
 *      default stays `off` — see `clients/desktop/electron/src/connectivity/
 *      rollout.ts` — and nothing here widens it), the GATEWAY-SERVED webmail
 *      origin (`SETJOIN_E6_APP_ORIGIN`, loopback-validated by the client),
 *      and the member session bootstrap (`SETJOIN_E6_SESSION_COOKIE` +
 *      `SETJOIN_E6_MEMBER_EMAIL`/`_PASSWORD` for the client's session
 *      watchdog) — comparator=member A, candidate=member B,
 *   3. waits for each instance's readiness line (printed by
 *      `composeConnectivityE6HarnessSurface` once the first window's renderer
 *      finished loading AND the in-page probe observed the AUTHENTICATED app
 *      shell (`sj-shell`) carrying the member's /auth/me identity — bounded
 *      probes; a login page or white/no-render window is a named fatal),
 *      carrying the REAL main + renderer OS PIDs and, for the execute
 *      candidate, the loopback saturation-status URL,
 *   4. cross-checks each readiness line against the fixture env (the window
 *      must be signed in as the RIGHT member, at the RIGHT origin, and
 *      `rendered:true` — a bundled-load or white instance can never pass),
 *   5. writes the pair-state file and prints the PIDs in the harness-expected
 *      shape (`E6_DRIVER_MAIN_PID` / `E6_DRIVER_RENDERER_PID` export blocks
 *      per member), plus the driver-wrapper invocation that makes the E6
 *      harness attribute the RIGHT instance per member run,
 *   6. holds both instances alive for the harness run and tears BOTH down on
 *      exit (SIGINT/SIGTERM/child death), verifying no measured PID survives.
 *
 * ---------------------------------------------------------------------------
 * Why the driver wrapper mode exists (harness-shape honesty)
 * ---------------------------------------------------------------------------
 * The harness carries the operator-exported `E6_DRIVER_*` environment to BOTH
 * member runs verbatim (`memberEnv` spreads `process.env`) — there is no
 * per-member PID env. A single exported `E6_DRIVER_MAIN_PID` therefore cannot
 * name the comparator's main for the comparator run and the candidate's main
 * for the candidate run, and a single exported bearer cannot carry the right
 * member's credential. This launcher closes that gap WITHOUT touching the
 * harness or driver files: the harness member env always carries `E6_MEMBER`,
 * so `--driver-wrapper` (pass it as the workload driver via
 * `--workload-driver-cmd node --workload-driver-arg
 * scripts/e6-client-pair-launch.mjs --driver-wrapper --workload-driver-arg
 * scripts/e6-workload-driver.mjs` with `E6_CLIENT_PAIR_STATE` exported)
 * resolves the member from the harness env, overrides
 * `E6_DRIVER_MAIN_PID`/`E6_DRIVER_RENDERER_PID` from the pair state (and
 * `E6_DRIVER_SATURATION_URL` for the candidate only), forwards the
 * harness-declared candidate optional-job origin seam
 * (`E6_CANDIDATE_OPTIONAL_JOB_ORIGIN` → `E6_OPTIONAL_JOB_ORIGIN` — the
 * window's FaultProxy listener as the optional-job gateway origin,
 * candidate-only and loopback-validated, stripped from the comparator;
 * scheme v4 §2.3.2), resolves the per-member
 * credential pair — freshness-checking this member's bearer and re-minting it
 * through the fixture's `login <member>` subcommand only when the TTL is
 * burning out (TTL-aware: fresh >10 min skips the login; a rate-limited 429
 * login waits once and defers to a still-fresh bearer), then reading
 * `E6_MEMBER_<A|B>_BEARER` +
 * `E6_DRIVER_CLASS_BODIES_MEMBER_<A|B>` (comparator=A, candidate=B) from the
 * fixture env (current-run symlink or `E6_FIXTURE_ENV`) into
 * `E6_DRIVER_AUTH_BEARER`/`E6_DRIVER_CLASS_BODIES` and stripping the other
 * member's keys — liveness-checks the PIDs fail-closed, and execs the real
 * contract driver with stdio passed through untouched. The wrapper writes
 * NOTHING to stdout, so the driver's content-free stdout contract is preserved
 * byte for byte.
 *
 * ---------------------------------------------------------------------------
 * Honesty posture
 * ---------------------------------------------------------------------------
 * - Readiness means RENDERED + AUTHENTICATED, not merely "a renderer process
 *   exists": the client's ready line is printed only after its in-page probe
 *   observed the authenticated `sj-shell` app marker with the member's
 *   /auth/me identity, and this launcher additionally cross-checks that
 *   identity and origin against the fixture env. The 2026-09-21 run attempt
 *   (`e6h-20260921t043001z`) was stopped as NON-EVIDENCE because the old
 *   posture (bundled-build `loadFile`, fresh user-data dirs, no sessions)
 *   measured two idle white shells against the gateway — the coordinator
 *   under measurement lives in the gateway-served webmail behind a logged-in
 *   session. This launcher can no longer pass readiness on such instances.
 * - PIDs are never fabricated or guessed: they arrive on the readiness line
 *   from the client process itself and are cross-checked against the spawned
 *   Electron binary PID and the driver's own fail-closed liveness check.
 * - Credentials are never carried stale into a member run: the wrapper
 *   TTL-checks the member's bearer and re-mints it (fixture `login <member>`,
 *   <1 s) when its remaining TTL could burn into the member run — skipping
 *   the login entirely while >10 min of the 1 h TTL remains, so a 20-pair
 *   run no longer makes ~40 logins from 127.0.0.1 (nightly-17 pair 16 died
 *   on the gateway per-IP login rate limiter's 429). A 429 waits 60 s and
 *   retries once; a second 429 defers to the current bearer only while it
 *   still keeps >5 min (> the ~8-min member run) and otherwise fails the
 *   member run closed — the wrapper never execs with a bearer that is
 *   neither freshly minted nor proven fresh. The WINDOW's
 *   session is kept alive by the client's own watchdog (re-mint through the
 *   gateway login endpoint + cookie re-plant + reload when the gateway
 *   revokes the session — reset-pair wipes sessions between pairs and the
 *   token TTL is 1 h), so the measured coordinator substrate stays live.
 * - The saturation URL is printed ONLY for the execute candidate (the
 *   flag-off comparator starts no server — inert under `off` by construction,
 *   which the pair smoke proves on the running instances). The endpoint's
 *   `saturating` value is a policy-mode declaration with basis
 *   `policy-mode-configured`, NOT a coordinator queue-depth observation —
 *   `src/connectivity/saturation.ts` documents exactly why, and the response
 *   body carries the same basis so run artifacts stay honest.
 * - Every failure is loud and cleaned up: a member that dies before
 *   readiness, prints no parsable readiness line, fails the rendered/member
 *   cross-check, or dies during the hold fails the launcher (non-zero exit)
 *   and the surviving member is torn down.
 *
 * ---------------------------------------------------------------------------
 * Modes
 * ---------------------------------------------------------------------------
 *   (default)            launch mode: build once, launch the pair, wait for
 *                        readiness, print the PID/export blocks, hold until
 *                        signalled, tear down on exit.
 *   --smoke              validation: identical, but tears the pair down
 *                        immediately after readiness is verified and exits 0.
 *                        This is the documented two-instance launch smoke.
 *   --no-build           skip the build step (build must already exist)
 *   --ready-timeout-ms N readiness deadline per member (default 90000)
 *   --driver-wrapper <driver.mjs>
 *                        harness-spawned mode: resolve E6_MEMBER, override the
 *                        role-PID/saturation env from the pair state named by
 *                        E6_CLIENT_PAIR_STATE, exec the real driver. Never
 *                        run this by hand; the harness invokes it.
 *   --self-test          pure in-memory assertions (no network, no writes)
 *   -h, --help           this text
 *
 * ---------------------------------------------------------------------------
 * Output contract (stdout)
 * ---------------------------------------------------------------------------
 *   {"type":"e6-client-pair",...}        once both members are ready
 *   {"type":"e6-client-pair-teardown",..} once teardown is verified
 *   {"type":"e6-client-pair-smoke",...}  smoke receipt (--smoke only)
 * Plus human/export blocks (the export lines ARE the harness-expected shape).
 * Instance stdout/stderr never reach this stdout: they are teed to
 * `<pairDir>/<member>.log`. The wrapper mode adds nothing to stdout.
 *
 * Exit codes: 0 ok (launch teardown/smoke/wrapper child exit 0); 1 machinery
 * or readiness failure; 130/143 on SIGINT/SIGTERM after verified teardown.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { spawn, spawnSync } from 'node:child_process';

const REPO_ROOT = path.resolve(import.meta.dirname, '..');
const ELECTRON_DIR = path.join(REPO_ROOT, 'clients/desktop/electron');
const DRIVER_REL = 'scripts/e6-workload-driver.mjs';
const LAUNCHER_REL = 'scripts/e6-client-pair-launch.mjs';
const FIXTURE_SCRIPT_REL = 'scripts/e6-gateway-fixture.sh';
const CONNECTIVITY_FLAG = 'feature.connectivity_aware_sync';
const STATE_ENV = 'E6_CLIENT_PAIR_STATE';
const FIXTURE_ENV_OVERRIDE_ENV = 'E6_FIXTURE_ENV';
const FIXTURE_ENV_FILE = 'e6-fixture.env';
const READY_LINE_TYPE = 'e6-client-ready';
const DEFAULT_READY_TIMEOUT_MS = 90_000;
const TEARDOWN_GRACE_MS = 5_000;
const LOGIN_MINT_TIMEOUT_MS = 30_000;
// Remint decision margins against the 1 h access-token TTL (nightly-17 pair 16:
// an unconditional pre-exec login per member minted ~40 logins per 20-pair run
// from 127.0.0.1 and the gateway's per-IP login rate limiter answered 429
// mid-run, aborting a pair over a bearer that was still fresh). A bearer with
// more than 10 min of TTL left is not re-minted at all; a double-429 defers to
// the current bearer while it keeps more than 5 min (≥ the ~8-min member run).
const REMINT_SKIP_IF_FRESHER_THAN_S = 600;
const REMINT_DEFER_IF_FRESHER_THAN_S = 300;
const REMINT_429_RETRY_DELAY_MS = 60_000;
const MEMBERS = ['comparator', 'candidate'];
const MEMBER_MODES = { comparator: 'off', candidate: 'execute' };
// The fixture's two accounts map to the pair members: account A (e6-a) is the
// comparator's, account B (e6-b) the candidate's. Bearer and class bodies MUST
// come from the same letter (the bodies carry A/B-account-scoped ids), so the
// pairing is made here, once, and every resolution derives from it.
const MEMBER_LETTER = { comparator: 'A', candidate: 'B' };
const DEFAULT_OUTPUT_ROOT_REL = 'test-results/connectivity-aware-sync/e6-client-pair';
// Fixture-env keys the launch itself consumes (the app-origin + member-session
// seams the client composes from): the gateway origin both windows load, and
// each member's login session — the cookie is the fixture's drift-guarded
// `access_token=<jwt>` Set-Cookie value, the identity cross-check source.
const FIXTURE_TARGET_URL_KEY = 'E6_TARGET_URL';
const memberEnvKey = (letter, suffix) => `E6_MEMBER_${letter}_${suffix}`;

class LaunchError extends Error {
	constructor(tag, message) {
		super(`E6-PAIR-${tag}: ${message}`);
		this.e6Tag = tag;
	}
}

function fail(tag, message) {
	throw new LaunchError(tag, message);
}

function log(message) {
	process.stderr.write(`e6-client-pair-launch: ${message}\n`);
}

function sha256(data) {
	return crypto.createHash('sha256').update(data).digest('hex');
}

function isoUtcNow() {
	return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function sleep(ms) {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

function pidAlive(pid) {
	try {
		process.kill(pid, 0);
		return true;
	} catch (error) {
		return error.code === 'EPERM';
	}
}

// ---------------------------------------------------------------------------
// Pure helpers — the --self-test surface.
// ---------------------------------------------------------------------------

function isLoopbackUrl(rawUrl) {
	let url;
	try {
		url = new URL(rawUrl);
	} catch {
		return false;
	}
	return url.protocol === 'http:' && ['127.0.0.1', 'localhost', '::1'].includes(url.hostname);
}

function isValidPid(value) {
	return Number.isInteger(value) && value > 1;
}

/** Parse and fully validate one readiness line; null for any non-ready line
 *  (Electron/Chromium chatter must never masquerade as readiness). The 2026-09-21
 *  shape: the ready line additionally carries the app-origin/rendered/member
 *  proof — `appOrigin` (null on the legacy bundled load, which the launcher
 *  refuses), `rendered` (true ONLY after the in-page probe observed the
 *  authenticated app shell), and `memberEmail` (the /auth/me identity the
 *  window is signed in as). */
function parseReadyLine(line) {
	if (!line.includes(READY_LINE_TYPE)) return null;
	let event;
	try {
		event = JSON.parse(line);
	} catch {
		return null;
	}
	if (event?.type !== READY_LINE_TYPE) return null;
	if (event.flag !== CONNECTIVITY_FLAG) return null;
	if (!['off', 'observe', 'execute'].includes(event.mode)) return null;
	if (!isValidPid(event.mainPid) || !isValidPid(event.rendererPid)) return null;
	if (event.mainPid === event.rendererPid) return null;
	if (event.saturationUrl !== null) {
		if (typeof event.saturationUrl !== 'string' || !isLoopbackUrl(event.saturationUrl)) return null;
	}
	if (event.appOrigin !== null) {
		if (typeof event.appOrigin !== 'string' || !isLoopbackUrl(event.appOrigin)) return null;
	}
	if (typeof event.rendered !== 'boolean') return null;
	if (event.memberEmail !== null && typeof event.memberEmail !== 'string') return null;
	return event;
}

/** Cross-check one member's parsed readiness line against the fixture env —
 *  the launcher-side half of the rendered/authenticated contract (the client
 *  half is the probe gate in `composeConnectivityE6HarnessSurface`). Fails
 *  closed with named errors: a `rendered:false` line is the white/no-render
 *  failure class; a wrong memberEmail would measure the WRONG member's
 *  substrate; a mismatched appOrigin means the window is not looking at the
 *  measured gateway. */
function validateMemberReadiness(member, ready, fixtureEnv) {
	const letter = MEMBER_LETTER[member];
	if (ready.rendered !== true) {
		fail(
			'READINESS',
			`the ${member} ready line says rendered=false (appOrigin ${JSON.stringify(ready.appOrigin ?? null)}, memberEmail ${JSON.stringify(ready.memberEmail ?? null)}); ` +
				`a window that did not render the authenticated webmail app cannot measure the coordinator substrate ` +
				`(the 2026-09-21 white-screen failure class) — see ${path.relative(REPO_ROOT, 'clients/desktop/electron/src/connectivity/appOrigin.ts')}`,
		);
	}
	if (typeof ready.memberEmail !== 'string' || ready.memberEmail === '') {
		fail('READINESS', `the ${member} ready line carries no memberEmail; the window's login state is unproven`);
	}
	const expectedEmail = fixtureEnv[memberEnvKey(letter, 'EMAIL')];
	if (ready.memberEmail !== expectedEmail) {
		fail(
			'READINESS',
			`the ${member} window is signed in as ${JSON.stringify(ready.memberEmail)} but the fixture env names ` +
				`${JSON.stringify(expectedEmail ?? null)} for member ${letter}; the flag delta would be measured on the wrong identity`,
		);
	}
	if (ready.appOrigin === null) {
		fail(
			'READINESS',
			`the ${member} ready line carries appOrigin=null (legacy bundled/dev load); the E6 window must load the gateway-served webmail`,
		);
	}
	const targetUrl = fixtureEnv[FIXTURE_TARGET_URL_KEY];
	if (typeof targetUrl !== 'string' || !isLoopbackUrl(targetUrl) || new URL(ready.appOrigin).origin !== new URL(targetUrl).origin) {
		fail(
			'READINESS',
			`the ${member} window loaded ${ready.appOrigin} but the fixture target is ${JSON.stringify(targetUrl ?? null)}; ` +
				`the measured origin and the workload driver's origin must be the same gateway`,
		);
	}
}

/** Validate the fixture-env slice the LAUNCH consumes (distinct from the
 *  wrapper's per-run credential resolution): the loopback target URL and,
 *  per member, email + password + session cookie. Missing pieces mean the
 *  client cannot boot a logged-in window — refuse before spawning anything. */
function validateLaunchFixtureEnv(fixtureEnv) {
	const targetUrl = fixtureEnv[FIXTURE_TARGET_URL_KEY];
	if (typeof targetUrl !== 'string' || !isLoopbackUrl(targetUrl)) {
		fail(
			'FIXTURE',
			`fixture env carries no loopback ${FIXTURE_TARGET_URL_KEY}; the pair windows have no gateway-served webmail to load — start/re-mint the fixture (bash ${FIXTURE_SCRIPT_REL} up)`,
		);
	}
	for (const member of MEMBERS) {
		const letter = MEMBER_LETTER[member];
		for (const suffix of ['EMAIL', 'PASSWORD', 'SESSION_COOKIE']) {
			const value = fixtureEnv[memberEnvKey(letter, suffix)];
			if (typeof value !== 'string' || value === '') {
				fail(
					'FIXTURE',
					`fixture env carries no ${memberEnvKey(letter, suffix)} for the ${member} member; ` +
						`the window would boot without its login session — re-mint with bash ${FIXTURE_SCRIPT_REL} login`,
				);
			}
		}
	}
	return targetUrl;
}

/** Validate a loaded pair-state document (wrapper mode input). */
function validatePairState(document) {
	if (document === null || typeof document !== 'object') {
		fail('USAGE', 'pair state is not an object');
	}
	if (document.kind !== 'e6-client-pair-state' || document.schemaVersion !== 1) {
		fail('USAGE', `pair state must be kind e6-client-pair-state schemaVersion 1 (got ${document.kind}/${document.schemaVersion})`);
	}
	if (document.members === null || typeof document.members !== 'object') {
		fail('USAGE', 'pair state carries no members');
	}
	const entries = {};
	for (const member of MEMBERS) {
		const entry = document.members[member];
		if (entry === null || typeof entry !== 'object') {
			fail('USAGE', `pair state carries no ${member} member`);
		}
		if (entry.member !== member || !isValidPid(entry.mainPid) || !isValidPid(entry.rendererPid)) {
			fail('USAGE', `pair state ${member} entry is malformed`);
		}
		if (member === 'candidate' && (typeof entry.saturationUrl !== 'string' || !isLoopbackUrl(entry.saturationUrl))) {
			fail('USAGE', 'pair state candidate carries no loopback saturationUrl; the wrapper exists to provide endpoint-verified saturation');
		}
		// Candidate transport seam (scheme v4 §2.3.2): the optional-job origin
		// is null until the per-window interlock supplies the window's proxy
		// listener; when present it must be loopback http and only ever on the
		// candidate — a comparator carrying one breaks the inert-under-off
		// posture this launcher exists to guard.
		const normalized = { ...entry, optionalJobOrigin: entry.optionalJobOrigin ?? null };
		if (normalized.optionalJobOrigin !== null) {
			if (!isLoopbackUrl(normalized.optionalJobOrigin)) {
				fail('USAGE', `pair state ${member} optionalJobOrigin is not a loopback http origin`);
			}
			if (member === 'comparator') {
				fail('USAGE', 'pair state comparator carries an optionalJobOrigin; the flag-off comparator stays inert under off (no optional-job transport)');
			}
		}
		entries[member] = normalized;
	}
	if (entries.comparator.mainPid === entries.candidate.mainPid || entries.comparator.rendererPid === entries.candidate.rendererPid) {
		fail('USAGE', 'pair state members share PIDs; two instances cannot be one process');
	}
	return { ...document, members: entries };
}

/** Parse the fixture-emitted env block (`export KEY='value'` lines, as written
 *  by e6-gateway-fixture.sh mint_and_write_env) into a plain map. Pure: comment
 *  and non-conforming lines are ignored, values are taken verbatim between the
 *  single quotes (the minted values — JWTs, jq JSON — never contain one). */
function parseFixtureEnv(text) {
	const map = {};
	for (const line of String(text ?? '').split('\n')) {
		const match = line.match(/^export ([A-Za-z_][A-Za-z0-9_]*)='(.*)'$/);
		if (match) map[match[1]] = match[2];
	}
	return map;
}

/** Locate the live fixture env file: the `E6_FIXTURE_ENV` override when set,
 *  else the fixture's current-run state dir symlink (`$TMPDIR/
 *  setjoin-e6-fixture-current` → `<state dir>/e6-fixture.env`). Fail-closed
 *  with a named error when absent — a member run without the fixture env has
 *  no credential to run under. */
function locateFixtureEnvFile({ env = process.env, existsSync = fs.existsSync, readlinkSync = fs.readlinkSync } = {}) {
	const override = env[FIXTURE_ENV_OVERRIDE_ENV];
	if (override !== undefined && override !== '') {
		if (!existsSync(override)) {
			fail('FIXTURE', `${FIXTURE_ENV_OVERRIDE_ENV}=${override} names a missing fixture env file; start/re-mint the fixture (bash ${FIXTURE_SCRIPT_REL} up) or clear the override`);
		}
		return override;
	}
	const stateLink = path.join(env.TMPDIR || '/tmp', 'setjoin-e6-fixture-current');
	let stateDir;
	try {
		stateDir = readlinkSync(stateLink);
	} catch {
		fail('FIXTURE', `no current fixture run (no symlink at ${stateLink}); start the fixture first: bash ${FIXTURE_SCRIPT_REL} up (or point ${FIXTURE_ENV_OVERRIDE_ENV} at its ${FIXTURE_ENV_FILE})`);
	}
	const envFile = path.join(stateDir, FIXTURE_ENV_FILE);
	if (!existsSync(envFile)) {
		fail('FIXTURE', `current fixture state dir ${stateDir} carries no ${FIXTURE_ENV_FILE}; re-mint it: bash ${FIXTURE_SCRIPT_REL} login`);
	}
	return envFile;
}

/** Decode the `exp` claim (epoch seconds) from a bearer JWT's payload —
 *  base64url decode of the middle dot-segment, pure in-process JS (no deps).
 *  Null for anything that is not a JWT carrying a numeric exp (the caller
 *  treats that as "no freshness proof": never skipped, never deferred-to). */
function decodeJwtExpSeconds(bearer) {
	if (typeof bearer !== 'string') return null;
	const segments = bearer.split('.');
	if (segments.length !== 3 || segments[1] === '') return null;
	try {
		const exp = JSON.parse(Buffer.from(segments[1], 'base64url').toString('utf8'))?.exp;
		return typeof exp === 'number' && Number.isFinite(exp) ? exp : null;
	} catch {
		return null;
	}
}

/** Re-mint THIS member's bearer immediately before the driver execs —
 *  TTL-aware and 429-tolerant. Decision table:
 *  1. current bearer fresh > 600s of its 1 h TTL:
 *     SKIP the fixture login entirely (named line `e6-remint-skip` with the
 *     seconds remaining) and keep the current bearer;
 *  2. else invoke fixture `login <member>`; success keeps the freshly written
 *     env (the caller re-reads the file);
 *  3. non-429 failures stay unconditionally fail-closed (the old posture);
 *  4. a 429 (gateway per-IP login rate limiter) waits 60 s and retries ONCE;
 *  5. a second 429 DEFERS to the current bearer when it still keeps
 *     > 300s (named line `e6-remint-deferred` —
 *     minted ≤1 h ago, valid for the ~8-min member run) and only fails closed
 *     when no fresh-enough bearer exists (expired or unparseable exp).
 *  The wrapper NEVER execs the driver with a bearer that is neither freshly
 *  minted nor proven fresh. Clock/delay/run/logging are injectable for the
 *  self-test. */
async function remintMemberBearer(member, currentBearer, { run = spawnSync, root = REPO_ROOT, nowMs = Date.now, delayMs = sleep, logFn = log } = {}) {
	const letter = MEMBER_LETTER[member];
	const remainingS = () => {
		const exp = decodeJwtExpSeconds(currentBearer);
		return exp === null ? null : Math.round(exp - nowMs() / 1000);
	};
	const fresh = remainingS();
	if (fresh !== null && fresh > REMINT_SKIP_IF_FRESHER_THAN_S) {
		logFn(`e6-remint-skip member=${member} current bearer keeps ${fresh}s of its 1h TTL (> ${REMINT_SKIP_IF_FRESHER_THAN_S}s margin); skipping the fixture login`);
		return;
	}
	const invokeFixtureLogin = () =>
		run('bash', [path.join(root, FIXTURE_SCRIPT_REL), 'login', letter.toLowerCase()], {
			cwd: root,
			encoding: 'utf8',
			timeout: LOGIN_MINT_TIMEOUT_MS,
		});
	const failed = (result) => result.error !== undefined || result.status !== 0 || result.signal !== null;
	const why = (result) => (result.error ? result.error.message : `exit ${result.status ?? 'killed by ' + result.signal}`);
	const hit429 = (result) => String(result.stderr ?? '').includes('429');
	const failClosed = (result, retried) =>
		fail(
			'FIXTURE',
			`bearer re-mint failed for the ${member} member (fixture ${FIXTURE_SCRIPT_REL} login ${letter.toLowerCase()}: ${why(result)}${retried ? ' after the 429 backoff retry' : ''}); ` +
				`refusing to exec the driver with a possibly stale bearer — check the fixture is up (bash ${FIXTURE_SCRIPT_REL} status)` +
				(result.stderr ? `; fixture stderr: ${String(result.stderr).trim().split('\n').slice(-3).join(' | ')}` : ''),
		);
	let result = invokeFixtureLogin();
	if (!failed(result)) return;
	if (!hit429(result)) failClosed(result, false);
	logFn(`e6-remint-429 member=${member} fixture login hit the gateway per-IP login rate limiter (429); waiting ${REMINT_429_RETRY_DELAY_MS / 1000}s and retrying once`);
	await delayMs(REMINT_429_RETRY_DELAY_MS);
	result = invokeFixtureLogin();
	if (!failed(result)) return;
	if (hit429(result)) {
		const stillFresh = remainingS();
		if (stillFresh !== null && stillFresh > REMINT_DEFER_IF_FRESHER_THAN_S) {
			logFn(`e6-remint-deferred member=${member} retry also 429s but the current bearer keeps ${stillFresh}s (> ${REMINT_DEFER_IF_FRESHER_THAN_S}s) of its 1h TTL — continuing this member run on the current bearer`);
			return;
		}
	}
	failClosed(result, true);
}

/** Launch-time credential mint: refresh BOTH members' sessions (the fixture's
 *  login subcommand re-mints A and B together and rewrites the env file) so
 *  the window session cookies boot fresh — the windows must start logged in,
 *  not on a bearer that a prior run already burned part of its 1 h TTL on. */
function remintLaunchCredentials({ run = spawnSync, root = REPO_ROOT } = {}) {
	const result = run('bash', [path.join(root, FIXTURE_SCRIPT_REL), 'login', 'a'], {
		cwd: root,
		encoding: 'utf8',
		timeout: LOGIN_MINT_TIMEOUT_MS,
	});
	if (result.error !== undefined || result.status !== 0 || result.signal !== null) {
		const why = result.error ? result.error.message : `exit ${result.status ?? 'killed by ' + result.signal}`;
		fail(
			'FIXTURE',
			`launch credential mint failed (fixture ${FIXTURE_SCRIPT_REL} login: ${why}); the pair windows need fresh member sessions to boot logged in — ` +
				`check the fixture is up (bash ${FIXTURE_SCRIPT_REL} status)` +
				(result.stderr ? `; fixture stderr: ${String(result.stderr).trim().split('\n').slice(-3).join(' | ')}` : ''),
		);
	}
}

/** Resolve the env for one wrapper-spawned driver child from the harness env.
 *  Pure (never mutates the input); liveness and the fixture env are injectable
 *  for the self-test. Beyond the per-member role-PID/saturation attribution
 *  this resolves the per-member credential/bodies pair: `E6_DRIVER_AUTH_BEARER`
 *  + `E6_DRIVER_CLASS_BODIES` are set from THIS member's fixture-env values
 *  (same letter, so the account-scoped body ids always match the bearer), any
 *  operator-exported stale values are replaced, the OTHER member's per-member
 *  keys are stripped from the child env, and a missing fixture env or missing
 *  member value fails closed instead of execing under the wrong identity. */
function resolveMemberEnv(member, pairState, baseEnv, { liveness = pidAlive, fixtureEnv = null } = {}) {
	if (!MEMBERS.includes(member)) {
		fail('USAGE', `E6_MEMBER must be comparator|candidate, got ${JSON.stringify(member ?? null)}`);
	}
	if (fixtureEnv === null || typeof fixtureEnv !== 'object') {
		fail('FIXTURE', `no fixture env available for the ${member} member run; the wrapper resolves per-member credentials from the fixture env (current-run symlink or ${FIXTURE_ENV_OVERRIDE_ENV}) and refuses to exec without them`);
	}
	const letter = MEMBER_LETTER[member];
	const otherLetter = MEMBER_LETTER[member === 'comparator' ? 'candidate' : 'comparator'];
	const bearer = fixtureEnv[`E6_MEMBER_${letter}_BEARER`];
	const bodies = fixtureEnv[`E6_DRIVER_CLASS_BODIES_MEMBER_${letter}`];
	if (typeof bearer !== 'string' || bearer === '') {
		fail('CREDENTIAL', `fixture env carries no E6_MEMBER_${letter}_BEARER for the ${member} member run; re-mint with bash ${FIXTURE_SCRIPT_REL} login — never exec under a missing credential`);
	}
	if (typeof bodies !== 'string' || bodies === '') {
		fail('CREDENTIAL', `fixture env carries no E6_DRIVER_CLASS_BODIES_MEMBER_${letter} for the ${member} member run; re-mint with bash ${FIXTURE_SCRIPT_REL} login — never exec with another class's bodies`);
	}
	const entry = pairState.members[member];
	const env = { ...baseEnv };
	env.E6_DRIVER_MAIN_PID = String(entry.mainPid);
	env.E6_DRIVER_RENDERER_PID = String(entry.rendererPid);
	env.E6_DRIVER_AUTH_BEARER = bearer;
	env.E6_DRIVER_CLASS_BODIES = bodies;
	if (member === 'candidate') {
		env.E6_DRIVER_SATURATION_URL = entry.saturationUrl;
	} else {
		delete env.E6_DRIVER_SATURATION_URL;
	}
	// Candidate transport seam (scheme v4 §2.3.2): the harness names the
	// CANDIDATE window's FaultProxy listener as the optional-job gateway
	// origin (E6_CANDIDATE_OPTIONAL_JOB_ORIGIN, set by the harness memberEnv
	// for candidate windows only — the same proxy config object the
	// comparator instrument's delivery path freezes onto). The wrapper
	// forwards a declared loopback origin as E6_OPTIONAL_JOB_ORIGIN — the
	// seam the candidate's optional-job transport consumes — and fails
	// closed on any declared non-loopback value. The COMPARATOR window never
	// carries the seam in either form (the flag-off member admits no
	// optional work), and an operator-exported E6_OPTIONAL_JOB_ORIGIN decoy
	// is stripped wherever the harness did not declare the seam: no child is
	// ever exec'd with an unvalidated optional-job origin.
	const seamOrigin = env.E6_CANDIDATE_OPTIONAL_JOB_ORIGIN;
	delete env.E6_CANDIDATE_OPTIONAL_JOB_ORIGIN;
	if (member === 'candidate' && seamOrigin !== undefined) {
		if (typeof seamOrigin !== 'string' || !isLoopbackUrl(seamOrigin)) {
			fail(
				'SEAM',
				`E6_CANDIDATE_OPTIONAL_JOB_ORIGIN=${JSON.stringify(seamOrigin)} is not a loopback http origin; ` +
					'the candidate optional-job transport may only target its window\'s loopback FaultProxy listener',
			);
		}
		env.E6_OPTIONAL_JOB_ORIGIN = seamOrigin;
	} else {
		delete env.E6_OPTIONAL_JOB_ORIGIN;
		if (member !== 'candidate' && seamOrigin !== undefined) {
			log(`e6-seam-strip member=comparator stripped a mis-declared candidate optional-job origin (${seamOrigin}); the flag-off comparator never carries one`);
		}
	}
	// The harness env reaches both member runs verbatim: whatever per-member
	// keys name the OTHER member must not reach this member's child.
	for (const key of Object.keys(env)) {
		if (key.startsWith(`E6_MEMBER_${otherLetter}_`) || key === `E6_DRIVER_CLASS_BODIES_MEMBER_${otherLetter}`) {
			delete env[key];
		}
	}
	for (const [label, pid] of [
		['E6_DRIVER_MAIN_PID', entry.mainPid],
		['E6_DRIVER_RENDERER_PID', entry.rendererPid],
	]) {
		if (!liveness(pid)) {
			fail('USAGE', `${label}=${pid} (${member} instance) is not a live process; refusing to hand the driver a dead measured role`);
		}
	}
	return env;
}

/** The harness-expected export block for one member (operator-facing). */
function buildExportBlock(member, entry) {
	const lines = [
		`# ${member} member run (mode ${entry.mode})`,
		`export E6_DRIVER_MAIN_PID=${entry.mainPid}`,
		`export E6_DRIVER_RENDERER_PID=${entry.rendererPid}`,
	];
	if (entry.saturationUrl) {
		lines.push(`export E6_DRIVER_SATURATION_URL=${entry.saturationUrl}`);
	}
	// Candidate transport seam (scheme v4 §2.3.2): emitted only when the
	// window's proxy-backed optional-job origin is known (per-window
	// interlock); the comparator never carries one.
	if (entry.optionalJobOrigin) {
		lines.push(`export E6_OPTIONAL_JOB_ORIGIN=${entry.optionalJobOrigin}`);
	}
	return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Launch mode.
// ---------------------------------------------------------------------------

function resolveElectronBinary() {
	const pkgDir = path.join(ELECTRON_DIR, 'node_modules', 'electron');
	let rel;
	try {
		// path.txt is the download archive layout relative to the package's
		// dist/ directory (e.g. "Electron.app/Contents/MacOS/Electron").
		rel = fs.readFileSync(path.join(pkgDir, 'path.txt'), 'utf8').trim();
	} catch {
		fail('MACHINERY', `electron package has no path.txt under ${pkgDir}; is the dependency installed?`);
	}
	const binary = path.join(pkgDir, 'dist', rel);
	if (!fs.existsSync(binary)) {
		fail('MACHINERY', `electron binary missing at ${binary}; run the package install for clients/desktop/electron`);
	}
	// Spawn the Electron binary DIRECTLY (not the `electron` cli shim): the
	// spawned PID must BE the measured `setjoin-desktop-electron-main` role,
	// and teardown must signal that process, not a shim between us and it.
	return binary;
}

function createMemberChild({ member, electronBinary, userDataDir, logFile, appOrigin, fixtureEnv }) {
	const letter = MEMBER_LETTER[member];
	const env = {
		...process.env,
		SETJOIN_E6_USER_DATA_DIR: userDataDir,
		SETJOIN_E6_CONNECTIVITY_SYNC_MODE: MEMBER_MODES[member],
		// The app-origin + member-session seams (the white-screen fix): load
		// the gateway-served webmail and boot logged in as THIS member. The
		// client validates the origin loopback-http-only and refuses to
		// compose a window without its session cookie.
		SETJOIN_E6_APP_ORIGIN: appOrigin,
		SETJOIN_E6_SESSION_COOKIE: fixtureEnv[memberEnvKey(letter, 'SESSION_COOKIE')],
		SETJOIN_E6_MEMBER_EMAIL: fixtureEnv[memberEnvKey(letter, 'EMAIL')],
		SETJOIN_E6_MEMBER_PASSWORD: fixtureEnv[memberEnvKey(letter, 'PASSWORD')],
	};
	const child = spawn(electronBinary, ['.'], {
		cwd: ELECTRON_DIR,
		env,
		stdio: ['ignore', 'pipe', 'pipe'],
	});
	const logStream = fs.createWriteStream(logFile, { flags: 'a' });
	logStream.write(`# ${member} launch ${isoUtcNow()} pid=${child.pid} mode=${MEMBER_MODES[member]}\n`);
	const readiness = { ready: null, stdoutBuffer: '', exited: null };
	child.stdout.setEncoding('utf8');
	child.stdout.on('data', (chunk) => {
		logStream.write(chunk);
		if (readiness.ready) return;
		readiness.stdoutBuffer += chunk;
		let newlineIndex;
		while ((newlineIndex = readiness.stdoutBuffer.indexOf('\n')) >= 0) {
			const line = readiness.stdoutBuffer.slice(0, newlineIndex).trim();
			readiness.stdoutBuffer = readiness.stdoutBuffer.slice(newlineIndex + 1);
			const parsed = parseReadyLine(line);
			if (parsed) {
				readiness.ready = parsed;
				return;
			}
		}
	});
	child.stderr.setEncoding('utf8');
	child.stderr.on('data', (chunk) => {
		logStream.write(chunk);
	});
	child.on('exit', (code, signal) => {
		readiness.exited = { code, signal };
		logStream.end(`# ${member} exit code=${code} signal=${signal} ${isoUtcNow()}\n`);
	});
	return { member, mode: MEMBER_MODES[member], child, readiness, logFile, userDataDir, env };
}

async function waitForReady(memberChild, timeoutMs) {
	const deadline = Date.now() + timeoutMs;
	for (;;) {
		if (memberChild.readiness.ready) return memberChild.readiness.ready;
		if (memberChild.readiness.exited !== null) {
			fail(
				'READINESS',
				`${memberChild.member} exited before readiness (code=${memberChild.readiness.exited.code} signal=${memberChild.readiness.exited.signal}); see ${path.relative(REPO_ROOT, memberChild.logFile)}`,
			);
		}
		if (Date.now() > deadline) {
			fail(
				'READINESS',
				`${memberChild.member} printed no readiness line within ${timeoutMs}ms; see ${path.relative(REPO_ROOT, memberChild.logFile)}`,
			);
		}
		await sleep(100);
	}
}

/** SIGTERM both mains, escalate to SIGKILL, then verify the measured main AND
 *  renderer PIDs are gone. The receipt names survivors honestly. */
async function teardownPair(memberChildren) {
	const receipt = { type: 'e6-client-pair-teardown', atUtc: isoUtcNow(), members: {}, ok: true };
	for (const memberChild of memberChildren) {
		const { child } = memberChild;
		if (child.exitCode === null && child.signalCode === null) {
			child.kill('SIGTERM');
		}
	}
	const graceDeadline = Date.now() + TEARDOWN_GRACE_MS;
	for (const memberChild of memberChildren) {
		const { child } = memberChild;
		while (child.exitCode === null && child.signalCode === null && Date.now() < graceDeadline) {
			await sleep(100);
		}
		if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
	}
	// Renderer helpers die with their main; give the OS a beat, then verify —
	// and SIGKILL any measured renderer that somehow outlived its main.
	await sleep(300);
	for (const memberChild of memberChildren) {
		const ready = memberChild.readiness.ready;
		const pids = ready ? { mainPid: ready.mainPid, rendererPid: ready.rendererPid } : {};
		let survivors = [];
		if (ready) {
			survivors = [ready.mainPid, ready.rendererPid].filter((pid) => pidAlive(pid));
			for (const pid of survivors) process.kill(pid, 'SIGKILL');
			if (survivors.length > 0) await sleep(300);
			survivors = [ready.mainPid, ready.rendererPid].filter((pid) => pidAlive(pid));
		}
		receipt.members[memberChild.member] = {
			exited: memberChild.child.exitCode !== null || memberChild.child.signalCode !== null,
			...pids,
			survivors,
		};
		if (survivors.length > 0) receipt.ok = false;
	}
	process.stdout.write(`${JSON.stringify(receipt)}\n`);
	return receipt;
}

async function runLaunchMode(argv) {
	const smoke = argv.includes('--smoke');
	const noBuild = argv.includes('--no-build');
	const timeoutIndex = argv.indexOf('--ready-timeout-ms');
	const readyTimeoutMs = timeoutIndex >= 0 ? Number(argv[timeoutIndex + 1]) : DEFAULT_READY_TIMEOUT_MS;
	if (!Number.isInteger(readyTimeoutMs) || readyTimeoutMs < 1000) {
		fail('USAGE', '--ready-timeout-ms must be an integer >= 1000');
	}

	const distMain = path.join(ELECTRON_DIR, 'dist/main.js');
	if (!noBuild) {
		log(`building the one identical client (${path.relative(REPO_ROOT, ELECTRON_DIR)}) once for both members`);
		const build = spawn('npm', ['run', 'build'], { cwd: ELECTRON_DIR, stdio: 'inherit' });
		const buildCode = await new Promise((resolve) => build.on('exit', (code) => resolve(code)));
		if (buildCode !== 0) fail('BUILD', `client build failed (exit ${buildCode})`);
	}
	if (!fs.existsSync(distMain)) fail('BUILD', `dist/main.js missing at ${distMain}; build the client first`);
	const distMainSha256 = sha256(fs.readFileSync(distMain));
	const electronBinary = resolveElectronBinary();

	// The launch needs the LIVE fixture env (gateway origin + both members'
	// login sessions) — the 2026-09-21 white-screen defect is exactly what
	// launching without it produces. Re-mint both members' credentials first
	// (the windows must boot logged in, not on a bearer already part-burned
	// by a prior run), then re-read and validate the env slice the launch
	// consumes. Fail-closed BEFORE any child exists: nothing to tear down.
	const fixtureEnvFile = locateFixtureEnvFile();
	remintLaunchCredentials();
	const launchFixtureEnv = parseFixtureEnv(fs.readFileSync(fixtureEnvFile, 'utf8'));
	const targetUrl = validateLaunchFixtureEnv(launchFixtureEnv);
	const appOrigin = new URL(targetUrl).origin;
	log(`pair members boot logged in against the fixture gateway ${appOrigin} (fixture env ${fixtureEnvFile})`);

	const pairRunId = `e6pair-${isoUtcNow().replace(/[-:]/g, '').toLowerCase()}-${sha256(String(process.pid + Date.now())).slice(0, 12)}`;
	const pairDir = path.join(REPO_ROOT, DEFAULT_OUTPUT_ROOT_REL, pairRunId);
	fs.mkdirSync(path.join(pairDir, 'comparator-user-data'), { recursive: true });
	fs.mkdirSync(path.join(pairDir, 'candidate-user-data'), { recursive: true });
	log(`pair ${pairRunId} under ${path.relative(REPO_ROOT, pairDir)}`);

	const memberChildren = MEMBERS.map((member) =>
		createMemberChild({
			member,
			electronBinary,
			userDataDir: path.join(pairDir, `${member}-user-data`),
			logFile: path.join(pairDir, `${member}.log`),
			appOrigin,
			fixtureEnv: launchFixtureEnv,
		}),
	);

	// Interrupt discipline: from the moment the instances exist, SIGINT/SIGTERM
	// route through teardownOnce — a plain exit here would orphan both
	// Electron instances, the exact leftover the E6 ledger discipline forbids.
	let interrupted = null;
	const interruptPromise = new Promise((resolve) => {
		const onSignal = (signal) => {
			if (interrupted === null) interrupted = signal;
			resolve(signal);
		};
		process.on('SIGINT', () => onSignal('SIGINT'));
		process.on('SIGTERM', () => onSignal('SIGTERM'));
	});

	let tornDown = false;
	const teardownOnce = async () => {
		if (tornDown) return null;
		tornDown = true;
		return teardownPair(memberChildren);
	};

	try {
		const raced = await Promise.race([
			Promise.all(memberChildren.map((memberChild) => waitForReady(memberChild, readyTimeoutMs))),
			interruptPromise.then(() => null),
		]);
		if (raced === null) {
			await teardownOnce();
			fail('INTERRUPTED', `interrupted before readiness (signal=${interrupted}); both instances torn down`);
		}
		const readyStates = raced;

		// Cross-checks: the ready line must name the process we spawned (it is
		// the Electron main), the renderer must be its own process, and every
		// measured PID must be live — four distinct processes across the pair.
		const allMeasuredPids = [];
		for (const [index, memberChild] of memberChildren.entries()) {
			const ready = readyStates[index];
			if (ready.mainPid !== memberChild.child.pid) {
				fail('READINESS', `${memberChild.member} readiness named mainPid=${ready.mainPid} but the spawned Electron main is pid=${memberChild.child.pid}`);
			}
			allMeasuredPids.push(ready.mainPid, ready.rendererPid);
		}
		if (new Set(allMeasuredPids).size !== allMeasuredPids.length) {
			fail('READINESS', `measured PIDs are not distinct across the pair: ${allMeasuredPids.join(', ')}`);
		}
		for (const pid of allMeasuredPids) {
			if (!pidAlive(pid)) fail('READINESS', `measured pid=${pid} is not live immediately after readiness`);
		}

		// Rendered/authenticated cross-checks against the fixture env (the
		// white-screen contract): each window rendered the authenticated app
		// shell, is signed in as ITS member, at the fixture's gateway origin.
		for (const [index, memberChild] of memberChildren.entries()) {
			validateMemberReadiness(memberChild.member, readyStates[index], launchFixtureEnv);
		}

		const byMember = {};
		for (const [index, memberChild] of memberChildren.entries()) {
			const ready = readyStates[index];
			byMember[memberChild.member] = {
				member: memberChild.member,
				mode: memberChild.mode,
				mainPid: ready.mainPid,
				rendererPid: ready.rendererPid,
				saturationUrl: ready.saturationUrl,
				// Candidate transport seam (scheme v4 §2.3.2): null under the
				// launch-both-up-front topology — the window's FaultProxy does
				// not exist until the harness opens that member's window, so
				// the proxy-backed optional-job origin is filled by the v3
				// per-window interlock. Readiness/boot keep the REAL gateway
				// origin (validateMemberReadiness, unchanged above).
				optionalJobOrigin: null,
				appOrigin: ready.appOrigin,
				rendered: ready.rendered,
				memberEmail: ready.memberEmail,
				userDataDir: memberChild.userDataDir,
				logFile: memberChild.logFile,
			};
		}
		if (byMember.comparator.saturationUrl !== null) {
			fail('READINESS', 'the flag-off comparator printed a saturation URL; the inert-under-off posture is broken');
		}
		if (typeof byMember.candidate.saturationUrl !== 'string') {
			fail('READINESS', 'the execute candidate printed no saturation URL; the saturation endpoint did not start');
		}

		const pairState = {
			schemaVersion: 1,
			kind: 'e6-client-pair-state',
			notAnE6ResultsDoc: true,
			runId: pairRunId,
			createdAtUtc: isoUtcNow(),
			flag: CONNECTIVITY_FLAG,
			electronDir: path.relative(REPO_ROOT, ELECTRON_DIR),
			electronBinary: path.relative(REPO_ROOT, electronBinary),
			distMainSha256,
			pairDir: path.relative(REPO_ROOT, pairDir),
			members: byMember,
		};
		const stateFile = path.join(pairDir, 'pair-state.json');
		fs.writeFileSync(stateFile, `${JSON.stringify(pairState, null, 2)}\n`);

		process.stdout.write(`${JSON.stringify({ type: 'e6-client-pair', ...pairState })}\n`);
		for (const member of MEMBERS) {
			process.stdout.write(`${buildExportBlock(member, byMember[member])}\n`);
		}
			process.stdout.write(
				[
					'# harness invocation with per-member attribution (driver wrapper):',
					`export ${STATE_ENV}=${stateFile}`,
					`bash scripts/run-connectivity-e6-harness.sh --profile docs/verification/connectivity-e6-profile.json \\`,
					`  --pairs 20 --target-url ${targetUrl} \\`,
					`  --workload-driver-cmd node --workload-driver-arg ${LAUNCHER_REL} --driver-wrapper \\`,
					`  --workload-driver-arg ${DRIVER_REL}`,
					'# plus the operator-exported E6_DRIVER_GATEWAY_PID and E6_DRIVER_CLASS_ROUTES.',
					'# Per-member E6_DRIVER_AUTH_BEARER / E6_DRIVER_CLASS_BODIES are resolved',
					'# (and re-minted pre-exec) by the wrapper from the fixture env',
					'# (current-run symlink or E6_FIXTURE_ENV); comparator=A, candidate=B.',
				].join('\n'),
			);
		process.stdout.write('\n');

		if (smoke) {
			const receipt = await teardownOnce();
			if (!receipt.ok) fail('TEARDOWN', 'smoke teardown left measured PIDs alive');
			process.stdout.write(
				`${JSON.stringify({
					type: 'e6-client-pair-smoke',
					ok: true,
					runId: pairRunId,
					pairDir: path.relative(REPO_ROOT, pairDir),
					atUtc: isoUtcNow(),
				})}\n`,
			);
			return;
		}

		log('pair is ready and held; Ctrl-C (SIGINT/SIGTERM) tears both instances down');
		const held = await Promise.race([
			interruptPromise.then((signal) => ({ signal })),
			...memberChildren.map((memberChild) =>
				new Promise((resolve) => {
					// A member that already died between readiness and this hold
					// window recorded it in readiness.exited; the child 'exit'
					// event alone would never fire again and the hold would wait
					// forever for a dead instance.
					const exited = memberChild.readiness.exited;
					if (exited !== null) {
						resolve({ died: memberChild.member, code: exited.code ?? exited.signal });
						return;
					}
					memberChild.child.on('exit', (code, signal) => resolve({ died: memberChild.member, code: code ?? signal }));
				}),
			),
		]);
		if (held.died) {
			await teardownOnce();
			fail('HOLD', `${held.died} instance died while the pair was held (code=${held.code}); the other member was torn down — a measured role dying mid-run invalidates sampling`);
		}
		await teardownOnce();
		process.exitCode = interrupted === 'SIGINT' ? 130 : interrupted === 'SIGTERM' ? 143 : 0;
	} catch (error) {
		await teardownOnce();
		throw error;
	}
}

// ---------------------------------------------------------------------------
// Driver-wrapper mode (harness-spawned). Stdout stays content-free: the real
// driver's contract NDJSON passes through untouched; every wrapper diagnostic
// goes to stderr.
// ---------------------------------------------------------------------------

async function runDriverWrapper(argv) {
	const wrapperIndex = argv.indexOf('--driver-wrapper');
	const driverArg = argv[wrapperIndex + 1];
	if (!driverArg) fail('USAGE', '--driver-wrapper needs the real driver path (e.g. scripts/e6-workload-driver.mjs)');
	const driverPath = path.isAbsolute(driverArg) ? driverArg : path.join(REPO_ROOT, driverArg);
	if (!fs.existsSync(driverPath)) fail('USAGE', `driver not found: ${driverArg}`);
	const statePath = process.env[STATE_ENV];
	if (!statePath) {
		fail('USAGE', `${STATE_ENV} must name the launcher's pair-state.json (printed by the launch run)`);
	}
	let pairState;
	try {
		pairState = validatePairState(JSON.parse(fs.readFileSync(statePath, 'utf8')));
	} catch (error) {
		if (error instanceof LaunchError) throw error;
		fail('USAGE', `pair state at ${statePath} is unreadable: ${error.message}`);
	}
	const member = process.env.E6_MEMBER;
	// Per-member credential discipline (fixture contract): the wrapper NEVER
	// trusts an operator-exported bearer. Before every member exec it
	// freshness-checks THIS member's credential (its fixture-env JWT exp) and
	// re-mints through the fixture's own login subcommand only when needed —
	// the access-token TTL is 1 h and the run spans 2.5-3.5 h with reset-pair
	// session wipes in between — then reads the fixture env and resolves this
	// member's bearer + class bodies from it. A rate-limited (429) login waits
	// once and defers to a still-fresh bearer; anything else fails closed
	// instead of execing under a possibly stale credential (the 429 tolerance
	// exists because ~40 unconditional mints tripped the gateway's per-IP
	// login rate limiter mid-run in nightly-17, pair 16).
	const fixtureEnvFile = locateFixtureEnvFile();
	const currentBearer = parseFixtureEnv(fs.readFileSync(fixtureEnvFile, 'utf8'))[`E6_MEMBER_${MEMBER_LETTER[member]}_BEARER`];
	await remintMemberBearer(member, currentBearer);
	const fixtureEnv = parseFixtureEnv(fs.readFileSync(fixtureEnvFile, 'utf8'));
	const env = resolveMemberEnv(member, pairState, process.env, { fixtureEnv });
	log(`wrapper member=${member} mainPid=${env.E6_DRIVER_MAIN_PID} rendererPid=${env.E6_DRIVER_RENDERER_PID}` +
		(member === 'candidate' ? ` saturationUrl=${env.E6_DRIVER_SATURATION_URL}` : ' (no saturation surface: comparator)') +
		` fixtureEnv=${fixtureEnvFile} (bearer TTL-checked/re-minted pre-exec)`);
	const child = spawn(process.execPath, [driverPath], {
		cwd: REPO_ROOT,
		env,
		stdio: 'inherit',
	});
	for (const signal of ['SIGINT', 'SIGTERM']) {
		process.on(signal, () => child.kill(signal));
	}
	const [code, signal] = await new Promise((resolve) => {
		child.on('exit', (exitCode, exitSignal) => resolve([exitCode, exitSignal]));
	});
	if (code !== null) process.exit(code);
	process.kill(process.pid, signal);
}

// ---------------------------------------------------------------------------
// Self-test — pure in-memory assertions; no network, no writes.
// ---------------------------------------------------------------------------

async function runSelfTest() {
	let checks = 0;
	const check = (label, condition) => {
		if (!condition) fail('SELFTEST', label);
		checks += 1;
	};
	const expectUsageRefusal = (label, fn, expectedTag = 'USAGE') => {
		try {
			fn();
		} catch (error) {
			check(label, error.e6Tag === expectedTag);
			return;
		}
		fail('SELFTEST', `${label}: expected ${expectedTag} refusal, got none`);
	};

	const readyLine = (overrides = {}) =>
		JSON.stringify({
			type: 'e6-client-ready',
			flag: CONNECTIVITY_FLAG,
			mode: 'execute',
			mainPid: 401,
			rendererPid: 402,
			saturationUrl: 'http://127.0.0.1:53121/internal/e6/saturation',
			appOrigin: 'http://127.0.0.1:34567',
			rendered: true,
			memberEmail: 'e6-b@e6.test',
			...overrides,
		});

	const parsed = parseReadyLine(readyLine());
	check('valid readiness line parses', parsed !== null && parsed.mainPid === 401 && parsed.rendererPid === 402);
	check('ready line carries the connectivity flag', parsed?.flag === CONNECTIVITY_FLAG);
	check('ready line carries the rendered/authenticated proof', parsed?.rendered === true && parsed?.memberEmail === 'e6-b@e6.test' && parsed?.appOrigin === 'http://127.0.0.1:34567');
	for (const [label, mutate] of Object.entries({
		'wrong type refuses': (line) => line.replace('e6-client-ready', 'e6-something-else'),
		'non-loopback saturation URL refuses': (line) => line.replace('127.0.0.1:53121', 'example.invalid:80'),
		'self-named renderer refuses': (line) => line.replace('"rendererPid":402', '"rendererPid":401'),
		'pid 0 refuses': (line) => line.replace('"mainPid":401', '"mainPid":0'),
		'foreign flag refuses': (line) => line.replace(CONNECTIVITY_FLAG, 'feature.other'),
		'non-loopback-ish garbage refuses': (line) => line.replace('http://', 'ftp://'),
		'non-boolean rendered refuses': (line) => line.replace('"rendered":true', '"rendered":"yes"'),
		'non-string memberEmail refuses': (line) => line.replace('"memberEmail":"e6-b@e6.test"', '"memberEmail":17'),
		'non-loopback appOrigin refuses': (line) => line.replace('"appOrigin":"http://127.0.0.1:34567"', '"appOrigin":"http://10.0.0.9:34567"'),
		'https appOrigin refuses': (line) => line.replace('"appOrigin":"http://127.0.0.1:34567"', '"appOrigin":"https://127.0.0.1:34567"'),
	})) {
		check(label, parseReadyLine(mutate(readyLine())) === null);
	}
	check('off-mode line with null URL parses', parseReadyLine(readyLine({ mode: 'off', saturationUrl: null }))?.saturationUrl === null);
	check('legacy line without the rendered-proof keys refuses (JSON.stringify omits undefined)', parseReadyLine(readyLine({ appOrigin: undefined, rendered: undefined, memberEmail: undefined })) === null);
	check('electron chatter never parses as readiness', parseReadyLine('[12345:0987:0912:...] INFO:CONSOLE(0) {"type":"e6-client-ready"') === null);
	check('plain JSON noise refuses', parseReadyLine('{"type":"e6-client-ready"}') === null);

	const pairState = {
		schemaVersion: 1,
		kind: 'e6-client-pair-state',
		members: {
			comparator: { member: 'comparator', mode: 'off', mainPid: 401, rendererPid: 402, saturationUrl: null },
			candidate: { member: 'candidate', mode: 'execute', mainPid: 501, rendererPid: 502, saturationUrl: 'http://127.0.0.1:53122/internal/e6/saturation' },
		},
	};
	check('valid pair state passes', validatePairState(pairState).members.candidate.mainPid === 501);
	expectUsageRefusal('wrong kind refuses', () => validatePairState({ ...pairState, kind: 'other' }));
	expectUsageRefusal('missing comparator refuses', () => validatePairState({ ...pairState, members: { candidate: pairState.members.candidate } }));
	expectUsageRefusal('candidate without saturation URL refuses', () =>
		validatePairState({
			...pairState,
			members: { ...pairState.members, candidate: { ...pairState.members.candidate, saturationUrl: null } },
		}));
	expectUsageRefusal('shared main PID refuses', () =>
		validatePairState({
			...pairState,
			members: { ...pairState.members, candidate: { ...pairState.members.candidate, mainPid: 401 } },
		}));

	// Candidate transport seam (scheme v4 §2.3.2): pair-state validation of
	// the optional-job origin — loopback-only, candidate-only, null until the
	// per-window interlock fills it.
	const seamPairState = {
		...pairState,
		members: {
			...pairState.members,
			candidate: { ...pairState.members.candidate, optionalJobOrigin: 'http://127.0.0.1:41000' },
		},
	};
	check('candidate optionalJobOrigin (loopback) passes and normalizes', validatePairState(seamPairState).members.candidate.optionalJobOrigin === 'http://127.0.0.1:41000');
	check('absent optionalJobOrigin normalizes to null', validatePairState(pairState).members.candidate.optionalJobOrigin === null && validatePairState(pairState).members.comparator.optionalJobOrigin === null);
	expectUsageRefusal('non-loopback candidate optionalJobOrigin refuses', () =>
		validatePairState({
			...pairState,
			members: { ...pairState.members, candidate: { ...pairState.members.candidate, optionalJobOrigin: 'http://10.0.0.9:41000' } },
		}));
	expectUsageRefusal('comparator optionalJobOrigin refuses (inert under off)', () =>
		validatePairState({
			...pairState,
			members: { ...pairState.members, comparator: { ...pairState.members.comparator, optionalJobOrigin: 'http://127.0.0.1:41000' } },
		}));

	const live = { liveness: (pid) => pid !== 999 };
	const fixtureEnvText = [
		"# CQ E6 fixture env — run e6-20260920T101034Z-19300 (sourceable; 0600)",
		"export E6_TARGET_URL='http://127.0.0.1:34567'",
		"export E6_DRIVER_GATEWAY_PID='4242'",
		"export E6_DRIVER_CLASS_ROUTES='{\"queued-send\":{\"method\":\"POST\",\"path\":\"/jmap\"}}'",
		"export E6_DRIVER_CLASS_BODIES_MEMBER_A='{\"queued-send\":{\"accountId\":\"5210000001\"}}'",
		"export E6_DRIVER_CLASS_BODIES_MEMBER_B='{\"queued-send\":{\"accountId\":\"5210000002\"}}'",
		"export E6_MEMBER_A_EMAIL='e6-a@e6.test'",
		"export E6_MEMBER_A_PASSWORD='TestPass123!'",
		"export E6_MEMBER_A_BEARER='bearer-A-fresh'",
		"export E6_MEMBER_A_SESSION_COOKIE='access_token=bearer-A-fresh'",
		"export E6_MEMBER_B_EMAIL='e6-b@e6.test'",
		"export E6_MEMBER_B_PASSWORD='TestPass123!'",
		"export E6_MEMBER_B_BEARER='bearer-B-fresh'",
		"export E6_MEMBER_B_SESSION_COOKIE='access_token=bearer-B-fresh'",
	].join('\n');
	const fixtureEnv = parseFixtureEnv(fixtureEnvText);
	check(
		'fixture env parser reads the minted shape and ignores prose',
		fixtureEnv.E6_MEMBER_A_BEARER === 'bearer-A-fresh' &&
			fixtureEnv.E6_MEMBER_B_SESSION_COOKIE === 'access_token=bearer-B-fresh' &&
			fixtureEnv.E6_DRIVER_CLASS_BODIES_MEMBER_B === '{"queued-send":{"accountId":"5210000002"}}' &&
			fixtureEnv.E6_TARGET_URL === 'http://127.0.0.1:34567' &&
			Object.keys(fixtureEnv).length === 13,
	);
	check(
		'fixture env parser is total on garbage',
		Object.keys(parseFixtureEnv('')).length === 0 &&
			parseFixtureEnv("not export\nexport BROKE\nexport OK='v'").OK === 'v',
	);

	// Launch fixture-env slice (the white-screen contract inputs): loopback
	// target + per-member email/password/session cookie, comparator=A,
	// candidate=B.
	check('launch fixture env slice validates', validateLaunchFixtureEnv(fixtureEnv) === 'http://127.0.0.1:34567');
	expectUsageRefusal('launch fixture env without target URL refuses', () =>
		validateLaunchFixtureEnv({ ...fixtureEnv, E6_TARGET_URL: undefined }), 'FIXTURE');
	expectUsageRefusal('non-loopback launch target refuses', () =>
		validateLaunchFixtureEnv({ ...fixtureEnv, E6_TARGET_URL: 'http://gateway.e6.internal:80/' }), 'FIXTURE');
	expectUsageRefusal('member B session cookie missing refuses', () =>
		validateLaunchFixtureEnv({ ...fixtureEnv, E6_MEMBER_B_SESSION_COOKIE: undefined }), 'FIXTURE');

	// Rendered/authenticated readiness cross-checks (the launcher half of the
	// client's probe gate).
	const goodReady = { mainPid: 501, rendererPid: 502, saturationUrl: 'http://127.0.0.1:53122/internal/e6/saturation', appOrigin: 'http://127.0.0.1:34567', rendered: true, memberEmail: 'e6-b@e6.test' };
	check('candidate readiness against the right member/origin passes', (validateMemberReadiness('candidate', goodReady, fixtureEnv), true));
	check('comparator readiness against member A passes', (validateMemberReadiness('comparator', { ...goodReady, memberEmail: 'e6-a@e6.test' }, fixtureEnv), true));
	const legacyBundledReady = parseReadyLine(readyLine({ rendered: false, appOrigin: null, memberEmail: null }));
	check('legacy bundled-load line parses but the readiness validator refuses it (white-screen class)', (() => {
		if (legacyBundledReady === null) return false;
		try {
			validateMemberReadiness('candidate', legacyBundledReady, fixtureEnv);
			return false;
		} catch (error) {
			return error.e6Tag === 'READINESS' && /rendered=false/.test(error.message);
		}
	})());
	expectUsageRefusal('rendered=false readiness refuses (white/no-render class)', () =>
		validateMemberReadiness('candidate', { ...goodReady, rendered: false }, fixtureEnv), 'READINESS');
	expectUsageRefusal('wrong-member identity refuses', () =>
		validateMemberReadiness('candidate', { ...goodReady, memberEmail: 'e6-a@e6.test' }, fixtureEnv), 'READINESS');
	expectUsageRefusal('missing memberEmail refuses', () =>
		validateMemberReadiness('candidate', { ...goodReady, memberEmail: null }, fixtureEnv), 'READINESS');
	expectUsageRefusal('null appOrigin (bundled load) refuses', () =>
		validateMemberReadiness('candidate', { ...goodReady, appOrigin: null }, fixtureEnv), 'READINESS');
	expectUsageRefusal('different-origin appOrigin refuses', () =>
		validateMemberReadiness('candidate', { ...goodReady, appOrigin: 'http://127.0.0.1:9999' }, fixtureEnv), 'READINESS');

	// P1-1 arms: per-member credential/bodies resolution (comparator=A,
	// candidate=B), other-member key stripping, decoy replacement.
	const comparatorEnv = resolveMemberEnv(
		'comparator',
		pairState,
		{
			E6_FLAG: 'off',
			E6_DRIVER_SATURATION_URL: 'http://127.0.0.1:9/x',
			E6_DRIVER_GATEWAY_PID: '7',
			E6_DRIVER_AUTH_BEARER: 'stale-operator-decoy',
			E6_DRIVER_CLASS_BODIES: '{"wrong":true}',
			E6_MEMBER_B_BEARER: 'bearer-B-decoy',
			E6_DRIVER_CLASS_BODIES_MEMBER_B: '{"b-decoy":true}',
		},
		{ ...live, fixtureEnv },
	);
	check('comparator env points at the comparator instance', comparatorEnv.E6_DRIVER_MAIN_PID === '401' && comparatorEnv.E6_DRIVER_RENDERER_PID === '402');
	check('comparator env strips any saturation URL', comparatorEnv.E6_DRIVER_SATURATION_URL === undefined);
	check('comparator env passes the gateway through', comparatorEnv.E6_DRIVER_GATEWAY_PID === '7');
	check('comparator env carries member A bearer and A bodies', comparatorEnv.E6_DRIVER_AUTH_BEARER === 'bearer-A-fresh' && comparatorEnv.E6_DRIVER_CLASS_BODIES === '{"queued-send":{"accountId":"5210000001"}}');
	check('comparator env replaces stale operator credential decoys', comparatorEnv.E6_DRIVER_AUTH_BEARER !== 'stale-operator-decoy' && comparatorEnv.E6_DRIVER_CLASS_BODIES !== '{"wrong":true}');
	check('comparator env strips every other-member (B) key', Object.keys(comparatorEnv).every((key) => !key.startsWith('E6_MEMBER_B_') && key !== 'E6_DRIVER_CLASS_BODIES_MEMBER_B'));
	check('comparator env does not synthesize per-member keys the harness env never carried', comparatorEnv.E6_MEMBER_A_BEARER === undefined);
	const candidateEnv = resolveMemberEnv('candidate', pairState, { E6_MEMBER_A_BEARER: 'bearer-A-decoy' }, { ...live, fixtureEnv });
	check('candidate env points at the candidate instance with the endpoint', candidateEnv.E6_DRIVER_MAIN_PID === '501' && candidateEnv.E6_DRIVER_SATURATION_URL === pairState.members.candidate.saturationUrl);
	check('candidate env carries member B bearer and B bodies', candidateEnv.E6_DRIVER_AUTH_BEARER === 'bearer-B-fresh' && candidateEnv.E6_DRIVER_CLASS_BODIES === '{"queued-send":{"accountId":"5210000002"}}');
	check('candidate env strips every other-member (A) key', Object.keys(candidateEnv).every((key) => !key.startsWith('E6_MEMBER_A_') && key !== 'E6_DRIVER_CLASS_BODIES_MEMBER_A'));
	check('base env is never mutated', pairState.members.candidate.mainPid === 501 && fixtureEnv.E6_MEMBER_A_BEARER === 'bearer-A-fresh');
	expectUsageRefusal('unknown member refuses', () => resolveMemberEnv('observer', pairState, {}, live));
	expectUsageRefusal('dead measured role refuses', () => resolveMemberEnv('candidate', { ...pairState, members: { ...pairState.members, candidate: { ...pairState.members.candidate, mainPid: 999 } } }, {}, { ...live, fixtureEnv }));
	expectUsageRefusal('missing fixture env refuses (fail-closed, no credential-free exec)', () => resolveMemberEnv('comparator', pairState, {}, live), 'FIXTURE');
	expectUsageRefusal('missing member bearer refuses', () =>
		resolveMemberEnv('candidate', pairState, {}, { ...live, fixtureEnv: { ...fixtureEnv, E6_MEMBER_B_BEARER: '' } }), 'CREDENTIAL');
	expectUsageRefusal('missing member class bodies refuse', () =>
		resolveMemberEnv('comparator', pairState, {}, { ...live, fixtureEnv: { E6_MEMBER_A_BEARER: 'bearer-A-fresh' } }), 'CREDENTIAL');

	// Candidate transport seam arms (scheme v4 §2.3.2): the harness-declared
	// window proxy origin is forwarded for the candidate only, validated
	// loopback fail-closed, and stripped everywhere else (decoys included).
	const seamCandidateEnv = resolveMemberEnv(
		'candidate',
		pairState,
		{ E6_CANDIDATE_OPTIONAL_JOB_ORIGIN: 'http://127.0.0.1:41000', E6_OPTIONAL_JOB_ORIGIN: 'operator-decoy' },
		{ ...live, fixtureEnv },
	);
	check('candidate env forwards the harness-declared window proxy origin as the optional-job seam', seamCandidateEnv.E6_OPTIONAL_JOB_ORIGIN === 'http://127.0.0.1:41000');
	check('candidate env strips the harness-internal seam key after forwarding', seamCandidateEnv.E6_CANDIDATE_OPTIONAL_JOB_ORIGIN === undefined);
	check('candidate env overrides any operator-exported optionalJobOrigin decoy with the harness value', seamCandidateEnv.E6_OPTIONAL_JOB_ORIGIN !== 'operator-decoy');
	const noSeamCandidateEnv = resolveMemberEnv('candidate', pairState, { E6_OPTIONAL_JOB_ORIGIN: 'operator-decoy' }, { ...live, fixtureEnv });
	check('candidate env without a harness-declared seam carries no optional-job origin (decoy stripped)', noSeamCandidateEnv.E6_OPTIONAL_JOB_ORIGIN === undefined);
	expectUsageRefusal('non-loopback harness-declared seam refuses (fail-closed)', () =>
		resolveMemberEnv('candidate', pairState, { E6_CANDIDATE_OPTIONAL_JOB_ORIGIN: 'http://10.0.0.9:41000' }, { ...live, fixtureEnv }), 'SEAM');
	const seamStrippedComparatorEnv = resolveMemberEnv(
		'comparator',
		pairState,
		{ E6_CANDIDATE_OPTIONAL_JOB_ORIGIN: 'http://127.0.0.1:41000', E6_OPTIONAL_JOB_ORIGIN: 'operator-decoy' },
		{ ...live, fixtureEnv },
	);
	check('comparator env strips a mis-declared candidate seam and carries no optional-job origin', seamStrippedComparatorEnv.E6_CANDIDATE_OPTIONAL_JOB_ORIGIN === undefined && seamStrippedComparatorEnv.E6_OPTIONAL_JOB_ORIGIN === undefined);

	// Remint decision-table arms (the nightly-17 pair-16 429 fix): the wrapper
	// must skip a fresh bearer, retry a rate-limited (429) login once, defer to
	// a still-fresh bearer on a second 429, and keep failing closed everywhere
	// else. The fixture login is mocked through the injectable run seam.
	const REMINT_T0_MS = 1_700_000_000_000;
	const jwtWithExp = (exp) => `hdr.${Buffer.from(JSON.stringify({ exp })).toString('base64url')}.sig`;
	const mintOk = { error: undefined, status: 0, signal: null, stderr: '' };
	const mint429 = { error: undefined, status: 22, signal: null, stderr: 'curl: (22) The requested URL returned error: 429' };
	const mintUnreachable = { error: undefined, status: 7, signal: null, stderr: 'curl: (7) Failed to connect to 127.0.0.1 port 34567' };
	const remintHarness = (responses) => {
		const state = { calls: [], delays: [], logs: [], nowMs: REMINT_T0_MS };
		const opts = {
			run: (cmd, args, runOpts) => {
				state.calls.push({ cmd, args, runOpts });
				return responses[Math.min(state.calls.length, responses.length) - 1];
			},
			nowMs: () => state.nowMs,
			delayMs: async (ms) => {
				state.delays.push(ms);
				state.nowMs += ms;
			},
			logFn: (message) => state.logs.push(message),
		};
		return { state, opts };
	};
	const expectFixtureRefusal = async (label, fn, messageProbe) => {
		try {
			await fn();
		} catch (error) {
			check(label, error.e6Tag === 'FIXTURE' && (messageProbe === undefined || messageProbe.test(error.message)));
			return;
		}
		fail('SELFTEST', `${label}: expected FIXTURE refusal, got none`);
	};

	check('jwt exp decoder reads the base64url payload segment', decodeJwtExpSeconds(jwtWithExp(1234)) === 1234);
	check(
		'jwt exp decoder refuses non-JWT / garbage / missing or non-numeric exp',
		[null, undefined, '', 'opaque-bearer', 'a.b', 'a.b.c', `hdr.${Buffer.from('not json').toString('base64url')}.sig`, `hdr.${Buffer.from('{"exp":"soon"}').toString('base64url')}.sig`].every(
			(bearer) => decodeJwtExpSeconds(bearer) === null,
		),
	);

	{
		const { state, opts } = remintHarness([mintOk]);
		await remintMemberBearer('comparator', jwtWithExp(REMINT_T0_MS / 1000 + 3600), opts);
		check('skip-if-fresh arm: a bearer with 3600s of TTL left never invokes the fixture login', state.calls.length === 0);
		check('skip-if-fresh arm logs the named e6-remint-skip line with the seconds remaining', state.logs.some((m) => m.includes('e6-remint-skip') && m.includes('3600s')));
	}
	{
		const { state, opts } = remintHarness([mintOk]);
		await remintMemberBearer('candidate', jwtWithExp(REMINT_T0_MS / 1000 - 10), opts);
		check('expired-bearer arm: an expired bearer forces exactly one fixture login for the right member', state.calls.length === 1 && state.calls[0].args[2] === 'b' && state.calls[0].runOpts.timeout === LOGIN_MINT_TIMEOUT_MS);
		check('expired-bearer arm waits no backoff and logs no skip/defer', state.delays.length === 0 && state.logs.every((m) => !m.includes('e6-remint-skip') && !m.includes('e6-remint-deferred')));
	}
	{
		const { state, opts } = remintHarness([mintOk]);
		await remintMemberBearer('comparator', 'opaque-bearer-no-jwt', opts);
		check('unparseable-exp arm: a bearer without a decodable exp forces a mint (never skipped)', state.calls.length === 1);
	}
	{
		const { state, opts } = remintHarness([mint429, mintOk]);
		await remintMemberBearer('comparator', jwtWithExp(REMINT_T0_MS / 1000 + 400), opts);
		check('429-then-success arm: the rate-limited login waits 60s and the retry succeeds', state.calls.length === 2 && state.delays.length === 1 && state.delays[0] === REMINT_429_RETRY_DELAY_MS);
	}
	{
		const { state, opts } = remintHarness([mint429, mint429]);
		await remintMemberBearer('candidate', jwtWithExp(REMINT_T0_MS / 1000 + 500), opts);
		check('429-twice-fresh-fallback arm: a second 429 defers to a bearer still holding 440s', state.calls.length === 2 && state.delays.length === 1);
		check('429-twice-fresh-fallback arm logs the named e6-remint-deferred line with seconds remaining', state.logs.some((m) => m.includes('e6-remint-deferred') && m.includes('440s')));
	}
	{
		const { state, opts } = remintHarness([mint429, mint429]);
		await expectFixtureRefusal(
			'429-twice-no-fallback arm: a second 429 with only 120s of TTL fails closed after the backoff',
			() => remintMemberBearer('comparator', jwtWithExp(REMINT_T0_MS / 1000 + 120), opts),
			/after the 429 backoff retry/,
		);
		check('429-twice-no-fallback arm made the single backoff wait before failing', state.calls.length === 2 && state.delays.length === 1 && state.delays[0] === REMINT_429_RETRY_DELAY_MS);
	}
	{
		const { state, opts } = remintHarness([mint429, mint429]);
		await expectFixtureRefusal(
			'429-twice-unparseable-exp arm: a second 429 with no decodable exp fails closed (no fresh proof)',
			() => remintMemberBearer('candidate', 'opaque-bearer-no-jwt', opts),
			/after the 429 backoff retry/,
		);
	}
	{
		const { state, opts } = remintHarness([mintUnreachable]);
		await expectFixtureRefusal(
			'non-429 arm: a fixture-unreachable login fails closed immediately (no retry, no defer)',
			() => remintMemberBearer('comparator', jwtWithExp(REMINT_T0_MS / 1000 + 400), opts),
			/exit 7/,
		);
		check('non-429 arm invoked the login exactly once and never waited', state.calls.length === 1 && state.delays.length === 0);
	}

	const exportBlock = buildExportBlock('candidate', pairState.members.candidate);
	check('export block is the harness-expected shape', exportBlock.includes('export E6_DRIVER_MAIN_PID=501') && exportBlock.includes('export E6_DRIVER_SATURATION_URL=http://127.0.0.1:53122/internal/e6/saturation'));
	check('export block without a seam origin emits no optional-job line', !exportBlock.includes('E6_OPTIONAL_JOB_ORIGIN'));
	const seamExportBlock = buildExportBlock('candidate', { ...pairState.members.candidate, optionalJobOrigin: 'http://127.0.0.1:41000' });
	check('export block emits the optional-job seam only when the window proxy origin is known', seamExportBlock.includes('export E6_OPTIONAL_JOB_ORIGIN=http://127.0.0.1:41000'));
	const comparatorBlock = buildExportBlock('comparator', pairState.members.comparator);
	check('comparator export block carries no saturation URL', !comparatorBlock.includes('SATURATION_URL'));
	check('comparator export block never carries the optional-job seam', !comparatorBlock.includes('E6_OPTIONAL_JOB_ORIGIN'));

	check('loopback detection: loopback hosts', ['http://127.0.0.1:1/x', 'http://localhost:1/x'].every((url) => isLoopbackUrl(url)));
	check('loopback detection matches the driver validator (bracketed IPv6 refused there too)', !isLoopbackUrl('http://[::1]:1/x'));
	check('loopback detection: non-loopback refused', ['http://10.0.0.1:1/', 'https://127.0.0.1:1/', 'not a url'].every((url) => !isLoopbackUrl(url)));

	process.stdout.write(`e6-client-pair-launch self-test: PASS (${checks} assertions)\n`);
}

// ---------------------------------------------------------------------------
// CLI.
// ---------------------------------------------------------------------------

function usage() {
	process.stdout.write(`Usage:
  bash scripts/e6-client-pair-launch.sh                    launch the pair (build once,
                                                           re-mint the fixture member
                                                           sessions, readiness wait, print
                                                           the harness-expected PID blocks,
                                                           hold). Requires the live fixture
                                                           (bash scripts/e6-gateway-fixture.sh
                                                           up): the windows load the
                                                           gateway-served webmail and must
                                                           boot logged in.
  bash scripts/e6-client-pair-launch.sh --smoke            validation: tear down right
                                                           after readiness is verified
  bash scripts/e6-client-pair-launch.sh --no-build         skip the client build step
  bash scripts/e6-client-pair-launch.sh --ready-timeout-ms <n>
  node scripts/e6-client-pair-launch.mjs --driver-wrapper <driver.mjs>
                                                           harness-spawned per-member
                                                           PID/saturation/credential
                                                           resolver (requires
                                                           E6_CLIENT_PAIR_STATE; TTL-checks
                                                           the member bearer and
                                                           re-mints it via the
                                                           fixture login subcommand
                                                           only when needed,
                                                           429-tolerant; resolves
                                                           the member env from
                                                           e6-fixture.env — override the
                                                           file with E6_FIXTURE_ENV)
  bash scripts/e6-client-pair-launch.sh --self-test        pure in-memory assertions
  -h, --help                                               this text

Readiness is rendered+authenticated: a ready line only counts when the client's
in-page probe observed the authenticated webmail shell at the fixture gateway
origin, signed in as the right member. The pair launcher is readiness item
"Client-pair launch wiring" of retired-docs:verification/2026-09-19-connectivity-e6-harness.md.
See the module header for the env seams (SETJOIN_E6_*), the wrapper rationale,
the white-screen defect history, and the honesty posture.
`);
}

async function main() {
	const argv = process.argv.slice(2);
	if (argv.includes('-h') || argv.includes('--help')) {
		usage();
		return;
	}
	if (argv.includes('--self-test')) {
		await runSelfTest();
		return;
	}
	if (argv.includes('--driver-wrapper')) {
		await runDriverWrapper(argv);
		return;
	}
	try {
		await runLaunchMode(argv);
	} catch (error) {
		if (error instanceof LaunchError) {
			log(`fatal ${error.message}`);
			process.exitCode = 1;
			return;
		}
		throw error;
	}
}

main().catch((error) => {
	process.stderr.write(`e6-client-pair-launch: fatal ${error?.stack ?? error}\n`);
	process.exit(1);
});
