//! E6 saturation-status endpoint + harness readiness composition for the
//! Electron main process (the MEET M5 `localCapture` composition genre:
//! origin-gated loopback surface, INERT unless the flag admits it, wired once
//! from the composition root).
//!
//! WHY THIS EXISTS: the E6 paired-run harness
//! (`scripts/run-connectivity-e6-harness.mjs`, frozen profile
//! `e6-electron-macos-arm64-v1`) requires its candidate member to declare
//! optional-work saturation with an explicit basis. The strongest basis
//! (`saturation-endpoint-verified`) needs a loopback URL answering
//! `{"saturating":<bool>}` that the workload driver polls during the
//! measurement window. This module is that endpoint, plus the harness
//! readiness line the pair launcher (`scripts/e6-client-pair-launch.mjs`)
//! parses for the measured main/renderer PIDs.
//!
//! HONESTY POSTURE (read before wiring the endpoint into a claim): the E4-I
//! coordinator owns the real optional-work queue and it lives in the webmail
//! TypeScript layer (`mailserver/webmail/src/lib/offline/coordinator.ts`),
//! composed at webmail boot behind the projected flag pair
//! (`mailserver/webmail/src/lib/offline/boot.ts`). When the composed webmail
//! exposes its queue state through the renderer-side
//! `window.__setjoinConnectivityQueueState` global, this endpoint polls it
//! through the window bridge (`webContents.executeJavaScript`, the same
//! mechanism as the render probe) and answers REAL queue depth with
//! `"basis":"engine-queue-observed"`. When the read fails, times out, or the
//! global is absent (pair OFF, comparator, plain webmail without the
//! composition), the endpoint falls back to the ROLLOUT MODE declaration —
//! `execute` means the engine's optional-work admission is open for the whole
//! measurement window, `off`/`observe` admit nothing — and the body says
//! exactly that: `"basis":"policy-mode-configured"` with
//! `"engineQueueState":"not-exposed-in-this-build"`. A driver run against the
//! fallback records `saturation-endpoint-verified` (every poll confirmed
//! `true`) — that recorded label must be read at claim time as the weaker
//! policy-mode declaration until the body carries the observed basis. The
//! flag-OFF comparator instance never listens at all: under `off` this
//! surface starts no server, prints no URL, and performs nothing.
//!
//! ORIGIN GATE: the server binds 127.0.0.1 on an ephemeral port only — it is
//! unreachable off-host by construction, and the launcher passes the printed
//! URL to the driver through `E6_DRIVER_SATURATION_URL`, which the driver
//! itself validates loopback. No other path answers (404), no other method
//! answers (405), and the body carries no secrets (mode strings, a flag name,
//! and content-free queue counters only).

import * as http from "node:http";

import {
	CONNECTIVITY_SYNC_APP_ORIGIN_ENV,
	CONNECTIVITY_SYNC_MEMBER_EMAIL_ENV,
	CONNECTIVITY_SYNC_MEMBER_PASSWORD_ENV,
	CONNECTIVITY_SYNC_SESSION_COOKIE_ENV,
	E6_APP_ENTRY_PATH,
	type E6SessionCookie,
	type RenderProbe,
	RENDER_PROBE_SCRIPT,
	parseRenderProbe,
	readinessFromProbe,
	resolveE6HarnessAppOrigin,
	resolveE6HarnessMemberCredentials,
	resolveE6HarnessSessionCookie,
} from "./appOrigin";
import {
	CONNECTIVITY_AWARE_SYNC_FLAG,
	CONNECTIVITY_SYNC_MODE_ENV,
	CONNECTIVITY_SYNC_USER_DATA_ENV,
	resolveConnectivitySyncRolloutMode,
	statusAdmitted,
	type ConnectivitySyncRolloutMode,
} from "./rollout";

/** The single path the status server answers on. Anything else is a 404. */
export const SATURATION_STATUS_PATH = "/internal/e6/saturation";

/** Queue-state honesty markers carried in every response body. */
export const SATURATION_BASIS_CONFIGURED = "policy-mode-configured";
export const SATURATION_BASIS_ADMITS_NONE = "mode-admits-no-optional-work";
export const SATURATION_BASIS_ENGINE_OBSERVED = "engine-queue-observed";
const ENGINE_QUEUE_STATE = "not-exposed-in-this-build";

/**
 * The renderer-side global the composed webmail installs
 * (`mailserver/webmail/src/lib/offline/boot.ts` — the names are pinned on
 * BOTH sides; there is no shared module across the two builds). The main
 * process reads it through the same window bridge as the render probe.
 */
export const CONNECTIVITY_QUEUE_STATE_GLOBAL = "__setjoinConnectivityQueueState";

/** Bounded in-page probe: resolves the queue-state snapshot object, or null
 *  on any absence/shape/throw — never readiness by forgery. */
export const QUEUE_STATE_PROBE_SCRIPT =
	`(async () => { try { const fn = window[${JSON.stringify(CONNECTIVITY_QUEUE_STATE_GLOBAL)}];` +
	" if (typeof fn !== 'function') return null;" +
	" const state = await fn();" +
	" return state && typeof state === 'object' ? state : null;" +
	" } catch { return null; } })()";

/** One queue-state read may hold the HTTP answer for at most this long; past
 *  it the endpoint answers from the policy-mode declaration (the honest
 *  fallback — a hung renderer must not hang the driver's poll). */
const QUEUE_STATE_READ_TIMEOUT_MS = 1_000;

/**
 * The REAL queue/work state as the composed webmail reports it. Strict parse:
 * the basis marker must be the observed one, the counters must be non-negative
 * safe integers, and `saturating` must AGREE with the numbers it reports — a
 * renderer cannot declare work without queue/running depth backing it.
 * `policyBasis` (which admission-policy path the engine is running under —
 * including `no-projection`, the neither-projection-nor-seam OFF stand-in the
 * live policy re-read reports after a session drops its projection) and the
 * content-free trigger counters ride through into the response body so
 * run artifacts stay self-describing.
 */
export interface EngineQueueState {
	queueDepth: number;
	running: number;
	saturating: boolean;
	observedAtUtc: string;
	policyBasis?: "session-projected" | "harness-seam" | "no-projection";
	triggersIngested?: number;
	triggersCoalesced?: number;
	lastTriggerKind?: string;
}

const TRIGGER_KINDS = new Set([
	"foreground",
	"reconnect",
	"authenticatedPush",
	"nativeOpportunity",
	"action",
]);

function isCount(value: unknown): value is number {
	return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

/** The finite platform-gate reasons the webmail composition may report for a
 *  refused (but flag-admitted) composition attempt. Inert cases never reach
 *  the window surface at all. */
const ENGINE_GATE_REASONS = new Set([
	"no-native-bridge",
	"no-durable-persistence",
	"store-init-failed",
]);

/**
 * Recognize the webmail's gate diagnostic: the flag-pair gates ADMITTED but
 * the platform capability refused. Distinct from a queue state (composed
 * true) and from absence (no global at all — the inert cases).
 */
export function parseEngineGate(value: unknown): string | null {
	if (typeof value !== "object" || value === null) return null;
	const v = value as Record<string, unknown>;
	if (v.composed !== false) return null;
	if (typeof v.reason !== "string" || !ENGINE_GATE_REASONS.has(v.reason)) return null;
	return v.reason;
}

export function parseEngineQueueState(value: unknown): EngineQueueState | null {
	if (typeof value !== "object" || value === null) return null;
	const v = value as Record<string, unknown>;
	if (v.composed !== true || v.basis !== SATURATION_BASIS_ENGINE_OBSERVED) return null;
	if (!isCount(v.queueDepth) || !isCount(v.running) || typeof v.saturating !== "boolean")
		return null;
	if (typeof v.observedAtUtc !== "string" || v.observedAtUtc === "") return null;
	if (v.saturating !== v.queueDepth + v.running > 0) return null;
	let policyBasis: EngineQueueState["policyBasis"];
	if (v.policyBasis !== undefined) {
		if (
			v.policyBasis !== "session-projected" &&
			v.policyBasis !== "harness-seam" &&
			v.policyBasis !== "no-projection"
		) {
			return null;
		}
		policyBasis = v.policyBasis;
	}
	let lastTriggerKind: string | undefined;
	if (v.lastTriggerKind !== undefined) {
		if (typeof v.lastTriggerKind !== "string") return null;
		if (v.lastTriggerKind !== "" && !TRIGGER_KINDS.has(v.lastTriggerKind)) return null;
		lastTriggerKind = v.lastTriggerKind;
	}
	if (v.triggersIngested !== undefined && !isCount(v.triggersIngested)) return null;
	if (v.triggersCoalesced !== undefined && !isCount(v.triggersCoalesced)) return null;
	return {
		queueDepth: v.queueDepth,
		running: v.running,
		saturating: v.saturating,
		observedAtUtc: v.observedAtUtc,
		...(policyBasis === undefined ? {} : { policyBasis }),
		...(v.triggersIngested === undefined ? {} : { triggersIngested: v.triggersIngested }),
		...(v.triggersCoalesced === undefined ? {} : { triggersCoalesced: v.triggersCoalesced }),
		...(lastTriggerKind === undefined ? {} : { lastTriggerKind }),
	};
}

export interface SaturationDeclaration {
	saturating: boolean;
	basis: string;
}

/**
 * The honest saturation declaration for a rollout mode. `execute` reports the
 * open optional-work admission (`policy-mode-configured` — see the header for
 * why this is NOT a queue-depth observation); `off`/`observe` admit no
 * optional work and report exactly that.
 */
export function saturatingForMode(mode: ConnectivitySyncRolloutMode): SaturationDeclaration {
	if (mode === "execute") {
		return { saturating: true, basis: SATURATION_BASIS_CONFIGURED };
	}
	return { saturating: false, basis: SATURATION_BASIS_ADMITS_NONE };
}

export interface SaturationStatusServer {
	/** Full loopback URL the driver polls (`E6_DRIVER_SATURATION_URL`). */
	endpoint: string;
	/** Actual bind port (the ephemeral port the OS assigned). */
	port: number;
	requests: number;
	close(): Promise<void>;
}

/**
 * Start the loopback-only status server. Binds 127.0.0.1 on an EPHEMERAL port
 * (port 0 — the launcher learns the URL from the ready line, never a config
 * file). Under rollout mode `off` this is INERT: it starts nothing and
 * resolves to null, so the flag-off comparator instance provably serves no
 * saturation surface.
 *
 * `readEngineQueueState` (the composition root passes a bounded
 * `webContents.executeJavaScript(QUEUE_STATE_PROBE_SCRIPT)` closure): when a
 * poll produces a VALID `EngineQueueState`, the body answers REAL queue depth
 * with the `engine-queue-observed` basis; every failure mode (no global,
 * wrong shape, throw, timeout) falls back to the policy-mode declaration —
 * the body always names the basis it actually used.
 */
export function startSaturationStatusServer({
	mode,
	host = "127.0.0.1",
	readEngineQueueState = null,
	log = () => {},
}: {
	mode: ConnectivitySyncRolloutMode;
	host?: string;
	readEngineQueueState?: (() => Promise<unknown>) | null;
	/** Named-line sink for the basis-regression marker below (the
	 *  composition root passes its stdout log; tests default to no-op). */
	log?: (line: string) => void;
}): Promise<SaturationStatusServer | null> {
	if (!statusAdmitted(mode)) {
		return Promise.resolve(null);
	}
	const declaration = saturatingForMode(mode);
	// The basis of the LAST answered poll (regression tracking below).
	let lastAnsweredBasis: string | null = null;
	const answer = async (): Promise<Record<string, unknown>> => {
		if (readEngineQueueState !== null) {
			const raw = await readWithTimeout(readEngineQueueState, QUEUE_STATE_READ_TIMEOUT_MS);
			const parsed = parseEngineQueueState(raw);
			if (parsed !== null) {
				return {
					saturating: parsed.saturating,
					basis: SATURATION_BASIS_ENGINE_OBSERVED,
					flag: CONNECTIVITY_AWARE_SYNC_FLAG,
					mode,
					engineQueueState: {
						queueDepth: parsed.queueDepth,
						running: parsed.running,
						observedAtUtc: parsed.observedAtUtc,
						...(parsed.policyBasis === undefined ? {} : { policyBasis: parsed.policyBasis }),
						...(parsed.triggersIngested === undefined
							? {}
							: { triggersIngested: parsed.triggersIngested }),
						...(parsed.triggersCoalesced === undefined
							? {}
							: { triggersCoalesced: parsed.triggersCoalesced }),
						...(parsed.lastTriggerKind === undefined
							? {}
							: { lastTriggerKind: parsed.lastTriggerKind }),
					},
				};
			}
			const gate = parseEngineGate(raw);
			if (gate !== null) {
				return {
					saturating: declaration.saturating,
					basis: declaration.basis,
					flag: CONNECTIVITY_AWARE_SYNC_FLAG,
					mode,
					engineQueueState: { gate },
				};
			}
		}
		return {
			saturating: declaration.saturating,
			basis: declaration.basis,
			flag: CONNECTIVITY_AWARE_SYNC_FLAG,
			mode,
			engineQueueState: ENGINE_QUEUE_STATE,
		};
	};
	const server = http.createServer((request, response) => {
		const path = (request.url ?? "").split("?")[0];
		if (path !== SATURATION_STATUS_PATH) {
			response.writeHead(404, { "content-type": "application/json" });
			response.end('{"error":"not-found"}');
			return;
		}
		if (request.method !== "GET") {
			response.writeHead(405, { "content-type": "application/json" });
			response.end('{"error":"method-not-allowed"}');
			return;
		}
		// Basis-regression marker (e6-client-session-refresh genre; no behavior
		// change): once a poll answered the REAL queue observation, a later
		// poll falling back to the policy-mode declaration is exactly when an
		// `engine-queue-observed` claim goes stale mid-run — name the
		// transition on stdout so run logs carry it. The HTTP bodies are
		// unchanged; only the regression edge prints.
		const answerWith = (body: Record<string, unknown>): void => {
			const basis = typeof body.basis === "string" ? body.basis : null;
			if (
				lastAnsweredBasis === SATURATION_BASIS_ENGINE_OBSERVED &&
				basis !== null &&
				basis !== SATURATION_BASIS_ENGINE_OBSERVED
			) {
				log(
					JSON.stringify({
						type: "e6-client-saturation-basis-regressed",
						atUtc: isoUtcNow(),
						mode,
						from: lastAnsweredBasis,
						to: basis,
					}),
				);
			}
			lastAnsweredBasis = basis;
			response.writeHead(200, { "content-type": "application/json" });
			response.end(JSON.stringify(body));
		};
		void answer().then(
			(body) => answerWith(body),
			() => {
				// A queue-state read failure is a fallback, never a dead poll:
				// answer from the declaration (the basis names it).
				answerWith({
					saturating: declaration.saturating,
					basis: declaration.basis,
					flag: CONNECTIVITY_AWARE_SYNC_FLAG,
					mode,
					engineQueueState: ENGINE_QUEUE_STATE,
				});
			},
		);
	});
	const sockets = new Set<import("node:net").Socket>();
	// Track connections so close() is decisive even with keep-alive sockets —
	// the launcher's teardown receipt must mean "nothing of this instance
	// survives", and the driver polls once per second.
	server.on("connection", (socket) => {
		sockets.add(socket);
		socket.on("close", () => sockets.delete(socket));
	});
	return new Promise((resolve, reject) => {
		server.once("error", reject);
		server.listen(0, host, () => {
			const address = server.address();
			if (address === null || typeof address === "string") {
				reject(
					new Error(`saturation status server bound an unexpected address: ${String(address)}`),
				);
				return;
			}
			resolve({
				endpoint: `http://${host}:${address.port}${SATURATION_STATUS_PATH}`,
				port: address.port,
				requests: 0,
				close: () =>
					new Promise<void>((resolveClose) => {
						for (const socket of sockets) socket.destroy();
						sockets.clear();
						server.close(() => resolveClose());
					}),
			});
		});
	});
}

/** Resolve with the reader's value, or null on throw OR after `timeoutMs` —
 *  a hung renderer must not hang the driver's poll. */
async function readWithTimeout(read: () => Promise<unknown>, timeoutMs: number): Promise<unknown> {
	let timer: NodeJS.Timeout | undefined;
	try {
		return await Promise.race([
			read(),
			new Promise<null>((resolve) => {
				timer = setTimeout(() => resolve(null), timeoutMs);
			}),
		]);
	} catch {
		return null;
	} finally {
		if (timer) clearTimeout(timer);
	}
}

export interface ClientReadyInfo {
	mode: ConnectivitySyncRolloutMode;
	mainPid: number;
	rendererPid: number;
	saturationUrl: string | null;
	/** The loopback app origin the window loaded the gateway-served webmail
	 *  from — null only on the legacy bundled/dev load path (which the pair
	 *  launcher refuses: it cannot prove a rendered app). */
	appOrigin: string | null;
	/** True ONLY when the in-page probe observed the authenticated app-shell
	 *  marker — the rendered proof the launcher's readiness contract requires. */
	rendered: boolean;
	/** The /auth/me identity the window is actually signed in as (the pair
	 *  launcher cross-checks it against the member's fixture email). */
	memberEmail: string | null;
}

/**
 * The single readiness line a harness-managed instance prints on stdout once
 * its first window's renderer has finished loading AND — under the harness
 * app-origin seam — the rendered/authenticated probe passed. The pair launcher
 * parses this exact shape (key order is pinned by the tests); stdout stays
 * otherwise quiet so the launcher's line scan cannot misread Electron/Chromium
 * chatter.
 */
export function formatReadyLine(info: ClientReadyInfo): string {
	return JSON.stringify({
		type: "e6-client-ready",
		flag: CONNECTIVITY_AWARE_SYNC_FLAG,
		mode: info.mode,
		mainPid: info.mainPid,
		rendererPid: info.rendererPid,
		saturationUrl: info.saturationUrl,
		appOrigin: info.appOrigin,
		rendered: info.rendered,
		memberEmail: info.memberEmail,
	});
}

/** The window surface this composition touches — structural so tests (and
 *  the composition root) can pass the real BrowserWindow without importing
 *  electron here. */
export interface HarnessWindowLike {
	webContents: {
		once(event: string, listener: () => void): unknown;
		getOSProcessId(): number;
		/** In-page evaluation used by the render/auth probe and (indirectly)
		 *  by the watchdog's session recovery. */
		executeJavaScript(code: string): Promise<unknown>;
		/** The watchdog's reload of the app entry path after a re-planted
		 *  session cookie. */
		loadURL(url: string): Promise<unknown>;
	};
}

/** Default render-probe budget: 120 probes x 500 ms = 60 s — comfortably
 *  inside the launcher's 90 s readiness deadline, and far past any honest
 *  loopback SPA boot. */
const RENDER_PROBE_ATTEMPTS = 120;
const RENDER_PROBE_INTERVAL_MS = 500;
/** Watchdog cadence and the fail-closed escalation bound: ~20 consecutive
 *  failed refresh cycles (~10 min) of a session the gateway REFUSES (401)
 *  kill the instance — a measured window without a live member session is
 *  invalid evidence, and dying loudly is the honest outcome. Transient
 *  gateway unavailability never counts (the probe reports it separately). */
const SESSION_WATCHDOG_INTERVAL_MS = 30_000;
const SESSION_REFRESH_MAX_CONSECUTIVE_FAILURES = 20;

function isoUtcNow(): string {
	return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

/**
 * The composition-root entry point (called from `main.ts`'s `createWindow`
 * under the root's own once-guard — the `ipcHandlersRegistered` genre — so
 * the FIRST window's renderer is the reported one). Fully INERT unless the
 * instance was launched with the harness user-data seam — unset in every
 * production launch, so production composes nothing, starts nothing, and
 * prints nothing. A set-but-invalid mode env, app origin, or session cookie
 * REFUSES (throws) at composition time: a misflagged pair member must never
 * boot quietly.
 *
 * Readiness semantics: the ready line prints once ALL of the status server
 * has resolved (null under `off`), the first window's renderer finished
 * loading, AND — under the harness app-origin seam — the in-page probe
 * observed the AUTHENTICATED app shell carrying the member's /auth/me
 * identity (bounded probes; a login page, an anonymous session, or an
 * exhausted budget is a named fail-closed fatal, never a ready line). A
 * launcher that saw the line therefore knows the measured renderer process
 * exists, the gateway-served webmail actually RENDERED, and the window is
 * signed in as a concrete member.
 *
 * Session watchdog (only when the member-credential seams are present): the
 * gateway revokes the planted session on every reset-pair and the access
 * token expires on its 1 h TTL, both inside a 2.5-3.5 h run — the watchdog
 * probes the session, re-mints it through the gateway's own login endpoint,
 * re-plants the cookie, and reloads the app entry, printing a named line per
 * recovery; ~10 min of continuous refusal escalates to a fatal (the pair is
 * invalid evidence from that moment).
 *
 * Returns the surface's DISPOSER (idempotent): it stops the session watchdog
 * (and any pending probe loop) so a quitting app — or a test — can tear the
 * composed timers down deterministically. The inert path returns a no-op.
 */
export function composeConnectivityE6HarnessSurface(
	window: HarnessWindowLike,
	{
		env = process.env,
		mainPid = process.pid,
		log = (line) => console.log(line),
		onServer = () => {},
		onFatal = (error) => {
			console.error("connectivity e6 surface composition failed", error);
			process.exit(1);
		},
		setSessionCookie,
		fetchFn = fetch,
		readEngineQueueState = null,
		renderProbeAttempts = RENDER_PROBE_ATTEMPTS,
		renderProbeIntervalMs = RENDER_PROBE_INTERVAL_MS,
		watchdogIntervalMs = SESSION_WATCHDOG_INTERVAL_MS,
		watchdogRefreshFailureLimit = SESSION_REFRESH_MAX_CONSECUTIVE_FAILURES,
	}: {
		env?: NodeJS.ProcessEnv;
		mainPid?: number;
		log?: (line: string) => void;
		onServer?: (server: SaturationStatusServer | null) => void;
		onFatal?: (error: unknown) => void;
		/** Plants the session cookie into the window's session (main.ts passes
		 *  `session.defaultSession.cookies.set` — this module stays
		 *  electron-free). REQUIRED when the app-origin seam is present. */
		setSessionCookie?: (origin: string, cookie: E6SessionCookie) => Promise<void>;
		fetchFn?: typeof fetch;
		/** Bounded window-bridge read of the composed webmail's queue state
		 *  (main.ts passes `webContents.executeJavaScript(QUEUE_STATE_PROBE_SCRIPT)`).
		 *  Absent/null-answering reads keep the policy-mode declaration basis. */
		readEngineQueueState?: (() => Promise<unknown>) | null;
		renderProbeAttempts?: number;
		renderProbeIntervalMs?: number;
		watchdogIntervalMs?: number;
		watchdogRefreshFailureLimit?: number;
	} = {},
): () => void {
	const userDataDir = env[CONNECTIVITY_SYNC_USER_DATA_ENV];
	// Not harness-managed → the surface does not exist at all.
	if (!userDataDir) return () => {};

	const disposers: Array<() => void> = [];
	const onceDisposed = (dispose: () => void) => {
		let done = false;
		disposers.push(() => {
			if (done) return;
			done = true;
			dispose();
		});
	};

	const mode = resolveConnectivitySyncRolloutMode(env[CONNECTIVITY_SYNC_MODE_ENV]);
	const appOrigin = resolveE6HarnessAppOrigin(env[CONNECTIVITY_SYNC_APP_ORIGIN_ENV]);
	const sessionCookie =
		appOrigin !== null
			? (resolveE6HarnessSessionCookie(env[CONNECTIVITY_SYNC_SESSION_COOKIE_ENV]) ??
				(() => {
					throw new Error(
						`${CONNECTIVITY_SYNC_SESSION_COOKIE_ENV} is required with ${CONNECTIVITY_SYNC_APP_ORIGIN_ENV}: ` +
							`a gateway-served window with no member session renders the login page, not the app`,
					);
				})())
			: null;
	if (appOrigin !== null && !setSessionCookie) {
		throw new Error(
			"composeConnectivityE6HarnessSurface requires setSessionCookie under the app-origin seam " +
				"(the session watchdog must be able to re-plant the member cookie)",
		);
	}
	// Const snapshot so the watchdog closure sees a narrowed non-optional
	// planting hook after its own guard (function parameters are re-widened
	// inside closures).
	const plantSessionCookie = setSessionCookie;
	const memberCredentials = resolveE6HarnessMemberCredentials(
		env[CONNECTIVITY_SYNC_MEMBER_EMAIL_ENV],
		env[CONNECTIVITY_SYNC_MEMBER_PASSWORD_ENV],
	);

	const state = {
		rendererPid: null as number | null,
		saturationUrl: null as string | null,
		serverResolved: !statusAdmitted(mode),
		loadFinished: false,
		probeReady: appOrigin === null, // legacy load path: no probe gate
		rendered: false,
		memberEmail: null as string | null,
		printed: false,
	};
	const maybePrint = () => {
		if (!state.serverResolved || !state.loadFinished || !state.probeReady || state.printed) return;
		state.printed = true;
		log(
			formatReadyLine({
				mode,
				mainPid,
				rendererPid: state.rendererPid ?? -1,
				saturationUrl: state.saturationUrl,
				appOrigin,
				rendered: state.rendered,
				memberEmail: state.memberEmail,
			}),
		);
	};

	if (statusAdmitted(mode)) {
		startSaturationStatusServer({ mode, readEngineQueueState, log }).then(
			(server) => {
				onServer(server);
				state.saturationUrl = server?.endpoint ?? null;
				state.serverResolved = true;
				maybePrint();
			},
			(error) => onFatal(error),
		);
	} else {
		onServer(null);
	}

	/** One in-page probe; a rejected/foreign answer is `unavailable`, never
	 *  readiness (the renderer cannot forge readiness with a wrong shape). */
	const probeOnce = async (): Promise<RenderProbe> => {
		try {
			return (
				parseRenderProbe(await window.webContents.executeJavaScript(RENDER_PROBE_SCRIPT)) ?? {
					auth: "unavailable",
					rendered: false,
					loginPage: false,
					email: null,
				}
			);
		} catch {
			return { auth: "unavailable", rendered: false, loginPage: false, email: null };
		}
	};

	const startRenderProbePoll = () => {
		// Disposal stops an in-flight poll loop at its next step boundary.
		let disposed = false;
		onceDisposed(() => {
			disposed = true;
		});
		void (async () => {
			let lastReason = "no-probe";
			for (let attempt = 1; attempt <= renderProbeAttempts; attempt += 1) {
				if (disposed) return;
				const probe = await probeOnce();
				if (disposed) return;
				const verdict = readinessFromProbe(probe);
				if (verdict.ready) {
					state.probeReady = true;
					state.rendered = true;
					state.memberEmail = probe.email;
					maybePrint();
					return;
				}
				lastReason = verdict.reason ?? "not-rendered";
				// A login page is terminal for THIS load (the SPA will not
				// self-recover a session it does not have) — fail now, don't burn
				// the full budget waiting for a white screen to fix itself.
				if (lastReason === "login-page" || lastReason === "session-anonymous") break;
				await sleep(renderProbeIntervalMs);
			}
			if (disposed) return;
			onFatal(
				new Error(
					`e6-client-render-failed: the webmail app did not render an authenticated shell ` +
						`(last probe reason: ${lastReason}; origin ${appOrigin}; ${renderProbeAttempts} probes). ` +
						`This is the white-screen/no-render failure class — the instance cannot measure the ` +
						`coordinator substrate and must not pass readiness.`,
				),
			);
		})();
	};

	const startSessionWatchdog = () => {
		let refreshInFlight = false;
		let consecutiveFailures = 0;
		// After a fatal escalation (or disposal) the watchdog stops driving
		// anything: a custom onFatal may not exit, but a dead session must not
		// keep re-mint attempts (or further fatals) running.
		let stopped = false;
		let timer: NodeJS.Timeout | undefined;
		// Disposal (quit/test teardown) stops the watchdog at the next tick or
		// step boundary — whichever comes first.
		let refreshDisposed = false;
		onceDisposed(() => {
			refreshDisposed = true;
			stopped = true;
			if (timer) clearInterval(timer);
		});
		timer = setInterval(() => {
			if (stopped || refreshInFlight) return;
			refreshInFlight = true;
			void (async () => {
				try {
					const probe = await probeOnce();
					if (stopped || refreshDisposed) return;
					if (probe.auth !== "anonymous") {
						// authenticated (healthy) or unavailable (transient/outage —
						// never a revocation signal): neither re-mints anything.
						if (probe.auth === "authenticated") consecutiveFailures = 0;
						return;
					}
					if (!plantSessionCookie || !appOrigin || !sessionCookie || !memberCredentials) return;
					try {
						const response = await fetchFn(`${appOrigin}/auth/login`, {
							method: "POST",
							headers: { "content-type": "application/json" },
							body: JSON.stringify({
								email: memberCredentials.email,
								password: memberCredentials.password,
							}),
						});
						if (!response.ok) throw new Error(`login responded ${response.status}`);
						const body = (await response.json()) as { access_token?: unknown };
						if (typeof body.access_token !== "string" || body.access_token === "") {
							throw new Error("login response carried no access_token");
						}
						await plantSessionCookie(appOrigin, {
							name: sessionCookie.name,
							value: body.access_token,
						});
						await window.webContents.loadURL(`${appOrigin}${E6_APP_ENTRY_PATH}`);
						consecutiveFailures = 0;
						log(
							JSON.stringify({
								type: "e6-client-session-refresh",
								atUtc: isoUtcNow(),
								memberEmail: memberCredentials.email,
								ok: true,
							}),
						);
					} catch (error) {
						consecutiveFailures += 1;
						log(
							JSON.stringify({
								type: "e6-client-session-refresh-failed",
								atUtc: isoUtcNow(),
								memberEmail: memberCredentials.email,
								attempt: consecutiveFailures,
								error: error instanceof Error ? error.message : String(error),
							}),
						);
						if (consecutiveFailures >= watchdogRefreshFailureLimit) {
							stopped = true;
							if (timer) clearInterval(timer);
							onFatal(
								new Error(
									`e6-client-session-lost: the gateway refused the member session for ` +
										`${consecutiveFailures} consecutive refresh cycles — the window ` +
										`can no longer run the coordinator substrate, so the pair is invalid ` +
										`evidence from this moment`,
								),
							);
						}
					}
				} finally {
					refreshInFlight = false;
				}
			})();
		}, watchdogIntervalMs);
		timer.unref?.();
	};

	window.webContents.once("did-finish-load", () => {
		state.loadFinished = true;
		state.rendererPid = window.webContents.getOSProcessId();
		if (appOrigin !== null) startRenderProbePoll();
		maybePrint();
		if (appOrigin !== null && memberCredentials !== null) startSessionWatchdog();
	});

	return () => {
		for (const dispose of disposers) dispose();
	};
}

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}
