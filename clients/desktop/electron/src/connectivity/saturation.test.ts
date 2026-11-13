import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { APP_SHELL_RENDER_MARKER } from "./appOrigin";
import { CONNECTIVITY_AWARE_SYNC_FLAG } from "./rollout";
import {
	type HarnessWindowLike,
	SATURATION_BASIS_ADMITS_NONE,
	SATURATION_BASIS_CONFIGURED,
	SATURATION_STATUS_PATH,
	composeConnectivityE6HarnessSurface,
	formatReadyLine,
	parseEngineGate,
	parseEngineQueueState,
	saturatingForMode,
	startSaturationStatusServer,
	type SaturationStatusServer,
} from "./saturation";

const USER_DATA_SEAM = { SETJOIN_E6_USER_DATA_DIR: "/tmp/e6-pair-test/comparator-user-data" };
const APP_ORIGIN_SEAM = {
	SETJOIN_E6_APP_ORIGIN: "http://127.0.0.1:34567",
	SETJOIN_E6_SESSION_COOKIE: "access_token=jwt-A",
	SETJOIN_E6_MEMBER_EMAIL: "e6-a@e6.test",
	SETJOIN_E6_MEMBER_PASSWORD: "TestPass123!",
};

/** A probe answer the fake renderer hands back for the next executeJavaScript
 *  call. */
function probe(
	overrides: Partial<{
		auth: string;
		rendered: boolean;
		loginPage: boolean;
		email: string | null;
	}> = {},
) {
	return {
		auth: "authenticated",
		rendered: true,
		loginPage: false,
		email: "e6-a@e6.test",
		...overrides,
	};
}

interface FakeWindowOptions {
	initialProbes?: Array<Record<string, unknown>>;
	onProbesExhausted?: () => Record<string, unknown>;
}

function fakeWindow(
	rendererPid: number,
	{ initialProbes = [], onProbesExhausted = () => probe() }: FakeWindowOptions = {},
): HarnessWindowLike & {
	listeners: Array<() => void>;
	emitDidFinishLoad(): void;
	executeJavaScript: ReturnType<typeof vi.fn>;
	loadURL: ReturnType<typeof vi.fn>;
	setProbe(answer: Record<string, unknown>): void;
} {
	const listeners: Array<() => void> = [];
	const queue = [...initialProbes];
	const executeJavaScript = vi.fn(async (_code: string) =>
		queue.length > 0 ? queue.shift() : onProbesExhausted(),
	);
	const loadURL = vi.fn(async (_url: string) => {});
	return {
		listeners,
		executeJavaScript,
		loadURL,
		webContents: {
			once: (event: string, listener: () => void) => {
				if (event === "did-finish-load") listeners.push(listener);
			},
			getOSProcessId: () => rendererPid,
			executeJavaScript: (code: string) => executeJavaScript(code),
			loadURL: (url: string) => loadURL(url),
		},
		setProbe: (answer: Record<string, unknown>) => {
			queue.length = 0;
			queue.push(answer);
		},
		emitDidFinishLoad: () => {
			for (const listener of listeners) listener();
		},
	};
}

const openServers: SaturationStatusServer[] = [];

afterEach(async () => {
	while (openServers.length > 0) {
		await openServers.pop()?.close();
	}
});

describe("saturatingForMode honesty", () => {
	it("declares open optional-work admission under execute with the policy-mode basis", () => {
		expect(saturatingForMode("execute")).toEqual({
			saturating: true,
			basis: SATURATION_BASIS_CONFIGURED,
		});
		expect(SATURATION_BASIS_CONFIGURED).toBe("policy-mode-configured");
	});

	it("declares no optional work under off and observe", () => {
		expect(saturatingForMode("off")).toEqual({
			saturating: false,
			basis: SATURATION_BASIS_ADMITS_NONE,
		});
		expect(saturatingForMode("observe")).toEqual({
			saturating: false,
			basis: SATURATION_BASIS_ADMITS_NONE,
		});
	});
});

describe("saturation status server", () => {
	it("is inert under the shipped default off: nothing listens", async () => {
		await expect(startSaturationStatusServer({ mode: "off" })).resolves.toBeNull();
	});

	it("binds loopback on an ephemeral port and answers the contract shape", async () => {
		const server = await startSaturationStatusServer({ mode: "execute" });
		expect(server).not.toBeNull();
		if (!server) return;
		openServers.push(server);
		expect(server.endpoint).toBe(`http://127.0.0.1:${server.port}${SATURATION_STATUS_PATH}`);
		expect(server.port).toBeGreaterThan(0);

		const response = await fetch(server.endpoint);
		expect(response.status).toBe(200);
		expect(response.headers.get("content-type")).toContain("application/json");
		expect(await response.json()).toEqual({
			saturating: true,
			basis: "policy-mode-configured",
			flag: CONNECTIVITY_AWARE_SYNC_FLAG,
			mode: "execute",
			engineQueueState: "not-exposed-in-this-build",
		});
	});

	it("answers observe honestly with no saturating work", async () => {
		const server = await startSaturationStatusServer({ mode: "observe" });
		if (!server) throw new Error("observe must admit the read-only status surface");
		openServers.push(server);
		const response = await fetch(server.endpoint);
		expect(await response.json()).toEqual({
			saturating: false,
			basis: "mode-admits-no-optional-work",
			flag: CONNECTIVITY_AWARE_SYNC_FLAG,
			mode: "observe",
			engineQueueState: "not-exposed-in-this-build",
		});
	});

	it("404s unknown paths and 405s non-GET methods", async () => {
		const server = await startSaturationStatusServer({ mode: "execute" });
		if (!server) throw new Error("expected a server");
		openServers.push(server);
		expect((await fetch(`${server.endpoint.replace(SATURATION_STATUS_PATH, "")}/`)).status).toBe(
			404,
		);
		expect((await fetch(server.endpoint, { method: "POST" })).status).toBe(405);
	});

	it("close() is decisive: the endpoint stops answering", async () => {
		const server = await startSaturationStatusServer({ mode: "execute" });
		if (!server) throw new Error("expected a server");
		const endpoint = server.endpoint;
		await expect(fetch(endpoint)).resolves.toHaveProperty("status", 200);
		await server.close();
		await expect(fetch(endpoint, { signal: AbortSignal.timeout(1000) })).rejects.toThrow();
	});
});

describe("formatReadyLine", () => {
	it("pins the launcher-parsed shape (key order included)", () => {
		expect(
			formatReadyLine({
				mode: "execute",
				mainPid: 401,
				rendererPid: 402,
				saturationUrl: "http://127.0.0.1:53121/internal/e6/saturation",
				appOrigin: "http://127.0.0.1:34567",
				rendered: true,
				memberEmail: "e6-b@e6.test",
			}),
		).toBe(
			'{"type":"e6-client-ready","flag":"feature.connectivity_aware_sync","mode":"execute",' +
				'"mainPid":401,"rendererPid":402,"saturationUrl":"http://127.0.0.1:53121/internal/e6/saturation",' +
				'"appOrigin":"http://127.0.0.1:34567","rendered":true,"memberEmail":"e6-b@e6.test"}',
		);
	});

	it("carries a null saturationUrl under off", () => {
		const parsed = JSON.parse(
			formatReadyLine({
				mode: "off",
				mainPid: 1,
				rendererPid: 2,
				saturationUrl: null,
				appOrigin: null,
				rendered: false,
				memberEmail: null,
			}),
		) as { saturationUrl: string | null; rendered: boolean };
		expect(parsed.saturationUrl).toBeNull();
		expect(parsed.rendered).toBe(false);
	});
});

describe("composeConnectivityE6HarnessSurface", () => {
	it("is fully inert without the harness user-data seam", () => {
		const window = fakeWindow(402);
		const log = vi.fn();
		expect(() => composeConnectivityE6HarnessSurface(window, { env: {}, log })).not.toThrow();
		expect(() =>
			composeConnectivityE6HarnessSurface(window, { env: { SETJOIN_E6_USER_DATA_DIR: "" }, log }),
		).not.toThrow();
		window.emitDidFinishLoad();
		expect(log).not.toHaveBeenCalled();
		expect(window.listeners).toHaveLength(0);
	});

	it("refuses to compose a misflagged instance", () => {
		const window = fakeWindow(402);
		expect(() =>
			composeConnectivityE6HarnessSurface(window, {
				env: { ...USER_DATA_SEAM, SETJOIN_E6_CONNECTIVITY_SYNC_MODE: "on" },
			}),
		).toThrow(/not a rollout mode/);
		expect(window.listeners).toHaveLength(0);
	});

	it("under off: prints the ready line with no endpoint and starts nothing", async () => {
		const window = fakeWindow(402);
		const log = vi.fn();
		let composedServer: SaturationStatusServer | null | undefined;
		composeConnectivityE6HarnessSurface(window, {
			env: { ...USER_DATA_SEAM, SETJOIN_E6_CONNECTIVITY_SYNC_MODE: "off" },
			mainPid: 401,
			log,
			onServer: (server) => {
				composedServer = server;
			},
		});
		window.emitDidFinishLoad();
		await vi.waitFor(() => expect(log).toHaveBeenCalledTimes(1));
		expect(composedServer).toBeNull();
		expect(log).toHaveBeenCalledWith(
			formatReadyLine({
				mode: "off",
				mainPid: 401,
				rendererPid: 402,
				saturationUrl: null,
				appOrigin: null,
				rendered: false,
				memberEmail: null,
			}),
		);
	});

	it("under execute: prints one ready line with the live endpoint once load finishes", async () => {
		const window = fakeWindow(402);
		const log = vi.fn();
		let composedServer: SaturationStatusServer | null | undefined;
		composeConnectivityE6HarnessSurface(window, {
			env: { ...USER_DATA_SEAM, SETJOIN_E6_CONNECTIVITY_SYNC_MODE: "execute" },
			mainPid: 401,
			log,
			onServer: (server) => {
				composedServer = server;
				if (server) openServers.push(server);
			},
		});
		// Load can finish before the server resolves — exactly one line either way.
		window.emitDidFinishLoad();
		await vi.waitFor(() => expect(log).toHaveBeenCalledTimes(1));
		expect(composedServer).not.toBeNull();
		const url = JSON.parse(log.mock.calls[0]?.[0] as string) as { saturationUrl: string };
		expect(url.saturationUrl).toBe((composedServer as SaturationStatusServer).endpoint);
		expect((await fetch((composedServer as SaturationStatusServer).endpoint)).status).toBe(200);
	});
});

describe("composeConnectivityE6HarnessSurface under the app-origin seam (the white-screen fix)", () => {
	const setSessionCookie = vi.fn(async () => {});
	const FAST = { renderProbeAttempts: 5, renderProbeIntervalMs: 1 };

	it("refuses a set-but-invalid app origin instead of degrading to the bundled build", () => {
		const window = fakeWindow(402);
		expect(() =>
			composeConnectivityE6HarnessSurface(window, {
				env: {
					...USER_DATA_SEAM,
					...APP_ORIGIN_SEAM,
					SETJOIN_E6_APP_ORIGIN: "http://10.0.0.9:34567",
				},
				setSessionCookie,
			}),
		).toThrow(/SETJOIN_E6_APP_ORIGIN.*not a loopback http origin/);
		expect(window.listeners).toHaveLength(0);
	});

	it("refuses an app origin with no member session cookie (a session-less window renders the login page)", () => {
		const window = fakeWindow(402);
		expect(() =>
			composeConnectivityE6HarnessSurface(window, {
				env: { ...USER_DATA_SEAM, ...APP_ORIGIN_SEAM, SETJOIN_E6_SESSION_COOKIE: undefined },
				setSessionCookie,
			}),
		).toThrow(/SETJOIN_E6_SESSION_COOKIE.*required/);
	});

	it("refuses a foreign cookie name", () => {
		const window = fakeWindow(402);
		expect(() =>
			composeConnectivityE6HarnessSurface(window, {
				env: { ...USER_DATA_SEAM, ...APP_ORIGIN_SEAM, SETJOIN_E6_SESSION_COOKIE: "sid=abc" },
				setSessionCookie,
			}),
		).toThrow(/access_token=/);
	});

	it("refuses composition without the cookie-planting hook (the watchdog could not recover)", () => {
		const window = fakeWindow(402);
		expect(() =>
			composeConnectivityE6HarnessSurface(window, {
				env: { ...USER_DATA_SEAM, ...APP_ORIGIN_SEAM },
			}),
		).toThrow(/setSessionCookie/);
	});

	it("holds the ready line until the in-page probe sees the authenticated rendered shell", async () => {
		const window = fakeWindow(402, {
			initialProbes: [
				probe({ rendered: false, email: null }), // hydrated, shell not up yet
				probe(), // authenticated + rendered
			],
		});
		const log = vi.fn();
		composeConnectivityE6HarnessSurface(window, {
			env: { ...USER_DATA_SEAM, SETJOIN_E6_CONNECTIVITY_SYNC_MODE: "off", ...APP_ORIGIN_SEAM },
			mainPid: 401,
			log,
			setSessionCookie,
			...FAST,
		});
		window.emitDidFinishLoad();
		await vi.waitFor(() => expect(log).toHaveBeenCalledTimes(1));
		const line = JSON.parse(log.mock.calls[0]?.[0] as string) as {
			rendered: boolean;
			memberEmail: string | null;
			appOrigin: string | null;
		};
		expect(line.rendered).toBe(true);
		expect(line.memberEmail).toBe("e6-a@e6.test");
		expect(line.appOrigin).toBe("http://127.0.0.1:34567");
		// The probe must run the shipped script, not any ad-hoc expression.
		expect(window.executeJavaScript).toHaveBeenCalledWith(
			expect.stringContaining(APP_SHELL_RENDER_MARKER),
		);
	});

	it("fails closed with a named render error when the SPA lands on the login page (dead session)", async () => {
		const window = fakeWindow(402, {
			initialProbes: [probe({ auth: "anonymous", rendered: false, loginPage: true, email: null })],
			onProbesExhausted: () =>
				probe({ auth: "anonymous", rendered: false, loginPage: true, email: null }),
		});
		const log = vi.fn();
		const onFatal = vi.fn();
		composeConnectivityE6HarnessSurface(window, {
			env: { ...USER_DATA_SEAM, SETJOIN_E6_CONNECTIVITY_SYNC_MODE: "off", ...APP_ORIGIN_SEAM },
			mainPid: 401,
			log,
			onFatal,
			setSessionCookie,
			...FAST,
		});
		window.emitDidFinishLoad();
		await vi.waitFor(() => expect(onFatal).toHaveBeenCalledTimes(1));
		expect(String(onFatal.mock.calls[0]?.[0])).toMatch(/e6-client-render-failed.*login-page/s);
		expect(log).not.toHaveBeenCalled(); // never a ready line for a white/login window
	});

	it("keeps probing through transient gateway unavailability and fails only when the budget is exhausted", async () => {
		const window = fakeWindow(402, {
			initialProbes: [
				probe({ auth: "unavailable", rendered: false, loginPage: false, email: null }),
			],
			onProbesExhausted: () =>
				probe({ auth: "unavailable", rendered: false, loginPage: false, email: null }),
		});
		const onFatal = vi.fn();
		composeConnectivityE6HarnessSurface(window, {
			env: { ...USER_DATA_SEAM, SETJOIN_E6_CONNECTIVITY_SYNC_MODE: "off", ...APP_ORIGIN_SEAM },
			mainPid: 401,
			log: vi.fn(),
			onFatal,
			setSessionCookie,
			renderProbeAttempts: 3,
			renderProbeIntervalMs: 1,
		});
		window.emitDidFinishLoad();
		await vi.waitFor(() => expect(onFatal).toHaveBeenCalledTimes(1));
		expect(window.executeJavaScript).toHaveBeenCalledTimes(3);
		expect(String(onFatal.mock.calls[0]?.[0])).toMatch(/gateway-unavailable/);
	});
});

describe("composeConnectivityE6HarnessSurface session watchdog", () => {
	const setSessionCookie = vi.fn(async () => {});
	// Each test asserts absence/presence of calls on this shared mock — start
	// every test from a clean call log, and stop every composed watchdog so
	// no zombie interval from one test fires into the next.
	const disposers: Array<() => void> = [];
	beforeEach(() => {
		setSessionCookie.mockClear();
		disposers.length = 0;
	});
	afterEach(() => {
		for (const dispose of disposers.splice(0)) dispose();
	});
	const jsonResponse = (status: number, body: unknown) =>
		new Response(JSON.stringify(body), { status });

	// Boot ready, THEN the gateway revokes the session (the reset-pair/TTL
	// posture mid-run): the first poll must pass readiness for the watchdog
	// to even start.
	function revokedAfterBootWindow() {
		return fakeWindow(402, {
			initialProbes: [probe()],
			onProbesExhausted: () =>
				probe({ auth: "anonymous", rendered: false, loginPage: true, email: null }),
		});
	}

	function composeWatchdog(
		window: ReturnType<typeof fakeWindow>,
		extra: Record<string, unknown> = {},
	) {
		const dispose = composeConnectivityE6HarnessSurface(window, {
			env: {
				...USER_DATA_SEAM,
				SETJOIN_E6_CONNECTIVITY_SYNC_MODE: "off",
				...APP_ORIGIN_SEAM,
			},
			mainPid: 401,
			log: vi.fn(),
			setSessionCookie,
			renderProbeAttempts: 2,
			renderProbeIntervalMs: 1,
			watchdogIntervalMs: 5,
			...extra,
		});
		disposers.push(dispose);
	}

	it("re-mints the session through the gateway login, re-plants the cookie, and reloads when the session dies", async () => {
		const window = revokedAfterBootWindow();
		const loginBodies: Array<unknown> = [];
		const fetchFn = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
			loginBodies.push(JSON.parse(String(init?.body)));
			return jsonResponse(200, { access_token: "jwt-refreshed" });
		});
		composeWatchdog(window, { fetchFn });
		window.emitDidFinishLoad();
		await vi.waitFor(() => expect(fetchFn).toHaveBeenCalled(), { timeout: 3000 });
		expect(String(fetchFn.mock.calls[0]?.[0])).toBe("http://127.0.0.1:34567/auth/login");
		expect(loginBodies[0]).toEqual({ email: "e6-a@e6.test", password: "TestPass123!" });
		await vi.waitFor(
			() =>
				expect(setSessionCookie).toHaveBeenCalledWith("http://127.0.0.1:34567", {
					name: "access_token",
					value: "jwt-refreshed",
				}),
			{ timeout: 3000 },
		);
		expect(window.loadURL).toHaveBeenCalledWith("http://127.0.0.1:34567/inbox");
	});

	it("never re-mints on transient unavailability (the outage stage is not a revocation)", async () => {
		const window = fakeWindow(402, {
			initialProbes: [probe()],
			onProbesExhausted: () =>
				probe({ auth: "unavailable", rendered: false, loginPage: false, email: null }),
		});
		const fetchFn = vi.fn(async () => jsonResponse(200, {}));
		composeWatchdog(window, { fetchFn, onFatal: vi.fn() });
		window.emitDidFinishLoad();
		await new Promise((resolve) => setTimeout(resolve, 40));
		expect(fetchFn).not.toHaveBeenCalled();
		expect(setSessionCookie).not.toHaveBeenCalled();
		expect(window.loadURL).not.toHaveBeenCalled();
	});

	it("escalates to a named fatal after sustained refusal (the pair is invalid evidence)", async () => {
		const window = revokedAfterBootWindow();
		const fetchFn = vi.fn(async () => jsonResponse(429, { error: "rate_limited" }));
		const onFatal = vi.fn();
		composeWatchdog(window, { fetchFn, onFatal, watchdogRefreshFailureLimit: 2 });
		window.emitDidFinishLoad();
		await vi.waitFor(() => expect(onFatal).toHaveBeenCalledTimes(1), { timeout: 3000 });
		expect(String(onFatal.mock.calls[0]?.[0])).toMatch(/e6-client-session-lost/);
	});
});

describe("engine queue-state truth (the composed webmail's real queue depth)", () => {
	const realState = {
		composed: true,
		basis: "engine-queue-observed",
		mode: "execute",
		queueDepth: 3,
		running: 1,
		saturating: true,
		observedAtUtc: "2026-09-21T00:00:00Z",
	};

	it("parses a valid observed state and refuses every forgery shape", () => {
		expect(parseEngineQueueState(realState)).toEqual({
			queueDepth: 3,
			running: 1,
			saturating: true,
			observedAtUtc: "2026-09-21T00:00:00Z",
		});
		// Non-objects and wrong basis markers are null.
		expect(parseEngineQueueState(null)).toBeNull();
		expect(parseEngineQueueState("saturating")).toBeNull();
		expect(parseEngineQueueState({ ...realState, basis: "policy-mode-configured" })).toBeNull();
		expect(parseEngineQueueState({ ...realState, composed: false })).toBeNull();
		// Counters must be non-negative safe integers.
		expect(parseEngineQueueState({ ...realState, queueDepth: -1 })).toBeNull();
		expect(parseEngineQueueState({ ...realState, running: 1.5 })).toBeNull();
		// saturating must AGREE with the numbers it reports.
		expect(parseEngineQueueState({ ...realState, queueDepth: 0, running: 0 })).toBeNull();
		expect(parseEngineQueueState({ ...realState, observedAtUtc: "" })).toBeNull();
	});

	it("upgrades the endpoint body to the observed basis with REAL queue depth", async () => {
		const server = await startSaturationStatusServer({
			mode: "execute",
			readEngineQueueState: async () => realState,
		});
		if (!server) throw new Error("expected a server");
		openServers.push(server);
		const body = (await fetch(server.endpoint).then((r) => r.json())) as Record<string, unknown>;
		expect(body).toEqual({
			saturating: true,
			basis: "engine-queue-observed",
			flag: CONNECTIVITY_AWARE_SYNC_FLAG,
			mode: "execute",
			engineQueueState: { queueDepth: 3, running: 1, observedAtUtc: "2026-09-21T00:00:00Z" },
		});
	});

	it("reports an idle engine honestly (saturating false while composed)", async () => {
		const server = await startSaturationStatusServer({
			mode: "execute",
			readEngineQueueState: async () => ({
				...realState,
				queueDepth: 0,
				running: 0,
				saturating: false,
			}),
		});
		if (!server) throw new Error("expected a server");
		openServers.push(server);
		const body = (await fetch(server.endpoint).then((r) => r.json())) as {
			saturating: boolean;
			basis: string;
		};
		expect(body.saturating).toBe(false);
		expect(body.basis).toBe("engine-queue-observed");
	});

	it("falls back to the policy-mode declaration when the global is absent (pair OFF / plain webmail)", async () => {
		const server = await startSaturationStatusServer({
			mode: "execute",
			readEngineQueueState: async () => null,
		});
		if (!server) throw new Error("expected a server");
		openServers.push(server);
		const body = (await fetch(server.endpoint).then((r) => r.json())) as Record<string, unknown>;
		expect(body).toEqual({
			saturating: true,
			basis: "policy-mode-configured",
			flag: CONNECTIVITY_AWARE_SYNC_FLAG,
			mode: "execute",
			engineQueueState: "not-exposed-in-this-build",
		});
	});

	it("falls back when the reader throws or hangs past the bounded read window", async () => {
		const throwing = await startSaturationStatusServer({
			mode: "execute",
			readEngineQueueState: async () => {
				throw new Error("renderer gone");
			},
		});
		if (!throwing) throw new Error("expected a server");
		openServers.push(throwing);
		const thrown = (await fetch(throwing.endpoint).then((r) => r.json())) as { basis: string };
		expect(thrown.basis).toBe("policy-mode-configured");

		const hanging = await startSaturationStatusServer({
			mode: "execute",
			readEngineQueueState: () => new Promise(() => {}), // never settles
		});
		if (!hanging) throw new Error("expected a server");
		openServers.push(hanging);
		const hung = (await fetch(hanging.endpoint).then((r) => r.json())) as { basis: string };
		expect(hung.basis).toBe("policy-mode-configured");
	});

	it("carries the content-free trigger counters and policy basis into the body", async () => {
		const server = await startSaturationStatusServer({
			mode: "execute",
			readEngineQueueState: async () => ({
				...realState,
				policyBasis: "harness-seam",
				triggersIngested: 7,
				triggersCoalesced: 2,
				lastTriggerKind: "reconnect",
			}),
		});
		if (!server) throw new Error("expected a server");
		openServers.push(server);
		const body = (await fetch(server.endpoint).then((r) => r.json())) as {
			engineQueueState: Record<string, unknown>;
		};
		expect(body.engineQueueState).toEqual({
			queueDepth: 3,
			running: 1,
			observedAtUtc: "2026-09-21T00:00:00Z",
			policyBasis: "harness-seam",
			triggersIngested: 7,
			triggersCoalesced: 2,
			lastTriggerKind: "reconnect",
		});
	});

	it("refuses forged trigger counters and unknown trigger kinds", () => {
		expect(parseEngineQueueState({ ...realState, triggersIngested: -1 })).toBeNull();
		expect(parseEngineQueueState({ ...realState, triggersCoalesced: 2.5 })).toBeNull();
		expect(parseEngineQueueState({ ...realState, lastTriggerKind: "space-heater" })).toBeNull();
		expect(parseEngineQueueState({ ...realState, lastTriggerKind: 7 })).toBeNull();
		// policyBasis: the finite webmail basis vocabulary — including the
		// neither-projection-nor-seam OFF stand-in — rides through; anything
		// else refuses the whole snapshot.
		expect(parseEngineQueueState({ ...realState, policyBasis: "no-projection" })?.policyBasis).toBe(
			"no-projection",
		);
		expect(parseEngineQueueState({ ...realState, policyBasis: "made-up" })).toBeNull();
	});

	it("prints a named line when the queue-state basis regresses to the declaration fallback", async () => {
		// First poll observes the REAL engine queue; the reader then dies (the
		// window closed mid-run): the endpoint falls back to the declaration —
		// exactly when an `engine-queue-observed` claim goes stale, so the
		// transition is named on the log (no HTTP behavior change).
		let healthy = true;
		const lines: string[] = [];
		const server = await startSaturationStatusServer({
			mode: "execute",
			readEngineQueueState: async () => (healthy ? realState : null),
			log: (line) => lines.push(line),
		});
		if (!server) throw new Error("expected a server");
		openServers.push(server);
		const first = (await fetch(server.endpoint).then((r) => r.json())) as { basis: string };
		expect(first.basis).toBe("engine-queue-observed");
		expect(lines).toEqual([]);

		healthy = false;
		const second = (await fetch(server.endpoint).then((r) => r.json())) as { basis: string };
		expect(second.basis).toBe("policy-mode-configured");
		expect(lines).toHaveLength(1);
		const named = JSON.parse(lines[0]) as Record<string, unknown>;
		expect(named).toMatchObject({
			type: "e6-client-saturation-basis-regressed",
			mode: "execute",
			from: "engine-queue-observed",
			to: "policy-mode-configured",
		});
		expect(typeof named.atUtc).toBe("string");

		// The regression prints ONCE per transition: a sustained fallback does
		// not spam the log on every later poll.
		const third = (await fetch(server.endpoint).then((r) => r.json())) as { basis: string };
		expect(third.basis).toBe("policy-mode-configured");
		expect(lines).toHaveLength(1);
	});

	it("prints no regression line when no observed basis preceded the fallback", async () => {
		const lines: string[] = [];
		const server = await startSaturationStatusServer({
			mode: "execute",
			readEngineQueueState: async () => null,
			log: (line) => lines.push(line),
		});
		if (!server) throw new Error("expected a server");
		openServers.push(server);
		await fetch(server.endpoint).then((r) => r.json());
		await fetch(server.endpoint).then((r) => r.json());
		expect(lines).toEqual([]);
	});

	it("names the platform gate when the webmail honestly refused to compose", async () => {
		// parseEngineGate: strict shape, finite reasons.
		expect(parseEngineGate({ composed: false, reason: "no-durable-persistence" })).toBe(
			"no-durable-persistence",
		);
		expect(parseEngineGate({ composed: true, reason: "no-durable-persistence" })).toBeNull();
		expect(parseEngineGate({ composed: false, reason: "because" })).toBeNull();
		expect(parseEngineGate(null)).toBeNull();

		const server = await startSaturationStatusServer({
			mode: "execute",
			readEngineQueueState: async () => ({ composed: false, reason: "no-durable-persistence" }),
		});
		if (!server) throw new Error("expected a server");
		openServers.push(server);
		const body = (await fetch(server.endpoint).then((r) => r.json())) as {
			basis: string;
			engineQueueState: Record<string, unknown>;
		};
		// The declaration stays the policy-mode fallback (no engine exists to
		// observe), but the body NAMES the gate instead of "not exposed".
		expect(body.basis).toBe("policy-mode-configured");
		expect(body.engineQueueState).toEqual({ gate: "no-durable-persistence" });
	});

	it("threads the window-bridge reader through the composition (main.ts wiring shape)", async () => {
		const window = fakeWindow(4242, { initialProbes: [probe()] });
		const setSessionCookie = vi.fn(async () => {});
		composeConnectivityE6HarnessSurface(window, {
			env: { ...USER_DATA_SEAM, ...APP_ORIGIN_SEAM, SETJOIN_E6_CONNECTIVITY_SYNC_MODE: "execute" },
			setSessionCookie,
			readEngineQueueState: window.executeJavaScript as unknown as () => Promise<unknown>,
		});
		window.emitDidFinishLoad();
		// The composition passes the reader through untouched; the probe
		// mechanism (executeJavaScript) is the same window bridge as the
		// render/readiness probe.
		await vi.waitFor(() => expect(window.executeJavaScript).toHaveBeenCalled());
	});

	it("keeps the default (no reader) byte-identical to the policy-mode contract", async () => {
		const server = await startSaturationStatusServer({ mode: "execute" });
		if (!server) throw new Error("expected a server");
		openServers.push(server);
		expect(await fetch(server.endpoint).then((r) => r.json())).toEqual({
			saturating: true,
			basis: "policy-mode-configured",
			flag: CONNECTIVITY_AWARE_SYNC_FLAG,
			mode: "execute",
			engineQueueState: "not-exposed-in-this-build",
		});
	});
});
