/**
 * E4-I production boot composition tests: the gating chain (projected flag
 * pair → mode → platform capability), trigger→ingest wiring, the honest
 * unavailable states, and the saturation-truth surface. The coordinator's own
 * machinery has its lane (coordinator.test.ts, e4i.*.test.ts) — here the
 * composition is the unit under test.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// The REAL `$lib/jmap/client` stays wired in (no module mock): the
// production-delta-port suite below drives the composition's actual client
// adapters over a stubbed-fetch fake server (the `jmap/client.test.ts`
// pattern). Every other suite either injects scripted step clients or never
// admits a step, and the setup file's unstubbed-fetch guard fails loudly if
// one of them ever reached the network by accident.
// The app-identity mirror (the real module pulls the IndexedDB queue graph).
vi.mock('$lib/db/offline', () => ({
	accountIdentity: (u: { userId?: number | null; email?: string } | null): string | null => {
		if (!u) return null;
		return u.userId != null ? `user:${u.userId}` : `email:${(u.email ?? '').toLowerCase()}`;
	},
}));

import {
	__resetBootForTests,
	composeOfflineCoordinator,
	composeOfflineCoordinatorForSession,
	deliverConnectivityCapabilityObservation,
	harnessSeamGrant,
	ingestConnectivityActionTrigger,
	ingestConnectivityPushTrigger,
	policyFromGrant,
	readBridgeHarnessMode,
	readConnectivityCoordinatorState,
	readSessionOfflineGrant,
	resolveEffectiveGrant,
	type SessionOfflineGrant,
} from './boot';
import { createCoordinator } from './coordinator';
import { createMemoryJobPersistence } from './jobStore';
import {
	BRIDGE_CAPABILITY_CONTRACT_VERSION,
	type BridgeCapabilitySnapshot,
} from './work-contract';
import {
	createMemoryOfflineStore,
} from '$lib/native/testing/backgroundWorkHarness';
import type { OfflineDbBridge } from '$lib/native/types';
import type { Email } from '$lib/types/jmap';

// ── fixtures ─────────────────────────────────────────────────────────────────

function sessionWithSyncQos(mode: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
	return {
		effectiveCapabilities: {
			apps: { mail: true },
			features: {},
			offline: {
				allowed: true,
				approvalState: 'approved',
				maxOfflineDays: 30,
				wipeOnLogout: 'admin_default',
				requireApproval: false,
				syncQoS: {
					schemaVersion: 1,
					mode,
					backgroundAllowed: true,
					requested: { automaticNetwork: 'unmetered', attachmentPrefetch: 'unmetered' },
					effective: {
						automaticNetwork: 'unmetered',
						attachmentPrefetch: 'never',
						opportunisticRequiresCharging: true,
					},
					sources: {},
					...overrides,
				},
			},
		},
	};
}

function grantFrom(mode: string): SessionOfflineGrant {
	const grant = readSessionOfflineGrant(sessionWithSyncQos(mode));
	if (grant === null) throw new Error('fixture must parse');
	return grant;
}

function nominalSnapshot(): BridgeCapabilitySnapshot {
	return {
		contractVersion: BRIDGE_CAPABILITY_CONTRACT_VERSION,
		executionMode: 'foregroundReconnectOnly',
		networkCost: 'unmetered',
		power: 'full',
		powerSaver: false,
		charging: true,
		thermal: 'nominal',
		storagePressure: 'normal',
		foregroundExecution: true,
		backgroundExecution: false,
		schedule: true,
		cancel: true,
		durableTransfer: true,
	};
}

function fakeDb(): OfflineDbBridge {
	return {
		open: vi.fn(),
		isOpen: vi.fn(),
		exec: vi.fn(),
		transactionBatch: vi.fn(async () => 1),
		query: vi.fn(async () => []),
		wipe: vi.fn(),
	} as unknown as OfflineDbBridge;
}

/** Delta client scripting one complete page (one new email), then nothing. */
function scriptedDeltaClient(emails: Email[]): {
	emailChanges: (args: { sinceState: string; maxChanges: number }) => Promise<{
		newState: string;
		hasMoreChanges: boolean;
		created: string[];
		updated: string[];
		destroyed: string[];
	}>;
	emailGet: (args: { ids: string[]; properties: string[] }) => Promise<{ list: Email[]; state: string }>;
} {
	let page = 0;
	return {
		emailChanges: async () => {
			page += 1;
			if (page > 1) {
				return { newState: 's-final', hasMoreChanges: false, created: [], updated: [], destroyed: [] };
			}
			return {
				newState: 's-1',
				hasMoreChanges: false,
				created: emails.map((e) => e.id),
				updated: [],
				destroyed: [],
			};
		},
		emailGet: async ({ ids }) => ({
			list: emails.filter((e) => ids.includes(e.id)),
			state: 's-1',
		}),
	};
}

function composedDeps(overrides: Record<string, unknown> = {}): Record<string, unknown> {
	return {
		isNativeShell: () => true,
		bridgeDb: () => fakeDb(),
		openStore: () => createMemoryOfflineStore(),
		createJobs: () => createMemoryJobPersistence(),
		windowTarget: new EventTarget(),
		documentTarget: new EventTarget(),
		installQueueStateGlobal: true,
		sessionSource: () => sessionWithSyncQos('execute'),
		...overrides,
	};
}

function fireEvent(target: EventTarget, type: string): void {
	target.dispatchEvent(new Event(type));
}

async function flushMicrotasks(): Promise<void> {
	await new Promise((resolve) => setTimeout(resolve, 0));
}

beforeEach(() => {
	__resetBootForTests();
});

afterEach(() => {
	__resetBootForTests();
	vi.clearAllMocks();
});

// ── the projection parser ────────────────────────────────────────────────────

describe('readSessionOfflineGrant (the flag-pair projection the app consumes)', () => {
	it('parses the strict syncQoS block the gateway projects with both flags ON', () => {
		const grant = readSessionOfflineGrant(sessionWithSyncQos('execute'));
		expect(grant).not.toBeNull();
		expect(grant?.syncQos.mode).toBe('execute');
		expect(grant?.syncQos.backgroundAllowed).toBe(true);
		expect(grant?.syncQos.requested.automaticNetwork).toBe('unmetered');
		expect(grant?.syncQos.effective.opportunisticRequiresCharging).toBe(true);
		expect(grant?.maxOfflineDays).toBe(30);
	});

	it('returns null when the block is ABSENT — the gateway strips syncQoS unless BOTH feature.offline_mail and feature.connectivity_aware_sync are ON', () => {
		// Either flag OFF ⇒ offline_effective_policy strips syncQoS ⇒ no block.
		const noSyncQos = {
			effectiveCapabilities: {
				offline: { allowed: false, approvalState: 'pending', maxOfflineDays: 0 },
			},
		};
		expect(readSessionOfflineGrant(noSyncQos)).toBeNull();
		expect(readSessionOfflineGrant({})).toBeNull();
		expect(readSessionOfflineGrant(null)).toBeNull();
	});

	it('fails closed on any shape drift (schema version, enums, missing fields)', () => {
		expect(readSessionOfflineGrant(sessionWithSyncQos('execute', { schemaVersion: 2 }))).toBeNull();
		expect(readSessionOfflineGrant(sessionWithSyncQos('bogus'))).toBeNull();
		expect(
			readSessionOfflineGrant(sessionWithSyncQos('execute', { backgroundAllowed: 'yes' })),
		).toBeNull();
		expect(
			readSessionOfflineGrant(sessionWithSyncQos('execute', { requested: { automaticNetwork: 'sometimes' } })),
		).toBeNull();
		const noMaxDays = sessionWithSyncQos('execute') as { effectiveCapabilities: { offline: Record<string, unknown> } };
		delete noMaxDays.effectiveCapabilities.offline.maxOfflineDays;
		expect(readSessionOfflineGrant(noMaxDays)?.maxOfflineDays).toBeNull();
	});
});

describe('policyFromGrant', () => {
	it('maps the projected grant onto the coordinator policy with flagEnabled true', () => {
		const policy = policyFromGrant(grantFrom('observe'), false);
		expect(policy.flagEnabled).toBe(true);
		expect(policy.rolloutMode).toBe('observe');
		expect(policy.requested).toEqual({
			backgroundSyncEnabled: true,
			automaticNetwork: 'unmetered',
		});
		expect(policy.effective.automaticNetwork).toBe('unmetered');
	});

	it('maps a DROPPED grant to the OFF policy — a flag narrowed OFF mid-job stops work at the next boundary', () => {
		const policy = policyFromGrant(null, false);
		expect(policy.flagEnabled).toBe(false);
		expect(policy.rolloutMode).toBe('off');
		expect(policy.effective.backgroundAllowed).toBe(false);
	});
});

// ── the gating chain ────────────────────────────────────────────────────────

describe('composition gating chain', () => {
	it('is INERT when the pair is not projected: nothing constructed, no global, no state', async () => {
		const disposer = composeOfflineCoordinatorForSession(
			{ effectiveCapabilities: { offline: { allowed: false } } },
			{ userId: 1, email: 'a@b.c' } as never,
		);
		expect(disposer).toBeUndefined();
		await expect(readConnectivityCoordinatorState()).resolves.toEqual({
			composed: false,
			reason: 'inert-pair-off',
		});
		expect(window.__setjoinConnectivityQueueState).toBeUndefined();
	});

	it('is INERT when the identity is unresolved', () => {
		const disposer = composeOfflineCoordinatorForSession(sessionWithSyncQos('execute'), null);
		expect(disposer).toBeUndefined();
	});

	it('is INERT when the projected mode is off (zero subscriptions even with the pair ON)', async () => {
		// An explicit server-projected `mode: 'off'` is the policy authority's
		// no: the wrapper composes NOTHING (returns undefined, no disposer).
		const disposer = composeOfflineCoordinatorForSession(
			sessionWithSyncQos('off'),
			{ userId: 1, email: 'a@b.c' } as never,
		);
		expect(disposer).toBeUndefined();
		await flushMicrotasks();
		await expect(readConnectivityCoordinatorState()).resolves.toEqual({
			composed: false,
			reason: 'inert-mode-off',
		});
		expect(window.__setjoinConnectivityQueueState).toBeUndefined();
	});

	it('reports the honest UNAVAILABLE state on a plain browser (no native bridge) — never a fake runner', async () => {
		const composition = await composeOfflineCoordinator({
			accountId: 'user:1',
			grant: grantFrom('execute'),
			deps: composedDeps({ isNativeShell: () => false }) as never,
		});
		expect(composition).toEqual({ kind: 'unavailable', reason: 'no-native-bridge' });
		expect(window.__setjoinConnectivityQueueState).toBeUndefined();
		await expect(readConnectivityCoordinatorState()).resolves.toEqual({
			composed: false,
			reason: 'platform-unavailable',
		});
	});

	it('refuses to compose durable persistence without the native atomic batch entry', async () => {
		const db = fakeDb() as unknown as Record<string, unknown>;
		delete db.transactionBatch;
		const composition = await composeOfflineCoordinator({
			accountId: 'user:1',
			grant: grantFrom('execute'),
			deps: composedDeps({ bridgeDb: () => db as unknown as OfflineDbBridge }) as never,
		});
		expect(composition).toEqual({ kind: 'unavailable', reason: 'no-durable-persistence' });
	});

	it('exposes the honest gate diagnostic when the flag gates admitted but the platform refused', async () => {
		// The seam admits (bridge carries the harness mode), but the db lacks
		// the E4-I atomic batch entry: the flag gates pass, the platform
		// refuses — and the refusal is observable through the window global.
		(window as unknown as Record<string, unknown>).setjoinNative = {
			connectivity: { rolloutMode: 'execute' },
		};
		const db = fakeDb() as unknown as Record<string, unknown>;
		delete db.transactionBatch;
		const disposer = composeOfflineCoordinatorForSession(
			{ effectiveCapabilities: { apps: { mail: true } } },
			{ userId: 9, email: 'gate@e6.test' } as never,
			composedDeps({ bridgeDb: () => db as unknown as OfflineDbBridge }) as never,
		);
		expect(disposer).toBeTypeOf('function');
		await flushMicrotasks();
		const gate = await window.__setjoinConnectivityQueueState?.();
		expect(gate).toEqual({ composed: false, reason: 'no-durable-persistence' });
		// The disposer clears the diagnostic too.
		disposer?.();
		expect(window.__setjoinConnectivityQueueState).toBeUndefined();
		delete (window as unknown as Record<string, unknown>).setjoinNative;
	});

	it('reports unavailable when the store cannot initialize (migration failure)', async () => {
		const composition = await composeOfflineCoordinator({
			accountId: 'user:1',
			grant: grantFrom('execute'),
			deps: composedDeps({
				openStore: () => Object.assign(createMemoryOfflineStore(), {
					init: async () => {
						throw new Error('migration interrupted');
					},
				}),
			}) as never,
		});
		expect(composition).toEqual({ kind: 'unavailable', reason: 'store-init-failed' });
	});
});

// ── composed: construction, triggers, saturation truth ──────────────────────

describe('composed coordinator (pair ON, capability admitted)', () => {
	async function composeExecuting(overrides: Record<string, unknown> = {}) {
		return composeOfflineCoordinator({
			accountId: 'user:1',
			grant: grantFrom('execute'),
			deps: composedDeps(overrides) as never,
		});
	}

	it('constructs the real coordinator and installs the saturation global', async () => {
		const composition = await composeExecuting();
		if (composition.kind !== 'composed') throw new Error('expected composed');
		expect(composition.coordinator.ownerId).toBe('coordinator');
		expect(typeof window.__setjoinConnectivityQueueState).toBe('function');
		const state = await readConnectivityCoordinatorState();
		expect(state).toMatchObject({
			composed: true,
			basis: 'engine-queue-observed',
			mode: 'execute',
			queueDepth: 0,
			running: 0,
			saturating: false,
		});
	});

	it('wires the online trigger to ingestion: a real window event ingests real work', async () => {
		const windowTarget = new EventTarget();
		const composition = await composeExecuting({ windowTarget });
		if (composition.kind !== 'composed') throw new Error('expected composed');
		fireEvent(windowTarget, 'online');
		await flushMicrotasks();
		const ingested = composition.events.find((e) => e.kind === 'trigger-ingested');
		expect(ingested).toMatchObject({ kind: 'trigger-ingested', trigger: 'reconnect', jobId: 'opt-reconnect-user:1' });
		// Without a shell capability observation the admission cycle honestly
		// pauses the job (capabilityUnavailable) — no invented work.
		await flushMicrotasks();
		const paused = [...(composition as { events: readonly unknown[] }).events]
			.filter((e) => (e as { kind: string }).kind === 'admission-blocked');
		expect(paused.length).toBeGreaterThan(0);
	});

	it('keeps observed work QUEUED in observe mode: real sustained queue depth', async () => {
		const composition = await composeOfflineCoordinator({
			accountId: 'user:1',
			grant: grantFrom('observe'),
			deps: composedDeps({
				sessionSource: () => sessionWithSyncQos('observe'),
				capabilityReader: async () => ({ snapshot: nominalSnapshot(), receivedMonoMs: performance.now(), epoch: 0 }),
			}) as never,
		});
		if (composition.kind !== 'composed') throw new Error('expected composed');
		await composition.coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'user:1', generation: 1 });
		await composition.coordinator.runDueWork();
		const state = await composition.queueState();
		// Observe admission records nothing terminal — the job stays QUEUED, so
		// the engine genuinely holds optional work it is not running.
		expect(state.queueDepth).toBe(1);
		expect(state.saturating).toBe(true);
	});

	it('coalesces foreground triggers (visibility + focus) onto one generation-scoped job', async () => {
		const documentTarget = new EventTarget();
		const windowTarget = new EventTarget();
		const composition = await composeExecuting({ documentTarget, windowTarget });
		if (composition.kind !== 'composed') throw new Error('expected composed');
		Object.defineProperty(document, 'visibilityState', { value: 'visible', configurable: true });
		fireEvent(documentTarget, 'visibilitychange');
		fireEvent(windowTarget, 'focus');
		fireEvent(windowTarget, 'focus');
		await flushMicrotasks();
		// One deduplicated foreground job (coalescing key kind:account), even
		// though three trigger events fired.
		const ingested = composition.events.filter((e) => e.kind === 'trigger-ingested').length;
		const coalesced = composition.events.filter((e) => e.kind === 'trigger-coalesced').length;
		expect(ingested).toBe(1);
		expect(coalesced).toBe(2);
	});

	it('serves the push and action seams only while composed (inert otherwise)', async () => {
		// Before composition the seams are honest no-ops.
		ingestConnectivityPushTrigger();
		ingestConnectivityActionTrigger();
		await flushMicrotasks();
		await expect(readConnectivityCoordinatorState()).resolves.toEqual({
			composed: false,
			reason: 'not-composed',
		});

		const composition = await composeExecuting();
		if (composition.kind !== 'composed') throw new Error('expected composed');
		ingestConnectivityPushTrigger();
		ingestConnectivityActionTrigger();
		await flushMicrotasks();
		expect(composition.events.some((e) => e.kind === 'trigger-ingested' && e.trigger === 'authenticatedPush')).toBe(true);
		expect(composition.events.some((e) => e.kind === 'trigger-ingested' && e.trigger === 'action')).toBe(true);
	});

	it('dispose() removes every subscription: no global, no trigger response', async () => {
		const windowTarget = new EventTarget();
		const composition = await composeExecuting({ windowTarget });
		if (composition.kind !== 'composed') throw new Error('expected composed');
		expect(window.__setjoinConnectivityQueueState).toBeTypeOf('function');
		composition.dispose();
		expect(window.__setjoinConnectivityQueueState).toBeUndefined();
		fireEvent(windowTarget, 'online');
		await flushMicrotasks();
		expect(composition.events.some((e) => e.kind === 'trigger-ingested')).toBe(false);
		await expect(readConnectivityCoordinatorState()).resolves.toEqual({ composed: false, reason: 'not-composed' });
	});

	it('admission stays honest without a shell capability observation: pause, never invented work', async () => {
		const jobs = createMemoryJobPersistence();
		const composition = await composeExecuting({ createJobs: () => jobs });
		if (composition.kind !== 'composed') throw new Error('expected composed');
		await composition.coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'user:1', generation: 1 });
		await composition.coordinator.runDueWork();
		const results = jobs.snapshotResults();
		const recorded = [...results.values()][0];
		expect(recorded?.result.state).toBe('paused');
		expect(
			recorded?.result.state === 'paused' ? recorded.result.reason : null,
		).toBe('capabilityUnavailable');
	});

	it('executes a real bounded step through the composed ports when the observation is fresh', async () => {
		const jobs = createMemoryJobPersistence();
		const email = {
			id: 'm1',
			threadId: 't1',
			mailboxIds: { inbox: true },
			from: [{ name: null, email: 's@e6.test' }],
			to: [],
			subject: 'delta page',
			receivedAt: '2026-09-21T00:00:00Z',
			keywords: { $seen: true },
		} as unknown as Email;
		const composition = await composeExecuting({
			createJobs: () => jobs,
			deltaClient: scriptedDeltaClient([email]),
			capabilityReader: async () => ({ snapshot: nominalSnapshot(), receivedMonoMs: performance.now(), epoch: 0 }),
		});
		if (composition.kind !== 'composed') throw new Error('expected composed');
		// The feed binds the epoch on the live coordinator (same-epoch rule).
		expect(deliverConnectivityCapabilityObservation(nominalSnapshot(), 0)).toBe(true);
		// Invalid snapshots are refused, never coerced.
		expect(deliverConnectivityCapabilityObservation({ fake: true }, 0)).toBe(false);

		await composition.coordinator.ingestTrigger({ kind: 'foreground', accountId: 'user:1', generation: 1 });
		await composition.coordinator.runDueWork();
		const recorded = [...jobs.snapshotResults().values()][0];
		expect(recorded?.result.state).toBe('complete');
		expect(composition.events.some((e) => e.kind === 'step-committed')).toBe(true);
	});

	it('drops a prior-epoch capability observation (freshness contract)', async () => {
		const jobs = createMemoryJobPersistence();
		const email = {
			id: 'm2',
			threadId: 't2',
			mailboxIds: { inbox: true },
			from: [{ name: null, email: 's@e6.test' }],
			to: [],
			subject: 'epoch page',
			receivedAt: '2026-09-21T00:00:00Z',
			keywords: { $seen: true },
		} as unknown as Email;
		const composition = await composeExecuting({
			createJobs: () => jobs,
			deltaClient: scriptedDeltaClient([email]),
		});
		if (composition.kind !== 'composed') throw new Error('expected composed');
		expect(deliverConnectivityCapabilityObservation(nominalSnapshot(), 7)).toBe(true);
		expect(composition.coordinator.epoch).toBe(7);
		// The observation feeds the composition reader only when its epoch
		// matches the bound lifecycle epoch — epoch 7 was just bound, so this
		// run is ADMITTED (eligibility passes the capability gate; the scripted
		// page completes).
		await composition.coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'user:1', generation: 1 });
		await composition.coordinator.runDueWork();
		const recorded = [...jobs.snapshotResults().values()][0];
		expect(recorded?.result.state).toBe('complete');
	});
});

// ── the harness bridge seam (the E6 pair's per-member flag delta) ───────────

describe('harness bridge seam (session projection cannot reach)', () => {
	afterEach(() => {
		delete (window as unknown as Record<string, unknown>).setjoinNative;
	});

	function installBridge(rolloutMode?: string): void {
		(window as unknown as Record<string, unknown>).setjoinNative = rolloutMode === undefined
			? {}
			: { connectivity: { rolloutMode } };
	}

	it('reads the seam only when the bridge carries a non-off mode', () => {
		expect(readBridgeHarnessMode()).toBeNull();
		installBridge();
		expect(readBridgeHarnessMode()).toBeNull();
		installBridge('off');
		expect(readBridgeHarnessMode()).toBeNull();
		installBridge('bogus');
		expect(readBridgeHarnessMode()).toBeNull();
		installBridge('execute');
		expect(readBridgeHarnessMode()).toBe('execute');
	});

	it('the seam grant carries the V209 schema-default ceilings', () => {
		const grant = harnessSeamGrant('execute');
		expect(grant.syncQos.mode).toBe('execute');
		expect(grant.syncQos.backgroundAllowed).toBe(true);
		expect(grant.syncQos.effective.automaticNetwork).toBe('unmetered');
		expect(grant.syncQos.effective.opportunisticRequiresCharging).toBe(true);
	});

	it('resolves the session projection FIRST and the seam only as fallback', () => {
		installBridge('execute');
		// A projecting session wins and names its basis.
		expect(resolveEffectiveGrant(sessionWithSyncQos('observe'))).toEqual({
			grant: expect.objectContaining({ syncQos: expect.objectContaining({ mode: 'observe' }) }),
			basis: 'session-projected',
		});
		// An explicit server-projected OFF beats the seam (the server is the
		// policy authority; the seam only stands in where projection cannot reach).
		expect(resolveEffectiveGrant(sessionWithSyncQos('off'))).toBeNull();
		// No projection → the seam stands in.
		const seam = resolveEffectiveGrant({ effectiveCapabilities: {} });
		expect(seam).toEqual({
			grant: expect.objectContaining({ syncQos: expect.objectContaining({ mode: 'execute' }) }),
			basis: 'harness-seam',
		});
	});

	it('composes the candidate through the seam when the session cannot project', async () => {
		installBridge('execute');
		// The E6 pair reality (verified against the fixture stack): the
		// password-login session document carries NO offline block at all.
		const sessionWithoutOfflineBlock = { effectiveCapabilities: { apps: { mail: true } } };
		const disposer = composeOfflineCoordinatorForSession(
			sessionWithoutOfflineBlock,
			{ userId: 2, email: 'e6-b@e6.test' } as never,
			composedDeps({ sessionSource: () => sessionWithoutOfflineBlock }) as never,
		);
		expect(disposer).toBeTypeOf('function');
		await flushMicrotasks();
		const state = await readConnectivityCoordinatorState();
		expect(state).toMatchObject({
			composed: true,
			basis: 'engine-queue-observed',
			policyBasis: 'harness-seam',
			mode: 'execute',
		});
		disposer?.();
	});

	it('stays INERT with no projection AND no seam (the shipped default)', async () => {
		const disposer = composeOfflineCoordinatorForSession(
			{ effectiveCapabilities: { apps: { mail: true } } },
			{ userId: 1, email: 'a@b.c' } as never,
		);
		expect(disposer).toBeUndefined();
		await flushMicrotasks();
		await expect(readConnectivityCoordinatorState()).resolves.toEqual({
			composed: false,
			reason: 'inert-pair-off',
		});
	});
});

// ── saturation truth through the window bridge ──────────────────────────────

describe('saturation truth (window global contract with the Electron endpoint)', () => {
	it('exposes REAL queue depth through __setjoinConnectivityQueueState', async () => {
		const windowTarget = new EventTarget();
		const composition = await composeOfflineCoordinator({
			accountId: 'user:1',
			grant: grantFrom('execute'),
			deps: composedDeps({ windowTarget }) as never,
		});
		if (composition.kind !== 'composed') throw new Error('expected composed');
		const read = window.__setjoinConnectivityQueueState;
		expect(read).toBeTypeOf('function');
		const empty = await read?.();
		expect(empty).toMatchObject({ composed: true, saturating: false, queueDepth: 0, running: 0 });
		fireEvent(windowTarget, 'online');
		await flushMicrotasks();
		// With no capability observation the trigger honestly pauses (the
		// unavailable state) — the queue depth is 0 again, never a fake
		// "saturating" while nothing admissible is pending.
		const afterPause = await read?.();
		expect(afterPause).toMatchObject({ composed: true, saturating: false, queueDepth: 0 });
		expect(afterPause?.observedAtUtc).toBeTypeOf('string');
	});

	it('answers with observed engine state only while a composition is live', async () => {
		const composition = await composeOfflineCoordinator({
			accountId: 'user:1',
			grant: grantFrom('observe'),
			deps: composedDeps({
				sessionSource: () => sessionWithSyncQos('observe'),
				capabilityReader: async () => ({ snapshot: nominalSnapshot(), receivedMonoMs: performance.now(), epoch: 0 }),
			}) as never,
		});
		if (composition.kind !== 'composed') throw new Error('expected composed');
		await composition.coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'user:1', generation: 1 });
		await composition.coordinator.runDueWork();
		const read = window.__setjoinConnectivityQueueState;
		// Observe mode keeps the ingested job QUEUED (observed, never executed):
		// the endpoint reads a REAL sustained queue depth.
		expect(await read?.()).toMatchObject({
			composed: true,
			basis: 'engine-queue-observed',
			mode: 'observe',
			saturating: true,
			queueDepth: 1,
		});
		composition.dispose();
		expect(window.__setjoinConnectivityQueueState).toBeUndefined();
	});

	it('counts a claimed (running) job in the saturation truth', async () => {
		// Property ref defeats the TS control-flow narrowing of the promise-
		// executor assignment (the resolver is captured asynchronously).
		const gate = { release: null as (() => void) | null };
		const stepGate = new Promise<void>((resolve) => {
			gate.release = resolve;
		});
		const composition = await composeOfflineCoordinator({
			accountId: 'user:1',
			grant: grantFrom('execute'),
			deps: composedDeps({
				deltaClient: {
					emailChanges: async () => {
						await stepGate;
						return { newState: 's-1', hasMoreChanges: false, created: [], updated: [], destroyed: [] };
					},
					emailGet: async () => ({ list: [], state: 's-1' }),
				},
				capabilityReader: async () => ({ snapshot: nominalSnapshot(), receivedMonoMs: performance.now(), epoch: 0 }),
			}) as never,
		});
		if (composition.kind !== 'composed') throw new Error('expected composed');
		deliverConnectivityCapabilityObservation(nominalSnapshot(), 0);
		await composition.coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'user:1', generation: 1 });
		// The cycle claims the job and hangs inside the bounded step.
		const cycle = composition.coordinator.runDueWork();
		await flushMicrotasks();
		const state = await composition.queueState();
		expect(state.running).toBe(1);
		expect(state.saturating).toBe(true);
		gate.release?.();
		await cycle;
		const settled = await composition.queueState();
		expect(settled.running).toBe(0);
	});
});

// ── construction sanity (the branded-steps refusal rides through) ───────────

describe('coordinator contract surface', () => {
	it('createCoordinator is the same factory the composition uses (bounded steps enforced)', () => {
		expect(typeof createCoordinator).toBe('function');
	});
});

// ── the production delta port over the REAL JMAP client (fake server) ───────
//
// E6 Astra P2: the composition's delta adapters wrap `$lib/jmap/client`. The
// port used to fabricate the Email/get response `state` as '' — the re-anchor
// committed `delta:state:` + '', the next run skipped re-anchoring, Email/
// changes with sinceState:'' answered cannotCalculateChanges, and the job
// parked on the '' checkpoint. This suite drives the REAL client adapter (no
// `deps.deltaClient`) over a stubbed-fetch fake server through the full
// re-anchor cycle: anchor from the returned state → commit the REAL state →
// pass it as sinceState → gateway cannotCalculateChanges → the coordinator's
// bounded window resync commits the new state.

describe('production delta port (real client adapter): the re-anchor cycle', () => {
	const ANCHOR_STATE_1 = 'st-42';
	const ANCHOR_STATE_2 = 'st-44';
	const RESYNCED_NEW_STATE = 'st-45';

	function resyncEmail(): Email {
		return {
			id: 'm-resync',
			threadId: 't-resync',
			mailboxIds: { inbox: true },
			from: [{ name: null, email: 's@e6.test' }],
			to: [],
			subject: 'window resync page',
			receivedAt: '2026-09-21T00:00:00Z',
			keywords: { $seen: true },
		} as unknown as Email;
	}

	/** Fake JMAP server over stubbed fetch: routes ONE method call per request
	 *  and records every outgoing (method, args) pair for outgoing-call
	 *  assertions. The handler returns the [responseName, body] pair so the
	 *  gateway's error envelope can ride under its real name ("error"). */
	function jmapFakeServer(
		route: (method: string, args: Record<string, unknown>) => [string, unknown],
	): Array<{ method: string; args: Record<string, unknown> }> {
		const calls: Array<{ method: string; args: Record<string, unknown> }> = [];
		const fetchMock = vi.fn(async (_url: unknown, opts: { body: string }) => {
			const parsed = JSON.parse(opts.body) as {
				methodCalls: Array<[string, Record<string, unknown>, string]>;
			};
			const [method, args] = parsed.methodCalls[0];
			calls.push({ method, args });
			const [name, body] = route(method, args);
			return {
				ok: true,
				status: 200,
				json: async () => ({ sessionState: 's1', methodResponses: [[name, body, '0']] }),
			};
		});
		vi.stubGlobal('fetch', fetchMock);
		return calls;
	}

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('anchors from the REAL Email/get state, passes it as sinceState, and the window resync replaces an unanchorable walk', async () => {
		const email = resyncEmail();
		let anchorReads = 0;
		const sinceStates: string[] = [];
		const calls = jmapFakeServer((method, args) => {
			if (method === 'Email/get') {
				const ids = args.ids as string[];
				if (ids.length === 0) {
					// The re-anchor read: each one returns the server's CURRENT
					// state (the walk moves the state forward between reads).
					const state = anchorReads === 0 ? ANCHOR_STATE_1 : ANCHOR_STATE_2;
					anchorReads += 1;
					return ['Email/get', { state, list: [] }];
				}
				return ['Email/get', { state: 'st-43', list: [email], notFound: [] }];
			}
			if (method === 'Email/changes') {
				sinceStates.push(String(args.sinceState));
				if (args.sinceState === ANCHOR_STATE_1) {
					// The gateway's real rejection shape for a state it cannot
					// calculate changes from (internal/jmap statecodec.go
					// sinceStateError): a method-level "error" envelope.
					return ['error', { type: 'cannotCalculateChanges', description: 'client must resync (malformed sinceState)' }];
				}
				return ['Email/changes', { newState: RESYNCED_NEW_STATE, hasMoreChanges: false, created: [], updated: [], destroyed: [] }];
			}
			if (method === 'Email/query') {
				return ['Email/query', { accountId: 'u1', ids: [email.id], total: 1, position: 0 }];
			}
			throw new Error(`unexpected JMAP method: ${method}`);
		});

		const jobs = createMemoryJobPersistence();
		// NO deps.deltaClient: the composition's production adapter over the
		// real client is the unit under test.
		const composition = await composeOfflineCoordinator({
			accountId: 'user:1',
			grant: grantFrom('execute'),
			deps: composedDeps({
				createJobs: () => jobs,
				capabilityReader: async () => ({ snapshot: nominalSnapshot(), receivedMonoMs: performance.now(), epoch: 0 }),
			}) as never,
		});
		if (composition.kind !== 'composed') throw new Error('expected composed');
		expect(deliverConnectivityCapabilityObservation(nominalSnapshot(), 0)).toBe(true);

		// ── dispatch 1: anchor from the real state, then cannotCalculateChanges.
		await composition.coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'user:1', generation: 1 });
		await composition.coordinator.runDueWork();

		// First delta (no cursor): the re-anchor Email/get ids=[] ran, and the
		// changes walk passed the REAL anchored state as sinceState — the
		// fabricated '' cursor never reaches the wire.
		const anchorCall = calls.find((c) => c.method === 'Email/get' && (c.args.ids as string[]).length === 0);
		expect(anchorCall).toBeTruthy();
		expect(sinceStates[0]).toBe(ANCHOR_STATE_1);
		expect(sinceStates.every((s) => s !== '')).toBe(true);

		// The gateway rejection reached the step (blocked outcome) and the
		// coordinator's ONE bounded window resync replaced the walk (complete).
		expect(composition.events.some((e) => e.kind === 'step-committed' && e.outcome === 'blocked')).toBe(true);
		expect(composition.events.some((e) => e.kind === 'step-committed' && e.outcome === 'complete')).toBe(true);
		const afterDispatch1 = jobs.snapshotJobs()[0];
		expect(afterDispatch1?.state).toBe('complete');
		// The fallback resync committed the NEW walk cursor — not a stranded
		// delta:state:'' checkpoint.
		expect(String(afterDispatch1?.checkpoint?.cursor)).toContain('window:page:');

		// ── dispatch 2: re-anchor again (a window cursor is not a delta anchor)
		// and commit the REAL server state as the durable delta cursor.
		await composition.coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'user:1', generation: 2 });
		await composition.coordinator.runDueWork();

		expect(sinceStates).toEqual([ANCHOR_STATE_1, ANCHOR_STATE_2]);
		const reopened = jobs.snapshotJobs()[0];
		expect(reopened?.state).toBe('complete');
		// The durable checkpoint carries the REAL server state string returned
		// by the Email/get anchor — exactly the value the old port fabricated.
		expect(reopened?.checkpoint?.cursor).toBe(`delta:state:${RESYNCED_NEW_STATE}`);
	});
});
