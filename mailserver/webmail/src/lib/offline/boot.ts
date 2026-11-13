/**
 * E4-I production boot composition: the ONLY production caller of
 * `createCoordinator` (`coordinator.ts`). The E4-I checkpoint
 * (retired-docs:verification/2026-09-17-connectivity-aware-sync-e4i.md) leaves the
 * coordinator's production composition to this module; its only other caller
 * is the test-build harness (`$lib/native/testing/backgroundWorkHarness.ts`).
 *
 * GATING CHAIN (each step fail-closed; the shipped default composes NOTHING):
 *
 *  1. SERVER PROJECTION — the session document's
 *     `effectiveCapabilities.offline.syncQoS` block. The gateway projects it
 *     through `offline_effective_policy`
 *     (sql/reducers/offline_effective_policy.sql), which STRIPS `syncQoS`
 *     unless BOTH `feature.offline_mail` AND `feature.connectivity_aware_sync`
 *     are ON. Presence of the block is therefore the projected flag pair; its
 *     `mode` is the winning policy rollout mode. Absent block ⇒ INERT; block
 *     present with `mode: 'off'` ⇒ INERT too (the server's explicit no): the
 *     coordinator is not constructed, no listener is registered, no window
 *     global exists — the E4-I default-inert contract.
 *  1b. HARNESS BRIDGE SEAM — when the session document cannot project (the
 *     E6 fixture's password-login session carries no JWT device claim, so the
 *     device-gated block is absent for BOTH pair members even with the
 *     fixture's toggle rows ON), the shell's harness rollout-mode seam
 *     (`SETJOIN_E6_CONNECTIVITY_SYNC_MODE`, delivered over the bridge as
 *     `window.setjoinNative.connectivity.rolloutMode` — the launcher-enforced
 *     per-member flag delta of the E6 paired-run lane) stands in, with the
 *     V209 schema-default policy ceilings and an explicit `harness-seam`
 *     policy basis in the saturation body. Unset on every production shell —
 *     the seam field is not attached at all, so production composes only
 *     through (1).
 *  2. PLATFORM CAPABILITY — the native shell injected a contract-valid
 *     `window.setjoinNative` bridge (`isNative()`) whose `db` exposes the E4-I
 *     atomic batch entry (`transactionBatch`). Without it the durable job
 *     persistence refuses to construct (jobStore.ts), so the composition
 *     reports the honest UNAVAILABLE state — never a fake runner.
 *
 * When composed, the ports are REAL: the branded bounded steps over the app's
 * JMAP client, the native SQLCipher store (`store.ts` init path, which applies
 * the versioned migration manifest), the durable persistence, and trigger
 * ingestion wired to the app's existing online/offline/focus/visibility
 * trigger points (push/native-opportunity/action expose seams for their owning
 * lanes). Admission stays authoritative inside the coordinator: policy is
 * re-read from the CURRENT session projection before every dispatch and every
 * step, and capability observations authorize only fresh, same-epoch work —
 * with no shell observation delivered yet the reader resolves null and
 * admission honestly blocks (`capabilityUnavailable`). The observation seam
 * (`deliverConnectivityCapabilityObservation`) is the native owners' entry
 * point, not a manufactured snapshot.
 *
 * SATURATION TRUTH: the composed coordinator's queue/work state is exposed
 * through `window.__setjoinConnectivityQueueState` (content-free, bounded), so
 * the Electron E6 saturation endpoint
 * (`clients/desktop/electron/src/connectivity/saturation.ts`) can answer REAL
 * queue depth instead of the documented `policy-mode-configured` placeholder.
 * The global exists ONLY while a composition is live.
 */

import {
	createCoordinator,
	type CapabilityObservation,
	type Coordinator,
	type CoordinatorClock,
	type CoordinatorEvent,
	type CoordinatorPolicy,
	type CoordinatorTrigger,
	type CoordinatorTriggerKind,
} from './coordinator';
import {
	createDurableJobPersistence,
	durableJobPersistenceAvailable,
	type JobPersistence,
} from './jobStore';
import {
	createSyncDeltaStep,
	createSyncWindowStep,
	type DeltaChangesClient,
	type WindowQueryClient,
} from './steps';
import { getStore, type OfflineStore } from './store';
import type { OfflineDbBridge } from '$lib/native/types';
import { isNative } from '$lib/native';
import { emailChanges, emailGetWithState, emailQuery, JmapMethodError } from '$lib/jmap/client';
import { normalizeBridgeCapabilitySnapshot, type RolloutMode } from './work-contract';
import type { AutomaticNetworkPolicy } from './eligibility';
import type { E5AttachmentPrefetchPref as AttachmentPrefetchPolicy } from './e5Settings';
import type { AuthUser } from '$lib/stores/auth';
import { accountIdentity } from '$lib/db/offline';

/**
 * The Electron-facing saturation surface: the composed webmail installs this
 * window global (name pinned on BOTH sides of the build boundary — see
 * `clients/desktop/electron/src/connectivity/saturation.ts`,
 * `CONNECTIVITY_QUEUE_STATE_GLOBAL`); the main process reads it through
 * `webContents.executeJavaScript(QUEUE_STATE_PROBE_SCRIPT)`. It exists ONLY
 * while a composition is live.
 */
declare global {
	interface Window {
		__setjoinConnectivityQueueState?: () => Promise<ConnectivityQueueStateSnapshot>;
	}
}

/** JMAP session projection enums (offline_effective_policy_snapshot.sql). */
const SYNC_QOS_MODES: readonly RolloutMode[] = ['off', 'observe', 'execute'];
const AUTOMATIC_NETWORK_VALUES: readonly AutomaticNetworkPolicy[] = ['never', 'unmetered', 'any'];
const ATTACHMENT_PREFETCH_VALUES: readonly AttachmentPrefetchPolicy[] = ['never', 'unmetered', 'always'];
const SYNC_QOS_SCHEMA_VERSION = 1 as const;

/** The strict server-projected syncQoS block (schemaVersion 1). */
export interface SessionSyncQos {
	mode: RolloutMode;
	backgroundAllowed: boolean;
	requested: { automaticNetwork: AutomaticNetworkPolicy; attachmentPrefetch: AttachmentPrefetchPolicy };
	effective: {
		automaticNetwork: AutomaticNetworkPolicy;
		attachmentPrefetch: AttachmentPrefetchPolicy;
		opportunisticRequiresCharging: boolean;
	};
}

/** The parsed offline grant: the flag-pair projection plus the window cap. */
export interface SessionOfflineGrant {
	syncQos: SessionSyncQos;
	/** `effectiveCapabilities.offline.maxOfflineDays` — null when absent/not numeric. */
	maxOfflineDays: number | null;
}

type InertReason = 'not-composed' | 'inert-pair-off' | 'inert-mode-off' | 'platform-unavailable';

function isEnumValue<T extends string>(value: unknown, values: readonly T[]): value is T {
	return typeof value === 'string' && (values as readonly string[]).includes(value);
}

function parseSyncQos(raw: unknown): SessionSyncQos | null {
	if (typeof raw !== 'object' || raw === null) return null;
	const qos = raw as Record<string, unknown>;
	if (qos.schemaVersion !== SYNC_QOS_SCHEMA_VERSION) return null;
	if (!isEnumValue(qos.mode, SYNC_QOS_MODES)) return null;
	if (typeof qos.backgroundAllowed !== 'boolean') return null;
	const requested = qos.requested;
	const effective = qos.effective;
	if (typeof requested !== 'object' || requested === null || typeof effective !== 'object' || effective === null) {
		return null;
	}
	const req = requested as Record<string, unknown>;
	const eff = effective as Record<string, unknown>;
	if (!isEnumValue(req.automaticNetwork, AUTOMATIC_NETWORK_VALUES)) return null;
	if (!isEnumValue(req.attachmentPrefetch, ATTACHMENT_PREFETCH_VALUES)) return null;
	if (!isEnumValue(eff.automaticNetwork, AUTOMATIC_NETWORK_VALUES)) return null;
	if (!isEnumValue(eff.attachmentPrefetch, ATTACHMENT_PREFETCH_VALUES)) return null;
	if (typeof eff.opportunisticRequiresCharging !== 'boolean') return null;
	return {
		mode: qos.mode,
		backgroundAllowed: qos.backgroundAllowed,
		requested: { automaticNetwork: req.automaticNetwork, attachmentPrefetch: req.attachmentPrefetch },
		effective: {
			automaticNetwork: eff.automaticNetwork,
			attachmentPrefetch: eff.attachmentPrefetch,
			opportunisticRequiresCharging: eff.opportunisticRequiresCharging,
		},
	};
}

/**
 * The codebase's own client-side read of the flag-pair projection. Returns
 * null whenever the session document carries no VALID `syncQoS` block — which
 * is exactly when either rollout gate is OFF (the SQL strips the block) or the
 * wire shape is not what the server projects (fail closed, never guess).
 */
export function readSessionOfflineGrant(session: unknown): SessionOfflineGrant | null {
	const caps = (session as { effectiveCapabilities?: unknown } | null | undefined)?.effectiveCapabilities;
	if (typeof caps !== 'object' || caps === null) return null;
	const offline = (caps as Record<string, unknown>).offline;
	if (typeof offline !== 'object' || offline === null) return null;
	const block = offline as Record<string, unknown>;
	const syncQos = parseSyncQos(block.syncQoS);
	if (syncQos === null) return null;
	let maxOfflineDays: number | null = null;
	if (typeof block.maxOfflineDays === 'number' && Number.isFinite(block.maxOfflineDays) && block.maxOfflineDays >= 0) {
		maxOfflineDays = block.maxOfflineDays;
	}
	return { syncQos, maxOfflineDays };
}

/**
 * Map the projected grant onto the coordinator's policy input. A null grant
 * (session dropped/changed the block) maps to the OFF policy
 * (`flagEnabled: false`) — the coordinator re-reads this fresh per admission,
 * so a flag narrowed OFF mid-job stops the job at the next step boundary.
 */
export function policyFromGrant(grant: SessionOfflineGrant | null, workOffline: boolean): CoordinatorPolicy {
	if (grant === null) {
		return {
			flagEnabled: false,
			rolloutMode: 'off',
			requested: { backgroundSyncEnabled: false, automaticNetwork: 'never' },
			effective: { backgroundAllowed: false, automaticNetwork: 'never', opportunisticRequiresCharging: true },
			workOffline,
		};
	}
	const { syncQos } = grant;
	return {
		flagEnabled: true,
		rolloutMode: syncQos.mode,
		requested: {
			backgroundSyncEnabled: syncQos.backgroundAllowed,
			automaticNetwork: syncQos.requested.automaticNetwork,
		},
		effective: {
			backgroundAllowed: syncQos.backgroundAllowed,
			automaticNetwork: syncQos.effective.automaticNetwork,
			opportunisticRequiresCharging: syncQos.effective.opportunisticRequiresCharging,
		},
		workOffline,
	};
}

/** Content-free queue/work snapshot for the E6 saturation surface. */
export interface ConnectivityQueueStateSnapshot {
	composed: true;
	/** The queue observation basis (the numbers are read from the live engine). */
	basis: 'engine-queue-observed';
	/**
	 * Which admission-policy path is live: the session projection
	 * (`effectiveCapabilities.offline.syncQoS`) or the harness bridge seam
	 * (`window.setjoinNative.connectivity.rolloutMode` — the E6 pair's
	 * per-member flag delta; unset on every production shell).
	 */
	policyBasis: ConnectivityPolicyBasis;
	mode: RolloutMode;
	/** Due (queued/backoff-due) optional jobs the coordinator would admit. */
	queueDepth: number;
	/** Jobs currently claimed (lease held) by this coordinator. */
	running: number;
	/** True when the engine holds real optional work (queue or running). */
	saturating: boolean;
	/** Content-free trigger accounting: settled ingestions and coalescences. */
	triggersIngested: number;
	triggersCoalesced: number;
	/** The finite trigger-kind enum, or null before the first settled trigger. */
	lastTriggerKind: CoordinatorTriggerKind | null;
	observedAtUtc: string;
}

/**
 * Which admission-policy path a live policy read resolved from. The third
 * value is the neither-projection-nor-seam path (the OFF policy stand-in): a
 * composition can reach it when a session refresh drops a projection the
 * composition was built with and no harness seam exists — reporting it as
 * 'session-projected' would name a projection that is not there.
 */
export type ConnectivityPolicyBasis = 'session-projected' | 'harness-seam' | 'no-projection';

/** The renderer-side saturation global (name pinned on BOTH sides of the
 *  build boundary — see `clients/desktop/electron/src/connectivity/
 *  saturation.ts`, `CONNECTIVITY_QUEUE_STATE_GLOBAL`). */
const windowGlobalName = '__setjoinConnectivityQueueState';

/**
 * The honest unavailable verdict, made observable: when the flag-pair gates
 * ADMITTED but the platform capability refused (no native bridge, no E4-I
 * atomic batch entry, store init failed), the saturation global answers this
 * diagnostic instead of the queue state — the Electron endpoint can name the
 * gate in its body instead of a blanket "not exposed". The INERT cases (pair
 * off / mode off) install NOTHING: the shipped default and the comparator
 * expose no connectivity surface at all. This is a static diagnostic, not an
 * engine: no listener, no coordinator, no work exists behind it.
 */
export interface ConnectivityGateState {
	composed: false;
	reason: 'no-native-bridge' | 'no-durable-persistence' | 'store-init-failed';
}

export type ConnectivityCompositionState =
	| { composed: false; reason: InertReason }
	| ConnectivityQueueStateSnapshot;

/** Bounded decision-record ring (privacy-safe CoordinatorEvents only). */
const EVENT_RING_LIMIT = 64;

/** Default window fallback when the grant carries no numeric cap: the app's
 *  default offline window in days (`window.ts DEFAULT_OFFLINE_WINDOW = '30d'`). */
const DEFAULT_WINDOW_DAYS = 30;

/** Mirror of `window.ts cutoffMillis` for a plain day count. */
function cutoffForDays(days: number, now: number): number | null {
	if (!Number.isFinite(days) || days <= 0) return null;
	return now - days * 86_400_000;
}

function monoNow(): number {
	return typeof performance !== 'undefined' ? performance.now() : Date.now();
}

export interface OfflineCoordinatorDeps {
	clock?: CoordinatorClock;
	random?: () => number;
	isNativeShell?: () => boolean;
	bridgeDb?: () => OfflineDbBridge | null;
	openStore?: () => OfflineStore | null;
	createJobs?: (db: OfflineDbBridge) => JobPersistence;
	deltaClient?: DeltaChangesClient;
	windowClient?: WindowQueryClient;
	/** Defaults to the module capability-observation feed (null until the
	 *  native owners deliver one — the honest unsupported path). */
	capabilityReader?: () => Promise<CapabilityObservation | null>;
	readWorkOffline?: () => boolean;
	/** The live session projection the policy re-reads per admission.
	 *  Defaults to the session bound by `composeOfflineCoordinatorForSession`. */
	sessionSource?: () => unknown;
	/** Trigger targets; overridable so tests drive real DOM events. */
	windowTarget?: EventTarget;
	documentTarget?: EventTarget;
	/** Install `window.__setjoinConnectivityQueueState` (default true when a
	 *  `window` exists; the Electron saturation surface reads it). */
	installQueueStateGlobal?: boolean;
	onEvent?: (event: CoordinatorEvent) => void;
}

export type ComposedOfflineCoordinator = {
	kind: 'composed';
	accountId: string;
	coordinator: Coordinator;
	/** Bounded, content-free decision-record ring (diagnostics). */
	readonly events: readonly CoordinatorEvent[];
	/** Content-free queue/work snapshot; resolved from the live coordinator. */
	queueState(): Promise<ConnectivityQueueStateSnapshot>;
	/** Removes every trigger listener, the window global, and the engine. */
	dispose(): void;
};

export type OfflineCoordinatorComposition =
	| { kind: 'inert'; reason: 'pair-off' | 'mode-off' }
	| { kind: 'unavailable'; reason: 'no-native-bridge' | 'no-durable-persistence' | 'store-init-failed' }
	| ComposedOfflineCoordinator;

interface ModuleState {
	/** The ONE live composition (module singleton per page lifetime). */
	current: ComposedOfflineCoordinator | null;
	/** Why no composition is live (diagnostics honesty for the inert state). */
	lastInertReason: InertReason;
	/** Latest validated capability observation (the native owners' feed). */
	observation: CapabilityObservation | null;
	/** The session projection the composed policy re-reads (wrapper-bound). */
	session: unknown;
}

const state: ModuleState = {
	current: null,
	lastInertReason: 'not-composed',
	observation: null,
	session: null,
};

/**
 * Capability-observation seam (the native owners' entry point). Stores the
 * LATEST validated observation and binds its lifecycle epoch on the live
 * coordinator; observations from a prior epoch cannot authorize work
 * (coordinator.ts freshness gate). Invalid snapshots are refused, never
 * coerced. Returns true when the observation was admitted to the feed.
 */
export function deliverConnectivityCapabilityObservation(snapshot: unknown, epoch: number): boolean {
	const validated = normalizeBridgeCapabilitySnapshot(snapshot);
	if (validated === null) return false;
	state.observation = { snapshot: validated, receivedMonoMs: monoNow(), epoch };
	if (state.current !== null) state.current.coordinator.bindLifecycleEpoch(epoch);
	return true;
}

/**
 * The production composition. Async only because the store open + versioned
 * migration run (`store.init()`) is async; every gate before it is sync and
 * fail-closed. Never throws.
 */
export async function composeOfflineCoordinator(input: {
	accountId: string;
	grant: SessionOfflineGrant;
	deps?: OfflineCoordinatorDeps;
}): Promise<OfflineCoordinatorComposition> {
	const { accountId, grant } = input;
	const deps = input.deps ?? {};
	// Gate 1 (server projection): mode 'off' admits no optional work, so the
	// composition stays INERT even with the flag pair projected ON — the
	// E4-I default-inert contract (zero background work, zero subscriptions).
	if (grant.syncQos.mode === 'off') {
		state.lastInertReason = 'inert-mode-off';
		return { kind: 'inert', reason: 'mode-off' };
	}
	const isNativeShell = deps.isNativeShell ?? (() => isNative());
	const bridgeDb = deps.bridgeDb ?? (() => (typeof window !== 'undefined' ? (window.setjoinNative?.db ?? null) : null));
	// Gate 2 (platform capability): the honest unavailable state — no fake
	// runner. Durable persistence refuses non-atomic storage by contract. The
	// wrapper makes the refusal observable through the gate-state global (a
	// static diagnostic; the inert cases never install one).
	if (!isNativeShell()) {
		state.lastInertReason = 'platform-unavailable';
		return { kind: 'unavailable', reason: 'no-native-bridge' };
	}
	const db = bridgeDb();
	if (db === null || !durableJobPersistenceAvailable(db)) {
		state.lastInertReason = 'platform-unavailable';
		return { kind: 'unavailable', reason: 'no-durable-persistence' };
	}
	const store = deps.openStore ? deps.openStore() : getStore();
	if (store === null) {
		state.lastInertReason = 'platform-unavailable';
		return { kind: 'unavailable', reason: 'store-init-failed' };
	}
	try {
		await store.init();
	} catch {
		state.lastInertReason = 'platform-unavailable';
		return { kind: 'unavailable', reason: 'store-init-failed' };
	}

	const clock: CoordinatorClock = deps.clock ?? { nowMonoMs: monoNow, nowUtcMs: () => Date.now() };
	const random = deps.random ?? Math.random;
	const readWorkOffline = deps.readWorkOffline ?? (() => false);
	const sessionSource = deps.sessionSource ?? (() => state.session);
	const jobs: JobPersistence = deps.createJobs ? deps.createJobs(db) : createDurableJobPersistence(db);
	let running = 0;
	// Lease accounting feeds the saturation truth: a job between its winning
	// CAS claim and its lease release is RUNNING. The wrapper observes the
	// persistence boundary the coordinator itself drives — no invented state.
	const observedJobs: JobPersistence = {
		...jobs,
		async claimLease(jobId, owner, nowUtcMs) {
			const fence = await jobs.claimLease(jobId, owner, nowUtcMs);
			if (fence !== null) running += 1;
			return fence;
		},
		async releaseLease(jobId, owner, options) {
			await jobs.releaseLease(jobId, owner, options);
			running = Math.max(0, running - 1);
		},
	};

	// The REAL Email/get response state rides through (E6 Astra P2 fix): the
	// delta step's re-anchor commits `anchored.state` as its durable delta
	// cursor, so a fabricated value here used to strand the walk — cursor
	// `delta:state:` + '' skipped re-anchoring forever, Email/changes with
	// sinceState:'' answered cannotCalculateChanges, and the job parked on the
	// '' checkpoint. emailGetWithState returns the server's state verbatim.
	const jmapEmailGet = async (
		args: { ids: string[]; properties: string[] },
		cancellation?: { signal: AbortSignal },
	) => emailGetWithState(args.ids, args.properties, cancellation?.signal);
	const deltaClient: DeltaChangesClient = deps.deltaClient ?? {
		emailChanges: async (args, cancellation) => {
			// errorPolicy 'throw': a method-level error envelope must REACH the
			// delta step. The default return-empty policy folded a gateway
			// cannotCalculateChanges into an empty success page whose ''
			// newState the step then committed as its next delta cursor — the
			// same fabrication class as the state string above, with the
			// blocked → window-resync fallback never engaging.
			try {
				return await emailChanges(args.sinceState, args.maxChanges, cancellation?.signal, { errorPolicy: 'throw' });
			} catch (error) {
				// The delta step's classifier reads `error.type`; rethrow the
				// structured JmapMethodError type on that field so a real
				// gateway cannotCalculateChanges maps to `blocked` → the one
				// bounded window resync (never a generic retryable failure —
				// the gateway's description text does not carry the token).
				if (error instanceof JmapMethodError) {
					throw Object.assign(new Error(error.message), { type: error.jmapType });
				}
				throw error;
			}
		},
		emailGet: jmapEmailGet,
	};
	const windowClient: WindowQueryClient = deps.windowClient ?? {
		emailQuery: async (filter, sort, limit, position, cancellation) =>
			emailQuery(filter, sort, limit, position, cancellation?.signal),
		emailGet: jmapEmailGet,
	};

	const events: CoordinatorEvent[] = [];
	const onEvent = (event: CoordinatorEvent) => {
		events.push(event);
		if (events.length > EVENT_RING_LIMIT) events.shift();
		deps.onEvent?.(event);
	};
	const stepClock = { nowMonoMs: clock.nowMonoMs };	const deltaStep = createSyncDeltaStep(deltaClient, stepClock);
	// The window step is the cannotCalculateChanges fallback resync; its
	// cutoff is the server-capped window fixed at factory time (the projection
	// itself is the authority for the cap; never widened client-side).
	const windowDaysCap = grant.maxOfflineDays ?? DEFAULT_WINDOW_DAYS;
	const windowCutoffMs = cutoffForDays(Math.min(DEFAULT_WINDOW_DAYS, windowDaysCap), clock.nowUtcMs());
	const windowStep = createSyncWindowStep(windowClient, { ...stepClock, windowCutoffMs });

	// Capability reader: the module observation feed while it carries a
	// same-epoch observation, else the honest null (unsupported/failed path).
	let coordinatorRef: Coordinator | null = null;
	const capabilityReader = deps.capabilityReader ?? (async (): Promise<CapabilityObservation | null> => {
		const coordinator = coordinatorRef;
		const observation = state.observation;
		if (coordinator === null || observation === null || observation.epoch !== coordinator.epoch) return null;
		return observation;
	});

	// The LIVE admission policy, re-resolved fresh at every read (the
	// coordinator re-reads per dispatch and per step): the session projection
	// when present, else the harness bridge seam, else the OFF policy. The
	// basis rides along so the saturation surface can name its source.
	const resolveLivePolicy = async (): Promise<{ policy: CoordinatorPolicy; basis: ConnectivityPolicyBasis }> => {
		const sessionGrant = readSessionOfflineGrant(sessionSource());
		if (sessionGrant !== null && sessionGrant.syncQos.mode !== 'off') {
			return { policy: policyFromGrant(sessionGrant, readWorkOffline()), basis: 'session-projected' };
		}
		const seamMode = readBridgeHarnessMode();
		if (seamMode !== null) {
			return { policy: policyFromGrant(harnessSeamGrant(seamMode), readWorkOffline()), basis: 'harness-seam' };
		}
		// Neither projection nor seam: the OFF policy stands in. Name the basis
		// truthfully — nothing was projected here (a composition only reaches
		// this read after a session refresh dropped the projection it was
		// built with, with no harness seam behind it).
		return { policy: policyFromGrant(null, readWorkOffline()), basis: 'no-projection' };
	};

	const coordinator = createCoordinator({
		clock,
		random,
		// Policy re-reads the CURRENT projection on every admission: a session
		// refresh that drops syncQoS maps to flagEnabled false and stops work
		// at the next step boundary.
		policy: {
			readPolicy: async () => (await resolveLivePolicy()).policy,
		},
		capability: { readCapability: capabilityReader },
		store,
		deltaStep,
		windowStep,
		jobs: observedJobs,
		onEvent,
	});
	coordinatorRef = coordinator;

	// Content-free trigger accounting for the saturation truth: counts and the
	// finite trigger-kind enum only — never content, never account identity.
	const triggerStats = { ingested: 0, coalesced: 0, lastKind: null as CoordinatorTriggerKind | null };

	const composition = await finishComposition({
		accountId,
		deps,
		coordinator,
		clock,
		events,
		resolveLivePolicy,
		ingest: (trigger: CoordinatorTrigger) => {
			void coordinator
				.ingestTrigger(trigger)
				.then((outcome) => {
					// One admission cycle per settled trigger (coalesced
					// generations collapse into one); fire-and-forget — a cycle
					// failure is a recorded coordinator event, never an
					// unhandled rejection.
					if (outcome.kind === 'queued' || outcome.kind === 'coalesced') {
						if (outcome.kind === 'queued') triggerStats.ingested += 1;
						else triggerStats.coalesced += 1;
						triggerStats.lastKind = trigger.kind;
						void coordinator.runDueWork().catch(() => {});
					}
				})
				.catch(() => {});
		},
		runningCount: () => running,
		triggerStats: () => ({ ...triggerStats }),
	});
	return composition;
}

/** Trigger-listener + saturation-global assembly (kept out of the way of the
 *  ports above; the composition is the module's ONLY writer of these). */
async function finishComposition(input: {
	accountId: string;
	deps: OfflineCoordinatorDeps;
	coordinator: Coordinator;
	clock: CoordinatorClock;
	events: CoordinatorEvent[];
	resolveLivePolicy: () => Promise<{ policy: CoordinatorPolicy; basis: ConnectivityPolicyBasis }>;
	ingest: (trigger: CoordinatorTrigger) => void;
	runningCount: () => number;
	triggerStats: () => { ingested: number; coalesced: number; lastKind: CoordinatorTriggerKind | null };
}): Promise<ComposedOfflineCoordinator> {
	const { accountId, deps, coordinator, clock, events, resolveLivePolicy, ingest, runningCount, triggerStats } = input;
	let generation = 0;
	const nextGeneration = () => {
		generation += 1;
		return generation;
	};
	const trigger = (kind: CoordinatorTriggerKind, extra?: Partial<CoordinatorTrigger>): void => {
		ingest({ kind, accountId, generation: nextGeneration(), ...extra });
	};

	// Trigger wiring — the app's existing online/offline/focus/visibility
	// trigger points. Each trigger carries a strictly increasing authenticated
	// generation; the coordinator coalesces per (kind, account).
	const windowTarget = deps.windowTarget ?? (typeof window !== 'undefined' ? window : undefined);
	const documentTarget = deps.documentTarget ?? (typeof document !== 'undefined' ? document : undefined);
	const listeners: Array<() => void> = [];
	const listen = (target: EventTarget | undefined, type: string, handler: () => void) => {
		if (target === undefined) return;
		target.addEventListener(type, handler);
		listeners.push(() => target.removeEventListener(type, handler));
	};
	listen(windowTarget, 'online', () => trigger('reconnect'));
	listen(documentTarget, 'visibilitychange', () => {
		if (typeof document === 'undefined' || document.visibilityState === 'visible') trigger('foreground');
	});
	listen(windowTarget, 'focus', () => trigger('foreground'));

	const queueState = async (): Promise<ConnectivityQueueStateSnapshot> => {
		const due = await coordinator.listJobs();
		const queueDepth = due.length;
		const running = runningCount();
		const { policy, basis } = await resolveLivePolicy();
		const stats = triggerStats();
		return {
			composed: true,
			basis: 'engine-queue-observed',
			policyBasis: basis,
			mode: policy.rolloutMode,
			queueDepth,
			running,
			saturating: queueDepth + running > 0,
			triggersIngested: stats.ingested,
			triggersCoalesced: stats.coalesced,
			lastTriggerKind: stats.lastKind,
			observedAtUtc: new Date(clock.nowUtcMs()).toISOString(),
		};
	};

	let globalInstalled = false;
	if (deps.installQueueStateGlobal ?? true) {
		if (typeof window !== 'undefined') {
			(window as unknown as Record<string, unknown>)[windowGlobalName] = () => queueState();
			globalInstalled = true;
		}
	}

	const composition: ComposedOfflineCoordinator = {
		kind: 'composed',
		accountId,
		coordinator,
		get events(): readonly CoordinatorEvent[] {
			return events;
		},
		queueState,
		dispose(): void {
			for (const remove of listeners) remove();
			listeners.length = 0;
			if (globalInstalled && typeof window !== 'undefined') {
				delete (window as unknown as Record<string, unknown>)[windowGlobalName];
				globalInstalled = false;
			}
			if (state.current === composition) state.current = null;
			coordinator.dispose();
		},
	};
	state.current = composition;
	// Persistence recovery: a prior session's durable queue resumes with one
	// admission cycle (the coordinator's own gates decide whether anything
	// may actually run).
	void coordinator.runDueWork().catch(() => {});
	return composition;
}

// ── Trigger seams (the lanes that own the other E4-I trigger kinds) ─────────

let seamGeneration = 0;
function nextSeamGeneration(): number {
	seamGeneration += 1;
	return seamGeneration;
}

function ingestFromSeam(trigger: CoordinatorTrigger): void {
	const current = state.current;
	if (current === null) return;
	void current.coordinator
		.ingestTrigger(trigger)
		.then((outcome) => {
			if (outcome.kind === 'queued' || outcome.kind === 'coalesced') {
				void current.coordinator.runDueWork().catch(() => {});
			}
		})
		.catch(() => {});
}

/**
 * Authenticated-push seam: the push lane calls this when an authenticated
 * push is delivered while the substrate is live. Inert (a no-op) when no
 * composition exists — the default-inert contract.
 */
export function ingestConnectivityPushTrigger(): void {
	const current = state.current;
	if (current === null) return;
	ingestFromSeam({ kind: 'authenticatedPush', accountId: current.accountId, generation: nextSeamGeneration() });
}

/**
 * Explicit-action seam: explicit user work runs as the interactive class (the
 * offline action queue's replay path calls this when the substrate is live).
 * Inert when no composition exists.
 */
export function ingestConnectivityActionTrigger(): void {
	const current = state.current;
	if (current === null) return;
	ingestFromSeam({ kind: 'action', accountId: current.accountId, generation: nextSeamGeneration(), workClass: 'interactive' });
}

/**
 * The harness bridge seam (`window.setjoinNative.connectivity.rolloutMode`):
 * the E6 pair's per-member flag delta. The member session document CANNOT
 * carry the device-gated `offline_effective_policy` block (the fixture's
 * password-login session has no JWT device claim — verified against the
 * fixture stack 2026-09-21), so the desktop lane's documented member-flag
 * mechanism (the launcher-enforced `SETJOIN_E6_CONNECTIVITY_SYNC_MODE`) is
 * delivered to the webmail over the bridge (`clients/desktop/electron/src/
 * connectivity/rollout.ts` → preload). Absent on every production shell
 * (the env seam is unset → the preload attaches nothing) — the shipped
 * default stays the session-projection path alone.
 */
export function readBridgeHarnessMode(): RolloutMode | null {
	if (typeof window === 'undefined') return null;
	const raw = window.setjoinNative?.connectivity?.rolloutMode;
	// The bridge is an unvalidated injection: the mode is re-checked here, an
	// 'off' (or unknown) value admits nothing.
	return isEnumValue(raw, SYNC_QOS_MODES) && raw !== 'off' ? raw : null;
}

/**
 * The harness-seam policy stand-in. The fixture's server posture is the V209
 * schema defaults (`background_sync_allowed=true`, `automatic_network_max=
 * 'unmetered'`, `opportunistic_requires_charging=true`) with the winning mode
 * carried by the seam itself. This stand-in exists ONLY while the session
 * document projects no `syncQoS` block; a session projection (production)
 * always supersedes it, per admission.
 */
export function harnessSeamGrant(mode: RolloutMode): SessionOfflineGrant {
	return {
		syncQos: {
			mode,
			backgroundAllowed: true,
			requested: { automaticNetwork: 'unmetered', attachmentPrefetch: 'never' },
			effective: {
				automaticNetwork: 'unmetered',
				attachmentPrefetch: 'never',
				opportunisticRequiresCharging: true,
			},
		},
		maxOfflineDays: null,
	};
}

/**
 * The effective admission grant for THIS session: the server projection when
 * the session document carries it (the production path), else the harness
 * bridge seam when the shell advertises one, else null (INERT). An explicit
 * server-projected `mode: 'off'` beats the seam — the server is the policy
 * authority; the seam only stands in where the projection cannot reach.
 */
export function resolveEffectiveGrant(
	session: unknown,
): { grant: SessionOfflineGrant; basis: ConnectivityPolicyBasis } | null {
	const sessionGrant = readSessionOfflineGrant(session);
	if (sessionGrant !== null && sessionGrant.syncQos.mode !== 'off') {
		return { grant: sessionGrant, basis: 'session-projected' };
	}
	if (sessionGrant !== null) {
		// An explicit server-projected `mode: 'off'` beats the seam — the
		// server is the policy authority; the seam only stands in where the
		// projection cannot reach at all.
		return null;
	}
	const seamMode = readBridgeHarnessMode();
	if (seamMode !== null) return { grant: harnessSeamGrant(seamMode), basis: 'harness-seam' };
	return null;
}

/**
 * The +layout.svelte boot wiring point (the `installCapsHandler` genre).
 * Returns undefined — the $effect cleanup contract — whenever the identity is
 * unresolved or the projected pair is OFF/mode-off: NOTHING is constructed
 * and NO listener or global exists. Returns a disposer otherwise.
 *
 * The composition is async (store init), so the disposer also guards the
 * in-flight compose: a session torn down before readiness disposes the
 * composition the moment it lands.
 */
export function composeOfflineCoordinatorForSession(
	session: unknown,
	user: AuthUser | null,
	deps?: OfflineCoordinatorDeps,
): (() => void) | undefined {
	const accountId = accountIdentity(user);
	if (accountId === null) return undefined;
	const parsed = readSessionOfflineGrant(session);
	if (parsed !== null && parsed.syncQos.mode === 'off') state.lastInertReason = 'inert-mode-off';
	const effective = resolveEffectiveGrant(session);
	if (effective === null) {
		if (parsed === null) state.lastInertReason = 'inert-pair-off';
		return undefined;
	}
	state.session = session;
	let handle: ComposedOfflineCoordinator | null = null;
	let cancelled = false;
	const installGateState = (reason: ConnectivityGateState['reason']): void => {
		if (deps?.installQueueStateGlobal ?? true) {
			if (typeof window !== 'undefined') {
				(window as unknown as Record<string, unknown>)[windowGlobalName] = (): ConnectivityGateState => ({
					composed: false,
					reason,
				});
			}
		}
	};
	void composeOfflineCoordinator({ accountId, grant: effective.grant, deps }).then((composition) => {
		if (composition.kind === 'composed') {
			if (cancelled) {
				composition.dispose();
				return;
			}
			handle = composition;
			return;
		}
		if (composition.kind === 'unavailable' && !cancelled) installGateState(composition.reason);
	});
	return () => {
		cancelled = true;
		handle?.dispose();
		handle = null;
		// Also clear a stale gate diagnostic from an earlier unavailable
		// attempt (effects clean up before they re-run, so a fresh
		// composition re-installs its own surface afterwards).
		if (typeof window !== 'undefined') {
			delete (window as unknown as Record<string, unknown>)[windowGlobalName];
		}
	};
}

/**
 * Read the LIVE composition state (saturation + diagnostics). The window
 * global `__setjoinConnectivityQueueState` is the Electron-facing surface;
 * this async accessor is the in-app one (it resolves from the live
 * coordinator, never from a cached guess).
 */
export async function readConnectivityCoordinatorState(): Promise<ConnectivityCompositionState> {
	const current = state.current;
	if (current === null) return { composed: false, reason: state.lastInertReason };
	return current.queueState();
}

/** Test isolation ONLY: the module singleton persists across suites. */
export function __resetBootForTests(): void {
	state.current?.dispose();
	state.current = null;
	state.observation = null;
	state.lastInertReason = 'not-composed';
	state.session = null;
	seamGeneration = 0;
}
