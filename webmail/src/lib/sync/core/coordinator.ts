// Shared framework-free SyncCoordinator (Wave 2.8, #555).
//
// Coordinates push/SSE/IPC wakeups, single-flight coalescing, bounded steps,
// reconnect recovery, revocation write barriers, and critical-activity
// preemption across Webmail and Electron main-process offline-core consumers.
//
// Strictly ESM with `.js`-relative imports; zero Svelte, `$lib`, `$app`, DOM,
// or Node-only imports.

import { ReconnectBackoff, type ReconnectBackoffOptions } from '../../ws/backoff.js';
import {
	DEFAULT_SYNC_BUDGET_BYTES,
	DEFAULT_SYNC_BUDGET_MS,
	DEFAULT_SYNC_BUDGET_RECORDS,
	isPreemptibleLane,
	scopeKeyString,
	type CriticalActivityLike,
	type OfflineWipeEvent,
	type RevocationFence,
	type ScopeKey,
	type ScopeRevokedEvent,
	type ScopeSyncState,
	type StepOutcome,
	type SyncBudget,
	type SyncLane,
	type SyncScopeAdapter,
	type SyncTriggerKind,
	type SyncWakeup,
	type WakeupTransport,
} from './types.js';
import {
	MAX_ATTACHED_SCOPES,
	validateOfflineWipe,
	validateScopeRevoked,
	validateSyncWakeup,
	type ValidationWarnFn,
} from './validate.js';

/** Default recovery backoff cap: 1s → 5m (PLAN-555 §1.1). */
export const DEFAULT_RECOVERY_BASE_MS = 1_000;
export const DEFAULT_RECOVERY_MAX_MS = 300_000;

export class SyncFenceAbortedError extends Error {
	constructor(message = 'sync commit aborted by revocation or session fence') {
		super(message);
		this.name = 'SyncFenceAbortedError';
	}
}

export interface SyncCoordinatorOptions {
	transport?: WakeupTransport;
	/** Injected shared CriticalActivityCounter (ARCH-023 — never instantiate a second one). */
	critical?: CriticalActivityLike;
	nowMonoMs?: () => number;
	random?: () => number;
	backoff?: ReconnectBackoffOptions;
	budget?: {
		maxRecords?: number;
		maxBytes?: number;
		maxDurationMs?: number;
	};
	onWarning?: ValidationWarnFn;
	/** Security-lane callback executed AFTER in-flight sync steps are aborted & settled. */
	onOfflineWipe?: (event: OfflineWipeEvent) => Promise<void> | void;
	/**
	 * Optional cap on simultaneously running consumer steps across all scopes
	 * (e.g. `1` in Electron MirrorService to serialize shared SQLite access).
	 */
	maxGlobalConcurrency?: number;
}

interface ConsumerEntry {
	readonly key: string;
	readonly scopeKey: string;
	readonly adapter: SyncScopeAdapter;
	readonly lane: SyncLane;
	readonly debounceMs: number;
	readonly backoff: ReconnectBackoff;
	inFlight: Promise<void> | null;
	controller: AbortController | null;
	debounceTimer: ReturnType<typeof setTimeout> | null;
	backoffTimer: ReturnType<typeof setTimeout> | null;
	dirty: boolean;
	pendingTrigger: SyncTriggerKind;
	pendingWakeup: SyncWakeup | undefined;
	/** Preserved step mode across SyncBudget yield boundaries (e.g. multi-page fullResync/reconcile). */
	pendingMode: 'delta' | 'fullResync' | 'reconcile' | null;
	budgetYieldPending: boolean;
	budgetYieldTimer: ReturnType<typeof setTimeout> | null;
	budgetYieldPromise: Promise<void> | null;
	reconnectPending: boolean;
	storageFull: boolean;
	storageFullDetail: string | null;
	lastAppliedSeq: number;
	detached: boolean;
	deferredByCritical: boolean;
	preemptedByCritical: boolean;
	disposed: boolean;
}

function defaultNowMonoMs(): number {
	return typeof performance !== 'undefined' ? performance.now() : Date.now();
}

/**
 * Coalesces a newly-arriving wakeup onto an already-pending wakeup for the same
 * consumer (Fix #1): preserves the union of `dataTypes` (keeping `undefined` if
 * either wakeup meant "all types"), merges `changed` state maps, and keeps the
 * highest monotonic `seq`.
 */
function mergeWakeups(prev: SyncWakeup | undefined, next: SyncWakeup): SyncWakeup {
	if (!prev) return next;
	const dataTypes =
		prev.dataTypes === undefined || next.dataTypes === undefined
			? undefined
			: [...new Set([...prev.dataTypes, ...next.dataTypes])];
	const changed =
		prev.changed || next.changed
			? { ...(prev.changed ?? {}), ...(next.changed ?? {}) }
			: undefined;
	return {
		scopeKind: next.scopeKind,
		scopeId: next.scopeId,
		seq: Math.max(prev.seq, next.seq),
		...(dataTypes !== undefined ? { dataTypes } : {}),
		...(changed !== undefined ? { changed } : {}),
		...(next.reason !== undefined
			? { reason: next.reason }
			: prev.reason !== undefined
				? { reason: prev.reason }
				: {}),
	};
}

function isAbortError(err: unknown): boolean {
	if (err instanceof SyncFenceAbortedError) return true;
	if (err instanceof Error && err.name === 'AbortError') return true;
	if (typeof err === 'object' && err !== null) {
		const typed = err as { name?: unknown; code?: unknown };
		if (typed.name === 'AbortError' || typed.code === 20) return true;
	}
	return false;
}

function isCapacityError(err: unknown): boolean {
	if (err instanceof Error && err.name === 'MailPageCapacityError') return true;
	if (typeof err === 'object' && err !== null) {
		const typed = err as { name?: unknown; code?: unknown };
		if (typed.name === 'MailPageCapacityError' || typed.code === 'storage' || typed.code === 'capacityExceeded') {
			return true;
		}
	}
	return false;
}

export class SyncCoordinator {
	readonly #nowMonoMs: () => number;
	readonly #random: () => number;
	readonly #backoffOptions: ReconnectBackoffOptions;
	readonly #maxRecords: number;
	readonly #maxBytes: number;
	readonly #maxDurationMs: number;
	readonly #maxGlobalConcurrency: number;
	readonly #onWarning: ValidationWarnFn;
	readonly #onOfflineWipe?: (event: OfflineWipeEvent) => Promise<void> | void;
	readonly #critical?: CriticalActivityLike;
	readonly #transport?: WakeupTransport;

	readonly #entries = new Map<string, ConsumerEntry>();
	readonly #entriesByScope = new Map<string, Set<ConsumerEntry>>();
	readonly #revocationEpochs = new Map<string, number>();
	readonly #purgeMutexByScope = new Map<string, Promise<void>>();
	readonly #scopeRevokedListeners = new Set<(event: ScopeRevokedEvent) => Promise<void> | void>();
	readonly #unsubscribers: Array<() => void> = [];
	readonly #concurrencyWaitQueue: ConsumerEntry[] = [];
	readonly #queuedForConcurrency = new Set<ConsumerEntry>();

	#activeRunCount = 0;
	#wipeFenceDepth = 0;
	#wipeFencePromise: Promise<void> | null = null;
	#resolveWipeFence: (() => void) | null = null;
	#sessionGeneration = 0;
	#disposed = false;

	constructor(options: SyncCoordinatorOptions = {}) {
		this.#nowMonoMs = options.nowMonoMs ?? defaultNowMonoMs;
		this.#random = options.random ?? (() => Math.random());
		this.#backoffOptions = {
			baseDelayMs: options.backoff?.baseDelayMs ?? DEFAULT_RECOVERY_BASE_MS,
			maxDelayMs: options.backoff?.maxDelayMs ?? DEFAULT_RECOVERY_MAX_MS,
			stableUptimeMs: options.backoff?.stableUptimeMs ?? 0,
			random: options.backoff?.random ?? this.#random,
			now: options.backoff?.now ?? this.#nowMonoMs,
		};
		this.#maxRecords = options.budget?.maxRecords ?? DEFAULT_SYNC_BUDGET_RECORDS;
		this.#maxBytes = options.budget?.maxBytes ?? DEFAULT_SYNC_BUDGET_BYTES;
		this.#maxDurationMs = options.budget?.maxDurationMs ?? DEFAULT_SYNC_BUDGET_MS;
		this.#maxGlobalConcurrency =
			options.maxGlobalConcurrency !== undefined && options.maxGlobalConcurrency > 0
				? Math.floor(options.maxGlobalConcurrency)
				: Number.POSITIVE_INFINITY;
		this.#onWarning =
			options.onWarning ??
			((reason, detail) => {
				if (detail) console.warn('[SyncCoordinator]', reason, detail);
				else console.warn('[SyncCoordinator]', reason);
			});
		this.#onOfflineWipe = options.onOfflineWipe;
		this.#critical = options.critical;
		this.#transport = options.transport;

		if (this.#critical) {
			this.#unsubscribers.push(
				this.#critical.subscribe((count) => {
					if (count > 0) {
						this.#abortPreemptibleInFlight();
					} else {
						this.#resumeDeferredPreemptible();
					}
				}),
			);
		}

		if (this.#transport) {
			this.#unsubscribers.push(this.#transport.onWakeup((w) => this.handleWakeup(w)));
			this.#unsubscribers.push(this.#transport.onScopeRevoked((e) => void this.handleScopeRevoked(e)));
			this.#unsubscribers.push(this.#transport.onReconnect(() => this.handleReconnect()));
			if (this.#transport.onOfflineWipe) {
				this.#unsubscribers.push(this.#transport.onOfflineWipe((e) => void this.handleOfflineWipe(e)));
			}
		}
	}

	get sessionGeneration(): number {
		return this.#sessionGeneration;
	}

	get disposed(): boolean {
		return this.#disposed;
	}

	getRevocationEpoch(scope: ScopeKey): number {
		return this.#revocationEpochs.get(scopeKeyString(scope)) ?? 0;
	}

	/** Registers a scope consumer adapter and updates the live transport scope union. */
	register(adapter: SyncScopeAdapter): () => void {
		if (this.#disposed) return () => {};
		const scopeKey = scopeKeyString(adapter.scope);
		const entryKey = `${adapter.consumerId}::${scopeKey}`;

		const existing = this.#entries.get(entryKey);
		if (existing) {
			this.#unregisterEntry(existing);
		}

		const entry: ConsumerEntry = {
			key: entryKey,
			scopeKey,
			adapter,
			lane: adapter.lane ?? 'foreground',
			debounceMs: Math.max(0, adapter.debounceMs ?? 0),
			backoff: new ReconnectBackoff(this.#backoffOptions),
			inFlight: null,
			controller: null,
			debounceTimer: null,
			backoffTimer: null,
			dirty: false,
			pendingTrigger: 'manual',
			pendingWakeup: undefined,
			pendingMode: null,
			budgetYieldPending: false,
			budgetYieldTimer: null,
			budgetYieldPromise: null,
			reconnectPending: false,
			storageFull: false,
			storageFullDetail: null,
			lastAppliedSeq: 0,
			detached: false,
			deferredByCritical: false,
			preemptedByCritical: false,
			disposed: false,
		};

		this.#entries.set(entryKey, entry);
		let set = this.#entriesByScope.get(scopeKey);
		if (!set) {
			set = new Set();
			this.#entriesByScope.set(scopeKey, set);
		}
		set.add(entry);
		this.#syncAttachedScopes();

		return () => {
			if (this.#entries.get(entryKey) === entry) {
				this.#unregisterEntry(entry);
			}
		};
	}

	/** Current attached scope union (excluding detached/revoked scopes, capped at 512). */
	getAttachedScopes(): ScopeKey[] {
		const seen = new Set<string>();
		const out: ScopeKey[] = [];
		for (const entry of this.#entries.values()) {
			if (entry.detached || entry.disposed) continue;
			if (seen.has(entry.scopeKey)) continue;
			seen.add(entry.scopeKey);
			out.push(entry.adapter.scope);
			if (out.length >= MAX_ATTACHED_SCOPES) break;
		}
		return out;
	}

	/** Diagnostic snapshot for a `(consumerId, scope)` registration. */
	getState(consumerId: string, scope: ScopeKey): ScopeSyncState | null {
		const entry = this.#entries.get(`${consumerId}::${scopeKeyString(scope)}`);
		return entry ? this.#snapshot(entry) : null;
	}

	/** Manually trigger a sync cycle for a scope (or one specific consumer). */
	trigger(
		scope: ScopeKey,
		opts?: { consumerId?: string; immediate?: boolean; wakeup?: SyncWakeup; clearStorageFull?: boolean },
	): void {
		if (this.#disposed) return;
		const scopeKey = scopeKeyString(scope);
		const set = this.#entriesByScope.get(scopeKey);
		if (!set) return;
		for (const entry of set) {
			if (opts?.consumerId && entry.adapter.consumerId !== opts.consumerId) continue;
			if (entry.detached || entry.disposed) continue;
			if (opts?.clearStorageFull) {
				entry.storageFull = false;
				entry.storageFullDetail = null;
			}
			this.#scheduleEntry(entry, 'manual', opts?.wakeup, opts?.immediate ?? true);
		}
	}

	/**
	 * Handles a wakeup frame (validates fail-closed if passed an untrusted object).
	 * Applies monotonic `seq <= lastAppliedSeq` skip unless `reconnectPending` is set.
	 */
	handleWakeup(raw: unknown): void {
		if (this.#disposed) return;
		const wakeup = validateSyncWakeup(raw, this.#onWarning);
		if (!wakeup) return;
		const scopeKey = scopeKeyString({ kind: wakeup.scopeKind, id: wakeup.scopeId });
		const set = this.#entriesByScope.get(scopeKey);
		if (!set) return;

		for (const entry of set) {
			if (entry.detached || entry.disposed) continue;
			if (entry.storageFull && isPreemptibleLane(entry.lane)) continue;
			if (wakeup.seq > 0 && wakeup.seq <= entry.lastAppliedSeq && !entry.reconnectPending) {
				continue;
			}
			this.#scheduleEntry(entry, 'wakeup', wakeup, false);
		}
	}

	/**
	 * Reconnect catch-up: sets `reconnectPending` on ALL registered non-detached
	 * scopes and schedules catch-up sync (respecting each consumer's debounce/lane).
	 */
	handleReconnect(): void {
		if (this.#disposed) return;
		for (const entry of this.#entries.values()) {
			if (entry.detached || entry.disposed) continue;
			entry.reconnectPending = true;
			this.#emitState(entry);
			if (entry.storageFull && isPreemptibleLane(entry.lane)) continue;
			this.#scheduleEntry(entry, 'reconnect', undefined, false);
		}
	}

	/**
	 * Subscribes a session-level security-lane observer invoked on every validated
	 * `scope_revoked` event — even when no consumer adapter is currently registered
	 * for that `scopeId` (e.g. evicting cached inactive Chat channels in ChatStore).
	 */
	onScopeRevoked(listener: (event: ScopeRevokedEvent) => Promise<void> | void): () => void {
		this.#scopeRevokedListeners.add(listener);
		return () => this.#scopeRevokedListeners.delete(listener);
	}

	/**
	 * Security-lane `scope_revoked` handler. NEVER blocked by `criticalActivity > 0`,
	 * debounce timers, or rollout flags.
	 *
	 * Synchronously bumps `revocationEpoch`, cancels pending timers, aborts
	 * in-flight `AbortController`s, detaches the scope (unless `subtreeAnchorId`
	 * is set), and serializes `purgeScopeCache` across every consumer for that
	 * scope through the per-scope purge mutex.
	 */
	handleScopeRevoked(raw: unknown): Promise<void> {
		if (this.#disposed) return Promise.resolve();
		const event = validateScopeRevoked(raw, this.#onWarning);
		if (!event) return Promise.resolve();
		const scopeKey = scopeKeyString({ kind: event.scopeKind, id: event.scopeId });

		// Synchronous write barrier: bump epoch & abort active work BEFORE any await.
		this.#revocationEpochs.set(scopeKey, (this.#revocationEpochs.get(scopeKey) ?? 0) + 1);

		const set = this.#entriesByScope.get(scopeKey);
		const consumers: ConsumerEntry[] = set ? [...set] : [];
		const inFlightToWait: Promise<void>[] = [];
		const shouldDetach = event.subtreeAnchorId === undefined;

		for (const entry of consumers) {
			this.#clearTimers(entry);
			this.#removeFromConcurrencyQueue(entry);
			entry.dirty = false;
			entry.pendingMode = null;
			entry.budgetYieldPending = false;
			entry.deferredByCritical = false;
			entry.reconnectPending = false;
			if (shouldDetach) {
				entry.detached = true;
			}
			if (entry.controller) {
				entry.controller.abort(new SyncFenceAbortedError('scope revoked'));
			}
			if (entry.inFlight) {
				inFlightToWait.push(entry.inFlight.catch(() => {}));
			}
			this.#emitState(entry);
		}
		if (shouldDetach) {
			this.#syncAttachedScopes();
		}

		// Serialize purge through the per-scope purge mutex so concurrent revokes
		// or late-settling steps can never race cache deletion.
		const previous = this.#purgeMutexByScope.get(scopeKey) ?? Promise.resolve();
		const next = previous
			.catch(() => {})
			.then(async () => {
				if (inFlightToWait.length > 0) {
					await Promise.allSettled(inFlightToWait);
				}
				// Fence scope_revoked cache writes behind any active offline.wipe (#555):
				// synchronous epoch bump + in-flight aborts already happened above; wait
				// for db.wipe() to finish before running purgeScopeCache so SQLite writes
				// can never race an active wipe.
				while (this.#wipeFenceDepth > 0 && this.#wipeFencePromise) {
					await this.#wipeFencePromise;
				}
				if (this.#disposed) return;
				for (const entry of consumers) {
					if (!entry.adapter.purgeScopeCache) continue;
					try {
						await entry.adapter.purgeScopeCache(event);
					} catch (err) {
						this.#onWarning('scope_revoked: purgeScopeCache failed', {
							consumerId: entry.adapter.consumerId,
							scopeKey,
							error: err instanceof Error ? err.message : String(err),
						});
					}
				}
				for (const listener of [...this.#scopeRevokedListeners]) {
					try {
						await listener(event);
					} catch (err) {
						this.#onWarning('scope_revoked: observer failed', {
							scopeKey,
							error: err instanceof Error ? err.message : String(err),
						});
					}
				}
			});

		this.#purgeMutexByScope.set(scopeKey, next);
		void next.finally(() => {
			if (this.#purgeMutexByScope.get(scopeKey) === next) {
				this.#purgeMutexByScope.delete(scopeKey);
			}
		});
		return next;
	}

	/**
	 * Security-lane `offline.wipe` handler. NEVER blocked by `criticalActivity > 0`
	 * or rollout flags. Holds an explicit wipe admission fence while aborting
	 * in-flight steps and running `onOfflineWipe` so no new sync step can be
	 * admitted mid-wipe.
	 */
	async handleOfflineWipe(raw: unknown): Promise<void> {
		if (this.#disposed) return;
		const event = validateOfflineWipe(raw, this.#onWarning);
		if (!event) return;
		await this.runWithWipeFence('offline.wipe', async () => {
			if (this.#onOfflineWipe) {
				await this.#onOfflineWipe(event);
			}
		});
	}

	/**
	 * Acquires an admission-blocking wipe fence, aborts & drains all in-flight sync
	 * work, and returns an idempotent release function. While held, no new step can
	 * be scheduled or acquire the bumped sessionGeneration.
	 */
	async beginWipeFence(reason = 'offline.wipe'): Promise<() => void> {
		this.#wipeFenceDepth += 1;
		if (this.#wipeFenceDepth === 1) {
			this.#wipeFencePromise = new Promise<void>((resolve) => {
				this.#resolveWipeFence = resolve;
			});
		}
		let released = false;
		const releaseFence = (): void => {
			if (released) return;
			released = true;
			this.#wipeFenceDepth = Math.max(0, this.#wipeFenceDepth - 1);
			if (this.#wipeFenceDepth === 0) {
				const resolve = this.#resolveWipeFence;
				this.#resolveWipeFence = null;
				this.#wipeFencePromise = null;
				resolve?.();
			}
		};
		try {
			await this.abortAllInFlightAndFence(reason);
		} catch (err) {
			releaseFence();
			throw err;
		}
		return releaseFence;
	}

	/** Runs `fn` with all sync admission fenced closed across the entire async wipe. */
	async runWithWipeFence<T>(reason: string, fn: () => Promise<T>): Promise<T> {
		const release = await this.beginWipeFence(reason);
		try {
			return await fn();
		} finally {
			release();
		}
	}

	/**
	 * Synchronously bumps `sessionGeneration`, cancels all pending timers, aborts
	 * all active `AbortController`s across every scope, and awaits their settlement.
	 */
	async abortAllInFlightAndFence(reason = 'session fenced'): Promise<void> {
		this.#sessionGeneration += 1;
		this.#concurrencyWaitQueue.length = 0;
		this.#queuedForConcurrency.clear();
		const active: Promise<void>[] = [];
		for (const entry of this.#entries.values()) {
			this.#clearTimers(entry);
			entry.dirty = false;
			entry.pendingMode = null;
			entry.budgetYieldPending = false;
			entry.deferredByCritical = false;
			if (entry.controller) {
				entry.controller.abort(new SyncFenceAbortedError(reason));
			}
			if (entry.inFlight) {
				active.push(entry.inFlight.catch(() => {}));
			}
		}
		if (active.length > 0) {
			await Promise.allSettled(active);
		}
		if (this.#purgeMutexByScope.size > 0) {
			await Promise.allSettled([...this.#purgeMutexByScope.values()]);
		}
	}

	/**
	 * Synchronous session teardown (wired to `registerAuthSessionTeardown` on
	 * logout / identity switch). Bumps `sessionGeneration`, cancels timers,
	 * aborts active work, resets cursors/seq state, and clears attached scopes.
	 */
	resetSession(): void {
		this.#sessionGeneration += 1;
		for (const entry of this.#entries.values()) {
			this.#clearTimers(entry);
			entry.dirty = false;
			entry.reconnectPending = false;
			entry.storageFull = false;
			entry.storageFullDetail = null;
			entry.lastAppliedSeq = 0;
			entry.deferredByCritical = false;
			entry.preemptedByCritical = false;
			entry.backoff.reset();
			if (entry.controller) {
				entry.controller.abort(new SyncFenceAbortedError('session reset'));
			}
			this.#emitState(entry);
		}
		this.#revocationEpochs.clear();
		this.#transport?.setAttachedScopes?.([]);
	}

	/** Awaits any currently running steps, scheduled budget-yield continuations, and pending purges. */
	async flush(scope?: ScopeKey): Promise<void> {
		const targetKey = scope ? scopeKeyString(scope) : null;
		// Loop because bounded global concurrency or budget-yield continuations may
		// start queued entries once earlier runs settle.
		while (true) {
			const waits: Promise<void>[] = [];
			for (const entry of this.#entries.values()) {
				const relevant = !targetKey || entry.scopeKey === targetKey;
				if (entry.inFlight && (relevant || this.#queuedForConcurrency.size > 0)) {
					waits.push(entry.inFlight.catch(() => {}));
				}
				if (relevant && entry.budgetYieldPromise) {
					waits.push(entry.budgetYieldPromise.catch(() => {}));
				}
			}
			for (const [k, p] of this.#purgeMutexByScope) {
				if (targetKey && k !== targetKey) continue;
				waits.push(p.catch(() => {}));
			}
			if (waits.length === 0) break;
			await Promise.allSettled(waits);
			// If nothing matching targetKey is still in-flight, yielding, or queued, stop.
			const stillPending =
				[...this.#entries.values()].some(
					(e) =>
						(!targetKey || e.scopeKey === targetKey) &&
						(e.inFlight !== null || e.budgetYieldPromise !== null || this.#queuedForConcurrency.has(e)),
				) ||
				[...this.#purgeMutexByScope.keys()].some((k) => !targetKey || k === targetKey);
			if (!stillPending) break;
		}
	}

	/** Permanently tears down the coordinator and all transport/critical subscriptions. */
	dispose(): void {
		if (this.#disposed) return;
		this.#disposed = true;
		this.resetSession();
		for (const unsub of this.#unsubscribers) {
			try {
				unsub();
			} catch {
				// isolate teardown errors
			}
		}
		this.#unsubscribers.length = 0;
		for (const entry of this.#entries.values()) {
			entry.disposed = true;
			this.#clearTimers(entry);
		}
		this.#entries.clear();
		this.#entriesByScope.clear();
	}

	// ── Internals ────────────────────────────────────────────────────────────

	#unregisterEntry(entry: ConsumerEntry): void {
		entry.disposed = true;
		this.#clearTimers(entry);
		this.#removeFromConcurrencyQueue(entry);
		if (entry.controller) {
			entry.controller.abort(new SyncFenceAbortedError('adapter unregistered'));
		}
		this.#entries.delete(entry.key);
		const set = this.#entriesByScope.get(entry.scopeKey);
		if (set) {
			set.delete(entry);
			if (set.size === 0) this.#entriesByScope.delete(entry.scopeKey);
		}
		this.#syncAttachedScopes();
	}

	#removeFromConcurrencyQueue(entry: ConsumerEntry): void {
		if (!this.#queuedForConcurrency.delete(entry)) return;
		const idx = this.#concurrencyWaitQueue.indexOf(entry);
		if (idx >= 0) this.#concurrencyWaitQueue.splice(idx, 1);
	}

	#drainConcurrencyQueue(): void {
		if (this.#disposed || this.#wipeFenceDepth > 0) return;
		while (this.#activeRunCount < this.#maxGlobalConcurrency && this.#concurrencyWaitQueue.length > 0) {
			const next = this.#concurrencyWaitQueue.shift()!;
			this.#queuedForConcurrency.delete(next);
			if (next.disposed || next.detached || next.inFlight || next.storageFull) continue;
			if (isPreemptibleLane(next.lane) && this.#critical?.isActive()) {
				next.deferredByCritical = true;
				this.#emitState(next);
				continue;
			}
			this.#startEntryRun(next);
		}
	}

	#syncAttachedScopes(): void {
		if (!this.#transport?.setAttachedScopes) return;
		this.#transport.setAttachedScopes(this.getAttachedScopes());
	}

	#clearTimers(entry: ConsumerEntry): void {
		if (entry.debounceTimer !== null) {
			clearTimeout(entry.debounceTimer);
			entry.debounceTimer = null;
		}
		if (entry.budgetYieldTimer !== null) {
			clearTimeout(entry.budgetYieldTimer);
			entry.budgetYieldTimer = null;
		}
		entry.budgetYieldPromise = null;
		if (entry.backoffTimer !== null) {
			clearTimeout(entry.backoffTimer);
			entry.backoffTimer = null;
		}
	}

	#abortPreemptibleInFlight(): void {
		for (const entry of this.#entries.values()) {
			if (entry.disposed || entry.detached) continue;
			if (!isPreemptibleLane(entry.lane)) continue;
			if (entry.debounceTimer !== null) {
				clearTimeout(entry.debounceTimer);
				entry.debounceTimer = null;
				entry.deferredByCritical = true;
				this.#emitState(entry);
			}
			if (entry.controller) {
				entry.preemptedByCritical = true;
				entry.deferredByCritical = true;
				entry.controller.abort(new Error('preempted by critical activity'));
				this.#emitState(entry);
			}
		}
	}

	#resumeDeferredPreemptible(): void {
		if (this.#disposed || this.#wipeFenceDepth > 0) return;
		if (this.#critical?.isActive()) return;
		for (const entry of this.#entries.values()) {
			if (entry.disposed || entry.detached || entry.storageFull) continue;
			if (!entry.deferredByCritical) continue;
			entry.deferredByCritical = false;
			this.#emitState(entry);
			this.#scheduleEntry(entry, entry.pendingTrigger, entry.pendingWakeup, true);
		}
	}

	#scheduleEntry(
		entry: ConsumerEntry,
		trigger: SyncTriggerKind,
		wakeup: SyncWakeup | undefined,
		immediate: boolean,
	): void {
		if (this.#disposed || this.#wipeFenceDepth > 0 || entry.disposed || entry.detached) return;

		// Preserve strongest trigger semantics (reconnect > wakeup > manual).
		if (trigger === 'reconnect' || entry.pendingTrigger !== 'reconnect') {
			entry.pendingTrigger = trigger;
		}
		if (wakeup) {
			entry.pendingWakeup = mergeWakeups(entry.pendingWakeup, wakeup);
		}

		// Preemptible lanes defer while CriticalActivityCounter is active.
		if (isPreemptibleLane(entry.lane) && this.#critical?.isActive()) {
			entry.deferredByCritical = true;
			this.#emitState(entry);
			return;
		}

		// Single-flight coalescing: mark dirty so the active run loops once more.
		if (entry.inFlight) {
			entry.dirty = true;
			this.#emitState(entry);
			return;
		}
		if (this.#queuedForConcurrency.has(entry)) {
			return;
		}

		// Cancel any pending backoff timer when an explicit trigger/wakeup arrives.
		if (entry.backoffTimer !== null) {
			clearTimeout(entry.backoffTimer);
			entry.backoffTimer = null;
		}

		if (!immediate && entry.debounceMs > 0) {
			if (entry.debounceTimer !== null) {
				clearTimeout(entry.debounceTimer);
			}
			entry.debounceTimer = setTimeout(() => {
				entry.debounceTimer = null;
				if (this.#disposed || this.#wipeFenceDepth > 0 || entry.disposed || entry.detached) return;
				if (isPreemptibleLane(entry.lane) && this.#critical?.isActive()) {
					entry.deferredByCritical = true;
					this.#emitState(entry);
					return;
				}
				this.#startEntryRun(entry);
			}, entry.debounceMs);
			return;
		}

		if (entry.debounceTimer !== null) {
			clearTimeout(entry.debounceTimer);
			entry.debounceTimer = null;
		}
		this.#startEntryRun(entry);
	}

	#startEntryRun(entry: ConsumerEntry): void {
		if (entry.inFlight || this.#disposed || this.#wipeFenceDepth > 0 || entry.disposed || entry.detached) return;
		if (this.#activeRunCount >= this.#maxGlobalConcurrency) {
			if (!this.#queuedForConcurrency.has(entry)) {
				this.#queuedForConcurrency.add(entry);
				this.#concurrencyWaitQueue.push(entry);
			}
			return;
		}
		this.#activeRunCount += 1;
		const run = this.#executeCycle(entry).finally(() => {
			this.#activeRunCount = Math.max(0, this.#activeRunCount - 1);
			if (entry.inFlight === run) {
				entry.inFlight = null;
			}
			entry.controller = null;
			this.#emitState(entry);

			if (
				!this.#disposed &&
				this.#wipeFenceDepth === 0 &&
				!entry.disposed &&
				!entry.detached &&
				entry.dirty &&
				!entry.storageFull &&
				entry.backoffTimer === null
			) {
				const yieldContinuation = entry.budgetYieldPending;
				entry.dirty = false;
				entry.budgetYieldPending = false;
				if (isPreemptibleLane(entry.lane) && this.#critical?.isActive()) {
					entry.deferredByCritical = true;
					this.#emitState(entry);
				} else if (yieldContinuation) {
					// Yield one turn before resuming a SyncBudget-paused multi-page resync/reconcile.
					// Track budgetYieldPromise so flush() awaits the continuation cleanly.
					entry.budgetYieldPromise = new Promise<void>((resolve) => {
						entry.budgetYieldTimer = setTimeout(() => {
							entry.budgetYieldTimer = null;
							entry.budgetYieldPromise = null;
							if (this.#disposed || this.#wipeFenceDepth > 0 || entry.disposed || entry.detached || entry.storageFull) {
								resolve();
								return;
							}
							if (isPreemptibleLane(entry.lane) && this.#critical?.isActive()) {
								entry.deferredByCritical = true;
								this.#emitState(entry);
								resolve();
								return;
							}
							this.#startEntryRun(entry);
							resolve();
						}, 0);
					});
				} else {
					this.#scheduleEntry(entry, entry.pendingTrigger, entry.pendingWakeup, entry.debounceMs === 0);
				}
			}
			this.#drainConcurrencyQueue();
		});
		entry.inFlight = run;
		this.#emitState(entry);
	}

	async #executeCycle(entry: ConsumerEntry): Promise<void> {
		const startSessionGen = this.#sessionGeneration;
		const startRevocationEpoch = this.#revocationEpochs.get(entry.scopeKey) ?? 0;
		const controller = new AbortController();
		entry.controller = controller;
		entry.preemptedByCritical = false;

		const trigger = entry.pendingTrigger;
		const wakeup = entry.pendingWakeup;
		entry.pendingTrigger = 'manual';
		entry.pendingWakeup = undefined;

		const fence: RevocationFence = {
			revocationEpoch: startRevocationEpoch,
			sessionGeneration: startSessionGen,
			isCommitAllowed: () =>
				!this.#disposed &&
				this.#wipeFenceDepth === 0 &&
				!entry.disposed &&
				!entry.detached &&
				!controller.signal.aborted &&
				this.#sessionGeneration === startSessionGen &&
				(this.#revocationEpochs.get(entry.scopeKey) ?? 0) === startRevocationEpoch,
			assertCommitAllowed: () => {
				if (!fence.isCommitAllowed()) {
					throw new SyncFenceAbortedError();
				}
			},
		};

		const deadlineMonoMs = this.#nowMonoMs() + this.#maxDurationMs;
		let recordsRemaining = this.#maxRecords;
		let bytesRemaining = this.#maxBytes;
		let mode: 'delta' | 'fullResync' | 'reconcile' = entry.pendingMode ?? 'delta';
		entry.pendingMode = null;
		let transitionedToFullResync = mode === 'fullResync';
		let reconciledThisCycle = mode === 'reconcile';
		let priorCursor: string | null = null;

		try {
			// Purge mutex fencing (4a): wait for any in-flight scope purge (e.g.
			// subtreeAnchorId fullVisibilityReconcile) before starting a step so
			// wakeups can never race cache eviction.
			while (this.#purgeMutexByScope.has(entry.scopeKey)) {
				const pendingPurge = this.#purgeMutexByScope.get(entry.scopeKey);
				if (pendingPurge) await pendingPurge.catch(() => {});
				if (!fence.isCommitAllowed()) return;
			}

			if (mode === 'delta' && entry.adapter.getCursor) {
				const cursor = await entry.adapter.getCursor();
				fence.assertCommitAllowed();
				priorCursor = cursor;
				if (cursor === null && entry.adapter.runFullResyncStep) {
					mode = 'fullResync';
				}
			}

			while (fence.isCommitAllowed()) {
				if (isPreemptibleLane(entry.lane) && this.#critical?.isActive()) {
					entry.deferredByCritical = true;
					entry.pendingMode = mode;
					return;
				}
				if (this.#nowMonoMs() >= deadlineMonoMs || recordsRemaining <= 0 || bytesRemaining <= 0) {
					// SyncBudget exhausted mid-pagination: yield cleanly and schedule
					// continuation so multi-page fullResync/reconcile finishes automatically.
					entry.dirty = true;
					entry.budgetYieldPending = true;
					entry.pendingMode = mode;
					entry.pendingTrigger = trigger;
					entry.pendingWakeup = wakeup;
					break;
				}

				const budget: SyncBudget = {
					maxRecords: recordsRemaining,
					maxBytes: bytesRemaining,
					deadlineMonoMs,
				};
				const stepTrigger: SyncTriggerKind =
					mode === 'fullResync' ? 'fullResync' : mode === 'reconcile' ? 'reconcile' : trigger;

				const ctx = {
					scope: entry.adapter.scope,
					signal: controller.signal,
					budget,
					fence,
					trigger: stepTrigger,
					wakeup,
				};

				let outcome: StepOutcome;
				if (mode === 'fullResync' && entry.adapter.runFullResyncStep) {
					outcome = await entry.adapter.runFullResyncStep(ctx);
				} else if (mode === 'reconcile' && entry.adapter.reconcileScopeMembership) {
					outcome = await entry.adapter.reconcileScopeMembership(ctx);
				} else {
					outcome = await entry.adapter.runDeltaStep(ctx);
				}

				if (!fence.isCommitAllowed()) {
					return;
				}

				recordsRemaining = Math.max(0, recordsRemaining - Math.max(0, outcome.recordsProcessed ?? 0));
				bytesRemaining = Math.max(0, bytesRemaining - Math.max(0, outcome.bytesProcessed ?? 0));

				if (outcome.appliedSeq !== undefined && outcome.appliedSeq > entry.lastAppliedSeq) {
					entry.lastAppliedSeq = outcome.appliedSeq;
				}

				switch (outcome.kind) {
					case 'complete': {
						if (wakeup && wakeup.seq > entry.lastAppliedSeq) {
							entry.lastAppliedSeq = wakeup.seq;
						}
						entry.reconnectPending = false;
						entry.backoff.markConnected();
						entry.backoff.reset();
						return;
					}
					case 'partial': {
						const nextCursor = outcome.cursor ?? null;
						const madeProgress =
							(outcome.recordsProcessed ?? 0) > 0 ||
							(outcome.bytesProcessed ?? 0) > 0 ||
							nextCursor !== priorCursor;
						priorCursor = nextCursor;
						if (!madeProgress) {
							// Zero-progress guard: avoid spinning until the deadline.
							return;
						}
						continue;
					}
					case 'cannotCalculateChanges': {
						// Circuit-breaker: max 1 automatic delta → full-resync transition per cycle.
						if (!transitionedToFullResync && entry.adapter.runFullResyncStep) {
							transitionedToFullResync = true;
							mode = 'fullResync';
							priorCursor = null;
							continue;
						}
						this.#scheduleBackoff(entry, trigger, wakeup);
						return;
					}
					case 'tombstoneFloorExceeded': {
						if (!reconciledThisCycle && entry.adapter.reconcileScopeMembership) {
							reconciledThisCycle = true;
							mode = 'reconcile';
							priorCursor = null;
							continue;
						}
						this.#scheduleBackoff(entry, trigger, wakeup);
						return;
					}
					case 'scopeRevoked': {
						void this.handleScopeRevoked({
							scopeKind: entry.adapter.scope.kind,
							scopeId: entry.adapter.scope.id,
							reason: outcome.detail ?? 'step_reported_revoked',
						});
						return;
					}
					case 'capacityExceeded': {
						entry.storageFull = true;
						entry.storageFullDetail = outcome.detail ?? 'storage capacity exceeded';
						entry.dirty = false;
						entry.adapter.onCapacityExceeded?.(entry.storageFullDetail);
						this.#emitState(entry);
						return;
					}
				}
			}
		} catch (err) {
			if (entry.preemptedByCritical) {
				entry.deferredByCritical = true;
				entry.pendingTrigger = trigger;
				entry.pendingWakeup = wakeup;
				return;
			}
			if (isAbortError(err) || !fence.isCommitAllowed()) {
				return;
			}
			if (isCapacityError(err)) {
				entry.storageFull = true;
				entry.storageFullDetail = err instanceof Error ? err.message : 'storage capacity exceeded';
				entry.dirty = false;
				entry.adapter.onCapacityExceeded?.(entry.storageFullDetail);
				this.#emitState(entry);
				return;
			}
			this.#scheduleBackoff(entry, trigger, wakeup);
		}
	}

	#scheduleBackoff(entry: ConsumerEntry, trigger: SyncTriggerKind, wakeup: SyncWakeup | undefined): void {
		if (this.#disposed || entry.disposed || entry.detached || entry.storageFull) return;
		const delayMs = entry.backoff.markDisconnected();
		entry.pendingTrigger = trigger;
		entry.pendingWakeup = wakeup;
		if (entry.backoffTimer !== null) {
			clearTimeout(entry.backoffTimer);
		}
		entry.backoffTimer = setTimeout(() => {
			entry.backoffTimer = null;
			if (this.#disposed || entry.disposed || entry.detached || entry.storageFull) return;
			this.#scheduleEntry(entry, entry.pendingTrigger, entry.pendingWakeup, true);
		}, delayMs);
		this.#emitState(entry);
	}

	#snapshot(entry: ConsumerEntry): ScopeSyncState {
		return {
			consumerId: entry.adapter.consumerId,
			scope: entry.adapter.scope,
			inFlight: entry.inFlight !== null,
			dirty: entry.dirty,
			reconnectPending: entry.reconnectPending,
			storageFull: entry.storageFull,
			storageFullDetail: entry.storageFullDetail,
			lastAppliedSeq: entry.lastAppliedSeq,
			revocationEpoch: this.#revocationEpochs.get(entry.scopeKey) ?? 0,
			detached: entry.detached,
			backoffAttempt: entry.backoff.attempt,
			deferredByCritical: entry.deferredByCritical,
		};
	}

	#emitState(entry: ConsumerEntry): void {
		entry.adapter.onStateChange?.(this.#snapshot(entry));
	}
}
