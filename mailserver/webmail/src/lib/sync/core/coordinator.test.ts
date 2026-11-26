import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createCriticalActivityCounter } from '../../offline/criticalScope';
import { SyncCoordinator, SyncFenceAbortedError } from './coordinator.js';
import type {
	OfflineWipeEvent,
	ScopeKey,
	ScopeRevokedEvent,
	StepOutcome,
	SyncScopeAdapter,
	SyncStepContext,
	SyncWakeup,
	WakeupTransport,
} from './types.js';

function createFakeTransport(): {
	transport: WakeupTransport;
	emitWakeup: (w: SyncWakeup) => void;
	emitRevoke: (e: ScopeRevokedEvent) => void;
	emitReconnect: () => void;
	emitWipe: (e: OfflineWipeEvent) => void;
	attachedHistory: ScopeKey[][];
} {
	const wakeups = new Set<(w: SyncWakeup) => void>();
	const revokes = new Set<(e: ScopeRevokedEvent) => void>();
	const reconnects = new Set<() => void>();
	const wipes = new Set<(e: OfflineWipeEvent) => void>();
	const attachedHistory: ScopeKey[][] = [];
	const transport: WakeupTransport = {
		onWakeup: (h) => {
			wakeups.add(h);
			return () => wakeups.delete(h);
		},
		onScopeRevoked: (h) => {
			revokes.add(h);
			return () => revokes.delete(h);
		},
		onReconnect: (h) => {
			reconnects.add(h);
			return () => reconnects.delete(h);
		},
		onOfflineWipe: (h) => {
			wipes.add(h);
			return () => wipes.delete(h);
		},
		setAttachedScopes: (scopes) => {
			attachedHistory.push([...scopes]);
		},
	};
	return {
		transport,
		emitWakeup: (w) => {
			for (const h of wakeups) h(w);
		},
		emitRevoke: (e) => {
			for (const h of revokes) h(e);
		},
		emitReconnect: () => {
			for (const h of reconnects) h();
		},
		emitWipe: (e) => {
			for (const h of wipes) h(e);
		},
		attachedHistory,
	};
}

describe('SyncCoordinator core', () => {
	beforeEach(() => {
		vi.useFakeTimers();
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it('coalesces single-flight wakeups, respects per-consumer debounceMs, and skips monotonic seq <= lastAppliedSeq', async () => {
		const fake = createFakeTransport();
		const coord = new SyncCoordinator({ transport: fake.transport });

		let resolveFirst!: (out: StepOutcome) => void;
		const deltaCalls: number[] = [];
		const adapter: SyncScopeAdapter = {
			consumerId: 'inbox',
			scope: { kind: 'mailbox', id: 'primary' },
			debounceMs: 300,
			runDeltaStep: async (ctx) => {
				deltaCalls.push(ctx.wakeup?.seq ?? 0);
				if (deltaCalls.length === 1) {
					return new Promise<StepOutcome>((resolve) => {
						resolveFirst = resolve;
					});
				}
				return { kind: 'complete', recordsProcessed: 1, appliedSeq: ctx.wakeup?.seq ?? 10 };
			},
		};
		coord.register(adapter);

		// Burst within 300ms debounce window collapses into ONE delta call.
		fake.emitWakeup({ scopeKind: 'mailbox', scopeId: 'primary', seq: 5 });
		vi.advanceTimersByTime(150);
		fake.emitWakeup({ scopeKind: 'mailbox', scopeId: 'primary', seq: 6 });
		vi.advanceTimersByTime(299);
		expect(deltaCalls).toHaveLength(0);
		vi.advanceTimersByTime(1);
		expect(deltaCalls).toEqual([6]);

		// Wakeups landing while in-flight coalesce into ONE dirty follow-up.
		fake.emitWakeup({ scopeKind: 'mailbox', scopeId: 'primary', seq: 7 });
		fake.emitWakeup({ scopeKind: 'mailbox', scopeId: 'primary', seq: 10 });
		resolveFirst({ kind: 'complete', recordsProcessed: 1, appliedSeq: 6 });
		await vi.advanceTimersByTimeAsync(300);
		await coord.flush();
		expect(deltaCalls).toEqual([6, 10]);

		// Stale/duplicate seq <= lastAppliedSeq (10) is skipped.
		fake.emitWakeup({ scopeKind: 'mailbox', scopeId: 'primary', seq: 10 });
		fake.emitWakeup({ scopeKind: 'mailbox', scopeId: 'primary', seq: 8 });
		await vi.advanceTimersByTimeAsync(500);
		expect(deltaCalls).toEqual([6, 10]);

		coord.dispose();
	});

	it('neutralizes mid-flight scope_revoked commit race via synchronous revocationEpoch fence and serialized purge', async () => {
		const coord = new SyncCoordinator();
		const committedRows: string[] = [];
		const order: string[] = [];

		let releaseFetch!: () => void;
		const fetchGate = new Promise<void>((r) => {
			releaseFetch = r;
		});

		const adapter: SyncScopeAdapter = {
			consumerId: 'chat:9',
			scope: { kind: 'channel', id: '9' },
			runDeltaStep: async (ctx) => {
				order.push('fetch-start');
				// Simulate fetch already completing just as scope_revoked arrives,
				// ignoring AbortSignal to prove synchronous assertCommitAllowed() blocks write.
				await fetchGate;
				order.push('fetch-resolved');
				ctx.fence.assertCommitAllowed();
				committedRows.push('revoked-secret-row');
				return { kind: 'complete', recordsProcessed: 1, appliedSeq: 5 };
			},
			purgeScopeCache: async () => {
				order.push('purge-start');
				committedRows.length = 0;
				order.push('purge-end');
			},
		};

		coord.register(adapter);
		const epochBefore = coord.getRevocationEpoch({ kind: 'channel', id: '9' });
		coord.trigger({ kind: 'channel', id: '9' });
		await Promise.resolve();
		expect(order).toEqual(['fetch-start']);

		// Revoke arrives while step is mid-flight.
		const revokePromise = coord.handleScopeRevoked({ scopeKind: 'channel', scopeId: '9', reason: 'removed' });
		// Epoch bumped synchronously BEFORE any await!
		expect(coord.getRevocationEpoch({ kind: 'channel', id: '9' })).toBe(epochBefore + 1);

		// Late-settling fetch resolves now — fence MUST block commit BEFORE purge completes.
		releaseFetch();
		await revokePromise;
		await coord.flush();

		expect(committedRows).toEqual([]);
		expect(order).toEqual(['fetch-start', 'fetch-resolved', 'purge-start', 'purge-end']);
		expect(coord.getState('chat:9', { kind: 'channel', id: '9' })?.detached).toBe(true);
		coord.dispose();
	});

	it('neutralizes mid-flight offline.wipe commit race via sessionGeneration fence and aborts before wipe callback', async () => {
		const events: string[] = [];
		let releaseFetch!: () => void;
		const fetchGate = new Promise<void>((r) => {
			releaseFetch = r;
		});

		const coord = new SyncCoordinator({
			onOfflineWipe: async () => {
				events.push('db-wipe');
			},
		});

		coord.register({
			consumerId: 'mail-sync',
			scope: { kind: 'mailbox', id: 'primary' },
			lane: 'offline-native',
			runDeltaStep: async (ctx) => {
				events.push('step-start');
				await fetchGate;
				try {
					ctx.fence.assertCommitAllowed();
					events.push('illegal-commit');
				} catch (err) {
					expect(err).toBeInstanceOf(SyncFenceAbortedError);
					events.push('commit-fenced');
					throw err;
				}
				return { kind: 'complete' };
			},
		});

		coord.trigger({ kind: 'mailbox', id: 'primary' });
		await Promise.resolve();
		expect(events).toEqual(['step-start']);

		const genBefore = coord.sessionGeneration;
		const wipePromise = coord.handleOfflineWipe({ appKey: 'mail', deviceId: 1 });
		expect(coord.sessionGeneration).toBe(genBefore + 1);

		releaseFetch();
		await wipePromise;

		expect(events).toEqual(['step-start', 'commit-fenced', 'db-wipe']);
		coord.dispose();
	});

	it('preempts ONLY background/opportunistic/offline-native lanes on criticalActivity > 0 — NEVER foreground or security lane', async () => {
		const critical = createCriticalActivityCounter();
		const coord = new SyncCoordinator({ critical });

		const ran: string[] = [];
		let bgAborted = false;
		let releaseBg!: () => void;

		coord.register({
			consumerId: 'bg-mail',
			scope: { kind: 'mailbox', id: 'primary' },
			lane: 'offline-native',
			runDeltaStep: async (ctx) => {
				ran.push('bg-start');
				if (ran.filter((x) => x === 'bg-start').length === 1) {
					await new Promise<void>((resolve) => {
						releaseBg = resolve;
						ctx.signal.addEventListener('abort', () => {
							bgAborted = true;
							resolve();
						});
					});
					ctx.fence.assertCommitAllowed();
				}
				ran.push('bg-complete');
				return { kind: 'complete' };
			},
		});

		coord.register({
			consumerId: 'fg-inbox',
			scope: { kind: 'mailbox', id: 'primary' },
			lane: 'foreground',
			runDeltaStep: async () => {
				ran.push('fg-run');
				return { kind: 'complete' };
			},
			purgeScopeCache: () => {
				ran.push('security-purge');
			},
		});

		// Start background step, then raise critical activity.
		coord.trigger({ kind: 'mailbox', id: 'primary' }, { consumerId: 'bg-mail' });
		await Promise.resolve();
		expect(ran).toEqual(['bg-start']);

		const handle = critical.begin('interactive-send');
		await coord.flush();
		expect(bgAborted).toBe(true);
		expect(coord.getState('bg-mail', { kind: 'mailbox', id: 'primary' })?.deferredByCritical).toBe(true);

		// Foreground interactive load runs immediately EVEN while criticalActivity > 0.
		coord.trigger({ kind: 'mailbox', id: 'primary' }, { consumerId: 'fg-inbox' });
		await coord.flush();
		expect(ran).toContain('fg-run');

		// Security lane scope_revoked runs immediately EVEN while criticalActivity > 0!
		coord.register({
			consumerId: 'sec-chan',
			scope: { kind: 'channel', id: '5' },
			lane: 'offline-native',
			runDeltaStep: async () => ({ kind: 'complete' }),
			purgeScopeCache: () => {
				ran.push('sec-chan-purged');
			},
		});
		await coord.handleScopeRevoked({ scopeKind: 'channel', scopeId: '5' });
		expect(ran).toContain('sec-chan-purged');

		// Ending critical scope resumes deferred background work.
		void releaseBg;
		handle.end();
		await coord.flush();
		expect(ran).toContain('bg-complete');
		coord.dispose();
	});

	it('enforces circuit breaker (max 1 delta→fullResync per cycle), jittered backoff, and tombstoneFloorExceeded reconciliation', async () => {
		const coord = new SyncCoordinator({
			backoff: { baseDelayMs: 1_000, maxDelayMs: 300_000, random: () => 1 },
		});

		let deltaCount = 0;
		let fullCount = 0;
		coord.register({
			consumerId: 'mail-resync',
			scope: { kind: 'mailbox', id: 'm1' },
			runDeltaStep: async () => {
				deltaCount += 1;
				return { kind: 'cannotCalculateChanges' };
			},
			runFullResyncStep: async () => {
				fullCount += 1;
				// Simulate persistent cannotCalculateChanges — circuit breaker MUST stop & backoff.
				return { kind: 'cannotCalculateChanges' };
			},
		});

		coord.trigger({ kind: 'mailbox', id: 'm1' });
		await coord.flush();
		expect(deltaCount).toBe(1);
		expect(fullCount).toBe(1);
		expect(coord.getState('mail-resync', { kind: 'mailbox', id: 'm1' })?.backoffAttempt).toBe(1);

		// Re-triggers after 1s backoff.
		await vi.advanceTimersByTimeAsync(1_000);
		await coord.flush();
		expect(deltaCount).toBe(2);
		expect(fullCount).toBe(2);

		// tombstoneFloorExceeded routes to reconcileScopeMembership.
		const reconciled = vi.fn(async (): Promise<StepOutcome> => ({ kind: 'complete', recordsProcessed: 3 }));
		coord.register({
			consumerId: 'chat-reconcile',
			scope: { kind: 'channel', id: '33' },
			runDeltaStep: async () => ({ kind: 'tombstoneFloorExceeded' }),
			reconcileScopeMembership: reconciled,
		});
		coord.trigger({ kind: 'channel', id: '33' });
		await coord.flush();
		expect(reconciled).toHaveBeenCalledOnce();
		coord.dispose();
	});

	it('enforces bounded step budget + zero-progress guard and pauses on MailPageCapacityError without retry-looping', async () => {
		let mono = 1000;
		const coord = new SyncCoordinator({
			nowMonoMs: () => mono,
			budget: { maxRecords: 64, maxBytes: 2 * 1024 * 1024, maxDurationMs: 5_000 },
		});

		// Zero-progress partial step stops after 1 call instead of spinning to deadline.
		const zeroProgressSpy = vi.fn(
			async (): Promise<StepOutcome> => ({
				kind: 'partial',
				recordsProcessed: 0,
				bytesProcessed: 0,
				cursor: null,
			}),
		);
		coord.register({
			consumerId: 'zero-prog',
			scope: { kind: 'space', id: '10' },
			runDeltaStep: zeroProgressSpy,
		});
		coord.trigger({ kind: 'space', id: '10' });
		await coord.flush();
		expect(zeroProgressSpy).toHaveBeenCalledTimes(1);

		// Bounded budget stops once 64 records consumed, then yields and continues automatically (5a).
		const budgetsSeen: number[] = [];
		coord.register({
			consumerId: 'bounded',
			scope: { kind: 'space', id: '11' },
			runDeltaStep: async (ctx: SyncStepContext) => {
				budgetsSeen.push(ctx.budget.maxRecords);
				mono += 100;
				if (budgetsSeen.length >= 3) {
					return { kind: 'complete', recordsProcessed: 10, bytesProcessed: 512 };
				}
				return { kind: 'partial', recordsProcessed: 32, bytesProcessed: 1024, cursor: `c${budgetsSeen.length}` };
			},
		});
		coord.trigger({ kind: 'space', id: '11' });
		await coord.flush();
		expect(budgetsSeen).toEqual([64, 32]);
		// After yield turn (setTimeout 0), continuation finishes page 3 automatically!
		await vi.advanceTimersByTimeAsync(1);
		await coord.flush();
		expect(budgetsSeen).toEqual([64, 32, 64]);

		// MailPageCapacityError pauses background sync without retry-looping.
		const onCapacityExceeded = vi.fn();
		const capCalls = vi.fn(async () => {
			const err = new Error('disk full');
			err.name = 'MailPageCapacityError';
			throw err;
		});
		coord.register({
			consumerId: 'offline-cap',
			scope: { kind: 'mailbox', id: 'primary' },
			lane: 'offline-native',
			runDeltaStep: capCalls,
			onCapacityExceeded,
		});
		coord.trigger({ kind: 'mailbox', id: 'primary' }, { consumerId: 'offline-cap' });
		await coord.flush();
		expect(capCalls).toHaveBeenCalledTimes(1);
		expect(onCapacityExceeded).toHaveBeenCalledWith('disk full');
		expect(coord.getState('offline-cap', { kind: 'mailbox', id: 'primary' })?.storageFull).toBe(true);

		// Further wakeups and timers do NOT retry-loop while storageFull is set.
		coord.handleWakeup({ scopeKind: 'mailbox', scopeId: 'primary', seq: 99 });
		await vi.advanceTimersByTimeAsync(60_000);
		expect(capCalls).toHaveBeenCalledTimes(1);
		coord.dispose();
	});

	it('sets reconnectPending and triggers catch-up on ALL registered scopes on reconnect', async () => {
		const fake = createFakeTransport();
		const coord = new SyncCoordinator({ transport: fake.transport });
		const triggers: string[] = [];

		for (const [consumerId, scope] of [
			['cal', { kind: 'mailbox', id: 'primary' } as ScopeKey],
			['drive', { kind: 'space', id: '3' } as ScopeKey],
			['chat', { kind: 'channel', id: '42' } as ScopeKey],
		] as const) {
			coord.register({
				consumerId,
				scope,
				runDeltaStep: async (ctx) => {
					triggers.push(`${consumerId}:${ctx.trigger}`);
					return { kind: 'complete' };
				},
			});
		}

		fake.emitReconnect();
		await coord.flush();
		expect(triggers.sort()).toEqual(['cal:reconnect', 'chat:reconnect', 'drive:reconnect']);
		coord.dispose();
	});

	it('keeps Drive space attached on subtreeAnchorId revocation while running purgeScopeCache', async () => {
		const fake = createFakeTransport();
		const coord = new SyncCoordinator({ transport: fake.transport });
		const purged: ScopeRevokedEvent[] = [];

		coord.register({
			consumerId: 'drive-7',
			scope: { kind: 'space', id: '7' },
			runDeltaStep: async () => ({ kind: 'complete' }),
			purgeScopeCache: (evt) => {
				purged.push(evt);
			},
		});

		await coord.handleScopeRevoked({ scopeKind: 'space', scopeId: '7', subtreeAnchorId: '501' });
		expect(purged).toEqual([{ scopeKind: 'space', scopeId: '7', subtreeAnchorId: '501' }]);
		expect(coord.getState('drive-7', { kind: 'space', id: '7' })?.detached).toBe(false);
		expect(coord.getAttachedScopes()).toEqual([{ kind: 'space', id: '7' }]);
		coord.dispose();
	});

	it('serializes wakeups behind an active subtreeAnchorId purgeScopeCache via the per-scope purge mutex (4a)', async () => {
		const coord = new SyncCoordinator();
		const order: string[] = [];
		let finishPurge!: () => void;
		const purgeGate = new Promise<void>((r) => {
			finishPurge = r;
		});

		coord.register({
			consumerId: 'drive-mutex',
			scope: { kind: 'space', id: '12' },
			runDeltaStep: async () => {
				order.push('delta-start');
				return { kind: 'complete' };
			},
			purgeScopeCache: async () => {
				order.push('purge-start');
				await purgeGate;
				order.push('purge-end');
			},
		});

		const revokeP = coord.handleScopeRevoked({ scopeKind: 'space', scopeId: '12', subtreeAnchorId: '88' });
		for (let i = 0; i < 4; i++) await Promise.resolve();
		expect(order).toEqual(['purge-start']);

		// Wakeup arrives while purgeScopeCache (e.g. fullVisibilityReconcile) is still running.
		coord.handleWakeup({ scopeKind: 'space', scopeId: '12', seq: 2 });
		await Promise.resolve();
		await Promise.resolve();
		// Delta MUST NOT start before purge completes!
		expect(order).toEqual(['purge-start']);

		finishPurge();
		await revokeP;
		await coord.flush();
		expect(order).toEqual(['purge-start', 'purge-end', 'delta-start']);
		coord.dispose();
	});

	it('enforces maxGlobalConcurrency=1 across multiple scopes (Finding #3)', async () => {
		const coord = new SyncCoordinator({ maxGlobalConcurrency: 1 });
		let inFlight = 0;
		let maxObserved = 0;
		const completed: string[] = [];

		for (const id of ['1', '2', '3']) {
			coord.register({
				consumerId: `space-${id}`,
				scope: { kind: 'space', id },
				runDeltaStep: async () => {
					inFlight += 1;
					maxObserved = Math.max(maxObserved, inFlight);
					await Promise.resolve();
					await Promise.resolve();
					completed.push(id);
					inFlight -= 1;
					return { kind: 'complete' };
				},
			});
		}

		coord.trigger({ kind: 'space', id: '1' });
		coord.trigger({ kind: 'space', id: '2' });
		coord.trigger({ kind: 'space', id: '3' });
		await coord.flush();

		expect(maxObserved).toBe(1);
		expect(completed).toEqual(['1', '2', '3']);
		coord.dispose();
	});

	it('notifies onScopeRevoked observers even when no adapter is registered for that scope (Finding #9)', async () => {
		const coord = new SyncCoordinator();
		const observed: Array<{ scopeKind: string; scopeId: string }> = [];
		const off = coord.onScopeRevoked((evt) => {
			observed.push({ scopeKind: evt.scopeKind, scopeId: evt.scopeId });
		});

		await coord.handleScopeRevoked({ scopeKind: 'channel', scopeId: '404' });
		expect(observed).toEqual([{ scopeKind: 'channel', scopeId: '404' }]);
		off();
		coord.dispose();
	});

	it('holds wipe admission fence closed mid-wipe so new wakeups/triggers cannot start during db.wipe (Finding #11)', async () => {
		const coord = new SyncCoordinator();
		let runs = 0;
		coord.register({
			consumerId: 'mail-offline',
			scope: { kind: 'mailbox', id: 'primary' },
			runDeltaStep: async () => {
				runs += 1;
				return { kind: 'complete' };
			},
		});

		let finishWipe!: () => void;
		const wipeGate = new Promise<void>((r) => {
			finishWipe = r;
		});

		const wipeP = coord.runWithWipeFence('offline.wipe', async () => {
			// Mid-wipe wakeups & manual triggers MUST be rejected while fence is held!
			coord.handleWakeup({ scopeKind: 'mailbox', scopeId: 'primary', seq: 1 });
			coord.trigger({ kind: 'mailbox', id: 'primary' });
			await Promise.resolve();
			expect(runs).toBe(0);
			await wipeGate;
		});

		for (let i = 0; i < 4; i++) await Promise.resolve();
		coord.trigger({ kind: 'mailbox', id: 'primary' });
		expect(runs).toBe(0);

		finishWipe();
		await wipeP;

		// After fence releases, normal triggers resume cleanly.
		coord.trigger({ kind: 'mailbox', id: 'primary' });
		await coord.flush();
		expect(runs).toBe(1);
		coord.dispose();
	});
});
