import { describe, it, expect } from 'vitest';

import { createCoordinator, createOffPolicySource, jobIdForTrigger, type CoordinatorPolicy } from './coordinator';
import { createHarnessCoordinator, createMemoryOfflineStore, HARNESS_EXECUTE_POLICY, HARNESS_NOMINAL_SNAPSHOT } from '$lib/native/testing/backgroundWorkHarness';
import { createMemoryJobPersistence, type JobPersistence } from './jobStore';
import { createSyncDeltaStep, markBoundedSyncStep, type DeltaChangesClient } from './steps';
import { CRITICAL_QUIET_RESUME_MS, YIELD_MAX_BYTES } from './work-contract';

const OFF_POLICY = {
	flagEnabled: false,
	rolloutMode: 'off' as const,
	requested: { backgroundSyncEnabled: false, automaticNetwork: 'never' as const },
	effective: { backgroundAllowed: false, automaticNetwork: 'never' as const, opportunisticRequiresCharging: true },
	workOffline: false,
};

function noopStep() {
	return createSyncDeltaStep({
		emailChanges: async () => ({ newState: '1', hasMoreChanges: false, created: [], updated: [], destroyed: [] }),
		emailGet: async () => ({ list: [], state: '1' }),
	});
}

describe('E4-I coordinator OFF defaults', () => {
	it('the default policy source is OFF and no admission can pass it', async () => {
		const policy = await createOffPolicySource().readPolicy();
		expect(policy.flagEnabled).toBe(false);
		expect(policy.rolloutMode).toBe('off');
	});

	it('flag OFF / mode off records policyDenied pauses and runs no work', async () => {
		const events: import('./coordinator').CoordinatorEvent[] = [];
		const coordinator = createHarnessCoordinator({
			events,
			policy: OFF_POLICY,
			pages: [{
				newState: '5', hasMoreChanges: false, created: ['1'], updated: [], destroyed: [],
				emails: [],
			}],
		});
		await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 1 });
		await coordinator.runDueWork();
		const read = await coordinator.readJobResult('opt-reconnect-acct-1');
		expect(read.kind).toBe('committed');
		if (read.kind === 'committed') {
			expect(read.result.state).toBe('paused');
			expect(read.result).toMatchObject({ reason: 'policyDenied' });
		}
		expect(events.some((event) => event.kind === 'admission-eligible')).toBe(false);
	});

	it('native-opportunity triggers from a prior lifecycle epoch cannot restore eligibility', async () => {
		const coordinator = createHarnessCoordinator({});
		coordinator.bindLifecycleEpoch(2);
		const stale = await coordinator.ingestTrigger({ kind: 'nativeOpportunity', accountId: 'a', generation: 1, epoch: 1 });
		expect(stale).toEqual({ kind: 'rejected-stale-epoch' });
		const fresh = await coordinator.ingestTrigger({ kind: 'nativeOpportunity', accountId: 'a', generation: 2, epoch: 2 });
		expect(fresh.kind === 'queued' || fresh.kind === 'coalesced').toBe(true);
		expect(coordinator.epoch).toBe(2);
	});

	it('stale capability observations cannot authorize new optional work', async () => {
		const coordinator = createHarnessCoordinator({ observationAgeMs: 6_000 });
		await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'a', generation: 1 });
		await coordinator.runDueWork();
		const read = await coordinator.readJobResult('opt-reconnect-a');
		expect(read.kind === 'committed' && read.result.state === 'paused').toBe(true);
		// The unavailable path is used, never a manufactured nominal snapshot.
		expect(read.kind === 'committed' && read.result.state === 'paused' && read.result.reason).toBe('capabilityUnavailable');
	});

	it('a failed or unsupported capability signal cannot authorize work', async () => {
		const coordinator = createHarnessCoordinator({ snapshot: null });
		await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'a', generation: 1 });
		await coordinator.runDueWork();
		const read = await coordinator.readJobResult('opt-reconnect-a');
		expect(read.kind === 'committed' && read.result.state === 'paused' && read.result.reason).toBe('capabilityUnavailable');
	});

	it('job identity is deterministic per trigger kind and account', () => {
		expect(jobIdForTrigger({ kind: 'reconnect', accountId: 'a', generation: 1 }))
			.toBe(jobIdForTrigger({ kind: 'reconnect', accountId: 'a', generation: 9 }));
		expect(jobIdForTrigger({ kind: 'reconnect', accountId: 'a', generation: 1 }))
			.not.toBe(jobIdForTrigger({ kind: 'authenticatedPush', accountId: 'a', generation: 1 }));
	});

	it('construction refuses steps that are not branded bounded sync steps', () => {
		const unbranded = async () => ({ checkpoint: { version: 1 as const, cursor: null }, progress: { done: 0, chargedUnits: 0 }, outcome: 'partial' as const });
		expect(() => createCoordinator({
			clock: { nowMonoMs: () => 0, nowUtcMs: () => 0 },
			random: () => 0.5,
			policy: createOffPolicySource(),
			capability: { readCapability: async () => null },
			store: createMemoryOfflineStore(),
			deltaStep: unbranded,
			windowStep: noopStep(),
			jobs: createHarnessCoordinator({}).jobs,
		})).toThrow(/not a bounded sync step/);
	});
});

// ── Astra correction regressions (scheduling / policy / fallback) ───────────

const START_UTC = Date.parse('2026-09-17T00:00:00Z');

function scriptedCoordinator(overrides: {
	policy?: CoordinatorPolicy;
	deltaStep?: ReturnType<typeof createSyncDeltaStep>;
	windowStep?: ReturnType<typeof createSyncDeltaStep>;
	clock?: { nowMonoMs(): number; nowUtcMs(): number };
	jobs?: JobPersistence;
	capability?: { readCapability(): Promise<{ snapshot: typeof HARNESS_NOMINAL_SNAPSHOT; receivedMonoMs: number; epoch: number } | null> };
}) {
	// The merged policy object is returned so tests can mutate the SAME
	// instance the coordinator reads (live policy narrowing).
	const policy: CoordinatorPolicy = { ...HARNESS_EXECUTE_POLICY, ...(overrides.policy ?? {}) };
	const clock = overrides.clock ?? { nowMonoMs: () => 0, nowUtcMs: () => START_UTC };
	const coordinator = createCoordinator({
		clock,
		random: () => 0.5,
		policy: { readPolicy: async () => policy },
		capability: overrides.capability ?? {
			// A live reader stamps the observation with the CURRENT monotonic
			// time, exactly like a real capability subscription.
			readCapability: async () => ({ snapshot: HARNESS_NOMINAL_SNAPSHOT, receivedMonoMs: clock.nowMonoMs(), epoch: 0 }),
		},
		store: createMemoryOfflineStore(),
		deltaStep: overrides.deltaStep ?? noopStep(),
		windowStep: overrides.windowStep ?? noopStep(),
		jobs: overrides.jobs ?? createMemoryJobPersistence(),
	});
	return { coordinator, policy };
}

function doneStep(done: number, outcome: 'partial' | 'complete' | 'blocked' = 'complete') {
	return markBoundedSyncStep(async () => ({
		checkpoint: { version: 1 as const, cursor: `c:${done}` },
		progress: { done, chargedUnits: done },
		outcome,
	}));
}

describe('E4-I coordinator scheduling corrections (Astra)', () => {
	it('admission runs through the E2 scheduler: at most two concurrent jobs, never two per account', async () => {
		// Astra finding 7 reproduction: four due jobs used to start four
		// simultaneous steps, including two for one account.
		const jobs = createMemoryJobPersistence();
		let started = 0;
		let maxConcurrent = 0;
		let concurrent = 0;
		let releasePages: (() => void) | null = null;
		const gate = new Promise<void>((resolve) => {
			releasePages = resolve;
		});
		const slowClient: DeltaChangesClient = {
			emailChanges: async () => {
				started += 1;
				concurrent += 1;
				maxConcurrent = Math.max(maxConcurrent, concurrent);
				await gate;
				concurrent -= 1;
				return { newState: '1', hasMoreChanges: false, created: [], updated: [], destroyed: [] };
			},
			emailGet: async () => ({ list: [], state: '1' }),
		};
		const { coordinator } = scriptedCoordinator({
			jobs,
			deltaStep: createSyncDeltaStep(slowClient),
		});
		for (const [kind, account] of [
			['reconnect', 'acct-1'],
			['foreground', 'acct-1'],
			['reconnect', 'acct-2'],
			['reconnect', 'acct-3'],
		] as const) {
			await coordinator.ingestTrigger({ kind, accountId: account, generation: 1 });
		}
		const firstCycle = coordinator.runDueWork();
		await new Promise<void>((resolve) => setTimeout(resolve, 0));
		// Exactly GLOBAL_OPTIONAL_CONCURRENCY jobs run, and the scheduler's
		// per-account rule kept acct-1's second job out of this cycle.
		expect(started).toBe(2);
		expect(maxConcurrent).toBe(2);
		await releasePages!();
		await firstCycle;
		// The remaining queue drains in later bounded cycles.
		for (let cycle = 0; cycle < 3; cycle += 1) {
			await coordinator.runDueWork();
		}
		expect(started).toBe(4);
		expect(maxConcurrent).toBe(2);
		for (const jobId of ['opt-reconnect-acct-1', 'opt-foreground-acct-1', 'opt-reconnect-acct-2', 'opt-reconnect-acct-3']) {
			const read = await coordinator.readJobResult(jobId);
			expect(read.kind === 'committed' && read.result.state).toBe('complete');
		}
	});

	it('a job admitted immediately after Critical ended is the criticalQuiet block, not admission', async () => {
		// Astra finding 7 reproduction: work was admitted the instant Critical
		// ended. The E2 5s quiet window must hold.
		let mono = 0;
		const jobs = createMemoryJobPersistence();
		const { coordinator } = scriptedCoordinator({
			jobs,
			clock: { nowMonoMs: () => mono, nowUtcMs: () => START_UTC + mono },
		});
		await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 1 });
		const handle = coordinator.criticalBegin();
		handle.end();
		await coordinator.runDueWork();
		// Still inside the quiet window: nothing admitted, job stays queued.
		const blocked = await coordinator.listJobs();
		expect(blocked.map((job) => job.jobId)).toContain('opt-reconnect-acct-1');
		mono += CRITICAL_QUIET_RESUME_MS + 1;
		await coordinator.runDueWork();
		const read = await coordinator.readJobResult('opt-reconnect-acct-1');
		expect(read.kind).toBe('committed');
		if (read.kind === 'committed') {
			expect(read.result.state).toBe('complete');
		}
	});

	it('policy narrowed OFF after one checkpoint stops the job before the next step', async () => {
		// Astra finding 8 reproduction: policy was read once per run, so
		// narrowing OFF mid-job still ran another step to completion.
		let stepCalls = 0;
		const client: DeltaChangesClient = {
			emailChanges: async () => {
				stepCalls += 1;
				// Narrow the flag after the FIRST step has committed: the mutation
				// hits the SAME policy object the coordinator re-reads per step.
				if (stepCalls === 1) {
					policy.flagEnabled = false;
					policy.rolloutMode = 'off';
				}
				return { newState: String(stepCalls), hasMoreChanges: true, created: ['1'], updated: [], destroyed: [] };
			},
			emailGet: async () => ({ list: [], state: '1' }),
		};
		const { coordinator, policy } = scriptedCoordinator({ deltaStep: createSyncDeltaStep(client) });
		await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 1 });
		await coordinator.runDueWork();
		// Exactly ONE step ran; the job paused instead of completing.
		expect(stepCalls).toBe(1);
		const read = await coordinator.readJobResult('opt-reconnect-acct-1');
		expect(read.kind).toBe('committed');
		if (read.kind === 'committed') {
			expect(read.result.state).toBe('paused');
			expect(read.result.state === 'paused' && read.result.reason).toBe('policyDenied');
		}
	});

	it('drainForRollback awaits running work and latches admission closed', async () => {
		// Astra finding 8 reproduction: the drain neither blocked future
		// admission nor awaited completion.
		let releasePage: (() => void) | null = null;
		const gate = new Promise<void>((resolve) => {
			releasePage = resolve;
		});
		const client: DeltaChangesClient = {
			emailChanges: async () => {
				await gate;
				return { newState: '1', hasMoreChanges: false, created: [], updated: [], destroyed: [] };
			},
			emailGet: async () => ({ list: [], state: '1' }),
		};
		const { coordinator } = scriptedCoordinator({ deltaStep: createSyncDeltaStep(client) });
		await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 1 });
		const cycle = coordinator.runDueWork();
		await new Promise<void>((resolve) => setTimeout(resolve, 0));
		// The drain aborts the running step and settles BEFORE it resolves.
		const drained = coordinator.drainForRollback();
		releasePage!();
		await Promise.all([cycle, drained]);
		// Post-drain admission is closed: the requeued job is not admitted.
		await coordinator.runDueWork();
		const read = await coordinator.readJobResult('opt-reconnect-acct-1');
		expect(read.kind === 'committed' && read.result.state === 'complete').toBe(false);
		expect(read.kind === 'committed' && read.result.state === 'failed').toBe(false);
	});

	it('a pruned delta (cannotCalculateChanges) reaches the bounded window recovery', async () => {
		// Astra finding 14 reproduction: the server answer surfaced as a thrown
		// terminal failure with zero window-step calls.
		const prunedClient: DeltaChangesClient = {
			emailChanges: async () => {
				throw Object.assign(new Error('cannotCalculateChanges'), { type: 'cannotCalculateChanges' });
			},
			emailGet: async () => ({ list: [], state: '0' }),
		};
		let windowCalls = 0;
		const windowStep = markBoundedSyncStep(async () => {
			windowCalls += 1;
			return {
				checkpoint: { version: 1 as const, cursor: 'window:recovered' },
				progress: { done: 1, chargedUnits: 1 },
				outcome: 'complete' as const,
			};
		});
		const { coordinator } = scriptedCoordinator({
			deltaStep: createSyncDeltaStep(prunedClient),
			windowStep: windowStep as unknown as ReturnType<typeof createSyncDeltaStep>,
		});
		await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 1 });
		await coordinator.runDueWork();
		// The window resync replaced the unanchored walk and completed.
		expect(windowCalls).toBeGreaterThanOrEqual(1);
		const read = await coordinator.readJobResult('opt-reconnect-acct-1');
		expect(read.kind).toBe('committed');
		if (read.kind === 'committed') {
			expect(read.result.state).toBe('complete');
		}
	});
});

// ── Astra r2 correction regressions (fencing / reservations / DRR / aborts) ─

describe('E4-I coordinator r2 corrections (Astra)', () => {
	it('a claimant that lost its lease between claim and commit never commits', async () => {
		// Astra r2 finding 2 reproduction: the fence was re-derived from a
		// post-claim read, so ownership moving to another owner set it to
		// undefined — fencing disabled — and A committed complete while B held
		// the lease. The claim's stamped fence is now the ONLY credential.
		const jobs = createMemoryJobPersistence();
		const originalClaim = jobs.claimLease.bind(jobs);
		jobs.claimLease = async (jobId, owner, now) => {
			const fence = await originalClaim(jobId, owner, now);
			if (fence) {
				// The claimed lease expires; a competing owner claims the SAME job
				// at the SAME generation before this claimant commits anything.
				await jobs.reclaimExpiredLeases(now + 60_000);
				expect(await originalClaim(jobId, 'owner-b', now + 60_000)).not.toBeNull();
			}
			return fence;
		};
		const { coordinator } = scriptedCoordinator({ jobs });
		await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 3 });
		await coordinator.runDueWork();
		// The stale writer committed NOTHING: no checkpoint, no result, and the
		// competing owner still holds the lease.
		const job = await jobs.readJob('opt-reconnect-acct-1');
		expect(job?.checkpoint?.cursor ?? null).toBeNull();
		expect(job?.leaseOwner).toBe('owner-b');
		expect(await coordinator.readJobResult('opt-reconnect-acct-1')).toEqual({ kind: 'unknown' });
	});

	it('Critical interruption releases undispatched scheduler reservations', async () => {
		// Astra r2 finding 5 reproduction: the dispatch loop broke on Critical
		// activity without removing entries already placed in scheduler.running,
		// so a queued account stayed permanently undispatchable.
		let mono = 0;
		const jobs = createMemoryJobPersistence();
		let handle: import('./criticalScope').CriticalScopeHandle | null = null;
		const coordinator = createCoordinator({
			clock: { nowMonoMs: () => mono, nowUtcMs: () => START_UTC + mono },
			random: () => 0.5,
			policy: { readPolicy: async () => ({ ...HARNESS_EXECUTE_POLICY }) },
			capability: { readCapability: async () => ({ snapshot: HARNESS_NOMINAL_SNAPSHOT, receivedMonoMs: mono, epoch: 0 }) },
			store: createMemoryOfflineStore(),
			deltaStep: noopStep(),
			windowStep: noopStep(),
			jobs,
		});
		// Flip Critical the moment the FIRST claim lands: the remaining
		// dispatches of this batch never run their loop body.
		const originalClaim = jobs.claimLease.bind(jobs);
		let flipped = false;
		jobs.claimLease = async (jobId, owner, now) => {
			const fence = await originalClaim(jobId, owner, now);
			if (fence && !flipped) {
				flipped = true;
				handle = coordinator.criticalBegin();
			}
			return fence;
		};
		for (const account of ['acct-1', 'acct-2', 'acct-3']) {
			await coordinator.ingestTrigger({ kind: 'reconnect', accountId: account, generation: 1 });
		}
		await coordinator.runDueWork();
		expect(flipped).toBe(true);
		// Critical ended; the quiet window elapsed.
		handle!.end();
		mono += CRITICAL_QUIET_RESUME_MS + 1;
		for (let cycle = 0; cycle < 5; cycle += 1) {
			await coordinator.runDueWork();
		}
		// EVERY queued account — including the one whose reservation was
		// stranded by the interruption — drains to completion.
		for (const account of ['acct-1', 'acct-2', 'acct-3']) {
			const read = await coordinator.readJobResult(`opt-reconnect-${account}`);
			expect(read.kind === 'committed' && read.result.state).toBe('complete');
		}
	});

	it('one dispatch executes under ONE budget: DRR bounds the actual service', async () => {
		// Astra r2 finding 6 reproduction: every step re-obtained a fresh budget
		// and renewed its deadline, so one dispatch kept running (steps at 0,
		// 4000, 8000 ms with deadlines renewed to 5000, 9000, 13000 ms).
		let mono = 0;
		let stepCalls = 0;
		const step = markBoundedSyncStep(async () => {
			stepCalls += 1;
			// Each step burns more than the whole 5s budget window.
			mono += 6_000;
			return {
				checkpoint: { version: 1 as const, cursor: `c:${stepCalls}` },
				progress: { done: 1, chargedUnits: 1 },
				outcome: 'partial' as const,
			};
		});
		const { coordinator } = scriptedCoordinator({
			deltaStep: step as unknown as ReturnType<typeof createSyncDeltaStep>,
			clock: { nowMonoMs: () => mono, nowUtcMs: () => START_UTC + mono },
		});
		await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 1 });
		await coordinator.runDueWork();
		// The dispatch budget (deadline fixed at dispatch time) stopped the job
		// after ONE step; the job paused instead of renewing its own deadline.
		expect(stepCalls).toBe(1);
		const read = await coordinator.readJobResult('opt-reconnect-acct-1');
		expect(read.kind === 'committed' && read.result.state).toBe('paused');
		expect(read.kind === 'committed' && read.result.state === 'paused' && read.result.reason).toBe('deadlineExceeded');
	});

	it('an actual request cancellation (DOM AbortError) is an interruption, never a terminal failure', async () => {
		// Astra r2 finding 7 reproduction: Critical aborted emailChanges
		// mid-flight; the fetch rejected with a DOM AbortError and the
		// coordinator recorded a nonretryable `failed`.
		let mono = 0;
		const jobs = createMemoryJobPersistence();
		let stepCalls = 0;
		let handle: import('./criticalScope').CriticalScopeHandle | null = null;
		const step = markBoundedSyncStep(async () => {
			stepCalls += 1;
			if (stepCalls === 1) {
				// Critical begins mid-request; the abort lands while the fetch is
				// in flight and the request rejects the way fetch does.
				handle = coordinator.criticalBegin();
				throw Object.assign(new Error('The operation was aborted'), { name: 'AbortError' });
			}
			return {
				checkpoint: { version: 1 as const, cursor: 'c:done' },
				progress: { done: 1, chargedUnits: 1 },
				outcome: 'complete' as const,
			};
		});
		const coordinator = createCoordinator({
			clock: { nowMonoMs: () => mono, nowUtcMs: () => START_UTC + mono },
			random: () => 0.5,
			policy: { readPolicy: async () => ({ ...HARNESS_EXECUTE_POLICY }) },
			capability: { readCapability: async () => ({ snapshot: HARNESS_NOMINAL_SNAPSHOT, receivedMonoMs: mono, epoch: 0 }) },
			store: createMemoryOfflineStore(),
			deltaStep: step as unknown as ReturnType<typeof createSyncDeltaStep>,
			windowStep: noopStep(),
			jobs,
		});
		await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 1 });
		await coordinator.runDueWork();
		// No terminal failure was recorded: the aborted job yielded silently.
		expect(await coordinator.readJobResult('opt-reconnect-acct-1')).toEqual({ kind: 'unknown' });
		// After Critical ended and the quiet window elapsed, the job reran.
		handle!.end();
		mono += CRITICAL_QUIET_RESUME_MS + 1;
		await coordinator.runDueWork();
		const read = await coordinator.readJobResult('opt-reconnect-acct-1');
		expect(read.kind === 'committed' && read.result.state).toBe('complete');
	});

	it('drainForRollback covers pending admissions: nothing is claimed or written after the drain', async () => {
		// Astra r2 finding 9 reproduction: an admission awaiting policy outlived
		// the completed drain, claimed a lease and wrote a result.
		const jobs = createMemoryJobPersistence();
		let releaseAdmission: (() => void) | null = null;
		const admissionGate = new Promise<void>((resolve) => {
			releaseAdmission = resolve;
		});
		const coordinator = createCoordinator({
			clock: { nowMonoMs: () => 0, nowUtcMs: () => START_UTC },
			random: () => 0.5,
			policy: { readPolicy: async () => {
				// The drain will complete while this admission is still pending.
				await admissionGate;
				return { ...HARNESS_EXECUTE_POLICY };
			} },
			capability: { readCapability: async () => ({ snapshot: HARNESS_NOMINAL_SNAPSHOT, receivedMonoMs: 0, epoch: 0 }) },
			store: createMemoryOfflineStore(),
			deltaStep: noopStep(),
			windowStep: noopStep(),
			jobs,
		});
		// Observe any post-drain claim.
		let postDrainClaim = false;
		const originalClaim = jobs.claimLease.bind(jobs);
		const drainStarted = { current: false };
		jobs.claimLease = async (jobId, owner, now) => {
			if (drainStarted.current) postDrainClaim = true;
			return originalClaim(jobId, owner, now);
		};
		await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 1 });
		const cycle = coordinator.runDueWork();
		await new Promise<void>((resolve) => setTimeout(resolve, 0));
		const drained = coordinator.drainForRollback();
		drainStarted.current = true;
		releaseAdmission!();
		await Promise.all([cycle, drained]);
		expect(postDrainClaim).toBe(false);
		const job = await jobs.readJob('opt-reconnect-acct-1');
		expect(job?.leaseOwner).toBeNull();
		expect(await coordinator.readJobResult('opt-reconnect-acct-1')).toEqual({ kind: 'unknown' });
	});
});

// ── Astra r5 correction regressions ──────────────────────────────────────────

describe('E4-I coordinator r5 corrections (Astra)', () => {
	it('the dispatch byte budget spans its steps: a partial step cannot re-spend the allowance', async () => {
		// Astra r5 finding 4 reproduction: every partial step received
		// `maxBytes: budget.maxBytes` anew while the step reset its byte
		// accounting per call, so ONE dispatch read its allowance N times
		// (2,200,050 bytes applied under a 2,097,152-byte dispatch). The
		// coordinator now deducts each step's reported appliedBytes and passes
		// only the REMAINING budget to the next call.
		let mono = 0;
		const seenBudgets: number[] = [];
		const consumed: number[] = [];
		const step = markBoundedSyncStep(async (opts) => {
			seenBudgets.push(opts.budget.maxBytes);
			// The step consumes HALF of whatever allowance it was handed.
			const applied = opts.budget.maxBytes > 0 ? Math.ceil(opts.budget.maxBytes / 2) : 0;
			consumed.push(applied);
			// Stay inside the 5s dispatch deadline between steps.
			mono += 1_000;
			return {
				checkpoint: { version: 1 as const, cursor: `c:${seenBudgets.length}` },
				progress: { done: 1, chargedUnits: 1, appliedBytes: applied },
				outcome: 'partial' as const,
			};
		});
		const { coordinator } = scriptedCoordinator({
			deltaStep: step as unknown as ReturnType<typeof createSyncDeltaStep>,
			clock: { nowMonoMs: () => mono, nowUtcMs: () => START_UTC + mono },
		});
		await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 1 });
		await coordinator.runDueWork();
		// Several partial steps ran within the single dispatch.
		expect(seenBudgets.length).toBeGreaterThanOrEqual(2);
		// The FIRST step received the full dispatch allowance; every later step
		// received only the remainder of what earlier steps already spent.
		expect(seenBudgets[0]).toBe(YIELD_MAX_BYTES);
		expect(seenBudgets[1]).toBeLessThan(seenBudgets[0]);
		// Total consumption across the whole dispatch never exceeds ONE
		// allowance (the old behavior spent it anew at every partial step).
		const totalApplied = consumed.reduce((sum, value) => sum + value, 0);
		expect(totalApplied).toBeLessThanOrEqual(YIELD_MAX_BYTES);
		expect(totalApplied).toBeGreaterThan(0);
		// The unbounded walking still ends honestly at the dispatch deadline.
		const read = await coordinator.readJobResult('opt-reconnect-acct-1');
		expect(read.kind === 'committed' && read.result.state).toBe('paused');
	});

	it('an exhausted byte budget stops the dispatch instead of spinning no-progress steps (r6)', async () => {
		// Astra r6 finding 4 reproduction: the coordinator deducted the applied
		// bytes but then looped unconditionally, so a zero/no-progress remainder
		// re-ran the step (and re-committed the same checkpoint) until the time
		// deadline — with the un-fixed steps issuing network calls each round.
		let mono = 0;
		const seenBudgets: number[] = [];
		const step = markBoundedSyncStep(async (opts) => {
			seenBudgets.push(opts.budget.maxBytes);
			mono += 1_000;
			if (seenBudgets.length === 1) {
				// The one productive step consumes the ENTIRE allowance.
				return {
					checkpoint: { version: 1 as const, cursor: 'c:1' },
					progress: { done: 1, chargedUnits: 1, appliedBytes: opts.budget.maxBytes },
					outcome: 'partial' as const,
				};
			}
			// With the budget exhausted, the real bounded steps fetch nothing and
			// return the remainder-carrying cursor unchanged (steps.ts r6 fix).
			return {
				checkpoint: { version: 1 as const, cursor: 'c:1' },
				progress: { done: 0, chargedUnits: 0, appliedBytes: 0 },
				outcome: 'partial' as const,
			};
		});
		const { coordinator } = scriptedCoordinator({
			deltaStep: step as unknown as ReturnType<typeof createSyncDeltaStep>,
			clock: { nowMonoMs: () => mono, nowUtcMs: () => START_UTC + mono },
		});
		await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 1 });
		await coordinator.runDueWork();
		// Exactly TWO step calls: the productive one and the zero-budget call
		// that proves no fetch runs — NOT a spin of identical no-progress calls
		// until the 5s dispatch deadline (the old loop re-ran it ~5 more times).
		expect(seenBudgets).toEqual([YIELD_MAX_BYTES, 0]);
		expect(seenBudgets.every((bytes) => bytes <= YIELD_MAX_BYTES)).toBe(true);
		// The spent budget still terminates as a paused result at the last
		// committed checkpoint.
		const read = await coordinator.readJobResult('opt-reconnect-acct-1');
		expect(read.kind === 'committed' && read.result.state).toBe('paused');
	});
});
