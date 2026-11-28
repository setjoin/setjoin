/**
 * Coordinator dispatch-loop edge branches (coverage round r2).
 *
 * Real behavior tests for the edges the main suites leave cold: the
 * window-step registration guard, stale-epoch capability observations, the
 * OBSERVED gate both at dispatch and mid-execution, scheduler-expired queue
 * entries, vanished dispatch records, lost claims, full-jitter backoff with
 * its scheduler requeue, abort-error shapes, lifecycle-epoch guards, equal
 * generation coalesce rejection, the drain latch, account cancellation and
 * disposal.
 */

import { describe, it, expect } from 'vitest';

import {
	createCoordinator,
	createOffPolicySource,
	jobIdForTrigger,
	type Coordinator,
	type CoordinatorPolicy,
	type CoordinatorEvent,
} from './coordinator';
import {
	createMemoryOfflineStore,
	HARNESS_EXECUTE_POLICY,
	HARNESS_NOMINAL_SNAPSHOT,
} from '$lib/native/testing/backgroundWorkHarness';
import { createMemoryJobPersistence, type JobPersistence, type OptionalJobRecord } from './jobStore';
import { createSyncDeltaStep, markBoundedSyncStep, type DeltaChangesClient } from './steps';

const START_UTC = Date.parse('2026-09-17T00:00:00Z');

function noopStep() {
	return createSyncDeltaStep({
		emailChanges: async () => ({ newState: '1', hasMoreChanges: false, created: [], updated: [], destroyed: [] }),
		emailGet: async () => ({ list: [], state: '1' }),
	});
}

function baseJobRecord(overrides: Partial<OptionalJobRecord> = {}): OptionalJobRecord {
	return {
		jobId: 'opt-reconnect-acct-1',
		accountId: 'acct-1',
		workClass: 'background',
		state: 'queued',
		triggerGeneration: 1,
		coalescingKey: 'reconnect:acct-1',
		attempts: 0,
		deadlineUtc: new Date(START_UTC + 7 * 24 * 60 * 60 * 1000).toISOString(),
		queuedAtUtcMs: START_UTC,
		retryAtUtcMs: null,
		stepKind: 'delta',
		checkpoint: null,
		leaseOwner: null,
		leaseExpiresAtMs: null,
		...overrides,
	};
}

interface Fixture {
	coordinator: Coordinator;
	jobs: ReturnType<typeof createMemoryJobPersistence>;
	events: CoordinatorEvent[];
	/** The SAME merged policy instance the coordinator re-reads. */
	policy: CoordinatorPolicy;
}

function buildCoordinator(overrides: {
	policy?: Partial<CoordinatorPolicy>;
	deltaStep?: ReturnType<typeof createSyncDeltaStep>;
	windowStep?: unknown;
	clock?: { nowMonoMs(): number; nowUtcMs(): number };
	jobs?: JobPersistence;
	capability?: { readCapability(): Promise<{ snapshot: typeof HARNESS_NOMINAL_SNAPSHOT; receivedMonoMs: number; epoch: number } | null> };
	random?: () => number;
}): Fixture {
	const policy: CoordinatorPolicy = { ...HARNESS_EXECUTE_POLICY, ...(overrides.policy ?? {}) };
	const clock = overrides.clock ?? { nowMonoMs: () => 0, nowUtcMs: () => START_UTC };
	const jobs = (overrides.jobs ?? createMemoryJobPersistence()) as ReturnType<typeof createMemoryJobPersistence>;
	const events: CoordinatorEvent[] = [];
	const coordinator = createCoordinator({
		clock,
		random: overrides.random ?? (() => 0.5),
		policy: { readPolicy: async () => policy },
		capability: overrides.capability ?? {
			readCapability: async () => ({ snapshot: HARNESS_NOMINAL_SNAPSHOT, receivedMonoMs: clock.nowMonoMs(), epoch: 0 }),
		},
		store: createMemoryOfflineStore(),
		deltaStep: overrides.deltaStep ?? noopStep(),
		windowStep: (overrides.windowStep ?? noopStep()) as never,
		jobs,
		onEvent: (event) => events.push(event),
	});
	return { coordinator, jobs, events, policy };
}

describe('coordinator construction and lifecycle guards', () => {
	it('refuses an unbranded WINDOW step just like an unbranded delta step', () => {
		const unbranded = async () => ({
			checkpoint: { version: 1 as const, cursor: null },
			progress: { done: 0, chargedUnits: 0 },
			outcome: 'partial' as const,
		});
		expect(() => buildCoordinator({ windowStep: unbranded })).toThrow(/windowStep is not a bounded sync step/);
	});

	it('an observation from a PRIOR lifecycle epoch cannot authorize work', async () => {
		// The coordinator bound epoch 1; the reader still reports epoch 0 —
		// the stale observation is discarded, never a manufactured nominal.
		const { coordinator } = buildCoordinator({
			clock: { nowMonoMs: () => 100, nowUtcMs: () => START_UTC },
		});
		coordinator.bindLifecycleEpoch(1);
		await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 1 });
		await coordinator.runDueWork();
		const read = await coordinator.readJobResult('opt-reconnect-acct-1');
		expect(read.kind === 'committed' && read.result.state === 'paused').toBe(true);
		expect(read.kind === 'committed' && read.result.state === 'paused' && read.result.reason).toBe('capabilityUnavailable');
	});

	it('bindLifecycleEpoch ignores disposed, non-integer and older epochs', async () => {
		const { coordinator } = buildCoordinator({});
		expect(coordinator.epoch).toBe(0);
		coordinator.bindLifecycleEpoch(Number.NaN);
		coordinator.bindLifecycleEpoch(-3);
		coordinator.bindLifecycleEpoch(1.5);
		expect(coordinator.epoch).toBe(0);
		coordinator.bindLifecycleEpoch(4);
		expect(coordinator.epoch).toBe(4);
		// A strictly older epoch never rolls the lifecycle back.
		coordinator.bindLifecycleEpoch(2);
		expect(coordinator.epoch).toBe(4);
		coordinator.dispose();
		coordinator.bindLifecycleEpoch(9);
		expect(coordinator.epoch).toBe(4);
	});

	it('ingestTrigger rejects invalid generations without touching the store', async () => {
		const { coordinator, jobs } = buildCoordinator({});
		for (const generation of [Number.NaN, -1, 2.5, Number.POSITIVE_INFINITY]) {
			const outcome = await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation });
			expect(outcome).toEqual({ kind: 'rejected-stale-generation' });
		}
		expect(jobs.snapshotJobs()).toHaveLength(0);
	});

	it('an EQUAL generation re-ingest is refused by the store as a stale trigger', async () => {
		// Only a materially NEWER generation re-opens work; the same generation
		// arriving again is a duplicate, not fresh work.
		const { coordinator, events } = buildCoordinator({});
		expect((await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 3 })).kind).toBe('queued');
		const again = await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 3 });
		expect(again).toEqual({ kind: 'rejected-stale-generation' });
		expect(events.filter((event) => event.kind === 'trigger-rejected' && event.reason === 'stale-generation')).toHaveLength(1);
	});

	it('ingestTrigger on a disposed coordinator refuses without writing', async () => {
		const { coordinator, jobs } = buildCoordinator({});
		coordinator.dispose();
		const outcome = await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 1 });
		expect(outcome).toEqual({ kind: 'rejected-stale-generation' });
		expect(jobs.snapshotJobs()).toHaveLength(0);
	});
});

describe('coordinator dispatch-loop edges', () => {
	it('OBSERVED admission at dispatch time emits and never executes the job', async () => {
		// Observe mode resolves every admission to 'observed': the job stays
		// queued and no step, claim or result ever happens.
		const { coordinator, events } = buildCoordinator({
			policy: { ...HARNESS_EXECUTE_POLICY, rolloutMode: 'observe' },
		});
		await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 1 });
		await coordinator.runDueWork();
		expect(events.filter((event) => event.kind === 'admission-observed')).toHaveLength(1);
		expect(await coordinator.readJobResult('opt-reconnect-acct-1')).toEqual({ kind: 'unknown' });
	});

	it('the OBSERVED gate re-resolves before the FIRST step: a policy narrowed to observe stops the job', async () => {
		// The dispatch resolved eligible under execute; the claim then flips the
		// shared policy to observe. The step gate must stop the job before any
		// step runs.
		let stepCalls = 0;
		const step = markBoundedSyncStep(async () => {
			stepCalls += 1;
			return {
				checkpoint: { version: 1 as const, cursor: 'c:1' },
				progress: { done: 1, chargedUnits: 1 },
				outcome: 'complete' as const,
			};
		});
		const { coordinator, policy, jobs } = buildCoordinator({
			deltaStep: step as unknown as ReturnType<typeof createSyncDeltaStep>,
		});
		const originalClaim = jobs.claimLease.bind(jobs);
		jobs.claimLease = async (jobId, owner, now) => {
			// The live policy object the coordinator re-reads narrows to observe
			// between the dispatch decision and the first step gate.
			policy.rolloutMode = 'observe';
			return originalClaim(jobId, owner, now);
		};
		await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 1 });
		await coordinator.runDueWork();
		expect(stepCalls).toBe(0);
		const read = await coordinator.readJobResult('opt-reconnect-acct-1');
		expect(read.kind === 'committed' && read.result.state === 'paused').toBe(true);
		// The mid-execution OBSERVED stop is a yield at the loop head, recorded
		// as the honest deadline pause (no invented step result).
		expect(read.kind === 'committed' && read.result.state === 'paused' && read.result.reason).toBe('deadlineExceeded');
	});

	it('a lost claim (null fence) yields the dispatch without running or recording', async () => {
		const { coordinator, jobs, events } = buildCoordinator({});
		jobs.claimLease = async () => null;
		await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 1 });
		await coordinator.runDueWork();
		expect(events.filter((event) => event.kind === 'admission-eligible')).toHaveLength(1);
		expect(await coordinator.readJobResult('opt-reconnect-acct-1')).toEqual({ kind: 'unknown' });
		const job = await jobs.readJob('opt-reconnect-acct-1');
		expect(job?.state).toBe('queued');
		expect(job?.leaseOwner).toBeNull();
	});

	it('a dispatch record that vanished between listDue and readJob is dropped without a crash', async () => {
		const jobs = createMemoryJobPersistence();
		const originalListDue = jobs.listDue.bind(jobs);
		const ghost = baseJobRecord({
			jobId: 'opt-reconnect-ghost',
			accountId: 'ghost',
			coalescingKey: 'reconnect:ghost',
			queuedAtUtcMs: START_UTC + 1,
		});
		jobs.listDue = async (now) => [...await originalListDue(now), ghost];
		const { coordinator } = buildCoordinator({ jobs });
		await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 1 });
		await expect(coordinator.runDueWork()).resolves.toBeUndefined();
		// The real job ran normally; the ghost simply never dispatched.
		const read = await coordinator.readJobResult('opt-reconnect-acct-1');
		expect(read.kind === 'committed' && read.result.state).toBe('complete');
		expect(await jobs.readJob('opt-reconnect-ghost')).toBeNull();
	});

	it('a scheduler-expired queue entry records its committed expired result', async () => {
		// A job whose deadline passed while queued is not silently dropped: the
		// batch reports it expired and the coordinator commits the terminal.
		const jobs = createMemoryJobPersistence();
		await jobs.enqueueJob(baseJobRecord({
			deadlineUtc: new Date(START_UTC - 1_000).toISOString(),
		}));
		const { coordinator, events } = buildCoordinator({ jobs });
		await coordinator.runDueWork();
		const read = await coordinator.readJobResult('opt-reconnect-acct-1');
		expect(read.kind).toBe('committed');
		expect(read.kind === 'committed' && read.result.state).toBe('expired');
		expect(
			events.some((event) => event.kind === 'result-recorded' && event.state === 'expired'),
		).toBe(true);
		const job = await jobs.readJob('opt-reconnect-acct-1');
		expect(job?.state).toBe('expired');
	});

	it('a retryable transport failure backs off full-jitter, mirrors the backoff into the scheduler, and reruns after the retry deadline', async () => {
		let mono = 0;
		let stepCalls = 0;
		const step = markBoundedSyncStep(async () => {
			stepCalls += 1;
			if (stepCalls === 1) {
				// A typed transport failure: retryable by its work code.
				throw Object.assign(new Error('socket reset'), { workCode: 'network' });
			}
			return {
				checkpoint: { version: 1 as const, cursor: 'c:done' },
				progress: { done: 1, chargedUnits: 1 },
				outcome: 'complete' as const,
			};
		});
		const { coordinator, jobs } = buildCoordinator({
			deltaStep: step as unknown as ReturnType<typeof createSyncDeltaStep>,
			clock: { nowMonoMs: () => mono, nowUtcMs: () => START_UTC + mono },
			random: () => 0.5,
		});
		await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 1 });
		await coordinator.runDueWork();
		// No terminal result after the retryable failure; the job is in backoff
		// with its attempt envelope bumped and a full-jitter retry deadline.
		expect(await coordinator.readJobResult('opt-reconnect-acct-1')).toEqual({ kind: 'unknown' });
		const backoffJob = await jobs.readJob('opt-reconnect-acct-1');
		expect(backoffJob?.state).toBe('backoff');
		expect(backoffJob?.attempts).toBe(1);
		expect(backoffJob?.retryAtUtcMs ?? 0).toBeGreaterThan(START_UTC);
		// Before the retry deadline the job is not due.
		mono = (backoffJob?.retryAtUtcMs ?? START_UTC) - START_UTC - 1;
		expect((await coordinator.listJobs()).map((job) => job.jobId)).not.toContain('opt-reconnect-acct-1');
		// After it, the SAME dispatch queue (DRR mirrored) serves the job again.
		mono += 10 * 60_000;
		await coordinator.runDueWork();
		const read = await coordinator.readJobResult('opt-reconnect-acct-1');
		expect(read.kind === 'committed' && read.result.state).toBe('complete');
		expect(stepCalls).toBe(2);
	});

	it('an AbortError-shaped Error is an interruption (never a terminal failure) even without an aborted signal', async () => {
		const step = markBoundedSyncStep(async () => {
			throw Object.assign(new Error('The operation was aborted'), { name: 'AbortError' });
		});
		const { coordinator } = buildCoordinator({
			deltaStep: step as unknown as ReturnType<typeof createSyncDeltaStep>,
		});
		await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 1 });
		await coordinator.runDueWork();
		expect(await coordinator.readJobResult('opt-reconnect-acct-1')).toEqual({ kind: 'unknown' });
		// The job rejoined the queue without a recorded result.
		expect((await coordinator.listJobs()).map((job) => job.jobId)).toContain('opt-reconnect-acct-1');
	});

	it('a plain object shaped { name: AbortError } is an interruption', async () => {
		// Legacy DOM shapes are not Error instances: the name check must not
		// depend on instanceof.
		const step = markBoundedSyncStep(async () => {
			throw { name: 'AbortError' };
		});
		const { coordinator } = buildCoordinator({
			deltaStep: step as unknown as ReturnType<typeof createSyncDeltaStep>,
		});
		await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 1 });
		await coordinator.runDueWork();
		expect(await coordinator.readJobResult('opt-reconnect-acct-1')).toEqual({ kind: 'unknown' });
	});

	it('a legacy DOMException ABORT_ERR (code 20) is an interruption', async () => {
		const step = markBoundedSyncStep(async () => {
			throw { code: 20, message: 'The operation was aborted' };
		});
		const { coordinator } = buildCoordinator({
			deltaStep: step as unknown as ReturnType<typeof createSyncDeltaStep>,
		});
		await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 1 });
		await coordinator.runDueWork();
		expect(await coordinator.readJobResult('opt-reconnect-acct-1')).toEqual({ kind: 'unknown' });
	});

	it('a drain landing between the drained check and the claim stops the dispatch at its first loop head', async () => {
		// The dispatch passed runAdmissionCycle's drained check, then the drain
		// landed during the claim await. executeJob starts AFTER the drain: its
		// signal was never aborted, so the loop head's drained latch is what
		// stops the job — nothing is stepped, committed or recorded.
		const jobs = createMemoryJobPersistence();
		const { coordinator } = buildCoordinator({ jobs });
		await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 1 });
		const originalClaim = jobs.claimLease.bind(jobs);
		let drainPromise: Promise<void> | null = null;
		jobs.claimLease = async (jobId, owner, now) => {
			// The rollback drain lands while the claim is in flight; the fence is
			// still won, so the execution starts against a latched coordinator.
			drainPromise = coordinator.drainForRollback();
			return originalClaim(jobId, owner, now);
		};
		await coordinator.runDueWork();
		await drainPromise;
		// The dispatch yielded at the drained loop head: no step result, and
		// the claim was released instead of holding the lease.
		expect(await coordinator.readJobResult('opt-reconnect-acct-1')).toEqual({ kind: 'unknown' });
		const job = await jobs.readJob('opt-reconnect-acct-1');
		expect(job?.leaseOwner).toBeNull();
		expect(job?.checkpoint ?? null).toBeNull();
	});

	it('a blocked WINDOW step pauses with validatorChanged (no second resync)', async () => {
		// The window fallback is attempted ONCE: a job already walking the
		// window that gets blocked again pauses with the honest reason instead
		// of looping.
		const blocked = markBoundedSyncStep(async () => ({
			checkpoint: { version: 1 as const, cursor: null },
			progress: { done: 0, chargedUnits: 0 },
			outcome: 'blocked' as const,
		}));
		const { coordinator, jobs } = buildCoordinator({
			deltaStep: blocked as unknown as ReturnType<typeof createSyncDeltaStep>,
			windowStep: blocked,
		});
		// The job's persisted step kind IS window: no delta attempt ever ran.
		await jobs.enqueueJob(baseJobRecord({ stepKind: 'window' }));
		await coordinator.runDueWork();
		const read = await coordinator.readJobResult('opt-reconnect-acct-1');
		expect(read.kind === 'committed' && read.result.state).toBe('paused');
		expect(read.kind === 'committed' && read.result.state === 'paused' && read.result.reason).toBe('validatorChanged');
		const job = await jobs.readJob('opt-reconnect-acct-1');
		expect(job?.leaseOwner).toBeNull();
	});

	it('a store failure while the dispatch settles does not escape the run', async () => {
		// The post-execution settle path reads the job back to mirror backoff
		// state; a rejecting store is contained (the read is best-effort).
		let stepCalls = 0;
		const step = markBoundedSyncStep(async () => {
			stepCalls += 1;
			// A non-retryable contract refusal: terminal failed, no backoff.
			throw new Error('refused: contract violation');
		});
		const jobs = createMemoryJobPersistence();
		const originalReadJob = jobs.readJob.bind(jobs);
		let reads = 0;
		jobs.readJob = async (jobId: string) => {
			reads += 1;
			if (reads >= 2) throw new Error('store read exploded');
			return originalReadJob(jobId);
		};
		const { coordinator } = buildCoordinator({
			jobs,
			deltaStep: step as unknown as ReturnType<typeof createSyncDeltaStep>,
		});
		await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 1 });
		await expect(coordinator.runDueWork()).resolves.toBeUndefined();
		const read = await coordinator.readJobResult('opt-reconnect-acct-1');
		expect(read.kind === 'committed' && read.result.state).toBe('failed');
		expect(stepCalls).toBe(1);
	});
});

describe('coordinator account cancellation and disposal', () => {
	it('cancelAccountJobs terminalizes the account\'s open jobs and reads as cancelled', async () => {
		const { coordinator } = buildCoordinator({});
		await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 1 });
		expect(await coordinator.cancelAccountJobs('acct-1')).toEqual(['opt-reconnect-acct-1']);
		const read = await coordinator.readJobResult('opt-reconnect-acct-1');
		expect(read.kind === 'committed' && read.result.state).toBe('cancelled');
	});

	it('dispose aborts running work, tears down Critical, and is idempotent', async () => {
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
		const { coordinator } = buildCoordinator({ deltaStep: createSyncDeltaStep(client) });
		await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 1 });
		const cycle = coordinator.runDueWork();
		await new Promise<void>((resolve) => setTimeout(resolve, 0));
		expect(coordinator.disposed).toBe(false);
		coordinator.dispose();
		expect(coordinator.disposed).toBe(true);
		// A second dispose is a no-op.
		coordinator.dispose();
		releasePage!();
		await cycle;
		// The aborted dispatch yielded without recording a terminal result.
		expect(await coordinator.readJobResult('opt-reconnect-acct-1')).toEqual({ kind: 'unknown' });
	});

	it('drainForRollback is latched: a second drain returns immediately', async () => {
		const { coordinator, jobs } = buildCoordinator({});
		await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 1 });
		await coordinator.drainForRollback();
		// The second drain resolves without re-entering the drain path.
		await expect(coordinator.drainForRollback()).resolves.toBeUndefined();
		// The latch also closes runDueWork: the queued job is untouched.
		await coordinator.runDueWork();
		const job = await jobs.readJob('opt-reconnect-acct-1');
		expect(job?.state).toBe('queued');
		expect(await coordinator.readJobResult('opt-reconnect-acct-1')).toEqual({ kind: 'unknown' });
	});
});

describe('job identity', () => {
	it('action triggers carry the interactive class by default', async () => {
		const { coordinator, jobs } = buildCoordinator({});
		await coordinator.ingestTrigger({ kind: 'action', accountId: 'acct-1', generation: 1 });
		const job = await jobs.readJob(jobIdForTrigger({ kind: 'action', accountId: 'acct-1', generation: 1 }));
		expect(job?.workClass).toBe('interactive');
	});
});

// createOffPolicySource stays exported and OFF — re-pinned here so the branch
// helper modules above cannot silently drop it from the surface.
describe('off policy source', () => {
	it('reads a fresh OFF policy on every call', async () => {
		const source = createOffPolicySource();
		const first = await source.readPolicy();
		const second = await source.readPolicy();
		expect(first).toEqual(second);
		expect(first.flagEnabled).toBe(false);
		expect(first.rolloutMode).toBe('off');
	});
});
