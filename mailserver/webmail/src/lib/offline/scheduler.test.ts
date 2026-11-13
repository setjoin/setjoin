import { describe, expect, it } from 'vitest';

import {
	applyBackoffSignal,
	chargedCost,
	completeJob,
	createBackoffState,
	createQueueItem,
	createSchedulerState,
	isQueueExpired,
	isRetryReady,
	makeQueueItem,
	retryAfterFailure,
	retryCeilingMs,
	retryDelayMs,
	scheduleBatch,
	scheduleNext,
	setCriticalActivity,
	yieldForCritical,
	enqueueJob,
	type SchedulerSnapshot,
	type SchedulerWork,
} from './scheduler';
import {
	MAX_QUEUE_AGE_DAYS,
	MAX_QUEUE_AGE_MS,
	OPTIONAL_WORK_CLASSES,
	RETRY_INITIAL_DELAY_MS,
	RETRY_MAX_DELAY_MS,
	PROTECTED_CRITICAL_SLOT_COUNT,
	GLOBAL_OPTIONAL_CONCURRENCY,
	type OptionalWorkClass,
	type OptionalWorkJob,
} from './work-contract';

const NOW_UTC = 1_900_000_000_000;
const NOW_MONO = 50_000;
const DEADLINE_UTC = new Date(NOW_UTC + MAX_QUEUE_AGE_MS * 2).toISOString();

function makeJob(
	jobId: string,
	accountId: string,
	workClass: OptionalWorkClass = 'interactive',
	state: OptionalWorkJob['state'] = 'queued',
	triggerGeneration = 1,
): OptionalWorkJob {
	return {
		jobId,
		accountId,
		workClass,
		state,
		triggerGeneration,
		coalescingKey: `${accountId}:${jobId}`,
		attempts: 0,
		deadlineUtc: DEADLINE_UTC,
		checkpoint: null,
	};
}

function add(
	state: SchedulerSnapshot,
	jobId: string,
	accountId: string,
	workClass: OptionalWorkClass = 'interactive',
	work: SchedulerWork = { kind: 'metadata' },
): SchedulerSnapshot {
	return enqueueJob(state, createQueueItem(makeJob(jobId, accountId, workClass), NOW_UTC, work));
}

function release(state: SchedulerSnapshot, jobId: string): SchedulerSnapshot {
	return completeJob(state, jobId).state;
}

function runOne(state: SchedulerSnapshot): { state: SchedulerSnapshot; accountId: string; workClass: OptionalWorkClass; jobId: string } {
	const decision = scheduleNext(state, { nowUtcMs: NOW_UTC, nowMonoMs: NOW_MONO });
	expect(decision.reason).toBe('scheduled');
	expect(decision.selected).not.toBeNull();
	const selected = decision.selected!;
	return {
		state: release(decision.state, selected.job.jobId),
		accountId: selected.job.accountId,
		workClass: selected.job.workClass,
		jobId: selected.job.jobId,
	};
}

describe('pure scheduler cost accounting', () => {
	it('charges one unit per metadata record and rounds transfers by started KiB', () => {
		expect(chargedCost({ kind: 'metadata' })).toBe(1);
		expect(chargedCost({ kind: 'metadata', records: 3 })).toBe(3);
		expect(chargedCost({ kind: 'transfer', bytes: 0 })).toBe(1);
		expect(chargedCost({ kind: 'transfer', bytes: 1 })).toBe(1);
		expect(chargedCost({ kind: 'transfer', bytes: 1024 })).toBe(1);
		expect(chargedCost({ kind: 'transfer', bytes: 1025 })).toBe(2);
		expect(chargedCost({ kind: 'transfer', bytes: 2 * 1024 + 1 })).toBe(3);
	});
});

describe('deterministic deficit round robin', () => {
	it('gives each class its 8/4/1 cost-unit quantum without starvation', () => {
		let state = createSchedulerState();
		for (let i = 0; i < 30; i += 1) {
			state = add(state, `i-${i}`, `interactive-${i}`, 'interactive');
			state = add(state, `b-${i}`, `background-${i}`, 'background');
			state = add(state, `o-${i}`, `opportunistic-${i}`, 'opportunistic');
		}

		const firstCycle: OptionalWorkClass[] = [];
		for (let i = 0; i < 13; i += 1) {
			const result = runOne(state);
			state = result.state;
			firstCycle.push(result.workClass);
		}
		expect(firstCycle).toEqual([
			...Array<OptionalWorkClass>(8).fill('interactive'),
			...Array<OptionalWorkClass>(4).fill('background'),
			'opportunistic',
		]);

		const counts = new Map(OPTIONAL_WORK_CLASSES.map((workClass) => [workClass, 0]));
		for (const workClass of firstCycle) counts.set(workClass, counts.get(workClass)! + 1);
		expect(counts.get('interactive')).toBe(8);
		expect(counts.get('background')).toBe(4);
		expect(counts.get('opportunistic')).toBe(1);
	});

	it('round-robins accounts within a class, not just queue insertion order', () => {
		let state = createSchedulerState();
		for (const accountId of ['a', 'b']) {
			state = add(state, `${accountId}-1`, accountId);
			state = add(state, `${accountId}-2`, accountId);
			state = add(state, `${accountId}-3`, accountId);
		}

		const accounts: string[] = [];
		for (let i = 0; i < 6; i += 1) {
			const result = runOne(state);
			state = result.state;
			accounts.push(result.accountId);
		}
		expect(accounts).toEqual(['a', 'b', 'a', 'b', 'a', 'b']);
	});

	it('keeps global and per-account concurrency bounds as invariants', () => {
		let state = createSchedulerState();
		state = add(state, 'a-1', 'a');
		state = add(state, 'a-2', 'a');
		state = add(state, 'b-1', 'b');
		state = add(state, 'c-1', 'c');

		const first = scheduleNext(state, { nowUtcMs: NOW_UTC, nowMonoMs: NOW_MONO });
		state = first.state;
		const second = scheduleNext(state, { nowUtcMs: NOW_UTC, nowMonoMs: NOW_MONO });
		state = second.state;
		expect(state.running).toHaveLength(GLOBAL_OPTIONAL_CONCURRENCY);
		expect(new Set(state.running.map((item) => item.job.accountId)).size).toBe(GLOBAL_OPTIONAL_CONCURRENCY);

		const globallySaturated = scheduleNext(state, { nowUtcMs: NOW_UTC, nowMonoMs: NOW_MONO });
		expect(globallySaturated.selected).toBeNull();
		expect(globallySaturated.reason).toBe('globalSaturation');

		state = release(state, first.selected!.job.jobId);
		state = release(state, second.selected!.job.jobId);
		let accountOnly = createSchedulerState();
		accountOnly = add(accountOnly, 'a-1', 'a');
		accountOnly = add(accountOnly, 'a-2', 'a');
		const running = scheduleNext(accountOnly, { nowUtcMs: NOW_UTC, nowMonoMs: NOW_MONO });
		const accountBlocked = scheduleNext(running.state, { nowUtcMs: NOW_UTC, nowMonoMs: NOW_MONO });
		expect(accountBlocked.selected).toBeNull();
		expect(accountBlocked.reason).toBe('accountSaturation');
	});

	it('does not accrue deficit while a class is account-saturated', () => {
		let state = add(createSchedulerState(), 'i-running', 'blocked', 'interactive');
		const running = scheduleNext(state, { nowUtcMs: NOW_UTC, nowMonoMs: NOW_MONO });
		state = add(running.state, 'i-waiting', 'blocked', 'interactive');

		for (let i = 0; i < 20; i += 1) {
			state = add(state, `b-${i}`, `free-${i}`, 'background');
			const result = scheduleNext(state, { nowUtcMs: NOW_UTC, nowMonoMs: NOW_MONO });
			expect(result.selected?.job.workClass).toBe('background');
			state = release(result.state, result.selected!.job.jobId);
		}

		expect(state.classDeficits.interactive).toBe(0);
	});

	it('replays the same trace exactly when inputs, time, and queue order match', () => {
		function replay(): { trace: string[]; state: SchedulerSnapshot } {
			let state = createSchedulerState();
			for (const [id, account, workClass] of [
				['1', 'z', 'interactive'],
				['2', 'a', 'background'],
				['3', 'z', 'opportunistic'],
				['4', 'a', 'interactive'],
			] as const) state = add(state, id, account, workClass);
			const trace: string[] = [];
			for (;;) {
				const result = scheduleNext(state, { nowUtcMs: NOW_UTC, nowMonoMs: NOW_MONO });
				state = result.state;
				if (!result.selected) break;
				trace.push(result.selected.job.jobId);
				state = release(state, result.selected.job.jobId);
			}
			return { trace, state };
		}

		expect(replay()).toEqual(replay());
	});
});

describe('protected Critical capacity and expiry', () => {
	it('never admits optional work while Critical is active or during quiet recovery', () => {
		let state = createSchedulerState();
		state = add(state, 'a-1', 'a');
		state = setCriticalActivity(state, 1, NOW_MONO);
		const critical = scheduleNext(state, { nowUtcMs: NOW_UTC, nowMonoMs: NOW_MONO });
		expect(critical.selected).toBeNull();
		expect(critical.reason).toBe('criticalActivity');
		expect(state.protectedCriticalSlots).toBe(PROTECTED_CRITICAL_SLOT_COUNT);

		state = setCriticalActivity(state, 0, NOW_MONO);
		const quiet = scheduleNext(state, { nowUtcMs: NOW_UTC, nowMonoMs: NOW_MONO });
		expect(quiet.selected).toBeNull();
		expect(quiet.reason).toBe('criticalQuiet');

		const resumed = scheduleNext(state, {
			nowUtcMs: NOW_UTC,
			nowMonoMs: NOW_MONO + 5_000,
		});
		expect(resumed.selected).not.toBeNull();
	});

	it('yields running optional work without stealing the protected slot', () => {
		let state = createSchedulerState();
		state = add(state, 'a-1', 'a');
		state = add(state, 'b-1', 'b');
		const batch = scheduleBatch(state, { nowUtcMs: NOW_UTC, nowMonoMs: NOW_MONO });
		const yielded = yieldForCritical(batch.state);
		expect(yielded.state.running).toHaveLength(0);
		expect(yielded.yielded).toHaveLength(2);
		expect(yielded.state.queued.map((item) => item.job.state)).toEqual(['queued', 'queued']);
		expect(yielded.state.protectedCriticalSlots).toBe(1);
	});

	it('expires queued work at the seven-day age ceiling and exposes terminal state', () => {
		const item = makeQueueItem(makeJob('old', 'a'), 0, { kind: 'metadata' });
		const state = enqueueJob(createSchedulerState(), item);
		expect(isQueueExpired(state.queued[0], MAX_QUEUE_AGE_MS - 1)).toBe(false);
		const decision = scheduleNext(state, { nowUtcMs: MAX_QUEUE_AGE_MS, nowMonoMs: NOW_MONO });
		expect(decision.selected).toBeNull();
		expect(decision.expired).toHaveLength(1);
		expect(decision.expired[0].job.state).toBe('expired');
		expect(decision.state.queued).toHaveLength(0);
		expect(MAX_QUEUE_AGE_DAYS).toBe(7);
	});
});

describe('bounded full-jitter retry and reset rules', () => {
	it('uses an injected random source and never exceeds the five-minute cap', () => {
		expect(RETRY_INITIAL_DELAY_MS).toBe(1_000);
		expect(retryCeilingMs(0)).toBe(RETRY_INITIAL_DELAY_MS);
		expect(retryDelayMs(0, () => 0)).toBe(0);
		expect(retryDelayMs(0, () => 0.5)).toBe(500);
		expect(retryDelayMs(0, () => 1)).toBe(RETRY_INITIAL_DELAY_MS);
		expect(retryCeilingMs(20)).toBe(RETRY_MAX_DELAY_MS);
		expect(retryDelayMs(20, () => 1)).toBe(RETRY_MAX_DELAY_MS);
		expect(retryDelayMs(20, () => 0.25)).toBe(Math.floor(RETRY_MAX_DELAY_MS / 4));
	});

	it('resets only for committed progress or a materially newer authenticated trigger', () => {
		const initial = { attempts: 3, retryAtUtcMs: 12_345, lastAuthenticatedTriggerGeneration: 7 };
		const flap = applyBackoffSignal(initial, { kind: 'networkFlap' });
		expect(flap).toEqual(initial);
		expect(applyBackoffSignal(initial, { kind: 'committedProgress', chargedUnits: 0 })).toEqual(initial);
		expect(applyBackoffSignal(initial, { kind: 'authenticatedTrigger', triggerGeneration: 7 })).toEqual(initial);
		expect(applyBackoffSignal(initial, { kind: 'authenticatedTrigger', triggerGeneration: 8 })).toEqual({
			attempts: 0,
			retryAtUtcMs: null,
			lastAuthenticatedTriggerGeneration: 8,
		});
		expect(applyBackoffSignal(initial, { kind: 'committedProgress', chargedUnits: 1 })).toEqual({
			attempts: 0,
			retryAtUtcMs: null,
			lastAuthenticatedTriggerGeneration: 7,
		});
	});

	it('keeps retry timing deterministic and advances the attempt cap', () => {
		const first = createBackoffState(4);
		const next = retryAfterFailure(first, 10_000, () => 0.5);
		expect(next).toEqual({
			attempts: 1,
			retryAtUtcMs: 10_000 + Math.floor(RETRY_INITIAL_DELAY_MS / 2),
			lastAuthenticatedTriggerGeneration: 4,
		});
		expect(isRetryReady(next, next.retryAtUtcMs! - 1)).toBe(false);
		expect(isRetryReady(next, next.retryAtUtcMs!)).toBe(true);
	});
});
