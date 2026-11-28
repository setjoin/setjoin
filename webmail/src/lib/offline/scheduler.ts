import {
	CRITICAL_QUIET_RESUME_MS,
	GLOBAL_OPTIONAL_CONCURRENCY,
	MAX_QUEUE_AGE_MS,
	OPTIONAL_WORK_CLASSES,
	PER_ACCOUNT_OPTIONAL_CONCURRENCY,
	PROTECTED_CRITICAL_SLOT_COUNT,
	RETRY_INITIAL_DELAY_MS,
	RETRY_MAX_DELAY_MS,
	WORK_CLASS_QUANTA,
	type OptionalJobState,
	type OptionalWorkClass,
	type OptionalWorkJob,
} from './work-contract';

/** One KiB is the scheduler's smallest transfer accounting unit. */
export const TRANSFER_CHARGE_UNIT_BYTES = 1024 as const;

export type SchedulerWork =
	| { kind: 'metadata'; records?: number }
	| { kind: 'transfer'; bytes: number };

/**
 * The scheduler charges the work that actually starts, rather than a guessed
 * cost supplied by a caller. Metadata is charged per record; transfers are
 * charged per started KiB and rounded up. A zero-byte transfer is still a
 * started transfer and therefore costs one unit.
 */
export function chargedCost(work: SchedulerWork): number {
	if (work.kind === 'metadata') {
		const records = work.records ?? 1;
		return Math.max(0, Math.ceil(Number.isFinite(records) ? records : 0));
	}
	const bytes = Math.max(0, Number.isFinite(work.bytes) ? work.bytes : 0);
	return Math.max(1, Math.ceil(bytes / TRANSFER_CHARGE_UNIT_BYTES));
}

export const costForWork = chargedCost;
export const chargeCost = chargedCost;

export interface SchedulerQueueInput {
	job: OptionalWorkJob;
	queuedAtUtcMs: number;
	work: SchedulerWork;
	retryAtUtcMs?: number | null;
}

/** A queued job plus the immutable data needed for deterministic accounting. */
export interface SchedulerQueueItem extends SchedulerQueueInput {
	sequence: number;
}

export interface SchedulerDispatch extends SchedulerQueueItem {
	startedAtMonoMs: number;
	chargedUnits: number;
	job: OptionalWorkJob & { state: 'running' };
}

export interface SchedulerSnapshot {
	queued: readonly SchedulerQueueItem[];
	running: readonly SchedulerDispatch[];
	classDeficits: Readonly<Record<OptionalWorkClass, number>>;
	classCursor: number;
	classQuantumLoaded: boolean;
	accountCursors: Readonly<Record<OptionalWorkClass, string | null>>;
	criticalActivity: number;
	criticalQuietSinceMonoMs: number | null;
	protectedCriticalSlots: typeof PROTECTED_CRITICAL_SLOT_COUNT;
	nextSequence: number;
}

export interface SchedulerStateOptions {
	criticalActivity?: number;
	criticalQuietSinceMonoMs?: number | null;
}

export interface SchedulerTime {
	nowUtcMs: number;
	nowMonoMs: number;
}

export type ScheduleBlockReason =
	| 'empty'
	| 'globalSaturation'
	| 'accountSaturation'
	| 'criticalActivity'
	| 'criticalQuiet'
	| 'backoff'
	| 'deficit';

export interface ScheduleDecision {
	state: SchedulerSnapshot;
	selected: SchedulerDispatch | null;
	/** Aliases make the model convenient for coordinators without changing state. */
	dispatch: SchedulerDispatch | null;
	job: SchedulerDispatch | null;
	expired: readonly SchedulerQueueItem[];
	reason: 'scheduled' | ScheduleBlockReason;
}

export interface ExpiryResult {
	state: SchedulerSnapshot;
	expired: readonly SchedulerQueueItem[];
}

export interface JobRelease {
	state: SchedulerSnapshot;
	job: SchedulerQueueItem | null;
}

const CLASS_COUNT = OPTIONAL_WORK_CLASSES.length;

function emptyDeficits(): Record<OptionalWorkClass, number> {
	return { interactive: 0, background: 0, opportunistic: 0 };
}

function emptyAccountCursors(): Record<OptionalWorkClass, string | null> {
	return { interactive: null, background: null, opportunistic: null };
}

function copyDeficits(state: SchedulerSnapshot): Record<OptionalWorkClass, number> {
	return {
		interactive: state.classDeficits.interactive,
		background: state.classDeficits.background,
		opportunistic: state.classDeficits.opportunistic,
	};
}

function copyAccountCursors(state: SchedulerSnapshot): Record<OptionalWorkClass, string | null> {
	return {
		interactive: state.accountCursors.interactive,
		background: state.accountCursors.background,
		opportunistic: state.accountCursors.opportunistic,
	};
}

function normalizeNonNegativeInteger(value: number, fallback = 0): number {
	if (!Number.isFinite(value)) return fallback;
	return Math.max(0, Math.floor(value));
}

/** Create an item before it is assigned its deterministic queue sequence. */
export function createQueueItem(
	job: OptionalWorkJob,
	queuedAtUtcMs: number,
	work: SchedulerWork,
	retryAtUtcMs: number | null = null,
): SchedulerQueueInput {
	return {
		job: { ...job },
		queuedAtUtcMs,
		work,
		retryAtUtcMs,
	};
}

export const makeQueueItem = createQueueItem;

export function createSchedulerState(options: SchedulerStateOptions = {}): SchedulerSnapshot {
	return {
		queued: [],
		running: [],
		classDeficits: emptyDeficits(),
		classCursor: 0,
		classQuantumLoaded: false,
		accountCursors: emptyAccountCursors(),
		criticalActivity: normalizeNonNegativeInteger(options.criticalActivity ?? 0),
		criticalQuietSinceMonoMs: options.criticalQuietSinceMonoMs ?? null,
		protectedCriticalSlots: PROTECTED_CRITICAL_SLOT_COUNT,
		nextSequence: 0,
	};
}

export const createScheduler = createSchedulerState;

function itemCost(item: SchedulerQueueItem): number {
	// A scheduled item represents one started unit. A malformed zero-cost
	// metadata batch cannot be used to bypass DRR progress or concurrency.
	return Math.max(1, chargedCost(item.work));
}

function deadlineMs(item: SchedulerQueueItem): number | null {
	const parsed = Date.parse(item.job.deadlineUtc);
	return Number.isFinite(parsed) ? parsed : null;
}

export function queueAgeMs(item: SchedulerQueueItem, nowUtcMs: number): number {
	return Math.max(0, nowUtcMs - item.queuedAtUtcMs);
}

export function isQueueExpired(item: SchedulerQueueItem, nowUtcMs: number): boolean {
	if (queueAgeMs(item, nowUtcMs) >= MAX_QUEUE_AGE_MS) return true;
	const deadline = deadlineMs(item);
	return deadline !== null && nowUtcMs >= deadline;
}

export const isExpired = isQueueExpired;

function expiredItem(item: SchedulerQueueItem): SchedulerQueueItem {
	return {
		...item,
		job: { ...item.job, state: 'expired' },
		retryAtUtcMs: null,
	};
}

export function expireQueuedJobs(state: SchedulerSnapshot, nowUtcMs: number): ExpiryResult {
	const expired: SchedulerQueueItem[] = [];
	const queued: SchedulerQueueItem[] = [];
	for (const item of state.queued) {
		if (isQueueExpired(item, nowUtcMs)) expired.push(expiredItem(item));
		else queued.push(item);
	}
	return {
		state: expired.length === 0 ? state : { ...state, queued },
		expired,
	};
}

function hasJob(state: SchedulerSnapshot, jobId: string): boolean {
	return state.queued.some((item) => item.job.jobId === jobId)
		|| state.running.some((item) => item.job.jobId === jobId);
}

/**
 * Enqueue is an immutable operation. A duplicate job identity is already
 * represented by the queue/running lease and is therefore a no-op.
 */
export function enqueueJob(state: SchedulerSnapshot, input: SchedulerQueueInput | SchedulerQueueItem): SchedulerSnapshot {
	if (hasJob(state, input.job.jobId)) return state;
	if (input.job.state === 'complete' || input.job.state === 'failed' || input.job.state === 'expired' || input.job.state === 'cancelled') {
		return state;
	}
	const sequence = 'sequence' in input && Number.isSafeInteger(input.sequence) && input.sequence >= state.nextSequence
		? input.sequence
		: state.nextSequence;
	const item: SchedulerQueueItem = {
		job: {
			...input.job,
			state: input.job.state === 'backoff' ? 'backoff' : 'queued',
		},
		queuedAtUtcMs: input.queuedAtUtcMs,
		work: input.work,
		retryAtUtcMs: input.retryAtUtcMs ?? null,
		sequence,
	};
	return {
		...state,
		queued: [...state.queued, item],
		nextSequence: sequence + 1,
	};
}

export const enqueue = enqueueJob;

function isReady(item: SchedulerQueueItem, nowUtcMs: number): boolean {
	if (item.job.state === 'queued') return true;
	if (item.job.state !== 'backoff') return false;
	return item.retryAtUtcMs === null || item.retryAtUtcMs === undefined || item.retryAtUtcMs <= nowUtcMs;
}

function activeCountForAccount(state: SchedulerSnapshot, accountId: string): number {
	return state.running.reduce((count, item) => count + (item.job.accountId === accountId ? 1 : 0), 0);
}

function accountsForClass(
	state: SchedulerSnapshot,
	workClass: OptionalWorkClass,
	nowUtcMs: number,
): string[] {
	const accounts = new Set<string>();
	for (const item of state.queued) {
		if (item.job.workClass === workClass && isReady(item, nowUtcMs)) accounts.add(item.job.accountId);
	}
	return [...accounts].sort();
}

function accountStartIndex(accounts: readonly string[], cursor: string | null): number {
	if (accounts.length === 0 || cursor === null) return 0;
	const index = accounts.indexOf(cursor);
	return index < 0 ? 0 : index;
}

function nextAccount(accounts: readonly string[], selected: string): string | null {
	if (accounts.length === 0) return null;
	const index = accounts.indexOf(selected);
	return index < 0 ? accounts[0] : accounts[(index + 1) % accounts.length];
}

function candidateForClass(
	state: SchedulerSnapshot,
	workClass: OptionalWorkClass,
	nowUtcMs: number,
	deficit: number,
): SchedulerQueueItem | null {
	const accounts = accountsForClass(state, workClass, nowUtcMs);
	const start = accountStartIndex(accounts, state.accountCursors[workClass]);
	for (let offset = 0; offset < accounts.length; offset += 1) {
		const accountId = accounts[(start + offset) % accounts.length];
		if (activeCountForAccount(state, accountId) >= PER_ACCOUNT_OPTIONAL_CONCURRENCY) continue;
		const candidates = state.queued
			.filter((item) => item.job.workClass === workClass && item.job.accountId === accountId && isReady(item, nowUtcMs))
			.sort((a, b) => a.sequence - b.sequence || a.job.jobId.localeCompare(b.job.jobId));
		const head = candidates[0];
		if (head && itemCost(head) <= deficit) return head;
	}
	return null;
}

function hasFittingCandidate(
	state: SchedulerSnapshot,
	workClass: OptionalWorkClass,
	nowUtcMs: number,
	deficit: number,
): boolean {
	return candidateForClass(state, workClass, nowUtcMs, deficit) !== null;
}

function withClassCursor(state: SchedulerSnapshot, classCursor: number): SchedulerSnapshot {
	return {
		...state,
		classCursor: (classCursor + CLASS_COUNT) % CLASS_COUNT,
		classQuantumLoaded: false,
	};
}

function queueHasReady(state: SchedulerSnapshot, nowUtcMs: number): boolean {
	return state.queued.some((item) => isReady(item, nowUtcMs));
}

function queueHasBackoff(state: SchedulerSnapshot, nowUtcMs: number): boolean {
	return state.queued.some((item) => item.job.state === 'backoff' && !isReady(item, nowUtcMs));
}

function queueHasPending(state: SchedulerSnapshot): boolean {
	return state.queued.some((item) => item.job.state === 'queued' || item.job.state === 'backoff');
}

function allReadyAccountsSaturated(state: SchedulerSnapshot, nowUtcMs: number): boolean {
	const ready = state.queued.filter((item) => isReady(item, nowUtcMs));
	return ready.length > 0 && ready.every((item) => activeCountForAccount(state, item.job.accountId) >= PER_ACCOUNT_OPTIONAL_CONCURRENCY);
}

function blockedDecision(
	state: SchedulerSnapshot,
	expired: readonly SchedulerQueueItem[],
	reason: ScheduleBlockReason,
): ScheduleDecision {
	return {
		state,
		selected: null,
		dispatch: null,
		job: null,
		expired,
		reason,
	};
}

function criticalAdmissionReason(state: SchedulerSnapshot, nowMonoMs: number): ScheduleBlockReason | null {
	if (state.criticalActivity > 0) return 'criticalActivity';
	if (
		state.criticalQuietSinceMonoMs !== null
		&& nowMonoMs - state.criticalQuietSinceMonoMs < CRITICAL_QUIET_RESUME_MS
	) return 'criticalQuiet';
	return null;
}

/**
 * Admit one optional unit using weighted DRR. A class receives its quantum
 * when the class cursor visits it, then keeps the cursor while another fitting
 * account can run. Once the current deficit cannot pay the next unit, the
 * cursor advances. Account cursors are independently round-robin and sorted
 * account ids provide replay-stable ordering.
 */
export function scheduleNext(state: SchedulerSnapshot, time: SchedulerTime): ScheduleDecision {
	const expiry = expireQueuedJobs(state, time.nowUtcMs);
	const working = expiry.state;
	const criticalReason = criticalAdmissionReason(working, time.nowMonoMs);
	if (criticalReason) return blockedDecision(working, expiry.expired, criticalReason);
	if (working.running.length >= GLOBAL_OPTIONAL_CONCURRENCY) {
		return blockedDecision(working, expiry.expired, 'globalSaturation');
	}
	if (!queueHasPending(working)) return blockedDecision(working, expiry.expired, 'empty');
	if (!queueHasReady(working, time.nowUtcMs)) return blockedDecision(working, expiry.expired, 'backoff');

	const deficits = copyDeficits(working);
	const accountCursors = copyAccountCursors(working);
	let classCursor = working.classCursor;
	let classQuantumLoaded = working.classQuantumLoaded;

	for (let visit = 0; visit < CLASS_COUNT; visit += 1) {
		const workClass = OPTIONAL_WORK_CLASSES[classCursor];
		const classHasQueued = working.queued.some((item) => item.job.workClass === workClass && (item.job.state === 'queued' || item.job.state === 'backoff'));
		if (!classHasQueued) {
			deficits[workClass] = 0;
			classCursor = (classCursor + 1) % CLASS_COUNT;
			classQuantumLoaded = false;
			continue;
		}

		// A class blocked only by retry time or per-account saturation earns no
		// service credit. Retaining/adding deficit while it cannot dispatch turns
		// a long blockage into an unbounded burst that defeats the 8/4/1 weights.
		if (candidateForClass(working, workClass, time.nowUtcMs, Number.POSITIVE_INFINITY) === null) {
			deficits[workClass] = 0;
			classCursor = (classCursor + 1) % CLASS_COUNT;
			classQuantumLoaded = false;
			continue;
		}

		if (!classQuantumLoaded) {
			deficits[workClass] += WORK_CLASS_QUANTA[workClass];
			classQuantumLoaded = true;
		}
		const candidate = candidateForClass(working, workClass, time.nowUtcMs, deficits[workClass]);
		if (!candidate) {
			classCursor = (classCursor + 1) % CLASS_COUNT;
			classQuantumLoaded = false;
			continue;
		}

		const chargedUnits = itemCost(candidate);
		deficits[workClass] -= chargedUnits;
		const dispatch: SchedulerDispatch = {
			...candidate,
			job: { ...candidate.job, state: 'running' },
			startedAtMonoMs: time.nowMonoMs,
			chargedUnits,
		};
		const queued = working.queued.filter((item) => item.job.jobId !== candidate.job.jobId);
		const accounts = accountsForClass(working, workClass, time.nowUtcMs);
		accountCursors[workClass] = nextAccount(accounts, candidate.job.accountId);
		const nextState: SchedulerSnapshot = {
			...working,
			queued,
			running: [...working.running, dispatch],
			classDeficits: deficits,
			classCursor,
			classQuantumLoaded,
			accountCursors,
		};
		const keepClass = hasFittingCandidate(nextState, workClass, time.nowUtcMs, deficits[workClass]);
		const finalState = keepClass
			? nextState
			: withClassCursor({ ...nextState, classQuantumLoaded: false }, classCursor + 1);
		return {
			state: finalState,
			selected: dispatch,
			dispatch,
			job: dispatch,
			expired: expiry.expired,
			reason: 'scheduled',
		};
	}

	if (allReadyAccountsSaturated(working, time.nowUtcMs)) {
		return blockedDecision({ ...working, classDeficits: deficits, accountCursors, classCursor, classQuantumLoaded }, expiry.expired, 'accountSaturation');
	}
	if (queueHasBackoff(working, time.nowUtcMs)) {
		return blockedDecision({ ...working, classDeficits: deficits, accountCursors, classCursor, classQuantumLoaded }, expiry.expired, 'backoff');
	}
	return blockedDecision({ ...working, classDeficits: deficits, accountCursors, classCursor, classQuantumLoaded }, expiry.expired, 'deficit');
}

export const nextSchedule = scheduleNext;
export const schedule = scheduleNext;

export interface ScheduleBatch {
	state: SchedulerSnapshot;
	dispatches: readonly SchedulerDispatch[];
	expired: readonly SchedulerQueueItem[];
	reason: 'scheduled' | ScheduleBlockReason;
}

export function scheduleBatch(state: SchedulerSnapshot, time: SchedulerTime, maxDispatches = GLOBAL_OPTIONAL_CONCURRENCY): ScheduleBatch {
	let working = state;
	const dispatches: SchedulerDispatch[] = [];
	const expired: SchedulerQueueItem[] = [];
	let reason: 'scheduled' | ScheduleBlockReason = 'empty';
	for (let i = 0; i < Math.max(0, maxDispatches); i += 1) {
		const decision = scheduleNext(working, time);
		working = decision.state;
		expired.push(...decision.expired);
		if (!decision.selected) {
			reason = dispatches.length > 0 ? 'scheduled' : decision.reason;
			break;
		}
		dispatches.push(decision.selected);
		reason = 'scheduled';
	}
	return { state: working, dispatches, expired, reason };
}

/**
 * Charge a RUNNING dispatch's actual service back to its class deficit (E4-I
 * Astra correction: the admission charge alone — one metadata record — let one
 * dispatch run step after step while DRR believed only one unit was served;
 * committed steps now return to DRR for service accounting, so the weighted
 * quanta bound the work actually performed, not just the dispatch count).
 * Deficits may go negative: a large committed step borrows from the class's
 * next quantum instead of silently exceeding it.
 */
export function chargeClassService(
	state: SchedulerSnapshot,
	workClass: OptionalWorkClass,
	units: number,
): SchedulerSnapshot {
	const normalized = Number.isSafeInteger(units) && units > 0 ? units : 0;
	if (normalized === 0) return state;
	const deficits = copyDeficits(state);
	deficits[workClass] -= normalized;
	return { ...state, classDeficits: deficits };
}

function terminalState(state: OptionalJobState): OptionalJobState {
	return state;
}

/** Release a running lease and return its terminal representation. */
export function releaseJob(
	state: SchedulerSnapshot,
	jobId: string,
	finalState: Extract<OptionalJobState, 'complete' | 'failed' | 'cancelled'> = 'complete',
): JobRelease {
	const running = state.running.find((item) => item.job.jobId === jobId);
	if (!running) return { state, job: null };
	const job: SchedulerQueueItem = {
		...running,
		job: { ...running.job, state: terminalState(finalState) },
		retryAtUtcMs: null,
	};
	return {
		state: { ...state, running: state.running.filter((item) => item.job.jobId !== jobId) },
		job,
	};
}

export const completeJob = releaseJob;
export const finishJob = releaseJob;

/** Requeue a released/running item without resetting its original queue age. */
export function requeueJob(
	state: SchedulerSnapshot,
	item: SchedulerQueueItem | SchedulerDispatch,
	options: { backoff?: boolean; retryAtUtcMs?: number | null; attempts?: number } = {},
): SchedulerSnapshot {
	const withoutRunning = state.running.some((running) => running.job.jobId === item.job.jobId)
		? { ...state, running: state.running.filter((running) => running.job.jobId !== item.job.jobId) }
		: state;
	const stateName: Extract<OptionalJobState, 'queued' | 'backoff'> = options.backoff ? 'backoff' : 'queued';
	return enqueueJob(withoutRunning, {
		job: {
			...item.job,
			state: stateName,
			attempts: options.attempts ?? item.job.attempts,
		},
		queuedAtUtcMs: item.queuedAtUtcMs,
		work: item.work,
		retryAtUtcMs: options.retryAtUtcMs ?? null,
	});
}

export function cancelJob(state: SchedulerSnapshot, jobId: string): JobRelease {
	const queued = state.queued.find((item) => item.job.jobId === jobId);
	if (queued) {
		return {
			state: { ...state, queued: state.queued.filter((item) => item.job.jobId !== jobId) },
			job: { ...queued, job: { ...queued.job, state: 'cancelled' }, retryAtUtcMs: null },
		};
	}
	return releaseJob(state, jobId, 'cancelled');
}

/** Update the external Critical counter without owning Critical work itself. */
export function setCriticalActivity(
	state: SchedulerSnapshot,
	criticalActivity: number,
	nowMonoMs: number,
): SchedulerSnapshot {
	const next = normalizeNonNegativeInteger(criticalActivity);
	if (state.criticalActivity === 0 && next > 0) {
		return { ...state, criticalActivity: next, criticalQuietSinceMonoMs: null };
	}
	if (state.criticalActivity > 0 && next === 0) {
		return { ...state, criticalActivity: 0, criticalQuietSinceMonoMs: nowMonoMs };
	}
	return { ...state, criticalActivity: next };
}

export const updateCriticalActivity = setCriticalActivity;

export function canAdmitOptional(state: SchedulerSnapshot, nowMonoMs: number): boolean {
	return criticalAdmissionReason(state, nowMonoMs) === null
		&& state.running.length < GLOBAL_OPTIONAL_CONCURRENCY
		&& state.protectedCriticalSlots === PROTECTED_CRITICAL_SLOT_COUNT;
}

/**
 * Critical activity aborts optional I/O at the model boundary. Running work is
 * returned to the queue as a fresh admission, while its checkpoint and queue
 * age remain unchanged. No optional job is ever placed in the protected slot.
 */
export function yieldForCritical(state: SchedulerSnapshot): {
	state: SchedulerSnapshot;
	yielded: readonly SchedulerQueueItem[];
} {
	if (state.running.length === 0) return { state, yielded: [] };
	const yielded = state.running.map((item) => ({
		job: { ...item.job, state: 'queued' as const },
		queuedAtUtcMs: item.queuedAtUtcMs,
		work: item.work,
		retryAtUtcMs: null,
		sequence: item.sequence,
	}));
	return {
		state: {
			...state,
			queued: [...state.queued, ...yielded].sort((a, b) => a.sequence - b.sequence),
			running: [],
		},
		yielded,
	};
}

export interface BackoffState {
	attempts: number;
	retryAtUtcMs: number | null;
	lastAuthenticatedTriggerGeneration: number;
}

export type RetryRandom = () => number;

export function createBackoffState(lastAuthenticatedTriggerGeneration = 0): BackoffState {
	return {
		attempts: 0,
		retryAtUtcMs: null,
		lastAuthenticatedTriggerGeneration: Math.max(0, Math.floor(lastAuthenticatedTriggerGeneration)),
	};
}

export function retryCeilingMs(attempt: number): number {
	const normalizedAttempt = Math.max(0, Math.floor(Number.isFinite(attempt) ? attempt : 0));
	let ceiling: number = RETRY_INITIAL_DELAY_MS;
	for (let i = 0; i < normalizedAttempt && ceiling < RETRY_MAX_DELAY_MS; i += 1) {
		ceiling = Math.min(RETRY_MAX_DELAY_MS, ceiling * 2);
	}
	return ceiling;
}

/** Full jitter is [0, exponential ceiling], with all randomness injected. */
export function retryDelayMs(attempt: number, random: RetryRandom): number {
	const sample = random();
	const normalized = Number.isFinite(sample) ? Math.min(1, Math.max(0, sample)) : 0;
	return Math.floor(retryCeilingMs(attempt) * normalized);
}

export const calculateRetryDelay = retryDelayMs;
export const fullJitterDelay = retryDelayMs;

export function retryAfterFailure(state: BackoffState, nowUtcMs: number, random: RetryRandom): BackoffState {
	const delay = retryDelayMs(state.attempts, random);
	return {
		...state,
		attempts: state.attempts + 1,
		retryAtUtcMs: nowUtcMs + delay,
	};
}

export function resetBackoff(state: BackoffState, lastAuthenticatedTriggerGeneration = state.lastAuthenticatedTriggerGeneration): BackoffState {
	return {
		attempts: 0,
		retryAtUtcMs: null,
		lastAuthenticatedTriggerGeneration: Math.max(
			state.lastAuthenticatedTriggerGeneration,
			Math.max(0, Math.floor(lastAuthenticatedTriggerGeneration)),
		),
	};
}

export type BackoffSignal =
	| { kind: 'retryableFailure'; nowUtcMs: number; random: RetryRandom }
	| { kind: 'committedProgress'; chargedUnits: number }
	| { kind: 'authenticatedTrigger'; triggerGeneration: number }
	| { kind: 'networkFlap' };

/**
 * Only positive committed progress and a strictly newer authenticated
 * trigger reset backoff. A network flap is deliberately observational.
 */
export function applyBackoffSignal(state: BackoffState, signal: BackoffSignal): BackoffState {
	switch (signal.kind) {
		case 'retryableFailure':
			return retryAfterFailure(state, signal.nowUtcMs, signal.random);
		case 'committedProgress':
			return signal.chargedUnits > 0 ? resetBackoff(state) : state;
		case 'authenticatedTrigger':
			return signal.triggerGeneration > state.lastAuthenticatedTriggerGeneration
				? resetBackoff(state, signal.triggerGeneration)
				: state;
		case 'networkFlap':
			return state;
	}
}

export const updateBackoff = applyBackoffSignal;

export function isRetryReady(state: BackoffState, nowUtcMs: number): boolean {
	return state.retryAtUtcMs === null || nowUtcMs >= state.retryAtUtcMs;
}
