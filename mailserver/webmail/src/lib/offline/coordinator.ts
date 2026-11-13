/**
 * E4-I production coordinator: deduplicated trigger ingestion, bounded step
 * execution, and allowed transfer-effect admission for optional connectivity
 * work.
 *
 * Authority: the connectivity plan §4/E4-I. This is the remaining integration,
 * not a second sync engine: scheduled execution calls only the branded bounded
 * steps (`steps.ts`), admission reuses the E2 pure resolver (`eligibility.ts`)
 * and the E2 pure weighted-DRR scheduler (`scheduler.ts`), and every persisted
 * decision is a committed `JobResult` read back through the job store — never
 * invented.
 *
 * E4-I Astra corrections:
 * - Due-job admission runs THROUGH the E2 scheduler: weighted DRR class
 *   service, global (`GLOBAL_OPTIONAL_CONCURRENCY`) and per-account
 *   (`PER_ACCOUNT_OPTIONAL_CONCURRENCY`) concurrency accounting, expiry, and
 *   the Critical activity + 5s quiet window (`CRITICAL_QUIET_RESUME_MS`) —
 *   work is never admitted while Critical is active or immediately after it
 *   ended.
 * - Policy is re-read and eligibility re-resolved before EVERY step of a
 *   running job: a flag narrowed OFF mid-job stops the job at the next step
 *   boundary; it can never run another step or reach completion.
 * - `drainForRollback` blocks all future admission (latched) and awaits the
 *   settled running work — it yields at the next checkpoint, admitting
 *   nothing.
 * - A step's local page and the durable checkpoint commit as ONE atomic unit
 *   (`stagedPage.ts` + the job store's composed commit), so a failure exposes
 *   neither the page nor the checkpoint.
 *
 * Behavior stays OFF until the plan's rollout step: the default policy source
 * reports `flagEnabled: false` / mode `off`, and E2 eligibility rejects all
 * admission in that state. No enablement authority exists here.
 *
 * E4 signal freshness (R4): capability observations bind to the native
 * lifecycle epoch and monotonic receipt time. Older than
 * `FRESH_SNAPSHOT_MAX_AGE_MS`, failed/unsupported, or from a stopped/prior
 * subscription, a signal cannot authorize new optional work — the unavailable
 * path is used, never a manufactured nominal snapshot.
 */

import {
	CRITICAL_QUIET_RESUME_MS,
	GLOBAL_OPTIONAL_CONCURRENCY,
	MAX_RECORDS_PER_STEP,
	WORK_CLASS_QUANTA,
	isPauseReason,
	type EligibilityDecision,
	type JobResult,
	type OptionalWorkClass,
	type PauseReason,
	type SyncCheckpoint,
	type SyncStep,
	type WorkBudget,
} from './work-contract';
import {
	chargeClassService,
	createSchedulerState,
	enqueueJob as enqueueSchedulerJob,
	requeueJob,
	scheduleBatch,
	setCriticalActivity,
	type SchedulerQueueItem,
	type SchedulerSnapshot,
} from './scheduler';
import type { OptionalWorkJob } from './work-contract';
import { resolveEligibility, type EffectiveEligibilityPolicy, type RequestedEligibilityPolicy } from './eligibility';
import {
	LEASE_TTL_MS,
	type JobPersistence,
	type LeaseFence,
	type OptionalJobRecord,
} from './jobStore';
import type { OfflineStore } from './store';
import type { BridgeCapabilitySnapshot } from './work-contract';
import { isBoundedSyncStep } from './steps';
import { createMailPagePersistence, MailPageCapacityError } from './mailPagePersistence';
import { retryCeilingMs } from './scheduler';
import { createCriticalActivityCounter, type CriticalScopeHandle, type CriticalActivityCounter } from './criticalScope';

/** E4 freshness bound: older observations cannot authorize optional work. */
export const FRESH_SNAPSHOT_MAX_AGE_MS = 5_000 as const;

export type CoordinatorTriggerKind =
	| 'foreground'
	| 'reconnect'
	| 'authenticatedPush'
	| 'nativeOpportunity'
	| 'action';

export interface CoordinatorTrigger {
	kind: CoordinatorTriggerKind;
	accountId: string;
	/** Strictly increasing authenticated trigger generation. */
	generation: number;
	/** Required for `nativeOpportunity`: the native lifecycle epoch. */
	epoch?: number;
	/** Only for `action`: explicit user work runs as interactive class. */
	workClass?: OptionalWorkClass;
}

export type CoordinatorTriggerIngest =
	| { kind: 'queued'; jobId: string }
	| { kind: 'coalesced'; jobId: string }
	| { kind: 'rejected-stale-generation' }
	| { kind: 'rejected-stale-epoch' };

export interface CapabilityObservation {
	snapshot: BridgeCapabilitySnapshot;
	/** Monotonic receipt time of the observation. */
	receivedMonoMs: number;
	/** Native lifecycle epoch this observation is bound to. */
	epoch: number;
}

export interface CoordinatorPolicy {
	flagEnabled: boolean;
	rolloutMode: 'off' | 'observe' | 'execute';
	requested: RequestedEligibilityPolicy;
	effective: EffectiveEligibilityPolicy;
	workOffline: boolean;
}

export interface CoordinatorClock {
	nowMonoMs(): number;
	nowUtcMs(): number;
}

/** Privacy-safe decision record (observe lane / diagnostics). */
export type CoordinatorEvent =
	| { kind: 'trigger-ingested'; jobId: string; trigger: CoordinatorTriggerKind; generation: number }
	| { kind: 'trigger-coalesced'; jobId: string; generation: number }
	| { kind: 'trigger-rejected'; reason: 'stale-generation' | 'stale-epoch' }
	| { kind: 'admission-blocked'; jobId: string; reason: PauseReason; mode: 'off' | 'observe' | 'execute' }
	| { kind: 'admission-observed'; jobId: string; workClass: OptionalWorkClass }
	| { kind: 'admission-eligible'; jobId: string; workClass: OptionalWorkClass }
	| { kind: 'step-committed'; jobId: string; outcome: 'partial' | 'complete' | 'blocked'; done: number }
	| { kind: 'step-refused-unbounded'; reason: string }
	| { kind: 'result-recorded'; jobId: string; state: JobResult['state'] }
	| { kind: 'critical-transition'; count: number }
	| { kind: 'capability-stale'; ageMs: number };

export interface CoordinatorPorts {
	clock: CoordinatorClock;
	/** Injected randomness for full-jitter backoff. */
	random: () => number;
	policy: { readPolicy(): Promise<CoordinatorPolicy> };
	/** Capability reader; resolving null models a failed/unsupported signal. */
	capability: { readCapability(): Promise<CapabilityObservation | null> };
	store: OfflineStore;
	deltaStep: SyncStep;
	windowStep: SyncStep;
	jobs: JobPersistence;
	/** Window cutoff epoch ms used by scheduled window steps. */
	windowCutoffMs?: number | null;
	/** Optional privacy-safe event sink (never raw content). */
	onEvent?: (event: CoordinatorEvent) => void;
	/** Lease owner identity for CAS claims (defaults deterministic). */
	ownerId?: string;
}

/** Requested/effective policy inputs carried for the E2 eligibility resolver. */
export type CoordinatorPolicyInputs = RequestedEligibilityPolicy & EffectiveEligibilityPolicy;

const DEFAULT_POLICY: CoordinatorPolicy = {
	flagEnabled: false,
	rolloutMode: 'off',
	requested: { backgroundSyncEnabled: false, automaticNetwork: 'never' },
	effective: { backgroundAllowed: false, automaticNetwork: 'never', opportunisticRequiresCharging: true },
	workOffline: false,
};

/** The OFF default policy source. No automatic enablement exists. */
export function createOffPolicySource(): { readPolicy(): Promise<CoordinatorPolicy> } {
	return { readPolicy: async () => ({ ...DEFAULT_POLICY }) };
}

export type ReadJobOutcome =
	| { kind: 'committed'; result: JobResult }
	| { kind: 'unknown' };

export interface Coordinator {
	readonly ownerId: string;
	/** Bind (or rebind after restart) the native lifecycle epoch. */
	bindLifecycleEpoch(epoch: number): void;
	readonly epoch: number;
	/** External Critical ingestion; balanced handle feeding the quiet window. */
	criticalBegin(): CriticalScopeHandle;
	/** The shared Critical counter (adapters compose via criticalScope.ts). */
	readonly critical: CriticalActivityCounter;
	ingestTrigger(trigger: CoordinatorTrigger): Promise<CoordinatorTriggerIngest>;
	/** One admission cycle: scheduler → eligibility → bounded step execution. */
	runDueWork(): Promise<void>;
	/**
	 * Rollback drain: abort running work at the next checkpoint, await its
	 * settlement, and latch admission closed — nothing new is admitted until a
	 * fresh coordinator takes over.
	 */
	drainForRollback(): Promise<void>;
	readJobResult(jobId: string): Promise<ReadJobOutcome>;
	listJobs(): Promise<OptionalJobRecord[]>;
	cancelAccountJobs(accountId: string): Promise<string[]>;
	dispose(): void;
	readonly disposed: boolean;
}

export function jobIdForTrigger(trigger: CoordinatorTrigger): string {
	// Deterministic job identity per coalescing key so dedup is 1:1 across
	// durable and in-memory persistence.
	return `opt-${trigger.kind}-${trigger.accountId}`;
}

function toSchedulerJob(job: OptionalJobRecord): OptionalWorkJob {
	return {
		jobId: job.jobId,
		accountId: job.accountId,
		workClass: job.workClass,
		state: job.state === 'backoff' ? 'backoff' : 'queued',
		triggerGeneration: job.triggerGeneration,
		coalescingKey: job.coalescingKey,
		attempts: job.attempts,
		deadlineUtc: job.deadlineUtc,
		checkpoint: job.checkpoint,
	};
}

interface RunningEntry {
	jobId: string;
	controller: AbortController;
	promise: Promise<void>;
}

export function createCoordinator(ports: CoordinatorPorts): Coordinator {
	if (!isBoundedSyncStep(ports.deltaStep)) {
		throw new Error(
			'coordinator: deltaStep is not a bounded sync step; unbounded wrappers are refused as scheduled work',
		);
	}
	if (!isBoundedSyncStep(ports.windowStep)) {
		throw new Error(
			'coordinator: windowStep is not a bounded sync step; unbounded wrappers are refused as scheduled work',
		);
	}

	const emit = ports.onEvent ?? (() => {});
	const ownerId = ports.ownerId ?? 'coordinator';
	let epoch = 0;
	let disposed = false;
	// Latched by drainForRollback: after a rollback drain the coordinator never
	// admits again — a fresh coordinator owns post-rollback admission.
	let drained = false;
	// Newest generation seen per coalescing scope; older triggers are dropped.
	const generationFloors = new Map<string, number>();
	const running = new Map<string, RunningEntry>();
	// In-flight admission cycles, awaited by drainForRollback so a dispatch
	// pending admission can never outlive a completed rollback drain.
	const cycles = new Set<Promise<void>>();
	// Persistent E2 scheduler state: DRR class deficits/cursors, account
	// cursors, concurrency accounting and the Critical quiet window carry
	// across admission cycles instead of resetting per run.
	let scheduler: SchedulerSnapshot = createSchedulerState();

	const critical: CriticalActivityCounter = createCriticalActivityCounter({
		onTransition: (count) => {
			emit({ kind: 'critical-transition', count });
			// The Critical activity counter feeds the E2 scheduler's admission
			// gate: 0→1 clears any quiet stamp, →0 opens the 5s quiet window.
			scheduler = setCriticalActivity(scheduler, count, ports.clock.nowMonoMs());
			if (count > 0) {
				// A 0→1 Critical transition aborts optional network I/O immediately;
				// only the last committed checkpoint survives, and the job returns
				// to the queue with its queue age preserved.
				for (const entry of running.values()) entry.controller.abort();
			}
		},
	});

	function jobKey(accountId: string, kind: CoordinatorTriggerKind): string {
		return `${kind}:${accountId}`;
	}

	function freshCapability(
		observation: CapabilityObservation | null,
		nowMonoMs: number,
	): BridgeCapabilitySnapshot | null {
		if (!observation) return null;
		if (observation.epoch !== epoch) return null;
		const ageMs = nowMonoMs - observation.receivedMonoMs;
		if (ageMs > FRESH_SNAPSHOT_MAX_AGE_MS) {
			emit({ kind: 'capability-stale', ageMs });
			return null;
		}
		return observation.snapshot;
	}

	/**
	 * Resolve admission FRESHLY: policy and capability are re-read and
	 * eligibility re-resolved at every call — before a dispatch and again
	 * before each step of a running job — so a flag narrowed OFF (or any
	 * newly-blocked condition) stops work at the next boundary.
	 */
	async function resolveAdmission(job: OptionalJobRecord): Promise<EligibilityDecision> {
		const policy = await ports.policy.readPolicy();
		const observation = await ports.capability.readCapability();
		const capability = freshCapability(observation, ports.clock.nowMonoMs());
		if (capability === null) {
			return {
				kind: 'blocked',
				mode: policy.rolloutMode,
				workClass: job.workClass,
				reason: 'capabilityUnavailable',
			};
		}
		return resolveEligibility({
			workClass: job.workClass,
			rolloutMode: policy.rolloutMode,
			flagEnabled: policy.flagEnabled,
			requested: policy.requested,
			effective: policy.effective,
			workOffline: policy.workOffline,
			capability,
			criticalActivity: critical.count(),
			queueAgeMs: Math.max(0, ports.clock.nowUtcMs() - job.queuedAtUtcMs),
			nowMonoMs: ports.clock.nowMonoMs(),
			nowUtcMs: ports.clock.nowUtcMs(),
			deadlineUtc: job.deadlineUtc,
		});
	}

	function dropRunningFromScheduler(jobId: string): void {
		scheduler = {
			...scheduler,
			running: scheduler.running.filter((item) => item.job.jobId !== jobId),
		};
	}

	async function recordResult(job: OptionalJobRecord, result: JobResult, fence?: LeaseFence): Promise<void> {
		const outcome = await ports.jobs.recordResult(job.jobId, job.triggerGeneration, result, fence);
		if (outcome.kind === 'committed') {
			emit({ kind: 'result-recorded', jobId: job.jobId, state: result.state });
		}
	}

	async function executeJob(job: OptionalJobRecord, dispatch: SchedulerQueueItem, fence: LeaseFence, stepBudget: WorkBudget): Promise<void> {
		const controller = new AbortController();
		const entry: RunningEntry = { jobId: job.jobId, controller, promise: Promise.resolve() };
		let settle: () => void = () => {};
		entry.promise = new Promise<void>((resolve) => {
			settle = resolve;
		});
		running.set(job.jobId, entry);
		const page = createMailPagePersistence(ports.store, ports.jobs, job, fence, () => ports.clock.nowUtcMs());
		// Lease fencing: the (owner, expiry) pair stamped by the WINNING CLAIM is
		// the claimant's ONLY commit credential. It is received from
		// `claimLease` verbatim — never re-derived from a post-claim read, whose
		// TOCTOU window used to disable fencing when ownership had already
		// moved on (an undefined fence is not a fence; a claimant that cannot
		// present its stamped fence never commits at all).
		let checkpoint: SyncCheckpoint | null = job.checkpoint;
		let stepKind = job.stepKind === 'window' ? 'window' as const : 'delta' as const;
		let windowRetried = false;
		// E4-I r6 Astra correction: set when a partial step made NO progress
		// (nothing applied, page frontier unmoved). The dispatch then stops at
		// the next loop head — AFTER the fresh policy gate, so a narrowed policy
		// still wins the pause reason — instead of re-running the identical
		// no-fetch step until the time deadline.
		let noProgress = false;
		// The dispatch's ONE budget bounds the entire execution (E4-I Astra
		// correction: re-reading a fresh budget at every step let one dispatch
		// run step after step with the deadline renewed each time — DRR charged
		// one admission unit while actual service was unbounded). The policy
		// gate is still re-resolved before every step, but a narrowed policy
		// STOPS the job; it never renews the step budget.
		const budget: WorkBudget = stepBudget;
		// E4-I r5 Astra correction: the byte allowance is tracked ACROSS the
		// dispatch's steps. Each call receives only the REMAINING budget and
		// reports its applied bytes back (`progress.appliedBytes`), so a partial
		// step can never re-spend the full allowance — one dispatch is bounded
		// by budget.maxBytes in TOTAL, not per step.
		let bytesRemaining = budget.maxBytes;
		try {
			while (!controller.signal.aborted) {
				if (drained) break;
				// FRESH policy gate before every step: a flag narrowed OFF after
				// one checkpoint stops the job here — never another step.
				const gate = await resolveAdmission(job);
				if (gate.kind === 'observed') {
					emit({ kind: 'admission-observed', jobId: job.jobId, workClass: gate.workClass });
					break;
				}
				if (gate.kind === 'blocked') {
					emit({
						kind: 'admission-blocked',
						jobId: job.jobId,
						reason: gate.reason,
						mode: gate.mode,
					});
					await recordResult(job, {
						state: 'paused',
						reason: isPauseReason(gate.reason) ? gate.reason : 'policyDenied',
						checkpoint: checkpoint ?? { version: 1, cursor: null },
						progress: { done: 0, chargedUnits: 0 },
					}, fence);
					await ports.jobs.releaseLease(job.jobId, ownerId);
					return;
				}
				const nowMono = ports.clock.nowMonoMs();
				if (nowMono >= budget.deadlineMonoMs) break;
				if (noProgress) break;
				const step: SyncStep = stepKind === 'delta' ? ports.deltaStep : ports.windowStep;
				const priorCursor = checkpoint?.cursor ?? null;
				const result = await step({
					store: page.store,
					accountId: job.accountId,
					signal: controller.signal,
					budget: {
						maxRecords: MAX_RECORDS_PER_STEP,
						maxBytes: bytesRemaining,
						deadlineMonoMs: budget.deadlineMonoMs,
					},
					checkpoint,
				});
				// Deduct this call's APPLIED bytes from the dispatch's remaining
				// allowance before anything else: the next step starts behind the
				// bytes this one already spent.
				bytesRemaining = Math.max(0, bytesRemaining - (result.progress.appliedBytes ?? 0));
				const committed = await page.commit(result.checkpoint);
				if (committed.kind !== 'committed') {
					// Superseded trigger or lost lease: a stale writer drops its
					// staged effects and yields without recording anything.
					page.discard();
					await ports.jobs.releaseLease(job.jobId, ownerId);
					return;
				}
				checkpoint = result.checkpoint;
				// Service accounting returns to DRR: the dispatch's admission
				// charge covered one metadata record, so every committed step
				// charges its ACTUAL record service against the class deficit.
				// Without this, weighted quanta bound only the dispatch count and
				// one dispatch could run unbounded steps (E4-I Astra correction).
				scheduler = chargeClassService(scheduler, job.workClass, Math.max(0, result.progress.chargedUnits));
				emit({
					kind: 'step-committed',
					jobId: job.jobId,
					outcome: result.outcome,
					done: result.progress.done,
				});

				if (result.outcome === 'complete') {
					await recordResult(job, {
						state: 'complete',
						checkpoint: checkpoint ?? { version: 1, cursor: null },
						progress: result.progress,
					}, fence);
					await ports.jobs.releaseLease(job.jobId, ownerId);
					return;
				}
				if (result.outcome === 'blocked') {
					if (stepKind === 'delta' && !windowRetried) {
						// cannotCalculateChanges-class fallback: one bounded window
						// resync replaces the unanchored delta walk.
						stepKind = 'window';
						windowRetried = true;
						checkpoint = null;
						continue;
					}
					await recordResult(job, {
						state: 'paused',
						reason: 'validatorChanged',
						checkpoint: checkpoint ?? { version: 1, cursor: null },
						progress: result.progress,
					}, fence);
					await ports.jobs.releaseLease(job.jobId, ownerId);
					return;
				}
				// E4-I r6 Astra correction: a PARTIAL step that applied nothing AND
				// could not even move its page frontier has no productive follow-up
				// — the byte remainder can only shrink and the deadline can only
				// advance, so continuing would re-run the identical no-fetch step
				// (and rewrite the same checkpoint) until the time deadline. The
				// stop itself happens at the next loop head, after the fresh gate.
				if (
					result.outcome === 'partial'
					&& (result.progress.appliedBytes ?? 0) === 0
					&& (result.checkpoint.cursor ?? null) === priorCursor
				) {
					noProgress = true;
				}
				// partial with progress: keep walking within the same budget; the
				// loop head re-checks the deadline, policy and the abort signal.
			}
			if (controller.signal.aborted || drained) {
				// Critical/rollback interruption: yield at the last committed
				// checkpoint, requeue (queue age and checkpoint preserved). No new
				// result is recorded — the yield is an admission state, not a
				// terminal one. The unflushed staged page is discarded; replay
				// re-applies it idempotently.
				page.discard();
				await ports.jobs.releaseLease(job.jobId, ownerId);
				return;
			}
			await recordResult(job, {
				state: 'paused',
				reason: 'deadlineExceeded',
				checkpoint: checkpoint ?? { version: 1, cursor: null },
				progress: { done: 0, chargedUnits: 0 },
			}, fence);
			await ports.jobs.releaseLease(job.jobId, ownerId);
		} catch (error) {
			// The staged page rolled back with its flush; no checkpoint advanced.
			page.discard();
			// An ACTUAL request cancellation (the step's AbortSignal aborted a
			// fetch mid-flight, surfacing as a DOM AbortError rejection) is an
			// interruption, never a terminal failure: the job yields at its last
			// committed checkpoint and rejoins the queue (E4-I Astra correction —
			// the coordinator used to record a nonretryable `failed` here).
			if (controller.signal.aborted || isAbortError(error)) {
				await ports.jobs.releaseLease(job.jobId, ownerId);
				return;
			}
			// Retryable failures back off full-jitter up to the exponential
			// ceiling; non-retryable failures record a terminal result.
			const retryable = isRetryableError(error);
			if (retryable) {
				const ceiling = retryCeilingMs(job.attempts);
				const delay = Math.floor(ceiling * Math.min(1, Math.max(0, ports.random())));
				await ports.jobs.releaseLease(job.jobId, ownerId, {
					backoff: true,
					retryAtUtcMs: ports.clock.nowUtcMs() + delay,
					attempts: job.attempts + 1,
				});
				return;
			}
			await recordResult(job, {
				state: 'failed',
				error: { code: error instanceof MailPageCapacityError ? 'storage' : 'unknown', retryable: false },
				checkpoint: checkpoint ?? { version: 1, cursor: null },
				progress: { done: 0, chargedUnits: 0 },
			}, fence);
			await ports.jobs.releaseLease(job.jobId, ownerId);
		} finally {
			running.delete(job.jobId);
			dropRunningFromScheduler(job.jobId);
			// Mirror retrying jobs back into the E2 snapshot with their backoff
			// envelope so DRR/concurrency accounting stays truthful; every other
			// exit re-derives the queue from the store on the next cycle.
			const releasedJob = await ports.jobs.readJob(job.jobId).catch(() => null);
			if (releasedJob && releasedJob.state === 'backoff') {
				scheduler = requeueJob(scheduler, dispatch, {
					backoff: true,
					retryAtUtcMs: releasedJob.retryAtUtcMs,
					attempts: releasedJob.attempts,
				});
			}
			settle();
		}
	}

	function isRetryableError(error: unknown): boolean {
		const code = (error as { workCode?: string } | null)?.workCode;
		if (typeof code === 'string') {
			return code === 'network' || code === 'deadline' || code === 'aborted';
		}
		const message = error instanceof Error ? error.message : String(error);
		// Transport-class failures retry; admission/contract refusals do not.
		return /network|timeout|transport|fetch/i.test(message)
			&& !/refused|admission|contract/i.test(message);
	}

	/**
	 * A request cancelled through its AbortSignal surfaces as a DOM
	 * `AbortError` (name, or the legacy DOM abort code 20) — an interruption,
	 * never a transport or contract failure.
	 */
	function isAbortError(error: unknown): boolean {
		if (error instanceof Error && error.name === 'AbortError') return true;
		const typed = error as { name?: unknown; code?: unknown } | null;
		if (typed !== null && typeof typed === 'object') {
			if (typed.name === 'AbortError') return true;
			if (typed.code === 20) return true; // DOMException ABORT_ERR
		}
		return false;
	}

	/** One admission cycle: scheduler → per-dispatch eligibility → bounded execution. */
	async function runAdmissionCycle(): Promise<void> {
		await ports.jobs.reclaimExpiredLeases(ports.clock.nowUtcMs());
		// Refresh the Critical admission gate (activity count + quiet window).
		scheduler = setCriticalActivity(scheduler, critical.count(), ports.clock.nowMonoMs());
		// The scheduler queue re-derives from the store's due set every cycle
		// (queue age rides queuedAtUtcMs; DRR deficits/cursors and running
		// accounting persist), so finished/paused jobs never linger as stale
		// dispatch candidates.
		scheduler = { ...scheduler, queued: [] };
		const due = await ports.jobs.listDue(ports.clock.nowUtcMs());
		for (const job of due) {
			scheduler = enqueueDue(scheduler, job);
		}
		const batch = scheduleBatch(scheduler, {
			nowUtcMs: ports.clock.nowUtcMs(),
			nowMonoMs: ports.clock.nowMonoMs(),
		}, GLOBAL_OPTIONAL_CONCURRENCY);
		scheduler = batch.state;
		// Scheduler-expired queue entries (queue age or deadline passed) get
		// their committed expired result — observable, never silently dropped.
		for (const item of batch.expired) {
			await recordResult({
				...toSchedulerJobRecord(item),
			}, {
				state: 'expired',
				checkpoint: item.job.checkpoint ?? { version: 1, cursor: null },
				progress: { done: 0, chargedUnits: 0 },
				expiredAtUtc: new Date(ports.clock.nowUtcMs()).toISOString(),
			});
		}
		const executions: Promise<void>[] = [];
		let dispatched = 0;
		for (const dispatch of batch.dispatches) {
			// A Critical transition stops NEW dispatches immediately.
			if (critical.isActive()) break;
			const jobRecord = await ports.jobs.readJob(dispatch.job.jobId);
			if (!jobRecord) {
				dropRunningFromScheduler(dispatch.job.jobId);
				dispatched += 1;
				continue;
			}
			// FRESH admission decision per dispatch (policy re-read). Its
			// WorkBudget is the ONE budget this dispatch executes under —
			// step loops stop at its deadline instead of renewing it.
			const decision = await resolveAdmission(jobRecord);
			// The awaits above can span a rollback drain or disposal: nothing is
			// claimed or written once the drain latched (E4-I Astra correction —
			// a pending admission used to outlive the drain and write results).
			if (drained || disposed) break;
			if (decision.kind === 'blocked') {
				emit({
					kind: 'admission-blocked',
					jobId: jobRecord.jobId,
					reason: decision.reason,
					mode: decision.mode,
				});
				// Paused jobs stay observable through a committed paused result
				// only once per pause; re-ingest of a newer trigger re-opens them.
				await recordResult(jobRecord, {
					state: 'paused',
					reason: isPauseReason(decision.reason) ? decision.reason : 'policyDenied',
					checkpoint: jobRecord.checkpoint ?? { version: 1, cursor: null },
					progress: { done: 0, chargedUnits: 0 },
				});
				dropRunningFromScheduler(dispatch.job.jobId);
				dispatched += 1;
				continue;
			}
			if (decision.kind === 'observed') {
				emit({ kind: 'admission-observed', jobId: jobRecord.jobId, workClass: decision.workClass });
				dropRunningFromScheduler(dispatch.job.jobId);
				dispatched += 1;
				continue;
			}
			emit({ kind: 'admission-eligible', jobId: jobRecord.jobId, workClass: decision.workClass });
			// CAS claim; the winner's stamped (owner, expiry) pair is the fence
			// EVERY commit of this execution presents verbatim. A lost claim
			// yields the reservation — a claimant without a fence never runs.
			const fence = await ports.jobs.claimLease(jobRecord.jobId, ownerId, ports.clock.nowUtcMs());
			if (!fence) {
				dropRunningFromScheduler(dispatch.job.jobId);
				dispatched += 1;
				continue;
			}
			dispatched += 1;
			executions.push(executeJob(jobRecord, dispatch, fence, decision.budget));
		}
		if (dispatched < batch.dispatches.length) {
			// Critical interruption / drain / disposal broke the loop: entries
			// already placed in scheduler.running but never dispatched must
			// RELEASE their reservations, or they permanently occupy concurrency
			// and DRR accounting (E4-I Astra correction — a queued account used
			// to stay undispatchable after Critical ended).
			const dispatchedIds = new Set(
				batch.dispatches.slice(0, dispatched).map((item) => item.job.jobId),
			);
			scheduler = {
				...scheduler,
				running: scheduler.running.filter((item) => dispatchedIds.has(item.job.jobId)),
			};
		}
		// Bounded concurrency: at most GLOBAL_OPTIONAL_CONCURRENCY jobs (and
		// at most one per account, enforced by the E2 scheduler) execute
		// concurrently; this cycle awaits their settlement.
		await Promise.all(executions);
	}

	const coordinator: Coordinator = {
		ownerId,
		get epoch(): number {
			return epoch;
		},
		bindLifecycleEpoch(next: number): void {
			if (disposed) return;
			if (!Number.isSafeInteger(next) || next < epoch) return;
			// A newer epoch invalidates every observation from prior epochs; the
			// capability reader must deliver a fresh receipt before admission.
			epoch = next;
		},
		criticalBegin(): CriticalScopeHandle {
			return critical.begin('coordinator');
		},
		critical,
		async ingestTrigger(trigger): Promise<CoordinatorTriggerIngest> {
			if (disposed) return { kind: 'rejected-stale-generation' };
			if (!Number.isSafeInteger(trigger.generation) || trigger.generation < 0) {
				return { kind: 'rejected-stale-generation' };
			}
			if (trigger.kind === 'nativeOpportunity') {
				if (trigger.epoch === undefined || trigger.epoch !== epoch) {
					// Prior-epoch opportunities cannot restore eligibility.
					emit({ kind: 'trigger-rejected', reason: 'stale-epoch' });
					return { kind: 'rejected-stale-epoch' };
				}
			}
			const key = jobKey(trigger.accountId, trigger.kind);
			const floor = generationFloors.get(key) ?? 0;
			if (trigger.generation < floor) {
				emit({ kind: 'trigger-rejected', reason: 'stale-generation' });
				return { kind: 'rejected-stale-generation' };
			}
			generationFloors.set(key, trigger.generation);
			const workClass: OptionalWorkClass = trigger.kind === 'action'
				? (trigger.workClass ?? 'interactive')
				: 'background';
			const jobId = jobIdForTrigger(trigger);
			const outcome = await ports.jobs.enqueueJob({
				jobId,
				accountId: trigger.accountId,
				workClass,
				state: 'queued',
				triggerGeneration: trigger.generation,
				coalescingKey: key,
				attempts: 0,
				// Persisted seven-day-age ceiling is enforced by eligibility via
				// queuedAt; the deadline defaults to queuedAt + the max queue age.
				deadlineUtc: new Date(
					ports.clock.nowUtcMs() + 7 * 24 * 60 * 60 * 1000,
				).toISOString(),
				queuedAtUtcMs: ports.clock.nowUtcMs(),
				retryAtUtcMs: null,
				stepKind: 'delta',
				checkpoint: null,
				leaseOwner: null,
				leaseExpiresAtMs: null,
			});
			if (outcome.kind === 'rejected-stale-generation') {
				emit({ kind: 'trigger-rejected', reason: 'stale-generation' });
				return { kind: 'rejected-stale-generation' };
			}
			if (outcome.kind === 'coalesced') {
				emit({ kind: 'trigger-coalesced', jobId, generation: trigger.generation });
				return { kind: 'coalesced', jobId };
			}
			emit({ kind: 'trigger-ingested', jobId, trigger: trigger.kind, generation: trigger.generation });
			return { kind: 'queued', jobId };
		},

		async runDueWork(): Promise<void> {
			if (disposed || drained) return;
			// An in-flight admission cycle is awaited by drainForRollback: a
			// dispatch that is between admission and its claim when the drain
			// starts can never outlive it (E4-I Astra correction — the drain used
			// to wait only for already-running entries).
			const cycle = runAdmissionCycle().finally(() => {
				cycles.delete(cycle);
			});
			cycles.add(cycle);
			await cycle;
		},

		async drainForRollback(): Promise<void> {
			if (drained) return;
			drained = true;
			for (const entry of running.values()) {
				// Abort at the next checkpoint: steps check the signal between
				// records and the loop yields with the last committed cursor.
				entry.controller.abort();
			}
			// The drain completes only when every running job has settled AND
			// every in-flight admission cycle (including its undispatched
			// claims) has finished.
			await Promise.allSettled([...cycles]);
		},

		async readJobResult(jobId): Promise<ReadJobOutcome> {
			const stored = await ports.jobs.readJobResult(jobId);
			if (!stored) return { kind: 'unknown' };
			return { kind: 'committed', result: stored.result };
		},

		listJobs(): Promise<OptionalJobRecord[]> {
			return ports.jobs.listDue(ports.clock.nowUtcMs());
		},

		cancelAccountJobs(accountId): Promise<string[]> {
			return ports.jobs.cancelAccountJobs(accountId, ports.clock.nowUtcMs());
		},

		dispose(): void {
			if (disposed) return;
			disposed = true;
			for (const entry of running.values()) entry.controller.abort();
			critical.teardown();
		},
		get disposed(): boolean {
			return disposed;
		},
	};

	function enqueueDue(state: SchedulerSnapshot, job: OptionalJobRecord): SchedulerSnapshot {
		// enqueueJob dedupes by jobId (queued/running) and refuses terminal
		// states, so re-feeding the store queue every cycle is idempotent.
		const next = enqueueSchedulerJob(state, {
			job: toSchedulerJob(job),
			queuedAtUtcMs: job.queuedAtUtcMs,
			work: { kind: 'metadata', records: 1 },
			retryAtUtcMs: job.retryAtUtcMs,
		});
		return next;
	}

	function toSchedulerJobRecord(item: SchedulerQueueItem): OptionalJobRecord {
		return {
			jobId: item.job.jobId,
			accountId: item.job.accountId,
			workClass: item.job.workClass,
			state: item.job.state as OptionalJobRecord['state'],
			triggerGeneration: item.job.triggerGeneration,
			coalescingKey: item.job.coalescingKey,
			attempts: item.job.attempts,
			deadlineUtc: item.job.deadlineUtc,
			queuedAtUtcMs: item.queuedAtUtcMs,
			retryAtUtcMs: item.retryAtUtcMs ?? null,
			stepKind: 'delta',
			checkpoint: item.job.checkpoint,
			leaseOwner: null,
			leaseExpiresAtMs: null,
		};
	}

	return coordinator;
}

/** Re-export for wiring modules. */
export { LEASE_TTL_MS, CRITICAL_QUIET_RESUME_MS };
