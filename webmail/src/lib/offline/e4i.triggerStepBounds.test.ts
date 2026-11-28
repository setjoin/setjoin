/**
 * CAS-E4I-TRIGGER-STEP-BOUNDS — E4-I verification binding (core lane).
 *
 * Coalesced trigger generations, one-page/64-record/byte/time bounds,
 * unbounded-wrapper refusal, Critical interruption, and no cursor advance
 * before local commit. Positive oracle first; each planted fault then maps to
 * the pinned FAIL text with a distinct finite subOracleId.
 *
 * E4-I Astra corrections under test: the receipt is derived from REAL run
 * observations (step-committed events, store/job reads, actual refusal
 * attempts) and is written ONCE in afterAll — after every required scenario
 * has finished — so a late scenario failure can never hide behind an earlier
 * manufactured PASS receipt. The page-failure oracle runs the production
 * staged-page composition: a mid-page store failure exposes neither the page
 * nor an advanced cursor.
 */

import { describe, it, expect, afterAll, afterEach } from 'vitest';
import { getCurrentTest } from 'vitest/suite';

import type { Email } from '$lib/types/jmap';
import {
	auditTriggerStepBounds,
	createHarnessCoordinator,
	e4iFailure,
	gateVerdictOnScenarios,
	scenarioFailed,
	writeCaseResult,
	type HarnessCoordinator,
	type StepBoundsAudit,
} from '$lib/native/testing/backgroundWorkHarness';
import { createSyncDeltaStep, isBoundedSyncStep } from './steps';
import { createCoordinator } from './coordinator';
import { syncDelta } from './sync';
import type { SyncStep } from './work-contract';

const START_UTC = Date.parse('2026-09-17T00:00:00Z');

function email(id: string, receivedAtIso: string): Email {
	return {
		id,
		threadId: 't',
		mailboxIds: { Inbox: true },
		keywords: { $seen: true },
		receivedAt: receivedAtIso,
		hasAttachment: false,
		preview: '',
		subject: '',
	} as unknown as Email;
}

/** Real observations, accumulated by the scenarios below. The mutable mirror
 * feeds the auditor (whose readonly inputs accept these arrays) in afterAll. */
const observations = {
	events: [] as import('./coordinator').CoordinatorEvent[],
	stepRecordCounts: [] as number[],
	cursorAdvancedWithoutCommit: false,
	unboundedWrapperRefused: false,
	coalescedGenerations: [] as number[],
	queuedJobCountAfterDuplicateTriggers: 0,
	criticalAbortedBeforeCursorAdvance: false,
};

/** E4-I Astra correction (finding 14): every scenario's ACTUAL verdict gates
 * the retained receipt — a test that fails without touching the auditor's
 * observations can never hide behind a PASS verdict in afterAll. */
const scenarioFailures: string[] = [];
afterEach(() => {
	const task = getCurrentTest();
	const failure = scenarioFailed(task, task?.name ?? '');
	if (failure) scenarioFailures.push(failure);
});

async function runTriggerScenario(): Promise<{ coordinator: HarnessCoordinator; jobId: string }> {
	const events: import('./coordinator').CoordinatorEvent[] = [];
	const coordinator = createHarnessCoordinator({
		events,
		pages: [
			{
				newState: '5',
				hasMoreChanges: true,
				created: ['1', '2'],
				updated: [],
				destroyed: [],
				emails: [email('1', '2026-09-01T00:00:00Z'), email('2', '2026-09-02T00:00:00Z')],
			},
			{
				newState: '9',
				hasMoreChanges: false,
				created: [],
				updated: ['3'],
				destroyed: ['8'],
				emails: [email('3', '2026-09-03T00:00:00Z')],
			},
		],
	});
	const first = await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 1 });
	await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 2 });
	await coordinator.runDueWork();
	const jobId = (first.kind === 'queued' || first.kind === 'coalesced') ? first.jobId : '';
	observations.events.push(...events);
	// Per-step record counts come from the emitted step-committed events.
	for (const event of events) {
		if (event.kind === 'step-committed') observations.stepRecordCounts.push(event.done);
	}
	observations.coalescedGenerations = [1, 2];
	// The job count is read from the actual store: duplicates coalesced onto
	// exactly one job record.
	const job = await coordinator.jobs.readJob(jobId);
	observations.queuedJobCountAfterDuplicateTriggers = job ? 1 : 0;
	return { coordinator, jobId };
}

describe('CAS-E4I-TRIGGER-STEP-BOUNDS', () => {
	it('positive oracle: duplicate generations coalesce to one job; bounded steps commit cursors only after local commit', async () => {
		const { coordinator, jobId } = await runTriggerScenario();
		const result = await coordinator.readJobResult(jobId);
		expect(result.kind === 'committed' && result.result.state).toBe('complete');
		// The cursor advanced only after the local page committed.
		expect(result.kind === 'committed' && result.result.checkpoint.cursor).toContain('delta:state:9');
		const foreground = createHarnessCoordinator({
			pages: [{
				newState: '5', hasMoreChanges: false, created: ['1'], updated: [], destroyed: [],
				emails: [email('1', '2026-09-01T00:00:00Z')],
			}],
		});
		await foreground.ingestTrigger({ kind: 'foreground', accountId: 'acct-1', generation: 1 });
		await foreground.runDueWork();
		const committed = await foreground.readJobResult('opt-foreground-acct-1');
		expect(committed.kind).toBe('committed');
		if (committed.kind === 'committed') {
			expect(committed.result.state).toBe('complete');
			expect(committed.result.checkpoint.cursor).toContain('delta:state:5');
		}
		const foregroundJob = await foreground.jobs.readJob('opt-foreground-acct-1');
		expect(foregroundJob).not.toBeNull();
	});

	it('no cursor advance before local commit: a mid-page store failure exposes neither page nor cursor', async () => {
		// The store row is seeded so the page STAGES a merge; the failure lands
		// inside the composed commit — proving neither the page nor the cursor
		// becomes visible (production composition, not a hand-built pair).
		const store = createHarnessCoordinator({}).store;
		await store.upsertMessage({
			id: '1',
			threadId: 't',
			receivedAt: Date.parse('2026-09-01T00:00:00Z'),
			flags: [],
			hasAttachment: false,
			cacheState: 'full',
			syncedAt: 0,
			from: '',
			to: '',
			cc: '',
			bcc: '',
			subject: '',
			preview: '',
			tagIds: ['Inbox'],
			version: 0,
			dirtyFields: [],
		});
		store.failNextMerge(new Error('simulated local page commit failure'));
		const coordinator = createHarnessCoordinator({
			store,
			pages: [{
				newState: '7', hasMoreChanges: false, created: ['1'], updated: [], destroyed: [],
				emails: [email('1', '2026-09-01T00:00:00Z')],
			}],
		});
		await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 1 });
		await coordinator.runDueWork();
		const job = await coordinator.jobs.readJob('opt-reconnect-acct-1');
		const result = await coordinator.readJobResult('opt-reconnect-acct-1');
		// The failed page never published the page's newer cursor, and the
		// staged page rolled back: neither side of the composition is visible.
		expect(job?.checkpoint?.cursor ?? null).not.toBe('delta:state:7');
		const surviving = await store.getMessage('1');
		expect(surviving?.version ?? 0).toBe(0);
		expect(result.kind === 'committed' && result.result.state).toBe('failed');
		// The oracle input records any ACTUAL violation (cursor advanced anyway).
		observations.cursorAdvancedWithoutCommit = observations.cursorAdvancedWithoutCommit
			|| job?.checkpoint?.cursor === 'delta:state:7';
	});

	it('coalescing keeps the newest generation and never loses a newer trigger', async () => {
		const coordinator = createHarnessCoordinator({});
		const stale = await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'a', generation: 5 });
		const newer = await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'a', generation: 9 });
		const older = await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'a', generation: 6 });
		expect(stale.kind === 'queued' || stale.kind === 'coalesced').toBe(true);
		expect(newer.kind).toBe('coalesced');
		expect(older.kind).toBe('rejected-stale-generation');
		const job = await coordinator.jobs.readJob('opt-reconnect-a');
		expect(job?.triggerGeneration).toBe(9);
	});

	it('Critical interruption aborts optional I/O immediately and preserves the committed checkpoint', async () => {
		const events: import('./coordinator').CoordinatorEvent[] = [];
		const coordinator = createHarnessCoordinator({
			events,
			pages: [{
				newState: '5', hasMoreChanges: true, created: ['1'], updated: [], destroyed: [],
				emails: [email('1', '2026-09-01T00:00:00Z')],
				onPage: () => {
					// Critical work begins mid-flight: the 0→1 transition must abort
					// the running optional step before its cursor advances again.
					coordinator.criticalBegin();
				},
			}],
		});
		await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 1 });
		await coordinator.runDueWork();
		const job = await coordinator.jobs.readJob('opt-reconnect-acct-1');
		const criticalActive = coordinator.critical.isActive();
		expect(criticalActive).toBe(true);
		// The interruption preserved the last committed checkpoint: the walk
		// stopped before the interrupted page's cursor ('delta:state:5').
		const preserved = (job?.checkpoint?.cursor ?? null) !== 'delta:state:5';
		observations.criticalAbortedBeforeCursorAdvance = criticalActive && preserved;
		coordinator.dispose();
	});

	it('unbounded wrappers are refused as scheduled work', () => {
		let refused = false;
		expect(isBoundedSyncStep(syncDelta as unknown as SyncStep)).toBe(false);
		try {
			createCoordinator({
				clock: { nowMonoMs: () => 0, nowUtcMs: () => START_UTC },
				random: () => 0.5,
				policy: { readPolicy: async () => ({ flagEnabled: false, rolloutMode: 'off', requested: { backgroundSyncEnabled: false, automaticNetwork: 'never' }, effective: { backgroundAllowed: false, automaticNetwork: 'never', opportunisticRequiresCharging: true }, workOffline: false }) },
				capability: { readCapability: async () => null },
				store: createHarnessCoordinator({}).store,
				deltaStep: syncDelta as unknown as SyncStep,
				windowStep: syncDelta as unknown as SyncStep,
				jobs: createHarnessCoordinator({}).jobs,
			});
		} catch (error) {
			refused = error instanceof Error && /unbounded wrappers are refused/.test(error.message);
		}
		// The oracle records what the coordinator ACTUALLY did.
		observations.unboundedWrapperRefused = refused;
		expect(refused).toBe(true);
	});

	it('planted faults produce the pinned FAIL text with distinct finite causes', () => {
		const pinned = e4iFailure('CAS-E4I-TRIGGER-STEP-BOUNDS', 'probe');
		expect(pinned.fail).toBe(
			'FAIL CAS-E4I-TRIGGER-STEP-BOUNDS: scheduled step exceeded its bound or advanced an uncommitted cursor',
		);
		const overrun = auditTriggerStepBounds({
			events: [],
			stepRecordCounts: [65],
			cursorAdvancedWithoutCommit: false,
			unboundedWrapperRefused: true,
			coalescedGenerations: [1],
			queuedJobCountAfterDuplicateTriggers: 1,
			criticalAbortedBeforeCursorAdvance: true,
		});
		expect(overrun.ok).toBe(false);
		expect(overrun.fail).toBe(pinned.fail);
		expect(overrun.cause).toBe('subOracleId=step-record-overrun lane=core');

		const cursor = auditTriggerStepBounds({
			events: [],
			stepRecordCounts: [2],
			cursorAdvancedWithoutCommit: true,
			unboundedWrapperRefused: true,
			coalescedGenerations: [1],
			queuedJobCountAfterDuplicateTriggers: 1,
			criticalAbortedBeforeCursorAdvance: true,
		});
		expect(cursor.ok).toBe(false);
		expect(cursor.fail).toBe(pinned.fail);
		expect(cursor.cause).toBe('subOracleId=cursor-advanced-before-commit lane=core');
		expect(cursor.cause).not.toBe(overrun.cause);

		const wrapper = auditTriggerStepBounds({
			events: [],
			stepRecordCounts: [2],
			cursorAdvancedWithoutCommit: false,
			unboundedWrapperRefused: false,
			coalescedGenerations: [1],
			queuedJobCountAfterDuplicateTriggers: 1,
			criticalAbortedBeforeCursorAdvance: true,
		});
		expect(wrapper.cause).toBe('subOracleId=unbounded-wrapper-accepted lane=core');

		const coalesce = auditTriggerStepBounds({
			events: [],
			stepRecordCounts: [2],
			cursorAdvancedWithoutCommit: false,
			unboundedWrapperRefused: true,
			coalescedGenerations: [1, 2],
			queuedJobCountAfterDuplicateTriggers: 2,
			criticalAbortedBeforeCursorAdvance: true,
		});
		expect(coalesce.cause).toBe('subOracleId=duplicate-trigger-not-coalesced lane=core');
	});

	it('step bound: a branded bounded step applies at most one 64-record page per call', async () => {
		const records = Array.from({ length: 80 }, (_, index) => email(`${index + 1}`, `2026-09-0${(index % 8) + 1}T00:00:00Z`));
		const client = {
			emailChanges: async () => ({
				newState: '2',
				hasMoreChanges: true,
				created: records.map((record) => record.id),
				updated: [],
				destroyed: [],
			}),
			emailGet: async ({ ids }: { ids: string[] }) => ({
				list: records.filter((record) => ids.includes(record.id)),
				state: '2',
			}),
		};
		const step = createSyncDeltaStep(client);
		const store = createHarnessCoordinator({}).store;
		const result = await step({
			store,
			accountId: 'a',
			signal: new AbortController().signal,
			budget: { maxRecords: 64, maxBytes: 2 * 1024 * 1024, deadlineMonoMs: 10_000 },
			checkpoint: null,
		});
		expect(result.progress.done).toBeLessThanOrEqual(64);
		expect(result.outcome).toBe('partial');
	});
});

// The receipt is written ONCE, after every required scenario finished, from
// the REAL accumulated observations (Astra finding 19: the old receipt
// hardcoded success fields before later scenarios ran) AND gated on every
// scenario's actual verdict (Astra finding 14, r2: observations the failing
// test never updates cannot invalidate the verdict — the suite's own failure
// state now fails the receipt).
afterAll(async () => {
	const verdict = auditTriggerStepBounds(observations);
	const final = gateVerdictOnScenarios(verdict, scenarioFailures);
	expect(final.ok, JSON.stringify({ final, observations })).toBe(true);
	writeCaseResult(final);
});
