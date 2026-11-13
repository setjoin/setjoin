/**
 * CAS-E5-SAVE-ALL-PARTIAL / CAS-E5-SAVE-ALL-CANCEL-RETRY /
 * CAS-E5-GROUP-ANNOUNCER — E5 verification bindings (core lane, UI level).
 *
 * R4: Save all retains independent child identities and reports completed/
 * total plus failed/cancelled/expired children. Success requires EVERY
 * requested child complete. Cancel stops unfinished children without deleting
 * completed downloads; Retry selects only eligible failed children with
 * current authorization. Unknown child sizes make aggregate progress
 * indeterminate. ONE accessible group announcement replaces bursts, and
 * transfer progress announces 10% thresholds — never chunks.
 */

import { describe, it, expect, afterAll, afterEach } from 'vitest';
import { getCurrentTest } from 'vitest/suite';

import {
	auditE5GroupAnnouncer,
	auditE5SaveAllCancelRetry,
	auditE5SaveAllPartial,
	e5Failure,
	gateVerdictOnScenarios,
	scenarioFailed,
	writeCaseResult,
} from '$lib/native/testing/backgroundWorkHarness';
import {
	shouldAnnounceTransferProgress,
	summarizeSaveAll,
} from './e5.uiProjection';
import { createSaveAllGroup } from './e5SaveAll';

const scenarioFailures: string[] = [];
afterEach(() => {
	const task = getCurrentTest();
	const failure = scenarioFailed(task, task?.name ?? '');
	if (failure) scenarioFailures.push(failure);
});

describe('CAS-E5-SAVE-ALL-PARTIAL', () => {
	it('partial completion reports completed/total plus failed/cancelled/expired — never success', () => {
		const group = createSaveAllGroup('msg-1', ['a', 'b', 'c', 'd']);
		group.applyChild('a', { state: 'complete', committedBytes: 10, totalBytes: 10 });
		group.applyChild('b', { state: 'recoverableError', committedBytes: 4, totalBytes: 10 });
		group.applyChild('c', { state: 'transferring', committedBytes: 5, totalBytes: 10 });
		const summary = group.summary();
		expect(summary.total).toBe(4);
		expect(summary.completed).toBe(1);
		expect(summary.failed).toBe(1);
		expect(summary.cancelled).toBe(0);
		expect(summary.expired).toBe(0);
		expect(summary.active).toBe(2); // one transferring + one still queued
		// Success requires EVERY requested child complete — 1/4 is not success.
		expect(summary.allComplete).toBe(false);

		const verdict = auditE5SaveAllPartial({
			summary,
			partialNotSuccess: summary.completed < summary.total && summary.allComplete === false,
			unknownSizesIndeterminate: true,
		});
		expect(verdict.ok, JSON.stringify(verdict)).toBe(true);
	});

	it('unknown child sizes make aggregate progress genuinely indeterminate', () => {
		const summary = summarizeSaveAll([
			{ id: 'a', state: 'complete', committedBytes: 10, totalBytes: 10 },
			{ id: 'b', state: 'transferring', committedBytes: 3 },
		]);
		expect(summary.indeterminate).toBe(true);
		expect(summary.bytes.total).toBeUndefined();
		expect(summary.bytes.done).toBe(13);
		const determinate = summarizeSaveAll([
			{ id: 'a', state: 'complete', committedBytes: 10, totalBytes: 10 },
		]);
		expect(determinate.indeterminate).toBe(false);
		expect(determinate.bytes.total).toBe(10);
	});

	it('planted fault: partial-as-success emits the pinned FAIL text', () => {
		const pinned = e5Failure('CAS-E5-SAVE-ALL-PARTIAL', 'probe');
		expect(pinned.fail).toBe(
			'FAIL CAS-E5-SAVE-ALL-PARTIAL: save-all group misreported partial progress as success',
		);
		const verdict = auditE5SaveAllPartial({
			summary: { total: 2, completed: 1, failed: 0, cancelled: 0, expired: 0, allComplete: true, indeterminate: false },
			partialNotSuccess: false,
			unknownSizesIndeterminate: true,
		});
		expect(verdict.ok).toBe(false);
		expect(verdict.fail).toBe(pinned.fail);
		expect(verdict.cause).toBe('subOracleId=partial-reported-success lane=core');
	});

	afterAll(async () => {
		const group = createSaveAllGroup('msg-receipt-partial', ['a', 'b']);
		group.applyChild('a', { state: 'complete', committedBytes: 1, totalBytes: 1 });
		const summary = group.summary();
		const final = gateVerdictOnScenarios(
			auditE5SaveAllPartial({
				summary,
				partialNotSuccess: summary.completed < summary.total && summary.allComplete === false,
				unknownSizesIndeterminate: summarizeSaveAll([{ id: 'x', state: 'transferring', committedBytes: 1 }]).indeterminate,
			}),
			scenarioFailures,
		);
		expect(final.ok, JSON.stringify({ final, scenarioFailures })).toBe(true);
		writeCaseResult(final);
	});
});

describe('CAS-E5-SAVE-ALL-CANCEL-RETRY', () => {
	it('cancel stops unfinished children and preserves completed downloads', () => {
		const group = createSaveAllGroup('msg-2', ['a', 'b', 'c', 'd']);
		group.applyChild('a', { state: 'complete', committedBytes: 10, totalBytes: 10 });
		group.applyChild('b', { state: 'transferring', committedBytes: 2, totalBytes: 10 });
		const plan = group.cancelPlan();
		expect(plan.preserved).toEqual(['a']);
		expect(plan.toCancel.sort()).toEqual(['b', 'c', 'd'].sort());
	});

	it('retry selects ONLY eligible failed children (never unavailable/cancelled/verification)', () => {
		const group = createSaveAllGroup('msg-3', ['ok', 'recoverable', 'expired', 'unavailable', 'cancelled', 'verification']);
		group.applyChild('ok', { state: 'complete', committedBytes: 1, totalBytes: 1 });
		group.applyChild('recoverable', { state: 'recoverableError' });
		group.applyChild('expired', { state: 'downloadExpired' });
		group.applyChild('unavailable', { state: 'contentUnavailable' });
		group.applyChild('cancelled', { state: 'cancelled' });
		group.applyChild('verification', { state: 'verificationFailed' });
		const retryIds = group.retryIds().sort();
		// Recoverable errors retry; expired carries a newly authorized restart;
		// unavailable never retries (R4); cancelled stays until re-requested;
		// verification failure needs an explicit fresh download.
		expect(retryIds).toEqual(['expired', 'recoverable']);
	});

	it('planted fault: ineligible retry selection emits the pinned FAIL text', () => {
		const pinned = e5Failure('CAS-E5-SAVE-ALL-CANCEL-RETRY', 'probe');
		expect(pinned.fail).toBe(
			'FAIL CAS-E5-SAVE-ALL-CANCEL-RETRY: save-all cancel/retry escaped the eligible-child contract',
		);
		const verdict = auditE5SaveAllCancelRetry({
			cancelPlan: { toCancel: ['b'], preserved: ['a'] },
			retryIds: ['unavailable'],
			retryOnlyEligible: false,
			cancelPreservesCompleted: true,
		});
		expect(verdict.ok).toBe(false);
		expect(verdict.fail).toBe(pinned.fail);
		expect(verdict.cause).toBe('subOracleId=retry-selected-ineligible lane=core');

		const deletesCompleted = auditE5SaveAllCancelRetry({
			cancelPlan: { toCancel: ['a'], preserved: [] },
			retryIds: [],
			retryOnlyEligible: true,
			cancelPreservesCompleted: false,
		});
		expect(deletesCompleted.cause).toBe('subOracleId=cancel-deleted-completed lane=core');
		expect(deletesCompleted.cause).not.toBe(verdict.cause);
	});

	afterAll(async () => {
		const group = createSaveAllGroup('msg-receipt-cancel', ['a', 'b', 'c']);
		group.applyChild('a', { state: 'complete', committedBytes: 1, totalBytes: 1 });
		group.applyChild('b', { state: 'recoverableError' });
		const plan = group.cancelPlan();
		const retryIds = group.retryIds();
		const final = gateVerdictOnScenarios(
			auditE5SaveAllCancelRetry({
				cancelPlan: plan,
				retryIds,
				retryOnlyEligible: retryIds.every((id) => id === 'b'),
				cancelPreservesCompleted: plan.preserved.includes('a') && !plan.toCancel.includes('a'),
			}),
			scenarioFailures,
		);
		expect(final.ok, JSON.stringify({ final, scenarioFailures })).toBe(true);
		writeCaseResult(final);
	});
});

describe('CAS-E5-GROUP-ANNOUNCER', () => {
	it('ONE group announcement replaces the per-child burst (batch, then announce once)', async () => {
		const { e5ui } = await import('./e5ui.svelte');
		e5ui.__resetForTests();
		e5ui.createSaveAllGroup('msg-announcer', ['a', 'b', 'c']);
		// Three children settle — the per-child ticks never announce by
		// themselves; the caller settles the batch and announces ONCE.
		const childStates = [
			['a', 'complete'],
			['b', 'complete'],
			['c', 'recoverableError'],
		] as const;
		for (const [id, state] of childStates) {
			e5ui.applySaveAllChild('msg-announcer', id, { state, committedBytes: 1, totalBytes: 1 });
		}
		const seqBefore = e5ui.announcement?.seq ?? 0;
		e5ui.announceSaveAllGroup('msg-announcer');
		expect(e5ui.announcement?.seq).toBe(seqBefore + 1);
		expect(e5ui.announcement?.key).toBe('offline.e5.saveall.announce');
		expect(e5ui.announcement?.params).toMatchObject({ completed: '2', total: '3', failed: '1' });

		const verdict = auditE5GroupAnnouncer({
			announcementCount: 1,
			changedChildren: childStates.length,
			intraBandChunkAnnounced: false,
			phaseChangeAnnounced: true,
		});
		expect(verdict.ok, JSON.stringify(verdict)).toBe(true);

		// 10% thresholds: intra-band movement never announces; band crossings
		// and phase changes do.
		expect(shouldAnnounceTransferProgress(41, 49)).toBe(false);
		expect(shouldAnnounceTransferProgress(49, 51)).toBe(true);
		expect(shouldAnnounceTransferProgress(null, 0)).toBe(true);
		expect(shouldAnnounceTransferProgress(95, 100)).toBe(true);
	});

	it('planted fault: per-chunk or burst announcing emits the pinned FAIL text', () => {
		const pinned = e5Failure('CAS-E5-GROUP-ANNOUNCER', 'probe');
		expect(pinned.fail).toBe(
			'FAIL CAS-E5-GROUP-ANNOUNCER: group announcer burst or announced per-chunk noise',
		);
		const burst = auditE5GroupAnnouncer({
			announcementCount: 3,
			changedChildren: 3,
			intraBandChunkAnnounced: false,
			phaseChangeAnnounced: true,
		});
		expect(burst.ok).toBe(false);
		expect(burst.fail).toBe(pinned.fail);
		expect(burst.cause).toBe('subOracleId=burst-announcements lane=core');

		const chunky = auditE5GroupAnnouncer({
			announcementCount: 1,
			changedChildren: 1,
			intraBandChunkAnnounced: true,
			phaseChangeAnnounced: true,
		});
		expect(chunky.cause).toBe('subOracleId=per-chunk-announced lane=core');
		expect(chunky.cause).not.toBe(burst.cause);

		const silentPhase = auditE5GroupAnnouncer({
			announcementCount: 1,
			changedChildren: 1,
			intraBandChunkAnnounced: false,
			phaseChangeAnnounced: false,
		});
		expect(silentPhase.cause).toBe('subOracleId=phase-change-silent lane=core');
	});

	afterAll(async () => {
		const final = gateVerdictOnScenarios(
			auditE5GroupAnnouncer({
				announcementCount: 1,
				changedChildren: 3,
				intraBandChunkAnnounced: shouldAnnounceTransferProgress(41, 49),
				phaseChangeAnnounced: shouldAnnounceTransferProgress(null, 0),
			}),
			scenarioFailures,
		);
		expect(final.ok, JSON.stringify({ final, scenarioFailures })).toBe(true);
		writeCaseResult(final);
	});
});
