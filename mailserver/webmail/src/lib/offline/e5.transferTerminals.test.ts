/**
 * CAS-E5-TRANSFER-TERMINALS — E5 verification binding (core lane, UI level).
 *
 * R4 "E5 complete states": terminal transfer expiry displays "Download
 * expired" with a newly authorized restart; authorized content-unavailable
 * classification displays "Attachment unavailable" WITHOUT retry; integrity
 * failure displays "Verification failed" WITHOUT Open/Save. Pause reasons
 * travel VERBATIM — one distinct key per contract PauseReason, no collapsing.
 * These are UI mappings, not new E3 states.
 */

import { describe, it, expect, afterAll, afterEach } from 'vitest';
import { getCurrentTest } from 'vitest/suite';

import {
	auditE5TransferTerminals,
	e5Failure,
	gateVerdictOnScenarios,
	scenarioFailed,
	writeCaseResult,
} from '$lib/native/testing/backgroundWorkHarness';
import {
	E5_PAUSE_REASON_KEYS,
	e5TransferDisplay,
	pauseReasonKey,
	transferRowStateForPause,
} from './e5.uiProjection';
import { PAUSE_REASONS } from './work-contract';

const scenarioFailures: string[] = [];
afterEach(() => {
	const task = getCurrentTest();
	const failure = scenarioFailed(task, task?.name ?? '');
	if (failure) scenarioFailures.push(failure);
});

describe('CAS-E5-TRANSFER-TERMINALS', () => {
	it('terminal expiry displays "Download expired" with a newly authorized restart', () => {
		const display = e5TransferDisplay({ state: 'downloadExpired' });
		expect(display.key).toBe('offline.e5.transfer.download_expired');
		expect(display.actions.retry).toBe(true);
		expect(display.actions.open).toBe(false);
		expect(display.actions.save).toBe(false);
	});

	it('authorized content-unavailable displays "Attachment unavailable" without retry', () => {
		const display = e5TransferDisplay({ state: 'contentUnavailable' });
		expect(display.key).toBe('offline.e5.transfer.content_unavailable');
		expect(display.actions.retry).toBe(false);
		expect(display.actions.cancel).toBe(false);
		expect(display.actions.open).toBe(false);
		expect(display.actions.save).toBe(false);
	});

	it('integrity failure displays "Verification failed" without Open/Save (alert-worthy)', () => {
		const display = e5TransferDisplay({ state: 'verificationFailed' });
		expect(display.key).toBe('offline.e5.transfer.verification_failed');
		expect(display.actions.open).toBe(false);
		expect(display.actions.save).toBe(false);
		expect(display.actions.retry).toBe(false);
		// Unverified bytes are never offered; this is the one terminal that is
		// user-action-required (role=alert reserved for it, Pass 5).
		expect(display.alert).toBe(true);
	});

	it('paused reasons are preserved verbatim: one distinct key per contract reason', () => {
		const keys = PAUSE_REASONS.map(pauseReasonKey);
		expect(keys).toEqual(E5_PAUSE_REASON_KEYS);
		expect(new Set(keys).size).toBe(keys.length);
		for (const key of keys) expect(key.startsWith('offline.e5.pause.')).toBe(true);

		// Every scheduler pause maps onto the matching transfer row state with
		// the SAME reason attached (verbatim travel through the chain).
		for (const reason of PAUSE_REASONS) {
			const rowState = transferRowStateForPause(reason);
			const display = e5TransferDisplay({ state: rowState, pauseReason: reason });
			expect(display.pauseReasonKey).toBe(pauseReasonKey(reason));
		}
		// Network-class reasons wait; resource-class reasons pause; a changed
		// validator announces a safe restart — never a silent rewind.
		expect(transferRowStateForPause('meteredNetwork')).toBe('waitingForNetwork');
		expect(transferRowStateForPause('thermal')).toBe('resourcePaused');
		expect(transferRowStateForPause('validatorChanged')).toBe('validatorRestart');
	});

	it('active rows keep resumable/cancellable actions; complete offers Open/Save only', () => {
		const waiting = e5TransferDisplay({ state: 'waitingForNetwork', pauseReason: 'meteredNetwork' });
		expect(waiting.actions.resume).toBe(true);
		expect(waiting.actions.cancel).toBe(true);
		const complete = e5TransferDisplay({ state: 'complete' });
		expect(complete.actions.open).toBe(true);
		expect(complete.actions.save).toBe(true);
		expect(complete.actions.retry).toBe(false);
		// Unknown totals stay indeterminate on the row.
		const indeterminate = e5TransferDisplay({ state: 'transferring', committedBytes: 1024 });
		expect(indeterminate.progress).toEqual({ done: 1024 });
	});

	it('planted faults produce the pinned FAIL text with distinct finite causes', () => {
		const pinned = e5Failure('CAS-E5-TRANSFER-TERMINALS', 'probe');
		expect(pinned.fail).toBe(
			'FAIL CAS-E5-TRANSFER-TERMINALS: transfer terminal display offered a prohibited action',
		);

		const badUnavailable = auditE5TransferTerminals({
			expiredKey: 'offline.e5.transfer.download_expired',
			unavailableKey: 'offline.e5.transfer.content_unavailable',
			verificationFailedKey: 'offline.e5.transfer.verification_failed',
			expiredOffersAuthorizedRestart: true,
			unavailableOffersNoRetry: false,
			verificationFailedOffersNoOpenSave: true,
			pauseReasonKeyCount: PAUSE_REASONS.length,
			pauseReasonKeyDistinct: true,
		});
		expect(badUnavailable.ok).toBe(false);
		expect(badUnavailable.fail).toBe(pinned.fail);
		expect(badUnavailable.cause).toBe('subOracleId=unavailable-offered-retry lane=core');

		const badVerification = auditE5TransferTerminals({
			expiredKey: 'offline.e5.transfer.download_expired',
			unavailableKey: 'offline.e5.transfer.content_unavailable',
			verificationFailedKey: 'offline.e5.transfer.verification_failed',
			expiredOffersAuthorizedRestart: true,
			unavailableOffersNoRetry: true,
			verificationFailedOffersNoOpenSave: false,
			pauseReasonKeyCount: PAUSE_REASONS.length,
			pauseReasonKeyDistinct: true,
		});
		expect(badVerification.cause).toBe('subOracleId=verification-offered-open-save lane=core');
		expect(badVerification.cause).not.toBe(badUnavailable.cause);

		const collapsedReasons = auditE5TransferTerminals({
			expiredKey: 'offline.e5.transfer.download_expired',
			unavailableKey: 'offline.e5.transfer.content_unavailable',
			verificationFailedKey: 'offline.e5.transfer.verification_failed',
			expiredOffersAuthorizedRestart: true,
			unavailableOffersNoRetry: true,
			verificationFailedOffersNoOpenSave: true,
			pauseReasonKeyCount: 1,
			pauseReasonKeyDistinct: false,
		});
		expect(collapsedReasons.cause).toBe('subOracleId=pause-reasons-collapsed lane=core');
	});

	afterAll(async () => {
		const expired = e5TransferDisplay({ state: 'downloadExpired' });
		const unavailable = e5TransferDisplay({ state: 'contentUnavailable' });
		const verification = e5TransferDisplay({ state: 'verificationFailed' });
		const keys = PAUSE_REASONS.map(pauseReasonKey);
		const final = gateVerdictOnScenarios(
			auditE5TransferTerminals({
				expiredKey: expired.key,
				unavailableKey: unavailable.key,
				verificationFailedKey: verification.key,
				expiredOffersAuthorizedRestart: expired.actions.retry && !expired.actions.open && !expired.actions.save,
				unavailableOffersNoRetry: !unavailable.actions.retry,
				verificationFailedOffersNoOpenSave: !verification.actions.open && !verification.actions.save,
				pauseReasonKeyCount: keys.length,
				pauseReasonKeyDistinct: new Set(keys).size === keys.length,
			}),
			scenarioFailures,
		);
		expect(final.ok, JSON.stringify({ final, scenarioFailures })).toBe(true);
		writeCaseResult(final);
	});
});
