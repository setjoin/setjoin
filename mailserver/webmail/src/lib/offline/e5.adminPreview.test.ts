/**
 * CAS-E5-PREVIEW-TARGET-RACE / CAS-E5-PREVIEW-UNAVAILABLE — E5 verification
 * bindings (core lane, UI level).
 *
 * R4 settings/admin amendments: the admin preview binds every response to the
 * selected target AND the request generation — old responses cannot replace a
 * newer selection; failed refresh labels retained facts stale;
 * loading/unavailable/unauthorized/current are honest states; malformed
 * payloads are refused; disabled winning policies stay visible.
 */

import { describe, it, expect, afterAll, afterEach } from 'vitest';
import { getCurrentTest } from 'vitest/suite';

import {
	auditE5PreviewTargetRace,
	auditE5PreviewUnavailable,
	e5Failure,
	gateVerdictOnScenarios,
	scenarioFailed,
	writeCaseResult,
} from '$lib/native/testing/backgroundWorkHarness';
import {
	createAdminPreviewController,
	parsePreviewEnvelope,
	parsePreviewProjection,
} from './e5AdminPreview';

const scenarioFailures: string[] = [];
afterEach(() => {
	const task = getCurrentTest();
	const failure = scenarioFailed(task, task?.name ?? '');
	if (failure) scenarioFailures.push(failure);
});

function envelopeFor(deviceId: string, overrides: Record<string, unknown> = {}): unknown {
	return {
		mailboxId: '42',
		deviceId,
		projection: {
			allowed: true,
			approvalState: 'approved',
			maxOfflineDays: 30,
			wipeOnLogout: 'admin_default',
			requireApproval: false,
			syncQoS: {
				schemaVersion: 1,
				mode: 'execute',
				backgroundAllowed: true,
				requested: { automaticNetwork: 'any', attachmentPrefetch: 'unmetered' },
				effective: { automaticNetwork: 'unmetered', attachmentPrefetch: 'never', opportunisticRequiresCharging: true },
				sources: {
					automaticNetwork: { policyId: 'pol-7', scope: 'group' },
					attachmentPrefetch: {},
				},
			},
			...overrides,
		},
	};
}

describe('CAS-E5-PREVIEW-TARGET-RACE', () => {
	it('an old-generation response can never replace a newer selection', () => {
		const controller = createAdminPreviewController();
		controller.selectTarget({ targetUserId: 'u-1', deviceId: 'dev-1' });
		const oldGeneration = controller.generation;

		// The admin re-selects before the first response lands.
		controller.selectTarget({ targetUserId: 'u-2', deviceId: 'dev-2' });
		const newGeneration = controller.generation;
		expect(newGeneration).toBe(oldGeneration + 1);

		// The FIRST (now stale) response arrives — it must be refused.
		const stale = controller.loaded(oldGeneration, envelopeFor('dev-1'));
		expect(stale.kind).toBe('stale-generation');
		expect(controller.status().kind).toBe('loading');

		// The CURRENT response applies.
		const current = controller.loaded(newGeneration, envelopeFor('dev-2'));
		expect(current.kind).toBe('applied');
		expect(controller.status().kind).toBe('current');
	});

	it('a response whose device identity does not match the selected target is refused', () => {
		const controller = createAdminPreviewController();
		controller.selectTarget({ targetUserId: 'u-1', deviceId: 'dev-A' });
		const generation = controller.generation;
		// Cross-identity substitution attempt: payload bound to another device.
		const mismatch = controller.loaded(generation, envelopeFor('dev-B'));
		expect(mismatch.kind).toBe('target-mismatch');
		expect(controller.status().kind).toBe('loading');
	});

	it('planted faults emit the pinned FAIL text with distinct finite causes', () => {
		const pinned = e5Failure('CAS-E5-PREVIEW-TARGET-RACE', 'probe');
		expect(pinned.fail).toBe(
			'FAIL CAS-E5-PREVIEW-TARGET-RACE: a stale preview response replaced a newer selection',
		);
		const staleApplied = auditE5PreviewTargetRace({ oldGenerationRejected: false, mismatchedTargetRejected: true });
		expect(staleApplied.ok).toBe(false);
		expect(staleApplied.fail).toBe(pinned.fail);
		expect(staleApplied.cause).toBe('subOracleId=old-generation-applied lane=core');

		const foreignApplied = auditE5PreviewTargetRace({ oldGenerationRejected: true, mismatchedTargetRejected: false });
		expect(foreignApplied.cause).toBe('subOracleId=foreign-target-applied lane=core');
		expect(foreignApplied.cause).not.toBe(staleApplied.cause);
	});

	afterAll(async () => {
		const final = gateVerdictOnScenarios(
			auditE5PreviewTargetRace({ oldGenerationRejected: true, mismatchedTargetRejected: true }),
			scenarioFailures,
		);
		expect(final.ok, JSON.stringify({ final, scenarioFailures })).toBe(true);
		writeCaseResult(final);
	});
});

describe('CAS-E5-PREVIEW-UNAVAILABLE', () => {
	it('failed refresh labels retained facts stale; unauthorized vs unavailable are distinct', () => {
		const controller = createAdminPreviewController();
		controller.selectTarget({ targetUserId: 'u-1', deviceId: 'dev-1' });
		const generation = controller.generation;
		expect(controller.loaded(generation, envelopeFor('dev-1')).kind).toBe('applied');

		// A background refresh fails with a permission error: retained facts
		// stay visible but clearly labeled stale; focus is never stolen.
		controller.selectTarget({ targetUserId: 'u-1', deviceId: 'dev-1' }); // same target → refresh generation
		const refreshGeneration = controller.generation;
		controller.failed(refreshGeneration, { forbidden: true });
		const status = controller.status();
		expect(status.kind).toBe('unauthorized');
		if (status.kind === 'unauthorized') {
			expect(status.stale).toBe(true);
			expect(status.retained).not.toBeNull();
		}

		// A non-permission failure is UNAVAILABLE, never silent success.
		const controller2 = createAdminPreviewController();
		controller2.selectTarget({ targetUserId: 'u-1', deviceId: 'dev-1' });
		controller2.failed(controller2.generation, { forbidden: false });
		expect(controller2.status().kind).toBe('unavailable');
		const freshStatus = controller2.status();
		if (freshStatus.kind === 'unavailable') expect(freshStatus.stale).toBe(false); // nothing retained yet
	});

	it('malformed payloads are refused and disabled winning policies stay visible', () => {
		const controller = createAdminPreviewController();
		controller.selectTarget({ targetUserId: 'u-1', deviceId: 'dev-1' });
		const generation = controller.generation;
		// Malformed / forged shapes fail closed at the controller boundary.
		expect(controller.loaded(generation, { garbage: true })).toMatchObject({ kind: 'malformed' });
		expect(controller.status().kind).toBe('loading');

		// The parser keeps a DISABLED winning policy visible — enablement never
		// filters the source facts away.
		const disabled = parsePreviewEnvelope(envelopeFor('dev-1', {
			syncQoS: {
				schemaVersion: 1,
				mode: 'off',
				backgroundAllowed: false,
				requested: { automaticNetwork: 'unmetered', attachmentPrefetch: 'never' },
				effective: { automaticNetwork: 'unmetered', attachmentPrefetch: 'never', opportunisticRequiresCharging: true },
				sources: { automaticNetwork: { policyId: 'disabled-pol', scope: 'user' } },
			},
		}));
		expect(disabled).not.toBeNull();
		expect(disabled?.projection.syncMode).toBe('off');
		expect(disabled?.projection.sources.automaticNetwork?.policyId).toBe('disabled-pol');

		// Strict refusal of unknown/ahead versions and partial envelopes.
		expect(parsePreviewProjection({ syncQoS: { schemaVersion: 9 } })).toBeNull();
		expect(parsePreviewEnvelope({ mailboxId: 'x' })).toBeNull();
		expect(parsePreviewEnvelope(null)).toBeNull();
	});

	it('planted faults emit the pinned FAIL text with distinct finite causes', () => {
		const pinned = e5Failure('CAS-E5-PREVIEW-UNAVAILABLE', 'probe');
		expect(pinned.fail).toBe(
			'FAIL CAS-E5-PREVIEW-UNAVAILABLE: preview failure was displayed as success or current facts',
		);
		const shownCurrent = auditE5PreviewUnavailable({
			unavailableLabeled: false,
			unauthorizedLabeled: true,
			retainedLabeledStale: true,
			malformedRefused: true,
		});
		expect(shownCurrent.ok).toBe(false);
		expect(shownCurrent.fail).toBe(pinned.fail);
		expect(shownCurrent.cause).toBe('subOracleId=unavailable-shown-current lane=core');

		const freshRetained = auditE5PreviewUnavailable({
			unavailableLabeled: true,
			unauthorizedLabeled: true,
			retainedLabeledStale: false,
			malformedRefused: true,
		});
		expect(freshRetained.cause).toBe('subOracleId=retained-shown-fresh lane=core');
		expect(freshRetained.cause).not.toBe(shownCurrent.cause);
	});

	afterAll(async () => {
		const parser = parsePreviewEnvelope(envelopeFor('dev-1', {
			syncQoS: {
				schemaVersion: 1,
				mode: 'off',
				backgroundAllowed: false,
				requested: { automaticNetwork: 'unmetered', attachmentPrefetch: 'never' },
				effective: { automaticNetwork: 'unmetered', attachmentPrefetch: 'never', opportunisticRequiresCharging: true },
				sources: { automaticNetwork: { policyId: 'disabled-pol', scope: 'user' } },
			},
		}));
		const disabledPolicyVisible = parser !== null
			&& parser.projection.sources.automaticNetwork?.policyId === 'disabled-pol'
			&& parser.projection.syncMode === 'off';
		const malformedRefused = parsePreviewEnvelope(null) === null
			&& parsePreviewEnvelope({ mailboxId: 'x' }) === null
			&& parsePreviewProjection({ syncQoS: { schemaVersion: 9 } }) === null;
		const final = gateVerdictOnScenarios(
			auditE5PreviewUnavailable({
				unavailableLabeled: true,
				unauthorizedLabeled: true,
				retainedLabeledStale: true,
				malformedRefused: malformedRefused && disabledPolicyVisible,
			}),
			scenarioFailures,
		);
		expect(final.ok, JSON.stringify({ final, scenarioFailures })).toBe(true);
		writeCaseResult(final);
	});
});
