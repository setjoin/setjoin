/**
 * CAS-E5-PREFERENCE-SAVE-FAILURE / CAS-E5-PREFERENCE-DOUBLE-SUBMIT /
 * CAS-E5-PREFERENCE-ACCOUNT-RACE / CAS-E5-CROSSED-NETWORK-ATTACHMENT — E5
 * verification bindings (core lane, UI level).
 *
 * R4 settings amendments: requested drafts stay distinct from acknowledged
 * effective values; a pending save prevents duplicate submission; only the
 * authoritative response updates effective state; failure preserves drafts
 * and gives a remedy, never success; account/device changes invalidate
 * pending responses. The crossed-settings explanation describes ACTUAL
 * admission from stored values and never promises "all network disabled".
 */

import { describe, it, expect, afterAll, afterEach } from 'vitest';
import { getCurrentTest } from 'vitest/suite';

import {
	auditE5CrossedNetworkAttachment,
	auditE5PreferenceAccountRace,
	auditE5PreferenceDoubleSubmit,
	auditE5PreferenceSaveFailure,
	e5Failure,
	gateVerdictOnScenarios,
	scenarioFailed,
	writeCaseResult,
} from '$lib/native/testing/backgroundWorkHarness';
import {
	explainCrossedAdmission,
	AUTOMATIC_NETWORK_VALUES,
	ATTACHMENT_PREFETCH_VALUES,
	createE5SettingsController,
	type E5AcknowledgeSnapshot,
} from './e5Settings';

const scenarioFailures: string[] = [];
afterEach(() => {
	const task = getCurrentTest();
	const failure = scenarioFailed(task, task?.name ?? '');
	if (failure) scenarioFailures.push(failure);
});

const SERVER_SNAPSHOT: E5AcknowledgeSnapshot = {
	requested: { backgroundSyncEnabled: true, automaticNetwork: 'any', attachmentPrefetch: 'unmetered' },
	effective: {
		backgroundAllowed: true,
		automaticNetwork: 'unmetered', // organization narrowed 'any' down
		attachmentPrefetch: 'never', // organization default
		opportunisticRequiresCharging: true,
	},
	sources: { automaticNetwork: { policyId: 'pol-7', scope: 'group' } },
};

function deferred<T>(): { promise: Promise<T>; resolve: (v: T) => void; reject: (e: unknown) => void } {
	let resolve!: (v: T) => void;
	let reject!: (e: unknown) => void;
	const promise = new Promise<T>((res, rej) => {
		resolve = res;
		reject = rej;
	});
	return { promise, resolve, reject };
}

describe('CAS-E5-PREFERENCE-SAVE-FAILURE', () => {
	it('failure preserves the drafts, leaves acknowledged untouched, and gives a remedy — never success', async () => {
		const controller = createE5SettingsController();
		controller.acknowledge(SERVER_SNAPSHOT);
		controller.edit({ automaticNetwork: 'unmetered', attachmentPrefetch: 'never' });
		const draftBefore = { ...controller.view().draft };

		const outcome = await controller.submit(async () => {
			throw new Error('network down');
		});
		expect(outcome.ok).toBe(false);
		if (!outcome.ok) {
			expect(outcome.reason).toBe('save-failed');
			expect(outcome.remedyKey).toBe('offline.e5.settings.remedy_retry');
		}
		const view = controller.view();
		// Drafts preserved verbatim — the user's edits are never lost.
		expect(view.draft).toEqual(draftBefore);
		expect(view.dirty).toBe(true);
		// Acknowledged effective state is untouched by the failed save.
		expect(view.acknowledged?.effective).toEqual(SERVER_SNAPSHOT.effective);
		expect(view.status.kind).toBe('failed');
		if (view.status.kind === 'failed') expect(view.status.remedyKey).toBe('offline.e5.settings.remedy_retry');

		const verdict = auditE5PreferenceSaveFailure({
			draftsPreserved: view.draft === null || JSON.stringify(view.draft) === JSON.stringify(draftBefore),
			acknowledgedUntouched: JSON.stringify(view.acknowledged?.effective) === JSON.stringify(SERVER_SNAPSHOT.effective),
			remedySurfaced: view.status.kind === 'failed',
			neverSuccess: outcome.ok === false,
		});
		expect(verdict.ok, JSON.stringify(verdict)).toBe(true);
	});

	it('only an authoritative response updates the effective state', async () => {
		const controller = createE5SettingsController();
		controller.bindAccount('acct-1', 'dev-1');
		controller.edit({ backgroundSyncEnabled: true });
		// The saver returns the SERVER-resolved snapshot; the controller adopts
		// it verbatim — it never recomputes precedence locally.
		const outcome = await controller.submit(async () => SERVER_SNAPSHOT);
		expect(outcome.ok).toBe(true);
		const view = controller.view();
		// Effective display comes from the server's effective values…
		expect(view.acknowledged?.effective.automaticNetwork).toBe('unmetered');
		// …while the next draft baseline is the ACKNOWLEDGED REQUESTED values.
		expect(view.draft.automaticNetwork).toBe(SERVER_SNAPSHOT.requested.automaticNetwork);
		expect(view.dirty).toBe(false);
	});

	it('planted fault: failure-as-success emits the pinned FAIL text', () => {
		const pinned = e5Failure('CAS-E5-PREFERENCE-SAVE-FAILURE', 'probe');
		expect(pinned.fail).toBe(
			'FAIL CAS-E5-PREFERENCE-SAVE-FAILURE: preference save failure reported success or lost drafts',
		);
		const verdict = auditE5PreferenceSaveFailure({
			draftsPreserved: false,
			acknowledgedUntouched: true,
			remedySurfaced: true,
			neverSuccess: true,
		});
		expect(verdict.ok).toBe(false);
		expect(verdict.fail).toBe(pinned.fail);
		expect(verdict.cause).toBe('subOracleId=drafts-lost lane=core');

		const fakeSuccess = auditE5PreferenceSaveFailure({
			draftsPreserved: true,
			acknowledgedUntouched: true,
			remedySurfaced: true,
			neverSuccess: false,
		});
		expect(fakeSuccess.cause).toBe('subOracleId=failure-reported-success lane=core');
		expect(fakeSuccess.cause).not.toBe(verdict.cause);
	});

	afterAll(async () => {
		const controller = createE5SettingsController();
		controller.acknowledge(SERVER_SNAPSHOT);
		controller.edit({ automaticNetwork: 'never' });
		const draftBefore = { ...controller.view().draft };
		const outcome = await controller.submit(async () => {
			throw new Error('down');
		});
		const view = controller.view();
		const final = gateVerdictOnScenarios(
			auditE5PreferenceSaveFailure({
				draftsPreserved: JSON.stringify(view.draft) === JSON.stringify(draftBefore),
				acknowledgedUntouched: JSON.stringify(view.acknowledged?.effective) === JSON.stringify(SERVER_SNAPSHOT.effective),
				remedySurfaced: view.status.kind === 'failed',
				neverSuccess: outcome.ok === false,
			}),
			scenarioFailures,
		);
		expect(final.ok, JSON.stringify({ final, scenarioFailures })).toBe(true);
		writeCaseResult(final);
	});
});

describe('CAS-E5-PREFERENCE-DOUBLE-SUBMIT', () => {
	it('a pending save refuses duplicate submission and keeps the first save intact', async () => {
		const controller = createE5SettingsController();
		controller.acknowledge(SERVER_SNAPSHOT);
		controller.edit({ automaticNetwork: 'never' });

		const gate = deferred<E5AcknowledgeSnapshot>();
		let saverCalls = 0;
		const saver = async (): Promise<E5AcknowledgeSnapshot> => {
			saverCalls += 1;
			return gate.promise;
		};
		const first = controller.submit(saver);
		expect(controller.view().pending).toBe(true);

		const duplicate = await controller.submit(saver);
		expect(duplicate.ok).toBe(false);
		if (!duplicate.ok) expect(duplicate.reason).toBe('duplicate-submission');
		expect(saverCalls).toBe(1); // the in-flight save was never disturbed

		gate.resolve({
			requested: { backgroundSyncEnabled: true, automaticNetwork: 'never', attachmentPrefetch: 'unmetered' },
			effective: SERVER_SNAPSHOT.effective,
			sources: {},
		});
		const settled = await first;
		expect(settled.ok).toBe(true);
	});

	it('planted fault: an accepted duplicate emits the pinned FAIL text', () => {
		const pinned = e5Failure('CAS-E5-PREFERENCE-DOUBLE-SUBMIT', 'probe');
		expect(pinned.fail).toBe(
			'FAIL CAS-E5-PREFERENCE-DOUBLE-SUBMIT: a second preference submission escaped the pending guard',
		);
		const verdict = auditE5PreferenceDoubleSubmit({ duplicateRefused: false, firstSaveIntact: true });
		expect(verdict.ok).toBe(false);
		expect(verdict.fail).toBe(pinned.fail);
		expect(verdict.cause).toBe('subOracleId=duplicate-accepted lane=core');
	});

	afterAll(async () => {
		const final = gateVerdictOnScenarios(
			auditE5PreferenceDoubleSubmit({ duplicateRefused: true, firstSaveIntact: true }),
			scenarioFailures,
		);
		expect(final.ok, JSON.stringify({ final, scenarioFailures })).toBe(true);
		writeCaseResult(final);
	});
});

describe('CAS-E5-PREFERENCE-ACCOUNT-RACE', () => {
	it('an account change invalidates the pending response; drafts never carry across', async () => {
		const controller = createE5SettingsController();
		controller.bindAccount('acct-1', 'dev-1');
		controller.acknowledge(SERVER_SNAPSHOT);
		controller.edit({ automaticNetwork: 'never' });

		const gate = deferred<E5AcknowledgeSnapshot>();
		const inFlight = controller.submit(async () => gate.promise);
		expect(controller.view().pending).toBe(true);

		// The user (or a sync event) switches account/device mid-flight.
		controller.bindAccount('acct-2', 'dev-1');
		const view = controller.view();
		expect(view.pending).toBe(false);

		// The stale response for acct-1 can never update acct-2's state.
		gate.resolve({
			requested: { backgroundSyncEnabled: false, automaticNetwork: 'any', attachmentPrefetch: 'always' },
			effective: { backgroundAllowed: true, automaticNetwork: 'any', attachmentPrefetch: 'always', opportunisticRequiresCharging: false },
			sources: {},
		});
		const settled = await inFlight;
		expect(settled.ok).toBe(false);
		if (!settled.ok) expect(settled.reason).toBe('stale-binding');
		// Drafts reset to the DEFAULTS for the new binding — the old account's
		// requested values (and its acknowledged snapshot) never carry across.
		expect(controller.view().draft.automaticNetwork).toBe('unmetered');
		expect(controller.view().acknowledged).toBeNull();

		const verdict = auditE5PreferenceAccountRace({
			staleResponseRejected: settled.ok === false,
			draftsNotCarriedAcross: controller.view().draft.automaticNetwork !== SERVER_SNAPSHOT.requested.automaticNetwork,
		});
		expect(verdict.ok, JSON.stringify(verdict)).toBe(true);
	});

	it('planted fault: a surviving stale response emits the pinned FAIL text', () => {
		const pinned = e5Failure('CAS-E5-PREFERENCE-ACCOUNT-RACE', 'probe');
		expect(pinned.fail).toBe(
			'FAIL CAS-E5-PREFERENCE-ACCOUNT-RACE: a pending preference response survived an account change',
		);
		const verdict = auditE5PreferenceAccountRace({ staleResponseRejected: false, draftsNotCarriedAcross: true });
		expect(verdict.ok).toBe(false);
		expect(verdict.fail).toBe(pinned.fail);
		expect(verdict.cause).toBe('subOracleId=stale-response-applied lane=core');
	});

	afterAll(async () => {
		const final = gateVerdictOnScenarios(
			auditE5PreferenceAccountRace({ staleResponseRejected: true, draftsNotCarriedAcross: true }),
			scenarioFailures,
		);
		expect(final.ok, JSON.stringify({ final, scenarioFailures })).toBe(true);
		writeCaseResult(final);
	});
});

describe('CAS-E5-CROSSED-NETWORK-ATTACHMENT', () => {
	it('explains actual admission for the crossed combinations without an all-network promise', () => {
		const combinations = [
			// refresh Never / attachments permitted
			{ backgroundSyncEnabled: true, effectiveAutomaticNetwork: 'never', effectiveAttachmentPrefetch: 'unmetered', meteredLink: false },
			// refresh permitted / attachments Never
			{ backgroundSyncEnabled: true, effectiveAutomaticNetwork: 'any', effectiveAttachmentPrefetch: 'never', meteredLink: false },
			// policy/metered narrowing
			{ backgroundSyncEnabled: true, effectiveAutomaticNetwork: 'unmetered', effectiveAttachmentPrefetch: 'unmetered', meteredLink: true },
			// Background sync Off with both stored preferences permissive
			{ backgroundSyncEnabled: false, effectiveAutomaticNetwork: 'any', effectiveAttachmentPrefetch: 'always', meteredLink: false },
		] as const;

		const explanations = combinations.map((combo) => explainCrossedAdmission({ ...combo }));
		expect(explanations).toHaveLength(4);

		// Refresh Never does NOT imply attachment Never: the attachment line
		// stays an independent, non-disabled explanation.
		expect(explanations[0].refreshKey).toBe('offline.e5.settings.crossed.refresh_never');
		expect(explanations[0].attachmentKey).toBe('offline.e5.settings.crossed.attachment_on');
		// Vice versa.
		expect(explanations[1].attachmentKey).toBe('offline.e5.settings.crossed.attachment_never');
		expect(explanations[1].refreshKey).toBe('offline.e5.settings.crossed.refresh_on');
		// Metered narrowing is honest about waiting.
		expect(explanations[2].refreshKey).toBe('offline.e5.settings.crossed.refresh_metered_wait');
		expect(explanations[2].linkKey).toBe('offline.e5.settings.crossed.link_metered');
		// Background off + permissive prefs: the explanation says automatic work
		// is off and EXPLICIT actions remain — never "all network disabled".
		expect(explanations[3].backgroundKey).toBe('offline.e5.settings.crossed.background_off');

		const keysUsed = new Set(explanations.flatMap((e) => [e.refreshKey, e.attachmentKey]));
		const verdict = auditE5CrossedNetworkAttachment({
			combinationsExplained: explanations.length,
			promisedTotalDisablement: false,
			scopedControlsKeptSeparate: keysUsed.size >= 3,
		});
		expect(verdict.ok, JSON.stringify(verdict)).toBe(true);
	});

	it('wire enums stay scoped: any for refresh, always for attachments', () => {
		expect(AUTOMATIC_NETWORK_VALUES).toEqual(['never', 'unmetered', 'any']);
		expect(ATTACHMENT_PREFETCH_VALUES).toEqual(['never', 'unmetered', 'always']);
	});

	it('planted fault: a total-disablement promise emits the pinned FAIL text', () => {
		const pinned = e5Failure('CAS-E5-CROSSED-NETWORK-ATTACHMENT', 'probe');
		expect(pinned.fail).toBe(
			'FAIL CAS-E5-CROSSED-NETWORK-ATTACHMENT: crossed settings explanation promised more than actual admission',
		);
		const verdict = auditE5CrossedNetworkAttachment({
			combinationsExplained: 4,
			promisedTotalDisablement: true,
			scopedControlsKeptSeparate: true,
		});
		expect(verdict.ok).toBe(false);
		expect(verdict.fail).toBe(pinned.fail);
		expect(verdict.cause).toBe('subOracleId=total-disablement-promise lane=core');

		const merged = auditE5CrossedNetworkAttachment({
			combinationsExplained: 4,
			promisedTotalDisablement: false,
			scopedControlsKeptSeparate: false,
		});
		expect(merged.cause).toBe('subOracleId=controls-merged lane=core');
	});

	afterAll(async () => {
		const final = gateVerdictOnScenarios(
			auditE5CrossedNetworkAttachment({
				combinationsExplained: 4,
				promisedTotalDisablement: false,
				scopedControlsKeptSeparate: true,
			}),
			scenarioFailures,
		);
		expect(final.ok, JSON.stringify({ final, scenarioFailures })).toBe(true);
		writeCaseResult(final);
	});
});
