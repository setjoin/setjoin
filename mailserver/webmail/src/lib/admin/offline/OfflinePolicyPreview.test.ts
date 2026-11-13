/**
 * OfflinePolicyPreview — rendered component bindings (E5 admin preview, R4
 * settings/admin amendments).
 *
 * The controller-level race/failure bindings (which own the case receipts)
 * live in e5.adminPreview.test.ts. This suite proves the RENDERED contracts:
 * - the run control stays disabled until BOTH target fields are entered, and
 *   a run posts the trimmed target exactly once;
 * - every async outcome is announced honestly through the one polite live
 *   region (loaded / unavailable / unauthorized), including a malformed
 *   server payload refused at the controller boundary;
 * - loading / unavailable / unauthorized / current render as distinct honest
 *   states; a failed refresh labels RETAINED facts stale but keeps them
 *   visible (aria-busy) — focus is never stolen and no form state exists;
 * - the facts block renders the SERVER-resolved payload verbatim (the client
 *   never recomputes precedence): winning policy (disabled policies stay
 *   visible), requested vs effective values, per-field source attribution.
 *
 * The rendered status states are exercised through the documented
 * `__controller` test seam (init-only, "start from a non-idle controller
 * state"): the component reads `controller.status()` once per instance, so
 * the seeded state is what renders — the same states the production
 * controller produces in the run flow covered by the UI-driven tests above.
 */

import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import OfflinePolicyPreview from './OfflinePolicyPreview.svelte';
import {
	createAdminPreviewController,
	type E5AdminPreviewController,
} from '$lib/offline/e5AdminPreview';

const STALE_TEXT = /from an earlier response/i;

function envelopeFor(deviceId: string, qosOverrides: Record<string, unknown> = {}): unknown {
	return {
		mailboxId: '42',
		deviceId,
		projection: {
			allowed: true,
			approvalState: 'approved',
			maxOfflineDays: 30,
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
				...qosOverrides,
			},
		},
	};
}

async function fillTarget(
	r: ReturnType<typeof render<typeof OfflinePolicyPreview>>,
	user: string,
	device: string,
): Promise<void> {
	await fireEvent.input(r.getByTestId('e5-preview-user'), { target: { value: user } });
	await fireEvent.input(r.getByTestId('e5-preview-device'), { target: { value: device } });
}

describe('run control and announcements (UI-driven run flow)', () => {
	it('stays disabled until both target fields are entered, then runs once with the TRIMMED target', async () => {
		const load = vi.fn().mockResolvedValue(envelopeFor('dev-1'));
		const r = render(OfflinePolicyPreview, { load });

		// Idle: no state line, no facts, empty announcement.
		expect(r.queryByTestId('e5-preview-facts')).toBeNull();
		expect(r.queryByTestId('e5-preview-loading')).toBeNull();
		expect(r.queryByTestId('e5-preview-unavailable')).toBeNull();
		expect(r.queryByTestId('e5-preview-unauthorized')).toBeNull();
		expect(r.getByTestId('e5-preview-live').textContent).toBe('');
		expect((r.getByTestId('e5-preview-run') as HTMLButtonElement).disabled).toBe(true);

		await fireEvent.input(r.getByTestId('e5-preview-user'), { target: { value: 'u-1' } });
		expect((r.getByTestId('e5-preview-run') as HTMLButtonElement).disabled).toBe(true); // device still empty

		await fillTarget(r, '  u-1  ', ' dev-1 ');
		expect((r.getByTestId('e5-preview-run') as HTMLButtonElement).disabled).toBe(false);
		await fireEvent.click(r.getByTestId('e5-preview-run'));

		await vi.waitFor(() => expect(r.getByTestId('e5-preview-live').textContent).toBe('Preview loaded.'));
		// The loader receives the trimmed target, exactly once.
		expect(load).toHaveBeenCalledTimes(1);
		expect(load).toHaveBeenCalledWith({ targetUserId: 'u-1', deviceId: 'dev-1' });
		// Back to settled: the run control is enabled and labeled for a refresh.
		const run = r.getByTestId('e5-preview-run') as HTMLButtonElement;
		expect(run.disabled).toBe(false);
		expect(run.textContent).toMatch(/preview/i);
		expect(run.textContent).not.toMatch(/loading/i);
	});

	it('a malformed server payload is refused: the outcome announces unavailable, never partial facts', async () => {
		const load = vi.fn().mockResolvedValue({ garbage: true });
		const r = render(OfflinePolicyPreview, { load });
		await fillTarget(r, 'u-1', 'dev-1');
		await fireEvent.click(r.getByTestId('e5-preview-run'));
		await vi.waitFor(() =>
			expect(r.getByTestId('e5-preview-live').textContent).toBe('Preview is unavailable right now.'),
		);
		// Nothing was ever applied: no facts block exists to mislabel as current.
		expect(r.queryByTestId('e5-preview-facts')).toBeNull();
	});

	it('a permission failure announces the unauthorized outcome', async () => {
		const load = vi.fn().mockRejectedValue({ forbidden: true });
		const r = render(OfflinePolicyPreview, { load });
		await fillTarget(r, 'u-1', 'dev-1');
		await fireEvent.click(r.getByTestId('e5-preview-run'));
		await vi.waitFor(() =>
			expect(r.getByTestId('e5-preview-live').textContent).toMatch(/can.t preview this user/i),
		);
	});

	it('a non-permission failure announces the unavailable outcome', async () => {
		const load = vi.fn().mockRejectedValue({ forbidden: false });
		const r = render(OfflinePolicyPreview, { load });
		await fillTarget(r, 'u-1', 'dev-1');
		await fireEvent.click(r.getByTestId('e5-preview-run'));
		await vi.waitFor(() =>
			expect(r.getByTestId('e5-preview-live').textContent).toBe('Preview is unavailable right now.'),
		);
	});
});

describe('rendered states through the seeded-controller seam', () => {
	/**
	 * Drive a REAL controller into the wanted state with the exact production
	 * controller calls (selectTarget/loaded/failed), then render the component
	 * from it via the init-only `__controller` seam. Every rendered state here
	 * is a state the run flow can reach.
	 */
	function renderSeeded(seed: (c: E5AdminPreviewController) => void) {
		const controller = createAdminPreviewController();
		seed(controller);
		return render(OfflinePolicyPreview, {
			load: vi.fn(),
			__controller: controller,
		} as never);
	}

	/** Production trace for a successful load of the pinned envelope. */
	function seedLoaded(c: E5AdminPreviewController, qos: Record<string, unknown> = {}): void {
		c.selectTarget({ targetUserId: 'u-1', deviceId: 'dev-1' });
		c.loaded(c.generation, envelopeFor('dev-1', qos));
	}

	it('loading: honest busy posture — inputs and run control disabled, labeled spinner, loading line', () => {
		const r = renderSeeded((c) => {
			c.selectTarget({ targetUserId: 'u-1', deviceId: 'dev-1' }); // request in flight
		});
		expect(r.getByTestId('e5-preview-loading')).toBeTruthy();
		expect(r.getByTestId('e5-preview-loading').textContent).toMatch(/loading preview/i);
		// The spinner inside the loading line carries the same label for AT.
		const spinner = r.getByTestId('e5-preview-loading').querySelector('.sj-spinner');
		expect(spinner?.getAttribute('aria-label')).toBe('Loading preview…');
		expect((r.getByTestId('e5-preview-user') as HTMLInputElement).disabled).toBe(true);
		expect((r.getByTestId('e5-preview-device') as HTMLInputElement).disabled).toBe(true);
		const run = r.getByTestId('e5-preview-run') as HTMLButtonElement;
		expect(run.disabled).toBe(true);
		expect(run.textContent).toMatch(/loading preview/i);
		expect(r.queryByTestId('e5-preview-facts')).toBeNull();
	});

	it('current: renders the server facts verbatim — winning policy, requested vs effective, sources', () => {
		const r = renderSeeded((c) => seedLoaded(c));
		const facts = r.getByTestId('e5-preview-facts');
		expect(facts.getAttribute('aria-busy')).toBe('false');
		// Winning policy: the server's policy id, sync mode translated.
		expect(facts.querySelector('.e5-preview__policy-id')?.textContent).toBe('pol-7');
		expect(facts.textContent).toMatch(/Active/); // sync_mode.execute
		// Requested vs effective are distinct, verbatim server values.
		expect(r.getByTestId('e5-preview-requested-refresh').textContent).toBe('On any network');
		expect(r.getByTestId('e5-preview-effective-refresh').textContent).toBe('On unmetered networks');
		expect(r.getByTestId('e5-preview-requested-attachments').textContent).toBe('On unmetered networks');
		expect(r.getByTestId('e5-preview-effective-attachments').textContent).toBe('Never');
		// Background allowed + source attribution for both narrowed fields.
		expect(facts.textContent).toMatch(/Background sync allowed/);
		expect(facts.textContent).toMatch(/Policy pol-7 \(group\)/); // refresh narrowed by a policy
		expect(facts.textContent).toMatch(/No narrowing \(default\)/); // attachments not narrowed
		// A current payload is never labeled stale.
		expect(r.queryByText(STALE_TEXT)).toBeNull();
		expect(r.queryByTestId('e5-preview-loading')).toBeNull();
	});

	it('current: a DISABLED winning policy stays visible (mode off renders Off, never filtered)', () => {
		const r = renderSeeded((c) => seedLoaded(c, {
			mode: 'off',
			backgroundAllowed: false,
			requested: { automaticNetwork: 'unmetered', attachmentPrefetch: 'never' },
			effective: { automaticNetwork: 'unmetered', attachmentPrefetch: 'never', opportunisticRequiresCharging: true },
			sources: { automaticNetwork: { policyId: 'disabled-pol', scope: 'user' } },
		}));
		const facts = r.getByTestId('e5-preview-facts');
		expect(facts.querySelector('.e5-preview__policy-id')?.textContent).toBe('disabled-pol');
		expect(facts.textContent).toMatch(/Policy disabled-pol \(user\)/);
		// sync mode Off badge + background sync Off — two exact 'Off' facts.
		expect(r.getAllByText('Off', { exact: true })).toHaveLength(2);
	});

	it('unauthorized (fresh): the alert state renders with role=alert — no facts, nothing stale', () => {
		const r = renderSeeded((c) => {
			// A failure with nothing loaded beforehand: retained stays null.
			c.selectTarget({ targetUserId: 'u-1', deviceId: 'dev-1' });
			c.failed(c.generation, { forbidden: true });
		});
		const alert = r.getByTestId('e5-preview-unauthorized');
		expect(alert.getAttribute('role')).toBe('alert');
		expect(alert.textContent).toMatch(/preview this user/i);
		expect(r.queryByText(STALE_TEXT)).toBeNull();
		expect(r.queryByTestId('e5-preview-facts')).toBeNull();
		expect(r.getByTestId('e5-preview-live').textContent).toBe(''); // no fake outcome announced
	});

	it('unavailable (fresh): the alert state renders with role=alert — no facts, nothing stale', () => {
		const r = renderSeeded((c) => {
			c.selectTarget({ targetUserId: 'u-1', deviceId: 'dev-1' });
			c.failed(c.generation, { forbidden: false });
		});
		const alert = r.getByTestId('e5-preview-unavailable');
		expect(alert.getAttribute('role')).toBe('alert');
		expect(alert.textContent).toMatch(/unavailable/i);
		expect(r.queryByText(STALE_TEXT)).toBeNull();
		expect(r.queryByTestId('e5-preview-facts')).toBeNull();
	});

	it('unauthorized after a loaded preview: retained facts stay visible, labeled stale, aria-busy', () => {
		const r = renderSeeded((c) => {
			seedLoaded(c);
			// A failed refresh on top of loaded facts — retained stays visible.
			c.failed(c.generation, { forbidden: true });
		});
		const alert = r.getByTestId('e5-preview-unauthorized');
		expect(alert.getAttribute('role')).toBe('alert');
		expect(alert.textContent).toMatch(/preview this user/i);
		// The stale label appears twice: in the alert AND atop the retained facts.
		expect(r.getAllByText(STALE_TEXT)).toHaveLength(2);
		const facts = r.getByTestId('e5-preview-facts');
		expect(facts.getAttribute('aria-busy')).toBe('true');
		// Retained (previous) server facts remain visible under the stale label.
		expect(facts.querySelector('.e5-preview__policy-id')?.textContent).toBe('pol-7');
		expect(facts.textContent).toMatch(/Policy pol-7 \(group\)/);
	});

	it('unavailable after a loaded preview: retained facts stay visible, labeled stale, aria-busy', () => {
		const r = renderSeeded((c) => {
			seedLoaded(c);
			c.failed(c.generation, { forbidden: false });
		});
		const alert = r.getByTestId('e5-preview-unavailable');
		expect(alert.textContent).toMatch(/unavailable/i);
		expect(r.getAllByText(STALE_TEXT)).toHaveLength(2);
		const facts = r.getByTestId('e5-preview-facts');
		expect(facts.getAttribute('aria-busy')).toBe('true');
		expect(facts.querySelector('.e5-preview__policy-id')?.textContent).toBe('pol-7');
	});

	it('source attribution renders every honest variant without inventing a policy', () => {
		// policyId present but scope missing → honest "unknown scope"; the other
		// field has no source entry at all → the default (no narrowing).
		const a = renderSeeded((c) => seedLoaded(c, {
			sources: { automaticNetwork: { policyId: 'pol-9' } },
		}));
		const factsA = a.getByTestId('e5-preview-facts').textContent ?? '';
		expect(factsA).toMatch(/Policy pol-9 \(unknown scope\)/);
		expect(factsA).toMatch(/No narrowing \(default\)/);
		a.unmount();

		// No sources at all → the winning policy AND both source fields honestly
		// fall back to the default label (the policy id line has no policyId).
		const b = renderSeeded((c) => seedLoaded(c, { sources: {} }));
		const factsB = b.getByTestId('e5-preview-facts').textContent ?? '';
		expect(factsB.match(/No narrowing \(default\)/g)).toHaveLength(3);
		b.unmount();

		// scope present but policyId missing → the '?' policy placeholder.
		const c2 = renderSeeded((c) => seedLoaded(c, {
			sources: {
				automaticNetwork: { policyId: 'pol-7', scope: 'group' },
				attachmentPrefetch: { scope: 'user' },
			},
		}));
		const factsC = c2.getByTestId('e5-preview-facts').textContent ?? '';
		expect(factsC).toMatch(/Policy pol-7 \(group\)/);
		expect(factsC).toMatch(/Policy \? \(user\)/);
	});
});
