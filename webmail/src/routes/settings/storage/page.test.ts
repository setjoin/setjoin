import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, waitFor, fireEvent } from '@testing-library/svelte';
import { clearToasts } from '$lib/components/ui';
import type { OfflineCaps } from '$lib/offline/caps';
import Page from './+page.svelte';

// Build an OfflineCaps; ALLOWED by default so control-exercising tests are active.
const caps = (o: Partial<OfflineCaps> = {}): OfflineCaps => ({
	allowed: true, approvalState: 'approved', maxOfflineDays: 30,
	wipeOnLogout: 'admin_default', requireApproval: false, ...o,
});
// Inject allowed caps via the page's __offlineCaps test seam (skips the network fetch).
const ALLOWED = { __offlineCaps: caps() } as never;

vi.mock('$lib/api/offline', () => ({
	getOfflineSizeEstimate: vi.fn().mockResolvedValue({
		buckets: [
			{ window: '7d', messageCount: 5, bodyBytes: 1_000_000 },
			{ window: '30d', messageCount: 20, bodyBytes: 5_000_000 },
			{ window: '90d', messageCount: 50, bodyBytes: 20_000_000 },
			{ window: '180d', messageCount: 80, bodyBytes: 50_000_000 },
			{ window: '365d', messageCount: 120, bodyBytes: 120_000_000 },
			{ window: 'all', messageCount: 200, bodyBytes: 300_000_000 }
		]
	}),
	getOfflineWindow: vi.fn().mockResolvedValue('30d'),
	saveOfflineWindow: vi.fn().mockResolvedValue(undefined),
	getMailboxQuota: vi.fn().mockResolvedValue({ usedBytes: 25_000_000_000, quotaBytes: 53_687_091_200 })
}));

// Native store facade: default to AVAILABLE (native shell) for most cases;
// override per-test for the plain-browser case.
vi.mock('$lib/offline/storeFacade', () => ({
	isOfflineAvailable: vi.fn().mockReturnValue(true),
	getCacheSizeBytes: vi.fn().mockResolvedValue(6_000_000),
	getFreeSpaceBytes: vi.fn().mockResolvedValue(94_000_000),
	clearOfflineCache: vi.fn().mockResolvedValue(undefined),
	syncNow: vi.fn().mockResolvedValue(undefined)
}));

import type { SizeEstimate } from '$lib/offline/sizeFit';

// Shared default estimate, matches the vi.mock factory above.
const DEFAULT_ESTIMATE: SizeEstimate = {
	buckets: [
		{ window: '7d', messageCount: 5, bodyBytes: 1_000_000 },
		{ window: '30d', messageCount: 20, bodyBytes: 5_000_000 },
		{ window: '90d', messageCount: 50, bodyBytes: 20_000_000 },
		{ window: '180d', messageCount: 80, bodyBytes: 50_000_000 },
		{ window: '365d', messageCount: 120, bodyBytes: 120_000_000 },
		{ window: 'all', messageCount: 200, bodyBytes: 300_000_000 }
	]
};

describe('storage settings page', () => {
	beforeEach(async () => {
		// vi.clearAllMocks() only clears call history, NOT mock implementations.
		// Re-apply factory defaults so each test starts from a known state.
		const facade = await import('$lib/offline/storeFacade');
		vi.mocked(facade.isOfflineAvailable).mockReturnValue(true);
		vi.mocked(facade.getCacheSizeBytes).mockResolvedValue(6_000_000);
		vi.mocked(facade.getFreeSpaceBytes).mockResolvedValue(94_000_000);
		vi.mocked(facade.clearOfflineCache).mockResolvedValue(undefined);
		vi.mocked(facade.syncNow).mockResolvedValue(undefined);
		const offline = await import('$lib/api/offline');
		vi.mocked(offline.getOfflineSizeEstimate).mockResolvedValue(DEFAULT_ESTIMATE);
		vi.mocked(offline.getOfflineWindow).mockResolvedValue('30d');
		vi.mocked(offline.saveOfflineWindow).mockResolvedValue(undefined);
		vi.mocked(offline.getMailboxQuota).mockResolvedValue({
			usedBytes: 25_000_000_000,
			quotaBytes: 53_687_091_200
		});
		// Clear toasts accumulated from previous test renders.
		clearToasts();
		// Default the /user/offline/caps fetch to 404 so a non-injected render stays
		// inert (safe default) and never hits the real network.
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
			ok: false, status: 404, json: async () => ({}), text: async () => '',
		}));
		vi.clearAllMocks();
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('renders the live estimate for the loaded window (30d ⇒ 4.8 MB)', async () => {
		const { getByText } = render(Page, ALLOWED);
		await waitFor(() => expect(getByText(/4\.8 MB/)).toBeTruthy());
	});

	it('Cloud card renders the mailbox quota bar (progressbar + used/quota text)', async () => {
		const { getByRole, findByText } = render(Page, ALLOWED);
		const bar = await waitFor(() => getByRole('progressbar'));
		// aria reflects used/quota straight from GET /user/quota.
		expect(bar.getAttribute('aria-valuenow')).toBe('25000000000');
		expect(bar.getAttribute('aria-valuemax')).toBe('53687091200');
		// summary line: formatBytes(used) of formatBytes(quota) used.
		expect(await findByText(/of\s+.+\s+used/i)).toBeTruthy();
	});

	it('EDGE — used exceeds quota clamps the bar to 100%', async () => {
		const offline = await import('$lib/api/offline');
		vi.mocked(offline.getMailboxQuota).mockResolvedValue({
			usedBytes: 60_000_000_000,
			quotaBytes: 50_000_000_000
		});
		const { getByRole } = render(Page, ALLOWED);
		const bar = await waitFor(() => getByRole('progressbar'));
		// Progress clamps valuenow to max → 100% fill, never over.
		expect(bar.getAttribute('aria-valuenow')).toBe('50000000000');
		expect(bar.getAttribute('aria-valuemax')).toBe('50000000000');
	});

	it('ACTIVE: caps.allowed && native ⇒ slider + actions enabled, no explainer', async () => {
		const { getByRole, queryByText } = render(Page, ALLOWED);
		await waitFor(() => getByRole('slider'));
		expect((getByRole('slider') as HTMLInputElement).disabled).toBe(false);
		expect(queryByText(/isn.t enabled/i)).toBeNull();
	});

	it('persists the window when the slider moves', async () => {
		const offline = await import('$lib/api/offline');
		const { getByRole } = render(Page, ALLOWED);
		await waitFor(() => getByRole('slider'));
		const slider = getByRole('slider') as HTMLInputElement;
		slider.value = '2'; // index 2 = 90d
		await fireEvent.input(slider);
		await waitFor(() => expect(offline.saveOfflineWindow).toHaveBeenCalledWith('90d'));
	});

	it('fit-to-space picks the largest window under free space (from the native bridge)', async () => {
		const offline = await import('$lib/api/offline');
		const { getByText } = render(Page, ALLOWED);
		await waitFor(() => getByText(/4\.8 MB/));
		// free = 94 MB (bridge getFreeSpaceBytes) → 180d (50 MB) fits, 365d (120 MB) doesn't.
		await fireEvent.click(getByText(/fit/i));
		await waitFor(() => expect(offline.saveOfflineWindow).toHaveBeenCalledWith('180d'));
	});

	it('hides the Offline section entirely on a plain browser', async () => {
		const facade = await import('$lib/offline/storeFacade');
		(facade.isOfflineAvailable as ReturnType<typeof vi.fn>).mockReturnValue(false);
		const { queryByRole } = render(Page);
		// No slider → no Offline section. (Cloud card may still render.)
		await waitFor(() => expect(queryByRole('slider')).toBeNull());
	});

	it('LOADING: shows a status spinner and disables the slider until data lands', async () => {
		const offline = await import('$lib/api/offline');
		// Never-resolving estimate to hold the loading state.
		(offline.getOfflineSizeEstimate as ReturnType<typeof vi.fn>).mockReturnValue(new Promise(() => {}));
		const { getByRole, queryByRole } = render(Page);
		expect(getByRole('status')).toBeTruthy(); // spinner
		expect(queryByRole('slider')).toBeNull(); // not yet rendered
	});

	it('ERROR: renders an alert with a Retry button that re-runs the loader', async () => {
		const offline = await import('$lib/api/offline');
		(offline.getOfflineSizeEstimate as ReturnType<typeof vi.fn>)
			.mockRejectedValueOnce(new Error('network'))
			.mockResolvedValue({ buckets: [{ window: '30d', messageCount: 1, bodyBytes: 5_000_000 }] });
		const { getByRole, findByText } = render(Page);
		await waitFor(() => expect(getByRole('alert')).toBeTruthy());
		const retry = await findByText(/retry/i);
		await fireEvent.click(retry);
		await waitFor(() => expect(getByRole('slider')).toBeTruthy());
	});

	it('OVERFLOW: when needed > free the slider gets the danger tone and the estimate alerts', async () => {
		const facade = await import('$lib/offline/storeFacade');
		(facade.getFreeSpaceBytes as ReturnType<typeof vi.fn>).mockResolvedValue(2_000_000); // < 30d's 5 MB
		const { container, getByRole } = render(Page, ALLOWED);
		await waitFor(() => getByRole('slider'));
		expect(container.querySelector('.sj-slider--danger')).toBeTruthy();
		// estimate line is a live region announcing the overflow copy
		expect(getByRole('status')).toBeTruthy();
	});

	it('FIRST-RUN: 0 B cached shows the EmptyState with a Sync-now primary action', async () => {
		const facade = await import('$lib/offline/storeFacade');
		(facade.getCacheSizeBytes as ReturnType<typeof vi.fn>).mockResolvedValue(0);
		const { findByText } = render(Page, ALLOWED);
		expect(await findByText(/nothing cached yet/i)).toBeTruthy();
	});

	it('DANGEROUS: Clear cache opens a confirm dialog showing the blast radius before wiping', async () => {
		const facade = await import('$lib/offline/storeFacade');
		const { getByText, getByRole, queryByRole } = render(Page, ALLOWED);
		await waitFor(() => getByRole('slider'));
		await fireEvent.click(getByText(/clear cache/i));
		// Dialog open with blast-radius copy; wipe NOT yet called.
		expect(getByRole('dialog')).toBeTruthy();
		expect(facade.clearOfflineCache).not.toHaveBeenCalled();
		// Confirm fires the wipe.
		await fireEvent.click(getByRole('dialog').querySelector('.sj-btn--danger') as HTMLElement);
		await waitFor(() => expect(facade.clearOfflineCache).toHaveBeenCalledOnce());
		await waitFor(() => expect(queryByRole('dialog')).toBeNull());
	});

	it('INERT: caps.allowed falsy disables the slider + actions with an explainer', async () => {
		// Inject denied caps (allowed:false) via the seam → section is inert even on native.
		const { getByRole, findByText } = render(Page, {
			__offlineCaps: caps({ allowed: false, approvalState: 'denied' }),
		} as never);
		await waitFor(() => getByRole('slider'));
		expect((getByRole('slider') as HTMLInputElement).disabled).toBe(true);
		expect(await findByText(/isn.t enabled/i)).toBeTruthy();
	});

	it('EDGE — empty mailbox: every window reads 0 B needed, no overflow/danger', async () => {
		const offline = await import('$lib/api/offline');
		(offline.getOfflineSizeEstimate as ReturnType<typeof vi.fn>).mockResolvedValue({
			buckets: [{ window: '30d', messageCount: 0, bodyBytes: 0 }]
		});
		const { container, findByText } = render(Page, ALLOWED);
		expect(await findByText(/0 B/)).toBeTruthy();
		expect(container.querySelector('.sj-slider--danger')).toBeNull();
	});

	it('EDGE — multi-GB mailbox: the estimate formats GB with one decimal, never raw bytes', async () => {
		const offline = await import('$lib/api/offline');
		(offline.getOfflineSizeEstimate as ReturnType<typeof vi.fn>).mockResolvedValue({
			buckets: [{ window: '30d', messageCount: 9000, bodyBytes: 3_650_000_000 }]
		});
		const facade = await import('$lib/offline/storeFacade');
		(facade.getFreeSpaceBytes as ReturnType<typeof vi.fn>).mockResolvedValue(50_000_000_000);
		const { findByText } = render(Page, ALLOWED);
		expect(await findByText(/3\.4 GB/)).toBeTruthy(); // formatBytes(3.65e9) ≈ 3.4 GB
	});

	it('EDGE — deviceFree unknown (0 from bridge): suppresses the danger tone (no false alarm)', async () => {
		const facade = await import('$lib/offline/storeFacade');
		(facade.getFreeSpaceBytes as ReturnType<typeof vi.fn>).mockResolvedValue(0);
		const { container, getByRole } = render(Page, ALLOWED);
		await waitFor(() => getByRole('slider'));
		expect(container.querySelector('.sj-slider--danger')).toBeNull();
	});
});

// UI-UX-PRO-MAX 2026-06-23: tabular figures on the size readouts prevent layout
// shift as the numbers change (slider drag, live sync). Source-read invariant
// (mirrors the redesign's style-invariant test style) so it can't silently regress.
import { readFileSync } from 'node:fs';
describe('Storage page — tabular figures (no layout shift)', () => {
	const src = readFileSync('src/routes/settings/storage/+page.svelte', 'utf8');
	const style = src.slice(src.indexOf('<style>'));
	it('the cached/free rows use tabular-nums', () => {
		// .sj-row carries the formatBytes() readouts; tabular figures keep their width
		// stable as digit counts change.
		expect(style).toMatch(/\.sj-row[^}]*font-variant-numeric:\s*tabular-nums/s);
	});
	it('the estimate line uses tabular-nums (stable width across slider stops)', () => {
		expect(style).toMatch(/\.sj-estimate[^}]*font-variant-numeric:\s*tabular-nums/s);
	});
});

// settings.storage.* i18n parity guard: every key in en must exist in zh + de.
// Fails CI if a translator misses a key, not a reviewer.
import en from '$lib/i18n/en';
import zh from '$lib/i18n/zh';
import de from '$lib/i18n/de';
describe('settings.storage.* i18n parity (en / zh / de)', () => {
	it('zh has all settings.storage.* keys', () => {
		const storageKeys = Object.keys(en as Record<string, string>).filter((k) =>
			k.startsWith('settings.storage.')
		);
		for (const k of storageKeys) {
			expect((zh as Record<string, string>)[k], `zh missing ${k}`).toBeDefined();
		}
	});
	it('de has all settings.storage.* keys', () => {
		const storageKeys = Object.keys(en as Record<string, string>).filter((k) =>
			k.startsWith('settings.storage.')
		);
		for (const k of storageKeys) {
			expect((de as Record<string, string>)[k], `de missing ${k}`).toBeDefined();
		}
	});
});
