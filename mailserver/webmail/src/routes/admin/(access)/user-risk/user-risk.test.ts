import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import Risk from './+page.svelte';

const mockFetch = (impl: (url: string, init?: any) => any) => vi.stubGlobal('fetch', vi.fn(impl));

describe('user-risk dashboard', () => {
	beforeEach(() => vi.restoreAllMocks());

	it('shows the "turned off" empty state when the feature is off', async () => {
		mockFetch(() => ({ ok: false, status: 409, headers: new Headers({ 'x-feature-off': 'user_risk' }) }));
		const { findByText } = render(Risk);
		expect(await findByText(/turned off/i)).toBeTruthy(); // risk.off_title exact copy
	});

	it('shows the reassuring clean empty state (good path), no destructive action', async () => {
		mockFetch(() => ({ ok: true, status: 200, headers: new Headers(), json: async () => [] }));
		const { findByText, queryByRole } = render(Risk);
		expect(await findByText(/no elevated-risk users/i)).toBeTruthy();
		expect(await findByText(/looks normal/i)).toBeTruthy(); // risk.clean_sub
		expect(queryByRole('button', { name: /reset/i })).toBeNull();
	});

	it('renders an error strip with role=alert + Retry on a load failure', async () => {
		mockFetch(() => ({ ok: false, status: 500, headers: new Headers() }));
		const { findByRole } = render(Risk);
		const alert = await findByRole('alert');
		expect(alert.textContent?.toLowerCase()).toContain('load');
		expect(await findByRole('button', { name: /retry/i })).toBeTruthy();
	});

	it('reset is a dangerous action behind a confirm Dialog and announces the outcome', async () => {
		const row = { user_id: 7, email: 'eve@corp', score: 95, level: 'high', signals: ['impossible_travel'], updated_at: '2026-06-23T00:00:00Z' };
		let resetCalled = false;
		mockFetch((url: string, init?: any) => {
			if (url.includes('/reset')) { resetCalled = true; return { ok: true, status: 204 }; }
			return { ok: true, status: 200, headers: new Headers(), json: async () => [row] };
		});
		const { findByRole, getByRole, container } = render(Risk);
		await fireEvent.click(await findByRole('button', { name: /reset risk for eve@corp/i }));
		// Confirm dialog opened (not a one-click destructive)
		const dialog = await findByRole('dialog');
		expect(dialog.textContent?.toLowerCase()).toContain('remediated');
		await fireEvent.click(getByRole('button', { name: /^reset risk$/i }));
		await waitFor(() => expect(resetCalled).toBe(true));
		const live = container.querySelector('[aria-live="polite"]');
		expect(live?.textContent?.toLowerCase()).toContain('eve@corp'); // risk.reset_announce
	});

	it('high-risk level badge carries text (not color-only) and shows showing-of count', async () => {
		const many = Array.from({ length: 30 }, (_, i) => ({ user_id: i, email: `u${i}@c`, score: 95, level: 'high', signals: [], updated_at: '2026-06-23T00:00:00Z' }));
		mockFetch(() => ({ ok: true, status: 200, headers: new Headers(), json: async () => many }));
		const { findByText, getAllByText } = render(Risk);
		expect((await findByText(/showing 25 of 30/i))).toBeTruthy(); // risk.showing_of, pagination honesty
		expect(getAllByText(/high/i).length).toBeGreaterThan(0); // badge label text present
	});
});
