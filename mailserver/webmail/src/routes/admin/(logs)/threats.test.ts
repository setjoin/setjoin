import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderAsUser, resetStores, mockSessionLoad } from '$lib/test-utils';
import { waitFor } from '@testing-library/svelte/svelte5';

import ThreatsPage from './threats/+page.svelte';

function countThreatCalls(calls: unknown[][]): number {
	return calls.filter((c) => {
		const url = typeof c[0] === 'string' ? c[0] : String(c[0]);
		return url.includes('/admin/threat/') && !url.includes('/ip-rules');
	}).length;
}

describe('Threats page — single initial load', () => {
	beforeEach(() => {
		resetStores();
		mockSessionLoad();
	});

	it('fetches the threat view exactly once on mount (no double-load)', async () => {
		const fetchSpy = vi.fn(async () => ({
			ok: true,
			status: 200,
			json: async () => ({ rows: [], total: 0, limit: 25, offset: 0 }),
			text: async () => '',
		}));
		vi.stubGlobal('fetch', fetchSpy);

		await renderAsUser(ThreatsPage, {}, { isAdmin: true });

		// Allow the mount + any effects to flush.
		await waitFor(() => {
			expect(countThreatCalls(fetchSpy.mock.calls)).toBeGreaterThan(0);
		});
		// Give microtasks a beat to surface a duplicate call if one exists.
		await new Promise((r) => setTimeout(r, 50));

		expect(countThreatCalls(fetchSpy.mock.calls)).toBe(1);
	});
});
