import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render } from '@testing-library/svelte/svelte5';
import type { MyRole } from '$lib/admin/client';

function okJson(body: unknown) {
	return Promise.resolve({
		ok: true,
		status: 200,
		json: async () => body,
		text: async () => JSON.stringify(body),
	});
}

const NOW = Date.now();

const ROLES: MyRole[] = [
	// standing (always-on)
	{ roleGroupId: 1, name: 'Auditor', eligible: false, activatedUntil: null, expiresAt: null, policy: { maxDurationMinutes: 480, requireJustification: false } },
	// eligible · dormant
	{ roleGroupId: 2, name: 'Super Admin', eligible: true, activatedUntil: null, expiresAt: null, policy: { maxDurationMinutes: 60, requireJustification: true } },
	// active (well over the 5-min band)
	{ roleGroupId: 3, name: 'Compliance Admin', eligible: true, activatedUntil: new Date(NOW + 45 * 60_000).toISOString(), expiresAt: null, policy: { maxDurationMinutes: 120, requireJustification: false } },
	// expiring (≤5 min)
	{ roleGroupId: 4, name: 'Help Desk', eligible: true, activatedUntil: new Date(NOW + 3 * 60_000).toISOString(), expiresAt: null, policy: { maxDurationMinutes: 60, requireJustification: false } },
];

function mockRolesFetch() {
	return vi.fn((url: string) =>
		String(url).includes('/admin/me/roles') ? okJson(ROLES) : okJson({})
	);
}

describe('My roles surface', () => {
	beforeEach(() => vi.restoreAllMocks());

	it('renders the four states with the right status', async () => {
		vi.stubGlobal('fetch', mockRolesFetch());
		const { default: MyRolesPage } = await import('./+page.svelte');
		const { container } = render(MyRolesPage);
		await new Promise((r) => setTimeout(r, 30));

		// One pill per state, with the dot+icon+label classes.
		expect(container.querySelectorAll('.jit-status--standing').length).toBe(1);
		expect(container.querySelectorAll('.jit-status--dormant').length).toBe(1);
		expect(container.querySelectorAll('.jit-status--active').length).toBe(1);
		expect(container.querySelectorAll('.jit-status--expiring').length).toBe(1);

		const text = container.textContent ?? '';
		expect(text).toMatch(/Standing/);
		expect(text).toMatch(/Eligible · dormant/);
		expect(text).toMatch(/min left/); // active + expiring share the countdown label

		// The dormant role carries the concept tooltip trigger; standing/active do not.
		expect(container.querySelectorAll('.jit-info').length).toBe(1);

		// Polite live region exists for the countdown announcement.
		expect(container.querySelector('[aria-live="polite"]')).not.toBeNull();

		vi.unstubAllGlobals();
	});
});
