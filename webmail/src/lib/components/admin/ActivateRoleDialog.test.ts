import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render } from '@testing-library/svelte/svelte5';
import { fireEvent } from '@testing-library/svelte';
import type { MyRole } from '$lib/admin/client';

function role(policy: Partial<MyRole['policy']> = {}, over: Partial<MyRole> = {}): MyRole {
	return {
		roleGroupId: 7,
		name: 'Super Admin',
		eligible: true,
		activatedUntil: null,
		expiresAt: null,
		policy: { maxDurationMinutes: 60, requireJustification: false, ...policy },
		...over,
	};
}

function okJson(body: unknown) {
	return Promise.resolve({
		ok: true,
		status: 200,
		json: async () => body,
		text: async () => JSON.stringify(body),
	});
}

function activateButton(container: HTMLElement): HTMLButtonElement {
	return [...container.querySelectorAll('button')].find(
		(b) => b.textContent?.trim() === 'Activate'
	) as HTMLButtonElement;
}

describe('ActivateRoleDialog', () => {
	beforeEach(() => vi.restoreAllMocks());

	it('disables over-max durations with a reason tooltip', async () => {
		vi.stubGlobal('fetch', vi.fn(() => okJson({})));
		const { default: Dlg } = await import('./ActivateRoleDialog.svelte');
		const { container } = render(Dlg, {
			props: { role: role({ maxDurationMinutes: 60 }), onClose: () => {}, onActivated: () => {} },
		});
		await new Promise((r) => setTimeout(r, 20));

		// Presets 120 / 240 / 480 exceed the 60-min cap → structurally non-selectable.
		const disabled = [...container.querySelectorAll('button[aria-disabled="true"]')];
		expect(disabled.length).toBe(3);

		// Focusing an over-max button reveals the keyboard-reachable reason tooltip.
		fireEvent.focusIn(disabled[0]);
		await new Promise((r) => setTimeout(r, 10));
		const tip = container.querySelector('[role="tooltip"]');
		expect(tip?.textContent ?? '').toMatch(/exceeds/i);

		vi.unstubAllGlobals();
	});

	it('submitting without a required justification shows the inline error and does NOT call activate', async () => {
		const fetchMock = vi.fn((_url: string) => okJson({}));
		vi.stubGlobal('fetch', fetchMock);
		const { default: Dlg } = await import('./ActivateRoleDialog.svelte');
		const onActivated = vi.fn();
		const { container } = render(Dlg, {
			props: {
				role: role({ maxDurationMinutes: 60, requireJustification: true }),
				onClose: () => {},
				onActivated,
			},
		});
		await new Promise((r) => setTimeout(r, 20));

		await fireEvent.click(activateButton(container));
		await new Promise((r) => setTimeout(r, 20));

		expect(container.textContent ?? '').toMatch(/reason is required/i);
		const hitActivate = fetchMock.mock.calls.some((c) => String(c[0]).includes('/activate'));
		expect(hitActivate).toBe(false);
		expect(onActivated).not.toHaveBeenCalled();

		vi.unstubAllGlobals();
	});

	it('a tokenRefreshRequired response triggers the refresh path', async () => {
		const fetchMock = vi.fn((url: string) =>
			String(url).includes('/activate')
				? okJson({ activatedUntil: '2026-06-27T15:00:00Z', tokenRefreshRequired: true })
				: okJson({})
		);
		vi.stubGlobal('fetch', fetchMock);
		const { default: Dlg } = await import('./ActivateRoleDialog.svelte');
		const refreshSession = vi.fn(async () => {});
		const onActivated = vi.fn();
		const { container } = render(Dlg, {
			props: {
				role: role({ maxDurationMinutes: 60, requireJustification: false }),
				onClose: () => {},
				onActivated,
				refreshSession,
			},
		});
		await new Promise((r) => setTimeout(r, 20));

		await fireEvent.click(activateButton(container));
		await new Promise((r) => setTimeout(r, 40));

		expect(refreshSession).toHaveBeenCalledOnce();
		expect(onActivated).toHaveBeenCalledOnce();

		vi.unstubAllGlobals();
	});
});
