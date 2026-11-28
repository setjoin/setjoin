import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render } from '@testing-library/svelte/svelte5';
import { fireEvent } from '@testing-library/svelte';
import { toasts, clearToasts } from '$lib/components/ui';

// ── fetch mock helpers ────────────────────────────────────────────────────────

function makeOkResponse(body: unknown) {
	return Promise.resolve({
		ok: true,
		status: 200,
		json: async () => body,
		text: async () => JSON.stringify(body)
	});
}

// A dynamic (banned) group + a static eligible one.
const GROUPS = [
	{ id: 1, name: 'All staff', isDynamic: true, scimSynced: false, usableAsAdminScope: false, memberCount: 100 },
	{ id: 2, name: 'Field team', isDynamic: false, scimSynced: true, usableAsAdminScope: false, memberCount: 12 }
];

function mockFetch(groups: unknown[] = GROUPS) {
	return vi.fn((url: string) => {
		if (url.includes('/admin/departments/tree')) return makeOkResponse([]);
		if (url.includes('/admin/distribution-groups')) return makeOkResponse(groups);
		if (url.includes('/admin/users')) return makeOkResponse([]);
		return makeOkResponse({});
	});
}

describe('ScopeSetMemberControl', () => {
	beforeEach(() => {
		vi.resetAllMocks();
		clearToasts();
	});

	it('shows a dynamic group as disabled with a reason (aria-disabled + the reason text)', async () => {
		vi.stubGlobal('fetch', mockFetch());
		const { default: ScopeSetMemberControl } = await import('./ScopeSetMemberControl.svelte');
		const { container } = render(ScopeSetMemberControl);
		await new Promise((r) => setTimeout(r, 20));

		// Switch to the Directory groups tab.
		const groupsTab = Array.from(container.querySelectorAll('[role="tab"]')).find(
			(b) => b.textContent?.includes('Directory groups')
		);
		expect(groupsTab).toBeDefined();
		await fireEvent.click(groupsTab!);
		await new Promise((r) => setTimeout(r, 20));

		// The dynamic group row is disabled with the reason.
		const disabledRow = container.querySelector('[aria-disabled="true"]');
		expect(disabledRow).not.toBeNull();
		expect(container.textContent).toContain('Dynamic — not allowed for scope');

		// The eligible static group exposes an Add button (not blocked).
		const addBtn = Array.from(container.querySelectorAll('button')).find((b) => b.textContent?.trim() === 'Add');
		expect(addBtn).toBeDefined();
		vi.unstubAllGlobals();
	});

	it('removing a chip offers an Undo toast', async () => {
		vi.stubGlobal('fetch', mockFetch());
		const { default: ScopeSetMemberControl } = await import('./ScopeSetMemberControl.svelte');
		const { container } = render(ScopeSetMemberControl, {
			props: { members: [{ memberType: 'group', memberId: 9, name: 'Field team', seats: 12 }] }
		});
		await new Promise((r) => setTimeout(r, 20));

		// The chip's remove button (aria-label "Remove Field team").
		const removeBtn = container.querySelector('button[aria-label="Remove Field team"]') as HTMLButtonElement | null;
		expect(removeBtn).not.toBeNull();
		await fireEvent.click(removeBtn!);
		await new Promise((r) => setTimeout(r, 10));

		// An act-then-undo toast was queued.
		expect(toasts.length).toBeGreaterThan(0);
		expect(toasts.some((t) => t.actionLabel === 'Undo')).toBe(true);
		vi.unstubAllGlobals();
	});

	it('an empty tray blocks save (danger state + disabled Save)', async () => {
		vi.stubGlobal('fetch', mockFetch());
		const { default: ScopeSetMemberControl } = await import('./ScopeSetMemberControl.svelte');
		const { container } = render(ScopeSetMemberControl, { props: { members: [] } });
		await new Promise((r) => setTimeout(r, 20));

		// The danger message is shown.
		expect(container.textContent).toContain('reaches nobody');

		// The Save button is disabled.
		const saveBtn = Array.from(container.querySelectorAll('button')).find(
			(b) => b.textContent?.includes('Save scope-set')
		) as HTMLButtonElement | undefined;
		expect(saveBtn).toBeDefined();
		expect(saveBtn!.disabled).toBe(true);
		vi.unstubAllGlobals();
	});

	it('a populated tray enables Save', async () => {
		vi.stubGlobal('fetch', mockFetch());
		const { default: ScopeSetMemberControl } = await import('./ScopeSetMemberControl.svelte');
		const { container } = render(ScopeSetMemberControl, {
			props: { members: [{ memberType: 'user', memberId: 5, name: 'a@example.com', seats: 1 }] }
		});
		await new Promise((r) => setTimeout(r, 20));

		const saveBtn = Array.from(container.querySelectorAll('button')).find(
			(b) => b.textContent?.includes('Save scope-set')
		) as HTMLButtonElement | undefined;
		expect(saveBtn).toBeDefined();
		expect(saveBtn!.disabled).toBe(false);
		vi.unstubAllGlobals();
	});
});
