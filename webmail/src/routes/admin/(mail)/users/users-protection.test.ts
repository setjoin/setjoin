/**
 * users-protection.test.ts
 *
 * Component tests for the Task 7 admin-protection guard on the Users page.
 * Verifies the Protected/You badge, disabled controls, and a11y wiring.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { waitFor } from '@testing-library/svelte/svelte5';
import { switchLocale } from '$lib/i18n';
import { jmapSession } from '$lib/stores/session';

import AdminUsers from './+page.svelte';

// ── fetch mock helpers ────────────────────────────────────────────────────────

function makeOkResponse(body: unknown) {
	return Promise.resolve({
		ok: true,
		status: 200,
		json: async () => body,
		text: async () => JSON.stringify(body)
	});
}

function baseUser(overrides: Record<string, unknown> = {}) {
	return {
		id: 1,
		email: 'alice@acme.com',
		displayName: 'Alice',
		enabled: true,
		isLocalAdmin: true,
		departmentId: null,
		createdAt: '2026-01-01T00:00:00Z',
		manageable: true,
		isSelf: false,
		mailboxId: 10,
		...overrides
	};
}

function mockFetch(users: unknown[]) {
	return vi.fn((url: string) => {
		const u = typeof url === 'string' ? url : String(url);
		if (u.includes('/admin/departments/tree')) return makeOkResponse([]);
		if (u.includes('/admin/users')) return makeOkResponse(users);
		return makeOkResponse({});
	});
}

// All the admin permissions needed by the buttons on this page
const ALL_PERMISSIONS = [
	'users.create', 'users.suspend', 'users.delete', 'users.password_reset',
	'users.impersonate', 'roles.manage'
];

// ── helpers ───────────────────────────────────────────────────────────────────

async function renderUsers(users: unknown[]) {
	vi.stubGlobal('fetch', mockFetch(users));
	const result = await renderAsUser(AdminUsers, {}, { isAdmin: true });
	// Populate the adminPermissions store so hasPermission gates are open.
	// adminPermissions is derived from jmapSession.capabilities.
	jmapSession.set({
		accounts: { a1: { name: 'alice@test.local', isPrimary: true } },
		primaryAccounts: { 'urn:ietf:params:jmap:mail': 'a1' },
		capabilities: {
			'urn:ietf:params:jmap:core': {},
			'urn:setjoin:params:jmap:mail': {
				admin: {
					consoles: ['mail', 'system', 'logs', 'auth', 'access'],
					permissions: ALL_PERMISSIONS
				}
			}
		}
	} as any);
	// Wait for the async onMount data fetch to complete
	await new Promise((r) => setTimeout(r, 20));
	return result;
}

// ── tests ─────────────────────────────────────────────────────────────────────

describe('Admin Users — protection guard (Task 7)', () => {
	beforeEach(async () => {
		resetStores();
		await switchLocale('en');
	});

	afterEach(async () => {
		vi.unstubAllGlobals();
		await switchLocale('en');
	});

	// ── PROTECTED row (manageable:false, isSelf:false) ────────────────────────

	it('protected row: renders "Protected" badge text', async () => {
		const { container } = await renderUsers([baseUser({ manageable: false, isSelf: false })]);
		await waitFor(() => {
			expect(container.textContent).toContain('Protected');
		});
	});

	it('protected row: the focusable tabindex=0 span is in tab order and carries aria-describedby', async () => {
		const { container } = await renderUsers([baseUser({ manageable: false, isSelf: false })]);
		await waitFor(() => {
			const span = container.querySelector('.sj-protection-indicator[tabindex="0"]');
			expect(span).not.toBeNull();
			// Tooltip wires aria-describedby onto the first child of the tooltip root
			const describedBy = span?.getAttribute('aria-describedby');
			expect(describedBy).toBeTruthy();
			expect(describedBy!.length).toBeGreaterThan(0);
		});
	});

	it('protected row: Password button is disabled', async () => {
		const { container } = await renderUsers([baseUser({ manageable: false, isSelf: false })]);
		await waitFor(() => {
			const buttons = [...container.querySelectorAll('button')];
			const pwdBtn = buttons.find((b) => b.textContent?.trim() === 'Password');
			expect(pwdBtn).not.toBeNull();
			expect(pwdBtn!.disabled).toBe(true);
		});
	});

	it('protected row: "View as user" button is disabled', async () => {
		const { container } = await renderUsers([baseUser({ manageable: false, isSelf: false })]);
		await waitFor(() => {
			const buttons = [...container.querySelectorAll('button')];
			const viewBtn = buttons.find((b) => b.textContent?.trim() === 'View as user');
			expect(viewBtn).not.toBeNull();
			expect(viewBtn!.disabled).toBe(true);
		});
	});

	it('protected row: Mailbox lifecycle button is disabled', async () => {
		const { container } = await renderUsers([baseUser({ manageable: false, isSelf: false })]);
		await waitFor(() => {
			const buttons = [...container.querySelectorAll('button')];
			const delBtn = buttons.find((b) => b.textContent?.trim() === 'Mailbox lifecycle');
			expect(delBtn).not.toBeNull();
			expect(delBtn!.disabled).toBe(true);
		});
	});

	it('protected row: non-sensitive buttons (Aliases, Quota, Keys, App access) stay enabled', async () => {
		const { container } = await renderUsers([baseUser({ manageable: false, isSelf: false })]);
		await waitFor(() => {
			const buttons = [...container.querySelectorAll('button')];
			for (const label of ['Aliases', 'Quota', 'Keys', 'App access']) {
				const btn = buttons.find((b) => b.textContent?.trim() === label);
				expect(btn, `${label} button should exist`).not.toBeNull();
				expect(btn!.disabled, `${label} button should not be disabled`).toBe(false);
			}
		});
	});

	// ── SELF row (isSelf:true) ─────────────────────────────────────────────────

	it('self row: renders "You" badge text', async () => {
		const { container } = await renderUsers([baseUser({ manageable: true, isSelf: true })]);
		await waitFor(() => {
			expect(container.textContent).toContain('You');
		});
	});

	it('self row: the "You" indicator span has tabindex=0 and aria-describedby', async () => {
		const { container } = await renderUsers([baseUser({ manageable: true, isSelf: true })]);
		await waitFor(() => {
			const span = container.querySelector('.sj-protection-indicator[tabindex="0"]');
			expect(span).not.toBeNull();
			const describedBy = span?.getAttribute('aria-describedby');
			expect(describedBy).toBeTruthy();
		});
	});

	it('self row: Mailbox lifecycle button is disabled', async () => {
		const { container } = await renderUsers([baseUser({ manageable: true, isSelf: true })]);
		await waitFor(() => {
			const buttons = [...container.querySelectorAll('button')];
			const delBtn = buttons.find((b) => b.textContent?.trim() === 'Mailbox lifecycle');
			expect(delBtn).not.toBeNull();
			expect(delBtn!.disabled).toBe(true);
		});
	});

	it('self row: Password button stays enabled (self password-reset is allowed)', async () => {
		const { container } = await renderUsers([
			// manageable: true so !manageable guard doesn't block; hasPermission gate
			// is bypassed in renderAsUser (all permissions granted for admin).
			baseUser({ manageable: true, isSelf: true })
		]);
		await waitFor(() => {
			const buttons = [...container.querySelectorAll('button')];
			const pwdBtn = buttons.find((b) => b.textContent?.trim() === 'Password');
			expect(pwdBtn).not.toBeNull();
			expect(pwdBtn!.disabled).toBe(false);
		});
	});

	// ── NORMAL row (manageable:true, isSelf:false) ────────────────────────────

	it('normal row: no protection indicator rendered', async () => {
		const { container } = await renderUsers([baseUser({ manageable: true, isSelf: false })]);
		await waitFor(() => {
			expect(container.querySelector('.sj-protection-indicator')).toBeNull();
		});
	});

	it('normal row: Mailbox lifecycle button is enabled', async () => {
		const { container } = await renderUsers([baseUser({ manageable: true, isSelf: false })]);
		await waitFor(() => {
			const buttons = [...container.querySelectorAll('button')];
			const delBtn = buttons.find((b) => b.textContent?.trim() === 'Mailbox lifecycle');
			expect(delBtn).not.toBeNull();
			expect(delBtn!.disabled).toBe(false);
		});
	});

	// ── i18n — 3-locale coverage ───────────────────────────────────────────────

	it('de locale: renders "Geschützt" badge text for protected row', async () => {
		await switchLocale('de');
		const { container } = await renderUsers([baseUser({ manageable: false, isSelf: false })]);
		await waitFor(() => {
			expect(container.textContent).toContain('Geschützt');
		});
	});

	it('de locale: renders "Sie" badge text for self row', async () => {
		await switchLocale('de');
		const { container } = await renderUsers([baseUser({ manageable: true, isSelf: true })]);
		await waitFor(() => {
			expect(container.textContent).toContain('Sie');
		});
	});

	it('zh locale: renders "受保护" badge text for protected row', async () => {
		await switchLocale('zh');
		const { container } = await renderUsers([baseUser({ manageable: false, isSelf: false })]);
		await waitFor(() => {
			expect(container.textContent).toContain('受保护');
		});
	});

	it('zh locale: renders "本人" badge text for self row', async () => {
		await switchLocale('zh');
		const { container } = await renderUsers([baseUser({ manageable: true, isSelf: true })]);
		await waitFor(() => {
			expect(container.textContent).toContain('本人');
		});
	});

	it('no hardcoded English in protected row (de locale shows non-English badge)', async () => {
		await switchLocale('de');
		const { container } = await renderUsers([baseUser({ manageable: false, isSelf: false })]);
		await waitFor(() => {
			// The badge text should be German "Geschützt", not English "Protected"
			const indicator = container.querySelector('.sj-protection-indicator');
			expect(indicator).not.toBeNull();
			expect(indicator!.textContent).not.toContain('Protected');
			expect(indicator!.textContent).toContain('Geschützt');
		});
	});
});
