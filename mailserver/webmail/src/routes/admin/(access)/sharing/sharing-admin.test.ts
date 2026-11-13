import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import { renderAsUser, resetStores, mockSessionLoad } from '$lib/test-utils';
import { jmapSession } from '$lib/stores/session';

import SharingPage from './+page.svelte';
import SharingDefaultEditor from './SharingDefaultEditor.svelte';

const DEFAULTS = [
	{
		id: 11,
		resource: 'calendar',
		ownerScope: 'org',
		ownerRef: 1,
		ownerLabel: 'test.local',
		audience: 'everyone',
		audienceRef: 1,
		audienceLabel: 'test.local',
		level: 'freebusy',
		createdBy: 3,
		updatedAt: '2026-07-03 12:00:00'
	}
];

function setSharingPerms(perms = ['sharing.read', 'sharing.manage']) {
	jmapSession.set({
		accounts: { a1: { name: 'admin@test.local', isPrimary: true } },
		primaryAccounts: { 'urn:ietf:params:jmap:mail': 'a1' },
		capabilities: {
			'urn:ietf:params:jmap:core': {},
			'urn:setjoin:params:jmap:mail': {
				admin: { consoles: ['access'], permissions: perms }
			}
		}
	} as any);
}

function stubFetch(defaults: unknown[] = DEFAULTS, fixtures: { users?: unknown[]; oversight?: unknown; audit?: unknown[] } = {}) {
	const calls: { url: string; method: string }[] = [];
	vi.stubGlobal(
		'fetch',
		vi.fn((url: string, init?: RequestInit) => {
			const method = init?.method ?? 'GET';
			calls.push({ url, method });
			if (url.includes('/api/admin/sharing/defaults') && method === 'GET') {
				return Promise.resolve({ ok: true, status: 200, json: async () => defaults, text: async () => '' });
			}
			if (url.includes('/api/admin/sharing/audit')) {
				return Promise.resolve({ ok: true, status: 200, json: async () => fixtures.audit ?? [], text: async () => '' });
			}
			if (url.includes('/api/admin/sharing/users/')) {
				return Promise.resolve({ ok: true, status: 200, json: async () => fixtures.oversight ?? {}, text: async () => '' });
			}
			if (url.includes('/api/admin/users')) {
				return Promise.resolve({ ok: true, status: 200, json: async () => fixtures.users ?? [], text: async () => '' });
			}
			if (url.includes('/api/admin/domains')) {
				return Promise.resolve({ ok: true, status: 200, json: async () => [{ id: 1, name: 'test.local' }], text: async () => '' });
			}
			if (url.includes('/api/admin/distribution-groups') || url.includes('/api/admin/departments/tree')) {
				return Promise.resolve({ ok: true, status: 200, json: async () => [], text: async () => '' });
			}
			return Promise.resolve({ ok: true, status: 204, json: async () => ({}), text: async () => '' });
		})
	);
	return calls;
}

describe('admin sharing console', () => {
	beforeEach(() => {
		resetStores();
		mockSessionLoad();
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('renders three tabs: defaults, per-user, audit', async () => {
		stubFetch();
		setSharingPerms();
		const { container } = await renderAsUser(SharingPage, {}, { isAdmin: true });
		await new Promise((r) => setTimeout(r, 30));
		expect(container.querySelectorAll('[role="tab"]').length).toBe(3);
	});

	it('lists sharing defaults with resolved labels + the precedence note', async () => {
		stubFetch();
		setSharingPerms();
		await renderAsUser(SharingPage, {}, { isAdmin: true });
		await waitFor(() => expect(screen.getByText(/Whole domain — test.local/)).toBeTruthy());
		expect(screen.getByText(/More specific rules override this/)).toBeTruthy();
	});

	it('shows the §6-D empty state with a create CTA when no policies exist', async () => {
		stubFetch([]);
		// renderAsUser overwrites jmapSession, so grant the perms AFTER render.
		await renderAsUser(SharingPage, {}, { isAdmin: true });
		setSharingPerms();
		await waitFor(() => expect(screen.getByText('No sharing defaults')).toBeTruthy());
		await waitFor(() => expect(screen.getAllByText('Add default').length).toBeGreaterThan(0));
	});

	it('delete fires DELETE /api/admin/sharing/defaults/{id}', async () => {
		const calls = stubFetch();
		await renderAsUser(SharingPage, {}, { isAdmin: true });
		setSharingPerms();
		await waitFor(() => expect(screen.getByText(/Whole domain — test.local/)).toBeTruthy());
		await waitFor(() => expect(screen.getByLabelText('Delete default')).toBeTruthy());

		await fireEvent.click(screen.getByLabelText('Delete default'));
		await waitFor(() => {
			expect(calls.some((c) => c.method === 'DELETE' && c.url.includes('/api/admin/sharing/defaults/11'))).toBe(true);
		});
	});

	it('hides the manage affordances for a read-only (sharing.read) admin', async () => {
		stubFetch();
		setSharingPerms(['sharing.read']);
		await renderAsUser(SharingPage, {}, { isAdmin: true });
		await waitFor(() => expect(screen.getByText(/Whole domain — test.local/)).toBeTruthy());
		expect(screen.queryByText('Add default')).toBeNull();
		expect(screen.queryByLabelText('Delete default')).toBeNull();
	});

	it('searches per-user oversight and renders effective grants and delegates', async () => {
		stubFetch(DEFAULTS, {
			users: [{ id: 42, email: 'alice@test.local', displayName: 'Alice' }],
			oversight: {
				userId: 42, email: 'alice@test.local', displayName: 'Alice',
				defaults: [{ ...DEFAULTS[0], id: 12, ownerScope: 'user', ownerLabel: 'alice@test.local' }],
				calendarGrants: [{ calendarId: 'cal-1', calendarName: 'Team', userEmail: 'bob@test.local', level: 'read' }],
				delegates: [{ userId: 8, email: 'delegate@test.local', permission: 'read' }],
			},
		});
		await renderAsUser(SharingPage, {}, { isAdmin: true }); setSharingPerms();
		await fireEvent.click(screen.getByRole('tab', { name: 'Per-user' }));
		await fireEvent.input(screen.getByLabelText('Find a user'), { target: { value: 'alice' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Search' }));
		await waitFor(() => expect(screen.getByRole('button', { name: /alice@test\.local/ })).toBeInTheDocument());
		await fireEvent.click(screen.getByRole('button', { name: /alice@test\.local/ }));
		await waitFor(() => expect(screen.getByText(/bob@test\.local/)).toBeInTheDocument());
		expect(screen.getByText(/delegate@test\.local/)).toBeInTheDocument();
		expect(screen.getByRole('button', { name: 'Set user default' })).toBeInTheDocument();
	});

	it('filters and renders sharing audit evidence', async () => {
		stubFetch(DEFAULTS, {
			users: [{ id: 42, email: 'alice@test.local', displayName: 'Alice' }],
			audit: [{ id: 91, occurredAt: '2026-07-03 12:34:00', userEmail: 'admin@test.local', action: 'sharing_default.created', targetType: 'user', targetId: '42' }],
		});
		await renderAsUser(SharingPage, {}, { isAdmin: true }); setSharingPerms();
		await fireEvent.click(screen.getByRole('tab', { name: 'Audit' }));
		await fireEvent.input(screen.getByLabelText('Filter by user'), { target: { value: 'alice' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
		await waitFor(() => expect(screen.getByText('sharing_default.created')).toBeInTheDocument());
		expect(screen.getByText('admin@test.local')).toBeInTheDocument();
		expect(screen.getByText(/user 42/)).toBeInTheDocument();
	});
});

describe('SharingDefaultEditor', () => {
	beforeEach(() => {
		resetStores();
		mockSessionLoad();
	});
	afterEach(() => vi.unstubAllGlobals());

	it('renders the precedence note, the level radiogroup, and validates incompleteness in-dialog', async () => {
		stubFetch();
		const onSubmit = vi.fn(async () => {});
		render(SharingDefaultEditor, { open: true, onSubmit, oncancel: () => {} });
		await new Promise((r) => setTimeout(r, 30));

		expect(screen.getByText(/More specific rules override this/)).toBeTruthy();
		expect(screen.getByRole('radiogroup', { name: 'Visibility level' })).toBeTruthy();

		// nothing picked → in-dialog validation error, no submit
		await fireEvent.click(screen.getByText('Save').closest('button')!);
		await waitFor(() => expect(screen.getByRole('alert')).toBeTruthy());
		expect(onSubmit).not.toHaveBeenCalled();
	});

	it('submits the picked org default', async () => {
		stubFetch();
		const onSubmit = vi.fn(async () => {});
		render(SharingDefaultEditor, { open: true, onSubmit, oncancel: () => {} });
		// wait for the domain options to actually load (label renders before the fetch lands)
		await waitFor(() =>
			expect((screen.getByLabelText('Domain') as HTMLSelectElement).options.length).toBeGreaterThan(1)
		);

		await fireEvent.change(screen.getByLabelText('Domain'), { target: { value: '1' } });
		await fireEvent.change(screen.getByLabelText('Audience domain'), { target: { value: '1' } });
		await fireEvent.click(screen.getByRole('radio', { name: 'Free-busy' }));
		await fireEvent.click(screen.getByText('Save').closest('button')!);

		await waitFor(() => {
			expect(onSubmit).toHaveBeenCalledWith({
				ownerScope: 'org',
				ownerRef: 1,
				audience: 'everyone',
				audienceRef: 1,
				level: 'freebusy'
			});
		});
	});
});
