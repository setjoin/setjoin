import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/svelte/svelte5';
import { jmapSession } from '$lib/stores/session';
import { resetStores } from '$lib/test-utils';
import * as client from '$lib/admin/client';
import type { ScopeSet, ScopeSetMember } from '$lib/admin/client';
import { clearToasts, toasts } from '$lib/components/ui';
import Page from './+page.svelte';

// The page deep-links off `$page.url.searchParams` inside onMount, so the
// mocked store exposes a mutable search string each render can vary.
const pageMock = vi.hoisted(() => ({ search: '' }));
vi.mock('$app/stores', () => ({
	page: {
		subscribe: (run: (value: unknown) => void) => {
			run({ url: new URL(`https://setjoin.test/admin/scope-sets${pageMock.search}`) });
			return () => {};
		}
	}
}));

// The editor dialog is its own component-under-test elsewhere; here a stub
// records the props the page passes so open/close/save wiring stays asserted
// without dragging in the editor's own fetch fan-out.
const editor = vi.hoisted(() => ({
	calls: [] as Array<{
		set: unknown;
		existingNames: string[];
		onClose: () => void;
		onSaved: () => void;
	}>
}));
vi.mock('$lib/components/admin/ScopeSetEditor.svelte', () => ({
	default: (...args: unknown[]) => {
		const props = (args[1] ?? args[0]) as {
			set: unknown;
			existingNames: string[];
			onClose: () => void;
			onSaved: () => void;
		};
		editor.calls.push(props);
		return null;
	}
}));

const sets: ScopeSet[] = [
	{ id: 1, name: 'engineering', description: 'Eng org', domainId: null },
	{ id: 2, name: 'contractors', domainId: null }
];

const members1: ScopeSetMember[] = [
	{ memberType: 'ou', memberId: 5 },
	{ memberType: 'ou', memberId: 6 },
	{ memberType: 'group', memberId: 9 },
	{ memberType: 'user', memberId: 100 },
	{ memberType: 'user', memberId: 101 },
	{ memberType: 'user', memberId: 102 }
];

function grant() {
	jmapSession.set({
		accounts: {},
		primaryAccounts: {},
		capabilities: {
			'urn:setjoin:params:jmap:mail': {
				admin: { consoles: ['system'], permissions: ['scope_sets.manage'] }
			}
		}
	} as never);
}

describe('/admin/scope-sets', () => {
	beforeEach(() => {
		resetStores();
		vi.clearAllMocks();
		editor.calls.length = 0;
		pageMock.search = '';
		clearToasts();
		vi.spyOn(client, 'adminListScopeSets').mockResolvedValue(sets);
		vi.spyOn(client, 'adminGetScopeSet').mockImplementation(async (id: number) => {
			if (id === 1) return { ...sets[0], members: members1 };
			throw new Error('set detail unavailable');
		});
		vi.spyOn(client, 'adminDeleteScopeSet').mockResolvedValue(undefined);
	});
	afterEach(() => resetStores());

	it('loads sets, resolves per-set composition, and renders rows', async () => {
		grant();
		render(Page);

		expect(await screen.findByText('engineering')).toBeInTheDocument();
		expect(screen.getByText('Eng org')).toBeInTheDocument();
		expect(screen.getByText('contractors')).toBeInTheDocument();
		// Reach summary for the fully-resolved set…
		expect(screen.getByText('2 departments · 1 groups · 3 users')).toBeInTheDocument();
		// …and the em-dash fallback when the per-set detail fetch fails.
		expect(screen.getByText('—')).toBeInTheDocument();
		expect(client.adminGetScopeSet).toHaveBeenCalledWith(1);
		expect(client.adminGetScopeSet).toHaveBeenCalledWith(2);
	});

	it('shows the loading spinner while the list request is in flight', async () => {
		grant();
		let resolveList!: (value: typeof sets) => void;
		vi.mocked(client.adminListScopeSets).mockImplementationOnce(
			() =>
				new Promise((resolve) => {
					resolveList = resolve;
				})
		);
		const { container } = render(Page);

		expect(container.querySelector('.sj-loading')).toBeTruthy();
		expect(screen.getByRole('status')).toBeInTheDocument();

		resolveList([]);
		expect(await screen.findByText('No scope-sets yet')).toBeInTheDocument();
	});

	it('renders the empty teach state with create entries for managers', async () => {
		grant();
		vi.mocked(client.adminListScopeSets).mockResolvedValue([]);
		render(Page);

		expect(await screen.findByText('No scope-sets yet')).toBeInTheDocument();
		// Header + empty-state create buttons.
		expect(screen.getAllByRole('button', { name: 'Create scope-set' }).length).toBe(2);
	});

	it('hides write controls and blocks name-click editing without scope_sets.manage', async () => {
		render(Page);
		expect(await screen.findByText('engineering')).toBeInTheDocument();
		expect(screen.queryByRole('button', { name: 'Create scope-set' })).not.toBeInTheDocument();
		expect(screen.queryByRole('button', { name: 'Edit' })).not.toBeInTheDocument();
		expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument();

		// The name is still a button but must not open the editor.
		await fireEvent.click(screen.getByRole('button', { name: 'engineering' }));
		expect(editor.calls.length).toBe(0);

		// Empty state without the permission: no create affordance either.
		vi.mocked(client.adminListScopeSets).mockResolvedValue([]);
		const second = render(Page);
		expect(await screen.findByText('No scope-sets yet')).toBeInTheDocument();
		expect(screen.queryByRole('button', { name: 'Create scope-set' })).not.toBeInTheDocument();
		second.unmount();
	});

	it('opens create/edit editors with targets, existing names, and reload/close wiring', async () => {
		grant();
		render(Page);
		await screen.findByText('engineering');

		// Create: null target + current names.
		await fireEvent.click(screen.getByRole('button', { name: 'Create scope-set' }));
		await waitFor(() => expect(editor.calls.length).toBe(1));
		expect(editor.calls[0].set).toBeNull();
		expect(editor.calls[0].existingNames).toEqual(['engineering', 'contractors']);
		editor.calls[0].onClose();

		// Edit via the row name button.
		await fireEvent.click(screen.getByRole('button', { name: 'engineering' }));
		await waitFor(() => expect(editor.calls.length).toBe(2));
		expect(editor.calls[1].set).toMatchObject({ id: 1, name: 'engineering' });
		editor.calls[1].onClose();

		// Edit via the row Edit button; onSaved re-runs the list load.
		await fireEvent.click(screen.getAllByRole('button', { name: 'Edit' })[1]);
		await waitFor(() => expect(editor.calls.length).toBe(3));
		expect(editor.calls[2].set).toMatchObject({ id: 2, name: 'contractors' });
		editor.calls[2].onSaved();
		await waitFor(() => expect(client.adminListScopeSets).toHaveBeenCalledTimes(2));
		// load() re-enters the loading state; wait for the table to come back.
		await screen.findByText('contractors');

		// onClose resets so the editor can be reopened.
		editor.calls[2].onClose();
		await fireEvent.click(screen.getAllByRole('button', { name: 'Edit' })[1]);
		await waitFor(() => expect(editor.calls.length).toBe(4));
	});

	it('deep links ?id= to open that set only when permitted and finite', async () => {
		grant();
		pageMock.search = '?id=2';
		const first = render(Page);
		await waitFor(() => expect(editor.calls.length).toBe(1));
		expect(editor.calls[0].set).toMatchObject({ id: 2 });
		first.unmount();

		// Non-numeric ids are ignored.
		pageMock.search = '?id=abc';
		const second = render(Page);
		await screen.findByText('contractors');
		expect(editor.calls.length).toBe(1);
		second.unmount();

		// Without scope_sets.manage the deep link stays inert.
		resetStores();
		pageMock.search = '?id=2';
		const third = render(Page);
		await screen.findByText('contractors');
		expect(editor.calls.length).toBe(1);
		third.unmount();
	});

	it('deletes a set after confirmation and reloads with a toast', async () => {
		grant();
		render(Page);
		await screen.findByText('engineering');

		await fireEvent.click(screen.getAllByRole('button', { name: 'Delete' })[0]);
		const dialog = screen.getByRole('dialog', { name: 'Delete scope-set' });
		expect(
			within(dialog).getByText(/Delete “engineering”\? This can’t be undone\./)
		).toBeInTheDocument();

		await fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }));
		await waitFor(() => expect(client.adminDeleteScopeSet).toHaveBeenCalledWith(1));
		await waitFor(() => expect(client.adminListScopeSets).toHaveBeenCalledTimes(2));
		expect(toasts.some((t) => t.message === 'Scope-set deleted.')).toBe(true);
		await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
	});

	it('surfaces the backend restriction message when deletion is blocked', async () => {
		grant();
		let rejectDelete!: (e: Error) => void;
		vi.mocked(client.adminDeleteScopeSet).mockImplementationOnce(
			() =>
				new Promise((_, reject) => {
					rejectDelete = reject;
				})
		);
		render(Page);
		await screen.findByText('engineering');

		await fireEvent.click(screen.getAllByRole('button', { name: 'Delete' })[0]);
		const dialog = screen.getByRole('dialog', { name: 'Delete scope-set' });
		await fireEvent.click(within(dialog).getByRole('button', { name: /Delete/ }));

		// In-flight: confirm disabled with a spinner, dialog stays open.
		await waitFor(() =>
			expect(within(dialog).getByRole('button', { name: /Delete/ })).toBeDisabled()
		);
		expect(within(dialog).getByRole('status')).toBeTruthy();

		// The RESTRICT 409 problem message lands inline in the dialog.
		rejectDelete(new Error('2 admins are scoped to this set'));
		expect(await within(dialog).findByText('2 admins are scoped to this set')).toBeInTheDocument();
		expect(screen.getByRole('dialog', { name: 'Delete scope-set' })).toBeInTheDocument();
	});

	it('cancels deletion via Cancel and the backdrop Close button', async () => {
		grant();
		render(Page);
		await screen.findByText('engineering');

		await fireEvent.click(screen.getAllByRole('button', { name: 'Delete' })[0]);
		let dialog = screen.getByRole('dialog', { name: 'Delete scope-set' });
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
		expect(screen.queryByRole('dialog')).not.toBeInTheDocument();

		await fireEvent.click(screen.getAllByRole('button', { name: 'Delete' })[0]);
		dialog = screen.getByRole('dialog', { name: 'Delete scope-set' });
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Close' }));
		expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
		expect(client.adminDeleteScopeSet).not.toHaveBeenCalled();
	});

	it('shows the list error state while management stays available', async () => {
		grant();
		vi.mocked(client.adminListScopeSets).mockRejectedValueOnce(new Error('scope sets offline'));
		render(Page);

		expect(await screen.findByRole('alert')).toHaveTextContent('scope sets offline');
		// The list request failed so sets is empty: header + empty-state create.
		expect(screen.getAllByRole('button', { name: 'Create scope-set' }).length).toBe(2);
	});
});
