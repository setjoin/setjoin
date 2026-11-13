import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import { tasks, viewMode, searchText, statusFilter } from '$lib/stores/tasks';
import { toasts, clearToasts } from '$lib/components/ui';
import TasksPage from './tasks/+page.svelte';

function createControlledPromise() {
	let resolve!: (value: any) => void;
	const promise = new Promise<any>((res) => { resolve = res; });
	return { promise, resolve };
}

describe('Tasks Page - Loading States', () => {
	let saveCtrl = createControlledPromise();
	let deleteCtrl = createControlledPromise();
	let saveCalls = 0;
	let deleteCalls = 0;

	function resetCtrls() {
		saveCtrl = createControlledPromise();
		deleteCtrl = createControlledPromise();
		saveCalls = 0;
		deleteCalls = 0;
	}

	function setupFetch(tasksList: any[] = [], interceptSave = true, interceptDelete = true) {
		vi.stubGlobal('fetch', vi.fn(async (_input: any, _init?: any) => {
			const url = typeof _input === 'string' ? _input : _input.toString();

			// Handle /.well-known/jmap (session discovery)
			if (url.includes('/.well-known/jmap')) {
				return {
					ok: true, status: 200,
					json: async () => ({ apiUrl: '/jmap', downloadUrl: '/blobs', uploadUrl: '/blobs', eventSourceUrl: '', username: 'alice@test.local', primaryAccounts: { 'urn:ietf:params:jmap:mail': 'a1' }, accounts: { a1: { name: 'alice@test.local' } } }),
					text: async () => '',
				};
			}

			const body = _init?.body ? JSON.parse(_init.body as string) : {};
			const methodCalls = body.methodCalls || [];

			// Intercept Task/set
			const taskSetCall = methodCalls.find((mc: string[]) => mc[0] === 'Task/set');
			if (taskSetCall) {
				const [, args] = taskSetCall;
				const hasDestroy = args && args.destroy && (Array.isArray(args.destroy) && args.destroy.length > 0);
				if (hasDestroy && interceptDelete) {
					deleteCalls++;
					return deleteCtrl.promise;
				}
				if (!hasDestroy && interceptSave) {
					saveCalls++;
					return saveCtrl.promise;
				}
				// Fallback: return success immediately
				const responses = [['Task/set', { created: {}, updated: {}, destroyed: [] }, '0']];
				return { ok: true, status: 200, json: async () => ({ methodResponses: responses }), text: async () => '' };
			}

			// Build response for known method calls
			const responses: any[] = [];
			for (const mc of methodCalls) {
				const [name, _args, callId] = mc;
				if (name === 'Task/query') {
					responses.push([name, { ids: tasksList.map((t: any) => t.id), total: tasksList.length, position: tasksList.length }, callId]);
				} else if (name === 'Task/get') {
					responses.push([name, { list: tasksList, state: 's1' }, callId]);
				} else if (name === 'Session') {
					responses.push([name, {
						accounts: { a1: { name: 'alice@test.local', isPrimary: true } },
						primaryAccounts: { 'urn:ietf:params:jmap:mail': 'a1' },
						capabilities: { 'urn:ietf:params:jmap:core': {} }
					}, callId]);
				} else {
					responses.push([name, {}, callId]);
				}
			}
			return { ok: true, status: 200, json: async () => ({ methodResponses: responses }), text: async () => '' };
		}));
	}

	beforeEach(() => {
		resetStores();
		resetCtrls();
		clearToasts();
		tasks.set([]);
		viewMode.set('list');
		searchText.set('');
		statusFilter.set(null);
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('mounts tasks page without crashing', async () => {
		setupFetch([]);
		const { container } = await renderAsUser(TasksPage);
		expect(container).toBeTruthy();
	});

	it('disables Save button and shows loading text during task save', async () => {
		setupFetch([]);
		await renderAsUser(TasksPage);

		// Open create modal
		await waitFor(() => {
			expect(screen.getByText('New task')).toBeTruthy();
		});
		fireEvent.click(screen.getByText('New task').closest('button')!);

		// Save button starts enabled (validation happens on submit)
		await waitFor(() => {
			expect(screen.getByText('Save')).toBeTruthy();
		});
		const saveBtn = screen.getByText('Save').closest('button')!;

		// Set title so validation passes
		const titleInput = screen.getByLabelText('Title') as HTMLInputElement;
		titleInput.value = 'Test Task';
		fireEvent.input(titleInput);

		// Click Save — button should show 'Saving...' and become disabled
		fireEvent.click(saveBtn);

		// Should show 'Saving...' and be disabled during save
		await waitFor(() => {
			expect(saveBtn.textContent).toContain('Saving...');
		});
		expect(saveBtn.disabled).toBe(true);

		// Resolve save
		saveCtrl.resolve({
			ok: true, status: 200,
			json: async () => ({ methodResponses: [[
				'Task/set', { created: { k1: { id: 't1' } }, updated: {}, destroyed: [] }, '0'
			]] }),
			text: async () => '',
		});

		// After save completes, modal closes
		await waitFor(() => {
			expect(screen.queryByText('Save')).toBeFalsy();
		});
	});

	it('shows tasks when store has data', async () => {
		const mockTask = { id: 't1', title: 'Task to delete', status: 'needs-action' as const, priority: 0 };
		// Pre-populate the store and set up fetch for onMount calls
		tasks.set([mockTask as any]);
		setupFetch([mockTask]);

		await renderAsUser(TasksPage);

		// Task should be visible
		await waitFor(() => {
			expect(screen.getByText('Task to delete')).toBeTruthy();
		});
	});

	it('list rows are keyboard-accessible (role=button, tabindex, key handler)', async () => {
		const mockTask = { id: 't1', title: 'Keyboard Task', status: 'needs-action' as const, priority: 0 };
		tasks.set([mockTask as any]);
		setupFetch([mockTask]);
		viewMode.set('list');

		await renderAsUser(TasksPage);

		await waitFor(() => {
			expect(screen.getByText('Keyboard Task')).toBeTruthy();
		});

		const row = document.querySelector('tr.list-row') as HTMLElement;
		expect(row).toBeTruthy();
		expect(row.getAttribute('role')).toBe('button');
		expect(row.getAttribute('tabindex')).toBe('0');

		// Space opens the detail modal (Enter-only is insufficient per WCAG 4.1.2).
		fireEvent.keyDown(row, { key: ' ' });
		await waitFor(() => {
			// Detail dialog renders the Edit action button.
			expect(screen.getByText('Edit')).toBeTruthy();
		});
	});

	it('deletes a task directly without a confirm() dialog (act-then-undo)', async () => {
		const mockTask = { id: 't1', title: 'Task to delete', status: 'needs-action' as const, priority: 0 };
		tasks.set([mockTask]);
		setupFetch([mockTask]);
		// confirm() must NOT be used for reversible actions (AGENTS.md voice rule).
		// Stub it to throw so any accidental usage fails the test loudly.
		const confirmMock = vi.fn(() => { throw new Error('confirm() must not be called'); });
		vi.stubGlobal('confirm', confirmMock);

		await renderAsUser(TasksPage);

		await waitFor(() => {
			expect(screen.getByText('Task to delete')).toBeTruthy();
		});

		// Find delete button by aria-label (restyled uses the Trash2 Lucide icon, not an emoji)
		const deleteBtn = document.querySelector('button[aria-label="Delete task"]') as HTMLButtonElement;
		expect(deleteBtn).toBeTruthy();

		fireEvent.click(deleteBtn);

		// No confirm dialog — the delete request fires immediately.
		expect(confirmMock).not.toHaveBeenCalled();
		await waitFor(() => {
			expect(deleteCalls).toBe(1);
		});

		// Resolve delete
		deleteCtrl.resolve({
			ok: true, status: 200,
			json: async () => ({ methodResponses: [[
				'Task/set', { destroyed: ['t1'] }, '0'
			]] }),
			text: async () => '',
		});

		// Destructive Task/delete cannot restore identity, children, or activity;
		// the UI therefore offers an honest copy restoration rather than "Undo".
		await waitFor(() => {
			expect(toasts.some((t) => t.actionLabel === 'Restore copy')).toBe(true);
		});
	});

	it('prevents double submit on Save button', async () => {
		setupFetch([]);
		await renderAsUser(TasksPage);

		await waitFor(() => {
			expect(screen.getByText('New task')).toBeTruthy();
		});
		fireEvent.click(screen.getByText('New task').closest('button')!);

		await waitFor(() => {
			expect(screen.getByText('Save')).toBeTruthy();
		});
		const titleInput = screen.getByLabelText('Title') as HTMLInputElement;
		titleInput.value = 'Test';
		fireEvent.input(titleInput);

		const saveBtn = screen.getByText('Save').closest('button')!;
		await waitFor(() => {
			expect(saveBtn.disabled).toBe(false);
		});

		fireEvent.click(saveBtn);
		// The guard (saving=true) should prevent second click from starting a new request
		fireEvent.click(saveBtn);

		// saveCalls is incremented synchronously inside the fetch stub before the promise
		await waitFor(() => {
			expect(saveCalls).toBe(1);
		});

		saveCtrl.resolve({
			ok: true, status: 200,
			json: async () => ({ methodResponses: [['Task/set', { created: { k1: { id: 't1' } } }, '0']] }),
			text: async () => '',
		});
	});
});
