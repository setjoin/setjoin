import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte/svelte5';
import { jmapSession } from '$lib/stores/session';
import { resetStores } from '$lib/test-utils';
const api = vi.hoisted(() => ({ list: vi.fn(), create: vi.fn(), remove: vi.fn() }));
vi.mock('$lib/admin/client', () => ({ listIPRules: api.list, createIPRule: api.create, deleteIPRule: api.remove }));
import IPRulesDialog from './IPRulesDialog.svelte';

const rule = { id: 7, cidr: '10.0.0.0/8', action: 'block', description: 'private', expiresAt: null };
function grant() { jmapSession.set({ accounts: {}, primaryAccounts: {}, capabilities: { 'urn:setjoin:params:jmap:mail': { admin: { consoles: ['auth'], permissions: ['security.write'] } } } } as never); }

describe('IPRulesDialog', () => {
	beforeEach(() => { resetStores(); vi.clearAllMocks(); api.list.mockResolvedValue({ rows: [rule] }); api.create.mockResolvedValue({}); api.remove.mockResolvedValue({}); });
	afterEach(() => resetStores());
	it('loads, validates, creates, and confirms deletion of a rule', async () => {
		render(IPRulesDialog, { open: true, onClose: vi.fn() }); grant();
		await waitFor(() => expect(screen.getByText('10.0.0.0/8')).toBeInTheDocument());
		await fireEvent.click(screen.getByRole('button', { name: 'Add rule' }));
		await fireEvent.input(screen.getByLabelText('CIDR'), { target: { value: 'invalid' } });
		await fireEvent.click(screen.getAllByRole('button', { name: 'Add rule' }).at(-1)!);
		expect(screen.getByText(/CIDR must include a prefix/)).toBeInTheDocument();
		await fireEvent.input(screen.getByLabelText('CIDR'), { target: { value: '192.0.2.0/24' } });
		await fireEvent.change(screen.getByLabelText('Action'), { target: { value: 'allow' } });
		await fireEvent.input(screen.getByLabelText('Description'), { target: { value: ' Office ' } });
		await fireEvent.click(screen.getAllByRole('button', { name: 'Add rule' }).at(-1)!);
		await waitFor(() => expect(api.create).toHaveBeenCalledWith({ cidr: '192.0.2.0/24', action: 'allow', description: 'Office' }));
		await fireEvent.click(screen.getByRole('button', { name: 'Delete rule' }));
		await fireEvent.click(screen.getByRole('button', { name: 'Yes, delete' }));
		await waitFor(() => expect(api.remove).toHaveBeenCalledWith(7));
	});

	it('shows a bounded loading failure and remains closed when requested', async () => {
		api.list.mockRejectedValueOnce(new Error('rules unavailable'));
		const { rerender } = render(IPRulesDialog, { open: true, onClose: vi.fn() });
		await waitFor(() => expect(screen.getByText('rules unavailable')).toBeInTheDocument());
		await rerender({ open: false, onClose: vi.fn() });
		expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
	});
});
