import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte/svelte5';
import { contacts } from '$lib/stores/contacts';
import ContactGroupModal from './ContactGroupModal.svelte';

const groupMocks = vi.hoisted(() => ({
	createGroup: vi.fn(),
	renameGroup: vi.fn(),
	setMembers: vi.fn(),
}));

vi.mock('$lib/stores/contactGroups', () => groupMocks);

describe('ContactGroupModal behavior', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		groupMocks.createGroup.mockResolvedValue('g-new');
		groupMocks.renameGroup.mockResolvedValue(undefined);
		groupMocks.setMembers.mockResolvedValue(undefined);
		contacts.set([{
			id: 'c1',
			displayName: 'Ada Lovelace',
			emails: [{ address: 'ada@example.test', type: 'work', is_primary: true }],
		} as never]);
	});

	it('validates, builds a group from contact and direct-email members, and closes', async () => {
		const onClose = vi.fn();
		const onSaved = vi.fn();
		render(ContactGroupModal, { open: true, onClose, onSaved });

		await fireEvent.click(screen.getByRole('button', { name: 'Save group' }));
		expect(screen.getByRole('alert')).toHaveTextContent('Give the group a name.');

		await fireEvent.input(screen.getByLabelText('Group name'), { target: { value: 'Project team' } });
		const picker = document.querySelector('select') as HTMLSelectElement;
		await fireEvent.change(picker, { target: { value: 'c1' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Add member' }));
		expect(screen.getByText('Ada Lovelace')).toBeInTheDocument();

		const email = screen.getByLabelText('Add email address');
		await fireEvent.input(email, { target: { value: 'outside@example.test' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Add email address' }));
		expect(screen.getByText('outside@example.test')).toBeInTheDocument();

		await fireEvent.click(screen.getByRole('button', { name: 'Save group' }));
		await waitFor(() => expect(groupMocks.createGroup).toHaveBeenCalledWith('Project team'));
		expect(groupMocks.setMembers).toHaveBeenCalledWith('g-new', [
			{ contactId: 'c1' },
			{ email: 'outside@example.test' },
		], []);
		expect(onSaved).toHaveBeenCalledOnce();
		expect(onClose).toHaveBeenCalledOnce();
	});

	it('edits by exact member delta and keeps the dialog open on a server error', async () => {
		groupMocks.setMembers.mockRejectedValueOnce(new Error('Group update rejected'));
		const group = {
			id: 'g1',
			name: 'Old team',
			members: [{ contactId: 'c1', email: 'ada@example.test', displayName: 'Ada Lovelace' }, { email: 'remove@example.test' }],
		};
		const onClose = vi.fn();
		render(ContactGroupModal, { open: true, group: group as never, onClose });
		await fireEvent.input(screen.getByLabelText('Group name'), { target: { value: 'New team' } });
		const removeButtons = screen.getAllByRole('button', { name: 'Delete group' });
		await fireEvent.click(removeButtons[1]);
		await fireEvent.click(screen.getByRole('button', { name: 'Save group' }));

		await waitFor(() => expect(groupMocks.renameGroup).toHaveBeenCalledWith('g1', 'New team'));
		expect(groupMocks.setMembers).toHaveBeenCalledWith('g1', [], [{ email: 'remove@example.test' }]);
		expect(screen.getByRole('alert')).toHaveTextContent('Group update rejected');
		expect(onClose).not.toHaveBeenCalled();
	});
});
