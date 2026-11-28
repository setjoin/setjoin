import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, within } from '@testing-library/svelte/svelte5';
import MembersSheet from './MembersSheet.svelte';
import type { DriveMember } from '$lib/drive/api';
import type { DirectoryMember } from '$lib/stores/directory';

const listMembers = vi.fn();
const grantMember = vi.fn();
const revokeMember = vi.fn();
const directorySearch = vi.fn();
const setDirectoryAccountId = vi.fn();

vi.mock('$lib/drive/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/drive/api')>('$lib/drive/api');
	return {
		...actual,
		listMembers: (...a: unknown[]) => listMembers(...a),
		grantMember: (...a: unknown[]) => grantMember(...a),
		revokeMember: (...a: unknown[]) => revokeMember(...a),
	};
});

vi.mock('$lib/stores/directory', () => ({
	directorySearch: (...a: unknown[]) => directorySearch(...a),
	setDirectoryAccountId: (...a: unknown[]) => setDirectoryAccountId(...a),
}));

function member(overrides: Partial<DriveMember> = {}): DriveMember {
	return { userId: 7, role: 'editor', email: 'bob@example.com', displayName: 'Bob', grantedAt: '2026-07-01T00:00:00Z', ...overrides };
}

function candidate(overrides: Partial<DirectoryMember> = {}): DirectoryMember {
	return {
		id: '9',
		email: 'alice@example.com',
		displayName: 'Alice',
		firstName: 'Alice',
		lastName: null,
		phone: null,
		jobTitle: null,
		department: null,
		isManager: false,
		avatar: null,
		...overrides,
	};
}

describe('MembersSheet (Task 15: self-fetch)', () => {
	beforeEach(() => {
		listMembers.mockReset();
		grantMember.mockReset();
		revokeMember.mockReset();
		directorySearch.mockReset();
		setDirectoryAccountId.mockReset();
	});

	it('self-fetches the member list on open, keyed on spaceId', async () => {
		listMembers.mockResolvedValue([member()]);
		render(MembersSheet, { open: true, spaceId: 3, isManager: true, selfEmail: 'me@example.com', onClose: vi.fn() });
		await vi.waitFor(() => expect(listMembers).toHaveBeenCalledWith(3));
		await vi.waitFor(() => expect(screen.getByText('Bob')).toBeTruthy());
	});

	it('searches by directory identity, grants the selected member, and reloads', async () => {
		listMembers.mockResolvedValue([]);
		grantMember.mockResolvedValue(undefined);
		directorySearch.mockResolvedValue([candidate()]);
		render(MembersSheet, { open: true, spaceId: 3, isManager: true, selfEmail: 'me@example.com', onClose: vi.fn() });
		await vi.waitFor(() => expect(listMembers).toHaveBeenCalledWith(3));
		const input = screen.getByPlaceholderText('Search by name or email');
		await fireEvent.input(input, { target: { value: 'alice@' } });
		await vi.waitFor(() => expect(directorySearch).toHaveBeenCalledWith('alice@', 8));
		expect(setDirectoryAccountId).toHaveBeenCalledWith('-1');
		await fireEvent.click(await screen.findByRole('button', { name: /Alice/ }));
		await fireEvent.click(screen.getByRole('button', { name: 'Add member' }));
		await vi.waitFor(() => expect(grantMember).toHaveBeenCalledWith(3, 9, 'viewer'));
		await vi.waitFor(() => expect(listMembers).toHaveBeenCalledTimes(2));
	});

	it('filters current members from directory results', async () => {
		listMembers.mockResolvedValue([member()]);
		directorySearch.mockResolvedValue([
			candidate({ id: '7', email: 'bob@example.com', displayName: 'Bob' }),
			candidate({ id: '9', email: 'carol@example.com', displayName: 'Carol' }),
		]);
		render(MembersSheet, { open: true, spaceId: 3, isManager: true, selfEmail: 'me@example.com', onClose: vi.fn() });
		await vi.waitFor(() => expect(screen.getByText('Bob')).toBeTruthy());
		await fireEvent.input(screen.getByPlaceholderText('Search by name or email'), { target: { value: 'example' } });
		const results = await screen.findByRole('list', { name: 'Search results' });
		expect(within(results).queryByText('Bob')).toBeNull();
		expect(within(results).getByText('Carol')).toBeTruthy();
	});

	it('does not search until the query has at least two characters', async () => {
		listMembers.mockResolvedValue([]);
		render(MembersSheet, { open: true, spaceId: 3, isManager: true, selfEmail: 'me@example.com', onClose: vi.fn() });
		await fireEvent.input(screen.getByPlaceholderText('Search by name or email'), { target: { value: 'a' } });
		await Promise.resolve();
		expect(directorySearch).not.toHaveBeenCalled();
	});

	it('ignores a stale search response after a newer query resolves', async () => {
		listMembers.mockResolvedValue([]);
		let resolveOld!: (value: DirectoryMember[]) => void;
		let resolveNew!: (value: DirectoryMember[]) => void;
		directorySearch
			.mockImplementationOnce(() => new Promise<DirectoryMember[]>((resolve) => { resolveOld = resolve; }))
			.mockImplementationOnce(() => new Promise<DirectoryMember[]>((resolve) => { resolveNew = resolve; }));
		render(MembersSheet, { open: true, spaceId: 3, isManager: true, selfEmail: 'me@example.com', onClose: vi.fn() });
		const input = screen.getByPlaceholderText('Search by name or email');
		await fireEvent.input(input, { target: { value: 'al' } });
		await fireEvent.input(input, { target: { value: 'ali' } });
		resolveNew([candidate({ displayName: 'Newest Alice' })]);
		await vi.waitFor(() => expect(screen.getByText('Newest Alice')).toBeTruthy());
		resolveOld([candidate({ id: '10', email: 'old@example.com', displayName: 'Old Alice' })]);
		await Promise.resolve();
		expect(screen.queryByText('Old Alice')).toBeNull();
		expect(screen.getByText('Newest Alice')).toBeTruthy();
	});

	it('shows a localized error when directory search fails', async () => {
		listMembers.mockResolvedValue([]);
		directorySearch.mockRejectedValue(new Error('offline'));
		render(MembersSheet, { open: true, spaceId: 3, isManager: true, selfEmail: 'me@example.com', onClose: vi.fn() });
		await fireEvent.input(screen.getByPlaceholderText('Search by name or email'), { target: { value: 'alice' } });
		await vi.waitFor(() => expect(screen.getByRole('alert').textContent).toContain('Could not search the directory'));
	});

	it('clears the pending person and role when the sheet closes and reopens', async () => {
		listMembers.mockResolvedValue([]);
		directorySearch.mockResolvedValue([candidate()]);
		const onClose = vi.fn();
		const props = { open: true, spaceId: 3, isManager: true, selfEmail: 'me@example.com', onClose };
		const { rerender } = render(MembersSheet, props);
		await fireEvent.input(screen.getByPlaceholderText('Search by name or email'), { target: { value: 'alice' } });
		await fireEvent.click(await screen.findByRole('button', { name: /Alice/ }));
		await fireEvent.change(screen.getByLabelText('Role'), { target: { value: 'editor' } });
		expect((screen.getByLabelText('Role') as HTMLSelectElement).value).toBe('editor');

		await fireEvent.click(screen.getByLabelText('Close'));
		expect(onClose).toHaveBeenCalledTimes(1);
		await rerender({ ...props, open: false });
		await rerender({ ...props, open: true });

		await vi.waitFor(() => expect(listMembers).toHaveBeenCalledTimes(2));
		expect((screen.getByPlaceholderText('Search by name or email') as HTMLInputElement).value).toBe('');
		expect((screen.getByLabelText('Role') as HTMLSelectElement).value).toBe('viewer');
		expect(screen.queryByText('alice@example.com')).toBeNull();
		expect((screen.getByRole('button', { name: 'Add member' }) as HTMLButtonElement).disabled).toBe(true);
	});

	it('clears the pending grant context when spaceId changes while open', async () => {
		listMembers.mockResolvedValue([]);
		directorySearch.mockResolvedValue([candidate()]);
		const props = { open: true, spaceId: 3, isManager: true, selfEmail: 'me@example.com', onClose: vi.fn() };
		const { rerender } = render(MembersSheet, props);
		await fireEvent.input(screen.getByPlaceholderText('Search by name or email'), { target: { value: 'alice' } });
		await fireEvent.click(await screen.findByRole('button', { name: /Alice/ }));
		await fireEvent.change(screen.getByLabelText('Role'), { target: { value: 'manager' } });

		await rerender({ ...props, spaceId: 4 });

		await vi.waitFor(() => expect(listMembers).toHaveBeenCalledWith(4));
		expect((screen.getByPlaceholderText('Search by name or email') as HTMLInputElement).value).toBe('');
		expect((screen.getByLabelText('Role') as HTMLSelectElement).value).toBe('viewer');
		expect(screen.queryByText('alice@example.com')).toBeNull();
		expect((screen.getByRole('button', { name: 'Add member' }) as HTMLButtonElement).disabled).toBe(true);
	});

	it('revokes a member', async () => {
		listMembers.mockResolvedValue([member()]);
		revokeMember.mockResolvedValue(undefined);
		render(MembersSheet, { open: true, spaceId: 3, isManager: true, selfEmail: 'me@example.com', onClose: vi.fn() });
		await vi.waitFor(() => expect(screen.getByText('Bob')).toBeTruthy());
		await fireEvent.click(screen.getByRole('button', { name: 'Remove member' }));
		await vi.waitFor(() => expect(revokeMember).toHaveBeenCalledWith(3, 7));
	});

	it('leaving calls onClose and onLeft after revoking self', async () => {
		listMembers.mockResolvedValue([member({ userId: 1, email: 'me@example.com', role: 'editor' })]);
		revokeMember.mockResolvedValue(undefined);
		const onClose = vi.fn();
		const onLeft = vi.fn();
		render(MembersSheet, { open: true, spaceId: 3, isManager: false, selfEmail: 'me@example.com', onClose, onLeft });
		await vi.waitFor(() => expect(screen.getByRole('button', { name: 'Leave space' })).toBeTruthy());
		await fireEvent.click(screen.getByRole('button', { name: 'Leave space' }));
		await vi.waitFor(() => expect(revokeMember).toHaveBeenCalledWith(3, 1));
		await vi.waitFor(() => expect(onClose).toHaveBeenCalled());
		expect(onLeft).toHaveBeenCalled();
	});
});
