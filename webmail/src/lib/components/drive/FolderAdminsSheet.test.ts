import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import FolderAdminsSheet from './FolderAdminsSheet.svelte';
import type { DriveFolderAdmin } from '$lib/drive/api';

const listFolderAdmins = vi.fn();
const grantFolderAdmin = vi.fn();
const revokeFolderAdmin = vi.fn();

vi.mock('$lib/drive/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/drive/api')>('$lib/drive/api');
	return {
		...actual,
		listFolderAdmins: (...a: unknown[]) => listFolderAdmins(...a),
		grantFolderAdmin: (...a: unknown[]) => grantFolderAdmin(...a),
		revokeFolderAdmin: (...a: unknown[]) => revokeFolderAdmin(...a),
	};
});

function admin(overrides: Partial<DriveFolderAdmin> = {}): DriveFolderAdmin {
	return { userId: 7, displayName: 'Bob', grantedBy: 1, grantedAt: '2026-07-01T00:00:00Z', ...overrides };
}

describe('FolderAdminsSheet', () => {
	beforeEach(() => {
		listFolderAdmins.mockReset();
		grantFolderAdmin.mockReset();
		revokeFolderAdmin.mockReset();
	});

	it('lists admins and shows the delegate powers line', async () => {
		listFolderAdmins.mockResolvedValue([admin()]);
		render(FolderAdminsSheet, { open: true, nodeId: 601, onClose: vi.fn() });
		await vi.waitFor(() => expect(screen.getByText('Bob')).toBeTruthy());
		expect(screen.getByText(/Can add editors\/viewers/)).toBeTruthy();
	});

	it('grants a new folder admin by user id', async () => {
		listFolderAdmins.mockResolvedValue([]);
		grantFolderAdmin.mockResolvedValue(undefined);
		render(FolderAdminsSheet, { open: true, nodeId: 601, onClose: vi.fn() });
		await vi.waitFor(() => expect(listFolderAdmins).toHaveBeenCalledWith(601));
		const input = screen.getByPlaceholderText('12345');
		await fireEvent.input(input, { target: { value: '9' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Add folder admin' }));
		await vi.waitFor(() => expect(grantFolderAdmin).toHaveBeenCalledWith(601, 9));
	});

	it('revokes an admin', async () => {
		listFolderAdmins.mockResolvedValue([admin()]);
		revokeFolderAdmin.mockResolvedValue(undefined);
		render(FolderAdminsSheet, { open: true, nodeId: 601, onClose: vi.fn() });
		await vi.waitFor(() => expect(screen.getByText('Bob')).toBeTruthy());
		await fireEvent.click(screen.getByRole('button', { name: /Remove/ }));
		await vi.waitFor(() => expect(revokeFolderAdmin).toHaveBeenCalledWith(601, 7));
	});
});
