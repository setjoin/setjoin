import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/svelte/svelte5';
import AdminTrashPanel from './AdminTrashPanel.svelte';

const api = vi.hoisted(() => ({
	trashAdminList: vi.fn(),
	purgeRestore: vi.fn(),
}));

vi.mock('$lib/drive/api', async () => ({
	...(await vi.importActual<typeof import('$lib/drive/api')>('$lib/drive/api')),
	trashAdminList: api.trashAdminList,
	purgeRestore: api.purgeRestore,
}));

const item = {
	id: 41,
	name: 'Quarterly evidence.pdf',
	kind: 'file' as const,
	purgedAt: '2026-07-20T10:00:00Z',
	purgedBy: 'admin@example.test',
	deletedAt: '2026-07-19T10:00:00Z',
	sizeBytes: 2048,
};

describe('AdminTrashPanel', () => {
	beforeEach(() => {
		api.trashAdminList.mockReset().mockResolvedValue({ items: [item] });
		api.purgeRestore.mockReset().mockResolvedValue(undefined);
	});

	it('loads the selected space and hides restore from read-only admins', async () => {
		render(AdminTrashPanel, { spaceId: 7, canManage: false });
		await vi.waitFor(() => expect(screen.getByText(item.name)).toBeTruthy());
		expect(api.trashAdminList).toHaveBeenCalledWith(7);
		expect(screen.queryByRole('button', { name: 'Restore' })).toBeNull();
	});

	it('confirms restore, calls the product API, and refreshes the list', async () => {
		render(AdminTrashPanel, { spaceId: 7, canManage: true });
		await vi.waitFor(() => expect(screen.getByText(item.name)).toBeTruthy());
		await fireEvent.click(screen.getByRole('button', { name: 'Restore' }));
		expect(screen.getAllByText(/Quarterly evidence\.pdf/)).toHaveLength(2);
		const restoreButtons = screen.getAllByRole('button', { name: 'Restore' });
		await fireEvent.click(restoreButtons.at(-1)!);
		await vi.waitFor(() => expect(api.purgeRestore).toHaveBeenCalledWith(41));
		expect(api.trashAdminList).toHaveBeenCalledTimes(2);
	});

	it('shows an empty state and surfaces a failed refresh', async () => {
		api.trashAdminList.mockResolvedValueOnce({ items: [] });
		const view = render(AdminTrashPanel, { spaceId: 7, canManage: true });
		await vi.waitFor(() => expect(document.body.textContent).toContain('The admin trash is empty.'));
		view.unmount();

		api.trashAdminList.mockRejectedValueOnce(new Error('trash unavailable'));
		render(AdminTrashPanel, { spaceId: 9, canManage: true });
		await vi.waitFor(() => expect(screen.getByRole('alert').textContent).toContain('An error occurred'));
	});
});
