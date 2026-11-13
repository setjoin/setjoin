import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/svelte/svelte5';
import DriveQuickView from './DriveQuickView.svelte';
import type { DriveQuickViewItem } from '$lib/drive/api';

const shared: DriveQuickViewItem = {
	kind: 'shared', nodeId: '12', spaceId: '7', name: 'Budget.xlsx', nodeKind: 'file',
	spaceName: 'Finance', source: 'group', preset: 'viewer', sharedAt: '2026-08-03T10:00:00Z',
};

describe('DriveQuickView', () => {
	it('groups virtual shared anchors by space and opens the selected anchor', async () => {
		const onOpen = vi.fn();
		render(DriveQuickView, { view: 'shared', items: [shared], loading: false, error: '', onOpen, onRetry: vi.fn(), onOpenSpace: vi.fn() });
		expect(screen.getByRole('heading', { name: 'Finance' })).toBeTruthy();
		await fireEvent.click(screen.getByRole('button', { name: /Budget\.xlsx/ }));
		expect(onOpen).toHaveBeenCalledWith(shared);
	});

	it('keeps an unapplied request non-navigable and offers a retry on failure', async () => {
		const request: DriveQuickViewItem = {
			kind: 'request', requestId: '90', nodeId: '12', spaceId: '7', name: 'Budget.xlsx',
			nodeKind: 'file', spaceName: 'Finance', status: 'pending', grantId: null,
		};
		const { rerender } = render(DriveQuickView, { view: 'requests', items: [request], loading: false, error: '', onOpen: vi.fn(), onRetry: vi.fn(), onOpenSpace: vi.fn() });
		expect(screen.getByRole('button', { name: /Budget\.xlsx/ })).toBeDisabled();
		const onRetry = vi.fn();
		await rerender({ view: 'requests', items: [], loading: false, error: 'offline', onOpen: vi.fn(), onRetry, onOpenSpace: vi.fn() });
		await fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
		expect(onRetry).toHaveBeenCalledOnce();
	});
});
