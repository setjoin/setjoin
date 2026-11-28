import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/svelte/svelte5';
import SpaceList from './SpaceList.svelte';

const space = { id: 7, name: 'Finance', isPersonal: false, classification: 'regular' as const, role: 'viewer', usedBytes: 0, quotaBytes: null, changeSeq: 1 };

describe('SpaceList quick views', () => {
	it('shows request governance only when server capability enables it', async () => {
		const onSelectQuickView = vi.fn();
		const { rerender } = render(SpaceList, { spaces: [space], selectedId: 7, governanceEnabled: false, onSelect: vi.fn(), onSelectQuickView, onNewSpace: vi.fn() });
		expect(screen.queryByRole('button', { name: 'My requests' })).toBeNull();
		await fireEvent.click(screen.getByRole('button', { name: 'Shared with me' }));
		expect(onSelectQuickView).toHaveBeenCalledWith('shared');
		await rerender({ spaces: [space], selectedId: 7, governanceEnabled: true, onSelect: vi.fn(), onSelectQuickView, onNewSpace: vi.fn() });
		expect(screen.getByRole('button', { name: 'My requests' })).toBeTruthy();
	});
});
