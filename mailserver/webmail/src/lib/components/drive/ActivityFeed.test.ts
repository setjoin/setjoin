import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import ActivityFeed from './ActivityFeed.svelte';
import type { DriveActivityItem } from '$lib/drive/api';

const activity = vi.fn();

vi.mock('$lib/drive/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/drive/api')>('$lib/drive/api');
	return {
		...actual,
		activity: (...a: unknown[]) => activity(...a),
	};
});

function item(overrides: Partial<DriveActivityItem> = {}): DriveActivityItem {
	return {
		id: 1,
		action: 'branch.create',
		actorId: 1,
		actorName: 'Anna',
		targetType: 'branch',
		targetId: 3,
		at: '2026-07-10T07:00:00Z',
		notes: null,
		...overrides,
	};
}

describe('ActivityFeed', () => {
	beforeEach(() => {
		activity.mockReset();
	});

	it('renders items newest-first as "{actor} · {action} · {time}" with role=feed/article', async () => {
		activity.mockResolvedValue({ items: [item({ id: 2, action: 'lock.acquire' }), item({ id: 1 })] });
		const { container } = render(ActivityFeed, { spaceId: 1 });
		await vi.waitFor(() => expect(screen.getAllByRole('article')).toHaveLength(2));
		expect(container.querySelector('[role="feed"]')).toBeTruthy();
		expect(screen.getAllByText('Anna')).toHaveLength(2);
		expect(screen.getByText('checked out')).toBeTruthy();
		expect(screen.getByText('created branch')).toBeTruthy();
		expect(activity).toHaveBeenCalledWith(1, { node: undefined, max: 50 });
	});

	it('passes nodeId through for per-file mode', async () => {
		activity.mockResolvedValue({ items: [] });
		render(ActivityFeed, { spaceId: 1, nodeId: 501 });
		await vi.waitFor(() => expect(activity).toHaveBeenCalledWith(1, { node: 501, max: 50 }));
	});

	it('unknown/forward-compat actions fall back to the raw action key', async () => {
		activity.mockResolvedValue({ items: [item({ action: 'p6.someFutureAction' })] });
		render(ActivityFeed, { spaceId: 1 });
		await vi.waitFor(() => expect(screen.getByText('p6.someFutureAction')).toBeTruthy());
	});

	it('"load more" keyset-pages via beforeId using the oldest loaded item id', async () => {
		const page1 = Array.from({ length: 50 }, (_, i) => item({ id: 100 - i }));
		activity.mockResolvedValueOnce({ items: page1 });
		render(ActivityFeed, { spaceId: 1 });
		await vi.waitFor(() => expect(screen.getAllByRole('article')).toHaveLength(50));

		activity.mockResolvedValueOnce({ items: [item({ id: 10 })] });
		await fireEvent.click(screen.getByRole('button', { name: 'Load more' }));
		await vi.waitFor(() => expect(activity).toHaveBeenLastCalledWith(1, { node: undefined, max: 50, beforeId: 51 }));
	});
});
