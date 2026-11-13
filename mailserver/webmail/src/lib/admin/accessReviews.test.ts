import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('./transport', () => ({
	adminFetch: vi.fn()
}));

import { adminFetch } from './transport';
import {
	listAccessReviews,
	getAccessReview,
	startAccessReview,
	decideAccessReviewItem,
	decideAccessReviewBulk,
	closeAccessReview
} from './accessReviews';

const mockedFetch = vi.mocked(adminFetch);

function jsonRes(body: unknown): Response {
	return { json: async () => body } as unknown as Response;
}

describe('accessReviews client', () => {
	beforeEach(() => {
		mockedFetch.mockReset();
	});

	it('listAccessReviews GETs the campaign list and parses it', async () => {
		const campaigns = [
			{
				id: 1,
				name: 'Q3 access review',
				status: 'open',
				reviewed: 2,
				total: 5,
				createdBy: 'admin@example.test',
				createdAt: '2026-09-01T00:00:00Z',
				closedBy: null,
				closedAt: null
			}
		];
		mockedFetch.mockResolvedValue(jsonRes(campaigns));

		await expect(listAccessReviews()).resolves.toEqual(campaigns);
		expect(mockedFetch).toHaveBeenCalledWith('/admin/access-reviews');
	});

	it('getAccessReview GETs one campaign detail by id', async () => {
		const detail = { campaign: { id: 7, name: 'Q3' }, items: [] };
		mockedFetch.mockResolvedValue(jsonRes(detail));

		await expect(getAccessReview(7)).resolves.toEqual(detail);
		expect(mockedFetch).toHaveBeenCalledWith('/admin/access-reviews/7');
	});

	it('startAccessReview POSTs the campaign name and returns the new id', async () => {
		mockedFetch.mockResolvedValue(jsonRes({ id: 42 }));

		await expect(startAccessReview('Quarterly review')).resolves.toBe(42);
		expect(mockedFetch).toHaveBeenCalledWith('/admin/access-reviews', {
			method: 'POST',
			body: JSON.stringify({ name: 'Quarterly review' })
		});
	});

	it('decideAccessReviewItem PUTs a decision with an optional note', async () => {
		mockedFetch.mockResolvedValue(jsonRes(undefined));

		await expect(decideAccessReviewItem(3, 9, 'keep', 'still needed')).resolves.toBeUndefined();
		expect(mockedFetch).toHaveBeenCalledWith('/admin/access-reviews/3/items/9', {
			method: 'PUT',
			body: JSON.stringify({ decision: 'keep', note: 'still needed' })
		});
	});

	it('decideAccessReviewItem omits the note when none is given', async () => {
		mockedFetch.mockResolvedValue(jsonRes(undefined));

		await decideAccessReviewItem(3, 9, 'revoke');
		expect(mockedFetch).toHaveBeenCalledWith('/admin/access-reviews/3/items/9', {
			method: 'PUT',
			body: JSON.stringify({ decision: 'revoke' })
		});
	});

	it('decideAccessReviewBulk PUTs the item ids and returns applied/skipped', async () => {
		mockedFetch.mockResolvedValue(jsonRes({ applied: 2, skipped: 1 }));

		await expect(decideAccessReviewBulk(5, [10, 11, 12], 'revoke')).resolves.toEqual({
			applied: 2,
			skipped: 1
		});
		expect(mockedFetch).toHaveBeenCalledWith('/admin/access-reviews/5/items', {
			method: 'PUT',
			body: JSON.stringify({ itemIds: [10, 11, 12], decision: 'revoke' })
		});
	});

	it('closeAccessReview POSTs the close endpoint', async () => {
		mockedFetch.mockResolvedValue(jsonRes(undefined));

		await expect(closeAccessReview(8)).resolves.toBeUndefined();
		expect(mockedFetch).toHaveBeenCalledWith('/admin/access-reviews/8/close', { method: 'POST' });
	});

	// adminFetch (via httpRequest) THROWS on non-OK responses and network
	// failures — the client functions must propagate that rejection verbatim so
	// callers (AccessReviewsPanel) can render the transport message instead of
	// a silent unhandled rejection.
	it('propagates transport rejections for reads and writes', async () => {
		mockedFetch.mockRejectedValue(new Error('Request failed (500)'));

		await expect(listAccessReviews()).rejects.toThrow('Request failed (500)');
		await expect(decideAccessReviewItem(3, 9, 'revoke')).rejects.toThrow('Request failed (500)');
		await expect(closeAccessReview(8)).rejects.toThrow('Request failed (500)');
		expect(mockedFetch).toHaveBeenCalledWith('/admin/access-reviews');
	});
});
