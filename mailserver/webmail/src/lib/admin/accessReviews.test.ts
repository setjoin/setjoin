import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
	listAccessReviews,
	getAccessReview,
	startAccessReview,
	decideAccessReviewItem,
	decideAccessReviewBulk,
	closeAccessReview
} from './accessReviews';

function jsonRes(body: unknown, status = 200): Response {
	return new Response(status === 204 ? null : JSON.stringify(body), {
		status,
		headers: status === 204 ? undefined : { 'content-type': 'application/json' }
	});
}

describe('accessReviews client', () => {
	const fetchMock = vi.fn();

	beforeEach(() => {
		fetchMock.mockReset();
		vi.stubGlobal('fetch', fetchMock);
	});

	afterEach(() => {
		vi.unstubAllGlobals();
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
		fetchMock.mockResolvedValue(jsonRes(campaigns));

		await expect(listAccessReviews()).resolves.toEqual(campaigns);
		expect(fetchMock).toHaveBeenCalledWith(
			'/api/admin/access-reviews',
			expect.objectContaining({ method: 'GET', cache: 'no-store' })
		);
	});

	it('getAccessReview GETs one campaign detail by id', async () => {
		const detail = { campaign: { id: 7, name: 'Q3' }, items: [] };
		fetchMock.mockResolvedValue(jsonRes(detail));

		await expect(getAccessReview(7)).resolves.toEqual(detail);
		expect(fetchMock).toHaveBeenCalledWith(
			'/api/admin/access-reviews/7',
			expect.objectContaining({ method: 'GET', cache: 'no-store' })
		);
	});

	it('startAccessReview POSTs the campaign name and returns the new id', async () => {
		fetchMock.mockResolvedValue(jsonRes({ id: 42 }, 201));

		await expect(startAccessReview('Quarterly review')).resolves.toBe(42);
		expect(fetchMock).toHaveBeenCalledWith(
			'/api/admin/access-reviews',
			expect.objectContaining({
				method: 'POST',
				body: JSON.stringify({ name: 'Quarterly review' })
			})
		);
	});

	it('decideAccessReviewItem PUTs a decision with an optional note', async () => {
		fetchMock.mockResolvedValue(jsonRes(null, 204));

		await expect(decideAccessReviewItem(3, 9, 'keep', 'still needed')).resolves.toBeUndefined();
		expect(fetchMock).toHaveBeenCalledWith(
			'/api/admin/access-reviews/3/items/9',
			expect.objectContaining({
				method: 'PUT',
				body: JSON.stringify({ decision: 'keep', note: 'still needed' })
			})
		);
	});

	it('decideAccessReviewItem omits the note when none is given', async () => {
		fetchMock.mockResolvedValue(jsonRes(null, 204));

		await decideAccessReviewItem(3, 9, 'revoke');
		expect(fetchMock).toHaveBeenCalledWith(
			'/api/admin/access-reviews/3/items/9',
			expect.objectContaining({
				method: 'PUT',
				body: JSON.stringify({ decision: 'revoke' })
			})
		);
	});

	it('decideAccessReviewBulk PUTs the item ids and returns applied/skipped', async () => {
		fetchMock.mockResolvedValue(jsonRes({ applied: 2, skipped: 1 }));

		await expect(decideAccessReviewBulk(5, [10, 11, 12], 'revoke')).resolves.toEqual({
			applied: 2,
			skipped: 1
		});
		expect(fetchMock).toHaveBeenCalledWith(
			'/api/admin/access-reviews/5/items',
			expect.objectContaining({
				method: 'PUT',
				body: JSON.stringify({ itemIds: [10, 11, 12], decision: 'revoke' })
			})
		);
	});

	it('closeAccessReview POSTs the close endpoint', async () => {
		fetchMock.mockResolvedValue(jsonRes(null, 204));

		await expect(closeAccessReview(8)).resolves.toBeUndefined();
		expect(fetchMock).toHaveBeenCalledWith(
			'/api/admin/access-reviews/8/close',
			expect.objectContaining({ method: 'POST' })
		);
	});

	it('propagates transport rejections for reads and writes', async () => {
		fetchMock.mockImplementation(async () =>
			new Response(JSON.stringify({ status: 500, detail: 'Request failed (500)' }), {
				status: 500,
				headers: { 'content-type': 'application/problem+json' }
			})
		);

		await expect(listAccessReviews()).rejects.toThrow('Request failed (500)');
		await expect(decideAccessReviewItem(3, 9, 'revoke')).rejects.toThrow('Request failed (500)');
		await expect(closeAccessReview(8)).rejects.toThrow('Request failed (500)');
		expect(fetchMock).toHaveBeenCalledWith(
			'/api/admin/access-reviews',
			expect.objectContaining({ method: 'GET' })
		);
	});
});
