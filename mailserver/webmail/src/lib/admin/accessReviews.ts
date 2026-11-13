import { adminFetch } from './transport';

export interface AccessReviewCampaign {
	id: number;
	name: string;
	status: 'open' | 'closed';
	reviewed: number;
	total: number;
	createdBy: string;
	createdAt: string;
	closedBy?: string | null;
	closedAt?: string | null;
}

export interface AccessReviewItem {
	id: number;
	userEmail: string;
	roleName: string;
	scope: number | null; // null = global
	grantedAt: string | null;
	grantedBy: string | null; // null = SSO
	isSso: boolean;
	isSelf: boolean;
	decision: 'undecided' | 'keep' | 'revoke';
	appliedAt: string | null;
}

export interface AccessReviewDetail {
	campaign: AccessReviewCampaign;
	items: AccessReviewItem[];
}

export interface BulkResult {
	applied: number;
	skipped: number;
}

export async function listAccessReviews(): Promise<AccessReviewCampaign[]> {
	const res = await adminFetch('/admin/access-reviews');
	return (await res.json()) as AccessReviewCampaign[];
}

export async function getAccessReview(id: number): Promise<AccessReviewDetail> {
	const res = await adminFetch(`/admin/access-reviews/${id}`);
	return (await res.json()) as AccessReviewDetail;
}

export async function startAccessReview(name: string): Promise<number> {
	const res = await adminFetch('/admin/access-reviews', {
		method: 'POST',
		body: JSON.stringify({ name })
	});
	return ((await res.json()) as { id: number }).id;
}

export async function decideAccessReviewItem(
	campaignId: number,
	itemId: number,
	decision: 'keep' | 'revoke',
	note?: string
): Promise<void> {
	await adminFetch(`/admin/access-reviews/${campaignId}/items/${itemId}`, {
		method: 'PUT',
		body: JSON.stringify({ decision, note })
	});
}

export async function decideAccessReviewBulk(
	campaignId: number,
	itemIds: number[],
	decision: 'keep' | 'revoke'
): Promise<BulkResult> {
	const res = await adminFetch(`/admin/access-reviews/${campaignId}/items`, {
		method: 'PUT',
		body: JSON.stringify({ itemIds, decision })
	});
	return (await res.json()) as BulkResult;
}

export async function closeAccessReview(campaignId: number): Promise<void> {
	await adminFetch(`/admin/access-reviews/${campaignId}/close`, { method: 'POST' });
}
