import { createEdgeClient, toEdgeProblemError } from '$lib/edge/client';

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

const accessReviewsEdge = createEdgeClient({
	cache: 'no-store',
	loginRedirect: '/login',
	forbiddenMessage: 'Admin access required'
});

export async function listAccessReviews(): Promise<AccessReviewCampaign[]> {
	const { data, error, response } = await accessReviewsEdge.GET('/api/admin/access-reviews');
	if (!response.ok || error !== undefined || data === undefined) {
		throw toEdgeProblemError(error, response);
	}
	return data as AccessReviewCampaign[];
}

export async function getAccessReview(id: number): Promise<AccessReviewDetail> {
	const { data, error, response } = await accessReviewsEdge.GET('/api/admin/access-reviews/{id}', {
		params: { path: { id } }
	});
	if (!response.ok || error !== undefined || data === undefined) {
		throw toEdgeProblemError(error, response);
	}
	return data as AccessReviewDetail;
}

export async function startAccessReview(name: string): Promise<number> {
	const { data, error, response } = await accessReviewsEdge.POST('/api/admin/access-reviews', {
		body: { name }
	});
	if (!response.ok || error !== undefined || data === undefined) {
		throw toEdgeProblemError(error, response);
	}
	return data.id;
}

export async function decideAccessReviewItem(
	campaignId: number,
	itemId: number,
	decision: 'keep' | 'revoke',
	note?: string
): Promise<void> {
	const { error, response } = await accessReviewsEdge.PUT(
		'/api/admin/access-reviews/{id}/items/{itemId}',
		{
			params: { path: { id: campaignId, itemId } },
			body: note !== undefined ? { decision, note } : { decision }
		}
	);
	if (!response.ok || error !== undefined) {
		throw toEdgeProblemError(error, response);
	}
}

export async function decideAccessReviewBulk(
	campaignId: number,
	itemIds: number[],
	decision: 'keep' | 'revoke'
): Promise<BulkResult> {
	const { data, error, response } = await accessReviewsEdge.PUT('/api/admin/access-reviews/{id}/items', {
		params: { path: { id: campaignId } },
		body: { itemIds, decision }
	});
	if (!response.ok || error !== undefined || data === undefined) {
		throw toEdgeProblemError(error, response);
	}
	return data;
}

export async function closeAccessReview(campaignId: number): Promise<void> {
	const { error, response } = await accessReviewsEdge.POST('/api/admin/access-reviews/{id}/close', {
		params: { path: { id: campaignId } }
	});
	if (!response.ok || error !== undefined) {
		throw toEdgeProblemError(error, response);
	}
}
