import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte/svelte5';

// ── Client module spy setup ───────────────────────────────────────────────────
// vi.mock is hoisted to the top of the module by Vitest. All tests in this file
// use the mocked module; the old shallow-render tests configure the mock via
// mockGetAccessReview.mockResolvedValue(...) in their test body.

const mockGetAccessReview = vi.fn();
const mockDecideAccessReviewItem = vi.fn();
const mockDecideAccessReviewBulk = vi.fn();
const mockCloseAccessReview = vi.fn();

vi.mock('$lib/admin/accessReviews', () => ({
	getAccessReview: (...args: unknown[]) => mockGetAccessReview(...args),
	decideAccessReviewItem: (...args: unknown[]) => mockDecideAccessReviewItem(...args),
	decideAccessReviewBulk: (...args: unknown[]) => mockDecideAccessReviewBulk(...args),
	closeAccessReview: (...args: unknown[]) => mockCloseAccessReview(...args),
	startAccessReview: vi.fn(),
	listAccessReviews: vi.fn(),
}));

vi.mock('$lib/components/ui', async (importOriginal) => {
	const actual = await importOriginal<typeof import('$lib/components/ui')>();
	return {
		...actual,
		showToast: vi.fn(),
	};
});

// ── Test data ─────────────────────────────────────────────────────────────────

const OPEN_CAMPAIGN = {
	id: 1,
	name: 'Q1 2026 Review',
	status: 'open',
	reviewed: 1,
	total: 3,
	createdBy: 'admin@acme.com',
	createdAt: '2026-01-15T10:00:00Z',
	closedBy: null,
	closedAt: null
};

const CLOSED_CAMPAIGN: {
	id: number;
	name: string;
	status: string;
	reviewed: number;
	total: number;
	createdBy: string;
	createdAt: string;
	closedBy: string | null;
	closedAt: string | null;
} = {
	id: 2,
	name: 'Q4 2025 Review',
	status: 'closed',
	reviewed: 3,
	total: 3,
	createdBy: 'admin@acme.com',
	createdAt: '2025-10-01T10:00:00Z',
	closedBy: 'admin@acme.com',
	closedAt: '2025-10-15T10:00:00Z'
};

const ITEMS = [
	{
		id: 101,
		userEmail: 'alice@acme.com',
		roleName: 'super_admin',
		scope: null,
		grantedAt: '2026-01-01T00:00:00Z',
		grantedBy: 'admin@acme.com',
		isSso: false,
		isSelf: false,
		decision: 'undecided',
		appliedAt: null
	},
	{
		id: 102,
		userEmail: 'bob@acme.com',
		roleName: 'domain_admin',
		scope: 5,
		grantedAt: null,
		grantedBy: null,
		isSso: true,
		isSelf: false,
		decision: 'undecided',
		appliedAt: null
	},
	{
		id: 103,
		userEmail: 'charlie@acme.com',
		roleName: 'mail_admin',
		scope: null,
		grantedAt: '2025-06-01T00:00:00Z',
		grantedBy: 'admin@acme.com',
		isSso: false,
		isSelf: true,
		decision: 'keep',
		appliedAt: null
	}
];

type CampaignLike = { id: number; name: string; status: string; reviewed: number; total: number; createdBy: string; createdAt: string; closedBy: string | null; closedAt: string | null };
type ItemLike = { id: number; userEmail: string; roleName: string; scope: number | null; grantedAt: string | null; grantedBy: string | null; isSso: boolean; isSelf: boolean; decision: string; appliedAt: string | null };

async function mountWithItems(campaign: CampaignLike, items: ItemLike[]) {
	mockGetAccessReview.mockResolvedValue({ campaign, items });
	const { default: AccessReviewCampaign } = await import('./AccessReviewCampaign.svelte');
	const result = render(AccessReviewCampaign, { props: { id: campaign.id, onBack: vi.fn() } });
	await new Promise((r) => setTimeout(r, 10));
	return result;
}

// ── Shallow render tests (existing, preserved) ────────────────────────────────

describe('AccessReviewCampaign', () => {
	beforeEach(() => {
		vi.resetAllMocks();
		mockDecideAccessReviewItem.mockResolvedValue(undefined);
		mockDecideAccessReviewBulk.mockResolvedValue({ applied: 0, skipped: 0 });
		mockCloseAccessReview.mockResolvedValue(undefined);
	});

	it('renders campaign name in breadcrumb and header', async () => {
		const { container } = await mountWithItems(OPEN_CAMPAIGN, ITEMS);
		expect(container.textContent).toContain('Q1 2026 Review');
	});

	it('shows Back breadcrumb button', async () => {
		const { container } = await mountWithItems(OPEN_CAMPAIGN, ITEMS);
		expect(container.querySelector('.sj-arc-back')).not.toBeNull();
	});

	it('calls onBack when back button clicked', async () => {
		mockGetAccessReview.mockResolvedValue({ campaign: OPEN_CAMPAIGN, items: ITEMS });
		const onBack = vi.fn();
		const { default: AccessReviewCampaign } = await import('./AccessReviewCampaign.svelte');
		const { container } = render(AccessReviewCampaign, { props: { id: 1, onBack } });
		await new Promise((r) => setTimeout(r, 10));
		const back = container.querySelector('.sj-arc-back') as HTMLButtonElement;
		back?.click();
		expect(onBack).toHaveBeenCalledTimes(1);
	});

	it('renders user emails in table rows', async () => {
		const { container } = await mountWithItems(OPEN_CAMPAIGN, ITEMS);
		const text = container.textContent ?? '';
		// Filter defaults to 'undecided' so alice and bob show (charlie is 'keep')
		expect(text).toContain('alice@acme.com');
		expect(text).toContain('bob@acme.com');
	});

	it('shows progress summary', async () => {
		const { container } = await mountWithItems(OPEN_CAMPAIGN, ITEMS);
		// 1 kept (charlie), 0 revoked → 1/3 reviewed
		expect(container.textContent).toContain('1 / 3 reviewed');
	});

	it('shows Keep all remaining button for open campaign with undecided items', async () => {
		const { container } = await mountWithItems(OPEN_CAMPAIGN, ITEMS);
		expect(container.textContent).toContain('Keep all remaining');
	});

	it('shows SSO tag for SSO-provisioned items', async () => {
		const { container } = await mountWithItems(OPEN_CAMPAIGN, ITEMS);
		expect(container.textContent).toContain('◆ SSO');
	});

	it('shows scope global for null scope', async () => {
		const { container } = await mountWithItems(OPEN_CAMPAIGN, ITEMS);
		expect(container.textContent).toContain('Global');
	});

	it('shows closed campaign in read-only mode', async () => {
		const closedItems: ItemLike[] = ITEMS.map((i) => ({ ...i, decision: 'keep', appliedAt: '2025-10-15' }));
		const { container } = await mountWithItems(CLOSED_CAMPAIGN, closedItems);
		expect(container.textContent).toContain('Closed');
		// No "Close review" button in closed mode
		expect(container.textContent).not.toContain('Close review');
	});

	it('shows error state with back button on fetch failure', async () => {
		mockGetAccessReview.mockRejectedValue(new Error('Not found'));
		const { default: AccessReviewCampaign } = await import('./AccessReviewCampaign.svelte');
		const { container } = render(AccessReviewCampaign, { props: { id: 99, onBack: vi.fn() } });
		await new Promise((r) => setTimeout(r, 10));
		const alert = container.querySelector('[role="alert"]');
		expect(alert).not.toBeNull();
		expect(container.textContent).toContain('Back');
	});

	it('shows self-review warning tag for isSelf items', async () => {
		const selfItems = [{ ...ITEMS[0], isSelf: true, decision: 'undecided' }];
		const { container } = await mountWithItems(OPEN_CAMPAIGN, selfItems);
		expect(container.textContent).toContain('⚠ self-review');
	});
});

// ── Behavioral tests (spy on client module, exercise interactive behaviors) ──

describe('AccessReviewCampaign (behavioral)', () => {
	beforeEach(() => {
		vi.resetAllMocks();
		mockDecideAccessReviewItem.mockResolvedValue(undefined);
		mockDecideAccessReviewBulk.mockResolvedValue({ applied: 0, skipped: 0 });
		mockCloseAccessReview.mockResolvedValue(undefined);
	});

	// (a) "not applied" Tag: closed campaign with revoke+null appliedAt row
	it('(a) shows "not applied" tag for closed revoke row with null appliedAt', async () => {
		const closedItems: ItemLike[] = [
			{ ...ITEMS[0], decision: 'keep', appliedAt: '2025-10-15' },
			{ ...ITEMS[2], decision: 'revoke', appliedAt: null },  // revoke without appliedAt
		];
		const { container } = await mountWithItems(CLOSED_CAMPAIGN, closedItems);

		// Switch to 'all' filter to see all decisions (default 'undecided' shows empty for closed)
		const allFilterBtn = Array.from(container.querySelectorAll('.sj-arc-filter')).find(
			(b) => b.textContent?.trim() === 'All'
		);
		expect(allFilterBtn).toBeTruthy();
		fireEvent.click(allFilterBtn!);
		await new Promise((r) => setTimeout(r, 0));

		// The "not applied" tag must appear for the revoke+null row
		expect(container.textContent).toContain('not applied');
		// Only 1 "not applied" tag (the keep row has appliedAt set)
		const notAppliedCount = (container.textContent?.match(/not applied/g) ?? []).length;
		expect(notAppliedCount).toBe(1);
	});

	// (b) SSO Revoke disabled: isSso item → Revoke button disabled, Keep enabled
	it('(b) SSO item: Revoke button is disabled, Keep button is enabled', async () => {
		const ssoItems: ItemLike[] = [
			{ ...ITEMS[1], decision: 'undecided' }, // isSso: true
		];
		const { container } = await mountWithItems(OPEN_CAMPAIGN, ssoItems);

		// Two toggle buttons in the row: Keep and Revoke
		const toggleBtns = container.querySelectorAll<HTMLButtonElement>('.sj-arc-toggle');
		expect(toggleBtns.length).toBe(2);
		const keepBtn = toggleBtns[0];
		const revokeBtn = toggleBtns[1];
		expect(keepBtn.disabled).toBe(false);
		expect(revokeBtn.disabled).toBe(true);
	});

	// (c) "Keep all remaining" fires ONE bulk call with undecided ids
	it('(c) "Keep all remaining" calls decideAccessReviewBulk once with undecided ids', async () => {
		const mixedItems: ItemLike[] = [
			{ ...ITEMS[0], id: 101, decision: 'undecided' },  // undecided
			{ ...ITEMS[2], id: 103, decision: 'keep' },        // already decided
			{ ...ITEMS[1], id: 102, decision: 'undecided' },  // undecided
		];
		mockDecideAccessReviewBulk.mockResolvedValue({ applied: 2, skipped: 0 });
		const { container } = await mountWithItems(OPEN_CAMPAIGN, mixedItems);

		const keepAllBtn = Array.from(container.querySelectorAll('button')).find(
			(b) => b.textContent?.includes('Keep all remaining')
		);
		expect(keepAllBtn).toBeTruthy();
		keepAllBtn!.click();

		await waitFor(() => {
			expect(mockDecideAccessReviewBulk).toHaveBeenCalledTimes(1);
		});

		const [campaignId, ids, decision] = mockDecideAccessReviewBulk.mock.calls[0];
		expect(campaignId).toBe(OPEN_CAMPAIGN.id);
		// Only undecided ids (101, 102), not the decided one (103)
		expect(ids).toHaveLength(2);
		expect(ids).toContain(101);
		expect(ids).toContain(102);
		expect(ids).not.toContain(103);
		expect(decision).toBe('keep');
	});

	// (d) Close confirm dialog shows revoked/kept/not-reviewed breakdown
	it('(d) Close dialog shows revoked/kept/not-reviewed counts', async () => {
		const mixedItems: ItemLike[] = [
			{ ...ITEMS[0], id: 101, decision: 'revoke', appliedAt: null },
			{ ...ITEMS[2], id: 103, decision: 'keep', appliedAt: null },
			{ ...ITEMS[1], id: 102, decision: 'undecided', appliedAt: null },
		];
		const { container } = await mountWithItems(OPEN_CAMPAIGN, mixedItems);

		// Click the "Close review" button to open dialog
		const closeBtn = Array.from(container.querySelectorAll('button')).find(
			(b) => b.textContent?.trim() === 'Close review'
		);
		expect(closeBtn).toBeTruthy();
		closeBtn!.click();
		await new Promise((r) => setTimeout(r, 0));

		// Dialog breakdown: 3 stats showing revoked/kept/not-reviewed
		const closeBreakdown = container.querySelector('.sj-arc-close-breakdown');
		expect(closeBreakdown).not.toBeNull();
		const stats = closeBreakdown!.querySelectorAll('.sj-arc-close-stat');
		expect(stats.length).toBe(3);
		// Stat 0: revoked count = 1
		expect(stats[0].textContent).toContain('1');
		// Stat 1: kept count = 1
		expect(stats[1].textContent).toContain('1');
		// Stat 2: undecided count = 1
		expect(stats[2].textContent).toContain('1');
	});

	// (e) decide revert-on-error: decideAccessReviewItem rejects → row decision reverts
	it('(e) decision reverts to prior value (undecided) on API error', async () => {
		const items: ItemLike[] = [
			{ ...ITEMS[0], id: 101, decision: 'undecided' },
		];
		mockDecideAccessReviewItem.mockRejectedValue(new Error('network error'));
		const { container } = await mountWithItems(OPEN_CAMPAIGN, items);

		// Switch to 'all' filter to ensure the undecided item is visible
		const allFilterBtn = Array.from(container.querySelectorAll('.sj-arc-filter')).find(
			(b) => b.textContent?.trim() === 'All'
		);
		allFilterBtn && fireEvent.click(allFilterBtn);
		await new Promise((r) => setTimeout(r, 0));

		// Find and click the Keep button for the row
		const toggleBtns = container.querySelectorAll<HTMLButtonElement>('.sj-arc-toggle');
		const keepBtn = Array.from(toggleBtns).find((b) => b.textContent?.trim() === 'Keep');
		expect(keepBtn).toBeTruthy();
		fireEvent.click(keepBtn!);

		// Wait for API call to be made and rejected
		await waitFor(() => {
			expect(mockDecideAccessReviewItem).toHaveBeenCalledTimes(1);
		});
		expect(mockDecideAccessReviewItem).toHaveBeenCalledWith(OPEN_CAMPAIGN.id, 101, 'keep');

		// After rejection + revert: Keep button aria-pressed should be false (back to undecided)
		await new Promise((r) => setTimeout(r, 20));
		const keptBtn = container.querySelectorAll<HTMLButtonElement>('.sj-arc-toggle')[0];
		expect(keptBtn.getAttribute('aria-pressed')).toBe('false');
	});
});
