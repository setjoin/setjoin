import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render } from '@testing-library/svelte/svelte5';

// ── fetch mock helpers ────────────────────────────────────────────────────────

function makeOkResponse(body: unknown) {
	return Promise.resolve({
		ok: true,
		status: 200,
		json: async () => body,
		text: async () => JSON.stringify(body)
	});
}

function makeErrorResponse(status: number, body: string) {
	return Promise.resolve({
		ok: false,
		status,
		json: async () => ({ detail: body }),
		text: async () => body
	});
}

const CAMPAIGNS = [
	{
		id: 1,
		name: 'Q1 2026 Review',
		status: 'open',
		reviewed: 3,
		total: 10,
		createdBy: 'admin@acme.com',
		createdAt: '2026-01-15T10:00:00Z',
		closedBy: null,
		closedAt: null
	},
	{
		id: 2,
		name: 'Q4 2025 Review',
		status: 'closed',
		reviewed: 8,
		total: 8,
		createdBy: 'admin@acme.com',
		createdAt: '2025-10-01T10:00:00Z',
		closedBy: 'admin@acme.com',
		closedAt: '2025-10-15T10:00:00Z'
	}
];

// ── tests ─────────────────────────────────────────────────────────────────────

describe('AccessReviewsPanel', () => {
	beforeEach(() => vi.resetAllMocks());

	it('shows title and start button', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn(() => makeOkResponse(CAMPAIGNS))
		);
		const { default: AccessReviewsPanel } = await import('./AccessReviewsPanel.svelte');
		const { container } = render(AccessReviewsPanel);
		await new Promise((r) => setTimeout(r, 0));
		expect(container.textContent).toContain('Access reviews');
		expect(container.textContent).toContain('Start review');
		vi.unstubAllGlobals();
	});

	it('renders campaign rows after load', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn(() => makeOkResponse(CAMPAIGNS))
		);
		const { default: AccessReviewsPanel } = await import('./AccessReviewsPanel.svelte');
		const { container } = render(AccessReviewsPanel);
		await new Promise((r) => setTimeout(r, 0));
		expect(container.textContent).toContain('Q1 2026 Review');
		expect(container.textContent).toContain('Q4 2025 Review');
		vi.unstubAllGlobals();
	});

	it('shows empty state when no campaigns', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn(() => makeOkResponse([]))
		);
		const { default: AccessReviewsPanel } = await import('./AccessReviewsPanel.svelte');
		const { container } = render(AccessReviewsPanel);
		await new Promise((r) => setTimeout(r, 0));
		expect(container.textContent).toContain('No access reviews yet');
		vi.unstubAllGlobals();
	});

	it('shows error alert on fetch failure', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn(() => makeErrorResponse(500, 'Server error'))
		);
		const { default: AccessReviewsPanel } = await import('./AccessReviewsPanel.svelte');
		const { container } = render(AccessReviewsPanel);
		await new Promise((r) => setTimeout(r, 0));
		const alert = container.querySelector('[role="alert"]');
		expect(alert).not.toBeNull();
		vi.unstubAllGlobals();
	});

	it('open campaigns sort before closed campaigns', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn(() => makeOkResponse(CAMPAIGNS))
		);
		const { default: AccessReviewsPanel } = await import('./AccessReviewsPanel.svelte');
		const { container } = render(AccessReviewsPanel);
		await new Promise((r) => setTimeout(r, 0));
		const links = container.querySelectorAll('.sj-arv-link');
		expect(links[0].textContent).toContain('Q1 2026 Review');
		expect(links[1].textContent).toContain('Q4 2025 Review');
		vi.unstubAllGlobals();
	});

	it('shows open badge with warning variant for open campaign', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn(() => makeOkResponse([CAMPAIGNS[0]]))
		);
		const { default: AccessReviewsPanel } = await import('./AccessReviewsPanel.svelte');
		const { container } = render(AccessReviewsPanel);
		await new Promise((r) => setTimeout(r, 0));
		expect(container.textContent).toContain('Open');
		vi.unstubAllGlobals();
	});

	it('shows reviewed count as fraction', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn(() => makeOkResponse([CAMPAIGNS[0]]))
		);
		const { default: AccessReviewsPanel } = await import('./AccessReviewsPanel.svelte');
		const { container } = render(AccessReviewsPanel);
		await new Promise((r) => setTimeout(r, 0));
		expect(container.textContent).toContain('3 / 10');
		vi.unstubAllGlobals();
	});
});
