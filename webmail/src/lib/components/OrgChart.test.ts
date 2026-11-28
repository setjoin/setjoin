import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import OrgChart from './OrgChart.svelte';

function jsonResponse(body: unknown): Response {
	return { ok: true, json: async () => body } as unknown as Response;
}

const baseData = {
	user: { id: 'me', displayName: 'Dana Lead', jobTitle: 'Director' },
	managers: [{ id: 'boss', displayName: 'Eve Boss', jobTitle: 'VP' }],
	reports: [{ id: 'r1', displayName: 'Frank Report', jobTitle: 'IC', managerId: null }]
};

describe('OrgChart', () => {
	let fetchMock: ReturnType<typeof vi.fn>;

	beforeEach(() => {
		fetchMock = vi.fn().mockResolvedValue(jsonResponse(baseData));
		vi.stubGlobal('fetch', fetchMock);
	});
	afterEach(() => {
		vi.unstubAllGlobals();
		vi.clearAllMocks();
	});

	it('loads the current user org chart on mount (no userId query param)', async () => {
		render(OrgChart, { props: { userId: '' } });
		await screen.findByText('Dana Lead');
		expect(fetchMock).toHaveBeenCalledWith('/auth/me/org-chart', expect.anything());
	});

	it('renders the manager chain with a Lucide chevron, not a ▸ glyph', async () => {
		const { container } = render(OrgChart, { props: { userId: '' } });
		await screen.findByText('Eve Boss');
		const arrow = container.querySelector('.chain-arrow');
		expect(arrow).not.toBeNull();
		expect(arrow!.querySelector('svg')).not.toBeNull();
		expect(arrow!.textContent).not.toContain('▸');
	});

	it('renders report avatars via the M1 Avatar primitive', async () => {
		const { container } = render(OrgChart, { props: { userId: '' } });
		await screen.findByText('Frank Report');
		expect(container.querySelector('.avatar')).not.toBeNull();
	});

	it('jumpTo navigates to a clicked breadcrumb manager', async () => {
		const { container } = render(OrgChart, { props: { userId: '' } });
		await screen.findByText('Eve Boss');
		fetchMock.mockClear();
		fetchMock.mockResolvedValue(
			jsonResponse({ user: { id: 'boss', displayName: 'Jumped Target', jobTitle: '' }, managers: [], reports: [] })
		);
		const link = container.querySelector('.chain-link') as HTMLButtonElement;
		await fireEvent.click(link);
		await screen.findByText('Jumped Target');
		expect(fetchMock.mock.calls[0][0]).toBe('/auth/me/org-chart?userId=boss');
	});

	it('encodes a userId containing reserved characters before building the fetch URL', async () => {
		// Security fix: ids with &, =, # or whitespace must be percent-encoded so they
		// cannot inject extra query parameters into /auth/me/org-chart.
		fetchMock.mockResolvedValue(
			jsonResponse({ user: { id: 'a&b', displayName: 'Seeded', jobTitle: '' }, managers: [], reports: [] })
		);
		render(OrgChart, { props: { userId: 'a&b=1 c' } });
		await screen.findByText('Seeded');
		const url = fetchMock.mock.calls[0][0] as string;
		expect(url).toBe('/auth/me/org-chart?userId=a%26b%3D1%20c');
		expect(url).not.toContain('a&b=1 c');
	});

	it('shows a user-facing error when the request fails', async () => {
		fetchMock.mockResolvedValue({ ok: false } as Response);
		render(OrgChart, { props: { userId: '' } });
		expect(await screen.findByText('Could not load the org chart. Please try again.')).toBeTruthy();
	});
});
