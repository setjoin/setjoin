import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/svelte/svelte5';

// The page deep-links off `$page.url.searchParams` inside onMount, so the
// mocked store exposes a mutable search string each render can vary
// (scope-sets.test.ts precedent).
const pageMock = vi.hoisted(() => ({ search: '' }));
vi.mock('$app/stores', () => ({
	page: {
		subscribe: (run: (value: unknown) => void) => {
			run({ url: new URL(`https://setjoin.test/admin/conditional-access/why${pageMock.search}`) });
			return () => {};
		}
	}
}));

const api = vi.hoisted(() => ({ adminFetch: vi.fn() }));
vi.mock('$lib/admin/client', () => api);

// ImpactCard self-fetches policy impact when mounted with fetchData — stub it
// and record the props so the trace wiring stays asserted without dragging in
// the card's own fetch fan-out.
const impact = vi.hoisted(() => ({ calls: [] as Array<{ policyId: number; fetchData: boolean }> }));
vi.mock('$lib/components/ca/ImpactCard.svelte', () => ({
	default: (...args: unknown[]) => {
		impact.calls.push((args[1] ?? args[0]) as { policyId: number; fetchData: boolean });
		return null;
	}
}));

import WhyPage from './+page.svelte';

function res(body: unknown, ok = true, status = ok ? 200 : 500) {
	return { ok, status, json: async () => body } as Response;
}

const traceRow = {
	policy_id: 5,
	priority: 1,
	policy_name: 'Geo block',
	outcome: 'would_block',
	first_failed_key: 'country_in',
	first_failed_detail: 'RU ∉ {US, CA}',
	matched: true
};

const records = [
	{
		id: 's1',
		correlation_id: 'c-1',
		outcome: 'blocked',
		policy_name: 'Geo block',
		policy_id: 5,
		timestamp: '2026-09-15T10:30:00Z',
		trace: [traceRow]
	},
	{
		id: 's2',
		correlation_id: 'c-2',
		outcome: 'allowed',
		timestamp: '2026-09-15T11:00:00Z'
	}
];

// jsdom has no smooth scrolling; the page's el?.scrollIntoView would throw.
beforeEach(() => {
	Element.prototype.scrollIntoView = vi.fn();
});

afterEach(() => {
	// @ts-expect-error test-global teardown
	delete Element.prototype.scrollIntoView;
	vi.unstubAllGlobals();
});

describe('/admin/conditional-access/why page', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		impact.calls.length = 0;
		pageMock.search = '';
		api.adminFetch.mockResolvedValue(res(records));
	});

	it('renders the idle teach state and keeps lookup disabled until a query is typed', async () => {
		render(WhyPage);

		expect(screen.getByTestId('why-page')).toBeInTheDocument();
		expect(screen.getByText('Enter a user to see why their sign-ins were evaluated.')).toBeInTheDocument();
		expect(screen.getByRole('button', { name: 'Look up' })).toBeDisabled();

		await fireEvent.input(screen.getByLabelText('User (email or ID)'), {
			target: { value: 'alice@example.com' }
		});
		// The optional correlation input is independently typable.
		await fireEvent.input(screen.getByLabelText('Correlation ID (optional)'), {
			target: { value: 'c-9' }
		});
		expect(screen.getByRole('button', { name: 'Look up' })).toBeEnabled();
		// No lookup fired by typing alone.
		expect(api.adminFetch).not.toHaveBeenCalled();
	});

	it('looks up by user + window, renders result rows, and expands the policy trace', async () => {
		let resolveLookup!: (value: unknown) => void;
		api.adminFetch.mockImplementationOnce(() => new Promise((r) => { resolveLookup = r; }));
		render(WhyPage);

		await fireEvent.input(screen.getByLabelText('User (email or ID)'), {
			target: { value: 'alice@example.com' }
		});
		await fireEvent.change(screen.getByLabelText('Time window'), { target: { value: '24h' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Look up' }));

		// In-flight: skeletons render and the controls are disabled.
		expect(screen.getByTestId('loading-state')).toBeInTheDocument();
		expect(screen.getByRole('button', { name: 'Look up' })).toBeDisabled();

		resolveLookup(res(records));
		expect(await screen.findByTestId('result-state')).toBeInTheDocument();
		expect(api.adminFetch).toHaveBeenCalledWith(
			'/admin/conditional-access/why-lookup?user=alice%40example.com&since=24h',
			{ allowStatuses: [404] }
		);
		const rows = screen.getAllByTestId('signin-record');
		expect(rows).toHaveLength(2);
		expect(screen.getByText('Geo block')).toBeInTheDocument();

		// Expand the first record: its trace rows render and the F1 ImpactCard
		// mounts for the matched policy. The trace-less record has nothing to expand.
		await fireEvent.click(within(rows[0]).getByTestId('expand-btn'));
		expect(within(rows[0]).getByTestId('trace-list')).toBeInTheDocument();
		expect(impact.calls).toEqual([{ policyId: 5, fetchData: true }]);

		// Clicking again collapses (toggle).
		await fireEvent.click(within(rows[0]).getByTestId('expand-btn'));
		expect(within(rows[0]).queryByTestId('trace-list')).not.toBeInTheDocument();
	});

	it('renders the distinct not-found state on 404 (warning tone, not error)', async () => {
		// Real transport semantics: httpRequest throws on non-OK unless the
		// caller admits the status via allowStatuses — the page admits 404 for
		// the server's unresolvable-user verdict. Exercise the seam by mocking
		// global fetch (NOT adminFetch) and delegating to the real client.
		const actual = await vi.importActual<typeof import('$lib/admin/client')>('$lib/admin/client');
		api.adminFetch.mockImplementationOnce((path: string, opts?: RequestInit) =>
			actual.adminFetch(path, opts)
		);
		vi.stubGlobal(
			'fetch',
			vi.fn(async () =>
				new Response(JSON.stringify({ found: false }), {
					status: 404,
					headers: { 'Content-Type': 'application/json' }
				})
			)
		);
		render(WhyPage);

		await fireEvent.input(screen.getByLabelText('User (email or ID)'), {
			target: { value: 'ghost@example.com' }
		});
		await fireEvent.click(screen.getByRole('button', { name: 'Look up' }));

		expect(await screen.findByTestId('not-found-state')).toHaveTextContent(
			'No user matches "ghost@example.com"'
		);
		expect(screen.queryByTestId('error-state')).not.toBeInTheDocument();
		// The lookup explicitly admits the 404 through the transport seam.
		expect(api.adminFetch).toHaveBeenCalledWith(
			'/admin/conditional-access/why-lookup?user=ghost%40example.com&since=7d',
			{ allowStatuses: [404] }
		);
	});

	it('renders the zero-signins state and widen cycles the time window', async () => {
		api.adminFetch.mockResolvedValue(res([]));
		render(WhyPage);

		await fireEvent.input(screen.getByLabelText('User (email or ID)'), {
			target: { value: 'alice@example.com' }
		});
		await fireEvent.click(screen.getByRole('button', { name: 'Look up' }));

		expect(await screen.findByTestId('zero-signins-state')).toHaveTextContent(
			'No sign-ins for alice@example.com in the last 7d.'
		);

		// Widen flips 7d -> 30d and re-looks-up; a second widen clamps at 30d.
		await fireEvent.click(within(screen.getByTestId('zero-signins-state')).getByRole('button'));
		await waitFor(() =>
			expect(api.adminFetch).toHaveBeenLastCalledWith(
				'/admin/conditional-access/why-lookup?user=alice%40example.com&since=30d',
				{ allowStatuses: [404] }
			)
		);
		await fireEvent.click(within(screen.getByTestId('zero-signins-state')).getByRole('button'));
		await waitFor(() =>
			expect(api.adminFetch).toHaveBeenLastCalledWith(
				'/admin/conditional-access/why-lookup?user=alice%40example.com&since=30d',
				{ allowStatuses: [404] }
			)
		);
	});

	it('renders the error state with the transport message and recovers on Retry', async () => {
		api.adminFetch.mockRejectedValueOnce(new Error('Request failed (503)'));
		render(WhyPage);

		await fireEvent.input(screen.getByLabelText('User (email or ID)'), {
			target: { value: 'alice@example.com' }
		});
		await fireEvent.click(screen.getByRole('button', { name: 'Look up' }));

		const errorState = await screen.findByTestId('error-state');
		expect(errorState).toHaveTextContent("Couldn't load the sign-in trace. Retry.");
		expect(errorState).toHaveTextContent('Request failed (503)');

		// Retry re-runs the lookup against the still-installed happy mock.
		await fireEvent.click(within(errorState).getByRole('button', { name: 'Retry' }));
		expect(await screen.findByTestId('result-state')).toBeInTheDocument();
	});

	it('deep-links ?correlation_id: auto-lookup, highlight, announce and focus the match', async () => {
		pageMock.search = '?correlation_id=c-2';
		render(WhyPage);

		// The correlation input is pre-filled before the auto-lookup.
		expect(await screen.findByTestId('result-state')).toBeInTheDocument();
		expect(screen.getByLabelText('Correlation ID (optional)')).toHaveValue('c-2');
		expect(api.adminFetch).toHaveBeenCalledWith(
			'/admin/conditional-access/why-lookup?correlation_id=c-2'
		);

		// The matching record (by correlation_id) is highlighted, expanded and
		// scrolled into view; the sr-only status announces it.
		const rows = screen.getAllByTestId('signin-record');
		const matched = rows.find((row) => row.getAttribute('data-signin-id') === 's2');
		expect(matched).toHaveClass('why-record--highlight');
		expect(screen.getByTestId('why-announce')).toHaveTextContent('Showing sign-in c-2.');
		expect(Element.prototype.scrollIntoView).toHaveBeenCalled();

		// Records without a trace expand to no trace section (record 2 has none).
		expect(within(matched!).queryByTestId('trace-list')).not.toBeInTheDocument();
	});

	it('deep-link with no matching record still resolves the list without a highlight', async () => {
		pageMock.search = '?correlation_id=c-missing';
		render(WhyPage);

		expect(await screen.findByTestId('result-state')).toBeInTheDocument();
		expect(screen.getAllByTestId('signin-record')).toHaveLength(2);
		expect(screen.queryByTestId('why-announce')).toHaveTextContent('');
		expect(document.querySelector('.why-record--highlight')).toBeNull();
	});

	it('deep-link resolving to zero records shows the zero-signins state', async () => {
		pageMock.search = '?correlation_id=c-quiet';
		api.adminFetch.mockResolvedValue(res([]));
		render(WhyPage);

		expect(await screen.findByTestId('zero-signins-state')).toBeInTheDocument();
		expect(api.adminFetch).toHaveBeenCalledWith(
			'/admin/conditional-access/why-lookup?correlation_id=c-quiet'
		);
	});

	it('deep-link lookup failure surfaces the error state', async () => {
		pageMock.search = '?correlation_id=c-boom';
		api.adminFetch.mockRejectedValue(new Error('Request failed (500)'));
		render(WhyPage);

		const errorState = await screen.findByTestId('error-state');
		expect(errorState).toHaveTextContent('Request failed (500)');
	});
});
