import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import Page from '../../../routes/admin/(identity)/device-lockdown/+page.svelte';

// ponytail: helper mirrors the brief's okJson — covers both the queue endpoint
// (returns an array) and the action endpoints (returns [] for success).
const okJson = (rows: unknown[]) =>
	Promise.resolve({ ok: true, json: () => Promise.resolve(rows) });

describe('device-approval queue — all states + a11y + motion', () => {
	afterEach(() => vi.unstubAllGlobals());

	it('LOADING: renders a skeleton (aria-busy) + disabled filter while fetching', async () => {
		vi.stubGlobal('fetch', vi.fn(() => new Promise(() => {}))); // never resolves
		render(Page);
		expect(screen.getByRole('status')).toHaveTextContent(/loading device approvals/i);
		expect(screen.getByLabelText(/state/i)).toBeDisabled();
	});

	it('ERROR: inline role=alert + Retry re-runs load()', async () => {
		const fetchMock = vi.fn(() =>
			Promise.resolve({ ok: false, status: 500, json: () => Promise.resolve({}) }),
		);
		vi.stubGlobal('fetch', fetchMock);
		render(Page);
		expect(await screen.findByRole('alert')).toHaveTextContent(/couldn.t load device approvals/i);
		await fireEvent.click(screen.getByRole('button', { name: /retry/i }));
		expect(fetchMock).toHaveBeenCalledTimes(2);
	});

	it('EMPTY caught-up vs no-match are distinct copy', async () => {
		vi.stubGlobal('fetch', vi.fn(() => okJson([])));
		render(Page); // default Waiting + no query
		expect(await screen.findByText(/all caught up/i)).toBeTruthy();
		await fireEvent.input(screen.getByLabelText(/search/i), { target: { value: 'bob' } });
		await fireEvent.click(screen.getByRole('button', { name: /search/i }));
		expect(await screen.findByText(/no devices match this filter/i)).toBeTruthy();
	});

	it('PARTIAL: truncation footer when limit hit', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn(() =>
				okJson(
					Array.from({ length: 100 }, (_, i) => ({
						id: i,
						user_email: `u${i}@x`,
						enroll_state: 'enrolled',
					})),
				),
			),
		);
		render(Page);
		expect(await screen.findByText(/showing the 100 most recent/i)).toBeTruthy();
	});

	it('A11Y: aria-live region announces the approve outcome', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn((u: string) =>
				String(u).includes('/approve')
					? okJson([])
					: okJson([
							{
								id: 1,
								user_email: 'a@x',
								user_display_name: 'Ann',
								enroll_state: 'enrolled',
							},
						]),
			),
		);
		render(Page);
		await fireEvent.click(await screen.findByRole('button', { name: /approve/i }));
		const live = document.querySelector('[aria-live="polite"]');
		expect(live?.textContent).toMatch(/approved/i);
	});

	it('A11Y: long name truncates with title but the badge does not', async () => {
		const long = 'X'.repeat(47);
		vi.stubGlobal(
			'fetch',
			vi.fn(() =>
				okJson([{ id: 1, user_email: 'a@x', user_display_name: long, enroll_state: 'enrolled' }]),
			),
		);
		render(Page);
		const cell = await screen.findByTitle(long);
		expect(cell).toBeTruthy();
		// badge label intact — select filter also shows "Waiting" so query by testid
		const badge = document.querySelector('[data-testid="enroll-badge"]');
		expect(badge?.textContent).toMatch(/waiting/i);
	});

	it('MOTION: emits no transition under prefers-reduced-motion', async () => {
		vi.stubGlobal('matchMedia', (q: string) => ({
			matches: q.includes('reduce'),
			media: q,
			addEventListener() {},
			removeEventListener() {},
		}));
		vi.stubGlobal(
			'fetch',
			vi.fn(() =>
				okJson([{ id: 1, user_email: 'a@x', enroll_state: 'enrolled' }]),
			),
		);
		const { container } = render(Page);
		// the page-wrap carries data-reduced-motion when reduced motion is detected
		expect(container.querySelector('[data-reduced-motion="true"]')).toBeTruthy();
	});
});
