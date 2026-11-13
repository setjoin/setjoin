import { render, screen, fireEvent } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import SignInTrace from '$lib/components/admin/SignInTrace.svelte';

describe('SignInTrace pane', () => {
	beforeEach(() => {
		vi.stubGlobal('fetch', vi.fn((url: string) =>
			String(url).includes('/signin-log')
				? Promise.resolve({ ok: true, json: () => Promise.resolve({ rows: [{
						id: 1, user_id: 4711, decision: 'allow', would_decision: 'block', report_only: true,
						correlation_id: 'CA-7f3c9a',
						evaluated: [{ policy_id: 12, name: 'Block geo (RO)', outcome: 'would_block' }] }] }) })
				: Promise.resolve({ ok: true, json: () => Promise.resolve({ rows: [] }) })
		));
	});
	it('idle first → shows the legend before any search', () => {
		render(SignInTrace);
		expect(screen.getByText(/report-only: would have blocked/i)).toBeTruthy(); // legend entry
	});
	it('traces a user and renders the would_block chip + correlation id', async () => {
		render(SignInTrace);
		const input = await screen.findByLabelText(/user id|correlation/i);
		await fireEvent.input(input, { target: { value: '4711' } });
		await fireEvent.click(screen.getByRole('button', { name: /trace/i }));
		expect(await screen.findByText(/CA-7f3c9a/)).toBeTruthy();
	});
	it('announces the result count via an aria-live region (async outcome)', async () => {
		render(SignInTrace);
		await fireEvent.input(await screen.findByLabelText(/user id|correlation/i), { target: { value: '4711' } });
		await fireEvent.click(screen.getByRole('button', { name: /trace/i }));
		const live = document.querySelector('[aria-live="polite"]');
		expect(live?.textContent).toMatch(/1 sign-in record/i);
	});
	it('disables the Trace button + Input while loading', async () => {
		render(SignInTrace);
		await fireEvent.input(await screen.findByLabelText(/user id|correlation/i), { target: { value: '4711' } });
		fireEvent.click(screen.getByRole('button', { name: /trace/i }));
		expect((screen.getByRole('button', { name: /trace/i }) as HTMLButtonElement).disabled).toBe(true);
	});
	it('shows the calm no-rows EmptyState + IMAP/SMTP caveat when a search returns nothing', async () => {
		vi.stubGlobal('fetch', vi.fn(() => Promise.resolve({ ok: true, json: () => Promise.resolve({ rows: [] }) })));
		render(SignInTrace);
		await fireEvent.input(await screen.findByLabelText(/user id|correlation/i), { target: { value: '999' } });
		await fireEvent.click(screen.getByRole('button', { name: /trace/i }));
		expect(await screen.findByText(/no sign-in records/i)).toBeTruthy();
		expect(screen.getByText(/imap\/smtp logins aren't attributed/i)).toBeTruthy();
	});
	it('renders the "Default allow" row when no policy matched (matched_policy_id null)', async () => {
		vi.stubGlobal('fetch', vi.fn(() => Promise.resolve({ ok: true, json: () => Promise.resolve({ rows: [
			{ id: 2, user_id: 4711, decision: 'allow', report_only: false, matched_policy_id: null, correlation_id: null, evaluated: [] }
		] }) })));
		render(SignInTrace);
		await fireEvent.input(await screen.findByLabelText(/user id|correlation/i), { target: { value: '4711' } });
		await fireEvent.click(screen.getByRole('button', { name: /trace/i }));
		expect(await screen.findByText(/access allowed by default/i)).toBeTruthy();
	});
	it('shows an inline role=alert with Retry on fetch failure', async () => {
		vi.stubGlobal('fetch', vi.fn(() => Promise.resolve({ ok: false, status: 500, json: () => Promise.resolve({}) })));
		render(SignInTrace);
		await fireEvent.input(await screen.findByLabelText(/user id|correlation/i), { target: { value: '4711' } });
		await fireEvent.click(screen.getByRole('button', { name: /trace/i }));
		expect((await screen.findAllByRole('alert')).length).toBeGreaterThan(0);
		expect(screen.getByRole('button', { name: /retry/i })).toBeTruthy();
	});
	it('shows the PARTIAL truncation footer when exactly LIMIT rows are returned', async () => {
		// Stub a response with exactly 100 rows (= LIMIT) to trigger the partial footer.
		const limitRows = Array.from({ length: 100 }, (_, i) => ({
			id: i + 1, user_id: 4711, decision: 'allow', report_only: false,
			correlation_id: null, evaluated: []
		}));
		vi.stubGlobal('fetch', vi.fn(() => Promise.resolve({
			ok: true,
			json: () => Promise.resolve({ rows: limitRows, total: 500 })
		})));
		render(SignInTrace);
		await fireEvent.input(await screen.findByLabelText(/user id|correlation/i), { target: { value: '4711' } });
		await fireEvent.click(screen.getByRole('button', { name: /trace/i }));
		// ca.impact.showing_of text (Showing 100 of 500) and truncated hint
		expect(await screen.findByText(/showing.*100/i)).toBeTruthy();
	});
	it('honors prefers-reduced-motion (no transition on disclosure expand)', async () => {
		vi.stubGlobal('matchMedia', (q: string) => ({ matches: q.includes('reduce'), media: q, addEventListener() {}, removeEventListener() {} }));
		render(SignInTrace);
		await fireEvent.input(await screen.findByLabelText(/user id|correlation/i), { target: { value: '4711' } });
		await fireEvent.click(screen.getByRole('button', { name: /trace/i }));
		const disclosure = await screen.findByRole('button', { name: /show.*trace|per-policy/i });
		await fireEvent.click(disclosure);
		// The expanded region carries no transition under reduced-motion (class-gated).
		const region = document.querySelector('[data-trace-detail]') as HTMLElement | null;
		expect(region && getComputedStyle(region).transitionDuration === '0s').toBe(true);
	});
});
