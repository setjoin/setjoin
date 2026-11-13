import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte/svelte5';

const api = vi.hoisted(() => ({ adminFetch: vi.fn() }));
vi.mock('$lib/admin/client', () => api);

import DmarcPage from './+page.svelte';

function res(body: unknown, ok = true) { return { ok, json: async () => body } as Response; }

const statsPayload = {
	pass: 12,
	fail: 4,
	none: 3,
	temperror: 1,
	byDomain: [
		{ domain: 'example.com', pass: 8, fail: 1, policy: 'reject' },
		{ domain: 'mail.example.org', pass: 2, fail: 2, policy: 'quarantine' },
		{ domain: 'legacy.example', pass: 1, fail: 0, policy: 'none' },
		// Missing policy falls back to the neutral 'none' label.
		{ domain: 'unsigned.example', pass: 1, fail: 1 },
		// Unrecognized policy still renders, with the neutral variant.
		{ domain: 'odd.example', pass: 0, fail: 0, policy: 'mystery' },
	],
};

const trendPayload = {
	days: [
		{ date: '2026-09-14', pass: 5, fail: 2, none: 1 },
		{ date: '2026-09-15', pass: 1, fail: 0, none: 0 },
	],
};

const failuresPayload = {
	failures: [
		{ time: '2026-09-15T10:30:00Z', from: 'spoof@bad.example', spf: 'fail', dkim: 'none', dmarc: 'fail' },
		{ time: '2026-09-15T11:00:00Z', from: 'phish@worse.example', spf: 'softfail', dkim: 'pass', dmarc: 'fail' },
	],
};

// Dispatch the page's three parallel loads by endpoint path.
function dispatcher(live = res(statsPayload), failures = res(failuresPayload), trend = res(trendPayload)) {
	return vi.fn(async (path: string) => {
		if (path.includes('/live')) return live;
		if (path.includes('/failures')) return failures;
		if (path.includes('/trend')) return trend;
		throw new Error(`unexpected adminFetch path: ${path}`);
	});
}

describe('admin DMARC monitor page', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		api.adminFetch.mockImplementation(dispatcher());
	});
	afterEach(() => {
		vi.restoreAllMocks();
	});

	it('renders live counters, per-domain policy badges, trend bars and failure rows', async () => {
		render(DmarcPage);
		await screen.findByText('example.com');

		// Live aggregate counters.
		expect(screen.getByText('12')).toBeInTheDocument();
		expect(screen.getByText('4')).toBeInTheDocument();
		expect(screen.getByText('3')).toBeInTheDocument();

		// Every domain row renders, including missing and unknown policies
		// ('none' appears for the explicit policy and the missing-policy fallback).
		expect(screen.getByText('mail.example.org')).toBeInTheDocument();
		expect(screen.getByText('legacy.example')).toBeInTheDocument();
		expect(screen.getByText('unsigned.example')).toBeInTheDocument();
		expect(screen.getByText('odd.example')).toBeInTheDocument();
		expect(screen.getByText('reject')).toBeInTheDocument();
		expect(screen.getByText('quarantine')).toBeInTheDocument();
		// Two policy badges default to 'none' (explicit + missing policy) and the
		// first failure row reports dkim: 'none'.
		expect(screen.getAllByText('none')).toHaveLength(3);
		expect(screen.getByText('mystery')).toBeInTheDocument();

		// Trend chart: max day total is 8, so bar heights scale to (value/8*80)px.
		expect(screen.getByTitle('2026-09-14: Pass 5, Fail 2, None 1')).toBeInTheDocument();
		expect(screen.getByTitle('2026-09-15: Pass 1, Fail 0, None 0')).toBeInTheDocument();
		const passBars = document.querySelectorAll('.sj-bar--pass');
		expect(passBars).toHaveLength(2);
		expect(passBars[0].getAttribute('style')).toBe('height: 50px;');
		expect(passBars[1].getAttribute('style')).toBe('height: 10px;');
		expect(document.querySelector('.sj-bar--fail')?.getAttribute('style')).toBe('height: 20px;');
		expect(document.querySelector('.sj-bar--none')?.getAttribute('style')).toBe('height: 10px;');

		// Failure table rows render parsed fields; times are locale-rendered.
		expect(screen.getByText('spoof@bad.example')).toBeInTheDocument();
		expect(screen.getByText('phish@worse.example')).toBeInTheDocument();
		expect(screen.getByText('softfail')).toBeInTheDocument();
	});

	it('toggles auto-refresh polling on and off with a 30s live interval', async () => {
		const setInt = vi.spyOn(globalThis, 'setInterval').mockReturnValue(17 as never);
		const clearInt = vi.spyOn(globalThis, 'clearInterval').mockImplementation(() => {});
		render(DmarcPage);
		await screen.findByText('example.com');
		const callsAfterMount = api.adminFetch.mock.calls.length;

		const toggle = screen.getByRole('checkbox', { name: 'Auto-refresh' });
		await fireEvent.click(toggle);
		expect(setInt).toHaveBeenCalledWith(expect.any(Function), 30000);

		// The registered interval fires the live endpoint only. Select the page's
		// own 30s registration — other setup code may also use setInterval.
		const tick = setInt.mock.calls.find((c) => c[1] === 30000)![0] as () => void;
		tick();
		await waitFor(() => expect(api.adminFetch).toHaveBeenLastCalledWith('/admin/dmarc/live'));
		expect(api.adminFetch.mock.calls.length).toBe(callsAfterMount + 1);

		await fireEvent.click(toggle);
		expect(clearInt).toHaveBeenCalledWith(17);
		// Exactly one 30s poll registration across the on/off cycle; unrelated
		// setup code may register its own intervals, so filter by the delay.
		expect(setInt.mock.calls.filter((c) => c[1] === 30000)).toHaveLength(1);
	});

	it('clears the poll timer on unmount', async () => {
		const clearInt = vi.spyOn(globalThis, 'clearInterval').mockImplementation(() => {});
		const instance = render(DmarcPage);
		await screen.findByText('example.com');
		vi.spyOn(globalThis, 'setInterval').mockReturnValue(42 as never);

		await fireEvent.click(screen.getByRole('checkbox', { name: 'Auto-refresh' }));
		instance.unmount();
		expect(clearInt).toHaveBeenCalledWith(42);
	});

	it('surfaces a load error and keeps zeroed defaults when every endpoint rejects', async () => {
		// Real adminFetch THROWS on non-OK (httpRequest's error path) — it never
		// resolves an `ok: false` response, so the loaders face rejections.
		api.adminFetch.mockImplementation(async () => {
			throw new Error('Request failed (503)');
		});
		render(DmarcPage);

		// The transport message renders in the shared alert; each failed loader
		// writes the same message, so the alert is stable regardless of which
		// rejection lands last.
		expect(await screen.findByRole('alert')).toHaveTextContent('Request failed (503)');
		// Initial $state defaults survive: pass/fail/none/temperror all zero and
		// every section keeps its empty-state copy.
		expect(screen.getAllByText('0')).toHaveLength(4);
		expect(screen.getByText('No data today')).toBeInTheDocument();
		expect(screen.getByText('No trend data available')).toBeInTheDocument();
		expect(screen.getByText('No recent failures')).toBeInTheDocument();
		expect(api.adminFetch).toHaveBeenCalledTimes(3);
		expect(api.adminFetch).toHaveBeenCalledWith('/admin/dmarc/live');
		expect(api.adminFetch).toHaveBeenCalledWith('/admin/dmarc/failures?limit=100');
		expect(api.adminFetch).toHaveBeenCalledWith('/admin/dmarc/trend');
	});

	// COV-3 helper: the listed endpoint rejects with `message`; the others
	// serve their happy payloads.
	function mixedDispatcher(failing: '/live' | '/failures' | '/trend', message: string) {
		return vi.fn(async (path: string) => {
			if (path.includes(failing)) throw new Error(message);
			if (path.includes('/live')) return res(statsPayload);
			if (path.includes('/failures')) return res(failuresPayload);
			if (path.includes('/trend')) return res(trendPayload);
			throw new Error(`unexpected adminFetch path: ${path}`);
		});
	}

	it('keeps a failed section error visible while successful siblings render (COV-3)', async () => {
		// Failures rejects; live + trend succeed. The failed section's error is
		// the aggregate alert and the successful siblings still render.
		api.adminFetch.mockImplementation(mixedDispatcher('/failures', 'Request failed (503)'));
		render(DmarcPage);

		expect(await screen.findByRole('alert')).toHaveTextContent('Request failed (503)');
		expect(screen.getByText('12')).toBeInTheDocument();
		expect(screen.getByTitle('2026-09-14: Pass 5, Fail 2, None 1')).toBeInTheDocument();
		// The failed section itself keeps its empty-state copy.
		expect(screen.getByText('No recent failures')).toBeInTheDocument();
	});

	it('clears the aggregate error once every section latest load succeeds (COV-3)', async () => {
		const setInt = vi.spyOn(globalThis, 'setInterval').mockReturnValue(23 as never);
		vi.spyOn(globalThis, 'clearInterval').mockImplementation(() => {});
		// Only live fails at mount; failures + trend succeed.
		api.adminFetch.mockImplementation(mixedDispatcher('/live', 'Request failed (500)'));
		render(DmarcPage);
		expect(await screen.findByRole('alert')).toHaveTextContent('Request failed (500)');

		// A later poll in which the live load succeeds leaves every section's
		// latest load green — the aggregate clears and the counters render.
		api.adminFetch.mockImplementation(dispatcher());
		await fireEvent.click(screen.getByRole('checkbox', { name: 'Auto-refresh' }));
		const tick = setInt.mock.calls.find((c) => c[1] === 30000)![0] as () => void;
		await tick();
		await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument());
		expect(screen.getByText('12')).toBeInTheDocument();
	});

	it('keeps the failures error after a successful live-only poll (COV-3)', async () => {
		const setInt = vi.spyOn(globalThis, 'setInterval').mockReturnValue(24 as never);
		vi.spyOn(globalThis, 'clearInterval').mockImplementation(() => {});
		// Live, failures and trend all fail at mount; failures gets its own
		// distinct message, live/trend share the fallback message.
		api.adminFetch.mockImplementation(async (path: string) => {
			if (path.includes('/failures')) throw new Error('Request failed (503)');
			throw new Error('Request failed (500)');
		});
		render(DmarcPage);
		expect(await screen.findByRole('alert')).toHaveTextContent('Request failed (500)');

		// The 30s poll retries live ONLY. Its success clears the live slot but
		// must NOT erase the failures section's unresolved error: the alert
		// downgrades to the failures message and persists.
		api.adminFetch.mockImplementation(dispatcher());
		await fireEvent.click(screen.getByRole('checkbox', { name: 'Auto-refresh' }));
		const tick = setInt.mock.calls.find((c) => c[1] === 30000)![0] as () => void;
		await tick();
		await waitFor(() => expect(screen.getByText('12')).toBeInTheDocument());
		const alert = screen.getByRole('alert');
		expect(alert).toHaveTextContent('Request failed (503)');
		expect(alert).not.toHaveTextContent('Request failed (500)');
	});

	it('falls back to empty lists when payloads omit failures/days and byDomain is empty', async () => {
		api.adminFetch.mockImplementation(
			dispatcher(res({ pass: 0, fail: 0, none: 0, temperror: 2, byDomain: [] }), res({}), res({})),
		);
		render(DmarcPage);

		// 'No data today' is also the pre-load default, so gate on the loaded
		// temperror counter before asserting the empty states.
		expect(await screen.findByText('2')).toBeInTheDocument();
		expect(screen.getByText('No data today')).toBeInTheDocument();
		expect(screen.getByText('No trend data available')).toBeInTheDocument();
		expect(screen.getByText('No recent failures')).toBeInTheDocument();
	});
});
