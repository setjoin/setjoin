import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte/svelte5';

const api = vi.hoisted(() => ({ health: vi.fn() }));
vi.mock('$lib/admin/health', () => ({ adminHealth: api.health }));
import Page from './+page.svelte';

const checks = [
	{ check_name: 'database_primary', status: 'ok', value: '12ms', details: 'healthy', checked_at: '2026-01-01T00:00:00Z' },
	{ check_name: 'queue_depth', status: 'warn', value: null, details: '', checked_at: '' },
	{ check_name: 'storage', status: 'error', value: 'offline', details: 'disk unavailable', checked_at: '2026-01-01T00:00:00Z' },
	{ check_name: undefined, status: 'unknown', value: null, details: undefined, checked_at: undefined },
];

function res(body: unknown, ok = true) { return { ok, json: async () => body } as Response; }

describe('admin dashboard', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		api.health.mockResolvedValue({ checks });
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(res({ volume: { received24h: 10, sent24h: 8 }, system: { goroutines: 44 }, threats: { rblBlocks: 2, authFailures: 3 } })));
	});
	afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

	it('summarizes all health variants and live operational counters', async () => {
		render(Page);
		expect(await screen.findByText('database primary')).toBeInTheDocument();
		expect(screen.getByText('queue depth')).toBeInTheDocument();
		expect(screen.getByText('disk unavailable')).toBeInTheDocument();
		expect(screen.getByText('10')).toBeInTheDocument();
		expect(screen.getByText('44')).toBeInTheDocument();
		expect(screen.getAllByText('-').length).toBeGreaterThan(0);
	});

	it('refreshes health and starts/stops bounded live auto-refresh', async () => {
		render(Page);
		await screen.findByText('database primary');
		await fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
		await waitFor(() => expect(api.health).toHaveBeenCalledTimes(2));

		const timer = vi.spyOn(globalThis, 'setInterval').mockReturnValue(17 as never);
		const clear = vi.spyOn(globalThis, 'clearInterval').mockImplementation(() => {});
		const toggle = screen.getByRole('switch', { name: 'Auto-refresh 30s' });
		await fireEvent.click(toggle);
		expect(timer).toHaveBeenCalledWith(expect.any(Function), 30000);
		await fireEvent.click(toggle);
		expect(clear).toHaveBeenCalledWith(17);
	});

	it('renders the no-check state and zero fallbacks for partial live data', async () => {
		api.health.mockResolvedValue({ checks: [] });
		vi.mocked(fetch).mockResolvedValue(res({ volume: { received24h: 0, sent24h: 0 } }));
		render(Page);
		expect(await screen.findByText('No health checks recorded yet')).toBeInTheDocument();
		expect(screen.getAllByText('0').length).toBeGreaterThanOrEqual(4);
	});

	it('surfaces health, non-ok live, and thrown live failures', async () => {
		api.health.mockRejectedValueOnce(new Error('health offline'));
		const first = render(Page);
		expect(await screen.findByText('health offline')).toBeInTheDocument();
		first.unmount();

		api.health.mockResolvedValue({ checks: [] });
		vi.mocked(fetch).mockResolvedValueOnce(res({}, false));
		const second = render(Page);
		expect(await screen.findByText('An error occurred')).toBeInTheDocument();
		second.unmount();

		vi.mocked(fetch).mockRejectedValueOnce(new Error('monitor offline'));
		render(Page);
		expect(await screen.findByText('monitor offline')).toBeInTheDocument();
	});
});
