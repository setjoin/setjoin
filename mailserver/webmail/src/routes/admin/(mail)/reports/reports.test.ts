import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte/svelte5';

const api = vi.hoisted(() => ({ summary: vi.fn() }));
vi.mock('$lib/admin/client', () => ({ adminReportsSummary: api.summary }));

import Page from './+page.svelte';

const full = {
	period: '7d', totalSent: 1234, totalReceived: 2345, totalBounced: 12, spamCount: 34,
	daily: [
		{ date: '2026-07-21', sent: 4, received: 6, bounced: 1, spam: 2 },
		{ date: '2026-07-22', sent: 0, received: 0, bounced: 0, spam: 0 },
	],
	topSenders: [{ email: 'sender@example.test', count: 8 }],
	topRecipients: [{ email: 'recipient@example.test', count: 7 }],
	ruleTriggers: [{ ruleName: 'Block executable', count: 3 }],
};

describe('mail-flow reports', () => {
	beforeEach(() => api.summary.mockReset());

	it('renders totals, volume bars, and every leaderboard from the API', async () => {
		api.summary.mockResolvedValue(full);
		const { container } = render(Page);
		await waitFor(() => expect(screen.getByText('1,234')).toBeInTheDocument());
		expect(api.summary).toHaveBeenCalledWith(7);
		expect(screen.getByText('sender@example.test')).toBeInTheDocument();
		expect(screen.getByText('recipient@example.test')).toBeInTheDocument();
		expect(screen.getByText('Block executable')).toBeInTheDocument();
		expect(container.querySelectorAll('.bar')).toHaveLength(6);
		expect(container.querySelector('.bar')?.getAttribute('style')).toContain('height:');
	});

	it('reloads for a changed period and replaces the prior report', async () => {
		api.summary.mockResolvedValueOnce(full).mockResolvedValueOnce({ ...full, totalSent: 30, daily: [], topSenders: [], topRecipients: [], ruleTriggers: [] });
		render(Page);
		await waitFor(() => expect(screen.getByText('1,234')).toBeInTheDocument());
		await fireEvent.change(screen.getByRole('combobox'), { target: { value: '30' } });
		await waitFor(() => expect(screen.getByText('30')).toBeInTheDocument());
		expect(api.summary).toHaveBeenLastCalledWith(30);
		expect(screen.queryByText('Daily Volume')).toBeNull();
		expect(screen.queryByText('Top Senders')).toBeNull();
	});

	it('shows API failures and a distinct no-data state', async () => {
		api.summary.mockRejectedValueOnce(new Error('reports unavailable'));
		const failed = render(Page);
		await waitFor(() => expect(screen.getByText('reports unavailable')).toBeInTheDocument());
		expect(screen.getByText('No data yet.')).toBeInTheDocument();
		failed.unmount();

		api.summary.mockResolvedValueOnce(null);
		render(Page);
		await waitFor(() => expect(screen.getByText('No data yet.')).toBeInTheDocument());
	});
});
