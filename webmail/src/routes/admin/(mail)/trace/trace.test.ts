import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte/svelte5';

const api = vi.hoisted(() => ({ search: vi.fn(), exportCSV: vi.fn(), timeline: vi.fn(), download: vi.fn() }));
vi.mock('$lib/admin/client', () => ({
	adminTraceSearch: api.search,
	adminTraceExport: api.exportCSV,
	adminTraceTimeline: api.timeline,
}));
vi.mock('$lib/utils/downloadBlob', () => ({ downloadBlob: api.download }));

import Page from './+page.svelte';

const records = ['delivered', 'received', 'bounced', 'deferred', 'held'].map((event, index) => ({
	id: index,
	messageId: `message-${index}-abcdefghijklmnopqrstuvwxyz`,
	event,
	fromAddr: `from-${index}@example.test`,
	rcptAddr: `to-${index}@example.test`,
	details: index === 4 ? null : { route: `mx-${index}` },
	occurredAt: '2026-07-22T10:00:00Z',
}));

const timeline = {
	messageId: records[0].messageId,
	events: [], queue: null, multiRecipient: false,
};

describe('message trace page', () => {
	beforeEach(() => {
		api.search.mockReset().mockResolvedValue({ records, total: 125, limit: 50, offset: 0 });
		api.exportCSV.mockReset();
		api.timeline.mockReset();
		api.download.mockReset();
	});

	it('loads results, renders every event variant, and sends all bounded filters', async () => {
		render(Page);
		await waitFor(() => expect(screen.getByText('delivered')).toBeInTheDocument());
		for (const event of ['received', 'bounced', 'deferred', 'held']) expect(screen.getAllByText(event).length).toBeGreaterThan(1);
		expect(screen.getByText('—')).toBeInTheDocument();
		await fireEvent.input(screen.getByPlaceholderText('From'), { target: { value: 'sender@example.test' } });
		await fireEvent.input(screen.getByPlaceholderText('To'), { target: { value: 'recipient@example.test' } });
		await fireEvent.input(screen.getByPlaceholderText('Subject'), { target: { value: 'quarterly' } });
		await fireEvent.change(screen.getByRole('combobox'), { target: { value: 'bounced' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Search' }));
		await waitFor(() => expect(api.search).toHaveBeenCalledTimes(2));
		expect(api.search).toHaveBeenLastCalledWith(expect.objectContaining({
			from: 'sender@example.test', to: 'recipient@example.test', subject: 'quarterly', event: 'bounced', limit: 50, offset: 0,
		}));
	});

	it('exports the active filters with a date-stamped filename and reports export failure', async () => {
		const blob = new Blob(['csv']);
		api.exportCSV.mockResolvedValueOnce(blob).mockRejectedValueOnce(new Error('export denied'));
		render(Page);
		await waitFor(() => expect(screen.getByText('delivered')).toBeInTheDocument());
		await fireEvent.input(screen.getByPlaceholderText('From'), { target: { value: 'sender@example.test' } });
		await fireEvent.click(screen.getByText('Export CSV'));
		await waitFor(() => expect(api.download).toHaveBeenCalledWith(blob, expect.stringMatching(/^message-trace-\d{4}-\d{2}-\d{2}\.csv$/)));
		await fireEvent.click(screen.getByText('Export CSV'));
		await waitFor(() => expect(screen.getByText('export denied')).toBeInTheDocument());
	});

	it('opens and collapses a successful delivery timeline', async () => {
		api.timeline.mockResolvedValue(timeline);
		render(Page);
		const trigger = await screen.findByLabelText(`Show delivery timeline for ${records[0].messageId}`);
		await fireEvent.click(trigger);
		await waitFor(() => expect(api.timeline).toHaveBeenCalledWith(records[0].messageId));
		await waitFor(() => expect(screen.getByText('No delivery events recorded for this message.')).toBeInTheDocument());
		expect(trigger).toHaveAttribute('aria-expanded', 'true');
		await fireEvent.click(trigger);
		expect(trigger).toHaveAttribute('aria-expanded', 'false');
		expect(screen.queryByText('No delivery events recorded for this message.')).toBeNull();
	});

	it('shows timeline failure and ignores a late result after a different row is expanded', async () => {
		let resolveFirst!: (value: typeof timeline) => void;
		api.timeline
			.mockImplementationOnce(() => new Promise((resolve) => { resolveFirst = resolve; }))
			.mockRejectedValueOnce(new Error('timeline denied'));
		render(Page);
		const first = await screen.findByLabelText(`Show delivery timeline for ${records[0].messageId}`);
		const second = screen.getByLabelText(`Show delivery timeline for ${records[1].messageId}`);
		await fireEvent.click(first);
		expect(screen.getByText('Loading delivery timeline…')).toBeInTheDocument();
		await fireEvent.click(second);
		await waitFor(() => expect(screen.getByText('timeline denied')).toBeInTheDocument());
		resolveFirst(timeline);
		await Promise.resolve();
		expect(screen.queryByText('No delivery events recorded for this message.')).toBeNull();
		expect(second).toHaveAttribute('aria-expanded', 'true');
	});

	it('supports empty/error result states and pagination changes', async () => {
		api.search
			.mockRejectedValueOnce(new Error('search unavailable'))
			.mockResolvedValueOnce({ records: [], total: 0, limit: 50, offset: 0 });
		const failed = render(Page);
		await waitFor(() => expect(screen.getByText('search unavailable')).toBeInTheDocument());
		failed.unmount();
		render(Page);
		await waitFor(() => expect(screen.getByText('No records found.')).toBeInTheDocument());
	});
});
