import { render, screen, waitFor, fireEvent } from '@testing-library/svelte/svelte5';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import DeliveryPanel from './DeliveryPanel.svelte';
import { messageTrace } from '$lib/api/delivery';
import type { Trace } from '$lib/types/delivery';

const http = vi.hoisted(() => ({ request: vi.fn() }));

vi.mock('$lib/api/delivery', () => ({
	messageTrace: vi.fn()
}));
vi.mock('$lib/http', () => ({ httpRequest: http.request }));

const inboundTrace: Trace = {
	direction: 'inbound',
	hopCount: 1,
	hops: [{ index: 0, byHost: 'a.example', timestamp: null, delayMs: null, tlsActive: false, isOurInfra: false, parseOk: true }]
};

const mockTrace = vi.mocked(messageTrace);

describe('DeliveryPanel', () => {
	beforeEach(() => {
		mockTrace.mockReset();
		mockTrace.mockResolvedValue(inboundTrace);
		http.request.mockReset().mockResolvedValue({ text: async () => 'Subject: Test\r\nFrom: a@example.test\r\n\r\nBody' });
	});

	it('shows a loading state then the timeline; has dialog role', async () => {
		render(DeliveryPanel, { emailId: '42', rawUrl: '/messages/42/download', open: true, onClose: () => {} });
		expect(screen.getByRole('dialog')).toBeTruthy();
		// Loading indicator must appear before trace resolves
		expect(screen.getByRole('status')).toBeTruthy();
		await waitFor(() => expect(screen.getByRole('list')).toBeTruthy());
	});

	it('renders the outbound verdict digest + OutboundTimeline for a Sent message (not the inbound error)', async () => {
		mockTrace.mockResolvedValue({
			direction: 'outbound',
			overallStatus: 'partial',
			recipients: [
				{ email: 'bob@bigcorp.com', status: 'bounced', mxHost: 'mx.bigcorp.com', deliveredAt: null, nextAttemptAt: null, lastSmtpCode: 550, lastSmtpText: '5.1.1 User unknown', attempts: [{ n: 1, at: null, mxHost: 'mx.bigcorp.com', smtpCode: 550, smtpText: '5.1.1 User unknown', outcome: 'rejected', tls: true }] },
				{ email: 'carol@slowmail.net', status: 'deferred', mxHost: 'mx.slowmail.net', deliveredAt: null, nextAttemptAt: null, lastSmtpCode: 450, lastSmtpText: 'busy', attempts: [{ n: 1, at: null, mxHost: 'mx.slowmail.net', smtpCode: 450, smtpText: 'busy', outcome: 'deferred', tls: true }] },
				{ email: 'alice@example.com', status: 'delivered', mxHost: 'mx1.example.com', deliveredAt: null, nextAttemptAt: null, lastSmtpCode: 250, lastSmtpText: 'OK', attempts: [] }
			]
		});
		render(DeliveryPanel, { emailId: '7', rawUrl: '/messages/7/download', open: true, onClose: () => {} });
		await waitFor(() => expect(screen.getByText('1 of 3 delivered')).toBeTruthy());
		// verdict pills present
		expect(screen.getByText('1 bounced')).toBeTruthy();
		expect(screen.getByText('1 retrying')).toBeTruthy();
		// the OutboundTimeline rendered (recipient list), not the inbound error
		expect(screen.getByRole('list')).toBeTruthy();
		expect(screen.queryByText(/Couldn't load delivery path/i)).toBeNull();
		// a Refresh affordance exists
		expect(screen.getByLabelText('Refresh delivery status')).toBeTruthy();
	});

	it('all-delivered outbound shows the calm "Delivered to all" verdict with no pills', async () => {
		mockTrace.mockResolvedValue({
			direction: 'outbound',
			overallStatus: 'delivered',
			recipients: [
				{ email: 'a@x.com', status: 'delivered', mxHost: 'mx.x.com', deliveredAt: null, nextAttemptAt: null, lastSmtpCode: 250, lastSmtpText: 'OK', attempts: [] },
				{ email: 'b@x.com', status: 'delivered', mxHost: 'mx.x.com', deliveredAt: null, nextAttemptAt: null, lastSmtpCode: 250, lastSmtpText: 'OK', attempts: [] }
			]
		});
		render(DeliveryPanel, { emailId: '8', rawUrl: '/messages/8/download', open: true, onClose: () => {} });
		await waitFor(() => expect(screen.getByText('Delivered to all 2 recipients')).toBeTruthy());
		expect(screen.queryByText(/bounced/i)).toBeNull();
		expect(screen.queryByText(/retrying/i)).toBeNull();
	});

	it('uses recipients (not hopCount) as the Flow tab count for outbound', async () => {
		mockTrace.mockResolvedValue({
			direction: 'outbound',
			overallStatus: 'delivered',
			recipients: [
				{ email: 'a@x.com', status: 'delivered', mxHost: 'mx.x.com', deliveredAt: null, nextAttemptAt: null, lastSmtpCode: 250, lastSmtpText: 'OK', attempts: [] }
			]
		});
		render(DeliveryPanel, { emailId: '9', rawUrl: '/messages/9/download', open: true, onClose: () => {} });
		await waitFor(() => expect(screen.getByText('Delivered to a@x.com')).toBeTruthy());
		const flowTab = screen.getByRole('tab', { name: /Flow/ });
		expect(flowTab.textContent).toContain('1');
	});

	const bouncedTrace: Trace = {
		direction: 'outbound',
		overallStatus: 'partial',
		recipients: [
			{ email: 'bob@bigcorp.com', status: 'bounced', mxHost: 'mx.bigcorp.com', deliveredAt: null, nextAttemptAt: null, lastSmtpCode: 550, lastSmtpText: '5.1.1 User unknown', attempts: [] },
			{ email: 'alice@example.com', status: 'delivered', mxHost: 'mx1.example.com', deliveredAt: null, nextAttemptAt: null, lastSmtpCode: 250, lastSmtpText: 'OK', attempts: [] }
		]
	};

	it('shows a Resend button in the bounced digest and fires onResend', async () => {
		mockTrace.mockResolvedValue(bouncedTrace);
		const onResend = vi.fn();
		render(DeliveryPanel, { emailId: '11', rawUrl: '/messages/11/download', open: true, onResend, onClose: () => {} });
		const btn = await screen.findByRole('button', { name: /resend/i });
		await fireEvent.click(btn);
		expect(onResend).toHaveBeenCalledTimes(1);
	});

	it('hides Resend when nothing bounced (all delivered)', async () => {
		mockTrace.mockResolvedValue({
			direction: 'outbound',
			overallStatus: 'delivered',
			recipients: [
				{ email: 'a@x.com', status: 'delivered', mxHost: 'mx.x.com', deliveredAt: null, nextAttemptAt: null, lastSmtpCode: 250, lastSmtpText: 'OK', attempts: [] }
			]
		});
		render(DeliveryPanel, { emailId: '12', rawUrl: '/messages/12/download', open: true, onResend: vi.fn(), onClose: () => {} });
		await waitFor(() => expect(screen.getByText('Delivered to a@x.com')).toBeTruthy());
		expect(screen.queryByRole('button', { name: /resend/i })).toBeNull();
	});

	it('hides Resend when onResend is not provided even if bounced', async () => {
		mockTrace.mockResolvedValue(bouncedTrace);
		render(DeliveryPanel, { emailId: '13', rawUrl: '/messages/13/download', open: true, onClose: () => {} });
		await waitFor(() => expect(screen.getByText('1 bounced')).toBeTruthy());
		expect(screen.queryByRole('button', { name: /resend/i })).toBeNull();
	});

	it('retention-skew (empty recipients + overallStatus) shows the caption, not an error panel', async () => {
		mockTrace.mockResolvedValue({
			direction: 'outbound',
			overallStatus: 'delivered',
			recipients: []
		});
		render(DeliveryPanel, { emailId: '10', rawUrl: '/messages/10/download', open: true, onClose: () => {} });
		await waitFor(() => expect(screen.getByText(/Per-recipient detail is no longer available/i)).toBeTruthy());
		// NOT an error
		expect(screen.queryByText(/Couldn't load delivery/i)).toBeNull();
	});

	it('does not fetch while closed and closes from the button, backdrop, and Escape', async () => {
		const onClose = vi.fn();
		const closed = render(DeliveryPanel, { emailId: 'closed', rawUrl: '/raw', open: false, onClose });
		expect(mockTrace).not.toHaveBeenCalled();
		expect(screen.queryByRole('dialog')).toBeNull();
		closed.unmount();

		const view = render(DeliveryPanel, { emailId: 'open', rawUrl: '/raw', open: true, onClose });
		await screen.findByRole('list');
		await fireEvent.click(screen.getByLabelText('Close'));
		expect(onClose).toHaveBeenCalledTimes(1);
		await fireEvent.keyDown(document, { key: 'Escape' });
		expect(onClose).toHaveBeenCalledTimes(2);
		await fireEvent.mouseDown(view.container.querySelector('.dp-backdrop')!);
		expect(onClose).toHaveBeenCalledTimes(3);
		await fireEvent.mouseDown(view.container.querySelector('.dp')!);
		expect(onClose).toHaveBeenCalledTimes(3);
	});

	it.each([
		[undefined, 'unknown'],
		[450, '450 ms'],
		[2500, '2.5 s'],
		[125000, '2 min'],
	])('formats inbound transit %s and shows the slow-hop digest', async (totalTransitMs, expected) => {
		mockTrace.mockResolvedValue({
			direction: 'inbound', hopCount: undefined, totalTransitMs, slowestHopIndex: 0,
			hops: [{ index: 0, byHost: 'mx', timestamp: null, delayMs: totalTransitMs ?? null, tlsActive: true, isOurInfra: true, parseOk: true }],
		});
		render(DeliveryPanel, { emailId: String(totalTransitMs), rawUrl: '/raw', open: true, onClose: vi.fn() });
		await waitFor(() => expect(screen.getByText(expected)).toBeInTheDocument());
		expect(screen.getByText('bottleneck at hop 1')).toBeInTheDocument();
		expect(screen.getByRole('tab', { name: /Flow/ })).toBeInTheDocument();
	});

	it('shows trace failures, accepts non-Error failures, and retries successfully', async () => {
		mockTrace
			.mockRejectedValueOnce(new Error('trace offline'))
			.mockRejectedValueOnce('opaque failure')
			.mockResolvedValueOnce(inboundTrace);
		render(DeliveryPanel, { emailId: 'failure', rawUrl: '/raw', open: true, onClose: vi.fn() });
		await waitFor(() => expect(screen.getByText("Couldn't load delivery path")).toBeInTheDocument());
		await fireEvent.click(screen.getByText('Retry'));
		await waitFor(() => expect(mockTrace).toHaveBeenCalledTimes(2));
		await fireEvent.click(screen.getByText('Retry'));
		await waitFor(() => expect(screen.getByRole('list')).toBeInTheDocument());
	});

	it('loads raw source lazily once and shares it between Headers and Raw tabs', async () => {
		render(DeliveryPanel, { emailId: 'raw', rawUrl: '/messages/raw', open: true, onClose: vi.fn() });
		await screen.findByRole('list');
		expect(http.request).not.toHaveBeenCalled();
		await fireEvent.click(screen.getByRole('tab', { name: 'Headers' }));
		await waitFor(() => expect(http.request).toHaveBeenCalledWith('/messages/raw', { method: 'GET' }));
		await waitFor(() => expect(screen.getByText('Subject')).toBeInTheDocument());
		await fireEvent.click(screen.getByRole('tab', { name: 'Raw' }));
		await waitFor(() => expect(screen.getByText(/Subject: Test/)).toBeInTheDocument());
		expect(http.request).toHaveBeenCalledTimes(1);
		await fireEvent.click(screen.getByRole('tab', { name: 'Auth' }));
		expect(screen.getByRole('tabpanel')).toHaveAttribute('aria-label', 'Auth');
	});

	it.each([
		[new Error('raw offline'), 'raw offline'],
		['opaque failure', 'Unknown error'],
	])('shows bounded raw and header failures for %s', async (failure, expected) => {
		http.request.mockRejectedValue(failure);
		render(DeliveryPanel, { emailId: expected, rawUrl: '/messages/fail', open: true, onClose: vi.fn() });
		await screen.findByRole('list');
		await fireEvent.click(screen.getByRole('tab', { name: 'Headers' }));
		await waitFor(() => expect(screen.getByText(`Couldn't load headers: ${expected}`)).toBeInTheDocument());
		await fireEvent.click(screen.getByRole('tab', { name: 'Raw' }));
		expect(screen.getByText(`Couldn't load raw message: ${expected}`)).toBeInTheDocument();
		expect(http.request).toHaveBeenCalledTimes(2);
	});

	it('refreshes an outbound result and transitions its verdict', async () => {
		mockTrace
			.mockResolvedValueOnce({ direction: 'outbound', overallStatus: 'queued', recipients: [{
				email: 'wait@example.test', status: 'deferred', mxHost: null, deliveredAt: null,
				nextAttemptAt: null, lastSmtpCode: null, lastSmtpText: null, attempts: [],
			}] })
			.mockResolvedValueOnce({ direction: 'outbound', overallStatus: 'delivered', recipients: [{
				email: 'wait@example.test', status: 'delivered', mxHost: 'mx', deliveredAt: null,
				nextAttemptAt: null, lastSmtpCode: 250, lastSmtpText: 'OK', attempts: [],
			}] });
		render(DeliveryPanel, { emailId: 'refresh', rawUrl: '/raw', open: true, onClose: vi.fn() });
		await waitFor(() => expect(screen.getByText('1 retrying')).toBeInTheDocument());
		await fireEvent.click(screen.getByLabelText('Refresh delivery status'));
		await waitFor(() => expect(screen.getByText('Delivered to wait@example.test')).toBeInTheDocument());
	});

	it('treats an inbound trace with no hops as an unavailable path and retries it', async () => {
		mockTrace
			.mockResolvedValueOnce({ direction: 'inbound', hopCount: 0, hops: [] })
			.mockResolvedValueOnce(inboundTrace);
		render(DeliveryPanel, { emailId: 'empty', rawUrl: '/raw', open: true, onClose: vi.fn() });
		await waitFor(() => expect(screen.getByText("Couldn't load delivery path")).toBeInTheDocument());
		await fireEvent.click(screen.getByText('Retry'));
		await waitFor(() => expect(screen.getByRole('list')).toBeInTheDocument());
	});

	it('traps Tab focus in both directions and leaves unrelated keys alone', async () => {
		const { container } = render(DeliveryPanel, { emailId: 'focus', rawUrl: '/raw', open: true, onClose: vi.fn() });
		await screen.findByRole('list');
		const panel = container.querySelector<HTMLElement>('.dp')!;
		const focusable = Array.from(panel.querySelectorAll<HTMLElement>('button:not([disabled]), [tabindex]:not([tabindex="-1"])'));
		const first = focusable[0];
		const last = focusable.at(-1)!;
		panel.focus();
		await fireEvent.keyDown(document, { key: 'ArrowRight' });
		expect(document.activeElement).toBe(panel);
		await fireEvent.keyDown(document, { key: 'Tab' });
		expect(document.activeElement).toBe(first);
		last.focus();
		await fireEvent.keyDown(document, { key: 'Tab' });
		expect(document.activeElement).toBe(first);
		first.focus();
		await fireEvent.keyDown(document, { key: 'Tab', shiftKey: true });
		expect(document.activeElement).toBe(last);
		document.body.focus();
		await fireEvent.keyDown(document, { key: 'Tab', shiftKey: true });
		expect(document.activeElement).toBe(last);
	});

	it('keeps one raw request in flight when switching between lazy tabs', async () => {
		let resolve!: (value: { text: () => Promise<string> }) => void;
		http.request.mockImplementation(() => new Promise((done) => { resolve = done; }));
		render(DeliveryPanel, { emailId: 'slow-raw', rawUrl: '/slow', open: true, onClose: vi.fn() });
		await screen.findByRole('list');
		await fireEvent.click(screen.getByRole('tab', { name: 'Headers' }));
		expect(screen.getByRole('status', { name: 'Loading headers…' })).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('tab', { name: 'Raw' }));
		expect(screen.getByRole('status', { name: 'Loading raw message…' })).toBeInTheDocument();
		expect(http.request).toHaveBeenCalledTimes(1);
		resolve({ text: async () => 'Subject: Slow\r\n\r\nBody' });
		await waitFor(() => expect(screen.getByText(/Subject: Slow/)).toBeInTheDocument());
	});
});
