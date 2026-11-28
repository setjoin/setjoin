import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte/svelte5';
import DeliveryTimelineDetail from './DeliveryTimelineDetail.svelte';
import type { TraceTimeline } from '$lib/admin/client';
import type { Recipient } from '$lib/types/delivery';

// Build fixture helpers
function makeTimeline(overrides: Partial<TraceTimeline> = {}): TraceTimeline {
	return {
		messageId: 'test-msg-id-001',
		events: [
			{
				event: 'received',
				rcptAddr: 'alice@example.com',
				fromAddr: 'bob@remote.test',
				remoteHost: 'mx.remote.test',
				details: null,
				occurredAt: '2026-06-21T10:00:00Z',
			},
			{
				event: 'delivered',
				rcptAddr: 'alice@example.com',
				fromAddr: null,
				remoteHost: null,
				details: null,
				occurredAt: '2026-06-21T10:00:01Z',
			},
		],
		queue: null,
		multiRecipient: false,
		...overrides,
	};
}

describe('DeliveryTimelineDetail', () => {
	it('renders each event in the timeline', () => {
		render(DeliveryTimelineDetail, { timeline: makeTimeline() });
		expect(screen.getByText('received')).toBeTruthy();
		expect(screen.getByText('delivered')).toBeTruthy();
	});

	it('shows rcptAddr and remoteHost in mono when present', () => {
		render(DeliveryTimelineDetail, { timeline: makeTimeline() });
		// Both events have rcptAddr so multiple elements expected
		expect(screen.getAllByText('alice@example.com').length).toBeGreaterThan(0);
		expect(screen.getByText('mx.remote.test')).toBeTruthy();
	});

	it('renders the 30-day retention caveat always', () => {
		render(DeliveryTimelineDetail, { timeline: makeTimeline() });
		expect(screen.getByText(/30 days/i)).toBeTruthy();
	});

	it('renders the bounce-reason caveat always', () => {
		render(DeliveryTimelineDetail, { timeline: makeTimeline() });
		expect(screen.getByText(/best.effort/i)).toBeTruthy();
	});

	it('renders the generic per-recipient-unavailable note when multiRecipient is true with no recipients', () => {
		render(DeliveryTimelineDetail, { timeline: makeTimeline({ multiRecipient: true }) });
		// Phase 2b replaced the old "first recipient only" caveat with this generic fallback.
		expect(screen.getByText(/isn't available for this message/i)).toBeTruthy();
		expect(screen.queryByText(/first recipient/i)).toBeNull();
	});

	it('does not render any per-recipient note when multiRecipient is false', () => {
		render(DeliveryTimelineDetail, { timeline: makeTimeline({ multiRecipient: false }) });
		expect(screen.queryByText(/first recipient/i)).toBeNull();
		expect(screen.queryByText(/isn't available for this message/i)).toBeNull();
	});

	it('shows empty message when events array is empty', () => {
		render(DeliveryTimelineDetail, {
			timeline: makeTimeline({ events: [] }),
		});
		expect(screen.getByText(/no delivery events/i)).toBeTruthy();
	});

	it('renders the live queue block when queue is non-null', () => {
		const queue = {
			status: 'deferred',
			attemptCount: 3,
			nextAttemptAt: '2026-06-21T11:00:00Z',
			lastError: 'Connection timed out',
			rcptAddrs: ['alice@example.com'],
			queuedAt: '2026-06-21T10:00:00Z',
		};
		render(DeliveryTimelineDetail, { timeline: makeTimeline({ queue }) });
		expect(screen.getByText(/deferred/i)).toBeTruthy();
		expect(screen.getByText(/connection timed out/i)).toBeTruthy();
		expect(screen.getByText(/3 attempt/i)).toBeTruthy(); // attemptCount label
	});

	it('does not render the queue block when queue is null', () => {
		render(DeliveryTimelineDetail, { timeline: makeTimeline({ queue: null }) });
		expect(screen.queryByText(/live queue/i)).toBeNull();
	});

	it('does not show rcptAddr cell when rcptAddr is null', () => {
		const timeline = makeTimeline({
			events: [
				{
					event: 'bounced',
					rcptAddr: null,
					fromAddr: null,
					remoteHost: null,
					details: null,
					occurredAt: '2026-06-21T10:05:00Z',
				},
			],
		});
		render(DeliveryTimelineDetail, { timeline });
		// Should render the event without erroring (no null shown as text)
		expect(screen.getByText('bounced')).toBeTruthy();
	});

	// ── Phase 2b: per-recipient OutboundTimeline (replaces the first-recipient caveat) ──

	const recipients: Recipient[] = [
		{
			email: 'bob@example.com',
			status: 'bounced',
			mxHost: 'mx.example.com',
			deliveredAt: null,
			nextAttemptAt: null,
			lastSmtpCode: 550,
			lastSmtpText: 'mailbox unavailable',
			attempts: [
				{
					n: 1,
					at: '2026-06-21T10:00:00Z',
					mxHost: 'mx.example.com',
					smtpCode: 550,
					smtpText: 'mailbox unavailable',
					outcome: 'rejected',
					tls: true,
				},
			],
		},
		{
			email: 'alice@example.com',
			status: 'delivered',
			mxHost: 'mx.other.test',
			deliveredAt: '2026-06-21T10:00:01Z',
			nextAttemptAt: null,
			lastSmtpCode: 250,
			lastSmtpText: 'ok',
			attempts: [
				{
					n: 1,
					at: '2026-06-21T10:00:01Z',
					mxHost: 'mx.other.test',
					smtpCode: 250,
					smtpText: 'ok',
					outcome: 'accepted',
					tls: true,
				},
			],
		},
	];

	it('renders OutboundTimeline (per-recipient) when recipients are present', () => {
		render(DeliveryTimelineDetail, {
			timeline: makeTimeline({ multiRecipient: true, recipients, overallStatus: 'bounced' }),
		});
		// OutboundTimeline rows render each recipient email + a status WORD chip.
		// (alice also appears in the default event fixtures, so it can occur more than once.)
		expect(screen.getByText('bob@example.com')).toBeTruthy();
		expect(screen.getAllByText('alice@example.com').length).toBeGreaterThan(0);
		expect(screen.getByText('Bounced')).toBeTruthy();
		expect(screen.getByText('Delivered')).toBeTruthy();
		expect(screen.getByText('Per-recipient delivery')).toBeTruthy();
		// The old "first recipient only" caveat must NOT render when recipients are present.
		expect(screen.queryByText(/first recipient/i)).toBeNull();
	});

	it('renders the detail-expired retention note when recipients are empty but detailExpired is true', () => {
		render(DeliveryTimelineDetail, {
			timeline: makeTimeline({ multiRecipient: true, recipients: [], detailExpired: true }),
		});
		expect(screen.getByText(/no longer available/i)).toBeTruthy();
		// Neither the per-recipient timeline nor the old first-recipient caveat should appear.
		expect(screen.queryByText(/first recipient/i)).toBeNull();
	});
});
