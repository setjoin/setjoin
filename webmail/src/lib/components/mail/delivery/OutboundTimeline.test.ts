import { render, screen } from '@testing-library/svelte/svelte5';
import { describe, it, expect } from 'vitest';
import OutboundTimeline from './OutboundTimeline.svelte';
import type { Recipient } from '$lib/types/delivery';

const minsAgo = (m: number) => new Date(Date.now() - m * 60_000).toISOString();
const minsFromNow = (m: number) => new Date(Date.now() + m * 60_000).toISOString();

const delivered: Recipient = {
	email: 'alice@example.com',
	status: 'delivered',
	mxHost: 'mx1.example.com',
	deliveredAt: minsAgo(2),
	nextAttemptAt: null,
	lastSmtpCode: 250,
	lastSmtpText: '2.0.0 OK',
	attempts: [
		{ n: 1, at: minsAgo(2), mxHost: 'mx1.example.com', smtpCode: 250, smtpText: '2.0.0 OK', outcome: 'accepted', tls: true },
	],
};

const bounced: Recipient = {
	email: 'bob@bigcorp.com',
	status: 'bounced',
	mxHost: 'mx.bigcorp.com',
	deliveredAt: null,
	nextAttemptAt: null,
	lastSmtpCode: 550,
	lastSmtpText: '5.1.1 <bob@bigcorp.com> User unknown',
	attempts: [
		{ n: 1, at: minsAgo(2), mxHost: 'mx.bigcorp.com', smtpCode: 550, smtpText: '5.1.1 <bob@bigcorp.com> User unknown', outcome: 'rejected', tls: true },
	],
};

const deferred: Recipient = {
	email: 'carol@slowmail.net',
	status: 'deferred',
	mxHost: 'mx.slowmail.net',
	deliveredAt: null,
	nextAttemptAt: minsFromNow(8),
	lastSmtpCode: 450,
	lastSmtpText: '4.2.1 Mailbox busy',
	attempts: [
		{ n: 1, at: minsAgo(5), mxHost: 'mx.slowmail.net', smtpCode: 450, smtpText: '4.2.1 Mailbox busy', outcome: 'deferred', tls: true },
		{ n: 2, at: minsAgo(1), mxHost: 'mx.slowmail.net', smtpCode: 450, smtpText: '4.2.1 Mailbox busy', outcome: 'deferred', tls: true },
	],
};

const queued: Recipient = {
	email: 'dave@queued.net',
	status: 'queued',
	mxHost: null,
	deliveredAt: null,
	nextAttemptAt: null,
	lastSmtpCode: null,
	lastSmtpText: null,
	attempts: [],
};

// Server delivers problems-first; the client renders as-is.
const all: Recipient[] = [bounced, deferred, queued, delivered];

describe('OutboundTimeline', () => {
	it('renders an ordered list with one disclosure per recipient, in the given order', () => {
		render(OutboundTimeline, { recipients: all });
		expect(screen.getByRole('list')).toBeTruthy();
		const buttons = screen.getAllByRole('button');
		expect(buttons.length).toBe(4);
		// Order preserved (no client sort): bounced first, delivered last.
		expect(buttons[0].textContent).toContain('bob@bigcorp.com');
		expect(buttons[3].textContent).toContain('alice@example.com');
	});

	it('a bounced recipient shows the danger chip, the verbatim SMTP text, and is auto-expanded', () => {
		const { container } = render(OutboundTimeline, { recipients: all });
		// danger chip word
		expect(screen.getByText('Bounced')).toBeTruthy();
		// the first bounced row is open on mount
		const bouncedBtn = screen.getAllByRole('button')[0];
		expect(bouncedBtn.getAttribute('aria-expanded')).toBe('true');
		// the verbatim remote text is rendered (in the expand detail)
		const detail = container.querySelector('.rcpt__detail');
		expect(detail).toBeTruthy();
		expect(detail?.textContent).toContain('5.1.1 <bob@bigcorp.com> User unknown');
		// danger chip class present
		expect(container.querySelector('.chip--bad')).toBeTruthy();
	});

	it('a queued recipient uses the info chip, not warning', () => {
		const { container } = render(OutboundTimeline, { recipients: [queued] });
		expect(screen.getByText('Queued')).toBeTruthy();
		expect(container.querySelector('.chip--info')).toBeTruthy();
		expect(container.querySelector('.chip--warn')).toBeNull();
	});

	it('never renders a per-recipient "Sending" chip (C3: sending lives only on the overall digest)', () => {
		// The per-recipient surface dropped 'sending'; only delivered/bounced/deferred/queued chips exist.
		render(OutboundTimeline, { recipients: all });
		expect(screen.queryByText('Sending')).toBeNull();
	});

	it('expanding a recipient reveals the per-attempt grid', async () => {
		const { container } = render(OutboundTimeline, { recipients: [deferred] });
		const btn = screen.getByRole('button');
		expect(btn.getAttribute('aria-expanded')).toBe('false');
		// no detail grid before opening
		expect(container.querySelector('.rcpt__detail')).toBeNull();
		btn.click();
		await screen.findByRole('button', { expanded: true });
		// the per-attempt grid is now present with one "attempt N" row per attempt
		const rows = container.querySelectorAll('.rcpt__detail .att__n');
		expect(rows.length).toBe(2);
		expect(rows[0].textContent).toContain('attempt 1');
		expect(rows[1].textContent).toContain('attempt 2');
	});

	it('a null mxHost omits the "to {mx}" clause from the aria-label', () => {
		render(OutboundTimeline, { recipients: [queued] });
		const label = screen.getByRole('button').getAttribute('aria-label') ?? '';
		expect(label).toContain('dave@queued.net');
		expect(label).toContain('queued');
		// no dangling "to null"
		expect(label.toLowerCase()).not.toContain('to null');
		expect(label.toLowerCase()).not.toContain('null');
	});

	it('a delivered recipient omits the SMTP code/text from the inline sub-line (lives in the expand)', () => {
		const { container } = render(OutboundTimeline, { recipients: [delivered] });
		const sub = container.querySelector('.rcpt__sub');
		expect(sub?.textContent).toContain('mx1.example.com');
		// D-D11: the 250 code is NOT inline on the happy path
		expect(sub?.textContent).not.toContain('250');
	});

	it('bounced inline sub-line shows the real MX + code, never literal {mx}/{code} placeholders', () => {
		const { container } = render(OutboundTimeline, { recipients: [bounced] });
		const sub = container.querySelector('.rcpt__sub');
		expect(sub?.textContent).toContain('rejected by');
		expect(sub?.textContent).toContain('mx.bigcorp.com');
		expect(sub?.textContent).toContain('550');
		expect(sub?.textContent).not.toContain('{mx}');
		expect(sub?.textContent).not.toContain('{code}');
	});

	it('deferred inline sub-line shows the relative next-attempt time, not a raw timestamp', () => {
		const { container } = render(OutboundTimeline, { recipients: [deferred] });
		const sub = container.querySelector('.rcpt__sub');
		expect(sub?.textContent).toMatch(/next attempt in/i);
		expect(sub?.textContent).toContain('(attempt 2)');
		// no ISO timestamp leaked
		expect(sub?.textContent).not.toMatch(/\dT\d/);
	});

	it('escapes remote SMTP text (no raw HTML injection)', () => {
		const evil: Recipient = {
			...bounced,
			lastSmtpText: '<img src=x onerror=alert(1)>',
			attempts: [{ ...bounced.attempts[0], smtpText: '<img src=x onerror=alert(1)>' }],
		};
		const { container } = render(OutboundTimeline, { recipients: [evil] });
		// No actual <img> element was injected — it's rendered as text.
		expect(container.querySelector('img')).toBeNull();
		expect(container.textContent).toContain('<img src=x onerror=alert(1)>');
	});
});
