import { describe, it, expect, vi, beforeEach } from 'vitest';

// Capture the document handed to the shared print-window harness so the
// containment contract of the POPUP document itself can be asserted.
const openPrintWindow = vi.fn();
vi.mock('$lib/util/printWindow', () => ({
	escapeHtml: (s: string) =>
		s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'),
	openPrintWindow: (...a: unknown[]) => openPrintWindow(...a),
}));

import { printMessage } from './printMessage';
import type { Email } from '$lib/types/jmap';

function email(overrides: Partial<Email> = {}): Email {
	return {
		id: 'm1',
		subject: 'Hello',
		from: [{ name: 'Ada', email: 'ada@example.test' }],
		to: [{ name: '', email: 'bob@example.test' }],
		receivedAt: '2026-09-01T10:00:00Z',
		keywords: {},
		...overrides,
	} as unknown as Email;
}

describe('printMessage secondary containment (S20)', () => {
	beforeEach(() => {
		openPrintWindow.mockReset();
	});

	it('ships a restrictive CSP in the printed document (script/remote/frame containment)', () => {
		printMessage(email({ bodyText: 'plain body' }));
		expect(openPrintWindow).toHaveBeenCalledTimes(1);
		const doc = openPrintWindow.mock.calls[0][0] as string;
		expect(doc).toContain('Content-Security-Policy');
		expect(doc).toContain("default-src 'none'");
		// Inline print styles remain allowed; script execution does not.
		expect(doc).toContain("style-src 'unsafe-inline'");
		expect(doc).not.toMatch(/<script/i);
	});

	it('escapes attacker-controlled header fields into the popup document', () => {
		printMessage(
			email({
				subject: '<script>alert(1)</script>',
				from: [{ name: '<b>Eve</b>', email: 'eve@example.test' }],
			}),
		);
		const doc = openPrintWindow.mock.calls[0][0] as string;
		expect(doc).toContain('&lt;script&gt;');
		expect(doc).not.toContain('<script>alert(1)</script>');
	});
});
