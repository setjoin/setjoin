import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { fireEvent } from '@testing-library/svelte/svelte5';

import QuarantinePage from './+page.svelte';

const ITEM = {
	id: 42,
	quarantinedAt: '2026-06-10T10:00:00Z',
	fromAddr: 'spammer@evil.test',
	subject: 'You won',
	recipient: 'victim@corp.test',
	reason: 'spam',
	virusName: ''
};

// Stub the global fetch that adminFetch wraps. The Go preview handler is
// deleted/never runs here — the page receives RAW bytes and must sanitize
// them client-side before injecting into the srcdoc.
function mockAdminFetch(previewHtml = '<p>safe</p><script>alert(1)</script>') {
	return vi.fn(async (input: RequestInfo | URL) => {
		const url = typeof input === 'string' ? input : input.toString();
		if (url.includes('/quarantine/') && url.includes('/preview')) {
			return {
				ok: true,
				status: 200,
				json: async () => ({ ...ITEM, html: previewHtml }),
				text: async () => ''
			} as Response;
		}
		if (url.includes('/quarantine/stats')) {
			return {
				ok: true,
				status: 200,
				json: async () => ({ active: 1, released: 0, rejected: 0 }),
				text: async () => ''
			} as Response;
		}
		// list
		return {
			ok: true,
			status: 200,
			json: async () => ({ items: [ITEM] }),
			text: async () => ''
		} as Response;
	});
}

describe('Admin quarantine page', () => {
	beforeEach(() => {
		resetStores();
	});

	it('renders quarantined rows from the list endpoint', async () => {
		vi.stubGlobal('fetch', mockAdminFetch());
		const { findByText } = await renderAsUser(QuarantinePage, {}, { isAdmin: true });
		expect(await findByText('spammer@evil.test')).toBeTruthy();
		expect(await findByText('You won')).toBeTruthy();
	});

	it('client-sanitizes preview HTML before iframe injection (strips <script>) and locks the sandbox + CSP', async () => {
		vi.stubGlobal('fetch', mockAdminFetch('<p>safe</p><script>alert(1)</script>'));
		const { findByRole, findByTitle } = await renderAsUser(
			QuarantinePage,
			{},
			{ isAdmin: true }
		);

		const previewBtn = await findByRole('button', { name: 'Preview' });
		await fireEvent.click(previewBtn);

		const frame = (await findByTitle('Message preview')) as HTMLIFrameElement;
		const srcdoc = frame.getAttribute('srcdoc') ?? '';

		// Markup layer: the client sanitize ran (fetch stubbed, Go handler gone).
		expect(srcdoc).toContain('safe');
		expect(srcdoc).not.toContain('<script>');

		// Script layer: sandbox stays exactly empty, never gains allow-*.
		expect(frame.getAttribute('sandbox')).toBe('');
		expect(frame.getAttribute('sandbox')).not.toContain('allow-scripts');
		expect(frame.getAttribute('sandbox')).not.toContain('allow-same-origin');

		// Resource layer: the beacon-killing CSP meta is prepended.
		expect(srcdoc).toContain('http-equiv="Content-Security-Policy"');
		expect(srcdoc).toContain("default-src 'none'");
		expect(srcdoc).toContain("base-uri 'none'");
		expect(srcdoc).toContain("form-action 'none'");
	});

	it('view-source shows the RAW bytes as escaped text, never as live HTML', async () => {
		vi.stubGlobal('fetch', mockAdminFetch('<p>safe</p><script>alert(1)</script>'));
		const { findByRole, findByTitle, container } = await renderAsUser(
			QuarantinePage,
			{},
			{ isAdmin: true }
		);

		const previewBtn = await findByRole('button', { name: 'Preview' });
		await fireEvent.click(previewBtn);
		// iframe is the default rendered view.
		await findByTitle('Message preview');

		// Toggle to source view.
		const sourceBtn = await findByRole('button', { name: 'View source' });
		await fireEvent.click(sourceBtn);

		const pre = container.querySelector('.sj-preview-source') as HTMLPreElement;
		expect(pre).not.toBeNull();
		// Raw bytes are present as TEXT (escaped) — textContent carries the raw
		// markup, but no live <script> element exists in the DOM.
		expect(pre.textContent).toContain('<script>alert(1)</script>');
		expect(pre.querySelector('script')).toBeNull();
		// The sanitized iframe is hidden while the source view is shown.
		expect(container.querySelector('iframe[title="Message preview"]')).toBeNull();
	});
});
