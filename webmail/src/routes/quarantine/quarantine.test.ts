import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { waitFor, fireEvent, cleanup } from '@testing-library/svelte/svelte5';
import { toasts, clearToasts } from '$lib/components/ui';
import { goto } from '$app/navigation';

import QuarantinePage from './+page.svelte';

const ITEM = {
	id: 7,
	quarantinedAt: '2026-06-10T10:00:00Z',
	fromAddr: 'spammer@evil.test',
	subject: 'You won',
	reason: 'spam',
	virusName: ''
};

function mockQuarantineFetch(previewHtml = '<p>hi</p><script>alert(1)</script>') {
	return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = typeof input === 'string' ? input : input.toString();
		if (url.includes('/preview')) {
			return {
				ok: true,
				status: 200,
				json: async () => ({ ...ITEM, html: previewHtml }),
				text: async () => ''
			} as Response;
		}
		if (url.includes('/release') || url.includes('/reject')) {
			return { ok: true, status: 200, json: async () => ({}), text: async () => '' } as Response;
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

describe('Quarantine page', () => {
	beforeEach(() => {
		resetStores();
		clearToasts();
	});

	it('renders quarantined rows from the list endpoint', async () => {
		vi.stubGlobal('fetch', mockQuarantineFetch());
		const { findByText } = await renderAsUser(QuarantinePage);
		expect(await findByText('spammer@evil.test')).toBeTruthy();
		expect(await findByText('You won')).toBeTruthy();
	});

	it('sanitizes preview HTML before iframe injection (strips <script>)', async () => {
		vi.stubGlobal('fetch', mockQuarantineFetch('<p>safe</p><script>alert(1)</script>'));
		const { findByRole, findByTitle } = await renderAsUser(QuarantinePage);
		const previewBtn = await findByRole('button', { name: 'Preview' });
		await fireEvent.click(previewBtn);
		const frame = (await findByTitle('Message preview')) as HTMLIFrameElement;
		const srcdoc = frame.getAttribute('srcdoc') ?? '';
		expect(srcdoc).toContain('safe');
		expect(srcdoc).not.toContain('<script>');
		// sandbox must stay locked down
		expect(frame.getAttribute('sandbox')).toBe('');
	});

	it('release shows an Undo toast and does not use native confirm()', async () => {
		const confirmSpy = vi.fn(() => true);
		vi.stubGlobal('confirm', confirmSpy);
		const fetchSpy = mockQuarantineFetch();
		vi.stubGlobal('fetch', fetchSpy);

		const { findByRole } = await renderAsUser(QuarantinePage);
		const releaseBtn = await findByRole('button', { name: 'Release' });
		await fireEvent.click(releaseBtn);

		expect(confirmSpy).not.toHaveBeenCalled();
		await waitFor(() => {
			expect(toasts.some((t) => !!t.actionLabel)).toBe(true);
		});
	});

	it('Undo on release cancels the pending release POST (act-then-undo)', async () => {
		vi.useFakeTimers();
		try {
			const fetchSpy = mockQuarantineFetch();
			vi.stubGlobal('fetch', fetchSpy);

			const { findByRole } = await renderAsUser(QuarantinePage);
			const releaseBtn = await findByRole('button', { name: 'Release' });
			await fireEvent.click(releaseBtn);

			// Undo before the window elapses.
			const undo = toasts.find((t) => !!t.onAction);
			expect(undo).toBeTruthy();
			undo?.onAction?.();

			await vi.advanceTimersByTimeAsync(7000);
			expect(fetchSpy.mock.calls.some((c) => String(c[0]).includes('/release'))).toBe(false);
		} finally {
			vi.useRealTimers();
		}
	});

	it('disables the Preview button while the preview fetch is in flight', async () => {
		let resolvePreview!: (v: Response) => void;
		const previewPromise = new Promise<Response>((r) => {
			resolvePreview = r;
		});
		const fetchSpy = vi.fn(async (input: RequestInfo | URL) => {
			const url = typeof input === 'string' ? input : input.toString();
			if (url.includes('/preview')) return previewPromise;
			return {
				ok: true,
				status: 200,
				json: async () => ({ items: [ITEM] }),
				text: async () => ''
			} as Response;
		});
		vi.stubGlobal('fetch', fetchSpy);

		const { findByRole } = await renderAsUser(QuarantinePage);
		const previewBtn = (await findByRole('button', { name: 'Preview' })) as HTMLButtonElement;
		await fireEvent.click(previewBtn);

		await waitFor(() => expect(previewBtn.disabled).toBe(true));

		resolvePreview({
			ok: true,
			status: 200,
			json: async () => ({ ...ITEM, html: '<p>x</p>' }),
			text: async () => ''
		} as Response);

		await waitFor(() => expect(previewBtn.disabled).toBe(false));
	});

	it('Reject opens an irreversible confirm Dialog; confirming posts the reject', async () => {
		const confirmSpy = vi.fn(() => true);
		vi.stubGlobal('confirm', confirmSpy);
		const fetchSpy = mockQuarantineFetch();
		vi.stubGlobal('fetch', fetchSpy);

		const { findByRole, getByRole } = await renderAsUser(QuarantinePage);
		const rejectBtn = await findByRole('button', { name: 'Reject' });
		await fireEvent.click(rejectBtn);

		// A Dialog appears; native confirm is not used and no reject is posted yet.
		const dialog = getByRole('dialog');
		expect(dialog).toBeTruthy();
		expect(confirmSpy).not.toHaveBeenCalled();
		expect(fetchSpy.mock.calls.some((c) => String(c[0]).includes('/reject'))).toBe(false);

		// Confirm inside the dialog.
		await fireEvent.click(getByRole('button', { name: 'Reject message' }));
		await waitFor(() => {
			expect(fetchSpy.mock.calls.some((c) => String(c[0]).includes('/reject'))).toBe(true);
		});
	});
});

// ── WP5 completion: the page bootstraps through authedBootstrap — the
// protected list load runs only after a PROVEN session probe. ──

describe('Quarantine page — authenticated bootstrap (WP5)', () => {
	beforeEach(() => {
		resetStores();
		clearToasts();
	});
	afterEach(() => {
		cleanup();
		vi.unstubAllGlobals();
	});

	function trapLoginRedirect(): { redirects: string[]; restore: () => void } {
		const redirects: string[] = [];
		const original = window.location;
		Object.defineProperty(window, 'location', {
			value: {
				host: 'localhost:5173',
				get href() {
					return 'http://localhost:5173/';
				},
				set href(v: string) {
					redirects.push(v);
				},
			},
			configurable: true,
		});
		return {
			redirects,
			restore: () => Object.defineProperty(window, 'location', { value: original, configurable: true }),
		};
	}

	it('an UNPROVEN session (401 probe) never fires the protected list load — silent-empty page, no redirects', async () => {
		const trap = trapLoginRedirect();
		try {
			const fetchSpy = vi.fn(async (_input: RequestInfo | URL) => ({ ok: false, status: 401, json: async () => ({}), text: async () => '' }) as Response);
			vi.stubGlobal('fetch', fetchSpy);
			const { findByText } = await renderAsUser(QuarantinePage);
			// The bootstrap probe 401s (loginRedirect:null inside loadSessionStore,
			// so the probe itself never redirects); the stale session the harness
			// installed is NOT proof, so the list endpoint is never touched and the
			// page settles to its silent-empty surface via onUnproven.
			expect(await findByText('Your quarantine is empty. No suspicious messages have been detected.')).toBeTruthy();
			expect(fetchSpy).toHaveBeenCalledTimes(1);
			expect(String(fetchSpy.mock.calls[0][0])).toContain('/.well-known/jmap');
			// No seam redirect fired (no protected call was made) and the page
			// never hand-rolls a goto.
			expect(trap.redirects).toEqual([]);
			expect(vi.mocked(goto)).not.toHaveBeenCalled();
		} finally {
			trap.restore();
		}
	});

	it('a PROVEN probe runs the protected list load through the settings-resource seam', async () => {
		const fetchSpy = vi.fn(async (input: RequestInfo | URL) => {
			const url = String(input);
			if (url.includes('/.well-known/jmap')) {
				return { ok: true, status: 200, json: async () => ({ capabilities: {} }), text: async () => '' } as Response;
			}
			return { ok: true, status: 200, json: async () => ({ items: [ITEM] }), text: async () => '' } as Response;
		});
		vi.stubGlobal('fetch', fetchSpy);
		const { findByText } = await renderAsUser(QuarantinePage);
		expect(await findByText('spammer@evil.test')).toBeTruthy();
		// The probe ran before the loader.
		expect(String(fetchSpy.mock.calls[0][0])).toContain('/.well-known/jmap');
		expect(fetchSpy.mock.calls.some(([u]) => String(u).includes('/api/quarantine?'))).toBe(true);
	});
});
