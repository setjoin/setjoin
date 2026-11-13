import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/svelte/svelte5';
import { toasts, clearToasts } from '$lib/components/ui';
import SignaturesPage from './+page.svelte';

const SIGS = [
	{ id: 1, alias_email: 'me@corp.test', signature_html: '<p>Best, Me</p>',
	  signature_text: 'Best, Me', default_for: 'new' },
	{ id: 2, alias_email: 'sales@corp.test', signature_html: '<p>Sales</p>',
	  signature_text: 'Sales', default_for: 'none' },
];

describe('Signatures settings card (Task 3)', () => {
	beforeEach(() => {
		clearToasts();
		// The $lib/http seam always sends an explicit method (GET for the list);
		// accept both the seam's shape and the legacy init-less raw fetch shape.
		vi.stubGlobal('fetch', vi.fn((url: string, init?: RequestInit) => {
			const method = (init?.method ?? 'GET').toUpperCase();
			if (url === '/api/settings/signatures-list' && method === 'GET')
				return Promise.resolve({ ok: true, status: 200, json: async () => SIGS, text: async () => '' });
			return Promise.resolve({ ok: true, status: 200, json: async () => ({}), text: async () => '' });
		}));
	});
	afterEach(() => {
		cleanup();
		vi.unstubAllGlobals();
	});

	it('lists existing signatures by alias', async () => {
		render(SignaturesPage);
		await waitFor(() => expect(screen.getByText('me@corp.test')).toBeInTheDocument());
		expect(screen.getByText('sales@corp.test')).toBeInTheDocument();
	});

	it('marks the new-mail default', async () => {
		render(SignaturesPage);
		await waitFor(() => expect(screen.getByTestId('sig-default-new-1')).toBeInTheDocument());
		expect((screen.getByTestId('sig-default-new-1') as HTMLInputElement).checked).toBe(true);
	});

	it('PUTs a new signature on save', async () => {
		render(SignaturesPage);
		await waitFor(() => screen.getByTestId('sig-new-btn'));
		await fireEvent.click(screen.getByTestId('sig-new-btn'));
		await fireEvent.input(screen.getByLabelText('Alias'), { target: { value: 'new@corp.test' } });
		await fireEvent.input(screen.getByLabelText('Signature'), { target: { value: 'Cheers' } });
		await fireEvent.click(screen.getByTestId('sig-save-btn'));
		await waitFor(() => {
			const calls = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls;
			expect(calls.some(([u, i]) =>
				u === '/api/settings/signatures' && i?.method === 'PUT')).toBe(true);
		});
	});

	it('DELETEs a signature', async () => {
		render(SignaturesPage);
		await waitFor(() => screen.getByTestId('sig-delete-2'));
		await fireEvent.click(screen.getByTestId('sig-delete-2'));
		await waitFor(() => {
			const calls = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls;
			expect(calls.some(([u, i]) =>
				u === '/api/settings/signatures/2' && i?.method === 'DELETE')).toBe(true);
		});
	});

	it('flips the new-mail default via PUT when a radio is clicked', async () => {
		render(SignaturesPage);
		await waitFor(() => screen.getByTestId('sig-default-new-2'));
		await fireEvent.click(screen.getByTestId('sig-default-new-2'));
		await waitFor(() => {
			const calls = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls;
			const put = calls.find(([u, i]) => u === '/api/settings/signatures' && i?.method === 'PUT');
			expect(put).toBeDefined();
			const body = JSON.parse((put![1] as RequestInit).body as string);
			expect(body.default_for).toBe('new');
		});
	});
});

// ── WP5: the page loads/saves through the settings-resource composable and
// bootstraps through authedBootstrap (probe → proven → protected loader). ──

describe('Signatures settings card — composable wiring (WP5)', () => {
	beforeEach(() => clearToasts());
	afterEach(() => {
		cleanup();
		vi.unstubAllGlobals();
	});

	it('shows the loadError toast when the list endpoint fails (seam typed error)', async () => {
		vi.stubGlobal('fetch', vi.fn((url: string | URL) => {
			// The bootstrap probe succeeds (any JSON body proves a fresh session
			// document); the protected list read fails.
			if (String(url).includes('/.well-known/jmap')) {
				return Promise.resolve({ ok: true, status: 200, json: async () => ({ capabilities: {} }), text: async () => '' } as Response);
			}
			return Promise.resolve({ ok: false, status: 500, json: async () => ({}), text: async () => '' } as Response);
		}));
		render(SignaturesPage);
		await waitFor(() => expect(toasts.length).toBeGreaterThan(0));
		expect(screen.queryByText('me@corp.test')).not.toBeInTheDocument();
	});

	it('aborts the in-flight list load on unmount; cancellation is not a load error', async () => {
		const captured: Array<{ url: string; signal: AbortSignal }> = [];
		vi.stubGlobal('fetch', vi.fn((url: string | URL, init?: RequestInit) => {
			if (init?.signal) captured.push({ url: String(url), signal: init.signal });
			if (String(url).includes('/.well-known/jmap')) {
				// The probe resolves so the protected loader starts.
				return Promise.resolve({ ok: true, status: 200, json: async () => ({ capabilities: {} }), text: async () => '' } as Response);
			}
			return new Promise<Response>((_resolve, reject) => {
				init?.signal?.addEventListener(
					'abort',
					() => reject(new DOMException('Aborted', 'AbortError')),
					{ once: true }
				);
			});
		}));
		const { unmount } = render(SignaturesPage);
		const listCall = await waitFor(() => {
			const found = captured.find((c) => c.url.includes('/api/settings/signatures-list'));
			expect(found).toBeTruthy();
			return found as { url: string; signal: AbortSignal };
		});
		unmount();
		// The bootstrap signal aborts the in-flight list load.
		expect(listCall.signal.aborted).toBe(true);
		// Cancellation must not surface the loadError toast.
		expect(toasts.some((t) => t.message === 'Could not load signatures.')).toBe(false);
	});

	it('an UNPROVEN probe never fires the protected list load and settles the page', async () => {
		const fetchSpy = vi.fn((_url: string | URL) =>
			Promise.resolve({ ok: false, status: 401, json: async () => ({}), text: async () => '' } as Response)
		);
		vi.stubGlobal('fetch', fetchSpy);
		const { container } = render(SignaturesPage);
		await waitFor(() => expect(fetchSpy).toHaveBeenCalled());
		// Give the probe's async tail a tick, then assert the list was never read.
		await new Promise((r) => setTimeout(r, 0));
		expect(fetchSpy.mock.calls.some(([u]) => String(u).includes('signatures-list'))).toBe(false);
		expect(container).toBeTruthy();
	});
});
