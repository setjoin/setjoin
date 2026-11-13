import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, cleanup } from '@testing-library/svelte/svelte5';
import { flushSync } from 'svelte';
import SecureViewer from './SecureViewer.svelte';
import type { VersionMeta } from '$lib/drive/opener.svelte';
import { jmapSession } from '$lib/stores/session';
import { user } from '$lib/stores/auth';

const { httpRequest } = vi.hoisted(() => ({
	httpRequest: vi.fn().mockResolvedValue({ status: 401, ok: false }),
}));
vi.mock('$lib/http', async (importOriginal) => ({
	...(await importOriginal<typeof import('$lib/http')>()),
	httpRequest: (...a: unknown[]) => httpRequest(...a),
}));

function version(overrides: Partial<VersionMeta> = {}): VersionMeta {
	return {
		versionId: 42,
		name: 'report.png',
		contentType: 'image/png',
		size: 1024,
		classification: 'secure',
		previewStatus: 'none',
		...overrides,
	};
}

describe('SecureViewer', () => {
	const createObjectURL = vi.fn(() => 'blob:mock-url');
	const revokeObjectURL = vi.fn();
	// AR-02 leak-balance harness: instrumented URL counters + controllable
	// (manually resolved/rejected) promises; every async test ends with
	// created === revoked and nothing revoked twice (AC1–AC4).
	const createdUrls: string[] = [];
	const revokedUrls: string[] = [];
	const unhandledRejections: unknown[] = [];
	const onUnhandled = (reason: unknown) => unhandledRejections.push(reason);
	// AR-02 scheduling hook: a test can arm a callback that fires synchronously
	// at URL creation — i.e. inside the acquisition thunk — and queue
	// microtask-timed cleanup into the acquire()→caller state-write handoff
	// window (the gap the module's own stale check cannot cover).
	let onCreate: (() => void) | null = null;

	function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void; reject: (error: unknown) => void } {
		let resolve!: (value: T) => void;
		let reject!: (error: unknown) => void;
		const promise = new Promise<T>((res, rej) => {
			resolve = res;
			reject = rej;
		});
		return { promise, resolve, reject };
	}

	const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

	function expectLeakBalanced(): void {
		expect([...revokedUrls].sort()).toEqual([...createdUrls].sort());
		expect(new Set(revokedUrls).size).toBe(revokedUrls.length);
	}

	beforeEach(() => {
		createObjectURL.mockClear();
		revokeObjectURL.mockClear();
		createdUrls.length = 0;
		revokedUrls.length = 0;
		unhandledRejections.length = 0;
		httpRequest.mockReset();
		onCreate = null;
		let n = 0;
		createObjectURL.mockImplementation(() => {
			const url = `blob:mock-${++n}`;
			createdUrls.push(url);
			if (onCreate) {
				const dance = onCreate;
				onCreate = null;
				dance();
			}
			return url;
		});
		revokeObjectURL.mockImplementation((url: string) => {
			revokedUrls.push(url);
		});
		URL.createObjectURL = createObjectURL as unknown as typeof URL.createObjectURL;
		URL.revokeObjectURL = revokeObjectURL;
		(window as unknown as { setjoinNative?: unknown }).setjoinNative = undefined;
		jmapSession.set(null);
		user.set(null);
		process.on('unhandledRejection', onUnhandled);
	});

	afterEach(async () => {
		cleanup(); // unmount live viewers first so effect teardown releases what it owns
		await tick(); // let any late rejection surface before judging it
		process.off('unhandledRejection', onUnhandled);
		expect(unhandledRejections).toEqual([]);
		expectLeakBalanced();
		delete (window as unknown as { setjoinNative?: unknown }).setjoinNative;
	});

	it('regular online image: fetches /content and renders an <img> from a RAM blob', async () => {
		httpRequest.mockResolvedValue({ status: 200, blob: async () => new Blob(['x'], { type: 'image/png' }) });
		render(SecureViewer, { version: version({ classification: 'regular' }), source: { kind: 'online' }, onclose: vi.fn() });
		await vi.waitFor(() => expect(screen.getByAltText('report.png')).toBeTruthy());

		expect(httpRequest).toHaveBeenCalledWith(
			'/api/drive/versions/42/content',
			{},
		);
		expect((screen.getByAltText('report.png') as HTMLImageElement).src).toBe('blob:mock-1'); // createdUrls[0] — instrumented harness
	});

	it('secure online image never requests original bytes and offers governed export', async () => {
		render(SecureViewer, { version: version(), source: { kind: 'online' }, onclose: vi.fn() });
		await vi.waitFor(() => expect(screen.getByText(/governed export request/i)).toBeTruthy());
		expect(httpRequest).not.toHaveBeenCalled();
		expect(screen.queryByAltText('report.png')).toBeNull();
		expect(screen.getByText('Request download')).toBeTruthy();
	});

	it('view-only guest does not request non-office original bytes and renders the identity watermark', async () => {
		jmapSession.set({
			isGuest: true,
			effectiveCapabilities: {
				apps: { chat: true },
				features: { assist: false, bundles: false },
				guest: { allowDownload: false },
			},
		} as never);
		user.set({ email: 'guest@partner.example', isAdmin: false, hasMailbox: false, accountType: 'guest' });
		const { container } = render(SecureViewer, { version: version(), source: { kind: 'online' }, onclose: vi.fn() });
		await vi.waitFor(() => expect(screen.getByText(/no view-only rendition/i)).toBeTruthy());
		expect(httpRequest).not.toHaveBeenCalled();
		expect(container.querySelector('.watermark')).toBeTruthy();
		expect(screen.queryByText('Request download')).toBeNull();
	});

	it('known auth guest stays view-only when JMAP capability loading failed', async () => {
		user.set({ email: 'guest@partner.example', isAdmin: false, hasMailbox: false, accountType: 'guest' });
		const { container } = render(SecureViewer, { version: version(), source: { kind: 'online' }, onclose: vi.fn() });
		await vi.waitFor(() => expect(screen.getByText(/no view-only rendition/i)).toBeTruthy());
		expect(httpRequest).not.toHaveBeenCalled();
		expect(container.querySelector('.watermark')).toBeTruthy();
		expect(screen.queryByText('Request download')).toBeNull();
	});

	it('never renders SVG via <img> — sanitized sandboxed iframe instead', async () => {
		httpRequest.mockResolvedValue({
			status: 200,
			blob: async () => ({ text: async () => '<svg onload="evil()"><script>evil()</script></svg>' }),
		});
		const { container } = render(SecureViewer, {
			version: version({ classification: 'regular', contentType: 'image/svg+xml', name: 'x.svg' }),
			source: { kind: 'online' },
			onclose: vi.fn(),
		});
		await vi.waitFor(() => expect(container.querySelector('iframe')).toBeTruthy());
		const frame = container.querySelector('iframe')!;
		expect(frame.getAttribute('sandbox')).toBe('');
		expect(frame.getAttribute('srcdoc')).not.toContain('onload');
		expect(frame.getAttribute('srcdoc')).not.toContain('<script>');
	});

	it('office rendition not ready: asks the server (never trusts a stale previewStatus prop), shows pending', async () => {
		httpRequest.mockResolvedValue({
			status: 404,
			json: async () => ({ detail: 'preview rendition not ready (status=pending)' }),
		});
		render(SecureViewer, {
			version: version({ contentType: 'application/msword', previewStatus: 'none' }),
			source: { kind: 'online' },
			onclose: vi.fn(),
		});
		await vi.waitFor(() => expect(screen.getByText('Rendition preview is not ready yet.')).toBeTruthy());
		expect(httpRequest).toHaveBeenCalledWith(
			'/api/drive/versions/42/preview',
			expect.objectContaining({ allowStatuses: [404] }),
		);
	});

	it('office rendition unsupported (live server status wins over a stale "ready" prop): shows the terminal state, no retry button', async () => {
		httpRequest.mockResolvedValue({
			status: 404,
			json: async () => ({ detail: 'preview rendition not ready (status=unsupported)' }),
		});
		render(SecureViewer, {
			version: version({ contentType: 'application/msword', previewStatus: 'ready' }),
			source: { kind: 'online' },
			onclose: vi.fn(),
		});
		await vi.waitFor(() => expect(screen.getByText('A preview is not available for this file type.')).toBeTruthy());
		expect(screen.queryByRole('button', { name: 'Retry' })).toBeNull();
	});

	it('vault + AV content: starts the loopback server and renders <video> from the ticket URL', async () => {
		const serveStart = vi.fn().mockResolvedValue({ port: 4321 });
		const serveGrant = vi.fn().mockResolvedValue('/t/abc123');
		const serveRevoke = vi.fn().mockResolvedValue(undefined);
		(window as unknown as { setjoinNative: unknown }).setjoinNative = {
			drive: { serveStart, serveGrant, serveRevoke },
		};
		const manifest = { contentSha256: 'x', size: 10, contentType: 'video/mp4', chunks: [{ sha256: 'a', size: 10 }] };
		const { unmount } = render(SecureViewer, {
			version: version({ contentType: 'video/mp4', name: 'clip.mp4' }),
			source: { kind: 'vault', manifest },
			onclose: vi.fn(),
		});
		await vi.waitFor(() => expect(serveGrant).toHaveBeenCalledWith(manifest));
		const video = document.querySelector('video')!;
		expect(video.src).toBe('http://127.0.0.1:4321/t/abc123');

		unmount();
		expect(serveRevoke).toHaveBeenCalledWith('/t/abc123');
	});

	it('vault + small non-AV content: reads chunk bytes via db.query and renders an <img> RAM blob', async () => {
		const query = vi.fn().mockResolvedValue([{ bytes: btoa('hello') }]);
		(window as unknown as { setjoinNative: unknown }).setjoinNative = { drive: {}, db: { query } };
		const manifest = { contentSha256: 'x', size: 5, chunks: [{ sha256: 'sha-a', size: 5 }] };
		render(SecureViewer, {
			version: version({ contentType: 'image/png' }),
			source: { kind: 'vault', manifest },
			onclose: vi.fn(),
		});
		await vi.waitFor(() => expect(screen.getByAltText('report.png')).toBeTruthy());
		expect(query).toHaveBeenCalledWith('drive', expect.stringContaining('SELECT bytes'), ['sha-a']);
	});

	it('unknown/unhandled content falls back to the metadata card with a request-export action', async () => {
		httpRequest.mockResolvedValue({ status: 200, blob: async () => new Blob(['x'], { type: 'application/zip' }) });
		render(SecureViewer, {
			version: version({ classification: 'regular', contentType: 'application/zip', name: 'archive.zip' }),
			source: { kind: 'online' },
			onclose: vi.fn(),
		});
		await vi.waitFor(() => expect(screen.getByText('Ask an admin to export this file.')).toBeTruthy());
	});

	it('P5: online source shows export/print request buttons in the footer', async () => {
		render(SecureViewer, { version: version(), source: { kind: 'online' }, onclose: vi.fn() });
		await vi.waitFor(() => expect(screen.getByText(/governed export request/i)).toBeTruthy());
		expect(screen.getByRole('button', { name: 'Request download' })).toBeTruthy();
		expect(screen.getByRole('button', { name: 'Request print' })).toBeTruthy();
	});

	it('P5: vault source does not show export/print request buttons (server-authoritative online-only flow)', async () => {
		const query = vi.fn().mockResolvedValue([{ bytes: btoa('hello') }]);
		(window as unknown as { setjoinNative: unknown }).setjoinNative = { drive: {}, db: { query } };
		const manifest = { contentSha256: 'x', size: 5, chunks: [{ sha256: 'sha-a', size: 5 }] };
		render(SecureViewer, {
			version: version({ contentType: 'image/png' }),
			source: { kind: 'vault', manifest },
			onclose: vi.fn(),
		});
		await vi.waitFor(() => expect(screen.getByAltText('report.png')).toBeTruthy());
		expect(screen.queryByRole('button', { name: 'Request download' })).toBeNull();
	});

	it('closing revokes the object URL and calls onclose', async () => {
		httpRequest.mockResolvedValue({ status: 200, blob: async () => new Blob(['x'], { type: 'image/png' }) });
		const onclose = vi.fn();
		render(SecureViewer, { version: version({ classification: 'regular' }), source: { kind: 'online' }, onclose });
		await vi.waitFor(() => expect(screen.getByAltText('report.png')).toBeTruthy());
		await fireEvent.click(screen.getByLabelText('Close'));
		expect(onclose).toHaveBeenCalledTimes(1);
	});

	// ── AR-02: late-acquisition windows the unmount-after-grant test above
	//    cannot see (viewAttempt stale check) ─────────────────────────────────

	it('AC1: unmount during the serveStart await — no grant is ever requested', async () => {
		const serveStartGate = deferred<{ port: number }>();
		const serveStart = vi.fn(() => serveStartGate.promise);
		const serveGrant = vi.fn();
		const serveRevoke = vi.fn();
		(window as unknown as { setjoinNative: unknown }).setjoinNative = {
			drive: { serveStart, serveGrant, serveRevoke },
		};
		const manifest = { contentSha256: 'x', size: 10, contentType: 'video/mp4', chunks: [{ sha256: 'a', size: 10 }] };
		const { unmount } = render(SecureViewer, {
			version: version({ contentType: 'video/mp4', name: 'clip.mp4' }),
			source: { kind: 'vault', manifest },
			onclose: vi.fn(),
		});
		await vi.waitFor(() => expect(serveStart).toHaveBeenCalled());
		unmount();
		serveStartGate.resolve({ port: 4321 });
		await tick();
		expect(serveGrant).not.toHaveBeenCalled(); // closed attempt never creates
		expect(serveRevoke).not.toHaveBeenCalled(); // nothing granted, nothing to revoke
		expect(document.querySelector('video')).toBeNull();
	});

	it('AC1: unmount between serveStart and serveGrant — a grant resolving post-unmount still gets serveRevoke', async () => {
		const grantGate = deferred<string>();
		const serveStart = vi.fn().mockResolvedValue({ port: 4321 });
		const serveGrant = vi.fn(() => grantGate.promise);
		const serveRevoke = vi.fn().mockResolvedValue(undefined); // DriveBridge contract: revoke returns a promise
		(window as unknown as { setjoinNative: unknown }).setjoinNative = {
			drive: { serveStart, serveGrant, serveRevoke },
		};
		const manifest = { contentSha256: 'x', size: 10, contentType: 'video/mp4', chunks: [{ sha256: 'a', size: 10 }] };
		const { unmount } = render(SecureViewer, {
			version: version({ contentType: 'video/mp4', name: 'clip.mp4' }),
			source: { kind: 'vault', manifest },
			onclose: vi.fn(),
		});
		await vi.waitFor(() => expect(serveGrant).toHaveBeenCalledWith(manifest));
		unmount(); // teardown while the grant is in flight
		grantGate.resolve('/t/late');
		await tick();
		expect(serveRevoke).toHaveBeenCalledTimes(1); // native grant never outlives close
		expect(serveRevoke).toHaveBeenCalledWith('/t/late');
		expect(document.querySelector('video')).toBeNull(); // never registered into dead state
	});

	it('AC1: unmount during res.blob() (online path) — the late blob never becomes a URL', async () => {
		const blobGate = deferred<Blob>();
		httpRequest.mockResolvedValue({ status: 200, blob: () => blobGate.promise });
		const { container, unmount } = render(SecureViewer, {
			version: version({ classification: 'regular' }),
			source: { kind: 'online' },
			onclose: vi.fn(),
		});
		await vi.waitFor(() => expect(httpRequest).toHaveBeenCalledWith('/api/drive/versions/42/content', {}));
		unmount();
		blobGate.resolve(new Blob(['x'], { type: 'image/png' }));
		await tick();
		expect(createdUrls).toEqual([]); // stale attempt: URL never created
		expect(container.querySelectorAll('img')).toHaveLength(0);
	});

	it('AC1: unmount during res.blob() (office rendition path) — the started thunk’s URL is revoked exactly once, never rendered', async () => {
		const blobEntered = deferred<void>();
		const blobGate = deferred<Blob>();
		httpRequest.mockResolvedValue({
			status: 200,
			blob: () => {
				blobEntered.resolve(); // synchronize on entry into blob(): the acquisition thunk has started
				return blobGate.promise;
			},
		});
		const { container, unmount } = render(SecureViewer, {
			version: version({ contentType: 'application/msword', previewStatus: 'ready' }),
			source: { kind: 'online' },
			onclose: vi.fn(),
		});
		await blobEntered.promise;
		unmount(); // teardown while res.blob() is in flight INSIDE the acquire thunk
		blobGate.resolve(new Blob(['pdf'], { type: 'application/pdf' }));
		await tick();
		// The thunk had already started, so the fresh URL IS created — the closed
		// attempt owns it and revokes it exactly once; the caller resolves null.
		// (Zero creation would only hold for a thunk that never started.)
		expect(createdUrls).toHaveLength(1);
		expect(revokedUrls).toEqual(createdUrls);
		expect(container.querySelector('embed')).toBeNull(); // no rendered result
	});

	it('AC2: version swap while in flight — the superseded run creates nothing and never writes state; the new version renders', async () => {
		const gates: ReturnType<typeof deferred<{ status: number; blob: () => Promise<Blob> }>>[] = [];
		httpRequest.mockImplementation(() => {
			const gate = deferred<{ status: number; blob: () => Promise<Blob> }>();
			gates.push(gate);
			return gate.promise;
		});
		const onclose = vi.fn();
		const { rerender } = render(SecureViewer, {
			version: version({ versionId: 1, classification: 'regular' }),
			source: { kind: 'online' },
			onclose,
		});
		rerender({
			version: version({ versionId: 2, classification: 'regular', name: 'other.png' }),
			source: { kind: 'online' },
			onclose,
		});
		expect(gates).toHaveLength(2);
		// Attempt 1 completes AFTER supersession: must not create or register.
		gates[0].resolve({ status: 200, blob: async () => new Blob(['old'], { type: 'image/png' }) });
		await tick();
		expect(createdUrls).toEqual([]);
		gates[1].resolve({ status: 200, blob: async () => new Blob(['new'], { type: 'image/png' }) });
		const img = await vi.waitFor(() => screen.getByAltText('other.png'));
		expect((img as HTMLImageElement).src).toBe('blob:mock-1');
	});

	it('AC2: a superseding rerender racing the acquisition thunk stays leak-balanced; the live attempt wins the render', async () => {
		const blobGate = deferred<Blob>();
		httpRequest.mockResolvedValue({ status: 200, blob: () => blobGate.promise });
		const serveStart = vi.fn().mockResolvedValue({ port: 4321 });
		const serveGrant = vi.fn().mockResolvedValue('/t/new');
		const serveRevoke = vi.fn().mockResolvedValue(undefined); // DriveBridge contract: revoke returns a promise
		(window as unknown as { setjoinNative: unknown }).setjoinNative = {
			drive: { serveStart, serveGrant, serveRevoke },
		};
		const onclose = vi.fn();
		const { container, rerender } = render(SecureViewer, {
			version: version({ contentType: 'application/msword', previewStatus: 'ready' }),
			source: { kind: 'online' },
			onclose,
		});
		await vi.waitFor(() =>
			expect(httpRequest).toHaveBeenCalledWith(
				'/api/drive/versions/42/preview',
				expect.objectContaining({ allowStatuses: [404] }),
			),
		);
		// Arm the dance: when the doomed attempt's URL is created (synchronously
		// inside the acquire thunk), queue the superseding rerender N microtasks
		// later so the rerender genuinely interleaves the acquisition lifetime.
		// The deterministic stale-write detector for this handoff window lives at
		// the module level (acquireAndCommit caller-handoff tests, promise-FIFO
		// ordered); this component-level race asserts the observable outcomes
		// whatever the interleaving point: leak-balance and live-attempt-wins.
		// flushSync forces Svelte's rerender work (teardown → releaseAll → the
		// new attempt's state reset) to complete before the dance returns. The
		// new attempt is a vault AV rendition, so the template renders
		// `objectUrl ?? loopbackSrc` — a stale blob:mock-1 surviving anywhere in
		// objectUrl would resurrect the revoked URL as the video source.
		onCreate = () => {
			const dance = () => {
				flushSync(() => {
					rerender({
						version: version({ versionId: 43, name: 'takeover.mp4', contentType: 'video/mp4', size: 536870913 }),
						source: { kind: 'vault', manifest: { contentSha256: 'x', size: 536870913, chunks: [] } },
						onclose,
					});
				});
			};
			let depth = 8;
			(function tick(): void {
				if (depth-- === 0) dance();
				else queueMicrotask(tick);
			})();
		};
		blobGate.resolve(new Blob(['old-office'], { type: 'application/pdf' }));
		const video = await vi.waitFor(() => {
			const el = container.querySelector('video');
			expect(el).toBeTruthy();
			return el as HTMLVideoElement;
		});
		expect(video.src).toBe('http://127.0.0.1:4321/t/new'); // the live attempt wins the render
		// The superseded attempt's resource: created once inside its thunk,
		// revoked exactly once — and never rendered.
		expect(createdUrls).toEqual(['blob:mock-1']);
		expect(revokedUrls).toEqual(['blob:mock-1']);
	});

	it('AC2/AC4: retry racing an in-flight attempt — the superseded run never renders or leaks; the last attempt wins', async () => {
		type Gate = { status: number; blob?: () => Promise<Blob>; json?: () => Promise<unknown> };
		const gates: ReturnType<typeof deferred<Gate>>[] = [];
		httpRequest.mockImplementation(() => {
			const gate = deferred<Gate>();
			gates.push(gate);
			return gate.promise;
		});
		const { container, unmount } = render(SecureViewer, {
			version: version({ contentType: 'application/msword', previewStatus: 'none' }),
			source: { kind: 'online' },
			onclose: vi.fn(),
		});
		expect(gates).toHaveLength(1); // first preview probe in flight
		gates[0].resolve({
			status: 404,
			json: async () => ({ detail: 'preview rendition not ready (status=pending)' }),
		});
		const retry = await vi.waitFor(() => screen.getByRole('button', { name: 'Retry' }));

		// Two retries back-to-back, dispatched synchronously like a real
		// double-click (RTL's fireEvent flushes Svelte between calls, which
		// would detach the button and mask the race): attempt 2 opens, then is
		// immediately superseded by attempt 3 while attempt 2's fetch is in
		// flight — the retry race the old L204 shape allowed.
		(retry as HTMLElement).click();
		(retry as HTMLElement).click();
		expect(gates).toHaveLength(3);
		gates[1].resolve({ status: 200, blob: async () => new Blob(['stale-pdf'], { type: 'application/pdf' }) });
		await tick();
		expect(createdUrls).toEqual([]); // superseded retry creates nothing
		gates[2].resolve({ status: 200, blob: async () => new Blob(['live-pdf'], { type: 'application/pdf' }) });
		await vi.waitFor(() => expect(container.querySelector('embed')).toBeTruthy());
		expect(createdUrls).toHaveLength(1);
		unmount();
		expect(revokedUrls).toEqual([createdUrls[0]]); // exactly once
	});

	it('AC5: loading state is visible while the acquisition is in flight', async () => {
		httpRequest.mockImplementation(() => new Promise(() => {})); // never settles
		render(SecureViewer, {
			version: version({ classification: 'regular' }),
			source: { kind: 'online' },
			onclose: vi.fn(),
		});
		expect(screen.getByText('Loading...')).toBeTruthy();
	});

	it('AC5: acquisition failure reaches the error state (never a blank or stale render)', async () => {
		httpRequest.mockRejectedValue(new Error('boom'));
		render(SecureViewer, {
			version: version({ classification: 'regular' }),
			source: { kind: 'online' },
			onclose: vi.fn(),
		});
		await vi.waitFor(() => expect(screen.getByText('boom')).toBeTruthy());
		expect(screen.queryByAltText('report.png')).toBeNull();
	});

	it('AC5: retry click after notReady re-asks the server and renders the live rendition', async () => {
		httpRequest
			.mockResolvedValueOnce({
				status: 404,
				json: async () => ({ detail: 'preview rendition not ready (status=pending)' }),
			})
			.mockResolvedValueOnce({ status: 200, blob: async () => new Blob(['pdf'], { type: 'application/pdf' }) });
		const { container, unmount } = render(SecureViewer, {
			version: version({ contentType: 'application/msword', previewStatus: 'none' }),
			source: { kind: 'online' },
			onclose: vi.fn(),
		});
		const retry = await vi.waitFor(() => screen.getByRole('button', { name: 'Retry' }));
		await fireEvent.click(retry);
		await vi.waitFor(() => expect(container.querySelector('embed')).toBeTruthy());
		expect(createdUrls).toHaveLength(1);
		unmount();
		expect(revokedUrls).toEqual([createdUrls[0]]);
	});
});
