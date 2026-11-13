import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, cleanup } from '@testing-library/svelte/svelte5';
import CompareView from './CompareView.svelte';
import { paneMode } from './comparePane';
import type { DriveVersion } from '$lib/drive/api';

const httpRequest = vi.fn();
vi.mock('$lib/http', async (importOriginal) => ({
	...(await importOriginal<typeof import('$lib/http')>()),
	httpRequest: (...a: unknown[]) => httpRequest(...a),
}));

function version(overrides: Partial<DriveVersion> = {}): DriveVersion {
	return {
		id: 1,
		parentVersionId: null,
		conflictOf: null,
		sha256: 'a'.repeat(64),
		size: 1024,
		contentType: 'application/zip',
		author: 7,
		note: 'fixed totals',
		previewStatus: 'none',
		createdAt: '2026-07-10T00:00:00Z',
		branchId: null,
		labels: ['Approved'],
		...overrides,
	};
}

describe('paneMode', () => {
	it('picks image for a non-svg image content type', () => {
		expect(paneMode({ contentType: 'image/png', previewStatus: 'none' }, 'x.png')).toBe('image');
	});
	it('never picks image for svg (routes to metadataOnly — no sandboxed pane here)', () => {
		expect(paneMode({ contentType: 'image/svg+xml', previewStatus: 'none' }, 'x.svg')).toBe('metadataOnly');
	});
	it('picks text for a text/* content type', () => {
		expect(paneMode({ contentType: 'text/csv', previewStatus: 'none' }, 'x.csv')).toBe('text');
	});
	it('picks officeRendition only when the file is an office-edit type AND previewStatus is ready', () => {
		expect(paneMode({ contentType: 'application/msword', previewStatus: 'ready' }, 'x.doc')).toBe('officeRendition');
		expect(paneMode({ contentType: 'application/msword', previewStatus: 'pending' }, 'x.doc')).toBe('metadataOnly');
	});
	it('falls back to metadataOnly for anything else', () => {
		expect(paneMode({ contentType: 'application/zip', previewStatus: 'none' }, 'x.zip')).toBe('metadataOnly');
	});
});

describe('CompareView', () => {
	const createObjectURL = vi.fn(() => 'blob:mock-url');
	const revokeObjectURL = vi.fn();
	// AR-02 leak-balance harness: instrumented counters + controllable
	// (manually resolved/rejected) promises; every async test ends with
	// created === revoked and no resource revoked twice (AC1–AC4).
	const createdUrls: string[] = [];
	const revokedUrls: string[] = [];
	const unhandledRejections: unknown[] = [];
	const onUnhandled = (reason: unknown) => unhandledRejections.push(reason);

	function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void; reject: (error: unknown) => void } {
		let resolve!: (value: T) => void;
		let reject!: (error: unknown) => void;
		const promise = new Promise<T>((res, rej) => {
			resolve = res;
			reject = rej;
		});
		return { promise, resolve, reject };
	}

	type FakeRes = { status: number; blob: () => Promise<Blob>; json?: () => Promise<unknown> };
	const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

	function expectLeakBalanced(): void {
		expect([...revokedUrls].sort()).toEqual([...createdUrls].sort());
		expect(new Set(revokedUrls).size).toBe(revokedUrls.length);
	}

	beforeEach(() => {
		httpRequest.mockReset();
		createObjectURL.mockClear();
		revokeObjectURL.mockClear();
		createdUrls.length = 0;
		revokedUrls.length = 0;
		unhandledRejections.length = 0;
		let n = 0;
		createObjectURL.mockImplementation(() => {
			const url = `blob:mock-${++n}`;
			createdUrls.push(url);
			return url;
		});
		revokeObjectURL.mockImplementation((url: string) => {
			revokedUrls.push(url);
		});
		URL.createObjectURL = createObjectURL as unknown as typeof URL.createObjectURL;
		URL.revokeObjectURL = revokeObjectURL;
		process.on('unhandledRejection', onUnhandled);
	});

	afterEach(async () => {
		cleanup(); // unmount live components first so effect teardown revokes what it owns
		await tick(); // let any late rejection surface before judging it
		process.off('unhandledRejection', onUnhandled);
		expect(unhandledRejections).toEqual([]);
		expectLeakBalanced();
		vi.restoreAllMocks();
	});

	it('always renders the metadata diff table: size, author, note, date, labels, identical/differs', () => {
		render(CompareView, {
			left: version({ id: 1, size: 1024, sha256: 'a'.repeat(64) }),
			right: version({ id: 2, size: 2048, sha256: 'b'.repeat(64) }),
			fileName: 'notes.txt',
		});
		expect(screen.getByText('Size')).toBeTruthy();
		expect(screen.getByText('Saved by')).toBeTruthy();
		expect(screen.getByText('Note')).toBeTruthy();
		expect(screen.getByText('Date')).toBeTruthy();
		expect(screen.getByText('Labels')).toBeTruthy();
		expect(screen.getByText('Content differs')).toBeTruthy();
	});

	it('shows "Identical content" when both sides share a sha256', () => {
		render(CompareView, {
			left: version({ id: 1, sha256: 'a'.repeat(64) }),
			right: version({ id: 2, sha256: 'a'.repeat(64) }),
			fileName: 'notes.txt',
		});
		expect(screen.getByText('Identical content')).toBeTruthy();
	});

	it('renders side-by-side <img> panes for two images', async () => {
		httpRequest.mockResolvedValue({ status: 200, blob: async () => new Blob(['x'], { type: 'image/png' }) });
		const { container } = render(CompareView, {
			left: version({ id: 1, contentType: 'image/png' }),
			right: version({ id: 2, contentType: 'image/png' }),
			fileName: 'photo.png',
		});
		await vi.waitFor(() => expect(container.querySelectorAll('img')).toHaveLength(2));
	});

	it('AC1: unmount while fetches are in flight — late completions register nothing and nothing leaks', async () => {
		const gate = deferred<FakeRes>();
		httpRequest.mockReturnValue(gate.promise);
		const { container, unmount } = render(CompareView, {
			left: version({ id: 1, contentType: 'image/png' }),
			right: version({ id: 2, contentType: 'image/png' }),
			fileName: 'photo.png',
		});
		unmount();
		gate.resolve({ status: 200, blob: async () => new Blob(['x'], { type: 'image/png' }) });
		await tick();
		expect(container.querySelectorAll('img')).toHaveLength(0);
		expect(createdUrls).toEqual([]); // stale attempt: URLs never even created
	});

	it('AC1: teardown after one side registered revokes its URL exactly once; the pending side never creates', async () => {
		const leftBlob = deferred<Blob>();
		const rightBlob = deferred<Blob>();
		httpRequest.mockImplementation((url: string) =>
			Promise.resolve({
				status: 200,
				blob: () => (url.includes('/versions/1/') ? leftBlob.promise : rightBlob.promise),
			}),
		);
		const { unmount } = render(CompareView, {
			left: version({ id: 1, contentType: 'image/png' }),
			right: version({ id: 2, contentType: 'image/png' }),
			fileName: 'photo.png',
		});
		leftBlob.resolve(new Blob(['x'], { type: 'image/png' }));
		await vi.waitFor(() => expect(createdUrls).toHaveLength(1)); // left registered
		unmount();
		expect(revokedUrls).toEqual([createdUrls[0]]); // exactly once
		rightBlob.resolve(new Blob(['y'], { type: 'image/png' }));
		await tick();
		expect(createdUrls).toHaveLength(1); // superseded side never created its URL
		expect(revokedUrls).toEqual([createdUrls[0]]);
	});

	it('AC2: mode flip mid-flight releases the superseded attempt; the new run renders', async () => {
		const gates: ReturnType<typeof deferred<FakeRes>>[] = [];
		httpRequest.mockImplementation(() => {
			const gate = deferred<FakeRes>();
			gates.push(gate);
			return gate.promise;
		});
		const { container, rerender, unmount } = render(CompareView, {
			left: version({ id: 1, contentType: 'image/png' }),
			right: version({ id: 2, contentType: 'image/png' }),
			fileName: 'data',
		});
		expect(gates).toHaveLength(2); // run 1: both side fetches in flight (image mode)

		// Left side fully lands pre-flip; right fetch still pending.
		gates[0].resolve({ status: 200, blob: async () => new Blob(['x'], { type: 'image/png' }) });
		await vi.waitFor(() => expect(createdUrls).toHaveLength(1));

		// Flip image -> text: prop identity change re-runs the effect and closes attempt 1.
		rerender({
			left: version({ id: 1, contentType: 'text/csv' }),
			right: version({ id: 2, contentType: 'text/csv' }),
			fileName: 'data.csv',
		});
		expect(revokedUrls).toEqual([createdUrls[0]]); // old attempt released its registered URL exactly once

		// Run 1's pending side resolves late — must never create or register.
		gates[1].resolve({ status: 200, blob: async () => new Blob(['y'], { type: 'image/png' }) });
		await tick();
		expect(createdUrls).toHaveLength(1);

		// Run 2 (text mode) renders both text panes.
		gates[2].resolve({ status: 200, blob: async () => new Blob(['a'], { type: 'text/csv' }) });
		gates[3].resolve({ status: 200, blob: async () => new Blob(['b'], { type: 'text/csv' }) });
		await vi.waitFor(() => expect(container.querySelectorAll('pre')).toHaveLength(2));
		unmount();
	});

	it('AC3: one-side failure (stale ready prop meets preview 404) degrades to the metadata note, releases the settled side, no unhandled rejection', async () => {
		const leftGate = deferred<FakeRes>();
		const rightGate = deferred<FakeRes>();
		httpRequest.mockImplementation((url: string) =>
			url.includes('/versions/1/') ? leftGate.promise : rightGate.promise,
		);
		const { container } = render(CompareView, {
			left: version({ id: 1, contentType: 'application/msword', previewStatus: 'ready' }),
			right: version({ id: 2, contentType: 'application/msword', previewStatus: 'ready' }),
			fileName: 'report.doc',
		});
		// Left rendition lands; right throws the httpRequest-typed 404 (CompareView
		// passes no allowStatuses — the stale-'ready'-prop trigger the review named).
		leftGate.resolve({ status: 200, blob: async () => new Blob(['pdf'], { type: 'application/pdf' }) });
		rightGate.reject(new Error('preview rendition not ready (status=pending)'));
		await vi.waitFor(() =>
			expect(screen.getByText('Preview not available — comparing details only.')).toBeTruthy(),
		);
		expect(container.querySelectorAll('embed')).toHaveLength(0); // settled side released, not rendered
		expect(revokedUrls).toEqual(createdUrls); // left URL revoked by the attempt
	});

	it('office pane not ready on either side: degrades to metadata-only with the noPreview note', () => {
		render(CompareView, {
			left: version({ id: 1, contentType: 'application/msword', previewStatus: 'none' }),
			right: version({ id: 2, contentType: 'application/msword', previewStatus: 'none' }),
			fileName: 'report.doc',
		});
		expect(screen.getByText('Preview not available — comparing details only.')).toBeTruthy();
	});
});
