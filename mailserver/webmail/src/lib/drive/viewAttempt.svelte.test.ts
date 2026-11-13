// @vitest-environment node
// (DOM-free module: URL.createObjectURL is stubbed below; the static consumer
// guard reads component sources from disk, which jsdom's http:// import.meta.url cannot.)
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
	openViewAttempt,
	acquireAndCommit,
	blobUrlAdapter,
	nativeTicketAdapter,
	valueResource,
	type AcquiredResource,
} from './viewAttempt.svelte';
import type { DriveBridge, DriveManifest } from '$lib/native/types';

// AR-02 leak-balance harness: every test ends with created === revoked and no
// resource released twice — the module-level contract under the component
// migrations (AC1 cancel-release, AC4 exactly-once).

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void; reject: (error: unknown) => void } {
	let resolve!: (value: T) => void;
	let reject!: (error: unknown) => void;
	const promise = new Promise<T>((res, rej) => {
		resolve = res;
		reject = rej;
	});
	return { promise, resolve, reject };
}

describe('viewAttempt', () => {
	const createdUrls: string[] = [];
	const revokedUrls: string[] = [];
	let urlCounter = 0;

	const createObjectURL = vi.fn(() => {
		const url = `blob:mock-${++urlCounter}`;
		createdUrls.push(url);
		return url;
	});
	const revokeObjectURL = vi.fn((url: string) => {
		revokedUrls.push(url);
	});

	beforeEach(() => {
		createdUrls.length = 0;
		revokedUrls.length = 0;
		urlCounter = 0;
		createObjectURL.mockClear();
		revokeObjectURL.mockClear();
		URL.createObjectURL = createObjectURL as unknown as typeof URL.createObjectURL;
		URL.revokeObjectURL = revokeObjectURL;
	});

	/** created === revoked, and nothing revoked twice (AC4). */
	function expectLeakBalanced(): void {
		expect([...revokedUrls].sort()).toEqual([...createdUrls].sort());
		expect(new Set(revokedUrls).size).toBe(revokedUrls.length);
	}

	it('hands each attempt a monotonic generation and starts open', () => {
		const a = openViewAttempt();
		const b = openViewAttempt();
		expect(b.generation).toBeGreaterThan(a.generation);
		expect(a.closed).toBe(false);
		expect(a.liveKinds).toEqual([]);
	});

	it('registers a live acquisition, returns it for render, and releaseAll revokes exactly once', async () => {
		const attempt = openViewAttempt();
		const res = await attempt.acquire('blob-url', () => blobUrlAdapter(new Blob(['x'])));
		expect(res).not.toBeNull();
		expect(res!.value).toBe('blob:mock-1');
		expect(attempt.liveKinds).toEqual(['blob-url']);
		expect(revokeObjectURL).not.toHaveBeenCalled();

		attempt.releaseAll();
		expect(revokeObjectURL).toHaveBeenCalledTimes(1);
		expect(revokeObjectURL).toHaveBeenCalledWith('blob:mock-1');
		expect(attempt.closed).toBe(true);
		expect(attempt.liveKinds).toEqual([]);

		// AC4: double cleanup — second releaseAll is a no-op.
		attempt.releaseAll();
		expect(revokeObjectURL).toHaveBeenCalledTimes(1);
		expectLeakBalanced();
	});

	it('acquire on an already-closed attempt never creates the resource (thunk not invoked)', async () => {
		const attempt = openViewAttempt();
		attempt.releaseAll();
		const thunk = vi.fn(() => blobUrlAdapter(new Blob(['x'])));
		const res = await attempt.acquire('blob-url', thunk);
		expect(res).toBeNull();
		expect(thunk).not.toHaveBeenCalled();
		expect(createObjectURL).not.toHaveBeenCalled();
	});

	it('AC1/AC2 stale path: acquisition in flight across releaseAll resolves null and releases the fresh resource exactly once', async () => {
		const attempt = openViewAttempt();
		const gate = deferred<void>();
		const pending = attempt.acquire('native-ticket', async () => {
			await gate.promise;
			return blobUrlAdapter(new Blob(['x']));
		});

		// Teardown (unmount / retry supersession) while the acquisition is in flight.
		attempt.releaseAll();
		gate.resolve();

		const res = await pending;
		expect(res).toBeNull();
		expect(revokeObjectURL).toHaveBeenCalledTimes(1); // late completion has an owner: the attempt
		expect(attempt.liveKinds).toEqual([]);
		expectLeakBalanced();
	});

	it('created-in-the-gap: releaseAll landing between thunk execution and registration still releases exactly once', async () => {
		const attempt = openViewAttempt();
		const pending = attempt.acquire('blob-url', () => blobUrlAdapter(new Blob(['x'])));
		// The sync thunk created the URL; the acquire continuation resumes on a
		// microtask — close the attempt inside that window.
		attempt.releaseAll();
		expect(await pending).toBeNull();
		expectLeakBalanced();
	});

	// ── AR-02 HOLD r2 scheduling regression: the acquisition-to-render handoff ──
	// `acquire()` rechecks `closed` at registration, but cleanup can land between
	// that resolution and the caller's state write. acquireAndCommit rechecks
	// immediately before the commit; these tests pin that window deterministically
	// via promise-reaction FIFO order (no tick counting).

	it('AC2 caller handoff: cleanup landing between acquire() resolution and the commit never commits', async () => {
		const attempt = openViewAttempt();
		const writes: string[] = [];
		// The thunk resolves through its own promise. acquire()'s await registers
		// on it first (inside acquireAndCommit); registering releaseAll on the
		// SAME promise afterwards queues the cleanup strictly between the
		// attempt's registration resume and the helper's commit resume — the
		// exact caller-gap window Astra's probe reproduced, without races.
		let thunkPromise!: Promise<AcquiredResource<string>>;
		const caller = acquireAndCommit(
			attempt,
			'blob-url',
			() => (thunkPromise = Promise.resolve(blobUrlAdapter(new Blob(['x'])))),
			(value) => writes.push(value),
		);
		thunkPromise.then(() => attempt.releaseAll());
		await caller;
		expect(writes).toEqual([]); // the stale value never reaches caller state
		expect(attempt.closed).toBe(true);
		expect(attempt.liveKinds).toEqual([]);
		expect(revokeObjectURL).toHaveBeenCalledTimes(1); // fresh resource still released exactly once
		expectLeakBalanced();
	});

	it('AC2 caller handoff: an attempt that stays current across the acquisition commits normally', async () => {
		const attempt = openViewAttempt();
		const writes: string[] = [];
		await acquireAndCommit(attempt, 'blob-url', () => blobUrlAdapter(new Blob(['x'])), (value) => writes.push(value));
		expect(writes).toEqual(['blob:mock-1']); // positive control: live handoff commits
		attempt.releaseAll();
		expect(revokeObjectURL).toHaveBeenCalledTimes(1);
		expectLeakBalanced();
	});

	it('an acquire thunk rejection propagates, registers nothing, and leaves releaseAll sound', async () => {
		const attempt = openViewAttempt();
		await expect(attempt.acquire('blob-url', () => Promise.reject(new Error('grant: chunk missing')))).rejects.toThrow(
			'grant: chunk missing',
		);
		expect(attempt.liveKinds).toEqual([]);
		// A healthy acquisition afterwards still works on the live attempt.
		const res = await attempt.acquire('blob-url', () => blobUrlAdapter(new Blob(['x'])));
		expect(res).not.toBeNull();
		attempt.releaseAll();
		expect(revokeObjectURL).toHaveBeenCalledTimes(1);
		expectLeakBalanced();
	});

	it('tracks liveKinds across mixed acquisitions for leak triage', async () => {
		const attempt = openViewAttempt();
		await attempt.acquire('blob-url', () => blobUrlAdapter(new Blob(['x'])));
		await attempt.acquire('text', () => valueResource('plain'));
		await attempt.acquire('sanitized-html', () => valueResource('<p>hi</p>'));
		expect(attempt.liveKinds).toEqual(['blob-url', 'text', 'sanitized-html']);
		attempt.releaseAll();
		expect(attempt.liveKinds).toEqual([]);
		expectLeakBalanced();
	});
});

describe('adapters', () => {
	it('nativeTicketAdapter: release calls serveRevoke with the granted ticket and handles its ASYNC rejection (tolerant native revoke)', async () => {
		// process-level unhandledRejection detection does not fire under vitest's
		// worker harness (verified: a bare `void Promise.reject()` is invisible to
		// process.on('unhandledRejection') here), so handler attachment is spied
		// directly: release must attach a rejection handler SYNCHRONOUSLY — the
		// old `void drive.serveRevoke(ticket)` never did.
		const rejection = Promise.reject(new Error('serve stopped'));
		const catchSpy = vi.spyOn(rejection, 'catch');
		const serveGrant = vi.fn().mockResolvedValue('/t/abc123');
		const serveRevoke = vi.fn(() => rejection);
		const drive = { serveGrant, serveRevoke } as unknown as DriveBridge;
		const manifest: DriveManifest = { contentSha256: 'x', size: 1, chunks: [] };

		const resource = await nativeTicketAdapter(drive, manifest);
		expect(serveGrant).toHaveBeenCalledWith(manifest);
		expect(resource.value).toBe('/t/abc123');
		expect(() => resource.release()).not.toThrow();
		expect(serveRevoke).toHaveBeenCalledTimes(1);
		expect(serveRevoke).toHaveBeenCalledWith('/t/abc123');
		// The rejection is handled asynchronously: a catch handler was attached
		// at release time, so `serve stopped` can never surface unhandled.
		expect(catchSpy).toHaveBeenCalledTimes(1);
		expect(catchSpy).toHaveBeenCalledWith(expect.any(Function));
		// Silence the (now handled) rejection for the leak-balance audit trail.
		rejection.catch(() => {});
	});

	it('nativeTicketAdapter: grant rejection propagates to the attempt error path with nothing to release', async () => {
		const serveGrant = vi.fn().mockRejectedValue(new Error('chunk missing'));
		const drive = { serveGrant, serveRevoke: vi.fn() } as unknown as DriveBridge;
		await expect(nativeTicketAdapter(drive, { contentSha256: 'x', size: 1, chunks: [] })).rejects.toThrow('chunk missing');
		expect(drive.serveRevoke).not.toHaveBeenCalled();
	});

	it('valueResource release is a no-op (non-resources flow through acquire for a uniform stale check)', () => {
		const resource: AcquiredResource<string> = valueResource('text');
		expect(() => {
			resource.release();
			resource.release();
		}).not.toThrow();
	});
});

// §6.3 deletion-test guard: the acquisition recipes must be GONE from the
// drive components — createObjectURL/serveGrant appear only in this module
// (and its tests). Open/close forwarding alone adds no depth.
describe('static consumer guard', () => {
	const componentDir = fileURLToPath(new URL('../components/drive/', import.meta.url));

	it('drive components contain no createObjectURL/serveGrant acquisition recipes', () => {
		for (const file of ['CompareView.svelte', 'SecureViewer.svelte']) {
			const source = readFileSync(componentDir + file, 'utf8');
			expect(source, `${file} must not create object URLs directly`).not.toMatch(/createObjectURL/);
			expect(source, `${file} must not grant native serve tickets directly`).not.toMatch(/serveGrant/);
			expect(source, `${file} must not revoke object URLs directly`).not.toMatch(/revokeObjectURL/);
		}
	});
});
