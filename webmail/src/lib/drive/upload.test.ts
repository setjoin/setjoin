import { beforeEach, describe, expect, it, vi } from 'vitest';
import { bytesToHex } from '@noble/hashes/utils.js';
import { EMPTY_SHA256, splitManifest, uploadFile } from './upload';

const apiMocks = vi.hoisted(() => ({
	headChunk: vi.fn(),
	putChunk: vi.fn(),
	putVersion: vi.fn(),
}));

vi.mock('./api', () => apiMocks);

// Deterministic 9 MiB buffer (not all-zero — a constant buffer could hide an
// off-by-one in the chunk-splitting math via hash collisions on repeated
// chunks, since chunk 1 and 2 would hash identically either way here, but the
// byte pattern still exercises the real slice/update path end to end).
// ponytail: pin the concrete `Uint8Array<ArrayBuffer>` — the bare `Uint8Array`
// alias defaults to `ArrayBufferLike`, which neither crypto.subtle nor Blob's
// BlobPart accept (mirrors upload.ts's own note on this).
function makeBuffer(size: number): Uint8Array<ArrayBuffer> {
	const buf = new Uint8Array(size);
	for (let i = 0; i < size; i++) buf[i] = i % 256;
	return buf;
}

async function oneShotSha256(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
	// Pass the view itself, not bytes.buffer — a subarray's .buffer is the
	// FULL backing store, not the sliced range (would silently hash the
	// wrong bytes for the second/third chunk assertions below).
	const digest = await crypto.subtle.digest('SHA-256', bytes);
	return bytesToHex(new Uint8Array(digest));
}

describe('splitManifest', () => {
	it('splits a 9 MiB file into 3 chunks: two full 4 MiB + a 1 MiB remainder', async () => {
		const size = 9 * 1024 * 1024;
		const bytes = makeBuffer(size);
		const manifest = await splitManifest(new Blob([bytes]));
		expect(manifest.size).toBe(size);
		expect(manifest.chunks.map((c) => c.size)).toEqual([4194304, 4194304, 1048576]);
	});

	it('per-chunk sha256 matches a direct one-shot hash of the same bytes', async () => {
		const size = 9 * 1024 * 1024;
		const bytes = makeBuffer(size);
		const manifest = await splitManifest(new Blob([bytes]));
		let off = 0;
		for (const chunk of manifest.chunks) {
			const slice = bytes.subarray(off, off + chunk.size);
			expect(chunk.sha256).toBe(await oneShotSha256(slice));
			off += chunk.size;
		}
	});

	it('whole-file incremental sha256 equals the one-shot hash of the full buffer', async () => {
		const size = 9 * 1024 * 1024;
		const bytes = makeBuffer(size);
		const manifest = await splitManifest(new Blob([bytes]));
		expect(manifest.contentSha256).toBe(await oneShotSha256(bytes));
	});

	it('a 0-byte file produces an empty manifest and the empty-string sha256', async () => {
		const manifest = await splitManifest(new Blob([]));
		expect(manifest.size).toBe(0);
		expect(manifest.chunks).toEqual([]);
		expect(manifest.contentSha256).toBe(EMPTY_SHA256);
	});

	it('onProgress reports cumulative bytes after each chunk', async () => {
		const size = 9 * 1024 * 1024;
		const bytes = makeBuffer(size);
		const seen: number[] = [];
		await splitManifest(new Blob([bytes]), (done) => seen.push(done));
		expect(seen).toEqual([4194304, 8388608, 9437184]);
	});
});

describe('uploadFile', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		apiMocks.headChunk.mockResolvedValue(false);
		apiMocks.putChunk.mockResolvedValue(undefined);
		apiMocks.putVersion.mockResolvedValue({
			versionId: 9,
			conflict: false,
			branchId: null,
			headVersionId: 9,
			wormPending: false,
		});
	});

	it('forwards each chunk size in the reducer manifest', async () => {
		const bytes = new Uint8Array([1, 2, 3, 4]);
		await uploadFile(7, 11, new Blob([bytes]), { baseVersionId: null, contentType: 'image/png' });

		expect(apiMocks.putVersion).toHaveBeenCalledOnce();
		expect(apiMocks.putVersion.mock.calls[0][1]).toMatchObject({
			size: 4,
			manifest: [{ size: 4 }],
		});
	});
});
