// Drive P1 chunked-upload pipeline (spec §3.3, Locked resolution R6).
//
// Per-chunk hashing uses one-shot WebCrypto (crypto.subtle.digest) — each
// chunk is already buffered (≤4 MiB) to be uploaded, so there's no streaming
// need there. The WHOLE-FILE content hash cannot use crypto.subtle.digest
// (one-shot only — a 6 GiB file can never be buffered in memory, spec §12-2),
// so it's computed incrementally via @noble/hashes' sha256.create() as each
// chunk is read. Never hand-roll crypto (R6).
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { headChunk, putChunk, putVersion, type PutVersionResult } from './api';

const CHUNK_SIZE = 4 * 1024 * 1024;

/** SHA-256 of the empty string — the manifest/contentSha256 for a 0-byte file. */
export const EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

/** Thrown by splitManifest/uploadFile when the caller's AbortSignal fires
 *  mid-upload (chat A2 Task 7 — composer attachment cancel). Distinct from a
 *  network DriveError so callers can special-case "user cancelled" vs. "the
 *  upload actually failed". */
export class UploadAbortedError extends Error {
	constructor() {
		super('upload aborted');
		this.name = 'UploadAbortedError';
	}
}

// ponytail: coarse-grained cancel — checked BETWEEN chunk reads/uploads, not
// threaded into the underlying fetch/digest calls themselves (headChunk/
// putChunk/crypto.subtle take no signal param). An in-flight chunk finishes;
// the NEXT one never starts. Good enough for a composer attach/remove click;
// upgrade to real in-flight abort if a multi-GiB chat attachment ever needs it.
function checkAborted(signal?: AbortSignal | null): void {
	if (signal?.aborted) throw new UploadAbortedError();
}

export interface ChunkRef {
	sha256: string;
	size: number;
}

export interface Manifest {
	contentSha256: string;
	size: number;
	chunks: ChunkRef[];
}

// ponytail: TS's bare `Uint8Array` alias defaults its ArrayBuffer type param
// to `ArrayBufferLike` (includes SharedArrayBuffer), which crypto.subtle /
// fetch's BodyInit both reject — every DOM-boundary Uint8Array here is
// pinned to the concrete `Uint8Array<ArrayBuffer>` instead of sprinkling
// casts at each call site.
async function hashChunk(buf: Uint8Array<ArrayBuffer>): Promise<string> {
	// Pass the view itself, not buf.buffer — a subarray's .buffer is its
	// backing store's FULL byte range, not the view's (irrelevant here since
	// splitManifest's buffers always start at a fresh Blob.slice().arrayBuffer(),
	// but the direct-view form is correct in general and is what the test's
	// verification helper needs when hashing a subarray).
	const digest = await crypto.subtle.digest('SHA-256', buf);
	return bytesToHex(new Uint8Array(digest));
}

/**
 * Split a file into ≤4 MiB chunks, hashing each one AND the whole file
 * incrementally — never buffers more than one chunk at a time (§12-2: a
 * 6 GiB upload must work). onProgress reports cumulative bytes hashed.
 */
export async function splitManifest(
	file: Blob,
	onProgress?: (done: number) => void,
	signal?: AbortSignal | null,
): Promise<Manifest> {
	if (file.size === 0) {
		return { contentSha256: EMPTY_SHA256, size: 0, chunks: [] };
	}
	checkAborted(signal);
	const whole = sha256.create();
	const chunks: ChunkRef[] = [];
	for (let off = 0; off < file.size; off += CHUNK_SIZE) {
		checkAborted(signal);
		const end = Math.min(off + CHUNK_SIZE, file.size);
		const buf: Uint8Array<ArrayBuffer> = new Uint8Array(await file.slice(off, end).arrayBuffer());
		whole.update(buf);
		chunks.push({ sha256: await hashChunk(buf), size: buf.length });
		onProgress?.(end);
	}
	return { contentSha256: bytesToHex(whole.digest()), size: file.size, chunks };
}

export interface UploadOptions {
	baseVersionId: number | null;
	contentType?: string | null;
	note?: string;
	deviceLabel?: string;
	/** Save-as-branch (P4 Task 14): land this save on a branch ref instead of main. */
	branchId?: number | null;
	onProgress?: (sent: number, total: number) => void;
	/** Chat A2 Task 7 (composer cancel) — checked between chunks; see
	 *  UploadAbortedError's ponytail note above for the granularity. */
	signal?: AbortSignal | null;
}

/**
 * Upload a file's content, then register the version. Per-chunk idempotent:
 * HEAD (I-4 anti-oracle proof-of-possession probe) → already-present ⇒ skip
 * the PUT. Retry-safe resume = re-run from the manifest (already-uploaded
 * chunks HEAD 200 and are skipped). DriveError propagates untouched — the
 * caller maps `.code` (BZ*) to a `drive.errors.*` i18n message.
 */
export async function uploadFile(spaceId: number, nodeId: number, file: Blob, opts: UploadOptions): Promise<PutVersionResult> {
	const manifest = await splitManifest(file, (done) => opts.onProgress?.(done, file.size), opts.signal);
	let off = 0;
	for (const chunk of manifest.chunks) {
		checkAborted(opts.signal);
		const end = off + chunk.size;
		const already = await headChunk(spaceId, chunk.sha256);
		if (!already) {
			const bytes: Uint8Array<ArrayBuffer> = new Uint8Array(await file.slice(off, end).arrayBuffer());
			await putChunk(spaceId, chunk.sha256, bytes);
		}
		opts.onProgress?.(end, file.size);
		off = end;
	}
	checkAborted(opts.signal);
	return putVersion(nodeId, {
		contentSha256: manifest.contentSha256,
		size: manifest.size,
		contentType: opts.contentType,
		baseVersionId: opts.baseVersionId,
		// The reducer validates both the whole-file size and every chunk size.
		// Keep the API payload lossless: dropping `size` makes every non-empty
		// browser upload fail with BZ141 / HTTP 422 even after its chunk PUTs
		// succeeded.
		manifest: manifest.chunks.map((c) => ({ sha256: c.sha256, size: c.size })),
		note: opts.note,
		deviceLabel: opts.deviceLabel,
		branchId: opts.branchId,
	});
}
