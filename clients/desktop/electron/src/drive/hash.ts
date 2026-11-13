// hash.ts — stream a file into the spec §3.1 manifest: fixed 4 MiB chunks,
// per-chunk SHA-256 + whole-file SHA-256, one pass, one chunk buffered at a
// time (a 6 GiB file must not allocate 6 GiB — acceptance §12-2 scale).
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { open } from 'node:fs/promises';
import { CHUNK_SIZE, SHA256_EMPTY, type ChunkRef, type Manifest } from '../../../../../mailserver/webmail/src/lib/drive/sync/types.js';

export async function hashFile(absPath: string): Promise<Manifest> {
	const whole = createHash('sha256');
	const chunks: ChunkRef[] = [];
	let chunk = createHash('sha256');
	let inChunk = 0;
	let size = 0;

	for await (const buf of createReadStream(absPath, { highWaterMark: CHUNK_SIZE })) {
		let b = buf as Buffer;
		while (b.length > 0) {
			const take = Math.min(CHUNK_SIZE - inChunk, b.length);
			const piece = b.subarray(0, take);
			whole.update(piece);
			chunk.update(piece);
			inChunk += take;
			size += take;
			b = b.subarray(take);
			if (inChunk === CHUNK_SIZE) {
				chunks.push({ sha256: chunk.digest('hex'), size: inChunk });
				chunk = createHash('sha256');
				inChunk = 0;
			}
		}
	}
	if (inChunk > 0) chunks.push({ sha256: chunk.digest('hex'), size: inChunk });

	return { contentSha256: size === 0 ? SHA256_EMPTY : whole.digest('hex'), size, chunks };
}

/** Read one 4 MiB chunk by ordinal (upload leg: pushMissingChunks). */
export async function readChunk(absPath: string, ordinal: number, size: number): Promise<Uint8Array> {
	const fh = await open(absPath, 'r');
	try {
		const buf = Buffer.alloc(size);
		await fh.read(buf, 0, size, ordinal * CHUNK_SIZE);
		return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
	} finally {
		await fh.close();
	}
}
