import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import * as path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { CHUNK_SIZE, SHA256_EMPTY } from '../../../../../mailserver/webmail/src/lib/drive/sync/types.js';
import { hashFile, readChunk } from './hash.js';

describe('hashFile', () => {
	let dir: string;
	beforeEach(async () => {
		dir = await mkdtemp(path.join(tmpdir(), 'drive-hash-'));
	});
	afterEach(async () => {
		await rm(dir, { recursive: true, force: true });
	});

	it('empty file -> SHA256_EMPTY, size 0, no chunks', async () => {
		const p = path.join(dir, 'empty.bin');
		await writeFile(p, Buffer.alloc(0));
		const m = await hashFile(p);
		expect(m).toEqual({ contentSha256: SHA256_EMPTY, size: 0, chunks: [] });
	});

	it('small file -> one chunk, chunk sha == whole sha', async () => {
		const p = path.join(dir, 'small.bin');
		const data = Buffer.from('hello world');
		await writeFile(p, data);
		const m = await hashFile(p);
		expect(m.size).toBe(data.length);
		expect(m.chunks).toHaveLength(1);
		expect(m.chunks[0].sha256).toBe(m.contentSha256);
		expect(m.contentSha256).toBe(createHash('sha256').update(data).digest('hex'));
	});

	it('exactly CHUNK_SIZE -> 1 chunk', async () => {
		const p = path.join(dir, 'exact.bin');
		const data = Buffer.alloc(CHUNK_SIZE, 7);
		await writeFile(p, data);
		const m = await hashFile(p);
		expect(m.chunks).toHaveLength(1);
		expect(m.chunks[0].size).toBe(CHUNK_SIZE);
	});

	it('CHUNK_SIZE + 1 byte -> 2 chunks sized [CHUNK_SIZE, 1]', async () => {
		const p = path.join(dir, 'plus1.bin');
		const data = Buffer.alloc(CHUNK_SIZE + 1, 9);
		await writeFile(p, data);
		const m = await hashFile(p);
		expect(m.chunks.map((c) => c.size)).toEqual([CHUNK_SIZE, 1]);
		expect(m.contentSha256).toBe(createHash('sha256').update(data).digest('hex'));
	});

	it('readChunk returns exactly the ordinal-th chunk bytes', async () => {
		const p = path.join(dir, 'two.bin');
		const first = Buffer.alloc(CHUNK_SIZE, 1);
		const second = Buffer.from('tail-bytes');
		await writeFile(p, Buffer.concat([first, second]));
		const chunk1 = await readChunk(p, 1, second.length);
		expect(Buffer.from(chunk1).equals(second)).toBe(true);
	});
});
