import { mkdir, mkdtemp, rm, rename, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import * as path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { LocalChange } from '../../../../../mailserver/webmail/src/lib/drive/sync/types.js';
import { MirrorWatcher } from './watcher.js';

// FS-timing suite: @parcel/watcher runs headless but event delivery + our
// settle window are both real clocks. Ceilings below are generous (5s).
const SETTLE_MS = 200;

async function waitFor(pred: () => boolean, timeoutMs = 5000): Promise<void> {
	const start = Date.now();
	while (!pred()) {
		if (Date.now() - start > timeoutMs) throw new Error('waitFor: timed out');
		await new Promise((r) => setTimeout(r, 25));
	}
}

describe('MirrorWatcher', () => {
	let dir: string;
	let changes: LocalChange[];
	let skipped: Array<{ relPath: string; reason: string }>;
	let watcher: MirrorWatcher;

	beforeEach(async () => {
		dir = await mkdtemp(path.join(tmpdir(), 'drive-watch-'));
		changes = [];
		skipped = [];
		watcher = new MirrorWatcher({
			root: dir,
			onChange: (c) => changes.push(c),
			onSkipped: (relPath, reason) => skipped.push({ relPath, reason }),
			settleMs: SETTLE_MS,
		});
		await watcher.start();
	});
	afterEach(async () => {
		await watcher.stop();
		await rm(dir, { recursive: true, force: true });
	});

	it('create -> one settled upsert', async () => {
		await writeFile(path.join(dir, 'a.txt'), 'hello');
		await waitFor(() => changes.some((c) => c.relPath === 'a.txt'));
		const hits = changes.filter((c) => c.relPath === 'a.txt');
		expect(hits).toHaveLength(1);
		expect(hits[0].kind).toBe('upsert');
	});

	it('Office atomic-save dance settles to a single upsert of the real name', async () => {
		const lock = path.join(dir, '~$doc.docx');
		const tmp = path.join(dir, 'doc.tmp');
		const real = path.join(dir, 'doc.docx');
		await writeFile(lock, 'lock');
		await writeFile(tmp, 'draft');
		await rename(tmp, real);
		await unlink(lock);
		await waitFor(() => changes.some((c) => c.relPath === 'doc.docx'));
		await new Promise((r) => setTimeout(r, SETTLE_MS * 2)); // let any trailing events land
		expect(changes.filter((c) => c.relPath === 'doc.tmp')).toHaveLength(0);
		expect(changes.filter((c) => c.relPath === '~$doc.docx')).toHaveLength(0);
		expect(changes.filter((c) => c.relPath === 'doc.docx')).toHaveLength(1);
	});

	it('rapid writes to one path within the window collapse to ONE upsert', async () => {
		const p = path.join(dir, 'b.txt');
		for (let i = 0; i < 5; i++) await writeFile(p, `v${i}`);
		await waitFor(() => changes.some((c) => c.relPath === 'b.txt'));
		await new Promise((r) => setTimeout(r, SETTLE_MS * 2));
		expect(changes.filter((c) => c.relPath === 'b.txt')).toHaveLength(1);
	});

	it('delete emits a delete change', async () => {
		const p = path.join(dir, 'c.txt');
		await writeFile(p, 'x');
		await waitFor(() => changes.some((c) => c.relPath === 'c.txt'));
		changes = [];
		await unlink(p);
		await waitFor(() => changes.some((c) => c.relPath === 'c.txt'));
		expect(changes.find((c) => c.relPath === 'c.txt')?.kind).toBe('delete');
	});

	it('our own .setjoin-tmp-* writes never surface as events', async () => {
		await writeFile(path.join(dir, '.setjoin-tmp-abc123'), 'partial download');
		await new Promise((r) => setTimeout(r, SETTLE_MS * 3));
		expect(changes).toHaveLength(0);
	});

	it('events under an excluded subdir are still emitted (exclusion is the engine\'s job)', async () => {
		await mkdir(path.join(dir, 'big'));
		await writeFile(path.join(dir, 'big', 'movie.mp4'), 'x');
		await waitFor(() => changes.some((c) => c.relPath === 'big/movie.mp4'));
		expect(changes.some((c) => c.relPath === 'big/movie.mp4')).toBe(true);
	});
});
