import { mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import * as path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { CHUNK_SIZE, SHA256_EMPTY, type MirrorContentStore, type NodeMeta } from '../../../../../mailserver/webmail/src/lib/drive/sync/types.js';
import { applySchema, SqlMirrorIndex } from '../../../../../mailserver/webmail/src/lib/drive/sync/schema.js';
import { memDb } from '../../../../../mailserver/webmail/src/lib/drive/sync/schema.test.js';
import { hashFile } from './hash.js';
import { FolderMirror, type MirrorHttp } from './mirror.js';

const SPACE = 1;

// Rule 10 (compile-time conformance): FolderMirror satisfies MirrorContentStore
// as-is — this line fails `tsc` (not vitest) if the shapes ever drift.
function _typeConformance(m: FolderMirror): MirrorContentStore {
	return m;
}
void _typeConformance;

function fakeHttp(overrides: Partial<MirrorHttp> = {}): MirrorHttp {
	return {
		headChunk: async () => false,
		pushChunk: async () => {},
		contentRange: async () => new Uint8Array(),
		...overrides,
	};
}

async function seedNode(index: SqlMirrorIndex, meta: Partial<NodeMeta> & { nodeId: number }): Promise<void> {
	await index.upsertNode({
		spaceId: SPACE,
		parentId: null,
		kind: 'file',
		name: 'x',
		deletedAt: null,
		headVersionId: null,
		contentSha256: null,
		sizeBytes: null,
		contentType: null,
		...meta,
	});
}

describe('FolderMirror', () => {
	let dir: string;
	let index: SqlMirrorIndex;

	beforeEach(async () => {
		dir = await mkdtemp(path.join(tmpdir(), 'drive-mirror-'));
		const db = memDb();
		await applySchema(db);
		index = new SqlMirrorIndex(db);
	});
	afterEach(async () => {
		await rm(dir, { recursive: true, force: true });
	});

	it('putLocal is crash-safe: a throw mid-download leaves no visible file; re-run completes', async () => {
		await seedNode(index, { nodeId: 1, name: 'a.txt' });
		const content = Buffer.alloc(CHUNK_SIZE + 100, 5);
		const whole = await (async () => {
			const tmp = path.join(dir, '__oracle.bin');
			await writeFile(tmp, content);
			const m = await hashFile(tmp);
			await rm(tmp);
			return m;
		})();

		let calls = 0;
		const http = fakeHttp({
			contentRange: async (_v, start, endIncl) => {
				calls++;
				if (calls === 2) throw new Error('simulated crash');
				return content.subarray(start, endIncl + 1);
			},
		});
		const mirror = new FolderMirror({ root: dir, spaceId: SPACE, http, index });

		await expect(
			mirror.putLocal(1, { contentSha256: whole.contentSha256, size: whole.size, headVersionId: 42 })
		).rejects.toThrow();
		await expect(readFile(path.join(dir, 'a.txt'))).rejects.toThrow(); // never visible half-written

		// re-run: contentRange no longer throws (calls already passed the trap) -- resumes from the temp file's size
		await mirror.putLocal(1, { contentSha256: whole.contentSha256, size: whole.size, headVersionId: 42 });
		const written = await readFile(path.join(dir, 'a.txt'));
		expect(written.equals(content)).toBe(true);
	});

	it('rename-over-locked retries then succeeds; exhausting attempts records a locked-file issue and cleans the temp file', async () => {
		await seedNode(index, { nodeId: 1, name: 'small.txt' });
		const data = Buffer.from('hello');
		const m = await (async () => {
			const tmp = path.join(dir, '__oracle2.bin');
			await writeFile(tmp, data);
			const manifest = await hashFile(tmp);
			await rm(tmp);
			return manifest;
		})();
		const http = fakeHttp({ contentRange: async () => data });

		let renameCalls = 0;
		const flakyRename = async (a: string, b: string) => {
			renameCalls++;
			if (renameCalls < 3) throw new Error('EBUSY');
			await import('node:fs/promises').then((fsp) => fsp.rename(a, b));
		};
		const mirror = new FolderMirror({
			root: dir,
			spaceId: SPACE,
			http,
			index,
			renameFn: flakyRename,
			renameRetryMs: 1,
		});
		await mirror.putLocal(1, { contentSha256: m.contentSha256, size: m.size, headVersionId: 7 });
		expect(renameCalls).toBe(3);
		const written = await readFile(path.join(dir, 'small.txt'));
		expect(written.equals(data)).toBe(true);

		// now force exhaustion
		await seedNode(index, { nodeId: 2, name: 'other.txt' });
		const alwaysFails = async () => {
			throw new Error('EBUSY forever');
		};
		const mirror2 = new FolderMirror({
			root: dir,
			spaceId: SPACE,
			http,
			index,
			renameFn: alwaysFails,
			renameMaxAttempts: 2,
			renameRetryMs: 1,
		});
		await mirror2.putLocal(2, { contentSha256: m.contentSha256, size: m.size, headVersionId: 8 });
		const issues = await index.issues(SPACE);
		expect(issues.some((i) => i.code === 'locked-file')).toBe(true);
		await expect(readFile(path.join(dir, 'other.txt'))).rejects.toThrow();
	});

	it('scanLocal skips a re-hash when (size, mtime) match the index; re-hashes on mismatch and only queues an upsert on real content change', async () => {
		await seedNode(index, { nodeId: 1, name: 'note.txt' });
		const p = path.join(dir, 'note.txt');
		await writeFile(p, 'v1');
		const manifest = await hashFile(p);
		const st = await (await import('node:fs/promises')).stat(p);
		await index.upsertMirror({
			nodeId: 1,
			spaceId: SPACE,
			relPath: 'note.txt',
			diskSha256: manifest.contentSha256,
			diskSize: manifest.size,
			diskMtimeMs: st.mtimeMs,
			baseVersionId: 1,
			materializedOfVersion: null,
		});

		const mirror = new FolderMirror({ root: dir, spaceId: SPACE, http: fakeHttp(), index });
		await mirror.scanLocal();
		expect(mirror.drainLocalChanges()).toHaveLength(0); // untouched -- skipped, no re-hash needed

		// touch mtime, keep the same content (mtime-preserving-edit-free case)
		await new Promise((r) => setTimeout(r, 5));
		const future = new Date(st.mtime.getTime() + 10_000);
		await (await import('node:fs/promises')).utimes(p, future, future);
		await mirror.scanLocal();
		expect(mirror.drainLocalChanges()).toHaveLength(0); // re-hashed, sha equal -> no change emitted

		const refreshed = await index.getMirror(1);
		expect(refreshed?.diskMtimeMs).toBe(future.getTime());

		// real content change
		await writeFile(p, 'v2-different-content');
		await new Promise((r) => setTimeout(r, 5));
		await mirror.scanLocal();
		const changes = mirror.drainLocalChanges();
		expect(changes).toEqual([{ kind: 'upsert', relPath: 'note.txt' }]);
	});

	it('verify() always re-hashes regardless of stat (the mtime-preserving-edit escape hatch)', async () => {
		await seedNode(index, { nodeId: 1, name: 'v.txt' });
		const p = path.join(dir, 'v.txt');
		await writeFile(p, 'original');
		const manifest = await hashFile(p);
		const st = await (await import('node:fs/promises')).stat(p);
		await index.upsertMirror({
			nodeId: 1,
			spaceId: SPACE,
			relPath: 'v.txt',
			diskSha256: manifest.contentSha256,
			diskSize: st.size, // same size as the edit below, same mtime -- scanLocal would skip this
			diskMtimeMs: st.mtimeMs,
			baseVersionId: 1,
			materializedOfVersion: null,
		});
		const mirror = new FolderMirror({ root: dir, spaceId: SPACE, http: fakeHttp(), index });

		// overwrite with same-length content but different bytes, then force the
		// mtime back to the original value (simulating an editor that preserves it)
		await writeFile(p, 'changed!'); // same length (8 bytes) as 'original' -- scanLocal's gate would miss this
		await (await import('node:fs/promises')).utimes(p, st.mtime, st.mtime);

		await mirror.verify();
		expect(mirror.drainLocalChanges()).toEqual([{ kind: 'upsert', relPath: 'v.txt' }]);
	});

	it('move/rename detection: delete+create with matching content pairs into one outbound move/rename, not delete+create', async () => {
		await seedNode(index, { nodeId: 1, name: 'x.bin', parentId: null });
		await mkdir(path.join(dir, 'a'));
		await mkdir(path.join(dir, 'b'));
		const data = Buffer.from('paired-content');
		await writeFile(path.join(dir, 'a', 'x.bin'), data);
		const manifest = await hashFile(path.join(dir, 'a', 'x.bin'));
		await index.upsertMirror({
			nodeId: 1,
			spaceId: SPACE,
			relPath: 'a/x.bin',
			diskSha256: manifest.contentSha256,
			diskSize: manifest.size,
			diskMtimeMs: Date.now(),
			baseVersionId: 5,
			materializedOfVersion: null,
		});
		// register the destination folder 'b' as a KNOWN node so resolveParentId succeeds
		await index.upsertNode({
			nodeId: 100,
			spaceId: SPACE,
			parentId: null,
			kind: 'folder',
			name: 'b',
			deletedAt: null,
			headVersionId: null,
			contentSha256: null,
			sizeBytes: null,
			contentType: null,
		});

		const mirror = new FolderMirror({ root: dir, spaceId: SPACE, http: fakeHttp(), index, movePairMs: 300 });
		await mirror.start();
		try {
			await rm(path.join(dir, 'a', 'x.bin'));
			await writeFile(path.join(dir, 'b', 'x.bin'), data); // same content, different dir -- a move
			await new Promise((r) => setTimeout(r, 1200)); // settle window (750ms default) + pairing check
		} finally {
			await mirror.stop();
		}

		const due = await index.due(Date.now() + 1, 100);
		const kinds = due.map((r) => r.kind);
		expect(kinds).toContain('move');
		expect(kinds).not.toContain('delete');
		const moveRow = due.find((r) => r.kind === 'move');
		if (!moveRow) throw new Error('expected paired rename to enqueue a move');
		expect((moveRow.payload as { nodeId: number; newParentId: number }).newParentId).toBe(100);
		expect(mirror.drainLocalChanges()).toHaveLength(0); // consumed by the pairing path, not a plain upsert/delete
	});

	it('pairing window expiry -> a genuine delete (no matching create arrives)', async () => {
		await seedNode(index, { nodeId: 1, name: 'gone.bin' });
		const data = Buffer.from('will-be-deleted');
		await writeFile(path.join(dir, 'gone.bin'), data);
		const manifest = await hashFile(path.join(dir, 'gone.bin'));
		await index.upsertMirror({
			nodeId: 1,
			spaceId: SPACE,
			relPath: 'gone.bin',
			diskSha256: manifest.contentSha256,
			diskSize: manifest.size,
			diskMtimeMs: Date.now(),
			baseVersionId: 3,
			materializedOfVersion: null,
		});
		const mirror = new FolderMirror({ root: dir, spaceId: SPACE, http: fakeHttp(), index, movePairMs: 100 });
		await mirror.start();
		try {
			await rm(path.join(dir, 'gone.bin'));
			await new Promise((r) => setTimeout(r, 1200)); // settle + pairing window fully expires
		} finally {
			await mirror.stop();
		}
		const changes = mirror.drainLocalChanges();
		expect(changes).toEqual([{ kind: 'delete', relPath: 'gone.bin' }]);
	});

	it('putLocal adopts silently when identical content already sits at the destination', async () => {
		await seedNode(index, { nodeId: 1, name: 'dup.txt' });
		const data = Buffer.from('same-everywhere');
		await writeFile(path.join(dir, 'dup.txt'), data);
		const manifest = await hashFile(path.join(dir, 'dup.txt'));
		const http = fakeHttp({ contentRange: async () => data });
		const mirror = new FolderMirror({ root: dir, spaceId: SPACE, http, index });

		await mirror.putLocal(1, { contentSha256: manifest.contentSha256, size: manifest.size, headVersionId: 9 });
		const issues = await index.issues(SPACE);
		expect(issues).toHaveLength(0);
		const written = await readFile(path.join(dir, 'dup.txt'));
		expect(written.equals(data)).toBe(true);
	});

	it('putLocal moves a conflicting pre-existing file aside (G4 dedupe) and records a name-collision issue', async () => {
		await seedNode(index, { nodeId: 1, name: 'dup2.txt' });
		await writeFile(path.join(dir, 'dup2.txt'), 'local-only-content');
		const remoteData = Buffer.from('remote-content-differs');
		const http = fakeHttp({ contentRange: async () => remoteData });
		const mirror = new FolderMirror({ root: dir, spaceId: SPACE, http, index });

		const remoteManifest = await (async () => {
			const tmp = path.join(dir, '__oracle3.bin');
			await writeFile(tmp, remoteData);
			const m = await hashFile(tmp);
			await rm(tmp);
			return m;
		})();
		await mirror.putLocal(1, { contentSha256: remoteManifest.contentSha256, size: remoteManifest.size, headVersionId: 11 });

		const atOriginal = await readFile(path.join(dir, 'dup2.txt'));
		expect(atOriginal.equals(remoteData)).toBe(true);
		const sibling = await readFile(path.join(dir, 'dup2 -2.txt'));
		expect(sibling.toString()).toBe('local-only-content');
		const issues = await index.issues(SPACE);
		expect(issues.some((i) => i.code === 'name-collision')).toBe(true);
	});

	it('FS-invalid names are quarantined on win32, never mangled or written', async () => {
		await seedNode(index, { nodeId: 1, name: 'a:b?.txt' });
		const http = fakeHttp({ contentRange: async () => Buffer.from('x') });
		const mirror = new FolderMirror({ root: dir, spaceId: SPACE, http, index, platform: 'win32' });
		await mirror.putLocal(1, { contentSha256: SHA256_EMPTY, size: 0, headVersionId: 1 });
		await expect(readFile(path.join(dir, 'a:b?.txt'))).rejects.toThrow();
		const issues = await index.issues(SPACE);
		expect(issues.some((i) => i.code === 'invalid-name')).toBe(true);
	});

	it('exclusion/remote-delete safety: remove() keeps a dirty file and records unsynced-local-edit instead of deleting', async () => {
		await seedNode(index, { nodeId: 1, name: 'keep.txt' });
		await writeFile(path.join(dir, 'keep.txt'), 'synced-content');
		const manifest = await hashFile(path.join(dir, 'keep.txt'));
		await index.upsertMirror({
			nodeId: 1,
			spaceId: SPACE,
			relPath: 'keep.txt',
			diskSha256: manifest.contentSha256,
			diskSize: manifest.size,
			diskMtimeMs: Date.now(),
			baseVersionId: 2,
			materializedOfVersion: null,
		});
		// dirty it locally without going through the sync path
		await writeFile(path.join(dir, 'keep.txt'), 'edited-since-last-sync');
		const mirror = new FolderMirror({ root: dir, spaceId: SPACE, http: fakeHttp(), index });
		await mirror.remove(1);
		const stillThere = await readFile(path.join(dir, 'keep.txt'));
		expect(stillThere.toString()).toBe('edited-since-last-sync');
		const issues = await index.issues(SPACE);
		expect(issues.some((i) => i.code === 'unsynced-local-edit')).toBe(true);
	});

	it('remove() deletes a clean (unedited) file with no issue', async () => {
		await seedNode(index, { nodeId: 1, name: 'clean.txt' });
		await writeFile(path.join(dir, 'clean.txt'), 'synced');
		const manifest = await hashFile(path.join(dir, 'clean.txt'));
		await index.upsertMirror({
			nodeId: 1,
			spaceId: SPACE,
			relPath: 'clean.txt',
			diskSha256: manifest.contentSha256,
			diskSize: manifest.size,
			diskMtimeMs: Date.now(),
			baseVersionId: 2,
			materializedOfVersion: null,
		});
		const mirror = new FolderMirror({ root: dir, spaceId: SPACE, http: fakeHttp(), index });
		await mirror.remove(1);
		await expect(readFile(path.join(dir, 'clean.txt'))).rejects.toThrow();
	});

	it('ACL revoke purges clean bytes but moves dirty/pending bytes into the watcher-ignored quarantine', async () => {
		for (const [nodeId, relPath, content] of [[1, 'clean-revoke.txt', 'clean'], [2, 'dirty-revoke.txt', 'before']] as const) {
			await seedNode(index, { nodeId, name: relPath });
			await writeFile(path.join(dir, relPath), content);
			const m = await hashFile(path.join(dir, relPath));
			await index.upsertMirror({
				nodeId, spaceId: SPACE, relPath, diskSha256: m.contentSha256, diskSize: m.size,
				diskMtimeMs: Date.now(), baseVersionId: 2, materializedOfVersion: null,
			});
		}
		await writeFile(path.join(dir, 'dirty-revoke.txt'), 'unsynced local edit');
		const mirror = new FolderMirror({ root: dir, spaceId: SPACE, http: fakeHttp(), index, now: () => 99 });

		await expect(mirror.revoke(1, false)).resolves.toBe('purged');
		await expect(readFile(path.join(dir, 'clean-revoke.txt'))).rejects.toThrow();
		await expect(mirror.revoke(2, true)).resolves.toBe('quarantined');
		await expect(readFile(path.join(dir, 'dirty-revoke.txt'))).rejects.toThrow();
		const quarantined = await readdir(path.join(dir, '.setjoin-quarantine'));
		expect(quarantined).toHaveLength(1);
		expect((await readFile(path.join(dir, '.setjoin-quarantine', quarantined[0]))).toString()).toBe('unsynced local edit');
	});

	it('ACL revoke reports a deterministic busy outcome and leaves the cursor-retryable file in place', async () => {
		await seedNode(index, { nodeId: 1, name: 'busy.txt' });
		await writeFile(path.join(dir, 'busy.txt'), 'synced');
		const m = await hashFile(path.join(dir, 'busy.txt'));
		await index.upsertMirror({
			nodeId: 1, spaceId: SPACE, relPath: 'busy.txt', diskSha256: m.contentSha256,
			diskSize: m.size, diskMtimeMs: Date.now(), baseVersionId: 2, materializedOfVersion: null,
		});
		const busy = Object.assign(new Error('file is open'), { code: 'EBUSY' });
		const mirror = new FolderMirror({
			root: dir, spaceId: SPACE, http: fakeHttp(), index,
			removeFn: async () => { throw busy; },
		});

		await expect(mirror.revoke(1, false)).resolves.toBe('busy');
		expect((await readFile(path.join(dir, 'busy.txt'))).toString()).toBe('synced');
		expect((await index.issues(SPACE)).some((issue) => issue.code === 'revocation-busy')).toBe(true);
	});

	it('rejects slash and Windows-backslash traversal at every revoke path sink', async () => {
		const sentinel = path.join(path.dirname(dir), `${path.basename(dir)}-sentinel.txt`);
		await writeFile(sentinel, 'must survive');
		try {
			const mirror = new FolderMirror({ root: dir, spaceId: SPACE, http: fakeHttp(), index, platform: 'win32' });
			await expect(mirror.revokePath(`../${path.basename(sentinel)}`, false)).rejects.toThrow('unsafe Drive mirror path');
			await expect(mirror.revokePath(`..\\${path.basename(sentinel)}`, false)).rejects.toThrow('unsafe Drive mirror path');

			await seedNode(index, { nodeId: 77, name: `..\\${path.basename(sentinel)}` });
			await index.upsertMirror({
				nodeId: 77, spaceId: SPACE, relPath: `..\\${path.basename(sentinel)}`,
				diskSha256: '0'.repeat(64), diskSize: 12, diskMtimeMs: Date.now(),
				baseVersionId: 1, materializedOfVersion: null,
			});
			await expect(mirror.revoke(77, false)).rejects.toThrow('unsafe Drive mirror path');
			expect((await readFile(sentinel)).toString()).toBe('must survive');
		} finally {
			await rm(sentinel, { force: true });
		}
	});

	it('P4 Task 17: readManifestAtPath/pushMissingChunksAtPath/removeAtPath are the relPath-keyed branch-sibling verbs', async () => {
		const siblingRel = 'Report (branch budget-redo).xlsx';
		await writeFile(path.join(dir, siblingRel), 'branch content');
		const pushed: { sha256: string; bytes: Uint8Array }[] = [];
		const mirror = new FolderMirror({
			root: dir,
			spaceId: SPACE,
			http: fakeHttp({ pushChunk: async (_space, sha256, bytes) => void pushed.push({ sha256, bytes }) }),
			index,
		});

		// readManifestAtPath hashes whatever is on disk at the exact relPath --
		// no nodeId/dc_mirror resolution (a branch sibling has no node_id of
		// its own).
		const manifest = await mirror.readManifestAtPath(siblingRel);
		expect(manifest?.contentSha256).toBeTruthy();
		expect(await mirror.readManifestAtPath('nope.xlsx')).toBeNull();

		await mirror.pushMissingChunksAtPath(siblingRel, manifest!.chunks);
		expect(pushed).toHaveLength(manifest!.chunks.length);

		await mirror.removeAtPath(siblingRel);
		await expect(readFile(path.join(dir, siblingRel))).rejects.toThrow();
		// Unconditional -- removing an already-gone path never throws.
		await expect(mirror.removeAtPath(siblingRel)).resolves.toBeUndefined();
	});

	it('spec ContentStore conformance: FolderMirror satisfies MirrorContentStore at compile time', async () => {
		const mirror = new FolderMirror({ root: dir, spaceId: SPACE, http: fakeHttp(), index });
		await expect(mirror.fetchChunk({ sha256: 'x', size: 1 }, 'http://x', 'tok')).rejects.toThrow();
		await expect(mirror.pushChunk({ sha256: 'x', size: 1 }, 'http://x', 'tok')).rejects.toThrow();
		expect(await mirror.hasChunk('deadbeef')).toBe(false);
	});

	// ── symlink confinement (ER5 occ_c0c3c6448af08564b1002cd7) ─────────────
	// A parent-directory symlink planted INSIDE the mirror root must not steer
	// mirror writes outside the root. absPath's lexical checks cannot see it;
	// the realpath confinement must refuse before any byte is written.

	describe('parent-directory symlink confinement', () => {
		let outside: string;
		let data: Buffer;
		let manifest: Awaited<ReturnType<typeof hashFile>>;

		beforeEach(async () => {
			outside = await mkdtemp(path.join(tmpdir(), 'drive-mirror-out-'));
			data = Buffer.from('exfiltration target');
			const oracle = path.join(outside, '__oracle.bin');
			await writeFile(oracle, data);
			manifest = await hashFile(oracle);
			await rm(oracle);
		});
		afterEach(async () => {
			await rm(outside, { recursive: true, force: true });
		});

		async function plantEscapeLink(name = 'link'): Promise<void> {
			await symlink(outside, path.join(dir, name), 'dir');
		}

		it('refuses a download whose parent is a symlink out of the root and writes nothing outside', async () => {
			await plantEscapeLink();
			const http = fakeHttp({ contentRange: async (_v, start, endIncl) => data.subarray(start, endIncl + 1) });
			const mirror = new FolderMirror({ root: dir, spaceId: SPACE, http, index });

			await expect(
				mirror.materializeVersion(9, 'link/evil.txt', manifest.contentSha256, manifest.size)
			).rejects.toThrow(/escapes the root through a parent symlink/);

			// Nothing landed outside the root — neither the payload nor the
			// download temp file, and the escape directory was never created.
			await expect(readFile(path.join(outside, 'evil.txt'))).rejects.toThrow();
			expect(readdirSync(outside)).toEqual([]);
			expect(existsSync(path.join(dir, 'link', 'evil.txt'))).toBe(false);
		});

		it('refuses a deep NEW path under a symlinked parent before creating any directory outside', async () => {
			await plantEscapeLink();
			const http = fakeHttp({ contentRange: async (_v, start, endIncl) => data.subarray(start, endIncl + 1) });
			const mirror = new FolderMirror({ root: dir, spaceId: SPACE, http, index });

			await expect(
				mirror.materializeVersion(9, 'link/newdir/f.bin', manifest.contentSha256, manifest.size)
			).rejects.toThrow(/escapes the root through a parent symlink/);
			expect(existsSync(path.join(outside, 'newdir'))).toBe(false);
		});

		it('refuses a symlinked MIDDLE component escaping the root', async () => {
			await mkdir(path.join(dir, 'keep'));
			await symlink(outside, path.join(dir, 'keep', 'out'), 'dir');
			const http = fakeHttp({ contentRange: async (_v, start, endIncl) => data.subarray(start, endIncl + 1) });
			const mirror = new FolderMirror({ root: dir, spaceId: SPACE, http, index });

			await expect(
				mirror.materializeVersion(9, 'keep/out/x.txt', manifest.contentSha256, manifest.size)
			).rejects.toThrow(/escapes the root through a parent symlink/);
			await expect(readFile(path.join(outside, 'x.txt'))).rejects.toThrow();
		});

		it('a symlink pointing INSIDE the root still materializes into its real target', async () => {
			// Confinement refuses ESCAPES, not symlinked layouts per se: an
			// in-root alias directory is a legal local arrangement (and macOS
			// /tmp → /private/tmp ancestor layouts must keep working — the
			// existing suites already run through one).
			await mkdir(path.join(dir, 'sub'));
			await symlink(path.join(dir, 'sub'), path.join(dir, 'alias'), 'dir');
			const http = fakeHttp({ contentRange: async (_v, start, endIncl) => data.subarray(start, endIncl + 1) });
			const mirror = new FolderMirror({ root: dir, spaceId: SPACE, http, index });

			await mirror.materializeVersion(9, 'alias/ok.txt', manifest.contentSha256, manifest.size);
			const written = await readFile(path.join(dir, 'sub', 'ok.txt'));
			expect(written.equals(data)).toBe(true);
		});

		it('removing a symlinked entry unlinks the link, never the target file', async () => {
			// The final path component is deliberately NOT symlink-resolved:
			// revocation must remove the in-root link, not follow it to the
			// outside file it points at.
			const target = path.join(outside, 'precious.txt');
			await writeFile(target, data);
			await symlink(target, path.join(dir, 'entry'));
			const m = await hashFile(target);
			const st = await stat(target);
			await index.upsertMirror({
				nodeId: 7,
				spaceId: SPACE,
				relPath: 'entry',
				diskSha256: m.contentSha256,
				diskSize: m.size,
				diskMtimeMs: st.mtimeMs,
				baseVersionId: null,
				materializedOfVersion: null,
			});
			const mirror = new FolderMirror({ root: dir, spaceId: SPACE, http: fakeHttp(), index });

			await expect(mirror.revoke(7, false)).resolves.toBe('purged');
			expect(existsSync(path.join(dir, 'entry'))).toBe(false);
			// The target survives byte-for-byte.
			expect((await readFile(target)).equals(data)).toBe(true);
		});
	});
});
