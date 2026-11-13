// convergence.test.ts — the two-instance convergence suite (Task 13, acceptance
// §12-11 in-proc). ONE FakeDriveServer; TWO full stacks (tmpdir root + memDb
// index + real FolderMirror + real SyncEngine each). Local edits are applied
// directly via engine.onLocalChange (bypassing the real @parcel/watcher's
// settle/move-pairing timers, which Task 8/9 already test in isolation) so
// this suite stays fast and deterministic while still exercising the real
// upload/download/conflict machinery end to end against a real (fake) server.
//
// Ponytail: covers scenarios 1 (full lifecycle), 2+3 (conflict sibling on
// both machines + repeat-conflict " -2" suffix), 5 (kill-and-restart resume),
// 6 (stale-cursor full resync), 9 (chunk-level delta dedup) from the plan's
// 9-scenario list. Skipped here because each is already a dedicated unit
// test elsewhere: 4 (Office temp dance) -> watcher.test.ts; 7 (selective
// sync exclusion) -> engine.test.ts's isExcluded case; 8 (delete-vs-edit) ->
// engine.test.ts's delete-vs-edit case + mirror.test.ts's remove() dirty
// check.
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, readdir, rm, rename, stat, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import * as path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { applySchema, SqlMirrorIndex } from '../../../../../mailserver/webmail/src/lib/drive/sync/schema.js';
import { memDb } from '../../../../../mailserver/webmail/src/lib/drive/sync/schema.test.js';
import { DriveHttp } from '../../../../../mailserver/webmail/src/lib/drive/sync/protocol.js';
import { SyncEngine } from '../../../../../mailserver/webmail/src/lib/drive/sync/engine.js';
import { FolderMirror } from './mirror.js';
import { FakeDriveServer } from './testing/fakeDriveServer.js';

const SPACE = 1;

interface Instance {
	root: string;
	index: SqlMirrorIndex;
	mirror: FolderMirror;
	engine: SyncEngine;
}

async function makeInstance(server: FakeDriveServer, deviceLabel: string, root: string): Promise<Instance> {
	const db = memDb();
	await applySchema(db);
	const index = new SqlMirrorIndex(db);
	// Indirect through the property (not `server.fetch` by value) so a test
	// that later reassigns `server.fetch` (e.g. test 9's PUT-counting spy)
	// still takes effect for instances already constructed.
	const http = new DriveHttp((input, init) => server.fetch(input, init), '');
	const mirror = new FolderMirror({ root, spaceId: SPACE, http, index });
	const engine = new SyncEngine({
		http,
		index,
		store: mirror,
		spaceId: SPACE,
		deviceLabel,
		isExcluded: () => false,
		// Matches FakeDriveServer's own clock day (Date.UTC(2026,0,1), advancing
		// only seconds per mutation) -- in reality both a device's local clock
		// and the server's recorded createdAt for the same round-trip agree on
		// the calendar day; picking an unrelated fixed date here would make the
		// two independent conflict-sibling naming paths (this device's own
		// todayYmd() vs. another device's v.createdAt from the server) diverge
		// only because of the test fixture, not because of a real bug.
		todayYmd: () => '2026-01-01',
		now: () => Date.now(),
	});
	return { root, index, mirror, engine };
}

/** Resolve a relPath's parent node id via the SAME dc_nodes walk
 *  FolderMirror/SyncEngine use internally (small, intentional duplication —
 *  each owner's copy is private; this is test-only glue). */
async function resolveParentId(index: SqlMirrorIndex, relPath: string): Promise<number | null> {
	const parts = relPath.split('/');
	parts.pop();
	let parentId: number | null = null;
	for (const seg of parts) {
		const child = await index.findChildByName(SPACE, parentId, seg);
		if (!child) throw new Error(`resolveParentId: unknown folder segment '${seg}' in ${relPath}`);
		parentId = child.nodeId;
	}
	return parentId;
}

/** Create a folder directly against the server + register it in every
 *  instance's local dc_nodes AND materialize the directory on disk — the
 *  harness's "this folder already exists on every machine" setup step. */
async function createSharedFolder(
	server: FakeDriveServer,
	instances: Instance[],
	relPath: string
): Promise<void> {
	const parts = relPath.split('/');
	let parentId: number | null = null;
	let builtPath = '';
	for (const seg of parts) {
		builtPath = builtPath ? `${builtPath}/${seg}` : seg;
		let nodeId = await findExistingFolderId(instances[0].index, builtPath);
		if (nodeId == null) {
			const http = new DriveHttp((input, init) => server.fetch(input, init), '');
			nodeId = await http.createNode(SPACE, parentId, 'folder', seg);
			for (const inst of instances) {
				await inst.index.upsertNode({
					nodeId,
					spaceId: SPACE,
					parentId,
					kind: 'folder',
					name: seg,
					deletedAt: null,
					headVersionId: null,
					contentSha256: null,
					sizeBytes: null,
					contentType: null,
				});
				await mkdir(path.join(inst.root, builtPath), { recursive: true });
			}
		}
		parentId = nodeId;
	}
}
async function findExistingFolderId(index: SqlMirrorIndex, relPath: string): Promise<number | null> {
	const parts = relPath.split('/');
	const name = parts.pop() as string;
	let parentId: number | null = null;
	for (const seg of parts) {
		const child = await index.findChildByName(SPACE, parentId, seg);
		if (!child) return null;
		parentId = child.nodeId;
	}
	const child = await index.findChildByName(SPACE, parentId, name);
	return child?.nodeId ?? null;
}

async function writeAndNotify(inst: Instance, relPath: string, content: string | Buffer): Promise<void> {
	const abs = path.join(inst.root, relPath);
	await mkdir(path.dirname(abs), { recursive: true });
	await writeFile(abs, content);
	await inst.engine.onLocalChange({ kind: 'upsert', relPath });
}

async function deleteAndNotify(inst: Instance, relPath: string): Promise<void> {
	await unlink(path.join(inst.root, relPath));
	await inst.engine.onLocalChange({ kind: 'delete', relPath });
}

/** Simulates the watcher's move/rename pairing (Task 9's FolderMirror owns
 *  the real, timer-based version) synchronously for test determinism. */
async function renameAndNotify(inst: Instance, oldRel: string, newRel: string): Promise<void> {
	const oldAbs = path.join(inst.root, oldRel);
	const newAbs = path.join(inst.root, newRel);
	await mkdir(path.dirname(newAbs), { recursive: true });
	await rename(oldAbs, newAbs);
	const mirror = await inst.index.findByPathCI(SPACE, oldRel);
	if (!mirror) throw new Error(`renameAndNotify: no mirror row for ${oldRel}`);
	const oldDir = path.dirname(oldRel);
	const newDir = path.dirname(newRel);
	const oldName = path.basename(oldRel);
	const newName = path.basename(newRel);
	if (oldDir !== newDir) {
		const newParentId = await resolveParentId(inst.index, newRel);
		await inst.index.enqueue(SPACE, 'move', { nodeId: mirror.nodeId, newParentId });
	}
	if (oldName !== newName) {
		await inst.index.enqueue(SPACE, 'rename', { nodeId: mirror.nodeId, newName });
	}
	const st = await stat(newAbs);
	await inst.index.upsertMirror({ ...mirror, relPath: newRel, diskMtimeMs: st.mtimeMs });
}

async function syncOnce(inst: Instance): Promise<void> {
	await inst.engine.syncOnce();
}

async function syncAll(instances: Instance[], rounds = 4): Promise<void> {
	for (let r = 0; r < rounds; r++) {
		for (const inst of instances) await syncOnce(inst);
	}
}

async function listFilesRec(root: string): Promise<Map<string, string>> {
	const out = new Map<string, string>();
	async function walk(dir: string, prefix: string): Promise<void> {
		let entries: import('node:fs').Dirent[];
		try {
			entries = await readdir(dir, { withFileTypes: true });
		} catch {
			return;
		}
		for (const e of entries) {
			if (e.name.startsWith('.setjoin-tmp-')) continue;
			const rel = prefix ? `${prefix}/${e.name}` : e.name;
			const abs = path.join(dir, e.name);
			if (e.isDirectory()) {
				await walk(abs, rel);
			} else {
				const bytes = await readFile(abs);
				out.set(rel.toLowerCase(), createHash('sha256').update(bytes).digest('hex'));
			}
		}
	}
	await walk(root, '');
	return out;
}

async function assertConverged(instances: Instance[]): Promise<void> {
	const snapshots = await Promise.all(instances.map((i) => listFilesRec(i.root)));
	const first = snapshots[0];
	for (let i = 1; i < snapshots.length; i++) {
		expect([...snapshots[i].entries()].sort()).toEqual([...first.entries()].sort());
	}
}

describe('two-instance convergence (fakeDriveServer)', () => {
	let server: FakeDriveServer;
	let rootA: string;
	let rootB: string;
	let a: Instance;
	let b: Instance;

	beforeEach(async () => {
		server = new FakeDriveServer();
		server.addSpace(SPACE, 'Team Space');
		rootA = await mkdtemp(path.join(tmpdir(), 'drive-conv-a-'));
		rootB = await mkdtemp(path.join(tmpdir(), 'drive-conv-b-'));
		a = await makeInstance(server, 'machine-a', rootA);
		b = await makeInstance(server, 'machine-b', rootB);
	});
	afterEach(async () => {
		await rm(rootA, { recursive: true, force: true });
		await rm(rootB, { recursive: true, force: true });
	});

	it('1: create/edit/rename/move/delete converge both ways', async () => {
		await createSharedFolder(server, [a, b], 'docs');
		await createSharedFolder(server, [a, b], 'arch');
		await writeAndNotify(a, 'old.txt', 'to be deleted');
		await syncAll([a, b]);
		await assertConverged([a, b]);

		await writeAndNotify(a, 'docs/a.txt', 'v1');
		await syncAll([a, b]);
		await assertConverged([a, b]);

		await writeAndNotify(a, 'docs/a.txt', 'v2-edited');
		await syncAll([a, b]);
		await assertConverged([a, b]);

		await renameAndNotify(a, 'docs/a.txt', 'docs/b.txt');
		await syncAll([a, b]);
		await assertConverged([a, b]);

		await renameAndNotify(a, 'docs/b.txt', 'arch/b.txt');
		await syncAll([a, b]);
		await assertConverged([a, b]);

		await deleteAndNotify(a, 'old.txt');
		await syncAll([a, b]);
		await assertConverged([a, b]);
		expect((await listFilesRec(rootB)).has('old.txt')).toBe(false);

		// B mutates; A receives.
		await writeAndNotify(b, 'arch/b.txt', 'v3-from-b');
		await syncAll([b, a]);
		await assertConverged([a, b]);
		expect((await readFile(path.join(rootA, 'arch/b.txt'))).toString()).toBe('v3-from-b');
	});

	it('2+3: concurrent edit -> conflict sibling on BOTH machines; a repeat conflict gets the " -2" suffix (G4)', async () => {
		await createSharedFolder(server, [a, b], 'x');
		await writeAndNotify(a, 'plan.md', 'base');
		await syncAll([a, b]);
		await assertConverged([a, b]);

		// Both edit from the same base, offline (engines not run in between).
		await writeAndNotify(a, 'plan.md', 'A-edit');
		await writeAndNotify(b, 'plan.md', 'B-edit');
		await syncAll([a, b], 6);

		const filesA = await listFilesRec(rootA);
		const filesB = await listFilesRec(rootB);
		const siblingRe = /^plan \(conflict machine-[ab] \d{4}-\d{2}-\d{2}\)\.md$/;
		const siblingA = [...filesA.keys()].find((f) => siblingRe.test(f));
		const siblingB = [...filesB.keys()].find((f) => siblingRe.test(f));
		expect(siblingA, `A's files: ${[...filesA.keys()]}`).toBeDefined();
		expect(siblingB, `B's files: ${[...filesB.keys()]}`).toBeDefined();

		// Exactly one head; both edits' bytes are preserved SOMEWHERE on both machines.
		const bytesOnA = new Set((await Promise.all([...filesA.keys()].map((f) => readFile(path.join(rootA, f), 'utf8')))));
		const bytesOnB = new Set((await Promise.all([...filesB.keys()].map((f) => readFile(path.join(rootB, f), 'utf8')))));
		expect(bytesOnA.has('A-edit')).toBe(true);
		expect(bytesOnA.has('B-edit')).toBe(true);
		expect(bytesOnB.has('A-edit')).toBe(true);
		expect(bytesOnB.has('B-edit')).toBe(true);
		await assertConverged([a, b]);

		// Force a second same-day conflict on the (now-converged) head.
		await writeAndNotify(a, 'plan.md', 'A-edit-2');
		await writeAndNotify(b, 'plan.md', 'B-edit-2');
		await syncAll([a, b], 6);
		const files2 = await listFilesRec(rootA);
		const dedupedRe = /^plan \(conflict machine-[ab] \d{4}-\d{2}-\d{2}\) -2\.md$/;
		expect([...files2.keys()].some((f) => dedupedRe.test(f)), `A's files: ${[...files2.keys()]}`).toBe(true);
		await assertConverged([a, b]);
	});

	it('5: kill-and-restart resumes from cursor (no from-zero refetch)', async () => {
		await writeAndNotify(a, 'r.txt', 'v1');
		await syncOnce(a); // a's cursor advances past this create
		server.changesCalls = [];
		await syncOnce(b); // b's first-ever sync: anchor + full resync (no `since` cursor yet)
		expect((await readFile(path.join(rootB, 'r.txt'))).toString()).toBe('v1');

		// More mutations happen server-side (from A) after B's baseline.
		await writeAndNotify(a, 'r2.txt', 'v2');
		await syncOnce(a);

		// "Kill" b: rebuild a FRESH engine/mirror instance from the SAME index
		// db + root (the cursor persisted in dc_meta survives).
		server.changesCalls = [];
		const http2 = new DriveHttp((input, init) => server.fetch(input, init), '');
		const mirror2 = new FolderMirror({ root: rootB, spaceId: SPACE, http: http2, index: b.index });
		const engine2 = new SyncEngine({
			http: http2,
			index: b.index,
			store: mirror2,
			spaceId: SPACE,
			deviceLabel: 'machine-b',
			isExcluded: () => false,
			todayYmd: () => '2026-01-15',
			now: () => Date.now(),
		});
		await engine2.syncOnce();

		expect((await readFile(path.join(rootB, 'r2.txt'))).toString()).toBe('v2');
		// The persisted cursor was used -- not a from-zero (`since=0`) refetch.
		expect(server.changesCalls).not.toContain('0');
		expect(server.changesCalls.some((c) => c !== '(anchor)')).toBe(true);
	});

	it('6: a 90-day-stale (pruned) cursor forces a windowed full resync that still converges', async () => {
		await writeAndNotify(a, 's.txt', 'v1');
		await syncAll([a, b]);
		await assertConverged([a, b]);

		const staleCursor = server.currentSeq(SPACE);
		await writeAndNotify(a, 's2.txt', 'v2');
		await syncOnce(a);
		// Simulate the 90-day journal prune: everything at/below the current
		// head is gone, stranding B's still-valid-looking cursor.
		server.pruneBelow(SPACE, server.currentSeq(SPACE));
		await b.index.setCursor(SPACE, String(staleCursor));

		await syncOnce(b); // hits the 409 -> engine.fullResync()
		expect((await readFile(path.join(rootB, 's2.txt'))).toString()).toBe('v2');
		await assertConverged([a, b]);
		const newCursor = await b.index.getCursor(SPACE);
		expect(newCursor).not.toBeNull();
	});

	it('9: a 6-chunk file dedups on edit — the second sync pushes exactly the 1 changed chunk', async () => {
		const CHUNK = 4 * 1024 * 1024;
		const original = Buffer.alloc(CHUNK * 5 + 1024, 1);
		await writeAndNotify(a, 'big.bin', original);
		await syncAll([a, b]);
		await assertConverged([a, b]);

		let pushed = 0;
		const rawPut = server.fetch;
		server.fetch = async (input: string, init?: RequestInit) => {
			const url = new URL(input, 'http://fake.invalid');
			if (url.pathname.startsWith('/chunks/') && (init?.method ?? '').toUpperCase() === 'PUT') pushed++;
			return rawPut(input, init);
		};

		const edited = Buffer.from(original);
		edited.fill(2, CHUNK * 2, CHUNK * 2 + 10); // touch only chunk #2
		await writeAndNotify(a, 'big.bin', edited);
		await syncOnce(a);

		expect(pushed).toBe(1);
		await syncAll([a, b]);
		await assertConverged([a, b]);
	});

	// P4 Task 17: the conflict-sibling P2 already materializes (scenario 2+3
	// above) now ALSO registers as a branch on BOTH machines -- upgrading the
	// P2-only materializedOfVersion dead end so a LATER edit of that sibling
	// is routable, not an orphan. Two scenarios: (10a) the conflict itself
	// auto-branches and both machines track it identically; (10b) editing the
	// sibling extends that branch server-side and propagates, main untouched.
	it('10a: concurrent edit auto-branches server-side; BOTH machines track the loser as the SAME branch-tracked sibling', async () => {
		await writeAndNotify(a, 'plan.md', 'base');
		await syncAll([a, b]);
		await assertConverged([a, b]);

		// Both edit from the same base, offline. Sync order (a before b, each
		// round) makes A the winner and B the loser deterministically.
		await writeAndNotify(a, 'plan.md', 'A-wins');
		await writeAndNotify(b, 'plan.md', 'B-loses');
		await syncAll([a, b], 6);
		await assertConverged([a, b]);

		expect((await readFile(path.join(rootA, 'plan.md'))).toString()).toBe('A-wins');
		expect((await readFile(path.join(rootB, 'plan.md'))).toString()).toBe('A-wins');

		const nodeId = (await a.index.findByPathCI(SPACE, 'plan.md'))!.nodeId;
		const serverBranches = server.openBranchesFor(nodeId);
		expect(serverBranches).toHaveLength(1); // the conflict auto-branched exactly once

		const branchOnA = await a.index.branchMirrorsForNode(nodeId);
		const branchOnB = await b.index.branchMirrorsForNode(nodeId);
		expect(branchOnA).toHaveLength(1);
		expect(branchOnB).toHaveLength(1);
		expect(branchOnA[0].branchId).toBe(serverBranches[0].id);
		expect(branchOnB[0].branchId).toBe(serverBranches[0].id); // same branch, not two independent trackings
		expect(branchOnA[0].relPath).toBe(branchOnB[0].relPath);
		expect((await readFile(path.join(rootA, branchOnA[0].relPath))).toString()).toBe('B-loses');
		expect((await readFile(path.join(rootB, branchOnB[0].relPath))).toString()).toBe('B-loses');
	});

	it('10b: editing the branch sibling extends the branch server-side; the OTHER machine picks up the new head; main stays untouched', async () => {
		await writeAndNotify(a, 'plan.md', 'base');
		await syncAll([a, b]);
		await writeAndNotify(a, 'plan.md', 'A-wins');
		await writeAndNotify(b, 'plan.md', 'B-loses');
		await syncAll([a, b], 6);
		await assertConverged([a, b]);

		const nodeId = (await a.index.findByPathCI(SPACE, 'plan.md'))!.nodeId;
		const branchId = server.openBranchesFor(nodeId)[0].id;
		const siblingRelPath = (await b.index.getBranchMirror(nodeId, branchId))!.relPath;
		const serverHeadBefore = server.openBranchesFor(nodeId)[0].headVersionId;

		// The loser (B) edits its own materialized sibling directly -- a save
		// from that ref must always land on the branch, never main (§5.3).
		await writeAndNotify(b, siblingRelPath, 'B-branch-edit');
		await syncAll([a, b], 4);

		expect(server.openBranchesFor(nodeId)[0].headVersionId).not.toBe(serverHeadBefore); // the branch head advanced
		await assertConverged([a, b]);
		expect((await readFile(path.join(rootA, siblingRelPath))).toString()).toBe('B-branch-edit'); // propagated to A
		expect((await readFile(path.join(rootB, siblingRelPath))).toString()).toBe('B-branch-edit');
		// Main is untouched -- the branch edit never landed on main on EITHER machine.
		expect((await readFile(path.join(rootA, 'plan.md'))).toString()).toBe('A-wins');
		expect((await readFile(path.join(rootB, 'plan.md'))).toString()).toBe('A-wins');
	});
});
