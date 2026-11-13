import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import { tmpdir } from 'node:os';
import * as path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { FetchLike } from '../../../../../mailserver/webmail/src/lib/drive/sync/types.js';
import type { NativeBinding } from '../native.js';
import { MirrorService, TRAY_STRINGS, makeDriveMirrorHandlers, normalizeLocale } from './service.js';

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

/** An unsigned JWT-shaped string carrying only the `uid` claim (self.ts
 *  decodes it for chmod self-exclusion — no signature verification needed
 *  for that informational read). */
function fakeJwt(uid: number): string {
	const payload = Buffer.from(JSON.stringify({ uid })).toString('base64url');
	return `h.${payload}.s`;
}

function fakeFetch(spaces: Array<{
	id: number;
	name: string;
	classification?: string;
	role?: string;
	changeSeq?: number;
	aclMode?: 'legacy' | 'shadow' | 'acl';
}>): FetchLike {
	return async (input, init) => {
		const url = new URL(input);
		if (url.pathname.endsWith('/spaces') && init?.method === undefined) {
			return jsonResponse(
				spaces.map((s) => ({ classification: 'regular', role: 'manager', changeSeq: 0, aclMode: 'legacy', aclEpoch: 0, ...s }))
			);
		}
		if (url.pathname.endsWith('/access-invalidations')) {
			return jsonResponse({ cursor: null, epoch: '0', invalidations: [], hasMore: false, fullReconcile: false });
		}
		if (url.pathname.endsWith('/visibility-snapshot')) {
			return jsonResponse({ epoch: '0', rootCapabilities: ['create_child'], nodes: [], nextAfter: '0', hasMore: false });
		}
		if (/\/spaces\/\d+\/tree$/.test(url.pathname)) return jsonResponse([]);
		if (url.pathname.endsWith('/native-token') && init?.method === 'POST') {
			return jsonResponse({ token: 'renewed-token', expiresAt: new Date(Date.now() + 3_600_000).toISOString() });
		}
		return jsonResponse([]);
	};
}

function fakeNative(dbOpenThrows = false): NativeBinding {
	// ponytail: a real in-memory table isn't worth building here — the
	// SqlMirrorIndex/schema.ts contract already has its own node:sqlite oracle
	// test (schema.test.ts); this fake only needs to not throw so
	// MirrorService's plumbing (config -> reconcile -> sync pass) can be
	// exercised end to end against an always-empty index.
	return {
		vaultUnlock: () => true,
		vaultIsUnlocked: () => true,
		vaultListTotp: () => [],
		vaultGenerateTotp: () => '000000',
		secureStoreGet: () => null,
		secureStoreSet: () => {},
		secureStoreRemove: () => {},
		dbOpen: vi.fn(() => {
			if (dbOpenThrows) throw new Error('vault locked');
		}),
		dbIsOpen: () => true,
		dbExec: vi.fn(() => 0),
		dbExecSchemaInit: () => 0,
		dbTransactionBatch: () => 0,
		dbMigrateStore: () => '{"version":2}',
		dbQuery: vi.fn(() => '[]'),
		dbWipe: vi.fn(),
		driveImportFile: vi.fn(async () => '{"contentSha256":"","size":0,"chunks":[]}'),
		driveFetchChunk: vi.fn(async () => {}),
		drivePushChunk: vi.fn(async () => 200),
		driveHasChunk: () => false,
		driveDeleteChunks: () => 0,
		driveSetConfinement: () => {},
		driveServeStart: vi.fn(async () => '{"port":0}'),
		driveServeGrant: () => '/t/fake',
		driveServeRevoke: () => {},
		driveServeStop: () => {},
		mamStoreDeviceId: () => {},
		mamStorePolicy: () => {},
		mamGetPolicy: () => null,
		mamMarkWiped: () => {},
		mamIsWiped: () => false,
		mamClearWiped: () => {},
	};
}

/** A real node:sqlite-backed fake (P4 Task 16 tests need actual dc_mirror
 *  rows to resolve nodeId<->relPath for chmod/soft-checkout — the always-empty
 *  `fakeNative()` above can't express that). `db` is exposed so a test can
 *  seed rows directly through the SAME connection MirrorService's
 *  `nativeDbLike` wrapper reads via native.dbExec/dbQuery. */
function sqliteBackedNative(): NativeBinding & { db: DatabaseSync } {
	const db = new DatabaseSync(':memory:');
	const base = fakeNative();
	return {
		...base,
		db,
		dbOpen: vi.fn(() => {}),
		dbExec: (_appKey, sql, paramsJson) => {
			const r = db.prepare(sql).run(...(JSON.parse(paramsJson) as never[]));
			return Number(r.changes);
		},
		dbQuery: (_appKey, sql, paramsJson) =>
			JSON.stringify(db.prepare(sql).all(...(JSON.parse(paramsJson) as never[]))),
	};
}

interface LockRowFixture {
	nodeId: number;
	name: string;
	holderId: number;
	holderName: string | null;
	mode: 'soft' | 'hard';
	branchId: number | null;
	acquiredAt: string;
	expiresAt: string;
	deviceLabel: string | null;
}

/** Extends the base `fakeFetch` with the P4 lock routes: a mutable `locks`
 *  array the test can reassign between passes, and a capture of every
 *  `PUT /files/{id}/lock` body (the auto-soft-checkout assertions). */
function fakeFetchWithLocks(
	spaces: Array<{ id: number; name: string }>,
	state: { locks: LockRowFixture[] },
	lockPutCalls: Array<{ nodeId: number; body: unknown }>
): FetchLike {
	const base = fakeFetch(spaces);
	return async (input, init) => {
		const url = new URL(input);
		const lockMatch = url.pathname.match(/\/files\/(\d+)\/lock$/);
		if (lockMatch && init?.method === 'PUT') {
			const nodeId = Number(lockMatch[1]);
			lockPutCalls.push({ nodeId, body: JSON.parse(init.body as string) });
			return jsonResponse({ status: 'acquired', expiresAt: new Date(Date.now() + 3_600_000).toISOString(), mode: 'soft' });
		}
		if (/\/spaces\/\d+\/locks$/.test(url.pathname)) {
			return jsonResponse({ locks: state.locks });
		}
		// A second (non-anchor) pass calls /changes -- the base fakeFetch's
		// catch-all (`[]`) isn't a valid ChangesPageWire; every test in this
		// file drives at least one such pass via resync().
		if (url.pathname.endsWith('/changes')) {
			return jsonResponse({ newState: '0', changed: [], hasMore: false });
		}
		return base(input, init);
	};
}

async function flush(times = 3): Promise<void> {
	for (let i = 0; i < times; i++) await new Promise((r) => setTimeout(r, 0));
}

describe('MirrorService', () => {
	let mirrorBase: string;
	let userDataDir: string;

	beforeEach(async () => {
		mirrorBase = await mkdtemp(path.join(tmpdir(), 'drive-svc-root-'));
		userDataDir = await mkdtemp(path.join(tmpdir(), 'drive-svc-data-'));
	});
	afterEach(async () => {
		await rm(mirrorBase, { recursive: true, force: true });
		await rm(userDataDir, { recursive: true, force: true });
	});

	it('status() never throws when unconfigured and reports empty (list fields never null)', async () => {
		const svc = new MirrorService({
			native: fakeNative(),
			userDataDir,
			fetchFn: fakeFetch([]),
			mirrorBase,
			deviceLabel: 'test-device',
			locale: 'en',
			openPath: () => {},
		});
		const s = await svc.status();
		expect(s).toEqual({ running: false, paused: false, perSpace: [], issues: [] });
	});

	it('configure() before any token reports the requested space as auth-expired, not silently missing', async () => {
		const svc = new MirrorService({
			native: fakeNative(),
			userDataDir,
			fetchFn: fakeFetch([{ id: 1, name: 'Team Space' }]),
			mirrorBase,
			deviceLabel: 'd',
			locale: 'en',
			openPath: () => {},
			pollMs: 10_000_000,
		});
		await svc.configure({ serverOrigin: 'http://gw', spaces: [{ spaceId: 1, excludes: [] }] });
		const s = await svc.status();
		expect(s.perSpace).toEqual([
			{ spaceId: 1, name: 'space-1', state: 'auth-expired', lastSyncMs: null, pendingUploads: 0, issues: 0 },
		]);
	});

	it('refreshToken() resolves the space name from the server and syncs to idle', async () => {
		const svc = new MirrorService({
			native: fakeNative(),
			userDataDir,
			fetchFn: fakeFetch([{ id: 1, name: 'Team Space' }]),
			mirrorBase,
			deviceLabel: 'd',
			locale: 'en',
			openPath: () => {},
			pollMs: 10_000_000,
		});
		await svc.configure({ serverOrigin: 'http://gw', spaces: [{ spaceId: 1, excludes: [] }] });
		await svc.refreshToken('tok-1', new Date(Date.now() + 3_600_000).toISOString());
		await flush();

		const s = await svc.status();
		expect(s.perSpace).toHaveLength(1);
		expect(s.perSpace[0].name).toBe('Team Space');
		expect(s.perSpace[0].state).toBe('idle');
		expect(s.running).toBe(true);
	});

	it('keeps an ACL-mode FolderMirror policy-blocked until residual-copy risk is explicitly accepted', async () => {
		const svc = new MirrorService({
			native: fakeNative(),
			userDataDir,
			fetchFn: fakeFetch([{ id: 1, name: 'Restricted', aclMode: 'acl' }]),
			mirrorBase,
			deviceLabel: 'd',
			locale: 'en',
			openPath: () => {},
			pollMs: 10_000_000,
		});
		await svc.configure({ serverOrigin: 'http://gw', spaces: [{ spaceId: 1, excludes: [] }] });
		await svc.refreshToken('tok-1', new Date(Date.now() + 3_600_000).toISOString());
		await flush();

		expect((await svc.status()).perSpace).toEqual([expect.objectContaining({
			spaceId: 1,
			state: 'policy-blocked',
			aclMode: 'acl',
			unmanagedAclRiskAccepted: false,
		})]);
		await expect(stat(path.join(mirrorBase, 'Restricted'))).rejects.toThrow();

		await svc.configure({
			serverOrigin: 'http://gw',
			spaces: [{ spaceId: 1, excludes: [], acceptUnmanagedAclRisk: true }],
		});
		await flush();
		expect((await svc.status()).perSpace).toEqual([expect.objectContaining({
			spaceId: 1,
			state: 'idle',
			unmanagedAclRiskAccepted: true,
		})]);
		await expect(stat(path.join(mirrorBase, 'Restricted'))).resolves.toBeTruthy();
	});

	it('vault-locked: native.dbOpen throwing degrades every space to vault-locked, never throws itself', async () => {
		const svc = new MirrorService({
			native: fakeNative(true),
			userDataDir,
			fetchFn: fakeFetch([{ id: 1, name: 'X' }]),
			mirrorBase,
			deviceLabel: 'd',
			locale: 'en',
			openPath: () => {},
		});
		await expect(svc.configure({ serverOrigin: 'http://gw', spaces: [{ spaceId: 1, excludes: [] }] })).resolves.toBeUndefined();
		const s = await svc.status();
		expect(s.perSpace).toEqual([
			{ spaceId: 1, name: 'space-1', state: 'vault-locked', lastSyncMs: null, pendingUploads: 0, issues: 0 },
		]);
	});

	it('setPaused(true) reports running:false without tearing down spaces', async () => {
		const svc = new MirrorService({
			native: fakeNative(),
			userDataDir,
			fetchFn: fakeFetch([{ id: 1, name: 'Team Space' }]),
			mirrorBase,
			deviceLabel: 'd',
			locale: 'en',
			openPath: () => {},
			pollMs: 10_000_000,
		});
		await svc.configure({ serverOrigin: 'http://gw', spaces: [{ spaceId: 1, excludes: [] }] });
		await svc.refreshToken('tok-1', new Date(Date.now() + 3_600_000).toISOString());
		await flush();
		await svc.setPaused(true);
		const s = await svc.status();
		expect(s.paused).toBe(true);
		expect(s.running).toBe(false);
		expect(s.perSpace).toHaveLength(1); // still configured, just not polling
	});

	it('resync() on an unknown space throws', async () => {
		const svc = new MirrorService({
			native: fakeNative(),
			userDataDir,
			fetchFn: fakeFetch([]),
			mirrorBase,
			deviceLabel: 'd',
			locale: 'en',
			openPath: () => {},
		});
		await expect(svc.resync(999)).rejects.toThrow(/unknown space/);
	});

	it('openRoot() delegates to the injected openPath with the space root', async () => {
		const openPath = vi.fn();
		const svc = new MirrorService({
			native: fakeNative(),
			userDataDir,
			fetchFn: fakeFetch([{ id: 1, name: 'Team Space' }]),
			mirrorBase,
			deviceLabel: 'd',
			locale: 'en',
			openPath,
			pollMs: 10_000_000,
		});
		await svc.configure({ serverOrigin: 'http://gw', spaces: [{ spaceId: 1, excludes: [] }] });
		await svc.refreshToken('tok-1', new Date(Date.now() + 3_600_000).toISOString());
		await flush();
		await svc.openRoot(1);
		expect(openPath).toHaveBeenCalledWith(path.join(mirrorBase, 'Team Space'));
	});

	it('removing a space from configure() stops it but leaves its files on disk', async () => {
		const svc = new MirrorService({
			native: fakeNative(),
			userDataDir,
			fetchFn: fakeFetch([{ id: 1, name: 'Team Space' }]),
			mirrorBase,
			deviceLabel: 'd',
			locale: 'en',
			openPath: () => {},
			pollMs: 10_000_000,
		});
		await svc.configure({ serverOrigin: 'http://gw', spaces: [{ spaceId: 1, excludes: [] }] });
		await svc.refreshToken('tok-1', new Date(Date.now() + 3_600_000).toISOString());
		await flush();
		expect((await svc.status()).perSpace).toHaveLength(1);

		await svc.configure({ serverOrigin: 'http://gw', spaces: [] });
		expect((await svc.status()).perSpace).toHaveLength(0);
		const { existsSync } = await import('node:fs');
		expect(existsSync(path.join(mirrorBase, 'Team Space'))).toBe(true); // un-mirroring never deletes
	});
});

describe('MirrorService — P4 hard-lock read-only bit (Task 16, LR-6)', () => {
	let mirrorBase: string;
	let userDataDir: string;

	beforeEach(async () => {
		mirrorBase = await mkdtemp(path.join(tmpdir(), 'drive-svc-lockroot-'));
		userDataDir = await mkdtemp(path.join(tmpdir(), 'drive-svc-lockdata-'));
	});
	afterEach(async () => {
		await rm(mirrorBase, { recursive: true, force: true });
		await rm(userDataDir, { recursive: true, force: true });
	});

	async function bootSpace(native: NativeBinding & { db: DatabaseSync }, fetchFn: FetchLike) {
		const svc = new MirrorService({
			native,
			userDataDir,
			fetchFn,
			mirrorBase,
			deviceLabel: 'bobs-laptop',
			locale: 'en',
			openPath: () => {},
			pollMs: 10_000_000,
		});
		await svc.configure({ serverOrigin: 'http://gw', spaces: [{ spaceId: 1, excludes: [] }] });
		await svc.refreshToken(fakeJwt(1), new Date(Date.now() + 3_600_000).toISOString());
		await flush();
		return svc;
	}

	it('a hard lock held by ANOTHER user chmods the synced path 0o444; clearing the lock restores 0o644', async () => {
		const native = sqliteBackedNative();
		const state = { locks: [] as LockRowFixture[] };
		const svc = await bootSpace(native, fakeFetchWithLocks([{ id: 1, name: 'Team Space' }], state, []));

		const filePath = path.join(mirrorBase, 'Team Space', 'readme.txt');
		await writeFile(filePath, 'hello');
		native.db
			.prepare(
				`INSERT INTO dc_mirror (node_id, space_id, rel_path, disk_sha256, disk_size, disk_mtime_ms, base_version_id, materialized_of_version)
				 VALUES (7, 1, 'readme.txt', 'sha', 5, 0, 1, NULL)`
			)
			.run();

		state.locks = [
			{
				nodeId: 7,
				name: 'readme.txt',
				holderId: 999, // not self -- self is uid 1 per fakeJwt(1)
				holderName: 'Bob',
				mode: 'hard',
				branchId: null,
				acquiredAt: new Date().toISOString(),
				expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
				deviceLabel: 'bobs-laptop',
			},
		];
		await svc.resync(1);
		expect((await stat(filePath)).mode & 0o777).toBe(0o444);

		state.locks = [];
		await svc.resync(1);
		expect((await stat(filePath)).mode & 0o777).toBe(0o644);
	});

	it('a soft lock never chmods; a hard lock held by SELF is not treated as foreign', async () => {
		const native = sqliteBackedNative();
		const state = { locks: [] as LockRowFixture[] };
		const svc = await bootSpace(native, fakeFetchWithLocks([{ id: 1, name: 'Team Space' }], state, []));

		const filePath = path.join(mirrorBase, 'Team Space', 'plan.txt');
		await writeFile(filePath, 'hi');
		native.db
			.prepare(
				`INSERT INTO dc_mirror (node_id, space_id, rel_path, disk_sha256, disk_size, disk_mtime_ms, base_version_id, materialized_of_version)
				 VALUES (11, 1, 'plan.txt', 'sha', 2, 0, 1, NULL)`
			)
			.run();

		state.locks = [
			{
				nodeId: 11,
				name: 'plan.txt',
				holderId: 999,
				holderName: 'Bob',
				mode: 'soft',
				branchId: null,
				acquiredAt: new Date().toISOString(),
				expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
				deviceLabel: null,
			},
		];
		await svc.resync(1);
		expect((await stat(filePath)).mode & 0o777).toBe(0o644); // soft lock: presence only, no chmod

		state.locks = [
			{
				nodeId: 11,
				name: 'plan.txt',
				holderId: 1, // self
				holderName: 'Me',
				mode: 'hard',
				branchId: null,
				acquiredAt: new Date().toISOString(),
				expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
				deviceLabel: 'this-device',
			},
		];
		await svc.resync(1);
		expect((await stat(filePath)).mode & 0o777).toBe(0o644); // own hard lock is not "another user"
	});

	it('a poisoned mirror row (relPath escaping the root) is never chmodded outside the mirror (D-CLIENTS-DESKTOP-008)', async () => {
		const native = sqliteBackedNative();
		const state = { locks: [] as LockRowFixture[] };
		const svc = await bootSpace(native, fakeFetchWithLocks([{ id: 1, name: 'Team Space' }], state, []));

		// Sentinel OUTSIDE the mirror root that a ../-escaping relPath would reach.
		const sentinel = path.join(path.dirname(mirrorBase), `${path.basename(mirrorBase)}-sentinel.txt`);
		await writeFile(sentinel, 'must survive');
		const sentinelModeBefore = (await stat(sentinel)).mode & 0o777;
		try {
			native.db
				.prepare(
					`INSERT INTO dc_mirror (node_id, space_id, rel_path, disk_sha256, disk_size, disk_mtime_ms, base_version_id, materialized_of_version)
					 VALUES (23, 1, '../${path.basename(sentinel)}', 'sha', 12, 0, 1, NULL)`
				)
				.run();

			state.locks = [
				{
					nodeId: 23,
					name: 'sentinel',
					holderId: 999, // foreign hard lock -> would chmod if uncontained
					holderName: 'Bob',
					mode: 'hard',
					branchId: null,
					acquiredAt: new Date().toISOString(),
					expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
					deviceLabel: 'bobs-laptop',
				},
			];
			await svc.resync(1);

			// The escape is skipped fail-closed: sentinel untouched and never
			// made read-only; the poisoned row also never enters readOnlyApplied
			// (stop() would otherwise try to "restore" a path outside the root).
			expect((await stat(sentinel)).mode & 0o777).toBe(sentinelModeBefore);
			expect((await readFile(sentinel)).toString()).toBe('must survive');
		} finally {
			await rm(sentinel, { force: true });
		}
	});

	it('stop() restores every read-only bit it applied — a dead mirror must not strand read-only files', async () => {
		const native = sqliteBackedNative();
		const state = { locks: [] as LockRowFixture[] };
		const svc = await bootSpace(native, fakeFetchWithLocks([{ id: 1, name: 'Team Space' }], state, []));

		const filePath = path.join(mirrorBase, 'Team Space', 'readme.txt');
		await writeFile(filePath, 'hello');
		native.db
			.prepare(
				`INSERT INTO dc_mirror (node_id, space_id, rel_path, disk_sha256, disk_size, disk_mtime_ms, base_version_id, materialized_of_version)
				 VALUES (7, 1, 'readme.txt', 'sha', 5, 0, 1, NULL)`
			)
			.run();
		state.locks = [
			{
				nodeId: 7,
				name: 'readme.txt',
				holderId: 999,
				holderName: 'Bob',
				mode: 'hard',
				branchId: null,
				acquiredAt: new Date().toISOString(),
				expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
				deviceLabel: 'bobs-laptop',
			},
		];
		await svc.resync(1);
		expect((await stat(filePath)).mode & 0o777).toBe(0o444);

		await svc.stop();
		expect((await stat(filePath)).mode & 0o777).toBe(0o644);
	});
});

describe('MirrorService — P4 office auto-soft-checkout (Task 16)', () => {
	let mirrorBase: string;
	let userDataDir: string;

	beforeEach(async () => {
		mirrorBase = await mkdtemp(path.join(tmpdir(), 'drive-svc-checkoutroot-'));
		userDataDir = await mkdtemp(path.join(tmpdir(), 'drive-svc-checkoutdata-'));
	});
	afterEach(async () => {
		await rm(mirrorBase, { recursive: true, force: true });
		await rm(userDataDir, { recursive: true, force: true });
	});

	it('fires ONE best-effort soft lock PUT per office-ext edit, deduped per node for 10 min, refires past the window', async () => {
		const native = sqliteBackedNative();
		const state = { locks: [] as LockRowFixture[] };
		const lockPutCalls: Array<{ nodeId: number; body: unknown }> = [];
		const svc = new MirrorService({
			native,
			userDataDir,
			fetchFn: fakeFetchWithLocks([{ id: 1, name: 'Team Space' }], state, lockPutCalls),
			mirrorBase,
			deviceLabel: 'bobs-laptop',
			locale: 'en',
			openPath: () => {},
			pollMs: 10_000_000,
		});
		await svc.configure({ serverOrigin: 'http://gw', spaces: [{ spaceId: 1, excludes: [] }] });
		await svc.refreshToken(fakeJwt(1), new Date(Date.now() + 3_600_000).toISOString());
		await flush();

		const filePath = path.join(mirrorBase, 'Team Space', 'report.xlsx');
		native.db
			.prepare(
				`INSERT INTO dc_mirror (node_id, space_id, rel_path, disk_sha256, disk_size, disk_mtime_ms, base_version_id, materialized_of_version)
				 VALUES (22, 1, 'report.xlsx', 'initial-sha', 0, 0, 1, NULL)`
			)
			.run();

		const now = vi.spyOn(Date, 'now');
		now.mockReturnValue(1_000_000);
		await writeFile(filePath, 'v1');
		await svc.resync(1); // verify() detects the mismatch -> local upsert -> office-ext auto-soft-checkout fires
		expect(lockPutCalls).toEqual([{ nodeId: 22, body: { mode: 'soft', deviceLabel: 'bobs-laptop' } }]);

		await writeFile(filePath, 'v2'); // a second edit inside the dedupe window
		await svc.resync(1);
		expect(lockPutCalls).toHaveLength(1); // deduped -- no second PUT within 10 min

		now.mockReturnValue(1_000_000 + 11 * 60 * 1000); // past the dedupe window
		await writeFile(filePath, 'v3');
		await svc.resync(1);
		expect(lockPutCalls).toHaveLength(2);

		now.mockRestore();
	});

	it('a non-office extension never fires a soft lock', async () => {
		const native = sqliteBackedNative();
		const state = { locks: [] as LockRowFixture[] };
		const lockPutCalls: Array<{ nodeId: number; body: unknown }> = [];
		const svc = new MirrorService({
			native,
			userDataDir,
			fetchFn: fakeFetchWithLocks([{ id: 1, name: 'Team Space' }], state, lockPutCalls),
			mirrorBase,
			deviceLabel: 'bobs-laptop',
			locale: 'en',
			openPath: () => {},
			pollMs: 10_000_000,
		});
		await svc.configure({ serverOrigin: 'http://gw', spaces: [{ spaceId: 1, excludes: [] }] });
		await svc.refreshToken(fakeJwt(1), new Date(Date.now() + 3_600_000).toISOString());
		await flush();

		const filePath = path.join(mirrorBase, 'Team Space', 'notes.txt');
		native.db
			.prepare(
				`INSERT INTO dc_mirror (node_id, space_id, rel_path, disk_sha256, disk_size, disk_mtime_ms, base_version_id, materialized_of_version)
				 VALUES (23, 1, 'notes.txt', 'initial-sha', 0, 0, 1, NULL)`
			)
			.run();
		await writeFile(filePath, 'v1');
		await svc.resync(1);
		expect(lockPutCalls).toEqual([]);
	});

	it('opens an Office file only after server policy authorization and never accepts a renderer path', async () => {
		const native = sqliteBackedNative();
		const opened: Array<{ appId: string; filePath: string }> = [];
		const baseFetch = fakeFetch([{ id: 1, name: 'Team Space' }]);
		const fetchFn: FetchLike = async (input, init) => {
			const url = new URL(input);
			if (url.pathname.endsWith('/files/23/office/local-open')) {
				expect(init?.headers).toEqual({ Authorization: expect.stringContaining('h.'), 'Content-Type': 'application/json' });
				expect(JSON.parse(String(init?.body))).toEqual({ appId: 'libreoffice', deviceId: 'd' });
				return jsonResponse({ accepted: true, baseVersionId: 1 });
			}
			return baseFetch(input, init);
		};
		const svc = new MirrorService({
			native,
			userDataDir,
			fetchFn,
			mirrorBase,
			deviceLabel: 'd',
			locale: 'en',
			openPath: () => {},
			localOffice: {
				available: async () => [{ id: 'libreoffice', label: 'LibreOffice' }],
				open: async (appId, filePath) => { opened.push({ appId, filePath }); },
			},
			pollMs: 10_000_000,
		});
		await svc.configure({ serverOrigin: 'http://gw', spaces: [{ spaceId: 1, excludes: [] }] });
		await svc.refreshToken(fakeJwt(1), new Date(Date.now() + 3_600_000).toISOString());
		await flush();
		native.db.prepare(
			`INSERT INTO dc_mirror (node_id, space_id, rel_path, disk_sha256, disk_size, disk_mtime_ms, base_version_id, materialized_of_version)
			 VALUES (23, 1, 'report.docx', 'sha', 1, 0, 1, NULL)`,
		).run();
		const expected = path.join(mirrorBase, 'Team Space', 'report.docx');
		await writeFile(expected, 'x');

		await svc.openLocalOffice(1, 23, 'libreoffice');
		expect(opened).toEqual([{ appId: 'libreoffice', filePath: expected }]);
		await svc.stop();
		native.db.close();
	});
});

describe('makeDriveMirrorHandlers', () => {
	it('registers exactly the 8 drive_mirror_* channels', () => {
		const svc = new MirrorService({
			native: fakeNative(),
			userDataDir: '/tmp',
			fetchFn: fakeFetch([]),
			mirrorBase: '/tmp',
			deviceLabel: 'd',
			locale: 'en',
			openPath: () => {},
		});
		const map = makeDriveMirrorHandlers(svc);
		expect(Object.keys(map).sort()).toEqual(
			[
				'drive_mirror_configure',
				'drive_mirror_office_choices',
				'drive_mirror_open_root',
				'drive_mirror_open_office',
				'drive_mirror_refresh_token',
				'drive_mirror_resync',
				'drive_mirror_set_paused',
				'drive_mirror_status',
			].sort()
		);
	});
});

describe('tray strings', () => {
	it('has all 8 keys for en/de/zh', () => {
		const keys = ['syncing', 'idle', 'paused', 'error', 'open', 'pause', 'resume', 'quit'];
		for (const locale of ['en', 'de', 'zh'] as const) {
			expect(Object.keys(TRAY_STRINGS[locale]).sort()).toEqual([...keys].sort());
		}
	});

	it('normalizeLocale picks de/zh by prefix, defaults to en', () => {
		expect(normalizeLocale('de-DE')).toBe('de');
		expect(normalizeLocale('zh-Hans')).toBe('zh');
		expect(normalizeLocale('fr-FR')).toBe('en');
		expect(normalizeLocale('en-US')).toBe('en');
	});
});
