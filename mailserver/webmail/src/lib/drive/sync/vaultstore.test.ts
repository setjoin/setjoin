// @vitest-environment node
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import type { DriveBridge, OfflineDbBridge } from '$lib/native/types';
import type { Manifest } from './types.js';

vi.mock('./nativeToken.js', () => ({ getNativeToken: vi.fn().mockResolvedValue('tok-abc') }));

// dc_chunks mirrors offline-core's Rust-owned DDL (drive.rs) -- tests own it
// here the way schema.test.ts's memDb() owns dc_nodes/dc_mirror for the P2 side.
const DC_CHUNKS_DDL = `CREATE TABLE IF NOT EXISTS dc_chunks (
	sha256 TEXT NOT NULL PRIMARY KEY, size INTEGER NOT NULL, bytes BLOB NOT NULL,
	pinned_at INTEGER, last_read INTEGER)`;

function dbBridge(db: DatabaseSync): OfflineDbBridge {
	return {
		open: async () => {},
		isOpen: async () => true,
		exec: async (_appKey, sql, params = []) => Number(db.prepare(sql).run(...(params as never[])).changes),
		query: async (_appKey, sql, params = []) => db.prepare(sql).all(...(params as never[])) as never,
		wipe: async () => {},
	};
}

class FakeDrive implements DriveBridge {
	fetchCalls: { url: string; bearer: string; sha256: string; size: number }[] = [];
	deleteCalls: string[][] = [];
	throwOnFetch: Error | null = null;
	throwOnDelete: Error | null = null;

	constructor(private db: DatabaseSync) {}

	async importFile(): Promise<never> {
		throw new Error('unused');
	}
	async fetchChunk(url: string, bearer: string, sha256: string, size: number): Promise<void> {
		this.fetchCalls.push({ url, bearer, sha256, size });
		if (this.throwOnFetch) throw this.throwOnFetch;
		this.db
			.prepare('INSERT OR IGNORE INTO dc_chunks (sha256, size, bytes, last_read) VALUES (?, ?, ?, ?)')
			.run(sha256, size, Buffer.alloc(size), Date.now());
	}
	async pushChunk(): Promise<number> {
		return 201;
	}
	async hasChunk(sha256: string): Promise<boolean> {
		return this.db.prepare('SELECT 1 FROM dc_chunks WHERE sha256 = ?').get(sha256) != null;
	}
	async deleteChunks(sha256s: string[]): Promise<number> {
		this.deleteCalls.push(sha256s);
		if (this.throwOnDelete) throw this.throwOnDelete;
		let n = 0;
		for (const s of sha256s) n += Number(this.db.prepare('DELETE FROM dc_chunks WHERE sha256 = ?').run(s).changes);
		return n;
	}
	async serveStart(): Promise<{ port: number }> {
		return { port: 0 };
	}
	async serveGrant(): Promise<string> {
		return '/t/x';
	}
	async serveRevoke(): Promise<void> {}
}

function setup() {
	const db = new DatabaseSync(':memory:');
	db.exec(DC_CHUNKS_DDL);
	const drive = new FakeDrive(db);
	return { db, drive, bridge: dbBridge(db) };
}

function manifest(chunks: { sha256: string; size: number }[]): Manifest {
	return { contentSha256: 'whole-sha', size: chunks.reduce((s, c) => s + c.size, 0), chunks };
}

function insertChunk(db: DatabaseSync, sha256: string, size: number, opts: { pinnedAt?: number | null; lastRead?: number } = {}) {
	db.prepare('INSERT OR REPLACE INTO dc_chunks (sha256, size, bytes, pinned_at, last_read) VALUES (?, ?, ?, ?, ?)').run(
		sha256,
		size,
		Buffer.alloc(size),
		opts.pinnedAt ?? null,
		opts.lastRead ?? 0,
	);
}

describe('VaultStore', () => {
	beforeEach(async () => {
		const { getNativeToken } = (await import('./nativeToken.js')) as unknown as { getNativeToken: ReturnType<typeof vi.fn> };
		getNativeToken.mockClear();
		getNativeToken.mockResolvedValue('tok-abc');
	});

	it('putLocal fetches only missing chunks and records the manifest', async () => {
		const { db, drive, bridge } = setup();
		insertChunk(db, 'have', 10); // already present -- must NOT be re-fetched
		const { VaultStore } = await import('./vaultstore.js');
		const store = new VaultStore(drive, bridge, 7, () => null);
		await store.open();

		const m = manifest([
			{ sha256: 'have', size: 10 },
			{ sha256: 'missing', size: 20 },
		]);
		await store.putLocal(1, m);

		expect(drive.fetchCalls).toHaveLength(1);
		expect(drive.fetchCalls[0]).toMatchObject({ sha256: 'missing', size: 20, bearer: 'tok-abc' });
		expect(drive.fetchCalls[0].url).toContain('space=7');
		const got = await store.readLocalManifest(1);
		expect(got).toEqual(m);
	});

	it('putLocal rejects a DownloadPlan (no per-chunk shas to verify)', async () => {
		const { drive, bridge } = setup();
		const { VaultStore } = await import('./vaultstore.js');
		const store = new VaultStore(drive, bridge, 7, () => null);
		await expect(
			store.putLocal(1, { contentSha256: 'x', size: 10, headVersionId: 1 }),
		).rejects.toThrow(/DownloadPlan/);
	});

	it('a tls: rejection from fetchChunk is re-thrown as DriveTlsError', async () => {
		const { drive, bridge } = setup();
		drive.throwOnFetch = new Error("tls: server certificate not trusted -- install the org CA");
		const { VaultStore, DriveTlsError } = await import('./vaultstore.js');
		const store = new VaultStore(drive, bridge, 7, () => null);
		await expect(store.putLocal(1, manifest([{ sha256: 'a', size: 4 }]))).rejects.toBeInstanceOf(DriveTlsError);
	});

	it('pin marks every manifest chunk pinned + prefetches missing; unpin clears when unreferenced elsewhere', async () => {
		const { db, drive, bridge } = setup();
		const { VaultStore } = await import('./vaultstore.js');
		const store = new VaultStore(drive, bridge, 1, () => null);
		await store.open();
		const m = manifest([{ sha256: 'p1', size: 4 }, { sha256: 'p2', size: 4 }]);
		await store.putLocal(10, m);
		expect(drive.fetchCalls).toHaveLength(2); // both were missing

		await store.pin(10);
		const rows = db.prepare('SELECT sha256, pinned_at FROM dc_chunks').all() as { sha256: string; pinned_at: number | null }[];
		expect(rows.every((r) => r.pinned_at != null)).toBe(true);

		await store.unpin(10);
		const after = db.prepare('SELECT pinned_at FROM dc_chunks WHERE sha256 IN (?, ?)').all('p1', 'p2') as {
			pinned_at: number | null;
		}[];
		expect(after.every((r) => r.pinned_at == null)).toBe(true);
	});

	it('unpin keeps pinned_at when another pinned manifest still references the chunk', async () => {
		const { db, drive, bridge } = setup();
		const { VaultStore } = await import('./vaultstore.js');
		const store = new VaultStore(drive, bridge, 1, () => null);
		await store.open();
		const shared = { sha256: 'shared', size: 4 };
		await store.putLocal(10, manifest([shared]));
		await store.putLocal(11, manifest([shared]));
		await store.pin(10);
		await store.pin(11);

		await store.unpin(10); // node 11 still pins it
		const row = db.prepare('SELECT pinned_at FROM dc_chunks WHERE sha256 = ?').get('shared') as { pinned_at: number | null };
		expect(row.pinned_at).not.toBeNull();
	});

	it('enforceQuota evicts unpinned chunks in ascending last_read order until under budget', async () => {
		const { db, drive, bridge } = setup();
		insertChunk(db, 'old', 1024 * 1024, { lastRead: 1 });
		insertChunk(db, 'newer', 1024 * 1024, { lastRead: 2 });
		insertChunk(db, 'pinned', 1024 * 1024, { pinnedAt: 999, lastRead: 0 }); // oldest read but PINNED -- must survive
		const { VaultStore } = await import('./vaultstore.js');
		const store = new VaultStore(drive, bridge, 1, () => 2); // 2 MiB cap, 3 MiB used

		const evicted = await store.enforceQuota();
		expect(evicted).toBe(1);
		expect(drive.deleteCalls).toEqual([['old']]);
		expect(await store.hasChunk('pinned')).toBe(true);
		expect(await store.hasChunk('newer')).toBe(true);
	});

	it('enforceQuota is a no-op under quota (zero calls) and when no quota is set', async () => {
		const { db, drive, bridge } = setup();
		insertChunk(db, 'small', 100);
		const { VaultStore } = await import('./vaultstore.js');
		const underQuota = new VaultStore(drive, bridge, 1, () => 999);
		expect(await underQuota.enforceQuota()).toBe(0);
		expect(drive.deleteCalls).toHaveLength(0);

		const noQuota = new VaultStore(drive, bridge, 1, () => null);
		expect(await noQuota.enforceQuota()).toBe(0);
		expect(drive.deleteCalls).toHaveLength(0);
	});

	it('remove drops the manifest row and evicts now-unreferenced, unpinned chunks', async () => {
		const { drive, bridge } = setup();
		const { VaultStore } = await import('./vaultstore.js');
		const store = new VaultStore(drive, bridge, 1, () => null);
		await store.open();
		await store.putLocal(20, manifest([{ sha256: 'solo', size: 4 }]));

		await store.remove(20);
		expect(drive.deleteCalls).toEqual([['solo']]);
		expect(await store.readLocalManifest(20)).toBeNull();
	});

	it('remove does NOT evict a chunk still referenced by another manifest', async () => {
		const { drive, bridge } = setup();
		const { VaultStore } = await import('./vaultstore.js');
		const store = new VaultStore(drive, bridge, 1, () => null);
		await store.open();
		const shared = { sha256: 'shared2', size: 4 };
		await store.putLocal(20, manifest([shared]));
		await store.putLocal(21, manifest([shared]));

		await store.remove(20);
		expect(drive.deleteCalls).toHaveLength(0);
		expect(await store.hasChunk('shared2')).toBe(true);
	});

	it('revoke purges an exclusively pinned chunk instead of leaving an orphaned encrypted-cache row', async () => {
		const { db, drive, bridge } = setup();
		const { VaultStore } = await import('./vaultstore.js');
		const store = new VaultStore(drive, bridge, 1, () => null);
		await store.open();
		await store.putLocal(30, manifest([{ sha256: 'revoked-only', size: 4 }]));
		await store.pin(30);

		await expect(store.revoke(30, false)).resolves.toBe('purged');
		expect(await store.readLocalManifest(30)).toBeNull();
		expect(await store.hasChunk('revoked-only')).toBe(false);
		expect(db.prepare('SELECT count(*) AS n FROM dc_chunks').get()).toEqual({ n: 0 });
	});

	it('revoke retains a shared chunk until the final authorized manifest is removed, then purges it', async () => {
		const { drive, bridge } = setup();
		const { VaultStore } = await import('./vaultstore.js');
		const store = new VaultStore(drive, bridge, 1, () => null);
		await store.open();
		const shared = { sha256: 'revoked-shared', size: 4 };
		await store.putLocal(40, manifest([shared]));
		await store.putLocal(41, manifest([shared]));
		await store.pin(40);

		await store.revoke(40, false);
		expect(await store.hasChunk(shared.sha256)).toBe(true);
		expect(drive.deleteCalls).toEqual([]);

		await store.revoke(41, false);
		expect(await store.hasChunk(shared.sha256)).toBe(false);
		expect(drive.deleteCalls).toEqual([[shared.sha256]]);
	});

	it('resumes a persisted purge checkpoint after native deletion fails between manifest and chunk removal', async () => {
		const { db, drive, bridge } = setup();
		const { VaultStore } = await import('./vaultstore.js');
		const store = new VaultStore(drive, bridge, 1, () => null);
		await store.open();
		await store.putLocal(50, manifest([{ sha256: 'retry-purge', size: 4 }]));
		drive.throwOnDelete = new Error('simulated native crash');

		await expect(store.revoke(50, false)).rejects.toThrow('simulated native crash');
		expect(await store.readLocalManifest(50)).toBeNull();
		expect(db.prepare('SELECT count(*) AS n FROM dc_purge_queue WHERE node_id=50').get()).toEqual({ n: 1 });
		expect(await store.hasChunk('retry-purge')).toBe(true);

		drive.throwOnDelete = null;
		await expect(store.revoke(50, false)).resolves.toBe('purged');
		expect(await store.hasChunk('retry-purge')).toBe(false);
		expect(db.prepare('SELECT count(*) AS n FROM dc_purge_queue WHERE node_id=50').get()).toEqual({ n: 0 });
	});

	it('backfills normalized chunk references for a pre-index vault without losing shared content', async () => {
		const { db, drive, bridge } = setup();
		db.exec(`CREATE TABLE dc_manifests (
			node_id INTEGER PRIMARY KEY, manifest_json TEXT NOT NULL,
			pinned INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL)`);
		const shared = manifest([{ sha256: 'legacy-shared', size: 1 }]);
		db.prepare('INSERT INTO dc_manifests VALUES (?,?,0,0)').run(70, JSON.stringify(shared));
		db.prepare('INSERT INTO dc_manifests VALUES (?,?,0,0)').run(71, JSON.stringify(shared));
		insertChunk(db,'legacy-shared',1);
		const { VaultStore } = await import('./vaultstore.js');
		const store = new VaultStore(drive,bridge,1,()=>null);
		await store.open();

		expect(db.prepare('SELECT count(*) AS n FROM dc_manifest_chunks').get()).toEqual({ n: 2 });
		await store.revoke(70,false);
		expect(await store.hasChunk('legacy-shared')).toBe(true);
		await store.revoke(71,false);
		expect(await store.hasChunk('legacy-shared')).toBe(false);
	});

	it('keeps the 100k-manifest scan and 1k managed revoke fixture within the A9 budgets', async () => {
		const { db, drive, bridge } = setup();
		db.exec(`CREATE TABLE dc_manifests (
			node_id INTEGER PRIMARY KEY, manifest_json TEXT NOT NULL,
			pinned INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL)`);
		const addManifest=db.prepare('INSERT INTO dc_manifests VALUES (?,?,0,0)');
		const addChunk=db.prepare('INSERT INTO dc_chunks(sha256,size,bytes,pinned_at,last_read) VALUES (?,?,?,NULL,0)');
		db.exec('BEGIN');
		for (let nodeId=1;nodeId<=100_000;nodeId++) {
			const chunks=nodeId<=1_000 ? [{ sha256:`managed-${nodeId}`,size:1 }] : [];
			addManifest.run(nodeId,JSON.stringify(manifest(chunks)));
			if (chunks.length) addChunk.run(chunks[0].sha256,1,Buffer.alloc(1));
		}
		db.exec('COMMIT');
		const { VaultStore } = await import('./vaultstore.js');
		const store = new VaultStore(drive,bridge,1,()=>null);
		await store.open();

		const scanStart=performance.now();
		for (let nodeId=1;nodeId<=100_000;nodeId++) {
			expect(await store.readLocalManifest(nodeId)).not.toBeNull();
		}
		const scanMs=performance.now()-scanStart;
		expect(scanMs).toBeLessThan(60_000);

		const revokeStart=performance.now();
		for (let nodeId=1;nodeId<=1_000;nodeId++) await store.revoke(nodeId,false);
		const revokeMs=performance.now()-revokeStart;
		expect(revokeMs).toBeLessThan(10_000);
		expect(db.prepare('SELECT count(*) AS n FROM dc_manifests').get()).toEqual({ n: 99_000 });
		expect(db.prepare('SELECT count(*) AS n FROM dc_chunks').get()).toEqual({ n: 0 });
	});
});
