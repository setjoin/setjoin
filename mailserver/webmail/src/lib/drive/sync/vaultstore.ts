// vaultstore.ts — VaultStore: the P3 secure-vault ContentStore (spec §4.1,
// ARCH-017). Chunks live in the SQLCipher 'drive' vault via the native
// window.setjoinNative.drive bridge; TS owns pin/LRU/quota POLICY only --
// Rust (offline-core drive.rs) owns dc_chunks bytes and their deletion, never
// a raw DELETE from here. Distinct from FolderMirror (P2's OS-folder
// mirror): this store backs the in-app SecureViewer, not a two-way disk sync.
import type { ChunkRef, ContentStore, DownloadPlan, LocalChange, Manifest, RevocationOutcome } from './types.js';
import type { DriveBridge, OfflineDbBridge } from '$lib/native/types';
import { getNativeToken } from './nativeToken.js';

/** TS-owned metadata DDL — Rust owns only dc_chunks (drive.rs). One row per
 *  node this device has pulled into the vault; `pinned` drives eviction
 *  exemption (enforceQuota) and unpin's "still referenced?" check.
 *  ponytail: dc_manifests is the whole P3 metadata surface for now — no
 *  localChanges() producer exists yet (the viewer has no "save into vault"
 *  action). Add one here, mirroring FolderMirror's FS watcher, if/when it ships. */
const VAULT_META_DDL = `CREATE TABLE IF NOT EXISTS dc_manifests (
	node_id INTEGER PRIMARY KEY, manifest_json TEXT NOT NULL,
	pinned INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL)`;
const VAULT_PURGE_DDL = `CREATE TABLE IF NOT EXISTS dc_purge_queue (
	node_id INTEGER PRIMARY KEY, manifest_json TEXT NOT NULL,
	updated_at INTEGER NOT NULL)`;
const VAULT_CHUNK_REFS_DDL = `CREATE TABLE IF NOT EXISTS dc_manifest_chunks (
	node_id INTEGER NOT NULL, sha256 TEXT NOT NULL,
	PRIMARY KEY (node_id, sha256))`;
const VAULT_CHUNK_REFS_INDEX_DDL = `CREATE INDEX IF NOT EXISTS dc_manifest_chunks_sha_idx
	ON dc_manifest_chunks (sha256, node_id)`;
const VAULT_CHUNK_REFS_BACKFILL = `INSERT OR IGNORE INTO dc_manifest_chunks(node_id,sha256)
	SELECT m.node_id,json_extract(c.value,'$.sha256')
	  FROM dc_manifests m,json_each(m.manifest_json,'$.chunks') c
	 WHERE json_type(c.value,'$.sha256')='text'`;

const APP = 'drive';

/** A `tls:`-prefixed native rejection (offline-core's OfflineError::Tls,
 *  grill G), re-thrown so callers can map it to the localized
 *  `drive.sync.tlsUntrusted` hint instead of a generic sync-failure message. */
export class DriveTlsError extends Error {}

export class VaultStore implements ContentStore {
	constructor(
		private drive: DriveBridge,
		private db: OfflineDbBridge,
		/** The space this store instance serves — chunk URLs are per-space. */
		private spaceId: number,
		/** Device-side pin cap from the space row (`vault_quota_mb`) — distinct
		 *  from the server's `quota_bytes` (two separate knobs, spec §0.1-2). */
		private quotaMb: () => number | null,
	) {}

	async open(): Promise<void> {
		await this.db.open(APP);
		await this.db.exec(APP, VAULT_META_DDL, []);
		await this.db.exec(APP, VAULT_PURGE_DDL, []);
		await this.db.exec(APP, VAULT_CHUNK_REFS_DDL, []);
		await this.db.exec(APP, VAULT_CHUNK_REFS_INDEX_DDL, []);
		// Existing vaults predate the normalized reference index. SQLite/SQLCipher
		// JSON1 performs one idempotent set-based backfill; subsequent opens touch
		// only missing rows.
		await this.db.exec(APP, VAULT_CHUNK_REFS_BACKFILL, []);
	}

	private chunkUrl(sha256: string): string {
		return `/api/drive/chunks/${sha256}?space=${this.spaceId}`;
	}

	/** The SPA's page origin (browser, dev server, ArkWeb). Node test envs and
	 *  opaque origins (file://, where `location.origin` is the string "null")
	 *  return null — the relative path then passes through unchanged and the
	 *  native layer fails it closed as before. */
	private pageOrigin(): string | null {
		if (typeof window === 'undefined') return null;
		const origin = window.location?.origin;
		return origin && origin !== 'null' ? origin : null;
	}

	/** Absolute SAME-ORIGIN chunk URL for the native byte plane (deep-scan
	 *  package desktop-drive-bridge-unconfined): the renderer never asks the
	 *  native GET/PUT to dial an arbitrary absolute URL — it hands over its own
	 *  origin-bounded URL, which the shell layers' approved-origin allowlists
	 *  (Electron `handlers/drive.ts`, HarmonyOS `BridgeProxy.ets`) then verify.
	 *  A relative fallback keeps node-side tests and the (already
	 *  native-rejected) opaque-origin case unchanged. */
	private nativeChunkUrl(sha256: string): string {
		const origin = this.pageOrigin();
		if (!origin) return this.chunkUrl(sha256);
		return new URL(this.chunkUrl(sha256), origin).href;
	}

	async hasChunk(sha256: string): Promise<boolean> {
		return this.drive.hasChunk(sha256);
	}

	async fetchChunk(c: ChunkRef, url: string, bearer: string): Promise<void> {
		try {
			await this.drive.fetchChunk(url, bearer, c.sha256, c.size);
		} catch (e) {
			const msg = e instanceof Error ? e.message : String(e);
			if (msg.startsWith('tls:')) throw new DriveTlsError(msg);
			throw e;
		}
	}

	async pushChunk(c: ChunkRef, url: string, bearer: string): Promise<void> {
		const status = await this.drive.pushChunk(url, bearer, c.sha256);
		if (status < 200 || status >= 300) throw new Error(`VaultStore.pushChunk: HTTP ${status} for ${c.sha256}`);
	}

	async readLocalManifest(nodeId: number): Promise<Manifest | null> {
		const rows = await this.db.query<{ manifest_json: string }>(
			APP,
			'SELECT manifest_json FROM dc_manifests WHERE node_id = ?',
			[nodeId],
		);
		return rows.length > 0 ? (JSON.parse(rows[0].manifest_json) as Manifest) : null;
	}

	async *localChanges(): AsyncIterable<LocalChange> {
		// ponytail: no producer yet — see the module doc.
	}

	/** Fetches every chunk of `plan` not already in the vault (via this
	 *  device's own native-scoped bearer, minted/cached by nativeToken.ts),
	 *  then records the manifest. Only Manifest is supported — DownloadPlan
	 *  carries no per-chunk shas to verify against (the symmetric restriction
	 *  to FolderMirror, which supports only DownloadPlan and throws on
	 *  Manifest). ponytail: wire a Range-based fetch here if a future sync
	 *  engine ever drives a secure space through this store. */
	async putLocal(nodeId: number, plan: Manifest | DownloadPlan): Promise<void> {
		if (!('chunks' in plan)) {
			throw new Error(
				'VaultStore.putLocal: DownloadPlan not supported — the viewer path always supplies a Manifest with known per-chunk shas',
			);
		}
		const bearer = await getNativeToken();
		for (const c of plan.chunks) {
			if (!(await this.hasChunk(c.sha256))) await this.fetchChunk(c, this.nativeChunkUrl(c.sha256), bearer);
		}
		await this.db.exec(APP, 'BEGIN', []);
		try {
			await this.db.exec(
				APP,
				`INSERT OR REPLACE INTO dc_manifests (node_id, manifest_json, pinned, updated_at)
				 VALUES (?, ?, COALESCE((SELECT pinned FROM dc_manifests WHERE node_id = ?), 0), ?)`,
				[nodeId, JSON.stringify(plan), nodeId, Date.now()],
			);
			await this.db.exec(APP, 'DELETE FROM dc_manifest_chunks WHERE node_id = ?', [nodeId]);
			for (const c of plan.chunks) {
				await this.db.exec(
					APP,
					'INSERT OR IGNORE INTO dc_manifest_chunks(node_id,sha256) VALUES (?,?)',
					[nodeId,c.sha256],
				);
			}
			await this.db.exec(APP, 'COMMIT', []);
		} catch (err) {
			await this.db.exec(APP, 'ROLLBACK', []).catch(() => {});
			throw err;
		}
	}

	/** Pin = durable offline availability: marks every chunk of `nodeId`'s
	 *  manifest LRU-exempt (`dc_chunks.pinned_at`) and prefetches anything
	 *  missing. Requires `putLocal`/an existing manifest row first. */
	async pin(nodeId: number): Promise<void> {
		const manifest = await this.readLocalManifest(nodeId);
		if (!manifest) throw new Error(`VaultStore.pin: no manifest recorded for node ${nodeId}`);
		const bearer = await getNativeToken();
		for (const c of manifest.chunks) {
			if (!(await this.hasChunk(c.sha256))) await this.fetchChunk(c, this.nativeChunkUrl(c.sha256), bearer);
		}
		if (manifest.chunks.length > 0) {
			const placeholders = manifest.chunks.map(() => '?').join(', ');
			await this.db.exec(APP, `UPDATE dc_chunks SET pinned_at = ? WHERE sha256 IN (${placeholders})`, [
				Date.now(),
				...manifest.chunks.map((c) => c.sha256),
			]);
		}
		await this.db.exec(APP, 'UPDATE dc_manifests SET pinned = 1 WHERE node_id = ?', [nodeId]);
	}

	/** Clears `pinned_at` for any chunk of `nodeId`'s manifest not referenced
	 *  by a still-pinned OTHER manifest. */
	async unpin(nodeId: number): Promise<void> {
		const manifest = await this.readLocalManifest(nodeId);
		await this.db.exec(APP, 'UPDATE dc_manifests SET pinned = 0 WHERE node_id = ?', [nodeId]);
		if (!manifest) return;
		for (const c of manifest.chunks) {
			if (!(await this.pinnedElsewhere(c.sha256, nodeId))) {
				await this.db.exec(APP, 'UPDATE dc_chunks SET pinned_at = NULL WHERE sha256 = ?', [c.sha256]);
			}
		}
	}

	private async pinnedElsewhere(sha256: string, excludeNodeId: number): Promise<boolean> {
		const rows = await this.db.query<{ present: number }>(
			APP,
			`SELECT 1 AS present FROM dc_manifest_chunks r
			 JOIN dc_manifests m ON m.node_id=r.node_id
			 WHERE r.sha256=? AND r.node_id!=? AND m.pinned=1 LIMIT 1`,
			[sha256,excludeNodeId],
		);
		return rows.length>0;
	}

	/** Drops `nodeId`'s manifest row, releases pins owned only by that manifest,
	 * and evicts every now-unreferenced chunk.  Pin state is a property of a
	 * live authorized manifest, not a reason to retain bytes after that
	 * manifest is deleted or revoked. */
	async remove(nodeId: number): Promise<void> {
		let manifest = await this.readLocalManifest(nodeId);
		if (manifest) {
			// Persist the purge intent in the same local transaction that removes
			// the authoritative manifest.  Native chunk deletion happens after the
			// commit and is idempotent; a crash therefore resumes from this queue
			// instead of forgetting which unreferenced chunks must be erased.
			await this.db.exec(APP, 'BEGIN', []);
			try {
				await this.db.exec(
					APP,
					`INSERT OR REPLACE INTO dc_purge_queue (node_id,manifest_json,updated_at)
					 VALUES (?,?,?)`,
					[nodeId, JSON.stringify(manifest), Date.now()],
				);
				await this.db.exec(APP, 'DELETE FROM dc_manifests WHERE node_id = ?', [nodeId]);
				await this.db.exec(APP, 'DELETE FROM dc_manifest_chunks WHERE node_id = ?', [nodeId]);
				await this.db.exec(APP, 'COMMIT', []);
			} catch (err) {
				await this.db.exec(APP, 'ROLLBACK', []).catch(() => {});
				throw err;
			}
		} else {
			manifest = await this.queuedPurgeManifest(nodeId);
		}
		if (!manifest) return;
		const victims: string[] = [];
		for (const c of manifest.chunks) {
			if (!(await this.pinnedElsewhere(c.sha256, nodeId))) {
				await this.db.exec(APP, 'UPDATE dc_chunks SET pinned_at = NULL WHERE sha256 = ?', [c.sha256]);
			}
			if (!(await this.referencedByAnyManifest(c.sha256)) && !(await this.chunkPinned(c.sha256))) {
				victims.push(c.sha256);
			}
		}
		if (victims.length) await this.drive.deleteChunks(victims);
		await this.db.exec(APP, 'DELETE FROM dc_purge_queue WHERE node_id = ?', [nodeId]);
	}

	async revoke(nodeId: number, _forceQuarantine: boolean): Promise<RevocationOutcome> {
		const present = (await this.readLocalManifest(nodeId)) != null || (await this.queuedPurgeManifest(nodeId)) != null;
		await this.remove(nodeId);
		return present ? 'purged' : 'absent';
	}

	private async queuedPurgeManifest(nodeId: number): Promise<Manifest | null> {
		const rows = await this.db.query<{ manifest_json: string }>(
			APP,
			' SELECT manifest_json FROM dc_purge_queue WHERE node_id = ?',
			[nodeId],
		);
		return rows.length > 0 ? (JSON.parse(rows[0].manifest_json) as Manifest) : null;
	}

	private async referencedByAnyManifest(sha256: string): Promise<boolean> {
		const rows = await this.db.query<{ present: number }>(
			APP,'SELECT 1 AS present FROM dc_manifest_chunks WHERE sha256=? LIMIT 1',[sha256],
		);
		return rows.length>0;
	}

	private async chunkPinned(sha256: string): Promise<boolean> {
		const rows = await this.db.query<{ pinned_at: number | null }>(
			APP,
			'SELECT pinned_at FROM dc_chunks WHERE sha256 = ?',
			[sha256],
		);
		return rows.length > 0 && rows[0].pinned_at != null;
	}

	/** LRU eviction against `vault_quota_mb`. Policy here; deletion native (§3.6). */
	async enforceQuota(): Promise<number> {
		const cap = this.quotaMb();
		if (cap == null) return 0;
		const rows = await this.db.query<{
			sha256: string;
			size: number;
			last_read: number | null;
			pinned_at: number | null;
		}>(APP, 'SELECT sha256, size, last_read, pinned_at FROM dc_chunks', []);
		let used = rows.reduce((s, r) => s + r.size, 0);
		const budget = cap * 1024 * 1024;
		if (used <= budget) return 0;
		const victims: string[] = [];
		for (const r of rows.filter((r) => r.pinned_at == null).sort((a, b) => (a.last_read ?? 0) - (b.last_read ?? 0))) {
			victims.push(r.sha256);
			used -= r.size;
			if (used <= budget) break;
		}
		return victims.length ? this.drive.deleteChunks(victims) : 0;
	}
}
