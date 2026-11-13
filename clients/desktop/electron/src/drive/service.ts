// service.ts — MirrorService: one FolderMirror + SyncEngine per selected
// space, sharing ONE SQLCipher 'drive' metadata store (schema.ts's dc_* tables
// are space_id-scoped, so one file serves every space on this device). Owns
// the auth story (C3/C14/C15 — see native/types.ts's DriveMirrorBridge doc):
// main has no server-origin cookie, so it authenticates with a short-lived
// bearer token the renderer mints and hands over via refreshToken, sliding it
// forward itself afterwards via POST /api/drive/native-token.
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import { DriveApiError, DriveHttp } from '../../../../../mailserver/webmail/src/lib/drive/sync/protocol.js';
import { applySchema, SqlMirrorIndex } from '../../../../../mailserver/webmail/src/lib/drive/sync/schema.js';
import { SyncEngine } from '../../../../../mailserver/webmail/src/lib/drive/sync/engine.js';
import { isOfficeEditPath } from '../../../../../mailserver/webmail/src/lib/drive/sync/names.js';
import type { DbLike, FetchLike, LocalChange, LockRow } from '../../../../../mailserver/webmail/src/lib/drive/sync/types.js';
import type {
	DriveMirrorSpaceStatus,
	DriveMirrorStatus,
} from '../../../../../mailserver/webmail/src/lib/native/types.js';
import type { NativeBinding } from '../native.js';
import { appKeyDbFile } from '../handlers/db.js';
import { FolderMirror } from './mirror.js';
import type { HandlerMap } from '../handlers/db.js';
import type { LocalOfficeApp, LocalOfficeAppId, LocalOfficeLauncher } from '../office/local.js';

// ── tray strings (main has no SPA i18n runtime) ──────────────────────────────

export const TRAY_STRINGS = {
	en: {
		syncing: 'Drive: syncing…',
		idle: 'Drive: up to date',
		paused: 'Drive: paused',
		error: 'Drive: sync issue',
		open: 'Open setjoin Drive folder',
		pause: 'Pause sync',
		resume: 'Resume sync',
		quit: 'Quit SetJoin',
	},
	de: {
		syncing: 'Drive: synchronisiert…',
		idle: 'Drive: aktuell',
		paused: 'Drive: pausiert',
		error: 'Drive: Sync-Problem',
		open: 'setjoin-Drive-Ordner öffnen',
		pause: 'Sync pausieren',
		resume: 'Sync fortsetzen',
		quit: 'SetJoin beenden',
	},
	zh: {
		syncing: 'Drive：正在同步…',
		idle: 'Drive：已是最新',
		paused: 'Drive：已暂停',
		error: 'Drive：同步问题',
		open: '打开 setjoin Drive 文件夹',
		pause: '暂停同步',
		resume: '继续同步',
		quit: '退出 SetJoin',
	},
} as const;
export type TrayLocale = keyof typeof TRAY_STRINGS;

export function normalizeLocale(locale: string): TrayLocale {
	const prefix = locale.slice(0, 2).toLowerCase();
	return prefix === 'de' || prefix === 'zh' ? (prefix as TrayLocale) : 'en';
}

// ── wiring surface ────────────────────────────────────────────────────────

export interface MirrorServiceDeps {
	native: NativeBinding;
	userDataDir: string;
	/** Raw, un-authenticated fetch (Node's global fetch / Electron's net.fetch).
	 *  MirrorService wraps it with the current bearer token per request. */
	fetchFn: FetchLike;
	mirrorBase: string;
	deviceLabel: string;
	locale: string;
	pollMs?: number;
	/** Renewal margin before the token's expiresAt (default 30 min). */
	renewMarginMs?: number;
	openPath: (p: string) => Promise<void> | void;
	localOffice?: LocalOfficeLauncher;
	onStateChange?: (s: DriveMirrorStatus) => void;
}

interface SpaceRuntime {
	spaceId: number;
	name: string;
	root: string;
	excludes: string[];
	mirror: FolderMirror;
	engine: SyncEngine;
	http: DriveHttp;
	state: DriveMirrorSpaceStatus['state'];
	lastSyncMs: number | null;
	aclMode: 'legacy' | 'shadow' | 'acl';
	unmanagedAclRiskAccepted: boolean;
}

interface BlockedSpace {
	spaceId: number;
	name: string;
}

interface MirrorSpaceConfig {
	spaceId: number;
	excludes: string[];
	acceptUnmanagedAclRisk?: boolean;
}

/** LR-10-adjacent: the mirror's auto-soft-checkout re-fires at most once per
 *  node per this window (a human editor renews every 5 min; a mirror-detected
 *  office edit is coarser -- it only needs to keep presence roughly current,
 *  not race a save). */
const SOFT_LOCK_DEDUPE_MS = 10 * 60 * 1000;

function nativeDbLike(native: NativeBinding): DbLike {
	return {
		exec: async (sql, params = []) => native.dbExec('drive', sql, JSON.stringify(params)),
		query: async (sql, params = []) => JSON.parse(native.dbQuery('drive', sql, JSON.stringify(params))) as never,
	};
}

/** Cross-platform-conservative folder name (strips characters invalid on
 *  Windows even when running elsewhere — a single safe default beats a
 *  per-OS branch here). Ponytail: no CI-dedup against sibling space folders
 *  yet — two spaces sanitizing to the same name is an unhandled edge case. */
function sanitizeFolderName(name: string): string {
	const cleaned = name.replace(/[<>:"/\\|?*\x00-\x1f]/g, '_').trim();
	return cleaned || 'space';
}

export class MirrorService {
	private index: SqlMirrorIndex | null = null;
	private vaultLocked = false;
	private token: string | null = null;
	private tokenExpiresAt: number | null = null;
	private serverOrigin = '';
	private pendingSpaces: MirrorSpaceConfig[] = [];
	private spaces = new Map<number, SpaceRuntime>();
	private blockedSpaces = new Map<number, BlockedSpace>();
	private paused = false;
	private pollTimer: ReturnType<typeof setInterval> | null = null;
	/** LR-6: absolute paths this device has forced OS-read-only for a
	 *  hard-locked-by-another-user file. Idempotent chmod + the restore set
	 *  for stop() (a dead mirror must not strand read-only files). */
	private readOnlyApplied = new Set<string>();
	/** Task 16 auto-soft-checkout dedupe: nodeId -> last-fired wall-clock ms. */
	private lastSoftLockAtMs = new Map<number, number>();

	constructor(private deps: MirrorServiceDeps) {}

	// ── bridge-facing API ──────────────────────────────────────────────────

	async configure(cfg: { serverOrigin: string; spaces: MirrorSpaceConfig[] }): Promise<void> {
		this.serverOrigin = cfg.serverOrigin;
		this.pendingSpaces = cfg.spaces;
		if (!(await this.ensureReady())) return; // vault-locked -- nothing else to do until unlocked
		await this.reconcileSpaces();
		this.startPollLoop();
	}

	async refreshToken(token: string, expiresAt: string): Promise<void> {
		this.token = token;
		this.tokenExpiresAt = Date.parse(expiresAt);
		if (await this.ensureReady()) {
			await this.reconcileSpaces();
			this.startPollLoop();
		}
	}

	async setPaused(paused: boolean): Promise<void> {
		this.paused = paused;
		this.notify();
	}

	async resync(spaceId?: number): Promise<void> {
		if (spaceId != null && !this.spaces.has(spaceId)) {
			throw new Error(`resync: unknown space ${spaceId}`);
		}
		const targets = spaceId != null ? [this.spaces.get(spaceId) as SpaceRuntime] : [...this.spaces.values()];
		for (const rt of targets) {
			await rt.mirror.verify();
			await this.runPass(rt);
		}
	}

	async openRoot(spaceId: number): Promise<void> {
		const rt = this.spaces.get(spaceId);
		if (rt) await this.deps.openPath(rt.root);
	}

	async localOfficeChoices(): Promise<LocalOfficeApp[]> {
		return this.deps.localOffice?.available() ?? [];
	}

	async openLocalOffice(spaceId: number, nodeId: number, appId: LocalOfficeAppId): Promise<void> {
		const rt = this.spaces.get(spaceId);
		if (!rt || !this.index) throw new Error('office-local: space is not mirrored');
		const mirror = await this.index.getMirror(nodeId);
		if (!mirror || mirror.spaceId !== spaceId || !isOfficeEditPath(mirror.relPath)) {
			throw new Error('office-local: file is not an editable mirrored Office file');
		}
		const absolute = path.resolve(rt.root, mirror.relPath);
		const relative = path.relative(rt.root, absolute);
		if (relative === '' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
			throw new Error('office-local: resolved path escapes the mirror root');
		}
		const stat = await fsp.lstat(absolute);
		if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('office-local: path is not a regular file');
		if (!this.token) throw new Error('office-local: authorization is unavailable');
		const auth = await this.deps.fetchFn(
			`${this.serverOrigin}/api/drive/files/${nodeId}/office/local-open`,
			{
				method: 'POST',
				headers: { Authorization: `Bearer ${this.token}`, 'Content-Type': 'application/json' },
				body: JSON.stringify({ appId, deviceId: this.deps.deviceLabel }),
			},
		);
		if (!auth.ok) throw new Error(`office-local: authorization failed (${auth.status})`);
		if (!this.deps.localOffice) throw new Error('office-local: launcher is unavailable');
		await this.deps.localOffice.open(appId, absolute);
	}

	async status(): Promise<DriveMirrorStatus> {
		if (this.vaultLocked) {
			return {
				running: false,
				paused: this.paused,
				perSpace: this.pendingSpaces.map((s) => ({
					spaceId: s.spaceId,
					name: `space-${s.spaceId}`,
					state: 'vault-locked' as const,
					lastSyncMs: null,
					pendingUploads: 0,
					issues: 0,
				})),
				issues: [],
			};
		}
		const perSpace: DriveMirrorSpaceStatus[] = [];
		const issues: DriveMirrorStatus['issues'] = [];
		for (const rt of this.spaces.values()) {
			const due = this.index ? await this.index.due(Number.MAX_SAFE_INTEGER, 10_000) : [];
			const pendingUploads = due.filter((r) => r.spaceId === rt.spaceId).length;
			const spaceIssues = this.index ? await this.index.issues(rt.spaceId) : [];
			perSpace.push({
				spaceId: rt.spaceId,
				name: rt.name,
				state: rt.state,
				lastSyncMs: rt.lastSyncMs,
				pendingUploads,
				issues: spaceIssues.length,
				...(rt.aclMode === 'acl' ? {
					aclMode: 'acl' as const,
					unmanagedAclRiskAccepted: rt.unmanagedAclRiskAccepted,
				} : {}),
			});
			issues.push(...spaceIssues);
		}
		for (const blocked of this.blockedSpaces.values()) {
			perSpace.push({
				spaceId: blocked.spaceId,
				name: blocked.name,
				state: 'policy-blocked',
				lastSyncMs: null,
				pendingUploads: 0,
				issues: 0,
				aclMode: 'acl',
				unmanagedAclRiskAccepted: false,
			});
		}
		// A space requested but not yet resolved (waiting on a first token) is
		// reported honestly instead of silently missing from the list.
		for (const cfg of this.pendingSpaces) {
			if (this.spaces.has(cfg.spaceId) || this.blockedSpaces.has(cfg.spaceId)) continue;
			perSpace.push({
				spaceId: cfg.spaceId,
				name: `space-${cfg.spaceId}`,
				state: 'auth-expired',
				lastSyncMs: null,
				pendingUploads: 0,
				issues: 0,
			});
		}
		return { running: this.pollTimer != null && !this.paused, paused: this.paused, perSpace, issues };
	}

	// ── lifecycle ────────────────────────────────────────────────────────────

	async stop(): Promise<void> {
		if (this.pollTimer) clearInterval(this.pollTimer);
		this.pollTimer = null;
		for (const rt of this.spaces.values()) await rt.mirror.stop();
		for (const abs of this.readOnlyApplied) {
			await fsp.chmod(abs, 0o644).catch(() => {}); // best-effort -- the process is shutting down regardless
		}
		this.readOnlyApplied.clear();
	}

	isRunning(): boolean {
		return this.pollTimer != null && !this.paused;
	}

	// ── internals ────────────────────────────────────────────────────────────

	private async ensureReady(): Promise<boolean> {
		if (this.index) return true;
		try {
			const dbPath = path.join(this.deps.userDataDir, appKeyDbFile('drive'));
			this.deps.native.dbOpen(dbPath, 'drive', 'standard');
			const db = nativeDbLike(this.deps.native);
			await applySchema(db);
			this.index = new SqlMirrorIndex(db);
			return true;
		} catch {
			this.vaultLocked = true;
			return false;
		}
	}

	private makeHttp(): DriveHttp {
		const fetchFn: FetchLike = async (input, init) => {
			if (!this.token) throw new Error('drive: no auth token (waiting on refreshToken)');
			return this.deps.fetchFn(input, {
				...init,
				headers: { ...(init?.headers ?? {}), Authorization: `Bearer ${this.token}` },
			});
		};
		return new DriveHttp(fetchFn, `${this.serverOrigin}/api/drive`);
	}

	private async reconcileSpaces(): Promise<void> {
		if (!this.index) return;
		const wanted = new Set(this.pendingSpaces.map((s) => s.spaceId));
		for (const [id, rt] of this.spaces) {
			if (!wanted.has(id)) {
				await rt.mirror.stop();
				this.spaces.delete(id); // files stay on disk -- un-mirroring never deletes
			} else {
				rt.excludes = this.pendingSpaces.find((s) => s.spaceId === id)?.excludes ?? rt.excludes;
			}
		}
		for (const id of this.blockedSpaces.keys()) {
			if (!wanted.has(id)) this.blockedSpaces.delete(id);
		}
		if (!this.token) return; // can't resolve space names / auth engines yet

		const probe = this.makeHttp();
		let remote: Array<{ id: number; name: string; aclMode: 'legacy' | 'shadow' | 'acl' }>;
		try {
			remote = await probe.spaces();
		} catch {
			return; // transient -- next poll/refreshToken retries
		}
		const remoteById = new Map(remote.map((s) => [s.id, s]));

		for (const cfg of this.pendingSpaces) {
			const remoteSpace = remoteById.get(cfg.spaceId);
			const name = remoteSpace?.name ?? `space-${cfg.spaceId}`;
			if (remoteSpace?.aclMode === 'acl' && cfg.acceptUnmanagedAclRisk !== true) {
				const active = this.spaces.get(cfg.spaceId);
				if (active) {
					await active.mirror.stop();
					this.spaces.delete(cfg.spaceId);
				}
				this.blockedSpaces.set(cfg.spaceId, { spaceId: cfg.spaceId, name });
				continue;
			}
			this.blockedSpaces.delete(cfg.spaceId);
			if (this.spaces.has(cfg.spaceId)) continue;
			const root = path.join(this.deps.mirrorBase, sanitizeFolderName(name));
			await fsp.mkdir(root, { recursive: true });
			const http = this.makeHttp();
			const mirror = new FolderMirror({ root, spaceId: cfg.spaceId, http, index: this.index });
			await mirror.start();
			const excludes = cfg.excludes;
			const engine = new SyncEngine({
				http,
				index: this.index,
				store: mirror,
				spaceId: cfg.spaceId,
				deviceLabel: this.deps.deviceLabel,
				isExcluded: (relPath) => excludes.some((ex) => relPath === ex || relPath.startsWith(`${ex}/`)),
				todayYmd: () => new Date().toISOString().slice(0, 10),
				now: () => Date.now(),
			});
			this.spaces.set(cfg.spaceId, {
				spaceId: cfg.spaceId,
				name,
				root,
				excludes,
				mirror,
				engine,
				http,
				state: 'idle',
				lastSyncMs: null,
				aclMode: remoteSpace?.aclMode ?? 'legacy',
				unmanagedAclRiskAccepted: cfg.acceptUnmanagedAclRisk === true,
			});
		}
	}

	private startPollLoop(): void {
		if (this.pollTimer) return;
		this.pollTimer = setInterval(() => void this.pollOnce(), this.deps.pollMs ?? 30_000);
		void this.pollOnce();
	}

	private async pollOnce(): Promise<void> {
		if (this.paused) return;
		await this.maybeRenewToken();
		for (const rt of this.spaces.values()) {
			await this.runPass(rt);
		}
	}

	/** A thrown pass marks the space 'error' and keeps the loop alive — the
	 *  next tick retries (spec: a transient failure must not wedge sync). */
	private async runPass(rt: SpaceRuntime): Promise<void> {
		if (!this.token) {
			rt.state = 'auth-expired';
			this.notify();
			return;
		}
		rt.state = 'syncing';
		this.notify();
		try {
			const changesBeforeScan = rt.mirror.drainLocalChanges() as LocalChange[];
			for (const c of changesBeforeScan) await rt.engine.onLocalChange(c);
			await rt.mirror.scanLocal();
			const changesAfterScan = rt.mirror.drainLocalChanges() as LocalChange[];
			for (const c of changesAfterScan) await rt.engine.onLocalChange(c);
			await this.maybeSoftCheckout(rt, [...changesBeforeScan, ...changesAfterScan]);
			await rt.engine.syncOnce();
			await this.applyLockChmods(rt);
			rt.state = 'idle';
			rt.lastSyncMs = Date.now();
		} catch (err) {
			if (err instanceof DriveApiError && err.status === 401) {
				rt.state = 'auth-expired';
				this.token = null;
			} else {
				rt.state = 'error';
			}
		}
		this.notify();
	}

	/** LR-6: the poll cycle learns hard locks from the live per-space lock list
	 *  (locks are deliberately not journal ops) and mirrors them as the OS
	 *  read-only bit on every synced path this device knows.
	 *  ponytail: chmod is the whole cross-platform story (maps to
	 *  FILE_ATTRIBUTE_READONLY on Windows); ACL-level enforcement is not
	 *  attempted — the server rejects the save regardless (this bit is UX,
	 *  not the enforcement boundary), so a locally-dirty file is chmod'd too. */
	private async applyLockChmods(rt: SpaceRuntime): Promise<void> {
		if (!this.index) return;
		let locks: LockRow[];
		try {
			locks = await rt.http.spaceLocks(rt.spaceId);
		} catch {
			return; // transient -- next pass retries, never wedges sync over a lock-list failure
		}
		const self = this.selfUserId();
		const hardLocked = new Set<string>();
		for (const lock of locks) {
			if (lock.mode !== 'hard' || lock.holderId === self) continue; // soft: tray-only; self: not "another user"
			const mirror = await this.index.getMirror(lock.nodeId);
			if (!mirror) continue; // not synced on this device -- nothing to chmod
			// Defense-in-depth containment (D-CLIENTS-DESKTOP-008): every absPath
			// sink resolves inside rt.root, matching revoke()/openLocalOffice().
			// A poisoned mirror row (relPath escaping the root) is skipped
			// fail-closed -- never chmod'd outside the mirror.
			const absolute = path.resolve(rt.root, mirror.relPath);
			const relative = path.relative(rt.root, absolute);
			if (relative === '' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
				continue; // poisoned row: never chmod outside the mirror root
			}
			hardLocked.add(absolute);
		}
		for (const abs of hardLocked) {
			if (this.readOnlyApplied.has(abs)) continue; // idempotent
			try {
				await fsp.chmod(abs, 0o444);
				this.readOnlyApplied.add(abs);
			} catch {
				/* not on disk yet (still downloading) -- next pass retries */
			}
		}
		for (const abs of [...this.readOnlyApplied]) {
			if (hardLocked.has(abs) || !abs.startsWith(rt.root + path.sep)) continue; // only this space's own paths
			await fsp.chmod(abs, 0o644).catch(() => {}); // already gone -- nothing to restore
			this.readOnlyApplied.delete(abs);
		}
	}

	/** Decodes the `uid` claim off the current bearer JWT for chmod
	 *  self-exclusion. Informational only — the server enforces the lock
	 *  regardless (LR-6), so a malformed/foreign token just means every hard
	 *  lock chmods (the safe default: never silently skip a real foreign
	 *  lock because self-identity was unknown). */
	private selfUserId(): number | null {
		if (!this.token) return null;
		try {
			const payload = this.token.split('.')[1];
			if (!payload) return null;
			const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as { uid?: unknown };
			return typeof claims.uid === 'number' ? claims.uid : null;
		} catch {
			return null;
		}
	}

	/** Auto-soft-checkout (§5.4's default courtesy for office types): a
	 *  detected local upsert on an OFFICE_EDIT_EXTS path fires ONE
	 *  best-effort soft lock PUT, deduped per node for SOFT_LOCK_DEDUPE_MS.
	 *  Failures are logged, never surfaced as a dc_issues row -- this is
	 *  presence UX layered on top of the always-on optimistic base-check, not
	 *  a save (Task 16 step 1.3). */
	private async maybeSoftCheckout(rt: SpaceRuntime, changes: LocalChange[]): Promise<void> {
		if (!this.index) return;
		const now = Date.now();
		for (const c of changes) {
			if (c.kind !== 'upsert' || !isOfficeEditPath(c.relPath)) continue;
			const mirror = await this.index.findByPathCI(rt.spaceId, c.relPath);
			if (!mirror) continue; // brand-new file -- no node yet; a later pass (post-create) catches it
			const last = this.lastSoftLockAtMs.get(mirror.nodeId) ?? 0;
			if (now - last < SOFT_LOCK_DEDUPE_MS) continue;
			this.lastSoftLockAtMs.set(mirror.nodeId, now);
			try {
				await rt.http.lockFile(mirror.nodeId, { mode: 'soft', deviceLabel: this.deps.deviceLabel });
			} catch (err) {
				console.error('drive: auto-soft-checkout failed', mirror.nodeId, err);
			}
		}
	}

	/** C15: slide the token forward via POST /api/drive/native-token before it
	 *  expires, using the still-valid current token as Bearer — no renderer
	 *  needed while the session stays valid. A failed renewal (session
	 *  revoked / token fully lapsed) drops the token; the next runPass then
	 *  surfaces 'auth-expired' instead of retry-looping. */
	private async maybeRenewToken(): Promise<void> {
		if (!this.token || this.tokenExpiresAt == null) return;
		const margin = this.deps.renewMarginMs ?? 30 * 60 * 1000;
		if (Date.now() < this.tokenExpiresAt - margin) return;
		try {
			const res = await this.deps.fetchFn(`${this.serverOrigin}/api/drive/native-token`, {
				method: 'POST',
				headers: { Authorization: `Bearer ${this.token}` },
			});
			if (!res.ok) throw new Error(`native-token renewal failed: ${res.status}`);
			const body = (await res.json()) as { token: string; expiresAt: string };
			this.token = body.token;
			this.tokenExpiresAt = Date.parse(body.expiresAt);
		} catch {
			this.token = null;
			this.tokenExpiresAt = null;
		}
	}

	private notify(): void {
		if (!this.deps.onStateChange) return;
		void this.status().then((s) => this.deps.onStateChange?.(s));
	}
}

/** IPC handler map (registered through the ONE origin-gated `registerHandlers`
 *  wrapper in main.ts — see ipc.ts). Mirrors the `makeDbHandlers` shape. */
export function makeDriveMirrorHandlers(service: MirrorService): HandlerMap {
	return {
		drive_mirror_status: () => service.status(),
		drive_mirror_configure: (cfg: unknown) =>
			service.configure(cfg as { serverOrigin: string; spaces: Array<{ spaceId: number; excludes: string[] }> }),
		drive_mirror_refresh_token: (token: unknown, expiresAt: unknown) =>
			service.refreshToken(String(token), String(expiresAt)),
		drive_mirror_set_paused: (paused: unknown) => service.setPaused(Boolean(paused)),
		drive_mirror_resync: (spaceId: unknown) => service.resync(spaceId == null ? undefined : Number(spaceId)),
		drive_mirror_open_root: (spaceId: unknown) => service.openRoot(Number(spaceId)),
		drive_mirror_office_choices: () => service.localOfficeChoices(),
		drive_mirror_open_office: (spaceId: unknown, nodeId: unknown, appId: unknown) =>
			service.openLocalOffice(Number(spaceId), Number(nodeId), String(appId) as LocalOfficeAppId),
	};
}
