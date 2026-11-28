// service.ts — MirrorService: one FolderMirror + SyncEngine per selected
// space, sharing ONE SQLCipher 'drive' metadata store (schema.ts's dc_* tables
// are space_id-scoped, so one file serves every space on this device). Owns
// the auth story (C3/C14/C15 — see native/types.ts's DriveMirrorBridge doc):
// main has no server-origin cookie, so it authenticates with a short-lived
// bearer token the renderer mints and hands over via refreshToken, sliding it
// forward itself afterwards via POST /api/drive/native-token.
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import { DriveApiError, DriveHttp } from '../../../../../webmail/src/lib/drive/sync/protocol.js';
import { applySchema, SqlMirrorIndex } from '../../../../../webmail/src/lib/drive/sync/schema.js';
import { SyncEngine } from '../../../../../webmail/src/lib/drive/sync/engine.js';
import { isOfficeEditPath } from '../../../../../webmail/src/lib/drive/sync/names.js';
import type { DbLike, FetchLike, LocalChange, LockRow } from '../../../../../webmail/src/lib/drive/sync/types.js';
import type {
	DriveMirrorSpaceStatus,
	DriveMirrorStatus,
} from '../../../../../webmail/src/lib/native/types.js';
import { SyncCoordinator } from '../../../../../webmail/src/lib/sync/core/coordinator.js';
import type { ScopeRevokedEvent, StepOutcome, SyncStepContext } from '../../../../../webmail/src/lib/sync/core/types.js';
import {
	validateScopeRevoked,
	validateSyncWakeup,
} from '../../../../../webmail/src/lib/sync/core/validate.js';
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
	/** Safety-net poll interval while an active renderer wakeup bridge is connected (default 5 min). */
	safetyNetPollMs?: number;
	/** Per-space minimum interval (ms) between untrusted renderer wakeup hints (default 250ms). */
	wakeupMinIntervalMs?: number;
	/** Per-space minimum interval (ms) between untrusted renderer scope_revoked hints (default 500ms). */
	revokeMinIntervalMs?: number;
	/** Minimum interval (ms) between renderer disconnect-induced reconnect catch-ups (default 1000ms). */
	reconnectMinIntervalMs?: number;
	/** Retry interval (ms) for draining `'busy'` pending revocations after a revoked space detaches (default 5000ms). */
	busyRevocationRetryMs?: number;
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
	lastPolledAtMs: number;
	verifyBeforeNextPass: boolean;
	manualResyncRequested: boolean;
	pendingFullRevocationVerify: ScopeRevokedEvent | null;
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
	/** Explicit running state independent of whether pollTimer is temporarily
	 *  slowed/suspended while renderer wakeup bridge is connected (#555). */
	private running = false;
	private wakeupConnectedAll = false;
	private wakeupConnectedSpaces = new Set<number>();
	private pollTimer: ReturnType<typeof setInterval> | null = null;
	private activePollIntervalMs: number | null = null;
	/** Global concurrency = 1 serializes shared SQLCipher `drive` store transactions across spaces (#555). */
	private syncCoordinator = new SyncCoordinator({ maxGlobalConcurrency: 1 });
	private adapterUnsubs = new Map<number, () => void>();
	/** Untrusted renderer IPC rate-limiting & burst accounting (#555). */
	private lastWakeupAtMs = new Map<number, number>();
	private lastRevokeAtMs = new Map<string, number>();
	private lastReconnectAtMs = 0;
	private globalNudgeWindowStartMs = 0;
	private globalNudgeCount = 0;
	/** Detached revoked spaces that still have `'busy'` open files awaiting purge retry (#555 4d). */
	private busyRetryTimers = new Map<number, ReturnType<typeof setTimeout>>();
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
		if (!(await this.ensureReady(true))) return; // vault-locked -- nothing else to do until unlocked
		await this.reconcileSpaces();
		this.startPollLoop();
	}

	async refreshToken(token: string, expiresAt: string): Promise<void> {
		this.token = token;
		this.tokenExpiresAt = Date.parse(expiresAt);
		if (await this.ensureReady(true)) {
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
		// Route manual resync through SyncCoordinator so it respects single-flight
		// coalescing, shared-DB serialization, and revocation fencing (#555).
		for (const rt of targets) {
			rt.verifyBeforeNextPass = true;
			rt.manualResyncRequested = true;
			this.syncCoordinator.trigger({ kind: 'space', id: String(rt.spaceId) }, { immediate: true });
		}
		await this.syncCoordinator.flush(spaceId != null ? { kind: 'space', id: String(spaceId) } : undefined);
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
		return { running: this.running && !this.paused, paused: this.paused, perSpace, issues };
	}

	// ── wakeup bridge (untrusted renderer IPC hints, #555) ───────────────────

	private allowGlobalNudge(now: number): boolean {
		if (now - this.globalNudgeWindowStartMs >= 1_000) {
			this.globalNudgeWindowStartMs = now;
			this.globalNudgeCount = 0;
		}
		if (this.globalNudgeCount >= 32) return false;
		this.globalNudgeCount += 1;
		return true;
	}

	private isSpaceWakeupConnected(spaceId: number): boolean {
		return this.wakeupConnectedAll || this.wakeupConnectedSpaces.has(spaceId);
	}

	private allSpacesWakeupCovered(): boolean {
		if (this.spaces.size === 0) return false;
		if (this.wakeupConnectedAll) return true;
		for (const id of this.spaces.keys()) {
			if (!this.wakeupConnectedSpaces.has(id)) return false;
		}
		return true;
	}

	/**
	 * Marks whether an active renderer wakeup bridge is connected (globally when
	 * `spaceId` is omitted, or scoped to a single viewed space when `spaceId` is
	 * passed). Only spaces actively covered by a connected renderer WS slow to
	 * `safetyNetPollMs`; sibling mirrored spaces keep the 30s main-process poll.
	 * On disconnect / window close / render-process-gone, fast polling is restored
	 * immediately with rate-limited reconnect catch-up. `isRunning()` stays `true`.
	 */
	setWakeupConnected(connected: boolean, spaceId?: number): void {
		let changed = false;
		let disconnectedScope: number | null | 'all' = null;
		if (spaceId !== undefined) {
			if (connected) {
				const rt = this.spaces.get(spaceId);
				if (rt && !this.wakeupConnectedSpaces.has(spaceId)) {
					this.wakeupConnectedSpaces.add(spaceId);
					if (rt.lastPolledAtMs === 0) rt.lastPolledAtMs = Date.now();
					changed = true;
				}
			} else if (this.wakeupConnectedSpaces.delete(spaceId)) {
				changed = true;
				disconnectedScope = spaceId;
			}
		} else if (connected) {
			if (!this.wakeupConnectedAll) {
				this.wakeupConnectedAll = true;
				const now = Date.now();
				for (const rt of this.spaces.values()) {
					if (rt.lastPolledAtMs === 0) rt.lastPolledAtMs = now;
				}
				changed = true;
			}
		} else if (this.wakeupConnectedAll || this.wakeupConnectedSpaces.size > 0) {
			this.wakeupConnectedAll = false;
			this.wakeupConnectedSpaces.clear();
			changed = true;
			disconnectedScope = 'all';
		}

		if (!changed) return;
		if (this.running) {
			this.reschedulePollTimer();
			if (disconnectedScope !== null && !this.paused) {
				const now = Date.now();
				const minGap = this.deps.reconnectMinIntervalMs ?? 1_000;
				if (now - this.lastReconnectAtMs >= minGap) {
					this.lastReconnectAtMs = now;
					if (disconnectedScope === 'all') {
						this.syncCoordinator.handleReconnect();
					} else {
						this.syncCoordinator.trigger(
							{ kind: 'space', id: String(disconnectedScope) },
							{ immediate: true },
						);
					}
				}
			}
		}
	}

	isWakeupConnected(spaceId?: number): boolean {
		if (spaceId !== undefined) return this.isSpaceWakeupConnected(spaceId);
		return this.wakeupConnectedAll || this.wakeupConnectedSpaces.size > 0;
	}

	/**
	 * Untrusted renderer IPC wakeup nudge (#555): validated fail-closed via
	 * `core/validate.ts` and rate-limited per space + globally. Never trusts
	 * data payloads — solely nudges MirrorService to query the authenticated
	 * server using its own main-process bearer token.
	 */
	notifyWakeup(rawHint: unknown): boolean {
		if (this.paused || !this.running) return false;
		const wakeup = validateSyncWakeup(rawHint);
		if (wakeup?.scopeKind !== 'space') return false;
		const spaceId = Number(wakeup.scopeId);
		if (!Number.isSafeInteger(spaceId) || !this.spaces.has(spaceId)) return false;
		const now = Date.now();
		const minGap = this.deps.wakeupMinIntervalMs ?? 250;
		const last = this.lastWakeupAtMs.get(spaceId) ?? 0;
		if (now - last < minGap || !this.allowGlobalNudge(now)) return false;
		this.lastWakeupAtMs.set(spaceId, now);
		this.syncCoordinator.handleWakeup(wakeup);
		return true;
	}

	/**
	 * Untrusted renderer IPC scope_revoked nudge (#555): validated fail-closed
	 * and rate-limited. NEVER trusts renderer IPC as authority to delete mirrored
	 * files — always verifies access against the authenticated server using
	 * MirrorService's own main-process native token first, purging/detaching a
	 * full space ONLY if the server confirms access loss (HTTP 403/404 or space
	 * absent from `/spaces`).
	 */
	async notifyScopeRevoked(rawHint: unknown): Promise<boolean> {
		const evt = validateScopeRevoked(rawHint);
		if (evt?.scopeKind !== 'space') return false;
		const spaceId = Number(evt.scopeId);
		const rt = Number.isSafeInteger(spaceId) ? this.spaces.get(spaceId) : undefined;
		if (!rt) return false;
		const now = Date.now();
		const minGap = this.deps.revokeMinIntervalMs ?? 500;
		const rateKey = `${spaceId}:${evt.subtreeAnchorId ?? '*'}`;
		const last = this.lastRevokeAtMs.get(rateKey) ?? 0;
		if (now - last < minGap || !this.allowGlobalNudge(now)) return false;
		this.lastRevokeAtMs.set(rateKey, now);

		await this.maybeRenewToken();
		if (!this.token) {
			// Cannot confirm revocation with the authenticated server without a token;
			// never delete local files on an unverified renderer hint.
			return true;
		}

		if (evt.subtreeAnchorId !== undefined) {
			// Subtree revocation: purgeScopeCache runs server-authoritative
			// reconcileVisibility() via main's bearer token (never trusts local/renderer closure).
			await this.syncCoordinator.handleScopeRevoked(evt);
			return true;
		}

		// Full-space revocation hint: route server-authoritative confirmation through
		// SyncCoordinator's serialized single-flight loop so confirmFullSpaceRevocation()
		// NEVER runs concurrently with runPass() or overlapping SQLite transactions (#555).
		rt.pendingFullRevocationVerify = evt;
		this.syncCoordinator.trigger({ kind: 'space', id: String(rt.spaceId) }, { immediate: true });
		await this.syncCoordinator.flush({ kind: 'space', id: String(rt.spaceId) });
		return true;
	}

	private async confirmFullSpaceRevocation(rt: SpaceRuntime): Promise<boolean> {
		try {
			await rt.engine.reconcileVisibility();
		} catch (err) {
			// Only explicit HTTP 403 proves access revocation here — HTTP 404 can
			// arise from a transient feature-flag lookup failure (drive_core.rs:85)
			// and must NOT delete local mirrored files unless /spaces also returns
			// 200 OK omitting this spaceId (#555).
			if (err instanceof DriveApiError && err.status === 403) {
				return true;
			}
			if (!(err instanceof DriveApiError && err.status === 404)) {
				// Transient network/5xx/401: fail safe — do NOT delete user files.
				return false;
			}
		}
		// Visibility probe returned 200 OK or ambiguous 404; check authoritative
		// membership via GET /spaces. Only 403 or a 200 OK list omitting rt.spaceId
		// confirms revocation.
		try {
			const remoteSpaces = await rt.http.spaces();
			return !remoteSpaces.some((s) => s.id === rt.spaceId);
		} catch (err) {
			if (err instanceof DriveApiError && err.status === 403) {
				return true;
			}
			return false;
		}
	}

	/** Exposed for tests to await coordinator-scheduled wakeup passes. */
	async flushSyncCoordinator(): Promise<void> {
		await this.syncCoordinator.flush();
	}

	// ── lifecycle ────────────────────────────────────────────────────────────

	async stop(): Promise<void> {
		this.running = false;
		this.wakeupConnectedAll = false;
		this.wakeupConnectedSpaces.clear();
		if (this.pollTimer) clearInterval(this.pollTimer);
		this.pollTimer = null;
		this.activePollIntervalMs = null;
		for (const timer of this.busyRetryTimers.values()) clearTimeout(timer);
		this.busyRetryTimers.clear();
		for (const unsub of this.adapterUnsubs.values()) unsub();
		this.adapterUnsubs.clear();
		this.syncCoordinator.dispose();
		for (const rt of this.spaces.values()) await rt.mirror.stop();
		for (const abs of this.readOnlyApplied) {
			await fsp.chmod(abs, 0o644).catch(() => {}); // best-effort -- the process is shutting down regardless
		}
		this.readOnlyApplied.clear();
	}

	isRunning(): boolean {
		return this.running && !this.paused;
	}

	// ── internals ────────────────────────────────────────────────────────────

	private async ensureReady(recheckSchema = false): Promise<boolean> {
		if (this.index && !recheckSchema) return true;
		try {
			const dbPath = path.join(this.deps.userDataDir, appKeyDbFile('drive'));
			this.deps.native.dbOpen(dbPath, 'drive', 'standard');
			const db = nativeDbLike(this.deps.native);
			await applySchema(db);
			if (!this.index) {
				this.index = new SqlMirrorIndex(db);
			}
			this.vaultLocked = false;
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
				this.adapterUnsubs.get(id)?.();
				this.adapterUnsubs.delete(id);
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
					this.adapterUnsubs.get(cfg.spaceId)?.();
					this.adapterUnsubs.delete(cfg.spaceId);
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
			const runtime: SpaceRuntime = {
				spaceId: cfg.spaceId,
				name,
				root,
				excludes,
				mirror,
				engine,
				http,
				state: 'idle',
				lastSyncMs: null,
				lastPolledAtMs: 0,
				verifyBeforeNextPass: false,
				manualResyncRequested: false,
				pendingFullRevocationVerify: null,
				aclMode: remoteSpace?.aclMode ?? 'legacy',
				unmanagedAclRiskAccepted: cfg.acceptUnmanagedAclRisk === true,
			};
			this.spaces.set(cfg.spaceId, runtime);
			this.registerSpaceAdapter(runtime);
		}
		if (this.running) {
			this.reschedulePollTimer();
		}
	}

	private scheduleBusyRevocationRetry(spaceId: number, engine: SyncEngine): void {
		if (!this.running || this.busyRetryTimers.has(spaceId)) return;
		const retryMs = this.deps.busyRevocationRetryMs ?? 5_000;
		const timer = setTimeout(() => {
			this.busyRetryTimers.delete(spaceId);
			if (!this.running) return;
			void engine
				.drainPendingRevocations()
				.then((drained) => {
					if (drained.remaining > 0) {
						this.scheduleBusyRevocationRetry(spaceId, engine);
					}
					this.notify();
				})
				.catch(() => {
					this.scheduleBusyRevocationRetry(spaceId, engine);
				});
		}, retryMs);
		this.busyRetryTimers.set(spaceId, timer);
	}

	private registerSpaceAdapter(rt: SpaceRuntime): void {
		this.adapterUnsubs.get(rt.spaceId)?.();
		const unsub = this.syncCoordinator.register({
			consumerId: `electron-mirror:${rt.spaceId}`,
			scope: { kind: 'space', id: String(rt.spaceId) },
			lane: 'offline-native',
			debounceMs: 0,
			runDeltaStep: async (ctx: SyncStepContext): Promise<StepOutcome> => {
				ctx.fence.assertCommitAllowed();
				if (!this.spaces.has(rt.spaceId)) {
					rt.manualResyncRequested = false;
					rt.verifyBeforeNextPass = false;
					rt.pendingFullRevocationVerify = null;
					return { kind: 'complete', recordsProcessed: 0 };
				}
				// Serialized server-authoritative confirmation for untrusted full-space
				// revocation hints (#555): runs inside coordinator single-flight so it
				// never races runPass() or shared SQLite transactions.
				if (rt.pendingFullRevocationVerify) {
					rt.pendingFullRevocationVerify = null;
					await this.maybeRenewToken();
					ctx.fence.assertCommitAllowed();
					if (this.token) {
						const confirmed = await this.confirmFullSpaceRevocation(rt);
						ctx.fence.assertCommitAllowed();
						if (confirmed) {
							rt.manualResyncRequested = false;
							rt.verifyBeforeNextPass = false;
							return { kind: 'scopeRevoked', detail: 'server_confirmed_space_revoked' };
						}
					}
					if (this.paused && !rt.manualResyncRequested) {
						return { kind: 'complete', recordsProcessed: 0 };
					}
				}
				const manual = rt.manualResyncRequested;
				const verify = rt.verifyBeforeNextPass;
				rt.verifyBeforeNextPass = false;
				if (this.paused && !manual) {
					return { kind: 'complete', recordsProcessed: 0 };
				}
				await this.maybeRenewToken();
				ctx.fence.assertCommitAllowed();
				if (verify) {
					await rt.mirror.verify();
					ctx.fence.assertCommitAllowed();
				}
				const pass = await this.runPass(rt, {
					signal: ctx.signal,
					fence: ctx.fence,
					budget: ctx.budget,
				});
				// Preserve manualResyncRequested across 'partial' pages so a paused
				// manual resync finishes every page before clearing the flag (#555).
				if (!pass.hasMore) {
					rt.manualResyncRequested = false;
				}
				return {
					kind: pass.hasMore ? 'partial' : 'complete',
					recordsProcessed: pass.processed,
					bytesProcessed: pass.bytesProcessed,
				};
			},
			reconcileScopeMembership: async (ctx: SyncStepContext): Promise<StepOutcome> => {
				ctx.fence.assertCommitAllowed();
				await this.maybeRenewToken();
				ctx.fence.assertCommitAllowed();
				const res = await rt.engine.reconcileVisibility({
					signal: ctx.signal,
					fence: ctx.fence,
					budget: ctx.budget,
				});
				return { kind: 'complete', recordsProcessed: res.downloaded };
			},
			purgeScopeCache: async (event: ScopeRevokedEvent): Promise<void> => {
				if (event.scopeKind !== 'space' || event.scopeId !== String(rt.spaceId)) return;
				await this.maybeRenewToken();
				if (event.subtreeAnchorId !== undefined) {
					// ARCH-020: always run server-authoritative fullVisibilityReconcile().
					await rt.engine.reconcileVisibility();
					return;
				}
				// Server-confirmed full-space revocation (4b + 4d): stop watching & detach
				// space from active sync map so pollOnce() never syncs a revoked space,
				// purge local files, and keep a bounded retry timer alive while any file is 'busy'.
				this.spaces.delete(rt.spaceId);
				this.wakeupConnectedSpaces.delete(rt.spaceId);
				this.adapterUnsubs.get(rt.spaceId)?.();
				this.adapterUnsubs.delete(rt.spaceId);
				await rt.mirror.stop();
				const purged = await rt.engine.purgeSpaceLocal();
				if (purged.busy > 0) {
					this.scheduleBusyRevocationRetry(rt.spaceId, rt.engine);
				}
				this.notify();
			},
		});
		this.adapterUnsubs.set(rt.spaceId, unsub);
	}

	private safetyNetIntervalMs(): number {
		const base = this.deps.pollMs ?? 30_000;
		return this.deps.safetyNetPollMs ?? Math.max(300_000, base * 10);
	}

	private currentPollIntervalMs(): number {
		const base = this.deps.pollMs ?? 30_000;
		if (this.allSpacesWakeupCovered()) {
			return this.safetyNetIntervalMs();
		}
		return base;
	}

	private reschedulePollTimer(): void {
		if (!this.running) {
			if (this.pollTimer) clearInterval(this.pollTimer);
			this.pollTimer = null;
			this.activePollIntervalMs = null;
			return;
		}
		const nextIntervalMs = this.currentPollIntervalMs();
		// Keep existing timer running when effective interval did not change so
		// repeated space switches / WS flaps never reset and starve uncovered spaces (#555).
		if (this.pollTimer !== null && this.activePollIntervalMs === nextIntervalMs) {
			return;
		}
		if (this.pollTimer) {
			clearInterval(this.pollTimer);
			this.pollTimer = null;
		}
		this.activePollIntervalMs = nextIntervalMs;
		this.pollTimer = setInterval(() => void this.pollOnce(), nextIntervalMs);
	}

	private startPollLoop(): void {
		if (this.running) return;
		this.running = true;
		this.reschedulePollTimer();
		void this.pollOnce();
	}

	private async pollOnce(): Promise<void> {
		if (this.paused) return;
		await this.maybeRenewToken();
		const now = Date.now();
		const safetyMs = this.safetyNetIntervalMs();
		// Route periodic passes through SyncCoordinator so pollOnce() shares
		// single-flight coalescing, DB serialization, and revocation fencing (#555 4b).
		// Wakeup-covered spaces skip fast ticks until safetyNetIntervalMs elapses,
		// while non-covered sibling spaces keep polling on every base tick (#555).
		for (const rt of [...this.spaces.values()]) {
			if (this.isSpaceWakeupConnected(rt.spaceId) && rt.lastPolledAtMs > 0 && now - rt.lastPolledAtMs < safetyMs) {
				continue;
			}
			rt.lastPolledAtMs = now;
			this.syncCoordinator.trigger({ kind: 'space', id: String(rt.spaceId) }, { immediate: true });
		}
		await this.syncCoordinator.flush();
	}

	/** A thrown pass marks the space 'error' and keeps the loop alive — the
	 *  next tick retries (spec: a transient failure must not wedge sync). */
	private async runPass(
		rt: SpaceRuntime,
		exec?: {
			signal?: AbortSignal;
			fence?: { assertCommitAllowed(): void };
			budget?: { maxRecords: number; maxBytes: number; deadlineMonoMs: number };
		},
	): Promise<{ processed: number; bytesProcessed: number; hasMore: boolean }> {
		if (!this.token) {
			rt.state = 'auth-expired';
			this.notify();
			return { processed: 0, bytesProcessed: 0, hasMore: false };
		}
		rt.state = 'syncing';
		this.notify();
		let processed = 0;
		let bytesProcessed = 0;
		let hasMore = false;
		try {
			exec?.fence?.assertCommitAllowed();
			const changesBeforeScan = rt.mirror.drainLocalChanges() as LocalChange[];
			for (const c of changesBeforeScan) await rt.engine.onLocalChange(c);
			await rt.mirror.scanLocal();
			const changesAfterScan = rt.mirror.drainLocalChanges() as LocalChange[];
			for (const c of changesAfterScan) await rt.engine.onLocalChange(c);
			await this.maybeSoftCheckout(rt, [...changesBeforeScan, ...changesAfterScan]);
			const res = await rt.engine.syncOnce(exec);
			processed = Math.max(
				res.appliedChanges ?? 0,
				res.uploaded + res.downloaded,
				res.cursorAdvanced ? 1 : 0,
			);
			bytesProcessed = res.bytesProcessed ?? 0;
			hasMore = Boolean(res.hasMore);
			exec?.fence?.assertCommitAllowed();
			await this.applyLockChmods(rt);
			rt.state = 'idle';
			rt.lastSyncMs = Date.now();
		} catch (err) {
			if (err instanceof Error && (err.name === 'SyncFenceAbortedError' || err.name === 'AbortError')) {
				return { processed, bytesProcessed, hasMore: false };
			}
			// If the Drive SQLite store was wiped mid-session (`db.wipe('drive')`),
			// re-open and re-apply schema idempotently so sync recovers cleanly
			// without restarting Electron (#555).
			const msg = err instanceof Error ? err.message.toLowerCase() : String(err).toLowerCase();
			if (msg.includes('no such table') || msg.includes('not open')) {
				await this.ensureReady(true);
			}
			if (err instanceof DriveApiError && err.status === 401) {
				rt.state = 'auth-expired';
				this.token = null;
			} else {
				rt.state = 'error';
			}
		}
		this.notify();
		return { processed, bytesProcessed, hasMore };
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
		...makeDriveMirrorWakeupHandlers(service),
	};
}

/**
 * Origin-gated renderer→main wakeup nudge channels (#555), included in
 * `makeDriveMirrorHandlers` and registered exclusively through `registerHandlers`
 * in `ipc.ts`.
 */
export function makeDriveMirrorWakeupHandlers(service: MirrorService): HandlerMap {
	return {
		drive_mirror_wakeup_nudge: (hint: unknown) => service.notifyWakeup(hint),
		drive_mirror_wakeup_state: (connected: unknown, spaceId?: unknown) =>
			service.setWakeupConnected(
				Boolean(connected),
				typeof spaceId === 'number' && Number.isSafeInteger(spaceId) ? spaceId : undefined,
			),
		drive_mirror_scope_revoked_nudge: (hint: unknown) => service.notifyScopeRevoked(hint),
	};
}
