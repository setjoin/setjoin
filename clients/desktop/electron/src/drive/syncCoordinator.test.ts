import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { FetchLike } from '../../../../../mailserver/webmail/src/lib/drive/sync/types.js';
import type { NativeBinding } from '../native.js';
import { buildBridge } from '../bridge.js';
import { SqlMirrorIndex, applySchema } from '../../../../../mailserver/webmail/src/lib/drive/sync/schema.js';
import { FolderMirror } from './mirror.js';
import { makeDriveMirrorHandlers, MirrorService } from './service.js';

function fakeNative(): NativeBinding {
	const db = new DatabaseSync(':memory:');
	return {
		dbOpen: () => {},
		dbExec: (_appKey: string, sql: string, paramsJson: string) => {
			const params = JSON.parse(paramsJson) as unknown[];
			return Number(db.prepare(sql).run(...(params as never[])).changes);
		},
		dbQuery: (_appKey: string, sql: string, paramsJson: string) => {
			const params = JSON.parse(paramsJson) as unknown[];
			return JSON.stringify(db.prepare(sql).all(...(params as never[])));
		},
	} as unknown as NativeBinding;
}

function fakeFetch(spaces: Array<{ id: number; name: string; aclMode?: string }>, onChanges?: () => void): FetchLike {
	return async (input: string) => {
		const url = new URL(input);
		if (url.pathname === '/api/drive/spaces') {
			return new Response(
				JSON.stringify(spaces.map((s) => ({ id: s.id, name: s.name, aclMode: s.aclMode ?? 'legacy' }))),
				{ status: 200 },
			);
		}
		if (url.pathname.endsWith('/access-invalidations')) {
			return new Response(
				JSON.stringify({ cursor: 'a1', epoch: 'e1', invalidations: [], hasMore: false, fullReconcile: false }),
				{ status: 200 },
			);
		}
		if (url.pathname.endsWith('/visibility-snapshot')) {
			return new Response(
				JSON.stringify({ epoch: 'e1', rootCapabilities: ['read_metadata'], nodes: [], nextAfter: '0', hasMore: false }),
				{ status: 200 },
			);
		}
		if (url.pathname.endsWith('/changes')) {
			onChanges?.();
			return new Response(JSON.stringify({ newState: 'c1', changed: [], hasMore: false }), { status: 200 });
		}
		if (url.pathname.endsWith('/locks')) {
			return new Response(JSON.stringify([]), { status: 200 });
		}
		return new Response(JSON.stringify({}), { status: 200 });
	};
}

async function flush(): Promise<void> {
	for (let i = 0; i < 10; i++) await Promise.resolve();
}

describe('Electron MirrorService SyncCoordinator integration (#555)', () => {
	let tmpDir: string;
	let userDataDir: string;
	let mirrorBase: string;
	let activeSvc: MirrorService | null = null;

	beforeEach(async () => {
		tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sj-mirror-sync-'));
		userDataDir = path.join(tmpDir, 'userdata');
		mirrorBase = path.join(tmpDir, 'mirror');
		await fsp.mkdir(userDataDir, { recursive: true });
		await fsp.mkdir(mirrorBase, { recursive: true });
	});

	afterEach(async () => {
		if (activeSvc) {
			await activeSvc.stop();
			activeSvc = null;
		}
		vi.useRealTimers();
		await fsp.rm(tmpDir, { recursive: true, force: true });
	});

	it('keeps isRunning() and status().running true while wakeup-connected, slows poll to safety-net, and restores fast poll on disconnect/window close', async () => {
		let changeCalls = 0;
		const changeWaiters: Array<() => void> = [];
		const waitForNextChange = (): Promise<void> =>
			new Promise((resolve) => {
				changeWaiters.push(resolve);
			});
		const svc = new MirrorService({
			native: fakeNative(),
			userDataDir,
			fetchFn: fakeFetch([{ id: 1, name: 'Team' }], () => {
				changeCalls += 1;
				while (changeWaiters.length > 0) changeWaiters.shift()?.();
			}),
			mirrorBase,
			deviceLabel: 'electron-dev',
			locale: 'en',
			openPath: () => {},
			pollMs: 80,
			safetyNetPollMs: 60_000,
		});
		activeSvc = svc;

		const initialPass = waitForNextChange();
		await svc.configure({ serverOrigin: 'http://gw', spaces: [{ spaceId: 1, excludes: [] }] });
		await svc.refreshToken('tok-1', new Date(Date.now() + 3_600_000).toISOString());
		await initialPass;
		await flush();

		expect(svc.isRunning()).toBe(true);
		expect((await svc.status()).running).toBe(true);

		// Connect renderer wakeup bridge → isRunning() MUST remain true, blind poll slows to 60s safety-net.
		svc.setWakeupConnected(true);
		expect(svc.isRunning()).toBe(true);
		expect((await svc.status()).running).toBe(true);
		const callsAfterConnect = changeCalls;

		await new Promise((r) => setTimeout(r, 220));
		expect(changeCalls).toBe(callsAfterConnect); // fast 80ms poll slowed to 60s safety-net!

		// Valid untrusted renderer IPC wakeup nudge triggers authenticated main-process sync.
		expect(svc.notifyWakeup({ scopeKind: 'space', scopeId: '1', seq: 42 })).toBe(true);
		await svc.flushSyncCoordinator();
		expect(changeCalls).toBeGreaterThan(callsAfterConnect);

		// Malformed / non-space / unknown-space renderer hints rejected fail-closed!
		expect(svc.notifyWakeup({ scopeKind: 'mailbox', scopeId: '1', seq: 1 })).toBe(false);
		expect(svc.notifyWakeup({ scopeKind: 'space', scopeId: '999', seq: 1 })).toBe(false);
		expect(svc.notifyWakeup({ scopeKind: 'space', scopeId: '1', seq: Number.NaN })).toBe(false);
		expect(svc.notifyWakeup('garbage')).toBe(false);

		// Renderer window closes / wakeup bridge disconnects → immediately restores 80ms main-process poll!
		svc.setWakeupConnected(false);
		await svc.flushSyncCoordinator();
		const callsAfterDisconnect = changeCalls;
		const nextPollDone = waitForNextChange();
		await nextPollDone;
		expect(changeCalls).toBeGreaterThan(callsAfterDisconnect);
		expect(svc.isRunning()).toBe(true);
	});

	it('routes renderer bridge.driveMirror wakeup hints through makeDriveMirrorHandlers, enforces rate-limits, refuses unconfirmed/404 full-space revoke, and detaches only server-confirmed 403/spaces-omitted revocations (#555 Findings #1, #2, #4, Delta #2)', async () => {
		let changeCalls = 0;
		let serverMode: 'ok' | 'transient-404' | 'revoked-403' = 'ok';
		const svc = new MirrorService({
			native: fakeNative(),
			userDataDir,
			fetchFn: async (input: string) => {
				const url = new URL(input);
				if (url.pathname === '/api/drive/spaces') {
					if (serverMode === 'transient-404') {
						return new Response(JSON.stringify({ error: 'feature flag lookup failed' }), { status: 404 });
					}
					const list = serverMode === 'revoked-403' ? [] : [{ id: 2, name: 'Docs', aclMode: 'legacy' }];
					return new Response(JSON.stringify(list), { status: 200 });
				}
				if (url.pathname.endsWith('/access-invalidations')) {
					if (serverMode === 'transient-404') {
						return new Response(JSON.stringify({ error: 'not found' }), { status: 404 });
					}
					if (serverMode === 'revoked-403') {
						return new Response(JSON.stringify({ error: 'forbidden' }), { status: 403 });
					}
					return new Response(
						JSON.stringify({ cursor: 'a1', epoch: 'e1', invalidations: [], hasMore: false, fullReconcile: false }),
						{ status: 200 },
					);
				}
				if (url.pathname.endsWith('/visibility-snapshot')) {
					return new Response(
						JSON.stringify({ epoch: 'e1', rootCapabilities: ['read_metadata'], nodes: [], nextAfter: '0', hasMore: false }),
						{ status: 200 },
					);
				}
				if (url.pathname.endsWith('/changes')) {
					changeCalls += 1;
					return new Response(JSON.stringify({ newState: 'c1', changed: [], hasMore: false }), { status: 200 });
				}
				if (url.pathname.endsWith('/locks')) {
					return new Response(JSON.stringify([]), { status: 200 });
				}
				return new Response(JSON.stringify({}), { status: 200 });
			},
			mirrorBase,
			deviceLabel: 'electron-dev',
			locale: 'en',
			openPath: () => {},
			pollMs: 10_000_000,
			wakeupMinIntervalMs: 500,
			revokeMinIntervalMs: 150,
			reconnectMinIntervalMs: 500,
		});
		activeSvc = svc;

		await svc.configure({ serverOrigin: 'http://gw', spaces: [{ spaceId: 2, excludes: [] }] });
		await svc.refreshToken('tok-2', new Date(Date.now() + 3_600_000).toISOString());
		await flush();

		// End-to-end renderer bridge → IPC channel map → MirrorService wiring.
		const handlers = makeDriveMirrorHandlers(svc);
		const bridge = buildBridge(async (channel, ...args) => {
			const fn = handlers[channel];
			if (!fn) throw new Error(`unregistered channel: ${channel}`);
			return fn(...args);
		});

		await bridge.driveMirror.setWakeupConnected(true, 2);
		expect(svc.isWakeupConnected(2)).toBe(true);

		// First wakeup admitted; immediate burst rate-limited fail-closed.
		expect(await bridge.driveMirror.notifyWakeup({ scopeKind: 'space', scopeId: '2', seq: 1 })).toBe(true);
		expect(await bridge.driveMirror.notifyWakeup({ scopeKind: 'space', scopeId: '2', seq: 2 })).toBe(false);

		// Malformed scope_revoked nudge rejected fail-closed.
		expect(
			await bridge.driveMirror.notifyScopeRevoked({ scopeKind: 'bogus' as 'space', scopeId: '2' }),
		).toBe(false);

		// Valid subtree revocation admitted; immediate repeat DoS rate-limited fail-closed!
		expect(
			await bridge.driveMirror.notifyScopeRevoked({
				scopeKind: 'space',
				scopeId: '2',
				subtreeAnchorId: '77',
			}),
		).toBe(true);
		expect(
			await bridge.driveMirror.notifyScopeRevoked({
				scopeKind: 'space',
				scopeId: '2',
				subtreeAnchorId: '77',
			}),
		).toBe(false);

		// Finding #1: spoofed renderer full-space scope_revoked hint while server STILL
		// confirms 200 OK access MUST NOT detach or wipe the space!
		expect(await bridge.driveMirror.notifyScopeRevoked({ scopeKind: 'space', scopeId: '2' })).toBe(true);
		await svc.flushSyncCoordinator();
		expect((await svc.status()).perSpace.some((s) => s.spaceId === 2)).toBe(true);

		// Finding #4: manual resync routes through SyncCoordinator cleanly while space is active.
		const callsBeforeManualResync = changeCalls;
		await bridge.driveMirror.resync(2);
		expect(changeCalls).toBeGreaterThan(callsBeforeManualResync);

		// Delta #2: bare HTTP 404 (e.g. drive_core.rs feature-flag lookup failure) MUST NOT
		// be treated as confirmed revocation or delete mirrored files!
		await new Promise((r) => setTimeout(r, 170));
		serverMode = 'transient-404';
		expect(await bridge.driveMirror.notifyScopeRevoked({ scopeKind: 'space', scopeId: '2' })).toBe(true);
		await svc.flushSyncCoordinator();
		expect((await svc.status()).perSpace.some((s) => s.spaceId === 2)).toBe(true);

		// Finding #1: once the authenticated server actually returns 403, the revocation hint
		// confirms access loss, detaches the space, and blocks subsequent wakeups!
		await new Promise((r) => setTimeout(r, 170));
		serverMode = 'revoked-403';
		expect(await bridge.driveMirror.notifyScopeRevoked({ scopeKind: 'space', scopeId: '2' })).toBe(true);
		await svc.flushSyncCoordinator();
		const callsAfterRevoke = changeCalls;
		expect(await bridge.driveMirror.notifyWakeup({ scopeKind: 'space', scopeId: '2', seq: 99 })).toBe(false);
		expect(changeCalls).toBe(callsAfterRevoke);
	});

	it('per-space wakeup connectivity slows only the viewed space while sibling mirrored space keeps fast polling (Finding #2)', async () => {
		const callsBySpace = new Map<number, number>();
		const svc = new MirrorService({
			native: fakeNative(),
			userDataDir,
			fetchFn: async (input: string) => {
				const url = new URL(input);
				if (url.pathname === '/api/drive/spaces') {
					return new Response(
						JSON.stringify([
							{ id: 1, name: 'SpaceA', aclMode: 'legacy' },
							{ id: 2, name: 'SpaceB', aclMode: 'legacy' },
						]),
						{ status: 200 },
					);
				}
				const sid = Number(
					url.searchParams.get('space') ?? url.pathname.match(/\/spaces\/(\d+)/)?.[1] ?? 0,
				);
				if (url.pathname.endsWith('/access-invalidations')) {
					return new Response(
						JSON.stringify({ cursor: 'a1', epoch: 'e1', invalidations: [], hasMore: false, fullReconcile: false }),
						{ status: 200 },
					);
				}
				if (url.pathname.endsWith('/visibility-snapshot')) {
					return new Response(
						JSON.stringify({ epoch: 'e1', rootCapabilities: ['read_metadata'], nodes: [], nextAfter: '0', hasMore: false }),
						{ status: 200 },
					);
				}
				if (url.pathname.endsWith('/changes')) {
					callsBySpace.set(sid, (callsBySpace.get(sid) ?? 0) + 1);
					return new Response(JSON.stringify({ newState: 'c1', changed: [], hasMore: false }), { status: 200 });
				}
				if (url.pathname.endsWith('/locks')) {
					return new Response(JSON.stringify([]), { status: 200 });
				}
				return new Response(JSON.stringify({}), { status: 200 });
			},
			mirrorBase,
			deviceLabel: 'electron-dev',
			locale: 'en',
			openPath: () => {},
			pollMs: 80,
			safetyNetPollMs: 60_000,
		});
		activeSvc = svc;

		await svc.configure({
			serverOrigin: 'http://gw',
			spaces: [
				{ spaceId: 1, excludes: [] },
				{ spaceId: 2, excludes: [] },
			],
		});
		await svc.refreshToken('tok-multi', new Date(Date.now() + 3_600_000).toISOString());
		await svc.flushSyncCoordinator();

		// Mark ONLY space 1 as wakeup-connected (e.g. DriveApp viewing space 1).
		svc.setWakeupConnected(true, 1);
		expect(svc.isWakeupConnected(1)).toBe(true);
		expect(svc.isWakeupConnected(2)).toBe(false);

		const s1Before = callsBySpace.get(1) ?? 0;
		const s2Before = callsBySpace.get(2) ?? 0;
		await new Promise((r) => setTimeout(r, 240));
		await svc.flushSyncCoordinator();

		// Space 1 slowed to safety-net; Space 2 kept polling at 80ms!
		expect(callsBySpace.get(1) ?? 0).toBe(s1Before);
		expect(callsBySpace.get(2) ?? 0).toBeGreaterThan(s2Before);
	});

	it('SqlMirrorIndex.transaction serializes overlapping transactions on one shared SQLite DB (Finding #3)', async () => {
		const rawDb = new DatabaseSync(':memory:');
		const db = {
			exec: async (sql: string, params: unknown[] = []) =>
				Number(rawDb.prepare(sql).run(...(params as never[])).changes),
			query: async <T>(sql: string, params: unknown[] = []) =>
				rawDb.prepare(sql).all(...(params as never[])) as T[],
		};
		await applySchema(db);
		const index = new SqlMirrorIndex(db);
		const order: string[] = [];

		await Promise.all([
			index.transaction(async () => {
				order.push('tx1-start');
				await new Promise((r) => setTimeout(r, 15));
				await index.setRootCapabilities(1, ['read_metadata']);
				order.push('tx1-end');
			}),
			index.transaction(async () => {
				order.push('tx2-start');
				await index.setRootCapabilities(2, ['read_metadata']);
				order.push('tx2-end');
			}),
		]);

		expect(order).toEqual(['tx1-start', 'tx1-end', 'tx2-start', 'tx2-end']);
		expect(await index.rootCapabilities(1)).toEqual(['read_metadata']);
		expect(await index.rootCapabilities(2)).toEqual(['read_metadata']);
	});

	it('FolderMirror.revoke returns busy (never absent) when a mirrored file is unreadable/locked (Finding #5)', async () => {
		const rawDb = new DatabaseSync(':memory:');
		const db = {
			exec: async (sql: string, params: unknown[] = []) =>
				Number(rawDb.prepare(sql).run(...(params as never[])).changes),
			query: async <T>(sql: string, params: unknown[] = []) =>
				rawDb.prepare(sql).all(...(params as never[])) as T[],
		};
		await applySchema(db);
		const index = new SqlMirrorIndex(db);
		const root = path.join(mirrorBase, 'locked-space');
		await fsp.mkdir(root, { recursive: true });
		const lockedFile = path.join(root, 'secret.txt');
		await fsp.writeFile(lockedFile, 'top-secret');
		await index.upsertMirror({
			nodeId: 101,
			spaceId: 1,
			relPath: 'secret.txt',
			diskSha256: 'abc',
			diskSize: 10,
			diskMtimeMs: null,
			baseVersionId: 1,
			materializedOfVersion: null,
		});

		const mirror = new FolderMirror({
			root,
			spaceId: 1,
			http: {} as never,
			index,
		});

		// Make file unreadable (EACCES) — hashFile fails with EACCES, NOT ENOENT!
		await fsp.chmod(lockedFile, 0o000);
		try {
			const outcome = await mirror.revoke(101, false);
			expect(outcome).toBe('busy');
			const issues = await index.issues(1);
			expect(issues.some((i) => i.code === 'revocation-busy')).toBe(true);
		} finally {
			await fsp.chmod(lockedFile, 0o644);
		}
	});
});
