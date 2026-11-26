import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { FetchLike } from '../../../../../mailserver/webmail/src/lib/drive/sync/types.js';
import type { NativeBinding } from '../native.js';
import { buildBridge } from '../bridge.js';
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

	it('routes renderer bridge.driveMirror wakeup hints through makeDriveMirrorHandlers, enforces rate-limits, and detaches full-revoked spaces', async () => {
		let changeCalls = 0;
		const svc = new MirrorService({
			native: fakeNative(),
			userDataDir,
			fetchFn: fakeFetch([{ id: 2, name: 'Docs' }], () => {
				changeCalls += 1;
			}),
			mirrorBase,
			deviceLabel: 'electron-dev',
			locale: 'en',
			openPath: () => {},
			pollMs: 10_000_000,
			wakeupMinIntervalMs: 500,
			revokeMinIntervalMs: 500,
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

		await bridge.driveMirror.setWakeupConnected(true);
		expect(svc.isWakeupConnected()).toBe(true);

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

		// Full-space revocation detaches the space so subsequent polls/wakeups never sync it!
		expect(await bridge.driveMirror.notifyScopeRevoked({ scopeKind: 'space', scopeId: '2' })).toBe(true);
		await svc.flushSyncCoordinator();
		const callsAfterRevoke = changeCalls;
		expect(await bridge.driveMirror.notifyWakeup({ scopeKind: 'space', scopeId: '2', seq: 99 })).toBe(false);
		expect(changeCalls).toBe(callsAfterRevoke);
	});
});
