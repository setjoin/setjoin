import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { DriveLockStore } from './locks.svelte';

const lockFile = vi.fn();
const unlockFile = vi.fn();
let driveWatchHandlers: Array<(payload: Record<string, unknown>) => void> = [];

vi.mock('./api', async () => {
	const actual = await vi.importActual<typeof import('./api')>('./api');
	return {
		...actual,
		lockFile: (...a: unknown[]) => lockFile(...a),
		unlockFile: (...a: unknown[]) => unlockFile(...a),
	};
});

// The mock's subscribeEvent mirrors the real hub-level unwrap (jmap/websocket.ts):
// fireDriveWatch keeps firing the full envelope shape, and each registered
// handler unwraps `event` before forwarding to locks.svelte.ts's callback —
// so locks.svelte.ts receives the already-unwrapped event, same as production.
vi.mock('$lib/jmap/websocket', () => ({
	subscribeEvent: (atType: string, handler: (event: Record<string, unknown>) => void) => {
		const wrapped = (envelope: Record<string, unknown>) => {
			const event = (envelope as { event?: unknown }).event;
			if (event && typeof event === 'object') handler(event as Record<string, unknown>);
		};
		if (atType === 'DriveWatch') driveWatchHandlers.push(wrapped);
		return () => {
			driveWatchHandlers = driveWatchHandlers.filter((h) => h !== wrapped);
		};
	},
}));

function fireDriveWatch(event: Record<string, unknown>) {
	for (const h of driveWatchHandlers) h({ '@type': 'DriveWatch', event });
}

describe('DriveLockStore', () => {
	beforeEach(() => {
		lockFile.mockReset();
		unlockFile.mockReset();
		driveWatchHandlers = [];
		vi.useFakeTimers();
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it('openForEdit acquires a soft lock for an office-edit file type and starts a 5-min heartbeat', async () => {
		lockFile.mockResolvedValue({ status: 'acquired', mode: 'soft', expiresAt: '2026-07-10T08:00:00Z' });
		const store = new DriveLockStore();
		await store.openForEdit(5, { name: 'Report.xlsx', branchId: null, versionId: 20 });

		expect(lockFile).toHaveBeenCalledTimes(1);
		expect(lockFile).toHaveBeenCalledWith(5, { mode: 'soft', branchId: null, versionId: 20, deviceLabel: undefined });
		expect(store.mode).toBe('soft');

		await vi.advanceTimersByTimeAsync(5 * 60 * 1000);
		expect(lockFile).toHaveBeenCalledTimes(2);
		await vi.advanceTimersByTimeAsync(5 * 60 * 1000);
		expect(lockFile).toHaveBeenCalledTimes(3);
	});

	it('openForEdit does NOT acquire a lock for a non-office file type', async () => {
		const store = new DriveLockStore();
		await store.openForEdit(5, { name: 'photo.png', branchId: null, versionId: 20 });
		expect(lockFile).not.toHaveBeenCalled();
		expect(store.mode).toBeNull();
	});

	it('checkOut() upgrades to a hard lock', async () => {
		lockFile.mockResolvedValue({ status: 'acquired', mode: 'soft', expiresAt: '' });
		const store = new DriveLockStore();
		await store.openForEdit(5, { name: 'Report.xlsx', branchId: null, versionId: 20 });

		lockFile.mockResolvedValue({ status: 'acquired', mode: 'hard', expiresAt: '' });
		await store.checkOut();
		expect(lockFile).toHaveBeenLastCalledWith(5, { mode: 'hard', branchId: null, versionId: 20, deviceLabel: undefined });
		expect(store.mode).toBe('hard');
	});

	it('close() clears the heartbeat and best-effort releases with keepalive', async () => {
		lockFile.mockResolvedValue({ status: 'acquired', mode: 'soft', expiresAt: '' });
		unlockFile.mockResolvedValue(undefined);
		const store = new DriveLockStore();
		await store.openForEdit(5, { name: 'Report.xlsx', branchId: null, versionId: 20 });

		store.close();
		expect(unlockFile).toHaveBeenCalledWith(5, { keepalive: true });

		await vi.advanceTimersByTimeAsync(10 * 60 * 1000);
		expect(lockFile).toHaveBeenCalledTimes(1); // no further heartbeat after close
	});

	it('a "held" response populates presence (holder, since) without throwing', async () => {
		lockFile.mockResolvedValue({ status: 'held', holderId: 9, holderName: 'Bob', mode: 'soft', since: '2026-07-10T07:00:00Z', branchId: null });
		const store = new DriveLockStore();
		await expect(store.openForEdit(5, { name: 'Report.xlsx', branchId: null, versionId: 20 })).resolves.not.toThrow();
		expect(store.presence).toEqual({ holderId: 9, mode: 'soft', since: '2026-07-10T07:00:00Z', branchId: null });
		expect(store.mode).toBeNull();
	});

	it('refreshes (renews) on a DriveWatch push event for the open node when we hold a lock', async () => {
		lockFile.mockResolvedValue({ status: 'acquired', mode: 'soft', expiresAt: '' });
		const store = new DriveLockStore();
		await store.openForEdit(5, { name: 'Report.xlsx', branchId: null, versionId: 20 });
		expect(lockFile).toHaveBeenCalledTimes(1);

		fireDriveWatch({ nodeId: 5, op: 'update', spaceId: 1 });
		await vi.waitFor(() => expect(lockFile).toHaveBeenCalledTimes(2));

		// A push event for a DIFFERENT node is ignored.
		fireDriveWatch({ nodeId: 999, op: 'update', spaceId: 1 });
		await Promise.resolve();
		expect(lockFile).toHaveBeenCalledTimes(2);
	});
});
