import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// isOfflineAvailable is now store.ts's version (reads window.setjoinNative?.db).
// getCacheSizeBytes/getFreeSpaceBytes/syncNow still delegate to $lib/native.getNative.
vi.mock('$lib/native', () => ({
	isNative: vi.fn(),
	hasCapability: vi.fn(),
	getNative: vi.fn()
}));

import * as native from '$lib/native';
import {
	isOfflineAvailable,
	getCacheSizeBytes,
	getFreeSpaceBytes,
	syncNow
} from './storeFacade';

// Helper: install / remove a fake db bridge on window.setjoinNative.
function setNativeDb(db: object | null) {
	if (db === null) {
		delete (window as unknown as { setjoinNative?: unknown }).setjoinNative;
	} else {
		(window as unknown as { setjoinNative: { db: object } }).setjoinNative = { db };
	}
}

describe('storeFacade', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		setNativeDb(null);
	});
	afterEach(() => {
		vi.restoreAllMocks();
		setNativeDb(null);
	});

	it('isOfflineAvailable is false on a plain browser (no native db bridge)', () => {
		// window.setjoinNative is absent — store.ts nativeDb() returns null.
		expect(isOfflineAvailable()).toBe(false);
	});

	it('isOfflineAvailable is false when setjoinNative is present but db is absent', () => {
		(window as unknown as { setjoinNative: object }).setjoinNative = {};
		expect(isOfflineAvailable()).toBe(false);
	});

	it('isOfflineAvailable is true when window.setjoinNative.db is present', () => {
		setNativeDb({});
		expect(isOfflineAvailable()).toBe(true);
	});

	it('cache + free sizes are 0 when offline is unavailable (browser-safe stubs)', async () => {
		// window.setjoinNative absent → isOfflineAvailable false → db() returns null.
		expect(await getCacheSizeBytes()).toBe(0);
		expect(await getFreeSpaceBytes()).toBe(0);
	});

	it('proxies the offline-core db sizes for the mail appKey when available', async () => {
		const sizeBytes = vi.fn().mockResolvedValue(6_000_000);
		const freeBytes = vi.fn().mockResolvedValue(94_000_000);
		const bridge = { sizeBytes, freeBytes };
		// Drive isOfflineAvailable() via db bridge presence (store.ts path).
		setNativeDb(bridge);
		// getNative() is still used by db() to read the bridge methods.
		(native.getNative as ReturnType<typeof vi.fn>).mockReturnValue({ db: bridge });
		expect(await getCacheSizeBytes()).toBe(6_000_000);
		expect(await getFreeSpaceBytes()).toBe(94_000_000);
		// size is scoped to the 'mail' store (one DB file per app).
		expect(sizeBytes).toHaveBeenCalledWith('mail');
	});

	it('syncNow calls requestSync on the sync module when offline is available', async () => {
		setNativeDb({});
		const requestSync = vi.fn();
		vi.doMock('./sync', () => ({ requestSync }));
		await syncNow();
		// requestSync is the debounced user-trigger exported by sync.ts; not syncNow.
		expect(requestSync).toHaveBeenCalledOnce();
		vi.doUnmock('./sync');
	});

	it('syncNow is a no-op when offline is unavailable', async () => {
		// window.setjoinNative absent → should not throw or import sync.ts at all.
		await expect(syncNow()).resolves.toBeUndefined();
	});
});
