/**
 * Canonical device identity read branches (coverage round r2).
 *
 * The secure-store read is the ONLY canonical device identity: a plain
 * browser has none, an empty stored value is none, and a read error degrades
 * honestly to none — never a placeholder constant.
 */

import { describe, it, expect, vi, afterEach } from 'vitest';

import { readOwnDeviceId } from './deviceId';

afterEach(() => {
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

describe('readOwnDeviceId', () => {
	it('returns the provisioned device id from a real native shell', async () => {
		vi.stubGlobal('window', {
			setjoinNative: {
				contractVersion: 1,
				capabilities: ['secureStore'],
				secureStore: { get: vi.fn().mockResolvedValue('device-abc') },
			},
		});
		// The real module seam reads through window.setjoinNative when valid.
		const mod = await import('./index');
		expect(mod.isNative()).toBe(true);
		const id = await readOwnDeviceId();
		expect(id).toBe('device-abc');
	});

	it('returns null on a plain browser (no made-up identity)', async () => {
		vi.stubGlobal('window', {});
		expect(await readOwnDeviceId()).toBeNull();
	});

	it('returns null when the stored value is empty', async () => {
		vi.stubGlobal('window', {
			setjoinNative: {
				contractVersion: 1,
				capabilities: ['secureStore'],
				secureStore: { get: vi.fn().mockResolvedValue('') },
			},
		});
		expect(await readOwnDeviceId()).toBeNull();
	});

	it('degrades to null when the secure store read rejects (fail closed)', async () => {
		vi.stubGlobal('window', {
			setjoinNative: {
				contractVersion: 1,
				capabilities: ['secureStore'],
				secureStore: { get: vi.fn().mockRejectedValue(new Error('vault locked')) },
			},
		});
		await expect(readOwnDeviceId()).resolves.toBeNull();
	});
});
