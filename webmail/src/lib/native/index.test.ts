import { describe, it, expect, vi, afterEach } from 'vitest';
import { getNative, isNative, hasCapability } from './index';
import { webFallbacks } from './fallbacks';
import { BRIDGE_VERSION } from './types';
import type { SetjoinNativeBridge } from './types';

afterEach(() => {
	delete (window as { setjoinNative?: unknown }).setjoinNative;
});

function fakeBridge(): SetjoinNativeBridge {
	return {
		version: 1,
		capabilities: [
			'push',
			'biometric',
			'secureStore',
			'vault',
			'share',
			'pickFile',
			'notify',
			'openExternal',
		],
		pushRegister: vi.fn().mockResolvedValue('device-token'),
		pushDevicePublicKey: vi.fn().mockResolvedValue(null),
		biometricUnlock: vi.fn().mockResolvedValue(true),
		secureStore: { get: vi.fn(), set: vi.fn(), remove: vi.fn() },
		vault: {
			version: 1,
			unlock: vi.fn(),
			isUnlocked: vi.fn().mockResolvedValue(true),
			listTotp: vi.fn(),
			generateTotp: vi.fn(),
			unlockBiometric: vi.fn().mockResolvedValue(true),
			unlockPassphrase: vi.fn().mockResolvedValue(true),
			isEnrolled: vi.fn().mockResolvedValue(true),
		},
		share: vi.fn().mockResolvedValue(undefined),
		pickFile: vi.fn().mockResolvedValue(null),
		notify: vi.fn().mockResolvedValue(undefined),
		openExternal: vi.fn().mockResolvedValue(undefined),
		deviceProof: vi.fn().mockResolvedValue(null),
		db: {
			open: vi.fn().mockResolvedValue(undefined),
			isOpen: vi.fn().mockResolvedValue(true),
			exec: vi.fn().mockResolvedValue(0),
			query: vi.fn().mockResolvedValue([]),
			wipe: vi.fn().mockResolvedValue(undefined),
		},
	};
}

describe('native facade', () => {
	it('reports not-native and uses fallbacks when no shell is injected', async () => {
		expect(isNative()).toBe(false);
		expect(hasCapability('push')).toBe(false);
		expect(await getNative().pushRegister()).toBeNull(); // web fallback
	});

	it('delegates to window.setjoinNative when present', async () => {
		const bridge = fakeBridge();
		window.setjoinNative = bridge;
		expect(isNative()).toBe(true);
		expect(hasCapability('push')).toBe(true);
		expect(await getNative().pushRegister()).toBe('device-token');
		expect(bridge.pushRegister).toHaveBeenCalledOnce();
	});

	it('degrades to web fallbacks when the injected bridge version is skewed', () => {
		// BRIDGE_VERSION contract: a shell bumping the version is a breaking
		// change; the webmail must not mis-call a changed API (fail closed).
		const bridge = { ...fakeBridge(), version: BRIDGE_VERSION + 1 };
		window.setjoinNative = bridge;
		expect(isNative()).toBe(false);
		expect(hasCapability('push')).toBe(false);
		expect(getNative()).toBe(webFallbacks);
	});

	it('degrades to web fallbacks when the injected bridge lacks a capability list', () => {
		const bridge = fakeBridge() as unknown as Record<string, unknown>;
		delete bridge.capabilities;
		window.setjoinNative = bridge as unknown as SetjoinNativeBridge;
		expect(isNative()).toBe(false);
		expect(getNative()).toBe(webFallbacks);
	});

	it('accepts a partial native bridge that asserts the current version and capabilities', () => {
		// Shells and tests may expose only the members a flow needs; the facade
		// asserts the version contract + capability list, sub-shape versions are
		// checked at each call site.
		window.setjoinNative = {
			version: BRIDGE_VERSION,
			capabilities: ['deviceProof'],
			deviceProof: vi.fn().mockResolvedValue(null),
			secureStore: { get: vi.fn(), set: vi.fn(), remove: vi.fn() },
		} as unknown as SetjoinNativeBridge;
		expect(isNative()).toBe(true);
		expect(hasCapability('deviceProof')).toBe(true);
	});

	it('tolerates a version-less legacy bridge (sub-shapes carry their own versions)', () => {
		window.setjoinNative = {
			capabilities: ['driveMirror'],
		} as unknown as SetjoinNativeBridge;
		expect(isNative()).toBe(true);
		expect(hasCapability('driveMirror')).toBe(true);
	});
});
