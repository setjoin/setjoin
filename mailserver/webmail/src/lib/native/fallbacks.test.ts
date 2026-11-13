import { describe, it, expect, vi, beforeEach } from 'vitest';
import { webFallbacks } from './fallbacks';
import { hasCapability } from './index';

beforeEach(() => {
	localStorage.clear();
});

describe('web fallbacks', () => {
	it('does not advertise secureStore (localStorage is not secure storage)', () => {
		// S22-insecure-storage-under-secure-name: the web fallback's SecureStore
		// stand-in is XSS-readable localStorage kept only for non-secret
		// device-identifier reads; it must never be advertised as a capability.
		expect(webFallbacks.capabilities).not.toContain('secureStore');
		expect(hasCapability('secureStore')).toBe(false);
	});

	it('secureStore round-trips via localStorage (prefixed)', async () => {
		await webFallbacks.secureStore.set('tok', 'abc');
		expect(await webFallbacks.secureStore.get('tok')).toBe('abc');
		expect(localStorage.getItem('sjn:tok')).toBe('abc');
		await webFallbacks.secureStore.remove('tok');
		expect(await webFallbacks.secureStore.get('tok')).toBeNull();
	});

	it('share() uses navigator.share when available', async () => {
		const share = vi.fn().mockResolvedValue(undefined);
		vi.stubGlobal('navigator', { share });
		await webFallbacks.share({ title: 'hi', url: 'https://x' });
		expect(share).toHaveBeenCalledWith({ title: 'hi', text: undefined, url: 'https://x' });
		vi.unstubAllGlobals();
	});

	it('share() falls back to clipboard when navigator.share is absent', async () => {
		const writeText = vi.fn().mockResolvedValue(undefined);
		vi.stubGlobal('navigator', { clipboard: { writeText } });
		await webFallbacks.share({ text: 'body', url: 'https://x' });
		expect(writeText).toHaveBeenCalledWith('body https://x');
		vi.unstubAllGlobals();
	});

	it('pushRegister() returns null on web (no native push)', async () => {
		expect(await webFallbacks.pushRegister()).toBeNull();
	});

	it('vault.isUnlocked() is false on web (vault is a native-only capability)', async () => {
		expect(await webFallbacks.vault.isUnlocked()).toBe(false);
	});
});
