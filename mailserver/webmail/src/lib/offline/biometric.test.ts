import { describe, it, expect, beforeEach, vi } from 'vitest';

describe('biometric bridge wrapper', () => {
	let bio: typeof import('./biometric');
	beforeEach(async () => { vi.resetModules(); });

	it('is inert on a plain browser', async () => {
		delete (window as never as { setjoinNative?: unknown }).setjoinNative;
		bio = await import('./biometric');
		expect(await bio.unlockMail()).toBe('cancelled');
		expect(await bio.isBiometricEnrolled()).toBe(false);
	});

	it('returns ok when vault unlock + db.open(\'mail\') succeed', async () => {
		(window as never as { setjoinNative: unknown }).setjoinNative = {
			db: { open: vi.fn(async (_appKey: string) => {}), isOpen: vi.fn(async (_appKey: string) => false), execSchemaInit: vi.fn(async (_appKey: string, _schema: string) => 0), exec: vi.fn(async () => 0), query: vi.fn(async () => [{ name: 'eligibility' }]) },
			vault: { version: 1, unlockBiometric: vi.fn(async () => true), isEnrolled: vi.fn(async () => true) }
		};
		bio = await import('./biometric');
		expect(await bio.unlockMail()).toBe('ok');
	});

	it('maps a native unlock failure to "failed" (never throws raw)', async () => {
		(window as never as { setjoinNative: unknown }).setjoinNative = {
			db: { open: vi.fn(), exec: vi.fn() },
			vault: { version: 1, unlockBiometric: vi.fn(async () => { throw new Error('LAError -2'); }), isEnrolled: vi.fn(async () => true) }
		};
		bio = await import('./biometric');
		expect(await bio.unlockMail()).toBe('failed'); // raw LAError never reaches the UI
	});

	it('returns false from isBiometricEnrolled when vault throws', async () => {
		(window as never as { setjoinNative: unknown }).setjoinNative = {
			db: { open: vi.fn(), exec: vi.fn() },
			vault: { version: 1, isEnrolled: vi.fn(async () => { throw new Error('bridge error'); }) }
		};
		bio = await import('./biometric');
		expect(await bio.isBiometricEnrolled()).toBe(false);
	});

	it('unlockWithPassphrase returns ok on success', async () => {
		(window as never as { setjoinNative: unknown }).setjoinNative = {
			db: { open: vi.fn(async () => {}), isOpen: vi.fn(async () => false), execSchemaInit: vi.fn(async (_appKey: string, _schema: string) => 0), exec: vi.fn(async () => 0), query: vi.fn(async () => [{ name: 'eligibility' }]) },
			vault: { version: 1, unlockPassphrase: vi.fn(async (_p: string) => true), isEnrolled: vi.fn(async () => true) }
		};
		bio = await import('./biometric');
		expect(await bio.unlockWithPassphrase('secret')).toBe('ok');
	});

	it('unlockWithPassphrase returns wrong on wrong passphrase (no throw)', async () => {
		(window as never as { setjoinNative: unknown }).setjoinNative = {
			db: { open: vi.fn(), exec: vi.fn() },
			vault: { version: 1, unlockPassphrase: vi.fn(async (_p: string) => false) }
		};
		bio = await import('./biometric');
		expect(await bio.unlockWithPassphrase('bad')).toBe('wrong');
	});

	it('degrades gracefully (never throws raw) on a vault sub-shape version mismatch', async () => {
		(window as never as { setjoinNative: unknown }).setjoinNative = {
			db: { open: vi.fn(), exec: vi.fn() },
			// version 99 doesn't match VAULT_VERSION (1) — treated as unavailable, not mis-called.
			vault: { version: 99, unlockBiometric: vi.fn(async () => true), isEnrolled: vi.fn(async () => true) }
		};
		bio = await import('./biometric');
		expect(await bio.isBiometricEnrolled()).toBe(false);
		expect(await bio.unlockMail()).toBe('failed');
	});

	it('lockMail is inert on plain browser (no throw)', async () => {
		delete (window as never as { setjoinNative?: unknown }).setjoinNative;
		bio = await import('./biometric');
		expect(() => bio.lockMail()).not.toThrow();
	});

	it('installIdleRelock returns a disposer; no-ops on plain browser', async () => {
		delete (window as never as { setjoinNative?: unknown }).setjoinNative;
		bio = await import('./biometric');
		const disposer = bio.installIdleRelock(5, vi.fn());
		expect(typeof disposer).toBe('function');
		expect(() => disposer()).not.toThrow();
	});
});
