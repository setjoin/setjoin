// biometric.ts — the ONLY module that touches window.setjoinNative.vault for mail unlock.
// All native calls are try/caught; discriminants are returned, never raw errors.
// Browser path guarded by isOfflineAvailable() — every fn is inert on plain browser.
import { isOfflineAvailable, getStore } from './store';
import { offline } from './state.svelte';
import { VAULT_VERSION } from '../native/types';

// ponytail: vault is accessed inline via window.setjoinNative; no caching needed
// (the bridge is stable for the page lifetime; re-reading on each call is free).

function vault() {
	const v = (typeof window !== 'undefined' ? window.setjoinNative?.vault : undefined) ?? null;
	if (v && v.version !== VAULT_VERSION) {
		// Degrade gracefully rather than mis-call a changed native API: a shell built
		// against a different vault sub-shape version is treated as unavailable.
		console.warn(`[biometric] vault sub-shape version mismatch: shell=${v.version} expected=${VAULT_VERSION}`);
		return null;
	}
	return v;
}

/** Whether the device has a biometric enrolled (Face/Touch ID or equivalent). */
export async function isBiometricEnrolled(): Promise<boolean> {
	if (!isOfflineAvailable()) return false;
	try {
		return await vault()!.isEnrolled();
	} catch (e) {
		console.debug('[biometric] isEnrolled error', e);
		return false;
	}
}

/**
 * Prompt the OS biometric sheet, then open the mail store (runs the schema
 * migration). Returns 'ok' | 'failed' | 'cancelled'. On 'ok' announces
 * offline.live.unlocked so screen-readers hear the result.
 */
export async function unlockMail(): Promise<'ok' | 'failed' | 'cancelled'> {
	if (!isOfflineAvailable()) return 'cancelled';
	try {
		const v = vault()!;
		const success = await v.unlockBiometric();
		if (!success) return 'failed';
		// Open (+ migrate schema) through the store's init() so the schema
		// migration runs atomically with the db.open call.
		const store = getStore();
		if (store) await store.init();
		offline.setLockState('unlocked');
		offline.announce('offline.live.unlocked');
		return 'ok';
	} catch (e) {
		console.debug('[biometric] unlockMail error', e);
		offline.announce('offline.live.unlock_failed');
		return 'failed';
	}
}

/**
 * Verify a passphrase against the mail store key.
 * Returns 'ok' | 'wrong'. Never throws raw errors to the UI.
 */
export async function unlockWithPassphrase(passphrase: string): Promise<'ok' | 'wrong'> {
	if (!isOfflineAvailable()) return 'wrong';
	try {
		const v = vault()!;
		const success = await v.unlockPassphrase(passphrase);
		if (!success) return 'wrong';
		const store = getStore();
		if (store) await store.init();
		offline.setLockState('unlocked');
		offline.announce('offline.live.unlocked');
		return 'ok';
	} catch (e) {
		console.debug('[biometric] unlockWithPassphrase error', e);
		return 'wrong';
	}
}

/**
 * Set the lock state to 'locked' (does NOT wipe — re-lock is reversible).
 * Inert on a plain browser.
 */
export function lockMail(): void {
	if (!isOfflineAvailable()) return;
	offline.setLockState('locked');
}

/**
 * Install an idle relock timer. Resets on pointer + keyboard activity.
 * `onRelock` is called when the idle timeout fires (wired to
 * offline.announce('offline.live.relocked') in T19).
 * Returns a disposer that removes all event listeners and cancels the timer.
 * Inert (returns a no-op disposer) on a plain browser.
 */
export function installIdleRelock(minutes: number, onRelock: () => void): () => void {
	if (!isOfflineAvailable()) return () => {};

	const ms = minutes * 60 * 1000;
	let timer: ReturnType<typeof setTimeout>;

	function reset() {
		clearTimeout(timer);
		timer = setTimeout(() => {
			lockMail();
			onRelock();
		}, ms);
	}

	// ponytail: pointer + keydown covers mouse, touch, and keyboard;
	// ceiling: add 'touchstart' if touch-only mobile misses it.
	const events = ['pointermove', 'keydown'] as const;
	for (const ev of events) window.addEventListener(ev, reset, { passive: true });
	reset(); // arm immediately

	return () => {
		clearTimeout(timer);
		for (const ev of events) window.removeEventListener(ev, reset);
	};
}
