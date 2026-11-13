import type {
	SecureStore,
	VaultBridge,
	SharePayload,
	NotifyPayload,
	SetjoinNativeBridge,
} from './types';
import { BRIDGE_VERSION, VAULT_VERSION } from './types';

const PREFIX = 'sjn:';

/**
 * NOT a secure store. This web-platform stand-in exists only so the
 * `SetjoinNativeBridge` shape is satisfiable in a plain browser for
 * non-secret device-identifier reads (e.g. `device_id`, which fails closed
 * to null/undefined without a native shell). It is backed by plain
 * XSS-readable localStorage. It is deliberately NOT advertised under
 * `capabilities` below: every writer of secrets gates on native-only
 * capabilities (recoveryBlob/deviceProof/mailDb), and the missing
 * capability keeps future callers from mistaking this for secure storage
 * (S22-insecure-storage-under-secure-name hardening).
 */
const secureStore: SecureStore = {
	async get(key) {
		return localStorage.getItem(PREFIX + key);
	},
	async set(key, value) {
		localStorage.setItem(PREFIX + key, value);
	},
	async remove(key) {
		localStorage.removeItem(PREFIX + key);
	},
};

// On the web there is no biometric-gated vault. The webmail's own TOTP UI (guard via server)
// remains the path; this fallback reports "locked / empty" so callers degrade gracefully.
const vault: VaultBridge = {
	version: VAULT_VERSION,
	async unlock() {
		return false;
	},
	async isUnlocked() {
		return false;
	},
	async listTotp() {
		return [];
	},
	async generateTotp() {
		throw new Error('vault unavailable on web');
	},
	// Mail biometric/passphrase unlock — inert on plain browser (isOfflineAvailable() gates callers).
	async unlockBiometric() { return false; },
	async unlockPassphrase() { return false; },
	async isEnrolled() { return false; },
};

async function share(p: SharePayload): Promise<void> {
	const nav = globalThis.navigator as Navigator & { share?: (d: ShareData) => Promise<void> };
	if (typeof nav?.share === 'function') {
		await nav.share({ title: p.title, text: p.text, url: p.url });
		return;
	}
	const text = [p.text, p.url].filter(Boolean).join(' ');
	if (nav?.clipboard?.writeText) await nav.clipboard.writeText(text);
}

async function notify(p: NotifyPayload): Promise<void> {
	if (typeof Notification === 'undefined') return;
	if (Notification.permission === 'granted') {
		new Notification(p.title, { body: p.body, tag: p.tag });
		return;
	}
	if (Notification.permission !== 'denied') {
		const perm = await Notification.requestPermission();
		if (perm === 'granted') new Notification(p.title, { body: p.body, tag: p.tag });
	}
}

async function pickFile(accept?: string): Promise<File | null> {
	return new Promise((resolve) => {
		const input = document.createElement('input');
		input.type = 'file';
		if (accept) input.accept = accept;
		input.onchange = () => resolve(input.files?.[0] ?? null);
		input.oncancel = () => resolve(null);
		input.click();
	});
}

async function biometricUnlock(_reason: string): Promise<boolean> {
	// WebAuthn user-verification is the closest web analogue; treated as unsupported here
	// (no registered credential context in plain browser) so callers fall back to passphrase.
	return false;
}

async function openExternal(url: string): Promise<void> {
	globalThis.open?.(url, '_blank', 'noopener');
}
async function pushRegister(): Promise<string | null> {
	return null;
}
async function pushDevicePublicKey(): Promise<string | null> {
	return null;
}

/** A full bridge shape backed entirely by web platform APIs.
 * ponytail: `db` is absent — SQLCipher only runs in native shells; isOfflineAvailable()
 * checks window.setjoinNative?.db presence. Upgrade path: OPFS+crypto for browser offline. */
export const webFallbacks: SetjoinNativeBridge = {
	version: BRIDGE_VERSION,
	capabilities: ['share', 'notify', 'pickFile', 'openExternal'],
	pushRegister,
	pushDevicePublicKey,
	biometricUnlock,
	secureStore,
	vault,
	share,
	pickFile,
	notify,
	openExternal,
	// ponytail: plain browser has no HMAC secret; hasCapability('deviceProof') gates callers.
	deviceProof: async () => null,
};
