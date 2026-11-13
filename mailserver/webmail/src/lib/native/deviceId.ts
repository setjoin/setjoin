import { getNative, isNative } from './index';

/**
 * This device's canonical lifecycle identity: the native secure store's
 * 'device_id' — the CA-2 identity the shell provisions at enrollment and
 * presents as X-Device-ID (native/deviceProof.ts), verified server-side
 * against devices.hmac_secret. This is the ONLY id the client knows about
 * itself; nothing here invents a placeholder when it is absent.
 *
 * Canonical identity reads ONLY a real native shell's secure store
 * (`isNative()`): a plain browser has NO provisioned device identity, so
 * this returns null there. The web fallback secure store (XSS-readable
 * localStorage under 'sjn:device_id') may carry values for non-identity
 * plumbing, but it is never a canonical device id — binding a
 * localStorage-persisted value as the settings identity would be a made-up
 * identity (Astra r3 P2). Also returns null on a read error — callers
 * degrade honestly and fail closed; a missing device identity is a state,
 * never a made-up constant.
 */
export async function readOwnDeviceId(): Promise<string | null> {
	if (!isNative()) return null; // no native shell → no canonical device identity
	try {
		const raw = await getNative().secureStore.get('device_id');
		return raw ? raw : null;
	} catch {
		return null;
	}
}
