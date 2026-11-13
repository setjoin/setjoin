import { getNative, hasCapability } from './index';
import { readOwnDeviceId } from './deviceId';

/**
 * Attach the native-shell device proof (X-Device-ID/-Timestamp/-HMAC) to an
 * outgoing request's headers. In a plain browser the bridge advertises no
 * 'deviceProof' capability, so nothing is attached — which is exactly why a
 * plain browser is blocked under lockdown.
 */
export async function attachDeviceProofHeaders(headers: Headers): Promise<void> {
	if (!hasCapability('deviceProof')) return;
	try {
		const native = getNative();
		const deviceId = (await readOwnDeviceId()) ?? '';
		if (!deviceId) return;
		const timestamp = String(Math.floor(Date.now() / 1000));
		const proof = await native.deviceProof({ deviceId, timestamp });
		if (!proof) return;
		headers.set('X-Device-ID', deviceId);
		headers.set('X-Device-Timestamp', timestamp);
		headers.set('X-Device-HMAC', proof.hmac);
	} catch {
		// ponytail: vault corruption (e.g. device_id fails i64 parse) degrades to no headers —
		// the server enforces CA-2 lockdown via 403 BZ095; the client stays live.
	}
}
