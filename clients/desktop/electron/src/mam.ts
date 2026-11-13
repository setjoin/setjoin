//! MAM (Mobile Application Management) native-host adapter. The adjacent pure
//! `mamLifecycle.ts` owns signed request construction and response reduction;
//! this module owns HTTP and executes its ordered native/storage effects. The
//! native module owns the cached VALUES
//! (mamStore*/mamGetPolicy/mamMarkWiped/mamIsWiped/mamClearWiped); the enrolment
//! credentials live in the vault secure store under `mam:*` keys.
//!
//! HMAC is computed inside the main-process lifecycle module with Node's stdlib
//! `crypto`; the secret never crosses preload/IPC into the renderer.

import type { NativeBinding } from './native';
import type { HandlerMap } from './handlers/db';
import {
	buildCheckinRequest,
	deviceHmac,
	knownPolicyVersion,
	reduceCheckinResponse,
	type CheckinOutcome,
	type MamEffectIntent,
	type MamPolicy,
} from './mamLifecycle';

export { defaultPolicy, deviceHmac, policyFromMap } from './mamLifecycle';
export type { MamPolicy } from './mamLifecycle';

/** Secure-store keys under which enrolment credentials are kept (mirror `mam.rs`). */
const SS_DEVICE_ID = 'mam:device_id';
const SS_HMAC_SECRET = 'mam:hmac_secret';
const SS_SERVER_URL = 'mam:server_url';

/** Current unix-seconds timestamp as a string (matches `mam.rs::unix_timestamp`). */
export function unixTimestamp(): string {
	return Math.floor(Date.now() / 1000).toString();
}

/**
 * Enrolment-endpoint validation (D-CLIENTS-DESKTOP-006): the enrolment triple
 * arrives from the renderer, so it is validated HERE in the main process
 * before it is persisted and long before `mam_checkin` ever fetches it. The
 * remediation's first arm — "validate serverUrl scheme (https) and shape" —
 * pins the stored endpoint to an absolute https URL with an explicit host and
 * no embedded credentials; anything else is rejected fail-closed. (Pin to the
 * configured gateway origin and an authenticated re-enrolment proof before
 * clear_wiped remain owner decisions; see the chunk report residual.)
 */
function validateEnrolmentTriple(serverUrl: unknown, deviceId: unknown, hmacSecret: unknown): {
	serverUrl: string;
	deviceId: string;
	hmacSecret: string;
} {
	if (typeof serverUrl !== 'string' || serverUrl.length === 0) {
		throw new Error('mam_enroll: server_url must be a non-empty string');
	}
	let parsed: URL;
	try {
		parsed = new URL(serverUrl);
	} catch {
		throw new Error('mam_enroll: server_url is not an absolute URL');
	}
	if (parsed.protocol !== 'https:') {
		throw new Error(`mam_enroll: server_url scheme must be https, got ${parsed.protocol}`);
	}
	if (parsed.hostname.length === 0) {
		throw new Error('mam_enroll: server_url has no host');
	}
	if (parsed.username.length > 0 || parsed.password.length > 0) {
		throw new Error('mam_enroll: server_url must not embed credentials');
	}
	if (typeof deviceId !== 'number' && typeof deviceId !== 'string') {
		throw new Error('mam_enroll: device_id must be a number or decimal string');
	}
	const id = String(deviceId);
	if (!/^[0-9]+$/.test(id) || !Number.isSafeInteger(Number.parseInt(id, 10))) {
		throw new Error('mam_enroll: device_id must be a non-negative decimal integer');
	}
	if (typeof hmacSecret !== 'string' || hmacSecret.length === 0) {
		throw new Error('mam_enroll: hmac_secret must be a non-empty string');
	}
	return { serverUrl, deviceId: id, hmacSecret };
}

interface Enrolment {
	serverUrl: string;
	deviceId: number;
	hmacSecret: string;
}

/** Load enrolment from the secure store, or null when locked / not enrolled. */
function loadEnrolment(native: NativeBinding): Enrolment | null {
	const serverUrl = native.secureStoreGet(SS_SERVER_URL);
	const deviceIdS = native.secureStoreGet(SS_DEVICE_ID);
	const hmacSecret = native.secureStoreGet(SS_HMAC_SECRET);
	if (serverUrl == null || deviceIdS == null || hmacSecret == null) return null;
	const deviceId = Number.parseInt(deviceIdS, 10);
	if (Number.isNaN(deviceId)) return null;
	return { serverUrl, deviceId, hmacSecret };
}

/** Injected effects: HTTP + storage-clear (electron session in production). */
export interface MamDeps {
	/** Defaults to the global fetch (Node 26). Injectable for tests. */
	fetch?: typeof fetch;
	/** Clear the renderer's session storage/cache on remote wipe. */
	clearStorage(): Promise<void>;
}

export function makeMamHandlers(native: NativeBinding, deps: MamDeps): HandlerMap {
	const doFetch = deps.fetch ?? fetch;

	return {
		// Persist enrolment creds after POST /device/register. Re-arms the device
		// (clears any durable wipe latch — documented intentional re-arm) and
		// caches the device id immediately. The renderer-supplied triple is
		// validated above before anything is persisted (D-CLIENTS-DESKTOP-006).
		mam_enroll: (serverUrl: unknown, deviceId: unknown, hmacSecret: unknown) => {
			const t = validateEnrolmentTriple(serverUrl, deviceId, hmacSecret);
			native.secureStoreSet(SS_SERVER_URL, t.serverUrl);
			native.secureStoreSet(SS_DEVICE_ID, t.deviceId);
			native.secureStoreSet(SS_HMAC_SECRET, t.hmacSecret);
			native.mamClearWiped();
			native.mamStoreDeviceId(t.deviceId);
		},

		mam_checkin: async (): Promise<CheckinOutcome> => {
			if (native.mamIsWiped()) {
				return { ran: false, policy_version: 0, wiped: true };
			}
			const enr = loadEnrolment(native);
			if (!enr) return { ran: false, policy_version: 0, wiped: false };

			const knownVersion = knownPolicyVersion(native.mamGetPolicy());
			const timestamp = unixTimestamp();
			const request = buildCheckinRequest(
				enr.serverUrl,
				enr.deviceId,
				enr.hmacSecret,
				timestamp,
				knownVersion,
			);

			const resp = await doFetch(request.url, {
				method: 'POST',
				headers: request.headers,
				body: JSON.stringify(request.body),
			});

			const parsed = resp.status === 304 || !resp.ok ? null : ((await resp.json()) as object);
			const transition = reduceCheckinResponse(resp.status, knownVersion, enr.deviceId, parsed);
			for (const effect of transition.effects) {
				await executeEffect(effect, native, deps);
			}
			return transition.outcome;
		},

		mam_get_policy: (): MamPolicy | null => {
			const raw = native.mamGetPolicy();
			if (!raw) return null;
			try {
				return JSON.parse(raw) as MamPolicy;
			} catch {
				return null;
			}
		},

		mam_is_wiped: () => native.mamIsWiped(),

		// The bridge-visible device proof: only the HMAC hex, never the secret.
		device_proof: (deviceId: unknown, timestamp: unknown): { hmac: string } | null => {
			const secret = native.secureStoreGet(SS_HMAC_SECRET);
			if (secret == null) return null; // locked or not enrolled
			const idNum = Number.parseInt(String(deviceId), 10);
			if (Number.isNaN(idNum)) {
				throw new Error(`device_proof: invalid device_id: ${String(deviceId)}`);
			}
			return { hmac: deviceHmac(secret, idNum, String(timestamp)) };
		},
	} as HandlerMap;
}

async function executeEffect(effect: MamEffectIntent, native: NativeBinding, deps: MamDeps): Promise<void> {
	switch (effect.type) {
		case 'latch_wipe':
			native.mamMarkWiped();
			return;
		case 'clear_web_storage':
			await deps.clearStorage();
			return;
		case 'cache_device':
			native.mamStoreDeviceId(effect.deviceId);
			return;
		case 'cache_policy':
			native.mamStorePolicy(JSON.stringify(effect.policy));
			return;
		case 'enforce_policy':
			// Electron has no platform screen-capture-block API.
			return;
	}
}
