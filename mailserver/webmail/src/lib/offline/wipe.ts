import { subscribeControl } from '../jmap/websocket';
import { getNative, isNative, hasCapability } from '../native';
import { readOwnDeviceId } from '../native/deviceId';
import { isOfflineAvailable } from './store';
import type { OfflineCaps } from './caps';
import { offline } from './state.svelte';

export interface WipeDeps {
	/** Tears down the session (drops cookies/tokens, navigates to security-event screen). */
	logout: () => void;
	/** Override the cache-clear (tests). Defaults to the offline-core 'mail' store wipe. */
	clearOfflineCache?: () => Promise<void>;
	/**
	 * Best-effort server ack: called after the local store is cleared so the server
	 * can set wipe_acked_at and stop re-issuing the wipe push. Defaults to a
	 * keepalive POST to /offline/wipe-ack (persists past the navigation that follows
	 * logout). Fire-and-forget — not awaited; logout proceeds regardless of ack outcome.
	 */
	postAck?: (deviceId: number) => Promise<void>;
}

// ownDeviceId reads this device's canonical devices.id from the native secure
// store under 'device_id' (shared readOwnDeviceId — the CA-2 identity the
// native shell provisions at enrollment and presents as X-Device-ID, see
// native/deviceId.ts), verified server-side against devices.hmac_secret. This
// is the ONLY id the client knows about itself, so it is what offline.wipe
// payloads target it by.
// Returns undefined for a plain browser (no bridge / no id) or on a read error —
// callers treat undefined as "not the target" for a targeted wipe (fail closed).
async function ownDeviceId(): Promise<number | undefined> {
	const raw = await readOwnDeviceId();
	if (raw === null) return undefined;
	const n = Number(raw);
	return Number.isFinite(n) ? n : undefined;
}

// installWipeHandler subscribes to the server's offline.wipe control push and,
// on receipt, drops the offline-core 'mail' store (window.setjoinNative.db.wipe('mail')
// — offline-core deletes the 'mail' store file + destroys its key, the key being
// held via guard-core) then acks the server and logs out. The wipe and ack are
// best-effort: even if they reject (or there is no native bridge — a plain
// online-only browser has no offline store), we STILL log out. The DURABLE
// guarantee is the server withholding the cache seed on the next session (#2a F4),
// so the cache is unreadable regardless.
//
// TARGETING (SECURITY): the push fans out on the user's shared tag:{mailbox}
// channel to every connected session. A payload carrying a specific `deviceId`
// is an admin single-device wipe and fires ONLY on the device whose own
// `device_id` matches — a sibling session no-ops (no wipe, no ack, no logout).
// A payload with no `deviceId` is the explicit all-my-devices wipe and fires
// everywhere (a plain browser then logs out too). See ownDeviceId (fail closed).
//
// The logout passed in MUST navigate to /security-event?reason=remote-wipe (not
// the plain login form) — the bootstrap composes this; installWipeHandler does not
// assume the destination (DESIGN: honest-recovery-path requirement, brief §DESIGN).
//
// Returns an unsubscribe function.
export function installWipeHandler(deps: WipeDeps): () => void {
	// ponytail: default clear = direct bridge call (brief §Reconcile note: do NOT
	// go through the store facade; the wipe handler owns session teardown
	// independently).
	const clear =
		deps.clearOfflineCache ??
		(async () => {
			if (isNative() && hasCapability('mailDb')) {
				await getNative().db!.wipe('mail');
			}
			// plain browser: no offline store → nothing to clear.
		});

	// ponytail: default ack = keepalive POST so the request survives the navigation
	// that follows logout. Best-effort: errors are logged but never block logout.
	const ack =
		deps.postAck ??
		((deviceId: number) =>
			fetch('/api/offline/wipe-ack', {
				method: 'POST',
				credentials: 'include',
				keepalive: true,
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ device_id: deviceId }),
			}).then(() => {}));

	return subscribeControl('offline.wipe', async (payload) => {
		const deviceId = typeof payload.deviceId === 'number' ? payload.deviceId : undefined;

		// Targeting (SECURITY): an admin wipe of ONE device carries that device's
		// canonical devices.id (server pushes user_devices.device_id). The push fans
		// out on the user's shared tag:{mbox} channel to EVERY connected session, so
		// each recipient must fire only if its own devices.id matches. A payload with
		// NO deviceId is the explicit all-my-devices
		// wipe and fires everywhere. Fail CLOSED: a device that can't read its own
		// id no-ops on a targeted wipe (the real target has its id and wipes) — never
		// over-wipe a sibling.
		if (deviceId !== undefined && (await ownDeviceId()) !== deviceId) {
			return;
		}

		try {
			await clear();
		} catch (e) {
			console.error('offline wipe: native cache clear failed (continuing to logout)', e);
		}

		// ponytail: fire-and-forget — logout must not block on ack, and keepalive
		// ensures the POST survives the navigation. Errors are logged only.
		if (deviceId != null) {
			void ack(deviceId).catch((e) =>
				console.error('offline wipe: server ack failed (wipe_acked_at not set)', e)
			);
		}

		deps.logout();
	});
}

// installCapsHandler subscribes to the server's capsChanged control push.
// When an admin flips the offline-mail toggle the server broadcasts
// {"type":"capsChanged"} (no embedded data) and each client re-fetches its
// own caps so the gate + watermark policy update without a page reload.
// Bootstrap: also fetches caps immediately on mount so watermarkEnabled is set
// from the initial payload — not just on a mid-session capsChanged push.
// ponytail: same WS subscription pattern as installWipeHandler; deps.fetch
// is injectable for test isolation.
export function installCapsHandler(deps?: {
	fetch?: typeof globalThis.fetch;
	available?: () => boolean;
}): () => void {
	// Offline mail is native-only. A plain authenticated browser has no
	// SQLCipher store to govern, so it must not probe a native capability
	// endpoint on every page load (or subscribe to refresh a capability it
	// cannot consume). The injected predicate keeps this boundary executable in
	// unit tests without fabricating a window.setjoinNative bridge.
	if (!(deps?.available ?? isOfflineAvailable)()) return () => {};

	const doFetch = deps?.fetch ?? ((...a: Parameters<typeof fetch>) => fetch(...a));

	async function applyCaps(): Promise<void> {
		try {
			const res = await doFetch('/api/user/offline/caps', { credentials: 'include' });
			if (!res.ok) return;
			const c = (await res.json()) as OfflineCaps;
			offline.capsAllowed = c.allowed;
			offline.watermarkEnabled = c.watermark ?? false;
		} catch {
			// best-effort: caps stay at last known value on transient failure
		}
	}

	void applyCaps(); // ponytail: bootstrap watermark + allowed on load, not just on push
	return subscribeControl('capsChanged', applyCaps);
}
