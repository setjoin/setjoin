import { getNative, isNative, hasCapability } from '$lib/native';

// Web Push subscribe flow (QoL #9). H5 binding: this module NEVER calls
// Notification.requestPermission() on its own initiative — every exported
// function that can trigger the native permission prompt is only ever wired
// to a user click (the Settings > Notifications "Enable" button). Reading
// current state (permissionState) is always safe to call on load.

export type PushPermissionState = 'not-asked' | 'granted' | 'denied' | 'unsupported';

/** Whether this browser can do Web Push at all (no SW / no PushManager / no Notification). */
export function isPushSupported(): boolean {
	return (
		typeof window !== 'undefined' &&
		'serviceWorker' in navigator &&
		'PushManager' in window &&
		typeof Notification !== 'undefined'
	);
}

/** Read-only: today's permission state. Safe to call on page load — never prompts. */
export function permissionState(): PushPermissionState {
	if (!isPushSupported()) return 'unsupported';
	switch (Notification.permission) {
		case 'granted':
			return 'granted';
		case 'denied':
			return 'denied';
		default:
			return 'not-asked';
	}
}

function urlBase64ToUint8Array(base64: string): Uint8Array {
	const padding = '='.repeat((4 - (base64.length % 4)) % 4);
	const base64Safe = (base64 + padding).replace(/-/g, '+').replace(/_/g, '/');
	const raw = atob(base64Safe);
	return Uint8Array.from([...raw].map((c) => c.charCodeAt(0)));
}

/**
 * The user-click-only entry point: requests the native permission prompt (if
 * not already decided), then subscribes pushManager and uploads the
 * subscription. Returns the resulting state; throws only on a genuine
 * unexpected error (network/server) — a user-denied prompt is a normal
 * 'denied' return, not a throw.
 */
export async function enablePushNotifications(): Promise<PushPermissionState> {
	if (!isPushSupported()) return 'unsupported';

	let permission = Notification.permission;
	if (permission === 'default') {
		permission = await Notification.requestPermission();
	}
	if (permission !== 'granted') return permission === 'denied' ? 'denied' : 'not-asked';

	const keyRes = await fetch('/auth/push/vapid-key', { credentials: 'include' });
	if (!keyRes.ok) throw new Error('push not configured on this server');
	const { vapid_public_key: vapidKey } = await keyRes.json();

	const registration = await navigator.serviceWorker.ready;
	let subscription = await registration.pushManager.getSubscription();
	if (!subscription) {
		subscription = await registration.pushManager.subscribe({
			userVisibleOnly: true,
			// The Uint8Array is a real BufferSource at runtime; the cast is only
			// needed because lib.dom's generic ArrayBufferLike vs. ArrayBuffer
			// parametrization doesn't line up here.
			applicationServerKey: urlBase64ToUint8Array(vapidKey) as BufferSource,
		});
	}

	const res = await fetch('/auth/device/register', {
		method: 'POST',
		credentials: 'include',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({
			provider: 'webpush',
			push_token: JSON.stringify(subscription),
			device_name: navigator.userAgent.slice(0, 120),
		}),
	});
	if (!res.ok) throw new Error('failed to register push subscription');

	return 'granted';
}

/** The native OS push provider for the current shell, or null on web/unknown. */
function nativePushProvider(): 'apns' | 'fcm' | 'hms' | null {
	const ua = typeof navigator !== 'undefined' ? navigator.userAgent : '';
	// ponytail: UA sniff instead of a new bridge getter (binding: no new bridge
	// abstractions for a value the userAgent already carries). Only HarmonyOS
	// completes end-to-end today (real HMS token); apns/fcm capture is a
	// device-gated stub. Upgrade path: add a bridge provider getter if UA sniff
	// proves unreliable across shell WebView versions.
	if (/OpenHarmony|ArkWeb/i.test(ua)) return 'hms';
	if (/iPhone|iPad|iPod/i.test(ua)) return 'apns';
	if (/Android/i.test(ua)) return 'fcm';
	return null;
}

/**
 * Native-shell push-MFA registration: on a native shell advertising the `push`
 * capability, capture the OS push token + the device's ECDH public key and
 * register both with the server (so it can ECIES-encrypt push-MFA challenges).
 * The counterpart to the Web Push path above for native shells.
 *
 * No-op (returns false) on web, on a shell without `push`, when the token isn't
 * available yet (permission denied / not initialized), or when the vault is
 * locked (no ECDH key). Safe to call unconditionally at app boot — it never
 * prompts; it only reads a token the shell already holds. Returns whether the
 * device was registered.
 */
export async function registerNativePush(): Promise<boolean> {
	if (!isNative() || !hasCapability('push')) return false;
	const provider = nativePushProvider();
	if (!provider) return false;

	const native = getNative();
	const pushToken = await native.pushRegister();
	if (!pushToken) return false; // permission denied / token not captured yet

	const devicePublicKey = await native.pushDevicePublicKey();
	if (!devicePublicKey) return false; // vault locked — no key to register

	const res = await fetch('/auth/device/register', {
		method: 'POST',
		credentials: 'include',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({
			provider,
			push_token: pushToken,
			device_public_key: devicePublicKey,
			device_name: navigator.userAgent.slice(0, 120),
		}),
	});
	return res.ok;
}
