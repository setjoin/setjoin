import { describe, it, expect, vi, afterEach } from 'vitest';
import {
	isPushSupported,
	permissionState,
	enablePushNotifications,
	registerNativePush,
} from './subscribe';
import type { SetjoinNativeBridge } from '$lib/native/types';

afterEach(() => {
	vi.unstubAllGlobals();
	delete (window as { setjoinNative?: unknown }).setjoinNative;
});

function nativeShell(overrides: Partial<SetjoinNativeBridge> = {}, ua = 'ArkWeb/OpenHarmony') {
	window.setjoinNative = {
		version: 1,
		capabilities: ['push'],
		pushRegister: vi.fn().mockResolvedValue('os-push-token'),
		pushDevicePublicKey: vi.fn().mockResolvedValue('04deadbeef'),
		...overrides,
	} as unknown as SetjoinNativeBridge;
	vi.stubGlobal('navigator', { ...navigator, userAgent: ua });
}

describe('registerNativePush (native shell push-MFA)', () => {
	it('no-ops on web (no native bridge)', async () => {
		const fetchMock = vi.fn();
		vi.stubGlobal('fetch', fetchMock);
		expect(await registerNativePush()).toBe(false);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it('no-ops when the shell lacks the push capability', async () => {
		const fetchMock = vi.fn();
		vi.stubGlobal('fetch', fetchMock);
		nativeShell({ capabilities: ['secureStore'] as SetjoinNativeBridge['capabilities'] });
		expect(await registerNativePush()).toBe(false);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it('skips registration when the push token is not available yet', async () => {
		const fetchMock = vi.fn();
		vi.stubGlobal('fetch', fetchMock);
		nativeShell({ pushRegister: vi.fn().mockResolvedValue(null) });
		expect(await registerNativePush()).toBe(false);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it('POSTs provider+token+device_public_key to /auth/device/register', async () => {
		const fetchMock = vi.fn().mockResolvedValue({ ok: true });
		vi.stubGlobal('fetch', fetchMock);
		nativeShell();

		expect(await registerNativePush()).toBe(true);

		const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe('/auth/device/register');
		const body = JSON.parse(init.body as string);
		expect(body.provider).toBe('hms'); // OpenHarmony UA
		expect(body.push_token).toBe('os-push-token');
		expect(body.device_public_key).toBe('04deadbeef');
	});
});

describe('permissionState (H5 binding: must never prompt)', () => {
	it('reports unsupported when Notification/PushManager/serviceWorker are absent', () => {
		expect(isPushSupported()).toBe(false);
		expect(permissionState()).toBe('unsupported');
	});

	it('maps Notification.permission to the 3 states without calling requestPermission', () => {
		const requestPermission = vi.fn();
		vi.stubGlobal('Notification', { permission: 'granted', requestPermission });
		vi.stubGlobal('window', { ...window, PushManager: class {} });
		vi.stubGlobal('navigator', { ...navigator, serviceWorker: {} });

		expect(permissionState()).toBe('granted');
		expect(requestPermission).not.toHaveBeenCalled();
	});

	it('maps denied', () => {
		vi.stubGlobal('Notification', { permission: 'denied', requestPermission: vi.fn() });
		vi.stubGlobal('window', { ...window, PushManager: class {} });
		vi.stubGlobal('navigator', { ...navigator, serviceWorker: {} });
		expect(permissionState()).toBe('denied');
	});

	it('maps the browser default to not-asked', () => {
		vi.stubGlobal('Notification', { permission: 'default', requestPermission: vi.fn() });
		vi.stubGlobal('window', { ...window, PushManager: class {} });
		vi.stubGlobal('navigator', { ...navigator, serviceWorker: {} });
		expect(permissionState()).toBe('not-asked');
	});
});

describe('enablePushNotifications (only ever called from a user click)', () => {
	it('returns unsupported without touching any push API when unsupported', async () => {
		expect(await enablePushNotifications()).toBe('unsupported');
	});

	it('prompts, subscribes, and registers the device on success', async () => {
		const requestPermission = vi.fn().mockResolvedValue('granted');
		const subscription = { endpoint: 'https://push.example/x', keys: { p256dh: 'a', auth: 'b' } };
		const subscribe = vi.fn().mockResolvedValue(subscription);
		const getSubscription = vi.fn().mockResolvedValue(null);

		vi.stubGlobal('Notification', { permission: 'default', requestPermission });
		vi.stubGlobal('window', { ...window, PushManager: class {} });
		vi.stubGlobal('navigator', {
			...navigator,
			serviceWorker: { ready: Promise.resolve({ pushManager: { getSubscription, subscribe } }) },
			userAgent: 'vitest',
		});
		vi.stubGlobal('atob', (s: string) => Buffer.from(s, 'base64').toString('binary'));

		const fetchMock = vi.fn((url: string, _init?: RequestInit) => {
			if (url === '/auth/push/vapid-key') {
				return Promise.resolve({ ok: true, json: async () => ({ vapid_public_key: 'abcd' }) });
			}
			if (url === '/auth/device/register') {
				return Promise.resolve({ ok: true });
			}
			throw new Error('unexpected fetch ' + url);
		});
		vi.stubGlobal('fetch', fetchMock);

		const result = await enablePushNotifications();

		expect(result).toBe('granted');
		expect(requestPermission).toHaveBeenCalledOnce();
		expect(subscribe).toHaveBeenCalledOnce();
		const registerCall = fetchMock.mock.calls.find(([url]) => url === '/auth/device/register')!;
		const body = JSON.parse((registerCall[1] as RequestInit).body as string);
		expect(body.provider).toBe('webpush');
		expect(JSON.parse(body.push_token)).toEqual(subscription);
	});

	it('returns denied (not throw) when the user dismisses the native prompt', async () => {
		vi.stubGlobal('Notification', { permission: 'default', requestPermission: vi.fn().mockResolvedValue('denied') });
		vi.stubGlobal('window', { ...window, PushManager: class {} });
		vi.stubGlobal('navigator', { ...navigator, serviceWorker: {} });

		expect(await enablePushNotifications()).toBe('denied');
	});

	it('reuses an existing subscription instead of creating a duplicate', async () => {
		const existing = { endpoint: 'https://push.example/existing' };
		const subscribe = vi.fn();
		const getSubscription = vi.fn().mockResolvedValue(existing);

		vi.stubGlobal('Notification', { permission: 'granted', requestPermission: vi.fn() });
		vi.stubGlobal('window', { ...window, PushManager: class {} });
		vi.stubGlobal('navigator', {
			...navigator,
			serviceWorker: { ready: Promise.resolve({ pushManager: { getSubscription, subscribe } }) },
			userAgent: 'vitest',
		});
		vi.stubGlobal('atob', (s: string) => Buffer.from(s, 'base64').toString('binary'));
		vi.stubGlobal('fetch', vi.fn((url: string) => {
			if (url === '/auth/push/vapid-key') return Promise.resolve({ ok: true, json: async () => ({ vapid_public_key: 'abcd' }) });
			return Promise.resolve({ ok: true });
		}));

		expect(await enablePushNotifications()).toBe('granted');
		expect(subscribe).not.toHaveBeenCalled();
	});
});
