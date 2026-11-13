import { describe, it, expect, vi, beforeEach } from 'vitest';
import { stubFetchRoutes } from '$lib/test-utils';
import { installWipeHandler, installCapsHandler } from './wipe';
import { __handleRawMessage } from '../jmap/websocket';
import { offline } from './state.svelte';

beforeEach(() => {
	delete (window as { setjoinNative?: unknown }).setjoinNative;
	offline.capsAllowed = false;
	offline.watermarkEnabled = false;
	// The default postAck fires a keepalive POST /api/offline/wipe-ack.
	stubFetchRoutes([['/api/offline/wipe-ack', {}]]);
});

// Build a native bridge mock that reports a given device_id from secureStore
// and a spyable db.wipe. deviceId undefined → secureStore has no device_id (a
// device that cannot identify itself, e.g. mid-enrollment).
function nativeBridge(deviceId: number | undefined, wipe = vi.fn().mockResolvedValue(undefined)) {
	window.setjoinNative = {
		// version: BRIDGE_VERSION — the native facade asserts the whole-bridge
		// version contract, so the fixture declares the compiled-against version.
		version: 1, capabilities: ['mailDb', 'secureStore'],
		secureStore: {
			get: async (k: string) => (k === 'device_id' && deviceId != null ? String(deviceId) : null),
			set: async () => {}, remove: async () => {},
		},
		db: { open: async () => {}, exec: async () => 0, query: async () => [], wipe, sizeBytes: async () => 0, freeBytes: async () => 0 },
	} as unknown as import('../native/types').SetjoinNativeBridge;
	return wipe;
}

// A few microtask flushes: the handler now awaits secureStore.get before deciding.
async function flush() {
	for (let i = 0; i < 4; i++) await Promise.resolve();
}

describe('offline.wipe self-wipe (offline-core mail store target)', () => {
	it('wipes + logs out when the push targets THIS device (deviceId matches own device_id)', async () => {
		const wipe = nativeBridge(1);
		const logout = vi.fn();
		const off = installWipeHandler({ logout });
		__handleRawMessage(JSON.stringify({ type: 'offline.wipe', deviceId: 1 }));
		await flush();
		expect(wipe).toHaveBeenCalledWith('mail');
		expect(logout).toHaveBeenCalledOnce();
		off();
	});

	it('does NOT wipe/ack/logout on a SIBLING device (push targets a different deviceId)', async () => {
		const wipe = nativeBridge(2); // this device is #2
		const postAck = vi.fn().mockResolvedValue(undefined);
		const logout = vi.fn();
		const off = installWipeHandler({ logout, postAck });
		__handleRawMessage(JSON.stringify({ type: 'offline.wipe', deviceId: 1 })); // admin targeted #1
		await flush();
		expect(wipe).not.toHaveBeenCalled();
		expect(postAck).not.toHaveBeenCalled();
		expect(logout).not.toHaveBeenCalled();
		off();
	});

	it('all-devices wipe (no deviceId in payload) fires everywhere, regardless of own id', async () => {
		const wipe = nativeBridge(7);
		const logout = vi.fn();
		const off = installWipeHandler({ logout });
		__handleRawMessage(JSON.stringify({ type: 'offline.wipe' })); // no deviceId = wipe all
		await flush();
		expect(wipe).toHaveBeenCalledWith('mail');
		expect(logout).toHaveBeenCalledOnce();
		off();
	});

	it('targeted wipe on a device that cannot read its own id: no-op (fail closed against over-wipe)', async () => {
		const wipe = nativeBridge(undefined); // no device_id in secureStore
		const logout = vi.fn();
		const off = installWipeHandler({ logout });
		__handleRawMessage(JSON.stringify({ type: 'offline.wipe', deviceId: 1 }));
		await flush();
		expect(wipe).not.toHaveBeenCalled();
		expect(logout).not.toHaveBeenCalled();
		off();
	});

	it('plain browser (no bridge): all-devices wipe still logs out', async () => {
		const logout = vi.fn();
		const off = installWipeHandler({ logout });
		__handleRawMessage(JSON.stringify({ type: 'offline.wipe' })); // wipe-all reaches browser sessions too
		await flush();
		expect(logout).toHaveBeenCalledOnce();
		off();
	});

	it('logs out even if the native wipe rejects (best-effort; durable deny is server-side)', async () => {
		const wipe = vi.fn().mockRejectedValue(new Error('bridge error'));
		nativeBridge(1, wipe);
		const logout = vi.fn();
		const off = installWipeHandler({ logout });
		__handleRawMessage(JSON.stringify({ type: 'offline.wipe', deviceId: 1 }));
		await flush();
		expect(logout).toHaveBeenCalledOnce();
		off();
	});

	it('fires postAck with deviceId from push payload (server wipe_acked_at telemetry)', async () => {
		nativeBridge(42);
		const postAck = vi.fn().mockResolvedValue(undefined);
		const logout = vi.fn();
		const off = installWipeHandler({ logout, postAck });
		__handleRawMessage(JSON.stringify({ type: 'offline.wipe', deviceId: 42 }));
		await flush();
		expect(postAck).toHaveBeenCalledWith(42);
		expect(logout).toHaveBeenCalledOnce();
		off();
	});
});

describe('installCapsHandler: capsChanged → offline state', () => {
	it('does not probe caps in a plain browser without the native offline store', async () => {
		const mockFetch = vi.fn();
		const off = installCapsHandler({ fetch: mockFetch as unknown as typeof fetch });
		await Promise.resolve();
		expect(mockFetch).not.toHaveBeenCalled();
		off();
	});

	it('bootstraps watermark + allowed from initial caps fetch on mount (not just on push)', async () => {
		const mockFetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({
				allowed: true, watermark: true, approvalState: 'approved',
				maxOfflineDays: 30, wipeOnLogout: 'admin_default', requireApproval: false,
			}),
		});
		const off = installCapsHandler({
			fetch: mockFetch as unknown as typeof fetch,
			available: () => true,
		});
		// No push fired — bootstrap fetch should have applied caps immediately.
		await Promise.resolve(); await Promise.resolve(); await Promise.resolve();
		expect(offline.watermarkEnabled).toBe(true);
		expect(offline.capsAllowed).toBe(true);
		expect(mockFetch).toHaveBeenCalledOnce(); // one call on mount, before any push
		expect(mockFetch).toHaveBeenCalledWith('/api/user/offline/caps', { credentials: 'include' });
		off();
	});

	it('applies allowed + watermark from caps payload on capsChanged', async () => {
		const mockFetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({
				allowed: true, watermark: true, approvalState: 'approved',
				maxOfflineDays: 30, wipeOnLogout: 'admin_default', requireApproval: false,
			}),
		});
		const off = installCapsHandler({
			fetch: mockFetch as unknown as typeof fetch,
			available: () => true,
		});
		__handleRawMessage(JSON.stringify({ type: 'capsChanged' }));
		// flush the async subscribeControl handler
		await Promise.resolve(); await Promise.resolve(); await Promise.resolve();
		expect(offline.capsAllowed).toBe(true);
		expect(offline.watermarkEnabled).toBe(true);
		off();
	});

	it('sets watermarkEnabled false when watermark field absent', async () => {
		const mockFetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({
				allowed: true, approvalState: 'approved',
				maxOfflineDays: 7, wipeOnLogout: 'never', requireApproval: false,
			}),
		});
		const off = installCapsHandler({
			fetch: mockFetch as unknown as typeof fetch,
			available: () => true,
		});
		__handleRawMessage(JSON.stringify({ type: 'capsChanged' }));
		await Promise.resolve(); await Promise.resolve(); await Promise.resolve();
		expect(offline.watermarkEnabled).toBe(false);
		off();
	});

	it('ignores a non-ok response (best-effort, state unchanged)', async () => {
		const mockFetch = vi.fn().mockResolvedValue({ ok: false });
		const off = installCapsHandler({
			fetch: mockFetch as unknown as typeof fetch,
			available: () => true,
		});
		__handleRawMessage(JSON.stringify({ type: 'capsChanged' }));
		await Promise.resolve(); await Promise.resolve(); await Promise.resolve();
		expect(offline.capsAllowed).toBe(false);
		expect(offline.watermarkEnabled).toBe(false);
		off();
	});
});
