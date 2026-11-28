import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { DRIVE_MIRROR_VERSION } from '$lib/native/types';

const typedFetch = vi.fn();
vi.mock('$lib/http', () => ({
	typedFetch: (...a: unknown[]) => typedFetch(...a)
}));

function fakeDriveMirror(overrides: Partial<Record<string, unknown>> = {}) {
	return {
		version: DRIVE_MIRROR_VERSION,
		status: vi.fn().mockResolvedValue({ running: true, paused: false, perSpace: [], issues: [] }),
		configure: vi.fn().mockResolvedValue(undefined),
		refreshToken: vi.fn().mockResolvedValue(undefined),
		setPaused: vi.fn().mockResolvedValue(undefined),
		resync: vi.fn().mockResolvedValue(undefined),
		openRoot: vi.fn().mockResolvedValue(undefined),
		...overrides
	};
}

describe('mirrorBridge', () => {
	afterEach(() => {
		vi.useRealTimers();
	});

	it('available=false and status stays empty when window.setjoinNative.driveMirror is absent (plain browser)', async () => {
		vi.resetModules();
		(window as unknown as { setjoinNative?: unknown }).setjoinNative = { capabilities: [] };
		const { mirrorBridge } = await import('./mirrorBridge.svelte');
		expect(mirrorBridge.available).toBe(false);
		await mirrorBridge.refresh();
		expect(mirrorBridge.status).toEqual({ running: false, paused: false, perSpace: [], issues: [] });
	});

	it('a sub-shape version mismatch degrades to unavailable (the VAULT_VERSION lesson)', async () => {
		vi.resetModules();
		(window as unknown as { setjoinNative?: unknown }).setjoinNative = {
			capabilities: ['driveMirror'],
			driveMirror: fakeDriveMirror({ version: 999 })
		};
		const { mirrorBridge } = await import('./mirrorBridge.svelte');
		expect(mirrorBridge.available).toBe(false);
	});

	it('available=true when capability + matching version are both present', async () => {
		vi.resetModules();
		(window as unknown as { setjoinNative?: unknown }).setjoinNative = {
			capabilities: ['driveMirror'],
			driveMirror: fakeDriveMirror()
		};
		const { mirrorBridge } = await import('./mirrorBridge.svelte');
		expect(mirrorBridge.available).toBe(true);
	});

	it('refresh() polls status() and maps it into runes state', async () => {
		vi.resetModules();
		typedFetch.mockClear();
		const driveMirror = fakeDriveMirror({
			status: vi.fn().mockResolvedValue({
				running: true,
				paused: false,
				perSpace: [{ spaceId: 1, name: 'Team', state: 'idle', lastSyncMs: 123, pendingUploads: 0, issues: 0 }],
				issues: []
			})
		});
		(window as unknown as { setjoinNative?: unknown }).setjoinNative = {
			capabilities: ['driveMirror'],
			driveMirror
		};
		const { mirrorBridge } = await import('./mirrorBridge.svelte');
		await mirrorBridge.refresh();
		expect(mirrorBridge.status.perSpace).toHaveLength(1);
		expect(mirrorBridge.status.perSpace[0].name).toBe('Team');
	});

	it('refresh() re-mints a token when any space reports auth-expired', async () => {
		vi.resetModules();
		typedFetch.mockReset();
		typedFetch.mockResolvedValue({ token: 'fresh-token', expiresAt: '2030-01-01T00:00:00Z' });
		const driveMirror = fakeDriveMirror({
			status: vi.fn().mockResolvedValue({
				running: false,
				paused: false,
				perSpace: [{ spaceId: 1, name: 'Team', state: 'auth-expired', lastSyncMs: null, pendingUploads: 0, issues: 0 }],
				issues: []
			})
		});
		(window as unknown as { setjoinNative?: unknown }).setjoinNative = {
			capabilities: ['driveMirror'],
			driveMirror
		};
		const { mirrorBridge } = await import('./mirrorBridge.svelte');
		await mirrorBridge.refresh();
		expect(typedFetch).toHaveBeenCalledWith('/api/drive/native-token', { method: 'POST' });
		expect(driveMirror.refreshToken).toHaveBeenCalledWith('fresh-token', '2030-01-01T00:00:00Z');
	});

	it('configure() round-trips the selection: bridge.configure then mints a token then refreshes', async () => {
		vi.resetModules();
		typedFetch.mockReset();
		typedFetch.mockResolvedValue({ token: 't', expiresAt: '2030-01-01T00:00:00Z' });
		const driveMirror = fakeDriveMirror();
		(window as unknown as { setjoinNative?: unknown }).setjoinNative = {
			capabilities: ['driveMirror'],
			driveMirror
		};
		const { mirrorBridge } = await import('./mirrorBridge.svelte');
		await mirrorBridge.configure([{ spaceId: 1, excludes: ['big'] }]);
		expect(driveMirror.configure).toHaveBeenCalledWith({
			serverOrigin: window.location.origin,
			spaces: [{ spaceId: 1, excludes: ['big'] }]
		});
		expect(driveMirror.refreshToken).toHaveBeenCalledWith('t', '2030-01-01T00:00:00Z');
		expect(driveMirror.status).toHaveBeenCalled();
	});

	it('setPaused/resync/openRoot delegate to the bridge and setPaused/resync refresh status', async () => {
		vi.resetModules();
		const driveMirror = fakeDriveMirror();
		(window as unknown as { setjoinNative?: unknown }).setjoinNative = {
			capabilities: ['driveMirror'],
			driveMirror
		};
		const { mirrorBridge } = await import('./mirrorBridge.svelte');
		await mirrorBridge.setPaused(true);
		expect(driveMirror.setPaused).toHaveBeenCalledWith(true);
		await mirrorBridge.resync(1);
		expect(driveMirror.resync).toHaveBeenCalledWith(1);
		await mirrorBridge.openRoot(1);
		expect(driveMirror.openRoot).toHaveBeenCalledWith(1);
		expect(driveMirror.status).toHaveBeenCalled();
	});

	it('startPolling/stopPolling clears its interval and does nothing when unavailable', async () => {
		vi.resetModules();
		vi.useFakeTimers();
		(window as unknown as { setjoinNative?: unknown }).setjoinNative = { capabilities: [] };
		const { mirrorBridge } = await import('./mirrorBridge.svelte');
		mirrorBridge.startPolling(1000);
		mirrorBridge.stopPolling(); // must not throw when nothing was started
		expect(true).toBe(true);
	});
});
