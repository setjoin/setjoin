// blur.test.ts — Meet B1 Task 16b. @livekit/track-processors pulls in a real
// WASM/mediapipe stack, so it's mocked entirely (the same seam
// codecProbe/room.svelte.test.ts use for livekit-client itself).
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const supportsBackgroundProcessors = vi.fn(() => true);
const setProcessor = vi.fn(async () => undefined);
const stopProcessor = vi.fn(async () => undefined);
const BackgroundProcessor = vi.fn((_opts: Record<string, unknown>) => ({ id: 'fake-processor' }));

vi.mock('@livekit/track-processors', () => ({
	BackgroundProcessor: (opts: Record<string, unknown>) => BackgroundProcessor(opts),
	supportsBackgroundProcessors: () => supportsBackgroundProcessors(),
}));

const { isBlurAvailable, loadBlurPref, saveBlurPref, setBlur } = await import('./blur');

function fakeTrack() {
	return { setProcessor, stopProcessor } as unknown as Parameters<typeof setBlur>[0];
}

beforeEach(() => {
	setProcessor.mockClear();
	stopProcessor.mockClear();
	BackgroundProcessor.mockClear();
	supportsBackgroundProcessors.mockReturnValue(true);
	localStorage.clear();
});

afterEach(() => {
	vi.unstubAllGlobals();
});

describe('isBlurAvailable', () => {
	it('is hidden for vp8 (the weak-hardware/信创-desktop probe signal) regardless of browser support', () => {
		expect(isBlurAvailable('vp8')).toBe(false);
		expect(supportsBackgroundProcessors).not.toHaveBeenCalled();
	});

	it('defers to the browser-capability check for vp9/av1', () => {
		supportsBackgroundProcessors.mockReturnValue(true);
		expect(isBlurAvailable('vp9')).toBe(true);
		supportsBackgroundProcessors.mockReturnValue(false);
		expect(isBlurAvailable('av1')).toBe(false);
	});

	it('a throwing capability check collapses to unsupported, never throws out', () => {
		supportsBackgroundProcessors.mockImplementation(() => {
			throw new Error('boom');
		});
		expect(isBlurAvailable('vp9')).toBe(false);
	});
});

describe('setBlur', () => {
	it('enabling calls BackgroundProcessor({mode: background-blur}) and track.setProcessor, returns true', async () => {
		const track = fakeTrack();
		const ok = await setBlur(track, true);
		expect(ok).toBe(true);
		expect(BackgroundProcessor).toHaveBeenCalledWith(expect.objectContaining({ mode: 'background-blur' }));
		expect(setProcessor).toHaveBeenCalledWith({ id: 'fake-processor' });
	});

	it('the processor is instructed to use self-hosted asset paths, never a CDN URL', async () => {
		await setBlur(fakeTrack(), true);
		const opts = BackgroundProcessor.mock.calls[0][0] as { assetPaths: Record<string, string> };
		expect(opts.assetPaths.tasksVisionFileSet).not.toMatch(/^https?:\/\//);
		expect(opts.assetPaths.modelAssetPath).not.toMatch(/^https?:\/\//);
	});

	it('disabling calls track.stopProcessor, returns true', async () => {
		const track = fakeTrack();
		const ok = await setBlur(track, false);
		expect(ok).toBe(true);
		expect(stopProcessor).toHaveBeenCalled();
		expect(setProcessor).not.toHaveBeenCalled();
	});

	it('a thrown attach error is swallowed and returns false — the toggle never half-works', async () => {
		setProcessor.mockRejectedValueOnce(new Error('unsupported at runtime'));
		const ok = await setBlur(fakeTrack(), true);
		expect(ok).toBe(false);
	});
});

describe('blur preference persistence', () => {
	it('defaults to false and round-trips through localStorage', () => {
		expect(loadBlurPref()).toBe(false);
		saveBlurPref(true);
		expect(loadBlurPref()).toBe(true);
		saveBlurPref(false);
		expect(loadBlurPref()).toBe(false);
	});

	it('a localStorage failure never throws — load defaults false, save is silently dropped', () => {
		vi.stubGlobal('localStorage', {
			getItem: () => {
				throw new Error('quota');
			},
			setItem: () => {
				throw new Error('quota');
			},
		});
		expect(loadBlurPref()).toBe(false);
		expect(() => saveBlurPref(true)).not.toThrow();
	});
});
