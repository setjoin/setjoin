// PreJoin.test.ts — Meet B1 Task 16, design #1's named tests: the
// denied-device state still allows a receive-only join, and the probe
// result renders while the Join button independently gates on the
// `joining` prop (never on the probe itself resolving).
import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import PreJoin from './PreJoin.svelte';

const { FakeLocalVideoTrack } = vi.hoisted(() => {
	class FakeLocalVideoTrack {
		attach = vi.fn();
		detach = vi.fn();
		constructor(public mediaStreamTrack: unknown) {}
	}
	return { FakeLocalVideoTrack };
});
vi.mock('livekit-client', () => ({
	Room: { getLocalDevices: vi.fn(async () => []) },
	LocalVideoTrack: FakeLocalVideoTrack,
}));

const pickVideoCodec = vi.fn(async () => 'vp9' as const);
vi.mock('$lib/meet/codecProbe', () => ({
	pickVideoCodec: () => pickVideoCodec(),
}));

// Task 16b: default unsupported so the pre-existing tests below (written
// before blur existed) keep exercising the plain preview path unchanged;
// the two blur-specific tests override this per-case.
const isBlurAvailable = vi.fn((_codec: string) => false);
const setBlur = vi.fn(async (_track: unknown, _enabled: boolean) => true);
vi.mock('$lib/meet/blur', () => ({
	isBlurAvailable: (codec: string) => isBlurAvailable(codec),
	loadBlurPref: () => false,
	saveBlurPref: () => undefined,
	setBlur: (track: unknown, enabled: boolean) => setBlur(track, enabled),
}));

function fakeStream() {
	const videoTrack = { kind: 'video', enabled: true, stop: vi.fn() };
	const audioTrack = { kind: 'audio', enabled: true, stop: vi.fn() };
	return {
		getAudioTracks: () => [audioTrack],
		getVideoTracks: () => [videoTrack],
		getTracks: () => [audioTrack, videoTrack],
	} as unknown as MediaStream;
}

afterEach(() => {
	vi.clearAllMocks();
	vi.unstubAllGlobals();
	isBlurAvailable.mockReturnValue(false);
});

describe('PreJoin', () => {
	it('renders the denied-state help and still allows a receive-only join', async () => {
		vi.stubGlobal('navigator', {
			...navigator,
			mediaDevices: {
				getUserMedia: async () => {
					const err = new Error('denied');
					err.name = 'NotAllowedError';
					throw err;
				},
			},
		});
		const onJoin = vi.fn();
		render(PreJoin, { onJoin });

		const joinReceiveOnlyBtn = await screen.findByText(/receive-only|without camera|without mic/i);
		expect(joinReceiveOnlyBtn).toBeTruthy();
		await fireEvent.click(joinReceiveOnlyBtn);
		expect(onJoin).toHaveBeenCalledWith(expect.objectContaining({ micOn: false, camOn: false }));
	});

	it('renders the probe result and disables Join only via the `joining` prop, never the probe itself', async () => {
		vi.stubGlobal('navigator', {
			...navigator,
			mediaDevices: {
				getUserMedia: async () => {
					const err = new Error('none');
					err.name = 'NotFoundError';
					throw err;
				},
			},
		});
		const onJoin = vi.fn();
		const { rerender } = render(PreJoin, { onJoin, joining: true });

		// Join is disabled while a join is already in flight (waiting on the token) …
		const joinBtn = screen.getByText(/Loading|Join/i).closest('button')!;
		expect(joinBtn).toBeDisabled();

		// … but resolves/renders the probe's result independently of that flag.
		await vi.waitFor(() => expect(pickVideoCodec).toHaveBeenCalled());
		await screen.findByTestId('prejoin-codec');

		// Once joining flips back to false the button re-enables — the probe
		// never held it hostage in the first place.
		await rerender({ onJoin, joining: false });
		expect(screen.getByText('Join').closest('button')).not.toBeDisabled();
	});

	// Task 16b: the blur toggle is hidden entirely — never a broken switch —
	// whenever the codec/browser gate says unsupported (vp8 fallback or a
	// browser lacking the background-processor stack).
	it('hides the blur toggle when the codec/browser gate says unsupported', async () => {
		isBlurAvailable.mockReturnValue(false);
		vi.stubGlobal('navigator', { ...navigator, mediaDevices: { getUserMedia: async () => fakeStream() } });
		render(PreJoin, { onJoin: vi.fn() });

		await vi.waitFor(() => expect(pickVideoCodec).toHaveBeenCalled());
		expect(screen.queryByText(/blur/i)).toBeNull();
	});

	it('shows the blur toggle and applies/persists it when the gate says supported', async () => {
		isBlurAvailable.mockReturnValue(true);
		vi.stubGlobal('navigator', { ...navigator, mediaDevices: { getUserMedia: async () => fakeStream() } });
		const onJoin = vi.fn();
		render(PreJoin, { onJoin });

		const toggle = await screen.findByText(/blur/i);
		await fireEvent.click(toggle);
		expect(setBlur).toHaveBeenCalledWith(expect.any(FakeLocalVideoTrack), true);

		const joinBtn = screen.getByText('Join').closest('button')!;
		await fireEvent.click(joinBtn);
		expect(onJoin).toHaveBeenCalledWith(expect.objectContaining({ blurEnabled: true }));
	});
});
