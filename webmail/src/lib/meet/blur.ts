// blur.ts — Meet B1 Task 16b: client-side background blur via
// @livekit/track-processors (spec §3.2 v1 must-have). Cost is small by
// construction: one npm dep + a toggle, zero server surface.
//
// Deviation from the plan's pseudocode (documented, not a real divergence
// — the plan's own Task 9 precedent already licenses this): the pinned
// package version (0.7.2) ships the unified `BackgroundProcessor({mode})`
// API + `supportsBackgroundProcessors()`; the plan's named `BackgroundBlur()`
// factory still exists but is `@deprecated` in favor of the mode-based one.
// Behavior/wiring matches the plan's intent exactly (probe-gated toggle,
// self-hosted WASM, setProcessor/stopProcessor on the local video track).
//
// Weak-hardware guard (locked): the Task 15 codec probe landing on 'vp8' is
// the signal for a weak/信创-desktop client — background segmentation is
// CPU/GPU-heavy, so the toggle is HIDDEN (never offered, never a broken
// switch) whenever codec === 'vp8', on top of the browser capability gate.
import { BackgroundProcessor, supportsBackgroundProcessors } from '@livekit/track-processors';
import type { LocalVideoTrack } from 'livekit-client';
import type { MeetCodec } from './codecProbe';

const BLUR_PREF_KEY = 'meet.blurEnabled';

// Self-hosted WASM + segmentation-model assets (locked — NEVER a CDN URL):
// the package's own default points at cdn.jsdelivr.net (WASM fileset) and
// storage.googleapis.com (the .tflite model). scripts/vendor-blur-assets.mjs
// (wired into package.json's predev/prebuild) copies/downloads both into
// static/meet/mediapipe/ at build time — same-origin, mirroring
// lib-livekit.sh's checksum-verified SFU-binary vendoring pattern.
const ASSET_PATHS = {
	tasksVisionFileSet: '/meet/mediapipe/wasm',
	modelAssetPath: '/meet/mediapipe/selfie_segmenter.tflite',
};

/** Probe-gated + browser-capability-gated visibility check (never throws —
 *  any detection failure collapses to "hidden", the spec's own posture). */
export function isBlurAvailable(codec: MeetCodec): boolean {
	if (codec === 'vp8') return false;
	try {
		return supportsBackgroundProcessors();
	} catch {
		return false;
	}
}

export function loadBlurPref(): boolean {
	try {
		return localStorage.getItem(BLUR_PREF_KEY) === 'true';
	} catch {
		return false;
	}
}

export function saveBlurPref(enabled: boolean): void {
	try {
		localStorage.setItem(BLUR_PREF_KEY, String(enabled));
	} catch {
		/* private-mode quota — preference just doesn't persist */
	}
}

/** Attaches/detaches the background-blur processor on `track`. Never
 *  throws — any failure (unsupported at runtime despite the probe gate, a
 *  missing vendored asset, a mid-attach error) collapses to `false` so the
 *  caller reverts its optimistic toggle state instead of shipping a
 *  half-working switch (Task 16b bullet 2's own posture). */
export async function setBlur(track: LocalVideoTrack, enabled: boolean): Promise<boolean> {
	try {
		if (!enabled) {
			await track.stopProcessor();
			return true;
		}
		const processor = BackgroundProcessor({ mode: 'background-blur', assetPaths: ASSET_PATHS });
		await track.setProcessor(processor);
		return true;
	} catch {
		return false;
	}
}
