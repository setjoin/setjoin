//! Electron-backed preflight probes for MEET M5 local capture — the
//! production `PreflightDeps` assembly slice 2's composition-root wiring
//! passes into `runCapturePreflight` (the `handlers/os.ts` pattern: effects
//! injected, decision core electron-free). NOT imported by unit tests; the
//! pure core in preflight.ts carries the tested guarantees.
//!
//! Permission mapping is honest per platform and fails to 'unknown' (never
//! 'granted') whenever the OS state cannot be read:
//!   - macOS: microphone → AVFoundation mic status; system-audio capture
//!     rides the screen-recording approval surface, so it maps to the
//!     screen status (documented approximation).
//!   - Windows: microphone → OS mic privacy status; system-audio is WASAPI
//!     loopback, which has no OS permission gate ('granted' is the truthful
//!     "no gate exists" answer, not an invented approval).
//!   - Linux (X11/Wayland/信创): PipeWire/PulseAudio exposes no stable
//!     permission API from Electron — microphone reports 'unknown' and
//!     system-audio 'unavailable' (fail-closed, action-required upstream).

import { systemPreferences } from 'electron';

import {
	nodeFreeDiskBytes,
	observedCaptureIdentity,
	type CaptureSurfaceId,
	type PermissionWireState,
	type PreflightDeps,
} from './preflight';

type ElectronMediaAccessStatus = 'not-determined' | 'granted' | 'denied' | 'restricted' | 'unknown';

function toWireState(status: ElectronMediaAccessStatus): PermissionWireState {
	switch (status) {
		case 'not-determined':
			return 'not_determined';
		case 'granted':
			return 'granted';
		case 'denied':
			return 'denied';
		case 'restricted':
			return 'restricted';
		case 'unknown':
			return 'unknown';
	}
}

function permissionStatus(surface: CaptureSurfaceId): PermissionWireState {
	try {
		if (process.platform === 'darwin') {
			// system-audio taps ride the screen-recording approval surface on macOS.
			const mediaType = surface === 'microphone' ? 'microphone' : 'screen';
			return toWireState(systemPreferences.getMediaAccessStatus(mediaType));
		}
		if (process.platform === 'win32') {
			if (surface === 'microphone') return toWireState(systemPreferences.getMediaAccessStatus('microphone'));
			// WASAPI loopback: no OS permission gate exists for system audio.
			return 'granted';
		}
		// Linux and other platforms: Electron exposes no permission read.
		return surface === 'systemAudio' ? 'unavailable' : 'unknown';
	} catch {
		return 'unknown'; // probe failure must never read as granted
	}
}

/** Production deps for `runCapturePreflight` (Electron main). */
export function makeElectronPreflightDeps(nowMs: () => number = Date.now): PreflightDeps {
	return {
		identity: observedCaptureIdentity,
		// M5 slice 1 surfaces: both are microphone-class capture APIs in the
		// Electron main runtime. Slice 2 narrows this against the qualified,
		// version-pinned capture profile before any capture is admitted.
		surfacesSupported: () => ['microphone', 'systemAudio'],
		freeDiskBytes: nodeFreeDiskBytes,
		permissionStatus,
		nowMs,
	};
}
