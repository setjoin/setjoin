//! Capture preflight for Electron local-first capture (MEET M5 slice 1).
//!
//! Pure, electron-free decision core with injected probes (the `handlers/os.ts`
//! pattern: main supplies the platform effects). Produces one typed,
//! serializable `CapturePreflight` per run: capability detection (capture
//! surfaces + the version-pinned platform/capture identity), the fit-to-space
//! disk check, and per-surface permission status. Admission is fail-closed:
//! every probe error or unknown status is action-required, never a silent
//! degradation — insufficient disk or an unprovable state refuses admission
//! with a named action instead of downgrading the capture plan.
//!
//! Flag discipline: with `feature.meet_local_recording` in rollout mode `off`
//! the preflight is structurally inert — `runCapturePreflight` returns the
//! `inert_flag_off` variant WITHOUT calling any injected probe (see rollout.ts).
//! In `observe` it may run (read-only probes); `execute` admits capture.

import * as fs from 'node:fs/promises';
import * as os from 'node:os';

import { MEET_LOCAL_RECORDING_FLAG, probesAdmitted, type MeetLocalRecordingRolloutMode } from './rollout';

/** Capture surfaces M5 slice 1 reasons about. Video surfaces stay outside
 *  this substrate (the separately authorized B2 MP4 keeps that role). */
export type CaptureSurfaceId = 'microphone' | 'systemAudio';

export const ALL_CAPTURE_SURFACES: readonly CaptureSurfaceId[] = ['microphone', 'systemAudio'];

/** Typed check outcome. `action_required` ALWAYS carries a human-action
 *  string; `unknown` means the probe could not prove anything (fail-closed). */
export type PreflightCheckStatus = 'available' | 'unavailable' | 'action_required' | 'unknown';

/** The version-pinned platform/capture identity a preflight ran under (the
 *  2026-09-06 composition amendment: a platform or provider version change
 *  re-qualifies the affected capture profile — consumers pin THIS value, and
 *  every field is observed from the running runtime, never drafted). */
export interface CaptureIdentity {
	platform: string;
	platformVersion: string;
	/** Observed capture-stack identity (Electron + Chromium versions). */
	captureApiVersion: string;
}

export interface CapabilityCheck {
	check: 'capture_api';
	status: PreflightCheckStatus;
	/** Surfaces the runtime's capture APIs can actually produce. */
	surfacesAvailable: CaptureSurfaceId[];
	detail: string;
}

export interface DiskSpaceCheck {
	check: 'disk_space';
	status: PreflightCheckStatus;
	targetPath: string;
	/** Null when the probe failed — fail-closed, never assumed. */
	freeBytes: number | null;
	/** Fit-to-space estimate for the planned capture (headroom included). */
	requiredBytes: number;
	/** freeBytes − requiredBytes when both are known; null otherwise. */
	headroomBytes: number | null;
	detail: string;
	/** The named action a user/operator must take. Non-null exactly when the
	 *  status is `action_required` or `unknown` (insufficient disk is NEVER
	 *  silently degraded — the plan's fit-to-space honesty rule). */
	actionRequired: string | null;
}

/** Wire vocabulary mirrors Electron's `getMediaAccessStatus` states plus
 *  `unavailable` for a platform without the API. Serializable as-is. */
export type PermissionWireState =
	| 'granted'
	| 'denied'
	| 'not_determined'
	| 'restricted'
	| 'unknown'
	| 'unavailable';

export interface PermissionCheck {
	check: 'permission';
	status: PreflightCheckStatus;
	surface: CaptureSurfaceId;
	permission: PermissionWireState;
	detail: string;
}

export type PreflightCheck = CapabilityCheck | DiskSpaceCheck | PermissionCheck;

export interface CapturePreflightRequest {
	meetingId: number;
	/** Surfaces the planned local capture needs. */
	surfaces: CaptureSurfaceId[];
	plannedDurationMs: number;
	/** Planner's bitrate estimate for the requested surfaces. */
	estimatedBitsPerSecond: number;
	/** Directory the capture package will be written to (the probed volume). */
	captureDir: string;
}

export interface CapturePreflightResult {
	kind: 'result';
	meetingId: number;
	identity: CaptureIdentity;
	/** True only when every check proved available. Never true when anything
	 *  is action_required/unknown — capture cannot be offered. */
	admitted: boolean;
	/** The honest action list; empty exactly when admitted. */
	actionRequired: string[];
	checks: PreflightCheck[];
	ranAtUnixMs: number;
}

/** The inert shape returned in rollout mode `off`: no probe ran, nothing is
 *  known, capture is refused. Kept as a separate variant so a caller cannot
 *  mistake "flag off" for "checked and admitted". */
export interface CapturePreflightInert {
	kind: 'inert_flag_off';
	flag: typeof MEET_LOCAL_RECORDING_FLAG;
	detail: string;
	ranAtUnixMs: number;
}

export type CapturePreflight = CapturePreflightResult | CapturePreflightInert;

/** Platform probes injected by the host (electron-backed in production,
 *  faked in tests). Every probe may throw — a throw is the probe refusing to
 *  claim knowledge, mapped to `unknown` (fail-closed), never to `available`. */
export interface PreflightDeps {
	identity(): CaptureIdentity;
	/** Capability probe: which surfaces this runtime's capture APIs support. */
	surfacesSupported(): CaptureSurfaceId[];
	/** Free bytes on the volume holding `path`. Throws when unprovable. */
	freeDiskBytes(path: string): Promise<number>;
	/** OS permission state for one surface ('unavailable' where the OS has
	 *  no such concept — e.g. system-audio loopback on most Linux). */
	permissionStatus(surface: CaptureSurfaceId): PermissionWireState;
	nowMs(): number;
}

/** Disk safety headroom over the raw byte estimate — capture containers grow
 *  past their nominal bitrate, and the volume needs working space besides. */
export const DISK_HEADROOM_FACTOR = 1.25;

/** Fit-to-space estimate: planned seconds × bitrate, headroom included. */
export function estimateRequiredBytes(plannedDurationMs: number, bitsPerSecond: number): number {
	if (!Number.isFinite(plannedDurationMs) || plannedDurationMs <= 0) return 0;
	if (!Number.isFinite(bitsPerSecond) || bitsPerSecond <= 0) return 0;
	const rawBytes = Math.ceil((plannedDurationMs / 1000) * (bitsPerSecond / 8));
	return Math.ceil(rawBytes * DISK_HEADROOM_FACTOR);
}

function bytesGiB(bytes: number): string {
	return `${(bytes / 1024 ** 3).toFixed(2)} GiB`;
}

/** Run the full preflight. In rollout mode `off` this calls NO probe and
 *  returns the inert refusal (the substrate must be inert unless enabled). */
export async function runCapturePreflight(
	mode: MeetLocalRecordingRolloutMode,
	deps: PreflightDeps,
	request: CapturePreflightRequest,
): Promise<CapturePreflight> {
	const ranAtUnixMs = deps.nowMs();
	if (!probesAdmitted(mode)) {
		return {
			kind: 'inert_flag_off',
			flag: MEET_LOCAL_RECORDING_FLAG,
			detail: `local capture preflight is inert: ${MEET_LOCAL_RECORDING_FLAG} rollout mode is 'off'`,
			ranAtUnixMs,
		};
	}

	const identity = deps.identity();
	const checks: PreflightCheck[] = [];
	const actionRequired: string[] = [];

	// ── Capability probe ──────────────────────────────────────────────────
	let capabilityOk = true;
	let capability: CapabilityCheck;
	try {
		const available = deps.surfacesSupported();
		const missing = request.surfaces.filter((s) => !available.includes(s));
		capabilityOk = missing.length === 0;
		capability = {
			check: 'capture_api',
			status: capabilityOk ? 'available' : 'unavailable',
			surfacesAvailable: available,
			detail:
				capabilityOk
					? `capture APIs support the requested surfaces (${request.surfaces.join(', ')})`
					: `capture APIs cannot provide: ${missing.join(', ')}`,
		};
	} catch (error) {
		capabilityOk = false;
		capability = {
			check: 'capture_api',
			status: 'unknown',
			surfacesAvailable: [],
			detail: `capability probe failed: ${errorMessage(error)}`,
		};
	}
	checks.push(capability);
	if (!capabilityOk) {
		actionRequired.push(
			capability.status === 'unknown'
				? 'Verify local capture support on this platform before offering recording.'
				: `Local capture cannot offer the requested surfaces (${capability.detail}).`,
		);
	}

	// ── Fit-to-space disk check (honesty: insufficient = action-required) ─
	const requiredBytes = estimateRequiredBytes(request.plannedDurationMs, request.estimatedBitsPerSecond);
	let diskOk = true;
	let disk: DiskSpaceCheck;
	try {
		const freeBytes = await deps.freeDiskBytes(request.captureDir);
		const headroomBytes = freeBytes - requiredBytes;
		diskOk = headroomBytes >= 0;
		disk = {
			check: 'disk_space',
			status: diskOk ? 'available' : 'action_required',
			targetPath: request.captureDir,
			freeBytes,
			requiredBytes,
			headroomBytes,
			detail: `needs ${bytesGiB(requiredBytes)} (estimate + ${DISK_HEADROOM_FACTOR}x headroom), ${bytesGiB(freeBytes)} free`,
			actionRequired: diskOk
				? null
				: `Free at least ${bytesGiB(requiredBytes - freeBytes)} more on the capture volume (need ${bytesGiB(requiredBytes)}, have ${bytesGiB(freeBytes)}) or choose another capture directory.`,
		};
	} catch (error) {
		diskOk = false;
		disk = {
			check: 'disk_space',
			status: 'unknown',
			targetPath: request.captureDir,
			freeBytes: null,
			requiredBytes,
			headroomBytes: null,
			detail: `disk probe failed: ${errorMessage(error)}`,
			actionRequired:
				'Free space on the capture volume could not be verified; recording is not offered until the disk check passes.',
		};
	}
	checks.push(disk);
	if (!diskOk) actionRequired.push(disk.actionRequired ?? 'Resolve the disk-space check.');

	// ── Per-surface permission status ─────────────────────────────────────
	for (const surface of request.surfaces) {
		let permission: PermissionWireState;
		try {
			permission = deps.permissionStatus(surface);
		} catch (error) {
			permission = 'unknown';
			checks.push({
				check: 'permission',
				status: 'unknown',
				surface,
				permission,
				detail: `permission probe failed: ${errorMessage(error)}`,
			});
			actionRequired.push(`Verify ${surface} permission manually; the OS state could not be read.`);
			continue;
		}
		switch (permission) {
			case 'granted': {
				checks.push({
					check: 'permission',
					status: 'available',
					surface,
					permission,
					detail: `${surface} access granted by the OS`,
				});
				break;
			}
			case 'denied':
			case 'restricted': {
				checks.push({
					check: 'permission',
					status: 'action_required',
					surface,
					permission,
					detail: `${surface} access is ${permission} by the OS`,
				});
				actionRequired.push(
					`Grant ${surface} access in the OS privacy settings; recording cannot start while the OS denies it.`,
				);
				break;
			}
			case 'not_determined': {
				checks.push({
					check: 'permission',
					status: 'action_required',
					surface,
					permission,
					detail: `${surface} permission has not been decided yet`,
				});
				actionRequired.push(`Approve the ${surface} permission prompt before recording starts.`);
				break;
			}
			case 'unavailable':
			case 'unknown': {
				checks.push({
					check: 'permission',
					status: 'unknown',
					surface,
					permission,
					detail: `${surface} permission state cannot be proven on this platform`,
				});
				actionRequired.push(
					`Confirm ${surface} availability on this platform; the permission state is unprovable here.`,
				);
				break;
			}
		}
	}

	return {
		kind: 'result',
		meetingId: request.meetingId,
		identity,
		admitted: actionRequired.length === 0,
		actionRequired,
		checks,
		ranAtUnixMs,
	};
}

function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

// ── Production probe implementations (main-process; slice 2 wires these) ──

/** Observed, version-pinned capture identity from the running runtime. */
export function observedCaptureIdentity(): CaptureIdentity {
	return {
		platform: os.platform(),
		platformVersion: os.release(),
		captureApiVersion: `electron-${process.versions.electron || 'unknown'}+chromium-${process.versions.chrome || 'unknown'}`,
	};
}

/** Node-backed disk probe: statfs on the volume holding `path`. */
export async function nodeFreeDiskBytes(path: string): Promise<number> {
	const stats = await fs.statfs(path);
	return stats.bavail * stats.bsize;
}
