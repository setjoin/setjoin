//! Capture heartbeat + stop contract, client side (MEET M5 slice 1).
//!
//! The typed heartbeat the Electron client emits while capturing, and the
//! pure stop-condition evaluation every capture loop runs: revocation,
//! meeting end, disk-floor breach, heartbeat stall, and a crash-recovery
//! marker all force a stop. SLICE-2 WIRING CONSTRAINT: `parseCrashMarker`
//! returns null for BOTH an absent marker and a drifted one, so the slice-2
//! caller must translate `raw !== null && parsed === null` into
//! `crash_recovery_pending` — treating raw corruption as a clean state would
//! defeat the fail-closed recovery arm. Slice 2 wires the server-side reducer lease
//! (the frames below are the wire shape those calls will carry); this module
//! owns the client truth and stays electron-free and timer-free — the caller
//! drives `evaluate(nowMs)` from whatever clock owns the loop (the
//! `mamLifecycleOwner` injected-clock genre).
//!
//! Honesty rules: heartbeats are numbered monotonically and never fabricated
//! (a stall is reported, never papered over); a failed disk probe is its own
//! stop condition, never assumed-healthy; and the crash marker parse fails
//! closed to `null` on any drift so a corrupted marker can never masquerade
//! as a clean state.

import type { CaptureSurfaceId } from './preflight';
import { captureAdmitted, type MeetLocalRecordingRolloutMode } from './rollout';

export const HEARTBEAT_SCHEMA = 'meet-local-heartbeat-v1';

/** Heartbeat cadence + stall budget (slice-2 defaults; the server lease may
 *  tighten them, never loosen the local stall stop). */
export const HEARTBEAT_INTERVAL_MS = 10_000;
export const MAX_MISSED_HEARTBEATS = 3;

export type CaptureHeartbeatState = 'capturing' | 'stopping' | 'stopped';

/** One heartbeat frame. Serializable as-is — this is the client half of the
 *  lease-keepalive wire shape slice 2 binds to the reducer capture lease. */
export interface CaptureHeartbeat {
	schema: typeof HEARTBEAT_SCHEMA;
	meetingId: number;
	/** Server-assigned recording identity; null until the slice-2 lease
	 *  assigns one (honest null, never a fabricated id). */
	recordingId: number | null;
	leaseGeneration: number | null;
	/** Monotonic per capture, from 1. */
	seq: number;
	sentAtUnixMs: number;
	captureState: CaptureHeartbeatState;
	/** Observed free bytes on the capture volume at send time; null when the
	 *  probe failed (the stop evaluator treats null as unprovable, not safe). */
	diskFreeBytes: number | null;
	surfaces: CaptureSurfaceId[];
	/** The version-pinned capture identity the heartbeat vouches for. */
	producerVersion: string;
}

// ── Stop conditions ────────────────────────────────────────────────────────

export type StopCondition =
	| 'consent_revoked'
	| 'meeting_ended'
	| 'disk_floor_breached'
	| 'disk_probe_failed'
	| 'heartbeat_stalled'
	| 'crash_recovery_pending';

/** Fixed priority order: consent truth first, then meeting end, then disk
 *  facts, then liveness, then recovery. Evaluators return conditions in this
 *  order so callers can rely on `conditions[0]` being the dominant reason. */
export const STOP_CONDITION_PRIORITY: readonly StopCondition[] = [
	'consent_revoked',
	'meeting_ended',
	'disk_floor_breached',
	'disk_probe_failed',
	'heartbeat_stalled',
	'crash_recovery_pending',
];

export interface StopConditionInput {
	/** Consent state machine says the meeting scope is revoked. */
	consentRevoked: boolean;
	/** The meeting has ended (any source). */
	meetingEnded: boolean;
	/** Observed free bytes on the capture volume; null when unprovable. */
	diskFreeBytes: number | null;
	/** Stop while free space is below this floor. */
	diskFloorBytes: number;
	heartbeatStalled: boolean;
	/** A crash-recovery marker was found (an earlier capture never finalized). */
	crashRecoveryMarker: boolean;
}

export interface StopDecision {
	mustStop: boolean;
	/** ALL detected conditions, in STOP_CONDITION_PRIORITY order. */
	conditions: StopCondition[];
}

/** Pure stop evaluation: every true condition is reported (never just the
 *  first), and any condition forces the stop. A null disk probe is its own
 *  condition (`disk_probe_failed`) — unprovable space is not healthy space. */
export function evaluateStopConditions(input: StopConditionInput): StopDecision {
	const detected = new Set<StopCondition>();
	if (input.consentRevoked) detected.add('consent_revoked');
	if (input.meetingEnded) detected.add('meeting_ended');
	if (input.diskFreeBytes !== null && input.diskFreeBytes < input.diskFloorBytes) {
		detected.add('disk_floor_breached');
	}
	if (input.diskFreeBytes === null) detected.add('disk_probe_failed');
	if (input.heartbeatStalled) detected.add('heartbeat_stalled');
	if (input.crashRecoveryMarker) detected.add('crash_recovery_pending');
	const conditions = STOP_CONDITION_PRIORITY.filter((c) => detected.has(c));
	return { mustStop: conditions.length > 0, conditions };
}

// ── Heartbeat monitor (pure; the caller owns the clock) ────────────────────

export interface HeartbeatEvaluation {
	/** A heartbeat should be sent now. */
	dueNow: boolean;
	/** Consecutive expected heartbeats never observed (0 while healthy). */
	missedCount: number;
	/** True when missedCount reached the stall budget — the capture must stop
	 *  (a stalled reporter is a stop condition, never a silent continue). */
	stalled: boolean;
}

export interface HeartbeatMonitorOptions {
	intervalMs: number;
	maxMissed: number;
	meetingId: number;
	recordingId: number | null;
	leaseGeneration: number | null;
	surfaces: CaptureSurfaceId[];
	producerVersion: string;
}

/** Tracks one live capture's heartbeat cadence. Constructed only in rollout
 *  modes that admit capture (the constructor throws otherwise — the substrate
 *  must be inert unless `feature.meet_local_recording` enables it). */
export class HeartbeatMonitor {
	#seq = 0;
	#lastSentAtUnixMs: number | null = null;
	#missed = 0;
	readonly #options: HeartbeatMonitorOptions;

	constructor(options: HeartbeatMonitorOptions, mode: MeetLocalRecordingRolloutMode) {
		if (!captureAdmitted(mode)) {
			throw new Error(
				`HeartbeatMonitor requires an 'execute' rollout mode (substrate stays inert otherwise)`,
			);
		}
		this.#options = options;
	}

	/** Build and record one outgoing heartbeat at `nowMs`. Seq is monotonic;
	 *  frames are never fabricated for missed slots (a gap IS the report). */
	recordSent(nowMs: number, diskFreeBytes: number | null): CaptureHeartbeat {
		this.#seq += 1;
		this.#lastSentAtUnixMs = nowMs;
		this.#missed = 0;
		return {
			schema: HEARTBEAT_SCHEMA,
			meetingId: this.#options.meetingId,
			recordingId: this.#options.recordingId,
			leaseGeneration: this.#options.leaseGeneration,
			seq: this.#seq,
			sentAtUnixMs: nowMs,
			captureState: 'capturing',
			diskFreeBytes,
			surfaces: [...this.#options.surfaces],
			producerVersion: this.#options.producerVersion,
		};
	}

	/** Pure liveness evaluation at `nowMs`. Contract: at exactly `intervalMs`
	 *  of silence a heartbeat is `dueNow` with 0 missed; each FULL interval
	 *  beyond the due slot counts one more missed heartbeat, and reaching
	 *  `maxMissed` is `stalled` — the capture must stop. Only the missed
	 *  counter grows here; `recordSent` resets it. */
	evaluate(nowMs: number): HeartbeatEvaluation {
		if (this.#lastSentAtUnixMs === null) {
			return { dueNow: true, missedCount: 0, stalled: false };
		}
		const elapsed = nowMs - this.#lastSentAtUnixMs;
		const slots = Math.floor(elapsed / this.#options.intervalMs);
		const dueNow = slots >= 1;
		if (dueNow) {
			this.#missed = Math.max(0, slots - 1);
		}
		return {
			dueNow,
			missedCount: this.#missed,
			stalled: this.#missed >= this.#options.maxMissed,
		};
	}

	/** The final `stopped` frame (state transition on the wire, seq keeps
	 *  counting — the stop is itself an observable heartbeat). */
	recordStopped(nowMs: number, diskFreeBytes: number | null): CaptureHeartbeat {
		const frame = this.recordSent(nowMs, diskFreeBytes);
		frame.captureState = 'stopped';
		return frame;
	}

	get missedCount(): number {
		return this.#missed;
	}
}

// ── Crash-recovery marker ─────────────────────────────────────────────────

export const CRASH_MARKER_SCHEMA = 'meet-local-crash-marker-v1';

export interface CrashRecoveryMarker {
	schema: typeof CRASH_MARKER_SCHEMA;
	meetingId: number;
	captureDir: string;
	startedAtUnixMs: number;
	/** Last heartbeat seq the crashed capture sent (recovery names its truth). */
	lastHeartbeatSeq: number;
}

/** Canonical JSON encode of the marker (sorted keys — deterministic bytes). */
export function encodeCrashMarker(marker: CrashRecoveryMarker): string {
	return JSON.stringify(marker, Object.keys(marker).sort());
}

/** Fail-closed parse: any schema drift, shape problem, or non-finite number
 *  parses to null — a corrupted marker must never read as "no crash". */
export function parseCrashMarker(raw: string | null): CrashRecoveryMarker | null {
	if (raw === null) return null;
	let value: unknown;
	try {
		value = JSON.parse(raw);
	} catch {
		return null;
	}
	if (typeof value !== 'object' || value === null) return null;
	const m = value as Partial<CrashRecoveryMarker>;
	if (m.schema !== CRASH_MARKER_SCHEMA) return null;
	if (
		typeof m.meetingId !== 'number' ||
		!Number.isFinite(m.meetingId) ||
		m.meetingId <= 0 ||
		typeof m.captureDir !== 'string' ||
		m.captureDir === '' ||
		typeof m.startedAtUnixMs !== 'number' ||
		!Number.isFinite(m.startedAtUnixMs) ||
		typeof m.lastHeartbeatSeq !== 'number' ||
		!Number.isFinite(m.lastHeartbeatSeq) ||
		m.lastHeartbeatSeq < 0
	) {
		return null;
	}
	return {
		schema: CRASH_MARKER_SCHEMA,
		meetingId: m.meetingId,
		captureDir: m.captureDir,
		startedAtUnixMs: m.startedAtUnixMs,
		lastHeartbeatSeq: m.lastHeartbeatSeq,
	};
}
