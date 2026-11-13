//! Flag discipline for MEET M5 Electron local-first capture (`src/meet/`).
//!
//! How meet feature flags reach this client: the toggles live server-side
//! (`shared/toggle/toggle.go`, the V264 registry projection, default OFF) and
//! reach the webmail SPA through server-projected API responses (e.g. the
//! meeting projection's `presentationEnabled` for
//! `feature.meet_document_presentation`). The Electron MAIN process has no
//! toggle plumbing of its own; the established client-side rollout seam is
//! MAM's `off|observe|execute` composition contract (`mamLifecycleOwner.ts`),
//! which `main.ts` wires with an explicit production default `off` so the
//! landed composition path performs nothing until a separate trusted rollout.
//!
//! This module applies that exact pattern to `feature.meet_local_recording`.
//! Every M5 capture module takes the rollout mode at its entry point, and the
//! shipped default `off` makes the whole substrate INERT: no capability
//! probes, no disk/permission reads, no consent state, no heartbeat, no
//! package descriptor. `observe` admits read-only probes (preflight) so a
//! trusted rollout can inspect capability truth without any capture path;
//! `execute` admits the full substrate. Nothing here reads or writes any
//! store; the gate is the single place the flag name is pinned client-side.

/** The V264 toggle this substrate hangs behind — mirrors
 *  `shared/toggle/toggle.go` FeatureMeetLocalRecording (default OFF). */
export const MEET_LOCAL_RECORDING_FLAG = 'feature.meet_local_recording';

/** Shared `off|observe|execute` rollout vocabulary (the MAM contract genre). */
export type MeetLocalRecordingRolloutMode = 'off' | 'observe' | 'execute';

export const MEET_LOCAL_RECORDING_ROLLOUT_MODES: readonly MeetLocalRecordingRolloutMode[] = [
	'off',
	'observe',
	'execute',
];

/** The shipped production default: the M5 substrate is inert. Slice 2's
 *  composition-root wiring must not widen this without its own trusted
 *  rollout decision. */
export const DEFAULT_MEET_LOCAL_RECORDING_ROLLOUT_MODE: MeetLocalRecordingRolloutMode = 'off';

/** True when the mode admits READ-ONLY probes (preflight capability, disk,
 *  permission reads). `off` admits nothing — the modules must be inert. */
export function probesAdmitted(mode: MeetLocalRecordingRolloutMode): boolean {
	return mode !== 'off';
}

/** True when the mode admits the capture path itself (consent state
 *  transitions toward a startable capture, heartbeats, package descriptors).
 *  Strictly stronger than `probesAdmitted`. */
export function captureAdmitted(mode: MeetLocalRecordingRolloutMode): boolean {
	return mode === 'execute';
}

/** Named refusal when a capture-path entry point is reached in a mode that
 *  does not admit it. Callers surface this as the fail-closed rollout refusal
 *  — never as a silent success or a fallback to another recording mode. */
export function assertCaptureAdmitted(
	mode: MeetLocalRecordingRolloutMode,
	what: string,
): void {
	if (!captureAdmitted(mode)) {
		throw new Error(
			`${what}: ${MEET_LOCAL_RECORDING_FLAG} is not admitted in rollout mode '${mode}' (capture requires 'execute'; substrate stays inert otherwise)`,
		);
	}
}
