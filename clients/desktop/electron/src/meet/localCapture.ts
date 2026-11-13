//! MEET M5 slice 2 — the composition-root wiring for the Electron
//! local-first capture substrate (`src/meet/`). This is the slice the
//! slice-1 module headers name: it binds
//!   - `makeElectronPreflightDeps` into `runCapturePreflight`,
//!   - the consent machine's `ConsentStore` seam to the native secure store
//!     (a reserved `meet-capture:` namespace that the renderer can NEVER
//!     touch — a compromised renderer must not be able to grant itself
//!     recording consent, exactly the `mam:` genre),
//!   - the heartbeat/lease/registration frames to the server through an
//!     injected `MeetServerTransport` (the MirrorService fetchFn genre:
//!     MAIN owns the admitted origin and the credential; the renderer's
//!     frames are payloads, never credentials),
//! and registers the whole surface through the ONE origin-gated
//! `registerHandlers` choke point (the `handlers/os.ts` pattern).
//!
//! FLAG DISCIPLINE (unchanged from slice 1): the composition is constructed
//! with the shipped default `off`, which makes every handler below refuse
//! before any effect — the preflight returns its typed `inert_flag_off`
//! variant without calling a probe, the consent machine admits nothing and
//! never touches the store (the load refuses before the first read), and
//! the wire handlers refuse without any transport call. Only `execute` —
//! which the shipped default never reaches — activates the wire, and even
//! there every capture-path call is gated on the non-dismissible consent
//! verdict FIRST (capture cannot start without an explicit grant covering
//! every requested surface).

import { randomUUID } from 'node:crypto';

import type { HandlerMap } from '../handlers/db';
import type { NativeBinding } from '../native';
import { LocalCaptureConsent, type ConsentStore, type ConsentVerdict } from './consent';
import type { CapturePreflightRequest, CaptureSurfaceId, PreflightDeps } from './preflight';
import { runCapturePreflight } from './preflight';
import { makeElectronPreflightDeps } from './electronDeps';
import {
	DEFAULT_MEET_LOCAL_RECORDING_ROLLOUT_MODE,
	MEET_LOCAL_RECORDING_FLAG,
	captureAdmitted,
	type MeetLocalRecordingRolloutMode,
} from './rollout';

/** Secure-store keys this composition owns. The whole `meet-capture:`
 * namespace is NATIVE-HOST-ONLY (securestore.ts denies renderer calls
 * naming it) — consent records and the capture device id are main-process
 * truth, never renderer-writable state. */
export const MEET_LOCAL_CAPTURE_CONSENT_KEY = 'meet-capture:consent';
export const MEET_LOCAL_CAPTURE_DEVICE_KEY = 'meet-capture:device';

/** The main→server transport seam for lease/heartbeat/stop/register frames.
 * Implementations bind the ADMITTED server origin + the session credential
 * themselves (main owns both); `postMeet` resolves to the parsed response
 * body and rejects on any non-2xx/problem response. */
export interface MeetServerTransport {
	postMeet(meetingId: number, path: string, body: unknown): Promise<unknown>;
}

export interface MeetTransportDeps {
	/** The trusted, admitted server origin — empty when none is admitted
	 * (the driveServerOrigin pattern; fail-closed: no origin, no wire). */
	getOrigin(): string;
	/** The session credential for that origin (the gateway's `access_token`
	 * cookie jar, read from the default session by the composition root).
	 * Null means unprovable — the transport refuses rather than guesses. */
	getAccessToken(): Promise<string | null>;
}

/** Fail-closed fetch transport: refuses unless BOTH an admitted origin and
 * a session credential are provable, and only ever speaks to
 * `${origin}/api/meet/...`. */
export function makeFetchMeetTransport(deps: MeetTransportDeps): MeetServerTransport {
	return {
		async postMeet(meetingId, path, body) {
			const origin = deps.getOrigin();
			if (origin === '') {
				throw new Error('meet local capture: no admitted server origin; the wire stays closed');
			}
			const token = await deps.getAccessToken();
			if (token === null || token === '') {
				throw new Error('meet local capture: no session credential; the wire stays closed');
			}
			const res = await fetch(`${origin}/api/meet/${meetingId}${path}`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Cookie: `access_token=${token}` },
				body: JSON.stringify(body),
			});
			if (!res.ok) {
				throw new Error(`meet local capture: server refused ${path} (${res.status})`);
			}
			return res.json();
		},
	};
}

/** The consent machine's store seam bound to the native secure store
 * (main-process only; the namespace is renderer-denied). */
export function makeSecureConsentStore(native: NativeBinding): ConsentStore {
	return {
		load: async () => native.secureStoreGet(MEET_LOCAL_CAPTURE_CONSENT_KEY),
		save: async (raw) => native.secureStoreSet(MEET_LOCAL_CAPTURE_CONSENT_KEY, raw),
	};
}

/** The capture device identity: minted ONCE per install, kept under the
 * renderer-denied namespace. A label, never a credential — ownership rides
 * the session credential on the wire (R2: identity from auth context). */
export function meetCaptureDeviceId(native: NativeBinding): string {
	const existing = native.secureStoreGet(MEET_LOCAL_CAPTURE_DEVICE_KEY);
	if (existing !== null && existing !== '') return existing;
	const minted = randomUUID();
	native.secureStoreSet(MEET_LOCAL_CAPTURE_DEVICE_KEY, minted);
	return minted;
}

export interface MeetLocalCaptureDeps {
	native: NativeBinding;
	transport: MeetServerTransport;
	/** The rollout mode — the composition root passes the shipped default
	 * `off`; only a separate trusted rollout decision may widen it. */
	mode?: MeetLocalRecordingRolloutMode;
	/** Probe/consent injection seam (tests pin inertness with fakes). */
	preflightDeps?: PreflightDeps;
	nowMs?: () => number;
}

/** The named inert refusal every capture-path handler carries in a rollout
 * mode that does not admit it — a return value, never a silent success. */
export interface MeetWireRefusal {
	ok: false;
	refusal: string;
}

export function meetWireRefused(what: string): MeetWireRefusal {
	return {
		ok: false,
		refusal: `${what}: ${MEET_LOCAL_RECORDING_FLAG} does not admit the capture path (substrate stays inert; capture requires 'execute')`,
	};
}

function meetingIdOf(args: unknown): number {
	return (args as { meetingId: number }).meetingId;
}

/** The wire's surface set — fail-closed: anything that is not exactly a
 * capture surface is dropped, so a renderer can never widen a grant past
 * the substrate's vocabulary. */
function surfacesOf(args: unknown): CaptureSurfaceId[] {
	const raw = (args as { surfaces?: unknown[] }).surfaces ?? [];
	return raw.filter((s): s is CaptureSurfaceId => s === 'microphone' || s === 'systemAudio');
}

/** The slice-2 composition owner. Holds the (lazily loaded) consent
 * machine and returns the HandlerMap main.ts registers ONCE through the
 * origin-gated wrapper. With the shipped `off` default, loading touches no
 * store and every capture-path handler refuses before any effect. */
export function makeMeetLocalCaptureHandlers(deps: MeetLocalCaptureDeps): HandlerMap {
	const mode: MeetLocalRecordingRolloutMode = deps.mode ?? DEFAULT_MEET_LOCAL_RECORDING_ROLLOUT_MODE;
	const nowMs = deps.nowMs ?? Date.now;
	const preflightDeps = deps.preflightDeps ?? makeElectronPreflightDeps(nowMs);
	// `off` constructs an INERT machine without reading the store (the
	// consent module's own contract) — the composition adds nothing on top.
	const consent: Promise<LocalCaptureConsent> = LocalCaptureConsent.load(
		mode,
		makeSecureConsentStore(deps.native),
	);

	/** Consent verdict gate for the wire — the non-dismissible consent bar:
	 * the server is contacted only for an explicitly granted meeting whose
	 * grant covers EVERY requested surface. In a non-execute mode this
	 * refuses WITHOUT consulting any state (the machine is never awaited
	 * on a refused path). */
	async function consentGate(meetingId: number, surfaces: CaptureSurfaceId[]): Promise<ConsentVerdict> {
		if (!captureAdmitted(mode)) {
			return {
				allowed: false,
				meetingId,
				refusal: {
					code: 'flag_not_admitted',
					detail: meetWireRefused('lease acquire').refusal,
				},
			};
		}
		return (await consent).verdict(meetingId, surfaces);
	}

	return {
		// READ-ONLY probe surface: admitted in observe + execute (the
		// preflight itself returns the inert variant in off — no probes).
		meet_local_preflight: (request: unknown) =>
			runCapturePreflight(mode, preflightDeps, request as CapturePreflightRequest),

		// Consent transitions (execute-only — the machine refuses otherwise).
		meet_local_consent_ask: async (args: unknown) =>
			(await consent).ask(meetingIdOf(args), nowMs()),
		meet_local_consent_grant: async (args: unknown) =>
			(await consent).grant(meetingIdOf(args), surfacesOf(args), nowMs()),
		meet_local_consent_deny: async (args: unknown) =>
			(await consent).deny(meetingIdOf(args), nowMs()),
		meet_local_consent_revoke: async (args: unknown) =>
			(await consent).revoke(meetingIdOf(args), 'user_revoked', nowMs()),
		meet_local_consent_end_meeting: async (args: unknown) =>
			(await consent).endMeeting(meetingIdOf(args), nowMs()),

		// The capture-start gate (pure read).
		meet_local_consent_verdict: async (args: unknown) =>
			(await consent).verdict(meetingIdOf(args), surfacesOf(args)),

		// The wire (execute-only, consent-gated, transport fail-closed).
		meet_local_lease_acquire: async (args: unknown) => {
			const surfaces = surfacesOf(args);
			const meetingId = meetingIdOf(args);
			const verdict = await consentGate(meetingId, surfaces);
			if (!verdict.allowed) {
				const reason = verdict.refusal?.code ?? 'unknown';
				return {
					ok: false as const,
					refusal: `consent refuses capture for meeting ${meetingId}: ${reason}`,
				};
			}
			return deps.transport.postMeet(meetingId, '/local/lease', {
				deviceId: meetCaptureDeviceId(deps.native),
				surfaces,
				producer: preflightDeps.identity(),
				heartbeatSeconds: (args as { heartbeatSeconds?: number }).heartbeatSeconds,
			});
		},
		meet_local_heartbeat: async (args: unknown) => {
			if (!captureAdmitted(mode)) return meetWireRefused('heartbeat');
			const { meetingId, recordingId, ...frame } = args as { meetingId: number; recordingId: number } &
				Record<string, unknown>;
			return deps.transport.postMeet(meetingId, `/local/${recordingId}/heartbeat`, frame);
		},
		meet_local_stop: async (args: unknown) => {
			if (!captureAdmitted(mode)) return meetWireRefused('lease stop');
			const { meetingId, recordingId, ...body } = args as { meetingId: number; recordingId: number } &
				Record<string, unknown>;
			return deps.transport.postMeet(meetingId, `/local/${recordingId}/stop`, body);
		},
		meet_local_register: async (args: unknown) => {
			if (!captureAdmitted(mode)) return meetWireRefused('register');
			const { meetingId, recordingId, descriptor } = args as {
				meetingId: number;
				recordingId: number;
				descriptor: unknown;
			};
			return deps.transport.postMeet(meetingId, `/local/${recordingId}/register`, descriptor);
		},
	};
}
