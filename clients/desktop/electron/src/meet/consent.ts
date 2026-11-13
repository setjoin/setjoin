//! Non-dismissible consent state machine for Electron local capture (M5 slice 1).
//!
//! The plan's M5 bar: consent is NON-DISMISSIBLE — capture cannot start
//! without an explicit grant for that meeting — and revocation or meeting end
//! forces the stop state. This module owns that truth client-side:
//!
//!   - Asking (`ask`) only records that a prompt was shown. It NEVER moves the
//!     state — a dismissed banner is not consent; only `grant` (an explicit
//!     user decision) sets `granted`.
//!   - Consent is bound to one meeting scope (keyed by meeting id) and to an
//!     explicit surface set. A grant for meeting A never authorizes meeting B,
//!     and a grant covering `microphone` never authorizes `systemAudio`.
//!   - `revoked` is TERMINAL within the meeting scope: user revocation, a
//!     policy revocation, meeting end, or a corrupted consent store all land
//!     there, and `grant` after `revoked` is refused (a new meeting scope is
//!     the only way to consent again).
//!   - `verdict` is the capture-start gate: fail-closed on unknown meetings,
//!     unasked/denied/revoked states, and uncovered surfaces.
//!
//! Persistence follows the client's existing key/value store pattern (the
//! secure-store seam): the raw serialized machine is loaded/saved through an
//! injected store and saved after EVERY accepted transition. A corrupted or
//! unreadable store (and any record failing validation) is DROPPED, so the
//! affected scopes fall back to `unasked` — and `verdict` refuses capture for
//! unasked scopes, so capture can never start on unprovable consent. (There
//! is deliberately no `store_corrupt` refusal code: dropping to `unasked`
//! forces a fresh explicit grant, which is strictly safer than honoring an
//! unreadable `revoked` state.) Slice 2 wires the store and the server-side
//! reducer lease; this module stays electron-free and pure.

import type { CaptureSurfaceId } from './preflight';
import { MEET_LOCAL_RECORDING_FLAG, captureAdmitted, type MeetLocalRecordingRolloutMode } from './rollout';

export const CONSENT_SCHEMA = 'meet-local-consent-v1';

export type ConsentState = 'unasked' | 'granted' | 'denied' | 'revoked';

/** Why a scope left the startable state. `meeting_ended` and `policy_revoked`
 *  are the forced-stop paths (meeting end / server revocation). */
export type ConsentRevokedReason = 'user_revoked' | 'meeting_ended' | 'policy_revoked';

/** One meeting scope's consent record. Timestamps are unix millis; nulls mean
 *  "never happened" and are part of the honest shape (an askedAt without a
 *  decidedAt is exactly the dismissed-but-not-granted case). */
export interface ConsentRecord {
	meetingId: number;
	state: ConsentState;
	/** Surfaces an explicit grant covers. Always empty unless state is granted. */
	grantedSurfaces: CaptureSurfaceId[];
	askedAtUnixMs: number | null;
	decidedAtUnixMs: number | null;
	/** Monotonic within the scope; bumps on every accepted transition so a
	 *  persistence race is observable. */
	generation: number;
	revokedReason: ConsentRevokedReason | null;
}

export interface ConsentVerdict {
	allowed: boolean;
	meetingId: number;
	/** The blocking fact when not allowed (typed, serializable). */
	refusal: ConsentRefusal | null;
}

export type ConsentRefusal =
	| { code: 'flag_not_admitted'; detail: string }
	| { code: 'unknown_meeting'; detail: string }
	| { code: 'not_asked'; detail: string }
	| { code: 'denied'; detail: string }
	| { code: 'revoked'; detail: string; reason: ConsentRevokedReason }
	| { code: 'surfaces_not_covered'; detail: string; missing: CaptureSurfaceId[] };

/** Typed transition outcome — tests pin every transition through this. */
export interface ConsentTransition {
	ok: boolean;
	record: ConsentRecord;
	/** Named refusal when `ok` is false (terminal-scope violations etc.). */
	refusal: string | null;
}

/** The persisted shape (one JSON document under the client's store). */
export interface ConsentPersisted {
	schema: typeof CONSENT_SCHEMA;
	records: Record<string, ConsentRecord>;
}

/** Key/value persistence seam (the secure-store genre: read raw string,
 *  write raw string). Slice 2 binds it to the native-host store; tests use
 *  an in-memory map. */
export interface ConsentStore {
	load(): Promise<string | null>;
	save(raw: string): Promise<void>;
}

export function serializeConsent(records: Record<string, ConsentRecord>): string {
	const doc: ConsentPersisted = { schema: CONSENT_SCHEMA, records };
	return JSON.stringify(doc);
}

function emptyRecord(meetingId: number): ConsentRecord {
	return {
		meetingId,
		state: 'unasked',
		grantedSurfaces: [],
		askedAtUnixMs: null,
		decidedAtUnixMs: null,
		generation: 0,
		revokedReason: null,
	};
}

function isValidRecord(value: unknown): value is ConsentRecord {
	if (typeof value !== 'object' || value === null) return false;
	const r = value as Partial<ConsentRecord>;
	return (
		typeof r.meetingId === 'number' &&
		r.meetingId > 0 &&
		(r.state === 'unasked' ||
			r.state === 'granted' ||
			r.state === 'denied' ||
			r.state === 'revoked') &&
		Array.isArray(r.grantedSurfaces) &&
		r.grantedSurfaces.every((s) => s === 'microphone' || s === 'systemAudio') &&
		(r.state !== 'granted' || r.grantedSurfaces.length > 0) &&
		typeof r.generation === 'number' &&
		r.generation >= 0
	);
}

export class LocalCaptureConsent {
	#records = new Map<string, ConsentRecord>();

	private constructor(
		private readonly store: ConsentStore | null,
		private readonly mode: MeetLocalRecordingRolloutMode,
	) {}

	/** Load persisted state. Rollout mode `off` constructs an INERT machine:
	 *  every entry point refuses with `flag_not_admitted` and the store is
	 *  never touched (the substrate must be inert unless the flag enables it).
	 *  Fail-closed on unprovable state: an unreadable or corrupted store (and
	 *  any record failing validation) is DROPPED, so the affected scope falls
	 *  back to `unasked` — and `verdict` refuses capture for unasked scopes.
	 *  Consent can never start capture on an unprovable persisted state. */
	static async load(
		mode: MeetLocalRecordingRolloutMode,
		store: ConsentStore | null,
	): Promise<LocalCaptureConsent> {
		const machine = new LocalCaptureConsent(store, mode);
		if (mode === 'off' || !store) return machine;
		let raw: string | null;
		try {
			raw = await store.load();
		} catch {
			return machine; // unreadable store: unknown scopes default to unasked (fail-closed verdicts)
		}
		if (raw === null) return machine;
		let doc: unknown;
		try {
			doc = JSON.parse(raw);
		} catch {
			return machine; // corrupted JSON: scopes stay unasked (fail-closed verdicts)
		}
		const records = (doc as Partial<ConsentPersisted> | null)?.records;
		if (typeof records !== 'object' || records === null) return machine;
		for (const [key, value] of Object.entries(records)) {
			if (!isValidRecord(value)) continue;
			machine.#records.set(key, value);
		}
		return machine;
	}

	#scope(meetingId: number): ConsentRecord {
		const key = String(meetingId);
		let record = this.#records.get(key);
		if (!record) {
			record = emptyRecord(meetingId);
			this.#records.set(key, record);
		}
		return record;
	}

	#checkFlag(what: string, meetingId: number): ConsentTransition | null {
		// Consent transitions are STATEFUL, not read-only: they are admitted
		// only in 'execute' (observe admits the read-only preflight probes).
		if (!captureAdmitted(this.mode)) {
			return {
				ok: false,
				record: this.#scope(meetingId),
				refusal: `${what}: ${MEET_LOCAL_RECORDING_FLAG} is not admitted in rollout mode '${this.mode}'`,
			};
		}
		return null;
	}

	async #mutate(
		meetingId: number,
		mutate: (record: ConsentRecord) => string | null,
	): Promise<ConsentTransition> {
		const record = this.#scope(meetingId);
		const refusal = mutate(record);
		if (refusal !== null) return { ok: false, record: { ...record }, refusal };
		record.generation += 1;
		await this.#persist();
		return { ok: true, record: { ...record }, refusal: null };
	}

	async #persist(): Promise<void> {
		if (!this.store) return;
		const records: Record<string, ConsentRecord> = {};
		for (const [key, record] of this.#records) records[key] = record;
		try {
			await this.store.save(serializeConsent(records));
		} catch {
			// A failed save must not roll back the in-memory truth (the user's
			// explicit decision stands for this session); slice 2's store binding
			// surfaces persistence failures to the operator path.
		}
	}

	/** Record that the consent prompt was shown. Deliberately state-neutral:
	 *  a dismissal can never manufacture consent (the non-dismissible rule). */
	async ask(meetingId: number, nowMs: number): Promise<ConsentTransition> {
		const flag = this.#checkFlag('consent.ask', meetingId);
		if (flag) return flag;
		return this.#mutate(meetingId, (record) => {
			if (record.state === 'revoked') {
				return `meeting ${meetingId} consent is revoked; prompting again cannot revive it`;
			}
			record.askedAtUnixMs = nowMs;
			return null;
		});
	}

	/** An explicit user decision to allow capture for THIS meeting, covering
	 *  exactly `surfaces`. Refused when the scope is already revoked. */
	async grant(
		meetingId: number,
		surfaces: CaptureSurfaceId[],
		nowMs: number,
	): Promise<ConsentTransition> {
		const flag = this.#checkFlag('consent.grant', meetingId);
		if (flag) return flag;
		const unique = [...new Set(surfaces)];
		if (unique.length === 0) {
			return { ok: false, record: { ...this.#scope(meetingId) }, refusal: 'grant must cover at least one surface' };
		}
		return this.#mutate(meetingId, (record) => {
			if (record.state === 'revoked') {
				return `meeting ${meetingId} consent is revoked (${record.revokedReason}); a new meeting scope is required to consent again`;
			}
			record.state = 'granted';
			record.grantedSurfaces = unique;
			record.decidedAtUnixMs = nowMs;
			return null;
		});
	}

	/** An explicit user decision to decline. The scope stays re-askable until
	 *  a revocation terminalizes it. */
	async deny(meetingId: number, nowMs: number): Promise<ConsentTransition> {
		const flag = this.#checkFlag('consent.deny', meetingId);
		if (flag) return flag;
		return this.#mutate(meetingId, (record) => {
			if (record.state === 'revoked') {
				return `meeting ${meetingId} consent is already revoked`;
			}
			record.state = 'denied';
			record.grantedSurfaces = [];
			record.decidedAtUnixMs = nowMs;
			return null;
		});
	}

	/** Forced stop path: revocation (user or server policy) terminalizes the
	 *  scope. Idempotent — re-revocation keeps the original reason. */
	async revoke(
		meetingId: number,
		reason: Extract<ConsentRevokedReason, 'user_revoked' | 'policy_revoked'>,
		nowMs: number,
	): Promise<ConsentTransition> {
		const flag = this.#checkFlag('consent.revoke', meetingId);
		if (flag) return flag;
		return this.#mutate(meetingId, (record) => {
			if (record.state === 'revoked') return null; // idempotent: first reason wins
			record.state = 'revoked';
			record.grantedSurfaces = [];
			record.revokedReason = reason;
			record.decidedAtUnixMs = nowMs;
			return null;
		});
	}

	/** Forced stop path: the meeting ended. A live grant is forced into the
	 *  stop state (`revoked`/`meeting_ended`). Idempotent. */
	async endMeeting(meetingId: number, nowMs: number): Promise<ConsentTransition> {
		const flag = this.#checkFlag('consent.endMeeting', meetingId);
		if (flag) return flag;
		return this.#mutate(meetingId, (record) => {
			if (record.state === 'revoked') return null; // idempotent: first reason wins
			record.state = 'revoked';
			record.grantedSurfaces = [];
			record.revokedReason = 'meeting_ended';
			record.decidedAtUnixMs = nowMs;
			return null;
		});
	}

	/** Capture-start gate: capture may start only for an explicitly granted
	 *  meeting whose grant covers EVERY requested surface. Fails closed on
	 *  unknown scopes, unasked/denied/revoked states, and rollout modes that
	 *  do not admit capture. Pure (no persistence). */
	verdict(meetingId: number, surfaces: CaptureSurfaceId[]): ConsentVerdict {
		if (!assertCaptureVerdictAdmitted(this.mode)) {
			return {
				allowed: false,
				meetingId,
				refusal: {
					code: 'flag_not_admitted',
					detail: `${MEET_LOCAL_RECORDING_FLAG} rollout mode '${this.mode}' does not admit capture`,
				},
			};
		}
		const record = this.#records.get(String(meetingId));
		if (!record) {
			return {
				allowed: false,
				meetingId,
				refusal: { code: 'unknown_meeting', detail: `no consent scope exists for meeting ${meetingId}` },
			};
		}
		switch (record.state) {
			case 'unasked':
				return { allowed: false, meetingId, refusal: { code: 'not_asked', detail: 'consent was never granted' } };
			case 'denied':
				return {
					allowed: false,
					meetingId,
					refusal: { code: 'denied', detail: 'the user declined capture for this meeting' },
				};
			case 'revoked':
				return {
					allowed: false,
					meetingId,
					refusal: {
						code: 'revoked',
						detail: 'consent for this meeting is revoked; capture must stop/stay stopped',
						reason: record.revokedReason ?? 'policy_revoked',
					},
				};
			case 'granted': {
				const missing = surfaces.filter((s) => !record.grantedSurfaces.includes(s));
				if (missing.length > 0) {
					return {
						allowed: false,
						meetingId,
						refusal: {
							code: 'surfaces_not_covered',
							detail: `the grant does not cover: ${missing.join(', ')}`,
							missing,
						},
					};
				}
				return { allowed: true, meetingId, refusal: null };
			}
		}
	}

	/** Read-only snapshot for tests/inspection — a copy that NEVER
	 *  materializes a scope (inspection must not create the state it
	 *  inspects; unknown scopes stay unknown to `verdict`). */
	scope(meetingId: number): ConsentRecord {
		const record = this.#records.get(String(meetingId));
		return record ? { ...record } : emptyRecord(meetingId);
	}
}

/** Mirrors rollout.captureAdmitted for the verdict path (kept sync — the
 *  verdict is a pure gate). */
function assertCaptureVerdictAdmitted(mode: MeetLocalRecordingRolloutMode): boolean {
	return captureAdmitted(mode);
}
