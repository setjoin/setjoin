// MeetActions — the in-meeting host-control/dispatch layer (Svelte 5 $state
// rune class), mirroring EmailActionStore (mailserver/webmail/src/lib/stores/
// emailActionStore.svelte.ts, the inbox's proven mutation/intent seam) and
// CalendarActionStore (the calendar's own mirror of it): the ~10 do*/move
// handlers MeetApp.svelte used to own inline (doStartRecording/doStopRecording/
// doStartCaptions/doStopCaptions/doEnd/doLock/doKick/doSetRole/moveToBreakout/
// rejoinMain) live here as typed methods behind a small `MeetActionHost`
// interface, so MeetApp stays thin call-through wiring: each method it still
// exposes to the template/WS handler is a one-line delegate into this store.
//
// `MeetActionHost` is realized in MeetApp.svelte as a get/set-accessor object
// over the component's OWN top-level $state — NOT a class instance the way
// InboxStore/CalendarEventsStore are, since this component's reactive state
// is plain runes, not a pre-existing reactive class. The accessors keep a
// single source of truth (MeetApp's own $state vars) while letting this
// module read/write them like ordinary fields — the same contract shape as
// EmailActionStore's ActionHost, just realized with accessors instead of
// class fields. Tests bind a plain mutable object instead (no accessors
// needed off-component), exactly like the inbox/calendar precedents.
//
// Busy-guards that are NEVER read outside their own action (stopBusy,
// captionsStopBusy — the double-click-fires-one-DELETE guards) are owned
// directly by this store as their own $state fields, mirroring
// CalendarActionStore's own saving/deleting/responding fields — no host
// surface needed for state nothing else touches.

import * as meetApi from '$lib/meet/api';
import { MeetError, type Meeting } from '$lib/meet/api';
import type { MeetRoom } from '$lib/meet/room.svelte';
import { t } from '$lib/i18n';
import { showToast } from '$lib/components/ui';

// 'kicked' (B1 live-gate ledger fix 1): a MEMBER-only terminal view — the
// LiveKit Disconnected reason PARTICIPANT_REMOVED, checked by MeetApp's own
// disconnect $effect. Distinct from 'ended' (server state, pushed) and
// 'error' (a request failure) — a kick is neither: the ban-until-re-admit
// posture means there is nothing to retry and nothing to explain via
// errorMessage. Guests already had an equivalent 'removed' view (the
// join/[slug] page's guestReconnect.ts, server-truth via a join-request
// poll); members have no such poll surface, so this reads LiveKit's own
// eviction signal instead — the same signal the room.svelte.ts
// disconnectReason field was added for and, until this fix, never consumed.
export type MeetView = 'landing' | 'loading' | 'prejoin' | 'knocking' | 'in-room' | 'ended' | 'kicked' | 'error';

/** B3 Task 7 (design D6): the forced-move/auto-return interstitial shape. */
export type MoveInterstitial = { kind: 'moving'; roomLabel: string | null } | { kind: 'returning' } | null;

/** The slice of MeetApp's own $state this store reads/writes (mirrors the
 *  inbox's ActionHost / the calendar's CalendarActionHost). */
export interface MeetActionHost {
	meeting: Meeting | null;
	readonly room: MeetRoom | null;
	view: MeetView;
	errorMessage: string;
	/** B2 retro F8 — the meeting-switch generation counter; incremented only
	 *  by MeetApp's own openMeeting/openBySlug/openEndedMeeting. Read-only
	 *  here: every gen guard below just compares against the live value. */
	readonly openGeneration: number;
	/** B2 retro F2a — "push wins": read-only here, only ever set true by
	 *  MeetApp's own recording_state WS handler. */
	readonly recordingSeededByPush: boolean;
	recordingActive: boolean;
	recordingStopping: boolean;
	recordingRequested: boolean;
	captionsOn: boolean;
	currentBreakoutId: number | null;
	moveInterstitial: MoveInterstitial;
	whiteboardOpen: boolean;
}

function errText(e: unknown): string {
	return e instanceof MeetError ? e.detail : t('common.error');
}

export class MeetActions {
	#host: MeetActionHost;

	/** B2 retro F5: mirrors ControlsBar's own startBusy guard — set
	 *  synchronously before the first await, so a double-click in the same
	 *  tick short-circuits on the second call rather than racing a second
	 *  DELETE into a 409. Never read outside stopRecording itself. */
	stopBusy = $state(false);
	/** Mirrors stopBusy — a double-click captions Stop must fire exactly one
	 *  DELETE, not race a second one. Never read outside stopCaptions itself. */
	captionsStopBusy = $state(false);

	constructor(host: MeetActionHost) {
		this.#host = host;
	}

	async startRecording(): Promise<void> {
		const meeting = this.#host.meeting;
		if (!meeting) return;
		try {
			await meetApi.startRecording(meeting.meetingId);
		} catch (e) {
			if (e instanceof MeetError && e.code === 'egressBusy') {
				showToast(t('meet.recording.busy'));
			} else if (e instanceof MeetError && e.code === 'BZ199') {
				// B2 retro F6: the guest⇄recording exclusion arm — a dead key
				// before this, live now.
				showToast(t('meet.recording.blockedByGuests'));
			} else {
				showToast(errText(e));
			}
		}
	}

	async stopRecording(): Promise<void> {
		const meeting = this.#host.meeting;
		if (!meeting || this.stopBusy) return;
		this.stopBusy = true;
		try {
			await meetApi.stopRecording(meeting.meetingId);
		} catch (e) {
			if (e instanceof MeetError && e.code === 'BZ200') {
				// B2 retro F6: a state-conflict stop (already stopped/failed) —
				// distinguishable copy instead of the generic error toast.
				showToast(t('meet.recording.stopConflict'));
			} else {
				showToast(errText(e));
			}
		} finally {
			this.stopBusy = false;
		}
	}

	/** B3 Task 15: no local optimism on success — captionsOn only ever flips
	 *  via the captions_state push (MeetApp's own WS handler; the reducer
	 *  commits the fact + push BEFORE any sidecar call, so it lands
	 *  essentially immediately). captionsBusy gets its own distinguishable
	 *  toast (the egressBusy genre). */
	async startCaptions(): Promise<void> {
		const meeting = this.#host.meeting;
		if (!meeting) return;
		try {
			await meetApi.startCaptions(meeting.meetingId);
		} catch (e) {
			if (e instanceof MeetError && e.code === 'captionsBusy') {
				showToast(t('meet.captions.busy'));
			} else {
				showToast(errText(e));
			}
		}
	}

	/** Mirrors stopRecording's own stopBusy guard — a double-click must fire
	 *  exactly one DELETE. Unconditional server-side either way (D8), so no
	 *  distinguishable-error branch is needed here. */
	async stopCaptions(): Promise<void> {
		const meeting = this.#host.meeting;
		if (!meeting || this.captionsStopBusy) return;
		this.captionsStopBusy = true;
		try {
			await meetApi.stopCaptions(meeting.meetingId);
		} catch (e) {
			showToast(errText(e));
		} finally {
			this.captionsStopBusy = false;
		}
	}

	async end(): Promise<void> {
		const meeting = this.#host.meeting;
		if (!meeting) return;
		try {
			await meetApi.end(meeting.meetingId);
		} catch (e) {
			showToast(errText(e));
		}
	}

	async lock(locked: boolean): Promise<void> {
		const meeting = this.#host.meeting;
		if (!meeting) return;
		try {
			await meetApi.lock(meeting.meetingId, locked);
			this.#host.meeting = { ...meeting, locked };
		} catch (e) {
			showToast(errText(e));
		}
	}

	async kick(identity: string): Promise<void> {
		const meeting = this.#host.meeting;
		if (!meeting) return;
		try {
			await meetApi.kick(meeting.meetingId, identity);
		} catch (e) {
			showToast(errText(e));
		}
	}

	async setRole(identity: string, role: 'cohost' | 'member'): Promise<void> {
		const meeting = this.#host.meeting;
		if (!meeting) return;
		try {
			await meetApi.setRole(meeting.meetingId, identity, role);
		} catch (e) {
			showToast(errText(e));
		}
	}

	/** B3 Task 7 (design D1, the flagship fix): the forced-move choreography
	 *  for a self-targeted `breakout_assigned` push (or a host/cohost's own
	 *  voluntary roam via BreakoutsPanel's Join button, retro fix design
	 *  finding #1). Shows the full-stage interstitial (focus-managed by
	 *  MeetApp's own $effect, `aria-live=polite`) while the move is in
	 *  flight. ONE automatic retry on failure — the retry count is a plain
	 *  loop-local counter, not persisted state, since it can never outlive a
	 *  single call. `gen` (MeetApp's own B2 retro F8 openGeneration counter,
	 *  read-only here) guards against a meeting switch landing mid-move — a
	 *  stale continuation from an abandoned meeting must never touch the NEW
	 *  meeting's room/state. `room` is deliberately re-read from the host
	 *  (never captured into a local) at every post-await checkpoint: a
	 *  concurrent teardownLiveRoom nulling it out mid-move must be observed
	 *  live, not through a stale snapshot. */
	async moveToBreakout(breakoutId: number): Promise<void> {
		const h = this.#host;
		const meeting = h.meeting;
		if (!meeting || !h.room) return;
		const gen = h.openGeneration;
		const target = meeting.breakouts.find((b) => b.breakoutId === breakoutId);
		// B3 retro fix (design finding #9): a race with the breakout_opened
		// refetch can leave `target` unresolved on the COMMON auto-assign
		// path (the assign push can arrive before getMeeting's refetch
		// lands) — null falls back to the generic "moving…" copy in the
		// template, rather than a numberless "Breakout " label.
		const label = target ? (target.title ?? t('meet.breakouts.defaultName', { n: String(target.idx) })) : null;
		h.moveInterstitial = { kind: 'moving', roomLabel: label };
		// B3 retro fix (design finding #3, the D4 genre): a board left open
		// from the room just vacated must never answer the NEW room's
		// wb_req with the OLD room's scene.
		h.whiteboardOpen = false;

		for (let attempt = 0; attempt < 2; attempt++) {
			try {
				const tok = await meetApi.joinBreakout(meeting.meetingId, breakoutId);
				const r = h.room;
				if (gen !== h.openGeneration || !r) return;
				await r.moveTo(tok.token, tok.wsPath);
				if (gen !== h.openGeneration) return;
				h.currentBreakoutId = breakoutId;
				h.moveInterstitial = null;
				return;
			} catch {
				if (gen !== h.openGeneration) return;
				// fall through — attempt 0 retries once; attempt 1 falls to the
				// D1 exit below.
			}
		}
		// B3 retro fix (eng finding #1, the D10 redirect): joinBreakout
		// failed twice, but the server-side assignment may still be live —
		// rejoinMain's plain `join` redirects there per D10 if so, landing
		// the caller in the SAME assignment rather than a dead end. Only
		// toast "moveFailed" when the fallback genuinely did not land them
		// in the target room (a still-assigned redirect is a real, if
		// belated, success — not a failure to narrate).
		await this.rejoinMain();
		if (gen === h.openGeneration && h.view === 'in-room' && h.currentBreakoutId !== breakoutId) {
			showToast(t('meet.breakouts.moveFailed'));
		}
	}

	/** The auto-return choreography (spec's own naming): a `breakout_closed`
	 *  push while self is in a breakout, OR the D1 move-failure fallback, OR
	 *  an unexpected mid-breakout Disconnected, OR a roaming host/cohost's
	 *  own "Return to main" click — all four route through here (each still
	 *  dispatched by MeetApp's own WS handler / BreakoutsPanel wiring, which
	 *  just delegates to this method). Uses the PLAIN `join` route (not
	 *  `joinBreakout`), matching the spec's "rejoin main via the normal join
	 *  (idempotent upsert)" wording — and, per design D3, re-seeds
	 *  `recordingActive` from THIS call's own fact (the main room's real
	 *  recording state, never the child room's hard-`false`), so a member
	 *  returning into a live recording sees the banner. */
	async rejoinMain(): Promise<void> {
		const h = this.#host;
		const meeting = h.meeting;
		if (!meeting || !h.room) return;
		const gen = h.openGeneration;
		h.moveInterstitial = { kind: 'returning' };
		// B3 retro fix (design finding #3, the D4 genre): see moveToBreakout's
		// own comment above.
		h.whiteboardOpen = false;
		try {
			const res = await meetApi.join(meeting.meetingId);
			const r = h.room;
			if (gen !== h.openGeneration || !r) return;
			if (!h.recordingSeededByPush) {
				h.recordingActive = res.recordingActive;
				h.recordingStopping = false;
				h.recordingRequested = false;
			}
			// B3 Task 15 (design D4): re-seed the chip from THIS call's own
			// fresh read on return to main — the overlay/chip were suppressed
			// (main-room-only) for the whole time this caller was in the
			// child room, so a captions_state push that landed mid-breakout
			// was never applied; this join is the catch-up read.
			h.captionsOn = res.meeting.captionsOn;
			await r.moveTo(res.token, res.wsPath);
			if (gen !== h.openGeneration) return;
			// B3 retro fix (HIGH eng finding #1, the D10 redirect): the plain
			// `join` route redirects an assignment still live server-side
			// straight back to its CHILD room grant (D10) — currentBreakoutId
			// must reflect THAT fact, never a hardcoded main-room null, or a
			// still-assigned member is left with captions un-suppressed / the
			// "not recorded" banner gone while actually connected to a child
			// room, and a LATER breakout_closed push would then skip the
			// rejoin its own guard requires (it checks currentBreakoutId !==
			// null). A roaming host/cohost has no server-side assignment to
			// redirect against, so this always resolves to null for them —
			// exactly the "Return to main" outcome they expect.
			h.currentBreakoutId = res.meeting.myBreakoutId ?? null;
			h.moveInterstitial = null;
		} catch (e) {
			if (gen !== h.openGeneration) return;
			// B3 retro fix (LOW eng finding #12): a member in a breakout at
			// meeting end races breakout_closed -> rejoinMain against the
			// meeting_end that caused it — join rejects BZ190. The ended push
			// (meeting_state:ended, handled in MeetApp) owns the view
			// transition; this is a silent no-op, not an error screen.
			if (e instanceof MeetError && e.code === 'BZ190') {
				h.moveInterstitial = null;
				// B3 confirm-pass fix (eng NEW-1): also clear currentBreakoutId so
				// the disconnect $effect's guard (currentBreakoutId !== null) breaks
				// — otherwise, when the SFU eviction that accompanies a meeting end
				// lands BEFORE the meeting_state:ended push, this same effect
				// re-fires rejoinMain every time this catch clears moveInterstitial,
				// looping one POST /join per iteration until the (loss-tolerant,
				// possibly-lost) ended push arrives. The meeting is ended — no
				// consumer of currentBreakoutId (captions suppression, the "not
				// recorded" banner, BreakoutsPanel's own roster) matters once the
				// terminal `view = 'ended'` transition lands from that push.
				h.currentBreakoutId = null;
				return;
			}
			h.moveInterstitial = null;
			h.room?.disconnect();
			h.errorMessage = errText(e);
			h.view = 'error';
		}
	}
}
