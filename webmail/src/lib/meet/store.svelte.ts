// store.svelte.ts — MeetStore (arch review #A12): owns the meeting/view/push
// slice MeetApp.svelte used to hold as its own top-level `$state` with
// MeetActions mutating it through a get/set-accessor host (an inverted
// ownership vs every other app — ChatStore/InboxStore/CalendarEventsStore own
// their state; components read). MeetStore is a real rune class implementing
// `MeetActionHost` directly (its fields ARE the interface, no accessor
// indirection needed), so `new MeetActions(store)` needs zero changes to
// actions.svelte.ts or its test — the interface shape was already exactly
// this. Instantiated FRESH per MeetApp mount (`const store = new
// MeetStore()`), not a module-level singleton like chatStore/driveLocks/
// calendarEvents — the original component-local `$state` reset to defaults
// on every mount (route away from /meet and back = a brand new component
// instance = fresh state), and a shared singleton would silently change that.
//
// `applyEvent` (mirrors ChatStore.applyEvent) is the ~240-line WS
// push-reconciliation handler MeetApp.svelte used to inline directly in its
// `subscribeEvent('MeetEvent', …)` callback — the SUBSCRIPTION itself still
// lives in the component (the chat precedent: ChatApp calls subscribeEvent
// and forwards to chatStore.applyEvent), since $effect-based DOM/subscription
// wiring belongs in a component's reactive scope, not a class constructor
// that unit tests construct outside any component (an `$effect` there would
// throw `effect_orphan`).
//
// What stayed in MeetApp.svelte (deliberately NOT moved here): DOM refs
// (interstitialEl/roomMainEl, the focus-restore $effect), the disconnect
// $effect and the slug-deep-link $effect (both Svelte $effects — component
// territory), the breakoutAssignments meeting-reseed $effect (same reason),
// template-only $derived values (sheetParticipants/hasGuestParticipant/
// bannedList/chatEnabled), the landing-page create/join form (createTitle/
// joinLinkInput/createMeeting/joinByLink/extractSlug — thin UI glue with no
// push/view-FSM role), and galleryView/currentTheme (display prefs, not
// meeting state).
import * as meetApi from '$lib/meet/api';
import { MeetError, type Meeting, type MeetToken } from '$lib/meet/api';
import { MeetRoom } from '$lib/meet/room.svelte';
import { MeetActions, type MeetActionHost, type MeetView, type MoveInterstitial } from '$lib/meet/actions.svelte';
import { PresentationStore } from '$lib/meet/presentationStore.svelte';
import type { MeetCodec } from '$lib/meet/codecProbe';
import { goto } from '$app/navigation';
import { t } from '$lib/i18n';
import { showToast } from '$lib/components/ui';

export type PreJoinChoice = { micOn: boolean; camOn: boolean; codec: MeetCodec; blurEnabled: boolean };

const DEFAULT_CHOICE: PreJoinChoice = { micOn: false, camOn: false, codec: 'vp8', blurEnabled: false };

function errText(e: unknown): string {
	return e instanceof MeetError ? e.detail : t('common.error');
}

function recordingControlState(active: boolean, requested: boolean, stopping: boolean): 'idle' | 'starting' | 'recording' | 'stopping' {
	if (!active) return 'idle';
	if (requested) return 'starting';
	if (stopping) return 'stopping';
	return 'recording';
}

export class MeetStore implements MeetActionHost {
	view = $state<MeetView>('landing');
	errorMessage = $state('');
	meetings = $state<Meeting[]>([]);
	meeting = $state<Meeting | null>(null);
	room = $state<MeetRoom | null>(null);
	// D6: BreakoutsPanel, MeetChatPanel, and LobbyPanel share the ONE exclusive
	// side slot — opening one closes the others.
	sidePanel = $state<'chat' | 'breakouts' | 'lobby' | null>(null);
	// B3 Task 9 (design D6): the whiteboard is a MAIN-STAGE surface, not part
	// of the sidePanel exclusive slot — it can be open at the same time.
	whiteboardOpen = $state(false);
	knockCreds = $state<{ requestId: number; secret: string } | null>(null);

	// B2 retro F8: a monotonic generation counter — every openMeeting/
	// openBySlug/openEndedMeeting call captures its own value before the
	// await and compares after; a call superseded by a NEWER open* call drops
	// its response instead of clobbering state the newer call already set.
	// Plain field (not $state) — never rendered, only compared inside async
	// closures, exactly like the original component-local `let`.
	openGeneration = 0;

	// B2 Task 10 (D5/D-1/D-7): the in-room recording banner is server state,
	// seeded from the join envelope's OWN recordingActive (E-F3 — the
	// admission fact, not a getMeeting snapshot) and updated live by the
	// recording_state push.
	recordingActive = $state(false);
	recordingStopping = $state(false);
	// B2 retro F5: distinguishes the reducer's 'requested' phase from 'active'.
	recordingRequested = $state(false);
	recordingConsented = $state(false);
	// B2 retro F2a: "push wins" — once a recording_state push has landed for
	// the current meeting, a join/knock-admission envelope's OWN
	// recordingActive no longer overwrites it.
	recordingSeededByPush = $state(false);
	// B2 retro F1: a recording that started WHILE the caller waited in the
	// lobby — mirrors the guest join page's pendingAdmittedToken belt.
	pendingAdmittedToken = $state<MeetToken | null>(null);
	// B3 Task 15: the captions chip — SERVER state (never local optimism).
	captionsOn = $state(false);
	// Task 14's join-envelope-only signal: whether the ASR sidecar pair is
	// deployed/reachable at all.
	captionsConfigured = $state(false);

	// ── B3 Task 7: breakouts — the panel map, the caller's own current room,
	// and the forced-move interstitial. ────────────────────────────────────
	// identity -> current breakoutId (absent/null = main room). Seeded from
	// meeting.breakouts[].assignees by MeetApp's own reactive $effect (stays
	// component-side — see the file header); kept current after that by every
	// breakout_assigned push via applyEvent below, without a re-fetch.
	breakoutAssignments = $state<Record<string, number | null>>({});
	// B1 live-gate ledger fix 2 / A/B leftover item 1: identity -> displayName,
	// host/cohost-visible re-admit affordance. Seeded from meeting.banned[]
	// every time `meeting` is set from a fresh server read (seedBanned), kept
	// current after that by participant_kicked/participant_role pushes below
	// WITHOUT a re-fetch — deliberately not reseeded reactively (several push
	// handlers patch `meeting` via a shallow spread that leaves `.banned`
	// referencing the pre-kick snapshot; reseeding on those would clobber a
	// push-added entry that hasn't landed in a fresh getMeeting response yet).
	bannedMembers = $state<Record<string, string>>({});
	// The room the SELF caller is CURRENTLY connected to: null = main,
	// otherwise a meeting_breakouts.id. Distinct from meeting.myBreakoutId (a
	// point-in-time server snapshot) — updated the moment room.moveTo lands.
	currentBreakoutId = $state<number | null>(null);
	// Full-stage move/return interstitial (design D6). null = not moving.
	moveInterstitial = $state<MoveInterstitial>(null);

	/** B2 retro F1/E-F3: the caller's own PreJoin choice, replayed for the
	 *  pendingAdmittedToken consent-gate connect. Plain field (not $state,
	 *  matches the original component-local closure variable) — never
	 *  rendered, only read inside connect flows. */
	savedChoice: PreJoinChoice | null = null;

	controlsRecordingState = $derived<'idle' | 'starting' | 'recording' | 'stopping'>(
		recordingControlState(this.recordingActive, this.recordingRequested, this.recordingStopping)
	);

	/** The host-control dispatch layer (recording/captions start-stop, end/
	 *  lock/kick/setRole, breakout move/auto-return) — MeetStore IS its own
	 *  MeetActionHost, so no accessor facade is needed. */
	readonly actions: MeetActions = new MeetActions(this);

	// ── MEET plan M3: the presentation session store — its own rune class
	// (picker/prepare/preview, promoted checkpoint/manifest, presenter rail,
	// handoff, local zoom, ephemeral pointer/ink). Fresh per MeetStore
	// instance, reset by teardownLiveRoom (the D4 room-scoped-state genre),
	// (re)bound + attached by connectRoom, and reauthorized by MeetApp's own
	// sync $effect (effects live component-side — the MeetStore posture).
	readonly presentation = new PresentationStore();

	seedBanned(m: Meeting): void {
		this.bannedMembers = Object.fromEntries(m.banned.map((b) => [b.identity, b.displayName]));
	}

	async loadMeetings(): Promise<void> {
		try {
			this.meetings = await meetApi.listMeetings();
		} catch (e) {
			showToast(errText(e));
		}
	}

	// B2 retro F3: a meeting switch mid-room (e.g. the knock-toast "Open"
	// action navigating `?slug=` while already in-room) must never leave the
	// PREVIOUS room's mic/cam hot. Shared by openMeeting/openBySlug (called
	// first-line) and leave/teardownRoom.
	teardownLiveRoom(): void {
		this.room?.disconnect();
		this.room = null;
		this.recordingActive = false;
		this.recordingStopping = false;
		this.recordingRequested = false;
		this.recordingConsented = false;
		this.recordingSeededByPush = false;
		this.pendingAdmittedToken = null;
		// stopBusy/captionsStopBusy (the recording/captions double-DELETE
		// guards) live on the MeetActions store — they self-reset in each
		// action's own `finally` regardless, but this belt-and-suspenders
		// reset (the original inline behavior) is kept verbatim.
		this.actions.stopBusy = false;
		this.actions.captionsStopBusy = false;
		// B3 Task 15 (design D4 genre): the captions chip is this store's own
		// state — a meeting switch must not carry a stale chip into the next
		// meeting.
		this.captionsOn = false;
		this.captionsConfigured = false;
		// B3 Task 7 (design D4): every breakout bit of state this store owns,
		// so a meeting switch mid-breakout leaks nothing into the next
		// meeting. captionSegments and the wb reassembly buffer (Task 6) live
		// INSIDE MeetRoom, not here — they die with the room object itself.
		this.sidePanel = null;
		this.breakoutAssignments = {};
		this.bannedMembers = {};
		this.currentBreakoutId = null;
		this.moveInterstitial = null;
		// B3 Task 9: the whiteboard is main-stage, not sidePanel, but the same
		// D4 rule applies.
		this.whiteboardOpen = false;
		// MEET plan M3 (D4 genre): the presentation slice dies with the
		// meeting — session truth, picker/preview flow, ephemeral overlay,
		// local zoom, and the room's frame-classifier context (reset inside
		// to fail closed). Returning participants reauthorize via sync(); no
		// cached grant ever crosses a meeting switch.
		this.presentation.reset();
	}

	async openMeeting(meetingId: number): Promise<void> {
		this.teardownLiveRoom();
		const gen = ++this.openGeneration;
		this.view = 'loading';
		try {
			const m = await meetApi.getMeeting(meetingId);
			if (gen !== this.openGeneration) return; // superseded by a newer open* call
			this.meeting = m;
			this.seedBanned(m);
			// A recording_state push for the PREVIOUS meeting landing inside the
			// await window above would have re-set the seed flag against the OLD
			// `meeting` — reset so the NEW meeting's join envelope seeds cleanly.
			this.recordingSeededByPush = false;
			this.view = 'prejoin';
		} catch (e) {
			if (gen !== this.openGeneration) return;
			this.errorMessage = errText(e);
			this.view = 'error';
		}
	}

	async openBySlug(slug: string): Promise<void> {
		this.teardownLiveRoom();
		const gen = ++this.openGeneration;
		this.view = 'loading';
		try {
			const m = await meetApi.resolveSlug(slug);
			if (gen !== this.openGeneration) return; // superseded by a newer open* call
			this.meeting = m;
			// A/B leftover item 5: the authed by-slug resolve is deliberately
			// post-end capable, but PreJoin has no join button that could ever
			// succeed against an ended meeting — an ended meeting routes
			// straight to the SAME ended/summary view openEndedMeeting renders.
			if (m.state === 'ended') {
				this.view = 'ended';
				return;
			}
			this.seedBanned(m);
			this.recordingSeededByPush = false;
			this.view = 'prejoin';
		} catch (e) {
			if (gen !== this.openGeneration) return;
			this.errorMessage = errText(e);
			this.view = 'error';
		}
	}

	/** D-2: Recent-list rows open the ENDED view directly — getMeeting is
	 *  post-end capable via meeting_attendee_role. Recent rows only render on
	 *  the landing view (no live room to leak), so no teardownLiveRoom() call
	 *  here — the shared generation counter (F8) still applies. */
	async openEndedMeeting(meetingId: number): Promise<void> {
		const gen = ++this.openGeneration;
		this.view = 'loading';
		try {
			const m = await meetApi.getMeeting(meetingId);
			if (gen !== this.openGeneration) return;
			this.meeting = m;
			this.view = 'ended';
		} catch (e) {
			if (gen !== this.openGeneration) return;
			this.errorMessage = errText(e);
			this.view = 'error';
		}
	}

	/** D5: "Don't join" — the caller never connects; back to the landing
	 *  screen, same shape as a normal teardown minus a room to disconnect. */
	declinePreJoin(): void {
		this.meeting = null;
		this.view = 'landing';
		this.recordingConsented = false;
		this.recordingSeededByPush = false;
		void this.loadMeetings();
	}

	async handlePreJoin(choice: PreJoinChoice, authenticatedGuest = false): Promise<void> {
		if (!this.meeting) return;
		this.savedChoice = choice;
		try {
			const res = await meetApi.join(this.meeting.meetingId);
			// B3 retro fix (eng finding #7/#11): the join response's OWN
			// `meeting` is the freshest read available at this point — a
			// breakout assignment (or any other server fact) made while the
			// caller dwelled on PreJoin is visible HERE, not on the pre-join
			// snapshot. Refresh this store's own `meeting` from it so
			// connectRoom's `meeting?.myBreakoutId` read below sees it too.
			this.meeting = res.meeting;
			this.seedBanned(res.meeting);
			// D5/E-F3: the join envelope's OWN recordingActive is the
			// admission fact — never re-derive it from meeting.recordingActive
			// (a pre-join snapshot that can be stale by the time join lands).
			// B2 retro F2a: unless a recording_state push already seeded fresher
			// state for this meeting — push wins over this one-shot envelope.
			if (!this.recordingSeededByPush) {
				this.recordingActive = res.recordingActive;
				this.recordingStopping = false;
				this.recordingRequested = false;
			}
			// B3 Task 15: seed the chip from the join envelope's OWN state.
			this.captionsOn = res.meeting.captionsOn;
			this.captionsConfigured = res.captionsConfigured ?? false;
			await this.connectRoom(res.token, res.wsPath, choice);
		} catch (e) {
			if (e instanceof MeetError && (e.code === 'BZ187' || (authenticatedGuest && e.code === 'BZ215'))) {
				try {
					this.knockCreds = authenticatedGuest
						? await meetApi.knock(this.meeting.meetingId, this.meeting.slug)
						: await meetApi.knock(this.meeting.meetingId);
					this.view = 'knocking';
				} catch (knockErr) {
					this.errorMessage = errText(knockErr);
					this.view = 'error';
				}
				return;
			}
			this.errorMessage = errText(e);
			this.view = 'error';
		}
	}

	/** B2 retro F1: LobbyWaiting's `onAdmitted` for the member-knock arm. The
	 *  caller already consented at PreJoin — this covers the narrower race
	 *  where a recording STARTS while they wait in the lobby: route through
	 *  the SAME consent gate one more time before ever connecting (the guest
	 *  join page's pendingAdmittedToken pattern, mirrored for authed members).
	 *  B3 retro fix (design findings #4/#5): ccIdentity is unused here — a
	 *  knocking member already has a live `meeting`, so connectRoom derives
	 *  the SAME `cc:{meetingId}` identity from it directly. */
	handleKnockAdmitted(token: MeetToken, rec: boolean, captionsOnAtAdmit: boolean, _ccIdentity: string): void {
		if (!this.recordingSeededByPush) {
			this.recordingActive = rec;
			this.recordingStopping = false;
			this.recordingRequested = false;
		}
		// ponytail: captionsConfigured has no equivalent on the knock/guest
		// poll admitted grant (meeting_lobby.sql projects only
		// recordingActive/captionsOn/ccIdentity, never Task 14's
		// join-envelope-only captionsConfigured) — a cohost who knocks on a
		// locked meeting keeps captionsConfigured=false (the teardownLiveRoom
		// reset) and so never sees the captions button until their next real
		// getMeeting/join round-trip. Fixing this for real needs
		// meeting_lobby.sql to also project captionsConfigured, a
		// reducer/SQL change outside this webmail-only task's remit.
		this.captionsOn = captionsOnAtAdmit;
		if (rec && !this.recordingConsented) {
			this.pendingAdmittedToken = token;
		} else {
			void this.connectRoom(token.token, token.wsPath, this.savedChoice ?? DEFAULT_CHOICE);
		}
	}

	/** The pendingAdmittedToken consent gate's own onConsent/onDecline —
	 *  extracted so MeetApp's template stays a thin call-through. */
	confirmPendingAdmission(): void {
		const token = this.pendingAdmittedToken;
		this.pendingAdmittedToken = null;
		this.recordingConsented = true;
		if (token) void this.connectRoom(token.token, token.wsPath, this.savedChoice ?? DEFAULT_CHOICE);
	}

	declinePendingAdmission(): void {
		this.pendingAdmittedToken = null;
		this.declinePreJoin();
	}

	async connectRoom(token: string, wsPath: string, choice: PreJoinChoice): Promise<void> {
		// B3 Task 6/7 (F8): the server-attested cc:{meetingId} captions bot
		// identity for THIS meeting — a data-channel frame from anyone else
		// claiming to be the bot is dropped (room.svelte.ts's own defense).
		const r = new MeetRoom(choice.codec, this.meeting ? `cc:${this.meeting.meetingId}` : '');
		r.localMuted = !choice.micOn;
		r.localCameraOff = !choice.camOn;
		await r.connect(token, wsPath, { blurEnabled: choice.blurEnabled });
		this.room = r;
		// MEET plan M3: bind + attach the presentation store to the live
		// room. The client gate seeds from THIS envelope's own projection
		// (default OFF until the M2 projection key lands); the live-summary
		// provider closes over THIS store's meeting projection — sync()'s
		// reauthorization reads meeting_get's `presentation` summary, then
		// the authorized checkpoint read. The envelope seeds visibility,
		// never a presenter grant.
		this.presentation.enabled = this.meeting?.presentationEnabled ?? false;
		this.presentation.bind(this.meeting?.meetingId ?? 0, () => this.meeting?.presentation ?? null);
		this.presentation.attach(r);
		// D10: a member already assigned to an open breakout is join-redirected
		// straight there by meeting_join itself — seed from the server fact
		// rather than assuming main.
		this.currentBreakoutId = this.meeting?.myBreakoutId ?? null;
		this.view = 'in-room';
	}

	leave(): void {
		this.teardownRoom();
	}

	teardownRoom(): void {
		this.teardownLiveRoom();
		this.meeting = null;
		this.view = 'landing';
		void this.loadMeetings();
	}

	/** Reconcile state after a guest EventSource opens or reconnects. Named
	 * SSE delivery has no replay cursor, so the current meeting projection is
	 * the authority for any recording/end/captions/breakout event missed in
	 * the gap. */
	async reconcileCurrentMeeting(): Promise<void> {
		const targetId = this.meeting?.meetingId;
		if (targetId == null) return;
		try {
			const m = await meetApi.getMeeting(targetId);
			if (this.meeting?.meetingId !== targetId) return;
			this.meeting = m;
			this.seedBanned(m);
			this.recordingActive = m.recordingActive;
			this.recordingStopping = false;
			this.recordingRequested = false;
			this.captionsOn = m.captionsOn;
			if (m.state === 'ended') {
				this.room?.disconnect();
				this.view = 'ended';
				return;
			}
			if (this.view === 'in-room' && m.myBreakoutId !== this.currentBreakoutId) {
				if (m.myBreakoutId == null) void this.actions.rejoinMain();
				else void this.actions.moveToBreakout(m.myBreakoutId);
			}
		} catch {
			// Best-effort reconciliation. The authenticated EventSource remains
			// open and the next named event or reconnect retries naturally.
		}
	}

	// ── WS wiring: meeting_state (incl. the named `ended` test), the knock
	// toast, and lock/guest-allowed live badges on the current meeting. ────
	//
	// B2 retro F2b (residual, honestly deferred): the ideal fix also
	// re-fetches getMeeting and re-seeds recording state on a WS RECONNECT
	// while in-room (a push missed entirely during the drop must not leave a
	// stale banner). $lib/jmap/websocket.ts exposes no reconnect callback —
	// only an internal `ws.onopen`/`ws.onclose` pair — so there is no
	// client-side hook to ride without editing that file. recording_state IS
	// still idempotent and self-healing the moment ANY future push for this
	// meeting lands (the push-wins seeding above), and the recording_ready
	// path already does a full re-fetch; the one true gap is a push that is
	// BOTH missed by the drop AND never followed by another one before the
	// caller leaves. Add a subscribeReconnect()-shaped export to
	// websocket.ts and call meetApi.getMeeting() from it if that gap ever
	// needs closing.
	//
	// The caller (MeetApp.svelte) registers this via
	// `subscribeEvent('MeetEvent', (evt) => store.applyEvent(evt))` —
	// subscribeEvent (jmap/websocket.ts, arch review #A2) unwraps the
	// envelope ONCE at the hub, so `evt` here is already the inner event, not
	// the raw `{"@type","event"}` wrapper. The event-shape check below stays:
	// it validates the INNER event's own required fields, not the envelope
	// (a MeetEvent with no `event`/`meetingId` is still a malformed inner
	// payload this must no-op on).
	applyEvent(evt: { event?: string; meetingId?: number; payload?: Record<string, unknown> | null }): void {
		if (!evt.event || evt.meetingId == null) return;
		if (evt.event === 'meeting_state') {
			if (this.meeting && evt.meetingId === this.meeting.meetingId) {
				if (evt.payload && 'locked' in evt.payload) this.meeting = { ...this.meeting, locked: !!evt.payload.locked };
				if (evt.payload && 'guestAllowed' in evt.payload) this.meeting = { ...this.meeting, guestAllowed: !!evt.payload.guestAllowed };
				if (evt.payload?.state === 'ended') {
					this.room?.disconnect();
					// D-2: the prejoin/in-room snapshot predates the recording
					// rows — refetch BEFORE the ended view (and its
					// RecordingsList/AttendancePanel) renders. Still transitions
					// on a failed refetch rather than stranding the caller
					// mid-teardown.
					const targetId = this.meeting.meetingId;
					void meetApi
						.getMeeting(targetId)
						.then((m) => {
							if (this.meeting?.meetingId === targetId) this.meeting = m;
						})
						.catch(() => undefined)
						.finally(() => {
							this.view = 'ended';
						});
				}
			}
			return;
		}
		if (evt.event === 'recording_state') {
			if (this.meeting && evt.meetingId === this.meeting.meetingId) {
				// D-1 truthful mapping: requested|active|stopping -> banner ON
				// (stopping also flips the copy switch, requested flips the
				// starting one, F5); stopped|failed -> OFF.
				const s = evt.payload?.state;
				if (s === 'requested' || s === 'active' || s === 'stopping') {
					this.recordingActive = true;
					this.recordingStopping = s === 'stopping';
					this.recordingRequested = s === 'requested';
				} else if (s === 'stopped' || s === 'failed') {
					this.recordingActive = false;
					this.recordingStopping = false;
					this.recordingRequested = false;
				}
				// F2a: "push wins" — a later join/knock-admission envelope's own
				// recordingActive no longer overwrites what a push already set.
				this.recordingSeededByPush = true;
			}
			return;
		}
		if (evt.event === 'presentation_state') {
			// MEET plan M2: the all-live-members stage fact — a fresh
			// checkpointSeq is exactly the bounded invalidation hint the
			// frozen CheckpointRefresher admits. NEVER a state promotion
			// (the M0 receive contract): the hint's payload values are
			// ignored; the authorized checkpoint read is the only promoter.
			this.presentation.hint();
			return;
		}
		if (evt.event === 'captions_state') {
			// B3 Task 15, DN3: an ordinary all-live-members fan-out — every
			// member renders the identical chip. Server state, never local
			// optimism: this is the ONLY place captionsOn ever flips true/false
			// for a member surface (the join/knock-admit seeds above are
			// one-shot snapshots).
			if (this.meeting && evt.meetingId === this.meeting.meetingId) {
				this.captionsOn = !!evt.payload?.on;
			}
			return;
		}
		// B1 live-gate ledger fix 2: notify_meet_state's fan-out excludes the
		// JUST-kicked identity itself (meeting_kick stamps left_at before this
		// PERFORM runs, and the fan-out SELECT filters left_at IS NULL) — so
		// this only ever reaches OTHER live members, host/cohost included.
		if (evt.event === 'participant_kicked') {
			if (this.meeting && evt.meetingId === this.meeting.meetingId) {
				const identity = evt.payload?.identity;
				if (typeof identity === 'string') {
					// sheetParticipants (the template-only room.participants
					// projection) lived in MeetApp; the equivalent fallback name
					// read directly off `room.participants` here (p.name || identity,
					// the same displayName derivation) — no need to duplicate the
					// derived array itself for this one lookup.
					const name =
						this.meeting.attendance.find((a) => a.identity === identity)?.displayName ??
						this.room?.participants.find((p) => p.identity === identity)?.name ??
						identity;
					this.bannedMembers = { ...this.bannedMembers, [identity]: name };
				}
			}
			return;
		}
		// meeting_set_role's own comment: assigning a role to a banned identity
		// IS the re-admit path — so a participant_role push for an identity
		// this store still has in bannedMembers means the re-admit landed
		// (push-is-truth — never cleared optimistically from doReAdmit's own
		// call site).
		if (evt.event === 'participant_role') {
			if (this.meeting && evt.meetingId === this.meeting.meetingId) {
				const identity = evt.payload?.identity;
				if (typeof identity === 'string' && identity in this.bannedMembers) {
					const next = { ...this.bannedMembers };
					delete next[identity];
					this.bannedMembers = next;
				}
			}
			return;
		}
		if (evt.event === 'recording_ready') {
			// D-2 / the A4b stale-response drop: scope BEFORE the await, then
			// compare the captured id AFTER it — a late response for a meeting
			// the caller has since left is discarded, never applied.
			if (this.meeting && evt.meetingId === this.meeting.meetingId) {
				const targetId = this.meeting.meetingId;
				void meetApi.getMeeting(targetId).then((m) => {
					if (this.meeting?.meetingId === targetId) this.meeting = m;
				});
			}
			return;
		}
		if (evt.event === 'join_request_created') {
			const sameRoom = this.view === 'in-room' && this.meeting?.meetingId === evt.meetingId;
			// UX #9: LobbyPanel is toggleable (sidePanel), not always-docked —
			// "LobbyPanel inside the room is the surface" only holds while it's
			// actually open. Refetch `meeting` whenever sameRoom, regardless of
			// whether the panel is open, so a host already in-room sees a knock
			// arrive live, in the panel OR via toast.
			void meetApi.getMeeting(evt.meetingId).then((m) => {
				if (sameRoom) this.meeting = m;
				if (sameRoom && this.sidePanel === 'lobby') return; // panel is the surface while open — never both
				const req = m.pendingJoinRequests[m.pendingJoinRequests.length - 1];
				if (!req) return;
				showToast(t('meet.knockToast.title', { name: req.displayName }), {
					actionLabel: t('meet.knockToast.open'),
					onAction: sameRoom
						? () => {
								this.sidePanel = 'lobby';
							}
						: () => void goto(`/meet?slug=${m.slug}`),
				});
			});
			return;
		}
		// ── B3 Task 7: breakouts ─────────────────────────────────────────────
		if (evt.event === 'breakout_opened') {
			// A count-only payload — the panel needs the actual room rows, so
			// refetch (mirrors recording_ready's own re-fetch shape).
			if (this.meeting && evt.meetingId === this.meeting.meetingId) {
				const targetId = this.meeting.meetingId;
				void meetApi.getMeeting(targetId).then((m) => {
					if (this.meeting?.meetingId === targetId) this.meeting = m;
				});
			}
			return;
		}
		if (evt.event === 'breakout_assigned') {
			if (!this.meeting || evt.meetingId !== this.meeting.meetingId) return;
			const identity = evt.payload?.identity;
			if (typeof identity !== 'string') return;
			const breakoutId = (evt.payload?.breakoutId as number | null | undefined) ?? null;
			// The panel map update — for EVERY identity, self included, no
			// re-fetch; self additionally triggers the move choreography below.
			this.breakoutAssignments = { ...this.breakoutAssignments, [identity]: breakoutId };
			const selfIdentity = this.room?.room.localParticipant.identity;
			if (identity === selfIdentity && this.view === 'in-room' && breakoutId !== null) {
				void this.actions.moveToBreakout(breakoutId);
			}
			return;
		}
		if (evt.event === 'breakout_closed') {
			// B3 retro fix (design finding #10): the foreign-meeting check
			// guards the WHOLE branch — a push for a meeting the caller isn't
			// even looking at must not touch this store's local panel map at
			// all.
			if (!this.meeting || evt.meetingId !== this.meeting.meetingId) return;
			// Every assignment resets to main server-side — mirror it locally.
			this.breakoutAssignments = {};
			if (this.currentBreakoutId !== null && this.view === 'in-room') {
				void this.actions.rejoinMain();
			}
			return;
		}
	}
}
