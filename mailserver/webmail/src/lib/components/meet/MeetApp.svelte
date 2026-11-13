<svelte:options runes={true} />

<script lang="ts">
	// MeetApp — Meet B1 Task 16: the /meet app shell. Design #9 ("the rail
	// opens a real page, not a filename"): landing (New meeting / join-by-
	// link / Upcoming / Recent) → PreJoin → (member-knock via the shared
	// LobbyWaiting when locked) → the in-meeting room (MeetingRoom +
	// ControlsBar + host LobbyPanel + the chat bridge). Design #14: `?slug=`
	// is the ONE canonical in-app deep-link shape.
	//
	// The knock toast (design #3): a global-ish consumer of
	// `join_request_created` — while mounted (i.e. anywhere under /meet,
	// landing included) it raises a Toast with inline Admit/Deny + an Open
	// action whenever the event is for a DIFFERENT meeting than the one
	// currently in-room (the both-surfaces rule: toast outside the room,
	// LobbyPanel inside, never both). True cross-app visibility (a host
	// reading MAIL sees it) needs a root-layout-level subscriber, which is
	// out of this component's reach — see Task 16's deviation note.
	//
	// Arch review #A12: the meeting/view/push slice — everything the WS
	// push-reconciliation handler and the view-FSM transitions (open*/
	// handlePreJoin/handleKnockAdmitted/connectRoom/leave/teardownRoom) touch
	// — now lives in `$lib/meet/store.svelte.ts` (MeetStore), a real rune
	// class that OWNS its state (this component just reads it), fixing the
	// inverted MeetActionHost-mutates-component-state ownership the earlier
	// arch #9 extraction left in place. What stays here: DOM refs, the focus/
	// disconnect/slug $effects (component-lifecycle territory), template-only
	// $derived projections, and the landing-page create/join form. See
	// store.svelte.ts's own header for the full boundary rationale.
	import { onDestroy, tick, untrack } from 'svelte';
	import { page } from '$app/state';
	import { DisconnectReason } from 'livekit-client';
	import * as meetApi from '$lib/meet/api';
	import { MeetError, type Meeting } from '$lib/meet/api';
	import { MeetStore } from '$lib/meet/store.svelte';
	import type { PresentationCleanup } from '$lib/meet/presentationStore.svelte';
	import { subscribeEvent } from '$lib/jmap/websocket';
	import { effectiveCaps, isGuestSession } from '$lib/stores/session';
	import { user } from '$lib/stores/auth';
	import { Button, Input, EmptyState, Spinner, Badge, showToast } from '$lib/components/ui';
	import { t } from '$lib/i18n';
	import PreJoin from './PreJoin.svelte';
	import LobbyWaiting from './LobbyWaiting.svelte';
	import LobbyPanel from './LobbyPanel.svelte';
	import MeetingRoom from './MeetingRoom.svelte';
	import ControlsBar from './ControlsBar.svelte';
	import MeetChatPanel from './MeetChatPanel.svelte';
	import BreakoutsPanel from './BreakoutsPanel.svelte';
	import WhiteboardPanel from './WhiteboardPanel.svelte';
	import PresentationPicker from './PresentationPicker.svelte';
	import PresentationStage from './PresentationStage.svelte';
	import RecordingBanner from './RecordingBanner.svelte';
	import RecordingConsentGate from './RecordingConsentGate.svelte';
	import RecordingsList from './RecordingsList.svelte';
	import AttendancePanel from './AttendancePanel.svelte';
	import type { SheetParticipant } from './ControlsBar.svelte';
	import { isExternalParticipant } from '$lib/meet/participantAttributes';
	import { subscribeGuestMeetEvents } from '$lib/chat/guestEventSource';

	const store = new MeetStore();

	// Cleanup belongs to the departed Meeting, never the replacement session.
	// Keep its existing Retry toast visible until handled/dismissed; failed
	// retries publish a fresh record and cannot start an automatic retry loop.
	let cleanupNotice: PresentationCleanup | null = null;
	let cleanupToast: ReturnType<typeof showToast> | null = null;
	$effect(() => {
		const next = store.presentation.cleanupFailures.at(-1) ?? null;
		untrack(() => {
			if (next === cleanupNotice) return;
			cleanupNotice = next;
			cleanupToast?.dismiss();
			cleanupToast = null;
			if (next) {
				cleanupToast = showToast(t('meet.presentation.cleanupFailed', { meeting: String(next.meetingId) }), {
					variant: 'danger', durationMs: 0, actionLabel: t('common.retry'),
					onAction: () => store.presentation.retryCleanup(next),
				});
			}
		});
	});
	onDestroy(() => cleanupToast?.dismiss());

	// ── UI-only local state: form fields, DOM refs, display prefs. The
	// meeting/view/push slice lives in `store` (MeetStore). ─────────────────
	let galleryView = $state<'gallery' | 'speaker'>('gallery');
	/** B3 Task 8: the Poll button's pass-through target — set via bind:this
	 *  on MeetChatPanel below (mounted only while store.sidePanel === 'chat'). */
	let chatPanelRef = $state<MeetChatPanel | null>(null);
	let joinLinkInput = $state('');
	let createTitle = $state('');
	let interstitialEl = $state<HTMLElement | undefined>();
	// B3 retro fix (design finding #11): the room-main region — the
	// interstitial's own focus-restore target once it unmounts (focus was
	// moving INTO it but dropping to <body> on exit).
	let roomMainEl = $state<HTMLElement | undefined>();
	let wasMoving = false;
	$effect(() => {
		if (store.moveInterstitial) {
			wasMoving = true;
			interstitialEl?.focus();
		} else if (wasMoving) {
			wasMoving = false;
			roomMainEl?.focus();
		}
	});

	// D3: seed the panel map from the meeting's own host/cohost-only
	// `breakouts[].assignees` projection — a plain member's rows carry no
	// `assignees` key at all (the server-side anti-oracle), so this is a
	// no-op map for them (BreakoutsPanel itself is host/cohost-only anyway).
	$effect(() => {
		const m = store.meeting;
		if (!m) {
			store.breakoutAssignments = {};
			return;
		}
		const map: Record<string, number | null> = {};
		for (const b of m.breakouts) for (const a of b.assignees ?? []) map[a.identity] = b.breakoutId;
		store.breakoutAssignments = map;
	});

	function errText(e: unknown): string {
		return e instanceof MeetError ? e.detail : t('common.error');
	}

	/** B3 Task 9: the whiteboard's INITIAL theme — no reactive theme store
	 *  exists app-wide (see WhiteboardPanel.svelte's own comment); this reads
	 *  the DOM attribute $lib/theme/apply.ts sets once, at open time.
	 *  WhiteboardPanel keeps itself in sync with any LIVE toggle afterward. */
	function currentTheme(): 'light' | 'dark' {
		return typeof document !== 'undefined' && document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light';
	}

	// createMeeting/joinByLink/extractSlug are thin landing-page glue (a
	// create-then-navigate / join-then-navigate form flow tightly bound to
	// the local createTitle/joinLinkInput fields) — not part of the meeting/
	// view/push slice, so they stay here and call into the store only at
	// their final navigation step.
	async function createMeeting(): Promise<void> {
		const title = createTitle.trim() || t('meet.app.titlePlaceholder');
		try {
			const created = await meetApi.createMeeting({ title });
			createTitle = '';
			await store.loadMeetings();
			await store.openMeeting(created.meetingId);
		} catch (e) {
			showToast(errText(e));
		}
	}

	/** design #14: `/meet?slug=…` is the ONE canonical in-app deep-link shape. */
	function extractSlug(raw: string): string {
		const trimmed = raw.trim();
		try {
			const url = new URL(trimmed, location.href);
			const slug = url.searchParams.get('slug');
			if (slug) return slug;
		} catch {
			/* not a URL — treat the raw input as a bare slug */
		}
		return trimmed;
	}

	async function joinByLink(): Promise<void> {
		const slug = extractSlug(joinLinkInput);
		if (!slug) return;
		await store.openBySlug(slug);
	}

	// doStartRecording/doStopRecording/doStartCaptions/doStopCaptions/doEnd/
	// doLock/doKick/doSetRole/doReAdmit are thin call-through wiring onto
	// `store.actions` (see $lib/meet/actions.svelte.ts) — every existing call
	// site (ControlsBar props) keeps calling these exact names/signatures
	// unchanged; only the dispatch logic lives in the action store, now
	// reached via `store.actions` instead of a local `actions` instance.
	async function doStartRecording(): Promise<void> {
		await store.actions.startRecording();
	}

	async function doStopRecording(): Promise<void> {
		await store.actions.stopRecording();
	}

	async function doStartCaptions(): Promise<void> {
		await store.actions.startCaptions();
	}

	async function doStopCaptions(): Promise<void> {
		await store.actions.stopCaptions();
	}

	async function doEnd(): Promise<void> {
		await store.actions.end();
	}

	async function doLock(locked: boolean): Promise<void> {
		await store.actions.lock(locked);
	}

	/** B3 Task 8: opens the chat side panel (mounting MeetChatPanel), then
	 *  delegates to its openPollDialog() pass-through — the SAME poll dialog
	 *  Composer's own "+" menu already offers (spec §4.2), never a duplicate. */
	async function openPoll(): Promise<void> {
		store.sidePanel = 'chat';
		await tick();
		await chatPanelRef?.openPollDialog();
	}

	// ── MEET plan M3: presentation integration ──────────────────────────
	// Whiteboard and document are MUTUALLY EXCLUSIVE main-stage modes, not
	// destructive data operations: opening the whiteboard suspends the
	// document stage (ephemeral ink cleared, durable state kept); closing it
	// returns and RELOADS the current checkpoint (sync's authorized read).
	// The room effect below owns suspension and return even with no session.
	function toggleWhiteboard(): void {
		store.whiteboardOpen = !store.whiteboardOpen;
	}

	// (Re)authorization + breakout suspension, owned by this component-side
	// $effect (the MeetStore posture: effects never live in a class). On a
	// connected MAIN room: sync() — a fresh authorized read, so reconnecting
	// or returning participants REAUTHORIZE rather than reuse any cached
	// grant. On a breakout: suspend — a child room grants no parent-room
	// capability, the stage clears, and the room swap itself fails the frame
	// classifier closed (room.moveTo resets the presentation context).
	$effect(() => {
		const r = store.room;
		const p = store.presentation;
		if (store.currentBreakoutId !== null || store.whiteboardOpen) {
			p.suspend();
			return;
		}
		if (!r || r.connectionState !== 'connected') return;
		void p.sync();
	});

	/** The ordinary screen-share fallback (existing mechanism): stop the
	 *  presentation and hand the stage to LiveKit screen share — two
	 *  interactions including the OS picker, never ending the meeting. */
	function presentationFallback(): void {
		void store.presentation.end();
		void store.room?.toggleScreenShare();
	}

	async function doKick(identity: string): Promise<void> {
		await store.actions.kick(identity);
	}

	async function doSetRole(identity: string, role: 'cohost' | 'member'): Promise<void> {
		await store.actions.setRole(identity, role);
	}

	/** B1 live-gate ledger fix 2: re-admit is `meeting_set_role` (server-side
	 *  comment on meeting_control.sql: "assigning a role to a banned identity
	 *  ALSO clears banned_at — this IS the re-admit path"), the SAME reducer
	 *  call `doSetRole` above already wires — no separate route exists or is
	 *  needed. 'member' (never 'cohost') matches the roster's own default for
	 *  a plain re-admit. Confirm-free (re-admit is reversible — a re-kick is
	 *  one click away); MeetActions.setRole already toasts errText(e) on
	 *  failure, the existing idiom. bannedMembers itself is cleared by
	 *  store.applyEvent's own participant_role handler on a CONFIRMED
	 *  re-admit, not optimistically here — mirrors every other push-is-truth
	 *  signal in this store (recording/captions/breakouts).
	 */
	async function doReAdmit(identity: string): Promise<void> {
		await store.actions.setRole(identity, 'member');
	}

	// ponytail: the locked HTTP surface has no "participants + current role"
	// read route (only pendingJoinRequests, host/cohost-scoped) — a
	// participant's role badge here is derived purely from the LiveKit
	// identity prefix (g: = guest, else member), not the real host/cohost
	// distinction. Cosmetic only: kick/promote authority is enforced
	// server-side (BZ186) regardless of what this badge shows. Add a real
	// roster-with-roles read route if the UI ever needs to render it accurately.
	let sheetParticipants = $derived<SheetParticipant[]>(
		store.room
			? store.room.participants.map((p) => ({
					identity: p.identity,
					displayName: p.name || p.identity,
					role: p.identity.startsWith('g:') ? ('guest' as const) : ('member' as const),
					external: !p.identity.startsWith('g:') && isExternalParticipant(p),
				}))
			: [],
	);
	let hasGuestParticipant = $derived(store.room?.participants.some((p) => p.identity.startsWith('g:')) ?? false);
	// B1 live-gate ledger fix 2: bannedMembers as a plain array for ControlsBar's props.
	let bannedList = $derived(Object.entries(store.bannedMembers).map(([identity, displayName]) => ({ identity, displayName })));

	// ── MEET plan M3: template-only presentation projections ────────────
	// Presenter display naming: the M2 wire identifies the presenter by
	// meeting_attendee participant id, which the LiveKit roster (identity +
	// name) cannot map — so NO display name is fabricated here. The stage
	// shows "You are presenting" from the server-derived amPresenter truth,
	// and falls back to the checkpoint's own presenterParticipantId for the
	// attendee presenter line. The handoff target list stays empty (its
	// explanatory empty state) until a participant-id-bearing roster
	// projection lands; takeover — the self-target, server-fenced rescue —
	// works without any mapping.
	/** The document stage is visible only on the MAIN room, only while a
	 *  session is actually live, and never while the whiteboard owns the
	 *  main stage (mutually exclusive main-stage modes). */
	let presentationVisible = $derived(
		store.presentation.isLive && store.currentBreakoutId === null && !store.whiteboardOpen,
	);
	/** MeetChatPanel's own bullet: "capability-gated on apps.chat — with
	 *  feature.chat OFF the panel is hidden and the meeting is otherwise
	 *  fully functional" (the reducers still bind/post regardless). */
	let chatEnabled = $derived($effectiveCaps.enabledApps.includes('chat'));

	// The WS subscription itself stays here (component/$effect-lifecycle
	// territory — see store.svelte.ts's header on why); subscribeEvent (arch
	// review #A2) unwraps the envelope once at the hub, so `evt` is already
	// the inner event. All reconciliation logic lives in store.applyEvent.
	$effect(() => {
		const handler = (evt: { event?: string; meetingId?: number; payload?: Record<string, unknown> | null }) => store.applyEvent(evt);
		const guestSession = $user?.accountType === 'guest' || $isGuestSession;
		return guestSession
			? subscribeGuestMeetEvents(handler, () => void store.reconcileCurrentMeeting())
			: subscribeEvent('MeetEvent', handler);
	});
	onDestroy(() => store.room?.disconnect());

	// B3 Task 7: an unexpected Disconnected while assigned to a breakout (the
	// client crashed mid-move, or simply missed the breakout_assigned push
	// entirely) — the same auto-return choreography. Guarded by
	// `moveInterstitial === null` so THIS component's own deliberate
	// moveTo/rejoinMain calls (which transiently flip the underlying
	// connectionState through 'disconnected' on the OLD room during their
	// internal teardown+reconnect) never re-trigger themselves — the
	// interstitial is set BEFORE either call's first await and cleared only
	// AFTER the room swap fully lands, so it is non-null for the entire
	// window such a transient blip could occur.
	//
	// B1 live-gate ledger fix 1: PARTICIPANT_REMOVED is LiveKit's own
	// eviction signal (RoomService.RemoveParticipant, meeting_kick's Go
	// caller) — the tier the server-side `participant_kicked` push NEVER
	// reaches for the kicked identity itself (notify_meet_state's fan-out
	// excludes it, see store.applyEvent). Checked FIRST, ahead of the
	// breakout auto-return branch below: a kick landing mid-breakout must
	// show the removed view, never a doomed rejoinMain() (banned_at rejects
	// `join` with BZ186 — that path already exists and would otherwise dump
	// the caller on the generic error screen, not the "you were removed"
	// copy this fixes). `teardownLiveRoom()` nulls `room`, which is this
	// effect's own dependency — the branch cannot re-fire on its own rerun
	// (idempotent, no BZ190-rejoin-loop-class repeat, fc7672f8).
	$effect(() => {
		const r = store.room;
		if (!r || !store.meeting || store.view !== 'in-room') return;
		if (r.connectionState !== 'disconnected') return;
		if (r.disconnectReason === String(DisconnectReason.PARTICIPANT_REMOVED)) {
			store.teardownLiveRoom();
			store.view = 'kicked';
			return;
		}
		if (store.currentBreakoutId !== null && store.moveInterstitial === null) {
			void store.actions.rejoinMain();
		}
	});

	$effect(() => {
		const slug = page.url.searchParams.get('slug');
		// untrack: openBySlug's SYNCHRONOUS prefix (teardownLiveRoom) reads
		// store fields — without untrack those become dependencies of THIS
		// effect, so the moment connectRoom set `store.room` the effect
		// re-ran, tore the just-connected room down mid-render (a null
		// `room.room` crash under the in-room template) and bounced the
		// caller back to PreJoin — every ?slug= deep-link join was broken
		// (found live by the B1 webmail-UI gate; the landing-page path never
		// tracked extra deps because loadMeetings reads nothing before its
		// first await). Deps stay page.url only — the design-#14 contract
		// (re-open on every slug CHANGE, the knock-toast Open action) is
		// unchanged.
		untrack(() => {
			if (slug) void store.openBySlug(slug);
			else void store.loadMeetings();
		});
	});

	function endedLabel(m: Meeting): boolean {
		return m.state === 'ended';
	}
</script>

{#if store.view === 'landing' || store.view === 'loading'}
	<div class="meet-app__landing">
		<header class="meet-app__landing-head">
			{#if !$isGuestSession || $effectiveCaps.allowMeetCreate}
				<div class="meet-app__create">
					<Input placeholder={t('meet.app.titlePlaceholder')} bind:value={createTitle} />
					<Button variant="primary" onclick={createMeeting}>{t('meet.app.newMeeting')}</Button>
				</div>
			{/if}
			<div class="meet-app__join">
				<Input placeholder={t('meet.app.joinByLinkPlaceholder')} bind:value={joinLinkInput} />
				<Button variant="secondary" onclick={joinByLink}>{t('meet.app.joinByLink')}</Button>
			</div>
		</header>

		{#if store.view === 'loading'}
			<div class="meet-app__loading"><Spinner /></div>
		{:else if store.meetings.length === 0}
			<EmptyState
				title={t(
					$isGuestSession && !$effectiveCaps.allowMeetCreate
						? 'meet.app.emptyJoinOnly'
						: 'meet.app.empty'
				)}
			/>
		{:else}
			<section>
				<h3>{t('meet.app.upcoming')}</h3>
				<ul class="meet-app__list" role="list">
					{#each store.meetings.filter((m) => m.state !== 'ended') as m (m.meetingId)}
						<li class="meet-app__row">
							<span>{m.title}</span>
							<Button variant="primary" size="sm" onclick={() => store.openMeeting(m.meetingId)}>{t('meet.app.join')}</Button>
						</li>
					{/each}
				</ul>
				<h3>{t('meet.app.recent')}</h3>
				<ul class="meet-app__list" role="list">
					{#each store.meetings.filter(endedLabel) as m (m.meetingId)}
						<li>
							<!-- D-2: Recent rows open the ended view (getMeeting is
							     post-end capable via meeting_attendee_role). -->
							<button type="button" class="meet-app__row meet-app__row--link" onclick={() => void store.openEndedMeeting(m.meetingId)}>
								<span>{m.title}</span>
								<Badge variant="neutral" label={t('meet.app.ended')} />
							</button>
						</li>
					{/each}
				</ul>
			</section>
		{/if}
	</div>
{:else if store.view === 'prejoin' && store.meeting}
	<RecordingConsentGate
		recordingActive={store.meeting.recordingActive && !store.recordingConsented}
		onConsent={() => (store.recordingConsented = true)}
		onDecline={() => store.declinePreJoin()}
	>
		{#snippet children()}
			<PreJoin onJoin={(choice) => store.handlePreJoin(choice, $isGuestSession)} />
		{/snippet}
	</RecordingConsentGate>
{:else if store.view === 'knocking' && store.meeting && store.knockCreds}
	{#if store.pendingAdmittedToken}
		<!-- B2 retro F1: a recording started WHILE this caller waited in the
		     lobby — gate on the SAME consent interstitial before connecting
		     (mirrors the guest join page's own pendingAdmittedToken belt). -->
		<RecordingConsentGate recordingActive={true} onConsent={() => store.confirmPendingAdmission()} onDecline={() => store.declinePendingAdmission()}>
			{#snippet children()}{/snippet}
		</RecordingConsentGate>
	{:else}
		<LobbyWaiting
			slug={store.meeting.slug}
			requestId={store.knockCreds.requestId}
			secret={store.knockCreds.secret}
			onAdmitted={(token, rec, captionsOnAtAdmit, ccIdentity) => store.handleKnockAdmitted(token, rec, captionsOnAtAdmit, ccIdentity)}
		/>
	{/if}
{:else if store.view === 'ended'}
	<div class="meet-app__ended">
		<EmptyState title={t('meet.app.meetingEnded')}>
			{#snippet action()}
				<Button variant="secondary" onclick={() => store.teardownRoom()}>{t('common.close')}</Button>
			{/snippet}
		</EmptyState>
		{#if store.meeting && store.meeting.recordings.length > 0}
			<RecordingsList recordings={store.meeting.recordings} />
		{/if}
		{#if store.meeting && store.meeting.attendance.length > 0}
			<AttendancePanel attendance={store.meeting.attendance} />
		{/if}
	</div>
{:else if store.view === 'kicked'}
	<!-- B1 live-gate ledger fix 1: ban-until-re-admit (BZ186/BZ190 registry) —
	     the copy says so explicitly, and there is deliberately no rejoin
	     control here; a host re-admitting (ControlsBar's new roster affordance,
	     fix 2) is the only way back in, and the caller would just get BZ186
	     again regardless. -->
	<div class="meet-app__ended">
		<EmptyState title={t('meet.app.removedTitle')}>
			{#snippet action()}
				<Button variant="secondary" onclick={() => store.teardownRoom()}>{t('common.close')}</Button>
			{/snippet}
		</EmptyState>
		<p class="meet-app__removed-detail">{t('meet.app.removedBody')}</p>
	</div>
{:else if store.view === 'error'}
	<EmptyState title={store.errorMessage}>
		{#snippet action()}
			<Button variant="secondary" onclick={() => store.teardownRoom()}>{t('common.close')}</Button>
		{/snippet}
	</EmptyState>
{:else if store.view === 'in-room' && store.room && store.meeting}
	<!-- B2 retro F4: a flex COLUMN wrapper — the banner is flex:none and
	     .meet-app__room is flex:1;min-height:0, so an active banner can never
	     push ControlsBar below the fold (a fixed height:100% on
	     .meet-app__room previously let the banner's own height overflow the
	     container instead of sharing it). D-7 still holds: the banner spans
	     the FULL WIDTH, directly above .meet-app__room, never inside
	     .meet-app__room-main. -->
	<div class="meet-app__inroom">
		<div class="meet-app__banner">
			{#if store.currentBreakoutId !== null}
				<!-- B3 Task 7 (§9): breakouts are never recorded (DN4) — this line
				     replaces the recording banner while in a child room, never both. -->
				<div class="meet-app__breakout-banner" role="status">{t('meet.breakouts.notRecorded')}</div>
			{:else}
				<RecordingBanner active={store.recordingActive} stopping={store.recordingStopping} />
			{/if}
		</div>
		<div class="meet-app__room">
			<div class="meet-app__room-main" bind:this={roomMainEl} tabindex="-1">
				<!-- B3 Task 9 (design D6): the whiteboard is a MAIN-STAGE surface,
				     not a side panel (a 320px canvas is useless) — while open it
				     takes the stage and the video grid collapses to a filmstrip
				     strip below it (CSS-only collapse; MeetingRoom itself is
				     unchanged/still mounted, never remounted, so no track/tile
				     state is lost switching the whiteboard on and off).
				     ponytail: the collapsed strip reuses MeetingRoom's own gallery
				     grid at a fixed height rather than a dedicated horizontal
				     filmstrip layout — a real filmstrip prop is a MeetingRoom.svelte
				     change, outside this task's file list; upgrade if the squeeze
				     ever reads as broken rather than just small. -->
				{#if store.whiteboardOpen}
					<div class="meet-app__whiteboard-stage">
						<WhiteboardPanel
							room={store.room}
							theme={currentTheme()}
							chatChannelId={chatEnabled ? (store.meeting.chatChannelId ?? null) : null}
							onClose={() => (store.whiteboardOpen = false)}
						/>
					</div>
				{:else if presentationVisible}
					<!-- MEET plan M3: the document-presentation main stage (mutually
					     exclusive with the whiteboard above — one main stage at a
					     time; the video region collapses to a strip beneath it, the
					     whiteboard genre, so captions keep flowing and no track/tile
					     state is lost on the stage switch). -->
					<div class="meet-app__presentation-stage">
						<PresentationStage presentation={store.presentation} onFallback={presentationFallback} />
					</div>
				{/if}
				<div class="meet-app__video-region" class:meet-app__video-region--collapsed={store.whiteboardOpen || presentationVisible}>
					<MeetingRoom
						localParticipant={store.room.room.localParticipant}
						remoteParticipants={store.room.participants}
						connectionQuality={store.room.connectionQuality}
						raisedHands={store.room.raisedHands}
						view={galleryView}
						dominantSpeakerId={store.room.dominantSpeakerId}
						captionsOn={store.currentBreakoutId === null ? store.captionsOn : false}
						captionSegments={store.currentBreakoutId === null ? store.room.captionSegments : []}
						captionsFinalsLog={store.currentBreakoutId === null ? store.room.finalsLog : []}
						captionsHideTranscript={store.whiteboardOpen || presentationVisible}
						captionsLastAttestedAt={store.currentBreakoutId === null ? store.room.lastAttestedCcAt : 0}
					/>
				</div>
				<ControlsBar
					room={store.room}
					selfRole={store.meeting.myRole ?? 'member'}
					locked={store.meeting.locked}
					view={galleryView}
					participants={sheetParticipants}
					banned={bannedList}
					onViewChange={(v) => (galleryView = v)}
					onLock={doLock}
					onKick={doKick}
					onSetRole={doSetRole}
					onReAdmit={doReAdmit}
					onLeave={() => store.leave()}
					onEndForAll={doEnd}
					onOpenChat={
						chatEnabled && store.meeting.chatChannelId && store.meeting.chatChannelMember
							? () => (store.sidePanel = store.sidePanel === 'chat' ? null : 'chat')
							: undefined
					}
					onOpenPoll={chatEnabled && store.meeting.chatChannelId && store.meeting.chatChannelMember ? openPoll : undefined}
					onOpenBreakouts={() => (store.sidePanel = store.sidePanel === 'breakouts' ? null : 'breakouts')}
					onOpenLobby={() => (store.sidePanel = store.sidePanel === 'lobby' ? null : 'lobby')}
					pendingLobbyCount={store.meeting.pendingJoinRequests.length}
					onToggleWhiteboard={toggleWhiteboard}
					whiteboardOpen={store.whiteboardOpen}
					breakoutsEnabled={store.meeting.breakoutsEnabled}
					recordingEnabled={store.meeting.recordingEnabled}
					recordingState={store.controlsRecordingState}
					onStartRecording={doStartRecording}
					onStopRecording={doStopRecording}
					captionsEnabled={store.meeting.captionsEnabled}
					captionsConfigured={store.captionsConfigured}
					captionsOn={store.captionsOn}
					onStartCaptions={doStartCaptions}
					onStopCaptions={doStopCaptions}
					onPresentDocument={
						store.presentation.enabled &&
						store.currentBreakoutId === null &&
						!store.presentation.isLive &&
						!store.presentation.isPreviewing
							? () => (store.presentation.pickerOpen = true)
							: undefined
					}
				/>
			</div>
			{#if store.sidePanel === 'lobby' && (store.meeting.myRole === 'host' || store.meeting.myRole === 'cohost')}
				<div class="meet-app__side">
					<LobbyPanel
						meetingId={store.meeting.meetingId}
						pendingRequests={store.meeting.pendingJoinRequests}
						guestAllowed={store.meeting.guestAllowed}
						onClose={() => (store.sidePanel = null)}
					/>
				</div>
			{/if}
			<!-- D6: BreakoutsPanel and MeetChatPanel share the ONE exclusive side
			     slot — `sidePanel` guarantees at most one of the two renders. -->
			{#if store.sidePanel === 'chat' && chatEnabled && store.meeting.chatChannelId && store.meeting.chatChannelMember}
				<div class="meet-app__side">
					<MeetChatPanel bind:this={chatPanelRef} channelId={store.meeting.chatChannelId} {hasGuestParticipant} onClose={() => (store.sidePanel = null)} />
				</div>
			{/if}
			{#if store.sidePanel === 'breakouts' && (store.meeting.myRole === 'host' || store.meeting.myRole === 'cohost')}
				<div class="meet-app__side">
					<BreakoutsPanel
						meetingId={store.meeting.meetingId}
						breakouts={store.meeting.breakouts}
						assignments={store.breakoutAssignments}
						participants={sheetParticipants}
						selfIdentity={store.room.room.localParticipant.identity}
						selfCurrentBreakoutId={store.currentBreakoutId}
						onJoinRoom={(id) => void store.actions.moveToBreakout(id)}
						onReturnToMain={() => void store.actions.rejoinMain()}
					/>
				</div>
			{/if}
		</div>
		{#if store.presentation.pickerOpen}
			<!-- MEET plan M3: the Drive picker dialog (prepare → private preview →
			     Present). Closing cancels pending preparation and READY preview,
			     including acceptance arriving after the dialog has closed. -->
			<PresentationPicker presentation={store.presentation} onClose={() => (store.presentation.pickerOpen = false)} />
		{/if}
	</div>
	{#if store.moveInterstitial}
		<!-- design D6: a full-stage layer over EVERYTHING (video grid, side
		     panels, ControlsBar) — the caller has no working media during the
		     ~1-2s move gap, so nothing underneath is interactive anyway.
		     The B2 D-5 a11y lesson: focus moves here the moment it mounts
		     (the $effect above); role=status/aria-live=polite is this
		     component's own live region until Task 15 lands the always-mounted
		     one it will fold into. -->
		<div class="meet-app__move-interstitial" role="status" aria-live="polite">
			<div bind:this={interstitialEl} tabindex="-1" class="meet-app__move-interstitial-body">
				<Spinner />
				<p>
					{store.moveInterstitial.kind === 'moving'
						? store.moveInterstitial.roomLabel !== null
							? t('meet.breakouts.moving', { room: store.moveInterstitial.roomLabel })
							: t('meet.breakouts.movingGeneric')
						: t('meet.breakouts.returning')}
				</p>
			</div>
		</div>
	{/if}
{/if}

<style>
	.meet-app__landing {
		max-width: 720px;
		margin: 0 auto;
		padding: var(--space-4);
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
	}
	.meet-app__landing-head {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.meet-app__create,
	.meet-app__join {
		display: flex;
		gap: var(--space-2);
	}
	.meet-app__loading {
		display: flex;
		justify-content: center;
		padding: var(--space-4);
	}
	.meet-app__list {
		list-style: none;
		margin: 0;
		padding: 0;
	}
	.meet-app__row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: var(--space-2) 0;
		border-bottom: 1px solid var(--border-subtle);
	}
	.meet-app__row--link {
		width: 100%;
		background: none;
		border: none;
		border-radius: 0;
		font: inherit;
		color: inherit;
		text-align: left;
		cursor: pointer;
	}
	.meet-app__ended {
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
		max-width: 720px;
		margin: 0 auto;
		padding: var(--space-4);
	}
	.meet-app__removed-detail {
		margin: 0;
		text-align: center;
		color: var(--text-secondary);
		font-size: var(--text-sm);
	}
	.meet-app__inroom {
		display: flex;
		flex-direction: column;
		height: 100%;
	}
	.meet-app__banner {
		flex: none;
	}
	.meet-app__room {
		display: flex;
		flex: 1;
		min-height: 0;
	}
	.meet-app__room-main {
		flex: 1;
		display: flex;
		flex-direction: column;
		min-width: 0;
		min-height: 0;
	}
	/* B3 retro fix (design finding #11): a programmatic focus-restore target
	   only (never a real interactive control) — same outline:none posture as
	   .meet-app__move-interstitial-body below. */
	.meet-app__room-main:focus {
		outline: none;
	}
	.meet-app__side {
		width: 320px;
		flex: none;
		border-left: 1px solid var(--border-subtle);
		background: var(--surface-card);
	}
	/* UX #9: reuse MeetChatPanel's own mobile-overlay breakpoint/z-index
	   verbatim (.meet-chat's identical rule) — below 768px, whichever panel
	   is open (chat/breakouts/lobby) covers the full viewport instead of
	   docking at a fixed 320px beside the video, which used to crush the
	   room-main column to a sliver on phone-width viewports. */
	@media (max-width: 767px) {
		.meet-app__side {
			position: fixed;
			inset: 0;
			z-index: 30;
			width: auto;
			border-left: none;
		}
	}
	/* B3 Task 9: main-stage whiteboard (design D6) — takes the room-main
	   area; the video region collapses to a fixed-height strip beneath it.
	   MEET plan M3: the document-presentation stage shares the exact same
	   main-stage slot (identical layout contract, its own class so the
	   existing whiteboard structural pins stay untouched), one main stage at
	   a time. */
	.meet-app__whiteboard-stage,
	.meet-app__presentation-stage {
		flex: 1;
		min-height: 0;
		display: flex;
	}
	.meet-app__video-region {
		flex: 1;
		min-height: 0;
		display: flex;
	}
	.meet-app__video-region--collapsed {
		flex: none;
		height: 96px;
	}
	.meet-app__breakout-banner {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: var(--space-2);
		padding: var(--space-1) var(--space-3);
		font-size: var(--text-sm);
		color: var(--text-secondary);
		background: var(--surface-sunken);
	}
	.meet-app__move-interstitial {
		position: fixed;
		inset: 0;
		z-index: 50;
		display: flex;
		align-items: center;
		justify-content: center;
		background: var(--surface-base);
	}
	.meet-app__move-interstitial-body {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: var(--space-3);
		outline: none;
		font-size: var(--text-md);
		color: var(--text-primary);
	}
</style>
