<svelte:options runes={true} />

<script lang="ts">
	// ControlsBar — Meet B1 Task 16. Mute/cam/screenshare/raise-hand/reactions/
	// leave + Gallery/Speaker toggle + host-only lock + participants sheet
	// (kick/role) + end-for-all. Design #18: end-for-all is destructive and
	// irreversible for every OTHER participant, so it sits behind a confirm
	// Dialog; Leave affects only the caller and never confirms.
	// Design #12: keyboard shortcuts `m` (mute) and Ctrl/Cmd+E (camera) —
	// ignored while focus is inside a text input/textarea so typing an "m" in
	// chat doesn't mute the call.
	import type { MeetRoom } from '$lib/meet/room.svelte';
	import type { MeetingRole } from '$lib/meet/api';
	import { saveBlurPref } from '$lib/meet/blur';
	import { Button, IconButton, Dialog, Badge, EmptyState } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';

	export interface SheetParticipant {
		identity: string;
		displayName: string;
		role: MeetingRole;
		external?: boolean;
	}

	let {
		room,
		selfRole,
		locked,
		view,
		participants,
		banned = [],
		onViewChange,
		onLock,
		onKick,
		onSetRole,
		onReAdmit,
		onLeave,
		onEndForAll,
		onOpenChat,
		onOpenPoll,
		onOpenBreakouts,
		onOpenLobby,
		pendingLobbyCount = 0,
		onToggleWhiteboard,
		whiteboardOpen,
		breakoutsEnabled,
		recordingEnabled,
		recordingState,
		onStartRecording,
		onStopRecording,
		captionsEnabled = false,
		captionsConfigured = false,
		captionsOn = false,
		onStartCaptions,
		onStopCaptions,
		onPresentDocument,
	}: {
		room: MeetRoom;
		selfRole: MeetingRole;
		locked: boolean;
		view: 'gallery' | 'speaker';
		participants: SheetParticipant[];
		/** B1 live-gate ledger fix 2 / A/B leftover item 1: the re-admit
		 *  affordance — banned members (identity + displayName), durable
		 *  across a reload (MeetApp seeds this from meeting_get's `banned[]`
		 *  projection on every fresh load, then keeps it current via push).
		 *  Rendered as a second list inside the SAME participants Dialog,
		 *  host/cohost-only like kick/makeCohost. */
		banned?: { identity: string; displayName: string }[];
		onViewChange: (view: 'gallery' | 'speaker') => void;
		onLock: (locked: boolean) => void;
		onKick: (identity: string) => void;
		onSetRole: (identity: string, role: 'cohost' | 'member') => void;
		/** meeting_set_role IS the re-admit path (assigning a role to a banned
		 *  identity clears banned_at server-side) — confirm-free, unlike kick:
		 *  re-admit is reversible (a re-kick is one click away), the
		 *  makeCohost precedent, not the destructive end-for-all/kick one. */
		onReAdmit?: (identity: string) => void;
		onLeave: () => void;
		onEndForAll: () => void;
		onOpenChat?: () => void;
		/** B3 Task 8: opens the chat side panel WITH the existing chat Composer's
		 *  poll dialog open (spec §4.2 — polls already work in-meeting via the
		 *  bridged chat_channels row; this is only the entry point). Same
		 *  visibility rule as onOpenChat — undefined whenever the chat panel
		 *  isn't mountable — never host-gated (poll creation carries no role
		 *  check, A3 Task 15). */
		onOpenPoll?: () => void;
		onOpenBreakouts?: () => void;
		/** UX #9: toggles LobbyPanel — the pending-join-request queue — into
		 *  the SAME exclusive `.meet-app__side` slot breakouts/chat use
		 *  (`onOpenBreakouts`'s genre). Always defined for a host/cohost
		 *  caller (unlike breakouts/recording/captions there is no feature
		 *  toggle gating it — the panel is reachable whenever the caller can
		 *  admit knocks at all), rendered inside the SAME `isHostOrCohost`
		 *  block below. */
		onOpenLobby?: () => void;
		/** Pending join-request count for the Lobby button's badge — 0 hides
		 *  the badge, matching the AppRail unread-badge convention. */
		pendingLobbyCount?: number;
		/** B3 Task 9 (design D2/DN6): flips MeetApp's main-stage whiteboard
		 *  state. No server toggle exists to gate it (client-only feature,
		 *  spec §4.4) and it is never role-gated (any participant may open
		 *  it, the poll-button precedent — collaborative by nature) — the
		 *  ONLY reason this is optional, same idiom as onOpenChat/onOpenPoll,
		 *  is spec §11's guest exclusion (whiteboard defers to the
		 *  guest-accounts program): the guest join page passes nothing and
		 *  the button simply never renders there. Every authed-member caller
		 *  (MeetApp.svelte) always passes a real callback. */
		onToggleWhiteboard?: () => void;
		whiteboardOpen: boolean;
		/** B3 Task 7: the BreakoutsPanel button-visibility signal —
		 *  meeting_get's breakoutsEnabled (feature.meet_breakouts). Nested
		 *  inside the host/cohost block below, the recordingEnabled genre. */
		breakoutsEnabled: boolean;
		/** Button-visibility signal — meeting_get's recordingEnabled (BOTH
		 *  feature.meet_recording and feature.drive ON). */
		recordingEnabled: boolean;
		/** 'requested' collapses into 'starting' (the server row already
		 *  exists and the banner is already on, but `meeting_recording_stop`
		 *  only accepts `state = 'active'` — stop is not yet issuable, so
		 *  'starting' stays disabled rather than rendering a Stop button
		 *  that would 409). */
		recordingState: 'idle' | 'starting' | 'recording' | 'stopping';
		onStartRecording: () => Promise<void>;
		onStopRecording: () => void;
		/** B3 Task 15: button-visibility signal — meeting_get's
		 *  captionsEnabled (feature.meet_captions), the recordingEnabled
		 *  genre. Nested inside the SAME host/cohost block, ANDed with
		 *  captionsConfigured below. */
		captionsEnabled?: boolean;
		/** The join envelope's captionsConfigured (Task 14 delta 4) — whether
		 *  the ASR sidecar pair is actually deployed/reachable, distinct from
		 *  the feature.meet_captions toggle above. Both must be true for the
		 *  button to render. */
		captionsConfigured?: boolean;
		/** The chip/toggle's current server-state truth (never local
		 *  optimism) — decides Start vs Stop wording/icon. */
		captionsOn?: boolean;
		onStartCaptions: () => Promise<void>;
		onStopCaptions: () => void;
		/** MEET plan M3: opens the document-presentation Drive picker ("Share
		 *  ▾ → Present a document", the plan's information hierarchy — this
		 *  button is the entry; screen share and whiteboard keep their own
		 *  buttons). Hidden when undefined: the meeting_get
		 *  presentationEnabled gate (feature.meet_document_presentation,
		 *  default OFF) and any live-session/breakout suppression — the
		 *  onOpenChat hide-when-undefined idiom. V1 file selection requires a
		 *  larger viewport, so the button is hidden at phone widths by CSS
		 *  while the stage itself stays fully usable (takeover/pages/pointer). */
		onPresentDocument?: () => void;
	} = $props();

	let isHostOrCohost = $derived(selfRole === 'host' || selfRole === 'cohost');
	let isHost = $derived(selfRole === 'host');

	let showParticipants = $state(false);
	let showReactions = $state(false);
	let showEndConfirm = $state(false);
	let showRecordConfirm = $state(false);
	/** UX #13: kick used to fire instantly on click — no confirmation, no
	 *  explanation that this is a ban-until-re-admit (BZ186), not a soft
	 *  "leave". Non-null while the confirm Dialog is open for that target;
	 *  the actual failure toast is MeetApp's existing doKick idiom (the
	 *  retro-wave showToast(errText(e)) pattern) — ControlsBar only gates
	 *  the call behind confirmation, the end-for-all precedent. */
	let showKickConfirm = $state<{ identity: string; displayName: string } | null>(null);
	let startBusy = $state(false);
	/** B3 Task 15: in-flight disable on the START leg only — Stop is
	 *  idempotent server-side (D8) and MeetApp's own doStopCaptions guards
	 *  the double-DELETE race, the recording stopBusy precedent; no visible
	 *  disabled state needed here for stop. */
	let captionsStartBusy = $state(false);

	const REACTION_EMOJI = ['👍', '❤️', '😂', '🎉', '👏', '🙌'] as const;

	function sendReaction(emoji: string): void {
		showReactions = false;
		room.sendReaction(emoji);
	}

	function isTypingTarget(el: EventTarget | null): boolean {
		if (!(el instanceof HTMLElement)) return false;
		const tag = el.tagName;
		return tag === 'INPUT' || tag === 'TEXTAREA' || el.isContentEditable;
	}

	function handleKeydown(e: KeyboardEvent): void {
		if (isTypingTarget(e.target)) return;
		if (e.key === 'm' || e.key === 'M') {
			e.preventDefault();
			void room.toggleMic();
		} else if ((e.metaKey || e.ctrlKey) && (e.key === 'e' || e.key === 'E')) {
			e.preventDefault();
			void room.toggleCamera();
		}
	}

	function confirmEnd(): void {
		showEndConfirm = false;
		onEndForAll();
	}

	function confirmKick(): void {
		if (!showKickConfirm) return;
		onKick(showKickConfirm.identity);
		showKickConfirm = null;
	}

	/** D-4: the confirm Dialog's confirm Button is disabled for the whole
	 *  awaited call — neither a double-click nor a second concurrent start
	 *  POST is possible from this control. */
	async function confirmStartRecording(): Promise<void> {
		startBusy = true;
		try {
			await onStartRecording();
			showRecordConfirm = false;
		} finally {
			startBusy = false;
		}
	}

	/** B3 Task 15: click toggles start/stop by the CURRENT server-state
	 *  captionsOn (never a local optimistic flip — the button re-renders once
	 *  the reducer's own captions_state push lands, MeetApp's job). */
	async function toggleCaptions(): Promise<void> {
		if (captionsOn) {
			onStopCaptions();
			return;
		}
		captionsStartBusy = true;
		try {
			await onStartCaptions();
		} finally {
			captionsStartBusy = false;
		}
	}

	/** Task 16b: mid-meeting blur toggle. room.toggleBlur only flips
	 *  room.blurEnabled on a SUCCESSFUL attach/detach, so the preference is
	 *  persisted from the post-toggle state, never the intended one. */
	async function toggleBlur(): Promise<void> {
		await room.toggleBlur(!room.blurEnabled);
		saveBlurPref(room.blurEnabled);
	}
</script>

<svelte:window onkeydown={handleKeydown} />

<!-- UX #12(b): the toolbar's own aria-label used to be meet.controls.participants
     ("Participants") — a screen reader announced the WHOLE mute/camera/etc.
     bar as "Participants", not just the participants-sheet trigger button
     below (which keeps that label, scoped correctly to itself). -->
<div class="controls-bar" role="toolbar" aria-label={t('meet.controls.toolbarLabel')}>
	<div class="controls-bar__group">
		<IconButton
			label={room.localMuted ? t('meet.controls.micOff') : t('meet.controls.micOn')}
			title={t('meet.controls.shortcutMute')}
			active={!room.localMuted}
			aria-pressed={!room.localMuted}
			onclick={() => room.toggleMic()}
		>
			<Icon name={room.localMuted ? 'MicOff' : 'Mic'} size={18} />
		</IconButton>
		<IconButton
			label={room.localCameraOff ? t('meet.controls.camOff') : t('meet.controls.camOn')}
			title={t('meet.controls.shortcutCamera')}
			active={!room.localCameraOff}
			aria-pressed={!room.localCameraOff}
			onclick={() => room.toggleCamera()}
		>
			<Icon name={room.localCameraOff ? 'VideoOff' : 'Video'} size={18} />
		</IconButton>
		<IconButton
			label={room.screenSharing ? t('meet.controls.screenShareOn') : t('meet.controls.screenShareOff')}
			active={room.screenSharing}
			aria-pressed={room.screenSharing}
			onclick={() => room.toggleScreenShare()}
		>
			<Icon name={room.screenSharing ? 'ScreenShareOff' : 'ScreenShare'} size={18} />
		</IconButton>
		{#if onPresentDocument}
			<!-- MEET plan M3: "Present a document" (the plan's information
			     hierarchy puts it above screen share; this bar keeps every
			     existing control in place and ADDS the entry). -->
			<IconButton
				label={t('meet.presentation.presentDocument')}
				onclick={onPresentDocument}
				data-testid="present-document"
				class="controls-bar__present"
			>
				<Icon name="FileText" size={18} />
			</IconButton>
		{/if}
		<IconButton
			label={room.raisedHandSelf ? t('meet.controls.lowerHand') : t('meet.controls.raiseHand')}
			active={room.raisedHandSelf}
			aria-pressed={room.raisedHandSelf}
			onclick={() => room.toggleRaiseHand()}
		>
			<Icon name="Hand" size={18} />
		</IconButton>
		{#if room.blurSupported}
			<IconButton
				label={room.blurEnabled ? t('meet.controls.blurOff') : t('meet.controls.blurOn')}
				active={room.blurEnabled}
				aria-pressed={room.blurEnabled}
				onclick={toggleBlur}
			>
				<Icon name="Sparkles" size={18} />
			</IconButton>
		{/if}
		<div class="controls-bar__popover-wrap">
			<IconButton
				label={t('meet.controls.reactions')}
				aria-haspopup="menu"
				aria-expanded={showReactions}
				onclick={() => (showReactions = !showReactions)}
			>
				<Icon name="Smile" size={18} />
			</IconButton>
			{#if showReactions}
				<div class="controls-bar__reaction-popover" role="menu">
					{#each REACTION_EMOJI as emoji (emoji)}
						<button type="button" class="controls-bar__emoji-btn" role="menuitem" onclick={() => sendReaction(emoji)}>{emoji}</button>
					{/each}
				</div>
			{/if}
		</div>
	</div>

	<div class="controls-bar__group">
		<div class="controls-bar__segmented">
			<button type="button" class:active={view === 'gallery'} onclick={() => onViewChange('gallery')}>
				<Icon name="LayoutGrid" size={16} />
				{t('meet.controls.gallery')}
			</button>
			<button type="button" class:active={view === 'speaker'} onclick={() => onViewChange('speaker')}>
				<Icon name="Maximize2" size={16} />
				{t('meet.controls.speaker')}
			</button>
		</div>
		{#if onOpenChat}
			<IconButton label={t('app.chat')} onclick={onOpenChat}>
				<Icon name="MessageCircle" size={18} />
			</IconButton>
		{/if}
		{#if onOpenPoll}
			<IconButton label={t('meet.controls.poll')} onclick={onOpenPoll}>
				<Icon name="BarChart3" size={18} />
			</IconButton>
		{/if}
		{#if onToggleWhiteboard}
			<!-- B3 Task 9 (D2/DN6): no server toggle to gate and never
			     role-gated (collaborative by nature, the Poll precedent) — the
			     ONLY reason this is conditional is the guest exclusion above. -->
			<IconButton
				label={t('meet.wb.open')}
				active={whiteboardOpen}
				aria-pressed={whiteboardOpen}
				onclick={onToggleWhiteboard}
			>
				<Icon name="PenTool" size={18} />
			</IconButton>
		{/if}
		<IconButton label={t('meet.controls.participants')} onclick={() => (showParticipants = true)}>
			<Icon name="Users" size={18} />
		</IconButton>
		{#if isHostOrCohost}
			<IconButton
				label={locked ? t('meet.controls.unlock') : t('meet.controls.lock')}
				active={locked}
				onclick={() => onLock(!locked)}
			>
				<Icon name={locked ? 'Lock' : 'Unlock'} size={18} />
			</IconButton>
			{#if breakoutsEnabled}
				<IconButton label={t('meet.breakouts.title')} onclick={onOpenBreakouts}>
					<Icon name="Columns3" size={18} />
				</IconButton>
			{/if}
			{#if onOpenLobby}
				<div class="controls-bar__badge-wrap">
					<IconButton
						label={pendingLobbyCount > 0 ? t('meet.lobby.titleWithCount', { count: String(pendingLobbyCount) }) : t('meet.lobby.title')}
						onclick={onOpenLobby}
					>
						<Icon name="UserCheck" size={18} />
					</IconButton>
					{#if pendingLobbyCount > 0}
						<span class="controls-bar__badge" aria-hidden="true">{pendingLobbyCount > 99 ? '99+' : pendingLobbyCount}</span>
					{/if}
				</div>
			{/if}
			{#if recordingEnabled}
				{#if recordingState === 'recording'}
					<IconButton label={t('meet.recording.stop')} active onclick={onStopRecording}>
						<Icon name="Square" size={18} />
					</IconButton>
				{:else if recordingState === 'stopping'}
					<IconButton label={t('meet.recording.stopping')} disabled>
						<Icon name="Square" size={18} />
					</IconButton>
				{:else if recordingState === 'starting'}
					<IconButton label={t('meet.recording.start')} disabled>
						<Icon name="Video" size={18} />
					</IconButton>
				{:else}
					<IconButton label={t('meet.recording.start')} onclick={() => (showRecordConfirm = true)}>
						<Icon name="Video" size={18} />
					</IconButton>
				{/if}
			{/if}
			{#if captionsEnabled && captionsConfigured}
				<IconButton
					label={captionsOn ? t('meet.captions.off') : t('meet.captions.on')}
					active={captionsOn}
					aria-pressed={captionsOn}
					disabled={captionsStartBusy}
					onclick={() => void toggleCaptions()}
				>
					<Icon name={captionsOn ? 'CaptionsOff' : 'Captions'} size={18} />
				</IconButton>
			{/if}
		{/if}
	</div>

	<div class="controls-bar__group">
		{#if isHost}
			<Button variant="danger" onclick={() => (showEndConfirm = true)} data-testid="end-for-all">
				<Icon name="PhoneOff" size={16} />
				{t('meet.controls.endForAll')}
			</Button>
		{:else}
			<Button variant="secondary" onclick={onLeave} data-testid="leave">
				<Icon name="PhoneOff" size={16} />
				{t('meet.controls.leave')}
			</Button>
		{/if}
	</div>
</div>

<Dialog open={showParticipants} title={t('meet.controls.participants')} onClose={() => (showParticipants = false)} wide>
	{#snippet children()}
		{#if participants.length === 0}
			<EmptyState title={t('meet.lobby.empty')} />
		{:else}
			<ul class="controls-bar__roster" role="list">
				{#each participants as p (p.identity)}
					<li class="controls-bar__roster-row">
						<span class="controls-bar__roster-name">{p.displayName}</span>
						<!-- UX #12(a)/(c): p.role used to render RAW (untranslated) and,
						     for a guest, a SECOND translated "Guest" badge was rendered
						     alongside it — one translated badge now, matching how
						     AttendancePanel already renders meet.role.*. -->
						<Badge variant={p.role === 'guest' ? 'info' : 'neutral'} label={t(`meet.role.${p.role}`)} />
						{#if p.external && p.role !== 'guest'}
							<Badge variant="info" label={t('meet.tile.external')} />
						{/if}
						{#if isHostOrCohost && p.role !== 'host'}
							<div class="controls-bar__roster-actions">
								{#if p.role === 'member' && !p.identity.startsWith('g:')}
									<Button variant="ghost" size="sm" onclick={() => onSetRole(p.identity, 'cohost')}>
										{t('meet.controls.makeCohost')}
									</Button>
								{/if}
								<Button
									variant="ghost"
									size="sm"
									onclick={() => (showKickConfirm = { identity: p.identity, displayName: p.displayName })}
								>
									{t('meet.controls.kick')}
								</Button>
							</div>
						{/if}
					</li>
				{/each}
			</ul>
		{/if}
		<!-- B1 live-gate ledger fix 2: the re-admit affordance. Host/cohost
		     only, same gate as kick/makeCohost above; confirm-free (unlike
		     kick's Dialog) since re-admit is reversible. -->
		{#if isHostOrCohost && banned.length > 0}
			<h4 class="controls-bar__roster-heading">{t('meet.controls.bannedHeading')}</h4>
			<ul class="controls-bar__roster" role="list">
				{#each banned as b (b.identity)}
					<li class="controls-bar__roster-row">
						<span class="controls-bar__roster-name">{b.displayName}</span>
						<Button variant="ghost" size="sm" onclick={() => onReAdmit?.(b.identity)}>
							{t('meet.controls.reAdmit')}
						</Button>
					</li>
				{/each}
			</ul>
		{/if}
	{/snippet}
	{#snippet footer()}
		<Button variant="secondary" onclick={() => (showParticipants = false)}>{t('common.close')}</Button>
	{/snippet}
</Dialog>

<Dialog open={showEndConfirm} title={t('meet.controls.endConfirmTitle')} onClose={() => (showEndConfirm = false)}>
	{#snippet children()}
		<p>{t('meet.controls.endConfirmBody')}</p>
	{/snippet}
	{#snippet footer()}
		<Button variant="danger" onclick={confirmEnd} data-testid="end-for-all-confirm">{t('meet.controls.endForAll')}</Button>
		<Button variant="secondary" onclick={() => (showEndConfirm = false)}>{t('common.cancel')}</Button>
	{/snippet}
</Dialog>

<Dialog open={showRecordConfirm} title={t('meet.recording.startConfirmTitle')} onClose={() => (showRecordConfirm = false)}>
	{#snippet children()}
		<p>{t('meet.recording.startConfirmBody')}</p>
	{/snippet}
	{#snippet footer()}
		<Button
			variant="primary"
			onclick={() => void confirmStartRecording()}
			disabled={startBusy}
			data-testid="start-recording-confirm"
		>
			{t('meet.recording.start')}
		</Button>
		<Button variant="secondary" onclick={() => (showRecordConfirm = false)} disabled={startBusy}>
			{t('common.cancel')}
		</Button>
	{/snippet}
</Dialog>

<!-- UX #13: kick is a ban-until-re-admit (BZ186), not a soft "leave" — the
     confirm dialog says so, the end-for-all confirm precedent. -->
<Dialog
	open={showKickConfirm !== null}
	title={t('meet.controls.kickConfirmTitle', { name: showKickConfirm?.displayName ?? '' })}
	onClose={() => (showKickConfirm = null)}
>
	{#snippet children()}
		<p>{t('meet.controls.kickConfirmBody')}</p>
	{/snippet}
	{#snippet footer()}
		<Button variant="danger" onclick={confirmKick} data-testid="kick-confirm">{t('meet.controls.kick')}</Button>
		<Button variant="secondary" onclick={() => (showKickConfirm = null)}>{t('common.cancel')}</Button>
	{/snippet}
</Dialog>

<style>
	.controls-bar {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-3);
		padding: var(--space-2) var(--space-3);
		background: var(--surface-raised);
		border-top: 1px solid var(--border-subtle);
		flex-wrap: wrap;
	}
	.controls-bar__group {
		display: flex;
		align-items: center;
		gap: var(--space-1);
	}
	.controls-bar__popover-wrap {
		position: relative;
		display: inline-flex;
	}
	.controls-bar__badge-wrap {
		position: relative;
		display: inline-flex;
	}
	.controls-bar__badge {
		position: absolute;
		top: -2px;
		right: -2px;
		background: var(--accent);
		color: var(--text-inverse);
		font-family: var(--font-mono);
		font-size: 9px;
		font-weight: 700;
		min-width: 14px;
		height: 14px;
		border-radius: var(--radius-full);
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 0 3px;
		line-height: 1;
		pointer-events: none;
	}
	.controls-bar__reaction-popover {
		position: absolute;
		bottom: calc(100% + 4px);
		left: 50%;
		transform: translateX(-50%);
		display: flex;
		gap: 2px;
		padding: 4px;
		background: var(--surface-raised);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		box-shadow: var(--shadow-md);
		z-index: 20;
	}
	.controls-bar__emoji-btn {
		min-height: 40px;
		min-width: 40px;
		border: none;
		background: transparent;
		border-radius: var(--radius-sm);
		font-size: var(--text-lg);
		cursor: pointer;
	}
	.controls-bar__emoji-btn:hover {
		background: var(--surface-hover);
	}
	.controls-bar__segmented {
		display: flex;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		overflow: hidden;
	}
	.controls-bar__segmented button {
		display: flex;
		align-items: center;
		gap: 4px;
		min-height: 32px;
		padding: 0 var(--space-2);
		border: none;
		background: transparent;
		color: var(--text-secondary);
		font-size: var(--text-xs);
		cursor: pointer;
	}
	.controls-bar__segmented button.active {
		background: var(--surface-selected);
		color: var(--accent);
	}
	.controls-bar__roster {
		list-style: none;
		margin: 0;
		padding: 0;
	}
	.controls-bar__roster-row {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-2) 0;
		border-bottom: 1px solid var(--border-subtle);
	}
	.controls-bar__roster-name {
		flex: 1;
		min-width: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.controls-bar__roster-actions {
		display: flex;
		gap: var(--space-1);
	}
	.controls-bar__roster-heading {
		margin: var(--space-3) 0 var(--space-1);
		font-size: var(--text-xs);
		font-weight: 600;
		color: var(--text-secondary);
	}
	/* MEET plan M3 (V1 responsive contract): file selection requires a larger
	   viewport — the PICKER entry is hidden at phone widths, while an active
	   presentation stage itself (pages, takeover, pointer) stays usable. */
	@media (max-width: 767px) {
		:global(.controls-bar__present) {
			display: none;
		}
	}
</style>
