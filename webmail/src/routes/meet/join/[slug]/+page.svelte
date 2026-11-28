<svelte:options runes={true} />

<!--
	/meet/join/[slug] — the PUBLIC guest lobby page (Meet B1 Task 17, spec
	§1.2). Standalone like /book/[slug]: no app shell, no session assumption —
	only /api/public/meet/* (+layout.svelte's auth guard exempts /meet/join/*
	the same way it exempts /book/*). An AUTHENTICATED visitor is redirected
	into the real app instead of shown the guest form at all — /meet?slug=…
	is the ONE canonical in-app deep link (design #14); MeetApp's own
	resolveSlug handles join-or-knock-on-locked from there.

	Flow: display-name form → guestJoinRequest → the SHARED LobbyWaiting
	(Task 16) with PreJoin mounted in its `pending` slot (design #1 — the
	guest does the device/permission dance WHILE waiting, so admit → instant
	connect) → on admit, the SAME MeetingRoom/ControlsBar mount in guest mode
	(no host controls; no chat panel — the documented B1 guest cut, one-line
	notice). expired renders an "Ask again" button (design #17) via
	LobbyWaiting's `expired` slot, re-keyed ({#key requestId}) to restart the
	whole machine clean with a fresh join-request.

	Post-admission (design #7): a LiveKit Disconnected while in-room is
	classified with ONE poll of the ORIGINAL join-request —
	classifyPostDisconnect (guestReconnect.ts) tells a real kick (denied)
	from the meeting ending (expired/404) from a transient blip (anything
	else); this component only renders the outcome.
-->
<script lang="ts">
	import { onDestroy } from 'svelte';
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import { authenticated, authInitializing } from '$lib/stores/auth';
	import * as meetApi from '$lib/meet/api';
	import { MeetError, type MeetToken } from '$lib/meet/api';
	import { MeetRoom } from '$lib/meet/room.svelte';
	import { RoomEvent } from 'livekit-client';
	import { classifyPostDisconnect } from '$lib/meet/guestReconnect';
	import type { MeetCodec } from '$lib/meet/codecProbe';
	import { Card, Button, Input, EmptyState, Spinner } from '$lib/components/ui';
	import { t } from '$lib/i18n';
	import PreJoin from '$lib/components/meet/PreJoin.svelte';
	import LobbyWaiting from '$lib/components/meet/LobbyWaiting.svelte';
	import MeetingRoom from '$lib/components/meet/MeetingRoom.svelte';
	import ControlsBar from '$lib/components/meet/ControlsBar.svelte';
	import RecordingConsentGate from '$lib/components/meet/RecordingConsentGate.svelte';
	import type { SheetParticipant } from '$lib/components/meet/ControlsBar.svelte';

	const slug = $derived(page.params.slug ?? '');

	interface DeviceChoice {
		micOn: boolean;
		camOn: boolean;
		codec: MeetCodec;
		blurEnabled: boolean;
	}
	// design #11's default-muted posture, reused here for the case a guest
	// gets admitted before ever touching the embedded PreJoin.
	const DEFAULT_CHOICE: DeviceChoice = { micOn: false, camOn: false, codec: 'vp8', blurEnabled: false };

	type View = 'form' | 'waiting' | 'in-room' | 'removed' | 'ended' | 'reconnecting';
	let view = $state<View>('form');

	let displayName = $state('');
	let submitting = $state(false);
	let formError = $state('');

	let requestId = $state<number | null>(null);
	let secret = $state('');
	let deviceChoice = $state<DeviceChoice | null>(null);
	let askAgainPending = $state(false);
	let askAgainError = $state('');

	let room = $state<MeetRoom | null>(null);
	let galleryView = $state<'gallery' | 'speaker'>('gallery');
	// B3 Task 15, DN3: the guest chip's ONLY signal — seeded once from the
	// admitted poll's own captionsOn (meeting_lobby.sql) and NEVER updated
	// again (no push rail exists post-admission for a guest, D8) — see
	// CaptionsOverlay.svelte's own comment for the full honest-gap account.
	let guestCaptionsOn = $state(false);
	// B3 retro fix (design findings #4/#5): the admitted grant's own
	// ccIdentity ('cc:' || meetingId) — the fix that dissolves the old
	// attestedCcIdentity='' ceiling below. Seeded once from the SAME
	// admitted poll, unconditional on captionsOn.
	let guestCcIdentity = $state('');

	// An authenticated visitor never sees the guest form at all.
	$effect(() => {
		if (!$authInitializing && $authenticated && slug) {
			void goto(`/meet?slug=${encodeURIComponent(slug)}`, { replaceState: true });
		}
	});

	function errText(e: unknown): string {
		return e instanceof MeetError ? e.detail : t('common.error');
	}

	async function submitJoinRequest(e: Event): Promise<void> {
		e.preventDefault();
		const name = displayName.trim();
		if (submitting || !name) return;
		submitting = true;
		formError = '';
		try {
			const res = await meetApi.guestJoinRequest(slug, name);
			requestId = res.requestId;
			secret = res.secret;
			view = 'waiting';
		} catch (err) {
			formError = errText(err);
		} finally {
			submitting = false;
		}
	}

	function captureChoice(choice: DeviceChoice): void {
		deviceChoice = choice;
	}

	// D5's flicker-window belt: an admitted grant that carries recordingActive
	// gates on RecordingConsentGate BEFORE MeetRoom.connect ever runs — "near-
	// dead once D4's admission-fact predicate lands, kept only for that
	// flicker window" (the reducer's own arm-2 already blocks a recording
	// guest admit; this belt only covers the narrow race where a recording
	// starts between admit and this poll response).
	// med-shard3-021: this is the ONE consent-gate evaluation on this
	// surface — the post-disconnect reconnect arm routes through it too, so
	// first admit and reconnect cannot diverge on recording consent.
	let pendingAdmittedToken = $state<MeetToken | null>(null);

	function handleAdmitted(token: MeetToken, recordingActive: boolean, captionsOnAtAdmit: boolean, ccIdentity: string): void {
		guestCaptionsOn = captionsOnAtAdmit;
		guestCcIdentity = ccIdentity;
		if (recordingActive) {
			pendingAdmittedToken = token;
			view = 'waiting'; // the gate renders in the waiting view; a reconnect lands here too
		} else {
			void connectRoom(token);
		}
	}

	async function connectRoom(token: MeetToken): Promise<void> {
		const choice = deviceChoice ?? DEFAULT_CHOICE;
		// B3 retro fix (design findings #4/#5): the admitted grant's own
		// ccIdentity ('cc:' || meetingId, meeting_lobby.sql) — the old gap
		// (this surface carried no meeting id, so a guest's MeetRoom always
		// failed closed to '') is dissolved; the guest attests real cc frames
		// exactly like a member does.
		const r = new MeetRoom(choice.codec, guestCcIdentity);
		r.localMuted = !choice.micOn;
		r.localCameraOff = !choice.camOn;
		// design #7: a direct listener on the underlying Room, not a reactive
		// $effect over connectionState — a real Disconnected is a one-shot
		// event, and `view === 'in-room'` read here (plain, not tracked) is
		// exactly the guard that skips a voluntary leave() (which sets view
		// away from 'in-room' before the SDK's own Disconnected fires).
		r.room.on(RoomEvent.Disconnected, () => {
			if (view === 'in-room') void handlePostDisconnect();
		});
		await r.connect(token.token, token.wsPath, { blurEnabled: choice.blurEnabled });
		room = r;
		view = 'in-room';
	}

	// design #17: expired → "Ask again" — a fresh guestJoinRequest with the
	// same display name; changing requestId re-keys the {#key} block below so
	// LobbyWaiting remounts and restarts its own pending/poll machine clean.
	async function askAgain(): Promise<void> {
		const name = displayName.trim();
		askAgainPending = true;
		askAgainError = '';
		try {
			const res = await meetApi.guestJoinRequest(slug, name);
			requestId = res.requestId;
			secret = res.secret;
			deviceChoice = null;
		} catch (err) {
			askAgainError = errText(err);
		} finally {
			askAgainPending = false;
		}
	}

	async function handlePostDisconnect(): Promise<void> {
		if (requestId == null) return;
		const outcome = await classifyPostDisconnect(slug, requestId, secret);
		if (outcome.kind === 'removed') {
			room = null;
			view = 'removed';
		} else if (outcome.kind === 'ended') {
			room = null;
			view = 'ended';
		} else if (outcome.kind === 'admitted') {
			// med-shard3-021 (CWE-359): route the reconnect through the SAME
			// consent-gate evaluation as the first admit — this arm used to
			// call connectRoom directly on the bare token, so a recording
			// started mid-call re-admitted the guest with no
			// RecordingConsentGate evaluation (the member surface re-gates;
			// for a guest this gate is the entire disclosure control). The
			// captions/cc seed args are the already-seeded values (DN3:
			// seeded once from the FIRST admitted poll, never updated), so
			// the re-seed is a no-op by construction.
			handleAdmitted(outcome.token, outcome.recordingActive, guestCaptionsOn, guestCcIdentity);
		} else {
			view = 'reconnecting';
		}
	}

	function leave(): void {
		room?.disconnect();
		room = null;
		view = 'form';
	}

	// ponytail: the public lobby surface has no "roster with roles" read
	// route (only the host/cohost-scoped pendingJoinRequests) — a guest's
	// participants sheet has nothing but the LiveKit identities it already
	// sees. Same posture MeetApp accepts for its own sheetParticipants.
	let sheetParticipants = $derived<SheetParticipant[]>(
		room
			? room.participants.map((p) => ({
					identity: p.identity,
					displayName: p.name || p.identity,
					role: p.identity.startsWith('g:') ? ('guest' as const) : ('member' as const),
				}))
			: [],
	);

	onDestroy(() => room?.disconnect());
</script>

<svelte:head><title>{t('meet.guestJoin.heading')} · setjoin</title></svelte:head>

{#if view === 'form'}
	<div class="sj-guestjoin-page">
		<div class="sj-guestjoin-inner">
			<Card title={t('meet.guestJoin.heading')}>
				<p class="sj-guestjoin-trust">{t('meet.guestJoin.trustLine')}</p>
				<form class="sj-guestjoin-form" onsubmit={submitJoinRequest}>
					<Input
						label={t('meet.guestJoin.nameLabel')}
						placeholder={t('meet.guestJoin.namePlaceholder')}
						bind:value={displayName}
						autocomplete="name"
						required
					/>
					{#if formError}<p class="sj-guestjoin-error" role="alert">{formError}</p>{/if}
					<Button type="submit" variant="primary" disabled={submitting || !displayName.trim()}>
						{submitting ? t('common.loading') : t('meet.guestJoin.submit')}
					</Button>
				</form>
			</Card>
		</div>
	</div>
{:else if view === 'waiting' && requestId != null}
	<div class="sj-guestjoin-page">
		<div class="sj-guestjoin-inner">
			{#if pendingAdmittedToken}
				<!-- D5 belt: shown before MeetRoom.connect ever runs. -->
				<RecordingConsentGate
					recordingActive={true}
					onConsent={() => {
						const token = pendingAdmittedToken;
						pendingAdmittedToken = null;
						if (token) void connectRoom(token);
					}}
					onDecline={() => {
						pendingAdmittedToken = null;
						view = 'form';
					}}
				>
					{#snippet children()}{/snippet}
				</RecordingConsentGate>
			{:else}
				{#key requestId}
					<LobbyWaiting {slug} {requestId} {secret} onAdmitted={handleAdmitted}>
						{#snippet pending()}
							{#if !deviceChoice}
								<PreJoin onJoin={captureChoice} />
							{/if}
						{/snippet}
						{#snippet expired()}
							<Button variant="primary" onclick={askAgain} disabled={askAgainPending}>
								{askAgainPending ? t('common.loading') : t('meet.waiting.askAgain')}
							</Button>
							{#if askAgainError}<p class="sj-guestjoin-error" role="alert">{askAgainError}</p>{/if}
						{/snippet}
					</LobbyWaiting>
				{/key}
			{/if}
		</div>
	</div>
{:else if view === 'removed'}
	<div class="sj-guestjoin-page"><EmptyState title={t('meet.waiting.removed')} /></div>
{:else if view === 'ended'}
	<div class="sj-guestjoin-page"><EmptyState title={t('meet.waiting.ended')} /></div>
{:else if view === 'reconnecting'}
	<div class="sj-guestjoin-page">
		<div class="sj-guestjoin-reconnecting">
			<Spinner />
			<p>{t('meet.guestJoin.reconnecting')}</p>
			<Button variant="secondary" onclick={handlePostDisconnect}>{t('common.retry')}</Button>
		</div>
	</div>
{:else if view === 'in-room' && room}
	<div class="sj-guestjoin-room">
		<p class="sj-guestjoin-chat-notice">{t('meet.chat.guestNotice')}</p>
		<MeetingRoom
			localParticipant={room.room.localParticipant}
			remoteParticipants={room.participants}
			connectionQuality={room.connectionQuality}
			raisedHands={room.raisedHands}
			view={galleryView}
			dominantSpeakerId={room.dominantSpeakerId}
			captionsOn={guestCaptionsOn}
			captionSegments={room.captionSegments}
			captionsFinalsLog={room.finalsLog}
			captionsLastAttestedAt={room.lastAttestedCcAt}
			captionsFadeOnDegrade
		/>
		<ControlsBar
			{room}
			selfRole="guest"
			locked={false}
			view={galleryView}
			participants={sheetParticipants}
			onViewChange={(v) => (galleryView = v)}
			onLock={() => {}}
			onKick={() => {}}
			onSetRole={() => {}}
			onLeave={leave}
			onEndForAll={() => {}}
			whiteboardOpen={false}
			breakoutsEnabled={false}
			recordingEnabled={false}
			recordingState="idle"
			onStartRecording={async () => {}}
			onStopRecording={() => {}}
			onStartCaptions={async () => {}}
			onStopCaptions={() => {}}
		/>
	</div>
{/if}

<style>
	.sj-guestjoin-page {
		min-height: 100vh;
		background: var(--surface-page);
		display: flex;
		align-items: flex-start;
		justify-content: center;
	}
	.sj-guestjoin-inner {
		width: 100%;
		max-width: 480px;
		margin: 0 auto;
		padding: clamp(16px, 4vw, 32px) clamp(12px, 4vw, 20px) 48px;
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.sj-guestjoin-trust {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0 0 var(--space-3);
	}
	.sj-guestjoin-form {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.sj-guestjoin-error {
		color: var(--danger-fg);
		font-size: var(--text-sm);
		margin: 0;
	}
	.sj-guestjoin-reconnecting {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: var(--space-3);
		padding: var(--space-4);
		text-align: center;
	}
	.sj-guestjoin-room {
		display: flex;
		flex-direction: column;
		height: 100vh;
		min-height: 0;
	}
	.sj-guestjoin-chat-notice {
		margin: 0;
		padding: var(--space-2) var(--space-3);
		font-size: var(--text-xs);
		color: var(--text-caption);
		background: var(--surface-sunken);
		text-align: center;
	}
</style>
