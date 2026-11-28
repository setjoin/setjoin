<svelte:options runes={true} />

<script lang="ts">
	// LobbyWaiting — Meet B1 Task 16, design #2: the SHARED waiting-state
	// machine BOTH a member who knocked on a locked meeting (this task) and
	// the guest join page (Task 17) ride — same public poll route
	// (`guestPoll`), same {requestId, secret} completion contract (the
	// authed knock route hands back the identical shape the public
	// join-request create route does). Task 17 mounts PreJoin INSIDE this
	// component's `pending` slot so a guest does the device/permission dance
	// while waiting (admit → instant connect); this task only needs the
	// state machine + a plain pending message for the member-knock arm.
	//
	// Polling cadence (spec): 3s + jitter; a 429 backs off to 10s, keeping
	// the SAME "pending" copy — a rate limit must never read as an error to
	// a waiting caller (design #16). A network error also just retries at
	// the current cadence rather than surfacing — Task 17's fuller test
	// suite pins the exact backoff arcs; this task pins the four terminal
	// transitions the member-knock path actually exercises.
	//
	// Task 17 addendum: the optional `expired` snippet (mirrors `pending`)
	// lets the guest join page render an "Ask again" button without this
	// component knowing anything about guest-vs-member semantics — it only
	// renders whatever the caller hands it while `phase === 'expired'`.
	//
	// The reactive state variable is named `phase`, not `state` — a local
	// $state()-bound variable literally named `state` collides with the
	// `$state` rune token in a way that breaks svelte-check's generated TS
	// the moment a SECOND `$state()` call exists in this file (confirmed by
	// bisection when B2 Task 10 added `pendingRecordingActive` below: with
	// `let state = $state(...)`, svelte-check reported the nonsensical
	// "'state' implicitly has type 'any'... Block-scoped variable '$state'
	// used before its declaration" on the FIRST call, purely from having a
	// second `$state()` present). `data-state`/`WaitingState` are unchanged —
	// only the local variable's name moved.
	import { onMount, onDestroy } from 'svelte';
	import type { Snippet } from 'svelte';
	import * as meetApi from '$lib/meet/api';
	import { MeetError, type MeetToken } from '$lib/meet/api';
	import { Spinner } from '$lib/components/ui';
	import { t } from '$lib/i18n';

	export type WaitingState = 'pending' | 'admitted' | 'denied' | 'expired';

	let {
		slug,
		requestId,
		secret,
		onAdmitted,
		pending,
		expired,
	}: {
		slug: string;
		requestId: number;
		secret: string;
		// B2 Task 10, D5's flicker-window belt: the SECOND argument is the
		// admitted grant's own recordingActive (false when the poll's
		// admitted arm carries none). BOTH callers act on it: the guest
		// join page gates before connect, and MeetApp's knock arm
		// (handleKnockAdmitted) seeds the banner + re-gates consent when a
		// recording started while the member waited in the lobby (retro F1).
		// B3 Task 15, DN3: the THIRD argument is the SAME admitted grant's
		// own captionsOn (meeting_lobby.sql's two admitted branches) — both
		// callers seed their in-room chip from it; this is the ONLY signal
		// the guest surface ever gets (no push rail post-admission, D8).
		// B3 retro fix (design findings #4/#5): the FOURTH argument is the
		// SAME admitted grant's `ccIdentity` (`'cc:' || meetingId`), now
		// unconditional on both admitted arms — the guest join page threads
		// it into MeetRoom's attestedCcIdentity, dissolving the guest-
		// captions attestation ceiling Task 7/15 documented. The member-
		// knock caller (MeetApp) already derives the same identity from its
		// own live `meeting.meetingId` and does not need this argument.
		onAdmitted: (token: MeetToken, recordingActive: boolean, captionsOn: boolean, ccIdentity: string) => void;
		/** Rendered only while phase === 'pending' — Task 17 mounts PreJoin here. */
		pending?: Snippet;
		/** Rendered only while phase === 'expired' — Task 17 renders an "Ask
		 *  again" button here (design #17). The member-knock caller (this task)
		 *  has no retry path and simply omits it. */
		expired?: Snippet;
	} = $props();

	const BASE_INTERVAL_MS = 3000;
	const JITTER_MS = 500;
	const RATE_LIMITED_INTERVAL_MS = 10000;

	let phase = $state<WaitingState>('pending');
	// D5: the poll→admit flicker-window belt — carried on the pending arm
	// only (D-7: denied/expired have no consent decision left to make).
	let pendingRecordingActive = $state(false);
	let timer: ReturnType<typeof setTimeout> | null = null;
	let stopped = false;

	function scheduleNext(delayMs: number): void {
		if (stopped) return;
		timer = setTimeout(() => void poll(), delayMs);
	}

	async function poll(): Promise<void> {
		try {
			const res = await meetApi.guestPoll(slug, requestId, secret);
			if (res.state === 'admitted') {
				phase = 'admitted';
				onAdmitted(
					{ token: res.token, wsPath: res.wsPath, expiresAt: res.expiresAt },
					!!res.recordingActive,
					!!res.captionsOn,
					res.ccIdentity ?? '',
				);
				return;
			}
			if (res.state === 'denied') {
				phase = 'denied';
				return;
			}
			if (res.state === 'expired') {
				phase = 'expired';
				return;
			}
			pendingRecordingActive = !!res.recordingActive;
			scheduleNext(BASE_INTERVAL_MS + Math.random() * JITTER_MS);
		} catch (err) {
			// design #16: a 429 backs off to 10s but shows the SAME pending copy —
			// never an error flash for a rate-limited poll. Any other transport
			// error (offline blip) also just retries at the base cadence.
			const rateLimited = err instanceof MeetError && err.status === 429;
			scheduleNext(rateLimited ? RATE_LIMITED_INTERVAL_MS : BASE_INTERVAL_MS + Math.random() * JITTER_MS);
		}
	}

	onMount(() => {
		void poll();
	});
	onDestroy(() => {
		stopped = true;
		if (timer) clearTimeout(timer);
	});
</script>

<div class="lobby-waiting" data-testid="lobby-waiting" data-state={phase}>
	{#if phase === 'pending'}
		<div class="lobby-waiting__pending" role="status" aria-live="polite">
			<Spinner />
			<p>{t('meet.waiting.pending')}</p>
			{#if pendingRecordingActive}
				<p class="lobby-waiting__recording-notice">{t('meet.recording.banner')}</p>
			{/if}
			{#if pending}{@render pending()}{/if}
		</div>
	{:else if phase === 'denied'}
		<p role="status">{t('meet.waiting.denied')}</p>
	{:else if phase === 'expired'}
		<p role="status">{t('meet.waiting.expired')}</p>
		{#if expired}{@render expired()}{/if}
	{:else}
		<p role="status">{t('meet.waiting.admitted')}</p>
	{/if}
</div>

<style>
	.lobby-waiting {
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		gap: var(--space-3);
		padding: var(--space-4);
		text-align: center;
	}
	.lobby-waiting__pending {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: var(--space-2);
	}
	.lobby-waiting__recording-notice {
		font-size: var(--text-sm);
		color: var(--danger-fg);
	}
</style>
