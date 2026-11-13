<svelte:options runes={true} />

<script lang="ts">
	// CaptionsOverlay — Meet B3 Task 15. Spec §8, F8, DN3, design D4/D7/D8.
	// Mounted UNCONDITIONALLY from MeetingRoom (member AND guest surfaces
	// alike) — the B2 D-5 a11y lesson: the role="log" region below is a
	// permanent CONTAINER whose CONTENT toggles, never conditionally
	// mounted/unmounted itself (a region inserted pre-populated is not
	// announced by screen readers). Only the STYLED chip/transcript layer
	// toggles via {#if}.
	//
	// `segments`/`captionsOn` arrive ALREADY suppressed by the caller while
	// assigned to a breakout (design D4 — captions are main-room-only, the
	// bot never joins a child room) and already F8-attested (room.svelte.ts's
	// #handleData only ever appends a `cc` frame whose SENDER matched
	// attestedCcIdentity) — this component trusts `segments` verbatim; there
	// is nothing left here to re-check.
	//
	// Degrade/fade timer (D8): captionsOn is server truth (never local
	// optimism) and stays true until a `captions_state{on:false}` push (or,
	// for a guest, the admitted-poll snapshot) says otherwise. But a crashed
	// ASR session between pushes would otherwise leave the chip claiming "on"
	// forever with nothing to show for it — so once ON, a 15s window with no
	// NEW attested frame (interim or final; `segments` is reassigned to a
	// fresh array reference on every #addCaption call, so depending on the
	// array reference itself, not just its length, catches an in-place
	// interim replace too) flips `degraded`. Members (fadeOnDegrade=false,
	// default) keep the chip visible with the meet.captions.unavailable
	// status line — they have a push rail that will correct this the moment
	// the worker's reconcile arm actually detects and fixes a crash. Guests
	// (fadeOnDegrade=true) have NO push rail at all post-admission — degraded
	// is terminal for them, so the whole chip+transcript fades away instead
	// of showing a status line that can never self-correct.
	//
	// THE GUEST-PAGE GAP IS DISSOLVED (B3 retro fix, design findings #4/#5):
	// `meeting_lobby.sql`'s admitted-poll envelope now projects `ccIdentity`
	// (`'cc:' || meetingId`) on BOTH admitted arms (guest and member-knock),
	// unconditionally — the guest join page threads it into `MeetRoom`'s
	// `attestedCcIdentity` constructor arg (routes/meet/join/[slug]/
	// +page.svelte), so a guest attests real `cc` frames exactly like a
	// member does. The old ceiling (fails closed to `''`, chip fades on a
	// fixed 15s timer with no way to self-correct) no longer applies — a
	// guest with live frames behaves identically to a member.
	import type { CaptionSegment } from '$lib/meet/room.svelte';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';

	let {
		captionsOn,
		segments,
		finalsLog = [],
		participantNames = {},
		fadeOnDegrade = false,
		hideTranscript = false,
		lastAttestedCcAt = 0,
	}: {
		captionsOn: boolean;
		segments: CaptionSegment[];
		/** B3 retro fix (eng #13 / D7-break): the sr-only role="log" region's
		 *  OWN append-only source — room.svelte.ts's `finalsLog`, decoupled
		 *  from `segments`' small visual ring. Defaults `[]` so an
		 *  un-updated caller still renders (an empty, never-mutating log). */
		finalsLog?: CaptionSegment[];
		participantNames?: Record<string, string>;
		fadeOnDegrade?: boolean;
		/** B3 retro fix (design #10): hides the styled 2-line transcript block
		 *  ONLY — the chip (small, fits regardless of a squeeze) and the
		 *  sr-only log region (never visual) are untouched. The caller sets
		 *  this while a squeeze (e.g. the whiteboard's 96px-tall video
		 *  filmstrip) leaves no room for the transcript to render without
		 *  bleeding over neighboring chrome. */
		hideTranscript?: boolean;
		/** B3 retro fix (design finding #5a): room.svelte.ts's
		 *  `lastAttestedCcAt` — an epoch-ms timestamp bumped on EVERY attested
		 *  `cc` frame, including the bot's 5s heartbeat (which never touches
		 *  `segments`). Read alongside `segments` below so a heartbeat-only
		 *  tick resets the degrade timer without ever creating a transcript
		 *  entry. Defaults 0 so an un-updated caller still renders. */
		lastAttestedCcAt?: number;
	} = $props();

	const DEGRADE_MS = 15000;
	let degraded = $state(false);

	$effect(() => {
		const on = captionsOn;
		void segments; // reactive dependency: a NEW array reference == a new attested frame (append or in-place replace both reassign)
		void lastAttestedCcAt; // a heartbeat-only tick (no segment change) is ALSO a live "still alive" signal
		if (!on) {
			degraded = false;
			return;
		}
		degraded = false;
		const id = setTimeout(() => {
			degraded = true;
		}, DEGRADE_MS);
		return () => clearTimeout(id);
	});

	function nameFor(identity: string): string {
		return participantNames[identity] ?? identity;
	}

	// The styled transcript layer: reduce the ring to ONE line per sid (the
	// LATEST update wins — an interim replace-in-place keeps one entry per
	// sid; a later final for the same sid is a second, later array entry, so
	// "last write per sid" naturally resolves to it) — this is what makes
	// "interim segments replace in place; finals persist briefly" true
	// visually without room.svelte.ts's own ring needing to change.
	let displaySegments = $derived.by(() => {
		const bySid = new Map<string, CaptionSegment>();
		for (const seg of segments) bySid.set(seg.sid, seg);
		return [...bySid.values()];
	});
	const VISIBLE_LINES = 2;
	let visibleLines = $derived(displaySegments.slice(-VISIBLE_LINES));

	// D8: the styled layer (chip + transcript) hides entirely once a
	// fade-on-degrade surface (guests) has gone dark; a non-fading surface
	// (members/host/cohost) keeps showing it, degraded status line and all.
	let styledVisible = $derived(captionsOn && !(degraded && fadeOnDegrade));
</script>

<!-- B2 D-5: always mounted, content-only toggle, sr-only (never takes visual
     space — the styled chip/transcript below is the sighted equivalent).
     B3 retro fix (eng #13 / D7-break): reads finalsLog — a SEPARATE,
     append-only source keyed by sid (a stable per-utterance identity, not
     array INDEX) — so an unrelated interim append evicting an old entry
     from the small VISUAL ring (segments) never mutates or re-keys this
     region's own rows (the SR re-announcement flood the index-key used to
     cause). -->
<div class="captions-overlay__log" role="log" aria-live="polite">
	{#each finalsLog as seg (seg.sid)}
		<div>{nameFor(seg.identity)}: {seg.text}</div>
	{/each}
</div>

{#if styledVisible}
	<div class="captions-overlay">
		<div class="captions-overlay__chip" role="status">
			<Icon name="Captions" size={12} />
			<span>{degraded ? t('meet.captions.unavailable') : t('meet.captions.chip')}</span>
		</div>
		{#if !hideTranscript && visibleLines.length > 0}
			<div class="captions-overlay__transcript" aria-hidden="true">
				{#each visibleLines as seg (seg.sid)}
					<p class="captions-overlay__line" class:captions-overlay__line--interim={!seg.final}>
						<span class="captions-overlay__speaker">{nameFor(seg.identity)}</span>
						{seg.text}
					</p>
				{/each}
			</div>
		{/if}
	</div>
{/if}

<style>
	.captions-overlay__log {
		position: absolute;
		width: 1px;
		height: 1px;
		overflow: hidden;
		clip-path: inset(50%);
	}
	.captions-overlay {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: var(--space-1);
		max-width: min(90%, 640px);
	}
	.captions-overlay__chip {
		display: flex;
		align-items: center;
		gap: var(--space-1);
		padding: var(--space-1) var(--space-2);
		background: var(--surface-raised);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-full);
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}
	.captions-overlay__transcript {
		display: flex;
		flex-direction: column;
		gap: 2px;
		padding: var(--space-2) var(--space-3);
		background: color-mix(in srgb, var(--surface-base) 80%, transparent);
		border-radius: var(--radius-md);
		text-align: center;
	}
	.captions-overlay__line {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-primary);
		line-height: 1.4;
	}
	.captions-overlay__line--interim {
		color: var(--text-secondary);
	}
	.captions-overlay__speaker {
		font-weight: 600;
		margin-right: var(--space-1);
	}
</style>
