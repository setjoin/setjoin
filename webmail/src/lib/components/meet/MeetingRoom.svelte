<svelte:options runes={true} />

<script lang="ts">
	// MeetingRoom — Meet B1 Task 16, design #5 (the locked layout rules):
	// gallery = auto CSS grid capped at 12 visible tiles + a "+N more"
	// overflow tile; speaker/screenshare layout auto-promotes the active
	// speaker (gallery never reshuffles mid-glance); screenshare takes the
	// stage with a filmstrip below; the self-tile is mirrored (ParticipantTile's
	// own concern) and always sorts last. Design #10: an aria-live=polite
	// region announces participant join/leave (the `/book` page's
	// `role=status` region is the in-repo precedent).
	//
	// Takes plain derived arrays/maps rather than the whole MeetRoom instance
	// — MeetApp is the integration point that reads room.participants/
	// room.room.localParticipant/room.connectionQuality and passes them down,
	// which keeps this component trivially testable with plain fakes.
	import { Track, ConnectionQuality, type Participant } from 'livekit-client';
	import ParticipantTile from './ParticipantTile.svelte';
	import CaptionsOverlay from './CaptionsOverlay.svelte';
	import type { CaptionSegment } from '$lib/meet/room.svelte';
	import { t } from '$lib/i18n';

	const GALLERY_CAP = 12;

	let {
		localParticipant,
		remoteParticipants,
		connectionQuality = {},
		raisedHands = new Set<string>(),
		view = 'gallery',
		dominantSpeakerId = null,
		captionsOn = false,
		captionSegments = [],
		captionsFinalsLog = [],
		captionsFadeOnDegrade = false,
		captionsHideTranscript = false,
		captionsLastAttestedAt = 0,
	}: {
		localParticipant: Participant;
		remoteParticipants: Participant[];
		connectionQuality?: Record<string, ConnectionQuality>;
		raisedHands?: Set<string>;
		view?: 'gallery' | 'speaker';
		dominantSpeakerId?: string | null;
		/** B3 Task 15: server-state chip truth (DN3 — visible to guests too).
		 *  The caller (MeetApp/the guest join page) is responsible for
		 *  suppressing this to `false` while assigned to a breakout (design
		 *  D4 — captions are main-room-only) and re-seeding it from server
		 *  state on return to main; this component does not know about
		 *  breakouts at all. */
		captionsOn?: boolean;
		/** room.captionSegments — already F8-attested. Same caller-side
		 *  breakout suppression as captionsOn above (pass `[]`). */
		captionSegments?: CaptionSegment[];
		/** B3 retro fix (eng #13 / D7-break): room.finalsLog — the sr-only
		 *  region's own append-only source, decoupled from captionSegments'
		 *  small visual ring. Same caller-side breakout suppression. */
		captionsFinalsLog?: CaptionSegment[];
		/** D8: the guest join page passes `true` (no push rail post-admission,
		 *  so a degraded session fades away rather than showing a status line
		 *  that can never self-correct). Members/host/cohost default `false`. */
		captionsFadeOnDegrade?: boolean;
		/** B3 retro fix (design #10): hides only the styled transcript block
		 *  while a squeeze (the open-whiteboard filmstrip) leaves no room for
		 *  it — the caller (MeetApp) passes `whiteboardOpen`. */
		captionsHideTranscript?: boolean;
		/** B3 retro fix (design finding #5a): room.lastAttestedCcAt, forwarded
		 *  to CaptionsOverlay's degrade timer. Same caller-side breakout
		 *  suppression as the other captions props. */
		captionsLastAttestedAt?: number;
	} = $props();

	// B3 Task 15: identity -> display name, for CaptionsOverlay's per-speaker
	// attribution — built from the SAME Participant objects this component
	// already renders tiles from, no new prop/route needed.
	let participantNames = $derived.by(() => {
		const map: Record<string, string> = { [localParticipant.identity]: localParticipant.name || localParticipant.identity };
		for (const p of remoteParticipants) map[p.identity] = p.name || p.identity;
		return map;
	});

	function hasScreenShare(p: Participant): boolean {
		return [...p.videoTrackPublications.values()].some((pub) => pub.source === Track.Source.ScreenShare);
	}
	let screenSharer = $derived([...remoteParticipants, localParticipant].find(hasScreenShare) ?? null);

	// Gallery cap: local always sorts last and is always visible (design #5) —
	// only remotes can be pushed into the "+N more" overflow.
	let visibleRemotes = $derived(remoteParticipants.slice(0, GALLERY_CAP - 1));
	let overflowCount = $derived(Math.max(0, remoteParticipants.length - visibleRemotes.length));

	// Speaker/screenshare layout auto-promotes the active speaker — gallery
	// itself NEVER reshuffles on this (design #5's explicit carve-out).
	let speakerParticipant = $derived.by(() => {
		if (screenSharer) return screenSharer;
		if (dominantSpeakerId === localParticipant.identity) return localParticipant;
		return remoteParticipants.find((p) => p.identity === dominantSpeakerId) ?? remoteParticipants[0] ?? localParticipant;
	});

	function qualityFor(p: Participant): ConnectionQuality {
		return connectionQuality[p.identity === localParticipant.identity ? 'local' : p.identity] ?? ConnectionQuality.Unknown;
	}

	// ── a11y: join/leave announcements (design #10) ─────────────────────────
	let announcement = $state('');
	let knownIdentities = new Set<string>();
	let seeded = false;
	// B1 live-gate ledger fix 3: identity -> last-known display name. A
	// participant who has already left is gone from `remoteParticipants` by
	// the time the "leave" branch below runs, so `id` used to be the only
	// thing left to announce — the raw LiveKit wire identity (`u:1 left the
	// meeting`), never the person's actual name. Populated from the SAME
	// `remoteParticipants` this component already renders tiles from, every
	// run, before either branch below reads it — so a leave always resolves
	// against the name last seen while they were still present.
	let nameCache = new Map<string, string>();
	$effect(() => {
		const current = new Set(remoteParticipants.map((p) => p.identity));
		for (const p of remoteParticipants) nameCache.set(p.identity, p.name || '');
		if (!seeded) {
			// First render just seeds the baseline — no join announcement for
			// participants already present when this component mounted.
			knownIdentities = current;
			seeded = true;
			return;
		}
		for (const id of current) {
			if (!knownIdentities.has(id)) {
				const p = remoteParticipants.find((rp) => rp.identity === id);
				announcement = t('meet.a11y.joined', { name: p?.name || t('meet.a11y.someone') });
			}
		}
		for (const id of knownIdentities) {
			if (!current.has(id)) {
				announcement = t('meet.a11y.left', { name: nameCache.get(id) || t('meet.a11y.someone') });
			}
		}
		knownIdentities = current;
	});
</script>

<div class="meeting-room">
	<div class="meeting-room__live-region" role="status" aria-live="polite">{announcement}</div>

	{#if screenSharer || view === 'speaker'}
		<div class="meeting-room__stage">
			<ParticipantTile
				participant={speakerParticipant}
				isLocal={speakerParticipant.identity === localParticipant.identity}
				quality={qualityFor(speakerParticipant)}
				raisedHand={raisedHands.has(speakerParticipant.identity)}
			/>
		</div>
		<div class="meeting-room__filmstrip" data-testid="filmstrip">
			{#each [...remoteParticipants, localParticipant].filter((p) => p !== speakerParticipant) as p (p.identity)}
				<ParticipantTile
					participant={p}
					isLocal={p.identity === localParticipant.identity}
					quality={qualityFor(p)}
					raisedHand={raisedHands.has(p.identity)}
				/>
			{/each}
		</div>
	{:else}
		<div class="meeting-room__gallery" data-testid="gallery">
			{#each visibleRemotes as p (p.identity)}
				<ParticipantTile participant={p} quality={qualityFor(p)} raisedHand={raisedHands.has(p.identity)} />
			{/each}
			{#if overflowCount > 0}
				<div class="meeting-room__overflow" data-testid="gallery-overflow">
					{t('meet.tile.overflow', { n: String(overflowCount) })}
				</div>
			{/if}
			<ParticipantTile participant={localParticipant} isLocal quality={qualityFor(localParticipant)} />
		</div>
	{/if}

	<!-- design D6 "Meet composition": the captions overlay is bottom-anchored
	     ABOVE the connection-degraded banner — a shared flex-column stack so
	     the two never overlap regardless of which is showing. CaptionsOverlay
	     is mounted UNCONDITIONALLY (B2 D-5): its own role=log region must
	     exist from this component's mount, never toggle with captionsOn. -->
	<div class="meeting-room__bottom-stack">
		<CaptionsOverlay
			{captionsOn}
			segments={captionSegments}
			finalsLog={captionsFinalsLog}
			{participantNames}
			fadeOnDegrade={captionsFadeOnDegrade}
			hideTranscript={captionsHideTranscript}
			lastAttestedCcAt={captionsLastAttestedAt}
		/>
		{#if qualityFor(localParticipant) === ConnectionQuality.Poor}
			<div class="meeting-room__degraded-banner" role="status">{t('meet.tile.connectionDegraded')}</div>
		{/if}
	</div>
</div>

<style>
	.meeting-room {
		display: flex;
		flex-direction: column;
		flex: 1;
		min-height: 0;
		gap: var(--space-2);
		padding: var(--space-2);
		position: relative;
	}
	.meeting-room__live-region {
		position: absolute;
		width: 1px;
		height: 1px;
		overflow: hidden;
		clip-path: inset(50%);
	}
	.meeting-room__gallery {
		flex: 1;
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
		gap: var(--space-2);
		align-content: center;
		overflow-y: auto;
	}
	.meeting-room__overflow {
		display: flex;
		align-items: center;
		justify-content: center;
		aspect-ratio: 16 / 9;
		background: var(--surface-sunken);
		border-radius: var(--radius-md);
		color: var(--text-secondary);
		font-size: var(--text-sm);
	}
	.meeting-room__stage {
		flex: 1;
		min-height: 0;
		display: flex;
	}
	.meeting-room__stage :global(.ptile) {
		width: 100%;
		height: 100%;
	}
	.meeting-room__filmstrip {
		display: flex;
		gap: var(--space-2);
		overflow-x: auto;
		flex: none;
		height: 96px;
	}
	.meeting-room__filmstrip :global(.ptile) {
		width: 160px;
		flex: none;
	}
	.meeting-room__bottom-stack {
		position: absolute;
		bottom: var(--space-2);
		left: 50%;
		transform: translateX(-50%);
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: var(--space-2);
		max-width: 90%;
		pointer-events: none;
	}
	.meeting-room__degraded-banner {
		background: var(--warning-bg);
		color: var(--warning-fg);
		padding: var(--space-1) var(--space-3);
		border-radius: var(--radius-full);
		font-size: var(--text-xs);
	}
</style>
