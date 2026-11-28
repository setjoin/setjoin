<svelte:options runes={true} />

<script lang="ts">
	// ParticipantTile — Meet B1 Task 16. Renders ONE participant (local or
	// remote — both extend livekit-client's Participant, so this component
	// doesn't care which). Design #4: a 3-state connection-quality dot;
	// design #8: a "Guest" Badge on every `g:`-identity tile (the display
	// name is guest-chosen and spoofable — the badge, not the name, is the
	// authority a viewer can trust).
	import { onDestroy } from 'svelte';
	import { ConnectionQuality, Track, type Participant } from 'livekit-client';
	import { Avatar, Badge } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';
	import { isExternalParticipant } from '$lib/meet/participantAttributes';

	let {
		participant,
		isLocal = false,
		quality = ConnectionQuality.Unknown,
		raisedHand = false,
	}: {
		participant: Participant;
		isLocal?: boolean;
		quality?: ConnectionQuality;
		raisedHand?: boolean;
	} = $props();

	let isGuest = $derived(participant.identity.startsWith('g:'));
	let isExternal = $derived(!isGuest && isExternalParticipant(participant));
	let displayName = $derived(isLocal ? t('meet.tile.you') : participant.name || participant.identity);
	let cameraOn = $derived(participant.isCameraEnabled);
	let micOn = $derived(participant.isMicrophoneEnabled);

	let videoEl = $state<HTMLVideoElement | undefined>();
	let audioEl = $state<HTMLAudioElement | undefined>();

	// Attaches/detaches the live MediaStreamTrack as publications change —
	// livekit-client's Track.attach()/detach() is the documented way to bind
	// a track to a media element (mirrors the SDK's own React/vanilla samples).
	$effect(() => {
		// Re-run whenever cameraOn flips (Participant is not itself a $state
		// object — its isCameraEnabled getter reads live SDK state, so this
		// effect re-derives from the reactive `cameraOn` local instead).
		void cameraOn;
		if (!videoEl) return;
		const pub = [...participant.videoTrackPublications.values()].find((p) => p.source === Track.Source.Camera);
		const track = pub?.videoTrack;
		if (track && cameraOn) {
			track.attach(videoEl);
			return () => track.detach(videoEl!);
		}
		return undefined;
	});

	// Remote audio must be attached to actually hear it (browser autoplay
	// policy aside — LiveKit's own docs call this out); the LOCAL participant
	// never attaches its own mic back to itself.
	$effect(() => {
		void micOn;
		if (isLocal || !audioEl) return;
		const pub = [...participant.audioTrackPublications.values()].find((p) => p.source === Track.Source.Microphone);
		const track = pub?.audioTrack;
		if (track) {
			track.attach(audioEl);
			return () => track.detach(audioEl!);
		}
		return undefined;
	});

	onDestroy(() => {
		if (videoEl) {
			for (const pub of participant.videoTrackPublications.values()) pub.videoTrack?.detach(videoEl);
		}
		if (audioEl) {
			for (const pub of participant.audioTrackPublications.values()) pub.audioTrack?.detach(audioEl);
		}
	});

	function connectionQualityClass(value: ConnectionQuality): 'poor' | 'good' | 'excellent' | 'unknown' {
		switch (value) {
			case ConnectionQuality.Poor:
				return 'poor';
			case ConnectionQuality.Good:
				return 'good';
			case ConnectionQuality.Excellent:
				return 'excellent';
			default:
				return 'unknown';
		}
	}

	let qualityClass = $derived(connectionQualityClass(quality));
	let qualityLabel = $derived(t(`meet.tile.quality.${qualityClass}`));
</script>

<div class="ptile" data-testid={`tile-${participant.identity}`} class:ptile--self={isLocal}>
	{#if cameraOn}
		<!-- svelte-ignore a11y_media_has_caption -->
		<video bind:this={videoEl} autoplay playsinline muted={isLocal} class="ptile__video" class:ptile__video--mirror={isLocal}
		></video>
	{:else}
		<div class="ptile__avatar-wrap">
			<Avatar name={displayName} size="lg" />
		</div>
	{/if}
	{#if !isLocal}
		<!-- svelte-ignore a11y_media_has_caption -->
		<audio bind:this={audioEl} autoplay></audio>
	{/if}

	<div class="ptile__footer">
		<span class="ptile__name">{displayName}</span>
		{#if !micOn}
			<span class="ptile__mute-badge" aria-label={t('meet.controls.micOff')}>
				<Icon name="MicOff" size={12} />
			</span>
		{/if}
		{#if isGuest}
			<Badge variant="info" label={t('meet.tile.guest')} />
		{:else if isExternal}
			<Badge variant="info" label={t('meet.tile.external')} />
		{/if}
		{#if raisedHand}
			<span class="ptile__hand" aria-label={t('meet.controls.raiseHand')}>
				<Icon name="Hand" size={12} />
			</span>
		{/if}
	</div>

	<span class="ptile__quality ptile__quality--{qualityClass}" role="img" aria-label={qualityLabel} title={qualityLabel}
	></span>
</div>

<style>
	.ptile {
		position: relative;
		display: flex;
		align-items: center;
		justify-content: center;
		background: var(--surface-sunken);
		border-radius: var(--radius-md);
		overflow: hidden;
		aspect-ratio: 16 / 9;
	}
	.ptile__video {
		width: 100%;
		height: 100%;
		object-fit: cover;
	}
	.ptile__video--mirror {
		transform: scaleX(-1);
	}
	.ptile__avatar-wrap {
		display: flex;
	}
	.ptile__footer {
		position: absolute;
		left: var(--space-2);
		bottom: var(--space-2);
		display: flex;
		align-items: center;
		gap: var(--space-1);
		background: rgb(0, 0, 0, 0.5);
		color: #ffffff;
		border-radius: var(--radius-sm);
		padding: 2px var(--space-2);
		font-size: var(--text-xs);
		max-width: calc(100% - var(--space-4));
	}
	.ptile__name {
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.ptile__mute-badge,
	.ptile__hand {
		display: inline-flex;
		flex: none;
	}
	.ptile__quality {
		position: absolute;
		top: var(--space-2);
		right: var(--space-2);
		width: 8px;
		height: 8px;
		border-radius: 50%;
	}
	.ptile__quality--excellent,
	.ptile__quality--good {
		background: var(--success-solid);
	}
	.ptile__quality--poor {
		background: var(--danger-solid);
	}
	.ptile__quality--unknown {
		background: var(--gray-400);
	}
</style>
