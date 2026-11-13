<svelte:options runes={true} />

<script lang="ts">
	// PreJoin — Meet B1 Task 16, design #1: the three device states are the
	// spec, not an implementer choice. getUserMedia is attempted once on
	// mount; its failure mode decides which of the three states renders.
	// The codec probe (Task 15's pickVideoCodec, ≤1.5s, never trusts
	// getCapabilities()) runs in parallel and NEVER blocks the Join button —
	// clicking mid-probe joins with whatever `codec` currently holds (the
	// safe vp8 default until the probe resolves).
	import { onMount, onDestroy } from 'svelte';
	import { Room, LocalVideoTrack } from 'livekit-client';
	import { pickVideoCodec, type MeetCodec } from '$lib/meet/codecProbe';
	import { isBlurAvailable, loadBlurPref, saveBlurPref, setBlur } from '$lib/meet/blur';
	import { Button, Select, Spinner } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';

	interface JoinChoice {
		micOn: boolean;
		camOn: boolean;
		codec: MeetCodec;
		audioDeviceId: string | null;
		videoDeviceId: string | null;
		blurEnabled: boolean;
	}

	let { onJoin, joining = false }: { onJoin: (choice: JoinChoice) => void; joining?: boolean } = $props();

	const PREFS_KEY = 'meet.devicePrefs';
	interface StoredPrefs {
		micOn: boolean;
		camOn: boolean;
		audioDeviceId: string | null;
		videoDeviceId: string | null;
	}
	function loadPrefs(): StoredPrefs {
		try {
			const raw = localStorage.getItem(PREFS_KEY);
			if (raw) return JSON.parse(raw) as StoredPrefs;
		} catch {
			/* ignore corrupt/absent storage — defaults below */
		}
		// design #11: mic and camera default MUTED.
		return { micOn: false, camOn: false, audioDeviceId: null, videoDeviceId: null };
	}
	function savePrefs(p: StoredPrefs): void {
		try {
			localStorage.setItem(PREFS_KEY, JSON.stringify(p));
		} catch {
			/* localStorage unavailable (private mode quota) — prefs just don't persist */
		}
	}

	const prefs = loadPrefs();
	let micOn = $state(prefs.micOn);
	let camOn = $state(prefs.camOn);
	let audioDeviceId = $state<string | null>(prefs.audioDeviceId);
	let videoDeviceId = $state<string | null>(prefs.videoDeviceId);

	type DeviceState = 'checking' | 'granted' | 'denied' | 'nodevice';
	let deviceState = $state<DeviceState>('checking');
	let audioInputs = $state<MediaDeviceInfo[]>([]);
	let videoInputs = $state<MediaDeviceInfo[]>([]);
	let previewStream = $state<MediaStream | null>(null);
	let videoEl = $state<HTMLVideoElement | undefined>();

	let codec = $state<MeetCodec>('vp8');
	let probing = $state(true);
	let codecLabel = $derived.by(() => {
		if (probing) return t('meet.prejoin.checkingVideo');
		if (codec === 'av1') return t('meet.prejoin.codecAv1');
		if (codec === 'vp9') return t('meet.prejoin.codecVp9');
		return t('meet.prejoin.codecVp8');
	});

	// Task 16b: background blur — hidden entirely (never a broken switch)
	// unless the codec probe landed on vp9/av1 AND the browser supports the
	// background-processor stack (blur.ts's own gate). The preview track is
	// wrapped in a LiveKit LocalVideoTrack ONLY in that case (rung, not the
	// default path) so the un-gated common case keeps the plain
	// srcObject preview untouched.
	let blurOn = $state(loadBlurPref());
	let blurSupported = $derived(isBlurAvailable(codec));
	let localVideoTrack = $state<LocalVideoTrack | null>(null);

	async function refreshBlurPreview(): Promise<void> {
		localVideoTrack?.detach();
		localVideoTrack = null;
		if (!blurSupported) return;
		try {
			const rawTrack = previewStream?.getVideoTracks()[0];
			if (!rawTrack) return;
			const lvt = new LocalVideoTrack(rawTrack);
			if (blurOn) await setBlur(lvt, true);
			localVideoTrack = lvt;
		} catch {
			// Blur wrapping must never regress the core device-permission flow
			// (called from inside acquirePreview()'s own try/catch — this inner
			// guard keeps a LocalVideoTrack/processor problem from being
			// mistaken for a camera/mic permission failure). The plain
			// srcObject path (videoEl's $effect, when localVideoTrack is null)
			// keeps the preview working regardless.
			localVideoTrack = null;
		}
	}

	async function toggleBlur(): Promise<void> {
		blurOn = !blurOn;
		if (localVideoTrack) {
			const ok = await setBlur(localVideoTrack, blurOn);
			if (!ok) blurOn = !blurOn; // revert — never claim a state the processor didn't reach
		}
		saveBlurPref(blurOn);
	}

	function applyTrackEnabled(): void {
		if (!previewStream) return;
		for (const tr of previewStream.getAudioTracks()) tr.enabled = micOn;
		for (const tr of previewStream.getVideoTracks()) tr.enabled = camOn;
	}

	// Keeps the <video> element in sync however camOn/previewStream/blur
	// change — including the case where the element itself only mounts once
	// deviceState flips to 'granted' (bind:this resolves a tick after acquirePreview()
	// sets previewStream, so assigning inside acquirePreview() directly would race it).
	// blurSupported sessions render via the LocalVideoTrack wrapper (so the
	// processor's output, if any, actually reaches the element); everyone
	// else keeps the plain srcObject path untouched.
	$effect(() => {
		if (!videoEl) return;
		if (camOn && localVideoTrack) {
			localVideoTrack.attach(videoEl);
		} else if (camOn && previewStream) {
			videoEl.srcObject = previewStream;
		} else {
			videoEl.srcObject = null;
		}
	});

	function stopPreview(): void {
		localVideoTrack?.detach();
		localVideoTrack = null;
		previewStream?.getTracks().forEach((tr) => tr.stop());
		previewStream = null;
	}

	/** Requests BOTH tracks once, regardless of the mic/cam default-muted
	 *  prefs (design #11) — deviceState must reflect real permission/device
	 *  reality even for a user who starts fully muted, and re-toggling later
	 *  just flips `track.enabled` (no repeat permission prompt). Called on
	 *  mount and whenever the user picks a different device (device-specific
	 *  constraints do need a fresh acquisition). */
	async function acquirePreview(): Promise<void> {
		stopPreview();
		try {
			const stream = await navigator.mediaDevices.getUserMedia({
				audio: audioDeviceId ? { deviceId: { exact: audioDeviceId } } : true,
				video: videoDeviceId ? { deviceId: { exact: videoDeviceId } } : true,
			});
			previewStream = stream;
			deviceState = 'granted';
			applyTrackEnabled();
			await refreshBlurPreview();
		} catch (err) {
			const name = err instanceof Error ? err.name : '';
			deviceState = name === 'NotAllowedError' || name === 'PermissionDeniedError' ? 'denied' : 'nodevice';
		}
	}

	async function loadDevices(): Promise<void> {
		try {
			audioInputs = await Room.getLocalDevices('audioinput');
			videoInputs = await Room.getLocalDevices('videoinput');
		} catch {
			audioInputs = [];
			videoInputs = [];
		}
	}

	onMount(() => {
		void acquirePreview().then(loadDevices);
		void pickVideoCodec().then((c) => {
			codec = c;
			probing = false;
			// blurSupported depends on codec, which only just resolved — the
			// preview may already be running on the plain srcObject path.
			void refreshBlurPreview();
		});
	});

	onDestroy(() => {
		stopPreview();
	});

	function toggleMic(): void {
		micOn = !micOn;
		applyTrackEnabled();
	}
	function toggleCam(): void {
		camOn = !camOn;
		applyTrackEnabled();
	}

	function join(): void {
		savePrefs({ micOn, camOn, audioDeviceId, videoDeviceId });
		stopPreview();
		onJoin({ micOn, camOn, codec, audioDeviceId, videoDeviceId, blurEnabled: blurOn });
	}

	/** design #1: receive-only is ALWAYS possible, from either failure state. */
	function joinReceiveOnly(): void {
		micOn = false;
		camOn = false;
		savePrefs({ micOn, camOn, audioDeviceId, videoDeviceId });
		onJoin({ micOn: false, camOn: false, codec, audioDeviceId, videoDeviceId, blurEnabled: blurOn });
	}
</script>

<div class="prejoin">
	<div class="prejoin__preview" data-testid="prejoin-preview">
		{#if camOn && deviceState === 'granted' && previewStream}
			<!-- svelte-ignore a11y_media_has_caption -->
			<video bind:this={videoEl} autoplay muted playsinline class="prejoin__video"></video>
		{:else}
			<div class="prejoin__preview-placeholder">
				<Icon name="VideoOff" size={28} />
			</div>
		{/if}
	</div>

	{#if deviceState === 'denied'}
		<div class="prejoin__notice" role="alert">
			<p>{t('meet.prejoin.deniedTitle')}</p>
			<p class="prejoin__notice-hint">{t('meet.prejoin.deniedHint')}</p>
			<Button variant="secondary" onclick={joinReceiveOnly}>{t('meet.prejoin.joinReceiveOnly')}</Button>
		</div>
	{:else if deviceState === 'nodevice'}
		<div class="prejoin__notice" role="alert">
			<p>{t('meet.prejoin.nodeviceTitle')}</p>
			<Button variant="secondary" onclick={joinReceiveOnly}>{t('meet.prejoin.joinReceiveOnly')}</Button>
		</div>
	{/if}

	<div class="prejoin__controls">
		<Button
			variant={micOn ? 'secondary' : 'ghost'}
			aria-pressed={micOn}
			onclick={toggleMic}
			disabled={deviceState !== 'granted'}
		>
			<Icon name={micOn ? 'Mic' : 'MicOff'} size={16} />
			{micOn ? t('meet.controls.micOn') : t('meet.controls.micOff')}
		</Button>
		<Button
			variant={camOn ? 'secondary' : 'ghost'}
			aria-pressed={camOn}
			onclick={toggleCam}
			disabled={deviceState !== 'granted'}
		>
			<Icon name={camOn ? 'Video' : 'VideoOff'} size={16} />
			{camOn ? t('meet.controls.camOn') : t('meet.controls.camOff')}
		</Button>
		{#if blurSupported}
			<Button
				variant={blurOn ? 'secondary' : 'ghost'}
				aria-pressed={blurOn}
				onclick={toggleBlur}
				disabled={deviceState !== 'granted'}
			>
				<Icon name="Sparkles" size={16} />
				{blurOn ? t('meet.prejoin.blurOn') : t('meet.prejoin.blurOff')}
			</Button>
		{/if}
	</div>

	{#if deviceState === 'granted' && (audioInputs.length > 1 || videoInputs.length > 1)}
		<div class="prejoin__devices">
			{#if audioInputs.length > 1}
				<Select
					label={t('meet.prejoin.microphone')}
					value={audioDeviceId ?? ''}
					options={audioInputs.map((d, i) => ({ value: d.deviceId, label: d.label || `Microphone ${i + 1}` }))}
					onchange={(e) => {
						audioDeviceId = (e.currentTarget as HTMLSelectElement).value || null;
						void acquirePreview();
					}}
				/>
			{/if}
			{#if videoInputs.length > 1}
				<Select
					label={t('meet.prejoin.camera')}
					value={videoDeviceId ?? ''}
					options={videoInputs.map((d, i) => ({ value: d.deviceId, label: d.label || `Camera ${i + 1}` }))}
					onchange={(e) => {
						videoDeviceId = (e.currentTarget as HTMLSelectElement).value || null;
						void acquirePreview();
					}}
				/>
			{/if}
		</div>
	{/if}

	<div class="prejoin__codec" data-testid="prejoin-codec">
		{#if probing}<Spinner size={16} />{/if}
		<span>{codecLabel}</span>
	</div>

	<Button variant="primary" size="lg" onclick={join} disabled={joining}>
		{joining ? t('common.loading') : t('meet.prejoin.join')}
	</Button>
</div>

<style>
	.prejoin {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
		align-items: stretch;
		max-width: 420px;
		margin: 0 auto;
	}
	.prejoin__preview {
		aspect-ratio: 16 / 9;
		background: var(--surface-sunken);
		border-radius: var(--radius-md);
		overflow: hidden;
		display: flex;
		align-items: center;
		justify-content: center;
	}
	.prejoin__video {
		width: 100%;
		height: 100%;
		object-fit: cover;
		transform: scaleX(-1); /* self-preview is mirrored, same as the in-room self-tile */
	}
	.prejoin__preview-placeholder {
		color: var(--text-caption);
	}
	.prejoin__notice {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		padding: var(--space-3);
		background: var(--warning-bg);
		color: var(--warning-fg);
		border-radius: var(--radius-sm);
		font-size: var(--text-sm);
	}
	.prejoin__notice-hint {
		font-size: var(--text-xs);
		opacity: 0.9;
	}
	.prejoin__controls {
		display: flex;
		gap: var(--space-2);
		justify-content: center;
	}
	.prejoin__devices {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.prejoin__codec {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		justify-content: center;
		font-size: var(--text-xs);
		color: var(--text-caption);
	}
</style>
