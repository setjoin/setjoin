<svelte:options runes={true} />

<script lang="ts">
	// Native-shell MAM watermark (§10): a TILED, pointer-events:none, aria-hidden overlay
	// of the user's identity over the offline reading pane's full scroll height. This DOM
	// tier deters screenshots (tiled so a cropped region is still stamped); the native
	// WebView shell (Task 12) adds the REAL overlay above the WebView + ScreenCapture
	// blocking (FLAG_SECURE / isCaptured) via window.setjoinNative. Offline is native-only,
	// so this never renders in a plain browser (the caller gates `enabled` on isNative()
	// && caps.offline.watermark). Theme-safe: --text-primary at low opacity inverts in dark.
	let { enabled = false, userEmail = '' }: { enabled?: boolean; userEmail?: string } = $props();
	const stamp = $derived(`${userEmail} · ${new Date().toISOString().slice(0, 10)}`);
	// ponytail: 120 repetitions tile a tall email; CSS flex-wrap lays them diagonally.
	// Ceiling: for extreme-length emails the pattern repeats from the top (still stamped).
	const tiles = Array.from({ length: 120 });
</script>

{#if enabled}
	<!-- ponytail: inline pointer-events/user-select so jsdom getComputedStyle sees them;
	     aria-hidden=true because this is a non-content, non-interactive visual deterrent. -->
	<div
		class="watermark"
		aria-hidden="true"
		style="pointer-events: none; user-select: none"
	>
		{#each tiles as _}
			<span class="watermark__text">{stamp}</span>
		{/each}
	</div>
{/if}

<style>
	.watermark {
		position: absolute;
		inset: 0;
		overflow: hidden;
		/* tile the stamps diagonally across the full height of the scrolling content */
		display: flex;
		flex-wrap: wrap;
		align-content: flex-start;
		gap: 90px 60px;
		padding: 40px;
		transform: rotate(-30deg) scale(1.6); /* cover the corners after rotation */
		transform-origin: center;
		z-index: var(--z-overlay, 100);
	}

	.watermark__text {
		flex: 0 0 auto;
		font-size: var(--text-sm);
		font-family: var(--font-sans);
		/* theme-safe: primary text at very low opacity reads on screenshot, faint on screen,
		   and inverts correctly in dark theme (unlike a fixed muted gray that can vanish). */
		color: var(--text-primary);
		opacity: 0.07;
		white-space: nowrap;
	}

	@media (prefers-contrast: more) {
		.watermark__text { opacity: 0.14; }
	}
</style>
