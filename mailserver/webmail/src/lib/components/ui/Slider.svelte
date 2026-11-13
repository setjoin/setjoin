<svelte:options runes={true} />

<script lang="ts">
	interface Props {
		label: string;
		value: number;
		stops: string[];
		oninput?: (index: number) => void;
		/** 'danger' = chosen window overflows free space; flips the track to --danger-solid. */
		tone?: 'normal' | 'danger';
		/** Inert when the native cache is unprovisioned / caps.offline.allowed is falsy. */
		disabled?: boolean;
		/** id of the live estimate line so SR users hear "≈ X needed vs Y free". */
		describedById?: string;
	}
	let {
		label,
		value = $bindable(0),
		stops,
		oninput,
		tone = 'normal',
		disabled = false,
		describedById
	}: Props = $props();

	function handleInput(e: Event) {
		if (disabled) return;
		const idx = Number((e.currentTarget as HTMLInputElement).value);
		value = idx;
		oninput?.(idx);
	}
</script>

<div
	class="sj-slider"
	class:sj-slider--danger={tone === 'danger'}
	class:sj-slider--disabled={disabled}
	data-tone={tone}
>
	<input
		type="range"
		min="0"
		max={stops.length - 1}
		step="1"
		{value}
		{disabled}
		aria-label={label}
		aria-valuetext={stops[value]}
		aria-disabled={disabled}
		aria-describedby={describedById}
		oninput={handleInput}
	/>
	<div class="sj-slider-stops" aria-hidden="true">
		{#each stops as stop, i}
			<span class="sj-slider-stop" class:sj-slider-stop-active={i === value}>{stop}</span>
		{/each}
	</div>
</div>

<style>
	.sj-slider {
		display: flex;
		flex-direction: column;
		gap: var(--space-2, 6px);
	}
	.sj-slider input[type='range'] {
		width: 100%;
		accent-color: var(--accent);
		cursor: pointer;
		/* tone/disabled cross-fade — honors reduced-motion below */
		transition: accent-color var(--duration-fast) var(--ease-out);
		/* visible focus ring on keyboard focus (matches the M1 primitives) */
	}
	.sj-slider-stop {
		transition: color var(--duration-fast) var(--ease-out);
	}
	/* reduced-motion: instant swap (mirrors Spinner/Dialog) */
	@media (prefers-reduced-motion: reduce) {
		.sj-slider input[type='range'],
		.sj-slider-stop {
			transition: none;
		}
	}
	.sj-slider input[type='range']:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
		border-radius: var(--radius-full);
	}
	/* OVERFLOW / DANGER: the load-bearing "won't fit" state. */
	.sj-slider--danger input[type='range'] {
		accent-color: var(--danger-solid);
	}
	/* Thumb ring survives Windows High Contrast / forced-color (OS overrides accent-color). */
	.sj-slider--danger input[type='range']::-webkit-slider-thumb {
		box-shadow: 0 0 0 1px var(--danger-fg);
	}
	.sj-slider--danger input[type='range']::-moz-range-thumb {
		box-shadow: 0 0 0 1px var(--danger-fg);
	}
	.sj-slider--danger .sj-slider-stop-active {
		color: var(--danger-fg);
	}
	/* DISABLED / INERT (caps-absent): desaturate, never-allowed cursor. */
	.sj-slider--disabled input[type='range'] {
		accent-color: var(--border-default);
		cursor: not-allowed;
	}
	.sj-slider--disabled .sj-slider-stop {
		color: var(--text-disabled);
	}
	.sj-slider-stops {
		display: flex;
		justify-content: space-between;
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}
	.sj-slider-stop-active {
		color: var(--text-accent);
		font-weight: var(--weight-semibold);
	}
	/* RESPONSIVE: enlarge the touch target on coarse pointers (native mobile shell). */
	/* ponytail: native input[type=range] handles all keyboard (arrows/home/end/pageup) for free */
	@media (pointer: coarse) {
		.sj-slider input[type='range'] {
			height: 44px; /* ≥44px thumb hit target; visual thumb stays ~20px */
		}
	}
</style>
