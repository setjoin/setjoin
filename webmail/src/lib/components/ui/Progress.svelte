<svelte:options runes={true} />

<script lang="ts">
	let {
		value,
		max = 100,
		label,
		indeterminate = false
	}: {
		value: number;
		max?: number;
		label: string;
		/** Unknown-duration phase (e.g. hashing before an upload): animated sweep, no aria-valuenow. */
		indeterminate?: boolean;
	} = $props();

	const clamped = $derived(Math.min(Math.max(value, 0), max));
	const pct = $derived(max > 0 ? (clamped / max) * 100 : 0);
</script>

<div
	class="sj-progress"
	role="progressbar"
	aria-valuemin={0}
	aria-valuemax={max}
	aria-valuenow={indeterminate ? undefined : clamped}
	aria-label={label}
>
	{#if indeterminate}
		<div class="sj-progress__fill sj-progress__fill--indeterminate"></div>
	{:else}
		<div class="sj-progress__fill" style:width="{pct}%"></div>
	{/if}
</div>

<style>
	.sj-progress {
		width: 100%;
		height: 4px;
		border-radius: var(--radius-full);
		background: var(--gray-100);
		overflow: hidden;
		position: relative;
	}
	.sj-progress__fill {
		height: 100%;
		border-radius: var(--radius-full);
		background: var(--accent);
		transition: width var(--duration-base) var(--ease-out);
	}
	.sj-progress__fill--indeterminate {
		position: absolute;
		width: 40%;
		animation: sj-progress-sweep 1.2s ease-in-out infinite;
	}

	@keyframes sj-progress-sweep {
		0% { left: -40%; }
		100% { left: 100%; }
	}

	@media (prefers-reduced-motion: reduce) {
		.sj-progress__fill--indeterminate {
			animation: none;
			left: 0;
			width: 100%;
			opacity: 0.4;
		}
	}
</style>
