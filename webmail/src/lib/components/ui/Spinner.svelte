<svelte:options runes={true} />

<script lang="ts">
	let {
		size = 20,
		label = 'Loading'
	}: {
		size?: 16 | 20 | 28;
		label?: string;
	} = $props();
</script>

<span class="sj-spinner sj-spinner--{size}" role="status" aria-label={label}></span>

<style>
	.sj-spinner {
		display: inline-block;
		flex: none;
		border: 2px solid var(--border-default);
		border-top-color: var(--accent);
		border-radius: var(--radius-full);
		animation: sj-spin 0.8s linear infinite;
	}
	.sj-spinner--16 {
		width: 16px;
		height: 16px;
	}
	.sj-spinner--20 {
		width: 20px;
		height: 20px;
	}
	.sj-spinner--28 {
		width: 28px;
		height: 28px;
	}

	@keyframes sj-spin {
		to { transform: rotate(360deg); }
	}

	@keyframes sj-pulse {
		0%, 100% { opacity: 1; }
		50% { opacity: 0.35; }
	}

	@media (prefers-reduced-motion: reduce) {
		.sj-spinner {
			animation: sj-pulse 1.6s ease-in-out infinite;
		}
	}
</style>
