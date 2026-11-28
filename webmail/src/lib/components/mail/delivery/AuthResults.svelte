<svelte:options runes={true} />
<script lang="ts">
	import Badge from '$lib/components/ui/Badge.svelte';
	import Icon from '$lib/components/Icon.svelte';
	import type { AuthResults as AuthResultsType } from '$lib/types/delivery';

	let { auth }: { auth?: AuthResultsType } = $props();

	interface Chip {
		name: string;
		result: string;
		variant: 'success' | 'warning' | 'danger' | 'neutral';
		icon: 'ShieldCheck' | 'ShieldAlert' | 'ShieldBan' | 'Shield';
	}

	function resultVariant(r: string): Chip['variant'] {
		if (r === 'pass') return 'success';
		if (r === 'fail' || r === 'reject') return 'danger';
		if (r === 'softfail' || r === 'neutral' || r === 'temperror' || r === 'permerror') return 'warning';
		return 'neutral';
	}

	function resultIcon(r: string): Chip['icon'] {
		if (r === 'pass') return 'ShieldCheck';
		if (r === 'fail' || r === 'reject') return 'ShieldBan';
		if (r === 'softfail' || r === 'neutral') return 'ShieldAlert';
		return 'Shield';
	}

	const chips = $derived<Chip[]>(
		auth
			? (['spf', 'dkim', 'dmarc', 'arc'] as const)
				.filter((k) => auth[k] != null)
				.map((k) => {
					const val = auth[k]!;
					return {
						name: k.toUpperCase(),
						result: val.result,
						variant: resultVariant(val.result),
						icon: resultIcon(val.result),
					};
				})
			: []
	);
</script>

<div class="auth-results">
	{#if chips.length > 0}
		<div class="auth-results__chips">
			{#each chips as chip (chip.name)}
				<div class="auth-chip">
					<Icon name={chip.icon} size={14} />
					<span class="auth-chip__name">{chip.name}</span>
					<Badge variant={chip.variant} dot label={chip.result} />
				</div>
			{/each}
		</div>
	{:else}
		<p class="auth-results__empty">Authentication results not available</p>
	{/if}
</div>

<style>
	.auth-results {
		padding: var(--space-3) 0;
	}

	.auth-results__chips {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-3);
	}

	.auth-chip {
		display: flex;
		align-items: center;
		gap: var(--space-1);
		color: var(--text-secondary);
	}

	.auth-chip__name {
		font-size: var(--text-caption);
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
	}

	.auth-results__empty {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0;
	}
</style>
