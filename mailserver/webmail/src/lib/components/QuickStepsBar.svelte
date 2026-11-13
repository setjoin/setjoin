<svelte:options runes={true} />

<script lang="ts">
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';
	import type { QuickStep } from '$lib/types/jmap';

	let {
		quickSteps = [],
		onApply,
		applying = null,
	}: {
		quickSteps: QuickStep[];
		onApply: (id: string) => void;
		/** Id of the quick step currently running (disables its button). */
		applying?: string | null;
	} = $props();
</script>

{#if quickSteps.length > 0}
	<div class="sj-quicksteps" role="group" aria-label={t('quickSteps.bar_label')}>
		{#each quickSteps as qs (qs.id)}
			<button
				class="sj-quicksteps__btn"
				disabled={applying === qs.id}
				onclick={() => onApply(qs.id)}
			>
				<Icon name={(qs.icon || 'Zap') as never} size={14} strokeWidth={1.75} />
				<span class="sj-quicksteps__label">{qs.name}</span>
			</button>
		{/each}
	</div>
{/if}

<style>
	.sj-quicksteps {
		display: flex;
		flex-wrap: wrap;
		gap: 6px;
		align-items: center;
	}

	.sj-quicksteps__btn {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		height: 26px;
		padding: 0 10px;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		background: var(--surface-card);
		color: var(--text-secondary);
		font-family: var(--font-sans);
		font-size: var(--text-xs);
		font-weight: var(--weight-medium);
		cursor: pointer;
	}

	.sj-quicksteps__btn:hover {
		border-color: var(--accent);
		color: var(--accent);
		background: var(--surface-hover);
	}

	.sj-quicksteps__btn:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	.sj-quicksteps__btn:disabled {
		opacity: 0.5;
		cursor: default;
	}

	.sj-quicksteps__label {
		white-space: nowrap;
	}
</style>
