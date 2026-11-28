<!-- OutcomeLegend.svelte — inline strip of all 6 outcome chips with one-liner meanings.
     Placed once at the top of Why / Simulate / Coverage so the colour code is taught before use.
     ponytail: iterates OUTCOME_LEGEND (single-source) — no local copy. -->
<svelte:options runes={true} />

<script lang="ts">
	import { t } from '$lib/i18n';
	import { OUTCOME_LEGEND } from '$lib/components/admin/signin-trace';
	import OutcomeChip from './OutcomeChip.svelte';
</script>

<!-- SR landmark so screen readers get a named section (§1). -->
<h2 class="sr-only">{t('ca.outcome.legend_title')}</h2>

<div class="outcome-legend" role="list" aria-label={t('ca.outcome.legend_title')}>
	{#each OUTCOME_LEGEND as o (o.outcome)}
		<span class="outcome-legend__item" role="listitem">
			<OutcomeChip outcome={o.outcome} />
			<!-- one-liner meaning — visible, not just a tooltip (§1) -->
			<span class="outcome-legend__meaning">{t(o.tip)}</span>
		</span>
	{/each}
</div>

<style>
	.outcome-legend {
		display: flex;
		flex-wrap: wrap;
		gap: 8px 16px;
		align-items: flex-start;
		padding: 8px 0;
	}

	.outcome-legend__item {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		white-space: nowrap;
	}

	.outcome-legend__meaning {
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}

	/* Collapse to 2-col grid under 640px (§1). */
	@media (max-width: 640px) {
		.outcome-legend {
			display: grid;
			grid-template-columns: 1fr 1fr;
		}
		.outcome-legend__item {
			white-space: normal;
			flex-wrap: wrap;
		}
	}

	.sr-only {
		position: absolute;
		width: 1px; height: 1px;
		padding: 0; margin: -1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
		border: 0;
	}
</style>
