<!-- OutcomeChip.svelte — shared 6-value CA decision vocabulary chip.
     Source of truth: retired-docs:superpowers/specs/2026-06-23-design-system-additions.md §1
     Reuses: OUTCOME_LEGEND / outcomeChip from admin/signin-trace.ts (single-source map).
     ponytail: wraps M1 Badge; no hand-rolled pill — just icon + Badge + count mono suffix. -->
<svelte:options runes={true} />

<script lang="ts">
	import { Badge, Tooltip } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';
	import { outcomeChip, type OutcomeMeta } from '$lib/components/admin/signin-trace';

	interface Props {
		outcome: string;
		size?: 'sm' | 'md';
		count?: number;
	}

	let { outcome, size = 'md', count }: Props = $props();

	// ponytail: $derived — one reactive lookup from the single-source map.
	const meta: OutcomeMeta = $derived(outcomeChip(outcome));

	// Unknown/forward-compat: use the raw value as the label (§1).
	const label = $derived(
		outcome === 'unknown' || !(outcome in _KNOWN)
			? (meta.key === 'ca.outcome.unknown' ? outcome : t(meta.key))
			: t(meta.key)
	);

	// For aria-label: use the per-outcome aria key when available, else fall back to tip text.
	const ariaKey = $derived(
		`${meta.key}.aria` in _ARIA_KEYS ? `${meta.key}.aria` : meta.tip
	);
	const ariaLabel = $derived(
		count !== undefined
			? t(ariaKey, { count: String(count) })
			: t(ariaKey)
	);

	// Display count as mono suffix when set.
	const countSuffix = $derived(count !== undefined ? `· ${count}` : '');

	// Tooltip text from the tip key.
	const tipText = $derived(t(meta.tip));
</script>

<!-- ponytail: known-outcomes check uses the OUTCOME_LEGEND set, not a local list. -->
<script lang="ts" module>
	import { OUTCOME_LEGEND } from '$lib/components/admin/signin-trace';
	const _KNOWN = Object.fromEntries(OUTCOME_LEGEND.map((o) => [o.outcome, true]));
	const _ARIA_KEYS: Record<string, true> = {
		'ca.outcome.applied.aria': true,
		'ca.outcome.would_block.aria': true,
	};
</script>

<Tooltip text={tipText}>
	<!-- role=img: chip is presentational, non-interactive (§1). Never role=button. -->
	<span
		role="img"
		aria-label={ariaLabel}
		class="outcome-chip"
		class:outcome-chip--sm={size === 'sm'}
		class:outcome-chip--excluded={outcome === 'excluded'}
		data-outcome={outcome}
	>
		<!-- Icon: aria-hidden, decorative (§1 WCAG 1.4.1 — label+icon, never icon-alone). -->
		<span aria-hidden="true" class="outcome-chip__icon" data-icon={meta.icon}>
			<Icon name={meta.icon as never} size={size === 'sm' ? 12 : 14} />
		</span>
		<Badge variant={meta.variant} label={label} />
		{#if countSuffix}
			<span class="outcome-chip__count" aria-hidden="true">{countSuffix}</span>
		{/if}
	</span>
</Tooltip>

<style>
	/* ponytail: chip is a flex wrapper — Badge already has the pill shape.
	   No entrance animation (chips appear with their row — §1).
	   Reduced-motion: tooltip fade handled by Tooltip.svelte; we guard here too. */
	.outcome-chip {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		/* no transition/animation on the chip itself — §1 */
	}

	.outcome-chip--excluded :global(.badge) {
		/* dashed border = "outside the rule" even in grayscale — §1/WCAG 1.4.1 */
		border: 1px dashed var(--border-strong);
	}

	.outcome-chip__icon {
		display: inline-flex;
		align-items: center;
		flex: none;
	}

	.outcome-chip__count {
		font-family: var(--font-mono);
		font-size: var(--text-2xs);
		color: var(--text-secondary);
	}

	@media (prefers-reduced-motion: reduce) {
		/* Tooltip fade handled in Tooltip.svelte; guard here for any future local animation. */
		.outcome-chip {
			transition: none;
			animation: none;
		}
	}
</style>
