<!-- PolicyTraceRow.svelte — one row of an ordered CA policy-evaluation trace.
     Used identically by Simulate + Why pages (§4, §5c design).
     ponytail: no local state — pure props-in, display-out. All heavy lifting in parents. -->
<svelte:options runes={true} />

<script lang="ts">
	import { t } from '$lib/i18n';
	import OutcomeChip from './OutcomeChip.svelte';

	export interface TraceRow {
		policy_id: number;
		priority: number;
		policy_name: string;
		scope_type?: string;
		outcome: string;           // applied | would_block | would_step_up | would_notify | skipped | excluded
		first_failed_key?: string; // e.g. 'country_in'
		first_failed_detail?: string; // e.g. 'RU ∉ {US, CA}'
		matched?: boolean;         // true for the deciding row
	}

	interface Props {
		row: TraceRow;
		/** href for the policy name link (optional — omit if no editor access). */
		policyHref?: string;
	}

	let { row, policyHref }: Props = $props();

	// Resolve human label for the condition key from i18n; fall back to raw key.
	// ponytail: one lookup, no local map.
	const conditionLabel = $derived(
		row.first_failed_key
			? t(`admin.conditional_access.trace.condition.${row.first_failed_key}`)
			: ''
	);

	// Long names truncate to ellipsis — title attr carries full value for mouse hover.
	// (SR: OutcomeChip aria-label and PolicyName link label cover meaning.)
</script>

<!-- <li> semantics — caller must wrap in <ol aria-label="…">. -->
<li
	class="ptr"
	class:ptr--matched={row.matched}
	data-testid="trace-row"
	data-outcome={row.outcome}
>
	<!-- Priority mono badge -->
	<span class="ptr__priority" aria-hidden="true">{row.priority}</span>

	<!-- Policy name — link when href given, else plain span -->
	{#if policyHref}
		<a
			href={policyHref}
			class="ptr__name"
			title={row.policy_name}
			data-testid="trace-row-name-link"
		>{row.policy_name}</a>
	{:else}
		<span class="ptr__name" title={row.policy_name} data-testid="trace-row-name">{row.policy_name}</span>
	{/if}

	<!-- Scope chip (inline text, not a full Badge to keep the row light) -->
	{#if row.scope_type}
		<span class="ptr__scope" aria-hidden="true">{row.scope_type}</span>
	{/if}

	<!-- OutcomeChip (keyboard-reachable tooltip via Tooltip.svelte) -->
	<span class="ptr__chip"><OutcomeChip outcome={row.outcome} size="sm" /></span>

	<!-- First-failed reason (skipped/excluded rows only) — plain text, not color-only -->
	{#if row.outcome === 'excluded'}
		<span class="ptr__reason" data-testid="trace-row-reason">
			{t('admin.conditional_access.trace.on_exclude_list')}
		</span>
	{:else if row.first_failed_key}
		<!-- Human condition label + raw key in mono for the technical reader -->
		<span class="ptr__reason" data-testid="trace-row-reason">
			<!-- i18n: "first failed:" prefix -->
			{t('admin.conditional_access.trace.first_failed', { condition: conditionLabel })}
			{#if row.first_failed_detail}
				<!-- raw key in mono = technical segment (a11y: plain text carries meaning) -->
				<code class="ptr__raw" data-testid="trace-row-raw">(<code class="ptr__key">{row.first_failed_key}</code>: {row.first_failed_detail})</code>
			{/if}
		</span>
	{/if}
</li>

<style>
	.ptr {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 7px 10px;
		border-radius: var(--radius-sm);
		/* row enter: fast fade-in — §(z) motion requirement */
		transition: background var(--duration-fast) var(--ease-out);
		/* logical inline-start for RTL mirror — §(z) */
		border-inline-start: 3px solid transparent;
		list-style: none;
		flex-wrap: wrap;
	}

	/* The deciding/matched row: surface-selected bg + accent left-rail — §4 */
	.ptr--matched {
		background: var(--surface-selected);
		border-inline-start-color: var(--accent);
	}

	.ptr__priority {
		font-family: var(--font-mono);
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		min-width: 24px;
		text-align: end;
		flex: none;
	}

	.ptr__name {
		font-size: var(--text-sm);
		color: var(--text-primary);
		font-weight: var(--weight-medium);
		/* long names truncate — §(z) */
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		min-width: 0;
		flex: 1 1 120px;
		text-decoration: none;
	}
	.ptr__name:hover { text-decoration: underline; }
	a.ptr__name { color: var(--accent); }

	.ptr__scope {
		font-size: var(--text-2xs);
		color: var(--text-tertiary);
		background: var(--gray-100);
		padding: 1px 6px;
		border-radius: var(--radius-full);
		white-space: nowrap;
		flex: none;
	}

	.ptr__chip {
		flex: none;
	}

	.ptr__reason {
		font-size: var(--text-xs);
		color: var(--text-secondary);
		flex: 1 1 100%;       /* wraps below when row is narrow */
		padding-inline-start: calc(24px + 8px); /* indent under name */
		min-width: 0;
	}

	.ptr__raw {
		font-family: var(--font-mono);
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}

	/* Bold the raw condition key — §4 "key bolded" */
	.ptr__key {
		font-weight: var(--weight-semibold);
		font-family: var(--font-mono);
		color: var(--text-primary);
	}

	@media (prefers-reduced-motion: reduce) {
		.ptr {
			transition: none;
		}
	}

	/* Touch: row isn't itself a tap target, but the link/chip inside are. */
	@media (pointer: coarse) {
		.ptr {
			padding: 10px;
		}
	}
</style>
