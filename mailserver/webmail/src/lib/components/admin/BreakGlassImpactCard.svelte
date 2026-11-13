<svelte:options runes={true} />
<!--
  BreakGlassImpactCard — pre-flight impact card shown in the policy form BEFORE save.
  Computed client-side from the current form + loaded break-glass set.
  Hidden unless form is: state=on or state=report_only, with global scope + block/step_up action.

  Props:
    state          'off'|'report_only'|'on'   — current form state
    scopeType      string                       — form scope_type
    action         string                       — form action
    remaining      number                       — admins remaining reachable (from preflightImpact)
    loading        boolean                      — true while break-glass is loading
    selfId?        number                       — current admin's user id (for "including you" copy)
    excludeUserIds number[]                     — resolved user ids in the exclusion set
-->
<script lang="ts">
	import { t } from '$lib/i18n';

	let {
		state,
		scopeType,
		action,
		remaining,
		loading = false,
		selfId,
		excludeUserIds = [],
	}: {
		state: string;
		scopeType: string;
		action: string;
		remaining: number;
		loading?: boolean;
		selfId?: number;
		excludeUserIds?: number[];
	} = $props();

	// Show only when scope=global + action ∈ {block,step_up}
	const isGlobalBlock = $derived(
		scopeType === 'global' && (action === 'block' || action === 'step_up')
	);
	const show = $derived(isGlobalBlock && (state === 'on' || state === 'report_only'));

	// Determine severity
	const isRejectState = $derived(state === 'on' && remaining === 0);
	const selfExcluded = $derived(selfId !== undefined && excludeUserIds.includes(selfId));
</script>

{#if show}
	<div
		class="impact-card"
		class:impact-card--danger={state === 'on' && remaining === 0}
		class:impact-card--ok={state === 'on' && remaining > 0}
		class:impact-card--neutral={state === 'report_only'}
		data-testid="impact-card"
	>
		{#if loading}
			<!-- Loading shimmer -->
			<div class="impact-card__shimmer" aria-busy="true">
				<span class="sr-only">{t('admin.ca.list.loading')}</span>
				<div class="impact-card__skel"></div>
			</div>
		{:else if state === 'report_only'}
			<p class="impact-card__body" data-testid="impact-card-report-only">
				{t('admin.ca.impact.report_only')}
			</p>
		{:else}
			<!-- on state: show remaining count with aria-live so screen reader announces changes -->
			<div aria-live="polite" aria-atomic="true" class="impact-card__count-region">
				{#if isRejectState}
					<p
						class="impact-card__count impact-card__count--danger"
						data-testid="impact-card-reject"
					>
						{t('admin.ca.impact.reject')}
					</p>
				{:else}
					<p
						class="impact-card__count impact-card__count--ok"
						data-testid="impact-card-ok"
					>
						{selfExcluded
							? t('admin.ca.promote.impact_you', { n: String(remaining) })
							: t('admin.ca.impact.ok', { n: String(remaining) })}
					</p>
				{/if}
			</div>
		{/if}
	</div>
{/if}

<style>
	.impact-card {
		border-radius: var(--radius-sm);
		padding: 10px 14px;
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		border: 1px solid transparent;
		transition: background var(--duration-base) var(--ease-out),
			border-color var(--duration-base) var(--ease-out);
	}

	.impact-card--danger {
		background: var(--danger-bg);
		border-color: var(--danger-fg);
		color: var(--danger-fg);
	}

	.impact-card--ok {
		background: var(--success-bg);
		border-color: var(--success-solid);
		color: var(--success-fg);
	}

	.impact-card--neutral {
		background: var(--gray-100);
		border-color: var(--border-default);
		color: var(--text-secondary);
	}

	.impact-card__body {
		margin: 0;
	}

	.impact-card__count {
		margin: 0;
		font-weight: var(--weight-semibold);
		font-size: var(--text-md);
		/* color cross-fade for danger flip */
		transition: color var(--duration-base) var(--ease-out);
	}

	.impact-card__count--danger {
		color: var(--danger-fg);
	}

	.impact-card__count--ok {
		color: var(--success-fg);
	}

	/* Loading shimmer */
	.impact-card__shimmer {
		padding: 10px 14px;
		border-radius: var(--radius-sm);
		background: var(--surface-sunken);
		overflow: hidden;
		position: relative;
	}
	.impact-card__skel {
		height: 18px;
		border-radius: var(--radius-xs);
		background: linear-gradient(90deg, var(--gray-100) 25%, var(--gray-200) 50%, var(--gray-100) 75%);
		background-size: 400% 100%;
		animation: impact-shimmer var(--duration-slow) ease-in-out infinite;
	}

	.sr-only {
		position: absolute;
		width: 1px;
		height: 1px;
		padding: 0;
		margin: -1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
		border: 0;
	}

	@keyframes impact-shimmer {
		0% { background-position: 100% 50%; }
		100% { background-position: 0% 50%; }
	}

	@media (prefers-reduced-motion: reduce) {
		.impact-card,
		.impact-card__count {
			transition: none;
		}
		.impact-card__skel {
			animation: none;
		}
	}
</style>
