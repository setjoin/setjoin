<!--
  PrecedenceExplainer — read-only offline-policy resolver explainer widget.
  Shows the 3-tier layer stack, the AND-of-4 gate, and the window math.
  Pure: no network calls, takes the policy list + master-toggle as props.
-->
<svelte:options runes={true} />

<script lang="ts">
	import { t, locale } from '$lib/i18n';
	import { Badge } from '$lib/components/ui';
	import type { OfflinePolicy } from '$lib/admin/client';

	let { policies, master }: {
		policies: OfflinePolicy[];
		master: boolean;
	} = $props();

	$locale; // reactive on locale switch

	const uid = $props.id();
	const contentId = `sj-explainer-${uid}`;

	// persist collapse in localStorage; default open
	const STORAGE_KEY = 'sj.offline.explainer.collapsed';
	let collapsed = $state(
		typeof localStorage !== 'undefined'
			? localStorage.getItem(STORAGE_KEY) === 'true'
			: false
	);

	// ponytail: reduced-motion check here so the parent's test stub applies
	const reducedMotion = $derived(
		typeof window !== 'undefined' && window.matchMedia != null
			? window.matchMedia('(prefers-reduced-motion: reduce)').matches
			: false
	);

	// highest-priority enabled policy = the effective layer
	const effectiveLayer = $derived(
		[...policies]
			.filter((p) => p.enabled)
			.sort((a, b) => b.priority - a.priority)[0] ?? null
	);

	const orgOff = $derived(!master || effectiveLayer === null);

	const tiers = $derived<Array<{ type: 'user' | 'group' | 'global'; label: string }>>([
		{ type: 'user',   label: t('admin.offline.scope.user') },
		{ type: 'group',  label: t('admin.offline.scope.group') },
		{ type: 'global', label: t('admin.offline.scope.global') },
	]);

	const gatePills = $derived([
		t('admin.offline.explainer.gate_master'),
		t('admin.offline.explainer.gate_policy'),
		t('admin.offline.explainer.gate_optin'),
		t('admin.offline.explainer.gate_device'),
	]);

	function toggle() {
		collapsed = !collapsed;
		try { localStorage.setItem(STORAGE_KEY, String(collapsed)); } catch { /* ignore */ }
	}
</script>

<div class="sj-explainer">
	<button
		type="button"
		class="sj-explainer__toggle"
		aria-expanded={!collapsed}
		aria-controls={contentId}
		onclick={toggle}
	>
		{t('admin.offline.explainer.title')}
		<span class="sj-explainer__chevron" aria-hidden="true">{collapsed ? '▶' : '▼'}</span>
	</button>

	{#if !collapsed}
		<div
			id={contentId}
			class="sj-explainer__body"
			style={reducedMotion ? 'transition: none; animation: none' : ''}
		>
			<!-- Layer stack -->
			<div class="sj-explainer__stack" class:sj-explainer__stack--dim={orgOff}>
				{#if orgOff}
					<div class="sj-explainer__org-off">
						<Badge variant="neutral" label={t('admin.offline.explainer.off_org')} />
					</div>
				{/if}
				{#each tiers as tier, i}
					{@const isEffective = !orgOff && effectiveLayer?.scope_type === tier.type}
					<div
						class="sj-explainer__layer"
						class:sj-explainer__layer--active={isEffective}
					>
						<span class="sj-explainer__tier-label">{tier.label}</span>
						{#if isEffective}
							<Badge variant="accent" label={t('admin.offline.explainer.effective')} />
						{/if}
					</div>
					{#if i < tiers.length - 1}
						<span class="sj-explainer__wins" aria-hidden="true">
							↓ {t('admin.offline.explainer.wins')}
						</span>
					{/if}
				{/each}
			</div>

			<!-- AND-of-4 gate -->
			<div class="sj-explainer__gate">
				{#each gatePills as pill, i}
					{#if i > 0}
						<span class="sj-explainer__and" aria-hidden="true">{t('admin.offline.explainer.and')}</span>
					{/if}
					<Badge variant="neutral" label={pill} />
				{/each}
			</div>
			<p class="sj-explainer__gate-caption">{t('admin.offline.explainer.gate_caption')}</p>

			<!-- Window math -->
			<p class="sj-explainer__window-math">{t('admin.offline.explainer.window_math')}</p>
		</div>
	{/if}
</div>

<style>
	.sj-explainer {
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-md);
		background: var(--surface-card);
		font-family: var(--font-sans);
		font-size: var(--text-sm);
	}
	.sj-explainer__toggle {
		width: 100%;
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 10px 14px;
		background: none;
		border: none;
		cursor: pointer;
		font: inherit;
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
		text-align: start;
	}
	.sj-explainer__toggle:focus-visible {
		outline: var(--focus-ring);
	}
	.sj-explainer__chevron {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}
	.sj-explainer__body {
		padding: 12px 14px;
		border-top: 1px solid var(--border-subtle);
		display: flex;
		flex-direction: column;
		gap: 12px;
	}
	.sj-explainer__stack {
		display: flex;
		flex-direction: column;
		gap: 4px;
	}
	.sj-explainer__stack--dim {
		opacity: 0.55;
	}
	.sj-explainer__org-off {
		margin-bottom: 4px;
	}
	.sj-explainer__layer {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 6px 8px;
		border-radius: var(--radius-sm);
		border-inline-start: 3px solid transparent;
	}
	.sj-explainer__layer--active {
		background: var(--accent-subtle);
		border-inline-start-color: var(--accent);
	}
	.sj-explainer__tier-label {
		color: var(--text-primary);
		font-weight: var(--weight-medium);
	}
	.sj-explainer__wins {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		padding-inline-start: 8px;
	}
	.sj-explainer__gate {
		display: flex;
		align-items: center;
		flex-wrap: wrap;
		gap: 6px;
	}
	.sj-explainer__and {
		font-size: var(--text-xs);
		font-weight: var(--weight-semibold);
		color: var(--text-tertiary);
	}
	.sj-explainer__gate-caption,
	.sj-explainer__window-math {
		margin: 0;
		font-size: var(--text-xs);
		color: var(--text-caption);
	}
</style>
