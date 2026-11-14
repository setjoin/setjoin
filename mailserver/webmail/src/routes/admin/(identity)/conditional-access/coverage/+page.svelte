<!-- coverage/+page.svelte — CA coverage report: Gaps + Shadowed.
     Load-bearing: ALL-CLEAR is a success state (ShieldCheck + green tone).
     ERROR must look nothing like all-clear (no silent false-positive). §5b design.
     ponytail: no client-side filtering; server sends pre-sorted danger-first. -->
<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { adminFetch } from '$lib/admin/client';
	import { t, formatNumber } from '$lib/i18n';
	import { parseError } from '$lib/errors';
	import { Card, Badge, Button, EmptyState, Spinner } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import ImpactCard from '$lib/components/ca/ImpactCard.svelte';

	interface Gap {
		kind: 'protocol' | 'scope';
		value: string;              // protocol name or scope name
		severity: 'danger' | 'warning';
	}

	interface Shadowed {
		policy_id: number;
		policy_name: string;
		priority: number;
		shadowed_by_id: number;
		shadowed_by_name: string;
		shadowed_by_priority: number;
	}

	interface CoverageReport {
		gaps: Gap[];
		shadowed: Shadowed[];
	}

	type Phase = 'loading' | 'error' | 'empty_policies' | 'all_clear' | 'has_issues';
	let phase = $state<Phase>('loading');
	let report = $state<CoverageReport | null>(null);
	let errMsg = $state('');

	// aria-live announce — once on load §(w)
	let announce = $state('');

	onMount(() => { load(); });

	async function load() {
		phase = 'loading';
		errMsg = '';
		announce = '';
		try {
			const res = await adminFetch('/admin/conditional-access/coverage');
			if (!res.ok) throw new Error(String(res.status));
			report = await res.json() as CoverageReport;
			if (!report.gaps.length && !report.shadowed.length) {
				phase = 'all_clear';
				announce = t('admin.conditional_access.coverage.announce_clear');
			} else {
				// Check for the "no policies yet" case (server returns a sentinel gap)
				const firstPoliciesEmpty = report.gaps.length === 1 && report.gaps[0].kind === 'scope' && report.gaps[0].value === '__no_policies__';
				phase = firstPoliciesEmpty ? 'empty_policies' : 'has_issues';
				if (phase === 'has_issues') {
					announce = t('admin.conditional_access.coverage.announce', {
						gaps: formatNumber(report.gaps.length),
						shadowed: formatNumber(report.shadowed.length),
					});
				}
			}
		} catch (e) {
			errMsg = parseError(e).message;
			phase = 'error';
		}
	}
</script>

<div class="cov-page" data-testid="coverage-page">
	<header class="cov-header">
		<h1>{t('admin.conditional_access.coverage.gaps_heading')} &amp; {t('admin.conditional_access.coverage.shadowed_heading')}</h1>
	</header>

	<!-- aria-live polite — SR hears the announce text on load §(w) -->
	<span class="sr-only" role="status" data-testid="coverage-announce" aria-live="polite">{announce}</span>

	{#if phase === 'loading'}
		<!-- LOADING — section skeletons — §5b -->
		<div data-testid="loading-state" aria-busy="true">
			<div class="cov-skel-section">
				<div class="cov-skel-heading"></div>
				{#each [1, 2] as _, i (i)}
					<div class="cov-skel-card"></div>
				{/each}
			</div>
		</div>

	{:else if phase === 'error'}
		<!-- ERROR — role=alert, Retry — never show "all clear" on read error §5b load-bearing -->
		<div role="alert" data-testid="error-state" class="cov-error">
			<span>{t('admin.conditional_access.coverage.load_error')}</span>
			{#if errMsg}<span class="cov-err-detail">{errMsg}</span>{/if}
			<Button variant="secondary" size="sm" onclick={load}>{t('common.retry')}</Button>
		</div>

	{:else if phase === 'empty_policies'}
		<!-- FIRST-TIME — no policies yet; nudge to wizard (not a scary "gaps" wall) — §5b -->
		<EmptyState
			title={t('admin.conditional_access.coverage.first_policies_empty')}
		>
			{#snippet action()}
				<a class="sj-btn sj-btn--primary sj-btn--sm" href="/admin/conditional-access/templates">
					{t('admin.conditional_access.coverage.gap_fix_template')}
				</a>
			{/snippet}
		</EmptyState>

	{:else if phase === 'all_clear'}
		<!-- ALL-CLEAR — success EmptyState; ShieldCheck watermark — §5b load-bearing -->
		<div data-testid="all-clear-state" class="cov-all-clear">
			<!-- ShieldCheck via Icon.svelte (aria-hidden; text carries meaning) -->
			<span class="cov-all-clear__icon" aria-hidden="true">
				<Icon name="ShieldCheck" size={40} />
			</span>
			<p class="cov-all-clear__text">{t('admin.conditional_access.coverage.all_clear')}</p>
		</div>

	{:else if phase === 'has_issues' && report}
		<!-- HAS ISSUES — Gaps section + Shadowed section -->

		{#if report.gaps.length > 0}
			<section class="cov-section" aria-labelledby="cov-gaps-heading" data-testid="gaps-section">
				<h2 id="cov-gaps-heading" class="cov-section-heading">{t('admin.conditional_access.coverage.gaps_heading')}</h2>
				<div class="cov-gap-list">
					{#each report.gaps as gap (gap.kind + ':' + gap.value)}
						<div class="cov-gap-card" data-testid="gap-card" data-severity={gap.severity}>
							<Card>
								{#snippet children()}
								<div class="cov-gap-body">
									<!-- severity badge — text+badge, not color-only §5b -->
									<Badge
										variant={gap.severity === 'danger' ? 'danger' : 'warning'}
										label={gap.severity === 'danger'
											? t('admin.conditional_access.coverage.severity_danger')
											: t('admin.conditional_access.coverage.severity_warning')}
									/>
									<p class="cov-gap-detail">
										{gap.kind === 'protocol'
											? t('admin.conditional_access.coverage.gap_protocol', { protocol: gap.value })
											: t('admin.conditional_access.coverage.gap_scope', { scope: gap.value })}
									</p>
									<div class="cov-gap-actions">
										<a
											class="sj-btn sj-btn--primary sj-btn--sm"
											href={`/admin/conditional-access?new=1&gap_kind=${gap.kind}&gap_value=${encodeURIComponent(gap.value)}`}
										>
											{t('admin.conditional_access.coverage.gap_fix_create')}
										</a>
										<a
											class="sj-btn sj-btn--secondary sj-btn--sm"
											href="/admin/conditional-access/templates"
										>
											{t('admin.conditional_access.coverage.gap_fix_template')}
										</a>
									</div>
								</div>
								{/snippet}
							</Card>
						</div>
					{/each}
				</div>
			</section>
		{/if}

		{#if report.shadowed.length > 0}
			<section class="cov-section" aria-labelledby="cov-shadow-heading" data-testid="shadowed-section">
				<h2 id="cov-shadow-heading" class="cov-section-heading">{t('admin.conditional_access.coverage.shadowed_heading')}</h2>
				<div class="cov-shadow-list">
					{#each report.shadowed as s (s.policy_id)}
						<div class="cov-shadow-card" data-testid="shadow-card">
							<Card>
								{#snippet children()}
								<div class="cov-shadow-body">
									<Badge variant="warning" label={t('admin.conditional_access.coverage.severity_warning')} />

									<!-- Plain-English explanation — both policies named + linked §5b load-bearing -->
									<p class="cov-shadow-explain">
										{t('admin.conditional_access.coverage.shadowed_explain', {
											p: s.policy_name,
											pp: String(s.priority),
											q: s.shadowed_by_name,
											qq: String(s.shadowed_by_priority),
										})}
									</p>

									<!-- Small inline diagram: Q above P with "shadows" arrow — aria-hidden §5b -->
									<div class="cov-shadow-diagram" aria-hidden="true">
										<span class="cov-shadow-diag-chip cov-shadow-diag-chip--top">{s.shadowed_by_name}</span>
										<span class="cov-shadow-diag-arrow">↓ shadows</span>
										<span class="cov-shadow-diag-chip">{s.policy_name}</span>
									</div>

									<!-- F1 ImpactCard for shadowed policy — §brief "Consumes: ImpactCard (F1)" -->
									<ImpactCard policyId={s.policy_id} fetchData />

									<div class="cov-gap-actions">
										<a
											class="sj-btn sj-btn--secondary sj-btn--sm"
											href={`/admin/conditional-access?edit=${s.policy_id}`}
											title={s.policy_name}
										>
											{t('admin.conditional_access.coverage.edit_policy', { name: s.policy_name })}
										</a>
										<a
											class="sj-btn sj-btn--secondary sj-btn--sm"
											href={`/admin/conditional-access?edit=${s.shadowed_by_id}`}
											title={s.shadowed_by_name}
										>
											{t('admin.conditional_access.coverage.edit_policy', { name: s.shadowed_by_name })}
										</a>
									</div>
								</div>
								{/snippet}
							</Card>
						</div>
					{/each}
				</div>
			</section>
		{/if}
	{/if}
</div>

<style>
	.cov-page { max-width: 900px; }

	.cov-header {
		margin-bottom: 16px;
	}
	.cov-header h1 {
		margin: 0;
		font-size: clamp(18px, 14px + 1vw, 22px);
		font-weight: 600;
		color: var(--text-primary);
	}

	/* Error */
	.cov-error {
		display: flex;
		flex-direction: column;
		gap: 8px;
		padding: 12px 14px;
		border-radius: var(--radius-sm);
		background: var(--danger-bg);
		color: var(--danger-fg);
		font-size: var(--text-sm);
	}
	.cov-err-detail { font-size: var(--text-xs); opacity: 0.8; }

	/* All-clear */
	.cov-all-clear {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 12px;
		padding: 40px 16px;
		text-align: center;
		color: var(--success-fg);
	}
	.cov-all-clear__icon { color: var(--success-solid, var(--success-fg)); }
	.cov-all-clear__text {
		margin: 0;
		font-size: var(--text-md);
		font-weight: var(--weight-medium);
	}

	/* Sections */
	.cov-section {
		margin-bottom: 28px;
	}
	.cov-section-heading {
		font-size: var(--text-md);
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
		margin: 0 0 10px;
	}

	.cov-gap-list, .cov-shadow-list {
		display: flex;
		flex-direction: column;
		gap: 10px;
	}

	.cov-gap-body, .cov-shadow-body {
		display: flex;
		flex-direction: column;
		gap: 8px;
		padding: 2px 0;
	}

	.cov-gap-detail, .cov-shadow-explain {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-primary);
	}

	.cov-gap-actions {
		display: flex;
		gap: 8px;
		flex-wrap: wrap;
	}

	/* Shadow inline diagram */
	.cov-shadow-diagram {
		display: flex;
		flex-direction: column;
		align-items: flex-start;
		gap: 2px;
		padding: 6px 10px;
		background: var(--surface-sunken);
		border-radius: var(--radius-sm);
		font-size: var(--text-xs);
	}
	.cov-shadow-diag-chip {
		padding: 2px 8px;
		border-radius: var(--radius-full);
		background: var(--warning-bg);
		color: var(--warning-fg);
		font-size: var(--text-2xs);
		font-weight: var(--weight-medium);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		max-width: 220px;
	}
	.cov-shadow-diag-chip--top {
		background: var(--accent-subtle);
		color: var(--accent-fg-on-subtle, var(--accent));
	}
	.cov-shadow-diag-arrow {
		color: var(--text-tertiary);
		padding-inline-start: 6px;
	}

	/* Loading skeletons */
	.cov-skel-section {
		display: flex;
		flex-direction: column;
		gap: 8px;
		margin-bottom: 20px;
	}
	.cov-skel-heading {
		height: 20px;
		width: 120px;
		border-radius: var(--radius-sm);
		background: var(--gray-200);
		opacity: 0.6;
	}
	.cov-skel-card {
		height: 80px;
		border-radius: var(--radius-md);
		position: relative;
		overflow: hidden;
		background: var(--surface-sunken);
	}
	.cov-skel-card::after {
		content: '';
		position: absolute;
		inset: 0;
		background: linear-gradient(90deg, var(--gray-100) 25%, var(--gray-200) 50%, var(--gray-100) 75%);
		background-size: 400% 100%;
		animation: cov-shimmer var(--duration-slow) ease-in-out infinite;
	}

	@keyframes cov-shimmer {
		0% { background-position: 100% 50%; }
		100% { background-position: 0% 50%; }
	}

	/* Touch targets for fix-link buttons ≥44px — §(aa) */
	@media (pointer: coarse) {
		:global(.cov-gap-actions .sj-btn) {
			min-height: 44px;
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

	@media (prefers-reduced-motion: reduce) {
		.cov-skel-card::after { animation: none; }
	}
</style>
