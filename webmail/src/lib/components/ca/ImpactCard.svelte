<!-- ImpactCard.svelte — measured impact of a CA policy over 24h/7d/30d.
     ponytail: NO-DATA ≠ ZERO (load-bearing distinction per §5a brief).
     Uses card-shaped tile skeletons during load (not a spinner — preserves layout).
     would_block_admins > 0 → danger tile promoted to first position. -->
<svelte:options runes={true} />

<script lang="ts">
	import { Card, Badge, EmptyState, Button } from '$lib/components/ui';
	import { t, formatNumber } from '$lib/i18n';
	import { adminFetch } from '$lib/admin/client';
	import { parseError } from '$lib/errors';

	interface ImpactSummary {
		window: string;
		window_has_data: boolean;
		matched: number;
		would_block: number;
		would_step_up: number;
		distinct_users: number;
		would_block_admins: number;
	}

	interface Props {
		policyId: number;
		/** Optional: pre-loaded data (skip fetch if provided). */
		data?: ImpactSummary | null;
		loading?: boolean;
		error?: string | null;
		onRetry?: () => void;
		/**
		 * Opt-in self-fetch: query the policy-impact read endpoint and render the
		 * real measured data. The component historically shipped with NO fetch at
		 * all, so every caller silently rendered an authoritative-looking NO-DATA
		 * state. Off by default: callers without a real policy id (TemplateWizard
		 * previews, where template.id would hit the wrong endpoint) keep the
		 * explicit no-evidence state instead of a doomed request.
		 */
		fetchData?: boolean;
	}

	let { policyId, data = null, loading = false, error = null, onRetry, fetchData = false }: Props = $props();

	// ── self-fetch state (only used when fetchData is on) ──
	let liveData = $state(null as ImpactSummary | null);
	let liveLoading = $state(false);
	let liveError = $state('');
	// Monotonic sequence: only the newest fetch may write state. Deliberately NOT
	// $state — the effect calls loadImpact(), which increments this counter; a
	// reactive read there would make the effect depend on its own write.
	let fetchSeq = 0;

	async function loadImpact() {
		const seq = ++fetchSeq;
		liveLoading = true;
		liveError = '';
		try {
			const res = await adminFetch(`/admin/conditional-access/policies/${policyId}/impact?window=7d`);
			const body: unknown = await res.json();
			// Guard the evidence surface: an unvalidated body must not render as
			// authoritative numbers (same class of bug as the promote-gate input).
			if (
				typeof body !== 'object' || body === null ||
				typeof (body as ImpactSummary).window_has_data !== 'boolean' ||
				typeof (body as ImpactSummary).window !== 'string'
			) {
				throw new Error('impact read returned an unexpected body shape');
			}
			if (seq !== fetchSeq) return; // superseded by a newer fetch
			liveData = body as ImpactSummary;
		} catch (e) {
			if (seq !== fetchSeq) return;
			liveData = null;
			liveError = parseError(e).message;
		} finally {
			if (seq === fetchSeq) liveLoading = false;
		}
	}

	// Fetch on mount / whenever the target policy changes (opt-in only).
	$effect(() => {
		if (!fetchData) return;
		void policyId;
		loadImpact();
	});

	// Effective render inputs: the self-fetch result wins when fetchData is on;
	// otherwise the caller-provided props drive the card exactly as before.
	const effectiveData = $derived(fetchData ? liveData : (data ?? null));
	const effectiveLoading = $derived(fetchData ? liveLoading || loading : loading);
	const effectiveError = $derived(fetchData ? liveError || (error ?? '') : (error ?? ''));
	const retry = $derived(fetchData ? loadImpact : (onRetry ?? undefined));

	// Derive the no-data vs zero distinction.
	const noData = $derived(effectiveData !== null && effectiveData.window_has_data === false);
	const zero = $derived(
		effectiveData !== null && effectiveData.window_has_data === true && effectiveData.would_block === 0
	);
	const hasAdminBlock = $derived((effectiveData?.would_block_admins ?? 0) > 0);

	// aria-live announce text — polite, fires on every data change.
	const announceText = $derived(
		effectiveData && effectiveData.window_has_data
			? t('admin.ca.impact.announce', {
					matched: formatNumber(effectiveData.matched),
					would_block: formatNumber(effectiveData.would_block),
				})
			: ''
	);
</script>

<div class="impact-card" data-testid="impact-card">
	<!-- aria-live: polite announce on data resolve (§5a h) -->
	<div aria-live="polite" aria-atomic="true" class="sr-only" data-testid="impact-announce">
		{announceText}
	</div>

	{#if effectiveLoading}
		<!-- Tile skeletons — preserve layout during load (§5a LOADING) -->
		<div class="impact-tiles" aria-busy="true" data-testid="impact-loading">
			{#each [1, 2, 3, 4] as _, i (i)}
				<div class="impact-tile impact-tile--skel">
					<div class="tile-skel-label"></div>
					<div class="tile-skel-value"></div>
				</div>
			{/each}
		</div>
	{:else if effectiveError}
		<!-- ERROR state — role=alert, Retry button (§5a ERROR) -->
		<div class="impact-error" role="alert" data-testid="impact-error">
			<span>{t('admin.ca.impact.load_error')}</span>
			{#if retry}
				<Button variant="ghost" size="sm" onclick={retry}>{t('common.retry')}</Button>
			{/if}
		</div>
	{:else if !effectiveData || noData}
		<!-- NO-DATA — EmptyState (NOT "0" — §5a load-bearing rule) -->
		<div data-testid="impact-no-data">
			<EmptyState title={t('admin.ca.impact.no_data', { window: effectiveData?.window ?? '7d' })} />
		</div>
	{:else}
		<!-- TILES — would_block_admins promoted to first if > 0 (§5a HIERARCHY) -->
		<div class="impact-tiles" data-testid="impact-tiles">
			{#if hasAdminBlock}
				<div
					class="impact-tile impact-tile--danger"
					data-testid="impact-tile-admins"
				>
					<span class="tile-label">
						<!-- AlertTriangle inline: aria-hidden, label carries meaning -->
						<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
							<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
							<line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
						</svg>
						{t('admin.ca.impact.tile.would_block_admins')}
					</span>
					<span class="tile-value tile-value--danger">{formatNumber(effectiveData.would_block_admins)}</span>
				</div>
			{/if}

			<div class="impact-tile" data-testid="impact-tile-matched">
				<span class="tile-label">{t('admin.ca.impact.tile.matched')}</span>
				<span class="tile-value">{formatNumber(effectiveData.matched)}</span>
			</div>

			<div
				class="impact-tile"
				class:impact-tile--success={zero}
				data-testid="impact-tile-would-block"
			>
				<span class="tile-label">{t('admin.ca.impact.tile.would_block')}</span>
				<span
					class="tile-value"
					class:tile-value--success={zero}
					class:tile-value--danger={!zero && effectiveData.would_block > 0}
				>
					{formatNumber(effectiveData.would_block)}
				</span>
			</div>

			<div class="impact-tile" data-testid="impact-tile-step-up">
				<span class="tile-label">{t('admin.ca.impact.tile.would_step_up')}</span>
				<span class="tile-value">{formatNumber(effectiveData.would_step_up)}</span>
			</div>

			<div class="impact-tile" data-testid="impact-tile-users">
				<span class="tile-label">{t('admin.ca.impact.tile.distinct_users')}</span>
				<span class="tile-value">{formatNumber(effectiveData.distinct_users)}</span>
			</div>
		</div>

		{#if zero}
			<p class="impact-zero-note" data-testid="impact-zero-note">
				{t('admin.ca.impact.zero_block', { matched: formatNumber(effectiveData.matched) })}
			</p>
		{/if}
	{/if}
</div>

<style>
	.impact-card {
		font-family: var(--font-sans);
	}

	.impact-tiles {
		display: flex;
		flex-wrap: wrap;
		gap: 8px;
	}

	.impact-tile {
		flex: 1 1 100px;
		min-width: 80px;
		padding: 10px 12px;
		border-radius: var(--radius-sm);
		background: var(--surface-sunken);
		border: 1px solid var(--border-subtle);
		display: flex;
		flex-direction: column;
		gap: 4px;
		/* keyed cross-fade on count change — §j motion requirement */
		transition: background var(--duration-base) var(--ease-out),
			border-color var(--duration-base) var(--ease-out);
	}

	.impact-tile--danger {
		background: var(--danger-bg);
		border-color: var(--danger-solid);
	}

	.impact-tile--success {
		background: var(--success-bg);
		border-color: var(--success-solid);
	}

	.tile-label {
		display: flex;
		align-items: center;
		gap: 4px;
		font-size: var(--text-2xs);
		font-weight: var(--weight-medium);
		color: var(--text-tertiary);
		white-space: nowrap;
	}

	.tile-value {
		font-size: var(--text-xl);
		font-weight: var(--weight-bold);
		font-family: var(--font-mono);
		color: var(--text-primary);
	}

	.tile-value--danger { color: var(--danger-fg); }
	.tile-value--success { color: var(--success-fg); }

	/* Skeleton tiles */
	.impact-tile--skel {
		animation: impact-shimmer var(--duration-slow) ease-in-out infinite;
		background: linear-gradient(90deg, var(--gray-100) 25%, var(--gray-200) 50%, var(--gray-100) 75%);
		background-size: 400% 100%;
		border-color: transparent;
	}

	.tile-skel-label {
		height: 10px;
		width: 60%;
		border-radius: var(--radius-xs);
		background: var(--gray-300);
		opacity: 0.5;
	}

	.tile-skel-value {
		height: 24px;
		width: 40%;
		border-radius: var(--radius-xs);
		background: var(--gray-300);
		opacity: 0.5;
	}

	@keyframes impact-shimmer {
		0% { background-position: 100% 50%; }
		100% { background-position: 0% 50%; }
	}

	.impact-error {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 10px 14px;
		border-radius: var(--radius-sm);
		background: var(--danger-bg);
		color: var(--danger-fg);
		font-size: var(--text-sm);
	}

	.impact-zero-note {
		margin: 8px 0 0;
		font-size: var(--text-xs);
		color: var(--success-fg);
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

	@media (prefers-reduced-motion: reduce) {
		.impact-tile {
			transition: none;
		}
		.impact-tile--skel {
			animation: none;
		}
	}

	/* Touch targets for controls inside the card (≥44px, §m) */
	@media (pointer: coarse) {
		:global(.impact-card .sj-btn) {
			min-height: 44px;
		}
	}
</style>
