<svelte:options runes={true} />

<script lang="ts">
	import { flushSync } from 'svelte';
	import { Badge, Button, Input, Select, EmptyState, Spinner, Card, Table } from '$lib/components/ui';
	import type { TableColumn } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { adminFetch } from '$lib/admin/client';
	import { parseError } from '$lib/errors';
	import { t } from '$lib/i18n';
	import { OUTCOME_LEGEND, outcomeChip, decisionVariant, type OutcomeMeta } from './signin-trace';

	// ── Row type returned by GET /admin/conditional-access/signin-log ──
	interface EvaluatedEntry {
		policy_id: number;
		name: string;
		outcome: string;
	}
	interface SignInRow {
		id: number;
		user_id: number;
		decision: string;
		would_decision?: string;
		report_only: boolean;
		matched_policy_id?: number | null;
		correlation_id?: string | null;
		evaluated: EvaluatedEntry[];
		occurred_at?: string;
		source_ip?: string;
		country?: string;
		client_type?: string;
	}

	// ── State ──
	type Axis = 'user_id' | 'correlation_id';
	let axis = $state<Axis>('user_id');
	let query = $state('');
	let lastQuery = $state('');

	type Phase = 'idle' | 'loading' | 'error' | 'empty' | 'success';
	let phase = $state<Phase>('idle');
	let rows = $state<SignInRow[]>([]);
	let total = $state(0);
	let errorMsg = $state('');
	let announcement = $state('');
	let copiedAnnouncement = $state(''); // for copy events (overrides announcement transiently)

	// Per-row expanded disclosure
	let expanded = $state<Record<number, boolean>>({});
	// Copy flash state
	let copied = $state<string | null>(null);

	// Reduced-motion detection — read once at mount time (jsdom needs a fn, not a $effect).
	// ponytail: no reactive listener; re-renders on locale change anyway.
	function prefersReducedMotion(): boolean {
		if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return false;
		try {
			return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
		} catch {
			return false;
		}
	}
	const reducedMotion = prefersReducedMotion();

	// ponytail: single-layout switch (Table on pointer/desktop, Cards on touch/mobile).
	// Only one layout is in the DOM at a time so tests never see duplicate text.
	// jsdom defaults to innerWidth=1024 → Table path; real browser respects the 720 breakpoint.
	const isDesktop = typeof window !== 'undefined' && window.innerWidth > 720;

	const LIMIT = 100;
	// ponytail: retention days hard-coded; wire to config endpoint when available.
	const RETENTION_DAYS = 90;

	async function runTrace() {
		if (!query.trim()) return;
		lastQuery = query.trim();
		phase = 'loading';
		announcement = '';
		copiedAnnouncement = '';
		expanded = {};
		rows = [];
		errorMsg = '';

		const params = new URLSearchParams();
		params.set(axis, lastQuery);
		params.set('limit', String(LIMIT));

		try {
			const res = await adminFetch(`/admin/conditional-access/signin-log?${params}`);
			const data: { rows: SignInRow[]; total?: number } = await res.json();
			rows = data.rows ?? [];
			total = data.total ?? rows.length;
			phase = rows.length === 0 ? 'empty' : 'success';
			announcement = phase === 'success'
				? t('admin.ca.trace.announce_count', { n: new Intl.NumberFormat().format(rows.length), q: lastQuery })
				: t('admin.ca.trace.announce_empty', { q: lastQuery });
			// ponytail: force-flush immediately after setting state.
				// ponytail: force-flush immediately so DOM reflects announcement before act() returns.
			flushSync();
		} catch (e) {
			errorMsg = parseError(e).message;
			phase = 'error';
			flushSync();
		}
	}

	function handleKeydown(e: KeyboardEvent) {
		if (e.key === 'Enter') runTrace();
	}

	function toggleRow(id: number) {
		expanded[id] = !expanded[id];
	}

	async function copyRef(id: string) {
		if (navigator.clipboard) {
			await navigator.clipboard.writeText(id).catch(() => {});
		}
		copied = id;
		copiedAnnouncement = t('admin.ca.trace.copied');
		setTimeout(() => { copied = null; copiedAnnouncement = ''; }, 1200);
	}

	// ── Legend helper — tooltip string for aria-label ──
	function chipTip(o: OutcomeMeta): string {
		return t(o.tip);
	}

	// ── Desktop table columns (pointer viewport) ──
	// ponytail: columns typed as const to satisfy Table generics; cell snippet handles custom rendering.
	const TABLE_COLS: TableColumn[] = [
		{ key: 'decision', label: 'Decision' },
		{ key: 'correlation_id', label: 'Reference', mono: true },
		{ key: 'occurred_at', label: 'Time' },
		{ key: 'source_ip', label: 'IP', mono: true },
		{ key: 'client_type', label: 'Client' },
		{ key: '_expand', label: '' }
	];
</script>

<!-- Persistent aria-live region (polite) — announces trace outcome + copy events -->
<div aria-live="polite" aria-atomic="true" class="sr-only">{copiedAnnouncement || announcement}</div>

<div class="sj-trace">
	<!-- ── Search bar ── -->
	<div class="sj-trace-bar">
		<Select
			label={t('admin.ca.trace.axis_label')}
			value={axis}
			onchange={(e) => (axis = (e.target as HTMLSelectElement).value as Axis)}
		>
			{#snippet children()}
				<option value="user_id">{t('admin.ca.trace.by_user')}</option>
				<option value="correlation_id">{t('admin.ca.trace.by_correlation')}</option>
			{/snippet}
		</Select>
		<Input
			label={axis === 'user_id' ? t('admin.ca.trace.by_user') : t('admin.ca.trace.by_correlation')}
			value={query}
			oninput={(e) => (query = (e.target as HTMLInputElement).value)}
			onkeydown={handleKeydown}
			disabled={phase === 'loading'}
			placeholder={axis === 'user_id' ? '4711' : 'CA-7f3c9a'}
			aria-describedby="trace-legend-desc"
			data-trace-input
		/>
		<Button
			variant="primary"
			disabled={phase === 'loading' || !query.trim()}
			onclick={runTrace}
		>
			{#if phase === 'loading'}<Spinner size={16} />{/if}
			{t('admin.ca.trace.trace_btn')}
		</Button>
	</div>

	<!-- ── 6-outcome chip legend (always shown) ── -->
	<div class="sj-trace-legend" id="trace-legend-desc" aria-label={t('admin.ca.trace.legend_label')}>
		{#each OUTCOME_LEGEND as o (o.outcome)}
			<!-- Badge + Icon per §1: icon aria-hidden; chip aria-label = full tooltip text -->
			<span class="sj-trace-chip" aria-label={chipTip(o)}>
				<Icon name={o.icon as never} size={12} aria-hidden="true" />
				<Badge variant={o.variant} label={t(o.key)} />
			</span>
		{/each}
		<!-- special legend entry for report-only would_block visible in tests -->
		<span class="sj-trace-legend-note">{t('admin.ca.trace.legend_report_only')}</span>
	</div>

	<!-- ── IDLE (no query typed yet) ── -->
	{#if phase === 'idle' && !query.trim()}
		<EmptyState title={t('admin.ca.trace.idle')}>
			{#snippet action()}
				<Button variant="primary" size="sm" onclick={() => {
					const input = document.querySelector('[data-trace-input]') as HTMLInputElement | null;
					input?.focus();
				}}>{t('admin.ca.trace.idle_cta')}</Button>
			{/snippet}
		</EmptyState>

	<!-- ── LOADING skeleton ── -->
	{:else if phase === 'loading'}
		<div aria-busy="true" class="sj-trace-skeleton">
			<span class="sr-only" role="status">{t('common.loading')}</span>
			{#each [0, 1, 2] as i (i)}
				<div class="sj-skeleton-row" class:sj-skeleton-row--nomotion={reducedMotion}></div>
			{/each}
		</div>

	<!-- ── ERROR ── -->
	{:else if phase === 'error'}
		<div class="sj-trace-error" role="alert">
			<span class="sj-trace-error-msg">{t('admin.ca.trace.load_error')} {errorMsg}</span>
			<Button variant="secondary" size="sm" onclick={runTrace}>{t('common.retry')}</Button>
		</div>

	<!-- ── EMPTY ── -->
	{:else if phase === 'empty'}
		<EmptyState title={t('admin.ca.trace.no_rows', { q: lastQuery })}>
			{#snippet action()}
				<div class="sj-trace-empty-hints">
					<p class="sj-trace-hint">{t('admin.ca.trace.no_rows_hint', { days: String(RETENTION_DAYS) })}</p>
					<p class="sj-trace-caveat">{t('admin.ca.trace.legacy_caveat')}</p>
				</div>
			{/snippet}
		</EmptyState>

	<!-- ── SUCCESS ── -->
	{:else if phase === 'success'}
		<div class="sj-trace-results">
			{#if isDesktop}
				<!-- Desktop (pointer ≥721px): M1 Table. Only one layout is in DOM at a time. -->
				<Table columns={TABLE_COLS} rows={rows as unknown as Record<string, unknown>[]}>
					{#snippet cell(row: Record<string, unknown>, col)}
						{@const r = row as unknown as SignInRow}
						{#if col.key === 'decision'}
							<Badge variant={decisionVariant(r.decision)} label={r.decision} />
							{#if r.report_only}<Badge variant="info" label="report-only" />{/if}
						{:else if col.key === 'correlation_id'}
							{#if r.correlation_id}
								<span class="sj-trace-corr" dir="ltr">{r.correlation_id}</span>
								<button
									type="button"
									class="sj-trace-copy"
									aria-label={t('admin.ca.trace.copy_ref', { id: r.correlation_id })}
									onclick={() => copyRef(r.correlation_id!)}
								>{copied === r.correlation_id ? '✓' : '⎘'}</button>
							{/if}
						{:else if col.key === 'occurred_at'}
							<span class="sj-muted">{r.occurred_at ?? ''}</span>
						{:else if col.key === 'source_ip'}
							<span class="sj-mono">{r.source_ip ?? ''}</span>
						{:else if col.key === 'client_type'}
							{r.client_type ?? ''}
						{:else if col.key === '_expand'}
							{#if r.evaluated.length > 0}
								<button
									type="button"
									class="sj-trace-disclose"
									aria-expanded={expanded[r.id] === true}
									aria-label="Show or hide the per-policy trace"
									onclick={() => toggleRow(r.id)}
								>{expanded[r.id] ? '▲' : '▼'}</button>
							{:else if !r.matched_policy_id}
								<span class="sj-trace-default-allow-inline">{t('ca.trace.default_allow')}</span>
							{/if}
						{/if}
					{/snippet}
				</Table>
				<!-- Expanded detail rows (per-policy chips) below table for desktop -->
				{#each rows as row (row.id)}
					{#if expanded[row.id] && row.evaluated.length > 0}
						<div
							class="sj-trace-detail"
							style={reducedMotion ? 'transition:none;transition-duration:0s;' : undefined}
							data-trace-detail
						>
							{#each row.evaluated as ev (ev.policy_id)}
								{@const chip = outcomeChip(ev.outcome)}
								<span class="sj-trace-chip" aria-label={chipTip(chip)} title={ev.name}>
									<Icon name={chip.icon as never} size={12} aria-hidden="true" />
									<Badge variant={chip.variant} label={t(chip.key)} />
									<span class="sj-trace-chip-name">{ev.name}</span>
								</span>
							{/each}
						</div>
					{/if}
				{/each}
			{:else}
				<!-- Mobile / native-shell (≤720px): stacked Cards -->
				{#each rows as row (row.id)}
					<Card flush={false}>
						<div class="sj-trace-row-head">
							<Badge variant={decisionVariant(row.decision)} label={row.decision} />
							{#if row.report_only}
								<Badge variant="info" label="report-only" />
							{/if}

							{#if row.correlation_id}
								<span class="sj-trace-corr" dir="ltr">{row.correlation_id}</span>
								<button
									type="button"
									class="sj-trace-copy"
									aria-label={t('admin.ca.trace.copy_ref', { id: row.correlation_id })}
									onclick={() => copyRef(row.correlation_id!)}
								>
									{#if copied === row.correlation_id}✓{:else}⎘{/if}
								</button>
							{/if}

							{#if row.occurred_at}
								<span class="sj-trace-meta sj-muted">{row.occurred_at}</span>
							{/if}
							{#if row.source_ip}
								<span class="sj-trace-meta sj-mono">{row.source_ip}</span>
							{/if}

							{#if row.evaluated.length > 0}
								<button
									type="button"
									class="sj-trace-disclose"
									aria-expanded={expanded[row.id] === true}
									aria-label="Show or hide the per-policy trace"
									onclick={() => toggleRow(row.id)}
								>
									{expanded[row.id] ? '▲' : '▼'}
								</button>
							{/if}
						</div>

						{#if !row.matched_policy_id && row.evaluated.length === 0}
							<p class="sj-trace-default-allow">{t('ca.trace.default_allow')}</p>
						{/if}

						{#if expanded[row.id] && row.evaluated.length > 0}
							<div
								class="sj-trace-detail"
								style={reducedMotion ? 'transition:none;transition-duration:0s;' : undefined}
								data-trace-detail
							>
								{#each row.evaluated as ev (ev.policy_id)}
									{@const chip = outcomeChip(ev.outcome)}
									<span class="sj-trace-chip" aria-label={chipTip(chip)} title={ev.name}>
										<Icon name={chip.icon as never} size={12} aria-hidden="true" />
										<Badge variant={chip.variant} label={t(chip.key)} />
										<span class="sj-trace-chip-name">{ev.name}</span>
									</span>
								{/each}
							</div>
						{/if}
					</Card>
				{/each}
			{/if}

			<!-- Partial/truncation footer -->
			{#if rows.length >= LIMIT}
				<p class="sj-trace-truncated">
					{t('ca.impact.showing_of', { shown: String(rows.length), total: String(total) })}
					{t('admin.ca.trace.truncated', { n: String(LIMIT) })}
				</p>
			{/if}
		</div>
	{/if}
</div>

<style>
	.sj-trace { display: flex; flex-direction: column; gap: 16px; }

	/* Search bar */
	.sj-trace-bar {
		display: flex;
		gap: 8px;
		align-items: flex-end;
		flex-wrap: wrap;
	}
	.sj-trace-bar > :global(*) { flex: 1 1 160px; min-width: 0; }
	.sj-trace-bar > :global(button) { flex: 0 0 auto; min-width: 80px; min-height: 44px; }

	/* Legend */
	.sj-trace-legend {
		display: flex;
		flex-wrap: wrap;
		gap: 6px;
		align-items: center;
		padding: 8px 0;
		border-bottom: 1px solid var(--border-subtle);
	}
	.sj-trace-legend-note {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		font-style: italic;
	}

	/* Outcome chips */
	.sj-trace-chip {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		height: 22px;
		padding: 0 8px;
		border-radius: var(--radius-full);
		font-size: var(--text-2xs);
		font-weight: var(--weight-semibold);
		white-space: nowrap;
		cursor: default;
	}
	.sj-trace-chip-name {
		font-weight: var(--weight-normal);
		font-size: var(--text-2xs);
		color: inherit;
		opacity: 0.8;
		max-width: 160px;
		overflow: hidden;
		text-overflow: ellipsis;
	}

	/* Skeleton rows */
	.sj-trace-skeleton { display: flex; flex-direction: column; gap: 8px; }
	.sj-skeleton-row {
		height: 48px;
		border-radius: var(--radius-sm);
		background: var(--surface-sunken);
		position: relative;
		overflow: hidden;
	}
	.sj-skeleton-row::after {
		content: '';
		position: absolute;
		inset: 0;
		background: linear-gradient(90deg, var(--gray-100) 25%, var(--gray-200) 50%, var(--gray-100) 75%);
		background-size: 400% 100%;
		animation: sj-trace-shimmer var(--duration-slow, 1.2s) ease-in-out infinite;
	}
	.sj-skeleton-row--nomotion::after { animation: none; }

	/* Error */
	.sj-trace-error {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 10px 14px;
		border-radius: var(--radius-sm);
		background: var(--danger-bg);
		color: var(--danger-fg);
		font-size: var(--text-sm);
	}
	.sj-trace-error-msg { flex: 1; }

	/* Empty hints */
	.sj-trace-empty-hints { display: flex; flex-direction: column; gap: 4px; text-align: center; }
	.sj-trace-hint, .sj-trace-caveat {
		margin: 0;
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}

	/* Result rows */
	.sj-trace-results { display: flex; flex-direction: column; gap: 8px; }
	.sj-trace-row-head {
		display: flex;
		flex-wrap: wrap;
		gap: 6px;
		align-items: center;
		padding: 8px 12px;
		min-height: 44px;
	}
	.sj-trace-corr {
		font-family: var(--font-mono);
		font-size: var(--text-xs);
		color: var(--text-primary);
	}
	.sj-trace-copy {
		/* ≥44px touch target (brief explicit requirement) */
		width: 44px; height: 44px; min-width: 44px;
		display: inline-flex; align-items: center; justify-content: center;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		background: transparent;
		cursor: pointer;
		color: var(--text-secondary);
		font-size: 13px;
	}
	.sj-trace-copy:hover { background: var(--surface-hover); }
	.sj-trace-copy:focus-visible { outline: none; box-shadow: var(--focus-ring); }
	.sj-trace-meta { font-size: var(--text-xs); }
	.sj-muted { color: var(--text-tertiary); }
	.sj-mono { font-family: var(--font-mono); }

	.sj-trace-disclose {
		margin-inline-start: auto;
		/* ≥44px touch target (brief explicit requirement) */
		width: 44px; height: 44px; min-width: 44px;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		background: transparent;
		cursor: pointer;
		color: var(--text-secondary);
		font-size: 10px;
		display: inline-flex; align-items: center; justify-content: center;
	}
	.sj-trace-disclose:focus-visible { outline: none; box-shadow: var(--focus-ring); }

	/* Per-policy detail */
	.sj-trace-detail {
		display: flex;
		flex-wrap: wrap;
		gap: 6px;
		padding: 8px 12px;
		border-top: 1px solid var(--border-subtle);
		overflow: hidden;
		max-height: 300px;
		opacity: 1;
		transition: max-height var(--duration-base, 200ms) var(--ease-out, ease), opacity var(--duration-fast, 120ms) var(--ease-out, ease);
	}
	/* Under reduced motion the detail has no transition; inline style is set for test visibility */
	@media (prefers-reduced-motion: reduce) {
		.sj-trace-detail { transition: none; }
		.sj-skeleton-row::after { animation: none; }
	}

	.sj-trace-default-allow {
		margin: 0;
		padding: 6px 12px;
		font-size: var(--text-sm);
		color: var(--info-fg);
		background: var(--info-bg);
		border-radius: 0 0 var(--radius-sm) var(--radius-sm);
	}
	/* Inline default-allow used in Table cell (no block padding) */
	.sj-trace-default-allow-inline {
		font-size: var(--text-xs);
		color: var(--info-fg);
	}

	.sj-trace-truncated {
		margin: 0;
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		text-align: center;
	}

	@keyframes sj-trace-shimmer {
		0% { background-position: 100% 50%; }
		100% { background-position: 0% 50%; }
	}

	/* Accessibility */
	.sr-only {
		position: absolute;
		width: 1px; height: 1px;
		padding: 0; margin: -1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
		border: 0;
	}

	/* Responsive layout: desktop = Table, mobile = Cards.
	   ponytail: JS innerWidth toggle (not CSS media query) so only one layout is in the DOM —
	   avoids duplicate text nodes that break Testing Library's findByText. */
	@media (max-width: 720px) {
		.sj-trace-bar { flex-direction: column; }
		.sj-trace-bar > :global(*) { flex: 1 1 100%; }
	}
</style>
