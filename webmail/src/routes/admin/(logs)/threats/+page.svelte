<svelte:options runes={true} />

<script lang="ts">
	import {
		Table, Card, Badge, Button, Input, Tabs, Pagination,
		EmptyState, Spinner, type TableColumn, type SortDir, type TabItem,
	} from '$lib/components/ui';
	import { fetchThreatFlows, type ThreatQueryParams } from '$lib/admin/client';
	import { parseThreatResponse, riskBars, actionBadgeVariant, type ThreatFlow } from '$lib/admin/threat';
	import { parseError } from '$lib/errors';
	import Icon from '$lib/components/Icon.svelte';
	import IPRulesDialog from '$lib/components/admin/IPRulesDialog.svelte';
	import { t } from '$lib/i18n';

	// ── View tabs ──
	const VIEW_TABS: TabItem[] = [
		{ id: 'attempts', label: t('admin.threats.view.attempts') },
		{ id: 'lockouts', label: t('admin.threats.view.lockouts') },
		{ id: 'feed-blocks', label: t('admin.threats.view.feed_blocks') },
		{ id: 'rate-counters', label: t('admin.threats.view.rate_counters') },
	];

	// Risk options — values sent to backend; labels are translated at render time.
	const RISK_OPTIONS = ['All', 'Low', 'Medium', 'High'] as const;
	type RiskFilter = (typeof RISK_OPTIONS)[number];

	// ── Table columns (8 columns, admin-kit §5.1) ──
	const COLUMNS: TableColumn[] = [
		{ key: 'time', label: t('admin.threats.col.time'), sortable: true, mono: true },
		{ key: 'src', label: t('admin.threats.col.source'), sortable: true, mono: true },
		{ key: 'country', label: t('admin.threats.col.geo'), sortable: false },
		{ key: 'dst', label: t('admin.threats.col.destination'), sortable: false, mono: true },
		{ key: 'service', label: t('admin.threats.col.service'), sortable: true },
		{ key: 'risk', label: t('admin.threats.col.risk'), sortable: false },
		{ key: 'rule', label: t('admin.threats.col.rule'), sortable: false, mono: true },
		{ key: 'action', label: t('admin.threats.col.action'), sortable: true },
	];

	// ── State ──
	let flows = $state<ThreatFlow[]>([]);
	let loading = $state(true);
	let error = $state('');
	let activeView = $state('attempts');
	let riskFilter = $state<RiskFilter>('All');
	let textFilter = $state('');
	let total = $state(0);
	let page = $state(1);
	let pageSize = $state(25);
	let sortKey = $state<string | undefined>('time');
	let sortDir = $state<SortDir>('desc');
	let debounceId: ReturnType<typeof setTimeout> | null = null;
	let showIPRules = $state(false);

	// ── Sort column name mapping (display key → backend column) ──
	const SORT_MAP: Record<string, string> = {
		time: 'occurred_at',
		src: 'source_ip',
		action: 'outcome',
		service: 'protocol',
	};

	// ── Data loading ──
	// The risk filter is sent to the backend so pagination and the result count
	// reflect the full filtered corpus, not just the rows on the current page.
	async function load() {
		loading = true;
		error = '';
		try {
			const params: ThreatQueryParams = {
				limit: pageSize,
				offset: (page - 1) * pageSize,
			};
			if (textFilter) params.q = textFilter;
			if (riskFilter !== 'All') params.risk = riskFilter.toLowerCase();
			if (sortKey && SORT_MAP[sortKey]) {
				params.sort = SORT_MAP[sortKey];
				params.dir = sortDir;
			}
			const data = await fetchThreatFlows(activeView, params);
			const result = parseThreatResponse(data);
			flows = result.flows;
			total = result.total;
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	// Initial load + reload on view, pagination, sort change.
	// The $effect runs once after first render (replacing onMount for fetch) and
	// re-runs whenever a tracked dependency changes. Text filtering goes through
	// the debounced handler, which suppresses this effect's load via debounceId.
	$effect(() => {
		// Track dependencies explicitly
		void activeView;
		void riskFilter;
		void page;
		void pageSize;
		void sortKey;
		void sortDir;
		// textFilter triggers via debounced handler
		if (debounceId === null) {
			load();
		}
	});

	function onTextInput() {
		if (debounceId) clearTimeout(debounceId);
		debounceId = setTimeout(() => {
			page = 1;
			load();
			debounceId = null;
		}, 300);
	}

	function onViewChange(id: string) {
		activeView = id;
		page = 1;
		riskFilter = 'All';
	}

	function onSort(key: string, dir: SortDir) {
		sortKey = key;
		sortDir = dir;
		page = 1;
	}

	function onPageChange(p: number) {
		page = p;
	}

	function onPageSizeChange(s: number) {
		pageSize = s;
		page = 1;
	}

	function onRiskChange(risk: RiskFilter) {
		riskFilter = risk;
		page = 1;
	}

	function onExportCSV() {
		// Export CSV — opens the same view with text/csv accept header
		const url = `/admin/threat/${activeView}?format=csv&limit=500`;
		window.open(url, '_blank');
	}

	// Risk label helper — translates display value for the active locale.
	function riskLabel(opt: RiskFilter): string {
		if (opt === 'All') return t('admin.threats.risk.all');
		if (opt === 'Low') return t('admin.threats.risk.low');
		if (opt === 'Medium') return t('admin.threats.risk.medium');
		return t('admin.threats.risk.high');
	}
</script>

<header class="page-header">
	<div class="page-header-left">
		<h1>{t('admin.threats.title')}</h1>
		<p class="page-desc">
			{t('admin.threats.description')}
		</p>
	</div>
	<div class="page-header-actions">
		<Button variant="secondary" size="sm" onclick={onExportCSV}>
			<Icon name="Download" size={14} strokeWidth={1.75} />
			{t('admin.threats.export_csv')}
		</Button>
		<Button variant="secondary" size="sm" onclick={() => { showIPRules = true; }}>
			<Icon name="Shield" size={14} strokeWidth={1.75} />
			{t('admin.threats.policies')}
		</Button>
	</div>
</header>

<Tabs items={VIEW_TABS} active={activeView} onChange={onViewChange} />

<!-- ── Filter bar ── -->
<div class="filter-bar">
	<div class="sec-segment" role="radiogroup" aria-label={t('admin.threats.risk_filter_label')}>
		{#each RISK_OPTIONS as opt}
			<button
				class="sec-segment-btn"
				class:sec-segment-btn--active={riskFilter === opt}
				role="radio"
				aria-checked={riskFilter === opt}
				tabindex={riskFilter === opt ? 0 : -1}
				onclick={() => onRiskChange(opt)}
				onkeydown={(e) => {
					const opts = RISK_OPTIONS;
					const idx = opts.indexOf(opt);
					if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
						e.preventDefault();
						onRiskChange(opts[(idx + 1) % opts.length]);
					} else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
						e.preventDefault();
						onRiskChange(opts[(idx - 1 + opts.length) % opts.length]);
					}
				}}
			>
				{riskLabel(opt)}
			</button>
		{/each}
	</div>

	<div class="filter-input-wrap">
		<Input
			type="text"
			placeholder={t('admin.threats.filter_placeholder')}
			mono={true}
			bind:value={textFilter}
			oninput={onTextInput}
		/>
	</div>

	<div class="result-count">
		{total} &middot; {t('admin.threats.last_1h')}
	</div>
</div>

<!-- ── Content area ── -->
{#if loading}
	<div class="threat-empty">
		<Spinner size={28} />
		<div>{t('admin.threats.loading')}</div>
	</div>
{:else if error}
	<div class="threat-error">
		<Icon name="Shield" size={24} strokeWidth={1.75} />
		<div>{error}</div>
		<Button variant="secondary" size="sm" onclick={load}>{t('admin.threats.retry')}</Button>
	</div>
{:else if flows.length === 0}
	<EmptyState title={t('admin.threats.empty')} watermark={true} />
{:else}
	<Card flush={true}>
		{@const rows = flows as unknown as Record<string, unknown>[]}
		<Table
			columns={COLUMNS}
			rows={rows}
			sortKey={sortKey}
			sortDir={sortDir}
			onSort={onSort}
		>
			{#snippet cell(row, col)}
				{@const f = row as unknown as ThreatFlow}
				{#if col.key === 'country'}
					{#if f.country}
						<span class="geo-chip">{f.country}</span>
					{/if}
				{:else if col.key === 'risk'}
					<div class="risk-bars" title={f.risk}>
						{#each [0, 1, 2] as i}
							<span
								class="risk-bar"
								class:risk-bar--filled={i < riskBars(f.risk)}
								class:risk-bar--high={f.risk === 'high'}
								class:risk-bar--medium={f.risk === 'medium'}
								class:risk-bar--low={f.risk === 'low'}
							></span>
						{/each}
					</div>
				{:else if col.key === 'action'}
					<Badge variant={actionBadgeVariant(String(f.action))} dot={true} label={String(f.action)} />
				{:else if col.key === 'rule'}
					<code class="rule-code">{f.rule || '—'}</code>
				{/if}
			{/snippet}

			{#snippet footer()}
				<Pagination
					page={page}
					pageSize={pageSize}
					total={total}
					pageSizeOptions={[25, 50, 100]}
					onPageChange={onPageChange}
					onPageSizeChange={onPageSizeChange}
				/>
			{/snippet}
		</Table>
	</Card>
{/if}

<IPRulesDialog open={showIPRules} onClose={() => { showIPRules = false; }} />

<style>
	/* ── Page header ── */
	.page-header {
		display: flex;
		align-items: flex-start;
		justify-content: space-between;
		gap: 16px;
		margin-bottom: 16px;
		flex-wrap: wrap;
	}

	.page-header-left {
		flex: 1;
		min-width: 0;
	}

	.page-header h1 {
		font-family: var(--font-sans);
		font-size: var(--text-2xl);
		font-weight: var(--weight-semibold);
		letter-spacing: var(--tracking-heading);
		color: var(--text-primary);
		margin: 0 0 4px;
	}

	.page-desc {
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0;
		line-height: var(--leading-normal);
	}

	.page-header-actions {
		display: flex;
		gap: 8px;
		flex-shrink: 0;
	}

	/* ── Filter bar ── */
	.filter-bar {
		display: flex;
		align-items: center;
		gap: 12px;
		margin-bottom: 12px;
		margin-top: 12px;
		flex-wrap: wrap;
	}

	/* ── Risk segmented control ── */
	.sec-segment {
		display: inline-flex;
		gap: 2px;
		background: var(--surface-sunken);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		padding: 2px;
	}

	.sec-segment-btn {
		height: 24px;
		padding: 0 10px;
		border: none;
		font-size: var(--text-xs);
		font-weight: var(--weight-medium);
		border-radius: 3px;
		background: transparent;
		color: var(--text-tertiary);
		cursor: pointer;
		font-family: var(--font-sans);
		transition: background var(--duration-fast) var(--ease-out),
		            color var(--duration-fast) var(--ease-out),
		            box-shadow var(--duration-fast) var(--ease-out);
	}

	.sec-segment-btn:hover {
		color: var(--text-primary);
	}

	.sec-segment-btn--active {
		background: var(--surface-card);
		color: var(--text-primary);
		box-shadow: var(--shadow-xs);
	}

	.sec-segment-btn:focus-visible {
		box-shadow: var(--focus-ring);
		outline: none;
	}

	.filter-input-wrap {
		flex: 1 1 200px;
		max-width: 280px;
		min-width: 160px;
	}

	.result-count {
		font-family: var(--font-mono);
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		white-space: nowrap;
	}

	/* ── Geo code chip ── */
	.geo-chip {
		font-family: var(--font-mono);
		font-size: var(--text-2xs);
		background: var(--surface-sunken);
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-xs);
		padding: 1px 5px;
		color: var(--text-secondary);
	}

	/* ── Risk bars ── */
	.risk-bars {
		display: flex;
		gap: 2px;
		align-items: flex-end;
		height: 16px;
	}

	.risk-bar {
		width: 8px;
		height: 4px;
		border-radius: 1px;
		background: var(--border-default);
	}

	.risk-bar--filled.risk-bar--high {
		background: var(--danger-solid);
	}

	.risk-bar--filled.risk-bar--medium {
		background: var(--warning-solid);
	}

	.risk-bar--filled.risk-bar--low {
		background: var(--success-solid);
	}

	/* ── Rule code ── */
	.rule-code {
		font-family: var(--font-mono);
		font-size: var(--text-2xs);
		color: var(--text-tertiary);
	}

	/* ── Empty / error states ── */
	.threat-empty {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 16px;
		padding: 64px 16px;
		color: var(--text-secondary);
		font-family: var(--font-sans);
		font-size: var(--text-sm);
	}

	.threat-error {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 12px;
		padding: 48px 16px;
		color: var(--text-secondary);
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		text-align: center;
	}
</style>
