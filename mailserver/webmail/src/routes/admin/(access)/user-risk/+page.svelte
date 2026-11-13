<svelte:options runes={true} />

<script lang="ts">
	import { Badge, Button, Dialog, EmptyState, Pagination, Select, Spinner, Table, showToast } from '$lib/components/ui';
	import type { TableColumn, SortDir } from '$lib/components/ui';
	import { nextSort } from '$lib/components/ui';
	import { t, formatDate } from '$lib/i18n';

	interface RiskRow { user_id: number; email: string; score: number; level: string; signals: string[]; updated_at: string; }
	type View = 'loading' | 'error' | 'empty-off' | 'empty-clean' | 'ready';

	let rows = $state<RiskRow[]>([]);
	let view = $state<View>('loading');
	let levelFilter = $state('all');
	let sortKey = $state('score');
	let sortDir = $state<SortDir>('desc');
	let page = $state(1);
	const PAGE = 25;

	let confirmRow = $state<RiskRow | null>(null);
	let resetting = $state(false);
	let announce = $state('');
	// ponytail: firstLoad flag prevents load() from overwriting a reset announce
	let firstLoad = $state(true);

	const BADGE: Record<string, 'danger' | 'warning' | 'info' | 'neutral'> =
		{ high: 'danger', medium: 'warning', low: 'info', none: 'neutral' };

	const filtered = $derived(
		rows
			.filter((r) => levelFilter === 'all' || r.level === levelFilter)
			.sort((a, b) => {
				const dir = sortDir === 'asc' ? 1 : -1;
				return sortKey === 'updated_at'
					? a.updated_at.localeCompare(b.updated_at) * dir
					: (a.score - b.score) * dir;
			})
	);
	const paged = $derived(filtered.slice((page - 1) * PAGE, page * PAGE));

	const COLUMNS: TableColumn[] = [
		{ key: 'email',      label: t('risk.col_user'),    sortable: false },
		{ key: 'level',      label: t('risk.col_level'),   sortable: false },
		{ key: 'score',      label: t('risk.col_score'),   sortable: true },
		{ key: 'signals',    label: t('risk.col_signals'), sortable: false },
		{ key: 'updated_at', label: t('risk.col_updated'), sortable: true },
		{ key: 'actions',    label: '',                    sortable: false, width: '80px' },
	];

	async function load() {
		view = 'loading';
		try {
			const res = await fetch('/api/admin/user-risk');
			if (!res.ok && (res.status === 409 || res.headers.get('x-feature-off') === 'user_risk')) {
				view = 'empty-off'; return;
			}
			if (!res.ok) { view = 'error'; return; }
			rows = await res.json();
			view = rows.length === 0 ? 'empty-clean' : 'ready';
			if (view === 'ready' && firstLoad) {
				announce = t('risk.count_announce', { n: String(rows.length) });
			}
			firstLoad = false;
		} catch { view = 'error'; }
	}

	async function doReset() {
		if (!confirmRow) return;
		const email = confirmRow.email;
		const id = confirmRow.user_id;
		resetting = true;
		try {
			const res = await fetch(`/api/admin/user-risk/${id}/reset`, { method: 'POST' });
			if (!res.ok) { showToast(t('risk.reset_failed'), { variant: 'danger' }); return; }
			showToast(t('risk.reset_done', { email }), { variant: 'success' });
			announce = t('risk.reset_announce', { email });
			confirmRow = null;
			await load();
		} finally { resetting = false; }
	}

	function handleSort(key: string, dir: SortDir) {
		sortKey = key;
		sortDir = dir;
		page = 1;
	}

	$effect(() => { load(); });
</script>

<section class="risk-dash">
	<h1>{t('risk.title')}</h1>
	<p class="risk-note">{t('risk.honesty')}</p>
	<div class="sr-only" aria-live="polite">{announce}</div>

	{#if view === 'loading'}
		<div class="risk-center"><Spinner /></div>
	{:else if view === 'error'}
		<div class="risk-error" role="alert">
			<span>{t('risk.load_failed')}</span>
			<Button variant="secondary" size="sm" onclick={load}>{t('common.retry')}</Button>
		</div>
	{:else if view === 'empty-off'}
		<EmptyState title={t('risk.off_title')} watermark>
			{#snippet action()}
				<Button variant="primary" onclick={() => location.assign('/admin/features')}>{t('risk.off_cta')}</Button>
			{/snippet}
		</EmptyState>
	{:else if view === 'empty-clean'}
		<EmptyState title={t('risk.clean_title')} watermark>
			{#snippet action()}
				<span class="risk-clean-sub">{t('risk.clean_sub')}</span>
			{/snippet}
		</EmptyState>
	{:else}
		<div class="risk-toolbar">
			<Select
				label={t('risk.filter_label')}
				value={levelFilter}
				onchange={(e: Event) => { levelFilter = (e.target as HTMLSelectElement).value; page = 1; }}
			>
				{#snippet children()}
					<option value="all">{t('risk.filter_all')}</option>
					<option value="high">{t('risk.level_high')}</option>
					<option value="medium">{t('risk.level_medium')}</option>
					<option value="low">{t('risk.level_low')}</option>
				{/snippet}
			</Select>
			<span class="risk-count">{t('risk.showing_of', { shown: String(paged.length), total: String(filtered.length) })}</span>
		</div>
		<Table
			columns={COLUMNS}
			rows={paged as unknown as Record<string, unknown>[]}
			sortKey={sortKey}
			sortDir={sortDir}
			onSort={handleSort}
		>
			{#snippet cell(row, col)}
				{@const r = row as unknown as RiskRow}
				{#if col.key === 'email'}
					<span class="risk-email" title={r.email}>{r.email}</span>
				{:else if col.key === 'level'}
					<Badge variant={BADGE[r.level] ?? 'neutral'} label={t('risk.level_' + r.level)} />
				{:else if col.key === 'score'}
					{r.score}
				{:else if col.key === 'signals'}
					{r.signals.length ? r.signals.map((s) => t('risk.signal_' + s)).join(t('common.list_sep')) : '—'}
				{:else if col.key === 'updated_at'}
					<time datetime={r.updated_at}>{formatDate(r.updated_at)}</time>
				{:else if col.key === 'actions'}
					<Button
						variant="ghost"
						size="sm"
						aria-label={t('risk.reset_for', { email: r.email })}
						onclick={() => (confirmRow = r)}
					>{t('risk.reset')}</Button>
				{/if}
			{/snippet}
			{#snippet footer()}
				<Pagination
					page={page}
					pageSize={PAGE}
					total={filtered.length}
					onPageChange={(p) => (page = p)}
				/>
			{/snippet}
		</Table>
	{/if}
</section>

<!-- Dangerous action: reset confirm (§brief Tier 1 simple-confirm) -->
<Dialog
	open={!!confirmRow}
	title={confirmRow ? t('risk.reset_title', { email: confirmRow.email }) : ''}
	onClose={() => (confirmRow = null)}
>
	{#snippet children()}
		<p>{t('risk.reset_body')}</p>
	{/snippet}
	{#snippet footer()}
		<Button variant="ghost" onclick={() => (confirmRow = null)} disabled={resetting}>{t('common.cancel')}</Button>
		<Button variant="danger" onclick={doReset} disabled={resetting}>{t('risk.reset_confirm')}</Button>
	{/snippet}
</Dialog>

<style>
	.risk-dash { padding: var(--space-4); color: var(--text-primary); }
	.risk-note { color: var(--text-tertiary); font-size: var(--text-sm); max-width: 64ch; }
	.risk-center { display: flex; justify-content: center; padding: var(--space-8); }
	.risk-error {
		display: flex;
		align-items: center;
		gap: var(--space-3);
		padding: var(--space-3);
		background: var(--danger-bg);
		color: var(--danger-fg);
		border-radius: var(--radius-md);
	}
	.risk-clean-sub { color: var(--text-tertiary); font-size: var(--text-sm); }
	.risk-toolbar { display: flex; align-items: center; gap: var(--space-3); margin: var(--space-3) 0; }
	.risk-count { color: var(--text-caption); font-size: var(--text-xs); }
	.risk-email { max-width: 22ch; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: inline-block; }
	.sr-only {
		position: absolute;
		width: 1px;
		height: 1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
	}

	@media (max-width: 900px) {
		.risk-email { max-width: 100%; }
	}

	@media (prefers-reduced-motion: reduce) {
		/* Badge level-swap cross-fade and skeleton shimmer disabled. */
		:global(.risk-dash *) { transition: none !important; animation: none !important; }
	}
</style>
