<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { parseError } from '$lib/errors';
	import { adminHealth, type HealthResponse } from '$lib/admin/health';
	import { t } from '$lib/i18n';
	import { Switch, Card, Badge, Table, Button, Spinner, EmptyState } from '$lib/components/ui';
	import type { TableColumn } from '$lib/components/ui';

	let healthData = $state<HealthResponse | null>(null);
	let liveStats = $state<any>(null);
	let loading = $state(true);
	let liveLoading = $state(false);
	let liveError = $state('');
	let error = $state('');
	let autoRefresh = $state(false);
	let timer: ReturnType<typeof setInterval> | null = null;

	onMount(() => {
		loadHealth();
		loadLive();
	});

	async function loadLive() {
		liveLoading = true;
		liveError = '';
		try {
			const res = await fetch('/api/admin/monitor/live?sections=volume,threats,system');
			if (res.ok) liveStats = await res.json();
			else liveError = t('common.error');
		} catch (e) {
			liveError = parseError(e).message;
		} finally {
			liveLoading = false;
		}
	}

	function toggleRefresh() {
		autoRefresh = !autoRefresh;
		if (autoRefresh) { timer = setInterval(loadLive, 30000); }
		else if (timer) { clearInterval(timer); timer = null; }
	}

	async function loadHealth() {
		loading = true;
		error = '';
		try {
			healthData = await adminHealth();
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	function statusVariant(status: string): 'success' | 'warning' | 'danger' | 'neutral' {
		switch (status) {
			case 'ok': return 'success';
			case 'warn': return 'warning';
			case 'error': return 'danger';
			default: return 'neutral';
		}
	}

	const checks = $derived(healthData?.checks || []);
	const errors = $derived(checks.filter(h => h.status === 'error').length);
	const warns = $derived(checks.filter(h => h.status === 'warn').length);
	const oks = $derived(checks.filter(h => h.status === 'ok').length);

	const CHECK_COLUMNS: TableColumn[] = [
		{ key: 'check_name', label: t('admin.dashboard.check'), sortable: false },
		{ key: 'status', label: t('admin.table.status'), sortable: false },
		{ key: 'value', label: t('admin.dashboard.value'), sortable: false, mono: true },
		{ key: 'details', label: t('admin.dashboard.details'), sortable: false },
		{ key: 'checked_at', label: t('admin.dashboard.checked'), sortable: false },
	];
</script>

<div class="dashboard">
	<header class="sj-page-head">
		<div class="sj-page-head-left">
			<h1>{t('admin.dashboard')}</h1>
			<p class="sj-subtitle">{t('admin.dashboard.subtitle')}</p>
		</div>
		<div class="sj-page-head-right">
			<label class="sj-refresh-toggle">
				<Switch checked={autoRefresh} onchange={toggleRefresh} />
				{t('admin.dashboard.auto_refresh')}
			</label>
			<Button variant="ghost" size="sm" onclick={loadHealth}>{t('admin.common.refresh')}</Button>
		</div>
	</header>

	{#if error}
		<div class="sj-alert sj-alert--danger">{error}</div>
	{/if}

	{#if loading && !healthData}
		<EmptyState title={t('admin.dashboard.loading_health')} />
	{:else if healthData}
		<div class="sj-stat-grid">
			<Card>
				{#snippet children()}
					<div class="sj-stat">
						<span class="sj-stat-label">{t('admin.dashboard.total_checks')}</span>
						<span class="sj-stat-value">{checks.length}</span>
					</div>
				{/snippet}
			</Card>
			<Card>
				{#snippet children()}
					<div class="sj-stat">
						<span class="sj-stat-label">{t('admin.dashboard.ok')}</span>
						<span class="sj-stat-value sj-stat-value--success">{oks}</span>
					</div>
				{/snippet}
			</Card>
			<Card>
				{#snippet children()}
					<div class="sj-stat">
						<span class="sj-stat-label">{t('admin.dashboard.warnings')}</span>
						<span class="sj-stat-value sj-stat-value--warning">{warns}</span>
					</div>
				{/snippet}
			</Card>
			<Card>
				{#snippet children()}
					<div class="sj-stat">
						<span class="sj-stat-label">{t('admin.dashboard.errors')}</span>
						<span class="sj-stat-value sj-stat-value--danger">{errors}</span>
					</div>
				{/snippet}
			</Card>
		</div>

		{#if liveLoading}
			<EmptyState title={t('admin.dashboard.loading_live')} />
		{:else if liveError}
			<div class="sj-alert sj-alert--danger">{liveError}</div>
		{:else if liveStats && liveStats.volume}
			<div class="sj-live-stats">
				<Card>
					{#snippet children()}
						<div class="sj-live-stat">
							<span class="sj-live-count">{liveStats.volume.received24h}</span>
							<span class="sj-live-label">{t('admin.dashboard.received_24h')}</span>
						</div>
					{/snippet}
				</Card>
				<Card>
					{#snippet children()}
						<div class="sj-live-stat">
							<span class="sj-live-count">{liveStats.volume.sent24h}</span>
							<span class="sj-live-label">{t('admin.dashboard.sent_24h')}</span>
						</div>
					{/snippet}
				</Card>
				<Card>
					{#snippet children()}
						<div class="sj-live-stat">
							<span class="sj-live-count">{liveStats.system?.goroutines || 0}</span>
							<span class="sj-live-label">{t('admin.dashboard.goroutines')}</span>
						</div>
					{/snippet}
				</Card>
				<Card>
					{#snippet children()}
						<div class="sj-live-stat">
							<span class="sj-live-count">{liveStats.threats?.rblBlocks || 0}</span>
							<span class="sj-live-label">{t('admin.dashboard.rbl_blocks')}</span>
						</div>
					{/snippet}
				</Card>
				<Card>
					{#snippet children()}
						<div class="sj-live-stat">
							<span class="sj-live-count">{liveStats.threats?.authFailures || 0}</span>
							<span class="sj-live-label">{t('admin.dashboard.auth_failures')}</span>
						</div>
					{/snippet}
				</Card>
			</div>
		{/if}

		<Card flush={true}>
			{#snippet children()}
				{#if checks.length === 0}
					<EmptyState title={t('admin.dashboard.no_checks')} />
				{:else}
					{@const rows = checks.slice(0, 30) as unknown as Record<string, unknown>[]}
					<Table columns={CHECK_COLUMNS} rows={rows}>
						{#snippet cell(row, col)}
							{@const r = row as unknown as { check_name?: string; status: string; value: string | null; details?: string; checked_at?: string }}
							{#if col.key === 'check_name'}
								<span class="sj-check-name">{r.check_name?.replace(/_/g, ' ') ?? '-'}</span>
							{:else if col.key === 'status'}
								<Badge variant={statusVariant(r.status)} label={r.status === 'ok' ? t('admin.dashboard.ok') : r.status === 'warn' ? t('admin.dashboard.warnings') : r.status === 'error' ? t('admin.dashboard.errors') : r.status ?? '-'} dot={true} />
							{:else if col.key === 'value'}
								{r.value != null ? r.value : '-'}
							{:else if col.key === 'details'}
								<span class="sj-detail-cell" title={r.details ?? ''}>{r.details ?? '-'}</span>
							{:else if col.key === 'checked_at'}
								<span class="sj-checked-cell">{r.checked_at ? new Date(r.checked_at).toLocaleString() : '-'}</span>
							{/if}
						{/snippet}
					</Table>
				{/if}
			{/snippet}
		</Card>
	{/if}
</div>

<style>
	.dashboard {
		max-width: 980px;
	}

	.sj-page-head {
		display: flex;
		align-items: flex-start;
		gap: 12px;
		margin-bottom: 16px;
		flex-wrap: wrap;
	}
	.sj-page-head-left {
		flex: 1 1 260px;
		min-width: 0;
	}
	.sj-page-head-left h1 {
		margin: 0;
		font-size: clamp(20px, 16px + 1.2vw, 24px);
		font-weight: 600;
		letter-spacing: var(--tracking-display);
		color: var(--text-primary);
	}
	.sj-page-head-right {
		display: flex;
		gap: 8px;
		align-items: center;
	}
	.sj-subtitle {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin-top: 0.15rem;
	}

	.sj-refresh-toggle {
		font-size: var(--text-sm);
		display: flex;
		align-items: center;
		gap: 4px;
		cursor: pointer;
		color: var(--text-secondary);
	}

	.sj-alert {
		padding: 8px 12px;
		border-radius: var(--radius-sm);
		margin-bottom: 12px;
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
	}
	.sj-alert--danger {
		background: var(--danger-bg);
		color: var(--danger-fg);
		border: 1px solid var(--danger-fg);
	}

	.sj-stat-grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
		gap: 12px;
		margin-bottom: 16px;
	}
	.sj-stat {
		padding: 4px 0;
		display: flex;
		flex-direction: column;
		gap: 6px;
	}
	.sj-stat-label {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-secondary);
	}
	.sj-stat-value {
		font-size: var(--text-xl);
		font-weight: 600;
		color: var(--text-primary);
		font-family: var(--font-mono);
	}
	.sj-stat-value--success { color: var(--success-fg); }
	.sj-stat-value--warning { color: var(--warning-fg); }
	.sj-stat-value--danger { color: var(--danger-fg); }

	.sj-live-stats {
		display: flex;
		gap: 12px;
		margin-bottom: 16px;
	}
	.sj-live-stat {
		padding: 8px;
		text-align: center;
	}
	.sj-live-count {
		display: block;
		font-size: var(--text-2xl);
		font-weight: 700;
		color: var(--text-primary);
	}
	.sj-live-label {
		font-size: var(--text-xs);
		text-transform: uppercase;
		color: var(--text-tertiary);
		letter-spacing: var(--tracking-caps);
	}

	.sj-check-name {
		font-weight: var(--weight-medium);
	}
	.sj-detail-cell {
		max-width: 220px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		display: block;
	}
	.sj-checked-cell {
		font-size: var(--text-xs);
		font-family: var(--font-mono);
		color: var(--text-tertiary);
	}
</style>
