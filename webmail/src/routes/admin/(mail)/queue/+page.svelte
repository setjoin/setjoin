<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { adminPermissions, hasPermission } from '$lib/stores/auth';
	import { adminFetch } from '$lib/admin/client';
	import { parseError } from '$lib/errors';
	import { Card, Table, Tabs, Badge, Button, EmptyState, Spinner, showToast } from '$lib/components/ui';
	import type { TableColumn, TabItem } from '$lib/components/ui';

	interface QueueItem {
		id: number;
		messageId: string;
		fromAddr: string;
		recipients: string[];
		status: string;
		attemptCount: number;
		nextAttemptAt: string;
		lastError: string;
		queuedAt: string;
		mailboxId: number | null;
	}

	let items = $state<QueueItem[]>([]);
	let summary = $state({ pending: 0, deferred: 0, bouncedToday: 0, stuck: 0, oldestMinutes: '0 min' });
	let statusFilter = $state<string>('all');
	let loading = $state(false);
	let error = $state('');
	let retrying = $state<Set<number>>(new Set());

	onMount(async () => {
		await loadAll();
	});

	async function loadAll() {
		loading = true;
		error = '';
		try {
			const [sRes, qRes] = await Promise.all([
				adminFetch('/admin/queue/summary'),
				adminFetch('/admin/queue?status=' + (statusFilter === 'all' ? '' : statusFilter) + '&limit=100')
			]);
			summary = await sRes.json();
			items = await qRes.json();
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	async function retryItem(id: number) {
		retrying = new Set(retrying).add(id);
		try {
			await adminFetch(`/admin/queue/${id}/retry`, { method: 'POST' });
			await loadAll();
			showToast('Retrying delivery now');
		} catch (e) {
			error = parseError(e).message;
		} finally {
			const next = new Set(retrying);
			next.delete(id);
			retrying = next;
		}
	}

	async function bounceItem(id: number) {
		retrying = new Set(retrying).add(id);
		try {
			await adminFetch(`/admin/queue/${id}/bounce`, { method: 'POST' });
			await loadAll();
			showToast('Released to recipient inbox', { actionLabel: 'Undo', onAction: async () => { await retryItem(id); } });
		} catch (e) {
			error = parseError(e).message;
		} finally {
			const next = new Set(retrying);
			next.delete(id);
			retrying = next;
		}
	}

	function formatSince(iso: string) {
		if (!iso) return '';
		const seconds = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
		if (seconds < 60) return `${seconds}s ago`;
		if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
		if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
		return `${Math.floor(seconds / 86400)}d ago`;
	}

	function truncate(s: string, n: number) {
		return s.length > n ? s.slice(0, n) + '...' : s;
	}

	function statusBadgeVariant(status: string): 'info' | 'danger' | 'warning' | 'neutral' {
		switch (status) {
			case 'pending': return 'info';
			case 'deferred': return 'warning';
			case 'delivered': return 'neutral';
			case 'bounced': return 'danger';
			default: return 'neutral';
		}
	}

	const tabItems: TabItem[] = $derived([
		{ id: 'all', label: 'All', count: summary.pending + summary.deferred + summary.bouncedToday + summary.stuck },
		{ id: 'pending', label: 'Pending', count: summary.pending },
		{ id: 'deferred', label: 'Deferred', count: summary.deferred },
		{ id: 'failed', label: 'Failed', count: summary.bouncedToday },
		{ id: 'held', label: 'Held', count: summary.stuck },
	]);

	const COLUMNS: TableColumn[] = [
		{ key: 'status', label: 'Status', sortable: false },
		{ key: 'to', label: 'To', sortable: false, mono: true },
		{ key: 'subject', label: 'Subject', sortable: false },
		{ key: 'age', label: 'Age', sortable: false, mono: true },
		{ key: 'detail', label: 'Detail', sortable: false },
		{ key: 'actions', label: '', sortable: false },
	];
</script>

<div class="sj-queue-page">
	<header class="sj-page-head">
		<div class="sj-page-head-left">
			<h1>Mail queue</h1>
			<p>Outbound deliveries and quarantine holds.</p>
		</div>
		<div class="sj-page-head-right">
			<Button variant="secondary" size="sm" onclick={loadAll} disabled={loading}>Refresh</Button>
		</div>
	</header>

	{#if error}
		<div class="alert alert-danger">{error}</div>
	{/if}

	<div class="sj-stat-grid">
		<Card>
			{#snippet children()}
				<div class="sj-stat">
					<span class="sj-stat-label">Pending</span>
					<span class="sj-stat-value">{summary.pending}</span>
				</div>
			{/snippet}
		</Card>
		<Card>
			{#snippet children()}
				<div class="sj-stat">
					<span class="sj-stat-label">Deferred</span>
					<span class="sj-stat-value sj-stat-value--warn">{summary.deferred}</span>
				</div>
			{/snippet}
		</Card>
		<Card>
			{#snippet children()}
				<div class="sj-stat">
					<span class="sj-stat-label">Bounced (24h)</span>
					<span class="sj-stat-value">{summary.bouncedToday}</span>
				</div>
			{/snippet}
		</Card>
		<Card>
			{#snippet children()}
				<div class="sj-stat">
					<span class="sj-stat-label">Stuck (10+)</span>
					<span class="sj-stat-value sj-stat-value--danger">{summary.stuck}</span>
				</div>
			{/snippet}
		</Card>
		<Card>
			{#snippet children()}
				<div class="sj-stat">
					<span class="sj-stat-label">Oldest</span>
					<span class="sj-stat-value">{summary.oldestMinutes}</span>
				</div>
			{/snippet}
		</Card>
	</div>

	<Tabs items={tabItems} active={statusFilter} onChange={(id: string) => { statusFilter = id; loadAll(); }} />

	<div class="sj-queue-table-wrap">
		<Card flush={true}>
			{#if loading}
				<EmptyState title="Loading…" />
			{:else if items.length === 0}
				<EmptyState title="Queue is empty." />
			{:else}
				{@const rows = items as unknown as Record<string, unknown>[]}
				<Table columns={COLUMNS} rows={rows}>
					{#snippet cell(row, col)}
						{@const item = row as unknown as QueueItem}
						{#if col.key === 'status'}
							<Badge variant={statusBadgeVariant(item.status)} dot={true} label={item.status} />
						{:else if col.key === 'to'}
							{item.recipients?.slice(0, 2).join(', ') || ''}{item.recipients?.length > 2 ? ' +' + (item.recipients.length - 2) : ''}
						{:else if col.key === 'subject'}
							<span class="sj-subject-cell">{truncate(item.fromAddr + ' — ' + (item.recipients?.[0] || ''), 40)}</span>
						{:else if col.key === 'age'}
							{formatSince(item.queuedAt)}
						{:else if col.key === 'detail'}
							<span class="sj-detail-cell" class:sj-detail-cell--error={!!item.lastError}>
								{truncate(item.lastError || `tries: ${item.attemptCount}`, 40)}
							</span>
						{:else if col.key === 'actions'}
							<div class="sj-actions">
								{#if item.status === 'deferred' || (item.attemptCount >= 10 && item.status === 'pending')}
									<Button variant="secondary" size="sm" onclick={() => retryItem(item.id)} disabled={retrying.has(item.id) || !hasPermission($adminPermissions, 'queue.write')}>
										{retrying.has(item.id) ? 'Retrying…' : 'Retry'}
									</Button>
									<Button variant="ghost" size="sm" onclick={() => bounceItem(item.id)} disabled={retrying.has(item.id) || !hasPermission($adminPermissions, 'queue.write')}>
										Release
									</Button>
								{/if}
							</div>
						{/if}
					{/snippet}
				</Table>
			{/if}
		</Card>
	</div>
</div>

<style>
	.sj-queue-page {
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
	.sj-page-head-left p {
		margin: 4px 0 0;
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.sj-page-head-right {
		display: flex;
		gap: 8px;
		align-items: center;
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
	.sj-stat-value--warn {
		color: var(--warning-fg);
	}
	.sj-stat-value--danger {
		color: var(--danger-fg);
	}
	.sj-queue-table-wrap {
		margin-top: 14px;
	}
	.sj-subject-cell {
		max-width: 220px;
		overflow: hidden;
		text-overflow: ellipsis;
		display: block;
	}
	.sj-detail-cell {
		max-width: 260px;
		overflow: hidden;
		text-overflow: ellipsis;
		display: block;
		font-size: var(--text-2xs);
		font-family: var(--font-mono);
		color: var(--text-tertiary);
	}
	.sj-detail-cell--error {
		color: var(--danger-fg);
	}
	.sj-actions {
		display: flex;
		gap: 4px;
		justify-content: flex-end;
	}
	.alert {
		padding: 8px 12px;
		border-radius: var(--radius-sm);
		margin-bottom: 12px;
		font-size: var(--text-sm);
	}
	.alert-danger {
		background: var(--danger-bg);
		color: var(--danger-fg);
		border: 1px solid var(--danger-fg);
	}
</style>
