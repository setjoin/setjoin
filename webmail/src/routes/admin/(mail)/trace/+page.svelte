<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { adminTraceSearch, adminTraceExport, adminTraceTimeline, type TraceRecord, type TraceResponse, type TraceTimeline } from '$lib/admin/client';
	import { Card, Badge, Button, Input, Select, EmptyState, Spinner, Pagination } from '$lib/components/ui';
	import DeliveryTimelineDetail from './DeliveryTimelineDetail.svelte';
	import { downloadBlob } from '$lib/utils/downloadBlob';

	let records = $state<TraceRecord[]>([]);
	let total = $state(0);
	let loading = $state(false);
	let error = $state('');

	let filters = $state({ from: '', to: '', subject: '', event: '', status: '', dateFrom: '', dateTo: '' });
	let limit = $state(50);
	let offset = $state(0);
	let page = $derived(Math.floor(offset / limit) + 1);

	const eventOptions = ['','received','delivered','bounced','deferred','spam_filtered','rule_applied','quarantined','held','archived','expired'];

	async function search() {
		loading = true; error = '';
		try { const res: TraceResponse = await adminTraceSearch({ ...filters, limit, offset }); records = res.records; total = res.total; }
		catch (e) { error = (e as Error).message; }
		finally { loading = false; }
	}

	onMount(() => search());

	async function exportCSV() {
		try { const blob = await adminTraceExport(filters); downloadBlob(blob, `message-trace-${new Date().toISOString().slice(0, 10)}.csv`); }
		catch (e) { error = (e as Error).message; }
	}

	function eventBadgeVariant(ev: string): 'success' | 'info' | 'danger' | 'warning' | 'neutral' {
		switch (ev) { case 'delivered': return 'success'; case 'received': return 'info'; case 'bounced': return 'danger'; case 'deferred': return 'warning'; default: return 'neutral'; }
	}

	function fmtDate(iso: string): string { return new Date(iso).toLocaleString(); }

	// ── Drill-down state ──
	let expandedMessageId = $state<string | null>(null);
	let timelineData = $state<TraceTimeline | null>(null);
	let timelineLoading = $state(false);
	let timelineError = $state('');

	async function toggleTimeline(messageId: string) {
		if (expandedMessageId === messageId) {
			expandedMessageId = null;
			timelineData = null;
			timelineError = '';
			return;
		}
		expandedMessageId = messageId;
		timelineData = null;
		timelineError = '';
		timelineLoading = true;
		const target = messageId;
		try {
			const result = await adminTraceTimeline(messageId);
			if (expandedMessageId !== target) return;
			timelineData = result;
		} catch (e) {
			if (expandedMessageId !== target) return;
			timelineError = (e as Error).message;
		} finally {
			if (expandedMessageId === target) timelineLoading = false;
		}
	}
</script>

<div class="sj-page">
	<header class="sj-page-head">
		<div class="sj-page-head-left"><h1>Message trace</h1><p>Search delivery and routing events across the mail system.</p></div>
		<div class="sj-page-head-right"><Button variant="secondary" size="sm" onclick={exportCSV}>Export CSV</Button></div>
	</header>

	{#if error}<div class="alert alert-danger">{error}</div>{/if}

	<Card>
		{#snippet children()}
			<div class="sj-filter-bar">
				<Input placeholder="From" value={filters.from} oninput={(e) => filters.from = (e.target as HTMLInputElement).value} />
				<Input placeholder="To" value={filters.to} oninput={(e) => filters.to = (e.target as HTMLInputElement).value} />
				<Input placeholder="Subject" value={filters.subject} oninput={(e) => filters.subject = (e.target as HTMLInputElement).value} />
				<select class="sj-select" bind:value={filters.event}>
					{#each eventOptions as opt}<option value={opt}>{opt || 'All events'}</option>{/each}
				</select>
				<input class="sj-dt" type="datetime-local" bind:value={filters.dateFrom} />
				<input class="sj-dt" type="datetime-local" bind:value={filters.dateTo} />
				<Button variant="primary" size="sm" onclick={() => { offset = 0; search(); }} disabled={loading}>Search</Button>
			</div>
		{/snippet}
	</Card>

	<div style="margin-top:12px">
	<Card flush={true}>
		{#if loading}
			<EmptyState title="Loading…" />
		{:else if records.length === 0}
			<EmptyState title="No records found." />
		{:else}
			<table class="sj-table">
				<thead><tr><th>Time</th><th>Event</th><th>From</th><th>To</th><th>Message ID</th><th>Details</th></tr></thead>
				<tbody>
					{#each records as r}
						<tr class:sj-row-expanded={expandedMessageId === r.messageId}>
							<td>{fmtDate(r.occurredAt)}</td>
							<td><Badge variant={eventBadgeVariant(r.event)} label={r.event} /></td>
							<td>{r.fromAddr}</td>
							<td>{r.rcptAddr}</td>
							<td>
								<button
									class="sj-msgid-btn sj-mono"
									onclick={() => toggleTimeline(r.messageId)}
									aria-expanded={expandedMessageId === r.messageId}
									aria-label="Show delivery timeline for {r.messageId}"
									title={r.messageId}
								>{r.messageId.slice(0, 24)}…</button>
							</td>
							<td class="sj-mono">{r.details ? JSON.stringify(r.details).slice(0, 60) : '—'}</td>
						</tr>
						{#if expandedMessageId === r.messageId}
							<tr class="sj-detail-row">
								<td colspan="6" class="sj-detail-cell">
									{#if timelineLoading}
										<div class="sj-detail-loading">
											<Spinner size={16} label="Loading delivery timeline" />
											<span>Loading delivery timeline…</span>
										</div>
									{:else if timelineError}
										<p class="sj-detail-error">{timelineError}</p>
									{:else if timelineData}
										<DeliveryTimelineDetail timeline={timelineData} />
									{/if}
								</td>
							</tr>
						{/if}
					{/each}
				</tbody>
			</table>
			{#snippet footer()}
				<Pagination page={page} pageSize={limit} total={total}
					onPageChange={(p) => { offset = (p - 1) * limit; search(); }}
					onPageSizeChange={(s) => { limit = s; offset = 0; search(); }} />
			{/snippet}
		{/if}
	</Card>
	</div>
</div>

<style>
	.sj-page { max-width: 980px; }
	.sj-page-head { display: flex; align-items: flex-start; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; }
	.sj-page-head-left { flex: 1 1 260px; min-width: 0; }
	.sj-page-head-left h1 { margin: 0; font-size: clamp(20px, 16px + 1.2vw, 24px); font-weight: 600; letter-spacing: var(--tracking-display); color: var(--text-primary); }
	.sj-page-head-left p { margin: 4px 0 0; font-size: var(--text-sm); color: var(--text-secondary); }
	.sj-page-head-right { display: flex; gap: 8px; align-items: center; }
	.sj-filter-bar { display: flex; gap: 8px; flex-wrap: wrap; align-items: flex-end; }
	.sj-select { height: var(--control-height); padding: 0 10px; border: 1px solid var(--border-default); border-radius: var(--radius-sm); background: var(--surface-card); color: var(--text-primary); font: var(--font-sans); font-size: var(--text-sm); }
	.sj-select:focus-visible { outline: none; box-shadow: var(--focus-ring); }
	.sj-dt { height: var(--control-height); padding: 0 8px; border: 1px solid var(--border-default); border-radius: var(--radius-sm); background: var(--surface-card); color: var(--text-primary); font: var(--font-sans); font-size: var(--text-sm); }
	.sj-dt:focus-visible { outline: none; box-shadow: var(--focus-ring); }
	.sj-table { width: 100%; border-collapse: collapse; }
	.sj-table th { text-align: left; padding: 8px 12px; font-size: var(--text-2xs); letter-spacing: var(--tracking-caps); text-transform: uppercase; color: var(--text-tertiary); font-weight: 600; border-bottom: 1px solid var(--border-default); }
	.sj-table td { padding: 8px 12px; font-size: var(--text-sm); border-bottom: 1px solid var(--border-subtle); }
	.sj-mono { font-family: var(--font-mono); font-size: var(--text-xs); color: var(--text-secondary); }
	.alert { padding: 8px 12px; border-radius: var(--radius-sm); margin-bottom: 12px; font-size: var(--text-sm); }
	.alert-danger { background: var(--danger-bg); color: var(--danger-fg); border: 1px solid var(--danger-fg); }
	.sj-msgid-btn { background: none; border: none; padding: 0; cursor: pointer; font-family: var(--font-mono); font-size: var(--text-xs); color: var(--accent); text-decoration: underline; text-underline-offset: 2px; text-decoration-color: transparent; }
	.sj-msgid-btn:hover { text-decoration-color: var(--accent); }
	.sj-msgid-btn:focus-visible { outline: none; box-shadow: var(--focus-ring); border-radius: var(--radius-sm); }
	.sj-row-expanded td { background: var(--surface-raised); }
	.sj-detail-row td { padding: 0; border-bottom: 2px solid var(--accent); }
	.sj-detail-cell { padding: 0 !important; }
	.sj-detail-loading { display: flex; align-items: center; gap: 8px; padding: 12px 16px; font-size: var(--text-sm); color: var(--text-secondary); }
	.sj-detail-error { padding: 12px 16px; font-size: var(--text-sm); color: var(--danger-fg); margin: 0; }
</style>
