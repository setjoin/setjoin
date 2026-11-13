<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { adminReportsSummary, type MailFlowSummary } from '$lib/admin/client';
	import Icon from '$lib/components/Icon.svelte';

	let data = $state<MailFlowSummary | null>(null);
	let loading = $state(true);
	let error = $state('');
	let days = $state(7);

	async function load() {
		loading = true;
		error = '';
		try {
			data = await adminReportsSummary(days);
		} catch (e) {
			error = (e as Error).message;
		} finally {
			loading = false;
		}
	}

	onMount(() => load());

	function maxVal(arr: Array<{ sent?: number; received?: number; bounced?: number; spam?: number }>): number {
		let m = 1;
		for (const d of arr) {
			m = Math.max(m, (d.sent || 0) + (d.received || 0) + (d.bounced || 0) + (d.spam || 0));
		}
		return m;
	}

	const dailyMax = $derived(data ? maxVal(data.daily) : 1);
</script>

<header class="page-header">
	<h1>Mail Flow Reports</h1>
	<select class="input" style="width:auto" bind:value={days} onchange={() => load()}>
		<option value={7}>Last 7 days</option>
		<option value={14}>Last 14 days</option>
		<option value={30}>Last 30 days</option>
	</select>
</header>

{#if error}
	<div class="alert alert-danger">{error}</div>
{/if}

{#if loading}
	<div class="empty-state">
		<div>Loading…</div>
	</div>
{:else if data}
	<div class="stat-grid">
		<div class="stat-card">
			<div class="stat-label">Sent</div>
			<div class="stat-value">{data.totalSent.toLocaleString()}</div>
		</div>
		<div class="stat-card">
			<div class="stat-label">Received</div>
			<div class="stat-value">{data.totalReceived.toLocaleString()}</div>
		</div>
		<div class="stat-card">
			<div class="stat-label">Bounced</div>
			<div class="stat-value danger">{data.totalBounced.toLocaleString()}</div>
		</div>
		<div class="stat-card">
			<div class="stat-label">Spam Filtered</div>
			<div class="stat-value warning">{data.spamCount.toLocaleString()}</div>
		</div>
	</div>

	{#if data.daily.length > 0}
		<div class="card" style="margin-bottom:1.5rem">
			<div class="card-header">Daily Volume</div>
			<div class="card-body">
				<div class="chart">
					{#each data.daily as d}
						<div class="bar-group" title={d.date}>
							<div class="bar" style="height: {(d.received / dailyMax * 120)}px; background: var(--success-solid)"></div>
							<div class="bar" style="height: {(d.sent / dailyMax * 120)}px; background: var(--info-solid)"></div>
							<div class="bar" style="height: {(d.bounced / dailyMax * 120)}px; background: var(--danger-solid)"></div>
							<div class="chart-label">{d.date.slice(5)}</div>
						</div>
					{/each}
				</div>
				<div class="legend">
					<span><span class="dot received"></span> Received</span>
					<span><span class="dot sent"></span> Sent</span>
					<span><span class="dot bounced"></span> Bounced</span>
				</div>
			</div>
		</div>
	{/if}

	<div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 1.5rem;">
		{#if data.topSenders.length > 0}
			<div class="card">
				<div class="card-header">Top Senders</div>
				<div class="card-body" style="padding:0">
					<table class="data-table">
						<thead><tr><th>Email</th><th>Count</th></tr></thead>
						<tbody>
							{#each data.topSenders as s}
								<tr><td>{s.email}</td><td>{s.count}</td></tr>
							{/each}
						</tbody>
					</table>
				</div>
			</div>
		{/if}
		{#if data.topRecipients.length > 0}
			<div class="card">
				<div class="card-header">Top Recipients</div>
				<div class="card-body" style="padding:0">
					<table class="data-table">
						<thead><tr><th>Email</th><th>Count</th></tr></thead>
						<tbody>
							{#each data.topRecipients as s}
								<tr><td>{s.email}</td><td>{s.count}</td></tr>
							{/each}
						</tbody>
					</table>
				</div>
			</div>
		{/if}
		{#if data.ruleTriggers.length > 0}
			<div class="card">
				<div class="card-header">Rule Triggers</div>
				<div class="card-body" style="padding:0">
					<table class="data-table">
						<thead><tr><th>Rule</th><th>Count</th></tr></thead>
						<tbody>
							{#each data.ruleTriggers as s}
								<tr><td>{s.ruleName}</td><td>{s.count}</td></tr>
							{/each}
						</tbody>
					</table>
				</div>
			</div>
		{/if}
	</div>
{:else}
	<div class="empty-state">
		<div class="empty-state-icon"><Icon name="TrendingUp" size={40} /></div>
		<div>No data yet.</div>
	</div>
{/if}
