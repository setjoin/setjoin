<svelte:options runes={true} />

<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { adminFetch } from '$lib/admin/client';
	import { Card, Badge, Button, Checkbox } from '$lib/components/ui';

	let stats = $state<any>({ pass: 0, fail: 0, none: 0, temperror: 0, byDomain: [] });
	let failures = $state<any[]>([]);
	let trend = $state<any[]>([]);
	let autoRefresh = $state(false);
	// COV-3: each section owns its error slot; the rendered alert is the
	// aggregate of the slots. A slot is cleared only by its own section's
	// success, so a successful sibling (e.g. the 30s live-only poll) can never
	// hide another section's unresolved failure — retention-style semantics:
	// the alert clears only when every section's latest load succeeded.
	let liveError = $state('');
	let failuresError = $state('');
	let trendError = $state('');
	let loadError = $derived(liveError || failuresError || trendError);
	let timer: ReturnType<typeof setInterval> | null = null;

	onMount(() => loadAll());
	function toggle() { autoRefresh = !autoRefresh; if (autoRefresh) { timer = setInterval(loadLive, 30000); } else if (timer) { clearInterval(timer); timer = null; } }
	onDestroy(() => { if (timer) clearInterval(timer); });

	// adminFetch THROWS on non-OK (httpRequest's error path) — a rejected load
	// must surface the transport message instead of bubbling an unhandled
	// rejection out of onMount/polling (same shape as the retention page).
	// Each loader writes only its own slot above (never a sibling's).
	async function loadAll() { await Promise.all([loadLive(), loadFailures(), loadTrend()]); }
	async function loadLive() { try { const res = await adminFetch('/admin/dmarc/live'); if (res.ok) stats = await res.json(); liveError = ''; } catch (e) { liveError = e instanceof Error ? e.message : 'Failed to load DMARC stats'; } }
	async function loadFailures() { try { const res = await adminFetch('/admin/dmarc/failures?limit=100'); if (res.ok) failures = (await res.json()).failures || []; failuresError = ''; } catch (e) { failuresError = e instanceof Error ? e.message : 'Failed to load DMARC failures'; } }
	async function loadTrend() { try { const res = await adminFetch('/admin/dmarc/trend'); if (res.ok) trend = (await res.json()).days || []; trendError = ''; } catch (e) { trendError = e instanceof Error ? e.message : 'Failed to load DMARC trend'; } }

	function maxTrend() { let m = 1; for (const d of trend) m = Math.max(m, d.pass + d.fail + d.none); return m; }
	function policyVariant(p: string): 'success' | 'danger' | 'warning' | 'neutral' {
		switch (p) { case 'none': return 'neutral'; case 'quarantine': return 'warning'; case 'reject': return 'danger'; default: return 'neutral'; }
	}
</script>

<div class="sj-page">
	<header class="sj-page-head">
		<div class="sj-page-head-left"><h1>DMARC monitor</h1><p>Live DMARC report aggregation and failure tracking.</p></div>
		<div class="sj-page-head-right">
			<Checkbox checked={autoRefresh} label="Auto-refresh" onchange={toggle} />
		</div>
	</header>

	{#if loadError}<div class="alert alert-danger" role="alert">{loadError}</div>{/if}

	<div class="sj-stat-grid">
		<div class="sj-stat-card sj-stat--pass"><span class="sj-stat-count">{stats.pass}</span><span class="sj-stat-label">Pass</span></div>
		<div class="sj-stat-card sj-stat--fail"><span class="sj-stat-count">{stats.fail}</span><span class="sj-stat-label">Fail</span></div>
		<div class="sj-stat-card sj-stat--none"><span class="sj-stat-count">{stats.none}</span><span class="sj-stat-label">None</span></div>
		<div class="sj-stat-card sj-stat--temperror"><span class="sj-stat-count">{stats.temperror}</span><span class="sj-stat-label">TempError</span></div>
	</div>

	<Card title="Domains">
		{#snippet children()}
			<table class="sj-table">
				<thead><tr><th>Domain</th><th>Pass</th><th>Fail</th><th>Policy</th></tr></thead>
				<tbody>
					{#if stats.byDomain.length === 0}<tr><td colspan="4">No data today</td></tr>
					{:else}{#each stats.byDomain as d}<tr><td>{d.domain}</td><td>{d.pass}</td><td>{d.fail}</td><td><Badge variant={policyVariant(d.policy || 'none')} label={d.policy || 'none'} /></td></tr>{/each}{/if}
				</tbody>
			</table>
		{/snippet}
	</Card>

	<div style="margin-top:12px">
	<Card title="30-day trend">
		{#snippet children()}
			{#if trend.length > 0}
				<div class="sj-trend-chart">
					{#each trend as d}
						<div class="sj-bar-group" title={d.date + ': Pass ' + d.pass + ', Fail ' + d.fail + ', None ' + d.none}>
							<div class="sj-bar sj-bar--pass" style="height: {d.pass / maxTrend() * 80}px"></div>
							<div class="sj-bar sj-bar--fail" style="height: {d.fail / maxTrend() * 80}px"></div>
							<div class="sj-bar sj-bar--none" style="height: {d.none / maxTrend() * 80}px"></div>
						</div>
					{/each}
				</div>
			{:else}<p class="sj-hint">No trend data available</p>{/if}
		{/snippet}
	</Card>
	</div>

	<div style="margin-top:12px">
	<Card title="Recent failures">
		{#snippet children()}
			<table class="sj-table">
				<thead><tr><th>Time</th><th>From</th><th>SPF</th><th>DKIM</th><th>DMARC</th></tr></thead>
				<tbody>
					{#if failures.length === 0}<tr><td colspan="5">No recent failures</td></tr>
					{:else}{#each failures as f}<tr><td>{new Date(f.time).toLocaleTimeString()}</td><td>{f.from}</td><td>{f.spf}</td><td>{f.dkim}</td><td>{f.dmarc}</td></tr>{/each}{/if}
				</tbody>
			</table>
		{/snippet}
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
	.sj-stat-grid { display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; }
	.sj-stat-card { flex: 1; min-width: 120px; padding: 16px; border-radius: var(--radius-md); text-align: center; border: 1px solid var(--border-default); }
	.sj-stat-count { display: block; font-size: var(--text-2xl); font-weight: 700; }
	.sj-stat-label { font-size: var(--text-xs); text-transform: uppercase; letter-spacing: var(--tracking-caps); opacity: 0.8; }
	.sj-stat--pass { background: var(--success-bg); color: var(--success-fg); border-color: var(--success-fg); }
	.sj-stat--fail { background: var(--danger-bg); color: var(--danger-fg); border-color: var(--danger-fg); }
	.sj-stat--none { background: var(--surface-sunken); color: var(--text-secondary); }
	.sj-stat--temperror { background: var(--warning-bg); color: var(--warning-fg); border-color: var(--warning-fg); }
	.sj-table { width: 100%; border-collapse: collapse; }
	.sj-table th { text-align: left; padding: 8px 12px; font-size: var(--text-2xs); letter-spacing: var(--tracking-caps); text-transform: uppercase; color: var(--text-tertiary); font-weight: 600; border-bottom: 1px solid var(--border-default); }
	.sj-table td { padding: 8px 12px; font-size: var(--text-sm); border-bottom: 1px solid var(--border-subtle); }
	.sj-hint { font-size: var(--text-sm); color: var(--text-secondary); }
	.sj-trend-chart { display: flex; align-items: flex-end; gap: 2px; height: 100px; padding: 8px; background: var(--surface-sunken); border-radius: var(--radius-sm); }
	.sj-bar-group { flex: 1; display: flex; flex-direction: column; justify-content: flex-end; gap: 1px; }
	.sj-bar { width: 100%; min-height: 1px; border-radius: 1px; }
	.sj-bar--pass { background: var(--success-solid); }
	.sj-bar--fail { background: var(--danger-solid); }
	.sj-bar--none { background: var(--gray-400); }
</style>
