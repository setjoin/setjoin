<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { adminFetch } from '$lib/admin/client';
	import { Card, Badge, Button, Table, Spinner, EmptyState } from '$lib/components/ui';
	import type { TableColumn } from '$lib/components/ui';

	interface VersionCount { version: string; count: number; }
	interface PlatformCount { platform: string; count: number; }
	interface DeviceInfo { id: number; name: string; platform: string; os_version: string; app_version: string; last_seen: string; status: string; }

	let summary = $state({ total_devices: 0, up_to_date: 0, outdated: 0, critical: 0, by_version: [] as VersionCount[], by_platform: [] as PlatformCount[] });
	let devices = $state<DeviceInfo[]>([]);
	let loading = $state(true);
	let error = $state('');

	onMount(async () => {
		try {
			const [sumRes, devRes] = await Promise.all([
				adminFetch('/admin/updates/summary'),
				adminFetch('/admin/updates/devices?limit=50'),
			]);
			summary = await sumRes.json();
			const devData = await devRes.json();
			devices = devData.devices || [];
		} catch (e) {
			error = 'Could not load version data.';
		} finally {
			loading = false;
		}
	});

	function platformVariant(p: string): 'info' | 'accent' | 'success' | 'neutral' {
		const lower = p.toLowerCase();
		if (lower.includes('ios')) return 'info';
		if (lower.includes('android')) return 'success';
		if (lower.includes('mac')) return 'accent';
		if (lower.includes('windows')) return 'info';
		return 'neutral';
	}

	function statusVariant(s: string): 'success' | 'warning' | 'danger' | 'neutral' {
		const lower = s.toLowerCase();
		if (lower === 'up to date' || lower === 'current') return 'success';
		if (lower === 'outdated') return 'warning';
		if (lower === 'critical') return 'danger';
		return 'neutral';
	}

	const DEVICE_COLUMNS: TableColumn[] = [
		{ key: 'name', label: 'Device', sortable: false },
		{ key: 'platform', label: 'Platform', sortable: false },
		{ key: 'app_version', label: 'Version', sortable: false },
		{ key: 'last_seen', label: 'Last seen', sortable: false },
		{ key: 'status', label: 'Status', sortable: false },
	];

	const VERSION_COLUMNS: TableColumn[] = [
		{ key: 'version', label: 'Version', sortable: false },
		{ key: 'count', label: 'Devices', sortable: false },
	];

	const PLATFORM_COLUMNS: TableColumn[] = [
		{ key: 'platform', label: 'Platform', sortable: false },
		{ key: 'count', label: 'Devices', sortable: false },
	];
</script>

<div class="sj-page">
	<header class="sj-page-head">
		<div class="sj-page-head-left">
			<h1>Client Versions</h1>
			<p class="sj-page-desc">Monitor client app versions across your organization and push updates.</p>
		</div>
	</header>

	{#if loading}
		<Spinner label="Loading device data..." />
	{:else if error}
		<div class="sj-alert-danger" role="alert">{error}</div>
	{:else}
		<div class="sj-summary-grid">
			<Card>
				{#snippet children()}
					<div class="sj-stat-cell">
						<span class="sj-stat-value">{summary.total_devices}</span>
						<span class="sj-stat-label">Total devices</span>
					</div>
				{/snippet}
			</Card>
			<Card>
				{#snippet children()}
					<div class="sj-stat-cell">
						<span class="sj-stat-value sj-stat-value--success">{summary.up_to_date}</span>
						<span class="sj-stat-label">Up to date</span>
					</div>
				{/snippet}
			</Card>
			<Card>
				{#snippet children()}
					<div class="sj-stat-cell">
						<span class="sj-stat-value sj-stat-value--warning">{summary.outdated}</span>
						<span class="sj-stat-label">Outdated</span>
					</div>
				{/snippet}
			</Card>
			<Card>
				{#snippet children()}
					<div class="sj-stat-cell">
						<span class="sj-stat-value sj-stat-value--danger">{summary.critical}</span>
						<span class="sj-stat-label">Critical</span>
					</div>
				{/snippet}
			</Card>
		</div>

		{#if summary.by_version.length > 0}
			<h2 class="sj-section-head">Version Distribution</h2>
			<Card flush={true}>
				{#snippet children()}
					{@const vrows = summary.by_version as unknown as Record<string, unknown>[]}
					<Table columns={VERSION_COLUMNS} rows={vrows} />
				{/snippet}
			</Card>
		{/if}

		{#if summary.by_platform.length > 0}
			<h2 class="sj-section-head">Platform Distribution</h2>
			<Card flush={true}>
				{#snippet children()}
					{@const prows = summary.by_platform.map(p => ({ ...p, _platform: p.platform })) as unknown as Record<string, unknown>[]}
					<Table columns={PLATFORM_COLUMNS} rows={prows}>
						{#snippet cell(row, col)}
							{#if col.key === 'platform'}
								<Badge variant={platformVariant(String(row.platform))} label={String(row.platform)} />
							{/if}
						{/snippet}
					</Table>
				{/snippet}
			</Card>
		{/if}

		<h2 class="sj-section-head">Devices</h2>
		<Card flush={true}>
			{#snippet children()}
				{#if devices.length === 0}
					<EmptyState title="No devices registered." />
				{:else}
					{@const drows = devices.map(d => ({
						_id: d.id,
						name: d.name || `Device #${d.id}`,
						platform: d.platform,
						app_version: d.app_version || '—',
						last_seen: d.last_seen ? new Date(d.last_seen).toLocaleString() : '—',
						status: d.status,
					})) as unknown as Record<string, unknown>[]}
					<Table columns={DEVICE_COLUMNS} rows={drows}>
						{#snippet cell(row, col)}
							{@const d = row as unknown as { _id: number; name: string; platform: string; app_version: string; last_seen: string; status: string }}
							{#if col.key === 'name'}
								<span class="sj-device-name">{d.name}</span>
							{:else if col.key === 'platform'}
								<Badge variant={platformVariant(d.platform)} label={d.platform} />
							{:else if col.key === 'app_version'}
								<span class="sj-mono-cell">{d.app_version}</span>
							{:else if col.key === 'last_seen'}
								<span class="sj-muted-cell">{d.last_seen}</span>
							{:else if col.key === 'status'}
								<Badge variant={statusVariant(d.status)} label={d.status} dot={true} />
							{/if}
						{/snippet}
					</Table>
				{/if}
			{/snippet}
		</Card>
	{/if}
</div>

<style>
	.sj-page { max-width: 960px; }
	.sj-page-head {
		display: flex;
		align-items: flex-start;
		gap: 12px;
		margin-bottom: 16px;
		flex-wrap: wrap;
	}
	.sj-page-head-left { flex: 1 1 260px; min-width: 0; }
	.sj-page-head-left h1 {
		margin: 0;
		font-size: clamp(20px, 16px + 1.2vw, 24px);
		font-weight: 600;
		letter-spacing: var(--tracking-display);
		color: var(--text-primary);
	}
	.sj-page-desc {
		margin: 4px 0 0;
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.sj-alert-danger {
		padding: 8px 12px;
		border-radius: var(--radius-sm);
		margin: 12px 0;
		font-size: var(--text-sm);
		background: var(--danger-bg);
		color: var(--danger-fg);
		border: 1px solid var(--danger-fg);
	}
	.sj-section-head {
		margin: 20px 0 8px;
		font-size: var(--text-lg);
		font-weight: 600;
		color: var(--text-primary);
	}
	.sj-summary-grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
		gap: 12px;
		margin-top: 12px;
	}
	.sj-stat-cell {
		padding: 8px;
		text-align: center;
		display: flex;
		flex-direction: column;
		gap: 4px;
	}
	.sj-stat-value {
		font-size: var(--text-2xl);
		font-weight: 700;
		color: var(--text-primary);
	}
	.sj-stat-value--success { color: var(--success-fg); }
	.sj-stat-value--warning { color: var(--warning-fg); }
	.sj-stat-value--danger { color: var(--danger-fg); }
	.sj-stat-label {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}
	.sj-device-name { font-size: var(--text-sm); font-weight: 500; color: var(--text-primary); }
	.sj-mono-cell { font-family: var(--font-mono); font-size: var(--text-xs); color: var(--text-secondary); }
	.sj-muted-cell { font-size: var(--text-xs); color: var(--text-tertiary); }
</style>
