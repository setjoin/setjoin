<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { formatBytes } from '$lib/utils/display';
	import Icon from '$lib/components/Icon.svelte';
	import {
		Card, Table, Tabs, Badge, Button, Progress,
		EmptyState, Spinner, showToast,
		type TableColumn, type TabItem,
	} from '$lib/components/ui';
	import { parseError } from '$lib/errors';
	import { adminPermissions, hasPermission } from '$lib/stores/auth';
	import {
		adminStorageStatus,
		adminStorageDRScanStart,
		adminStorageDRScanList,
		adminStorageDRScanGet,
		adminStorageDRScanReconcile,
		type StorageStatus,
		type DRScan
	} from '$lib/admin/client';

	type BadgeVariant = 'neutral' | 'success' | 'warning' | 'danger' | 'info' | 'accent';

	let status = $state<StorageStatus | null>(null);
	let scans = $state<DRScan[]>([]);
	let activeScan = $state<DRScan | null>(null);
	let loading = $state(false);
	let error = $state('');
	let tab = $state<'status' | 'dr'>('status');
	let pollInterval: ReturnType<typeof setInterval> | null = null;

	const TAB_ITEMS: TabItem[] = [
		{ id: 'status', label: 'Cluster status' },
		{ id: 'dr', label: 'Disaster recovery' },
	];

	const SERVER_COLUMNS: TableColumn[] = [
		{ key: 'endpoint', label: 'Endpoint', sortable: false, mono: true },
		{ key: 'state', label: 'State', sortable: false },
		{ key: 'poolNumber', label: 'Pool', sortable: false },
		{ key: 'drives', label: 'Drives', sortable: false },
	];

	const SCAN_COLUMNS: TableColumn[] = [
		{ key: 'id', label: 'ID', sortable: false, mono: true },
		{ key: 'status', label: 'Status', sortable: false },
		{ key: 'totalScanned', label: 'Scanned', sortable: false },
		{ key: 'orphanedCount', label: 'Orphaned', sortable: false },
		{ key: 'missingCount', label: 'Missing', sortable: false },
		{ key: 'reimportedCount', label: 'Reimported', sortable: false },
		{ key: 'startedAt', label: 'Started', sortable: false },
		{ key: 'actions', label: '', sortable: false },
	];

	onMount(() => {
		loadStatus();
		loadScans();
		return () => {
			if (pollInterval) clearInterval(pollInterval);
		};
	});

	async function loadStatus() {
		try {
			status = await adminStorageStatus();
		} catch (e) { error = parseError(e).message; }
	}

	async function loadScans() {
		try {
			scans = await adminStorageDRScanList();
			const running = scans.find(s => s.status === 'running');
			if (running) {
				activeScan = running;
				startPolling();
			} else if (activeScan?.status === 'running') {
				activeScan = scans.find(s => s.id === activeScan!.id) || null;
			}
		} catch (e) { error = parseError(e).message; }
	}

	function startPolling() {
		if (pollInterval) clearInterval(pollInterval);
		pollInterval = setInterval(async () => {
			if (activeScan) {
				try {
					const updated = await adminStorageDRScanGet(activeScan.id);
					activeScan = updated;
					if (updated.status !== 'running') {
						clearInterval(pollInterval!);
						pollInterval = null;
						await loadScans();
					}
				} catch { /* ignore */ }
			}
		}, 3000);
	}

	async function startDRScan() {
		loading = true;
		try {
			const res = await adminStorageDRScanStart();
			activeScan = await adminStorageDRScanGet(res.id);
			startPolling();
			await loadScans();
		} catch (e) { error = parseError(e).message; }
		finally { loading = false; }
	}

	async function reconcileScan(scan: DRScan) {
		if (!confirm(`Re-import ${scan.orphanedCount} orphaned objects into the blobs table?`)) return;
		try {
			const res = await adminStorageDRScanReconcile(scan.id);
			await loadScans();
			if (activeScan?.id === scan.id) {
				activeScan = await adminStorageDRScanGet(scan.id);
			}
			showToast(`Re-imported ${res.reimported} objects.`);
		} catch (e) { error = parseError(e).message; }
	}

	function driveStateVariant(state: string): BadgeVariant {
		if (state === 'ok' || state === 'OK') return 'success';
		if (state === 'offline') return 'danger';
		return 'warning';
	}

	function scanStatusVariant(s: string): BadgeVariant {
		if (s === 'running') return 'info';
		if (s === 'completed') return 'success';
		if (s === 'failed') return 'danger';
		return 'neutral';
	}

	function issueVariant(issue: string): BadgeVariant {
		if (issue === 'orphaned') return 'warning';
		if (issue === 'missing') return 'danger';
		return 'neutral';
	}

	let serverRows = $derived((status?.servers ?? []) as unknown as Record<string, unknown>[]);
	let scanRows = $derived(scans as unknown as Record<string, unknown>[]);
</script>

<header class="page-header">
	<div class="page-header-left">
		<h1>Storage</h1>
		<p class="page-desc">Object-store cluster health and blob-integrity disaster recovery.</p>
	</div>
</header>

<h2 class="sr-only">{tab === 'status' ? 'Cluster status' : 'Disaster recovery'}</h2>
<Tabs items={TAB_ITEMS} active={tab} onChange={(id: string) => (tab = id as 'status' | 'dr')} />

{#if error}
	<p class="storage-error" role="alert">{error}</p>
{/if}

{#if tab === 'status'}
	{#if !status}
		<div class="storage-loading">
			<Spinner size={28} />
			<div>Loading cluster status…</div>
		</div>
	{:else}
		{@const s = status}
		<div class="stat-grid">
			<Card>
				{#snippet children()}
					<div class="stat"><span class="stat-label">Objects</span><span class="stat-value">{s.objects.count.toLocaleString()}</span></div>
				{/snippet}
			</Card>
			<Card>
				{#snippet children()}
					<div class="stat"><span class="stat-label">Size</span><span class="stat-value">{formatBytes(s.usage.size)}</span></div>
				{/snippet}
			</Card>
			<Card>
				{#snippet children()}
					<div class="stat"><span class="stat-label">Buckets</span><span class="stat-value">{s.buckets.count}</span></div>
				{/snippet}
			</Card>
			<Card>
				{#snippet children()}
					<div class="stat"><span class="stat-label">Online disks</span><span class="stat-value stat-value--ok">{s.backend.onlineDisks}</span></div>
				{/snippet}
			</Card>
		</div>

		<div class="card-stack">
			<Card title="Cluster">
				{#snippet children()}
					<dl class="kv">
						<div><dt>Mode</dt><dd>{s.mode}</dd></div>
						<div><dt>Version</dt><dd>{s.version}</dd></div>
						<div><dt>Deployment</dt><dd><code class="mono">{s.deploymentID}</code></dd></div>
					</dl>
				{/snippet}
			</Card>

			<Card title="Backend">
				{#snippet children()}
					<dl class="kv">
						<div><dt>Type</dt><dd>{s.backend.type === 1 ? 'Erasure' : 'FS'}</dd></div>
						<div><dt>Online disks</dt><dd><Badge variant="success" label={String(s.backend.onlineDisks)} /></dd></div>
						<div><dt>Offline disks</dt><dd><Badge variant={s.backend.offlineDisks > 0 ? 'danger' : 'success'} label={String(s.backend.offlineDisks)} /></dd></div>
						<div><dt>Standard parity</dt><dd>{s.backend.standardParity}</dd></div>
					</dl>
				{/snippet}
			</Card>

			{#if s.healing?.scannedItems}
				<Card title="Healing">
					{#snippet actions()}
						<Badge variant="warning" dot={true} label="Active" />
					{/snippet}
					{#snippet children()}
						<dl class="kv">
							<div><dt>Scanned items</dt><dd>{s.healing.scannedItems.toLocaleString()}</dd></div>
							<div><dt>Heal disks</dt><dd>{s.healing.healDisks?.join(', ') || '—'}</dd></div>
						</dl>
					{/snippet}
				</Card>
			{/if}

			<Card title="Pools">
				{#snippet children()}
					<div class="pool-grid">
						{#each s.pools as pool}
							<div class="pool-card">
								<h3 class="pool-title">Pool {pool.index}</h3>
								<p class="pool-meta">{pool.objects.toLocaleString()} objects &middot; {pool.sets} set{pool.sets === 1 ? '' : 's'}</p>
								<Progress
									value={pool.rawCapacity > 0 ? (pool.rawUsage / pool.rawCapacity) * 100 : 0}
									label={`Pool ${pool.index} usage`}
								/>
								<p class="pool-cap">{formatBytes(pool.rawUsage)} / {formatBytes(pool.rawCapacity)}</p>
							</div>
						{/each}
					</div>
				{/snippet}
			</Card>

			<Card title="Servers" flush={true}>
				{#snippet children()}
					<Table columns={SERVER_COLUMNS} rows={serverRows}>
					{#snippet cell(row, col)}
						{@const srv = row as unknown as StorageStatus['servers'][number]}
						{#if col.key === 'endpoint'}
							{srv.endpoint}
						{:else if col.key === 'state'}
								<Badge variant={srv.state === 'online' ? 'success' : 'danger'} dot={true} label={srv.state} />
							{:else if col.key === 'poolNumber'}
								{srv.poolNumber ?? '—'}
							{:else if col.key === 'drives'}
								<div class="drive-chips">
									{#each srv.drives as d}
										<span class="drive-chip drive-chip--{driveStateVariant(d.state)}">
											{d.endpoint} ({formatBytes(d.used)}/{formatBytes(d.total)})
										</span>
									{/each}
								</div>
							{/if}
						{/snippet}
					</Table>
				{/snippet}
			</Card>
		</div>

		<div class="page-actions">
			<Button variant="secondary" size="md" onclick={loadStatus}>Refresh</Button>
		</div>
	{/if}
{:else}
	<Card title="Disaster recovery scans">
		{#snippet actions()}
			<Button variant="primary" size="sm" onclick={startDRScan} disabled={loading || activeScan?.status === 'running' || !hasPermission($adminPermissions, 'system.config')}>
				{loading ? 'Starting…' : 'Start DR scan'}
			</Button>
		{/snippet}
		{#snippet children()}
			<p class="dr-intro">Verify object-store contents against the blobs table and reconcile orphans.</p>
		{/snippet}
	</Card>

	{#if activeScan?.status === 'running'}
		{@const a = activeScan}
		<div class="card-stack">
			<Card title={`Scan #${a.id} in progress`}>
				{#snippet children()}
					<Progress value={100} label="Scan in progress" />
					<p class="scan-progress-meta">Scanned: {a.totalScanned.toLocaleString()} objects</p>
				{/snippet}
			</Card>
		</div>
	{/if}

	{#if scans.length === 0}
		<EmptyState title="No DR scans yet. Start one to verify blob storage integrity." watermark={true} />
	{:else}
		<div class="card-stack">
			<Card flush={true}>
				{#snippet children()}
					<Table columns={SCAN_COLUMNS} rows={scanRows}>
						{#snippet cell(row, col)}
							{@const scan = row as unknown as DRScan}
							{#if col.key === 'id'}
								#{scan.id}
							{:else if col.key === 'status'}
								<Badge variant={scanStatusVariant(scan.status)} dot={true} label={scan.status} />
							{:else if col.key === 'totalScanned'}
								{scan.totalScanned.toLocaleString()}
							{:else if col.key === 'orphanedCount'}
								{#if scan.orphanedCount > 0}<Badge variant="warning" label={String(scan.orphanedCount)} />{:else}{scan.orphanedCount}{/if}
							{:else if col.key === 'missingCount'}
								{#if scan.missingCount > 0}<Badge variant="danger" label={String(scan.missingCount)} />{:else}{scan.missingCount}{/if}
							{:else if col.key === 'reimportedCount'}
								{scan.reimportedCount}
							{:else if col.key === 'startedAt'}
								{new Date(scan.startedAt).toLocaleString()}
							{:else if col.key === 'actions'}
								<div class="scan-actions">
									{#if scan.status === 'completed' && scan.orphanedCount > 0 && scan.reimportedCount === 0}
										<Button variant="primary" size="sm" onclick={() => reconcileScan(scan)} disabled={!hasPermission($adminPermissions, 'system.config')}>Reconcile</Button>
									{/if}
									<Button variant="ghost" size="sm" onclick={() => { activeScan = scan; }}>Details</Button>
								</div>
							{/if}
						{/snippet}
					</Table>
				{/snippet}
			</Card>
		</div>
	{/if}

	{#if activeScan && activeScan.status !== 'running'}
		{@const a = activeScan}
		<div class="card-stack">
			<Card title={`Scan #${a.id} details`}>
				{#snippet actions()}
					<Button variant="ghost" size="sm" onclick={() => (activeScan = null)}>Close</Button>
				{/snippet}
				{#snippet children()}
					<dl class="kv">
						<div><dt>Status</dt><dd><Badge variant={scanStatusVariant(a.status)} dot={true} label={a.status} /></dd></div>
						<div><dt>Total scanned</dt><dd>{a.totalScanned.toLocaleString()}</dd></div>
						<div><dt>Orphaned</dt><dd>{a.orphanedCount}</dd></div>
						<div><dt>Missing</dt><dd>{a.missingCount}</dd></div>
						<div><dt>Reimported</dt><dd>{a.reimportedCount}</dd></div>
					</dl>
					{#if a.details && a.details.length > 0}
						<details class="scan-details">
							<summary>Show {a.details.length} details</summary>
							<ul class="detail-list">
								{#each a.details as d}
									<li class="detail-row">
										<code class="mono">{d.sha256}</code>
										<Badge variant={issueVariant(d.issue)} label={d.issue} />
										{#if d.size !== undefined}<span class="detail-size">{formatBytes(d.size)}</span>{/if}
									</li>
								{/each}
							</ul>
						</details>
					{/if}
				{/snippet}
			</Card>
		</div>
	{/if}
{/if}

<style>
	.page-header {
		margin-bottom: 16px;
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

	.storage-error {
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--danger-fg);
		background: var(--danger-bg);
		border-radius: var(--radius-sm);
		padding: 8px 12px;
		margin: 12px 0;
	}

	.storage-loading {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 16px;
		padding: 48px 16px;
		color: var(--text-secondary);
		font-family: var(--font-sans);
		font-size: var(--text-sm);
	}

	.stat-grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
		gap: 12px;
		margin: 16px 0;
	}

	.stat {
		display: flex;
		flex-direction: column;
		gap: 6px;
	}

	.stat-label {
		font-family: var(--font-sans);
		font-size: var(--text-xs);
		letter-spacing: var(--tracking-caps);
		text-transform: uppercase;
		color: var(--text-tertiary);
	}

	.stat-value {
		font-family: var(--font-mono);
		font-size: var(--text-xl);
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
	}

	.stat-value--ok {
		color: var(--success-fg);
	}

	.card-stack {
		display: flex;
		flex-direction: column;
		gap: 14px;
		margin-bottom: 14px;
	}

	.kv {
		display: flex;
		flex-direction: column;
		gap: 8px;
		margin: 0;
	}

	.kv div {
		display: flex;
		gap: 10px;
		align-items: center;
	}

	.kv dt {
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-secondary);
		min-width: 120px;
	}

	.kv dd {
		margin: 0;
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-primary);
	}

	.mono {
		font-family: var(--font-mono);
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}

	.pool-grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
		gap: 12px;
	}

	.pool-card {
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		padding: 12px;
		background: var(--surface-sunken);
	}

	.pool-title {
		margin: 0 0 4px;
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
	}

	.pool-meta {
		margin: 0 0 8px;
		font-family: var(--font-sans);
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}

	.pool-cap {
		margin: 6px 0 0;
		font-family: var(--font-mono);
		font-size: var(--text-2xs);
		color: var(--text-tertiary);
	}

	.drive-chips {
		display: flex;
		flex-wrap: wrap;
		gap: 4px;
	}

	.drive-chip {
		font-family: var(--font-mono);
		font-size: var(--text-2xs);
		padding: 1px 5px;
		border-radius: var(--radius-xs);
		border: 1px solid var(--border-subtle);
		color: var(--text-secondary);
		background: var(--surface-sunken);
	}

	.drive-chip--success {
		color: var(--success-fg);
		background: var(--success-bg);
	}

	.drive-chip--danger {
		color: var(--danger-fg);
		background: var(--danger-bg);
	}

	.drive-chip--warning {
		color: var(--warning-fg);
		background: var(--warning-bg);
	}

	.page-actions {
		display: flex;
		gap: 8px;
		margin-top: 4px;
	}

	.dr-intro {
		margin: 0;
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}

	.scan-progress-meta {
		margin: 8px 0 0;
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}

	.scan-actions {
		display: flex;
		gap: 6px;
		justify-content: flex-end;
	}

	.scan-details {
		margin-top: 10px;
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}

	.scan-details summary {
		cursor: pointer;
	}

	.detail-list {
		list-style: none;
		padding: 0;
		max-height: 300px;
		overflow-y: auto;
		margin-top: 8px;
	}

	.detail-row {
		display: flex;
		gap: 8px;
		align-items: center;
		padding: 4px 0;
		border-bottom: 1px solid var(--border-subtle);
		font-size: var(--text-sm);
	}

	.detail-size {
		font-family: var(--font-mono);
		font-size: var(--text-2xs);
		color: var(--text-tertiary);
	}
</style>
