<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { adminFetch } from '$lib/admin/client';
	import { adminPermissions, hasPermission } from '$lib/stores/auth';
	import { downloadBlob } from '$lib/utils/downloadBlob';
	import { Card, Button, Badge, Table, Spinner, EmptyState, Input, Select, showToast } from '$lib/components/ui';
	import type { TableColumn } from '$lib/components/ui';

	let health = $state<any>({});
	let backups = $state<any[]>([]);
	let version = $state<any>({});
	let schemaVersion = $state({ current: 0, expected: 0, up_to_date: true });
	let loading = $state(false);
	let backupRunning = $state(false);
	let importResult = $state('');

	let listenAddr = $state('');
	let listenAddrSaving = $state(false);
	let listenAddrChanged = $state(false);
	let httpMode = $state('redirect');

	let replicaProvider = $state('');
	let replicaEndpoint = $state('');
	let replicaBucket = $state('');
	let replicaAccessKey = $state('');
	let replicaSecretKey = $state('');

	let haStatus = $state('');
	let haDeploying = $state(false);

	let brandName = $state('SetJoin');
	let brandLogoUrl = $state('');
	let brandLogoFile = $state<File | null>(null);
	let brandSaving = $state(false);

	onMount(() => { loadAll(); loadBranding(); });

	async function loadAll() {
		await Promise.all([loadHealth(), loadBackups(), loadVersion(), loadConfig()]);
	}

	async function loadHealth() {
		const res = await adminFetch('/admin/system/health');
		if (res.ok) health = await res.json();
	}
	async function loadBackups() {
		const res = await adminFetch('/admin/system/backup/list');
		if (res.ok) backups = (await res.json()).items || [];
	}
	async function deleteBackup(id: number, path: string) {
		if (!confirm('Delete this backup? This cannot be undone.')) return;
		// Server-provided values are always URL-encoded before interpolation
		// (encode-server-data invariant; mirrors the download sibling below) —
		// a path is never allowed to alter the query string.
		const res = await adminFetch(`/admin/system/backup?id=${encodeURIComponent(String(id))}&path=${encodeURIComponent(path)}`, { method: 'DELETE' });
		if (!res.ok) {
			showToast('Failed to delete backup');
			return;
		}
		await loadBackups();
	}
	async function loadVersion() {
		const res = await adminFetch('/admin/system/version');
		if (res.ok) version = await res.json();
		try {
			const mRes = await adminFetch('/admin/system/schema-version');
			if (mRes.ok) schemaVersion = await mRes.json();
		} catch { /* schema_migrations table may not exist yet */ }
	}

	async function loadConfig() {
		const addrRes = await adminFetch('/admin/system/config/get?key=listen.addr');
		if (addrRes.ok) {
			const data = await addrRes.json();
			listenAddr = data.value || ':443';
		}
		const modeRes = await adminFetch('/admin/system/config/get?key=http.mode');
		if (modeRes.ok) {
			const data = await modeRes.json();
			httpMode = data.value || 'redirect';
		}
	}

	async function loadBranding() {
		try {
			const resp = await adminFetch('/admin/branding');
			if (resp.ok) {
				const data = await resp.json();
				brandName = data.name || 'SetJoin';
				brandLogoUrl = data.logoUrl || '';
			}
		} catch { /* use defaults */ }
	}

	async function saveBranding() {
		brandSaving = true;
		try {
			const form = new FormData();
			form.append('name', brandName);
			if (brandLogoFile) form.append('logo', brandLogoFile);
			await adminFetch('/admin/branding', { method: 'POST', body: form });
			brandLogoFile = null;
			await loadBranding();
		} finally {
			brandSaving = false;
		}
	}

	async function triggerBackup() {
		backupRunning = true;
		const res = await adminFetch('/admin/system/backup', { method: 'POST' });
		if (res.ok) {
			setTimeout(loadBackups, 2000);
			setTimeout(loadBackups, 5000);
			setTimeout(() => { backupRunning = false; loadBackups(); }, 15000);
		}
	}

	async function exportConfig() {
		const res = await adminFetch('/admin/system/config/export');
		if (!res.ok) { alert('Export failed'); return; }
		const blob = await res.blob();
		downloadBlob(blob, 'mailserver-config.json');
	}

	async function importConfig(file: File) {
		const text = await file.text();
		let config: unknown;
		try { config = JSON.parse(text); } catch {
			importResult = 'Invalid JSON file';
			return;
		}
		const res = await adminFetch('/admin/system/config/import', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(config),
		});
		if (!res.ok) {
			importResult = 'Import failed: ' + await res.text();
			return;
		}
		importResult = 'Configuration imported successfully';
	}

	async function enableHA() {
		const standbyIPs = prompt('Enter standby server IPs (comma-separated):');
		if (!standbyIPs) return;
		const ips = standbyIPs.split(',').map((s: string) => s.trim());
		if (ips.length < 2) { alert('Need at least 2 standby IPs'); return; }
		const sshUser = prompt('SSH user for remote nodes:', 'root');
		if (!sshUser) return;
		const sshKey = prompt('SSH private key (inline or path):', '');
		if (!sshKey) return;

		const primaryIP = prompt('Primary node IP (this server):', window.location.hostname);
		if (!primaryIP) return;

		const nodes = [
			{ host: primaryIP, role: 'primary', ssh_user: sshUser, ssh_key: sshKey },
			{ host: ips[0], role: 'standby', ssh_user: sshUser, ssh_key: sshKey },
			{ host: ips[1], role: 'standby', ssh_user: sshUser, ssh_key: sshKey },
		];

		haDeploying = true;
		haStatus = 'Deploying...';
		const res = await adminFetch('/admin/deploy/start', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ nodes }),
		});
		if (res.ok) {
			haStatus = 'Deployment started';
			const poll = setInterval(async () => {
				const s = await adminFetch('/admin/deploy/status');
				if (s.ok) {
					const data = await s.json();
					haStatus = data.status || data.Status || 'deploying';
					if (haStatus === 'done' || haStatus === 'failed') {
						clearInterval(poll);
						haDeploying = false;
					}
				}
			}, 5000);
		} else {
			haStatus = 'Failed to start deployment';
			haDeploying = false;
		}
	}

	async function saveListenAddr() {
		listenAddrSaving = true;
		try {
			await adminFetch('/admin/system/config/set', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ key: 'listen.addr', value: listenAddr }),
			});
			listenAddrChanged = false;
			await adminFetch('/admin/reload', { method: 'POST' });
		} catch (e) {
			console.error('Failed to save listen address', e);
		} finally {
			listenAddrSaving = false;
		}
	}

	async function saveHTTPMode() {
		await adminFetch('/admin/system/config/set', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ key: 'http.mode', value: httpMode }),
		});
	}


	function healthVariant(s: string): 'success' | 'danger' | 'neutral' {
		if (s === 'ok') return 'success';
		if (s === 'error') return 'danger';
		return 'neutral';
	}

	const BACKUP_PROVIDER_OPTIONS = [
		{ value: 's3', label: 'Amazon S3' },
		{ value: 'b2', label: 'Backblaze B2' },
		{ value: 'oss', label: 'Aliyun OSS' },
		{ value: 'generic', label: 'Other S3-compatible' },
	];

	const HTTP_MODE_OPTIONS = [
		{ value: 'redirect', label: 'Redirect :80 to :443' },
		{ value: 'serve', label: 'Serve content on :80' },
	];

	const BACKUP_COLUMNS: TableColumn[] = [
		{ key: 'date', label: 'Date', sortable: false },
		{ key: 'status', label: 'Status', sortable: false },
		{ key: 'size', label: 'Size', sortable: false, mono: true },
		{ key: 'actions', label: '', sortable: false },
	];
</script>

<div class="sj-page">
	<header class="sj-page-head">
		<div class="sj-page-head-left">
			<h1>System</h1>
		</div>
	</header>

	<h2 class="sj-section-head">Health</h2>
	<div class="sj-health-grid">
		<Card>
			{#snippet children()}
				<div class="sj-hc">
					<div class="sj-hc-row">
						<span class="sj-hc-label">DB</span>
						<Badge variant={healthVariant(health.database)} label={health.database || '...'} dot={true} />
					</div>
					<span class="sj-hc-detail">{health.database_detail || ''}</span>
				</div>
			{/snippet}
		</Card>
		<Card>
			{#snippet children()}
				<div class="sj-hc">
					<div class="sj-hc-row">
						<span class="sj-hc-label">MinIO</span>
						<Badge variant={healthVariant(health.storage)} label={health.storage || '...'} dot={true} />
					</div>
					<span class="sj-hc-detail">{health.storage_detail || ''}</span>
				</div>
			{/snippet}
		</Card>
		<Card>
			{#snippet children()}
				<div class="sj-hc">
					<div class="sj-hc-row">
						<span class="sj-hc-label">Queue</span>
					</div>
					<span class="sj-hc-detail">{health.queue?.pending || 0} pending</span>
				</div>
			{/snippet}
		</Card>
		<Card>
			{#snippet children()}
				<div class="sj-hc">
					<div class="sj-hc-row">
						<span class="sj-hc-label">Quarantine</span>
					</div>
					<span class="sj-hc-detail">{health.quarantine || 0} active</span>
				</div>
			{/snippet}
		</Card>
	</div>

	<h2 class="sj-section-head">Gateway</h2>
	<div class="sj-info-row">
		<span class="sj-version-info">v{version.version || '...'} ({version.gitHash || '...'}) &middot; {version.go || '...'} &middot; {version.platform || '...'} &middot; up {version.uptime ? Math.floor(version.uptime / 86400) + 'd' : '...'}</span>
		{#if schemaVersion.expected > 0}
			<Badge variant={schemaVersion.up_to_date ? 'success' : 'warning'} label={schemaVersion.up_to_date ? 'Schema: ' + schemaVersion.current + '/' + schemaVersion.expected + ' OK' : 'Schema: ' + schemaVersion.current + '/' + schemaVersion.expected + ' ' + (schemaVersion.expected - schemaVersion.current) + ' pending'} />
		{/if}
	</div>

	<h2 class="sj-section-head">Backups</h2>
	<div class="sj-backup-actions">
		<Button variant="primary" size="sm" onclick={triggerBackup} disabled={backupRunning || !hasPermission($adminPermissions, 'backup.write')}>
			{backupRunning ? 'Backing up...' : 'Backup Now'}
		</Button>
	</div>

	<Card flush={true}>
		{#snippet children()}
			{#if backups.length === 0}
				<EmptyState title="No backups yet" />
			{:else}
				{@const rows = backups.map(b => ({
					...b,
					_date: new Date(b.createdAt).toLocaleString(),
					_size: b.sizeBytes ? (b.sizeBytes / 1048576).toFixed(1) + ' MB' : ''
				})) as unknown as Record<string, unknown>[]}
				<Table columns={BACKUP_COLUMNS} rows={rows}>
					{#snippet cell(row, col)}
						{@const b = row as unknown as { id: number; resultPath?: string; status: string; _date: string; _size: string }}
						{#if col.key === 'date'}{b._date}
						{:else if col.key === 'status'}<Badge variant={b.status === 'complete' ? 'success' : 'warning'} label={b.status} />
						{:else if col.key === 'size'}{b._size}
						{:else if col.key === 'actions'}
							<div class="sj-actions">
								{#if b.status === 'complete' && b.resultPath}
									<a href={`/admin/system/backup/download?path=${encodeURIComponent(b.resultPath)}`}>
										<Button variant="ghost" size="sm">Download</Button>
									</a>
								{/if}
								<Button variant="ghost" size="sm" disabled={!hasPermission($adminPermissions, 'backup.write')} onclick={() => deleteBackup(b.id, b.resultPath || '')}>Del</Button>
							</div>
						{/if}
					{/snippet}
				</Table>
			{/if}
		{/snippet}
	</Card>

	<h2 class="sj-section-head">Configuration</h2>
	<div class="sj-config-actions">
		<Button variant="primary" size="sm" onclick={exportConfig}>Export Config</Button>
		<label class="sj-import-label">
			<span class="sj-import-btn">Import Config</span>
			<input type="file" accept=".json" style="display:none"
				disabled={!hasPermission($adminPermissions, 'system.config')}
				onchange={(e) => {
					const file = (e.target as HTMLInputElement).files?.[0];
					if (file) importConfig(file);
				}} />
		</label>
	</div>
	{#if importResult}
		<p class="sj-import-result">{importResult}</p>
	{/if}

	<h2 class="sj-section-head">Backup Replica</h2>
	<Card>
		{#snippet children()}
			<!-- S19 secret-form hygiene: replica settings are server-managed
			     (BACKUP_REPLICA_* env / config file) and are NOT writable via the
			     admin config API, so these inputs are display-only placeholders —
			     never collectors for a secret that has no save path. -->
			<div class="sj-form-grid">
				<Select label="Provider" disabled={true} options={[{ value: '', label: 'Disabled' }, ...BACKUP_PROVIDER_OPTIONS]} value={replicaProvider} onchange={(e) => replicaProvider = (e.target as HTMLSelectElement).value} />
				<Input label="Endpoint" disabled={true} value={replicaEndpoint} oninput={(e) => replicaEndpoint = (e.target as HTMLInputElement).value} />
				<Input label="Bucket" disabled={true} value={replicaBucket} oninput={(e) => replicaBucket = (e.target as HTMLInputElement).value} />
				<Input label="Access Key" disabled={true} value={replicaAccessKey} oninput={(e) => replicaAccessKey = (e.target as HTMLInputElement).value} />
				<Input label="Secret Key" type="password" disabled={true} value={replicaSecretKey} oninput={(e) => replicaSecretKey = (e.target as HTMLInputElement).value} />
			</div>
			<p class="sj-hint">Configured server-side via BACKUP_REPLICA_PROVIDER / _ENDPOINT / _BUCKET / _ACCESS_KEY / _SECRET_KEY — this console cannot edit them.</p>
		{/snippet}
	</Card>

	<h2 class="sj-section-head">High Availability</h2>
	<Card>
		{#snippet children()}
			<div class="sj-ha-row">
				<span>Status: {haStatus || 'Single Node — No Failover'}</span>
				<Button variant="primary" size="sm" onclick={enableHA} disabled={haDeploying || !hasPermission($adminPermissions, 'system.upgrade')}>
					{haDeploying ? 'Deploying...' : 'Enable HA'}
				</Button>
			</div>
		{/snippet}
	</Card>

	<h2 class="sj-section-head">Network Settings</h2>
	<Card>
		{#snippet children()}
			<div class="sj-form-group">
				<label class="sj-field-label" for="listen-addr">Listen address</label>
				<div class="sj-input-row">
					<Input id="listen-addr" type="text" placeholder=":443" value={listenAddr} oninput={(e) => { listenAddr = (e.target as HTMLInputElement).value; listenAddrChanged = true; }} />
					<Button variant="primary" size="sm" onclick={saveListenAddr} disabled={listenAddrSaving || !hasPermission($adminPermissions, 'system.config')}>
						{listenAddrSaving ? 'Reloading...' : 'Apply & Reload'}
					</Button>
				</div>
				<p class="sj-hint">Default: :443. Change triggers graceful reload — zero downtime.</p>
			</div>
			<div class="sj-form-group">
				<Select label="HTTP port mode" options={HTTP_MODE_OPTIONS} value={httpMode} onchange={(e) => { httpMode = (e.target as HTMLSelectElement).value; saveHTTPMode(); }} />
				<p class="sj-hint">"Redirect" sends :80 visitors to HTTPS. "Serve" delivers content on :80 directly (works standalone or behind nginx/cloudflare/reverse proxy).</p>
			</div>
		{/snippet}
	</Card>

	<h2 class="sj-section-head">Branding</h2>
	<Card>
		{#snippet children()}
			<div class="sj-form-group">
				<Input label="Brand name" type="text" placeholder="SetJoin" value={brandName} oninput={(e) => brandName = (e.target as HTMLInputElement).value} />
				<p class="sj-hint">Displayed on the login page, toolbar, and app launcher.</p>
			</div>
			<div class="sj-form-group">
				<label class="sj-field-label" for="brand-logo">Logo</label>
				<input class="sj-file-input" id="brand-logo" type="file" accept="image/png,image/svg+xml,image/jpeg"
					onchange={(e) => brandLogoFile = (e.target as HTMLInputElement).files?.[0] || null} />
				<p class="sj-hint">PNG, SVG, or JPEG. Recommended 64x64px.</p>
			</div>
			{#if brandLogoUrl || brandLogoFile}
				<div class="sj-form-group">
					<span class="sj-hint">Preview:</span>
					<div class="sj-brand-preview">
						{#if brandLogoFile}
							<img src={URL.createObjectURL(brandLogoFile)} alt="Logo preview" class="sj-brand-logo" />
						{:else if brandLogoUrl}
							<img src={brandLogoUrl} alt="Logo preview" class="sj-brand-logo" />
						{/if}
						<span>{brandName}</span>
					</div>
				</div>
			{/if}
			<Button variant="primary" size="sm" onclick={saveBranding} disabled={brandSaving || !hasPermission($adminPermissions, 'mail.pipeline')}>
				{brandSaving ? 'Saving...' : 'Save Branding'}
			</Button>
		{/snippet}
	</Card>

	<h2 class="sj-section-head">Server updates</h2>
	<Card>
		{#snippet children()}
			<p class="sj-upgrade-copy">Transactional update planning and durable progress are available here. Host execution remains fail-closed until the installation passes its recovery and runtime gates.</p>
			<a class="sj-inline-link" href="/admin/updates/server">Open server updates</a>
		{/snippet}
	</Card>
</div>

<style>
	.sj-page { max-width: 980px; }

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

	.sj-section-head {
		margin-top: 20px;
		margin-bottom: 8px;
		font-size: var(--text-lg);
		font-weight: 600;
		color: var(--text-primary);
	}

	.sj-health-grid { display: flex; gap: 12px; flex-wrap: wrap; }
	.sj-hc {
		padding: 8px;
		display: flex;
		flex-direction: column;
		gap: 6px;
		min-width: 140px;
	}
	.sj-hc-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 8px;
	}
	.sj-hc-label {
		font-size: var(--text-xs);
		color: var(--text-secondary);
		text-transform: uppercase;
		letter-spacing: var(--tracking-caps);
		font-weight: 600;
	}
	.sj-hc-detail {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		font-family: var(--font-mono);
	}

	.sj-info-row {
		display: flex;
		justify-content: space-between;
		align-items: center;
		flex-wrap: wrap;
		gap: 8px;
	}
	.sj-version-info {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		font-family: var(--font-mono);
	}

	.sj-backup-actions { display: flex; gap: 8px; margin-bottom: 12px; }
	.sj-actions { display: flex; gap: 4px; }

	.sj-config-actions { display: flex; gap: 8px; }
	.sj-import-label { cursor: pointer; }
	.sj-import-btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		height: 26px;
		padding: 0 10px;
		border-radius: var(--radius-sm);
		font-size: var(--text-xs);
		font-weight: 500;
		border: 1px solid var(--border-default);
		background: var(--surface-card);
		color: var(--text-primary);
	}
	.sj-import-result { font-size: var(--text-sm); color: var(--text-secondary); margin: 8px 0 0; }

	.sj-form-grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
		gap: 12px;
	}
	.sj-form-group { margin-bottom: 12px; }
	.sj-field-label {
		display: block;
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-primary);
		margin-bottom: 4px;
	}
	.sj-input-row { display: flex; gap: 8px; align-items: center; }
	.sj-input-row :global(.sj-select-wrap) { flex: 1; }
	.sj-hint { font-size: var(--text-xs); color: var(--text-tertiary); margin: 4px 0 0; }
	.sj-file-input { font-size: var(--text-sm); }

	.sj-ha-row {
		display: flex;
		justify-content: space-between;
		align-items: center;
		gap: 8px;
		font-size: var(--text-sm);
	}

	.sj-brand-preview { display: flex; align-items: center; gap: 12px; margin-top: 4px; }
	.sj-brand-logo { max-height: 48px; }

	.sj-upgrade-copy { margin: 0 0 8px; color: var(--text-secondary); font-size: var(--text-sm); }
	.sj-inline-link { color: var(--text-accent); font-size: var(--text-sm); font-weight: 500; }

</style>
