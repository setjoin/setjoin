<svelte:options runes={true} />

<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { adminFetch } from '$lib/admin/client';
	import { Button, Checkbox, Badge, Input, Select, Tabs, Table, Spinner, EmptyState } from '$lib/components/ui';
	import type { TableColumn } from '$lib/components/ui';
	import type { TabItem } from '$lib/components/ui/Tabs.svelte';
	import { logLevelBadgeVariant, eventBadgeVariant } from '$lib/admin/logHelpers';
	import { downloadBlob } from '$lib/utils/downloadBlob';

	let activeTab = $state('system');
	let entries = $state<any[]>([]);
	let authEntries = $state<any[]>([]);
	let level = $state('all');
	let since = $state('1h');
	let search = $state('');
	let autoRefresh = $state(false);
	let loading = $state(true);
	let exporting = $state(false);
	let error = $state('');
	let timer: ReturnType<typeof setInterval> | null = null;
	let authProvider = $state('all');
	let authEvent = $state('all');

	const TABS: TabItem[] = [
		{ id: 'system', label: 'System' },
		{ id: 'auth', label: 'Auth' },
	];

	const LEVELS = ['all', 'debug', 'info', 'warn', 'error'];
	const LEVEL_OPTIONS = LEVELS.map(l => ({ value: l, label: l === 'all' ? 'All levels' : l }));
	const TIME_RANGES = [
		{ value: '1h', label: 'Last hour' },
		{ value: '6h', label: 'Last 6 hours' },
		{ value: '24h', label: 'Last 24 hours' },
		{ value: '7d', label: 'Last 7 days' },
	];
	const PROVIDERS = ['all', 'bcrypt', 'app_password', 'kerberos', 'jwt', 'ldap', 'webauthn', 'basic'];
	const PROVIDER_OPTIONS = PROVIDERS.map(p => ({ value: p, label: p === 'all' ? 'All providers' : p }));
	const EVENTS = ['all', 'login', 'login_failed'];
	const EVENT_OPTIONS = EVENTS.map(e => ({ value: e, label: e === 'all' ? 'All events' : e }));

	const SYSTEM_COLUMNS: TableColumn[] = [
		{ key: 'timestamp', label: 'Timestamp', sortable: false, mono: true },
		{ key: 'level', label: 'Level', sortable: false },
		{ key: 'message', label: 'Message', sortable: false },
	];

	const AUTH_COLUMNS: TableColumn[] = [
		{ key: 'timestamp', label: 'Time', sortable: false, mono: true },
		{ key: 'email', label: 'Email', sortable: false },
		{ key: 'provider', label: 'Provider', sortable: false },
		{ key: 'event', label: 'Event', sortable: false },
		{ key: 'ip', label: 'IP', sortable: false, mono: true },
	];

	async function load() {
		error = '';
		try {
			const params = new URLSearchParams({ since, limit: '200' });
			if (level !== 'all') params.set('level', level);
			if (search) params.set('search', search);
			const res = await adminFetch('/admin/system/logs?' + params.toString());
			if (res.ok) entries = await res.json();
		} catch (e) { error = e instanceof Error ? e.message : 'Failed to load'; }
		finally { loading = false; }
	}

	async function loadAuthLog() {
		error = '';
		try {
			const params = new URLSearchParams({ since, limit: '200' });
			if (authProvider !== 'all') params.set('provider', authProvider);
			if (authEvent !== 'all') params.set('event', authEvent);
			if (search) params.set('email', search);
			const res = await adminFetch('/admin/auth-log?' + params.toString());
			if (res.ok) authEntries = await res.json();
		} catch (e) { error = e instanceof Error ? e.message : 'Failed to load'; }
		finally { loading = false; }
	}

	function applyFilters() {
		loading = true;
		activeTab === 'auth' ? loadAuthLog() : load();
	}

	function onTabChange(id: string) {
		activeTab = id;
		loading = true;
		id === 'auth' ? loadAuthLog() : load();
	}

	$effect(() => {
		if (autoRefresh) {
			timer = setInterval(() => activeTab === 'auth' ? loadAuthLog() : load(), 5000);
		} else {
			if (timer) { clearInterval(timer); timer = null; }
		}
		return () => { if (timer) clearInterval(timer); };
	});

	async function exportLogs() {
		exporting = true;
		try {
			const params = new URLSearchParams({ since, limit: '10000' });
			if (level !== 'all') params.set('level', level);
			if (search) params.set('search', search);
			const res = await adminFetch('/admin/system/logs?' + params.toString());
			if (!res.ok) throw new Error('Export failed');
			const data = await res.json();
			const text = data.map((e: any) => `${e.timestamp || ''} [${e.level || ''}] ${e.message || ''}`).join('\n');
			const blob = new Blob([text], { type: 'text/plain' });
			downloadBlob(blob, `logs-${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.txt`);
		} catch (e) { error = e instanceof Error ? e.message : 'Export failed'; }
		finally { exporting = false; }
	}

	function formatTimestamp(ts: string): string {
		if (!ts) return '—';
		return new Date(ts).toLocaleString();
	}

	onMount(load);
	onDestroy(() => { if (timer) clearInterval(timer); });
</script>

<div class="sj-page">
	<header class="sj-page-head">
		<div class="sj-page-head-left">
			<h1>Logs</h1>
		</div>
	</header>

	<Tabs items={TABS} active={activeTab} onChange={onTabChange} />

	{#if error}
		<div class="sj-alert-danger" role="alert">{error}</div>
	{/if}

	{#if activeTab === 'system'}
		<div class="sj-filter-bar">
			<Select label="Level" options={LEVEL_OPTIONS} value={level} onchange={(e) => { level = (e.target as HTMLSelectElement).value; applyFilters(); }} />
			<Select label="Time range" options={TIME_RANGES} value={since} onchange={(e) => { since = (e.target as HTMLSelectElement).value; applyFilters(); }} />
			<Input label="Search" placeholder="Filter messages..." value={search} oninput={(e) => { search = (e.target as HTMLInputElement).value; applyFilters(); }} />
		</div>

		<div class="sj-toolbar">
			<Checkbox checked={autoRefresh} label="Auto-refresh (5s)" onchange={(e) => autoRefresh = (e.target as HTMLInputElement).checked} />
			<Button variant="ghost" size="sm" onclick={exportLogs} disabled={exporting}>
				{exporting ? 'Exporting...' : 'Export'}
			</Button>
		</div>

		{#if loading}
			<div class="sj-loading">
				<Spinner size={20} label="Loading logs..." />
			</div>
		{:else if entries.length === 0}
			<EmptyState title="No log entries found" />
		{:else}
			{@const rows = entries.map((e: any) => ({
				timestamp: formatTimestamp(e.timestamp),
				level: e.level || '—',
				message: e.message || '—',
				_levelRaw: e.level,
			})) as unknown as Record<string, unknown>[]}
			<Table columns={SYSTEM_COLUMNS} rows={rows}>
				{#snippet cell(row, col)}
					{@const r = row as unknown as { timestamp: string; level: string; message: string; _levelRaw: string }}
					{#if col.key === 'level'}
						<Badge variant={logLevelBadgeVariant(r._levelRaw)} label={r.level} />
					{:else if col.key === 'timestamp'}
						<span class="sj-mono-cell">{r.timestamp}</span>
					{:else if col.key === 'message'}
						<span class="sj-message-cell">{r.message}</span>
					{/if}
				{/snippet}
			</Table>
		{/if}
	{:else}
		<div class="sj-filter-bar">
			<Select label="Provider" options={PROVIDER_OPTIONS} value={authProvider} onchange={(e) => { authProvider = (e.target as HTMLSelectElement).value; applyFilters(); }} />
			<Select label="Event" options={EVENT_OPTIONS} value={authEvent} onchange={(e) => { authEvent = (e.target as HTMLSelectElement).value; applyFilters(); }} />
			<Select label="Time range" options={TIME_RANGES} value={since} onchange={(e) => { since = (e.target as HTMLSelectElement).value; applyFilters(); }} />
			<Input label="Email" placeholder="Filter by email..." value={search} oninput={(e) => { search = (e.target as HTMLInputElement).value; applyFilters(); }} />
		</div>

		<div class="sj-toolbar">
			<Checkbox checked={autoRefresh} label="Auto-refresh (5s)" onchange={(e) => autoRefresh = (e.target as HTMLInputElement).checked} />
		</div>

		{#if loading}
			<div class="sj-loading">
				<Spinner size={20} label="Loading auth log..." />
			</div>
		{:else if authEntries.length === 0}
			<EmptyState title="No auth log entries found" />
		{:else}
			{@const rows = authEntries.map((e: any) => ({
				timestamp: formatTimestamp(e.timestamp),
				email: e.email || '—',
				provider: e.provider || '—',
				event: e.event || '—',
				ip: e.ip || '—',
				_eventRaw: e.event,
			})) as unknown as Record<string, unknown>[]}
			<Table columns={AUTH_COLUMNS} rows={rows}>
				{#snippet cell(row, col)}
					{@const r = row as unknown as { timestamp: string; email: string; provider: string; event: string; ip: string; _eventRaw: string }}
					{#if col.key === 'event'}
						<Badge variant={eventBadgeVariant(r._eventRaw)} label={r.event} />
					{:else if col.key === 'timestamp'}
						<span class="sj-mono-cell">{r.timestamp}</span>
					{:else if col.key === 'ip'}
						<span class="sj-mono-cell">{r.ip}</span>
					{:else if col.key === 'email'}
						{r.email}
					{:else if col.key === 'provider'}
						{r.provider}
					{/if}
				{/snippet}
			</Table>
		{/if}
	{/if}
</div>

<style>
	.sj-page {
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

	.sj-alert-danger {
		padding: 8px 12px;
		border-radius: var(--radius-sm);
		margin-bottom: 12px;
		font-size: var(--text-sm);
		font-weight: 500;
		background: var(--danger-bg);
		color: var(--danger-fg);
		border: 1px solid var(--danger-fg);
	}

	.sj-filter-bar {
		display: flex;
		gap: 12px;
		align-items: flex-end;
		flex-wrap: wrap;
		margin: 12px 0 8px;
	}

	.sj-toolbar {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 8px;
	}

	.sj-loading {
		padding: 32px;
		display: flex;
		justify-content: center;
	}

	.sj-mono-cell {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		white-space: nowrap;
	}

	.sj-message-cell {
		overflow-wrap: anywhere;
	}
</style>
