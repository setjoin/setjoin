<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { parseError } from '$lib/errors';
	import {
		adminMAMListDevices,
		adminMAMLockDevice,
		adminMAMUnlockDevice,
		type MAMDevice,
	} from '$lib/admin/client';
	import { t } from '$lib/i18n';
	import { adminPermissions, hasPermission } from '$lib/stores/auth';
import { Checkbox } from '$lib/components/ui';
import Icon from '$lib/components/Icon.svelte';

	let devices: MAMDevice[] = $state([]);
	let total = $state(0);
	let loading = $state(true);
	let error = $state('');
	let actionError = $state('');

	// Filters
	let filterPlatform = $state('');
	let filterCompliance = $state('');

	// Bulk selection
	let selectedIds = $state(new Set<number>());
	let bulkActionLoading = $state(false);

	async function load() {
		loading = true;
		error = '';
		try {
			const res = await adminMAMListDevices();
			devices = res.devices;
			total = res.total;
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	onMount(() => load());

	const filteredDevices = $derived(devices.filter((d) => {
		if (filterPlatform && d.platform !== filterPlatform) return false;
		if (filterCompliance && d.compliance_status !== filterCompliance) return false;
		return true;
	}));

	const platforms = $derived([...new Set(devices.map((d) => d.platform))].sort());

	function toggleSelect(id: number) {
		const next = new Set(selectedIds);
		if (next.has(id)) next.delete(id);
		else next.add(id);
		selectedIds = next;
	}

	function toggleSelectAll() {
		if (selectedIds.size === filteredDevices.length) {
			selectedIds = new Set();
		} else {
			selectedIds = new Set(filteredDevices.map((d) => d.id));
		}
	}

	async function bulkLock() {
		bulkActionLoading = true;
		actionError = '';
		for (const id of selectedIds) {
			try { await adminMAMLockDevice(id); } catch { /* continue */ }
		}
		bulkActionLoading = false;
		selectedIds = new Set();
		await load();
	}

	async function bulkUnlock() {
		bulkActionLoading = true;
		actionError = '';
		for (const id of selectedIds) {
			try { await adminMAMUnlockDevice(id); } catch { /* continue */ }
		}
		bulkActionLoading = false;
		selectedIds = new Set();
		await load();
	}

	async function lockDevice(id: number) {
		actionError = '';
		try {
			await adminMAMLockDevice(id);
			await load();
		} catch (e) {
			actionError = parseError(e).message;
		}
	}

	async function unlockDevice(id: number) {
		actionError = '';
		try {
			await adminMAMUnlockDevice(id);
			await load();
		} catch (e) {
			actionError = parseError(e).message;
		}
	}
</script>

<header class="page-header">
	<div>
		<h1>MAM Devices</h1>
		<p class="subtitle">{total} registered devices</p>
	</div>
	<div class="header-actions">
		<button class="btn btn-ghost btn-sm" onclick={load}>Refresh</button>
	</div>
</header>

{#if error}
	<div class="alert alert-danger">{error}</div>
{/if}

{#if actionError}
	<div class="alert alert-danger">{actionError}</div>
{/if}

<div class="filters">
	<select class="input" style="width:auto" bind:value={filterPlatform}>
		<option value="">All platforms</option>
		{#each platforms as p}
			<option value={p}>{p}</option>
		{/each}
	</select>
	<select class="input" style="width:auto" bind:value={filterCompliance}>
		<option value="">All statuses</option>
		<option value="compliant">Compliant</option>
		<option value="non_compliant">Non-compliant</option>
		<option value="grace">Grace period</option>
		<option value="quarantined">Quarantined</option>
	</select>

	{#if selectedIds.size > 0}
		<div class="bulk-actions">
			<span class="bulk-count">{selectedIds.size} selected</span>
			<button class="btn btn-sm btn-ghost" onclick={bulkLock} disabled={bulkActionLoading || !hasPermission($adminPermissions, 'mam.write')}>Lock all</button>
			<button class="btn btn-sm btn-ghost" onclick={bulkUnlock} disabled={bulkActionLoading || !hasPermission($adminPermissions, 'mam.write')}>Unlock all</button>
		</div>
	{/if}
</div>

{#if loading}
	<div class="empty-state">
		<div>Loading devices…</div>
	</div>
{:else if filteredDevices.length === 0}
	<div class="empty-state">
		<div class="empty-state-icon"><Icon name="MonitorSmartphone" size={40} /></div>
		<div>No devices found.</div>
	</div>
{:else}
	<div class="card" style="margin-bottom:1.5rem">
		<div class="card-body" style="padding:0">
			<table class="data-table">
				<thead>
					<tr>
						<th style="width:40px">
							<Checkbox checked={selectedIds.size === filteredDevices.length && filteredDevices.length > 0}
								onchange={toggleSelectAll} />
						</th>
						<th>ID</th>
						<th>Name</th>
						<th>Platform</th>
						<th>OS</th>
						<th>App</th>
						<th>Status</th>
						<th>Last Check-in</th>
						<th>Wipe</th>
						<th>Actions</th>
					</tr>
				</thead>
				<tbody>
					{#each filteredDevices as d}
						<tr>
							<td>
								<Checkbox
									checked={selectedIds.has(d.id)}
									onchange={() => toggleSelect(d.id)} />
							</td>
							<td style="font-family:var(--font-mono); font-size:var(--font-size-xs)">{d.id}</td>
							<td>
								<a href="/admin/mam/devices/{d.id}" class="link">{d.device_name || '–'}</a>
							</td>
							<td>{d.platform}</td>
							<td style="font-size:var(--font-size-xs)">{d.os_version || '–'}</td>
							<td style="font-size:var(--font-size-xs)">{d.app_version || '–'}</td>
							<td>
								{#if d.compliance_status === 'compliant'}
									<span class="badge badge-green">Compliant</span>
								{:else if d.compliance_status === 'non_compliant'}
									<span class="badge badge-red">Non-compliant</span>
								{:else if d.compliance_status === 'grace'}
									<span class="badge badge-orange">Grace</span>
								{:else if d.compliance_status === 'quarantined'}
									<span class="badge badge-red">Quarantined</span>
								{:else}
									<span class="badge badge-gray">{d.compliance_status || '–'}</span>
								{/if}
							</td>
							<td style="font-size:var(--font-size-xs); color:var(--gray-500)">
								{d.last_checkin_at ? new Date(d.last_checkin_at).toLocaleString() : 'Never'}
							</td>
							<td>
								{#if d.wipe_requested}
									<span class="badge badge-orange">Pending</span>
								{:else}
									<span class="badge badge-gray">–</span>
								{/if}
							</td>
							<td class="actions">
								<a href="/admin/mam/devices/{d.id}" class="btn btn-sm btn-ghost">Details</a>
								<button class="btn btn-sm btn-ghost-danger" onclick={() => lockDevice(d.id)} disabled={!hasPermission($adminPermissions, 'mam.write')}>Lock</button>
								<button class="btn btn-sm btn-ghost" onclick={() => unlockDevice(d.id)} disabled={!hasPermission($adminPermissions, 'mam.write')}>Unlock</button>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	</div>
{/if}

<style>
	.subtitle {
		font-size: var(--font-size-sm);
		color: var(--gray-500);
		margin-top: 0.15rem;
	}
	.header-actions { display: flex; align-items: center; gap: 1rem; }
	.filters {
		display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem; flex-wrap: wrap;
	}
	.bulk-actions {
		display: flex; align-items: center; gap: 0.5rem;
		margin-left: auto;
	}
	.bulk-count {
		font-size: var(--font-size-sm);
		font-weight: var(--weight-medium);
		color: var(--gray-700);
	}
	.actions { display: flex; gap: 0.25rem; }
	.link {
		color: var(--app-mail);
		text-decoration: none;
		font-weight: var(--weight-medium);
	}
	.link:hover { text-decoration: underline; }
	.alert {
		padding: 0.65rem 1rem;
		border-radius: var(--radius-md);
		margin-bottom: 1rem;
		font-size: var(--font-size-sm);
		font-weight: var(--weight-medium);
	}
	.alert-danger {
		background: var(--danger-bg);
		color: var(--danger-fg);
		border: 0.5px solid rgb(255,59,48,0.2);
	}
</style>
