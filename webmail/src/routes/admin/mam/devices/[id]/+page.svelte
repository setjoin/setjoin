<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { parseError } from '$lib/errors';
	import Icon from '$lib/components/Icon.svelte';
	import {
		adminMAMGetDeviceEvents,
		adminMAMSetPerDevicePolicy,
		adminMAMUnsetPerDevicePolicy,
		adminMAMListDevices,
		adminMAMLockDevice,
		adminMAMUnlockDevice,
		type MAMDevice,
		type MAMDeviceEvent,
	} from '$lib/admin/client';
	import { adminPermissions, hasPermission } from '$lib/stores/auth';

	let deviceId = $derived(Number($page.params.id));

	let device: MAMDevice | null = $state(null);
	let events: MAMDeviceEvent[] = $state([]);
	let loading = $state(true);
	let error = $state('');
	let actionError = $state('');

	// Policy override form
	let newPolicyKey = $state('');
	let newPolicyValue = $state('');
	let policyLoading = $state(false);

	async function load() {
		loading = true;
		error = '';
		try {
			const [devRes, evtRes] = await Promise.all([
				adminMAMListDevices(),
				adminMAMGetDeviceEvents(deviceId),
			]);
			device = devRes.devices.find((d) => d.id === deviceId) ?? null;
			events = evtRes.events;
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	onMount(() => load());

	async function doLock() {
		actionError = '';
		try {
			await adminMAMLockDevice(deviceId);
			await load();
		} catch (e) {
			actionError = parseError(e).message;
		}
	}

	async function doUnlock() {
		actionError = '';
		try {
			await adminMAMUnlockDevice(deviceId);
			await load();
		} catch (e) {
			actionError = parseError(e).message;
		}
	}

	async function addPolicyOverride() {
		if (!newPolicyKey.trim() || !newPolicyValue.trim()) return;
		policyLoading = true;
		actionError = '';
		try {
			await adminMAMSetPerDevicePolicy(deviceId, {
				[newPolicyKey.trim()]: newPolicyValue.trim(),
			});
			newPolicyKey = '';
			newPolicyValue = '';
		} catch (e) {
			actionError = parseError(e).message;
		} finally {
			policyLoading = false;
		}
	}

	async function removePolicyOverride(key: string) {
		actionError = '';
		try {
			await adminMAMUnsetPerDevicePolicy(deviceId, key);
		} catch (e) {
			actionError = parseError(e).message;
		}
	}

	function severityClass(s: string): string {
		if (s === 'critical' || s === 'error') return 'badge-red';
		if (s === 'warn') return 'badge-orange';
		return 'badge-gray';
	}
</script>

<header class="page-header">
	<div>
		<h1>Device Details</h1>
		<p class="subtitle">Device #{deviceId}</p>
	</div>
	<div class="header-actions">
		<a href="/admin/mam/devices" class="btn btn-ghost btn-sm">Back to list</a>
		<button class="btn btn-ghost btn-sm" onclick={load}>Refresh</button>
	</div>
</header>

{#if error}
	<div class="alert alert-danger">{error}</div>
{/if}

{#if actionError}
	<div class="alert alert-danger">{actionError}</div>
{/if}

{#if loading}
	<div class="empty-state">
		<div>Loading device…</div>
	</div>
{:else if !device}
	<div class="empty-state">
		<div class="empty-state-icon"><Icon name="MonitorSmartphone" size={40} /></div>
		<div>Device not found.</div>
	</div>
{:else}
	<!-- Device info card -->
	<div class="card" style="margin-bottom:1.5rem">
		<div class="card-header">Device Information</div>
		<div class="card-body">
			<dl class="detail-grid">
				<div>
					<dt>Name</dt>
					<dd>{device.device_name || '–'}</dd>
				</div>
				<div>
					<dt>Platform</dt>
					<dd>{device.platform}</dd>
				</div>
				<div>
					<dt>OS Version</dt>
					<dd>{device.os_version || '–'}</dd>
				</div>
				<div>
					<dt>App Version</dt>
					<dd>{device.app_version || '–'}</dd>
				</div>
				<div>
					<dt>User ID</dt>
					<dd style="font-family:var(--font-mono)">{device.user_id}</dd>
				</div>
				<div>
					<dt>Created</dt>
					<dd>{device.created_at ? new Date(device.created_at).toLocaleString() : '–'}</dd>
				</div>
				<div>
					<dt>Last Check-in</dt>
					<dd>{device.last_checkin_at ? new Date(device.last_checkin_at).toLocaleString() : 'Never'}</dd>
				</div>
				<div>
					<dt>Compliance</dt>
					<dd>
						{#if device.compliance_status === 'compliant'}
							<span class="badge badge-green">Compliant</span>
						{:else if device.compliance_status === 'non_compliant'}
							<span class="badge badge-red">Non-compliant</span>
						{:else if device.compliance_status === 'grace'}
							<span class="badge badge-orange">Grace period</span>
						{:else if device.compliance_status === 'quarantined'}
							<span class="badge badge-red">Quarantined</span>
						{:else}
							<span class="badge badge-gray">{device.compliance_status || '–'}</span>
						{/if}
					</dd>
				</div>
				<div>
					<dt>Wipe Status</dt>
					<dd>
						{#if device.wipe_requested}
							<span class="badge badge-orange">Pending</span>
						{:else}
							<span class="badge badge-gray">None</span>
						{/if}
					</dd>
				</div>
			</dl>

			<div class="device-actions" style="margin-top:1rem; display:flex; gap:0.5rem;">
				<button class="btn btn-ghost-danger btn-sm" onclick={doLock}
					disabled={!hasPermission($adminPermissions, 'mam.write')}>Lock Device</button>
				<button class="btn btn-ghost btn-sm" onclick={doUnlock}
					disabled={!hasPermission($adminPermissions, 'mam.write')}>Unlock Device</button>
			</div>
		</div>
	</div>

	<!-- Policy overrides card -->
	<div class="card" style="margin-bottom:1.5rem">
		<div class="card-header">Policy Overrides</div>
		<div class="card-body">
			<p style="color:var(--gray-500); font-size:var(--font-size-sm); margin-bottom:0.75rem">
				Per-device policy overrides take precedence over global and group policies.
			</p>

			<div class="policy-add" style="display:flex; gap:0.5rem; margin-bottom:1rem;">
				<input class="input" type="text" placeholder="Policy key (e.g. require_pin)"
					bind:value={newPolicyKey} maxlength={128} style="flex:1" />
				<input class="input" type="text" placeholder="Value (e.g. true)"
					bind:value={newPolicyValue} maxlength={256} style="flex:1" />
				<button class="btn btn-primary btn-sm" onclick={addPolicyOverride}
					disabled={policyLoading || !newPolicyKey.trim() || !newPolicyValue.trim() || !hasPermission($adminPermissions, 'mam.write')}>
					Add
				</button>
			</div>

			<table class="data-table">
				<thead>
					<tr>
						<th>Key</th>
						<th>Value</th>
						<th>Actions</th>
					</tr>
				</thead>
				<tbody>
					<tr>
						<td colspan="3" style="color:var(--gray-500); font-size:var(--font-size-sm)">
							Policy overrides are managed server-side. Add keys above to set per-device overrides.
						</td>
					</tr>
				</tbody>
			</table>
		</div>
	</div>

	<!-- Events timeline -->
	<div class="card">
		<div class="card-header">Device Events</div>
		<div class="card-body" style="padding:0">
			{#if events.length === 0}
				<div class="empty-state">
					<div>No events recorded for this device.</div>
				</div>
			{:else}
				<table class="data-table">
					<thead>
						<tr>
							<th>Event</th>
							<th>Severity</th>
							<th>Details</th>
							<th>Occurred</th>
						</tr>
					</thead>
					<tbody>
						{#each events as evt}
							<tr>
								<td style="font-weight:var(--weight-medium)">{evt.event_type}</td>
								<td>
									<span class="badge {severityClass(evt.severity)}">{evt.severity}</span>
								</td>
								<td style="font-size:var(--font-size-xs); max-width:300px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap">
									{evt.details ? JSON.stringify(evt.details) : '–'}
								</td>
								<td style="font-size:var(--font-size-xs); color:var(--gray-500)">
									{new Date(evt.occurred_at).toLocaleString()}
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			{/if}
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
	.detail-grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
		gap: 1rem;
		margin: 0;
		padding: 0;
	}
	.detail-grid dt {
		font-size: var(--font-size-xs);
		font-weight: var(--weight-medium);
		color: var(--gray-500);
		text-transform: uppercase;
		letter-spacing: 0.05em;
		margin-bottom: 0.15rem;
	}
	.detail-grid dd {
		margin: 0;
		font-size: var(--font-size-base);
		color: var(--gray-900);
	}
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
