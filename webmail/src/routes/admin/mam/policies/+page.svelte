<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { parseError } from '$lib/errors';
	import { adminPermissions, hasPermission } from '$lib/stores/auth';
	import {
		adminMAMListPolicies,
		adminMAMSetGlobalPolicy,
		adminMAMSetGroupPolicy,
		adminMAMUnsetGroupPolicy,
		type MAMPolicyItem,
		type MAMGroupPolicyItem,
	} from '$lib/admin/client';

	let globalPolicies: MAMPolicyItem[] = $state([]);
	let groupPolicies: MAMGroupPolicyItem[] = $state([]);
	let loading = $state(true);
	let error = $state('');
	let actionError = $state('');
	let actionOk = $state('');

	// Global policy form
	let newGlobalKey = $state('');
	let newGlobalValue = $state('');
	let globalSaving = $state(false);

	// Group policy form
	let newGroupType = $state('department');
	let newGroupId = $state(0);
	let newGroupPolicyKey = $state('');
	let newGroupPolicyValue = $state('');
	let groupSaving = $state(false);

	async function load() {
		loading = true;
		error = '';
		try {
			const res = await adminMAMListPolicies();
			globalPolicies = res.global;
			groupPolicies = res.groups;
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	onMount(() => load());

	async function addGlobalPolicy() {
		if (!newGlobalKey.trim() || !newGlobalValue.trim()) return;
		globalSaving = true;
		actionError = '';
		actionOk = '';
		try {
			await adminMAMSetGlobalPolicy({
				[newGlobalKey.trim()]: newGlobalValue.trim(),
			});
			newGlobalKey = '';
			newGlobalValue = '';
			actionOk = 'Global policy updated.';
			await load();
		} catch (e) {
			actionError = parseError(e).message;
		} finally {
			globalSaving = false;
		}
	}

	async function removeGlobalPolicy(key: string) {
		actionError = '';
		actionOk = '';
		try {
			// Unset by setting empty string or deleting via global update
			// The server doesn't expose DELETE for global policies individually,
			// but setting an empty value effectively disables it
			await adminMAMSetGlobalPolicy({ [key]: '' });
			await load();
			actionOk = `Removed policy key: ${key}`;
		} catch (e) {
			actionError = parseError(e).message;
		}
	}

	async function addGroupPolicy() {
		if (!newGroupPolicyKey.trim() || !newGroupPolicyValue.trim()) return;
		if (newGroupId <= 0) {
			actionError = 'Group ID must be greater than 0';
			return;
		}
		groupSaving = true;
		actionError = '';
		actionOk = '';
		try {
			await adminMAMSetGroupPolicy(newGroupType, newGroupId, {
				[newGroupPolicyKey.trim()]: newGroupPolicyValue.trim(),
			});
			newGroupPolicyKey = '';
			newGroupPolicyValue = '';
			actionOk = 'Group policy added.';
			await load();
		} catch (e) {
			actionError = parseError(e).message;
		} finally {
			groupSaving = false;
		}
	}

	async function removeGroupPolicy(item: MAMGroupPolicyItem) {
		actionError = '';
		actionOk = '';
		try {
			await adminMAMUnsetGroupPolicy(
				item.group_type,
				item.group_id,
				item.policy_key,
			);
			actionOk = `Removed group policy: ${item.policy_key}`;
			await load();
		} catch (e) {
			actionError = parseError(e).message;
		}
	}

	const groupTypeLabels: Record<string, string> = {
		department: 'Department',
		role: 'Role',
		domain: 'Domain',
	};
</script>

<header class="page-header">
	<div>
		<h1>MAM Policies</h1>
		<p class="subtitle">Global and group-based device policies</p>
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

{#if actionOk}
	<div class="alert alert-success">{actionOk}</div>
{/if}

{#if loading}
	<div class="empty-state">
		<div>Loading policies…</div>
	</div>
{:else}
	<!-- Global policies -->
	<div class="card" style="margin-bottom:1.5rem">
		<div class="card-header">Global Policies</div>
		<div class="card-body">
			<p style="color:var(--text-tertiary); font-size:var(--text-sm); margin-bottom:0.75rem">
				Global policies apply to all devices unless overridden by group or per-device policies.
			</p>

			<div class="policy-add" style="display:flex; gap:0.5rem; margin-bottom:1rem;">
				<input class="input" type="text" placeholder="Policy key (e.g. require_pin)"
					bind:value={newGlobalKey} maxlength={128} style="flex:1" />
				<input class="input" type="text" placeholder="Value (e.g. true)"
					bind:value={newGlobalValue} maxlength={256} style="flex:1" />
				<button class="btn btn-primary btn-sm" onclick={addGlobalPolicy}
					disabled={globalSaving || !newGlobalKey.trim() || !newGlobalValue.trim() || !hasPermission($adminPermissions, 'mam.write')}>
					Add / Update
				</button>
			</div>

			<table class="data-table">
				<thead>
					<tr>
						<th>Key</th>
						<th>Value</th>
						<th>Updated</th>
						<th>Actions</th>
					</tr>
				</thead>
				<tbody>
					{#if globalPolicies.length === 0}
						<tr>
							<td colspan="4" style="color:var(--text-tertiary)">No global policies configured.</td>
						</tr>
					{:else}
						{#each globalPolicies as p}
							<tr>
								<td style="font-family:var(--font-mono); font-size:var(--text-sm)">{p.policy_key}</td>
								<td style="font-family:var(--font-mono); font-size:var(--text-sm)">{p.policy_value}</td>
								<td style="font-size:var(--text-xs); color:var(--text-tertiary)">
									{p.updated_at ? new Date(p.updated_at as string).toLocaleString() : '–'}
								</td>
								<td>
									<button class="btn btn-sm btn-ghost-danger"
										onclick={() => removeGlobalPolicy(p.policy_key)}
										disabled={!hasPermission($adminPermissions, 'mam.write')}>Remove</button>
								</td>
							</tr>
						{/each}
					{/if}
				</tbody>
			</table>
		</div>
	</div>

	<!-- Group policies -->
	<div class="card">
		<div class="card-header">Group Policies</div>
		<div class="card-body">
			<p style="color:var(--text-tertiary); font-size:var(--text-sm); margin-bottom:0.75rem">
				Group policies apply to devices belonging to specific departments, roles, or domains.
			</p>

			<div class="policy-add" style="display:flex; gap:0.5rem; margin-bottom:1rem; flex-wrap:wrap;">
				<select class="input" style="width:auto" bind:value={newGroupType}>
					<option value="department">Department</option>
					<option value="role">Role</option>
					<option value="domain">Domain</option>
				</select>
				<input class="input" type="number" placeholder="Group ID" bind:value={newGroupId}
					min={1} style="width:120px" />
				<input class="input" type="text" placeholder="Policy key"
					bind:value={newGroupPolicyKey} maxlength={128} style="flex:1" />
				<input class="input" type="text" placeholder="Value"
					bind:value={newGroupPolicyValue} maxlength={256} style="flex:1" />
				<button class="btn btn-primary btn-sm" onclick={addGroupPolicy}
					disabled={groupSaving || !newGroupPolicyKey.trim() || !newGroupPolicyValue.trim() || newGroupId <= 0 || !hasPermission($adminPermissions, 'mam.write')}>
					Add
				</button>
			</div>

			<table class="data-table">
				<thead>
					<tr>
						<th>Group Type</th>
						<th>Group ID</th>
						<th>Key</th>
						<th>Value</th>
						<th>Updated</th>
						<th>Actions</th>
					</tr>
				</thead>
				<tbody>
					{#if groupPolicies.length === 0}
						<tr>
							<td colspan="6" style="color:var(--text-tertiary)">No group policies configured.</td>
						</tr>
					{:else}
						{#each groupPolicies as p}
							<tr>
								<td>{groupTypeLabels[p.group_type] ?? p.group_type}</td>
								<td style="font-family:var(--font-mono)">{p.group_id}</td>
								<td style="font-family:var(--font-mono); font-size:var(--text-sm)">{p.policy_key}</td>
								<td style="font-family:var(--font-mono); font-size:var(--text-sm)">{p.policy_value}</td>
								<td style="font-size:var(--text-xs); color:var(--text-tertiary)">
									{p.updated_at ? new Date(p.updated_at as string).toLocaleString() : '–'}
								</td>
								<td>
									<button class="btn btn-sm btn-ghost-danger"
										onclick={() => removeGroupPolicy(p)}
										disabled={!hasPermission($adminPermissions, 'mam.write')}>Remove</button>
								</td>
							</tr>
						{/each}
					{/if}
				</tbody>
			</table>
		</div>
	</div>
{/if}

<style>
	.subtitle {
		font-size: var(--text-sm);
		color: var(--text-tertiary);
		margin-top: 0.15rem;
	}
	.header-actions { display: flex; align-items: center; gap: 1rem; }
	.alert {
		padding: 0.65rem 1rem;
		border-radius: var(--radius-md);
		margin-bottom: 1rem;
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
	}
	.alert-danger {
		background: var(--danger-bg);
		color: var(--danger-fg);
		border: 0.5px solid color-mix(in srgb, var(--danger-solid) 20%, transparent);
	}
	.alert-success {
		background: var(--success-bg);
		color: var(--success-fg);
		border: 0.5px solid color-mix(in srgb, var(--success-solid) 20%, transparent);
	}
</style>
