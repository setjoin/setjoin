<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { adminDomainList, adminDomainCreate, adminDomainUpdate, adminDomainDelete, type Domain } from '$lib/admin/client';
	import { adminPermissions, hasPermission } from '$lib/stores/auth';
	import { parseError } from '$lib/errors';
	import { Card, Table, Badge, Button, Input, Checkbox, Select, Dialog, EmptyState, Spinner } from '$lib/components/ui';
	import type { TableColumn } from '$lib/components/ui';

	let domains = $state<Domain[]>([]);
	let loading = $state(true);
	let error = $state('');

	let showDeleteConfirm = $state(false);
	let deleteTargetId = $state(0);
	let deleteTargetName = $state('');

	let showForm = $state(false);
	let editing: Domain | null = $state(null);
	let formName = $state('');
	let formIsLocal = $state(true);
	let formIsPrimary = $state(false);
	let formDmarcPolicy = $state('none');
	let formMtaStsPolicy = $state('none');
	let formMaxMessageBytes = $state(52428800);

	onMount(() => load());

	async function load() {
		loading = true;
		error = '';
		try { domains = await adminDomainList(); }
		catch (e) { error = parseError(e).message; }
		finally { loading = false; }
	}

	function openNew() {
		editing = null;
		formName = '';
		formIsLocal = true;
		formIsPrimary = false;
		formDmarcPolicy = 'none';
		formMtaStsPolicy = 'none';
		formMaxMessageBytes = 52428800;
		showForm = true;
	}

	function openEdit(d: Domain) {
		editing = d;
		formName = d.name;
		formIsLocal = d.isLocal;
		formIsPrimary = d.isPrimary;
		formDmarcPolicy = d.dmarcPolicy ?? 'none';
		formMtaStsPolicy = d.mtaStsPolicy ?? 'none';
		formMaxMessageBytes = d.maxMessageBytes ?? 52428800;
		showForm = true;
	}

	async function removeDomain(d: Domain) {
		deleteTargetId = d.id;
		deleteTargetName = d.name;
		showDeleteConfirm = true;
	}

	async function doDeleteDomain() {
		try {
			await adminDomainDelete(deleteTargetId);
			showDeleteConfirm = false;
			deleteTargetId = 0;
			await load();
		} catch (e) { error = parseError(e).message; }
	}

	async function save() {
		if (!formName.trim()) { error = 'Domain name is required'; return; }
		const payload = {
			name: formName.trim(),
			isLocal: formIsLocal,
			isPrimary: formIsPrimary,
			dmarcPolicy: formDmarcPolicy,
			mtaStsPolicy: formMtaStsPolicy,
			maxMessageBytes: formMaxMessageBytes
		};
		try {
			if (editing) await adminDomainUpdate(editing.id, payload);
			else await adminDomainCreate(payload);
			showForm = false;
			await load();
		} catch (e) { error = parseError(e).message; }
	}

	function dmarcVariant(policy: string): 'success' | 'warning' | 'danger' | 'neutral' {
		switch (policy) {
			case 'none': return 'neutral';
			case 'quarantine': return 'warning';
			case 'reject': return 'danger';
			default: return 'neutral';
		}
	}

	const COLUMNS: TableColumn[] = [
		{ key: 'name', label: 'Name', sortable: false },
		{ key: 'type', label: 'Type', sortable: false },
		{ key: 'dmarc', label: 'DMARC', sortable: false },
		{ key: 'mtasts', label: 'MTA-STS', sortable: false },
		{ key: 'size', label: 'Max size', sortable: false },
		{ key: 'actions', label: '', sortable: false },
	];
</script>

<div class="sj-page">
	<header class="sj-page-head">
		<div class="sj-page-head-left">
			<h1>Domains</h1>
			<p>{domains.length} domain{domains.length !== 1 ? 's' : ''}</p>
		</div>
		<div class="sj-page-head-right">
			<Button variant="primary" size="sm" onclick={openNew} disabled={!hasPermission($adminPermissions, 'domains.write')}>Add domain</Button>
		</div>
	</header>

	{#if error}
		<div class="alert alert-danger">{error}</div>
	{/if}

	<Card flush={true}>
		{#if loading}
			<EmptyState title="Loading…" />
		{:else if domains.length === 0}
			<EmptyState title="No domains configured." />
		{:else}
			{@const rows = domains as unknown as Record<string, unknown>[]}
			<Table columns={COLUMNS} rows={rows}>
				{#snippet cell(row, col)}
					{@const d = row as unknown as Domain}
					{#if col.key === 'name'}
						<span class="sj-name">{d.name}</span>
						{#if d.isPrimary}<Badge variant="accent" label="primary" />{/if}
					{:else if col.key === 'type'}
						<Badge variant={d.isLocal ? 'success' : 'info'} label={d.isLocal ? 'Local' : 'Relay'} />
					{:else if col.key === 'dmarc'}
						<Badge variant={dmarcVariant(d.dmarcPolicy)} label={d.dmarcPolicy} />
					{:else if col.key === 'mtasts'}
						{d.mtaStsPolicy || '—'}
					{:else if col.key === 'size'}
						{((d.maxMessageBytes ?? 52428800) / 1048576).toFixed(0)} MB
					{:else if col.key === 'actions'}
						<div class="sj-actions">
							<Button variant="ghost" size="sm" onclick={() => openEdit(d)} disabled={!hasPermission($adminPermissions, 'domains.write')}>Edit</Button>
							<Button variant="ghost" size="sm" onclick={() => removeDomain(d)} disabled={!hasPermission($adminPermissions, 'domains.write')}>Delete</Button>
						</div>
					{/if}
				{/snippet}
			</Table>
		{/if}
	</Card>

	{#if showForm}
	<Dialog open={showForm} title={editing ? 'Edit domain' : 'Add domain'} onClose={() => showForm = false}>
		{#snippet children()}
			<div class="sj-form">
				<Input label="Domain name" value={formName}
					oninput={(e) => formName = (e.target as HTMLInputElement).value}
					placeholder="example.com" maxlength={253} />
				<div class="sj-form-row">
					<Checkbox checked={formIsLocal} label="Local domain"
						onchange={(e) => formIsLocal = (e.target as HTMLInputElement).checked} />
					<Checkbox checked={formIsPrimary} label="Primary"
						onchange={(e) => formIsPrimary = (e.target as HTMLInputElement).checked} />
				</div>
				<div class="form-group">
					<label for="dmarc-sel">DMARC policy</label>
					<select id="dmarc-sel" bind:value={formDmarcPolicy}>
						<option value="none">None</option>
						<option value="quarantine">Quarantine</option>
						<option value="reject">Reject</option>
					</select>
				</div>
				<div class="form-group">
					<label for="mtasts-sel">MTA-STS</label>
					<select id="mtasts-sel" bind:value={formMtaStsPolicy}>
						<option value="none">None</option>
						<option value="testing">Testing</option>
						<option value="enforce">Enforce</option>
					</select>
				</div>
				<Input label="Max size (bytes)" type="number" value={String(formMaxMessageBytes)}
					oninput={(e) => formMaxMessageBytes = parseInt((e.target as HTMLInputElement).value) || 0} />
			</div>
		{/snippet}
		{#snippet footer()}
			<Button variant="primary" onclick={save}>Save</Button>
			<Button variant="ghost" onclick={() => showForm = false}>Cancel</Button>
		{/snippet}
	</Dialog>
	{/if}

	{#if showDeleteConfirm}
	<Dialog open={showDeleteConfirm} title="Delete domain" onClose={() => { showDeleteConfirm = false; }}>
		{#snippet children()}
			<p>Delete {deleteTargetName}? All users and mail under this domain will be affected.</p>
		{/snippet}
		{#snippet footer()}
			<Button variant="danger" onclick={doDeleteDomain}>Delete</Button>
			<Button variant="ghost" onclick={() => { showDeleteConfirm = false; }}>Cancel</Button>
		{/snippet}
	</Dialog>
	{/if}
</div>

<style>
	.sj-page { max-width: 980px; }
	.sj-page-head {
		display: flex; align-items: flex-start; gap: 12px;
		margin-bottom: 16px; flex-wrap: wrap;
	}
	.sj-page-head-left { flex: 1 1 260px; min-width: 0; }
	.sj-page-head-left h1 {
		margin: 0; font-size: clamp(20px, 16px + 1.2vw, 24px);
		font-weight: 600; letter-spacing: var(--tracking-display); color: var(--text-primary);
	}
	.sj-page-head-left p { margin: 4px 0 0; font-size: var(--text-sm); color: var(--text-secondary); }
	.sj-page-head-right { display: flex; gap: 8px; align-items: center; }
	.sj-name { font-weight: 500; }
	.sj-actions { display: flex; gap: 4px; }
	.sj-form { display: flex; flex-direction: column; gap: 12px; }
	.sj-form-row { display: flex; gap: 16px; flex-wrap: wrap; }
	.form-group select {
		width: 100%; height: var(--control-height); padding: 0 10px;
		border: 1px solid var(--border-default); border-radius: var(--radius-sm);
		background: var(--surface-card); color: var(--text-primary);
		font: var(--font-sans); font-size: var(--text-sm);
	}
	.form-group select:focus-visible { outline: none; box-shadow: var(--focus-ring); }
	.form-group label {
		display: block; font-size: var(--text-sm); font-weight: 500;
		margin-bottom: 4px; color: var(--text-primary);
	}
	.alert {
		padding: 8px 12px; border-radius: var(--radius-sm); margin-bottom: 12px; font-size: var(--text-sm);
	}
	.alert-danger { background: var(--danger-bg); color: var(--danger-fg); border: 1px solid var(--danger-fg); }
</style>
