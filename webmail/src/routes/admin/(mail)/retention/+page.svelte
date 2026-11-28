<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import {
		adminRetentionPolicies, adminRetentionCreate, adminRetentionUpdate, adminRetentionDelete,
		adminLogRetention, adminLogRetentionSet, adminRetentionPrune,
		adminConfigGet, adminConfigSet,
		type RetentionPolicy, type LogRetentionSettings
	} from '$lib/admin/client';
	import { Card, Badge, Button, Input, Dialog, EmptyState, Spinner, Select, Checkbox, ConfirmDestructive } from '$lib/components/ui';
	import { adminPermissions, hasPermission } from '$lib/stores/auth';

	let policies = $state<RetentionPolicy[]>([]);
	let logSettings = $state<LogRetentionSettings>({ messageTraceDays: 30, mailboxAuditLogDays: 90, authEventDays: 30 });
	let purgeDays = $state<number>(30);
	let spamPurgeDays = $state<number>(30);
	let loading = $state(true);
	let error = $state('');
	let pruneResult = $state<{ table: string; deleted: number }[] | null>(null);
	let showForm = $state(false);
	let editing = $state<RetentionPolicy | null>(null);

	let formName = $state(''); let formDescription = $state('');
	let formRetainDays = $state(''); let formForever = $state(false);
	let formAction = $state<'delete' | 'hold'>('delete');
	let formIsDefault = $state(false); let formDomainId = $state('');

	const TEMPLATES: Array<{name: string; description: string; retainDays: number; action: 'delete' | 'hold'}> = [
		{name: 'Default 2-Year', description: 'Standard retention — keep for 2 years then delete.', retainDays: 730, action: 'delete'},
		{name: 'Finance 7-Year', description: 'SEC/IRS recordkeeping — 7 years.', retainDays: 2555, action: 'delete'},
		{name: 'HR 1-Year', description: 'Employment records — 1 year.', retainDays: 365, action: 'delete'},
		{name: 'Auto-Purge 90-Day', description: 'Transient mail — 90 days then delete.', retainDays: 90, action: 'delete'}
	];

	function loadTemplate(name: string) {
		const tmpl = TEMPLATES.find(t => t.name === name); if (!tmpl) return;
		editing = null; formName = tmpl.name; formDescription = tmpl.description;
		formRetainDays = tmpl.retainDays.toString(); formForever = false;
		formAction = tmpl.action; formIsDefault = false; formDomainId = '';
		showForm = true;
	}

	onMount(async () => { await loadAll(); });

	async function loadAll() {
		loading = true; error = '';
		try {
			const [p, l, c1, c2] = await Promise.all([
				adminRetentionPolicies(), adminLogRetention(),
				adminConfigGet('deleted_items_purge_days').catch(() => ({ value: 30 })),
				adminConfigGet('spam_purge_days').catch(() => ({ value: 30 }))
			]);
			policies = p; logSettings = l;
			purgeDays = typeof c1.value === 'number' ? c1.value : parseInt(c1.value as string, 10) || 30;
			spamPurgeDays = typeof c2.value === 'number' ? c2.value : parseInt(c2.value as string, 10) || 30;
		} catch (e) { error = e instanceof Error ? e.message : 'Failed to load retention settings'; }
		finally { loading = false; }
	}

	async function loadPolicies() { try { policies = await adminRetentionPolicies(); } catch (_) { /* best-effort refresh */ } }

	function openCreate() { editing = null; formName = ''; formDescription = ''; formRetainDays = ''; formForever = false; formAction = 'delete'; formIsDefault = false; formDomainId = ''; showForm = true; }
	function openEdit(policy: RetentionPolicy) { editing = policy; formName = policy.name; formDescription = policy.description ?? ''; formForever = policy.retainDays === null; formRetainDays = policy.retainDays?.toString() ?? ''; formAction = policy.action; formIsDefault = policy.isDefault; formDomainId = policy.domainId?.toString() ?? ''; showForm = true; }

	async function savePolicy() {
		if (!formName.trim()) { error = 'Name is required'; return; }
		const retainDays = formForever ? null : parseInt(formRetainDays, 10);
		if (!formForever && (isNaN(retainDays!) || retainDays! <= 0)) { error = 'Retention days must be a positive number, or check Keep forever'; return; }
		const payload = { name: formName.trim(), description: formDescription.trim() || undefined, retainDays, action: formAction, isDefault: formIsDefault, domainId: formDomainId ? parseInt(formDomainId, 10) : undefined };
		try { if (editing) await adminRetentionUpdate(editing.id, payload); else await adminRetentionCreate(payload); showForm = false; await loadPolicies(); }
		catch (e) { error = e instanceof Error ? e.message : 'Save failed'; }
	}

	async function removePolicy(id: number) { try { await adminRetentionDelete(id); await loadPolicies(); deleteTarget = null; } catch (e) { error = e instanceof Error ? e.message : 'Delete failed'; } finally { deleteBusy = false; } }
	async function saveLogSettings() { try { await adminLogRetentionSet({ messageTraceDays: logSettings.messageTraceDays, mailboxAuditLogDays: logSettings.mailboxAuditLogDays, authEventDays: logSettings.authEventDays }); error = ''; } catch (e) { error = e instanceof Error ? e.message : 'Save failed'; } }
	async function savePurgeDays() { try { await adminConfigSet('deleted_items_purge_days', purgeDays.toString()); await adminConfigSet('spam_purge_days', spamPurgeDays.toString()); error = ''; } catch (e) { error = e instanceof Error ? e.message : 'Save failed'; } }
	async function runPrune() { try { pruneResult = await adminRetentionPrune(); await loadPolicies(); confirmPrune = false; } catch (e) { error = e instanceof Error ? e.message : 'Prune failed'; } finally { pruneBusy = false; } }

	// Destructive-action guards (S19): prune and policy deletion are gated
	// behind the shared typed-confirm dialog, matching the tree convention
	// (rules/storage/security) instead of firing on a single click.
	let confirmPrune = $state(false);
	let pruneBusy = $state(false);
	let deleteTarget = $state<RetentionPolicy | null>(null);
	let deleteBusy = $state(false);
</script>

<div class="sj-page">
	<header class="sj-page-head">
		<div class="sj-page-head-left"><h1>Retention</h1><p>Data lifecycle policies and log retention.</p></div>
	</header>

	{#if error}<div class="alert alert-danger">{error}</div>{/if}

	{#if loading}
		<EmptyState title="Loading…" />
	{:else}
		<Card title="Log retention">
			{#snippet children()}
				<p class="sj-hint">Controls how long message trace and mailbox audit rows are kept before automatic deletion.</p>
				<div class="sj-form">
					<Input label="Message trace (days)" type="number" min="1" value={String(logSettings.messageTraceDays)} oninput={(e) => logSettings.messageTraceDays = parseInt((e.target as HTMLInputElement).value) || 30} />
					<p class="sj-hint-sm">Default: 30. Leave empty to keep forever.</p>
					<Input label="Mailbox audit log (days)" type="number" min="1" value={String(logSettings.mailboxAuditLogDays)} oninput={(e) => logSettings.mailboxAuditLogDays = parseInt((e.target as HTMLInputElement).value) || 90} />
					<p class="sj-hint-sm">Default: 90.</p>
					<Input label="Auth event log (days)" type="number" min="1" value={String(logSettings.authEventDays)} oninput={(e) => logSettings.authEventDays = parseInt((e.target as HTMLInputElement).value) || 30} />
					<p class="sj-hint-sm">Default: 30.</p>
				</div>
				<div class="sj-btn-row"><Button variant="primary" size="sm" disabled={!hasPermission($adminPermissions, 'compliance.write')} onclick={saveLogSettings}>Save log settings</Button><Button variant="ghost" size="sm" disabled={!hasPermission($adminPermissions, 'compliance.write')} onclick={() => confirmPrune = true}>Run prune now</Button></div>
				{#if pruneResult}<div class="sj-result">{#each pruneResult as r}<p>{r.table}: {r.deleted} rows deleted</p>{/each}</div>{/if}
			{/snippet}
		</Card>

		<div style="margin-top:12px">
		<Card title="Deleted items">
			{#snippet children()}
				<p class="sj-hint">Controls how long soft-deleted emails are kept before automatic permanent purging.</p>
				<Input label="Auto-purge after (days)" type="number" min="0" value={String(purgeDays)} oninput={(e) => purgeDays = parseInt((e.target as HTMLInputElement).value) || 0} />
				<p class="sj-hint-sm">Set to 0 to disable auto-purge. Default: 30</p>
				<div class="sj-btn-row"><Button variant="primary" size="sm" disabled={!hasPermission($adminPermissions, 'system.config')} onclick={savePurgeDays}>Save</Button></div>
			{/snippet}
		</Card>
		</div>

		<div style="margin-top:12px">
		<Card title="Spam purge">
			{#snippet children()}
				<p class="sj-hint">Controls how long messages marked as spam are kept before automatic permanent deletion.</p>
				<Input label="Spam auto-purge (days)" type="number" min="0" value={String(spamPurgeDays)} oninput={(e) => spamPurgeDays = parseInt((e.target as HTMLInputElement).value) || 0} />
				<p class="sj-hint-sm">Default: 30</p>
				<div class="sj-btn-row"><Button variant="primary" size="sm" disabled={!hasPermission($adminPermissions, 'system.config')} onclick={savePurgeDays}>Save</Button></div>
			{/snippet}
		</Card>
		</div>

		<div style="margin-top:12px">
		<Card>
			{#snippet actions()}
				<div class="sj-card-actions">
					<select class="sj-select-sm" onchange={(e) => { const v = (e.target as HTMLSelectElement).value; if (v) loadTemplate(v); (e.target as HTMLSelectElement).value = ''; }}>
						<option value="">Load template…</option>
						{#each TEMPLATES as tmpl (tmpl.name)}<option value={tmpl.name}>{tmpl.name}</option>{/each}
					</select>
					<Button variant="primary" size="sm" disabled={!hasPermission($adminPermissions, 'compliance.write')} onclick={openCreate}>New policy</Button>
				</div>
			{/snippet}
			{#snippet children()}
				<p class="sj-hint">Policies are applied to messages at delivery time. The most specific domain policy wins; if none matches, the global default is used.</p>
				{#if policies.length === 0}
					<EmptyState title="No retention policies configured." />
				{:else}
					<table class="sj-table">
						<thead><tr><th>Name</th><th>Retain</th><th>Action</th><th>Default</th><th>Domain</th><th></th></tr></thead>
						<tbody>
							{#each policies as policy}
								<tr>
									<td><div class="sj-policy-name">{policy.name}</div>{#if policy.description}<div class="sj-policy-desc">{policy.description}</div>{/if}</td>
									<td>{policy.retainDays === null ? 'Forever' : policy.retainDays + ' days'}</td>
									<td><Badge variant={policy.action === 'delete' ? 'danger' : 'info'} label={policy.action} /></td>
									<td>{policy.isDefault ? 'Default' : ''}</td>
									<td>{policy.domainId ?? 'Global'}</td>
									<td class="sj-actions"><Button variant="ghost" size="sm" onclick={() => openEdit(policy)}>Edit</Button><Button variant="ghost" size="sm" disabled={!hasPermission($adminPermissions, 'compliance.write')} onclick={() => deleteTarget = policy}>Delete</Button></td>
								</tr>
							{/each}
						</tbody>
					</table>
				{/if}
			{/snippet}
		</Card>
		</div>
	{/if}

	{#if showForm}
	<Dialog open={showForm} title={editing ? 'Edit policy' : 'New retention policy'} onClose={() => showForm = false}>
		{#snippet children()}
			<div class="sj-form">
				<Input label="Name" value={formName} oninput={(e) => formName = (e.target as HTMLInputElement).value} />
				<Input label="Description" value={formDescription} oninput={(e) => formDescription = (e.target as HTMLInputElement).value} />
				<div class="sj-form-row">
					<Input label="Retention (days)" type="number" min="1" value={formRetainDays} oninput={(e) => formRetainDays = (e.target as HTMLInputElement).value} />
					<Checkbox checked={formForever} label="Keep forever" onchange={(e) => formForever = (e.target as HTMLInputElement).checked} />
				</div>
				<div class="form-group"><label for="form-action">Action</label><select id="form-action" bind:value={formAction}><option value="delete">Delete</option><option value="hold">Hold</option></select></div>
				<Checkbox checked={formIsDefault} label="Default policy" onchange={(e) => formIsDefault = (e.target as HTMLInputElement).checked} />
				<Input label="Domain ID (optional)" type="number" value={formDomainId} oninput={(e) => formDomainId = (e.target as HTMLInputElement).value} />
			</div>
		{/snippet}
		{#snippet footer()}
			<Button variant="primary" disabled={!hasPermission($adminPermissions, 'compliance.write')} onclick={savePolicy}>Save</Button>
			<Button variant="ghost" onclick={() => showForm = false}>Cancel</Button>
		{/snippet}
	</Dialog>
	{/if}

	<!-- Destructive-action typed confirms (S19 hardening) -->
	<ConfirmDestructive
		open={confirmPrune}
		title="Run prune now"
		message="Prune permanently deletes rows already past their configured retention lifetime. This cannot be undone."
		confirmWord="PRUNE"
		confirmLabel="Run prune"
		busy={pruneBusy}
		onConfirm={runPrune}
		onCancel={() => (confirmPrune = false)}
	/>
	{#if deleteTarget}
		<ConfirmDestructive
			open={true}
			title="Delete retention policy"
			message={'Delete the retention policy "' + deleteTarget.name + '"? Mail governed by it will no longer be affected by it.'}
			confirmWord="DELETE"
			confirmLabel="Delete policy"
			busy={deleteBusy}
			onConfirm={() => deleteTarget && removePolicy(deleteTarget.id)}
			onCancel={() => (deleteTarget = null)}
		/>
	{/if}
</div>

<style>
	.sj-page { max-width: 980px; }
	.sj-page-head { display: flex; align-items: flex-start; gap: 12px; margin-bottom: 16px; }
	.sj-page-head-left { flex: 1 1 260px; min-width: 0; }
	.sj-page-head-left h1 { margin: 0; font-size: clamp(20px, 16px + 1.2vw, 24px); font-weight: 600; letter-spacing: var(--tracking-display); color: var(--text-primary); }
	.sj-page-head-left p { margin: 4px 0 0; font-size: var(--text-sm); color: var(--text-secondary); }
	.sj-form { display: flex; flex-direction: column; gap: 12px; }
	.sj-hint { font-size: var(--text-sm); color: var(--text-secondary); margin: 0 0 12px; }
	.sj-hint-sm { font-size: var(--text-xs); color: var(--text-tertiary); margin: -8px 0 4px; }
	.sj-btn-row { display: flex; gap: 12px; margin-top: 8px; }
	.sj-card-actions { display: flex; gap: 8px; align-items: center; }
	.sj-select-sm { height: var(--control-height-sm); padding: 0 8px; border: 1px solid var(--border-default); border-radius: var(--radius-sm); background: var(--surface-card); color: var(--text-primary); font: var(--font-sans); font-size: var(--text-xs); }
	.sj-select-sm:focus-visible { outline: none; box-shadow: var(--focus-ring); }
	.sj-table { width: 100%; border-collapse: collapse; }
	.sj-table th { text-align: left; padding: 8px 12px; font-size: var(--text-2xs); letter-spacing: var(--tracking-caps); text-transform: uppercase; color: var(--text-tertiary); font-weight: 600; border-bottom: 1px solid var(--border-default); }
	.sj-table td { padding: 8px 12px; font-size: var(--text-sm); border-bottom: 1px solid var(--border-subtle); }
	.sj-policy-name { font-weight: 500; }
	.sj-policy-desc { font-size: var(--text-xs); color: var(--text-tertiary); }
	.sj-actions { display: flex; gap: 4px; }
	.sj-form-row { display: flex; gap: 12px; align-items: center; }
	.sj-result { margin-top: 8px; padding: 8px 12px; background: var(--surface-sunken); border-radius: var(--radius-md); font-size: var(--text-sm); }
	.form-group label { display: block; font-size: var(--text-sm); font-weight: 500; margin-bottom: 4px; color: var(--text-primary); }
	.form-group select { width: 100%; height: var(--control-height); padding: 0 10px; border: 1px solid var(--border-default); border-radius: var(--radius-sm); background: var(--surface-card); color: var(--text-primary); font: var(--font-sans); font-size: var(--text-sm); }
	.form-group select:focus-visible { outline: none; box-shadow: var(--focus-ring); }
	.alert { padding: 8px 12px; border-radius: var(--radius-sm); margin-bottom: 12px; font-size: var(--text-sm); }
	.alert-danger { background: var(--danger-bg); color: var(--danger-fg); border: 1px solid var(--danger-fg); }
</style>
