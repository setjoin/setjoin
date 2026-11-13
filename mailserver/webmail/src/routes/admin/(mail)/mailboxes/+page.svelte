<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import {
		adminMailboxList, adminMailboxCreate, adminMailboxUpdate, adminMailboxDelete,
		adminMailboxFolders, adminMailboxCreateFolder, adminMailboxDeleteFolder,
		adminMailboxImport, adminMailboxExport, adminUserList,
		type AdminMailbox, type AdminFolder, type AdminUser
	} from '$lib/admin/client';
	import { parseError } from '$lib/errors';
	import { formatBytes } from '$lib/utils/display';
	import { downloadBlob } from '$lib/utils/downloadBlob';
	import { Card, Table, Badge, Button, Input, Switch, Dialog, EmptyState, Spinner } from '$lib/components/ui';
	import type { TableColumn } from '$lib/components/ui';
	import { adminPermissions, hasPermission } from '$lib/stores/auth';

	let mailboxes = $state<AdminMailbox[]>([]);
	let users = $state<AdminUser[]>([]);
	let loading = $state(true);
	let error = $state('');
	let usersLoadError = $state('');
	let search = $state('');

	let showCreate = $state(false);
	let createUserId = $state<number | null>(null);
	let createName = $state('');
	let createRole = $state('');
	let createQuota = $state(5368709120);

	let showEdit = $state(false);
	let editingMb = $state<AdminMailbox | null>(null);
	let editName = $state('');
	let editQuota = $state(0);
	let editEnabled = $state(true);
	let editDeletedPurgeDays = $state<number | null>(null);
	let editSpamPurgeDays = $state<number | null>(null);
	let editLitigationHold = $state(false);

	let showFolders = $state(false);
	let folderMb = $state<AdminMailbox | null>(null);
	let folders = $state<AdminFolder[]>([]);
	let newFolderName = $state('');

	let showImport = $state(false);
	let importMb = $state<AdminMailbox | null>(null);
	let importFile = $state<File | null>(null);
	let importResult = $state<{ imported: number; failed: Array<{ index?: number; file?: string; error: string }> } | null>(null);

	let showExport = $state(false);
	let exportMb = $state<AdminMailbox | null>(null);
	let exportFormat = $state<'mbox' | 'eml'>('eml');

	let showDeleteConfirm = $state(false);
	let deleteTarget = $state<AdminMailbox | null>(null);

	onMount(async () => { await Promise.all([refreshMailboxes(), loadUsers()]); });

	async function refreshMailboxes() {
		loading = true;
		try { mailboxes = await adminMailboxList(search || undefined); }
		catch (e) { error = parseError(e).message; }
		finally { loading = false; }
	}

	async function loadUsers() {
		usersLoadError = '';
		try { users = await adminUserList(); }
		catch (e) { usersLoadError = parseError(e).message; console.error('Failed to load users', e); }
	}

	async function createMailbox() {
		if (!createUserId || !createName.trim()) return;
		try {
			await adminMailboxCreate({ userId: createUserId, name: createName.trim(), role: createRole || undefined, quotaBytes: createQuota > 0 ? createQuota : undefined });
			showCreate = false; createUserId = null; createName = ''; createRole = ''; createQuota = 5368709120;
			await refreshMailboxes();
		} catch (e) { error = parseError(e).message; }
	}

	async function saveEdit() {
		if (!editingMb) return;
		try {
			await adminMailboxUpdate(editingMb.id, { name: editName, quotaBytes: editQuota, enabled: editEnabled, deletedPurgeDays: editDeletedPurgeDays, spamPurgeDays: editSpamPurgeDays, litigationHold: editLitigationHold });
			showEdit = false; editingMb = null; await refreshMailboxes();
		} catch (e) { error = parseError(e).message; }
	}

	async function deleteMailbox(mb: AdminMailbox) {
		deleteTarget = mb;
		showDeleteConfirm = true;
	}

	async function doDeleteMailbox() {
		if (!deleteTarget) return;
		try {
			await adminMailboxDelete(deleteTarget.id);
			showDeleteConfirm = false; deleteTarget = null; await refreshMailboxes();
		} catch (e) { error = parseError(e).message; }
	}

	async function loadFolders(mb: AdminMailbox) {
		folderMb = mb; newFolderName = ''; showFolders = true;
		try { folders = await adminMailboxFolders(mb.id); }
		catch (e) { error = parseError(e).message; }
	}

	async function addFolder() {
		if (!folderMb || !newFolderName.trim()) return;
		try { await adminMailboxCreateFolder(folderMb.id, { name: newFolderName.trim() }); newFolderName = ''; folders = await adminMailboxFolders(folderMb.id); await refreshMailboxes(); }
		catch (e) { error = parseError(e).message; }
	}

	async function removeFolder(f: AdminFolder) {
		if (!folderMb) return;
		try { await adminMailboxDeleteFolder(folderMb.id, f.id); folders = await adminMailboxFolders(folderMb.id); await refreshMailboxes(); }
		catch (e) { error = parseError(e).message; }
	}

	async function doImport() {
		if (!importMb || !importFile) return;
		try { importResult = await adminMailboxImport(importMb.id, importFile); if (importResult.imported > 0) await refreshMailboxes(); }
		catch (e) { error = parseError(e).message; }
	}

	async function doExport() {
		if (!exportMb) return;
		try {
			const blob = await adminMailboxExport(exportMb.id, exportFormat);
			downloadBlob(blob, `export-${exportMb.name}.${exportFormat === 'eml' ? 'zip' : 'mbox'}`);
			showExport = false; exportMb = null;
		} catch (e) { error = parseError(e).message; }
	}

	const COLUMNS: TableColumn[] = [
		{ key: 'name', label: 'Name', sortable: false },
		{ key: 'user', label: 'User', sortable: false },
		{ key: 'quota', label: 'Quota', sortable: false },
		{ key: 'status', label: 'Status', sortable: false },
		{ key: 'actions', label: '', sortable: false },
	];
</script>

<div class="sj-page">
	<header class="sj-page-head">
		<div class="sj-page-head-left">
			<h1>Mailboxes</h1>
			<p>{mailboxes.length} mailbox{mailboxes.length !== 1 ? 'es' : ''}</p>
		</div>
		<div class="sj-page-head-right">
			<div class="sj-search"><Input placeholder="Search mailboxes…" value={search} oninput={(e) => search = (e.target as HTMLInputElement).value} onkeydown={(e) => { if (e.key === 'Enter') refreshMailboxes(); }} /></div>
			<Button variant="primary" size="sm" onclick={() => showCreate = true} disabled={!hasPermission($adminPermissions, 'users.create')}>New mailbox</Button>
			{#if mailboxes.length > 0}
				<Button variant="secondary" size="sm" onclick={() => { importMb = mailboxes[0]; importFile = null; importResult = null; showImport = true; }} disabled={!hasPermission($adminPermissions, 'users.create')}>Import</Button>
				<Button variant="secondary" size="sm" onclick={() => { exportMb = mailboxes[0]; showExport = true; }}>Export</Button>
			{/if}
		</div>
	</header>

	{#if error}<div class="alert alert-danger">{error}</div>{/if}
	{#if usersLoadError}<div class="alert alert-danger">{usersLoadError}</div>{/if}

	<Card flush={true}>
		{#if loading}
			<EmptyState title="Loading…" />
		{:else if mailboxes.length === 0}
			<EmptyState title="No mailboxes found." />
		{:else}
			{@const rows = mailboxes as unknown as Record<string, unknown>[]}
			<Table columns={COLUMNS} rows={rows}>
				{#snippet cell(row, col)}
					{@const mb = row as unknown as AdminMailbox}
					{#if col.key === 'name'}
						{mb.name}{#if mb.isPrimary} <Badge variant="info" label="Primary" />{/if}
					{:else if col.key === 'user'}
						{mb.userEmail}
					{:else if col.key === 'quota'}
						<span class="sj-mono">{formatBytes(mb.usedBytes)} / {formatBytes(mb.quotaBytes)}</span>
					{:else if col.key === 'status'}
						<Badge variant={mb.enabled ? 'success' : 'neutral'} dot={true} label={mb.enabled ? 'Active' : 'Disabled'} />
					{:else if col.key === 'actions'}
						<div class="sj-actions">
							<Button variant="ghost" size="sm" onclick={() => { editingMb = mb; editName = mb.name; editQuota = mb.quotaBytes; editEnabled = mb.enabled; editDeletedPurgeDays = mb.deletedPurgeDays ?? null; editSpamPurgeDays = mb.spamPurgeDays ?? null; editLitigationHold = mb.litigationHold ?? false; showEdit = true; }} disabled={!hasPermission($adminPermissions, 'users.create')}>Edit</Button>
							<Button variant="ghost" size="sm" onclick={() => loadFolders(mb)}>Folders</Button>
							<Button variant="ghost" size="sm" onclick={() => deleteMailbox(mb)} disabled={!hasPermission($adminPermissions, 'users.create')}>Delete</Button>
						</div>
					{/if}
				{/snippet}
			</Table>
		{/if}
	</Card>

	{#if showCreate}
	<Dialog open={showCreate} title="Create mailbox" onClose={() => showCreate = false}>
		{#snippet children()}
			<div class="sj-form">
				{#if usersLoadError}<p class="sj-field-error">{usersLoadError}</p>{/if}
				<div class="form-group"><label for="create-user">User</label>
					<select id="create-user" bind:value={createUserId}><option value={null}>Select user</option>{#each users as u}<option value={u.id}>{u.email}</option>{/each}</select>
				</div>
				<Input label="Name" value={createName} oninput={(e) => createName = (e.target as HTMLInputElement).value} placeholder="e.g. Project team" />
				<Input label="Role" value={createRole} oninput={(e) => createRole = (e.target as HTMLInputElement).value} placeholder="e.g. custom" />
				<Input label="Quota (bytes)" type="number" value={String(createQuota)} oninput={(e) => createQuota = parseInt((e.target as HTMLInputElement).value) || 0} />
			</div>
		{/snippet}
		{#snippet footer()}
			<Button variant="primary" onclick={createMailbox} disabled={!hasPermission($adminPermissions, 'users.create')}>Create</Button>
			<Button variant="ghost" onclick={() => showCreate = false}>Cancel</Button>
		{/snippet}
	</Dialog>
	{/if}

	{#if showEdit && editingMb}
	<Dialog open={showEdit} title="Edit mailbox" onClose={() => { showEdit = false; editingMb = null; }}>
		{#snippet children()}
			<div class="sj-form">
				<p class="sj-sub">{(editingMb as AdminMailbox).userEmail}</p>
				<Input label="Name" value={editName} oninput={(e) => editName = (e.target as HTMLInputElement).value} />
				<Input label="Quota (bytes)" type="number" value={String(editQuota)} oninput={(e) => editQuota = parseInt((e.target as HTMLInputElement).value) || 0} />
				<Switch checked={editEnabled} label="Enabled" onchange={() => editEnabled = !editEnabled} />
				<Input label="Deleted items purge (days)" type="number" min="0" value={editDeletedPurgeDays != null ? String(editDeletedPurgeDays) : ''} oninput={(e) => { const v = (e.target as HTMLInputElement).value; editDeletedPurgeDays = v ? parseInt(v) : null; }} placeholder="30 (global default)" />
				<Input label="Spam purge (days)" type="number" min="0" value={editSpamPurgeDays != null ? String(editSpamPurgeDays) : ''} oninput={(e) => { const v = (e.target as HTMLInputElement).value; editSpamPurgeDays = v ? parseInt(v) : null; }} placeholder="30 (global default)" />
				<Switch checked={editLitigationHold} label="Litigation hold" onchange={() => editLitigationHold = !editLitigationHold} />
			</div>
		{/snippet}
		{#snippet footer()}
			<Button variant="primary" onclick={saveEdit} disabled={!hasPermission($adminPermissions, 'users.create')}>Save</Button>
			<Button variant="ghost" onclick={() => { showEdit = false; editingMb = null; }}>Cancel</Button>
		{/snippet}
	</Dialog>
	{/if}

	{#if showFolders && folderMb}
	<Dialog open={showFolders} title={'Folders — ' + (folderMb as AdminMailbox).name} onClose={() => { showFolders = false; folderMb = null; }}>
		{#snippet children()}
			<p class="sj-sub">{(folderMb as AdminMailbox).userEmail}</p>
			{#if folders.length === 0}
				<p class="sj-hint">No folders (system folders auto-created).</p>
			{:else}
				<ul class="sj-folder-list">
					{#each folders as f}
						<li><span class="sj-folder-path">{f.path}</span>{#if f.role}<Badge variant="info" label={f.role} />{/if}<span class="sj-folder-count">{f.totalCount} msgs ({f.unreadCount} unread)</span><Button variant="ghost" size="sm" onclick={() => removeFolder(f)} disabled={!hasPermission($adminPermissions, 'users.create')}>Delete</Button></li>
					{/each}
				</ul>
			{/if}
			<div class="sj-folder-add">
				<Input value={newFolderName} oninput={(e) => newFolderName = (e.target as HTMLInputElement).value} placeholder="New folder name" onkeydown={(e) => { if (e.key === 'Enter') addFolder(); }} />
				<Button variant="primary" size="sm" onclick={addFolder} disabled={!hasPermission($adminPermissions, 'users.create')}>Add folder</Button>
			</div>
		{/snippet}
		{#snippet footer()}
			<Button variant="ghost" onclick={() => { showFolders = false; folderMb = null; }}>Close</Button>
		{/snippet}
	</Dialog>
	{/if}

	{#if showImport && importMb}
	<Dialog open={showImport} title={'Import messages — ' + (importMb as AdminMailbox).name} onClose={() => { showImport = false; importMb = null; importResult = null; }}>
		{#snippet children()}
			<p class="sj-sub">{(importMb as AdminMailbox).userEmail}</p>
			<p class="sj-hint">Supports .mbox, .eml, or .zip of .eml files</p>
			<div class="form-group"><input type="file" accept=".mbox,.eml,.zip" onchange={(e) => { importFile = (e.target as HTMLInputElement).files?.[0] ?? null; }} /></div>
			{#if importResult}
				<div class="sj-result"><p class="sj-result-ok">Imported: {importResult.imported}</p>
					{#if importResult.failed.length}<p class="sj-result-fail">Failed: {importResult.failed.length}</p><ul>{#each importResult.failed as f}<li>{f.file ? f.file : 'Message ' + f.index}: {f.error}</li>{/each}</ul>{/if}
				</div>
			{/if}
		{/snippet}
		{#snippet footer()}
			<Button variant="primary" onclick={doImport} disabled={!importFile || !hasPermission($adminPermissions, 'users.create')}>Import</Button>
			<Button variant="ghost" onclick={() => { showImport = false; importMb = null; importResult = null; }}>Close</Button>
		{/snippet}
	</Dialog>
	{/if}

	{#if showExport && exportMb}
	<Dialog open={showExport} title={'Export messages — ' + (exportMb as AdminMailbox).name} onClose={() => { showExport = false; exportMb = null; }}>
		{#snippet children()}
			<p class="sj-sub">{(exportMb as AdminMailbox).userEmail}</p>
			<div class="form-group"><label for="export-fmt">Format</label><select id="export-fmt" bind:value={exportFormat}><option value="eml">ZIP of EML files</option><option value="mbox">MBOX file</option></select></div>
		{/snippet}
		{#snippet footer()}
			<Button variant="primary" onclick={doExport}>Export</Button>
			<Button variant="ghost" onclick={() => { showExport = false; exportMb = null; }}>Cancel</Button>
		{/snippet}
	</Dialog>
	{/if}

	{#if showDeleteConfirm && deleteTarget}
	<Dialog open={showDeleteConfirm} title="Delete mailbox" onClose={() => { showDeleteConfirm = false; deleteTarget = null; }}>
		{#snippet children()}
			<p>Delete mailbox "{(deleteTarget as AdminMailbox).name}" for {(deleteTarget as AdminMailbox).userEmail}? All messages will be lost.</p>
		{/snippet}
		{#snippet footer()}
			<Button variant="danger" onclick={doDeleteMailbox} disabled={!hasPermission($adminPermissions, 'users.create')}>Delete</Button>
			<Button variant="ghost" onclick={() => { showDeleteConfirm = false; deleteTarget = null; }}>Cancel</Button>
		{/snippet}
	</Dialog>
	{/if}
</div>

<style>
	.sj-page { max-width: 980px; }
	.sj-page-head { display: flex; align-items: flex-start; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; }
	.sj-page-head-left { flex: 1 1 260px; min-width: 0; }
	.sj-page-head-left h1 { margin: 0; font-size: clamp(20px, 16px + 1.2vw, 24px); font-weight: 600; letter-spacing: var(--tracking-display); color: var(--text-primary); }
	.sj-page-head-left p { margin: 4px 0 0; font-size: var(--text-sm); color: var(--text-secondary); }
	.sj-page-head-right { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
	.sj-search { max-width: 240px; }
	.sj-mono { font-family: var(--font-mono); font-size: var(--text-xs); }
	.sj-actions { display: flex; gap: 4px; }
	.sj-form { display: flex; flex-direction: column; gap: 12px; }
	.sj-sub { color: var(--text-secondary); font-size: var(--text-sm); margin: 0 0 4px; }
	.sj-hint { font-size: var(--text-xs); color: var(--text-tertiary); margin: 0 0 8px; }
	.sj-result { background: var(--surface-sunken); border-radius: var(--radius-md); padding: 12px; margin-bottom: 8px; font-size: var(--text-sm); }
	.sj-result-ok { color: var(--success-fg); margin: 0; }
	.sj-result-fail { color: var(--danger-fg); margin: 4px 0 0; }
	.sj-folder-list { list-style: none; padding: 0; margin: 0 0 12px; max-height: 300px; overflow-y: auto; }
	.sj-folder-list li { display: flex; align-items: center; gap: 8px; padding: 6px 0; border-bottom: 1px solid var(--border-subtle); font-size: var(--text-sm); }
	.sj-folder-path { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; min-width: 0; }
	.sj-folder-count { font-size: var(--text-xs); color: var(--text-tertiary); white-space: nowrap; }
	.sj-folder-add { display: flex; gap: 8px; align-items: flex-end; }
	.sj-field-error { color: var(--danger-fg); font-size: var(--text-xs); margin: 0 0 4px; }
	.form-group select { width: 100%; height: var(--control-height); padding: 0 10px; border: 1px solid var(--border-default); border-radius: var(--radius-sm); background: var(--surface-card); color: var(--text-primary); font: var(--font-sans); font-size: var(--text-sm); }
	.form-group select:focus-visible { outline: none; box-shadow: var(--focus-ring); }
	.form-group label { display: block; font-size: var(--text-sm); font-weight: 500; margin-bottom: 4px; color: var(--text-primary); }
	.alert { padding: 8px 12px; border-radius: var(--radius-sm); margin-bottom: 12px; font-size: var(--text-sm); }
	.alert-danger { background: var(--danger-bg); color: var(--danger-fg); border: 1px solid var(--danger-fg); }
</style>
