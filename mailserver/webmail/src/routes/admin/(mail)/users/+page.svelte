<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { impersonateUser, adminPermissions, hasPermission } from '$lib/stores/auth';
	import { formatBytes } from '$lib/utils/display';
	import {
		adminFetch,
		adminUserList,
		adminUserCreate,
		adminUserUpdate,
		adminUserResetPassword,
		adminUserAliases,
		adminUserAddAlias,
		adminUserRemoveAlias,
		adminUserQuota,
		adminUserSetQuota,
		adminUserImportCSV,
		adminMailboxLifecyclePreview,
		adminMailboxLifecycleTransition,
		adminMailboxPurgeSchedule,
		adminRetainedMailboxes,
		adminDeptTree,
		type AdminUser,
		type MailboxLifecyclePreview,
		type RetainedMailbox,
		type Alias,
		type Quota,
		type TreeNode
	} from '$lib/admin/client';
	import { parseError } from '$lib/errors';
	import { validate, required, maxLength, minLength, isEmail, isNumber, normalize } from '$lib/validation';
	import { t } from '$lib/i18n';
	import AppAccessEditor from '$lib/components/admin/AppAccessEditor.svelte';
	import {
		Button, Input, Checkbox,
		Avatar, Badge, Card, Dialog, Table, Switch, Tooltip,
		EmptyState, Spinner, showToast
	} from '$lib/components/ui';
	import type { TableColumn } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';

	let users = $state<AdminUser[]>([]);
	let depts = $state<TreeNode[]>([]);
	let loading = $state(true);
	let error = $state('');
	let deptsLoadError = $state('');
	let search = $state('');
	let searchDebounce: ReturnType<typeof setTimeout> | undefined;

	let showCreate = $state(false);
	let createForm = $state({ email: '', displayName: '', password: '', isLocalAdmin: false });

	let showImport = $state(false);
	let importFile = $state<File | null>(null);
	let importResult = $state<{ created: number; failed: Array<{ row: number; email: string; error: string }> } | null>(null);

	let createErrors = $state<Record<string, string>>({});
	// Server-side create rejection (password policy, duplicate, domain scope):
	// rendered INSIDE the dialog — the page-level `error` banner sits BEHIND the
	// modal overlay, which left the admin staring at a dead Create button.
	let createServerError = $state('');
	let pwdErrors = $state<Record<string, string>>({});
	let aliasErrors = $state<Record<string, string>>({});
	let quotaErrors = $state<Record<string, string>>({});
	let editErrors = $state<Record<string, string>>({});
	let importErrors = $state<Record<string, string>>({});

	let editingUser = $state<AdminUser | null>(null);
	let editDisplayName = $state('');
	let editDeptId = $state<number | null>(null);

	let pwdUser = $state<AdminUser | null>(null);
	let newPassword = $state('');
	let pwdMustChange = $state(true);

	let aliasUser = $state<AdminUser | null>(null);
	let aliases = $state<Alias[]>([]);
	let newAlias = $state('');

	let quotaUser = $state<AdminUser | null>(null);
	let quota = $state<Quota | null>(null);
	let editQuotaBytes = $state(5368709120);
	let editSendQuota = $state(500);

	let apModalUser = $state<any>(null);
	let apModalList = $state<any[]>([]);
	let apModalLoading = $state(false);

	let lifecycleTarget = $state<AdminUser | null>(null);
	let lifecyclePreview = $state<MailboxLifecyclePreview | null>(null);
	let retainedMailboxes = $state<RetainedMailbox[]>([]);
	let retainedTarget = $state<RetainedMailbox | null>(null);
	let lifecycleReason = $state('');
	let reconnectUserId = $state<number | null>(null);
	let purgeApproverId = $state<number | null>(null);
	let lifecycleBusy = $state(false);
	let showRevokeAppPwdConfirm = $state(false);
	let revokeApTarget = $state<{ userId: number; apId: number } | null>(null);

	// App access editor
	let showAppAccess = $state(false);
	let appAccessUser = $state<AdminUser | null>(null);

	function openAppPasswords(user: any) {
		apModalUser = user;
		apModalList = [];
		loadUserAppPasswords(user.id);
	}

	async function loadUserAppPasswords(userID: number) {
		apModalLoading = true;
		const res = await adminFetch(`/admin/users/${userID}/app-passwords`);
		if (res.ok) apModalList = await res.json();
		apModalLoading = false;
	}

	async function adminRevokeAppPassword(userID: number, apID: number) {
		revokeApTarget = { userId: userID, apId: apID };
		showRevokeAppPwdConfirm = true;
	}

	async function doRevokeAppPassword() {
		if (!revokeApTarget) return;
		await adminFetch(`/admin/users/${revokeApTarget.userId}/app-passwords/${revokeApTarget.apId}`, { method: 'DELETE' });
		showRevokeAppPwdConfirm = false;
		revokeApTarget = null;
		loadUserAppPasswords(apModalUser.id);
	}

	onMount(async () => {
		await Promise.all([refreshUsers(), refreshRetainedMailboxes(), loadDepts()]);
	});

	async function refreshUsers() {
		loading = true;
		try {
			users = await adminUserList(search || undefined);
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	async function refreshRetainedMailboxes() {
		try { retainedMailboxes = await adminRetainedMailboxes(); }
		catch { retainedMailboxes = []; }
	}

	async function openLifecycle(u: AdminUser) {
		if (!u.mailboxId) { error = t('admin.mailbox_lifecycle.no_primary'); return; }
		lifecycleTarget = u;
		lifecycleReason = '';
		try { lifecyclePreview = await adminMailboxLifecyclePreview(u.mailboxId); }
		catch (e) { lifecycleTarget = null; error = parseError(e).message; }
	}

	async function runLifecycleAction(action: 'suspend' | 'resume' | 'detach_retain') {
		if (!lifecycleTarget?.mailboxId || !lifecyclePreview || lifecycleReason.trim().length < 8) return;
		lifecycleBusy = true;
		try {
			await adminMailboxLifecycleTransition(lifecycleTarget.mailboxId, action, lifecyclePreview.state.generation, lifecycleReason.trim());
			lifecycleTarget = null;
			lifecyclePreview = null;
			await Promise.all([refreshUsers(), refreshRetainedMailboxes()]);
			showToast(t(action === 'detach_retain' ? 'admin.mailbox_lifecycle.toast_detached' :
				action === 'suspend' ? 'admin.mailbox_lifecycle.toast_suspended' : 'admin.mailbox_lifecycle.toast_resumed'), { variant: 'success' });
		} catch (e) { error = parseError(e).message; }
		finally { lifecycleBusy = false; }
	}

	async function reconnectRetained() {
		if (!retainedTarget || !reconnectUserId || lifecycleReason.trim().length < 8) return;
		lifecycleBusy = true;
		try {
			await adminMailboxLifecycleTransition(Number(retainedTarget.mailboxId), 'reconnect', retainedTarget.generation,
				lifecycleReason.trim(), { targetUserId: String(reconnectUserId), evidenceKind: 'local_user' });
			retainedTarget = null;
			await Promise.all([refreshUsers(), refreshRetainedMailboxes()]);
			showToast(t('admin.mailbox_lifecycle.toast_reconnected'), { variant: 'success' });
		} catch (e) { error = parseError(e).message; }
		finally { lifecycleBusy = false; }
	}

	async function scheduleRetainedPurge() {
		if (!retainedTarget || !purgeApproverId || lifecycleReason.trim().length < 8) return;
		lifecycleBusy = true;
		try {
			const preview = await adminMailboxLifecyclePreview(Number(retainedTarget.mailboxId));
			await adminMailboxPurgeSchedule(Number(retainedTarget.mailboxId), preview.state.generation,
				preview.previewDigest, purgeApproverId, lifecycleReason.trim());
			retainedTarget = null;
			showToast(t('admin.mailbox_lifecycle.toast_purge_requested'), { variant: 'success' });
		} catch (e) { error = parseError(e).message; }
		finally { lifecycleBusy = false; }
	}

	async function loadDepts() {
		deptsLoadError = '';
		try { depts = await adminDeptTree(); }
		catch (e) {
			deptsLoadError = parseError(e).message;
			console.error('Failed to load departments', e);
		}
	}

	function flatDepts(nodes: TreeNode[]): TreeNode[] {
		const out: TreeNode[] = [];
		for (const n of nodes) {
			out.push(n);
			if (n.children?.length) out.push(...flatDepts(n.children));
		}
		return out;
	}
	const flatDeptList = $derived(flatDepts(depts));

	async function createUser() {
		createErrors = {};
		createServerError = '';
		const cResult = validate({
			email:    [required('Email is required'), isEmail(), maxLength(254)],
			password: [required('Password is required'), minLength(8, 'Password must be at least 8 characters'), maxLength(128)],
			displayName: [maxLength(128)],
		}, { email: normalize(createForm.email), password: normalize(createForm.password), displayName: normalize(createForm.displayName) });
		if (!cResult.valid) { createErrors = cResult.errors; return; }
		try {
			await adminUserCreate({
				email: createForm.email,
				displayName: createForm.displayName,
				password: createForm.password,
				isLocalAdmin: createForm.isLocalAdmin
			});
			showCreate = false;
			createForm = { email: '', displayName: '', password: '', isLocalAdmin: false };
			await refreshUsers();
		} catch (e) { createServerError = parseError(e).message; }
	}

	async function toggleEnabled(u: AdminUser) {
		try { await adminUserUpdate(u.id, { enabled: !u.enabled }); await refreshUsers(); }
		catch (e) { error = parseError(e).message; }
	}

	async function toggleAdmin(u: AdminUser) {
		try { await adminUserUpdate(u.id, { isLocalAdmin: !u.isLocalAdmin }); await refreshUsers(); }
		catch (e) { error = parseError(e).message; }
	}

	async function saveEdit() {
		if (!editingUser) return;
		editErrors = {};
		const eResult = validate({ displayName: [maxLength(128)] }, { displayName: normalize(editDisplayName) });
		if (!eResult.valid) { editErrors = eResult.errors; return; }
		try {
			await adminUserUpdate(editingUser.id, { displayName: editDisplayName, departmentId: editDeptId ?? undefined });
			editingUser = null;
			await refreshUsers();
		} catch (e) { error = parseError(e).message; }
	}

	async function savePassword() {
		if (!pwdUser) return;
		pwdErrors = {};
		const pResult = validate({
			newPassword: [required('Password is required'), minLength(8, 'Password must be at least 8 characters'), maxLength(128)],
		}, { newPassword: normalize(newPassword) });
		if (!pResult.valid) { pwdErrors = pResult.errors; return; }
		try {
			await adminUserResetPassword(pwdUser.id, newPassword, pwdMustChange);
			pwdUser = null;
			newPassword = '';
			pwdMustChange = true;
		} catch (e) { error = parseError(e).message; }
	}

	async function loadAliases(u: AdminUser) {
		aliasUser = u;
		newAlias = '';
		try { aliases = await adminUserAliases(u.id); }
		catch (e) { error = parseError(e).message; }
	}

	async function addAlias() {
		if (!aliasUser) return;
		aliasErrors = {};
		const aResult = validate({ alias: [required('Alias is required'), isEmail(), maxLength(254)] }, { alias: normalize(newAlias) });
		if (!aResult.valid) { aliasErrors = aResult.errors; return; }
		try {
			await adminUserAddAlias(aliasUser.id, newAlias.trim());
			newAlias = '';
			aliases = await adminUserAliases(aliasUser.id);
			await refreshUsers();
		} catch (e) { error = parseError(e).message; }
	}

	async function removeAlias(a: Alias) {
		if (!aliasUser) return;
		try {
			await adminUserRemoveAlias(aliasUser.id, a.id);
			aliases = await adminUserAliases(aliasUser.id);
			await refreshUsers();
		} catch (e) { error = parseError(e).message; }
	}

	async function loadQuota(u: AdminUser) {
		quotaUser = u;
		try {
			quota = await adminUserQuota(u.id);
			editQuotaBytes = quota.quotaBytes;
			editSendQuota = quota.sendingQuotaDay;
		} catch (e) { error = parseError(e).message; }
	}

	async function saveQuota() {
		if (!quotaUser) return;
		quotaErrors = {};
		const qResult = validate({
			quotaBytes: [isNumber()],
			sendQuota: [isNumber()],
		}, { quotaBytes: String(editQuotaBytes), sendQuota: String(editSendQuota) });
		if (!qResult.valid) { quotaErrors = qResult.errors; return; }
		try {
			await adminUserSetQuota(quotaUser.id, { quotaBytes: editQuotaBytes, sendingQuotaDay: editSendQuota });
			quotaUser = null;
			quota = null;
			await refreshUsers();
		} catch (e) { error = parseError(e).message; }
	}


	async function doImpersonate(u: AdminUser) {
		try {
			await impersonateUser(u.id);
			goto('/inbox');
		} catch (e) { error = parseError(e).message; }
	}

	async function doImport() {
		if (!importFile) return;
		importErrors = {};
		if (!importFile.name.endsWith('.csv')) { importErrors.file = 'File must be a .csv file'; return; }
		if (importFile.size > 10 * 1024 * 1024) { importErrors.file = 'File must be less than 10MB'; return; }
		try {
			importResult = await adminUserImportCSV(importFile);
			if (importResult.created > 0) await refreshUsers();
		} catch (e) { error = parseError(e).message; }
	}

	const COLUMNS: TableColumn[] = [
		{ key: 'user', label: 'User', sortable: false },
		{ key: 'department', label: 'Department', sortable: false },
		{ key: 'enabled', label: 'Status', sortable: false },
		{ key: 'isLocalAdmin', label: 'Admin', sortable: false },
		{ key: 'actions', label: '', sortable: false },
	];

	const AP_COLUMNS: TableColumn[] = [
		{ key: 'name', label: 'Name', sortable: false },
		{ key: 'created', label: 'Created', sortable: false },
		{ key: 'lastUsed', label: 'Last used', sortable: false },
		{ key: 'status', label: 'Status', sortable: false },
		{ key: 'actions', label: '', sortable: false },
	];
</script>

<div class="sj-users-page">
	<header class="sj-page-head">
		<div class="sj-page-head-left">
			<h1>Users</h1>
			<p>{users.length} account{users.length !== 1 ? 's' : ''} &middot; it's your server.</p>
		</div>
		<div class="sj-page-head-right">
			<Button variant="primary" size="sm" disabled={!hasPermission($adminPermissions, 'users.create')} onclick={() => showCreate = true}>Add user</Button>
			<Button variant="secondary" size="sm" disabled={!hasPermission($adminPermissions, 'users.create')} onclick={() => { showImport = true; importFile = null; importResult = null; }}>
				Import CSV
			</Button>
		</div>
	</header>

	{#if error}
		<div class="alert alert-danger">{error}</div>
	{/if}
	{#if deptsLoadError}
		<div class="alert alert-danger">{deptsLoadError}</div>
	{/if}

	<div class="sj-filter-bar">
		<Input
			placeholder="Filter by name, email, role…"
			value={search}
			oninput={(e) => {
				search = (e.target as HTMLInputElement).value;
				clearTimeout(searchDebounce);
				searchDebounce = setTimeout(refreshUsers, 300);
			}}
			onkeydown={(e) => { if (e.key === 'Enter') { clearTimeout(searchDebounce); refreshUsers(); } }}
		/>
	</div>

	<Card flush={true}>
		{#if loading}
			<EmptyState title="Loading…" />
		{:else if users.length === 0}
			<EmptyState title="No users found." />
		{:else}
			{@const rows = users as unknown as Record<string, unknown>[]}
			<Table columns={COLUMNS} rows={rows}>
				{#snippet cell(row, col)}
					{@const u = row as unknown as AdminUser}
					{#if col.key === 'user'}
						<div class="sj-user-cell">
							<Avatar name={u.displayName || u.email} size="sm" />
							<div class="sj-user-meta">
								<span class="sj-user-name">{u.displayName || u.email}</span>
								<span class="sj-user-email">{u.email}</span>
							</div>
							{#if !u.manageable && !u.isSelf}
								<Tooltip text={t('admin.protection.reason_protected', { email: u.email })}>
									<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
									<span tabindex="0" class="sj-protection-indicator">
										<Icon name="ShieldCheck" size={13} strokeWidth={1.75} aria-hidden={true} />
										<Badge label={t('admin.protection.badge_protected')} />
									</span>
								</Tooltip>
							{:else if u.isSelf}
								<Tooltip text={t('admin.protection.reason_self')}>
									<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
									<span tabindex="0" class="sj-protection-indicator">
										<Badge label={t('admin.protection.badge_self')} />
									</span>
								</Tooltip>
							{/if}
						</div>
					{:else if col.key === 'department'}
						{flatDeptList.find(d => d.id === u.departmentId)?.name || '—'}
					{:else if col.key === 'enabled'}
						<Switch checked={u.enabled} label="" disabled={!hasPermission($adminPermissions, 'users.suspend') || !u.manageable || u.isSelf} onchange={() => toggleEnabled(u)} />
					{:else if col.key === 'isLocalAdmin'}
						<!-- Gate parity (S19): the Admin switch enforces the same
						     manageable/isSelf predicates as the enabled switch and the
						     lifecycle action — protected rows and the admin's own
						     account are not flippable from this table. -->
						<Switch checked={u.isLocalAdmin} label="" disabled={!hasPermission($adminPermissions, 'users.suspend') || !u.manageable || u.isSelf} onchange={() => toggleAdmin(u)} />
					{:else if col.key === 'actions'}
						<div class="sj-actions">
							<Button variant="ghost" size="sm" onclick={() => { editingUser = u; editDisplayName = u.displayName || ''; editDeptId = u.departmentId ?? null; }} disabled={!hasPermission($adminPermissions, 'users.suspend')}>Edit</Button>
							<Button variant="ghost" size="sm" onclick={() => { pwdUser = u; newPassword = ''; }} disabled={!hasPermission($adminPermissions, 'users.password_reset') || !u.manageable}>Password</Button>
							<Button variant="ghost" size="sm" onclick={() => loadAliases(u)}>Aliases</Button>
							<Button variant="ghost" size="sm" onclick={() => loadQuota(u)}>Quota</Button>
							<Button variant="ghost" size="sm" onclick={() => openAppPasswords(u)}>Keys</Button>
							<Button variant="ghost" size="sm" onclick={() => { appAccessUser = u; showAppAccess = true; }}>App access</Button>
							<Button variant="ghost" size="sm" onclick={() => doImpersonate(u)} disabled={!hasPermission($adminPermissions, 'users.impersonate') || !u.manageable}>View as user</Button>
							<Button variant="ghost" size="sm" onclick={() => goto(`/admin/roles?tab=effective&user=${u.id}`)} disabled={!hasPermission($adminPermissions, 'roles.manage')}>{t('admin.access_preview.preview_action')}</Button>
							<Button variant="ghost" size="sm" onclick={() => openLifecycle(u)} disabled={!hasPermission($adminPermissions, 'users.delete') || !u.manageable || u.isSelf || !u.mailboxId}>{t('admin.mailbox_lifecycle.action')}</Button>
						</div>
					{/if}
				{/snippet}
			</Table>
		{/if}
	</Card>

	{#if retainedMailboxes.length > 0}
		<section class="sj-retained-section" aria-labelledby="retained-mailboxes-title">
			<h2 id="retained-mailboxes-title">{t('admin.mailbox_lifecycle.retained_title')}</h2>
			<p>{t('admin.mailbox_lifecycle.retained_description')}</p>
			<Card flush={true}>
				<ul class="sj-retained-list">
					{#each retainedMailboxes as mailbox}
						<li>
							<div><strong>{mailbox.displayName || mailbox.email}</strong><span>{mailbox.email} · {t('admin.mailbox_lifecycle.retained_until')} {new Date(mailbox.retentionUntil).toLocaleDateString()}</span></div>
							<Button variant="secondary" size="sm" onclick={() => { retainedTarget = mailbox; lifecycleReason = ''; reconnectUserId = null; purgeApproverId = null; }}>{t('admin.mailbox_lifecycle.manage')}</Button>
						</li>
					{/each}
				</ul>
			</Card>
		</section>
	{/if}

	{#if showCreate}
	<Dialog open={showCreate} title="Create user" onClose={() => { showCreate = false; createServerError = ''; }}>
		{#snippet children()}
			<div class="sj-dialog-form">
				<Input label="Email" type="email" placeholder="user@domain.com" value={createForm.email}
					oninput={(e) => createForm.email = (e.target as HTMLInputElement).value}
					error={createErrors.email} maxlength={254} required={true} />
				<Input label="Display name" placeholder="Display name" value={createForm.displayName}
					oninput={(e) => createForm.displayName = (e.target as HTMLInputElement).value}
					error={createErrors.displayName} maxlength={128} />
				<Input label="Password" type="password" placeholder="Password" value={createForm.password}
					oninput={(e) => createForm.password = (e.target as HTMLInputElement).value}
					error={createErrors.password} maxlength={128} minlength={8} />
				<Checkbox checked={createForm.isLocalAdmin} label="Local admin"
					onchange={(e) => createForm.isLocalAdmin = (e.target as HTMLInputElement).checked} />
				{#if createServerError}<p class="sj-dialog-error" role="alert">{createServerError}</p>{/if}
			</div>
		{/snippet}
		{#snippet footer()}
			<Button variant="primary" onclick={createUser} disabled={!hasPermission($adminPermissions, 'users.create')}>Create</Button>
			<Button variant="ghost" onclick={() => showCreate = false}>Cancel</Button>
		{/snippet}
	</Dialog>
	{/if}

	{#if showImport}
	<Dialog open={showImport} title="Import users from CSV" onClose={() => { showImport = false; importResult = null; }}>
		{#snippet children()}
			<p class="sj-hint">Columns: email, password (required); optional: display_name, is_local_admin, department_id, quota_bytes</p>
			<div class="form-group">
				<label for="import-csv">CSV file</label>
				<input id="import-csv" type="file" accept=".csv"
					onchange={(e) => { importFile = (e.target as HTMLInputElement).files?.[0] ?? null; importErrors = {}; }} />
			</div>
			{#if importResult}
				<div class="sj-import-result">
					<p class="sj-import-ok">Created: {importResult.created}</p>
					{#if importResult.failed.length}
						<p class="sj-import-fail">Failed: {importResult.failed.length}</p>
						<ul>
							{#each importResult.failed as f}
								<li>Row {f.row} ({f.email}): {f.error}</li>
							{/each}
						</ul>
					{/if}
				</div>
			{/if}
		{/snippet}
		{#snippet footer()}
			<Button variant="primary" onclick={doImport} disabled={!importFile || !hasPermission($adminPermissions, 'users.create')}>Import</Button>
			<Button variant="ghost" onclick={() => { showImport = false; importResult = null; }}>Close</Button>
		{/snippet}
	</Dialog>
	{/if}

	{#if editingUser}
	{@const showEditOpen = editingUser != null}
	<Dialog open={showEditOpen} title="Edit user" onClose={() => editingUser = null}>
		{#snippet children()}
			<p class="sj-dialog-sub">{(editingUser as AdminUser).email}</p>
			<Input label="Display name" placeholder="Display name" value={editDisplayName}
				oninput={(e) => editDisplayName = (e.target as HTMLInputElement).value}
				error={editErrors.displayName} maxlength={128} />
			<div class="form-group" style="margin-top:8px">
				<label for="edit-dept">Department</label>
				{#if deptsLoadError}
					<p class="sj-field-error">{deptsLoadError}</p>
				{/if}
				<select id="edit-dept" bind:value={editDeptId}>
					<option value={null}>No department</option>
					{#each flatDeptList as d}
						<option value={d.id}>{d.path}</option>
					{/each}
				</select>
			</div>
		{/snippet}
		{#snippet footer()}
			<Button variant="primary" onclick={saveEdit} disabled={!hasPermission($adminPermissions, 'users.suspend')}>Save</Button>
			<Button variant="ghost" onclick={() => editingUser = null}>Cancel</Button>
		{/snippet}
	</Dialog>
	{/if}

	{#if pwdUser}
	{@const showPwdOpen = pwdUser != null}
	<Dialog open={showPwdOpen} title="Reset password" onClose={() => { pwdUser = null; pwdMustChange = true; }}>
		{#snippet children()}
			<p class="sj-dialog-sub">{(pwdUser as AdminUser).email}</p>
			<Input label="New password" type="password" placeholder="New password (min 8 chars)" value={newPassword}
				oninput={(e) => newPassword = (e.target as HTMLInputElement).value}
				error={pwdErrors.newPassword} maxlength={128} minlength={8} />
			<div class="form-group" style="margin-top:8px">
				<Checkbox checked={pwdMustChange} label="Must change password on next login"
					onchange={(e) => pwdMustChange = (e.target as HTMLInputElement).checked} />
			</div>
		{/snippet}
		{#snippet footer()}
			<Button variant="primary" onclick={savePassword} disabled={!hasPermission($adminPermissions, 'users.password_reset')}>Reset</Button>
			<Button variant="ghost" onclick={() => { pwdUser = null; pwdMustChange = true; }}>Cancel</Button>
		{/snippet}
	</Dialog>
	{/if}

	{#if aliasUser}
	<Dialog open={aliasUser != null} title={'Aliases — ' + aliasUser.email} wide={true} onClose={() => aliasUser = null}>
		{#snippet children()}
			<div class="sj-alias-add">
				<Input type="email" placeholder="new@domain.com" value={newAlias}
					oninput={(e) => newAlias = (e.target as HTMLInputElement).value}
					error={aliasErrors.alias} maxlength={254} />
				<Button variant="primary" size="sm" onclick={addAlias} disabled={!hasPermission($adminPermissions, 'users.create')}>Add</Button>
			</div>
			{#if aliases.length === 0}
				<EmptyState title="No aliases." />
			{:else}
				<ul class="sj-alias-list">
					{#each aliases as a}
						<li>
							<span>{a.email} {#if a.isPrimary}<Badge variant="info" label="primary" />{/if}</span>
							<Button variant="ghost" size="sm" onclick={() => removeAlias(a)} disabled={!hasPermission($adminPermissions, 'users.create')}>Remove</Button>
						</li>
					{/each}
				</ul>
			{/if}
		{/snippet}
		{#snippet footer()}
			<Button variant="ghost" onclick={() => aliasUser = null}>Close</Button>
		{/snippet}
	</Dialog>
	{/if}

	{#if quotaUser && quota}
		{@const q = quota}
		{@const showQuotaOpen = true}
	<Dialog open={showQuotaOpen} title={'Quota — ' + (quotaUser as AdminUser).email} onClose={() => { quotaUser = null; quota = null; }}>
		{#snippet children()}
			<div class="sj-quota-stats">
				<div class="sj-quota-stat">
					<span class="sj-quota-label">Storage</span>
					<span class="sj-quota-value">{formatBytes(q.usedBytes)} <span class="sj-quota-total">/ {formatBytes(q.quotaBytes)}</span></span>
				</div>
				<div class="sj-quota-stat">
					<span class="sj-quota-label">Sent today</span>
					<span class="sj-quota-value">{q.sendingSentToday} <span class="sj-quota-total">/ {q.sendingQuotaDay}</span></span>
				</div>
			</div>
			<Input label="Storage quota (bytes)" type="number" value={String(editQuotaBytes)}
				oninput={(e) => editQuotaBytes = parseInt((e.target as HTMLInputElement).value) || 0}
				error={quotaErrors.quotaBytes} />
			<div class="form-group" style="margin-top:8px">
				<Input label="Daily send limit" type="number" value={String(editSendQuota)}
					oninput={(e) => editSendQuota = parseInt((e.target as HTMLInputElement).value) || 0}
					error={quotaErrors.sendQuota} />
			</div>
		{/snippet}
		{#snippet footer()}
			<Button variant="primary" onclick={saveQuota} disabled={!hasPermission($adminPermissions, 'users.create')}>Save</Button>
			<Button variant="ghost" onclick={() => { quotaUser = null; quota = null; }}>Cancel</Button>
		{/snippet}
	</Dialog>
	{/if}

	{#if apModalUser}
	<Dialog open={apModalUser != null} title={'App passwords — ' + apModalUser.email} wide={true} onClose={() => apModalUser = null}>
		{#snippet children()}
			{#if apModalLoading}
				<Spinner size={20} label="Loading app passwords" />
			{:else if apModalList.length === 0}
				<p class="sj-hint">No app passwords configured for this user.</p>
			{:else}
				{@const apRows = apModalList.map((ap) => ({
					name: ap.name,
					created: new Date(ap.createdAt).toLocaleDateString(),
					lastUsed: ap.lastUsedAt ? new Date(ap.lastUsedAt).toLocaleDateString() : 'Never',
					status: ap.revokedAt ? 'Revoked' : 'Active',
					revokedAt: ap.revokedAt,
					id: ap.id,
				})) as Record<string, unknown>[]}
				<Table columns={AP_COLUMNS} rows={apRows}>
					{#snippet cell(row, col)}
						{#if col.key === 'status'}
							<Badge variant={row.revokedAt ? 'danger' : 'success'} label={String(row.status)} dot={true} />
						{:else if col.key === 'actions'}
							{#if !row.revokedAt}
								<Button variant="ghost" size="sm" onclick={() => adminRevokeAppPassword(apModalUser.id, Number(row.id))} disabled={!hasPermission($adminPermissions, 'users.create')}>Revoke</Button>
							{/if}
						{/if}
					{/snippet}
				</Table>
			{/if}
		{/snippet}
		{#snippet footer()}
			<Button variant="ghost" onclick={() => apModalUser = null}>Close</Button>
		{/snippet}
	</Dialog>
	{/if}

	{#if lifecycleTarget && lifecyclePreview}
	{@const preview = lifecyclePreview}
	<Dialog open={true} title={t('admin.mailbox_lifecycle.dialog_title') + ' — ' + lifecycleTarget.email} onClose={() => { lifecycleTarget = null; lifecyclePreview = null; }}>
		{#snippet children()}
			<div class="sj-lifecycle-summary">
				<div><span>{t('admin.mailbox_lifecycle.binding')}</span><strong>{preview.state.binding}</strong></div>
				<div><span>{t('admin.mailbox_lifecycle.access')}</span><strong>{preview.state.access}</strong></div>
				<div><span>{t('admin.mailbox_lifecycle.delivery')}</span><strong>{preview.state.delivery}</strong></div>
				<div><span>{t('admin.mailbox_lifecycle.messages')}</span><strong>{preview.messageCount}</strong></div>
			</div>
			<p class="sj-hint">{t('admin.mailbox_lifecycle.explanation')}</p>
			<Input label={t('admin.mailbox_lifecycle.audit_reason')} value={lifecycleReason} minlength={8} maxlength={1024}
				oninput={(e) => lifecycleReason = (e.target as HTMLInputElement).value} />
		{/snippet}
		{#snippet footer()}
			{#if preview.state.access === 'active'}
				<Button variant="secondary" onclick={() => runLifecycleAction('suspend')} disabled={lifecycleBusy || lifecycleReason.trim().length < 8}>{t('admin.mailbox_lifecycle.suspend')}</Button>
			{:else}
				<Button variant="secondary" onclick={() => runLifecycleAction('resume')} disabled={lifecycleBusy || lifecycleReason.trim().length < 8}>{t('admin.mailbox_lifecycle.resume')}</Button>
			{/if}
			<Button variant="danger" onclick={() => runLifecycleAction('detach_retain')} disabled={lifecycleBusy || lifecycleReason.trim().length < 8}>{t('admin.mailbox_lifecycle.detach')}</Button>
			<Button variant="ghost" onclick={() => { lifecycleTarget = null; lifecyclePreview = null; }}>{t('common.cancel')}</Button>
		{/snippet}
	</Dialog>
	{/if}

	{#if retainedTarget}
	{@const retained = retainedTarget}
	<Dialog open={true} title={t('admin.mailbox_lifecycle.retained_dialog') + ' — ' + retainedTarget.email} wide={true} onClose={() => retainedTarget = null}>
		{#snippet children()}
			<p class="sj-hint">{t('admin.mailbox_lifecycle.reconnect_explanation', { id: retained.mailboxId })}</p>
			<div class="form-group">
				<label for="reconnect-user">{t('admin.mailbox_lifecycle.verified_identity')}</label>
				<select id="reconnect-user" bind:value={reconnectUserId}>
					<option value={null}>{t('admin.mailbox_lifecycle.select_user')}</option>
					{#each users.filter((u) => u.manageable && !u.mailboxId) as u}
						<option value={u.id}>{u.displayName || u.email} — {u.email}</option>
					{/each}
				</select>
			</div>
			<div class="form-group">
				<label for="purge-approver">{t('admin.mailbox_lifecycle.approver')}</label>
				<select id="purge-approver" bind:value={purgeApproverId}>
					<option value={null}>{t('admin.mailbox_lifecycle.select_approver')}</option>
					{#each users.filter((u) => u.manageable) as u}
						<option value={u.id}>{u.displayName || u.email} — {u.email}</option>
					{/each}
				</select>
			</div>
			<Input label={t('admin.mailbox_lifecycle.audit_reason')} value={lifecycleReason} minlength={8} maxlength={1024}
				oninput={(e) => lifecycleReason = (e.target as HTMLInputElement).value} />
			{#if retained.addresses.length > 0}<p class="sj-hint">{t('admin.mailbox_lifecycle.reserved')}: {retained.addresses.join(', ')}</p>{/if}
		{/snippet}
		{#snippet footer()}
			<Button variant="primary" onclick={reconnectRetained} disabled={lifecycleBusy || !reconnectUserId || lifecycleReason.trim().length < 8}>{t('admin.mailbox_lifecycle.reconnect')}</Button>
			<Button variant="danger" onclick={scheduleRetainedPurge} disabled={lifecycleBusy || !purgeApproverId || lifecycleReason.trim().length < 8}>{t('admin.mailbox_lifecycle.request_purge')}</Button>
			<Button variant="ghost" onclick={() => retainedTarget = null}>{t('common.cancel')}</Button>
		{/snippet}
	</Dialog>
	{/if}

	{#if showRevokeAppPwdConfirm}
	<Dialog open={showRevokeAppPwdConfirm} title="Revoke app password" onClose={() => { showRevokeAppPwdConfirm = false; revokeApTarget = null; }}>
		{#snippet children()}
			<p>Revoke this app password? The user will lose access from any client using it.</p>
		{/snippet}
		{#snippet footer()}
			<Button variant="danger" onclick={doRevokeAppPassword} disabled={!hasPermission($adminPermissions, 'users.create')}>Revoke</Button>
			<Button variant="ghost" onclick={() => { showRevokeAppPwdConfirm = false; revokeApTarget = null; }}>Cancel</Button>
		{/snippet}
	</Dialog>
	{/if}

	{#if showAppAccess}
	<AppAccessEditor open={showAppAccess} userId={appAccessUser?.id ?? 0} userEmail={appAccessUser?.email ?? ''} onClose={() => { showAppAccess = false; appAccessUser = null; }} />
	{/if}
</div>

<style>
	.sj-dialog-error { color: var(--danger-fg); font-size: var(--text-sm); margin: var(--space-2) 0 0; }
	.sj-users-page {
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
	.sj-page-head-left p {
		margin: 4px 0 0;
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.sj-page-head-right {
		display: flex;
		gap: 8px;
		align-items: center;
	}
	.sj-filter-bar {
		margin-bottom: 12px;
		max-width: 320px;
	}
	.sj-user-cell {
		display: flex;
		align-items: center;
		gap: 8px;
	}
	.sj-protection-indicator {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		cursor: default;
		border-radius: var(--radius-sm);
		outline-offset: 2px;
	}
	.sj-protection-indicator:focus-visible {
		outline: 2px solid var(--accent);
	}
	.sj-user-meta {
		display: flex;
		flex-direction: column;
		min-width: 0;
	}
	.sj-user-name {
		font-size: var(--text-sm);
		font-weight: 500;
		color: var(--text-primary);
	}
	.sj-user-email {
		font-size: var(--text-2xs);
		font-family: var(--font-mono);
		color: var(--text-tertiary);
	}
	.sj-actions {
		display: flex;
		gap: 2px;
		flex-wrap: wrap;
	}
	.sj-dialog-form {
		display: flex;
		flex-direction: column;
		gap: 12px;
	}
	.sj-dialog-sub {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		margin: 0 0 12px;
	}
	.sj-hint {
		font-size: var(--text-sm);
		color: var(--text-caption);
		margin: 0 0 12px;
	}
	.sj-retained-section {
		margin-top: var(--space-5);
	}
	.sj-retained-section h2 {
		margin: 0;
		font-size: var(--text-lg);
		color: var(--text-primary);
	}
	.sj-retained-section > p {
		margin: var(--space-1) 0 var(--space-3);
		font-size: var(--text-sm);
		color: var(--text-caption);
	}
	.sj-retained-list {
		list-style: none;
		padding: 0;
		margin: 0;
	}
	.sj-retained-list li {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-3);
		padding: var(--space-3);
		border-bottom: 1px solid var(--border-subtle);
	}
	.sj-retained-list li:last-child { border-bottom: 0; }
	.sj-retained-list li div { display: flex; flex-direction: column; min-width: 0; }
	.sj-retained-list li span { font-size: var(--text-sm); color: var(--text-caption); }
	.sj-lifecycle-summary {
		display: grid;
		grid-template-columns: repeat(2, minmax(0, 1fr));
		gap: var(--space-2);
		margin-bottom: var(--space-3);
	}
	.sj-lifecycle-summary div {
		display: flex;
		flex-direction: column;
		padding: var(--space-2) var(--space-3);
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-sm);
		background: var(--surface-sunken);
	}
	.sj-lifecycle-summary span { font-size: var(--text-sm); color: var(--text-caption); }
	.sj-lifecycle-summary strong { color: var(--text-primary); }
	.sj-import-result {
		background: var(--surface-sunken);
		border-radius: var(--radius-md);
		padding: 12px;
		margin-bottom: 12px;
		font-size: var(--text-sm);
	}
	.sj-import-ok { color: var(--success-fg); margin: 0; }
	.sj-import-fail { color: var(--danger-fg); margin: 4px 0 0; }
	.sj-alias-add {
		display: flex;
		gap: 8px;
		align-items: flex-end;
		margin-bottom: 12px;
	}
	.sj-alias-list {
		list-style: none;
		padding: 0;
		margin: 0;
		max-height: 200px;
		overflow-y: auto;
	}
	.sj-alias-list li {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 6px 0;
		border-bottom: 1px solid var(--border-subtle);
		font-size: var(--text-sm);
	}
	.sj-quota-stats {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 12px;
		margin-bottom: 12px;
	}
	.sj-quota-stat {
		background: var(--surface-sunken);
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-sm);
		padding: 10px 12px;
		display: flex;
		flex-direction: column;
		gap: 4px;
	}
	.sj-quota-label {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		text-transform: uppercase;
		letter-spacing: var(--tracking-caps);
	}
	.sj-quota-value {
		font-size: var(--text-md);
		font-weight: 600;
		color: var(--text-primary);
	}
	.sj-quota-total {
		font-size: var(--text-sm);
		font-weight: 400;
		color: var(--text-tertiary);
	}
	.sj-field-error {
		color: var(--danger-fg);
		font-size: var(--text-xs);
		margin: 0 0 4px;
	}
	.alert {
		padding: 8px 12px;
		border-radius: var(--radius-sm);
		margin-bottom: 12px;
		font-size: var(--text-sm);
	}
	.alert-danger {
		background: var(--danger-bg);
		color: var(--danger-fg);
		border: 1px solid var(--danger-fg);
	}
	.form-group select {
		width: 100%;
		height: var(--control-height);
		padding: 0 10px;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		background: var(--surface-card);
		color: var(--text-primary);
		font: var(--font-sans);
		font-size: var(--text-sm);
	}
	.form-group select:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
</style>
