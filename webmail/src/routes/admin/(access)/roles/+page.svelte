<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { adminPermissions, hasPermission } from '$lib/stores/auth';
	import {
		Tabs,
		Table,
		Card,
		Button,
		Badge,
		Dialog,
		EmptyState,
		showToast
	} from '$lib/components/ui';
	import type { TableColumn, TabItem } from '$lib/components/ui';
	import { adminListRoles, adminDeleteRole, adminPermissionCatalog, type AdminRole } from '$lib/admin/roles';
	import { diffPerms } from '$lib/admin/permissionMeta';
	import { adminDomainList, getAuditPolicy } from '$lib/admin/client';
	import RoleEditorDialog from '$lib/components/admin/RoleEditorDialog.svelte';
	import ReasonPrompt from '$lib/components/admin/ReasonPrompt.svelte';
	import RoleMembersPanel from '$lib/components/admin/RoleMembersPanel.svelte';
	import AccessPreview from '$lib/components/admin/AccessPreview.svelte';
	import SodEnablementPanel from '$lib/components/admin/SodEnablementPanel.svelte';
	import JitSettingsPanel from '$lib/components/admin/JitSettingsPanel.svelte';
	import AccessReviewsPanel from '$lib/components/admin/AccessReviewsPanel.svelte';
	import RoleClassBadge from '$lib/components/admin/RoleClassBadge.svelte';
	import { parseError } from '$lib/errors';
	import { t } from '$lib/i18n';
	import { page } from '$app/stores';

	let roles = $state<AdminRole[]>([]);
	let domains = $state<{ id: number; name: string }[]>([]);
	let loading = $state(true);
	let error = $state('');
	let search = $state('');
	let activeTab = $state('roles');
	let previewUserId = $state<number | null>(null);
	let reviewCampaignId = $state<number | null>(null);

	let editorOpen = $state(false);
	let editorMode = $state<'create' | 'edit' | 'clone'>('create');
	let editorRole = $state<AdminRole | null>(null);

	let detailRole = $state<AdminRole | null>(null);
	let compareA = $state<AdminRole | null>(null);
	let compareB = $state<AdminRole | null>(null);

	let deleteTarget = $state<AdminRole | null>(null);
	let catalog = $state<Map<string, string>>(new Map());

	// ── Audit policy: reason-required gate ──
	// ponytail: fetched once on mount; false = no prompt (default policy)
	let rolesReasonRequired = $state(false);

	let canManageRoles = $derived(hasPermission($adminPermissions, 'roles.manage'));

	let TABS: TabItem[] = $derived([
		{ id: 'roles', label: t('admin.roles.tab_roles') },
		{ id: 'effective', label: t('admin.access_preview.tab') },
		{ id: 'sod', label: t('admin.sod.tab') },
		{ id: 'reviews', label: t('admin.access_reviews.tab') },
		// JIT activation surface (toggle + org defaults) is roles.manage-gated.
		...(canManageRoles ? [{ id: 'jit', label: t('admin.jit.tab') }] : []),
	]);

	const COLUMNS: TableColumn[] = [
		{ key: 'name', label: t('admin.roles.name') },
		{ key: 'sodClass', label: t('admin.roles.sod_class') },
		{ key: 'permissions', label: t('admin.roles.permissions') },
		{ key: 'members', label: t('admin.roles.members') },
		{ key: 'actions', label: '' }
	];

	let filtered = $derived(
		roles.filter((r) => {
			const q = search.toLowerCase();
			return !q || r.name.toLowerCase().includes(q) || r.permissions.some((p) => p.includes(q));
		})
	);

	let compareResult = $derived(
		compareA && compareB ? diffPerms(compareA.permissions, compareB.permissions) : null
	);

	onMount(async () => {
		const sp = $page.url.searchParams;
		if (sp.get('tab') === 'effective') {
			activeTab = 'effective';
			const u = sp.get('user');
			if (u && Number.isFinite(Number(u))) previewUserId = Number(u);
		} else if (sp.get('tab') === 'reviews') {
			activeTab = 'reviews';
			const c = sp.get('campaign');
			if (c && Number.isFinite(Number(c))) reviewCampaignId = Number(c);
		}
		// ponytail: audit policy failure is non-fatal
		void getAuditPolicy().then((p) => {
			rolesReasonRequired = p.reasonRequiredAreas.includes('roles');
		}).catch(() => { /* non-fatal: default = no prompt */ });
		await Promise.all([loadRoles(), loadDomains(), loadCatalog()]);
	});

	async function loadCatalog() {
		try {
			const entries = await adminPermissionCatalog();
			catalog = new Map(entries.map((e) => [e.key, e.category]));
		} catch {
			/* catalog is optional — categories degrade gracefully */
		}
	}

	async function loadRoles() {
		loading = true;
		error = '';
		try {
			roles = await adminListRoles();
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	async function loadDomains() {
		try {
			const list = await adminDomainList();
			domains = list.map((d) => ({ id: d.id, name: d.name }));
		} catch {
			/* domains optional for global roles */
		}
	}

	function openCreate() {
		editorMode = 'create';
		editorRole = null;
		editorOpen = true;
	}

	function openEdit(r: AdminRole) {
		editorMode = 'edit';
		editorRole = r;
		editorOpen = true;
	}

	function openClone(r: AdminRole) {
		editorMode = 'clone';
		editorRole = r;
		editorOpen = true;
	}

	function del(r: AdminRole) {
		if (r.isBuiltin) return;
		deleteTarget = r;
	}

	async function doDelete(reason?: string) {
		if (!deleteTarget) return;
		try {
			await adminDeleteRole(deleteTarget.id, reason);
			showToast(t('admin.roles.deleted'));
			deleteTarget = null;
			await loadRoles();
		} catch (e) {
			error = parseError(e).message;
		}
	}

	function handleDelete(reason?: string) {
		void doDelete(rolesReasonRequired ? (reason ?? '') || undefined : undefined);
	}
</script>

<div class="sj-admin-page">
	<header class="sj-admin-head">
		<h1>{t('admin.roles.title')}</h1>
		{#if hasPermission($adminPermissions, 'roles.manage')}
			<Button variant="primary" onclick={openCreate}>{t('admin.roles.create')}</Button>
		{/if}
	</header>

	<Tabs items={TABS} active={activeTab} onChange={(id: string) => (activeTab = id)} />

	{#if error}<div class="sj-alert-danger" role="alert">{error}</div>{/if}

	{#if activeTab === 'roles'}
		<input
			class="sj-search"
			type="search"
			placeholder={t('admin.roles.search')}
			bind:value={search}
		/>
		<Card flush={true}>
			{#if loading}
				<EmptyState title={t('common.loading')} />
			{:else if filtered.length === 0}
				<EmptyState title={t('admin.roles.none')} />
			{:else}
				{@const rows = filtered as unknown as Record<string, unknown>[]}
				<Table columns={COLUMNS} {rows}>
					{#snippet cell(row, col)}
						{@const r = row as unknown as AdminRole}
						{#if col.key === 'name'}
							<strong>{r.name}</strong>
							{#if r.isBuiltin}
								<Badge variant="neutral" label={t('admin.roles.builtin')} />
							{/if}
							<div class="sj-muted">{r.description}</div>
						{:else if col.key === 'sodClass'}
							<RoleClassBadge sodClass={r.sodClass} />
						{:else if col.key === 'permissions'}
							{@const cats = [...new Set(r.permissions.map((p) => catalog.get(p)).filter((c): c is string => c != null))]}
							{@const shown = cats.slice(0, 5)}
							{@const extra = cats.length - shown.length}
							<span class="sj-cat-chips">
								{#each shown as cat}
									<Badge variant="neutral" label={cat} />
								{/each}
								{#if extra > 0}
									<span class="sj-muted">+{extra}</span>
								{/if}
								{#if r.permissions.length > 0}
									<span class="sj-perm-count sj-muted">({r.permissions.length})</span>
								{/if}
							</span>
						{:else if col.key === 'members'}
							{r.memberCount}
						{:else if col.key === 'actions'}
							<Button variant="ghost" size="sm" onclick={() => (detailRole = r)}
								>{t('admin.roles.members')}</Button
							>
							{#if hasPermission($adminPermissions, 'roles.manage')}
								<Button variant="ghost" size="sm" onclick={() => openClone(r)}
									>{t('admin.roles.clone')}</Button
								>
							{/if}
							{#if !r.isBuiltin && hasPermission($adminPermissions, 'roles.manage')}
								<Button variant="ghost" size="sm" onclick={() => openEdit(r)}
									>{t('common.edit')}</Button
								>
								<Button variant="ghost" size="sm" onclick={() => del(r)}
									>{t('common.delete')}</Button
								>
							{/if}
							<Button
								variant={compareA?.id === r.id ? 'primary' : 'ghost'}
								size="sm"
								aria-label={t('admin.roles.pin_compare_a', { name: r.name })}
								onclick={() => {
									if (compareA?.id === r.id) { compareA = null; return; }
									if (compareB?.id === r.id) { compareB = compareA; }
									compareA = r;
								}}>A</Button
							>
							<Button
								variant={compareB?.id === r.id ? 'primary' : 'ghost'}
								size="sm"
								aria-label={t('admin.roles.pin_compare_b', { name: r.name })}
								onclick={() => {
									if (compareB?.id === r.id) { compareB = null; return; }
									if (compareA?.id === r.id) { compareA = compareB; }
									compareB = r;
								}}>B</Button
							>
						{/if}
					{/snippet}
				</Table>
			{/if}
		</Card>

		{#if compareResult}
			<Card>
				<h3>{t('admin.roles.compare')}: {compareA?.name} ↔ {compareB?.name}</h3>
				<p class="sj-added">+ {compareResult.added.join(', ') || '—'}</p>
				<p class="sj-removed">− {compareResult.removed.join(', ') || '—'}</p>
			</Card>
		{/if}
	{:else if activeTab === 'effective'}
		<AccessPreview userId={previewUserId} />
	{:else if activeTab === 'sod'}
		<SodEnablementPanel />
	{:else if activeTab === 'reviews'}
		<AccessReviewsPanel bind:campaignId={reviewCampaignId} />
	{:else if activeTab === 'jit'}
		<JitSettingsPanel />
	{/if}
</div>

{#if editorOpen}
	<RoleEditorDialog
		open={editorOpen}
		role={editorRole}
		mode={editorMode}
		{domains}
		onClose={() => (editorOpen = false)}
		onSaved={loadRoles}
	/>
{/if}

{#if detailRole}
	<Dialog
		open={detailRole != null}
		title={detailRole.name + ' — ' + t('admin.roles.members')}
		onClose={() => (detailRole = null)}
	>
		{#snippet children()}
			<RoleMembersPanel roleId={detailRole!.id} {domains} canEdit={hasPermission($adminPermissions, 'roles.manage')} />
		{/snippet}
		{#snippet footer()}
			<Button variant="ghost" onclick={() => (detailRole = null)}>{t('common.close')}</Button>
		{/snippet}
	</Dialog>
{/if}

{#if deleteTarget}
	<Dialog
		open={deleteTarget != null}
		title={t('admin.roles.confirm_delete_title')}
		onClose={() => (deleteTarget = null)}
	>
		{#snippet children()}
			<p>{t('admin.roles.confirm_delete_body', { name: deleteTarget!.name })}</p>
			{#if rolesReasonRequired}
				<div class="sj-assign-form" style="margin-top: var(--space-3)">
					<ReasonPrompt
						area="roles"
						onSubmit={(r) => handleDelete(r)}
						submitLabel={t('common.delete')}
					/>
				</div>
			{/if}
		{/snippet}
		{#snippet footer()}
			{#if !rolesReasonRequired}
				<Button variant="danger" onclick={() => handleDelete()} disabled={!hasPermission($adminPermissions, 'roles.manage')}>{t('common.delete')}</Button>
			{/if}
			<Button variant="ghost" onclick={() => (deleteTarget = null)}>{t('common.cancel')}</Button>
		{/snippet}
	</Dialog>
{/if}

<style>
	.sj-admin-page {
		padding: var(--space-4);
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.sj-admin-head {
		display: flex;
		justify-content: space-between;
		align-items: center;
	}
	.sj-search {
		padding: var(--space-2);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-primary);
		background: var(--surface-input);
	}
	.sj-muted {
		color: var(--color-text-muted, var(--text-tertiary));
		font-size: var(--text-sm);
	}
	.sj-assign-form {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.sj-added {
		color: var(--color-success, var(--success));
	}
	.sj-removed {
		color: var(--color-danger, var(--danger));
	}
	.sj-cat-chips {
		display: inline-flex;
		flex-wrap: wrap;
		gap: var(--space-1);
		align-items: center;
	}
	.sj-perm-count {
		white-space: nowrap;
	}
</style>
