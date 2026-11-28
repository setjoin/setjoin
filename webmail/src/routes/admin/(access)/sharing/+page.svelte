<svelte:options runes={true} />

<!--
	Admin Sharing console (spec 2026-06-27-sharing-delegation-design.md §7).
	Three tabs: Defaults (sharing_defaults CRUD, sharing.manage to write),
	Per-user oversight (search a user → effective defaults + explicit calendar
	grants + mailbox delegates; manage can set a user-scope override), and
	Audit (the four D8 sharing audit actions, filterable by user).
	Read gate: sharing.read or sharing.manage; the backend re-enforces both.
-->

<script lang="ts">
	import { onMount } from 'svelte';
	import { adminPermissions, hasPermission } from '$lib/stores/auth';
	import { Card, Button, Input, Spinner, Tabs, showToast } from '$lib/components/ui';
	import type { TabItem } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import SharingDefaultEditor from './SharingDefaultEditor.svelte';
	import {
		adminListSharingDefaults,
		adminCreateSharingDefault,
		adminDeleteSharingDefault,
		adminSharingUserOversight,
		adminListSharingAudit,
		adminUserList,
		type SharingDefaultAdminRow,
		type SharingUserOversight,
		type SharingAuditRow,
		type AdminUser
	} from '$lib/admin/client';
	import { parseError } from '$lib/errors';
	import { t } from '$lib/i18n';

	type TabId = 'defaults' | 'user' | 'audit';

	const TABS: TabItem[] = [
		{ id: 'defaults', label: t('admin.sharing.tab.defaults') },
		{ id: 'user', label: t('admin.sharing.tab.user') },
		{ id: 'audit', label: t('admin.sharing.tab.audit') }
	];

	let activeTab = $state<TabId>('defaults');
	let error = $state('');
	let canManage = $derived(hasPermission($adminPermissions, 'sharing.manage'));

	// ── Defaults tab ──
	let defaults = $state<SharingDefaultAdminRow[]>([]);
	let defaultsLoading = $state(false);
	let editorOpen = $state(false);
	let editorLockUser = $state<{ userId: number; email: string } | null>(null);

	// ── Per-user tab ──
	let userQuery = $state('');
	let userResults = $state<AdminUser[]>([]);
	let userSearching = $state(false);
	let oversight = $state<SharingUserOversight | null>(null);
	let oversightLoading = $state(false);

	// ── Audit tab ──
	let auditRows = $state<SharingAuditRow[]>([]);
	let auditLoading = $state(false);
	let auditOffset = $state(0);
	let auditHasMore = $state(true);
	let auditUserFilter = $state('');

	onMount(() => loadTab(activeTab));

	function changeTab(id: string) {
		activeTab = id as TabId;
		error = '';
		void loadTab(activeTab);
	}

	async function loadTab(tab: TabId) {
		if (tab === 'defaults') await loadDefaults();
		else if (tab === 'audit') await loadAudit(0);
	}

	async function loadDefaults() {
		defaultsLoading = true;
		try {
			defaults = await adminListSharingDefaults();
		} catch (e) {
			error = parseError(e).message;
		} finally {
			defaultsLoading = false;
		}
	}

	function openCreate(lock: { userId: number; email: string } | null = null) {
		editorLockUser = lock;
		editorOpen = true;
	}

	async function handleSubmit(data: {
		ownerScope: SharingDefaultAdminRow['ownerScope'];
		ownerRef: number;
		audience: SharingDefaultAdminRow['audience'];
		audienceRef: number;
		level: SharingDefaultAdminRow['level'];
	}) {
		// Thrown errors render inside the editor dialog (role=alert).
		await adminCreateSharingDefault(data);
		editorOpen = false;
		showToast(t('admin.sharing.saved'));
		await loadDefaults();
		if (oversight) await selectUser(oversight.userId, oversight.email);
	}

	async function deleteDefault(id: number) {
		try {
			await adminDeleteSharingDefault(id);
			showToast(t('admin.sharing.deleted'));
			await loadDefaults();
			if (oversight) await selectUser(oversight.userId, oversight.email);
		} catch (e) {
			error = parseError(e).message;
		}
	}

	async function searchUsers() {
		const q = userQuery.trim();
		if (!q) return;
		userSearching = true;
		error = '';
		try {
			userResults = await adminUserList(q, 10, 0);
		} catch (e) {
			error = parseError(e).message;
		} finally {
			userSearching = false;
		}
	}

	async function selectUser(id: number, _email: string) {
		oversightLoading = true;
		error = '';
		try {
			oversight = await adminSharingUserOversight(id);
		} catch (e) {
			oversight = null;
			error = parseError(e).message;
		} finally {
			oversightLoading = false;
		}
	}

	async function loadAudit(offset: number) {
		auditLoading = true;
		try {
			let uid: number | undefined;
			const filter = auditUserFilter.trim();
			if (filter) {
				const users = await adminUserList(filter, 1, 0);
				uid = users[0]?.id;
				if (!uid) {
					auditRows = [];
					auditHasMore = false;
					return;
				}
			}
			const rows = await adminListSharingAudit(50, offset, uid);
			auditRows = offset === 0 ? rows : [...auditRows, ...rows];
			auditOffset = offset + rows.length;
			auditHasMore = rows.length === 50;
		} catch (e) {
			error = parseError(e).message;
		} finally {
			auditLoading = false;
		}
	}

	function scopeLabel(row: SharingDefaultAdminRow): string {
		const scope = t(`admin.sharing.scope.${row.ownerScope}`);
		return row.ownerLabel ? `${scope} — ${row.ownerLabel}` : scope;
	}

	function audienceLabel(row: SharingDefaultAdminRow): string {
		const aud = t(`admin.sharing.audience.${row.audience}`);
		return row.audienceLabel ? `${aud} — ${row.audienceLabel}` : aud;
	}
</script>

<svelte:head><title>{t('admin.sharing.title')} · setjoin</title></svelte:head>

<div class="shc-page">
	<div class="shc-header">
		<div>
			<h1 class="shc-title">{t('admin.sharing.title')}</h1>
			<p class="shc-subtitle">{t('admin.sharing.subtitle')}</p>
		</div>
		{#if canManage && activeTab === 'defaults'}
			<Button variant="primary" onclick={() => openCreate()}>
				<Icon name="Plus" size={16} />
				{t('admin.sharing.add_default')}
			</Button>
		{/if}
	</div>

	<Tabs items={TABS} active={activeTab} onChange={changeTab} />

	{#if error}
		<p class="shc-error" role="alert">{error}</p>
	{/if}

	{#if activeTab === 'defaults'}
		{#if defaultsLoading}
			<div class="shc-loading"><Spinner /></div>
		{:else if defaults.length === 0}
			<Card>
				<div class="shc-empty">
					<p class="shc-empty__title">{t('admin.sharing.empty_title')}</p>
					<p class="shc-empty__body">{t('admin.sharing.empty_body')}</p>
					{#if canManage}
						<Button variant="primary" onclick={() => openCreate()}>{t('admin.sharing.add_default')}</Button>
					{/if}
				</div>
			</Card>
		{:else}
			<p class="shc-hint">{t('admin.sharing.precedence_hint')}</p>
			<Card flush>
				<table class="shc-table">
					<thead>
						<tr>
							<th>{t('admin.sharing.col_scope')}</th>
							<th>{t('admin.sharing.col_audience')}</th>
							<th>{t('admin.sharing.col_level')}</th>
							<th>{t('admin.sharing.col_updated')}</th>
							{#if canManage}<th class="shc-th-actions">{t('admin.sharing.col_actions')}</th>{/if}
						</tr>
					</thead>
					<tbody>
						{#each defaults as row (row.id)}
							<tr class="shc-row">
								<td>{scopeLabel(row)}</td>
								<td>{audienceLabel(row)}</td>
								<td>{t(`sharing.level.${row.level}`)}</td>
								<td class="shc-mono">{row.updatedAt.slice(0, 16)}</td>
								{#if canManage}
									<td class="shc-td-actions">
										<button
											type="button"
											class="shc-icon-btn shc-icon-btn--danger"
											aria-label={t('admin.sharing.delete')}
											onclick={() => deleteDefault(row.id)}
										>
											<Icon name="Trash2" size={16} />
										</button>
									</td>
								{/if}
							</tr>
						{/each}
					</tbody>
				</table>
			</Card>
		{/if}
	{:else if activeTab === 'user'}
		<Card>
			<div class="shc-search">
				<Input
					label={t('admin.sharing.user.search_label')}
					placeholder={t('admin.sharing.user.search_placeholder')}
					bind:value={userQuery}
					onkeydown={(e: KeyboardEvent) => e.key === 'Enter' && searchUsers()}
				/>
				<Button variant="secondary" size="sm" disabled={userSearching} onclick={searchUsers}>
					{t('admin.sharing.user.search')}
				</Button>
			</div>
			{#if userResults.length > 0}
				<ul class="shc-user-results">
					{#each userResults as u (u.id)}
						<li>
							<button type="button" class="shc-user-result" onclick={() => selectUser(u.id, u.email)}>
								<span>{u.email}</span>
								<span class="shc-user-name">{u.displayName}</span>
							</button>
						</li>
					{/each}
				</ul>
			{/if}
		</Card>

		{#if oversightLoading}
			<div class="shc-loading"><Spinner /></div>
		{:else if oversight}
			<Card title={`${oversight.email} — ${oversight.displayName}`}>
				<div class="shc-oversight">
					<div class="shc-oversight__head">
						<h3 class="shc-section">{t('admin.sharing.user.defaults')}</h3>
						{#if canManage}
							<Button
								variant="secondary"
								size="sm"
								onclick={() => openCreate({ userId: oversight!.userId, email: oversight!.email })}
							>
								{t('admin.sharing.user.set_default')}
							</Button>
						{/if}
					</div>
					{#if oversight.defaults.length === 0}
						<p class="shc-muted">{t('admin.sharing.user.no_defaults')}</p>
					{:else}
						<ul class="shc-list">
							{#each oversight.defaults as d (d.id)}
								<li class="shc-list-row">
									<span>{t(`admin.sharing.scope.${d.ownerScope}`)} · {t(`admin.sharing.audience.${d.audience}`)} · {t(`sharing.level.${d.level}`)}</span>
									{#if canManage && d.ownerScope === 'user'}
										<button
											type="button"
											class="shc-icon-btn shc-icon-btn--danger"
											aria-label={t('admin.sharing.delete')}
											onclick={() => deleteDefault(d.id)}
										>
											<Icon name="Trash2" size={16} />
										</button>
									{/if}
								</li>
							{/each}
						</ul>
					{/if}

					<h3 class="shc-section">{t('admin.sharing.user.grants')}</h3>
					{#if oversight.calendarGrants.length === 0}
						<p class="shc-muted">{t('admin.sharing.user.none')}</p>
					{:else}
						<ul class="shc-list">
							{#each oversight.calendarGrants as g (`${g.calendarId}-${g.userEmail}`)}
								<li class="shc-list-row"><span>{g.userEmail} · {t(`calendar.share.level.${g.level}`)} · {g.calendarName}</span></li>
							{/each}
						</ul>
					{/if}

					<h3 class="shc-section">{t('admin.sharing.user.delegates')}</h3>
					{#if oversight.delegates.length === 0}
						<p class="shc-muted">{t('admin.sharing.user.none')}</p>
					{:else}
						<ul class="shc-list">
							{#each oversight.delegates as d (`${d.userId}-${d.permission}`)}
								<li class="shc-list-row"><span>{d.email} · {t(`sharing.perm.${d.permission}`)}</span></li>
							{/each}
						</ul>
					{/if}
				</div>
			</Card>
		{/if}
	{:else}
		<Card>
			<div class="shc-search">
				<Input
					label={t('admin.sharing.audit.filter')}
					placeholder={t('admin.sharing.user.search_placeholder')}
					bind:value={auditUserFilter}
					onkeydown={(e: KeyboardEvent) => e.key === 'Enter' && loadAudit(0)}
				/>
				<Button variant="secondary" size="sm" disabled={auditLoading} onclick={() => loadAudit(0)}>
					{t('admin.sharing.audit.apply')}
				</Button>
			</div>
		</Card>
		{#if auditLoading && auditRows.length === 0}
			<div class="shc-loading"><Spinner /></div>
		{:else if auditRows.length === 0}
			<Card><p class="shc-muted shc-audit-empty">{t('admin.sharing.audit.empty')}</p></Card>
		{:else}
			<Card flush>
				<table class="shc-table">
					<thead>
						<tr>
							<th>{t('admin.sharing.audit.col_when')}</th>
							<th>{t('admin.sharing.audit.col_actor')}</th>
							<th>{t('admin.sharing.audit.col_action')}</th>
							<th>{t('admin.sharing.audit.col_target')}</th>
						</tr>
					</thead>
					<tbody>
						{#each auditRows as row (row.id)}
							<tr class="shc-row">
								<td class="shc-mono">{row.occurredAt.slice(0, 16)}</td>
								<td>{row.userEmail}</td>
								<td class="shc-mono">{row.action}</td>
								<td class="shc-mono">{row.targetType ?? ''} {row.targetId ?? ''}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</Card>
			{#if auditHasMore}
				<div class="shc-load-more">
					<Button variant="ghost" onclick={() => loadAudit(auditOffset)} disabled={auditLoading}>
						{#if auditLoading}<Spinner />{/if}
						{t('admin.sharing.audit.load_more')}
					</Button>
				</div>
			{/if}
		{/if}
	{/if}
</div>

<SharingDefaultEditor
	open={editorOpen}
	lockUser={editorLockUser}
	onSubmit={handleSubmit}
	oncancel={() => (editorOpen = false)}
/>

<style>
	.shc-page {
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
		padding: var(--space-6);
		max-width: 900px;
	}
	.shc-header {
		display: flex;
		align-items: flex-start;
		justify-content: space-between;
		gap: var(--space-4);
	}
	.shc-title {
		font-size: var(--text-xl);
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
		margin: 0;
	}
	.shc-subtitle {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: var(--space-1) 0 0;
	}
	.shc-hint {
		font-size: var(--text-sm);
		color: var(--text-caption);
		margin: 0;
	}
	.shc-error {
		font-size: var(--text-sm);
		color: var(--danger-fg);
	}
	.shc-loading {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-6);
		color: var(--text-secondary);
		font-size: var(--text-sm);
	}
	.shc-empty {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: var(--space-3);
		padding: var(--space-8);
		text-align: center;
	}
	.shc-empty__title {
		font-size: var(--text-base);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
		margin: 0;
	}
	.shc-empty__body {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0;
	}
	.shc-table {
		width: 100%;
		border-collapse: collapse;
		font-size: var(--text-sm);
	}
	.shc-table th {
		text-align: left;
		padding: var(--space-2) var(--space-3);
		font-weight: var(--weight-medium);
		color: var(--text-secondary);
		border-bottom: 1px solid var(--border-default);
		white-space: nowrap;
	}
	.shc-th-actions {
		width: 60px;
	}
	.shc-row td {
		padding: var(--space-3);
		border-bottom: 1px solid var(--border-subtle);
		vertical-align: middle;
	}
	.shc-row:last-child td {
		border-bottom: none;
	}
	.shc-td-actions {
		text-align: right;
	}
	.shc-icon-btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-width: 44px;
		min-height: 44px;
		border: none;
		background: transparent;
		border-radius: var(--radius-md);
		cursor: pointer;
		color: var(--text-secondary);
	}
	.shc-icon-btn:hover {
		background: var(--surface-hover);
		color: var(--text-primary);
	}
	.shc-icon-btn--danger:hover {
		background: var(--danger-bg);
		color: var(--danger-fg);
	}
	.shc-mono {
		font-family: var(--font-mono);
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}
	.shc-search {
		display: flex;
		gap: var(--space-2);
		align-items: flex-end;
	}
	.shc-user-results {
		list-style: none;
		margin: var(--space-2) 0 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.shc-user-result {
		display: flex;
		justify-content: space-between;
		width: 100%;
		min-height: 44px;
		align-items: center;
		padding: var(--space-2) var(--space-3);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		background: transparent;
		cursor: pointer;
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	.shc-user-result:hover {
		background: var(--surface-hover);
	}
	.shc-user-name {
		color: var(--text-caption);
	}
	.shc-oversight {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.shc-oversight__head {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-2);
	}
	.shc-section {
		margin: 0;
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-secondary);
	}
	.shc-muted {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-caption);
	}
	.shc-list {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.shc-list-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: var(--space-2) var(--space-3);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	.shc-audit-empty {
		padding: var(--space-6);
		text-align: center;
	}
	.shc-load-more {
		display: flex;
		justify-content: center;
		padding-top: var(--space-2);
	}
</style>
