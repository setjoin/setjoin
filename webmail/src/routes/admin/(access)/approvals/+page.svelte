<svelte:options runes={true} />

<!--
	Admin approval-policy console (Task 13 — spec §11).
	Tabbed by consumer type (RBAC/JIT · External send · Group moderation) + Audit log.
	Read gate: approvals.view or approvals.manage.
	Write gate: approvals.manage (Add policy / Edit / Delete / Reorder).
	All queries run inside RunUserScoped on the backend (FORCE RLS on approval_policies).
-->

<script lang="ts">
	import { onMount } from 'svelte';
	import { adminPermissions, hasPermission } from '$lib/stores/auth';
	import { Card, Button, Spinner, Tabs, showToast } from '$lib/components/ui';
	import type { TabItem } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import PolicyEditor from './PolicyEditor.svelte';
	import {
		adminListApprovalPolicies,
		adminCreateApprovalPolicy,
		adminUpdateApprovalPolicy,
		adminDeleteApprovalPolicy,
		adminReorderApprovalPolicies,
		adminListApprovalAudit,
		type ApprovalPolicy,
		type ApprovalConsumerType,
		type ApprovalRequestAuditRow,
	} from '$lib/admin/client';
	import { parseError } from '$lib/errors';
	import { t } from '$lib/i18n';

	type TabId = 'rbac' | 'external_send' | 'group_mod' | 'hr_leave' | 'hr_expense' | 'audit';

	const TABS: TabItem[] = [
		{ id: 'rbac', label: t('admin.approvals.tab.rbac') },
		{ id: 'external_send', label: t('admin.approvals.tab.external_send') },
		{ id: 'group_mod', label: t('admin.approvals.tab.group_mod') },
		{ id: 'hr_leave', label: t('admin.approvals.tab.hr_leave') },
		{ id: 'hr_expense', label: t('admin.approvals.tab.hr_expense') },
		{ id: 'audit', label: t('admin.approvals.tab.audit') },
	];

	const CONSUMER_FOR_TAB: Record<string, ApprovalConsumerType> = {
		rbac: 'rbac.jit_activation',
		external_send: 'mail.external_send',
		group_mod: 'mail.group_moderation',
		hr_leave: 'hr.leave',
		hr_expense: 'hr.expense',
	};

	let activeTab = $state<TabId>('rbac');
	let policies = $state<ApprovalPolicy[]>([]);
	let auditRows = $state<ApprovalRequestAuditRow[]>([]);
	let auditOffset = $state(0);
	let auditHasMore = $state(true);
	let loading = $state(false);
	let auditLoading = $state(false);
	let error = $state('');

	let editorOpen = $state(false);
	let editTarget = $state<ApprovalPolicy | null>(null);

	let deleteTarget = $state<ApprovalPolicy | null>(null);
	let deleting = $state(false);

	// aria-live announcement for keyboard reorder
	let announcement = $state('');

	let canManage = $derived(hasPermission($adminPermissions, 'approvals.manage'));

	onMount(() => loadTab(activeTab));

	async function loadTab(tab: TabId) {
		if (tab === 'audit') {
			await loadAudit(0);
			return;
		}
		loading = true;
		error = '';
		try {
			policies = await adminListApprovalPolicies(CONSUMER_FOR_TAB[tab]);
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	async function loadAudit(offset: number) {
		auditLoading = true;
		try {
			const rows = await adminListApprovalAudit(50, offset);
			if (offset === 0) {
				auditRows = rows;
			} else {
				auditRows = [...auditRows, ...rows];
			}
			auditOffset = offset + rows.length;
			auditHasMore = rows.length === 50;
		} catch (e) {
			error = parseError(e).message;
		} finally {
			auditLoading = false;
		}
	}

	function changeTab(id: string) {
		activeTab = id as TabId;
		error = '';
		loadTab(activeTab);
	}

	// ── drag-to-reorder (native HTML5) ───────────────────────────────────────

	let dragSrcIdx = $state<number | null>(null);

	function onDragStart(idx: number) {
		dragSrcIdx = idx;
	}

	function onDragOver(e: DragEvent, idx: number) {
		e.preventDefault();
		if (dragSrcIdx === null || dragSrcIdx === idx) return;
		const reordered = [...policies];
		const [moved] = reordered.splice(dragSrcIdx, 1);
		reordered.splice(idx, 0, moved);
		policies = reordered;
		dragSrcIdx = idx;
	}

	async function onDrop() {
		dragSrcIdx = null;
		await commitReorder();
	}

	// ── keyboard move-up / move-down ─────────────────────────────────────────

	async function movePolicy(idx: number, dir: -1 | 1) {
		const next = idx + dir;
		if (next < 0 || next >= policies.length) return;
		const reordered = [...policies];
		[reordered[idx], reordered[next]] = [reordered[next], reordered[idx]];
		policies = reordered;
		announcement = t('admin.approvals.order_announce')
			.replace('{pos}', String(next + 1))
			.replace('{total}', String(policies.length));
		await commitReorder();
	}

	async function commitReorder() {
		if (!canManage) return;
		const ct = CONSUMER_FOR_TAB[activeTab];
		if (!ct) return;
		try {
			await adminReorderApprovalPolicies(ct, policies.map((p) => p.id));
		} catch (e) {
			error = parseError(e).message;
		}
	}

	// ── create / edit ─────────────────────────────────────────────────────────

	function openCreate() {
		editTarget = null;
		editorOpen = true;
	}

	function openEdit(p: ApprovalPolicy) {
		editTarget = p;
		editorOpen = true;
	}

	async function handleSave(data: Omit<ApprovalPolicy, 'id' | 'createdAt' | 'updatedAt'>) {
		try {
			if (editTarget) {
				await adminUpdateApprovalPolicy(editTarget.id, data);
			} else {
				await adminCreateApprovalPolicy(data);
			}
			editorOpen = false;
			showToast(t('admin.approvals.saved'));
			await loadTab(activeTab);
		} catch (e) {
			error = parseError(e).message;
		}
	}

	// ── delete ────────────────────────────────────────────────────────────────

	function confirmDelete(p: ApprovalPolicy) {
		deleteTarget = p;
	}

	async function doDelete() {
		if (!deleteTarget) return;
		deleting = true;
		try {
			await adminDeleteApprovalPolicy(deleteTarget.id);
			showToast(t('admin.approvals.deleted'));
			deleteTarget = null;
			await loadTab(activeTab);
		} catch (e) {
			error = parseError(e).message;
		} finally {
			deleting = false;
		}
	}

	// ── approver spec summary label ───────────────────────────────────────────

	function approverLabel(p: ApprovalPolicy): string {
		const spec = p.approverSpec as unknown as { kind: string };
		return t(`admin.approvals.spec.${spec?.kind ?? 'default_admin'}`);
	}
</script>

<svelte:head><title>{t('admin.approvals.title')} · setjoin</title></svelte:head>

<div class="ap-page">
	<div class="ap-header">
		<div>
			<h1 class="ap-title">{t('admin.approvals.title')}</h1>
			<p class="ap-subtitle">{t('admin.approvals.subtitle')}</p>
		</div>
		{#if canManage && activeTab !== 'audit'}
			<Button variant="primary" onclick={openCreate}>
				<Icon name="Plus" size={16} />
				{t('admin.approvals.add_policy')}
			</Button>
		{/if}
	</div>

	<Tabs items={TABS} active={activeTab} onChange={changeTab} />

	<!-- aria-live region for keyboard reorder announcements -->
	<div aria-live="polite" aria-atomic="true" class="ap-sr-only">{announcement}</div>

	{#if error}
		<p class="ap-error" role="alert">{error}</p>
	{/if}

	{#if activeTab !== 'audit'}
		<!-- Policy list tab content -->
		{#if loading}
			<div class="ap-loading"><Spinner /></div>
		{:else if policies.length === 0}
			<Card>
				<div class="ap-empty">
					<p class="ap-empty__title">{t('admin.approvals.empty_title')}</p>
					<p class="ap-empty__body">{t('admin.approvals.empty_body')}</p>
					{#if canManage}
						<Button variant="primary" onclick={openCreate}>{t('admin.approvals.add_policy')}</Button>
					{/if}
				</div>
			</Card>
		{:else}
			<p class="ap-hint">{t('admin.approvals.precedence_hint')}</p>
			<Card flush>
				<table class="ap-table">
					<thead>
						<tr>
							<th>{t('admin.approvals.col_name')}</th>
							<th>{t('admin.approvals.col_requires')}</th>
							<th>{t('admin.approvals.col_approver')}</th>
							<th>{t('admin.approvals.col_enabled')}</th>
							<th class="ap-th-actions">{t('admin.approvals.col_actions')}</th>
						</tr>
					</thead>
					<tbody>
						{#each policies as policy, idx (policy.id)}
							<tr
								class="ap-row"
								draggable={canManage}
								ondragstart={() => onDragStart(idx)}
								ondragover={(e) => onDragOver(e, idx)}
								ondrop={onDrop}
							>
								<td class="ap-td-name">
									{#if canManage}
										<span class="ap-drag-handle" aria-hidden="true">⠿</span>
									{/if}
									<span>{policy.name}</span>
								</td>
								<td>
									{#if policy.requiresApproval}
										<span class="ap-badge ap-badge--yes">{t('admin.approvals.val_yes')}</span>
									{:else}
										<span class="ap-badge ap-badge--no">{t('admin.approvals.val_no')}</span>
									{/if}
								</td>
								<td>{approverLabel(policy)}</td>
								<td>
									{#if policy.enabled}
										<span class="ap-badge ap-badge--yes">{t('admin.approvals.col_enabled')}</span>
									{:else}
										<span class="ap-badge ap-badge--no">—</span>
									{/if}
								</td>
								<td class="ap-td-actions">
									{#if canManage}
										<button
											type="button"
											class="ap-icon-btn"
											aria-label={t('admin.approvals.move_up')}
											disabled={idx === 0}
											onclick={() => movePolicy(idx, -1)}
										>
											<Icon name="ChevronUp" size={16} />
										</button>
										<button
											type="button"
											class="ap-icon-btn"
											aria-label={t('admin.approvals.move_down')}
											disabled={idx === policies.length - 1}
											onclick={() => movePolicy(idx, 1)}
										>
											<Icon name="ChevronDown" size={16} />
										</button>
										<button
											type="button"
											class="ap-icon-btn"
											aria-label={t('admin.approvals.edit')}
											onclick={() => openEdit(policy)}
										>
											<Icon name="Pencil" size={16} />
										</button>
										<button
											type="button"
											class="ap-icon-btn ap-icon-btn--danger"
											aria-label={t('admin.approvals.delete')}
											onclick={() => confirmDelete(policy)}
										>
											<Icon name="Trash2" size={16} />
										</button>
									{/if}
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</Card>
		{/if}
	{:else}
		<!-- Audit log tab content -->
		<h2 class="ap-audit-title">{t('admin.approvals.audit.title')}</h2>
		{#if auditLoading && auditRows.length === 0}
			<div class="ap-loading"><Spinner /> {t('admin.approvals.audit.loading')}</div>
		{:else if auditRows.length === 0}
			<Card><p class="ap-audit-empty">{t('admin.approvals.audit.empty')}</p></Card>
		{:else}
			<Card flush>
				<table class="ap-table">
					<thead>
						<tr>
							<th>{t('admin.approvals.audit.col_subject')}</th>
							<th>{t('admin.approvals.audit.col_consumer')}</th>
							<th>{t('admin.approvals.audit.col_status')}</th>
							<th>{t('admin.approvals.audit.col_requested')}</th>
							<th>{t('admin.approvals.audit.col_decided')}</th>
						</tr>
					</thead>
					<tbody>
						{#each auditRows as row (row.id)}
							<tr class="ap-row">
								<td>{row.subject}</td>
								<td class="ap-mono">{row.consumerType}</td>
								<td><span class="ap-badge ap-badge--status">{row.status}</span></td>
								<td class="ap-mono">{row.createdAt.slice(0, 16)}</td>
								<td class="ap-mono">{row.decidedAt ? row.decidedAt.slice(0, 16) : '—'}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</Card>
			{#if auditHasMore}
				<div class="ap-load-more">
					<Button variant="ghost" onclick={() => loadAudit(auditOffset)} disabled={auditLoading}>
						{#if auditLoading}<Spinner />{/if}
						{t('admin.approvals.audit.load_more')}
					</Button>
				</div>
			{/if}
		{/if}
	{/if}
</div>

<!-- PolicyEditor dialog -->
<PolicyEditor
	open={editorOpen}
	policy={editTarget}
	consumerType={CONSUMER_FOR_TAB[activeTab] ?? 'rbac.jit_activation'}
	onsave={handleSave}
	oncancel={() => (editorOpen = false)}
/>

<!-- Inline delete confirmation — Escape closes, confirm button gets initial focus -->
{#if deleteTarget}
	<div
		class="ap-confirm-overlay"
		role="dialog"
		aria-modal="true"
		aria-label="Confirm delete"
		tabindex="-1"
		onkeydown={(e) => { if (e.key === 'Escape' && !deleting) deleteTarget = null; }}
	>
		<Card>
			<p class="ap-confirm-msg">
				{t('admin.approvals.delete_confirm').replace('{name}', deleteTarget.name)}
			</p>
			<div class="ap-confirm-actions">
				<Button variant="ghost" onclick={() => (deleteTarget = null)} disabled={deleting}>
					{t('admin.approvals.editor.cancel')}
				</Button>
				<Button variant="danger" onclick={doDelete} disabled={deleting} autofocus>
					{#if deleting}<Spinner />{/if}
					{t('admin.approvals.delete')}
				</Button>
			</div>
		</Card>
	</div>
{/if}

<style>
	.ap-page {
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
		padding: var(--space-6);
		max-width: 900px;
	}
	.ap-header {
		display: flex;
		align-items: flex-start;
		justify-content: space-between;
		gap: var(--space-4);
	}
	.ap-title {
		font-size: var(--text-xl);
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
		margin: 0;
	}
	.ap-subtitle {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: var(--space-1) 0 0;
	}
	.ap-hint {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		margin: 0;
	}
	.ap-error {
		font-size: var(--text-sm);
		color: var(--text-danger);
	}
	.ap-loading {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-6);
		color: var(--text-secondary);
		font-size: var(--text-sm);
	}
	.ap-empty {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: var(--space-3);
		padding: var(--space-8);
		text-align: center;
	}
	.ap-empty__title {
		font-size: var(--text-base);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
		margin: 0;
	}
	.ap-empty__body {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0;
	}
	.ap-table {
		width: 100%;
		border-collapse: collapse;
		font-size: var(--text-sm);
	}
	.ap-table th {
		text-align: left;
		padding: var(--space-2) var(--space-3);
		font-weight: var(--weight-medium);
		color: var(--text-secondary);
		border-bottom: 1px solid var(--border-default);
		white-space: nowrap;
	}
	.ap-th-actions {
		width: 140px;
	}
	.ap-row td {
		padding: var(--space-3);
		border-bottom: 1px solid var(--border-subtle);
		vertical-align: middle;
	}
	.ap-row:last-child td {
		border-bottom: none;
	}
	.ap-td-name {
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}
	.ap-drag-handle {
		cursor: grab;
		color: var(--text-tertiary);
		font-size: var(--text-base);
		line-height: 1;
		user-select: none;
	}
	.ap-td-actions {
		display: flex;
		align-items: center;
		gap: 4px;
	}
	.ap-icon-btn {
		display: flex;
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
	.ap-icon-btn:hover:not(:disabled) {
		background: var(--surface-hover);
		color: var(--text-primary);
	}
	.ap-icon-btn:disabled {
		opacity: 0.35;
		cursor: default;
	}
	.ap-icon-btn--danger:hover:not(:disabled) {
		background: var(--red-50);
		color: var(--text-danger);
	}
	.ap-badge {
		display: inline-flex;
		align-items: center;
		padding: 2px 8px;
		border-radius: var(--radius-full);
		font-size: var(--text-xs);
		font-weight: var(--weight-medium);
	}
	.ap-badge--yes {
		background: var(--green-50);
		color: var(--green-700);
	}
	.ap-badge--no {
		background: var(--gray-100);
		color: var(--text-tertiary);
	}
	.ap-badge--status {
		background: var(--surface-subtle);
		color: var(--text-secondary);
		font-family: var(--font-mono);
	}
	.ap-mono {
		font-family: var(--font-mono);
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}
	.ap-audit-title {
		font-size: var(--text-lg);
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
		margin: 0;
	}
	.ap-audit-empty {
		padding: var(--space-6);
		text-align: center;
		font-size: var(--text-sm);
		color: var(--text-tertiary);
	}
	.ap-load-more {
		display: flex;
		justify-content: center;
		padding-top: var(--space-2);
	}
	.ap-sr-only {
		position: absolute;
		width: 1px;
		height: 1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
	}
	.ap-confirm-overlay {
		position: fixed;
		inset: 0;
		background: rgb(0, 0, 0, 0.4);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 50;
	}
	.ap-confirm-msg {
		font-size: var(--text-sm);
		color: var(--text-primary);
		margin: 0 0 var(--space-4);
	}
	.ap-confirm-actions {
		display: flex;
		justify-content: flex-end;
		gap: var(--space-2);
	}
</style>
