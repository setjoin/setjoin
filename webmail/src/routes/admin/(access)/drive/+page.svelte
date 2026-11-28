<svelte:options runes={true} />

<script lang="ts">
	import { adminPermissions, hasPermission } from '$lib/stores/auth';
	import * as api from '$lib/drive/api';
	import { type DriveSpace, type DriveLockRow } from '$lib/drive/api';
	import { formatDateTime } from '$lib/i18n';
	import { Card, Table, Button, Badge, EmptyState, Spinner, Dialog, Tabs } from '$lib/components/ui';
	import type { TableColumn, TabItem } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import CompliancePanel from '$lib/components/admin/drive/CompliancePanel.svelte';
	import AdminTrashPanel from '$lib/components/admin/drive/AdminTrashPanel.svelte';
	import AdminAuditPanel from '$lib/components/admin/drive/AdminAuditPanel.svelte';
	import { t } from '$lib/i18n';
	import { driveErrorMessage } from '$lib/drive/errors';

	// P6 Task 15/16: a per-space tab strip below the space table — Locks &
	// compliance (P4/P5, unchanged) / Trash (admin tier-2 bin) / Audit.
	let activeTab = $state<'locks' | 'trash' | 'audit'>('locks');
	const TABS: TabItem[] = [
		{ id: 'locks', label: t('drive.admin.tabs.locks') },
		{ id: 'trash', label: t('drive.trash.adminBin') },
		{ id: 'audit', label: t('drive.audit.title') },
	];

	// P4 Task 15: the minimal drive.view-gated admin shell — P1 shipped no
	// admin drive page (Task 0 finding). P5 Task 10 adds the compliance panel
	// + the wormPending column below.
	let canView = $derived(hasPermission($adminPermissions, 'drive.view'));
	let canManage = $derived(hasPermission($adminPermissions, 'drive.manage'));

	let spaces = $state<DriveSpace[]>([]);
	let spaceId = $state<number | null>(null);
	let selectedSpace = $derived(spaces.find((s) => s.id === spaceId) ?? null);
	let locks = $state<DriveLockRow[]>([]);
	let loading = $state(false);
	let error = $state('');
	let breakTarget = $state<DriveLockRow | null>(null);

	// listSpacesAdmin (?admin=1, drive.view-gated cross-tenant read) — every
	// space in the org, not just ones this admin happens to be a member of
	// (the previous listSpaces() call silently missed non-member spaces; this
	// was the ponytail gap flagged here before P5, now closed since the
	// compliance table needs every gxp space regardless of membership).
	async function loadSpaces() {
		try {
			spaces = await api.listSpacesAdmin();
			if (spaces.length > 0 && spaceId === null) {
				spaceId = spaces[0].id;
				await loadLocks();
			}
		} catch (e) {
			error = driveErrorMessage(e);
		}
	}

	async function loadLocks() {
		if (spaceId === null) return;
		loading = true;
		try {
			const res = await api.listLocks(spaceId);
			locks = res.locks;
			error = '';
		} catch (e) {
			error = driveErrorMessage(e);
		} finally {
			loading = false;
		}
	}

	function selectSpace(id: number) {
		spaceId = id;
		void loadLocks();
	}

	async function confirmBreak() {
		if (!breakTarget) return;
		const nodeId = breakTarget.nodeId;
		breakTarget = null;
		try {
			await api.unlockFile(nodeId, { break: true });
			await loadLocks();
		} catch (e) {
			error = driveErrorMessage(e);
		}
	}

	// $effect (not onMount): canView resolves from the session's admin
	// permission list, which can still be loading at first mount — this must
	// re-fire once it flips true, not just check it a single time at mount.
	$effect(() => {
		if (canView) void loadSpaces();
	});

	const COLUMNS: TableColumn[] = [
		{ key: 'file', label: t('drive.admin.lockList.file') },
		{ key: 'holder', label: t('drive.admin.lockList.holder') },
		{ key: 'mode', label: t('drive.admin.lockList.mode') },
		{ key: 'since', label: t('drive.admin.lockList.since') },
		{ key: 'expires', label: t('drive.admin.lockList.expires') },
		{ key: 'actions', label: '' },
	];

	const SPACE_COLUMNS: TableColumn[] = [
		{ key: 'name', label: t('drive.compliance.spacesTable.name') },
		{ key: 'classification', label: t('drive.compliance.spacesTable.classification') },
		{ key: 'wormPending', label: t('drive.compliance.spacesTable.wormPending') },
		{ key: 'manage', label: '' },
	];

	// Classification is conveyed by an icon AND text together — never color
	// alone (a11y — mirrors SpaceList.svelte's convention). 'regular' shows no icon.
	function classificationIcon(c: DriveSpace['classification']) {
		return c === 'gxp' ? 'ShieldCheck' : c === 'secure' ? 'Lock' : null;
	}
</script>

{#if !canView}
	<EmptyState title={t('drive.errors.BZ140')} />
{:else}
	<div class="drive-admin">
		<h1 class="drive-admin__title">{t('app.drive')}</h1>

		{#if error}
			<p class="drive-admin__error" role="alert">{error}</p>
		{/if}

		<Card flush={true}>
			{#if spaces.length === 0}
				<EmptyState title={t('drive.compliance.spacesTable.empty')} />
			{:else}
				{@const spaceRows = spaces as unknown as Record<string, unknown>[]}
				<Table columns={SPACE_COLUMNS} rows={spaceRows}>
					{#snippet cell(row, col)}
						{@const sp = row as unknown as DriveSpace}
						{#if col.key === 'name'}
							{sp.name}
						{:else if col.key === 'classification'}
							{#if classificationIcon(sp.classification)}
								<span class="drive-admin__badge">
									<Icon name={classificationIcon(sp.classification) as 'ShieldCheck' | 'Lock'} size={12} />
									{t(`drive.space.classification.${sp.classification}`)}
								</span>
							{:else}
								{t('drive.space.classification.regular')}
							{/if}
						{:else if col.key === 'wormPending'}
							{#if (sp.wormPending ?? 0) > 0}
								<Badge variant="warning" label={String(sp.wormPending)} />
							{:else}
								<Badge variant="success" label="0" />
							{/if}
						{:else if col.key === 'manage'}
							<Button variant="ghost" size="sm" onclick={() => selectSpace(sp.id)}>
								{t('drive.compliance.spacesTable.manage')}
							</Button>
						{/if}
					{/snippet}
				</Table>
			{/if}
		</Card>

		{#if selectedSpace}
			<Tabs items={TABS} active={activeTab} onChange={(id) => (activeTab = id as typeof activeTab)} />

			{#if activeTab === 'locks'}
				<CompliancePanel
					space={selectedSpace}
					wormPending={selectedSpace.wormPending ?? 0}
					{canManage}
					{canView}
					onchanged={loadSpaces}
				/>

				<Card flush={true}>
					<h2 class="drive-admin__subtitle">{t('drive.admin.lockList.title')}</h2>
					{#if loading}
						<div class="drive-admin__loading"><Spinner /></div>
					{:else if locks.length === 0}
						<EmptyState title={t('drive.admin.lockList.empty')} />
					{:else}
						{@const rows = locks as unknown as Record<string, unknown>[]}
						<Table columns={COLUMNS} {rows}>
							{#snippet cell(row, col)}
								{@const lock = row as unknown as DriveLockRow}
								{#if col.key === 'file'}
									{lock.name}
								{:else if col.key === 'holder'}
									{lock.holderName}
								{:else if col.key === 'mode'}
									{lock.mode}
								{:else if col.key === 'since'}
									{formatDateTime(lock.acquiredAt)}
								{:else if col.key === 'expires'}
									{formatDateTime(lock.expiresAt)}
								{:else if col.key === 'actions'}
									{#if canManage}
										<Button variant="ghost" size="sm" onclick={() => (breakTarget = lock)}>
											{t('drive.admin.lockList.break')}
										</Button>
									{/if}
								{/if}
							{/snippet}
						</Table>
					{/if}
				</Card>
			{:else if activeTab === 'trash'}
				<AdminTrashPanel spaceId={selectedSpace.id} {canManage} />
			{:else if activeTab === 'audit'}
				<AdminAuditPanel spaceId={selectedSpace.id} {canManage} />
			{/if}
		{/if}
	</div>
{/if}

<Dialog open={breakTarget !== null} title={t('drive.admin.lockList.break')} onClose={() => (breakTarget = null)}>
	<p>{t('drive.admin.lockList.confirmBreak', { name: breakTarget?.name ?? '' })}</p>
	{#snippet footer()}
		<Button variant="danger" onclick={confirmBreak}>{t('drive.admin.lockList.break')}</Button>
		<Button variant="secondary" onclick={() => (breakTarget = null)}>{t('common.cancel')}</Button>
	{/snippet}
</Dialog>

<style>
	.drive-admin {
		max-width: 900px;
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.drive-admin__title {
		font-size: var(--text-lg);
		font-weight: 600;
		margin: 0;
	}
	.drive-admin__subtitle {
		font-size: var(--text-md);
		font-weight: 600;
		margin: 0 0 var(--space-2);
	}
	.drive-admin__badge {
		display: inline-flex;
		align-items: center;
		gap: 3px;
		font-size: var(--text-xs);
		color: var(--text-caption);
	}
	.drive-admin__error {
		font-size: var(--text-sm);
		color: var(--danger-fg);
		background: var(--danger-bg);
		padding: var(--space-2);
		border-radius: var(--radius-sm);
		margin: 0;
	}
	.drive-admin__loading {
		display: flex;
		justify-content: center;
		padding: var(--space-6);
	}
</style>
