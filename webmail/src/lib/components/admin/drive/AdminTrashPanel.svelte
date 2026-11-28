<svelte:options runes={true} />

<script lang="ts">
	// P6 Task 15 — admin tier-2 ("admin bin") trash console. Lists
	// GET /spaces/{id}/trash?tier=2 for the selected space and restores a
	// subtree to its original path via POST /nodes/{id}/purge-restore
	// (drive.manage-gated server-side — this panel is only ever mounted
	// behind the same canManage gate the parent admin page already applies).
	import * as api from '$lib/drive/api';
	import { type DriveTrashItem } from '$lib/drive/api';
	import { formatDateTime } from '$lib/i18n';
	import { Card, Table, Button, EmptyState, Spinner, Dialog } from '$lib/components/ui';
	import type { TableColumn } from '$lib/components/ui';
	import { formatBytes } from '$lib/utils/display';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';
	import { driveErrorMessage } from '$lib/drive/errors';

	let {
		spaceId,
		canManage,
	}: {
		spaceId: number;
		canManage: boolean;
	} = $props();

	let items = $state<DriveTrashItem[]>([]);
	let loading = $state(false);
	let error = $state('');
	let restoreTarget = $state<DriveTrashItem | null>(null);
	let restoring = $state(false);

	async function load() {
		loading = true;
		try {
			const res = await api.trashAdminList(spaceId);
			items = res.items;
			error = '';
		} catch (e) {
			error = driveErrorMessage(e);
		} finally {
			loading = false;
		}
	}

	$effect(() => {
		spaceId; // re-run on space switch
		void load();
	});

	async function confirmRestore() {
		if (!restoreTarget) return;
		const target = restoreTarget;
		restoreTarget = null;
		restoring = true;
		try {
			await api.purgeRestore(target.id);
			await load();
		} catch (e) {
			error = driveErrorMessage(e);
		} finally {
			restoring = false;
		}
	}

	const COLUMNS: TableColumn[] = [
		{ key: 'name', label: t('drive.trash.name') },
		{ key: 'kind', label: t('drive.trash.kind') },
		{ key: 'size', label: t('drive.trash.size') },
		{ key: 'purgedAt', label: t('drive.trash.purgedAt') },
		{ key: 'purgedBy', label: t('drive.trash.purgedBy') },
		{ key: 'actions', label: '' },
	];
</script>

<Card flush={true}>
	<div class="atp">
		<h2 class="atp__title">{t('drive.trash.adminBin')}</h2>
		<p class="atp__note">{t('drive.trash.graceNote')}</p>
		<p class="atp__note">{t('drive.trash.quotaNote')}</p>

		{#if error}
			<p class="atp__error" role="alert">{error}</p>
		{/if}

		{#if loading}
			<div class="atp__loading"><Spinner /></div>
		{:else if items.length === 0}
			<EmptyState title={t('drive.trash.empty')} />
		{:else}
			{@const rows = items as unknown as Record<string, unknown>[]}
			<Table columns={COLUMNS} {rows}>
				{#snippet cell(row, col)}
					{@const item = row as unknown as DriveTrashItem}
					{#if col.key === 'name'}
						{item.name}
					{:else if col.key === 'kind'}
						<span class="atp__kind">
							<Icon name={item.kind === 'folder' ? 'Folder' : 'FileText'} size={13} />
							{item.kind}
						</span>
					{:else if col.key === 'size'}
						{formatBytes(item.sizeBytes)}
					{:else if col.key === 'purgedAt'}
						{formatDateTime(item.purgedAt)}
					{:else if col.key === 'purgedBy'}
						{item.purgedBy ?? t('drive.trash.agedOut')}
					{:else if col.key === 'actions'}
						{#if canManage}
							<Button variant="ghost" size="sm" onclick={() => (restoreTarget = item)}>
								{t('drive.trash.restore')}
							</Button>
						{/if}
					{/if}
				{/snippet}
			</Table>
		{/if}
	</div>
</Card>

<Dialog open={restoreTarget !== null} title={t('drive.trash.restore')} onClose={() => (restoreTarget = null)}>
	<p>{t('drive.trash.restoreConfirm', { name: restoreTarget?.name ?? '' })}</p>
	{#snippet footer()}
		<Button variant="primary" disabled={restoring} onclick={confirmRestore}>{t('drive.trash.restore')}</Button>
		<Button variant="secondary" onclick={() => (restoreTarget = null)}>{t('common.cancel')}</Button>
	{/snippet}
</Dialog>

<style>
	.atp {
		padding: var(--space-3);
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.atp__title {
		font-size: var(--text-md);
		font-weight: 600;
		margin: 0;
	}
	.atp__note {
		font-size: var(--text-sm);
		color: var(--text-caption);
		margin: 0;
	}
	.atp__error {
		font-size: var(--text-sm);
		color: var(--danger-fg);
		background: var(--danger-bg);
		padding: var(--space-2);
		border-radius: var(--radius-sm);
		margin: 0;
	}
	.atp__loading {
		display: flex;
		justify-content: center;
		padding: var(--space-6);
	}
	.atp__kind {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		font-size: var(--text-xs);
		color: var(--text-caption);
	}
</style>
