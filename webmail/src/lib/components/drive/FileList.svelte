<svelte:options runes={true} />

<script lang="ts">
	import type { DriveNode } from '$lib/drive/api';
	import { formatBytes } from '$lib/utils/display';
	import { formatDateTime } from '$lib/i18n';
	import Icon from '$lib/components/Icon.svelte';
	import { IconButton, Spinner, EmptyState } from '$lib/components/ui';
	import { t } from '$lib/i18n';

	let {
		nodes,
		loading,
		deletedView,
		onOpenFolder,
		onSelectFile,
		onRename,
		onTrash,
		onRestore,
		onDestroy,
		onManageFolderAdmins,
		onManageAccess,
		onWatch,
	}: {
		nodes: DriveNode[];
		loading: boolean;
		deletedView: boolean;
		onOpenFolder: (id: number) => void;
		onSelectFile: (node: DriveNode) => void;
		onRename: (node: DriveNode, newName: string) => void;
		onTrash: (node: DriveNode) => void;
		onRestore: (node: DriveNode) => void;
		onDestroy: (node: DriveNode) => void;
		onManageFolderAdmins?: (node: DriveNode) => void;
		onManageAccess?: (node: DriveNode) => void;
		/** P6 Task 14: quick "watch this" entry point (all events) — the
		 *  Subscription manager sheet is where ops get narrowed/edited/removed.
		 *  A member action, not editor-gated, so it renders regardless of canWrite. */
		onWatch?: (node: DriveNode) => void;
	} = $props();

	function allows(node: DriveNode, capability: string): boolean {
		return node.capabilities?.includes(capability as never) ?? false;
	}

	let renamingId = $state<number | null>(null);
	let renameValue = $state('');

	function startRename(node: DriveNode) {
		renamingId = node.id;
		renameValue = node.name;
	}

	function commitRename(node: DriveNode) {
		const v = renameValue.trim();
		renamingId = null;
		if (v && v !== node.name) onRename(node, v);
	}
</script>

<div class="fl">
	{#if loading}
		<div class="fl__loading"><Spinner /></div>
	{:else if nodes.length === 0}
		<EmptyState title={deletedView ? t('drive.tree.emptyTrash') : t('drive.tree.emptyFolder')} />
	{:else}
		<ul class="fl__rows">
			{#each nodes as node (node.id)}
				<li class="fl-row">
					{#if renamingId === node.id}
						<Icon name={node.kind === 'folder' ? 'Folder' : 'FileText'} size={16} />
						<input
							class="fl-row__rename"
							bind:value={renameValue}
							onblur={() => commitRename(node)}
							onkeydown={(e) => {
								if (e.key === 'Enter') commitRename(node);
								if (e.key === 'Escape') renamingId = null;
							}}
						/>
					{:else}
						<button
							class="fl-row__main"
							onclick={() => (node.kind === 'folder' ? onOpenFolder(node.id) : onSelectFile(node))}
							onkeydown={(e) => {
								if (e.key === 'F2' && allows(node, 'rename')) startRename(node);
								if (e.key === 'Delete' && allows(node, 'delete') && !deletedView) onTrash(node);
							}}
						>
							<Icon name={node.kind === 'folder' ? 'Folder' : 'FileText'} size={16} />
							<span class="fl-row__name">{node.name}</span>
							{#if node.branchCount > 0}
								<span class="fl-row__branch-badge" aria-label={t('drive.branch.badge', { n: String(node.branchCount) })}>
									<Icon name="GitBranch" size={12} />
									{node.branchCount}
								</span>
							{/if}
							{#if node.lock}
								<span class="fl-row__lock" aria-live="polite">
									<Icon name="Lock" size={12} />
									{t('drive.lock.editingSince', { name: node.lock.holderName, time: formatDateTime(node.lock.acquiredAt) })}
								</span>
							{/if}
							{#if node.kind === 'file' && node.size != null}
								<span class="fl-row__size">{formatBytes(node.size)}</span>
							{/if}
						</button>
					{/if}
					{#if (onWatch || onManageAccess) && !deletedView}
						<div class="fl-row__actions">
							{#if onManageAccess}<IconButton label={t('drive.access.properties')} size="sm" onclick={() => onManageAccess?.(node)}><Icon name="Lock" size={14} /></IconButton>{/if}
							{#if onWatch}<IconButton label={t('drive.watch.watchThis')} size="sm" onclick={() => onWatch?.(node)}><Icon name="Bell" size={14} /></IconButton>{/if}
						</div>
					{/if}
					{#if allows(node, 'rename') || allows(node, 'delete') || allows(node, 'manage_acl')}
						<div class="fl-row__actions">
							{#if deletedView}
								{#if allows(node, 'delete')}<IconButton label={t('drive.tree.restore')} size="sm" onclick={() => onRestore(node)}>
									<Icon name="Undo2" size={14} />
								</IconButton>{/if}
								{#if allows(node, 'delete')}<IconButton label={t('drive.tree.destroy')} size="sm" onclick={() => onDestroy(node)}>
									<Icon name="X" size={14} />
								</IconButton>{/if}
							{:else}
								{#if allows(node, 'manage_acl') && node.kind === 'folder' && onManageFolderAdmins}
									<IconButton label={t('drive.folderAdmin.title')} size="sm" onclick={() => onManageFolderAdmins?.(node)}>
										<Icon name="ShieldCheck" size={14} />
									</IconButton>
								{/if}
								{#if allows(node, 'rename')}<IconButton label={t('drive.tree.rename')} size="sm" onclick={() => startRename(node)}>
									<Icon name="Pencil" size={14} />
								</IconButton>{/if}
								{#if allows(node, 'delete')}<IconButton label={t('drive.tree.trash')} size="sm" onclick={() => onTrash(node)}>
									<Icon name="Trash2" size={14} />
								</IconButton>{/if}
							{/if}
						</div>
					{/if}
				</li>
			{/each}
		</ul>
	{/if}
</div>

<style>
	.fl {
		flex: 1;
		min-width: 0;
		overflow-y: auto;
	}
	.fl__loading {
		display: flex;
		justify-content: center;
		padding: var(--space-6);
	}
	.fl__rows {
		list-style: none;
		margin: 0;
		padding: var(--space-2);
	}
	.fl-row {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-1) var(--space-2);
		border-radius: var(--radius-sm);
	}
	.fl-row:hover {
		background: var(--surface-hover);
	}
	.fl-row:hover .fl-row__actions,
	.fl-row:focus-within .fl-row__actions {
		visibility: visible;
	}
	.fl-row__main {
		flex: 1;
		min-width: 0;
		display: flex;
		align-items: center;
		gap: var(--space-2);
		border: none;
		background: none;
		cursor: pointer;
		padding: var(--space-1) 0;
		text-align: left;
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	.fl-row__main:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.fl-row__name {
		flex: 1;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.fl-row__size {
		font-size: var(--text-xs);
		color: var(--text-caption);
		flex-shrink: 0;
	}
	.fl-row__branch-badge,
	.fl-row__lock {
		display: inline-flex;
		align-items: center;
		gap: 2px;
		font-size: var(--text-xs);
		color: var(--text-caption);
		flex-shrink: 0;
	}
	.fl-row__rename {
		flex: 1;
		font-size: var(--text-sm);
		border: 1px solid var(--border-focus, var(--indigo-600));
		border-radius: var(--radius-xs);
		padding: 2px 6px;
		background: var(--surface-card);
		color: var(--text-primary);
	}
	.fl-row__actions {
		display: flex;
		gap: var(--space-1);
		visibility: hidden;
		flex-shrink: 0;
	}

	@media (max-width: 700px), (hover: none) {
		.fl-row__actions {
			visibility: visible;
		}
	}
</style>
