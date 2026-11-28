<svelte:options runes={true} />

<script lang="ts">
	import { tree as fetchTree, type DriveNode } from '$lib/drive/api';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';

	let { spaceId, selectedFolderId, onSelect }: {
		spaceId: number;
		selectedFolderId: number | null;
		onSelect: (folderId: number | null) => void;
	} = $props();

	let rootFolders = $state<DriveNode[]>([]);
	// ponytail: a plain Map keyed by folder id — one fetch per expand, cached
	// for the space's lifetime (no invalidation on rename/move here; the tree
	// re-fetches wholesale on space switch, which is the common case P1 needs).
	let childrenCache = $state<Map<number, DriveNode[]>>(new Map());
	let expanded = $state<Set<number>>(new Set());

	async function loadRoot() {
		const nodes = await fetchTree(spaceId, {});
		rootFolders = nodes.filter((n) => n.kind === 'folder');
	}

	$effect(() => {
		void spaceId;
		expanded = new Set();
		childrenCache = new Map();
		void loadRoot();
	});

	async function toggle(node: DriveNode) {
		if (expanded.has(node.id)) {
			expanded.delete(node.id);
			expanded = new Set(expanded);
			return;
		}
		if (!childrenCache.has(node.id)) {
			const nodes = await fetchTree(spaceId, { parent: node.id });
			childrenCache.set(
				node.id,
				nodes.filter((n) => n.kind === 'folder'),
			);
			childrenCache = new Map(childrenCache);
		}
		expanded.add(node.id);
		expanded = new Set(expanded);
	}

	// ponytail: tabindex=0 on every row (simple Tab-reachable rows) rather than
	// a full roving-tabindex single-stop implementation — arrow keys still
	// expand/collapse/open the FOCUSED row; add roving tabindex if a keyboard
	// user reports the extra Tab stops as friction.
	function handleKeydown(e: KeyboardEvent, node: DriveNode) {
		if (e.key === 'ArrowRight') {
			if (!expanded.has(node.id)) void toggle(node);
		} else if (e.key === 'ArrowLeft') {
			if (expanded.has(node.id)) void toggle(node);
		} else if (e.key === 'Enter') {
			onSelect(node.id);
		}
	}
</script>

<div class="drive-tree" role="tree" aria-label={t('drive.tree.root')}>
	<div
		class="tree-row"
		class:selected={selectedFolderId === null}
		role="treeitem"
		aria-level={1}
		aria-selected={selectedFolderId === null}
		tabindex="0"
		onkeydown={(e) => e.key === 'Enter' && onSelect(null)}
	>
		<span class="chevron-placeholder"></span>
		<button class="tree-label" onclick={() => onSelect(null)}>
			<Icon name="HardDrive" size={14} />
			<span>{t('drive.tree.root')}</span>
		</button>
	</div>
	{#snippet treenode(node: DriveNode, depth: number)}
		{@const isExpanded = expanded.has(node.id)}
		{@const kids = childrenCache.get(node.id) ?? []}
		<div
			class="tree-row"
			class:selected={selectedFolderId === node.id}
			role="treeitem"
			aria-level={depth + 1}
			aria-selected={selectedFolderId === node.id}
			aria-expanded={isExpanded}
			tabindex="0"
			style="padding-left: {depth * 1.2}rem"
			onkeydown={(e) => handleKeydown(e, node)}
		>
			<button
				class="chevron"
				aria-label={isExpanded ? t('drive.tree.collapse') : t('drive.tree.expand')}
				onclick={() => toggle(node)}
			>
				<Icon name={isExpanded ? 'ChevronDown' : 'ChevronRight'} size={14} />
			</button>
			<button class="tree-label" onclick={() => onSelect(node.id)}>
				<Icon name="Folder" size={14} />
				<span>{node.name}</span>
			</button>
		</div>
		{#if isExpanded}
			<div role="group">
				{#each kids as child (child.id)}
					{@render treenode(child, depth + 1)}
				{/each}
			</div>
		{/if}
	{/snippet}
	{#each rootFolders as node (node.id)}
		{@render treenode(node, 1)}
	{/each}
</div>

<style>
	.drive-tree {
		width: 220px;
		flex-shrink: 0;
		border-right: 1px solid var(--border-default);
		overflow-y: auto;
		padding: var(--space-2);
	}
	.tree-row {
		display: flex;
		align-items: center;
		gap: 0;
		padding: 0.2rem 0.5rem;
		border-radius: var(--radius-sm);
	}
	.tree-row:hover {
		background: var(--surface-hover);
	}
	.tree-row.selected {
		background: var(--surface-selected);
	}
	.tree-row:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.chevron,
	.chevron-placeholder {
		width: 20px;
		height: 20px;
		flex-shrink: 0;
	}
	.chevron {
		border: none;
		background: none;
		cursor: pointer;
		color: var(--text-tertiary);
		padding: 0;
		display: flex;
		align-items: center;
		justify-content: center;
		border-radius: var(--radius-xs);
	}
	.chevron:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.tree-label {
		border: none;
		background: none;
		cursor: pointer;
		display: flex;
		align-items: center;
		gap: 0.35rem;
		font-size: var(--text-sm);
		color: var(--text-primary);
		padding: 0;
		text-align: left;
		flex: 1;
		border-radius: var(--radius-xs);
		overflow: hidden;
	}
	.tree-label span {
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.tree-label:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	@media (max-width: 700px) {
		.drive-tree {
			width: 100%;
			max-height: 116px;
			border-right: 0;
			border-bottom: 1px solid var(--border-default);
			flex-shrink: 0;
		}
	}
</style>
