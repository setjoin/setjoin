<svelte:options runes={true} />

<script lang="ts">
	import type { DirectoryNode } from '$lib/stores/directory';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';

	let { nodes = [] as DirectoryNode[], onsetSelect }: {
		nodes: DirectoryNode[];
		onsetSelect?: (id: string) => void;
	} = $props();

	let expanded = $state<Set<string>>(new Set());
	let selectedId = $state<string | null>(null);

	function toggle(id: string) {
		if (expanded.has(id)) expanded.delete(id); else expanded.add(id);
		expanded = new Set(expanded);
	}

	function select(id: string) {
		selectedId = id;
		onsetSelect?.(id);
	}

	function buildTree(): TreeNode[] {
		const map = new Map<string, TreeNode>();
		const roots: TreeNode[] = [];
		for (const n of nodes) {
			map.set(n.id, { ...n, children: [] });
		}
		for (const n of nodes) {
			const t = map.get(n.id)!;
			if (n.parentId && map.has(n.parentId)) {
				map.get(n.parentId)!.children.push(t);
			} else {
				roots.push(t);
			}
		}
		return roots;
	}

	interface TreeNode extends DirectoryNode {
		children: TreeNode[];
	}

	const tree = $derived(buildTree());
</script>

<div class="dir-tree" role="tree" aria-label={t('directory.tree.label')}>
	{#each tree as node}
		{#snippet treenode(args: { node: TreeNode; depth: number })}
			{@const { node: n, depth } = args}
			{@const hasChildren = n.children.length > 0 || n.memberCount > 0}
			<div
				class="tree-row"
				class:selected={selectedId === n.id}
				role="treeitem"
				aria-level={depth + 1}
				aria-selected={selectedId === n.id}
				aria-expanded={hasChildren ? expanded.has(n.id) : undefined}
				style="padding-left: {depth * 1.2 + 0.5}rem"
			>
				{#if hasChildren}
					<button
						class="chevron"
						aria-label={expanded.has(n.id) ? t('directory.tree.collapse') : t('directory.tree.expand')}
						onclick={() => toggle(n.id)}
					>
						<Icon name={expanded.has(n.id) ? 'ChevronDown' : 'ChevronRight'} size={14} />
					</button>
				{:else}
					<span class="chevron-placeholder"></span>
				{/if}
				<button class="tree-label" onclick={() => select(n.id)}>
					<span class="dept-icon"><Icon name="Folder" size={14} /></span>
					<span class="dept-name">{n.name}</span>
					{#if n.memberCount > 0}
						<span class="dept-count">({n.memberCount})</span>
					{/if}
				</button>
			</div>
			{#if expanded.has(n.id) && n.children.length > 0}
				<div role="group">
					{#each n.children as child}
						{@render treenode({ node: child, depth: depth + 1 })}
					{/each}
				</div>
			{/if}
		{/snippet}
		{@render treenode({ node, depth: 0 })}
	{/each}
</div>

<style>
	.dir-tree {
		display: flex;
		flex-direction: column;
		gap: 0;
	}
	.dir-tree :global([role='group']) {
		display: flex;
		flex-direction: column;
		gap: 0;
	}
	.tree-row {
		display: flex;
		align-items: center;
		gap: 0;
		padding: 0.2rem 0.5rem;
		border-radius: var(--radius-sm);
		cursor: pointer;
	}
	.tree-row:hover {
		background: var(--surface-hover);
	}
	.tree-row.selected {
		background: var(--surface-selected);
	}
	.chevron {
		width: 20px;
		height: 20px;
		border: none;
		background: none;
		cursor: pointer;
		color: var(--text-tertiary);
		padding: 0;
		display: flex;
		align-items: center;
		justify-content: center;
		flex-shrink: 0;
		border-radius: var(--radius-xs);
	}
	.chevron:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.chevron-placeholder {
		width: 20px;
		flex-shrink: 0;
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
	}
	.tree-label:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.dept-icon {
		display: inline-flex;
		color: var(--text-tertiary);
	}
	.dept-name {
		flex: 1;
	}
	.dept-count {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}
</style>
