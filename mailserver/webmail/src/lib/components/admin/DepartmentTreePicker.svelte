<svelte:options runes={true} />

<!--
	DepartmentTreePicker — reusable OU-scope picker for RBAC grant dialogs.
	Contract: <DepartmentTreePicker bind:value />
	  value = { scopeType: 'ou', scopeId: number } | null  (null = whole domain)

	WAI-ARIA tree widget: role=tree + role=treeitem + roving tabindex.
	Reuses TreeNode row pattern from OrgChart.svelte (depth-indent, hover, focus ring).
-->

<script lang="ts">
	import { onMount } from 'svelte';
	import { adminDeptTree } from '$lib/admin/client';
	import type { TreeNode } from '$lib/admin/client';
	import { Button, Input, Tooltip } from '$lib/components/ui';

	// ── Props ──────────────────────────────────────────────────────────────────

	interface OuScope {
		scopeType: 'ou';
		scopeId: number;
	}

	interface Props {
		value?: OuScope | null;
		/**
		 * Embedded mode: skip the "Whole domain / Limit to a department" radio and
		 * show the tree directly. The host owns the "whole vs. scoped" choice (e.g.
		 * the 3-radio grant picker or the scope-set member control). value stays
		 * null until a node is picked.
		 */
		embedded?: boolean;
	}

	let { value = $bindable(null), embedded = false }: Props = $props();

	// ── State ──────────────────────────────────────────────────────────────────

	// 'whole' = no OU restriction; 'ou' = limit to a department.
	let radio = $state<'whole' | 'ou'>('whole');
	// In embedded mode there is no radio — the tree is always shown (host owns
	// the whole-vs-scoped choice; the tree loads on mount regardless of `radio`).
	let showTree = $derived(embedded || radio === 'ou');

	let loading = $state(false);
	let fetchError = $state('');
	let tree = $state<TreeNode[]>([]);

	// flat list of visible (expanded) nodes in DOM order, for keyboard nav
	let flatVisible = $state<TreeNode[]>([]);

	// which node is selected
	let selectedId = $state<number | null>(null);

	// roving tabindex: which index in flatVisible is the "focused" one
	let rovingIdx = $state(0);

	// which node ids are expanded
	let expanded = $state<Set<number>>(new Set());

	// search filter (shown when total nodes > SEARCH_THRESHOLD)
	const SEARCH_THRESHOLD = 50;
	let searchQ = $state('');

	// ── Derived ────────────────────────────────────────────────────────────────

	// count all nodes in tree recursively
	function countAll(nodes: TreeNode[]): number {
		return nodes.reduce((acc, n) => acc + 1 + countAll(n.children), 0);
	}

	let totalNodes = $derived(countAll(tree));
	let showSearch = $derived(totalNodes > SEARCH_THRESHOLD);

	// The selected node
	let selectedNode = $derived(selectedId != null ? findNode(tree, selectedId) : null);

	// Count of descendants of a node
	function countDescendants(node: TreeNode): number {
		return node.children.reduce((acc, c) => acc + 1 + countDescendants(c), 0);
	}

	// All descendant ids of a node
	function descendantIds(node: TreeNode): Set<number> {
		const ids = new Set<number>();
		function walk(n: TreeNode) {
			for (const c of n.children) {
				ids.add(c.id);
				walk(c);
			}
		}
		walk(node);
		return ids;
	}

	// Set of ids tinted (descendants of selected)
	let tintedIds = $derived(selectedNode ? descendantIds(selectedNode) : new Set<number>());

	// Confirmation chip text — uses the node name, not path manipulation
	let chipText = $derived(
		selectedNode
			? `Scope: ${selectedNode.name} — manages this department + its sub-departments`
			: ''
	);

	// Live region text
	let liveText = $state('');

	// ── Helpers ────────────────────────────────────────────────────────────────

	function findNode(nodes: TreeNode[], id: number): TreeNode | null {
		for (const n of nodes) {
			if (n.id === id) return n;
			const found = findNode(n.children, id);
			if (found) return found;
		}
		return null;
	}

	// Build flat list of currently-visible nodes (respecting expansion and search filter)
	function buildFlat(nodes: TreeNode[], depth = 0): TreeNode[] {
		const out: TreeNode[] = [];
		for (const n of nodes) {
			// filter: if search is active, only show matching nodes or ancestors of matches
			if (searchQ && !nodeOrDescendantMatches(n, searchQ.toLowerCase())) continue;
			out.push(n);
			if (n.children.length > 0 && (expanded.has(n.id) || searchMatchesDescendant(n, searchQ.toLowerCase()))) {
				out.push(...buildFlat(n.children, depth + 1));
			}
		}
		return out;
	}

	function nodeOrDescendantMatches(n: TreeNode, q: string): boolean {
		if (n.name.toLowerCase().includes(q)) return true;
		return n.children.some((c) => nodeOrDescendantMatches(c, q));
	}

	function searchMatchesDescendant(n: TreeNode, q: string): boolean {
		if (!q) return false;
		return n.children.some((c) => nodeOrDescendantMatches(c, q));
	}

	function nodeDepth(nodes: TreeNode[], id: number, depth = 0): number {
		for (const n of nodes) {
			if (n.id === id) return depth;
			const d = nodeDepth(n.children, id, depth + 1);
			if (d >= 0) return d;
		}
		return -1;
	}

	$effect(() => {
		// Recompute flat list whenever tree/expanded/search changes
		flatVisible = buildFlat(tree);
	});

	// ── Load ───────────────────────────────────────────────────────────────────

	async function load() {
		loading = true;
		fetchError = '';
		try {
			tree = await adminDeptTree();
			// Expand top-level and depth-1 by default
			const toExpand = new Set<number>();
			for (const n of tree) {
				toExpand.add(n.id);
				for (const c of n.children) toExpand.add(c.id);
			}
			expanded = toExpand;
		} catch {
			fetchError = "Couldn't load departments";
			// Ensure value stays null so the form is still submittable
			// (radio UI stays in 'ou' panel showing the error card; effective scope is null)
			selectedId = null;
			value = null;
		} finally {
			loading = false;
		}
	}

	onMount(load);

	// ── Radio change ────────────────────────────────────────────────────────────

	function onRadioChange(newVal: 'whole' | 'ou') {
		radio = newVal;
		if (newVal === 'whole') {
			selectedId = null;
			value = null;
		} else {
			// (re-)load the tree when the user opts into OU scope
			// If a previous load already succeeded, this is a no-op (tree.length > 0)
			rovingIdx = 0;
			load();
		}
	}

	// ── Node selection ──────────────────────────────────────────────────────────

	function selectNode(node: TreeNode) {
		selectedId = node.id;
		value = { scopeType: 'ou', scopeId: node.id };
		liveText = `${node.name}, selected, includes all sub-departments`;
	}

	// ── Keyboard navigation ─────────────────────────────────────────────────────

	function onTreeKeydown(e: KeyboardEvent) {
		const flat = flatVisible;
		if (!flat.length) return;

		const cur = rovingIdx;
		const node = flat[cur];
		if (!node) return;

		switch (e.key) {
			case 'ArrowDown':
				e.preventDefault();
				rovingIdx = Math.min(cur + 1, flat.length - 1);
				break;
			case 'ArrowUp':
				e.preventDefault();
				rovingIdx = Math.max(cur - 1, 0);
				break;
			case 'ArrowRight':
				e.preventDefault();
				if (node.children.length > 0 && !expanded.has(node.id)) {
					expanded = new Set([...expanded, node.id]);
				} else if (node.children.length > 0 && expanded.has(node.id)) {
					// already expanded → move to first child
					rovingIdx = Math.min(cur + 1, flat.length - 1);
				}
				break;
			case 'ArrowLeft':
				e.preventDefault();
				if (node.children.length > 0 && expanded.has(node.id)) {
					const next = new Set(expanded);
					next.delete(node.id);
					expanded = next;
				} else {
					// move to parent
					const depth = nodeDepth(tree, node.id);
					if (depth > 0) {
						// find previous item at depth-1
						for (let i = cur - 1; i >= 0; i--) {
							if (nodeDepth(tree, flat[i].id) < depth) {
								rovingIdx = i;
								break;
							}
						}
					}
				}
				break;
			case 'Enter':
			case ' ':
				e.preventDefault();
				selectNode(node);
				break;
			case 'Home':
				e.preventDefault();
				rovingIdx = 0;
				break;
			case 'End':
				e.preventDefault();
				rovingIdx = flat.length - 1;
				break;
		}
	}
</script>

<!-- Polite live region for screen-reader announcements -->
<div aria-live="polite" aria-atomic="true" class="dtp-sr-only">{liveText}</div>

<div class="dtp">
	<!-- ── Two-tier radio (skipped in embedded mode; host owns whole-vs-scoped) ── -->
	{#if !embedded}
	<fieldset class="dtp-radiogroup">
		<legend class="dtp-legend">Scope</legend>
		<label class="dtp-radio-label">
			<input
				type="radio"
				name="dtp-scope"
				value="whole"
				checked={radio === 'whole'}
				onchange={() => onRadioChange('whole')}
			/>
			<span class="dtp-radio-text">
				<strong>Whole domain</strong>
				<span class="dtp-radio-hint">No department limit</span>
			</span>
		</label>
		<label class="dtp-radio-label">
			<input
				type="radio"
				name="dtp-scope"
				value="ou"
				checked={radio === 'ou'}
				onchange={() => onRadioChange('ou')}
			/>
			<span class="dtp-radio-text">
				<strong>Limit to a department</strong>
				<span class="dtp-radio-hint">Includes the department and all nested sub-departments</span>
			</span>
		</label>
	</fieldset>
	{/if}

	<!-- ── Tree panel (shown when scoped, or always in embedded mode) ───────── -->
	{#if showTree}
		<div class="dtp-tree-panel">
			{#if loading}
				<!-- Loading: skeleton tree -->
				<div class="dtp-skeleton" aria-label="Loading departments">
					<div class="dtp-skeleton-row"></div>
					<div class="dtp-skeleton-row dtp-skeleton-row--indent"></div>
					<div class="dtp-skeleton-row dtp-skeleton-row--indent"></div>
					<div class="dtp-skeleton-row"></div>
				</div>
			{:else if fetchError}
				<!-- Error state -->
				<div class="dtp-error-card">
					<span class="dtp-error-msg">{fetchError}</span>
					<Button variant="secondary" size="sm" onclick={load}>Retry</Button>
				</div>
			{:else if tree.length === 0}
				<!-- Empty state -->
				<div class="dtp-empty">
					<p class="dtp-empty-msg">
						No departments yet. They sync from your directory (LDAP OU), or
						<a href="/admin/directory" class="dtp-empty-link">create one</a>.
					</p>
				</div>
			{:else}
				<!-- Search box for deep trees -->
				{#if showSearch}
					<div class="dtp-search">
						<Input
							type="search"
							placeholder="Filter departments..."
							bind:value={searchQ}
							aria-label="Filter departments"
						/>
					</div>
				{/if}

				<!-- WAI-ARIA tree widget -->
				<!-- svelte-ignore a11y_interactive_supports_focus -->
				<ul
					role="tree"
					class="dtp-tree"
					aria-label="Department tree"
					onkeydown={onTreeKeydown}
				>
					{#each flatVisible as node, idx (node.id)}
						{@const depth = nodeDepth(tree, node.id)}
						{@const isSelected = node.id === selectedId}
						{@const isTinted = tintedIds.has(node.id)}
						{@const isExpanded = expanded.has(node.id)}
						{@const hasChildren = node.children.length > 0}
						{@const subCount = countDescendants(node)}
						<!-- svelte-ignore a11y_interactive_supports_focus -->
						<li
							role="treeitem"
							aria-selected={isSelected}
							aria-expanded={hasChildren ? isExpanded : undefined}
							tabindex={idx === rovingIdx ? 0 : -1}
							style="--depth: {depth}"
							class="dtp-item"
							onclick={() => {
								rovingIdx = idx;
								selectNode(node);
							}}
							onkeydown={(e) => {
								if (e.key === 'Enter' || e.key === ' ') {
									e.preventDefault();
									selectNode(node);
								}
							}}
						>
							<!-- role=none: presentational wrapper; the li[role=treeitem] is the interactive element -->
							<div
								role="none"
								class="dtp-row"
								class:dtp-row--selected={isSelected}
								class:dtp-row--tinted={isTinted}
							>
								<!-- Expand/collapse caret -->
								{#if hasChildren}
									<button
										class="dtp-caret"
										aria-label={isExpanded ? 'Collapse' : 'Expand'}
										onclick={(e) => {
											e.stopPropagation();
											const next = new Set(expanded);
											if (isExpanded) next.delete(node.id);
											else next.add(node.id);
											expanded = next;
										}}
									>
										<span class:dtp-caret--open={isExpanded}>▶</span>
									</button>
								{:else}
									<span class="dtp-caret-spacer"></span>
								{/if}

								<!-- Node name -->
								<span class="dtp-name">{node.name}</span>

								<!-- Badge + tooltip on selected node -->
								{#if isSelected && subCount > 0}
									<Tooltip
										text="Admins limited here can manage users in this department and all departments nested under it."
									>
										<!-- ponytail: button styled as badge — the only way to get tabindex=0 without a lint warning -->
										<button
											class="dtp-subtree-badge"
											type="button"
											onclick={(e) => e.stopPropagation()}
											aria-label="+ all {subCount} sub-department{subCount === 1 ? '' : 's'}: includes all nested departments"
										>
											+ all {subCount} sub-department{subCount === 1 ? '' : 's'}
										</button>
									</Tooltip>
								{/if}
							</div>
						</li>
					{/each}
				</ul>

				<!-- Confirmation chip -->
				{#if selectedNode}
					<div class="dtp-chip" role="status" aria-live="polite">
						{chipText}
					</div>
				{/if}
			{/if}
		</div>
	{/if}
</div>

<style>
	/* Screen-reader only utility */
	.dtp-sr-only {
		position: absolute;
		width: 1px;
		height: 1px;
		padding: 0;
		margin: -1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
		border: 0;
	}

	.dtp {
		font-family: var(--font-sans);
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}

	/* ── Radio group ── */
	.dtp-radiogroup {
		border: none;
		padding: 0;
		margin: 0;
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.dtp-legend {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-secondary);
		margin-bottom: 0.5rem;
	}

	.dtp-radio-label {
		display: flex;
		align-items: flex-start;
		gap: 0.5rem;
		cursor: pointer;
		min-height: 44px; /* 44px touch target */
		padding: 0.25rem 0;
	}

	.dtp-radio-label input[type='radio'] {
		margin-top: 0.25rem;
		accent-color: var(--accent);
		width: 16px;
		height: 16px;
		flex-shrink: 0;
		cursor: pointer;
	}

	.dtp-radio-text {
		display: flex;
		flex-direction: column;
		gap: 0.125rem;
	}

	.dtp-radio-text strong {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
	}

	.dtp-radio-hint {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}

	/* ── Tree panel ── */
	.dtp-tree-panel {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	/* ── Loading skeleton ── */
	.dtp-skeleton {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
		padding: 0.25rem 0;
	}

	.dtp-skeleton-row {
		height: 36px;
		background: var(--surface-hover);
		border-radius: var(--radius-sm);
		animation: dtp-shimmer 1.4s ease-in-out infinite;
	}

	.dtp-skeleton-row--indent {
		margin-left: 1.25rem;
		width: calc(100% - 1.25rem);
	}

	@keyframes dtp-shimmer {
		0%,
		100% {
			opacity: 1;
		}
		50% {
			opacity: 0.4;
		}
	}

	/* ── Error state ── */
	.dtp-error-card {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		padding: 0.75rem;
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
	}

	.dtp-error-msg {
		flex: 1;
		font-size: var(--text-sm);
		color: var(--danger-fg);
	}

	/* ── Empty state ── */
	.dtp-empty {
		padding: 1rem;
		text-align: center;
	}

	.dtp-empty-msg {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0;
	}

	.dtp-empty-link {
		color: var(--text-accent);
		text-decoration: underline;
	}

	/* ── Search ── */
	.dtp-search {
		margin-bottom: 0.25rem;
	}

	/* ── Tree ── */
	.dtp-tree {
		list-style: none;
		margin: 0;
		padding: 0;
		outline: none;
	}

	.dtp-item {
		margin: 0;
		padding: 0;
		outline: none;
	}

	/* Focus ring on focused treeitem (roving tabindex) */
	.dtp-item:focus-visible > .dtp-row {
		outline: none;
		box-shadow: var(--focus-ring);
		border-radius: var(--radius-sm);
	}

	.dtp-row {
		display: flex;
		align-items: center;
		gap: 0.375rem;
		min-height: 44px; /* 44px touch target */
		padding: 0.25rem 0.5rem;
		padding-left: calc(0.5rem + var(--depth, 0) * 1.25rem);
		border-radius: var(--radius-sm);
		cursor: pointer;
		user-select: none;
	}

	.dtp-row:hover {
		background: var(--surface-hover);
	}

	/* ponytail: --accent-subtle is the spec token; tint must keep text ≥4.5:1 */
	.dtp-row--tinted {
		background: var(--accent-subtle);
	}

	.dtp-row--tinted:hover {
		background: var(--accent-subtle);
		filter: brightness(0.97);
	}

	.dtp-row--selected {
		background: var(--accent-subtle);
	}

	/* Caret */
	.dtp-caret {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 20px;
		height: 20px;
		background: none;
		border: none;
		cursor: pointer;
		color: var(--text-tertiary);
		font-size: 10px;
		border-radius: var(--radius-xs);
		padding: 0;
		flex-shrink: 0;
	}

	.dtp-caret:hover {
		color: var(--text-primary);
		background: var(--surface-hover);
	}

	.dtp-caret:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	.dtp-caret--open {
		transform: rotate(90deg);
	}

	.dtp-caret-spacer {
		width: 20px;
		flex-shrink: 0;
	}

	.dtp-name {
		flex: 1;
		font-size: var(--text-sm);
		color: var(--text-primary);
		min-width: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	/* Sub-department badge */
	.dtp-subtree-badge {
		display: inline-flex;
		align-items: center;
		padding: 0 0.375rem;
		height: 20px;
		font-size: var(--text-xs);
		font-weight: var(--weight-medium);
		color: var(--accent-fg);
		background: var(--accent-muted);
		border-radius: var(--radius-full, 9999px);
		white-space: nowrap;
		flex-shrink: 0;
		cursor: default;
	}

	.dtp-subtree-badge:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	/* Confirmation chip */
	.dtp-chip {
		padding: 0.5rem 0.75rem;
		background: var(--surface-sunken);
		border: 1px solid var(--border-subtle, var(--border-default));
		border-radius: var(--radius-sm);
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
</style>
