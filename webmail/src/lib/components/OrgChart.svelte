<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { Avatar } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';

	let { userId = '' } = $props();

	// Local navigation state. Seeded once from the userId prop in onMount;
	// thereafter driven only by jumpTo (breadcrumb / report clicks).
	let activeUserId = $state('');
	let user = $state<any>(null);
	let managers = $state<any[]>([]);
	let reports = $state<any[]>([]);
	let loading = $state(false);
	let error = $state('');

	async function load(userIdParam?: string) {
		loading = true;
		error = '';
		try {
			const params = userIdParam ? `?userId=${encodeURIComponent(userIdParam)}` : '';
			const res = await fetch(`/auth/me/org-chart${params}`, { credentials: 'include' });
			if (!res.ok) throw new Error('Failed to load org chart');
			const data = await res.json();
			user = data.user;
			managers = data.managers || [];
			reports = data.reports || [];
		} catch {
			error = t('directory.org.error');
		} finally {
			loading = false;
		}
	}

	function jumpTo(uid: string) {
		activeUserId = uid;
		load(uid);
	}

	onMount(() => {
		activeUserId = userId;
		load(activeUserId || undefined);
	});
</script>

<div class="org-chart">
	{#if loading}
		<p class="status-text">{t('directory.org.loading')}</p>
	{:else if error}
		<p class="error">{error}</p>
	{:else if user}
		<!-- Manager chain breadcrumb -->
		<div class="chain">
			{#each managers as m}
				<button class="chain-link" onclick={() => jumpTo(m.id)}>
					<span class="chain-name">{m.displayName}</span>
					{#if m.jobTitle}<span class="chain-title"> · {m.jobTitle}</span>{/if}
				</button>
				<span class="chain-arrow"><Icon name="ChevronRight" size={14} /></span>
			{/each}
			<span class="chain-current">{user.displayName}</span>
			{#if user.jobTitle}<span class="chain-title"> · {user.jobTitle}</span>{/if}
		</div>

		<!-- Reports tree -->
		<div class="reports-section">
			{#if reports.length > 0}
				<h3>{t('directory.org.reports', { count: String(reports.length) })}</h3>
				<div class="reports-tree">
					{#each buildTree(reports, null) as node}
						{@render TreeNode(node)}
					{/each}
				</div>
			{:else}
				<p class="no-reports">{t('directory.org.no_reports')}</p>
			{/if}
		</div>
	{:else}
		<p class="status-text">{t('directory.org.empty')}</p>
	{/if}
</div>

{#snippet TreeNode(node: any)}
	<div class="org-node" style="margin-left: {(node.depth || 0) * 2}rem">
		<div class="org-card">
			<Avatar name={node.displayName} src={node.avatar?.blobId ? `/api/blobs/${node.avatar.blobId}` : ''} size="md" />
			<div class="org-info">
				<button class="org-name" onclick={() => jumpTo(node.id)}>{node.displayName}</button>
				{#if node.jobTitle}<div class="org-title">{node.jobTitle}</div>{/if}
				{#if node.department}<div class="org-dept">{node.department}</div>{/if}
			</div>
		</div>
		{#if node.children}
			{#each node.children as child}
				{@render TreeNode(child)}
			{/each}
		{/if}
	</div>
{/snippet}

<style>
	.org-chart {
		padding: 1rem;
	}
	.chain {
		display: flex;
		align-items: center;
		flex-wrap: wrap;
		gap: 0.25rem;
		margin-bottom: 1.5rem;
		font-size: var(--text-sm);
	}
	.chain-link {
		border: none;
		background: none;
		color: var(--text-accent);
		cursor: pointer;
		padding: 0;
		border-radius: var(--radius-xs);
	}
	.chain-link:hover {
		color: var(--accent-hover);
		text-decoration: underline;
	}
	.chain-link:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.chain-arrow {
		display: inline-flex;
		color: var(--text-tertiary);
		margin: 0 0.25rem;
	}
	.chain-current {
		font-weight: 600;
		color: var(--text-primary);
	}
	.chain-title, .chain-name {
		font-size: var(--text-sm);
	}
	.chain-title {
		color: var(--text-tertiary);
	}
	.reports-section h3 {
		font-size: var(--text-md);
		margin: 0 0 0.75rem;
		color: var(--text-secondary);
	}
	.reports-tree {
		display: flex;
		flex-direction: column;
		gap: 0;
	}
	.org-node {
		margin-bottom: 0.25rem;
	}
	.org-card {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.3rem 0.5rem;
		border-radius: var(--radius-sm);
	}
	.org-card:hover {
		background: var(--surface-hover);
	}
	.org-info {
		flex: 1;
		min-width: 0;
	}
	.org-name {
		font-size: var(--text-sm);
		font-weight: 600;
		border: none;
		background: none;
		color: var(--text-accent);
		cursor: pointer;
		padding: 0;
		text-align: left;
		border-radius: var(--radius-xs);
	}
	.org-name:hover {
		text-decoration: underline;
	}
	.org-name:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.org-title {
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}
	.org-dept {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}
	.no-reports, .status-text, .error {
		color: var(--text-tertiary);
		font-size: var(--text-sm);
	}
	.error {
		color: var(--danger-fg);
	}
</style>

<script module lang="ts">
	function buildTree(nodes: any[], parentId: string | null): any[] {
		const children = nodes.filter(n => n.managerId === parentId);
		return children.map(n => ({ ...n, children: buildTree(nodes, n.id) }));
	}
</script>
