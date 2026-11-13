<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { loadSession } from '$lib/jmap/client';
	import { directoryTree, setDirectoryAccountId } from '$lib/stores/directory';
	import type { DirectoryNode } from '$lib/stores/directory';
	import DirectorySidebar from '$lib/components/DirectorySidebar.svelte';
	import DirectoryMemberList from '$lib/components/DirectoryMemberList.svelte';
	import OrgChart from '$lib/components/OrgChart.svelte';
	import { Tabs } from '$lib/components/ui';
	import { t } from '$lib/i18n';

	let tab = $state<'browse' | 'org'>('browse');
	let dirNodes = $state<DirectoryNode[]>([]);
	let selectedDeptId = $state<string | null>(null);
	let selectedDeptNumId = $state(0);
	let dirError = $state('');

	const tabItems = $derived([
		{ id: 'browse', label: t('directory.tab.browse') },
		{ id: 'org', label: t('directory.tab.org') }
	]);

	onMount(async () => {
		try {
			await loadSession();
			setDirectoryAccountId('-1');
			dirNodes = await directoryTree();
		} catch {
			dirError = t('directory.load_error');
		}
	});

	function selectDepartment(id: string) {
		selectedDeptId = id;
		selectedDeptNumId = parseInt(id);
	}
</script>

<div class="directory-page">
	{#if dirError}
		<p class="error-banner">{dirError}</p>
	{/if}
	<div class="tab-bar">
		<Tabs items={tabItems} active={tab} onChange={(id) => (tab = id as 'browse' | 'org')} />
	</div>

	{#if tab === 'browse'}
		<div class="browse-layout">
			<aside class="sidebar">
				<DirectorySidebar nodes={dirNodes} onsetSelect={selectDepartment} />
			</aside>
			<main class="main">
				<h4>
					{selectedDeptId
						? dirNodes.find((n) => n.id === selectedDeptId)?.name || t('directory.department')
						: t('directory.title')}
				</h4>
				<DirectoryMemberList departmentId={selectedDeptNumId} />
			</main>
		</div>
	{:else}
		<div class="org-layout">
			<OrgChart userId="" />
		</div>
	{/if}
</div>

<style>
	.error-banner {
		background: var(--danger-bg);
		color: var(--danger-fg);
		padding: 0.75rem;
		margin: 0.5rem;
		border-radius: var(--radius-sm);
		font-size: var(--text-sm);
	}
	.directory-page {
		display: flex;
		flex-direction: column;
		height: 100%;
	}
	.tab-bar {
		border-bottom: 1px solid var(--border-default);
		padding: 0 1rem;
	}
	.browse-layout {
		display: flex;
		flex: 1;
		overflow: hidden;
	}
	.sidebar {
		width: 260px;
		min-width: 260px;
		border-right: 1px solid var(--border-default);
		padding: 0.75rem;
		overflow-y: auto;
	}
	.main {
		flex: 1;
		padding: 1rem;
		overflow-y: auto;
	}
	.main h4 {
		margin: 0 0 0.75rem;
		font-size: var(--text-md);
		color: var(--text-primary);
	}
	.org-layout {
		flex: 1;
		overflow-y: auto;
	}
</style>
