<svelte:options runes={true} />
<script lang="ts">
	import type { Snippet } from 'svelte';
	interface Props {
		title: string;
		topbarActions?: Snippet;
		sidebar: Snippet;
		main: Snippet;
	}
	let { title, topbarActions, sidebar, main }: Props = $props();
</script>

<div
	class="pim-shell"
	data-pim-shell
	style="container-type: inline-size; height: 100%; display: flex; flex-direction: column;"
>
	<header class="pim-topbar">
		<span class="pim-topbar__title">{title}</span>
		{#if topbarActions}
			<div class="pim-topbar__actions">{@render topbarActions()}</div>
		{/if}
	</header>
	<div class="pim-body">
		<aside class="pim-sidebar">{@render sidebar()}</aside>
		<main class="pim-main">{@render main()}</main>
	</div>
</div>

<style>
	.pim-shell {
		background: var(--surface-page, var(--gray-50));
	}
	.pim-topbar {
		height: 52px;
		flex: none;
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 0 16px;
		border-bottom: 1px solid var(--border-default);
		background: var(--surface-card);
	}
	.pim-topbar__title {
		font-size: var(--text-md);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
		flex: 1;
	}
	.pim-topbar__actions {
		display: flex;
		align-items: center;
		gap: 6px;
	}
	.pim-body {
		flex: 1;
		display: flex;
		min-height: 0;
		overflow: hidden;
	}
	.pim-sidebar {
		display: none; /* hidden by default — mobile/slot single-pane */
		width: 232px;
		flex: none;
		border-right: 1px solid var(--border-default);
		background: var(--surface-card);
		overflow-y: auto;
	}
	.pim-main {
		flex: 1;
		min-width: 0;
		overflow: auto;
	}

	@container (min-width: 768px) {
		.pim-sidebar {
			display: flex;
			flex-direction: column;
		}
	}
</style>
