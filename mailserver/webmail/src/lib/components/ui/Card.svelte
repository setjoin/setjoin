<script lang="ts">
	import type { Snippet } from 'svelte';

	interface Props {
		title?: string;
		flush?: boolean;
		actions?: Snippet;
		children: Snippet;
	}

	let { title = '', flush = false, actions, children }: Props = $props();
</script>

<div class="card">
	{#if title || actions}
		<div class="card__header">
			<span class="card__title" role="heading" aria-level="2">{title}</span>
			{#if actions}<span class="card__actions">{@render actions()}</span>{/if}
		</div>
	{/if}
	<div class="card__body" class:card__body--flush={flush}>
		{@render children()}
	</div>
</div>

<style>
	.card {
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		box-shadow: var(--shadow-xs);
		font-family: var(--font-sans);
	}
	.card__header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 12px;
		padding: 12px 16px;
		border-bottom: 1px solid var(--border-subtle);
	}
	.card__title {
		font-size: var(--text-md);
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
	}
	.card__actions {
		display: flex;
		gap: 8px;
	}
	.card__body {
		padding: 16px;
	}
	.card__body--flush {
		padding: 0;
	}
</style>
