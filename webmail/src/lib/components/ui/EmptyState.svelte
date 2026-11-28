<svelte:options runes={true} />

<script lang="ts">
	import type { Snippet } from 'svelte';

	let {
		title,
		watermark = false,
		action
	}: {
		title: string;
		watermark?: boolean;
		action?: Snippet;
	} = $props();
</script>

<div class="sj-empty">
	{#if watermark}
		<img class="sj-ink sj-empty__mark" src="/brand/logo-mark.svg" alt="" width="40" height="40" />
	{/if}
	<p class="sj-empty__title">{title}</p>
	{#if action}
		<div class="sj-empty__action">{@render action()}</div>
	{/if}
</div>

<style>
	.sj-empty {
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		gap: 10px;
		padding: 32px 16px;
		text-align: center;
		font-family: var(--font-sans);
	}
	.sj-empty__mark {
		width: 40px;
		height: 40px;
		opacity: 0.35;
	}
	.sj-empty__title {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-tertiary);
	}
	.sj-empty__action {
		display: flex;
	}
</style>
