<svelte:options runes={true} />
<script lang="ts">
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';
	let { lockedDown = false, approved = false }: { lockedDown?: boolean; approved?: boolean } = $props();
	const show = $derived(lockedDown && !approved);
</script>
{#if show}
	<div class="banner" role="alert">
		<Icon name="ShieldAlert" size={16} strokeWidth={1.75} aria-hidden={true} />
		<span>{t('device_lockdown.report_only_banner')}</span>
	</div>
{/if}
<style>
	.banner {
		display: flex; gap: 8px; align-items: center;
		padding: 10px 12px;
		background: var(--warning-bg); color: var(--warning-fg);
		border-radius: var(--radius-md); font-family: var(--font-sans); font-size: var(--text-sm);
	}
</style>
