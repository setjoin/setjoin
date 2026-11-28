<svelte:options runes={true} />

<script lang="ts">
	import { Dialog, Button, Input, Badge } from '$lib/components/ui';
	import { canConfirmGrant } from '$lib/rbac/sensitiveGrant';
	import { t } from '$lib/i18n';

	let {
		open = false,
		roleName = '',
		sensitiveKeys = [],
		requireType = false,
		onConfirm = () => {},
		onCancel = () => {}
	}: {
		open?: boolean;
		roleName?: string;
		sensitiveKeys?: string[];
		requireType?: boolean;
		onConfirm?: () => void;
		onCancel?: () => void;
	} = $props();

	let typed = $state('');
	let canConfirm = $derived(canConfirmGrant(requireType, typed, roleName));
</script>

<Dialog {open} title={t('admin.roles.confirm_sensitive_title')} onClose={onCancel}>
	{#snippet children()}
		<p>{t('admin.roles.confirm_sensitive_body', { role: roleName })}</p>
		<div class="sj-sens-list">
			{#each sensitiveKeys as k}
				<Badge variant="warning" label={k} />
			{/each}
		</div>
		{#if requireType}
			<Input
				label={t('admin.roles.type_to_confirm', { role: roleName })}
				value={typed}
				oninput={(e) => (typed = (e.target as HTMLInputElement).value)}
			/>
		{/if}
	{/snippet}
	{#snippet footer()}
		<Button variant="danger" disabled={!canConfirm} onclick={onConfirm}
			>{t('admin.roles.grant_anyway')}</Button
		>
		<Button variant="ghost" onclick={onCancel}>{t('common.cancel')}</Button>
	{/snippet}
</Dialog>

<style>
	.sj-sens-list {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-2);
		margin: var(--space-3) 0;
	}
</style>
