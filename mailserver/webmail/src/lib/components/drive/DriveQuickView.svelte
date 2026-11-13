<svelte:options runes={true} />

<script lang="ts">
	import type { DriveQuickViewItem } from '$lib/drive/api';
	import { Button, EmptyState, Spinner } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { formatDateTime, t } from '$lib/i18n';

	let { view, items, loading, error, onOpen, onRetry, onOpenSpace }: {
		view: 'shared' | 'shares' | 'requests';
		items: DriveQuickViewItem[];
		loading: boolean;
		error: string;
		onOpen: (item: DriveQuickViewItem) => void;
		onRetry: () => void;
		onOpenSpace: () => void;
	} = $props();

	let groups = $derived.by(() => {
		const out = new Map<string, DriveQuickViewItem[]>();
		for (const item of items) {
			const rows = out.get(item.spaceName) ?? [];
			rows.push(item);
			out.set(item.spaceName, rows);
		}
		return [...out.entries()];
	});
</script>

<section class="dqv" aria-label={t(`drive.quick.${view}`)}>
	<header><h2>{t(`drive.quick.${view}`)}</h2><span aria-live="polite">{t('drive.quick.count', { n: String(items.length) })}</span></header>
	{#if loading}<div class="dqv__state"><Spinner /></div>
	{:else if error}<div class="dqv__state" role="alert"><p>{error}</p><Button variant="secondary" onclick={onRetry}>{t('common.retry')}</Button></div>
	{:else if items.length === 0}<EmptyState title={t(`drive.quick.${view}.empty`)}>{#snippet action()}<Button variant="secondary" onclick={onOpenSpace}>{t('drive.quick.openSpace')}</Button>{/snippet}</EmptyState>
	{:else}
		{#each groups as [spaceName, rows] (spaceName)}
			<section class="dqv__group"><h3>{spaceName}</h3><ul>{#each rows as item (item.requestId ?? item.nodeId)}<li><button type="button" onclick={() => onOpen(item)} disabled={item.kind === 'request' && !item.grantId}><Icon name={item.nodeKind === 'folder' ? 'Folder' : 'FileText'} size={16} /><span><strong>{item.name}</strong><small>{#if item.kind === 'request'}{t(`drive.quick.requestStatus.${item.status ?? 'pending'}`)}{:else}{item.source ? t(`drive.access.source.${item.source}`) : spaceName}{/if}{#if item.sharedAt} · {formatDateTime(item.sharedAt)}{/if}</small></span>{#if item.kind === 'share'}<span class="dqv__count">{t('drive.quick.grantCount', { n: String(item.activeGrantCount ?? 0) })}</span>{/if}</button></li>{/each}</ul></section>
		{/each}
	{/if}
</section>

<style>
	.dqv { flex: 1; overflow-y: auto; padding: var(--space-4); }
	.dqv > header { display: flex; align-items: baseline; justify-content: space-between; gap: var(--space-3); border-bottom: 1px solid var(--border-subtle); padding-bottom: var(--space-3); }
	.dqv h2,.dqv h3 { margin: 0; }
	.dqv h2 { font-size: var(--text-lg); }
	.dqv h3 { font-size: var(--text-sm); color: var(--text-secondary); margin: var(--space-4) 0 var(--space-2); }
	.dqv header span,.dqv small,.dqv__count { font-size: var(--text-xs); color: var(--text-caption); }
	.dqv__state { display: flex; flex-direction: column; align-items: center; gap: var(--space-3); padding: var(--space-6); }
	.dqv ul { list-style: none; margin: 0; padding: 0; border: 1px solid var(--border-default); border-radius: var(--radius-sm); }
	.dqv li + li { border-top: 1px solid var(--border-subtle); }
	.dqv li button { width: 100%; display: flex; align-items: center; gap: var(--space-2); padding: var(--space-3); border: 0; background: transparent; color: var(--text-primary); text-align: left; }
	.dqv li button:not(:disabled):hover,.dqv li button:not(:disabled):focus-visible { background: var(--surface-hover); }
	.dqv li button:disabled { cursor: default; }
	.dqv li span:nth-child(2) { flex: 1; min-width: 0; }
	.dqv strong,.dqv small { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

	@media (max-width: 767px) { .dqv { padding: var(--space-3); } .dqv li button { min-height: 52px; } }
</style>
