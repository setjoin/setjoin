<svelte:options runes={true} />

<script lang="ts">
	import * as api from '$lib/drive/api';
	import { type DriveActivityItem } from '$lib/drive/api';
	import { formatDateTime } from '$lib/i18n';
	import { Button, EmptyState, Spinner } from '$lib/components/ui';
	import { t } from '$lib/i18n';
	import { driveErrorMessage } from '$lib/drive/errors';

	let {
		spaceId,
		nodeId,
	}: {
		spaceId: number;
		/** Per-file mode (§5.6) — omit for the space-wide feed. */
		nodeId?: number;
	} = $props();

	const PAGE = 50;

	let items = $state<DriveActivityItem[]>([]);
	let loading = $state(true);
	let loadingMore = $state(false);
	let hasMore = $state(false);
	let error = $state('');

	async function loadFirst() {
		loading = true;
		try {
			const res = await api.activity(spaceId, { node: nodeId, max: PAGE });
			items = res.items;
			hasMore = res.items.length === PAGE;
			error = '';
		} catch (e) {
			error = driveErrorMessage(e);
		} finally {
			loading = false;
		}
	}

	async function loadMore() {
		const last = items[items.length - 1];
		if (!last) return;
		loadingMore = true;
		try {
			const res = await api.activity(spaceId, { node: nodeId, max: PAGE, beforeId: last.id });
			items = [...items, ...res.items];
			hasMore = res.items.length === PAGE;
		} catch (e) {
			error = driveErrorMessage(e);
		} finally {
			loadingMore = false;
		}
	}

	$effect(() => {
		spaceId;
		nodeId;
		void loadFirst();
	});

	// §9.3 closed-catalog action lines — unknown/forward-compat actions (a
	// future P5/P6 event) fall back to the raw action string: t() itself
	// falls back to returning the KEY unchanged on a miss, which here would
	// be the full "drive.activity.action.<x>" prefix — strip it back down to
	// just <x> so an unrecognized action still reads as plain text, not a key.
	function actionLine(action: string): string {
		const key = `drive.activity.action.${action}`;
		const line = t(key);
		return line === key ? action : line;
	}
</script>

<div class="af">
	<h3 class="af__title">{t('drive.activity.title')}</h3>
	{#if error}
		<p class="af__error" role="alert">{error}</p>
	{/if}
	{#if loading}
		<div class="af__loading"><Spinner /></div>
	{:else if items.length === 0}
		<EmptyState title={t('drive.activity.empty')} />
	{:else}
		<ul class="af__list" role="feed" aria-label={t('drive.activity.title')}>
			{#each items as item (item.id)}
				<li class="af__item" role="article">
					<span class="af__actor">{item.actorName}</span>
					<span class="af__action">{actionLine(item.action)}</span>
					<span class="af__time">{formatDateTime(item.at)}</span>
				</li>
			{/each}
		</ul>
		{#if hasMore}
			<Button variant="ghost" size="sm" disabled={loadingMore} onclick={loadMore}>
				{loadingMore ? t('common.loading') : t('drive.activity.loadMore')}
			</Button>
		{/if}
	{/if}
</div>

<style>
	.af {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.af__title {
		margin: 0;
		font-size: var(--text-sm);
		font-weight: 600;
	}
	.af__error {
		font-size: var(--text-sm);
		color: var(--danger-fg);
		background: var(--danger-bg);
		padding: var(--space-2);
		border-radius: var(--radius-sm);
		margin: 0;
	}
	.af__loading {
		display: flex;
		justify-content: center;
		padding: var(--space-4);
	}
	.af__list {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		max-height: 50vh;
		overflow-y: auto;
	}
	.af__item {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		font-size: var(--text-sm);
		padding: var(--space-1) var(--space-2);
		border-bottom: 1px solid var(--border-subtle);
	}
	.af__actor {
		font-weight: 500;
	}
	.af__action {
		flex: 1;
		color: var(--text-secondary);
	}
	.af__time {
		font-size: var(--text-xs);
		color: var(--text-caption);
		flex-shrink: 0;
	}
</style>
