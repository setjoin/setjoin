<svelte:options runes={true} />

<script lang="ts">
	// SearchView — A3 QoL Task 16. Main-pane view for both entry points the
	// plan calls for: the GLOBAL search input in ChannelList's header
	// (initialQuery, no scope) and the conversation header's "search in this
	// channel" icon (initialChannelId, `in:` scoping — a checkbox lets the
	// user broaden back to every channel without retyping). Results are
	// grouped per channel (plan's own wording) — chat_search returns
	// newest-first on the GLOBAL id (chat/AGENTS.md), so grouping by
	// first-occurrence order naturally orders the groups by "most recent hit
	// per channel first" with zero extra sort.
	import * as chatApi from '$lib/chat/api';
	import type { ChatMessage } from '$lib/chat/api';
	import { chatStore } from '$lib/chat/store.svelte';
	import { EmptyState, Spinner, Input, Checkbox, Button, showToast } from '$lib/components/ui';
	import { t, formatRelativeTime, localeCode } from '$lib/i18n';

	const PAGE_LIMIT = 50;

	let {
		initialQuery = '',
		initialChannelId = null,
		onJump,
	}: {
		initialQuery?: string;
		initialChannelId?: number | null;
		onJump: (channelId: number, seq: number) => void;
	} = $props();

	// Seeded to their real values by the mount-time run of the effect below
	// (lastKey starts null, so the first run always seeds) — not seeded
	// directly from the props here, which would only capture their value at
	// mount and never react to a later prop change on the same instance.
	let query = $state('');
	let scopeToChannel = $state(false);
	let rows = $state<ChatMessage[]>([]);
	let hasSearched = $state(false);
	let loading = $state(false);
	let hasMore = $state(false);
	// [UX #7/#14, pipeline review] a fetch failure used to render identically
	// to a genuinely-empty result set — distinguish the two so a network/5xx
	// failure doesn't read as "no messages match."
	let error = $state(false);

	// Reseed local state when the caller re-triggers this SAME mounted
	// instance with a different query/scope (ChatApp reuses one SearchView
	// across every "search in this channel" click) — mirrors ThreadPane's
	// lastParentId re-seed-on-prop-change pattern.
	let lastKey: string | null = null;
	$effect(() => {
		const key = `${initialQuery}:${initialChannelId}`;
		if (lastKey === key) return;
		lastKey = key;
		query = initialQuery;
		scopeToChannel = initialChannelId != null;
		if (initialQuery.trim()) void runSearch();
		else {
			rows = [];
			hasSearched = false;
		}
	});

	function currentScopeId(): number | undefined {
		return scopeToChannel && initialChannelId != null ? initialChannelId : undefined;
	}

	async function runSearch(before?: number): Promise<void> {
		const q = query.trim();
		if (!q) return;
		loading = true;
		error = false;
		try {
			const filters: chatApi.ChatSearchFilters = { ...(currentScopeId() != null ? { in: currentScopeId() } : {}), ...(before != null ? { before } : {}) };
			const page = await chatApi.searchMessages(q, filters);
			rows = before != null ? [...rows, ...page] : page;
			hasMore = page.length >= PAGE_LIMIT;
			hasSearched = true;
		} catch {
			hasMore = false;
			hasSearched = true;
			if (before == null) {
				rows = [];
				error = true;
			} else {
				// a load-more failure with results already on screen shouldn't
				// blow away the visible list — toast instead of the full inline error.
				showToast(t('chat.search.error'), { variant: 'danger' });
			}
		} finally {
			loading = false;
		}
	}

	function onKeydown(e: KeyboardEvent): void {
		if (e.key === 'Enter') void runSearch();
	}

	function loadMore(): void {
		const min = rows.reduce((m, r) => Math.min(m, r.messageId), Infinity);
		if (min !== Infinity) void runSearch(min);
	}

	function channelLabel(channelId: number): string {
		const c = chatStore.conversations.find((cv) => cv.channelId === channelId);
		return c?.name ?? t('chat.list.unknownDm');
	}

	function snippet(m: ChatMessage): string {
		if (m.body) return m.body;
		if (m.msgType === 'voice') return t('chat.list.voiceMessage');
		return '';
	}

	function formatTime(iso: string): string {
		const diffSec = (Date.now() - new Date(iso).getTime()) / 1000;
		if (diffSec < 60) return t('chat.time.justNow');
		if (diffSec < 3600) return formatRelativeTime(-Math.round(diffSec / 60), 'minute');
		if (diffSec < 86400) return formatRelativeTime(-Math.round(diffSec / 3600), 'hour');
		return new Intl.DateTimeFormat(localeCode(), { hour: '2-digit', minute: '2-digit' }).format(new Date(iso));
	}

	// Groups preserve chat_search's newest-first order; a channel's FIRST
	// occurrence in that order is its most recent hit, so Map insertion order
	// already sorts groups "most-recently-active channel first" for free.
	let groups = $derived.by(() => {
		const byChannel = new Map<number, ChatMessage[]>();
		for (const m of rows) {
			const list = byChannel.get(m.channelId);
			if (list) list.push(m);
			else byChannel.set(m.channelId, [m]);
		}
		return [...byChannel.entries()];
	});
</script>

<div class="search-view">
	<div class="search-view__bar">
		<Input placeholder={t('chat.search.placeholder')} bind:value={query} onkeydown={onKeydown} />
		<Button variant="secondary" size="sm" onclick={() => void runSearch()}>{t('chat.search.title')}</Button>
	</div>
	{#if initialChannelId != null}
		<div class="search-view__scope">
			<Checkbox bind:checked={scopeToChannel} label={t('chat.search.scopeChannel')} onchange={() => void runSearch()} />
		</div>
	{/if}
	<div class="search-view__results">
		{#if loading && rows.length === 0}
			<div class="search-view__loading"><Spinner /></div>
		{:else if !hasSearched}
			<EmptyState title={t('chat.search.prompt')} />
		{:else if error}
			<EmptyState title={t('chat.search.error')}>
				{#snippet action()}
					<Button variant="secondary" size="sm" onclick={() => void runSearch()}>{t('common.retry')}</Button>
				{/snippet}
			</EmptyState>
		{:else if rows.length === 0}
			<EmptyState title={t('chat.search.empty')} />
		{:else}
			{#each groups as [channelId, hits] (channelId)}
				<div class="search-view__group">
					<div class="search-view__group-head">{channelLabel(channelId)}</div>
					<ul class="search-view__list">
						{#each hits as m (m.messageId)}
							<li>
								<button type="button" class="search-view__row" onclick={() => onJump(m.channelId, m.seq)}>
									<span class="search-view__snippet">{snippet(m)}</span>
									<span class="search-view__time">{formatTime(m.createdAt)}</span>
								</button>
							</li>
						{/each}
					</ul>
				</div>
			{/each}
			{#if hasMore}
				<Button variant="ghost" size="sm" onclick={loadMore} disabled={loading}>{t('chat.search.loadMore')}</Button>
			{/if}
		{/if}
	</div>
</div>

<style>
	.search-view {
		flex: 1;
		min-height: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		padding: var(--space-3);
		overflow-y: auto;
	}
	.search-view__bar {
		display: flex;
		gap: var(--space-2);
		align-items: flex-end;
		max-width: 640px;
	}
	.search-view__bar :global(.sj-field) {
		flex: 1;
	}
	.search-view__scope {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.search-view__results {
		flex: 1;
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.search-view__loading {
		display: flex;
		align-items: center;
		justify-content: center;
		padding: var(--space-4);
	}
	.search-view__group {
		max-width: 640px;
	}
	.search-view__group-head {
		font-size: var(--text-xs);
		font-weight: 600;
		color: var(--text-caption);
		text-transform: uppercase;
		letter-spacing: 0.02em;
		margin-bottom: var(--space-1);
	}
	.search-view__list {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.search-view__row {
		width: 100%;
		display: flex;
		align-items: baseline;
		justify-content: space-between;
		gap: var(--space-2);
		text-align: left;
		border: 1px solid var(--border-subtle);
		background: var(--surface-card);
		cursor: pointer;
		padding: var(--space-2) var(--space-3);
		border-radius: var(--radius-sm);
	}
	.search-view__row:hover {
		background: var(--surface-hover);
	}
	.search-view__snippet {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.search-view__time {
		flex: none;
		font-size: var(--text-2xs);
		color: var(--text-caption);
	}
</style>
