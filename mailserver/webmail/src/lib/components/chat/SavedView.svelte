<svelte:options runes={true} />

<script lang="ts">
	// SavedView — A3 QoL Task 16. Main-pane view for the ChannelList's fixed
	// "Saved" row (Slack's "Later" placement) — personal bookmarks across
	// EVERY channel/DM the caller is in, not scoped to any one conversation.
	// One-shot load on mount (chatApi.listSaves); no live-push arm (save/unsave
	// is self-only state, chat_save_toggle never fans out a notify — see
	// chat/AGENTS.md — so there's nothing to subscribe to here).
	import { onMount } from 'svelte';
	import * as chatApi from '$lib/chat/api';
	import type { ChatMessage } from '$lib/chat/api';
	import { chatStore } from '$lib/chat/store.svelte';
	import { EmptyState, Spinner, Button } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t, formatRelativeTime, localeCode } from '$lib/i18n';

	let { onJump }: { onJump: (channelId: number, seq: number) => void } = $props();

	let rows = $state<ChatMessage[]>([]);
	let loading = $state(true);
	// [UX #7/#14, pipeline review] a fetch failure used to render identically
	// to "no saved messages" — distinguish the two, with a retry affordance.
	let error = $state(false);

	async function load(): Promise<void> {
		loading = true;
		error = false;
		try {
			rows = await chatApi.listSaves();
		} catch {
			rows = [];
			error = true;
		} finally {
			loading = false;
		}
	}

	onMount(() => void load());

	// ponytail: conversation.name only — a saved message in a DM/group_dm (no
	// server-side name) falls back to the generic "Direct message" label
	// rather than resolving the real counterpart(s) via a per-row roster
	// fetch; ChannelList's resolveDmTitles does the real resolution for the
	// conversation list itself, where it's worth the round trip.
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

	async function unsave(m: ChatMessage, e: Event): Promise<void> {
		e.stopPropagation();
		const before = rows;
		rows = rows.filter((r) => r.messageId !== m.messageId);
		try {
			const { saved } = await chatApi.toggleSave(m.messageId);
			if (saved) rows = before;
		} catch {
			rows = before;
		}
	}
</script>

<div class="saved-view">
	{#if loading}
		<div class="saved-view__loading"><Spinner /></div>
	{:else if error}
		<EmptyState title={t('chat.saved.error')}>
			{#snippet action()}
				<Button variant="secondary" size="sm" onclick={() => void load()}>{t('common.retry')}</Button>
			{/snippet}
		</EmptyState>
	{:else if rows.length === 0}
		<EmptyState title={t('chat.saved.empty')} />
	{:else}
		<ul class="saved-view__list">
			{#each rows as m (m.messageId)}
				<li>
					<button type="button" class="saved-view__row" onclick={() => onJump(m.channelId, m.seq)}>
						<span class="saved-view__row-head">
							<span class="saved-view__channel">{channelLabel(m.channelId)}</span>
							<span class="saved-view__time">{formatTime(m.createdAt)}</span>
						</span>
						<span class="saved-view__snippet">{snippet(m)}</span>
					</button>
					<button type="button" class="saved-view__unsave" aria-label={t('chat.row.unsave')} onclick={(e) => unsave(m, e)}>
						<Icon name="Bookmark" size={14} />
					</button>
				</li>
			{/each}
		</ul>
	{/if}
</div>

<style>
	.saved-view {
		flex: 1;
		min-height: 0;
		overflow-y: auto;
	}
	.saved-view__loading {
		display: flex;
		align-items: center;
		justify-content: center;
		height: 100%;
	}
	.saved-view__list {
		list-style: none;
		margin: 0;
		padding: var(--space-3);
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		max-width: 640px;
	}
	.saved-view__list li {
		display: flex;
		align-items: stretch;
		gap: 2px;
	}
	.saved-view__row {
		flex: 1;
		min-width: 0;
		display: flex;
		flex-direction: column;
		gap: 2px;
		text-align: left;
		border: 1px solid var(--border-subtle);
		background: var(--surface-card);
		cursor: pointer;
		padding: var(--space-2) var(--space-3);
		border-radius: var(--radius-sm);
	}
	.saved-view__row:hover {
		background: var(--surface-hover);
	}
	.saved-view__row-head {
		display: flex;
		align-items: baseline;
		gap: var(--space-2);
	}
	.saved-view__channel {
		font-size: var(--text-xs);
		font-weight: 600;
		color: var(--text-primary);
	}
	.saved-view__time {
		font-size: var(--text-2xs);
		color: var(--text-caption);
	}
	.saved-view__snippet {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.saved-view__unsave {
		flex: none;
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 32px;
		border: none;
		background: transparent;
		color: var(--text-caption);
		cursor: pointer;
		border-radius: var(--radius-sm);
	}
	.saved-view__unsave:hover {
		background: var(--surface-hover);
		color: var(--danger-solid);
	}
</style>
