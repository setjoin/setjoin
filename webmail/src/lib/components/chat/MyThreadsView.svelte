<svelte:options runes={true} />

<script lang="ts">
	// MyThreadsView — A3 QoL Task 16. Main-pane view for the ChannelList's
	// fixed "Threads" row: threads I authored/replied-to/was-mentioned-in,
	// across every channel I'm still a member of (chat_my_threads — membership
	// re-checked at query time, chat/AGENTS.md). One-shot load on mount, same
	// posture as SavedView (no live-push arm — the aggregate unread badge in
	// ChannelList already refreshes whenever conversations reload).
	import { onMount } from 'svelte';
	import * as chatApi from '$lib/chat/api';
	import type { ChatThread } from '$lib/chat/api';
	import { chatStore } from '$lib/chat/store.svelte';
	import { EmptyState, Spinner, Badge, Button } from '$lib/components/ui';
	import { t, formatRelativeTime, localeCode } from '$lib/i18n';

	let { onJump }: { onJump: (channelId: number, seq: number) => void } = $props();

	let rows = $state<ChatThread[]>([]);
	let loading = $state(true);
	// [UX #7/#14, pipeline review] a fetch failure used to render identically
	// to "no threads" — distinguish the two, with a retry affordance.
	let error = $state(false);

	async function load(): Promise<void> {
		loading = true;
		error = false;
		try {
			rows = await chatApi.listMyThreads();
		} catch {
			rows = [];
			error = true;
		} finally {
			loading = false;
		}
	}

	onMount(() => void load());

	// ponytail: see SavedView's identical comment — DM/group_dm threads fall
	// back to the generic "Direct message" label rather than a per-row roster
	// resolve.
	function channelLabel(channelId: number): string {
		const c = chatStore.conversations.find((cv) => cv.channelId === channelId);
		return c?.name ?? t('chat.list.unknownDm');
	}

	function replyLabel(n: number): string {
		return n === 1 ? t('chat.messageList.replyCountOne') : t('chat.messageList.replyCount', { n: String(n) });
	}

	function formatTime(iso: string | null): string {
		if (!iso) return '';
		const diffSec = (Date.now() - new Date(iso).getTime()) / 1000;
		if (diffSec < 60) return t('chat.time.justNow');
		if (diffSec < 3600) return formatRelativeTime(-Math.round(diffSec / 60), 'minute');
		if (diffSec < 86400) return formatRelativeTime(-Math.round(diffSec / 3600), 'hour');
		return new Intl.DateTimeFormat(localeCode(), { hour: '2-digit', minute: '2-digit' }).format(new Date(iso));
	}
</script>

<div class="threads-view">
	{#if loading}
		<div class="threads-view__loading"><Spinner /></div>
	{:else if error}
		<EmptyState title={t('chat.threads.error')}>
			{#snippet action()}
				<Button variant="secondary" size="sm" onclick={() => void load()}>{t('common.retry')}</Button>
			{/snippet}
		</EmptyState>
	{:else if rows.length === 0}
		<EmptyState title={t('chat.threads.empty')} />
	{:else}
		<ul class="threads-view__list">
			{#each rows as th (th.messageId)}
				<li>
					<button type="button" class="threads-view__row" onclick={() => onJump(th.channelId, th.seq)}>
						<span class="threads-view__row-head">
							<span class="threads-view__channel">{channelLabel(th.channelId)}</span>
							<span class="threads-view__time">{formatTime(th.lastReplyAt)}</span>
						</span>
						<span class="threads-view__snippet">{th.body}</span>
						<span class="threads-view__meta">
							<span class="threads-view__replies">{replyLabel(th.replyCount)}</span>
							{#if th.unreadCount > 0}
								<Badge count={th.unreadCount} />
							{/if}
						</span>
					</button>
				</li>
			{/each}
		</ul>
	{/if}
</div>

<style>
	.threads-view {
		flex: 1;
		min-height: 0;
		overflow-y: auto;
	}
	.threads-view__loading {
		display: flex;
		align-items: center;
		justify-content: center;
		height: 100%;
	}
	.threads-view__list {
		list-style: none;
		margin: 0;
		padding: var(--space-3);
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		max-width: 640px;
	}
	.threads-view__row {
		width: 100%;
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
	.threads-view__row:hover {
		background: var(--surface-hover);
	}
	.threads-view__row-head {
		display: flex;
		align-items: baseline;
		justify-content: space-between;
		gap: var(--space-2);
	}
	.threads-view__channel {
		font-size: var(--text-xs);
		font-weight: 600;
		color: var(--text-primary);
	}
	.threads-view__time {
		font-size: var(--text-2xs);
		color: var(--text-caption);
	}
	.threads-view__snippet {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.threads-view__meta {
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}
	.threads-view__replies {
		font-size: var(--text-2xs);
		color: var(--text-caption);
	}
</style>
