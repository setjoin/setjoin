<svelte:options runes={true} />

<script lang="ts">
	// ThreadPane — Task 15. Renders in the dock's third region on desktop
	// (mobile: pushed view) — the layout/mobile-stack CSS for that region
	// lives in ChatApp.svelte (matching how it already owns MessageList's own
	// mobile treatment), so this file stays layout-agnostic (fill its
	// container, no fixed positioning of its own).
	//
	// Read model: chat_thread_list (via chatApi.threadMessages) seeds the
	// initial root+replies set; from then on this pane reads the SAME live
	// chatStore.messagesByChannel[channelId] array MessageList reads (every
	// push event — reply, edit, delete, reaction — lands there via
	// applyEvent), so a brand-new reply typed by anyone while the thread is
	// open appears without a second fetch. The seed only supplies which ids
	// belong to this thread and their fallback content before the channel
	// array catches up.
	import { chatStore, type StoreMessage } from '$lib/chat/store.svelte';
	import * as chatApi from '$lib/chat/api';
	import type { RosterMember } from '$lib/chat/api';
	import MessageRow, { sameGroup } from './MessageRow.svelte';
	import Composer from './Composer.svelte';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';

	let {
		parentId,
		channelId,
		roster = [],
		selfUserId = null,
		canModerate = false,
		canBroadcast = false,
		composerDisabled = false,
		composerDisabledMessage,
		noAttachments = false,
		onClose,
	}: {
		parentId: number;
		channelId: number;
		roster?: RosterMember[];
		selfUserId?: number | null;
		canModerate?: boolean;
		canBroadcast?: boolean;
		composerDisabled?: boolean;
		/** Pillar C2 Task 7 — threaded straight through to Composer's own
		 *  disabledMessage/noAttachments (see Composer.svelte). */
		composerDisabledMessage?: string;
		noAttachments?: boolean;
		onClose: () => void;
	} = $props();

	let seedRows = $state<StoreMessage[]>([]);
	let loading = $state(true);
	let lastParentId: number | null = null;

	$effect(() => {
		const pid = parentId;
		if (lastParentId === pid) return;
		lastParentId = pid;
		loading = true;
		chatApi
			.threadMessages(pid)
			.then((rows) => {
				seedRows = rows.map((m) => ({ ...m, status: 'sent' as const }));
			})
			.catch(() => {
				seedRows = [];
			})
			.finally(() => {
				loading = false;
			});
	});

	// Pillar C2 Task 7 — same signal MessageList derives, threaded to this
	// pane's own MessageRow instances so a thread reply's edit/delete
	// confirmations carry the divergence warning inside a federated room too.
	let isFederatedRoom = $derived(chatStore.conversations.find((c) => c.channelId === channelId)?.federatedRoomId != null);

	let rows = $derived.by(() => {
		const channelRows = chatStore.messagesByChannel[channelId] ?? [];
		const live = channelRows.filter((r) => r.messageId === parentId || r.parentMessageId === parentId);
		const byId = new Map<number, StoreMessage>();
		for (const r of seedRows) byId.set(r.messageId, r);
		for (const r of live) byId.set(r.messageId, r); // live push data supersedes the seed
		return [...byId.values()].sort((a, b) => a.seq - b.seq);
	});

	// Pillar C1 Task 3: authorId is null for a federated inbound message —
	// fall back to the remote address (federatedSenderAddr) instead of the
	// roster lookup, which only ever contains the local member.
	function authorName(authorId: number | null, federatedSenderAddr?: string | null): string {
		if (authorId == null) return federatedSenderAddr ?? t('chat.dm.federatedUnknownSender');
		return roster.find((m) => m.userId === authorId)?.displayName ?? String(authorId);
	}
</script>

<div class="thread-pane">
	<div class="thread-pane__header">
		<span class="thread-pane__title">{t('chat.thread.title')}</span>
		<button type="button" class="thread-pane__close" aria-label={t('chat.thread.close')} onclick={onClose}>
			<Icon name="X" size={16} />
		</button>
	</div>
	<div class="thread-pane__scroll">
		{#if loading && rows.length === 0}
			<div class="thread-pane__loading">{t('common.loading')}</div>
		{:else}
			<ul class="thread-pane__list">
				{#each rows as m, i (m.messageId)}
					<li>
						<MessageRow
							message={m}
							{channelId}
							showHeader={!sameGroup(rows[i - 1], m)}
							authorName={authorName(m.authorId, m.federatedSenderAddr)}
							isMine={m.authorId === selfUserId}
							{canModerate}
							{roster}
							{isFederatedRoom}
						/>
					</li>
				{/each}
			</ul>
		{/if}
	</div>
	<Composer
		{channelId}
		{parentId}
		{canBroadcast}
		disabled={composerDisabled}
		disabledMessage={composerDisabledMessage}
		{noAttachments}
	/>
</div>

<style>
	.thread-pane {
		display: flex;
		flex-direction: column;
		height: 100%;
		min-width: 0;
		border-left: 1px solid var(--border-default);
		background: var(--surface-card);
	}
	.thread-pane__header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: var(--space-2) var(--space-3);
		border-bottom: 1px solid var(--border-subtle);
		min-height: 44px;
	}
	.thread-pane__title {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-secondary);
	}
	.thread-pane__close {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-width: 44px;
		min-height: 44px;
		border: none;
		background: transparent;
		color: var(--text-secondary);
		cursor: pointer;
		border-radius: var(--radius-sm);
	}
	.thread-pane__close:hover {
		background: var(--surface-hover);
	}
	.thread-pane__scroll {
		flex: 1;
		min-height: 0;
		overflow-y: auto;
	}
	.thread-pane__loading {
		display: flex;
		align-items: center;
		justify-content: center;
		height: 100%;
		color: var(--text-caption);
		font-size: var(--text-sm);
	}
	.thread-pane__list {
		list-style: none;
		margin: 0;
		padding: var(--space-3);
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
</style>
