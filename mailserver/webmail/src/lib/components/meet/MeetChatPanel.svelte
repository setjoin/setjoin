<svelte:options runes={true} />

<script lang="ts">
	// MeetChatPanel — Meet B1 Task 16, spec §3.3 bridge: a meeting's chat IS
	// an ordinary chat_channels row — this renders the EXISTING chat
	// MessageList/Composer bound to `channelId`, zero new message plumbing.
	// Capability-gated on apps.chat by the CALLER (MeetApp) — with
	// feature.chat OFF this component is simply not mounted, the meeting
	// stays otherwise fully functional (the reducers still bind/post
	// regardless; toggles gate routes, not reducers).
	//
	// Layout: right-docked panel on desktop, full-height sheet on mobile
	// (the chat mobile-stack precedent) — driven by CSS only, no separate
	// mobile markup. The guest-visibility note (`hasGuestParticipant`) is a
	// persistent header, never conditional on scroll position — in a
	// compliance product "who can read this" is never ambiguous.
	//
	// B3 Task 8 — Q&A tab (spec §4.2 zero-backend verdict): a client-side
	// filter over the SAME chatStore.messagesByChannel data MessageList
	// already reads — no new store field, no new reducer. A question is an
	// ordinary chat message (msgType='question', Task 3's route allowlist);
	// upvote is the existing reactions '👍' count via chatStore.toggleReaction;
	// the D9 "Answered" badge is derived from chatApi.threadMessages(parentId)
	// ONLY when a question is expanded (never eagerly for every row — that
	// would be a fetch per question just to paint a badge nobody may look
	// at). "host/cohost" for D9 has no dedicated roster+meeting-role route
	// client-side (see MeetApp.svelte's sheetParticipants ponytail note —
	// the same accepted gap); the channel roster's OWN role IS an accurate
	// proxy here: chat_channel_create seeds the meeting's creator (the
	// meeting host) as channel role 'owner' (chat_channel.sql), and
	// meeting_join never role-bumps anyone else, so 'owner'/'admin' in the
	// already-fetched `roster` is the host/cohost signal without a new read
	// route. Also exposes openPollDialog() (bind:this target) — switches to
	// the chat tab (Composer only mounts there) and delegates into
	// Composer's OWN openPollDialog (Composer.svelte:307), never duplicated.
	import { onMount, tick } from 'svelte';
	import { chatStore, chatErrorMessage, type StoreMessage } from '$lib/chat/store.svelte';
	import * as chatApi from '$lib/chat/api';
	import type { ChatWireEvent, RosterMember } from '$lib/chat/api';
	import { subscribeEvent } from '$lib/jmap/websocket';
	import { subscribeGuestChatEvents } from '$lib/chat/guestEventSource';
	import { isGuestSession } from '$lib/stores/session';
	import { user } from '$lib/stores/auth';
	import MessageList from '$lib/components/chat/MessageList.svelte';
	import Composer from '$lib/components/chat/Composer.svelte';
	import { IconButton, Tabs, Badge, EmptyState, Input, showToast } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';

	let {
		channelId,
		hasGuestParticipant = false,
		onClose,
	}: {
		channelId: number;
		hasGuestParticipant?: boolean;
		onClose?: () => void;
	} = $props();

	let roster = $state<RosterMember[]>([]);
	let activeTab = $state<'chat' | 'qa'>('chat');
	let composerRef = $state<Composer | null>(null);

	// [UX #2b, pipeline review] this panel used to never call
	// chatStore.loadConversations() — MessageList's markReadIfEligible looks
	// up the channel in chatStore.conversations before it marks anything
	// read (see MessageList.svelte), and openChannel() below never populates
	// that array (only loadConversations does). A caller who opens MeetApp
	// without ever having visited /chat this session read every in-meeting
	// message live yet none of it was ever marked read — a phantom unread
	// left behind once the meeting ends. Best-effort: a stale/failed load
	// just means mark-read stays a no-op until the next successful one,
	// never blocks the panel from rendering.
	onMount(() => {
		void chatStore.loadConversations();
	});

	$effect(() => {
		const cid = channelId;
		void chatStore.openChannel(cid);
		chatApi
			.listMembers(cid)
			.then((r) => (roster = r))
			.catch(() => (roster = []));
	});

	$effect(() => {
		const handler = (evt: ChatWireEvent) => void chatStore.applyEvent(evt);
		const guestSession = $user?.accountType === 'guest' || $isGuestSession;
		return guestSession
			? subscribeGuestChatEvents(handler, () => void chatStore.onSocketOpen())
			: subscribeEvent<ChatWireEvent>('ChatEvent', handler);
	});

	/** B3 Task 8: switches to the chat tab (mounting Composer, which the Q&A
	 *  tab keeps unmounted) then delegates to its EXISTING poll dialog. */
	export async function openPollDialog(): Promise<void> {
		activeTab = 'chat';
		await tick();
		composerRef?.openPollDialog();
	}

	function upvoteCount(m: StoreMessage): number {
		return m.reactions.find((r) => r.emoji === '👍')?.count ?? 0;
	}

	let questions = $derived.by(() => {
		const rows = chatStore.messagesByChannel[channelId] ?? [];
		return rows
			.filter((m) => m.msgType === 'question' && m.parentMessageId == null && m.deletedAt == null)
			.slice()
			.sort((a, b) => upvoteCount(b) - upvoteCount(a) || a.seq - b.seq);
	});

	// Pillar C1 Task 3 widened ChatMessage.authorId to `number | null` (a
	// federated inbound message has no local author) — a meeting's bridged
	// chat channel is never a federated DM (meeting_create never sets
	// chat_channels.federated_peer_domain), so userId is null here only
	// defensively, never in practice.
	function authorName(userId: number | null): string {
		if (userId == null) return t('chat.dm.federatedUnknownSender');
		return roster.find((m) => m.userId === userId)?.displayName ?? String(userId);
	}

	/** D9's host/cohost proxy — see the file-header note. */
	function isHostOrCohostAuthor(userId: number | null): boolean {
		if (userId == null) return false;
		const role = roster.find((m) => m.userId === userId)?.role;
		return role === 'owner' || role === 'admin';
	}

	let expandedQuestionId = $state<number | null>(null);
	let threadLoading = $state<number | null>(null);
	let repliesByQuestion = $state<Record<number, StoreMessage[]>>({});
	let answeredByQuestion = $state<Record<number, boolean>>({});

	async function toggleExpand(messageId: number): Promise<void> {
		if (expandedQuestionId === messageId) {
			expandedQuestionId = null;
			return;
		}
		expandedQuestionId = messageId;
		if (repliesByQuestion[messageId]) return;
		threadLoading = messageId;
		try {
			const rows = await chatApi.threadMessages(messageId);
			const replies = rows.filter((r) => r.messageId !== messageId).map((r) => ({ ...r, status: 'sent' as const }));
			repliesByQuestion = { ...repliesByQuestion, [messageId]: replies };
			answeredByQuestion = { ...answeredByQuestion, [messageId]: replies.some((r) => isHostOrCohostAuthor(r.authorId)) };
		} catch {
			repliesByQuestion = { ...repliesByQuestion, [messageId]: [] };
		} finally {
			threadLoading = null;
		}
	}

	function upvote(messageId: number): void {
		void chatStore.toggleReaction(channelId, messageId, '👍');
	}

	let questionDraft = $state('');
	let askBusy = $state(false);

	async function submitQuestion(e: SubmitEvent): Promise<void> {
		e.preventDefault();
		const body = questionDraft.trim();
		if (!body || askBusy) return;
		askBusy = true;
		try {
			await chatApi.sendMessage(channelId, body, null, [], null, [], 'question');
			questionDraft = '';
		} catch (err) {
			showToast(chatErrorMessage(err), { variant: 'danger' });
		} finally {
			askBusy = false;
		}
	}
</script>

<div class="meet-chat">
	<div class="meet-chat__header">
		<Tabs
			items={[
				{ id: 'chat', label: t('app.chat') },
				{ id: 'qa', label: t('meet.qa.tab') },
			]}
			active={activeTab}
			onChange={(id) => (activeTab = id as 'chat' | 'qa')}
		/>
		{#if onClose}
			<IconButton label={t('common.close')} size="sm" onclick={onClose}>
				<Icon name="X" size={16} />
			</IconButton>
		{/if}
	</div>
	{#if hasGuestParticipant}
		<div class="meet-chat__guest-notice" role="note" data-testid="meet-chat-guest-notice">
			<Icon name="ShieldAlert" size={14} />
			{t('meet.chat.guestNotice')}
		</div>
	{/if}
	{#if activeTab === 'chat'}
		<div class="meet-chat__body">
			<MessageList {channelId} {roster} selfUserId={chatStore.selfUserId} />
		</div>
		<Composer bind:this={composerRef} {channelId} />
	{:else}
		<div class="meet-chat__body meet-chat__qa">
			{#if questions.length === 0}
				<EmptyState title={t('meet.qa.empty')} />
			{:else}
				<ul class="qa-list" role="list">
					{#each questions as q (q.messageId)}
						{@const expanded = expandedQuestionId === q.messageId}
						<li class="qa-item" data-testid="qa-item-{q.messageId}">
							<button
								type="button"
								class="qa-item__toggle"
								aria-expanded={expanded}
								data-testid="qa-item-{q.messageId}-toggle"
								onclick={() => toggleExpand(q.messageId)}
							>
								<Icon name={expanded ? 'ChevronUp' : 'ChevronDown'} size={14} />
								<span class="qa-item__author">{authorName(q.authorId)}</span>
								{#if answeredByQuestion[q.messageId]}
									<Badge variant="success" label={t('meet.qa.answered')} />
								{/if}
							</button>
							<p class="qa-item__body">{q.body}</p>
							<div class="qa-item__footer">
								<button
									type="button"
									class="qa-item__upvote"
									aria-pressed={q.reactions.some((r) => r.emoji === '👍' && r.mine)}
									data-testid="qa-item-{q.messageId}-upvote"
									onclick={() => upvote(q.messageId)}
								>
									👍 {upvoteCount(q)}
								</button>
								{#if q.replyCount > 0}
									<span class="qa-item__replies">{q.replyCount}</span>
								{/if}
							</div>
							{#if expanded}
								<div class="qa-item__thread">
									{#if threadLoading === q.messageId}
										<span class="qa-item__loading">{t('common.loading')}</span>
									{:else}
										{#each repliesByQuestion[q.messageId] ?? [] as r (r.messageId)}
											<div class="qa-item__reply">
												<span class="qa-item__reply-author">{authorName(r.authorId)}</span>
												<span>{r.body}</span>
											</div>
										{/each}
									{/if}
								</div>
							{/if}
						</li>
					{/each}
				</ul>
			{/if}
			<form class="qa-ask" onsubmit={submitQuestion}>
				<Input
					bind:value={questionDraft}
					placeholder={t('meet.qa.ask')}
					aria-label={t('meet.qa.ask')}
					disabled={askBusy}
				/>
				<IconButton type="submit" label={t('meet.qa.ask')} disabled={askBusy || questionDraft.trim().length === 0}>
					<Icon name="Send" size={16} />
				</IconButton>
			</form>
		</div>
	{/if}
</div>

<style>
	.meet-chat {
		display: flex;
		flex-direction: column;
		height: 100%;
		min-width: 0;
		border-left: 1px solid var(--border-subtle);
		background: var(--surface-card);
	}
	.meet-chat__header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 0 var(--space-2);
		border-bottom: 1px solid var(--border-subtle);
		min-height: 44px;
	}
	.meet-chat__guest-notice {
		display: flex;
		align-items: center;
		gap: var(--space-1);
		padding: var(--space-1) var(--space-3);
		font-size: var(--text-2xs);
		color: var(--warning-fg);
		background: var(--warning-bg);
	}
	.meet-chat__body {
		flex: 1;
		min-height: 0;
	}
	.meet-chat__qa {
		display: flex;
		flex-direction: column;
		min-height: 0;
	}
	.qa-list {
		list-style: none;
		margin: 0;
		padding: var(--space-3);
		flex: 1;
		min-height: 0;
		overflow-y: auto;
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.qa-item {
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-md);
		padding: var(--space-2);
	}
	.qa-item__toggle {
		display: flex;
		align-items: center;
		gap: var(--space-1);
		width: 100%;
		border: none;
		background: transparent;
		padding: 0;
		cursor: pointer;
		color: var(--text-primary);
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		text-align: left;
	}
	.qa-item__author {
		flex: 1;
		min-width: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.qa-item__body {
		margin: var(--space-1) 0 0;
		font-size: var(--text-sm);
		color: var(--text-secondary);
		white-space: pre-wrap;
	}
	.qa-item__footer {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		margin-top: var(--space-2);
	}
	.qa-item__upvote {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		min-height: 26px;
		padding: 0 var(--space-2);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-full);
		background: var(--surface-page);
		color: var(--text-secondary);
		font-size: var(--text-xs);
		cursor: pointer;
	}
	.qa-item__upvote[aria-pressed='true'] {
		border-color: var(--accent);
		color: var(--text-accent);
		background: var(--accent-subtle);
	}
	.qa-item__replies {
		font-size: var(--text-2xs);
		color: var(--text-caption);
	}
	.qa-item__thread {
		margin-top: var(--space-2);
		padding-top: var(--space-2);
		border-top: 1px solid var(--border-subtle);
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.qa-item__loading {
		font-size: var(--text-xs);
		color: var(--text-caption);
	}
	.qa-item__reply {
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}
	.qa-item__reply-author {
		font-weight: var(--weight-medium);
		margin-right: var(--space-1);
		color: var(--text-primary);
	}
	.qa-ask {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-2) var(--space-3);
		border-top: 1px solid var(--border-subtle);
		flex: none;
	}
	.qa-ask :global(.sj-field) {
		flex: 1;
	}

	@media (max-width: 767px) {
		.meet-chat {
			position: fixed;
			inset: 0;
			z-index: 30;
			border-left: none;
		}
	}
</style>
