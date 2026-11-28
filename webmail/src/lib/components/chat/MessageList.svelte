<svelte:options runes={true} />

<script module lang="ts">
	// Pure, DOM-free so the ≤80px stick-to-bottom rule (Design F2) is testable
	// without simulating real layout metrics in jsdom.
	export const NEAR_BOTTOM_PX = 80;
	export function isNearBottom(scrollTop: number, scrollHeight: number, clientHeight: number): boolean {
		return scrollHeight - scrollTop - clientHeight <= NEAR_BOTTOM_PX;
	}
	const NEAR_TOP_PX = 40; // prepend trigger threshold
</script>

<script lang="ts">
	// MessageList — Task 14 (scroll/watermark/typing shell), rows now rendered
	// by MessageRow (Task 15). Renders the active channel's top-level timeline
	// (thread replies never appear here — chat_messages_list already filters
	// them server-side; the client-side filter below only matters for rows
	// that arrive via chat_messages_since's reconnect replay, which returns
	// EVERY row incl. replies). `roster` resolves author display names/roles
	// for MessageRow — fetched once per channel by ChatApp and passed straight
	// through (single fetch, not duplicated per row).
	import { tick } from 'svelte';
	import { chatStore } from '$lib/chat/store.svelte';
	import * as chatApi from '$lib/chat/api';
	import type { RosterMember } from '$lib/chat/api';
	import MessageRow, { sameGroup } from './MessageRow.svelte';
	import Icon from '$lib/components/Icon.svelte';
	import { t, formatDate } from '$lib/i18n';

	// Task 16: calendar-day dividers, independent of the "New" unread divider
	// above. Grouping is by LOCAL calendar day (not a 24h rolling window), so
	// "Yesterday at 11pm" and "Today at 1am" correctly fall on either side of a
	// divider even though they're <24h apart.
	function startOfLocalDay(d: Date): number {
		return new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
	}
	function isNewDay(prev: { createdAt: string } | undefined, cur: { createdAt: string }): boolean {
		if (!prev) return true;
		return startOfLocalDay(new Date(prev.createdAt)) !== startOfLocalDay(new Date(cur.createdAt));
	}
	function dayLabel(iso: string): string {
		const diffDays = Math.round((startOfLocalDay(new Date()) - startOfLocalDay(new Date(iso))) / 86_400_000);
		if (diffDays === 0) return t('chat.messageList.dateToday');
		if (diffDays === 1) return t('chat.messageList.dateYesterday');
		return formatDate(iso, 'medium');
	}

	let {
		channelId,
		roster = [],
		selfUserId = null,
		onOpenThread,
	}: {
		channelId: number;
		roster?: RosterMember[];
		selfUserId?: number | null;
		onOpenThread?: (messageId: number) => void;
	} = $props();

	let canModerate = $derived.by(() => {
		const role = roster.find((m) => m.userId === selfUserId)?.role;
		return role === 'owner' || role === 'admin';
	});
	// Pillar C2 Task 7 — threaded to MessageRow so its edit/delete
	// confirmations can carry the ratified Q1 divergence warning ONLY inside
	// a federated room (a plain channel/DM keeps its existing, warning-free
	// flow). Read the same way ChatApp/ThreadPane already read
	// chatStore.conversations for their own per-channel federation state.
	let isFederatedRoom = $derived(
		chatStore.conversations.find((c) => c.channelId === channelId)?.federatedRoomId != null,
	);
	// Pillar C1 Task 3: authorId is null for a federated inbound message —
	// fall back to the remote address (federatedSenderAddr) instead of the
	// roster lookup, which only ever contains the local member.
	function authorName(authorId: number | null, federatedSenderAddr?: string | null): string {
		if (authorId == null) return federatedSenderAddr ?? t('chat.dm.federatedUnknownSender');
		return roster.find((m) => m.userId === authorId)?.displayName ?? String(authorId);
	}

	let containerEl = $state<HTMLDivElement | undefined>();

	// ── top-level messages, ascending ─────────────────────────────────────
	let messages = $derived((chatStore.messagesByChannel[channelId] ?? []).filter((m) => m.parentMessageId == null));

	// ── "New" divider — frozen at the lastReadSeq this session started with ──
	let frozenLastReadSeq = $state(0);
	let dividerMessageId = $derived.by(() => {
		const idx = messages.findIndex((m) => m.seq > frozenLastReadSeq);
		return idx === -1 ? null : messages[idx].messageId;
	});

	// ── per-channel session state, reset whenever channelId changes ─────────
	let exhausted = $state(false);
	let loadingOlder = $state(false);
	let focusedIndex = $state(-1);
	let prevLength = $state(0);
	let prevLastMessageId = $state<number | null>(null);
	let skipAnnounce = $state(true);
	let announcement = $state('');

	// Plain (non-reactive) instance field, deliberately NOT `$state` — this is
	// a one-shot latch, not UI state. Guards the freeze so it reads
	// `chatStore.conversations` exactly once per channel-open: the effect's
	// dependency set is recomputed fresh on every run, so once this guard
	// short-circuits BEFORE touching `conversations`, that read (and its
	// dependency) drops off — a later `lastReadSeq` bump (e.g. our own
	// mark-read) can no longer re-invalidate this effect and drag the
	// divider along with it.
	let frozenForChannelId: number | null = null;

	$effect(() => {
		const cid = channelId;
		if (frozenForChannelId === cid) return;
		frozenForChannelId = cid;
		const conv = chatStore.conversations.find((c) => c.channelId === cid);
		frozenLastReadSeq = conv?.lastReadSeq ?? 0;
		exhausted = false;
		loadingOlder = false;
		focusedIndex = -1;
		prevLength = 0;
		prevLastMessageId = null;
		skipAnnounce = true;
		announcement = '';
	});

	// ── autoscroll / mark-read / aria-live on tail growth (new message) ──────
	// Structural diff, not a seq/length heuristic: a PREPEND also grows the
	// array but leaves the last element unchanged, so it's correctly ignored
	// here (loadOlder's own tick handles that scroll anchor separately). An
	// edit/delete/reaction merge is in-place (no length change) and is also
	// correctly ignored.
	$effect(() => {
		const list = messages;
		const currentLast = list.length ? list[list.length - 1].messageId : null;
		const grew = list.length > prevLength;
		const tailChanged = currentLast !== prevLastMessageId;
		if (grew && tailChanged) {
			if (chatStore.atBottom) {
				void tick().then(() => {
					if (containerEl) containerEl.scrollTop = containerEl.scrollHeight;
				});
			}
			markReadIfEligible();
			if (skipAnnounce) skipAnnounce = false;
			else announcement = t('chat.messageList.newMessage');
		}
		prevLength = list.length;
		prevLastMessageId = currentLast;
	});

	function markReadIfEligible(): void {
		const conv = chatStore.conversations.find((c) => c.channelId === channelId);
		if (!conv) return;
		chatStore.markReadDebounced(channelId, conv.changeSeq);
	}

	function handleScroll(): void {
		if (!containerEl) return;
		chatStore.setAtBottom(isNearBottom(containerEl.scrollTop, containerEl.scrollHeight, containerEl.clientHeight));
		if (chatStore.atBottom) markReadIfEligible();
		void maybeLoadOlder();
	}

	async function maybeLoadOlder(): Promise<void> {
		if (loadingOlder || exhausted || !containerEl) return;
		if (containerEl.scrollTop > NEAR_TOP_PX) return;
		const oldest = messages[0];
		if (!oldest) return;
		loadingOlder = true;
		const prevScrollHeight = containerEl.scrollHeight;
		const prevScrollTop = containerEl.scrollTop;
		try {
			const added = await chatStore.loadOlderMessages(channelId, oldest.seq);
			if (added === 0) {
				exhausted = true;
				return;
			}
			await tick();
			if (containerEl) containerEl.scrollTop = containerEl.scrollHeight - prevScrollHeight + prevScrollTop;
		} finally {
			loadingOlder = false;
		}
	}

	function jumpToBottom(): void {
		chatStore.setAtBottom(true);
		void tick().then(() => {
			if (containerEl) containerEl.scrollTop = containerEl.scrollHeight;
		});
	}

	$effect(() => {
		function onFocus() {
			if (chatStore.atBottom) markReadIfEligible();
		}
		window.addEventListener('focus', onFocus);
		return () => window.removeEventListener('focus', onFocus);
	});

	function handleKeydown(e: KeyboardEvent): void {
		if (e.key === 'ArrowDown') {
			e.preventDefault();
			focusedIndex = Math.min(focusedIndex + 1, messages.length - 1);
		} else if (e.key === 'ArrowUp') {
			e.preventDefault();
			focusedIndex = Math.max(focusedIndex - 1, 0);
		}
	}

	// ── typing row: this channel only, >2 collapses ──────────────────────────
	let typingHere = $derived(chatStore.typingUsers.filter((tu) => tu.channelId === channelId));
	let typingLabel = $derived.by(() => {
		if (typingHere.length === 0) return '';
		if (typingHere.length === 1) return t('chat.messageList.typingOne');
		if (typingHere.length === 2) return t('chat.messageList.typingTwo');
		return t('chat.messageList.typingSeveral');
	});

</script>

<div class="ml">
	<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
	<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
	<div
		class="ml__scroll"
		data-testid="message-list-scroll"
		role="log"
		tabindex="0"
		aria-label={t('chat.list.title')}
		bind:this={containerEl}
		onscroll={handleScroll}
		onkeydown={handleKeydown}
	>
		{#if messages.length === 0}
			<div class="ml__empty">{t('chat.messageList.empty')}</div>
		{:else}
			<ul class="ml__items">
				{#each messages as m, i (m.messageId)}
					{#if isNewDay(messages[i - 1], m)}
						<li class="ml__date-divider" data-testid="date-divider" role="separator">
							<span>{dayLabel(m.createdAt)}</span>
						</li>
					{/if}
					{#if m.messageId === dividerMessageId}
						<li class="ml__divider" data-testid="new-divider" aria-hidden="true">
							<span>{t('chat.messageList.newDivider')}</span>
						</li>
					{/if}
					<li>
						<MessageRow
							message={m}
							{channelId}
							showHeader={!sameGroup(messages[i - 1], m)}
							focused={i === focusedIndex}
							authorName={authorName(m.authorId, m.federatedSenderAddr)}
							isMine={m.authorId === selfUserId}
							{canModerate}
							{roster}
							{isFederatedRoom}
							{onOpenThread}
						/>
					</li>
				{/each}
			</ul>
		{/if}
	</div>

	{#if !chatStore.atBottom && chatStore.unseenBelow > 0}
		<button type="button" class="ml__jump-pill" data-testid="jump-pill" onclick={jumpToBottom}>
			<Icon name="ChevronDown" size={14} />
			{t('chat.messageList.jumpToLatest', { n: String(chatStore.unseenBelow) })}
		</button>
	{/if}

	{#if typingLabel}
		<div class="ml__typing" data-testid="typing-row">{typingLabel}</div>
	{/if}

	<div aria-live="polite" class="sr-only" data-testid="chat-live-region">{announcement}</div>
</div>

<style>
	.ml {
		position: relative;
		display: flex;
		flex-direction: column;
		flex: 1;
		min-height: 0;
	}
	.ml__scroll {
		flex: 1;
		min-height: 0;
		overflow-y: auto;
		outline: none;
	}
	.ml__empty {
		display: flex;
		align-items: center;
		justify-content: center;
		height: 100%;
		color: var(--text-caption);
		font-size: var(--text-sm);
	}
	.ml__items {
		list-style: none;
		margin: 0;
		padding: var(--space-3);
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.ml__divider {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		margin: var(--space-2) 0;
		color: var(--danger-solid);
		font-size: var(--text-2xs);
		font-weight: 600;
		text-transform: uppercase;
	}
	.ml__divider::before,
	.ml__divider::after {
		content: '';
		flex: 1;
		height: 1px;
		background: var(--danger-solid);
	}
	.ml__date-divider {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		margin: var(--space-2) 0;
		color: var(--text-caption);
		font-size: var(--text-2xs);
		font-weight: 600;
	}
	.ml__date-divider::before,
	.ml__date-divider::after {
		content: '';
		flex: 1;
		height: 1px;
		background: var(--border-default);
	}
	/* .ml__row/--focused/__author/__time/__body/__reply-chip now live in
	   MessageRow.svelte's own scoped styles (Task 15) — this file only lays
	   out the scroll shell around whatever MessageRow renders. */
	.ml__jump-pill {
		position: absolute;
		bottom: var(--space-3);
		left: 50%;
		transform: translateX(-50%);
		display: inline-flex;
		align-items: center;
		gap: 4px;
		border: none;
		border-radius: var(--radius-full);
		background: var(--accent);
		color: var(--text-inverse);
		padding: var(--space-1) var(--space-3);
		font-size: var(--text-xs);
		font-weight: 600;
		cursor: pointer;
		box-shadow: var(--shadow-md);
	}
	.ml__typing {
		padding: 0 var(--space-3) var(--space-1);
		font-size: var(--text-xs);
		color: var(--text-caption);
		font-style: italic;
	}
	.sr-only {
		position: absolute;
		width: 1px;
		height: 1px;
		padding: 0;
		margin: -1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
		border: 0;
	}
</style>
