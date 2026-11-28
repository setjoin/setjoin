<svelte:options runes={true} />

<script lang="ts">
	import { Spinner, EmptyState, Button, IconButton, Tabs } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import MailRow from './MailRow.svelte';
	import { setOpenSwipeRowId } from './mailRowSwipe.svelte';
	import type { Email, Mailbox } from '$lib/types/jmap';
	import type { MailWorkItem } from '$lib/mail/mailWork';
	import { t } from '$lib/i18n';

	interface ThreadData {
		id: string;
		emails: Email[];
		expanded: boolean;
		muted: boolean;
	}

	/**
	 * The message-list action facade (candidate 7 — EmailActionStore seam). The
	 * coordinator passes ONE `actions` object instead of the individual per-row /
	 * per-thread callbacks; the individual props remain the fallback (and win when
	 * `actions` is absent) so existing render-with-callbacks tests stay green.
	 */
	export interface MessageListActions {
		onOpen: (email: Email) => void;
		onArchive: (email: Email) => void;
		onStar: (email: Email) => void;
		onTrash: (email: Email) => void;
		onToggleRead?: (email: Email, read: boolean) => void;
		onToggleThread: (threadId: string) => void;
		onMuteThread: (threadId: string) => void;
		onArchiveThread: (threadId: string) => void;
		onLoadMore: () => void;
		onCancelScheduled?: (emailId: string) => void;
		/** Move a row to Focused/Other (V078). When set, MailRow shows a move button. */
		onMoveFocus?: (email: Email, focused: boolean) => void;
		/** Swipe/long-press tray "Snooze" (QoL #2). When set, MailRow's tray shows a
		 *  Snooze button that opens the SnoozePicker inline. */
		onSnooze?: (email: Email, date: Date) => void;
	}

	interface Props {
		threads: ThreadData[];
		viewMode: 'flat' | 'threaded';
		selectedId: string | null;
		/** Resolved tag mailboxes for chip rendering (passed through to MailRow). */
		tags: Mailbox[];
		loading: boolean;
		loadingMore: boolean;
		hasMore: boolean;
		remaining: number;
		/**
		 * The action facade (candidate 7). When provided, its members supply the
		 * row/thread callbacks; the individual props below are the fallback.
		 */
		actions?: MessageListActions;
		onOpen?: (email: Email) => void;
		onArchive?: (email: Email) => void;
		onStar?: (email: Email) => void;
		onTrash?: (email: Email) => void;
		/** Mark read/unread toggle per row (email, desired read state). Optional. */
		onToggleRead?: (email: Email, read: boolean) => void;
		onToggleThread?: (threadId: string) => void;
		onMuteThread?: (threadId: string) => void;
		onArchiveThread?: (threadId: string) => void;
		onLoadMore?: () => void;
		/** Scheduled sendAt timestamps keyed by emailId. When set, MailRow shows sendAt instead of receivedAt. */
		scheduledTimes?: Record<string, string>;
		/** Cancel-scheduled callback (emailId). When set, MailRow shows a Cancel button. */
		onCancelScheduled?: (emailId: string) => void;
		/** The `Other` pile tag id (Focused/Other split, V078). A row whose mailboxIds
		 *  include it is "Other" — flips the move button's label. */
		otherTagId?: string | null;
		/** Active Focused/Other tab (V078). Only meaningful when {@link onFocusTab} is set. */
		focusTab?: 'focused' | 'other';
		/** Unread count for the Other tab badge (V078). */
		otherUnread?: number;
		/** Switch the Focused/Other tab (V078). When set, the two-tab header renders atop
		 *  the list — the page wires this ONLY for the plain Inbox view. */
		onFocusTab?: (tab: 'focused' | 'other') => void;
		/** Reducer projections keyed by thread id; present only in shared-mail workspaces. */
		workByThread?: Record<string, MailWorkItem>;
	}

	let {
		threads = [],
		viewMode = 'flat',
		selectedId = null,
		tags = [],
		loading = false,
		loadingMore = false,
		hasMore = false,
		remaining = 0,
		actions,
		onOpen: propOnOpen,
		onArchive: propOnArchive,
		onStar: propOnStar,
		onTrash: propOnTrash,
		onToggleRead: propOnToggleRead,
		onToggleThread: propOnToggleThread,
		onMuteThread: propOnMuteThread,
		onArchiveThread: propOnArchiveThread,
		onLoadMore: propOnLoadMore,
		scheduledTimes,
		onCancelScheduled: propOnCancelScheduled,
		otherTagId = null,
		focusTab = 'focused',
		otherUnread = 0,
		onFocusTab,
		workByThread = {},
	}: Props = $props();

	// ── Action resolution ──
	// The `actions` facade (candidate 7) wins when provided; the individual props
	// are the fallback. A no-op default for the always-wired callbacks so a missing
	// callback never throws.
	const noop = () => {};
	const onOpen = $derived(actions?.onOpen ?? propOnOpen ?? noop);
	const onArchive = $derived(actions?.onArchive ?? propOnArchive ?? noop);
	const onStar = $derived(actions?.onStar ?? propOnStar ?? noop);
	const onTrash = $derived(actions?.onTrash ?? propOnTrash ?? noop);
	const onToggleRead = $derived(actions?.onToggleRead ?? propOnToggleRead);
	const onToggleThread = $derived(actions?.onToggleThread ?? propOnToggleThread ?? noop);
	const onMuteThread = $derived(actions?.onMuteThread ?? propOnMuteThread ?? noop);
	const onArchiveThread = $derived(actions?.onArchiveThread ?? propOnArchiveThread ?? noop);
	const onLoadMore = $derived(actions?.onLoadMore ?? propOnLoadMore ?? noop);
	const onCancelScheduled = $derived(actions?.onCancelScheduled ?? propOnCancelScheduled);
	const onMoveFocus = $derived(actions?.onMoveFocus);
	const onSnooze = $derived(actions?.onSnooze);

	/** A row is "Other" (Focused/Other split) when its mailboxIds carry the Other tag. */
	function isOther(email: Email): boolean {
		return otherTagId ? !!email.mailboxIds?.[otherTagId] : false;
	}

	const pinned = $derived(threads.filter((t) => t.emails[0]?.pinnedAt));
	const unpinned = $derived(threads.filter((t) => !t.emails[0]?.pinnedAt));
	const showDivider = $derived(pinned.length > 0 && unpinned.length > 0);

	/** Resolve tag mailboxes for a specific email (up to 2 chips for MailRow). */
	function tagsForEmail(email: Email): Mailbox[] {
		const ids = Object.keys(email.mailboxIds ?? {});
		return ids
			.map((id) => tags.find((t) => t.id === id))
			.filter((t): t is Mailbox => !!t)
			.slice(0, 2);
	}

	function isSelected(email: Email): boolean {
		return selectedId === email.id;
	}

	function workFor(threadId: string): MailWorkItem | undefined {
		return workByThread[threadId];
	}

	function handleThreadClick(e: MouseEvent, threadId: string) {
		const target = e.target as HTMLElement;
		if (target.closest('button')) return;
		onToggleThread(threadId);
	}

	function handleThreadKeydown(e: KeyboardEvent, threadId: string) {
		if (e.key === 'Enter' || e.key === ' ') {
			e.preventDefault();
			onToggleThread(threadId);
		}
	}

	function handleMuteClick(e: MouseEvent, threadId: string) {
		e.stopPropagation();
		onMuteThread(threadId);
	}

	function handleArchiveClick(e: MouseEvent, threadId: string) {
		e.stopPropagation();
		onArchiveThread(threadId);
	}
</script>

<div class="sj-msglist">
	{#if onFocusTab}
		<div class="sj-msglist__tabs">
			<Tabs
				items={[
					{ id: 'focused', label: 'Focused' },
					{ id: 'other', label: 'Other', count: otherUnread || null },
				]}
				active={focusTab}
				onChange={(id) => onFocusTab(id as 'focused' | 'other')}
			/>
		</div>
	{/if}
	{#if loading}
		<div class="sj-msglist__loading">
			<Spinner size={28} label="Loading messages" />
		</div>
	{:else if threads.length === 0}
		<div class="sj-msglist__empty">
			<EmptyState
				title="Nothing here. Inbox zero feels good."
				watermark={false}
			/>
		</div>
	{:else}
		<div class="sj-msglist__scroll" onscroll={() => setOpenSwipeRowId(null)}>
			{#each pinned as thread, i (thread.id)}
				{#if viewMode === 'threaded' && thread.emails.length > 1}
					<div class="sj-msglist__thread">
						<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
						<div
							class="sj-msglist__thread-header"
							class:sj-msglist__thread-header--expanded={thread.expanded}
							role="button"
							tabindex="0"
							onclick={(e) => handleThreadClick(e, thread.id)}
							onkeydown={(e) => handleThreadKeydown(e, thread.id)}
						>
							<span class="sj-msglist__thread-chevron" aria-hidden="true">
								<Icon name={thread.expanded ? 'ChevronDown' : 'ChevronRight'} size={14} strokeWidth={1.75} />
							</span>
							<span class="sj-msglist__thread-subject">
								{thread.emails[0].subject || '(no subject)'}
							</span>
							<span class="sj-msglist__thread-count">{thread.emails.length}</span>
							{#if workFor(thread.id)}
								<span class="sj-msglist__work" data-status={workFor(thread.id)?.status}>
									{t(`inbox.work.${workFor(thread.id)?.status}`)}
								</span>
							{/if}
							<span class="sj-msglist__thread-date">
								{thread.emails[0].pinnedAt ? 'Pinned' : ''}
							</span>
							<IconButton
								label={thread.muted ? 'Unmute thread' : 'Mute thread'}
								size="sm"
								onclick={(e) => handleMuteClick(e, thread.id)}
							>
								<Icon name={thread.muted ? 'BellOff' : 'Bell'} size={14} strokeWidth={1.75} />
							</IconButton>
							<IconButton
								label="Archive thread"
								size="sm"
								onclick={(e) => handleArchiveClick(e, thread.id)}
							>
								<Icon name="Archive" size={14} strokeWidth={1.75} />
							</IconButton>
						</div>
						{#if thread.expanded}
							<div class="sj-msglist__child">
								{#each thread.emails as email (email.id)}
									<MailRow
										email={email}
										tags={tagsForEmail(email)}
										selected={isSelected(email)}
										onOpen={() => onOpen(email)}
										onArchive={() => onArchive(email)}
										onStar={() => onStar(email)}
										onTrash={() => onTrash(email)}
										onToggleRead={onToggleRead ? (read) => onToggleRead(email, read) : undefined}
										sendAt={scheduledTimes?.[email.id]}
										onCancel={onCancelScheduled ? () => onCancelScheduled(email.id) : undefined}
										isOther={isOther(email)}
										onMoveFocus={onMoveFocus ? (focused) => onMoveFocus(email, focused) : undefined}
										onSnooze={onSnooze ? (date) => onSnooze(email, date) : undefined}
										workStatus={workFor(thread.id)?.status}
									/>
								{/each}
							</div>
						{/if}
					</div>
				{:else}
					{@const email = thread.emails[0]}
					<MailRow
						email={email}
						tags={tagsForEmail(email)}
						selected={isSelected(email)}
						tour={i === 0 ? 'organize' : undefined}
						onOpen={() => onOpen(email)}
						onArchive={() => onArchive(email)}
						onStar={() => onStar(email)}
						onTrash={() => onTrash(email)}
						onToggleRead={onToggleRead ? (read) => onToggleRead(email, read) : undefined}
						sendAt={scheduledTimes?.[email.id]}
						onCancel={onCancelScheduled ? () => onCancelScheduled(email.id) : undefined}
						isOther={isOther(email)}
						onMoveFocus={onMoveFocus ? (focused) => onMoveFocus(email, focused) : undefined}
						onSnooze={onSnooze ? (date) => onSnooze(email, date) : undefined}
						workStatus={workFor(thread.id)?.status}
					/>
				{/if}
			{/each}

			{#if showDivider}
				<div class="sj-msglist__divider" aria-hidden="true"></div>
			{/if}

			{#each unpinned as thread, i (thread.id)}
				{#if viewMode === 'threaded' && thread.emails.length > 1}
					<div class="sj-msglist__thread">
						<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
						<div
							class="sj-msglist__thread-header"
							class:sj-msglist__thread-header--expanded={thread.expanded}
							role="button"
							tabindex="0"
							onclick={(e) => handleThreadClick(e, thread.id)}
							onkeydown={(e) => handleThreadKeydown(e, thread.id)}
						>
							<span class="sj-msglist__thread-chevron" aria-hidden="true">
								<Icon name={thread.expanded ? 'ChevronDown' : 'ChevronRight'} size={14} strokeWidth={1.75} />
							</span>
							<span class="sj-msglist__thread-subject">
								{thread.emails[0].subject || '(no subject)'}
							</span>
							<span class="sj-msglist__thread-count">{thread.emails.length}</span>
							{#if workFor(thread.id)}
								<span class="sj-msglist__work" data-status={workFor(thread.id)?.status}>
									{t(`inbox.work.${workFor(thread.id)?.status}`)}
								</span>
							{/if}
							<span class="sj-msglist__thread-date"></span>
							<IconButton
								label={thread.muted ? 'Unmute thread' : 'Mute thread'}
								size="sm"
								onclick={(e) => handleMuteClick(e, thread.id)}
							>
								<Icon name={thread.muted ? 'BellOff' : 'Bell'} size={14} strokeWidth={1.75} />
							</IconButton>
							<IconButton
								label="Archive thread"
								size="sm"
								onclick={(e) => handleArchiveClick(e, thread.id)}
							>
								<Icon name="Archive" size={14} strokeWidth={1.75} />
							</IconButton>
						</div>
						{#if thread.expanded}
							<div class="sj-msglist__child">
								{#each thread.emails as email (email.id)}
									<MailRow
										email={email}
										tags={tagsForEmail(email)}
										selected={isSelected(email)}
										onOpen={() => onOpen(email)}
										onArchive={() => onArchive(email)}
										onStar={() => onStar(email)}
										onTrash={() => onTrash(email)}
										onToggleRead={onToggleRead ? (read) => onToggleRead(email, read) : undefined}
										sendAt={scheduledTimes?.[email.id]}
										onCancel={onCancelScheduled ? () => onCancelScheduled(email.id) : undefined}
										isOther={isOther(email)}
										onMoveFocus={onMoveFocus ? (focused) => onMoveFocus(email, focused) : undefined}
										onSnooze={onSnooze ? (date) => onSnooze(email, date) : undefined}
										workStatus={workFor(thread.id)?.status}
									/>
								{/each}
							</div>
						{/if}
					</div>
				{:else}
					{@const email = thread.emails[0]}
					<MailRow
						email={email}
						tags={tagsForEmail(email)}
						selected={isSelected(email)}
						tour={i === 0 && pinned.length === 0 ? 'organize' : undefined}
						onOpen={() => onOpen(email)}
						onArchive={() => onArchive(email)}
						onStar={() => onStar(email)}
						onTrash={() => onTrash(email)}
						onToggleRead={onToggleRead ? (read) => onToggleRead(email, read) : undefined}
						sendAt={scheduledTimes?.[email.id]}
						onCancel={onCancelScheduled ? () => onCancelScheduled(email.id) : undefined}
						isOther={isOther(email)}
						onMoveFocus={onMoveFocus ? (focused) => onMoveFocus(email, focused) : undefined}
						onSnooze={onSnooze ? (date) => onSnooze(email, date) : undefined}
						workStatus={workFor(thread.id)?.status}
					/>
				{/if}
			{/each}
		</div>

		{#if hasMore}
			<div class="sj-msglist__load-more-wrap">
				<Button
					class="sj-msglist__load-more"
					variant="ghost"
					size="sm"
					disabled={loadingMore}
					onclick={onLoadMore}
				>
					{loadingMore ? `Loading...` : `Load more (${remaining} remaining)`}
				</Button>
			</div>
		{/if}
	{/if}
</div>

<style>
	.sj-msglist {
		display: flex;
		flex-direction: column;
		height: 100%;
		overflow: hidden;
		background: var(--surface-card);
	}

	/* Focused/Other tab header (V078) — pinned above the scroll region. */
	.sj-msglist__tabs {
		flex: none;
		padding: 0 12px;
		background: var(--surface-card);
		border-bottom: 1px solid var(--border-subtle);
	}

	.sj-msglist__loading {
		display: flex;
		align-items: center;
		justify-content: center;
		height: 100%;
	}

	.sj-msglist__empty {
		display: flex;
		align-items: center;
		justify-content: center;
		height: 100%;
		padding: 32px;
	}

	.sj-msglist__scroll {
		flex: 1;
		overflow-y: auto;
	}

	/* Thread header */
	.sj-msglist__thread-header {
		display: flex;
		align-items: center;
		gap: 6px;
		padding: 8px 12px;
		cursor: pointer;
		border-bottom: 1px solid var(--border-subtle);
		background: var(--surface-sunken);
		user-select: none;
	}

	.sj-msglist__thread-header:hover {
		background: var(--surface-hover);
	}

	.sj-msglist__thread-header:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	.sj-msglist__thread-chevron {
		color: var(--text-tertiary);
		display: inline-flex;
		align-items: center;
		flex: none;
		width: 16px;
	}

	.sj-msglist__thread-subject {
		flex: 1;
		font-size: var(--text-sm);
		font-weight: 500;
		color: var(--text-primary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.sj-msglist__thread-count {
		font-size: var(--text-xs);
		font-family: var(--font-mono);
		font-weight: 600;
		color: var(--text-secondary);
		background: var(--surface-hover);
		padding: 1px 6px;
		border-radius: var(--radius-sm);
		flex: none;
	}

	.sj-msglist__work {
		flex: none;
		padding: 1px 6px;
		border-radius: var(--radius-sm);
		background: var(--surface-selected);
		font-size: var(--text-2xs);
		color: var(--text-caption);
	}

	.sj-msglist__thread-date {
		font-size: var(--text-2xs);
		color: var(--text-tertiary);
		flex: none;
		width: 60px;
		text-align: right;
	}

	/* Child emails in thread */
	.sj-msglist__child {
		border-left: 2px solid var(--accent);
		margin-left: 8px;
	}

	/* Divider between pinned / unpinned */
	.sj-msglist__divider {
		border-bottom: 1px solid var(--border-default);
		margin: 0;
	}

	/* Load more */
	.sj-msglist__load-more-wrap {
		padding: 8px;
		display: flex;
		justify-content: center;
		border-top: 1px solid var(--border-subtle);
	}
</style>
