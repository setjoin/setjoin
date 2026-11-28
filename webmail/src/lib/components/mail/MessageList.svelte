<svelte:options runes={true} />

<script lang="ts">
	import { onMount, tick } from 'svelte';
	import { Spinner, EmptyState, Button, IconButton, Tabs } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import MailRow from './MailRow.svelte';
	import { setOpenSwipeRowId } from './mailRowSwipe.svelte';
	import {
		DEFAULT_OVERSCAN,
		buildVirtualLayout,
		computeScrollTopForIndex,
		computeVirtualRange,
		findBoundaryNavigableIndex,
		findIndexAtOffset,
		findItemIndexByEmailId,
		findNextNavigableIndex,
		findPageNavigableIndex,
		flattenThreadsToVirtualItems,
		isNavigableItem,
		itemHeight,
		resolveAnchorScrollTop,
		type ScrollAlign,
		type ThreadData,
		type VirtualDensity,
	} from './virtualList';
	import type { Email, Mailbox } from '$lib/types/jmap';
	import type { MailWorkItem } from '$lib/mail/mailWork';
	import { t } from '$lib/i18n';

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
		/** Optional explicit density override; defaults to observing `<html data-density>`. */
		density?: VirtualDensity;
		/** When true, inserts virtualized date/group headers (Pinned, Today, Yesterday, This week, Older). */
		groupByDate?: boolean;
		/** Extra items mounted above and below the visible viewport. */
		overscan?: number;
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
		density: densityProp,
		groupByDate = false,
		overscan = DEFAULT_OVERSCAN,
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

	// ── Density detection ──
	function readDocumentDensity(): VirtualDensity {
		return typeof document !== 'undefined' && document.documentElement?.dataset?.density === 'compact'
			? 'compact'
			: 'comfortable';
	}

	let docDensity = $state<VirtualDensity>(readDocumentDensity());
	const activeDensity = $derived<VirtualDensity>(densityProp ?? docDensity);

	// ── Virtualization state (#625) ──
	let scrollEl = $state<HTMLDivElement | null>(null);
	let scrollTop = $state(0);
	let viewportHeight = $state(0);
	let activeIndex = $state(-1);
	let measureVersion = $state(0);

	const measuredHeights = new Map<string, number>();
	let rowObserver: ResizeObserver | null = null;
	let anchorKey: string | null = null;
	let anchorDelta = 0;
	let lastDensity: VirtualDensity = readDocumentDensity();
	let lastSyncedSelectedId: string | null = null;
	let focusSeq = 0;

	const flattened = $derived(
		flattenThreadsToVirtualItems(threads, viewMode, { groupByDate }),
	);
	const virtualItems = $derived(flattened.items);
	const totalRowCount = $derived(flattened.totalRowCount);

	const itemIndexByKey = $derived.by(() => {
		const map = new Map<string, number>();
		for (let i = 0; i < virtualItems.length; i++) {
			map.set(virtualItems[i].key, i);
		}
		return map;
	});

	const layout = $derived.by(() => {
		// Subscribe to measured height updates via version counter.
		void measureVersion;
		return buildVirtualLayout(virtualItems, activeDensity, measuredHeights);
	});

	const range = $derived(computeVirtualRange(layout, scrollTop, viewportHeight, overscan));
	const startIndex = $derived(range.start);
	const endIndex = $derived(range.end);
	const paddingTop = $derived(range.paddingTop);
	const paddingBottom = $derived(range.paddingBottom);
	const visibleItems = $derived(virtualItems.slice(startIndex, endIndex));

	const effectiveActiveIndex = $derived.by(() => {
		if (
			activeIndex >= 0 &&
			activeIndex < virtualItems.length &&
			isNavigableItem(virtualItems[activeIndex])
		) {
			return activeIndex;
		}
		if (selectedId) {
			const sel = findItemIndexByEmailId(virtualItems, selectedId);
			if (sel >= 0) return sel;
		}
		return findBoundaryNavigableIndex(virtualItems, 'start');
	});

	function captureAnchor(nextScrollTop: number) {
		if (virtualItems.length === 0 || nextScrollTop <= 0) {
			anchorKey = null;
			anchorDelta = 0;
			return;
		}
		const firstIdx = findIndexAtOffset(layout.offsets, nextScrollTop);
		anchorKey = virtualItems[firstIdx]?.key ?? null;
		anchorDelta = nextScrollTop - layout.offsets[firstIdx];
	}

	function recordMeasuredHeight(key: string, rawHeight: number) {
		if (!Number.isFinite(rawHeight) || rawHeight <= 0) return;
		const rounded = Math.round(rawHeight);
		const idx = itemIndexByKey.get(key);
		if (idx === undefined) return;
		const prev = itemHeight(virtualItems[idx], activeDensity, measuredHeights);
		if (Math.abs(rounded - prev) < 1) return;

		const itemTop = layout.offsets[idx];
		const aboveViewport = scrollTop > 0 && itemTop < scrollTop;
		measuredHeights.set(key, rounded);
		measureVersion += 1;

		if (aboveViewport) {
			const nextScroll = Math.max(0, scrollTop + (rounded - prev));
			scrollTop = nextScroll;
			if (scrollEl) scrollEl.scrollTop = nextScroll;
		}
	}

	function measureRow(node: HTMLElement, key: string) {
		let currentKey = key;
		const initialHeight = node.getBoundingClientRect().height;
		if (initialHeight > 0) recordMeasuredHeight(currentKey, initialHeight);
		rowObserver?.observe(node);

		return {
			update(nextKey: string) {
				currentKey = nextKey;
				const h = node.getBoundingClientRect().height;
				if (h > 0) recordMeasuredHeight(currentKey, h);
			},
			destroy() {
				rowObserver?.unobserve(node);
			},
		};
	}

	/** Scroll a virtual item index into view and synchronize window state immediately. */
	export function scrollToIndex(index: number, align: ScrollAlign = 'nearest'): void {
		const nextScroll = computeScrollTopForIndex(layout, index, scrollTop, viewportHeight, align);
		scrollTop = nextScroll;
		if (scrollEl) scrollEl.scrollTop = nextScroll;
		captureAnchor(nextScroll);
	}

	onMount(() => {
		if (typeof ResizeObserver !== 'undefined') {
			rowObserver = new ResizeObserver((entries) => {
				for (const entry of entries) {
					const el = entry.target as HTMLElement;
					const key = el.dataset.vkey;
					if (!key) continue;
					const height = entry.borderBoxSize?.[0]?.blockSize ?? entry.contentRect.height;
					recordMeasuredHeight(key, height);
				}
			});
		}

		let densityObserver: MutationObserver | null = null;
		if (typeof MutationObserver !== 'undefined' && typeof document !== 'undefined') {
			densityObserver = new MutationObserver(() => {
				docDensity = readDocumentDensity();
			});
			densityObserver.observe(document.documentElement, {
				attributes: true,
				attributeFilter: ['data-density'],
			});
		}

		return () => {
			rowObserver?.disconnect();
			rowObserver = null;
			densityObserver?.disconnect();
		};
	});

	// Observe scroll container viewport size changes.
	$effect(() => {
		const el = scrollEl;
		if (!el) return;
		if (el.clientHeight > 0) viewportHeight = el.clientHeight;
		if (typeof ResizeObserver === 'undefined') return;
		const ro = new ResizeObserver(() => {
			if (el.clientHeight > 0) viewportHeight = el.clientHeight;
		});
		ro.observe(el);
		return () => ro.disconnect();
	});

	// Clear cached measurements when density toggles so compact/comfortable estimates apply immediately.
	$effect(() => {
		if (activeDensity !== lastDensity) {
			lastDensity = activeDensity;
			measuredHeights.clear();
			measureVersion += 1;
		}
	});

	// Preserve scroll anchor across thread expand/collapse, density changes, or filter updates.
	$effect(() => {
		const resolved = resolveAnchorScrollTop(
			virtualItems,
			layout,
			anchorKey,
			anchorDelta,
			scrollTop,
			viewportHeight,
		);
		if (Math.abs(resolved - scrollTop) >= 1) {
			scrollTop = resolved;
			if (scrollEl) scrollEl.scrollTop = resolved;
		}
		captureAnchor(resolved);
	});

	// Keep off-screen selection synchronized when selectedId changes externally (e.g. global j/k or deep link).
	$effect(() => {
		if (!selectedId) {
			lastSyncedSelectedId = null;
			return;
		}
		if (selectedId === lastSyncedSelectedId) return;
		const idx = findItemIndexByEmailId(virtualItems, selectedId);
		if (idx < 0) return;
		lastSyncedSelectedId = selectedId;
		activeIndex = idx;
		scrollToIndex(idx, 'nearest');
	});

	function handleScroll() {
		setOpenSwipeRowId(null);
		if (!scrollEl) return;
		const next = scrollEl.scrollTop;
		if (next !== scrollTop) {
			scrollTop = next;
		}
		captureAnchor(next);
	}

	function focusRowAtIndex(targetIdx: number) {
		const seq = ++focusSeq;
		void tick().then(() => {
			if (seq !== focusSeq || !scrollEl) return;
			const target = scrollEl.querySelector<HTMLElement>(
				`[data-vindex="${targetIdx}"] .sj-mailrow, [data-vindex="${targetIdx}"] .sj-msglist__thread-header`,
			);
			target?.focus({ preventScroll: true });
		});
	}

	function handleListKeydown(e: KeyboardEvent) {
		if (e.ctrlKey || e.metaKey || e.altKey) return;
		const target = e.target as HTMLElement | null;
		const tag = target?.tagName;
		if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || target?.isContentEditable) {
			return;
		}

		let nextIdx = -1;
		switch (e.key) {
			case 'ArrowDown':
			case 'j':
				nextIdx = findNextNavigableIndex(virtualItems, effectiveActiveIndex, 1);
				break;
			case 'ArrowUp':
			case 'k':
				nextIdx = findNextNavigableIndex(virtualItems, effectiveActiveIndex, -1);
				break;
			case 'Home':
				nextIdx = findBoundaryNavigableIndex(virtualItems, 'start');
				break;
			case 'End':
				nextIdx = findBoundaryNavigableIndex(virtualItems, 'end');
				break;
			case 'PageDown':
				nextIdx = findPageNavigableIndex(virtualItems, layout, effectiveActiveIndex, 1, viewportHeight);
				break;
			case 'PageUp':
				nextIdx = findPageNavigableIndex(virtualItems, layout, effectiveActiveIndex, -1, viewportHeight);
				break;
			default:
				return;
		}

		if (nextIdx < 0) return;
		e.preventDefault();
		if (e.key === 'j' || e.key === 'k') {
			// Prevent document-level j/k shortcut in inbox/+page.svelte from double-stepping.
			e.stopPropagation();
		}

		activeIndex = nextIdx;
		scrollToIndex(nextIdx, 'nearest');

		const item = virtualItems[nextIdx];
		if (item.kind === 'row' || item.kind === 'thread-child') {
			lastSyncedSelectedId = item.email.id;
			onOpen(item.email);
		}
		focusRowAtIndex(nextIdx);
	}

	/** A row is "Other" (Focused/Other split) when its mailboxIds carry the Other tag. */
	function isOther(email: Email): boolean {
		return otherTagId ? !!email.mailboxIds?.[otherTagId] : false;
	}

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
		<!-- WAI-ARIA 1.2 composite interactive list: role="grid" supports aria-rowcount /
		     aria-rowindex and allows MailRow's role="button" + action IconButtons inside
		     gridcells with zero axe-core aria-allowed-attr / aria-required-children /
		     nested-interactive violations (unlike role="listbox" + role="option"). -->
		<div
			class="sj-msglist__scroll"
			role="grid"
			tabindex="-1"
			aria-label="Messages"
			aria-rowcount={totalRowCount}
			bind:this={scrollEl}
			onscroll={handleScroll}
			onkeydown={handleListKeydown}
		>
			{#if paddingTop > 0}
				<div
					class="sj-msglist__spacer"
					role="presentation"
					aria-hidden="true"
					style={`height: ${paddingTop}px`}
				></div>
			{/if}

			{#each visibleItems as item (item.key)}
				{#if item.kind === 'divider'}
					<div class="sj-msglist__divider" role="presentation" aria-hidden="true"></div>
				{:else if item.kind === 'header'}
					<div
						class="sj-msglist__group-header"
						role="row"
						aria-rowindex={item.rowIndex}
						data-vindex={item.index}
						data-vkey={item.key}
						use:measureRow={item.key}
					>
						<div class="sj-msglist__group-label" role="rowheader">{item.label}</div>
					</div>
				{:else if item.kind === 'thread-header'}
					<div
						class="sj-msglist__item sj-msglist__thread"
						role="row"
						aria-rowindex={item.rowIndex}
						aria-selected={false}
						data-vindex={item.index}
						data-vkey={item.key}
						use:measureRow={item.key}
					>
						<div class="sj-msglist__cell" role="gridcell">
							<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
							<div
								class="sj-msglist__thread-header"
								class:sj-msglist__thread-header--expanded={item.thread.expanded}
								role="button"
								tabindex={item.index === effectiveActiveIndex ? 0 : -1}
								aria-expanded={item.thread.expanded}
								onclick={(e) => {
									activeIndex = item.index;
									handleThreadClick(e, item.thread.id);
								}}
								onkeydown={(e) => handleThreadKeydown(e, item.thread.id)}
							>
								<span class="sj-msglist__thread-chevron" aria-hidden="true">
									<Icon name={item.thread.expanded ? 'ChevronDown' : 'ChevronRight'} size={14} strokeWidth={1.75} />
								</span>
								<span class="sj-msglist__thread-subject">
									{item.thread.emails[0].subject || '(no subject)'}
								</span>
								<span class="sj-msglist__thread-count">{item.thread.emails.length}</span>
								{#if workFor(item.thread.id)}
									<span class="sj-msglist__work" data-status={workFor(item.thread.id)?.status}>
										{t(`inbox.work.${workFor(item.thread.id)?.status}`)}
									</span>
								{/if}
								<span class="sj-msglist__thread-date">
									{item.pinned ? 'Pinned' : ''}
								</span>
								<IconButton
									label={item.thread.muted ? 'Unmute thread' : 'Mute thread'}
									size="sm"
									onclick={(e) => handleMuteClick(e, item.thread.id)}
								>
									<Icon name={item.thread.muted ? 'BellOff' : 'Bell'} size={14} strokeWidth={1.75} />
								</IconButton>
								<IconButton
									label="Archive thread"
									size="sm"
									onclick={(e) => handleArchiveClick(e, item.thread.id)}
								>
									<Icon name="Archive" size={14} strokeWidth={1.75} />
								</IconButton>
							</div>
						</div>
					</div>
				{:else}
					<div
						class="sj-msglist__item"
						class:sj-msglist__child={item.kind === 'thread-child'}
						role="row"
						aria-rowindex={item.rowIndex}
						aria-selected={isSelected(item.email)}
						data-vindex={item.index}
						data-vkey={item.key}
						use:measureRow={item.key}
					>
						<div class="sj-msglist__cell" role="gridcell">
							<MailRow
								email={item.email}
								tags={tagsForEmail(item.email)}
								selected={isSelected(item.email)}
								rowTabIndex={item.index === effectiveActiveIndex ? 0 : -1}
								tour={item.kind === 'row' ? item.tour : undefined}
								onOpen={() => {
									activeIndex = item.index;
									lastSyncedSelectedId = item.email.id;
									onOpen(item.email);
								}}
								onArchive={() => onArchive(item.email)}
								onStar={() => onStar(item.email)}
								onTrash={() => onTrash(item.email)}
								onToggleRead={onToggleRead ? (read) => onToggleRead(item.email, read) : undefined}
								sendAt={scheduledTimes?.[item.email.id]}
								onCancel={onCancelScheduled ? () => onCancelScheduled(item.email.id) : undefined}
								isOther={isOther(item.email)}
								onMoveFocus={onMoveFocus ? (focused) => onMoveFocus(item.email, focused) : undefined}
								onSnooze={onSnooze ? (date) => onSnooze(item.email, date) : undefined}
								workStatus={workFor(item.thread.id)?.status}
							/>
						</div>
					</div>
				{/if}
			{/each}

			{#if paddingBottom > 0}
				<div
					class="sj-msglist__spacer"
					role="presentation"
					aria-hidden="true"
					style={`height: ${paddingBottom}px`}
				></div>
			{/if}
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

	.sj-msglist__spacer {
		flex: none;
		pointer-events: none;
	}

	.sj-msglist__item,
	.sj-msglist__cell {
		display: block;
	}

	.sj-msglist__group-header {
		display: flex;
		align-items: center;
		padding: var(--space-1) var(--space-3);
		background: var(--surface-sunken);
		border-bottom: 1px solid var(--border-subtle);
	}

	.sj-msglist__group-label {
		font-size: var(--text-2xs);
		font-weight: 600;
		color: var(--text-caption);
		letter-spacing: 0.02em;
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

	:global([data-density="compact"]) .sj-msglist__thread-header {
		padding: var(--space-1) var(--space-3);
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
