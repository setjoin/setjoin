import type { Email } from '$lib/types/jmap';

export interface ThreadData {
	id: string;
	emails: Email[];
	expanded: boolean;
	muted: boolean;
}

export type VirtualDensity = 'comfortable' | 'compact';

export type VirtualItemKind = 'row' | 'thread-header' | 'thread-child' | 'header' | 'divider';

export type DateGroupBucket = 'pinned' | 'today' | 'yesterday' | 'this_week' | 'older';

export type ScrollAlign = 'nearest' | 'start' | 'center';

export type VirtualItem =
	| {
			kind: 'row';
			key: string;
			index: number;
			rowIndex: number;
			thread: ThreadData;
			email: Email;
			tour?: string;
	  }
	| {
			kind: 'thread-header';
			key: string;
			index: number;
			rowIndex: number;
			thread: ThreadData;
			pinned: boolean;
	  }
	| {
			kind: 'thread-child';
			key: string;
			index: number;
			rowIndex: number;
			thread: ThreadData;
			email: Email;
	  }
	| {
			kind: 'header';
			key: string;
			index: number;
			rowIndex: number;
			bucket: DateGroupBucket;
	  }
	| {
			kind: 'divider';
			key: string;
			index: number;
	  };

export interface VirtualLayout {
	offsets: Float64Array;
	totalHeight: number;
}

export interface VirtualRange {
	start: number;
	end: number;
	paddingTop: number;
	paddingBottom: number;
	totalHeight: number;
}

export const DEFAULT_VIEWPORT_HEIGHT = 600;
export const DEFAULT_OVERSCAN = 6;

/**
 * Default height estimates (px) per density and item kind. Used before a mounted
 * row's actual rendered height is measured via ResizeObserver (and as the stable
 * fallback in non-layout environments such as jsdom/SSR).
 */
export const ESTIMATED_HEIGHTS: Record<VirtualDensity, Record<VirtualItemKind, number>> = {
	comfortable: {
		row: 84,
		'thread-child': 84,
		'thread-header': 42,
		header: 28,
		divider: 1,
	},
	compact: {
		row: 64,
		'thread-child': 64,
		'thread-header': 34,
		header: 24,
		divider: 1,
	},
};

const MS_PER_DAY = 86_400_000;

/** Bucket an ISO timestamp into a stable, DST-safe calendar-day group bucket. */
export function dateGroupBucket(
	iso: string | undefined,
	now: Date = new Date(),
): Exclude<DateGroupBucket, 'pinned'> {
	if (!iso) return 'older';
	const d = new Date(iso);
	if (Number.isNaN(d.getTime())) return 'older';
	const startOfTodayUtc = Date.UTC(now.getFullYear(), now.getMonth(), now.getDate());
	const startOfDateUtc = Date.UTC(d.getFullYear(), d.getMonth(), d.getDate());
	const dayDiff = Math.floor((startOfTodayUtc - startOfDateUtc) / MS_PER_DAY);
	if (dayDiff <= 0) return 'today';
	if (dayDiff === 1) return 'yesterday';
	if (dayDiff < 7) return 'this_week';
	return 'older';
}

export interface FlattenOptions {
	groupByDate?: boolean;
	now?: Date;
}

/**
 * Flatten pinned/unpinned threads (including expanded child messages, optional
 * date/group headers, and the pinned divider) into a linear virtual item list
 * with 1-based ARIA row indices.
 */
export function flattenThreadsToVirtualItems(
	threads: ThreadData[],
	viewMode: 'flat' | 'threaded',
	options: FlattenOptions = {},
): { items: VirtualItem[]; totalRowCount: number } {
	const groupByDate = options.groupByDate ?? false;
	const now = options.now ?? new Date();
	const nonEmpty = threads.filter((t) => t.emails.length > 0);
	const pinned = nonEmpty.filter((t) => Boolean(t.emails[0].pinnedAt));
	const unpinned = nonEmpty.filter((t) => !t.emails[0].pinnedAt);

	const items: VirtualItem[] = [];
	let rowIndex = 0;
	let headerSeq = 0;

	const appendThread = (thread: ThreadData, isPinned: boolean, allowTour: boolean) => {
		if (viewMode === 'threaded' && thread.emails.length > 1) {
			items.push({
				kind: 'thread-header',
				key: `thread:${thread.id}`,
				index: items.length,
				rowIndex: ++rowIndex,
				thread,
				pinned: isPinned,
			});
			if (thread.expanded) {
				for (const email of thread.emails) {
					items.push({
						kind: 'thread-child',
						key: `child:${thread.id}:${email.id}`,
						index: items.length,
						rowIndex: ++rowIndex,
						thread,
						email,
					});
				}
			}
		} else {
			const email = thread.emails[0];
			items.push({
				kind: 'row',
				key: `row:${thread.id}:${email.id}`,
				index: items.length,
				rowIndex: ++rowIndex,
				thread,
				email,
				tour: allowTour ? 'organize' : undefined,
			});
		}
	};

	if (groupByDate && pinned.length > 0) {
		items.push({
			kind: 'header',
			key: `header:pinned:${headerSeq++}`,
			index: items.length,
			rowIndex: ++rowIndex,
			bucket: 'pinned',
		});
	}

	for (let i = 0; i < pinned.length; i++) {
		appendThread(pinned[i], true, i === 0);
	}

	if (pinned.length > 0 && unpinned.length > 0) {
		items.push({
			kind: 'divider',
			key: 'divider:pinned',
			index: items.length,
		});
	}

	let lastBucket = '';
	for (let i = 0; i < unpinned.length; i++) {
		const thread = unpinned[i];
		if (groupByDate) {
			const bucket = dateGroupBucket(thread.emails[0].receivedAt, now);
			if (bucket !== lastBucket) {
				lastBucket = bucket;
				items.push({
					kind: 'header',
					key: `header:${bucket}:${headerSeq++}`,
					index: items.length,
					rowIndex: ++rowIndex,
					bucket,
				});
			}
		}
		appendThread(thread, false, i === 0 && pinned.length === 0);
	}

	return { items, totalRowCount: rowIndex };
}

export function isNavigableItem(item: VirtualItem): boolean {
	return item.kind === 'row' || item.kind === 'thread-header' || item.kind === 'thread-child';
}

export function itemHeight(
	item: VirtualItem,
	density: VirtualDensity,
	measuredHeights: ReadonlyMap<string, number>,
): number {
	const measured = measuredHeights.get(item.key);
	if (measured !== undefined && measured > 0) return measured;
	return ESTIMATED_HEIGHTS[density][item.kind];
}

/** Build O(N) prefix-sum offsets so range and scroll lookups run in O(log N). */
export function buildVirtualLayout(
	items: readonly VirtualItem[],
	density: VirtualDensity,
	measuredHeights: ReadonlyMap<string, number>,
): VirtualLayout {
	const offsets = new Float64Array(items.length + 1);
	for (let i = 0; i < items.length; i++) {
		offsets[i + 1] = offsets[i] + itemHeight(items[i], density, measuredHeights);
	}
	return { offsets, totalHeight: offsets[items.length] };
}

/** Binary search for the item index whose span contains `offset`. */
export function findIndexAtOffset(offsets: Float64Array, offset: number): number {
	const count = offsets.length - 1;
	if (count <= 0 || offset <= 0) return 0;
	if (offset >= offsets[count]) return count - 1;

	let low = 0;
	let high = count - 1;
	while (low < high) {
		const mid = (low + high + 1) >> 1;
		if (offsets[mid] <= offset) {
			low = mid;
		} else {
			high = mid - 1;
		}
	}
	return low;
}

/** Compute the mounted slice [start, end) and spacer heights for the current scroll position. */
export function computeVirtualRange(
	layout: VirtualLayout,
	scrollTop: number,
	viewportHeight: number,
	overscan: number = DEFAULT_OVERSCAN,
): VirtualRange {
	const count = layout.offsets.length - 1;
	if (count === 0) {
		return { start: 0, end: 0, paddingTop: 0, paddingBottom: 0, totalHeight: 0 };
	}

	const effectiveViewport = viewportHeight > 0 ? viewportHeight : DEFAULT_VIEWPORT_HEIGHT;
	const maxScroll = Math.max(0, layout.totalHeight - effectiveViewport);
	const clampedScroll = Math.max(0, Math.min(scrollTop, maxScroll));
	const safeOverscan = Math.max(0, overscan);

	const firstVisible = findIndexAtOffset(layout.offsets, clampedScroll);
	const lastVisible = findIndexAtOffset(layout.offsets, clampedScroll + effectiveViewport);

	const start = Math.max(0, firstVisible - safeOverscan);
	const end = Math.min(count, lastVisible + 1 + safeOverscan);
	const paddingTop = layout.offsets[start];
	const paddingBottom = Math.max(0, layout.totalHeight - layout.offsets[end]);

	return {
		start,
		end,
		paddingTop,
		paddingBottom,
		totalHeight: layout.totalHeight,
	};
}

/** Compute the target scrollTop to bring `index` into view without unnecessary scrolling. */
export function computeScrollTopForIndex(
	layout: VirtualLayout,
	index: number,
	currentScrollTop: number,
	viewportHeight: number,
	align: ScrollAlign = 'nearest',
): number {
	const count = layout.offsets.length - 1;
	if (count === 0) return 0;

	const clampedIdx = Math.max(0, Math.min(count - 1, index));
	const effectiveViewport = viewportHeight > 0 ? viewportHeight : DEFAULT_VIEWPORT_HEIGHT;
	const itemTop = layout.offsets[clampedIdx];
	const itemBottom = layout.offsets[clampedIdx + 1];
	const maxScroll = Math.max(0, layout.totalHeight - effectiveViewport);

	if (align === 'start') {
		return Math.min(maxScroll, Math.max(0, itemTop));
	}
	if (align === 'center') {
		const centered = itemTop - (effectiveViewport - (itemBottom - itemTop)) / 2;
		return Math.min(maxScroll, Math.max(0, centered));
	}

	if (itemTop < currentScrollTop) {
		return Math.min(maxScroll, Math.max(0, itemTop));
	}
	if (itemBottom > currentScrollTop + effectiveViewport) {
		return Math.min(maxScroll, Math.max(0, itemBottom - effectiveViewport));
	}
	return currentScrollTop;
}

/** Locate the virtual item representing an email (or its collapsed parent thread header). */
export function findItemIndexByEmailId(items: readonly VirtualItem[], emailId: string): number {
	let collapsedThreadIdx = -1;
	for (let i = 0; i < items.length; i++) {
		const item = items[i];
		if ((item.kind === 'row' || item.kind === 'thread-child') && item.email.id === emailId) {
			return i;
		}
		if (
			collapsedThreadIdx === -1 &&
			item.kind === 'thread-header' &&
			item.thread.emails.some((e) => e.id === emailId)
		) {
			collapsedThreadIdx = i;
		}
	}
	return collapsedThreadIdx;
}

/** Find the first or last keyboard-navigable item index, or -1 if none exist. */
export function findBoundaryNavigableIndex(
	items: readonly VirtualItem[],
	edge: 'start' | 'end',
): number {
	if (edge === 'start') {
		for (let i = 0; i < items.length; i++) {
			if (isNavigableItem(items[i])) return i;
		}
		return -1;
	}
	for (let i = items.length - 1; i >= 0; i--) {
		if (isNavigableItem(items[i])) return i;
	}
	return -1;
}

/** Step forward (+1) or backward (-1) to the next navigable item, skipping headers/dividers. */
export function findNextNavigableIndex(
	items: readonly VirtualItem[],
	fromIndex: number,
	delta: 1 | -1,
): number {
	if (items.length === 0) return -1;
	if (fromIndex < 0 || fromIndex >= items.length) {
		return findBoundaryNavigableIndex(items, delta > 0 ? 'start' : 'end');
	}
	for (let i = fromIndex + delta; i >= 0 && i < items.length; i += delta) {
		if (isNavigableItem(items[i])) return i;
	}
	return isNavigableItem(items[fromIndex]) ? fromIndex : -1;
}

/** Jump by one viewport page up (-1) or down (+1) using measured/estimated layout offsets. */
export function findPageNavigableIndex(
	items: readonly VirtualItem[],
	layout: VirtualLayout,
	fromIndex: number,
	direction: 1 | -1,
	viewportHeight: number,
): number {
	if (items.length === 0) return -1;
	if (fromIndex < 0 || fromIndex >= items.length) {
		return findBoundaryNavigableIndex(items, direction > 0 ? 'start' : 'end');
	}
	const effectiveViewport = viewportHeight > 0 ? viewportHeight : DEFAULT_VIEWPORT_HEIGHT;
	const targetOffset =
		direction > 0
			? layout.offsets[fromIndex] + effectiveViewport
			: Math.max(0, layout.offsets[fromIndex] - effectiveViewport);
	const rawIdx = findIndexAtOffset(layout.offsets, targetOffset);

	if (rawIdx === fromIndex) {
		return findNextNavigableIndex(items, fromIndex, direction);
	}
	if (isNavigableItem(items[rawIdx])) return rawIdx;

	const forward = findNextNavigableIndex(items, rawIdx, direction);
	if (forward !== -1 && forward !== rawIdx) return forward;
	return findBoundaryNavigableIndex(items, direction > 0 ? 'end' : 'start');
}

/**
 * Re-anchor scrollTop when layout heights or items above the viewport change
 * (density switch, thread expand/collapse, row re-measurement) so visible rows
 * stay pinned without a scroll jump. When a previously anchored item disappears
 * on a disjoint list transition (e.g. filter or folder switch), resets to top.
 */
export function resolveAnchorScrollTop(
	items: readonly VirtualItem[],
	layout: VirtualLayout,
	anchorKey: string | null,
	anchorDelta: number,
	currentScrollTop: number,
	viewportHeight: number,
): number {
	const effectiveViewport = viewportHeight > 0 ? viewportHeight : DEFAULT_VIEWPORT_HEIGHT;
	const maxScroll = Math.max(0, layout.totalHeight - effectiveViewport);
	if (currentScrollTop <= 0) return 0;
	if (anchorKey) {
		const idx = items.findIndex((item) => item.key === anchorKey);
		if (idx >= 0) {
			return Math.min(maxScroll, Math.max(0, layout.offsets[idx] + anchorDelta));
		}
		return 0;
	}
	return Math.min(maxScroll, Math.max(0, currentScrollTop));
}
