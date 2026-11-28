import { describe, it, expect } from 'vitest';
import type { Email } from '$lib/types/jmap';
import {
	DEFAULT_VIEWPORT_HEIGHT,
	ESTIMATED_HEIGHTS,
	buildVirtualLayout,
	computeScrollTopForIndex,
	computeVirtualRange,
	dateGroupLabel,
	findBoundaryNavigableIndex,
	findIndexAtOffset,
	findItemIndexByEmailId,
	findNextNavigableIndex,
	findPageNavigableIndex,
	flattenThreadsToVirtualItems,
	isNavigableItem,
	itemHeight,
	resolveAnchorScrollTop,
	type ThreadData,
} from './virtualList';

function makeEmail(id: string, overrides: Partial<Email> = {}): Email {
	return {
		id,
		threadId: `t-${id}`,
		mailboxIds: { mb1: true },
		from: [{ name: 'Alice', email: 'alice@example.com' }],
		subject: `Subject ${id}`,
		preview: 'Preview text',
		receivedAt: '2026-06-14T10:00:00Z',
		hasAttachment: false,
		keywords: { $seen: true },
		...overrides,
	};
}

function makeThread(
	id: string,
	emails: Email[],
	overrides: Partial<Pick<ThreadData, 'expanded' | 'muted'>> = {},
): ThreadData {
	return {
		id,
		emails,
		expanded: overrides.expanded ?? false,
		muted: overrides.muted ?? false,
	};
}

describe('virtualList pure helpers', () => {
	describe('dateGroupLabel', () => {
		const now = new Date(2026, 5, 14, 15, 0, 0); // local 2026-06-14 15:00

		it('buckets today, yesterday, this week, older, and invalid/missing timestamps', () => {
			expect(dateGroupLabel(new Date(2026, 5, 14, 9, 0, 0).toISOString(), now)).toBe('Today');
			expect(dateGroupLabel(new Date(2026, 5, 15, 9, 0, 0).toISOString(), now)).toBe('Today');
			expect(dateGroupLabel(new Date(2026, 5, 13, 20, 0, 0).toISOString(), now)).toBe('Yesterday');
			expect(dateGroupLabel(new Date(2026, 5, 10, 12, 0, 0).toISOString(), now)).toBe('This week');
			expect(dateGroupLabel(new Date(2026, 5, 1, 12, 0, 0).toISOString(), now)).toBe('Older');
			expect(dateGroupLabel(undefined, now)).toBe('Older');
			expect(dateGroupLabel('not-a-date', now)).toBe('Older');
		});
	});

	describe('flattenThreadsToVirtualItems', () => {
		it('flattens pinned, divider, unpinned, thread headers, expanded children, and skips empty threads', () => {
			const pinnedThread = makeThread('tp', [
				makeEmail('ep1', { threadId: 'tp', pinnedAt: '2026-06-14T10:00:00Z' }),
			]);
			const multiCollapsed = makeThread(
				'tmc',
				[makeEmail('ec1', { threadId: 'tmc' }), makeEmail('ec2', { threadId: 'tmc' })],
				{ expanded: false },
			);
			const multiExpanded = makeThread(
				'tme',
				[makeEmail('ee1', { threadId: 'tme' }), makeEmail('ee2', { threadId: 'tme' })],
				{ expanded: true },
			);
			const emptyThread = makeThread('tempty', []);

			const { items, totalRowCount } = flattenThreadsToVirtualItems(
				[emptyThread, multiCollapsed, pinnedThread, multiExpanded],
				'threaded',
			);

			expect(items.map((it) => it.kind)).toEqual([
				'row',
				'divider',
				'thread-header',
				'thread-header',
				'thread-child',
				'thread-child',
			]);
			// Divider is role="presentation", so totalRowCount counts only ARIA rows (5).
			expect(totalRowCount).toBe(5);
			expect(items[0].kind === 'row' && items[0].tour).toBe('organize');
			expect(items[2].kind === 'thread-header' && items[2].rowIndex).toBe(2);
			expect(items[5].kind === 'thread-child' && items[5].rowIndex).toBe(5);
		});

		it('inserts Pinned and date headers when groupByDate is enabled', () => {
			const now = new Date(2026, 5, 14, 15, 0, 0);
			const threads = [
				makeThread('tp', [makeEmail('ep', { pinnedAt: '2026-06-14T08:00:00Z' })]),
				makeThread('t1', [makeEmail('e1', { receivedAt: new Date(2026, 5, 14, 10, 0, 0).toISOString() })]),
				makeThread('t2', [makeEmail('e2', { receivedAt: new Date(2026, 5, 14, 8, 0, 0).toISOString() })]),
				makeThread('t3', [makeEmail('e3', { receivedAt: new Date(2026, 5, 13, 12, 0, 0).toISOString() })]),
				makeThread('t4', [makeEmail('e4', { receivedAt: new Date(2026, 5, 2, 12, 0, 0).toISOString() })]),
			];

			const { items, totalRowCount } = flattenThreadsToVirtualItems(threads, 'flat', {
				groupByDate: true,
				now,
			});

			const headers = items.filter((it) => it.kind === 'header').map((it) => it.label);
			expect(headers).toEqual(['Pinned', 'Today', 'Yesterday', 'Older']);
			// 4 headers + 5 rows = 9 ARIA rows (divider excluded)
			expect(totalRowCount).toBe(9);
		});

		it('assigns tour="organize" to first unpinned row when there are no pinned threads', () => {
			const threads = [
				makeThread('t1', [makeEmail('e1')]),
				makeThread('t2', [makeEmail('e2')]),
			];
			const { items } = flattenThreadsToVirtualItems(threads, 'flat');
			expect(items[0].kind === 'row' && items[0].tour).toBe('organize');
			expect(items[1].kind === 'row' && items[1].tour).toBeUndefined();
		});
	});

	describe('layout, binary search, and range computation', () => {
		it('uses measured heights when present and falls back to density estimates', () => {
			const threads = [
				makeThread('t1', [makeEmail('e1')]),
				makeThread('t2', [makeEmail('e2')]),
			];
			const { items } = flattenThreadsToVirtualItems(threads, 'flat');
			const measured = new Map<string, number>([
				[items[0].key, 100],
				[items[1].key, 0], // zero ignored
			]);

			expect(itemHeight(items[0], 'comfortable', measured)).toBe(100);
			expect(itemHeight(items[1], 'comfortable', measured)).toBe(ESTIMATED_HEIGHTS.comfortable.row);
			expect(itemHeight(items[1], 'compact', measured)).toBe(ESTIMATED_HEIGHTS.compact.row);

			const layout = buildVirtualLayout(items, 'comfortable', measured);
			expect(layout.totalHeight).toBe(100 + ESTIMATED_HEIGHTS.comfortable.row);
			expect(findIndexAtOffset(layout.offsets, -10)).toBe(0);
			expect(findIndexAtOffset(layout.offsets, 0)).toBe(0);
			expect(findIndexAtOffset(layout.offsets, 99)).toBe(0);
			expect(findIndexAtOffset(layout.offsets, 100)).toBe(1);
			expect(findIndexAtOffset(layout.offsets, 9999)).toBe(1);
			expect(findIndexAtOffset(new Float64Array([0]), 50)).toBe(0);
		});

		it('windows 10,000 rows to a bounded slice with exact spacer heights', () => {
			const threads = Array.from({ length: 10_000 }, (_, i) =>
				makeThread(`t${i}`, [makeEmail(`e${i}`)]),
			);
			const { items } = flattenThreadsToVirtualItems(threads, 'flat');
			const layout = buildVirtualLayout(items, 'comfortable', new Map());

			expect(layout.totalHeight).toBe(10_000 * ESTIMATED_HEIGHTS.comfortable.row);

			const topRange = computeVirtualRange(layout, 0, 600, 6);
			expect(topRange.start).toBe(0);
			expect(topRange.end).toBeLessThan(25);
			expect(topRange.paddingTop).toBe(0);
			expect(topRange.paddingBottom).toBeGreaterThan(800_000);

			const midOffset = 5_000 * ESTIMATED_HEIGHTS.comfortable.row;
			const midRange = computeVirtualRange(layout, midOffset, 600, 6);
			expect(midRange.start).toBe(5_000 - 6);
			expect(midRange.end - midRange.start).toBeLessThanOrEqual(24);
			expect(midRange.paddingTop).toBe(layout.offsets[midRange.start]);
			expect(midRange.paddingBottom).toBe(layout.totalHeight - layout.offsets[midRange.end]);

			const emptyRange = computeVirtualRange({ offsets: new Float64Array([0]), totalHeight: 0 }, 0, 600);
			expect(emptyRange).toEqual({ start: 0, end: 0, paddingTop: 0, paddingBottom: 0, totalHeight: 0 });
		});

		it('falls back to DEFAULT_VIEWPORT_HEIGHT when viewportHeight is 0', () => {
			const threads = Array.from({ length: 100 }, (_, i) =>
				makeThread(`t${i}`, [makeEmail(`e${i}`)]),
			);
			const { items } = flattenThreadsToVirtualItems(threads, 'flat');
			const layout = buildVirtualLayout(items, 'comfortable', new Map());

			const rangeDefault = computeVirtualRange(layout, 0, 0, 4);
			const rangeExplicit = computeVirtualRange(layout, 0, DEFAULT_VIEWPORT_HEIGHT, 4);
			expect(rangeDefault).toEqual(rangeExplicit);
		});
	});

	describe('scrollToIndex & scroll anchor math', () => {
		const threads = Array.from({ length: 100 }, (_, i) =>
			makeThread(`t${i}`, [makeEmail(`e${i}`)]),
		);
		const { items } = flattenThreadsToVirtualItems(threads, 'flat');
		const layout = buildVirtualLayout(items, 'comfortable', new Map());

		it('computes nearest, start, and center scroll positions', () => {
			const rowH = ESTIMATED_HEIGHTS.comfortable.row;
			// Empty layout returns 0
			expect(computeScrollTopForIndex({ offsets: new Float64Array([0]), totalHeight: 0 }, 0, 0, 600)).toBe(0);
			// Already visible -> unchanged
			expect(computeScrollTopForIndex(layout, 2, 0, 600, 'nearest')).toBe(0);
			// Below viewport -> aligns bottom of row to bottom of viewport
			expect(computeScrollTopForIndex(layout, 50, 0, 600, 'nearest')).toBe(51 * rowH - 600);
			// Above viewport -> aligns top of row to top of viewport
			expect(computeScrollTopForIndex(layout, 10, 3000, 600, 'nearest')).toBe(10 * rowH);
			// Explicit start alignment
			expect(computeScrollTopForIndex(layout, 20, 0, 600, 'start')).toBe(20 * rowH);
			// Explicit center alignment
			expect(computeScrollTopForIndex(layout, 50, 0, 600, 'center')).toBe(50 * rowH - (600 - rowH) / 2);
			// Viewport fallback when 0
			expect(computeScrollTopForIndex(layout, 50, 0, 0, 'nearest')).toBe(51 * rowH - DEFAULT_VIEWPORT_HEIGHT);
		});

		it('re-anchors scrollTop without jump when items are inserted above or density changes', () => {
			expect(resolveAnchorScrollTop(items, layout, null, 0, 0, 600)).toBe(0);
			expect(resolveAnchorScrollTop(items, layout, items[40].key, 12, 500, 600)).toBe(
				layout.offsets[40] + 12,
			);
			// Missing anchor clamps to maxScroll
			expect(resolveAnchorScrollTop(items, layout, 'missing-key', 0, 999_999, 600)).toBe(
				layout.totalHeight - 600,
			);
			// Fallback viewportHeight
			expect(resolveAnchorScrollTop(items, layout, 'missing-key', 0, 999_999, 0)).toBe(
				layout.totalHeight - DEFAULT_VIEWPORT_HEIGHT,
			);
		});
	});

	describe('navigation helpers', () => {
		const now = new Date(2026, 5, 14, 15, 0, 0);
		const threads = [
			makeThread('tp', [makeEmail('ep', { pinnedAt: '2026-06-14T09:00:00Z' })]),
			makeThread(
				't1',
				[
					makeEmail('e1', { threadId: 't1', receivedAt: new Date(2026, 5, 14, 10, 0, 0).toISOString() }),
					makeEmail('e2', { threadId: 't1', receivedAt: new Date(2026, 5, 14, 9, 0, 0).toISOString() }),
				],
				{ expanded: false },
			),
			makeThread('t2', [makeEmail('e3', { receivedAt: new Date(2026, 5, 12, 10, 0, 0).toISOString() })]),
		];
		const { items } = flattenThreadsToVirtualItems(threads, 'threaded', { groupByDate: true, now });
		const layout = buildVirtualLayout(items, 'comfortable', new Map());

		it('identifies navigable items and locates email IDs including collapsed threads', () => {
			expect(isNavigableItem(items[0])).toBe(false); // header:Pinned
			expect(isNavigableItem(items[1])).toBe(true); // row:ep
			expect(findItemIndexByEmailId(items, 'ep')).toBe(1);
			// e2 belongs to collapsed thread t1 -> resolves to t1's thread-header
			const headerIdx = items.findIndex((it) => it.kind === 'thread-header');
			expect(findItemIndexByEmailId(items, 'e2')).toBe(headerIdx);
			expect(findItemIndexByEmailId(items, 'does-not-exist')).toBe(-1);
		});

		it('skips non-navigable headers and dividers for next/prev/boundary/page navigation', () => {
			const first = findBoundaryNavigableIndex(items, 'start');
			const last = findBoundaryNavigableIndex(items, 'end');
			expect(first).toBe(1);
			expect(last).toBe(items.length - 1);
			expect(findBoundaryNavigableIndex([], 'start')).toBe(-1);
			expect(findBoundaryNavigableIndex([], 'end')).toBe(-1);

			// From first navigable, stepping forward skips divider + Today header straight to thread-header
			const second = findNextNavigableIndex(items, first, 1);
			expect(items[second].kind).toBe('thread-header');
			// Stepping back from second returns to first
			expect(findNextNavigableIndex(items, second, -1)).toBe(first);
			// Stepping past boundaries stays on boundary
			expect(findNextNavigableIndex(items, first, -1)).toBe(first);
			expect(findNextNavigableIndex(items, last, 1)).toBe(last);
			// Invalid fromIndex picks boundary
			expect(findNextNavigableIndex(items, -1, 1)).toBe(first);
			expect(findNextNavigableIndex(items, -1, -1)).toBe(last);
			expect(findNextNavigableIndex([], 0, 1)).toBe(-1);
			// Non-navigable fromIndex at boundary returns -1
			expect(findNextNavigableIndex([items[0]], 0, 1)).toBe(-1);

			// Page navigation
			expect(findPageNavigableIndex([], layout, 0, 1, 600)).toBe(-1);
			expect(findPageNavigableIndex(items, layout, -1, 1, 600)).toBe(first);
			expect(findPageNavigableIndex(items, layout, -1, -1, 600)).toBe(last);
			expect(findPageNavigableIndex(items, layout, first, 1, 600)).toBe(last);
			expect(findPageNavigableIndex(items, layout, last, -1, 600)).toBe(first);
			// Small viewport still advances at least one step
			expect(findPageNavigableIndex(items, layout, first, 1, 10)).toBe(second);
			// Landing on a non-navigable divider/header snaps forward to navigable item
			const dividerIdx = items.findIndex((it) => it.kind === 'divider');
			const tinyViewport = layout.offsets[dividerIdx] - layout.offsets[first] + 0.5;
			expect(findPageNavigableIndex(items, layout, first, 1, tinyViewport)).toBe(second);
			// Viewport fallback when 0
			expect(findPageNavigableIndex(items, layout, first, 1, 0)).toBe(last);
		});
	});
});
