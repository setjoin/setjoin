import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte/svelte5';
import { tick } from 'svelte';
import axe from 'axe-core';
import { setLocale } from '$lib/i18n';
import MessageList from './MessageList.svelte';
import { getOpenSwipeRowId, setOpenSwipeRowId } from './mailRowSwipe.svelte';
import type { Email, Mailbox } from '$lib/types/jmap';

function makeEmail(overrides: Partial<Email> = {}): Email {
	return {
		id: 'e1',
		threadId: 't1',
		mailboxIds: { mb1: true },
		from: [{ name: 'Alice', email: 'alice@example.com' }],
		subject: 'Hello',
		preview: 'Preview text...',
		receivedAt: '2026-06-14T10:00:00Z',
		hasAttachment: false,
		keywords: { $seen: true },
		...overrides,
	};
}

function makeTag(id: string, name: string): Mailbox {
	return { id, name };
}

function makeThread(overrides: Partial<{ id: string; emails: Email[]; expanded: boolean; muted: boolean }> = {}) {
	return {
		id: overrides.id ?? 't1',
		emails: overrides.emails ?? [makeEmail({ id: 'e1', threadId: overrides.id ?? 't1' })],
		expanded: overrides.expanded ?? false,
		muted: overrides.muted ?? false,
	};
}

describe('MessageList', () => {
	const baseProps = {
		threads: [] as ReturnType<typeof makeThread>[],
		viewMode: 'flat' as const,
		selectedId: null as string | null,
		tags: [] as Mailbox[],
		loading: false,
		loadingMore: false,
		hasMore: false,
		remaining: 0,
		onOpen: vi.fn(),
		onArchive: vi.fn(),
		onStar: vi.fn(),
		onTrash: vi.fn(),
		onToggleThread: vi.fn(),
		onMuteThread: vi.fn(),
		onArchiveThread: vi.fn(),
		onLoadMore: vi.fn(),
	};

	it('renders Spinner when loading', () => {
		const { container } = render(MessageList, { ...baseProps, loading: true });
		expect(container.querySelector('.sj-spinner')).not.toBeNull();
	});

	it('shows EmptyState when list is empty and not loading', () => {
		const { container } = render(MessageList, baseProps);
		expect(container.querySelector('.sj-empty')).not.toBeNull();
		expect(container.textContent).toContain('Nothing here');
	});

	it('in flat mode, renders one MailRow per thread first email', () => {
		const threads = [
			makeThread({ id: 't1', emails: [makeEmail({ id: 'e1', threadId: 't1' })] }),
			makeThread({ id: 't2', emails: [makeEmail({ id: 'e2', threadId: 't2', from: [{ name: 'Bob', email: 'bob@test.com' }] })] }),
		];
		const { container } = render(MessageList, { ...baseProps, threads, viewMode: 'flat' });
		const rows = container.querySelectorAll('.sj-mailrow');
		expect(rows.length).toBe(2);
	});

	it('in threaded mode, single-email threads render as MailRow (no thread header)', () => {
		const threads = [makeThread({ id: 't1', emails: [makeEmail({ id: 'e1', threadId: 't1' })] })];
		const { container } = render(MessageList, { ...baseProps, threads, viewMode: 'threaded' });
		expect(container.querySelector('.sj-mailrow')).not.toBeNull();
		// No thread header for single-email thread
		expect(container.querySelector('.sj-msglist__thread-header')).toBeNull();
	});

	it('in threaded mode, multi-email threads render a thread header', () => {
		const threads = [
			makeThread({
				id: 't1',
				emails: [
					makeEmail({ id: 'e1', threadId: 't1' }),
					makeEmail({ id: 'e2', threadId: 't1', from: [{ name: 'Bob', email: 'bob@test.com' }] }),
				],
				expanded: false,
			}),
		];
		const { container } = render(MessageList, { ...baseProps, threads, viewMode: 'threaded' });
		expect(container.querySelector('.sj-msglist__thread-header')).not.toBeNull();
	});

	it('thread header shows email count', () => {
		const threads = [
			makeThread({
				id: 't1',
				emails: [makeEmail({ id: 'e1' }), makeEmail({ id: 'e2' }), makeEmail({ id: 'e3' })],
			}),
		];
		const { container } = render(MessageList, { ...baseProps, threads, viewMode: 'threaded' });
		const count = container.querySelector('.sj-msglist__thread-count');
		expect(count?.textContent?.trim()).toBe('3');
	});

	it('thread header shows subject of first email', () => {
		const threads = [
			makeThread({
				id: 't1',
				emails: [makeEmail({ id: 'e1', subject: 'Team sync' }), makeEmail({ id: 'e2', subject: 'Re: Team sync' })],
			}),
		];
		const { container } = render(MessageList, { ...baseProps, threads, viewMode: 'threaded' });
		const subject = container.querySelector('.sj-msglist__thread-subject');
		expect(subject?.textContent?.trim()).toBe('Team sync');
	});

	it('clicking thread header calls onToggleThread', async () => {
		const onToggleThread = vi.fn();
		const threads = [
			makeThread({ id: 't1', emails: [makeEmail({ id: 'e1' }), makeEmail({ id: 'e2' })] }),
		];
		const { container } = render(MessageList, {
			...baseProps,
			threads,
			viewMode: 'threaded',
			onToggleThread,
		});
		const header = container.querySelector('.sj-msglist__thread-header') as HTMLElement;
		await fireEvent.click(header);
		expect(onToggleThread).toHaveBeenCalledWith('t1');
	});

	it('mute button in thread header calls onMuteThread', async () => {
		const onMuteThread = vi.fn();
		const threads = [
			makeThread({ id: 't1', emails: [makeEmail({ id: 'e1' }), makeEmail({ id: 'e2' })], muted: false }),
		];
		const { container } = render(MessageList, {
			...baseProps,
			threads,
			viewMode: 'threaded',
			onMuteThread,
		});
		const muteBtn = container.querySelector('[aria-label="Mute thread"]') as HTMLButtonElement;
		expect(muteBtn).not.toBeNull();
		await fireEvent.click(muteBtn);
		expect(onMuteThread).toHaveBeenCalledWith('t1');
	});

	it('expanded thread renders child emails', () => {
		const threads = [
			makeThread({
				id: 't1',
				emails: [makeEmail({ id: 'e1' }), makeEmail({ id: 'e2' })],
				expanded: true,
			}),
		];
		const { container } = render(MessageList, { ...baseProps, threads, viewMode: 'threaded' });
		const childRows = container.querySelectorAll('.sj-msglist__child .sj-mailrow');
		expect(childRows.length).toBe(2);
	});

	it('hasMore shows load-more button calling onLoadMore', async () => {
		const onLoadMore = vi.fn();
		const threads = [makeThread()];
		const { container } = render(MessageList, {
			...baseProps,
			threads,
			hasMore: true,
			remaining: 50,
			onLoadMore,
		});
		const btn = container.querySelector('.sj-msglist__load-more') as HTMLButtonElement;
		expect(btn).not.toBeNull();
		await fireEvent.click(btn);
		expect(onLoadMore).toHaveBeenCalled();
	});

	it('load-more button shows "Loading..." when loadingMore', () => {
		const threads = [makeThread()];
		const { container } = render(MessageList, {
			...baseProps,
			threads,
			hasMore: true,
			loadingMore: true,
			remaining: 50,
		});
		const btn = container.querySelector('.sj-msglist__load-more') as HTMLButtonElement;
		expect(btn?.textContent).toContain('Loading');
		expect(btn?.hasAttribute('disabled')).toBe(true);
	});

	it('separates pinned from unpinned threads with a divider', () => {
		const threads = [
			makeThread({ id: 'tp', emails: [makeEmail({ id: 'ep', pinnedAt: '2026-01-01T00:00:00Z' })] }),
			makeThread({ id: 'tu', emails: [makeEmail({ id: 'eu' })] }),
		];
		const { container } = render(MessageList, { ...baseProps, threads, viewMode: 'flat' });
		expect(container.querySelector('.sj-msglist__divider')).not.toBeNull();
	});

	it('no divider when only one group has threads', () => {
		const threads = [makeThread({ id: 't1', emails: [makeEmail({ id: 'e1' })] })];
		const { container } = render(MessageList, { ...baseProps, threads, viewMode: 'flat' });
		expect(container.querySelector('.sj-msglist__divider')).toBeNull();
	});

	it('maps shared-mail work state to both flat rows and collapsed thread headers', () => {
		const flat = render(MessageList, {
			...baseProps,
			threads: [makeThread({ id: 't1' })],
			workByThread: { t1: { id: 't1', threadId: 't1', status: 'owned', assigneeUserId: '7', dueAt: null, generation: '1' } },
		});
		expect(flat.container.querySelector('.sj-mailrow__work')?.textContent).toContain('Owned');
		flat.unmount();

		const threaded = render(MessageList, {
			...baseProps,
			viewMode: 'threaded',
			threads: [makeThread({ id: 't1', emails: [makeEmail({ id: 'e1' }), makeEmail({ id: 'e2' })] })],
			workByThread: { t1: { id: 't1', threadId: 't1', status: 'done', assigneeUserId: '7', dueAt: null, generation: '2' } },
		});
		expect(threaded.container.querySelector('.sj-msglist__work')?.textContent).toContain('Done');
	});
});

describe('MessageList tour anchor', () => {
	it('tags exactly one row with data-tour="organize" and it is the first .sj-mailrow', () => {
		const threads = [
			makeThread({ id: 't1', emails: [makeEmail({ id: 'e1', threadId: 't1' })] }),
			makeThread({ id: 't2', emails: [makeEmail({ id: 'e2', threadId: 't2', from: [{ name: 'Bob', email: 'bob@test.com' }] })] }),
		];
		const basePropsLocal = {
			threads,
			viewMode: 'flat' as const,
			selectedId: null as string | null,
			tags: [] as Mailbox[],
			loading: false,
			loadingMore: false,
			hasMore: false,
			remaining: 0,
			onOpen: vi.fn(),
			onArchive: vi.fn(),
			onStar: vi.fn(),
			onTrash: vi.fn(),
			onToggleThread: vi.fn(),
			onMuteThread: vi.fn(),
			onArchiveThread: vi.fn(),
			onLoadMore: vi.fn(),
		};
		const { container } = render(MessageList, basePropsLocal);
		const tagged = container.querySelectorAll('[data-tour="organize"]');
		expect(tagged.length).toBe(1);
		expect(container.querySelector('.sj-mailrow')).toBe(tagged[0]);
	});
});

describe('MessageList virtualization, keyboard nav & accessibility (#625)', () => {
	afterEach(() => {
		delete document.documentElement.dataset.density;
		setOpenSwipeRowId(null);
		setLocale('en');
		vi.unstubAllGlobals();
	});

	function makeLargeList(count: number) {
		return Array.from({ length: count }, (_, i) =>
			makeThread({
				id: `t-${i}`,
				emails: [
					makeEmail({
						id: `e-${i}`,
						threadId: `t-${i}`,
						subject: `Message ${i}`,
						from: [{ name: `Sender ${i}`, email: `sender${i}@example.com` }],
					}),
				],
			}),
		);
	}

	const baseProps = {
		threads: [] as ReturnType<typeof makeThread>[],
		viewMode: 'flat' as const,
		selectedId: null as string | null,
		tags: [] as Mailbox[],
		loading: false,
		loadingMore: false,
		hasMore: false,
		remaining: 0,
		onOpen: vi.fn(),
		onArchive: vi.fn(),
		onStar: vi.fn(),
		onTrash: vi.fn(),
		onToggleThread: vi.fn(),
		onMuteThread: vi.fn(),
		onArchiveThread: vi.fn(),
		onLoadMore: vi.fn(),
	};

	it('windows a 10,000-row mailbox to a bounded DOM slice and updates on scroll', async () => {
		const threads = makeLargeList(10_000);
		const { container } = render(MessageList, {
			...baseProps,
			threads,
			overscan: 4,
		});

		const grid = container.querySelector('.sj-msglist__scroll') as HTMLDivElement;
		expect(grid.getAttribute('role')).toBe('grid');
		expect(grid.getAttribute('aria-rowcount')).toBe('10000');

		// Only visible + overscan rows are mounted — never all 10,000.
		const initialRows = container.querySelectorAll('.sj-mailrow');
		expect(initialRows.length).toBeGreaterThan(0);
		expect(initialRows.length).toBeLessThan(30);
		expect(container.querySelector('[role="row"]')?.getAttribute('aria-rowindex')).toBe('1');

		// Scroll halfway down (row 5000 * 84px = 420,000px).
		setOpenSwipeRowId('e-0');
		grid.scrollTop = 5_000 * 84;
		await fireEvent.scroll(grid);
		await tick();

		expect(getOpenSwipeRowId()).toBeNull();
		const midRows = container.querySelectorAll('.sj-mailrow');
		expect(midRows.length).toBeGreaterThan(0);
		expect(midRows.length).toBeLessThan(30);
		const mountedIndices = Array.from(container.querySelectorAll('[role="row"]')).map((el) =>
			Number(el.getAttribute('aria-rowindex')),
		);
		expect(mountedIndices).toContain(5001);
		// Top and bottom spacers keep total scrollable geometry intact.
		const spacers = container.querySelectorAll('.sj-msglist__spacer');
		expect(spacers.length).toBe(2);
	});

	it('supports compact and comfortable densities including live data-density mutations without scroll jump', async () => {
		const threads = makeLargeList(500);
		const { container } = render(MessageList, {
			...baseProps,
			threads,
		});

		const grid = container.querySelector('.sj-msglist__scroll') as HTMLDivElement;
		// Scroll to row 200 in comfortable density (200 * 84 = 16,800px).
		grid.scrollTop = 200 * 84;
		await fireEvent.scroll(grid);
		await tick();
		expect(container.querySelector('[data-vindex="200"]')).not.toBeNull();

		// Toggle <html data-density="compact"> -> MutationObserver updates density and re-anchors row 200.
		document.documentElement.dataset.density = 'compact';
		await new Promise((r) => setTimeout(r, 0));
		await tick();

		// Row 200 remains mounted and scrollTop re-anchored from 16,800 to 200 * 64 = 12,800.
		expect(grid.scrollTop).toBe(200 * 64);
		expect(container.querySelector('[data-vindex="200"]')).not.toBeNull();
	});

	it('adjusts scrollTop without jump when a measured row above viewport changes height via ResizeObserver', async () => {
		const observed = new Map<Element, ResizeObserverCallback>();
		class MockResizeObserver {
			cb: ResizeObserverCallback;
			constructor(cb: ResizeObserverCallback) {
				this.cb = cb;
			}
			observe(el: Element) {
				observed.set(el, this.cb);
			}
			unobserve(el: Element) {
				observed.delete(el);
			}
			disconnect() {
				observed.clear();
			}
		}
		vi.stubGlobal('ResizeObserver', MockResizeObserver);

		const threads = makeLargeList(200);
		const { container } = render(MessageList, {
			...baseProps,
			threads,
			overscan: 6,
		});
		const grid = container.querySelector('.sj-msglist__scroll') as HTMLDivElement;
		Object.defineProperty(grid, 'clientHeight', { value: 500, configurable: true });
		// Trigger container ResizeObserver callback
		const gridCb = observed.get(grid);
		gridCb?.([], {} as ResizeObserver);

		// Scroll down so overscan row 96 is mounted above scrollTop (100 * 84 = 8400).
		grid.scrollTop = 100 * 84;
		await fireEvent.scroll(grid);
		await tick();

		const aboveRow = container.querySelector('[data-vindex="96"]') as HTMLElement;
		expect(aboveRow).not.toBeNull();
		const rowCb = observed.get(aboveRow);
		expect(rowCb).toBeDefined();

		// Report row 96 as 104px tall (+20px over 84px estimate).
		rowCb!(
			[
				{
					target: aboveRow,
					contentRect: { height: 104 } as DOMRectReadOnly,
					borderBoxSize: [{ blockSize: 104, inlineSize: 300 }] as unknown as ResizeObserverSize[],
				} as unknown as ResizeObserverEntry,
			],
			{} as ResizeObserver,
		);
		await tick();

		// Scroll offset compensated by +20px so visible row 100 stays locked in place.
		expect(grid.scrollTop).toBe(100 * 84 + 20);
	});

	it('renders date/group headers and expanded threads without scroll jump', async () => {
		const now = new Date();
		const yesterday = new Date(now.getTime() - 86_400_000);
		const threads = [
			makeThread({
				id: 'tp',
				emails: [makeEmail({ id: 'ep', threadId: 'tp', pinnedAt: now.toISOString(), receivedAt: now.toISOString() })],
			}),
			makeThread({
				id: 't-multi',
				emails: [
					makeEmail({ id: 'em1', threadId: 't-multi', subject: 'Multi thread', receivedAt: now.toISOString() }),
					makeEmail({ id: 'em2', threadId: 't-multi', subject: 'Re: Multi thread', receivedAt: now.toISOString() }),
				],
				expanded: false,
			}),
			...Array.from({ length: 40 }, (_, i) =>
				makeThread({
					id: `tu-${i}`,
					emails: [makeEmail({ id: `eu-${i}`, threadId: `tu-${i}`, receivedAt: yesterday.toISOString() })],
				}),
			),
		];

		const { container, rerender } = render(MessageList, {
			...baseProps,
			threads,
			viewMode: 'threaded',
			groupByDate: true,
		});

		const headers = Array.from(container.querySelectorAll('.sj-msglist__group-label')).map((el) =>
			el.textContent?.trim(),
		);
		expect(headers).toContain('Pinned');
		expect(headers).toContain('Today');
		expect(headers).toContain('Yesterday');

		// Scroll down to row 20, then expand the thread above the viewport -> anchor preserves scroll.
		const grid = container.querySelector('.sj-msglist__scroll') as HTMLDivElement;
		grid.scrollTop = 1600;
		await fireEvent.scroll(grid);
		await tick();
		const beforeScroll = grid.scrollTop;

		const expandedThreads = threads.map((t) => (t.id === 't-multi' ? { ...t, expanded: true } : t));
		await rerender({
			...baseProps,
			threads: expandedThreads,
			viewMode: 'threaded',
			groupByDate: true,
		});
		await tick();

		// Expanding 2 child rows above viewport shifted scrollTop by +168px (2 * 84px) so visible row didn't jump.
		expect(grid.scrollTop).toBe(beforeScroll + 2 * 84);
	});

	it('keyboard navigation (Arrow/j/k/Home/End/PageUp/PageDown) keeps focus and selection synced via scrollToIndex', async () => {
		const onOpen = vi.fn();
		const threads = makeLargeList(500);
		const { container, component } = render(MessageList, {
			...baseProps,
			threads,
			onOpen,
		});

		const grid = container.querySelector('.sj-msglist__scroll') as HTMLDivElement;

		// ArrowDown moves from index 0 -> 1
		await fireEvent.keyDown(grid, { key: 'ArrowDown' });
		await tick();
		expect(onOpen).toHaveBeenLastCalledWith(expect.objectContaining({ id: 'e-1' }));
		expect(document.activeElement?.getAttribute('aria-label')).toContain('Message 1');

		// 'j' moves 1 -> 2
		await fireEvent.keyDown(grid, { key: 'j' });
		await tick();
		expect(onOpen).toHaveBeenLastCalledWith(expect.objectContaining({ id: 'e-2' }));

		// 'k' moves 2 -> 1
		await fireEvent.keyDown(grid, { key: 'k' });
		await tick();
		expect(onOpen).toHaveBeenLastCalledWith(expect.objectContaining({ id: 'e-1' }));

		// ArrowUp moves 1 -> 0
		await fireEvent.keyDown(grid, { key: 'ArrowUp' });
		await tick();
		expect(onOpen).toHaveBeenLastCalledWith(expect.objectContaining({ id: 'e-0' }));

		// PageDown jumps roughly one viewport
		await fireEvent.keyDown(grid, { key: 'PageDown' });
		await tick();
		const afterPageDownId = onOpen.mock.calls.at(-1)?.[0]?.id as string;
		expect(Number(afterPageDownId.replace('e-', ''))).toBeGreaterThanOrEqual(5);

		// PageUp jumps back toward top
		await fireEvent.keyDown(grid, { key: 'PageUp' });
		await tick();
		expect(onOpen).toHaveBeenLastCalledWith(expect.objectContaining({ id: 'e-0' }));

		// End jumps all the way to off-screen row 499, scrolls it into view, selects & focuses it
		await fireEvent.keyDown(grid, { key: 'End' });
		await tick();
		expect(onOpen).toHaveBeenLastCalledWith(expect.objectContaining({ id: 'e-499' }));
		expect(grid.scrollTop).toBeGreaterThan(30_000);
		expect(container.querySelector('[data-vindex="499"]')).not.toBeNull();
		expect(document.activeElement?.getAttribute('aria-label')).toContain('Message 499');

		// Home jumps back to row 0
		await fireEvent.keyDown(grid, { key: 'Home' });
		await tick();
		expect(onOpen).toHaveBeenLastCalledWith(expect.objectContaining({ id: 'e-0' }));
		expect(grid.scrollTop).toBe(0);
		expect(document.activeElement?.getAttribute('aria-label')).toContain('Message 0');

		// Modifier keys and unrelated keys (e.g. '/' for in-app full-list search) are not intercepted
		const callCountBefore = onOpen.mock.calls.length;
		await fireEvent.keyDown(grid, { key: 'j', ctrlKey: true });
		await fireEvent.keyDown(grid, { key: '/' });
		expect(onOpen.mock.calls.length).toBe(callCountBefore);

		// Exported scrollToIndex method works imperatively
		component.scrollToIndex(300, 'start');
		await tick();
		expect(grid.scrollTop).toBe(300 * 84);
		expect(container.querySelector('[data-vindex="300"]')).not.toBeNull();
	});

	it('syncs scroll position when selectedId changes externally to an off-screen row', async () => {
		const threads = makeLargeList(500);
		const { container, rerender } = render(MessageList, {
			...baseProps,
			threads,
			selectedId: 'e-0',
		});

		const grid = container.querySelector('.sj-msglist__scroll') as HTMLDivElement;
		expect(grid.scrollTop).toBe(0);

		await rerender({
			...baseProps,
			threads,
			selectedId: 'e-400',
		});
		await tick();

		expect(grid.scrollTop).toBeGreaterThan(30_000);
		const selectedRow = container.querySelector('[data-vindex="400"]');
		expect(selectedRow).not.toBeNull();
		expect(selectedRow?.getAttribute('aria-selected')).toBe('true');
		expect(selectedRow?.getAttribute('aria-rowindex')).toBe('401');
	});

	it('preserves thread header keyboard toggle, archive button, focus tabs, and action facade', async () => {
		const actions = {
			onOpen: vi.fn(),
			onArchive: vi.fn(),
			onStar: vi.fn(),
			onTrash: vi.fn(),
			onToggleRead: vi.fn(),
			onToggleThread: vi.fn(),
			onMuteThread: vi.fn(),
			onArchiveThread: vi.fn(),
			onLoadMore: vi.fn(),
			onCancelScheduled: vi.fn(),
			onMoveFocus: vi.fn(),
			onSnooze: vi.fn(),
		};
		const onFocusTab = vi.fn();
		const threads = [
			makeThread({
				id: 'tm',
				emails: [
					makeEmail({ id: 'em1', threadId: 'tm', mailboxIds: { other: true } }),
					makeEmail({ id: 'em2', threadId: 'tm' }),
				],
				expanded: false,
			}),
			makeThread({
				id: 'ts',
				emails: [makeEmail({ id: 'es1', threadId: 'ts', mailboxIds: { tag1: true, other: true } })],
			}),
		];

		const { container } = render(MessageList, {
			threads,
			viewMode: 'threaded',
			selectedId: 'es1',
			tags: [makeTag('tag1', 'Finance')],
			loading: false,
			loadingMore: false,
			hasMore: false,
			remaining: 0,
			actions,
			scheduledTimes: { es1: '2026-06-15T09:00:00Z' },
			otherTagId: 'other',
			focusTab: 'focused',
			otherUnread: 3,
			onFocusTab,
		});

		// Focus tabs wire onFocusTab
		const otherTab = container.querySelectorAll('[role="tab"]')[1] as HTMLButtonElement;
		await fireEvent.click(otherTab);
		expect(onFocusTab).toHaveBeenCalledWith('other');

		// Thread header Enter/Space toggles thread and Archive thread button calls onArchiveThread
		const threadHeader = container.querySelector('.sj-msglist__thread-header') as HTMLElement;
		expect(threadHeader.getAttribute('aria-expanded')).toBe('false');
		await fireEvent.keyDown(threadHeader, { key: 'Enter' });
		expect(actions.onToggleThread).toHaveBeenCalledWith('tm');

		const archiveThreadBtn = container.querySelector('[aria-label="Archive thread"]') as HTMLButtonElement;
		await fireEvent.click(archiveThreadBtn);
		expect(actions.onArchiveThread).toHaveBeenCalledWith('tm');

		// Row actions propagate through facade
		const row = container.querySelector('.sj-mailrow') as HTMLElement;
		await fireEvent.click(row);
		expect(actions.onOpen).toHaveBeenCalledWith(expect.objectContaining({ id: 'es1' }));
		await fireEvent.click(row.querySelector('[aria-label="Archive"]') as HTMLButtonElement);
		expect(actions.onArchive).toHaveBeenCalled();
		await fireEvent.click(row.querySelector('[aria-label="Star"]') as HTMLButtonElement);
		expect(actions.onStar).toHaveBeenCalled();
		await fireEvent.click(row.querySelector('[aria-label="Trash"]') as HTMLButtonElement);
		expect(actions.onTrash).toHaveBeenCalled();
		await fireEvent.click(row.querySelector('[aria-label="Move to Focused"]') as HTMLButtonElement);
		expect(actions.onMoveFocus).toHaveBeenCalledWith(expect.objectContaining({ id: 'es1' }), true);
		await fireEvent.click(row.querySelector('[aria-label="Cancel send"]') as HTMLButtonElement);
		expect(actions.onCancelScheduled).toHaveBeenCalledWith('es1');
	});

	it('produces zero ARIA grid/row/attribute violations in axe-core', async () => {
		const threads = makeLargeList(50);
		const { container } = render(MessageList, {
			...baseProps,
			threads,
			selectedId: 'e-1',
			groupByDate: true,
		});

		const results = await axe.run(container, {
			runOnly: {
				type: 'rule',
				values: [
					'aria-allowed-attr',
					'aria-conditional-attr',
					'aria-required-attr',
					'aria-required-children',
					'aria-required-parent',
					'aria-roles',
					'aria-valid-attr',
					'aria-valid-attr-value',
				],
			},
		});
		expect(results.violations).toEqual([]);
	});

	it('resets scrollTop cleanly on loading remount and disjoint folder/filter transitions', async () => {
		const inboxThreads = makeLargeList(300);
		const { container, rerender } = render(MessageList, {
			...baseProps,
			threads: inboxThreads,
		});

		const grid1 = container.querySelector('.sj-msglist__scroll') as HTMLDivElement;
		grid1.scrollTop = 200 * 84;
		await fireEvent.scroll(grid1);
		await tick();
		expect(container.querySelector('[data-vindex="200"]')).not.toBeNull();

		// Transition through loading=true -> loading=false (unmounts and remounts scrollEl)
		await rerender({ ...baseProps, threads: inboxThreads, loading: true });
		await tick();
		expect(container.querySelector('.sj-msglist__scroll')).toBeNull();

		const sentThreads = Array.from({ length: 200 }, (_, i) =>
			makeThread({
				id: `sent-${i}`,
				emails: [makeEmail({ id: `se-${i}`, threadId: `sent-${i}`, subject: `Sent ${i}` })],
			}),
		);
		await rerender({ ...baseProps, threads: sentThreads, loading: false });
		await tick();

		const grid2 = container.querySelector('.sj-msglist__scroll') as HTMLDivElement;
		expect(grid2.scrollTop).toBe(0);
		expect(container.querySelector('[data-vindex="0"]')).not.toBeNull();

		// Direct disjoint filter switch (without loading phase) resets scroll to 0
		grid2.scrollTop = 100 * 84;
		await fireEvent.scroll(grid2);
		await tick();
		expect(container.querySelector('[data-vindex="100"]')).not.toBeNull();

		const filteredThreads = Array.from({ length: 50 }, (_, i) =>
			makeThread({
				id: `flt-${i}`,
				emails: [makeEmail({ id: `fe-${i}`, threadId: `flt-${i}`, subject: `Filtered ${i}` })],
			}),
		);
		await rerender({ ...baseProps, threads: filteredThreads, loading: false });
		await tick();

		expect(grid2.scrollTop).toBe(0);
		expect(container.querySelector('[data-vindex="0"]')).not.toBeNull();
	});

	it('renders interleaved non-chronological groupByDate headers without duplicate keys and respects i18n locale', async () => {
		setLocale('zh');
		const now = new Date();
		const old = new Date(now.getTime() - 20 * 86_400_000);
		const threads = [
			makeThread({ id: 'tp', emails: [makeEmail({ id: 'ep', pinnedAt: now.toISOString(), receivedAt: now.toISOString() })] }),
			makeThread({ id: 't1', emails: [makeEmail({ id: 'e1', subject: 'A', receivedAt: now.toISOString() })] }),
			makeThread({ id: 't2', emails: [makeEmail({ id: 'e2', subject: 'B', receivedAt: old.toISOString() })] }),
			makeThread({ id: 't3', emails: [makeEmail({ id: 'e3', subject: 'C', receivedAt: now.toISOString() })] }),
			makeThread({ id: 't4', emails: [makeEmail({ id: 'e4', subject: 'D', receivedAt: old.toISOString() })] }),
		];

		const { container } = render(MessageList, {
			...baseProps,
			threads,
			groupByDate: true,
		});

		const labels = Array.from(container.querySelectorAll('.sj-msglist__group-label')).map((el) =>
			el.textContent?.trim(),
		);
		expect(labels).toEqual(['置顶', '今天', '更早', '今天', '更早']);
	});

	it('keeps a tabbable tabindex="0" row mounted when effectiveActiveIndex scrolls off-screen', async () => {
		const threads = makeLargeList(500);
		const { container } = render(MessageList, {
			...baseProps,
			threads,
			selectedId: 'e-0',
		});

		const grid = container.querySelector('.sj-msglist__scroll') as HTMLDivElement;
		expect(container.querySelectorAll('.sj-mailrow[tabindex="0"]').length).toBe(1);

		// Scroll far past index 0 so active row 0 unmounts
		grid.scrollTop = 250 * 84;
		await fireEvent.scroll(grid);
		await tick();

		expect(container.querySelector('[data-vindex="0"]')).toBeNull();
		const tabbableRows = container.querySelectorAll('.sj-mailrow[tabindex="0"]');
		expect(tabbableRows.length).toBe(1);
	});

	it('does not re-fire onOpen on boundary keypresses when the target email is already selected', async () => {
		const onOpen = vi.fn();
		const threads = makeLargeList(5);
		const { container } = render(MessageList, {
			...baseProps,
			threads,
			selectedId: 'e-0',
			onOpen,
		});

		const grid = container.querySelector('.sj-msglist__scroll') as HTMLDivElement;
		await fireEvent.keyDown(grid, { key: 'ArrowUp' });
		await fireEvent.keyDown(grid, { key: 'Home' });
		expect(onOpen).not.toHaveBeenCalled();

		// Move to last row -> calls onOpen once, then boundary ArrowDown/End when selectedId matches does not re-fire
		const { container: c2 } = render(MessageList, {
			...baseProps,
			threads,
			selectedId: 'e-4',
			onOpen,
		});
		const grid2 = c2.querySelector('.sj-msglist__scroll') as HTMLDivElement;
		await fireEvent.keyDown(grid2, { key: 'ArrowDown' });
		await fireEvent.keyDown(grid2, { key: 'End' });
		expect(onOpen).not.toHaveBeenCalled();
	});

	it('applies data-density on explicit density prop and renders EmptyState for degenerate empty-email threads', async () => {
		const { container } = render(MessageList, {
			...baseProps,
			threads: [makeThread({ id: 'empty', emails: [] })],
			density: 'compact',
		});

		expect(container.querySelector('.sj-msglist')?.getAttribute('data-density')).toBe('compact');
		expect(container.querySelector('.sj-empty')).not.toBeNull();
		expect(container.querySelector('[role="grid"]')).toBeNull();
	});

	it('prunes stale measuredHeights entries after large disjoint list transitions', async () => {
		let observerCb: ResizeObserverCallback | null = null;
		class MockResizeObserver {
			constructor(cb: ResizeObserverCallback) {
				observerCb = cb;
			}
			observe() {}
			unobserve() {}
			disconnect() {}
		}
		vi.stubGlobal('ResizeObserver', MockResizeObserver);

		// Populate 200 items with non-zero bounding rects via mocked getBoundingClientRect
		const origRect = HTMLElement.prototype.getBoundingClientRect;
		HTMLElement.prototype.getBoundingClientRect = () =>
			({ height: 92, width: 300, top: 0, left: 0, bottom: 92, right: 300, x: 0, y: 0, toJSON: () => {} }) as DOMRect;
		try {
			const batchA = makeLargeList(200);
			const { container, rerender } = render(MessageList, {
				...baseProps,
				threads: batchA,
				overscan: 150,
			});
			await tick();
			expect(observerCb).not.toBeNull();

			// Switch to tiny disjoint batch B -> measuredHeights.size (>150) > virtualItems.length (2) + 128 triggers prune
			const batchB = [
				makeThread({ id: 'b-0', emails: [makeEmail({ id: 'be-0', threadId: 'b-0' })] }),
				makeThread({ id: 'b-1', emails: [makeEmail({ id: 'be-1', threadId: 'b-1' })] }),
			];
			await rerender({ ...baseProps, threads: batchB, overscan: 6 });
			await tick();

			expect(container.querySelectorAll('.sj-mailrow').length).toBe(2);
		} finally {
			HTMLElement.prototype.getBoundingClientRect = origRect;
		}
	});
});
