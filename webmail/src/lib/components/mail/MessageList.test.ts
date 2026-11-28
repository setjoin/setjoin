import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte/svelte5';
import MessageList from './MessageList.svelte';
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
