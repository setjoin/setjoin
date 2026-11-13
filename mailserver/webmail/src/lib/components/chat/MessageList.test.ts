import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import { tick } from 'svelte';
import MessageList from './MessageList.svelte';
import { chatStore, type StoreMessage } from '$lib/chat/store.svelte';
import type { ChatMessage, Conversation } from '$lib/chat/api';

const listMessages = vi.fn();

vi.mock('$lib/chat/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/chat/api')>('$lib/chat/api');
	return {
		...actual,
		listMessages: (...a: unknown[]) => listMessages(...a),
	};
});

function msg(over: Partial<ChatMessage> = {}): StoreMessage {
	return {
		messageId: 1,
		channelId: 1,
		seq: 1,
		authorId: 99,
		authorExternal: false,
		authorRemoved: false,
		parentMessageId: null,
		msgType: 'text',
		broadcast: null,
		body: 'hello',
		editedAt: null,
		deletedAt: null,
		createdAt: '2026-07-11T00:00:00Z',
		reactions: [],
		mentionsMe: false,
		replyCount: 0,
		lastReplyAt: null,
		status: 'sent',
		...over,
	};
}

function conv(over: Partial<Conversation> = {}): Conversation {
	return {
		channelId: 1,
		kind: 'channel',
		name: 'eng',
		topic: null,
		changeSeq: 5,
		lastReadSeq: 0,
		unreadCount: 0,
		hasMention: false,
		hasExternalMembers: false,
		lastMessagePreview: null,
		memberIds: [],
		...over,
	};
}

/** jsdom never computes real layout, so scrollHeight/clientHeight are inert
 *  0-returning getters. scrollHeight is stubbed as a LIVE getter keyed off
 *  the rendered row count (100px/row) rather than a fixed number, so it
 *  tracks DOM growth the same way a real browser's reflow would — the
 *  component's post-await reads then see accurate "new" values without the
 *  test racing to hand-patch the stub between microtasks. */
function stubScrollMetrics(el: HTMLElement, opts: { clientHeight: number; scrollTop?: number }) {
	Object.defineProperty(el, 'scrollHeight', {
		configurable: true,
		get: () => el.querySelectorAll('.ml__row').length * 100,
	});
	Object.defineProperty(el, 'clientHeight', { value: opts.clientHeight, configurable: true });
	if (opts.scrollTop != null) el.scrollTop = opts.scrollTop;
}

beforeEach(() => {
	listMessages.mockReset();
	// Safe default: the prepend path (maybeLoadOlder) can fire incidentally off
	// any scroll event whose scrollTop happens to land near 0 — tests that
	// don't care about pagination shouldn't have to know that.
	listMessages.mockResolvedValue([]);
	chatStore.messagesByChannel = {};
	chatStore.conversations = [];
	chatStore.atBottom = true;
	chatStore.unseenBelow = 0;
	chatStore.typingUsers = [];
	chatStore.selfUserId = null;
	chatStore.activeChannelId = null;
});

afterEach(() => {
	vi.clearAllMocks();
});

describe('MessageList', () => {
	it('renders top-level messages only; a reply chip opens ThreadPane via onOpenThread', async () => {
		chatStore.conversations = [conv()];
		chatStore.messagesByChannel[1] = [
			msg({ messageId: 1, seq: 1, body: 'root', replyCount: 2 }),
			msg({ messageId: 2, seq: 2, body: 'a reply', parentMessageId: 1 }),
		];
		const onOpenThread = vi.fn();
		render(MessageList, { channelId: 1, onOpenThread });

		expect(screen.getByText('root')).toBeTruthy();
		expect(screen.queryByText('a reply')).toBeNull();
		const chip = screen.getByText('2 replies');
		await fireEvent.click(chip);
		expect(onOpenThread).toHaveBeenCalledWith(1);
	});

	it('stick-to-bottom (≤80px): an append while atBottom autoscrolls to the new bottom', async () => {
		chatStore.conversations = [conv()];
		chatStore.messagesByChannel[1] = [msg({ messageId: 1, seq: 1 })];
		chatStore.atBottom = true;
		const { container } = render(MessageList, { channelId: 1 });
		const scroller = container.querySelector('[data-testid="message-list-scroll"]') as HTMLElement;
		stubScrollMetrics(scroller, { clientHeight: 300, scrollTop: 100 });

		chatStore.messagesByChannel[1] = [...chatStore.messagesByChannel[1], msg({ messageId: 2, seq: 2 })];
		await tick();
		await tick();

		expect(scroller.scrollTop).toBe(scroller.scrollHeight); // 2 rows * 100
	});

	it('an append while scrolled away from bottom pins the scroll position (no autoscroll) — jump pill reads store.unseenBelow', async () => {
		chatStore.conversations = [conv()];
		chatStore.messagesByChannel[1] = [msg({ messageId: 1, seq: 1 })];
		chatStore.atBottom = false;
		chatStore.unseenBelow = 3;
		const { container } = render(MessageList, { channelId: 1 });
		const scroller = container.querySelector('[data-testid="message-list-scroll"]') as HTMLElement;
		stubScrollMetrics(scroller, { clientHeight: 300, scrollTop: 10 });

		chatStore.messagesByChannel[1] = [...chatStore.messagesByChannel[1], msg({ messageId: 2, seq: 2 })];
		await tick();
		await tick();

		expect(scroller.scrollTop).toBe(10); // pinned, not moved
		expect(screen.getByText('New messages ↓ (3)')).toBeTruthy();
	});

	it('renders a sticky "New" divider at the first message past lastReadSeq, frozen for the session', async () => {
		chatStore.conversations = [conv({ lastReadSeq: 2 })];
		chatStore.messagesByChannel[1] = [
			msg({ messageId: 1, seq: 1 }),
			msg({ messageId: 2, seq: 2 }),
			msg({ messageId: 3, seq: 3 }),
			msg({ messageId: 4, seq: 4 }),
		];
		const { container } = render(MessageList, { channelId: 1 });
		await tick();

		const divider = container.querySelector('[data-testid="new-divider"]');
		expect(divider).toBeTruthy();
		// divider sits immediately before message 3 (first seq > 2)
		expect(divider?.nextElementSibling?.querySelector('[data-testid="msg-3"]')).toBeTruthy();

		// A mark-read bump to lastReadSeq=4 must NOT move the frozen divider.
		chatStore.conversations[0].lastReadSeq = 4;
		await tick();
		const dividerAfter = container.querySelector('[data-testid="new-divider"]');
		expect(dividerAfter).toBeTruthy();
		expect(dividerAfter?.nextElementSibling?.querySelector('[data-testid="msg-3"]')).toBeTruthy();
	});

	it('history prepend (beforeSeq) anchors the pre-load top element — no viewport jump', async () => {
		chatStore.conversations = [conv()];
		chatStore.messagesByChannel[1] = [msg({ messageId: 5, seq: 5, body: 'oldest-loaded' })];
		listMessages.mockResolvedValue([msg({ messageId: 4, seq: 4, body: 'older-1' }), msg({ messageId: 3, seq: 3, body: 'older-2' })]);
		const { container } = render(MessageList, { channelId: 1 });
		const scroller = container.querySelector('[data-testid="message-list-scroll"]') as HTMLElement;
		stubScrollMetrics(scroller, { clientHeight: 300, scrollTop: 0 });
		const preLoadScrollHeight = scroller.scrollHeight; // 1 row * 100

		await fireEvent.scroll(scroller);
		await waitFor(() => expect(listMessages).toHaveBeenCalledWith(1, { beforeSeq: 5, limit: 50 }));
		await waitFor(() => expect(screen.getByText('older-2')).toBeTruthy());

		// The anchor keeps its visual position: newScrollTop = newScrollHeight
		// (now 3 rows) - preLoadScrollHeight + preLoadScrollTop(0).
		expect(scroller.scrollTop).toBe(scroller.scrollHeight - preLoadScrollHeight);
	});

	it('mark-read fires on bottom-scroll and on window focus (delegates to store.markReadDebounced, gated there)', async () => {
		chatStore.conversations = [conv({ changeSeq: 9 })];
		chatStore.messagesByChannel[1] = [msg({ messageId: 1, seq: 1 })];
		const spy = vi.spyOn(chatStore, 'markReadDebounced');
		const { container } = render(MessageList, { channelId: 1 });
		const scroller = container.querySelector('[data-testid="message-list-scroll"]') as HTMLElement;
		stubScrollMetrics(scroller, { clientHeight: 300, scrollTop: 0 });

		await fireEvent.scroll(scroller);
		expect(spy).toHaveBeenCalledWith(1, 9);

		spy.mockClear();
		await fireEvent(window, new Event('focus'));
		expect(spy).toHaveBeenCalledWith(1, 9);
	});

	it('typing row collapses: none, 1, 2, then >2 as "several people"', async () => {
		chatStore.conversations = [conv()];
		chatStore.messagesByChannel[1] = [msg()];
		const { rerender } = render(MessageList, { channelId: 1 });
		expect(screen.queryByTestId('typing-row')).toBeNull();

		chatStore.typingUsers = [{ channelId: 1, userId: 7, expiresAt: Date.now() + 4000 }];
		await rerender({ channelId: 1 });
		expect(screen.getByText('1 person is typing…')).toBeTruthy();

		chatStore.typingUsers = [
			{ channelId: 1, userId: 7, expiresAt: Date.now() + 4000 },
			{ channelId: 1, userId: 8, expiresAt: Date.now() + 4000 },
		];
		await rerender({ channelId: 1 });
		expect(screen.getByText('2 people are typing…')).toBeTruthy();

		chatStore.typingUsers = [
			{ channelId: 1, userId: 7, expiresAt: Date.now() + 4000 },
			{ channelId: 1, userId: 8, expiresAt: Date.now() + 4000 },
			{ channelId: 1, userId: 9, expiresAt: Date.now() + 4000 },
			// a typer from a DIFFERENT channel must never count toward THIS channel's row
			{ channelId: 2, userId: 42, expiresAt: Date.now() + 4000 },
		];
		await rerender({ channelId: 1 });
		expect(screen.getByText('Several people are typing…')).toBeTruthy();
	});

	it('arrow-key navigation moves the focused row without stealing DOM focus', async () => {
		chatStore.conversations = [conv()];
		chatStore.messagesByChannel[1] = [msg({ messageId: 1, seq: 1 }), msg({ messageId: 2, seq: 2 })];
		const outside = document.createElement('input');
		document.body.appendChild(outside);
		outside.focus();

		const { container } = render(MessageList, { channelId: 1 });
		const scroller = container.querySelector('[data-testid="message-list-scroll"]') as HTMLElement;

		await fireEvent.keyDown(scroller, { key: 'ArrowDown' });
		expect(container.querySelector('[data-testid="msg-1"]')?.classList.contains('ml__row--focused')).toBe(true);

		await fireEvent.keyDown(scroller, { key: 'ArrowDown' });
		expect(container.querySelector('[data-testid="msg-2"]')?.classList.contains('ml__row--focused')).toBe(true);

		// Never steals focus, including from incoming messages / nav itself.
		expect(document.activeElement).toBe(outside);
		outside.remove();
	});

	it('aria-live=polite announces a genuinely new message, but not the initial page load', async () => {
		chatStore.conversations = [conv()];
		chatStore.messagesByChannel[1] = [msg({ messageId: 1, seq: 1 })];
		const { container } = render(MessageList, { channelId: 1 });
		await tick();
		const region = container.querySelector('[data-testid="chat-live-region"]');
		expect(region?.getAttribute('aria-live')).toBe('polite');
		expect(region?.textContent).toBe('');

		chatStore.messagesByChannel[1] = [...chatStore.messagesByChannel[1], msg({ messageId: 2, seq: 2 })];
		await tick();
		await tick();
		expect(container.querySelector('[data-testid="chat-live-region"]')?.textContent).toBe('New message');
	});

	it('shows an empty state when the channel has no messages', () => {
		chatStore.conversations = [conv()];
		chatStore.messagesByChannel[1] = [];
		render(MessageList, { channelId: 1 });
		expect(screen.getByText('No messages yet — say hello.')).toBeTruthy();
	});

	describe('Task 16: date dividers', () => {
		it('inserts one date divider per calendar-day boundary, not between same-day messages', () => {
			// lastReadSeq set past every seq so the unread "New" divider (a
			// separate feature, seq-driven) never interposes and confuses the
			// date-divider sibling assertions below.
			chatStore.conversations = [conv({ lastReadSeq: 999 })];
			chatStore.messagesByChannel[1] = [
				msg({ messageId: 1, seq: 1, createdAt: '2026-07-09T10:00:00Z' }),
				msg({ messageId: 2, seq: 2, createdAt: '2026-07-09T11:00:00Z' }), // same day as #1
				msg({ messageId: 3, seq: 3, createdAt: '2026-07-10T09:00:00Z' }), // new day
			];
			const { container } = render(MessageList, { channelId: 1 });
			const dividers = container.querySelectorAll('[data-testid="date-divider"]');
			expect(dividers.length).toBe(2); // one before msg-1, one before msg-3
			expect(dividers[0].nextElementSibling?.querySelector('[data-testid="msg-1"]')).toBeTruthy();
			expect(dividers[1].nextElementSibling?.querySelector('[data-testid="msg-3"]')).toBeTruthy();
		});

		it('labels today/yesterday specially and falls back to a formatted date otherwise', () => {
			vi.useFakeTimers();
			vi.setSystemTime(new Date('2026-07-11T12:00:00Z'));
			chatStore.conversations = [conv()];
			chatStore.messagesByChannel[1] = [
				msg({ messageId: 1, seq: 1, createdAt: '2026-07-01T10:00:00Z' }),
				msg({ messageId: 2, seq: 2, createdAt: '2026-07-10T10:00:00Z' }), // yesterday
				msg({ messageId: 3, seq: 3, createdAt: '2026-07-11T10:00:00Z' }), // today
			];
			const { container } = render(MessageList, { channelId: 1 });
			const labels = Array.from(container.querySelectorAll('[data-testid="date-divider"]')).map((d) => d.textContent);
			expect(labels).toContain('Today');
			expect(labels).toContain('Yesterday');
			expect(labels.some((l) => l && !['Today', 'Yesterday'].includes(l))).toBe(true);
			vi.useRealTimers();
		});
	});
});
