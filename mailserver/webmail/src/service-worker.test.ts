import { describe, it, expect, vi } from 'vitest';

// $service-worker is a SvelteKit virtual module only available at build time;
// stub it so the unit-test harness can import service-worker.ts directly.
vi.mock('$service-worker', () => ({ build: [], files: [], version: 'test' }));

import {
	shouldServeShell,
	buildMailNotification,
	buildChatNotification,
	routeNotificationClick,
	chatNotificationUrl,
	handleNotificationClick,
} from './service-worker';

// jsdom's Request rejects mode:'navigate' — patch .mode on the instance so the
// test exercises the same code path as the real SW environment.
// ponytail: jsdom shim; upgrade path = run these tests in a web worker env if mode becomes broader.
function nav(url: string): Request {
	const req = new Request(url, { headers: { Accept: 'text/html' } });
	Object.defineProperty(req, 'mode', { value: 'navigate', configurable: true });
	return req;
}

describe('SW navigation fallback', () => {
	it('serves the shell for an app route', () => {
		expect(shouldServeShell(nav('https://app/mail/inbox'))).toBe(true);
	});
	it('never intercepts /jmap (mail-caching ban preserved)', () => {
		const req = new Request('https://app/jmap');
		Object.defineProperty(req, 'mode', { value: 'navigate', configurable: true });
		expect(shouldServeShell(req)).toBe(false);
	});
	it('never intercepts native attachment transfer routes', () => {
		expect(shouldServeShell(nav('https://app/mail-attachment/' + 'a'.repeat(64)))).toBe(false);
	});
	it('ignores non-navigation requests', () => {
		expect(shouldServeShell(new Request('https://app/x.js'))).toBe(false);
	});
});

describe('push -> showNotification shape', () => {
	// Pre-existing bug (A3.5 Task 4, fix-bugs-before-continuing): pushjobs/worker.go
	// (the ONLY real producer of a mail webpush payload, buildPayload@worker.go:301-308)
	// emits `type:"mail"` with `sender:{name,email}` + `subject` — never a flat
	// title/body. This function's guard only ever accepted `type:'new_mail'` AND
	// read title/body — fields nothing in the repo ever sent — so the live mail
	// webpush path never rendered real content. Fixed to accept the real type AND
	// map sender.name/subject; this fixture now matches the producer's actual wire
	// shape (see mailpush_e2e_test.go:371, which pins `payload["subject"]` server-side).
	it('builds a mail notification with sender.name as title, subject as body, message id as tag', () => {
		const n = buildMailNotification({
			type: 'mail',
			sender: { name: 'Alice', email: 'alice@example.com' },
			subject: 'Re: budget',
			messageId: 'm1',
			threadId: 't1',
		});
		expect(n).not.toBeNull();
		expect(n!.title).toBe('Alice');
		expect(n!.options.body).toBe('Re: budget');
		expect(n!.options.tag).toBe('m1'); // dedupe/replace key
		expect(n!.options.actions).toEqual([
			{ action: 'archive', title: 'Archive' },
			{ action: 'reply', title: 'Reply' },
		]);
	});

	it('falls back to threadId for the tag when messageId is absent', () => {
		const n = buildMailNotification({ type: 'mail', threadId: 't1' });
		expect(n!.options.tag).toBe('t1');
	});

	it('ignores a non-mail push payload (e.g. the MFA webpush shape)', () => {
		expect(buildMailNotification({ type: 'mfa_challenge' })).toBeNull();
	});

	it('ignores a chat push payload (routed to buildChatNotification instead)', () => {
		expect(buildMailNotification({ type: 'chat' })).toBeNull();
	});

	it('treats an untyped payload as mail (back-compat default)', () => {
		expect(buildMailNotification({ title: 'Bob' })).not.toBeNull();
	});
});

describe('chat push -> showNotification shape (A3.5 Task 4)', () => {
	it('renders the sender as title and the channel name as body, tagged for per-channel replacement', () => {
		const n = buildChatNotification({
			type: 'chat',
			channelId: 7,
			messageId: 42,
			seq: 5,
			sender: 'Alice',
			channelName: 'eng',
			mention: false,
			dedupeTag: 'chat-7',
		});
		expect(n).not.toBeNull();
		expect(n!.title).toBe('Alice');
		expect(n!.options.body).toBe('eng');
		expect(n!.options.tag).toBe('chat-7');
	});

	it('prefixes the title with the mention marker when mention is true', () => {
		const n = buildChatNotification({
			type: 'chat',
			channelId: 7,
			messageId: 42,
			seq: 5,
			sender: 'Alice',
			channelName: 'eng',
			mention: true,
			dedupeTag: 'chat-7',
		});
		expect(n!.title).not.toBe('Alice');
		expect(n!.title.endsWith('Alice')).toBe(true);
	});

	it('renders the localized "Direct message" body when channelName is empty (plain DM, chat_channels.name is NULL)', () => {
		const n = buildChatNotification({
			type: 'chat',
			channelId: 3,
			messageId: 9,
			seq: 1,
			sender: 'Bob',
			channelName: '',
			mention: false,
			dedupeTag: 'chat-3',
		});
		expect(n!.options.body).toBe('Direct message');
	});

	it('never renders message content — options.body is only ever the sender/channel shape, never a text/preview field', () => {
		// Payload-privacy posture (A3.5 Global Constraint): the server-side payload
		// itself carries no message body — planChatFanout (worker.go) never sets a
		// text/preview field, so there is nothing for the client to render even if
		// it wanted to. This pins the CLIENT side of that contract: passing a
		// (hypothetical, server would never send one) extra body-shaped field is
		// simply not read.
		const n = buildChatNotification({
			type: 'chat',
			channelId: 7,
			messageId: 42,
			seq: 5,
			sender: 'Alice',
			channelName: 'eng',
			mention: false,
			dedupeTag: 'chat-7',
			text: 'the actual message content', // not part of ChatPushPayload; proves it's ignored
		} as unknown as Parameters<typeof buildChatNotification>[0]);
		expect(n!.options.body).toBe('eng');
	});

	it('ignores a non-chat push payload', () => {
		expect(buildChatNotification({ type: 'mail' })).toBeNull();
	});
});

describe('notificationclick routing', () => {
	it('routes the archive action to an archive with the message id', () => {
		expect(routeNotificationClick('archive', { messageId: 'm1' })).toEqual({ kind: 'archive', messageId: 'm1' });
	});

	it('falls back to focus/open when archive is clicked with no message id', () => {
		expect(routeNotificationClick('archive', {})).toEqual({ kind: 'focus', url: '/inbox?t=' });
	});

	it('routes the reply action to the deep link (thread id preferred)', () => {
		expect(routeNotificationClick('reply', { messageId: 'm1', threadId: 't1' })).toEqual({ kind: 'focus', url: '/inbox?t=t1' });
	});

	it('routes a bare (body) click the same as reply', () => {
		expect(routeNotificationClick('', { messageId: 'm1' })).toEqual({ kind: 'focus', url: '/inbox?t=m1' });
	});

	it('closes immediately and registers exactly one waitUntil command', () => {
		const close = vi.fn();
		const waitUntil = vi.fn();
		const runCommand = vi.fn().mockResolvedValue({ kind: 'opened' });
		handleNotificationClick({
			action: 'archive',
			notification: { data: { messageId: 'm1' }, close } as unknown as Notification,
			waitUntil,
		}, runCommand);
		expect(close).toHaveBeenCalledTimes(1);
		expect(runCommand).toHaveBeenCalledWith({ kind: 'archive', messageId: 'm1', targetUrl: '/inbox?t=m1' });
		expect(waitUntil).toHaveBeenCalledTimes(1);
		expect(waitUntil).toHaveBeenCalledWith(runCommand.mock.results[0].value);
	});

	it('keeps chat on the focus command and bypasses the mail archive branch', () => {
		const runCommand = vi.fn().mockResolvedValue({ kind: 'focused' });
		handleNotificationClick({
			action: 'archive',
			notification: { data: { type: 'chat', channelId: 7, seq: 42 }, close: vi.fn() } as unknown as Notification,
			waitUntil: vi.fn(),
		}, runCommand);
		expect(runCommand).toHaveBeenCalledWith({ kind: 'focus', targetUrl: '/chat?channel=7&seq=42' });
	});
});

describe('chatNotificationUrl (A3.5 Task 4 deep link)', () => {
	it('builds the /chat?channel=&seq= deep link openChannelAt needs (seq-keyed, not messageId, per the plan\'s payload shape)', () => {
		expect(chatNotificationUrl({ channelId: 7, seq: 42 })).toBe('/chat?channel=7&seq=42');
	});
});
