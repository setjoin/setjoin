import { describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
	runNotificationCommand,
	type NotificationClientsPort,
	type NotificationWindowClient,
} from './notificationCommand';

const origin = 'https://mail.example.test';

function jmapResponse(methodResponses: unknown[]): Response {
	return new Response(JSON.stringify({ methodResponses }), {
		status: 200,
		headers: { 'content-type': 'application/json' },
	});
}

function makeFetch(options: {
	keywords?: Record<string, boolean>;
	notUpdated?: Record<string, unknown>;
	wrongGetCallId?: boolean;
	wrongSetMethod?: boolean;
	mailboxIds?: Record<string, boolean>;
} = {}) {
	return vi.fn(async function (input: RequestInfo | URL, init?: RequestInit) {
		if (String(input).endsWith('/jmap/session')) {
			return new Response(
				JSON.stringify({
					apiUrl: `${origin}/jmap`,
					primaryAccounts: { 'urn:ietf:params:jmap:mail': 'account-a' },
				}),
				{ status: 200 },
			);
		}
		const body = JSON.parse(String(init?.body ?? '{}'));
		const isSet = body.methodCalls?.some((call: unknown[]) => call[0] === 'Email/set');
		if (isSet) {
			return jmapResponse([
				[
					options.wrongSetMethod ? 'Email/get' : 'Email/set',
					{ updated: { 'message-a': null }, notUpdated: options.notUpdated ?? {} },
					'set',
				],
			]);
		}
		return jmapResponse([
			['Email/get', { list: [{ id: 'message-a', mailboxIds: options.mailboxIds ?? { inbox: true }, keywords: options.keywords ?? {} }] }, options.wrongGetCallId ? 'wrong' : 'email'],
			['Mailbox/get', { list: [{ id: 'inbox', role: 'inbox' }, { id: 'archive', role: 'archive' }] }, 'mailboxes'],
		]);
	});
}

function client(url: string, overrides: Partial<NotificationWindowClient> = {}): NotificationWindowClient {
	return {
		url,
		focus: vi.fn().mockResolvedValue(undefined),
		navigate: vi.fn().mockResolvedValue(undefined),
		...overrides,
	};
}

function clientsPort(windows: NotificationWindowClient[]) {
	return {
		matchAll: vi.fn().mockResolvedValue(windows),
		openWindow: vi.fn().mockResolvedValue(client(`${origin}/inbox?t=message-a`)),
	} satisfies NotificationClientsPort;
}

describe('runNotificationCommand', () => {
	it('keeps the inline service-worker transaction and unsafe fallback deleted', () => {
		const source = readFileSync(join(process.cwd(), 'src/service-worker.ts'), 'utf8');
		expect(source).toContain('runNotificationCommand');
		expect(source).not.toContain('async function archiveViaJmap');
		expect(source).not.toContain('async function focusOrOpenClient');
	});

	it('requires exact JMAP method names and call ids before navigating', async () => {
		const fetchPort = makeFetch({ wrongGetCallId: true });
		const windows = clientsPort([]);

		const outcome = await runNotificationCommand(
			{ kind: 'archive', messageId: 'message-a', targetUrl: '/inbox?t=message-a' },
			fetchPort,
			windows,
			origin,
		);

		expect(outcome.kind).toBe('failed');
		expect(windows.openWindow).toHaveBeenCalledTimes(1);
	});

	it('treats notUpdated as failure and does not claim or navigate success', async () => {
		const fetchPort = makeFetch({ notUpdated: { 'message-a': { type: 'forbidden' } } });
		const windows = clientsPort([]);

		const outcome = await runNotificationCommand(
			{ kind: 'archive', messageId: 'message-a', targetUrl: '/inbox?t=message-a' },
			fetchPort,
			windows,
			origin,
		);

		expect(outcome).toMatchObject({ kind: 'failed', reason: 'archive-not-updated', fallback: 'opened' });
		expect(windows.openWindow).toHaveBeenCalledTimes(1);
	});

	it('rejects a wrong Email/set method even on HTTP 200 and still opens the safe fallback', async () => {
		const windows = clientsPort([]);
		const outcome = await runNotificationCommand(
			{ kind: 'archive', messageId: 'message-a', targetUrl: '/inbox?t=message-a' },
			makeFetch({ wrongSetMethod: true }),
			windows,
			origin,
		);
		expect(outcome).toMatchObject({ kind: 'failed', reason: 'invalid-archive-response', fallback: 'opened' });
		expect(windows.openWindow).toHaveBeenCalledTimes(1);
	});

	it('distinguishes malformed JSON and uses the same bounded fallback', async () => {
		const fetchPort = vi.fn().mockResolvedValue(new Response('{', { status: 200 }));
		const windows = clientsPort([]);
		const outcome = await runNotificationCommand(
			{ kind: 'archive', messageId: 'malformed-json', targetUrl: '/inbox?t=malformed-json' },
			fetchPort,
			windows,
			origin,
		);
		expect(outcome).toMatchObject({ kind: 'failed', reason: 'invalid-session-json', fallback: 'opened' });
	});

	it('focuses an exact inbox thread without navigating it', async () => {
		const matching = client(`${origin}/inbox?t=message-a`);
		const windows = clientsPort([matching]);

		const outcome = await runNotificationCommand(
			{ kind: 'focus', targetUrl: '/inbox?t=message-a' },
			makeFetch(),
			windows,
			origin,
		);

		expect(outcome.kind).toBe('focused');
		expect(matching.focus).toHaveBeenCalledTimes(1);
		expect(matching.navigate).not.toHaveBeenCalled();
		expect(windows.openWindow).not.toHaveBeenCalled();
	});

	it('navigates only an explicitly attested idle inbox and never overwrites compose, tasks, chat, or settings', async () => {
		for (const protectedPath of ['/compose', '/tasks', '/chat', '/settings']) {
			const protectedClient = client(`${origin}${protectedPath}`);
			const windows = clientsPort([protectedClient]);
			await runNotificationCommand(
				{ kind: 'focus', targetUrl: '/inbox?t=message-a' },
				makeFetch(),
				windows,
				origin,
			);
			expect(protectedClient.navigate).not.toHaveBeenCalled();
			expect(protectedClient.focus).not.toHaveBeenCalled();
			expect(windows.openWindow).toHaveBeenCalledTimes(1);
		}

		const unknownInbox = client(`${origin}/inbox`);
		const unknownWindows = clientsPort([unknownInbox]);
		await runNotificationCommand(
			{ kind: 'focus', targetUrl: '/inbox?t=unattested' },
			makeFetch(),
			unknownWindows,
			origin,
		);
		expect(unknownInbox.navigate).not.toHaveBeenCalled();
		expect(unknownInbox.focus).not.toHaveBeenCalled();
		expect(unknownWindows.openWindow).toHaveBeenCalledTimes(1);

		const idleInbox = client(`${origin}/inbox`, { idleInbox: true });
		const windows = clientsPort([idleInbox]);
		const outcome = await runNotificationCommand(
			{ kind: 'focus', targetUrl: '/inbox?t=message-a' },
			makeFetch(),
			windows,
			origin,
		);
		expect(outcome.kind).toBe('focused');
		expect(idleInbox.navigate).toHaveBeenCalledWith(`${origin}/inbox?t=message-a`);
		expect(idleInbox.focus).toHaveBeenCalledTimes(1);
	});

	it('falls back to one openWindow attempt when navigation fails', async () => {
		const idleInbox = client(`${origin}/inbox`, {
			idleInbox: true,
			navigate: vi.fn().mockRejectedValue(new Error('detached')),
		});
		const windows = clientsPort([idleInbox]);

		const outcome = await runNotificationCommand(
			{ kind: 'focus', targetUrl: '/inbox?t=message-a' },
			makeFetch(),
			windows,
			origin,
		);

		expect(outcome.kind).toBe('opened');
		expect(windows.openWindow).toHaveBeenCalledTimes(1);
	});

	it('returns a bounded failure when openWindow returns null', async () => {
		const windows = clientsPort([]);
		windows.openWindow.mockResolvedValue(null);
		const outcome = await runNotificationCommand(
			{ kind: 'focus', targetUrl: '/inbox?t=message-a' },
			makeFetch(),
			windows,
			origin,
		);
		expect(outcome).toEqual({ kind: 'failed', reason: 'open-window-failed' });
		expect(windows.openWindow).toHaveBeenCalledTimes(1);
	});

	it('coalesces duplicate in-process archive commands into one mutation and no success navigation', async () => {
		const fetchPort = makeFetch();
		const existingInbox = client(`${origin}/inbox`);
		const windows = clientsPort([existingInbox]);
		const command = { kind: 'archive', messageId: 'message-a', targetUrl: '/inbox?t=message-a' } as const;

		const first = runNotificationCommand(command, fetchPort, windows, origin);
		const duplicate = runNotificationCommand(command, fetchPort, windows, origin);
		const [firstOutcome, duplicateOutcome] = await Promise.all([first, duplicate]);

		expect(duplicate).toBe(first);
		expect(firstOutcome).toEqual(duplicateOutcome);
		expect(fetchPort).toHaveBeenCalledTimes(3);
		expect(firstOutcome).toEqual({ kind: 'archived' });
		expect(windows.matchAll).not.toHaveBeenCalled();
		expect(windows.openWindow).not.toHaveBeenCalled();
		expect(existingInbox.navigate).not.toHaveBeenCalled();
		expect(existingInbox.focus).not.toHaveBeenCalled();
	});

	it('skips Email/set when already outside inbox and returns archived without navigation', async () => {
		const fetchPort = makeFetch({ mailboxIds: { archive: true }, keywords: { $seen: true } });
		const windows = clientsPort([]);

		const outcome = await runNotificationCommand(
			{ kind: 'archive', messageId: 'message-a', targetUrl: '/inbox?t=message-a' },
			fetchPort,
			windows,
			origin,
		);

		expect(outcome.kind).toBe('archived');
		expect(fetchPort).toHaveBeenCalledTimes(2);
		expect(windows.matchAll).not.toHaveBeenCalled();
		expect(windows.openWindow).not.toHaveBeenCalled();
	});
});
