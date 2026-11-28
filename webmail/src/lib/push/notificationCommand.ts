import type { JmapSession, Mailbox } from '$lib/types/jmap';
import { stripLocationTags } from '$lib/stores/tagHelpers';

export type NotificationCommand =
	| { kind: 'focus'; targetUrl: string }
	| { kind: 'archive'; messageId: string; targetUrl: string };

export interface NotificationWindowClient {
	url: string;
	/** Explicit non-sensitive host attestation; never infer idle state from URL. */
	idleInbox?: true;
	focus(): Promise<unknown>;
	navigate?(url: string): Promise<unknown>;
}

export interface NotificationClientsPort {
	matchAll(): Promise<NotificationWindowClient[]>;
	openWindow(url: string): Promise<NotificationWindowClient | null>;
}

export type NotificationFetchPort = (
	input: RequestInfo | URL,
	init?: RequestInit,
) => Promise<Response>;

export type NotificationCommandOutcome =
	| { kind: 'archived' }
	| { kind: 'focused' }
	| { kind: 'opened' }
	| { kind: 'failed'; reason: string; fallback?: 'focused' | 'opened' | 'failed' };

type NotificationNavigationOutcome = Exclude<NotificationCommandOutcome, { kind: 'archived' }>;

type MethodResponse = [string, Record<string, unknown>, string];

const inFlightCommands = new Map<string, Promise<NotificationCommandOutcome>>();

async function readJsonObject(response: Response): Promise<Record<string, unknown> | null> {
	try {
		const value: unknown = await response.json();
		return value !== null && typeof value === 'object' && !Array.isArray(value)
			? value as Record<string, unknown>
			: null;
	} catch {
		return null;
	}
}

function commandKey(command: NotificationCommand): string {
	return command.kind === 'archive'
		? `archive:${command.messageId}:${command.targetUrl}`
		: `focus:${command.targetUrl}`;
}

function exactMethod(
	responses: unknown,
	methodName: string,
	callId: string,
): Record<string, unknown> | null {
	if (!Array.isArray(responses)) return null;
	const matches = responses.filter(
		(response): response is MethodResponse =>
			Array.isArray(response) &&
			response.length === 3 &&
			response[0] === methodName &&
			response[2] === callId &&
			response[1] !== null &&
			typeof response[1] === 'object',
	);
	return matches.length === 1 ? matches[0][1] : null;
}

function safeTarget(targetUrl: string, origin: string): URL | null {
	try {
		const target = new URL(targetUrl, origin);
		return target.origin === origin ? target : null;
	} catch {
		return null;
	}
}

function isExactTarget(clientUrl: string, target: URL): boolean {
	try {
		const current = new URL(clientUrl);
		return current.origin === target.origin && current.href === target.href;
	} catch {
		return false;
	}
}

function isIdleInbox(client: NotificationWindowClient, origin: string): boolean {
	if (client.idleInbox !== true) return false;
	try {
		const current = new URL(client.url);
		return (
			current.origin === origin &&
			current.pathname.replace(/\/$/, '').endsWith('/inbox') &&
			current.search === '' &&
			current.hash === ''
		);
	} catch {
		return false;
	}
}

async function focusSafely(
	targetUrl: string,
	clientsPort: NotificationClientsPort,
	origin: string,
): Promise<NotificationNavigationOutcome> {
	const target = safeTarget(targetUrl, origin);
	if (!target) return { kind: 'failed', reason: 'unsafe-target' };

	let windows: NotificationWindowClient[];
	try {
		windows = await clientsPort.matchAll();
	} catch {
		windows = [];
	}

	const exact = windows.find((candidate) => isExactTarget(candidate.url, target));
	if (exact) {
		try {
			await exact.focus();
			return { kind: 'focused' };
		} catch {
			// Fall through to one bounded openWindow attempt.
		}
	}

	const idleInbox = windows.find((candidate) => isIdleInbox(candidate, origin));
	if (idleInbox?.navigate) {
		try {
			await idleInbox.navigate(target.href);
			await idleInbox.focus();
			return { kind: 'focused' };
		} catch {
			// Fall through to one bounded openWindow attempt.
		}
	}

	try {
		const opened = await clientsPort.openWindow(target.href);
		return opened ? { kind: 'opened' } : { kind: 'failed', reason: 'open-window-failed' };
	} catch {
		return { kind: 'failed', reason: 'open-window-failed' };
	}
}

async function archiveViaJmap(
	messageId: string,
	fetchPort: NotificationFetchPort,
	origin: string,
): Promise<{ ok: true } | { ok: false; reason: string }> {
	let sessionResponse: Response;
	try {
		sessionResponse = await fetchPort('/jmap/session');
	} catch {
		return { ok: false, reason: 'session-request-failed' };
	}
	if (!sessionResponse.ok) return { ok: false, reason: 'session-request-failed' };

	const sessionBody = await readJsonObject(sessionResponse);
	if (!sessionBody) return { ok: false, reason: 'invalid-session-json' };
	const session = sessionBody as unknown as JmapSession;
	const accountId = session.primaryAccounts?.['urn:ietf:params:jmap:mail'];
	const apiUrl = safeTarget(session.apiUrl, origin);
	if (!accountId || !apiUrl) return { ok: false, reason: 'invalid-session' };

	let getResponse: Response;
	try {
		getResponse = await fetchPort(apiUrl.href, {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({
				using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'],
				methodCalls: [
					['Email/get', { accountId, ids: [messageId], properties: ['id', 'mailboxIds', 'keywords'] }, 'email'],
					['Mailbox/get', { accountId, properties: ['id', 'role'] }, 'mailboxes'],
				],
			}),
		});
	} catch {
		return { ok: false, reason: 'mail-state-request-failed' };
	}
	if (!getResponse.ok) return { ok: false, reason: 'mail-state-request-failed' };
	const getBody = await readJsonObject(getResponse);
	if (!getBody) return { ok: false, reason: 'invalid-mail-state-json' };
	const emailResponse = exactMethod(getBody.methodResponses, 'Email/get', 'email');
	const mailboxResponse = exactMethod(getBody.methodResponses, 'Mailbox/get', 'mailboxes');
	if (!emailResponse || !mailboxResponse) return { ok: false, reason: 'invalid-mail-state-response' };

	const emails = emailResponse.list;
	const mailboxes = mailboxResponse.list;
	if (!Array.isArray(emails) || !Array.isArray(mailboxes)) {
		return { ok: false, reason: 'invalid-mail-state-response' };
	}
	const email = emails.find(
		(candidate): candidate is { id: string; mailboxIds: Record<string, boolean> } =>
			candidate !== null && typeof candidate === 'object' && candidate.id === messageId,
	);
	if (!email || !email.mailboxIds || typeof email.mailboxIds !== 'object') {
		return { ok: false, reason: 'message-not-found' };
	}
	const inboxId = (mailboxes as Mailbox[]).find((mailbox) => mailbox.role === 'inbox')?.id;
	if (!inboxId) return { ok: false, reason: 'inbox-not-found' };
	const nextMailboxIds = stripLocationTags(email.mailboxIds, mailboxes as Mailbox[]);
	if (!email.mailboxIds[inboxId]) return { ok: true };

	let setResponse: Response;
	try {
		setResponse = await fetchPort(apiUrl.href, {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({
				using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'],
				methodCalls: [['Email/set', { accountId, update: { [messageId]: { mailboxIds: nextMailboxIds } } }, 'set']],
			}),
		});
	} catch {
		return { ok: false, reason: 'archive-request-failed' };
	}
	if (!setResponse.ok) return { ok: false, reason: 'archive-request-failed' };
	const setBody = await readJsonObject(setResponse);
	if (!setBody) return { ok: false, reason: 'invalid-archive-json' };
	const result = exactMethod(setBody.methodResponses, 'Email/set', 'set');
	if (!result) return { ok: false, reason: 'invalid-archive-response' };
	const notUpdated = result.notUpdated;
	if (
		notUpdated !== null &&
		typeof notUpdated === 'object' &&
		Object.prototype.hasOwnProperty.call(notUpdated, messageId)
	) {
		return { ok: false, reason: 'archive-not-updated' };
	}
	const updated = result.updated;
	if (
		updated === null ||
		typeof updated !== 'object' ||
		!Object.prototype.hasOwnProperty.call(updated, messageId)
	) {
		return { ok: false, reason: 'archive-not-confirmed' };
	}
	return { ok: true };
}

function executeNotificationCommand(
	command: NotificationCommand,
	fetchPort: NotificationFetchPort,
	clientsPort: NotificationClientsPort,
	origin: string,
): Promise<NotificationCommandOutcome> {
	if (command.kind === 'focus') return focusSafely(command.targetUrl, clientsPort, origin);
	return archiveViaJmap(command.messageId, fetchPort, origin).then(async (archive) => {
		if (archive.ok) return { kind: 'archived' };
		const fallback = await focusSafely(command.targetUrl, clientsPort, origin);
		return {
			kind: 'failed',
			reason: archive.reason,
			fallback: fallback.kind,
		};
	});
}

export function runNotificationCommand(
	command: NotificationCommand,
	fetchPort: NotificationFetchPort,
	clientsPort: NotificationClientsPort,
	origin: string,
): Promise<NotificationCommandOutcome> {
	const key = commandKey(command);
	const existing = inFlightCommands.get(key);
	if (existing) return existing;
	const promise = executeNotificationCommand(command, fetchPort, clientsPort, origin).finally(() => {
		inFlightCommands.delete(key);
	});
	inFlightCommands.set(key, promise);
	return promise;
}
