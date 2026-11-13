// #222 regression: after the push WebSocket drops and reconnects, the inbox must
// resync from its last known Email state (Email/changes), not wait for the next
// push or a manual reload. Exercised end-to-end over the REAL hub
// ($lib/jmap/websocket) and the REAL PushHandlerStore with a fake WebSocket;
// only the JMAP client is mocked.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { Email } from '$lib/types/jmap';
import { JmapMethodError } from '$lib/jmap/client';

const emailQuery = vi.fn();
const emailGetWithState = vi.fn();
const emailChanges = vi.fn();
const mailboxState = vi.fn();

vi.mock('$lib/jmap/client', async (importOriginal) => {
	const real = await importOriginal<typeof import('$lib/jmap/client')>();
	return {
		JmapMethodError: real.JmapMethodError,
		isJmapMethodError: real.isJmapMethodError,
		mailboxState: (...a: unknown[]) => mailboxState(...a),
		FULL_EMAIL_PROPS: [],
		emailQuery: (...a: unknown[]) => emailQuery(...a),
		emailGetWithState: (...a: unknown[]) => emailGetWithState(...a),
		emailGet: async (...a: unknown[]) => (await emailGetWithState(...a)).list,
		emailChanges: (...a: unknown[]) => emailChanges(...a),
		emailSubmissionQuery: vi.fn(),
		emailSubmissionGet: vi.fn(),
		searchSnippetGet: vi.fn().mockResolvedValue([]),
	};
});
vi.mock('$lib/jmap/offline-client', () => ({ drainPendingActions: vi.fn().mockResolvedValue(undefined) }));
vi.mock('$lib/offline/readpath', () => ({ loadList: vi.fn(), searchList: vi.fn() }));
vi.mock('$lib/offline/state.svelte', () => ({ offline: { effectiveOffline: false } }));
vi.mock('$lib/jmap/savedsearches', () => ({
	savedSearchList: vi.fn().mockResolvedValue([]),
	savedSearchSet: vi.fn(),
	savedSearchDelete: vi.fn(),
}));

import { InboxStore } from './inboxStore.svelte';
import { disconnect } from '$lib/jmap/websocket';

class FakeWebSocket {
	static readonly OPEN = 1;
	static readonly CLOSED = 3;
	static instances: FakeWebSocket[] = [];
	readyState = FakeWebSocket.OPEN;
	onopen: (() => void) | null = null;
	onmessage: ((ev: { data: string }) => void) | null = null;
	onclose: (() => void) | null = null;
	onerror: (() => void) | null = null;
	constructor(_url: string) {
		FakeWebSocket.instances.push(this);
	}
	send(_data: string) {}
	close() {
		this.readyState = FakeWebSocket.CLOSED;
		this.onclose?.();
	}
}

const sock = () => FakeWebSocket.instances[FakeWebSocket.instances.length - 1];
const push = (typeMap: Record<string, string>) =>
	sock().onmessage?.({ data: JSON.stringify({ '@type': 'StateChange', changed: { '91001': typeMap } }) });

// Server model: one message whose $seen flips while client B is offline.
let serverState = '5';
let mailboxServerState = '3';
let seen = false;
const message = (): Email => ({
	id: 'm1',
	threadId: 'm1',
	mailboxIds: { 'mb-inbox': true },
	keywords: seen ? { $seen: true } : {},
	receivedAt: '2026-10-29T00:00:00Z',
});

async function connectedStore(): Promise<InboxStore> {
	const s = new InboxStore();
	s.mailboxes = [{ id: 'mb-inbox', name: 'Inbox', role: 'inbox' }];
	s.subscribeToChanges();
	sock().onopen?.();
	await s.loadEmails();
	return s;
}

async function dropAndReconnect(): Promise<void> {
	sock().close();
	await vi.advanceTimersByTimeAsync(1000); // hub reconnect backoff
	sock().onopen?.();
}

const isSeen = (s: InboxStore) => Boolean(s.emails.find((e) => e.id === 'm1')?.keywords?.$seen);

beforeEach(() => {
	vi.useFakeTimers();
	FakeWebSocket.instances = [];
	vi.stubGlobal('WebSocket', FakeWebSocket as unknown as typeof WebSocket);
	serverState = '5';
	mailboxServerState = '3';
	seen = false;
	mailboxState.mockReset().mockImplementation(async () => mailboxServerState);
	emailQuery.mockReset().mockImplementation(async () => ({ ids: ['m1'], total: 1, position: 0 }));
	emailGetWithState.mockReset().mockImplementation(async () => ({ list: [message()], state: serverState }));
	emailChanges.mockReset().mockImplementation(async (since: string) => ({
		newState: serverState,
		hasMoreChanges: false,
		created: [],
		updated: since === serverState ? [] : ['m1'],
		destroyed: [],
	}));
});

afterEach(() => {
	disconnect();
	vi.useRealTimers();
	vi.unstubAllGlobals();
});

describe('InboxStore — resync after a WebSocket reconnect (#222)', () => {
	it('picks up a change made while disconnected, via Email/changes from the last known state', async () => {
		const s = await connectedStore();
		expect(isSeen(s)).toBe(false);

		sock().close();
		// Client A marks the message read while B is offline: no push reaches B.
		seen = true;
		serverState = '6';
		await vi.advanceTimersByTimeAsync(1000);
		sock().onopen?.();
		await vi.advanceTimersByTimeAsync(300);

		expect(emailChanges).toHaveBeenCalledOnce();
		expect(emailChanges.mock.calls[0][0]).toBe('5');
		expect(isSeen(s)).toBe(true);
	});

	it('does not resync on the first connect', async () => {
		await connectedStore();
		await vi.advanceTimersByTimeAsync(1000);
		expect(emailChanges).not.toHaveBeenCalled();
		expect(emailQuery).toHaveBeenCalledOnce(); // only the initial load
	});

	it('does not reload when nothing changed while disconnected', async () => {
		await connectedStore();
		await dropAndReconnect();
		await vi.advanceTimersByTimeAsync(300);
		expect(emailChanges).toHaveBeenCalledOnce();
		expect(emailQuery).toHaveBeenCalledOnce();
	});

	it('falls back to a reload on cannotCalculateChanges', async () => {
		const s = await connectedStore();
		emailChanges.mockRejectedValueOnce(new JmapMethodError('cannotCalculateChanges'));
		sock().close();
		seen = true;
		serverState = '9';
		await vi.advanceTimersByTimeAsync(1000);
		sock().onopen?.();
		await vi.advanceTimersByTimeAsync(300);
		expect(emailQuery).toHaveBeenCalledTimes(2);
		expect(isSeen(s)).toBe(true);
	});

	it('loads once when a StateChange arrives right after the reconnect (coalesced)', async () => {
		const s = await connectedStore();
		sock().close();
		seen = true;
		serverState = '6';
		await vi.advanceTimersByTimeAsync(1000);
		sock().onopen?.();
		push({ Email: '6', Mailbox: '3' });
		await vi.advanceTimersByTimeAsync(300);
		// a late duplicate push for the state the reload already reflects
		push({ Email: '6', Mailbox: '3' });
		await vi.advanceTimersByTimeAsync(300);
		expect(emailQuery).toHaveBeenCalledTimes(2); // initial + exactly one resync load
		expect(isSeen(s)).toBe(true);
	});

	it('loads once when the push lands after the resync reload completed', async () => {
		await connectedStore();
		sock().close();
		seen = true;
		serverState = '6';
		await vi.advanceTimersByTimeAsync(1000);
		sock().onopen?.();
		await vi.advanceTimersByTimeAsync(300);
		push({ Email: '6', Mailbox: '3' });
		await vi.advanceTimersByTimeAsync(300);
		expect(emailChanges).toHaveBeenCalledOnce();
		expect(emailQuery).toHaveBeenCalledTimes(2);
	});

	it('still reloads on a genuinely new push after reconnect', async () => {
		await connectedStore();
		await dropAndReconnect();
		await vi.advanceTimersByTimeAsync(300);
		serverState = '7';
		push({ Email: '7' });
		await vi.advanceTimersByTimeAsync(300);
		expect(emailQuery).toHaveBeenCalledTimes(2);
	});
});

describe('InboxStore — push skip covers every state the inbox depends on (#225)', () => {
	it('reloads on a Mailbox-only change even when the Email token is unchanged', async () => {
		await connectedStore();
		mailboxServerState = '4';
		push({ Email: '5', Mailbox: '4' });
		await vi.advanceTimersByTimeAsync(300);
		expect(emailQuery).toHaveBeenCalledTimes(2);
	});

	it('skips a push whose Email and Mailbox tokens the list already reflects', async () => {
		await connectedStore();
		push({ Email: '5', Mailbox: '3' });
		await vi.advanceTimersByTimeAsync(300);
		expect(emailQuery).toHaveBeenCalledOnce();
	});

	it('reloads after a reconnect when only Mailbox state moved while disconnected', async () => {
		await connectedStore();
		sock().close();
		mailboxServerState = '4'; // e.g. a tag renamed while offline: no Email change
		await vi.advanceTimersByTimeAsync(1000);
		sock().onopen?.();
		await vi.advanceTimersByTimeAsync(300);
		expect(emailQuery).toHaveBeenCalledTimes(2);
	});
});

describe('InboxStore — Email state anchoring across pagination (#225)', () => {
	it('a later page never advances the anchor past a change the visible first page missed', async () => {
		const s = await connectedStore(); // page 1 reflects Email state 5
		// A change lands between page 1 and page 2; page 2 is read at state 6.
		seen = true;
		serverState = '6';
		emailQuery.mockImplementationOnce(async () => ({ ids: ['m2'], total: 2, position: 1 }));
		await s.loadEmails(false);
		// The push for state 6 must still reload: page 1 (m1) was read before it.
		push({ Email: '6', Mailbox: '3' });
		await vi.advanceTimersByTimeAsync(300);
		expect(emailQuery).toHaveBeenCalledTimes(3);
		expect(isSeen(s)).toBe(true);
	});

	it('a later page does not move the reconnect resync anchor', async () => {
		const s = await connectedStore();
		serverState = '6';
		emailQuery.mockImplementationOnce(async () => ({ ids: ['m2'], total: 2, position: 1 }));
		await s.loadEmails(false);
		await dropAndReconnect();
		await vi.advanceTimersByTimeAsync(300);
		expect(emailChanges.mock.calls[0][0]).toBe('5');
	});

	it('an empty result clears the anchor, so the next push reloads', async () => {
		const s = await connectedStore(); // anchored at Email state 5
		emailQuery.mockImplementationOnce(async () => ({ ids: [], total: 0, position: 0 }));
		await s.loadEmails();
		push({ Email: '5', Mailbox: '3' });
		await vi.advanceTimersByTimeAsync(300);
		expect(emailQuery).toHaveBeenCalledTimes(3);
	});

	it('an empty result makes the reconnect resync fall back to a reload', async () => {
		const s = await connectedStore();
		emailQuery.mockImplementationOnce(async () => ({ ids: [], total: 0, position: 0 }));
		await s.loadEmails();
		await dropAndReconnect();
		await vi.advanceTimersByTimeAsync(300);
		expect(emailChanges).not.toHaveBeenCalled();
		expect(emailQuery).toHaveBeenCalledTimes(3);
	});
});
