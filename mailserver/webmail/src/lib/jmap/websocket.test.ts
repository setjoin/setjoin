import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { unwrapTypeMap, subscribe, disconnect, __handleRawMessage, subscribeControl, subscribeType } from './websocket';
import { drainPendingActions } from '$lib/jmap/offline-client';

// A8: the hub's onopen is a drain trigger for the offline action-queue. The
// mock keeps the trigger observable without loading the offline-client graph
// (client/db/auth stores) into these hub tests.
vi.mock('$lib/jmap/offline-client', () => ({
	drainPendingActions: vi.fn()
}));

// Regression guard for the producer↔consumer StateChange shape contract.
//
// The Go producer (internal/ws/handler.go, pushStateChangeBatchLocked) emits a
// JMAP-correct, accountId-keyed StateChange:
//   { '@type': 'StateChange', changed: { '<accountId>': { Email, Mailbox, … } } }
// Consumers (inbox/+page.svelte, CalendarApp.svelte) read the TYPE map
// (`changes.Email`, `changes.Calendar`). If the consumer indexes the outer
// accountId-keyed object, every type key is undefined and the push is DEAD.
// `unwrapTypeMap` is the single seam that resolves the per-account type map, so
// every consumer receives `{Email, …}` regardless of the wrapping accountId.
describe('unwrapTypeMap', () => {
	it('resolves the per-account type map from an accountId-keyed changed object', () => {
		const changed = {
			'91001': { Email: '42', Mailbox: '7', Thread: '3' }
		};
		const t = unwrapTypeMap(changed);
		expect(t.Email).toBe('42');
		expect(t.Mailbox).toBe('7');
		expect(t.Thread).toBe('3');
	});

	it('exposes Calendar/CalendarEvent keys when the producer adds them', () => {
		const changed = {
			'91001': { Email: '5', Calendar: '9', CalendarEvent: '9' }
		};
		const t = unwrapTypeMap(changed);
		expect(t.Calendar).toBe('9');
		expect(t.CalendarEvent).toBe('9');
	});

	it('drops a multi-account changed map (not attributable on a single-account socket)', () => {
		const changed = {
			'91001': { Email: '1' },
			'91002': { Email: '2' },
		};
		expect(unwrapTypeMap(changed)).toEqual({});
	});

	it('returns the first (only) account entry — a WS connection is single-account', () => {
		const changed = { '91001': { Email: '1' } };
		expect(unwrapTypeMap(changed).Email).toBe('1');
	});

	it('returns an empty object for null/undefined/empty input (no throw)', () => {
		expect(unwrapTypeMap(null)).toEqual({});
		expect(unwrapTypeMap(undefined)).toEqual({});
		expect(unwrapTypeMap({})).toEqual({});
	});

	it('a consumer truthy-check on the unwrapped map fires (the dead-push fix)', () => {
		// Before the fix, consumers did `changes.Email` on the OUTER object, where
		// `Email` was always undefined. After unwrapping, the check is truthy.
		const changed = { '91001': { Email: '42' } };
		const t = unwrapTypeMap(changed);
		expect(Boolean(t.Email)).toBe(true);
	});
});

// ── Multi-listener hub ──────────────────────────────────────────────────────
//
// A controllable fake WebSocket so the test can drive open/message/close and
// inspect what the hub sends. The hub captures the latest instance in its
// module-level `ws`, so the test grabs it via the shared `instances` array.
interface FakeSocket {
	readyState: number;
	sent: string[];
	onopen: (() => void) | null;
	onmessage: ((ev: { data: string }) => void) | null;
	onclose: (() => void) | null;
	onerror: (() => void) | null;
	send: (data: string) => void;
	close: () => void;
}

let instances: FakeSocket[];

class FakeWebSocket implements FakeSocket {
	static readonly OPEN = 1;
	static readonly CLOSED = 3;
	readyState = FakeWebSocket.OPEN;
	sent: string[] = [];
	onopen: (() => void) | null = null;
	onmessage: ((ev: { data: string }) => void) | null = null;
	onclose: (() => void) | null = null;
	onerror: (() => void) | null = null;
	constructor(_url: string) {
		instances.push(this);
	}
	send(data: string) {
		this.sent.push(data);
	}
	close() {
		this.readyState = FakeWebSocket.CLOSED;
		this.onclose?.();
	}
}

function current(): FakeSocket {
	return instances[instances.length - 1];
}

// Build an accountId-keyed StateChange as the gateway emits it.
function stateChange(typeMap: Record<string, string>): { data: string } {
	return { data: JSON.stringify({ '@type': 'StateChange', changed: { '91001': typeMap } }) };
}

function lastPushEnable(sock: FakeSocket): { '@type': string; dataTypes: string[] } {
	const frame = [...sock.sent].reverse().find((s) => s.includes('WebSocketPushEnable'));
	return JSON.parse(frame!);
}

describe('websocket hub', () => {
	beforeEach(() => {
		instances = [];
		vi.useFakeTimers();
		vi.stubGlobal('WebSocket', FakeWebSocket as unknown as typeof WebSocket);
		vi.spyOn(console, 'error').mockImplementation(() => {});
	});

	afterEach(() => {
		disconnect();
		vi.useRealTimers();
		vi.restoreAllMocks();
		vi.unstubAllGlobals();
	});

	it('self-arms on first subscribe and fans out to two disjoint-type listeners on the right StateChange', () => {
		const emailHits: Record<string, unknown>[] = [];
		const calHits: Record<string, unknown>[] = [];

		subscribe(['Email', 'Mailbox'], (c) => emailHits.push(c));
		subscribe(['Calendar'], (c) => calHits.push(c));

		// First subscribe opened the socket (self-arming).
		expect(instances).toHaveLength(1);
		current().onopen?.();

		// An Email change reaches only the Email listener.
		current().onmessage?.(stateChange({ Email: '42', Mailbox: '7' }));
		expect(emailHits).toHaveLength(1);
		expect(emailHits[0].Email).toBe('42');
		expect(calHits).toHaveLength(0);

		// A Calendar change reaches only the Calendar listener.
		current().onmessage?.(stateChange({ Calendar: '9', CalendarEvent: '9' }));
		expect(calHits).toHaveLength(1);
		expect(calHits[0].Calendar).toBe('9');
		expect(emailHits).toHaveLength(1);
	});

	it('unsubscribe stops delivery to that listener', () => {
		const hits: Record<string, unknown>[] = [];
		const unsub = subscribe(['Email'], (c) => hits.push(c));
		current().onopen?.();

		current().onmessage?.(stateChange({ Email: '1' }));
		expect(hits).toHaveLength(1);

		unsub();
		current().onmessage?.(stateChange({ Email: '2' }));
		expect(hits).toHaveLength(1); // no further delivery
	});

	it('a throwing listener does not abort the fan-out loop (steady state — error isolation)', () => {
		const order: string[] = [];
		// Register a throwing listener FIRST so a non-isolated loop would starve
		// the second one.
		subscribe(['Email'], () => {
			order.push('bad');
			throw new Error('boom');
		});
		subscribe(['Email'], () => {
			order.push('good');
		});
		current().onopen?.();

		expect(() => current().onmessage?.(stateChange({ Email: '1' }))).not.toThrow();
		expect(order).toEqual(['bad', 'good']); // the good listener still fired
	});

	it('error isolation holds on the first StateChange after a reconnect (re-registered from the registry)', () => {
		const order: string[] = [];
		subscribe(['Email'], () => {
			order.push('bad');
			throw new Error('boom');
		});
		subscribe(['Email'], () => {
			order.push('good');
		});
		current().onopen?.();

		// Drop the socket → hub schedules a reconnect from the live registry.
		current().onclose?.();
		vi.runAllTimers();
		expect(instances).toHaveLength(2); // reconnected
		current().onopen?.();

		order.length = 0;
		expect(() => current().onmessage?.(stateChange({ Email: '1' }))).not.toThrow();
		expect(order).toEqual(['bad', 'good']);
	});

	it('re-advertises the UNION of subscribed dataTypes on open and on reconnect', () => {
		subscribe(['Email', 'Mailbox'], () => {});
		subscribe(['Calendar'], () => {});
		current().onopen?.();

		const advert = lastPushEnable(current());
		expect(advert['@type']).toBe('WebSocketPushEnable');
		expect([...advert.dataTypes].sort()).toEqual(['Calendar', 'Email', 'Mailbox']);

		// Reconnect re-advertises the same union from the registry.
		current().onclose?.();
		vi.runAllTimers();
		current().onopen?.();
		const readvert = lastPushEnable(current());
		expect([...readvert.dataTypes].sort()).toEqual(['Calendar', 'Email', 'Mailbox']);
	});

	it('A8: a connect and a reconnect transition each drain the offline outbox', async () => {
		vi.mocked(drainPendingActions).mockClear();
		subscribe(['Email'], () => {});

		// First connect (which doubles as a redundant bootstrap path) fires the drain.
		current().onopen?.();
		await vi.runAllTimersAsync();
		expect(drainPendingActions).toHaveBeenCalledTimes(1);

		// A reconnect transition (drop → backoff → reopen) fires it again.
		current().onclose?.();
		vi.runAllTimers();
		current().onopen?.();
		await vi.runAllTimersAsync();
		expect(drainPendingActions).toHaveBeenCalledTimes(2);
	});
});

// ── Control-message routing ─────────────────────────────────────────────────
//
// The gateway forwards verbatim control pushes with a lowercase `type` field
// (offline.wipe / capsChanged). These are NOT RFC 8887 StateChanges (which
// use `@type`). __handleRawMessage is the single message entry point; control
// messages are routed to subscribeControl handlers without touching StateChange
// dispatch, and vice versa.
describe('WS control-message routing', () => {
	it('routes offline.wipe to a control handler', () => {
		const seen: Record<string, unknown>[] = [];
		const off = subscribeControl('offline.wipe', (p) => seen.push(p));
		__handleRawMessage(JSON.stringify({ type: 'offline.wipe', deviceId: 42 }));
		expect(seen).toEqual([{ type: 'offline.wipe', deviceId: 42 }]);
		off();
	});

	it('does not treat StateChange as control', () => {
		const seen: unknown[] = [];
		const off = subscribeControl('offline.wipe', (p) => seen.push(p));
		__handleRawMessage(JSON.stringify({ '@type': 'StateChange', changed: { u1: { Email: 's2' } } }));
		expect(seen).toEqual([]);
		off();
	});

	it('capsChanged reaches its handler', () => {
		const fn = vi.fn();
		const off = subscribeControl('capsChanged', fn);
		__handleRawMessage(JSON.stringify({ type: 'capsChanged' }));
		expect(fn).toHaveBeenCalledOnce();
		off();
	});
});

// Drive P4 §5.6 live push: internal/ws/handler.go forwards drive-watch:<uid>
// NOTIFY payloads as {"@type":"DriveWatch","event":{...}} — an uppercase
// "@type" but NOT "StateChange", so neither existing routing branch would
// otherwise see it. subscribeType is the seam locks.svelte.ts (Task 14) uses.
describe('WS @type-message routing (subscribeType)', () => {
	it('routes a DriveWatch envelope to its @type handler', () => {
		const seen: Record<string, unknown>[] = [];
		const off = subscribeType('DriveWatch', (p) => seen.push(p));
		__handleRawMessage(JSON.stringify({ '@type': 'DriveWatch', event: { nodeId: 5, op: 'update', spaceId: 1 } }));
		expect(seen).toEqual([{ '@type': 'DriveWatch', event: { nodeId: 5, op: 'update', spaceId: 1 } }]);
		off();
	});

	it('a StateChange is not routed to a DriveWatch handler', () => {
		const seen: unknown[] = [];
		const off = subscribeType('DriveWatch', (p) => seen.push(p));
		__handleRawMessage(JSON.stringify({ '@type': 'StateChange', changed: { u1: { Email: 's2' } } }));
		expect(seen).toEqual([]);
		off();
	});
});

// #222: pushes sent while the socket is down are lost, so a listener's
// onReconnect fires on every RE-open (never the first) to let it resync.
describe('websocket hub — onReconnect', () => {
	beforeEach(() => {
		instances = [];
		vi.useFakeTimers();
		vi.stubGlobal('WebSocket', FakeWebSocket as unknown as typeof WebSocket);
		vi.spyOn(console, 'error').mockImplementation(() => {});
	});

	afterEach(() => {
		disconnect();
		vi.useRealTimers();
		vi.restoreAllMocks();
		vi.unstubAllGlobals();
	});

	it('fires on re-open after a drop, not on the first open', () => {
		const onReconnect = vi.fn();
		subscribe(['Email'], () => {}, { onReconnect });
		current().onopen?.();
		expect(onReconnect).not.toHaveBeenCalled();
		current().close();
		vi.advanceTimersByTime(1000);
		current().onopen?.();
		expect(onReconnect).toHaveBeenCalledOnce();
	});

	it('isolates a throwing reconnect hook from co-registered listeners', () => {
		const ok = vi.fn();
		subscribe(['Email'], () => {}, { onReconnect: () => { throw new Error('boom'); } });
		subscribe(['Email'], () => {}, { onReconnect: ok });
		current().onopen?.();
		current().close();
		vi.advanceTimersByTime(1000);
		current().onopen?.();
		expect(ok).toHaveBeenCalledOnce();
	});

	it('treats the first open after disconnect() (fresh login) as a first connect', () => {
		subscribe(['Email'], () => {});
		current().onopen?.();
		disconnect();
		vi.advanceTimersByTime(60000);
		const onReconnect = vi.fn();
		subscribe(['Email'], () => {}, { onReconnect });
		current().onopen?.();
		expect(onReconnect).not.toHaveBeenCalled();
	});
});
