import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
	unwrapTypeMap,
	subscribe,
	disconnect,
	__handleRawMessage,
	subscribeControl,
	subscribeType,
	createWebSocketHub,
} from './websocket';
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

function mulberry32(seed: number): () => number {
	let a = seed >>> 0;
	return () => {
		a = (a + 0x6d2b79f5) >>> 0;
		let t = Math.imul(a ^ (a >>> 15), 1 | a);
		t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
}

// #389: full-jitter exponential backoff + uptime-gated reset + mass-disconnect spread.
describe('websocket hub — jittered exponential backoff (#389)', () => {
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

	it('stays within [0, min(60s, 1s * 2^attempt)] and caps at 60s with a seeded RNG', () => {
		const rng = mulberry32(0x5e7101);
		const expectedRng = mulberry32(0x5e7101);
		const hub = createWebSocketHub({ backoff: { random: rng } });

		hub.subscribe(['Email'], () => {});
		expect(instances).toHaveLength(1);

		for (let attempt = 0; attempt < 10; attempt++) {
			const ceiling = Math.min(60_000, 1000 * 2 ** attempt);
			const expectedDelay = Math.floor(expectedRng() * ceiling);
			expect(expectedDelay).toBeGreaterThanOrEqual(0);
			expect(expectedDelay).toBeLessThanOrEqual(ceiling);
			expect(expectedDelay).toBeLessThanOrEqual(60_000);

			const beforeCount = instances.length;
			current().onclose?.();

			if (expectedDelay > 0) {
				vi.advanceTimersByTime(expectedDelay - 1);
				expect(instances).toHaveLength(beforeCount);
				vi.advanceTimersByTime(1);
			} else {
				vi.advanceTimersByTime(0);
			}
			expect(instances).toHaveLength(beforeCount + 1);
		}

		hub.disconnect();
	});

	it('resets backoff ONLY after staying connected past the stability threshold, not on flapping sockets', () => {
		// random = () => 1 yields exact ceilings (1s, 2s, 4s, 8s...) so resets are exact.
		const hub = createWebSocketHub({
			backoff: { baseDelayMs: 1000, maxDelayMs: 60_000, stableUptimeMs: 15_000, random: () => 1 },
		});

		hub.subscribe(['Email'], () => {});
		expect(instances).toHaveLength(1);

		// Flap 1: open then drop after 100ms (< 15s) → delay 1000ms (attempt 0).
		current().onopen?.();
		vi.advanceTimersByTime(100);
		current().onclose?.();
		vi.advanceTimersByTime(999);
		expect(instances).toHaveLength(1);
		vi.advanceTimersByTime(1);
		expect(instances).toHaveLength(2);

		// Flap 2: open then drop after 5000ms (< 15s) → NOT reset, delay 2000ms (attempt 1).
		current().onopen?.();
		vi.advanceTimersByTime(5_000);
		current().onclose?.();
		vi.advanceTimersByTime(1999);
		expect(instances).toHaveLength(2);
		vi.advanceTimersByTime(1);
		expect(instances).toHaveLength(3);

		// Flap 3: open then drop after 14999ms (< 15s) → NOT reset, delay 4000ms (attempt 2).
		current().onopen?.();
		vi.advanceTimersByTime(14_999);
		current().onclose?.();
		vi.advanceTimersByTime(3999);
		expect(instances).toHaveLength(3);
		vi.advanceTimersByTime(1);
		expect(instances).toHaveLength(4);

		// Healthy connection: stay open for 15000ms (>= threshold) → next drop resets to 1000ms.
		current().onopen?.();
		vi.advanceTimersByTime(15_000);
		current().onclose?.();
		vi.advanceTimersByTime(999);
		expect(instances).toHaveLength(4);
		vi.advanceTimersByTime(1);
		expect(instances).toHaveLength(5);

		hub.disconnect();
	});

	it('spreads 100 simultaneous WebSocket clients reconnecting after a mass disconnect', () => {
		const CLIENT_COUNT = 100;
		const hubs = Array.from({ length: CLIENT_COUNT }, (_, i) =>
			createWebSocketHub({ backoff: { random: mulberry32(20_000 + i) } }),
		);

		const initialSockets: FakeSocket[] = [];
		for (const hub of hubs) {
			hub.subscribe(['Email'], () => {});
			const sock = current();
			sock.onopen?.();
			initialSockets.push(sock);
		}
		expect(instances).toHaveLength(CLIENT_COUNT);

		// Advance past stability threshold, then drop all 100 sockets at the exact same instant.
		vi.advanceTimersByTime(20_000);
		const dropAt = Date.now();
		const reconnectOffsets: number[] = [];

		class TimestampedWebSocket extends FakeWebSocket {
			constructor(url: string) {
				super(url);
				reconnectOffsets.push(Date.now() - dropAt);
			}
		}
		vi.stubGlobal('WebSocket', TimestampedWebSocket as unknown as typeof WebSocket);

		for (const sock of initialSockets) {
			sock.onclose?.();
		}

		// Advance through the attempt-0 window (1000ms); all 100 must have reconnected.
		vi.advanceTimersByTime(1000);
		expect(reconnectOffsets).toHaveLength(CLIENT_COUNT);

		const uniqueTimestamps = new Set(reconnectOffsets);
		const minOffset = Math.min(...reconnectOffsets);
		const maxOffset = Math.max(...reconnectOffsets);

		expect(minOffset).toBeGreaterThanOrEqual(0);
		expect(maxOffset).toBeLessThanOrEqual(1000);
		expect(maxOffset - minOffset).toBeGreaterThan(750);
		expect(uniqueTimestamps.size).toBeGreaterThan(80);

		// Confirm no single 100ms bucket holds a thundering-herd majority of clients.
		const buckets = new Array<number>(10).fill(0);
		for (const t of reconnectOffsets) {
			buckets[Math.min(9, Math.floor(t / 100))] += 1;
		}
		expect(Math.max(...buckets)).toBeLessThan(30);

		for (const hub of hubs) hub.disconnect();
	});

	it('does not bypass a pending reconnect backoff when a late subscriber mounts, and advertises its types on reconnect', () => {
		const hub = createWebSocketHub({
			backoff: { baseDelayMs: 1000, maxDelayMs: 60_000, stableUptimeMs: 15_000, random: () => 1 },
		});

		hub.subscribe(['Email'], () => {});
		expect(instances).toHaveLength(1);
		current().onopen?.();

		// Drop immediately → schedules attempt-0 backoff for 1000ms.
		current().onclose?.();
		vi.advanceTimersByTime(400);
		expect(instances).toHaveLength(1);

		// Late subscriber mounts mid-backoff: must NOT open early or reset the remaining 600ms timer.
		hub.subscribe(['Calendar'], () => {});
		expect(instances).toHaveLength(1);

		vi.advanceTimersByTime(599);
		expect(instances).toHaveLength(1);

		// At the exact originally scheduled 1000ms mark, the single reconnect opens and advertises both types.
		vi.advanceTimersByTime(1);
		expect(instances).toHaveLength(2);
		current().onopen?.();
		const advert = lastPushEnable(current());
		expect([...advert.dataTypes].sort()).toEqual(['Calendar', 'Email']);

		hub.disconnect();
	});
});
