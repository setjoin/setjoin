import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ── websocket hub mock ──
// PushHandlerStore is a thin coordinator over the single `subscribe()` hub: it
// owns the per-dataType debounce and the unsubscribe bookkeeping. We mock the
// hub so the test drives StateChange delivery and inspects what was registered.
type HubHandler = (changes: Record<string, unknown>) => void;
interface Registration {
	types: string[];
	handler: HubHandler;
	onReconnect?: () => void;
	unsub: ReturnType<typeof vi.fn>;
}

let registrations: Registration[];

type HubOptions = { onReconnect?: () => void };
const subscribe = vi.fn((types: string[], handler: HubHandler, options?: HubOptions) => {
	const unsub = vi.fn();
	registrations.push({ types, handler, onReconnect: options?.onReconnect, unsub });
	return unsub;
});

vi.mock('$lib/jmap/websocket', () => ({
	subscribe: (...a: unknown[]) => subscribe(...(a as [string[], HubHandler, HubOptions?])),
}));

import { PushHandlerStore } from './pushHandler.svelte';

/** Deliver a StateChange type-map to the most-recently-registered hub listener. */
function deliver(reg: Registration, typeMap: Record<string, string>): void {
	reg.handler(typeMap);
}

beforeEach(() => {
	registrations = [];
	subscribe.mockClear();
	vi.useFakeTimers();
});

afterEach(() => {
	vi.useRealTimers();
});

describe('PushHandlerStore.register — hub wiring', () => {
	it('opens exactly one hub subscription per register() with the declared dataTypes', () => {
		const store = new PushHandlerStore();
		store.register(['Email', 'Mailbox'], () => {});
		store.register(['Task'], () => {});

		expect(subscribe).toHaveBeenCalledTimes(2);
		expect(registrations[0].types).toEqual(['Email', 'Mailbox']);
		expect(registrations[1].types).toEqual(['Task']);
	});

	it('only invokes a handler when a changed key intersects its dataTypes', () => {
		const store = new PushHandlerStore();
		const emailHits: Record<string, unknown>[] = [];
		const taskHits: Record<string, unknown>[] = [];
		store.register(['Email', 'Mailbox'], (c) => emailHits.push(c));
		store.register(['Task'], (c) => taskHits.push(c));

		deliver(registrations[0], { Email: '42', Mailbox: '7' });
		deliver(registrations[1], { Task: '9' });

		expect(emailHits).toHaveLength(1);
		expect(emailHits[0].Email).toBe('42');
		expect(taskHits).toHaveLength(1);
	});

	it('passes the changes type-map straight through to an undebounced handler', () => {
		const store = new PushHandlerStore();
		let received: Record<string, unknown> | null = null;
		store.register(['Contact'], (c) => {
			received = c;
		});
		deliver(registrations[0], { Contact: '3' });
		expect(received).toEqual({ Contact: '3' });
	});
});

describe('PushHandlerStore.register — debounce batching', () => {
	it('coalesces a burst into a single handler call after debounceMs', () => {
		const store = new PushHandlerStore();
		const hits: number[] = [];
		store.register(['Email'], () => hits.push(1), { debounceMs: 300 });

		deliver(registrations[0], { Email: '1' });
		deliver(registrations[0], { Email: '2' });
		deliver(registrations[0], { Email: '3' });
		// Debounced — nothing has fired yet.
		expect(hits).toHaveLength(0);

		vi.advanceTimersByTime(300);
		// Exactly one call despite three events.
		expect(hits).toHaveLength(1);
	});

	it('preserves the per-type 300ms delay (no early fire before the window elapses)', () => {
		const store = new PushHandlerStore();
		const hits: number[] = [];
		store.register(['Email'], () => hits.push(1), { debounceMs: 300 });

		deliver(registrations[0], { Email: '1' });
		vi.advanceTimersByTime(299);
		expect(hits).toHaveLength(0);
		vi.advanceTimersByTime(1);
		expect(hits).toHaveLength(1);
	});

	it('fires immediately (no debounce) when debounceMs is omitted', () => {
		const store = new PushHandlerStore();
		const hits: number[] = [];
		store.register(['Task'], () => hits.push(1));

		deliver(registrations[0], { Task: '1' });
		deliver(registrations[0], { Task: '2' });
		// No debounce → one call per change, synchronously.
		expect(hits).toHaveLength(2);
	});

	it('debounces each registration independently', () => {
		const store = new PushHandlerStore();
		const emailHits: number[] = [];
		const calHits: number[] = [];
		store.register(['Email'], () => emailHits.push(1), { debounceMs: 300 });
		store.register(['Calendar'], () => calHits.push(1), { debounceMs: 500 });

		deliver(registrations[0], { Email: '1' });
		deliver(registrations[1], { Calendar: '1' });

		vi.advanceTimersByTime(300);
		expect(emailHits).toHaveLength(1);
		expect(calHits).toHaveLength(0); // 500ms window not yet elapsed
		vi.advanceTimersByTime(200);
		expect(calHits).toHaveLength(1);
	});
});

describe('PushHandlerStore.register — unsubscribe', () => {
	it('returns an unsubscribe that tears down the hub listener', () => {
		const store = new PushHandlerStore();
		const unsubscribe = store.register(['Email'], () => {});
		unsubscribe();
		expect(registrations[0].unsub).toHaveBeenCalledOnce();
	});

	it('cancels a pending debounced reload on unsubscribe (no late fire)', () => {
		const store = new PushHandlerStore();
		const hits: number[] = [];
		const unsubscribe = store.register(['Email'], () => hits.push(1), { debounceMs: 300 });

		deliver(registrations[0], { Email: '1' });
		unsubscribe();
		vi.advanceTimersByTime(300);
		expect(hits).toHaveLength(0); // timer was cancelled
	});

	it('teardown() removes every registration', () => {
		const store = new PushHandlerStore();
		store.register(['Email'], () => {});
		store.register(['Task'], () => {});
		store.teardown();
		expect(registrations[0].unsub).toHaveBeenCalledOnce();
		expect(registrations[1].unsub).toHaveBeenCalledOnce();
	});

	it('teardown() cancels pending debounced reloads across registrations', () => {
		const store = new PushHandlerStore();
		const a: number[] = [];
		const b: number[] = [];
		store.register(['Email'], () => a.push(1), { debounceMs: 300 });
		store.register(['Task'], () => b.push(1), { debounceMs: 300 });

		deliver(registrations[0], { Email: '1' });
		deliver(registrations[1], { Task: '1' });
		store.teardown();
		vi.advanceTimersByTime(300);
		expect(a).toHaveLength(0);
		expect(b).toHaveLength(0);
	});
});

describe('PushHandlerStore.register — error isolation', () => {
	it('a throwing undebounced handler does not propagate out of dispatch', () => {
		const store = new PushHandlerStore();
		store.register(['Email'], () => {
			throw new Error('boom');
		});
		vi.spyOn(console, 'error').mockImplementation(() => {});
		expect(() => deliver(registrations[0], { Email: '1' })).not.toThrow();
	});

	it('a throwing debounced handler does not crash the timer flush', () => {
		const store = new PushHandlerStore();
		store.register(['Email'], () => {
			throw new Error('boom');
		}, { debounceMs: 300 });
		vi.spyOn(console, 'error').mockImplementation(() => {});

		deliver(registrations[0], { Email: '1' });
		expect(() => vi.advanceTimersByTime(300)).not.toThrow();
	});

	it('one throwing registration does not starve a co-registered one', () => {
		const store = new PushHandlerStore();
		const good: number[] = [];
		store.register(['Email'], () => {
			throw new Error('boom');
		}, { debounceMs: 300 });
		store.register(['Email'], () => good.push(1), { debounceMs: 300 });
		vi.spyOn(console, 'error').mockImplementation(() => {});

		deliver(registrations[0], { Email: '1' });
		deliver(registrations[1], { Email: '1' });
		vi.advanceTimersByTime(300);
		expect(good).toHaveLength(1);
	});
});

// #222: a reconnect resync hook shares the registration's debounce window so a
// reconnect + a push in one window collapse into ONE call (the push wins).
describe('PushHandlerStore.register — onReconnect', () => {
	it('does not opt into hub reconnect delivery without a hook', () => {
		new PushHandlerStore().register(['Email'], () => {});
		expect(registrations[0].onReconnect).toBeUndefined();
	});

	it('runs the hook (debounced) on a reconnect with no push in the window', () => {
		const handler = vi.fn();
		const onReconnect = vi.fn();
		new PushHandlerStore().register(['Email'], handler, { debounceMs: 300, onReconnect });
		registrations[0].onReconnect!();
		expect(onReconnect).not.toHaveBeenCalled();
		vi.advanceTimersByTime(300);
		expect(onReconnect).toHaveBeenCalledOnce();
		expect(handler).not.toHaveBeenCalled();
	});

	it('collapses a reconnect and a push in one window into a single handler call', () => {
		const handler = vi.fn();
		const onReconnect = vi.fn();
		new PushHandlerStore().register(['Email'], handler, { debounceMs: 300, onReconnect });
		registrations[0].onReconnect!();
		deliver(registrations[0], { Email: '6' });
		vi.advanceTimersByTime(300);
		expect(handler).toHaveBeenCalledExactlyOnceWith({ Email: '6' });
		expect(onReconnect).not.toHaveBeenCalled();
	});

	it('teardown cancels a pending reconnect hook', () => {
		const onReconnect = vi.fn();
		const store = new PushHandlerStore();
		store.register(['Email'], () => {}, { debounceMs: 300, onReconnect });
		registrations[0].onReconnect!();
		store.teardown();
		vi.advanceTimersByTime(300);
		expect(onReconnect).not.toHaveBeenCalled();
	});
});
