import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { subscribeGuestChatEvents, subscribeGuestMeetEvents } from './guestEventSource';

type FakeListener = EventListenerOrEventListenerObject;

class FakeEventSource {
	static instances: FakeEventSource[] = [];
	readonly url: string;
	closed = false;
	#listeners = new Map<string, Set<FakeListener>>();

	constructor(url: string | URL) {
		this.url = String(url);
		FakeEventSource.instances.push(this);
	}

	addEventListener(type: string, listener: FakeListener): void {
		let listeners = this.#listeners.get(type);
		if (!listeners) {
			listeners = new Set();
			this.#listeners.set(type, listeners);
		}
		listeners.add(listener);
	}

	removeEventListener(type: string, listener: FakeListener): void {
		this.#listeners.get(type)?.delete(listener);
	}

	emit(type: string, data: unknown): void {
		const event = { data } as MessageEvent<unknown>;
		for (const listener of this.#listeners.get(type) ?? []) {
			if (typeof listener === 'function') listener(event);
			else listener.handleEvent(event);
		}
	}

	close(): void {
		this.closed = true;
	}
}

describe('guest Chat EventSource client', () => {
	beforeEach(() => {
		FakeEventSource.instances = [];
		vi.stubGlobal('EventSource', FakeEventSource as unknown as typeof EventSource);
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('opens the guest stream, dispatches valid named chat JSON, drops malformed frames, and closes on unsubscribe', () => {
		const seen: Array<Record<string, unknown>> = [];
		const onOpen = vi.fn();
		const unsubscribe = subscribeGuestChatEvents<Record<string, unknown>>((event) => seen.push(event), onOpen);

		expect(FakeEventSource.instances).toHaveLength(1);
		const source = FakeEventSource.instances[0];
		expect(source.url).toBe('/api/jmap/eventsource?types=*&ping=30');
		source.emit('open', undefined);
		source.emit('open', undefined);
		expect(onOpen).toHaveBeenCalledTimes(2);

		source.emit('message', JSON.stringify({ event: 'wrong-name' }));
		source.emit('chat', '{broken');
		source.emit('chat', 'null');
		source.emit('chat', '[]');
		source.emit('chat', JSON.stringify({ event: 'message_created', channelId: 7, messageId: 9, seq: 3 }));
		expect(seen).toEqual([{ event: 'message_created', channelId: 7, messageId: 9, seq: 3 }]);

		unsubscribe();
		expect(source.closed).toBe(true);
		source.emit('chat', JSON.stringify({ event: 'message_created', channelId: 7 }));
		source.emit('open', undefined);
		expect(seen).toHaveLength(1);
		expect(onOpen).toHaveBeenCalledTimes(2);
	});

	it('dispatches only valid named meet JSON through the shared guest stream parser', () => {
		const seen: Array<Record<string, unknown>> = [];
		const unsubscribe = subscribeGuestMeetEvents<Record<string, unknown>>((event) => seen.push(event));
		const source = FakeEventSource.instances[0];
		source.emit('chat', JSON.stringify({ event: 'wrong-stream' }));
		source.emit('meet', '{broken');
		source.emit('meet', JSON.stringify({ event: 'recording_state', meetingId: 7, payload: { state: 'active' } }));
		expect(seen).toEqual([{ event: 'recording_state', meetingId: 7, payload: { state: 'active' } }]);
		unsubscribe();
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

describe('guest EventSource — jittered exponential backoff (#389)', () => {
	beforeEach(() => {
		FakeEventSource.instances = [];
		vi.useFakeTimers();
		vi.stubGlobal('EventSource', FakeEventSource as unknown as typeof EventSource);
	});

	afterEach(() => {
		vi.useRealTimers();
		vi.unstubAllGlobals();
	});

	it('closes on error to suppress native fixed retries and backs off with full jitter capped at 60s', () => {
		const rng = mulberry32(0x55e001);
		const expectedRng = mulberry32(0x55e001);
		const onOpen = vi.fn();
		const seen: Array<Record<string, unknown>> = [];

		const unsubscribe = subscribeGuestChatEvents<Record<string, unknown>>(
			(event) => seen.push(event),
			onOpen,
			{ backoff: { random: rng } },
		);
		expect(FakeEventSource.instances).toHaveLength(1);

		for (let attempt = 0; attempt < 9; attempt++) {
			const ceiling = Math.min(60_000, 1000 * 2 ** attempt);
			const expectedDelay = Math.floor(expectedRng() * ceiling);
			expect(expectedDelay).toBeGreaterThanOrEqual(0);
			expect(expectedDelay).toBeLessThanOrEqual(ceiling);
			expect(expectedDelay).toBeLessThanOrEqual(60_000);

			const prevCount = FakeEventSource.instances.length;
			const failing = FakeEventSource.instances[prevCount - 1];
			failing.emit('error', undefined);
			expect(failing.closed).toBe(true);

			if (expectedDelay > 0) {
				vi.advanceTimersByTime(expectedDelay - 1);
				expect(FakeEventSource.instances).toHaveLength(prevCount);
				vi.advanceTimersByTime(1);
			} else {
				vi.advanceTimersByTime(0);
			}
			expect(FakeEventSource.instances).toHaveLength(prevCount + 1);
		}

		// After reconnect opens, events and onOpen reconcile resume normally.
		const latest = FakeEventSource.instances[FakeEventSource.instances.length - 1];
		latest.emit('open', undefined);
		expect(onOpen).toHaveBeenCalledOnce();
		latest.emit('chat', JSON.stringify({ event: 'message_created', channelId: 9, seq: 4 }));
		expect(seen).toEqual([{ event: 'message_created', channelId: 9, seq: 4 }]);

		// Unsubscribing during a pending reconnect cancels the scheduled open.
		latest.emit('error', undefined);
		const countAtError = FakeEventSource.instances.length;
		unsubscribe();
		vi.advanceTimersByTime(120_000);
		expect(FakeEventSource.instances).toHaveLength(countAtError);
	});

	it('resets backoff only after remaining open past stableUptimeMs (flapping streams keep backing off)', () => {
		const unsubscribe = subscribeGuestMeetEvents<Record<string, unknown>>(
			() => {},
			undefined,
			{ backoff: { baseDelayMs: 1000, maxDelayMs: 60_000, stableUptimeMs: 15_000, random: () => 1 } },
		);
		const last = () => FakeEventSource.instances[FakeEventSource.instances.length - 1];

		// Flap 1: open → immediate error after 200ms → 1000ms.
		last().emit('open', undefined);
		vi.advanceTimersByTime(200);
		last().emit('error', undefined);
		vi.advanceTimersByTime(999);
		expect(FakeEventSource.instances).toHaveLength(1);
		vi.advanceTimersByTime(1);
		expect(FakeEventSource.instances).toHaveLength(2);

		// Flap 2: open → error after 14_999ms (< 15s) → NOT reset → 2000ms.
		last().emit('open', undefined);
		vi.advanceTimersByTime(14_999);
		last().emit('error', undefined);
		vi.advanceTimersByTime(1999);
		expect(FakeEventSource.instances).toHaveLength(2);
		vi.advanceTimersByTime(1);
		expect(FakeEventSource.instances).toHaveLength(3);

		// Stable stream: open for 15_000ms → error resets to 1000ms.
		last().emit('open', undefined);
		vi.advanceTimersByTime(15_000);
		last().emit('error', undefined);
		vi.advanceTimersByTime(999);
		expect(FakeEventSource.instances).toHaveLength(3);
		vi.advanceTimersByTime(1);
		expect(FakeEventSource.instances).toHaveLength(4);

		unsubscribe();
	});

	it('spreads 100 guest EventSource clients reconnecting after a simultaneous error', () => {
		const CLIENT_COUNT = 100;
		const unsubscribes: Array<() => void> = [];
		for (let i = 0; i < CLIENT_COUNT; i++) {
			unsubscribes.push(
				subscribeGuestChatEvents(
					() => {},
					undefined,
					{ backoff: { random: mulberry32(30_000 + i) } },
				),
			);
		}
		const initialSources = [...FakeEventSource.instances];
		for (const s of initialSources) s.emit('open', undefined);
		vi.advanceTimersByTime(20_000);

		const dropAt = Date.now();
		const reconnectOffsets: number[] = [];
		class TimestampedEventSource extends FakeEventSource {
			constructor(url: string | URL) {
				super(url);
				reconnectOffsets.push(Date.now() - dropAt);
			}
		}
		vi.stubGlobal('EventSource', TimestampedEventSource as unknown as typeof EventSource);

		for (const s of initialSources) s.emit('error', undefined);
		vi.advanceTimersByTime(1000);

		expect(reconnectOffsets).toHaveLength(CLIENT_COUNT);
		const uniqueTimestamps = new Set(reconnectOffsets);
		expect(Math.min(...reconnectOffsets)).toBeGreaterThanOrEqual(0);
		expect(Math.max(...reconnectOffsets)).toBeLessThanOrEqual(1000);
		expect(Math.max(...reconnectOffsets) - Math.min(...reconnectOffsets)).toBeGreaterThan(750);
		expect(uniqueTimestamps.size).toBeGreaterThan(80);

		for (const off of unsubscribes) off();
	});
});
