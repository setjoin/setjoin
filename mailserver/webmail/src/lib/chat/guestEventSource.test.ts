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
