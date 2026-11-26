import { browser } from '$app/environment';
import { ReconnectBackoff, type ReconnectBackoffOptions } from '$lib/ws/backoff';

const guestEventSourceURL = '/api/jmap/eventsource?types=*&ping=30';

export type GuestEventName = 'chat' | 'meet' | 'sync_wakeup' | 'scope_revoked';

const GUEST_EVENT_NAMES: readonly GuestEventName[] = ['chat', 'meet', 'sync_wakeup', 'scope_revoked'];

export interface GuestEventSourceOptions {
	backoff?: ReconnectBackoffOptions;
}

interface GuestSubscriber {
	eventName: GuestEventName;
	handler: (event: Record<string, unknown>) => void;
	onOpen?: () => void;
	disposed: boolean;
}

export interface GuestEventSourceHub {
	subscribe<T extends object>(
		eventName: GuestEventName,
		handler: (event: T) => void,
		onOpen?: () => void,
	): () => void;
	disconnect(): void;
	readonly subscriberCount: number;
	readonly isOpen: boolean;
}

// Mailbox-less guests cannot use the JMAP WebSocket protocol because that
// socket also accepts client Request frames. Their live collaboration rail is
// the server's read-only EventSource surface, which authenticates with the
// same-origin access-token cookie and emits raw objects as named events.
//
// #389: Native EventSource auto-reconnects on a fixed server/browser interval
// with zero jitter, causing a thundering herd after a gateway restart. On
// `error`, we immediately close the failed EventSource to suppress native
// fixed-interval retries and reopen a fresh stream using full-jitter
// exponential backoff (~1s base, ~60s cap, stability-gated reset).
//
// #555: One shared ref-counted EventSource serves ChatApp, MeetApp,
// MeetChatPanel, and SyncCoordinator's guest wakeup transport, listening to
// 'chat', 'meet', 'sync_wakeup', and 'scope_revoked'. Late subscribers joining
// an already-open stream receive a deterministic `onOpen` catch-up microtask
// without re-opening the SSE connection; reconnect invokes every active
// subscriber's `onOpen`.
export function createGuestEventSourceHub(options?: GuestEventSourceOptions): GuestEventSourceHub {
	const backoff = new ReconnectBackoff(options?.backoff);
	const subscribers = new Set<GuestSubscriber>();
	let source: EventSource | null = null;
	let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
	let detachCurrent: (() => void) | null = null;
	let open = false;

	function closeStream(): void {
		open = false;
		if (reconnectTimer !== null) {
			clearTimeout(reconnectTimer);
			reconnectTimer = null;
		}
		if (detachCurrent) {
			const detach = detachCurrent;
			detachCurrent = null;
			source = null;
			detach();
		} else {
			source = null;
		}
	}

	function connect(): void {
		if (!browser || typeof EventSource === 'undefined' || subscribers.size === 0 || source !== null) return;
		if (reconnectTimer !== null) {
			clearTimeout(reconnectTimer);
			reconnectTimer = null;
		}

		const current = new EventSource(guestEventSourceURL);
		source = current;

		const namedListeners: Array<[GuestEventName, EventListener]> = GUEST_EVENT_NAMES.map((name) => {
			const listener: EventListener = (raw) => {
				if (source !== current) return;
				const data = (raw as MessageEvent<unknown>).data;
				if (typeof data !== 'string') return;
				let parsed: unknown;
				try {
					parsed = JSON.parse(data);
				} catch {
					// A malformed server/extension frame is isolated to that frame and
					// does not tear down or reconnect the authenticated stream.
					return;
				}
				if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return;
				const payload = parsed as Record<string, unknown>;
				for (const sub of [...subscribers]) {
					if (sub.disposed || sub.eventName !== name) continue;
					try {
						sub.handler(payload);
					} catch (e) {
						console.error('Guest EventSource listener error', e);
					}
				}
			};
			return [name, listener];
		});

		const handleOpen: EventListener = () => {
			if (source !== current) return;
			open = true;
			backoff.markConnected();
			for (const sub of [...subscribers]) {
				if (sub.disposed || !sub.onOpen) continue;
				try {
					sub.onOpen();
				} catch (e) {
					console.error('Guest EventSource onOpen error', e);
				}
			}
		};

		const detach = () => {
			for (const [name, listener] of namedListeners) {
				current.removeEventListener(name, listener);
			}
			current.removeEventListener('open', handleOpen);
			current.removeEventListener('error', handleError);
			current.close();
		};

		const handleError: EventListener = () => {
			if (source !== current) return;
			open = false;
			source = null;
			detachCurrent = null;
			// Close immediately so the browser's unjittered auto-reconnect cannot fire.
			detach();
			if (subscribers.size === 0) return;
			const delayMs = backoff.markDisconnected();
			reconnectTimer = setTimeout(() => {
				reconnectTimer = null;
				connect();
			}, delayMs);
		};

		detachCurrent = detach;
		for (const [name, listener] of namedListeners) {
			current.addEventListener(name, listener);
		}
		current.addEventListener('open', handleOpen);
		current.addEventListener('error', handleError);
	}

	function subscribe<T extends object>(
		eventName: GuestEventName,
		handler: (event: T) => void,
		onOpen?: () => void,
	): () => void {
		if (!browser) return () => {};
		const sub: GuestSubscriber = {
			eventName,
			handler: handler as (event: Record<string, unknown>) => void,
			onOpen,
			disposed: false,
		};
		subscribers.add(sub);

		if (source === null && reconnectTimer === null) {
			connect();
		} else if (open && onOpen) {
			// Deterministic late-subscriber catch-up: joining an already-open stream
			// runs the subscriber's onOpen microtask without re-opening SSE.
			queueMicrotask(() => {
				if (!sub.disposed && open) {
					try {
						onOpen();
					} catch (e) {
						console.error('Guest EventSource late onOpen error', e);
					}
				}
			});
		}

		return () => {
			if (sub.disposed) return;
			sub.disposed = true;
			subscribers.delete(sub);
			if (subscribers.size === 0) {
				closeStream();
				backoff.reset();
			}
		};
	}

	function disconnect(): void {
		for (const sub of subscribers) sub.disposed = true;
		subscribers.clear();
		closeStream();
		backoff.reset();
	}

	return {
		subscribe,
		disconnect,
		get subscriberCount(): number {
			return subscribers.size;
		},
		get isOpen(): boolean {
			return open;
		},
	};
}

const defaultGuestHub = createGuestEventSourceHub();

function subscribeGuestEvents<T extends object>(
	eventName: GuestEventName,
	handler: (event: T) => void,
	onOpen?: () => void,
	options?: GuestEventSourceOptions,
): () => void {
	if (!browser) return () => {};
	// Preserve #389's isolated injectable `options.backoff` contract for tests
	// (e.g. seeded single-client and 100-client reconnect spread tests), while
	// all standard callers share the single ref-counted EventSource hub.
	if (options?.backoff) {
		const isolated = createGuestEventSourceHub(options);
		return isolated.subscribe(eventName, handler, onOpen);
	}
	return defaultGuestHub.subscribe(eventName, handler, onOpen);
}

export function subscribeGuestChatEvents<T extends object>(
	handler: (event: T) => void,
	onOpen?: () => void,
	options?: GuestEventSourceOptions,
): () => void {
	return subscribeGuestEvents('chat', handler, onOpen, options);
}

export function subscribeGuestMeetEvents<T extends object>(
	handler: (event: T) => void,
	onOpen?: () => void,
	options?: GuestEventSourceOptions,
): () => void {
	return subscribeGuestEvents('meet', handler, onOpen, options);
}

export function subscribeGuestSyncWakeup<T extends object = Record<string, unknown>>(
	handler: (event: T) => void,
	onOpen?: () => void,
	options?: GuestEventSourceOptions,
): () => void {
	return subscribeGuestEvents('sync_wakeup', handler, onOpen, options);
}

export function subscribeGuestScopeRevoked<T extends object = Record<string, unknown>>(
	handler: (event: T) => void,
	onOpen?: () => void,
	options?: GuestEventSourceOptions,
): () => void {
	return subscribeGuestEvents('scope_revoked', handler, onOpen, options);
}

export function disconnectGuestEventSource(): void {
	defaultGuestHub.disconnect();
}
