import { browser } from '$app/environment';
import { ReconnectBackoff, type ReconnectBackoffOptions } from '$lib/ws/backoff';

const guestEventSourceURL = '/api/jmap/eventsource?types=*&ping=30';

type GuestEventName = 'chat' | 'meet';

export interface GuestEventSourceOptions {
	backoff?: ReconnectBackoffOptions;
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
function subscribeGuestEvents<T extends object>(
	eventName: GuestEventName,
	handler: (event: T) => void,
	onOpen?: () => void,
	options?: GuestEventSourceOptions,
): () => void {
	if (!browser) return () => {};

	const backoff = new ReconnectBackoff(options?.backoff);
	let source: EventSource | null = null;
	let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
	let disposed = false;

	let detachCurrent: (() => void) | null = null;

	function connect(): void {
		if (disposed || source !== null) return;
		if (reconnectTimer !== null) {
			clearTimeout(reconnectTimer);
			reconnectTimer = null;
		}

		const current = new EventSource(guestEventSourceURL);
		source = current;

		const onEvent: EventListener = (raw) => {
			if (disposed || source !== current) return;
			const data = (raw as MessageEvent<unknown>).data;
			if (typeof data !== 'string') return;
			try {
				const event: unknown = JSON.parse(data);
				if (!event || typeof event !== 'object' || Array.isArray(event)) return;
				handler(event as T);
			} catch {
				// A malformed server/extension frame is isolated to that frame and
				// does not tear down or reconnect the authenticated stream.
			}
		};

		const handleOpen: EventListener = () => {
			if (disposed || source !== current) return;
			backoff.markConnected();
			onOpen?.();
		};

		const detach = () => {
			current.removeEventListener(eventName, onEvent);
			current.removeEventListener('open', handleOpen);
			current.removeEventListener('error', handleError);
			current.close();
		};

		const handleError: EventListener = () => {
			if (disposed || source !== current) return;
			source = null;
			detachCurrent = null;
			// Close immediately so the browser's unjittered auto-reconnect cannot fire.
			detach();
			const delayMs = backoff.markDisconnected();
			reconnectTimer = setTimeout(() => {
				reconnectTimer = null;
				connect();
			}, delayMs);
		};

		detachCurrent = detach;
		current.addEventListener(eventName, onEvent);
		current.addEventListener('open', handleOpen);
		current.addEventListener('error', handleError);
	}

	connect();

	return () => {
		disposed = true;
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
		backoff.reset();
	};
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
