import { browser } from '$app/environment';

const guestEventSourceURL = '/api/jmap/eventsource?types=*&ping=30';

type GuestEventName = 'chat' | 'meet';

// Mailbox-less guests cannot use the JMAP WebSocket protocol because that
// socket also accepts client Request frames. Their live collaboration rail is
// the server's read-only EventSource surface, which authenticates with the
// same-origin access-token cookie and emits raw objects as named events.
function subscribeGuestEvents<T extends object>(
	eventName: GuestEventName,
	handler: (event: T) => void,
	onOpen?: () => void,
): () => void {
	if (!browser) return () => {};

	const source = new EventSource(guestEventSourceURL);
	const onEvent: EventListener = (raw) => {
		const data = (raw as MessageEvent<unknown>).data;
		if (typeof data !== 'string') return;
		try {
			const event: unknown = JSON.parse(data);
			if (!event || typeof event !== 'object' || Array.isArray(event)) return;
			handler(event as T);
		} catch {
			// A malformed server/extension frame is isolated to that frame. Native
			// EventSource keeps the authenticated stream open and reconnects itself.
		}
	};
	const handleOpen: EventListener = () => onOpen?.();

	source.addEventListener(eventName, onEvent);
	source.addEventListener('open', handleOpen);
	return () => {
		source.removeEventListener(eventName, onEvent);
		source.removeEventListener('open', handleOpen);
		source.close();
	};
}

export function subscribeGuestChatEvents<T extends object>(
	handler: (event: T) => void,
	onOpen?: () => void,
): () => void {
	return subscribeGuestEvents('chat', handler, onOpen);
}

export function subscribeGuestMeetEvents<T extends object>(
	handler: (event: T) => void,
	onOpen?: () => void,
): () => void {
	return subscribeGuestEvents('meet', handler, onOpen);
}
