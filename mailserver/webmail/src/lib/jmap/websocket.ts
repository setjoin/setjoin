// JMAP WebSocket push client (RFC 8887) — always-on, self-arming multi-listener hub.
//
// One process-global socket fans each StateChange out to every registered
// listener whose declared dataTypes intersect the changed type-map. The socket
// is ALWAYS-ON: the first `subscribe()` opens it (call-order irrelevant) and it
// stays open for the session. It is NOT ref-counted — the server pushes all
// state by default (the `dataTypes` advert is advisory, a no-op on the gateway),
// so an idle socket is free and ref-counting would only add a "closed while a
// listener still wants it" bug. `disconnect()` is for explicit teardown (logout).
import { browser } from '$app/environment';

let ws: WebSocket | null = null;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let reconnectDelay = 1000;
// True once a socket of this session has opened: the next onopen is a
// RE-connect, whose missed-StateChange gap listeners must resync (#222). Reset
// by disconnect() so a fresh login's first open is not mistaken for one.
let everOpened = false;
const MAX_RECONNECT_DELAY = 60000;

type StateChangeHandler = (changes: Record<string, unknown>) => void;

interface Listener {
	types: string[];
	handler: StateChangeHandler;
	onReconnect?: () => void;
}

/** Optional per-listener hooks beyond StateChange delivery. */
export interface SubscribeOptions {
	/**
	 * Fired after the socket re-opens following a drop (never on the first
	 * connect). StateChanges pushed while the socket was down are lost, so a
	 * listener that caches server state resyncs from its last known state here.
	 */
	onReconnect?: () => void;
}

// The listener registry IS the source of truth across reconnects: open() reads
// the union of declared types to advertise, and onmessage fans out to whoever is
// currently registered (so a reconnect re-delivers to live listeners).
const listeners = new Set<Listener>();

// Control-message registry: verbatim server pushes that are NOT RFC 8887
// StateChanges. The gateway forwards these with a lowercase "type" field
// (offline.wipe / capsChanged). Keyed by that type.
// ponytail: Map<string, Set> is stdlib — no EventEmitter dep needed.
type ControlHandler = (payload: Record<string, unknown>) => void;
const controlHandlers = new Map<string, Set<ControlHandler>>();

export function subscribeControl(type: string, handler: ControlHandler): () => void {
	let set = controlHandlers.get(type);
	if (!set) {
		set = new Set();
		controlHandlers.set(type, set);
	}
	set.add(handler);
	return () => set!.delete(handler);
}

// @type-keyed registry: verbatim, non-StateChange server pushes carrying an
// uppercase "@type" (unlike the lowercase-"type" control messages above).
// Drive P4's DriveWatch envelope (`{"@type":"DriveWatch","event":{...}}` —
// internal/ws/handler.go's drive-watch:<uid> forward, plan Task 11/14) is the
// first consumer; SessionRevoked stays a one-off handled inline elsewhere and
// isn't rerouted through this to avoid touching working code.
type AtTypeHandler = (payload: Record<string, unknown>) => void;
const atTypeHandlers = new Map<string, Set<AtTypeHandler>>();

export function subscribeType(atType: string, handler: AtTypeHandler): () => void {
	let set = atTypeHandlers.get(atType);
	if (!set) {
		set = new Set();
		atTypeHandlers.set(atType, set);
	}
	set.add(handler);
	return () => set!.delete(handler);
}

// subscribeEvent is the typed, unwrapped sibling of subscribeType: every
// `{"@type":<atType>,"event":{...}}` producer (ChatEvent/MeetEvent/DriveWatch/
// DriveAlarm) wraps its payload in an `event` field, and every consumer used
// to redo `payload.event as <cast>` inline (6 call sites, unchecked cast, no
// malformed-envelope guard). This unwraps ONCE at the hub: a missing or
// non-object `event` is silently dropped here instead of reaching the
// handler as `undefined`/garbage — this is the seam the MeetEvent bug (raw
// envelope cast as the event, `evt.meetingId` always undefined) shipped
// through. Handlers receive the already-unwrapped, typed event.
export function subscribeEvent<T extends object>(atType: string, handler: (event: T) => void): () => void {
	return subscribeType(atType, (payload) => {
		const event = payload.event;
		if (!event || typeof event !== 'object') return;
		handler(event as T);
	});
}

// __handleRawMessage is the single message entry point (exported for tests). A
// control payload (lowercase "type") is fanned to its control handlers; an
// @type-keyed payload is fanned to its subscribeType handlers; an RFC 8887
// StateChange ("@type":"StateChange") is unwrapped + fanned to state listeners.
export function __handleRawMessage(raw: string): void {
	let msg: { '@type'?: string; type?: string; changed?: Record<string, Record<string, string>> };
	try {
		msg = JSON.parse(raw);
	} catch (e) {
		console.error('WebSocket parse error', e);
		return;
	}
	if (typeof msg.type === 'string' && controlHandlers.has(msg.type)) {
		const payload = msg as unknown as Record<string, unknown>;
		for (const h of controlHandlers.get(msg.type)!) {
			try {
				h(payload);
			} catch (e) {
				console.error('WebSocket control handler error', e);
			}
		}
		return;
	}
	if (typeof msg['@type'] === 'string' && atTypeHandlers.has(msg['@type'])) {
		const payload = msg as unknown as Record<string, unknown>;
		for (const h of atTypeHandlers.get(msg['@type'])!) {
			try {
				h(payload);
			} catch (e) {
				console.error('WebSocket @type handler error', e);
			}
		}
	}
	if (msg['@type'] === 'StateChange' && msg.changed) {
		dispatch(unwrapTypeMap(msg.changed));
	}
}

// subscribe registers a listener for the given dataTypes and returns an
// unsubscribe function. It opens the always-on socket on first use (self-arming;
// any caller may be first). A StateChange is delivered to this listener only when
// its changed type-map intersects `types`. Each listener is dispatched inside its
// own try/catch so one throwing listener never aborts the fan-out (error
// isolation), in steady state AND on the first StateChange after a reconnect.
export function subscribe(
	types: string[],
	handler: StateChangeHandler,
	options?: SubscribeOptions
): () => void {
	const listener: Listener = { types, handler, onReconnect: options?.onReconnect };
	listeners.add(listener);

	if (browser && !ws) {
		open();
	} else if (ws && ws.readyState === WebSocket.OPEN) {
		// Late subscriber against an already-open socket: re-advertise the union
		// so a newly-declared dataType is documented to the server.
		sendPushEnable();
	}

	return () => {
		listeners.delete(listener);
	};
}

// unionDataTypes is the deduped union of every registered listener's declared
// types — advertised in WebSocketPushEnable on open and re-advertised on
// reconnect. It gates nothing (the gateway pushes all state regardless); kept as
// documentation / forward-compat for the real push contract.
function unionDataTypes(): string[] {
	const set = new Set<string>();
	for (const l of listeners) {
		for (const t of l.types) set.add(t);
	}
	return [...set];
}

function sendPushEnable(): void {
	ws?.send(
		JSON.stringify({
			'@type': 'WebSocketPushEnable',
			dataTypes: unionDataTypes()
		})
	);
}

function open(): void {
	if (!browser) return;
	if (ws) return;

	// Use relative URL so wss:// is auto-negotiated when page is served over HTTPS.
	ws = new WebSocket(`ws${location.protocol === 'https:' ? 's' : ''}://${location.host}/jmap/ws`);

	ws.onopen = () => {
		reconnectDelay = 1000;
		// Advertise the union of every registered listener's types (re-advertised
		// here on every (re)connect from the live registry).
		sendPushEnable();
		// #222: pushes sent while the socket was down are gone — tell every
		// listener that opted in so it can resync from its last known state.
		if (everOpened) notifyReconnect();
		everOpened = true;
		// A8: a (re)connect transition is a drain trigger for the offline
		// action-queue (bootstrap + reconnect replay shape) — the JMAP session is
		// reachable again. Dynamic import: a static one would close the
		// auth → websocket → offline-client cycle. Fire-and-forget: the push
		// channel never depends on the drain (overlapping triggers collapse on
		// the drain's in-flight guard).
		import('$lib/jmap/offline-client')
			.then((m) => m.drainPendingActions())
			.catch(() => {});
	};

	ws.onmessage = (event) => {
		__handleRawMessage(event.data as string);
	};

	ws.onclose = () => {
		ws = null;
		reconnectTimer = setTimeout(() => {
			reconnectDelay = Math.min(reconnectDelay * 2, MAX_RECONNECT_DELAY);
			open();
		}, reconnectDelay);
	};

	ws.onerror = () => {
		// Some network conditions fire onerror without subsequent onclose.
		// Force-close so the onclose handler triggers reconnect.
		ws?.close();
	};
}

// dispatch fans an unwrapped type-map out to every listener whose declared types
// intersect the changed keys. Per-listener error isolation: a throwing handler
// is caught and logged so it cannot starve co-registered listeners (steady-state
// and on the first StateChange after a reconnect, since reconnect re-delivers
// from the same registry).
function dispatch(changes: Record<string, string>): void {
	for (const l of listeners) {
		if (!l.types.some((t) => t in changes)) continue;
		try {
			l.handler(changes);
		} catch (e) {
			console.error('WebSocket listener error', e);
		}
	}
}

// notifyReconnect fans a reconnect to every listener with an onReconnect hook,
// with the same per-listener error isolation as dispatch().
function notifyReconnect(): void {
	for (const l of listeners) {
		if (!l.onReconnect) continue;
		try {
			l.onReconnect();
		} catch (e) {
			console.error('WebSocket reconnect listener error', e);
		}
	}
}

// unwrapTypeMap resolves the per-account TYPE map from a RFC 8887 StateChange
// `changed` object (`{ <accountId>: { Email, Mailbox, Thread, Calendar, … } }`).
// A WS connection is scoped to a single account, so any account entry is the one
// we want; we return the first. Exported for unit testing.
export function unwrapTypeMap(
	changed: Record<string, Record<string, string>> | null | undefined
): Record<string, string> {
	if (!changed) return {};
	// Account attribution: the socket is server-scoped to ONE authenticated
	// account, so a well-formed frame carries exactly one accountId key. A
	// multi-key map is not attributable on this connection — drop it (empty
	// map dispatches to nothing) instead of blindly applying an arbitrary
	// entry's state for an account this connection may not represent.
	const ids = Object.keys(changed);
	if (ids.length !== 1) return {};
	return changed[ids[0]] ?? {};
}

// disconnect tears the socket down explicitly (e.g. logout) and clears the
// registry. Not called on last-unsubscribe — the hub is always-on, not
// ref-counted.
export function disconnect(): void {
	if (reconnectTimer) {
		clearTimeout(reconnectTimer);
		reconnectTimer = null;
	}
	listeners.clear();
	controlHandlers.clear();
	everOpened = false;
	if (ws) {
		ws.close();
		ws = null;
	}
}
