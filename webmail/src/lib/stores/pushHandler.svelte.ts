// PushHandlerStore — the single WebSocket→action seam for the SPA.
//
// Every consumer that wants to react to a JMAP StateChange registers a handler
// here instead of calling the `$lib/jmap/websocket` hub directly. The store owns
// ALL hub subscriptions and ONE optional per-registration debounce, so the
// "open a subscription, debounce a reload, tear it down on destroy" boilerplate
// that used to live in InboxStore / TasksApp / CalendarApp / ContactsApp lives
// in exactly one place.
//
// `register(dataTypes, handler, { debounceMs?, onReconnect? })` opens a hub
// listener scoped to `dataTypes` and returns its unsubscribe. The options object
// extends the hub's `SubscribeOptions` (#225), so hub hooks keep one shape:
//   - debounceMs omitted/0 → the handler fires synchronously on each matching
//     StateChange (preserves the immediate-refresh behavior of Tasks/Calendar/
//     Contacts, whose own loading guards coalesce bursts).
//   - debounceMs > 0 → matching StateChanges are coalesced into a single handler
//     call per window (preserves the inbox's 300ms debounce).
//
//
// `onReconnect` (optional) runs after the hub's socket re-opens following a drop
// (#222: pushes sent while it was down are lost). It shares the registration's
// debounce window with StateChanges, so a reconnect and a push landing inside
// one window collapse into ONE call — the push wins (it already says something
// changed), the reconnect hook runs only when no push arrived.
//
// The hub already isolates a throwing listener in steady state; the debounce
// path adds its own try/catch so a throwing handler can never crash the timer
// flush (and so a synchronous handler's throw is swallowed here too, keeping the
// register() contract uniform regardless of debounce).

import { subscribe, type SubscribeOptions } from '$lib/jmap/websocket';

/** Per-registration options: the hub's SubscribeOptions plus the debounce window. */
export interface PushRegisterOptions extends SubscribeOptions {
	/** Coalescing window in ms; omit (or 0) to fire immediately. */
	debounceMs?: number;
}

/** The unwrapped per-account StateChange type-map (`{Email, Mailbox, …}`). */
export type PushChanges = Record<string, unknown>;

/** A consumer's reaction to a StateChange touching one of its dataTypes. */
export type PushHandler = (changes: PushChanges) => void;

interface Registration {
	unsubscribe: () => void;
	timer: ReturnType<typeof setTimeout> | null;
	/** Latest StateChange seen in the open debounce window, if any. */
	pending: PushChanges | null;
	/** A reconnect landed in the open debounce window. */
	reconnected: boolean;
}

export class PushHandlerStore {
	#registrations = new Set<Registration>();

	/**
	 * Register a handler over the single WebSocket hub.
	 *
	 * @param dataTypes  the JMAP types this consumer reacts to (e.g. `['Email']`).
	 * @param handler    invoked with the StateChange type-map on a matching change.
	 * @param options    `debounceMs`: optional coalescing window (omit/0 = fire
	 *                   immediately); `onReconnect`: optional resync hook run after a
	 *                   socket re-open (never on the first connect), coalesced with
	 *                   pushes in the window.
	 * @returns an unsubscribe that tears down the hub listener + any pending timer.
	 */
	register(dataTypes: string[], handler: PushHandler, options: PushRegisterOptions = {}): () => void {
		const { debounceMs = 0, onReconnect } = options;
		const reg: Registration = { unsubscribe: () => {}, timer: null, pending: null, reconnected: false };

		const guarded = (run: () => void) => {
			try {
				run();
			} catch (e) {
				console.error('PushHandlerStore handler error', e);
			}
		};

		const flush = () => {
			const changes = reg.pending;
			const reconnected = reg.reconnected;
			reg.timer = null;
			reg.pending = null;
			reg.reconnected = false;
			if (changes) guarded(() => handler(changes));
			else if (reconnected && onReconnect) guarded(onReconnect);
		};

		const schedule = () => {
			if (debounceMs > 0) {
				if (reg.timer) clearTimeout(reg.timer);
				reg.timer = setTimeout(flush, debounceMs);
			} else {
				flush();
			}
		};

		const onChange = (changes: PushChanges) => {
			reg.pending = changes;
			schedule();
		};
		reg.unsubscribe = onReconnect
			? subscribe(dataTypes, onChange, {
					onReconnect: () => {
						reg.reconnected = true;
						schedule();
					},
				})
			: subscribe(dataTypes, onChange);

		this.#registrations.add(reg);

		return () => this.#remove(reg);
	}

	#remove(reg: Registration): void {
		if (reg.timer) {
			clearTimeout(reg.timer);
			reg.timer = null;
		}
		reg.pending = null;
		reg.reconnected = false;
		reg.unsubscribe();
		this.#registrations.delete(reg);
	}

	/** Tear down every registration + cancel every pending debounce (onDestroy). */
	teardown(): void {
		for (const reg of [...this.#registrations]) {
			this.#remove(reg);
		}
	}
}

/**
 * Shared process-wide instance. Components that don't manage their own lifecycle
 * register against this and keep the returned unsubscribe; the InboxStore owns
 * its own instance so its teardown() stays self-contained.
 */
export const pushHandlers = new PushHandlerStore();
