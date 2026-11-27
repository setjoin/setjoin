// Webmail WakeupTransport binding (Wave 2.8, #555).
//
// Bridges:
// - Members: JMAP WebSocket hub (`$lib/jmap/websocket`) — Wave 2.5
//   `SyncWakeup` / `ScopeRevoked` frames + legacy RFC 8887 `StateChange`,
//   `ChatEvent`, `DriveWatch`, and dynamic `ScopeAttach`/`ScopeDetach`.
//   Note: `offline.wipe` is owned exclusively by `$lib/offline/wipe.ts`
//   (`installWipeHandler`) which enforces fail-closed `deviceId === ownDeviceId()`
//   targeting BEFORE invoking registered pre-wipe abort hooks (#555 4e), so a
//   sibling-device wipe never aborts this device's in-flight sync.
// - Mailbox-less Guests: single shared ref-counted EventSource
//   (`$lib/chat/guestEventSource`) subscribing to 'chat', 'meet',
//   'sync_wakeup', and 'scope_revoked'.
//
// Uses namespace imports with runtime guards so the 19+ existing Vitest suites
// with partial `vi.mock('$lib/jmap/websocket', ...)` / `guestEventSource` mocks
// remain 100% compatible when live components import the runtime.

import * as wsModule from '$lib/jmap/websocket';
import type { WebSocketHub } from '$lib/jmap/websocket';
import * as guestSseModule from '$lib/chat/guestEventSource';
import type { GuestEventSourceHub } from '$lib/chat/guestEventSource';
import type {
	ScopeKey,
	ScopeRevokedEvent,
	SyncWakeup,
	WakeupTransport,
} from '../core/types.js';
import {
	validateScopeRevoked,
	validateSyncWakeup,
	type ValidationWarnFn,
} from '../core/validate.js';

export type WebmailTransportMode = 'member' | 'guest';

export interface WebmailWakeupTransportOptions {
	mode: WebmailTransportMode;
	/** Canonical scopeId used when bridging legacy account-wide JMAP StateChanges. */
	primaryMailboxScopeId?: string;
	/** Optional injected WebSocketHub (tests). Defaults to module singleton. */
	wsHub?: WebSocketHub;
	/** Optional injected GuestEventSourceHub (tests). Defaults to shared singleton. */
	guestHub?: GuestEventSourceHub;
	onWarning?: ValidationWarnFn;
}

const LEGACY_JMAP_TYPES = [
	'Email',
	'Mailbox',
	'Thread',
	'Calendar',
	'CalendarEvent',
	'Contact',
	'Task',
] as const;

/**
 * Safely reads an optional function export from a namespace import.
 * Vitest partial `vi.mock(...)` proxies throw in their `get` trap when an
 * unmocked export name is read; catching here lets live components share
 * `WebmailWakeupTransport` without breaking the 19+ partial-mock test suites.
 */
function readOptionalExport<T>(mod: object, key: string): T | null {
	try {
		const value = (mod as Record<string, unknown>)[key];
		return typeof value === 'function' ? (value as T) : null;
	} catch {
		return null;
	}
}

export class WebmailWakeupTransport implements WakeupTransport {
	readonly #mode: WebmailTransportMode;
	readonly #primaryMailboxScopeId: string;
	readonly #wsHub?: WebSocketHub;
	readonly #guestHub?: GuestEventSourceHub;
	readonly #onWarning: ValidationWarnFn;

	readonly #wakeupHandlers = new Set<(w: SyncWakeup) => void>();
	readonly #revokeHandlers = new Set<(e: ScopeRevokedEvent) => void>();
	readonly #reconnectHandlers = new Set<() => void>();
	readonly #unsubscribers: Array<() => void> = [];

	#started = false;
	#guestOpenedOnce = false;

	constructor(options: WebmailWakeupTransportOptions) {
		this.#mode = options.mode;
		this.#primaryMailboxScopeId = options.primaryMailboxScopeId ?? 'primary';
		this.#wsHub = options.wsHub;
		this.#guestHub = options.guestHub;
		this.#onWarning =
			options.onWarning ??
			((reason, detail) => {
				if (detail) console.warn('[WebmailWakeupTransport]', reason, detail);
				else console.warn('[WebmailWakeupTransport]', reason);
			});
	}

	#ensureStarted(): void {
		if (this.#started) return;
		this.#started = true;
		if (this.#mode === 'member') {
			this.#wireMemberTransport();
		} else {
			this.#wireGuestTransport();
		}
	}

	#wireMemberTransport(): void {
		const subType = this.#wsHub
			? this.#wsHub.subscribeType.bind(this.#wsHub)
			: readOptionalExport<typeof wsModule.subscribeType>(wsModule, 'subscribeType');
		const subControl = this.#wsHub
			? this.#wsHub.subscribeControl.bind(this.#wsHub)
			: readOptionalExport<typeof wsModule.subscribeControl>(wsModule, 'subscribeControl');
		const subJmap = this.#wsHub
			? this.#wsHub.subscribe.bind(this.#wsHub)
			: readOptionalExport<typeof wsModule.subscribe>(wsModule, 'subscribe');
		const subReconnect = this.#wsHub
			? this.#wsHub.subscribeReconnect.bind(this.#wsHub)
			: readOptionalExport<typeof wsModule.subscribeReconnect>(wsModule, 'subscribeReconnect');

		if (subType) {
			// Wave 2.5 canonical frames: SyncWakeup & ScopeRevoked
			this.#unsubscribers.push(
				subType('SyncWakeup', (payload) => {
					const wakeup = validateSyncWakeup(payload.event ?? payload, this.#onWarning);
					if (wakeup) this.#emitWakeup(wakeup);
				}),
			);
			this.#unsubscribers.push(
				subType('ScopeRevoked', (payload) => {
					const evt = validateScopeRevoked(payload.event ?? payload, this.#onWarning);
					if (evt) this.#emitRevoke(evt);
				}),
			);

			// Legacy ChatEvent bridge
			this.#unsubscribers.push(
				subType('ChatEvent', (payload) => {
					const raw = payload.event;
					if (!raw || typeof raw !== 'object') return;
					const evt = raw as { channelId?: unknown; seq?: unknown; event?: unknown };
					if (typeof evt.channelId !== 'number' || !Number.isSafeInteger(evt.channelId) || evt.channelId <= 0) {
						return;
					}
					const seq =
						typeof evt.seq === 'number' && Number.isSafeInteger(evt.seq) && evt.seq >= 0 ? evt.seq : 0;
					const wakeup = validateSyncWakeup(
						{
							scopeKind: 'channel',
							scopeId: String(evt.channelId),
							seq,
							reason: typeof evt.event === 'string' ? evt.event : 'chat_event',
						},
						this.#onWarning,
					);
					if (wakeup) this.#emitWakeup(wakeup);
				}),
			);

			// Legacy DriveWatch bridge
			this.#unsubscribers.push(
				subType('DriveWatch', (payload) => {
					const raw = payload.event;
					if (!raw || typeof raw !== 'object') return;
					const evt = raw as { spaceId?: unknown; op?: unknown };
					if (typeof evt.spaceId !== 'number' || !Number.isSafeInteger(evt.spaceId) || evt.spaceId <= 0) {
						return;
					}
					const wakeup = validateSyncWakeup(
						{
							scopeKind: 'space',
							scopeId: String(evt.spaceId),
							seq: 0,
							reason: typeof evt.op === 'string' ? evt.op : 'drive_watch',
						},
						this.#onWarning,
					);
					if (wakeup) this.#emitWakeup(wakeup);
				}),
			);
		}

		if (subControl) {
			this.#unsubscribers.push(
				subControl('scope_revoked', (payload) => {
					const evt = validateScopeRevoked(payload, this.#onWarning);
					if (evt) this.#emitRevoke(evt);
				}),
			);
		}

		if (subJmap) {
			// Legacy RFC 8887 StateChange bridge (mixed-version rollout)
			this.#unsubscribers.push(
				subJmap([...LEGACY_JMAP_TYPES], (changes) => {
					const changed: Record<string, string> = {};
					const dataTypes: string[] = [];
					for (const [k, v] of Object.entries(changes)) {
						if (typeof v === 'string') {
							changed[k] = v;
							dataTypes.push(k);
						}
					}
					if (dataTypes.length === 0) return;
					this.#emitWakeup({
						scopeKind: 'mailbox',
						scopeId: this.#primaryMailboxScopeId,
						seq: 0,
						dataTypes,
						changed,
						reason: 'legacy_state_change',
					});
				}),
			);
		}

		if (subReconnect) {
			// Reconnect catch-up hook (everOpened-guarded inside WebSocketHub)
			this.#unsubscribers.push(subReconnect(() => this.#emitReconnect()));
		}
	}

	#wireGuestTransport(): void {
		const handleOpen = () => {
			if (this.#guestOpenedOnce) {
				this.#emitReconnect();
			}
			this.#guestOpenedOnce = true;
		};

		const handleSyncWakeup = (payload: Record<string, unknown>) => {
			const wakeup = validateSyncWakeup(payload, this.#onWarning);
			if (wakeup) this.#emitWakeup(wakeup);
		};

		const handleScopeRevoked = (payload: Record<string, unknown>) => {
			const evt = validateScopeRevoked(payload, this.#onWarning);
			if (evt) this.#emitRevoke(evt);
		};

		const handleChatEvent = (payload: Record<string, unknown>) => {
			const channelId = payload.channelId;
			if (typeof channelId !== 'number' || !Number.isSafeInteger(channelId) || channelId <= 0) return;
			const seq =
				typeof payload.seq === 'number' && Number.isSafeInteger(payload.seq) && payload.seq >= 0
					? payload.seq
					: 0;
			const wakeup = validateSyncWakeup(
				{
					scopeKind: 'channel',
					scopeId: String(channelId),
					seq,
					reason: typeof payload.event === 'string' ? payload.event : 'guest_chat_event',
				},
				this.#onWarning,
			);
			if (wakeup) this.#emitWakeup(wakeup);
		};

		if (this.#guestHub) {
			this.#unsubscribers.push(this.#guestHub.subscribe('sync_wakeup', handleSyncWakeup, handleOpen));
			this.#unsubscribers.push(this.#guestHub.subscribe('scope_revoked', handleScopeRevoked));
			this.#unsubscribers.push(this.#guestHub.subscribe('chat', handleChatEvent));
		} else {
			const subWakeup = readOptionalExport<typeof guestSseModule.subscribeGuestSyncWakeup>(
				guestSseModule,
				'subscribeGuestSyncWakeup',
			);
			const subRevoked = readOptionalExport<typeof guestSseModule.subscribeGuestScopeRevoked>(
				guestSseModule,
				'subscribeGuestScopeRevoked',
			);
			if (subWakeup) {
				this.#unsubscribers.push(subWakeup(handleSyncWakeup, handleOpen));
			}
			if (subRevoked) {
				this.#unsubscribers.push(subRevoked(handleScopeRevoked));
			}
		}
	}

	onWakeup(handler: (wakeup: SyncWakeup) => void): () => void {
		this.#ensureStarted();
		this.#wakeupHandlers.add(handler);
		return () => this.#wakeupHandlers.delete(handler);
	}

	onScopeRevoked(handler: (event: ScopeRevokedEvent) => void): () => void {
		this.#ensureStarted();
		this.#revokeHandlers.add(handler);
		return () => this.#revokeHandlers.delete(handler);
	}

	onReconnect(handler: () => void): () => void {
		this.#ensureStarted();
		this.#reconnectHandlers.add(handler);
		return () => this.#reconnectHandlers.delete(handler);
	}

	setAttachedScopes(scopes: readonly ScopeKey[]): void {
		if (this.#mode !== 'member') return;
		if (this.#wsHub) {
			this.#wsHub.setAttachedScopes(scopes);
			return;
		}
		const setAttached = readOptionalExport<typeof wsModule.setAttachedScopes>(wsModule, 'setAttachedScopes');
		if (setAttached) {
			setAttached(scopes);
		}
	}

	disconnect(): void {
		for (const unsub of this.#unsubscribers) {
			try {
				unsub();
			} catch {
				// isolate teardown errors
			}
		}
		this.#unsubscribers.length = 0;
		this.#started = false;
		this.#guestOpenedOnce = false;
		this.#wakeupHandlers.clear();
		this.#revokeHandlers.clear();
		this.#reconnectHandlers.clear();
		if (this.#mode === 'member') {
			if (this.#wsHub) {
				this.#wsHub.disconnect();
			} else {
				const disc = readOptionalExport<typeof wsModule.disconnect>(wsModule, 'disconnect');
				if (disc) disc();
			}
		}
	}

	#emitWakeup(w: SyncWakeup): void {
		for (const h of [...this.#wakeupHandlers]) {
			try {
				h(w);
			} catch (e) {
				console.error('[WebmailWakeupTransport] wakeup handler error', e);
			}
		}
	}

	#emitRevoke(e: ScopeRevokedEvent): void {
		for (const h of [...this.#revokeHandlers]) {
			try {
				h(e);
			} catch (err) {
				console.error('[WebmailWakeupTransport] revoke handler error', err);
			}
		}
	}

	#emitReconnect(): void {
		for (const h of [...this.#reconnectHandlers]) {
			try {
				h();
			} catch (err) {
				console.error('[WebmailWakeupTransport] reconnect handler error', err);
			}
		}
	}
}
