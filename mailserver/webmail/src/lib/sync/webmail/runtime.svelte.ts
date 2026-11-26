// Singleton Webmail SyncCoordinator runtime (Wave 2.8, #555).
//
// - Shares the single `CriticalActivityCounter` with `$lib/offline/boot.ts`
//   (ARCH-023: never creates a second counter).
// - Wired to `registerAuthSessionTeardown` (`$lib/stores/auth.ts:105`) so logout
//   and identity switch dispose the coordinator & transport cleanly, ensuring a
//   subsequent re-login constructs a fresh connected transport/coordinator pair.
// - Wired to `registerPreWipeHook` (`$lib/offline/wipe.ts`) so `offline.wipe`
//   aborts in-flight SyncCoordinator work AFTER fail-closed deviceId targeting
//   and BEFORE `db.wipe('mail')` executes.

import { getSharedCriticalActivity, registerPreWipeHook } from '$lib/offline/criticalScope';
import * as wsModule from '$lib/jmap/websocket';
import * as guestSseModule from '$lib/chat/guestEventSource';
import { SyncCoordinator } from '../core/coordinator.js';
import { WebmailWakeupTransport, type WebmailTransportMode } from './transport';

let activeTransport: WebmailWakeupTransport | null = null;
let activeCoordinator: SyncCoordinator | null = null;
let activeMode: WebmailTransportMode | null = null;
let teardownWired = false;

function teardownRuntime(): void {
	activeCoordinator?.dispose();
	activeCoordinator = null;
	activeTransport?.disconnect();
	activeTransport = null;
	activeMode = null;
	try {
		const disc = (guestSseModule as Record<string, unknown>)['disconnectGuestEventSource'];
		if (typeof disc === 'function') {
			(disc as () => void)();
		}
	} catch {
		// partial Vitest mocks of $lib/chat/guestEventSource may omit disconnectGuestEventSource
	}
}

function wireSessionHooks(): void {
	if (teardownWired) return;
	teardownWired = true;
	// Lazy dynamic import avoids pulling `$lib/stores/auth` (and `$lib/jmap/client`)
	// into component unit tests that partially mock `$lib/jmap/client`.
	void import('$lib/stores/auth')
		.then((mod) => {
			if (typeof mod.registerAuthSessionTeardown === 'function') {
				mod.registerAuthSessionTeardown(() => {
					teardownRuntime();
				});
			}
		})
		.catch(() => {});
	registerPreWipeHook(async () => {
		if (!activeCoordinator) return;
		return activeCoordinator.beginWipeFence('offline.wipe');
	});
}

/**
 * Safely subscribes to the member JMAP WebSocket open/close state without
 * breaking partial Vitest mocks of `$lib/jmap/websocket`.
 */
export function subscribeMemberWsConnected(handler: (connected: boolean) => void): () => void {
	try {
		const sub = (wsModule as Record<string, unknown>)['subscribeConnectionState'];
		if (typeof sub === 'function') {
			return (sub as (fn: (connected: boolean) => void) => () => void)(handler);
		}
	} catch {
		// partial Vitest mock of $lib/jmap/websocket omits subscribeConnectionState
	}
	return () => {};
}

/**
 * Returns the process-wide Webmail SyncCoordinator singleton, sharing
 * `offline/boot.ts`'s `CriticalActivityCounter`. Reconstructs cleanly after
 * logout/teardown so re-login always has a live transport.
 */
export function getWebmailSyncCoordinator(mode: WebmailTransportMode = 'member'): SyncCoordinator {
	wireSessionHooks();
	if (
		activeCoordinator &&
		!activeCoordinator.disposed &&
		activeTransport !== null &&
		activeMode === mode
	) {
		return activeCoordinator;
	}
	activeCoordinator?.dispose();
	activeTransport?.disconnect();
	activeMode = mode;
	activeTransport = new WebmailWakeupTransport({ mode });
	activeCoordinator = new SyncCoordinator({
		transport: activeTransport,
		critical: getSharedCriticalActivity(),
	});
	return activeCoordinator;
}

/** Test-only reset for the Webmail SyncCoordinator singleton. */
export function resetWebmailSyncRuntimeForTests(): void {
	teardownRuntime();
}
