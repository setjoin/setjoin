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

import { registerAuthSessionTeardown } from '$lib/stores/auth';
import { getSharedCriticalActivity } from '$lib/offline/boot';
import { registerPreWipeHook } from '$lib/offline/wipe';
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
	registerAuthSessionTeardown(() => {
		teardownRuntime();
	});
	registerPreWipeHook(async () => {
		await activeCoordinator?.abortAllInFlightAndFence('offline.wipe');
	});
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
