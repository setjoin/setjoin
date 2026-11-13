//! ADR-013 invariant 2 (wiring half): the ONE place `ipcMain.handle` is called.
//!
//! `registerHandler` is the single registration wrapper — it validates the
//! sender origin and tracks the registered channel set, so no handler can bypass
//! the origin check (a new handler physically cannot skip it; there is no other
//! `ipcMain.handle` call in the codebase — grep-enforced). Unknown channels have
//! no handler and Electron rejects the invoke by construction.

import { ipcMain, type IpcMainInvokeEvent } from 'electron';
import { isSenderAllowed } from './security/ipc-origin';
import type { HandlerMap } from './handlers/db';

let allowedOrigins: string[] = [];
const registeredChannels = new Set<string>();

/** Set the exact app-origin allowlist (bundled index.html URL, or dev server). */
export function configureAllowedOrigins(origins: string[]): void {
	allowedOrigins = origins;
}

/** Channels registered so far (audit/test helper). */
export function registeredChannelList(): string[] {
	return [...registeredChannels];
}

/** Reset registrations (test helper). */
export function _resetForTest(): void {
	registeredChannels.clear();
	allowedOrigins = [];
}

/**
 * Register one IPC handler behind the origin gate. `handler` receives the invoke
 * args only (the event is consumed here for the origin check). Throws on a
 * duplicate channel so a copy-paste collision fails loudly at startup.
 */
export function registerHandler(
	channel: string,
	handler: (...args: unknown[]) => unknown,
): void {
	if (registeredChannels.has(channel)) {
		throw new Error(`duplicate IPC channel registration: ${channel}`);
	}
	registeredChannels.add(channel);
	ipcMain.handle(channel, async (event: IpcMainInvokeEvent, ...args: unknown[]) => {
		if (!isSenderAllowed(event.senderFrame?.url, allowedOrigins)) {
			throw new Error(`ipc: rejected sender origin for channel ${channel}`);
		}
		return handler(...args);
	});
}

/** Register a whole `{channel: fn}` map through the wrapper. */
export function registerHandlers(map: HandlerMap): void {
	for (const [channel, fn] of Object.entries(map)) {
		registerHandler(channel, fn as (...args: unknown[]) => unknown);
	}
}
