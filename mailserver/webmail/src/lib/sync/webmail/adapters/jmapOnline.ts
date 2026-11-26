// JMAP online SyncScopeAdapters (Wave 2.8, #555):
// - InboxStore (`debounceMs: 300`, preserves `#reflects` + `#loadGen` fencing;
//   shared-mailbox `scope_revoked` evicts ONLY InboxStore memory + sets
//   `accessRevoked = true`, NEVER calls `db.wipe('mail')`).
// - CalendarApp, ContactsApp, TasksApp (`debounceMs: 0`) & RemindersWindow
//   (`debounceMs: 500`) — all gain reconnect catch-up via SyncCoordinator.

import type { InboxStore } from '$lib/stores/inboxStore.svelte';
import type { PushChanges } from '$lib/stores/pushHandler.svelte';
import type { ScopeRevokedEvent, StepOutcome, SyncScopeAdapter, SyncStepContext } from '../../core/types.js';

export const INBOX_DEBOUNCE_MS = 300;
export const PIM_DEBOUNCE_MS = 0;
export const REMINDERS_DEBOUNCE_MS = 500;

export interface InboxSyncAdapterOptions {
	store: InboxStore;
	mailboxScopeId: string;
	/** True when browsing a delegated/shared mailbox (`/inbox?mbx=<id>`). */
	isSharedMailbox?: boolean;
	consumerId?: string;
}

/**
 * SyncScopeAdapter for `InboxStore`.
 * - Foreground lane (never preempted by `CriticalActivityCounter`).
 * - Preserves `InboxStore`'s `#reflects` and `#loadGen` stale-load fencing.
 * - On shared-mailbox `scope_revoked`: evicts ONLY in-memory InboxStore state
 *   and sets `accessRevoked = true`; NEVER touches native SQLCipher `db.wipe('mail')`.
 */
export function createInboxSyncAdapter(options: InboxSyncAdapterOptions): SyncScopeAdapter {
	const { store, mailboxScopeId } = options;
	const isShared = options.isSharedMailbox ?? store.accountOverride !== null;

	return {
		consumerId: options.consumerId ?? (isShared ? `inbox:shared:${mailboxScopeId}` : 'inbox:primary'),
		scope: { kind: 'mailbox', id: mailboxScopeId },
		lane: 'foreground',
		debounceMs: INBOX_DEBOUNCE_MS,

		async runDeltaStep(ctx: SyncStepContext): Promise<StepOutcome> {
			ctx.fence.assertCommitAllowed();
			const exec = { signal: ctx.signal, fence: ctx.fence };
			if (ctx.trigger === 'reconnect') {
				await store.resyncFromReconnect(exec);
				ctx.fence.assertCommitAllowed();
				return { kind: 'complete', recordsProcessed: 1 };
			}
			const changed = ctx.wakeup?.changed as PushChanges | undefined;
			if (
				ctx.wakeup?.dataTypes &&
				!ctx.wakeup.dataTypes.includes('Email') &&
				!ctx.wakeup.dataTypes.includes('Mailbox')
			) {
				return { kind: 'complete', recordsProcessed: 0 };
			}
			await store.handleSyncWakeup(changed, exec);
			ctx.fence.assertCommitAllowed();
			return { kind: 'complete', recordsProcessed: 1 };
		},

		purgeScopeCache(event: ScopeRevokedEvent): void {
			if (event.scopeKind !== 'mailbox') return;
			if (isShared || store.accountOverride === event.scopeId) {
				// Shared mailboxes are strictly online-only: evict memory + mark
				// accessRevoked = true, and NEVER invoke db.wipe('mail').
				store.revokeSharedMailbox(event.scopeId);
			}
		},
	};
}

export interface JmapRefreshAdapterOptions {
	consumerId: string;
	mailboxScopeId: string;
	dataTypes: readonly string[];
	debounceMs?: number;
	refresh: (signal: AbortSignal) => Promise<void> | void;
	onRevoke?: (event: ScopeRevokedEvent) => Promise<void> | void;
}

/**
 * SyncScopeAdapter for JMAP PIM surfaces (CalendarApp, ContactsApp, TasksApp,
 * RemindersWindow). Provides uniform wakeup filtering AND reconnect catch-up.
 */
export function createJmapRefreshAdapter(options: JmapRefreshAdapterOptions): SyncScopeAdapter {
	const typeSet = new Set(options.dataTypes);
	return {
		consumerId: options.consumerId,
		scope: { kind: 'mailbox', id: options.mailboxScopeId },
		lane: 'foreground',
		debounceMs: options.debounceMs ?? PIM_DEBOUNCE_MS,

		async runDeltaStep(ctx: SyncStepContext): Promise<StepOutcome> {
			ctx.fence.assertCommitAllowed();
			if (ctx.trigger === 'wakeup' && ctx.wakeup?.dataTypes && ctx.wakeup.dataTypes.length > 0) {
				const matches = ctx.wakeup.dataTypes.some((t) => typeSet.has(t));
				if (!matches) return { kind: 'complete', recordsProcessed: 0 };
			}
			await options.refresh(ctx.signal);
			ctx.fence.assertCommitAllowed();
			return { kind: 'complete', recordsProcessed: 1 };
		},

		async purgeScopeCache(event: ScopeRevokedEvent): Promise<void> {
			await options.onRevoke?.(event);
		},
	};
}
