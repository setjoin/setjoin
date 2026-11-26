// Chat online SyncScopeAdapter (Wave 2.8, #555).
//
// Coordinates per-channel replay (`sinceMessages`), reconnect catch-up,
// Wave 2.6 (#553) `resync` / `tombstoneFloorExceeded` non-additive snapshot
// replacement (server-authoritative ordering, zero TS re-sorting per ARCH-008),
// and `scope_revoked` eviction across all 7 ChatStore slices.

import * as chatApi from '$lib/chat/api';
import type { ChatStore } from '$lib/chat/store.svelte';
import type { ScopeRevokedEvent, StepOutcome, SyncScopeAdapter, SyncStepContext } from '../../core/types.js';

export interface ChatChannelSyncAdapterOptions {
	store: ChatStore;
	channelId: number;
	consumerId?: string;
	/** Injectable `sinceMessages` for unit tests. Defaults to `chatApi.sinceMessages`. */
	sinceMessages?: typeof chatApi.sinceMessages;
	/** Injectable `listMessages` for unit tests. Defaults to `chatApi.listMessages`. */
	listMessages?: typeof chatApi.listMessages;
	/** Refresh conversations after replay/resync (default true). */
	refreshConversations?: boolean;
}

export function createChatChannelSyncAdapter(options: ChatChannelSyncAdapterOptions): SyncScopeAdapter {
	const { store, channelId } = options;
	const sinceFn = options.sinceMessages ?? chatApi.sinceMessages;
	const listFn = options.listMessages ?? chatApi.listMessages;
	const refreshConversations = options.refreshConversations ?? true;

	return {
		consumerId: options.consumerId ?? `chat:channel:${channelId}`,
		scope: { kind: 'channel', id: String(channelId) },
		lane: 'foreground',
		debounceMs: 0,

		async runDeltaStep(ctx: SyncStepContext): Promise<StepOutcome> {
			ctx.fence.assertCommitAllowed();
			const since = store.getReplayCursor(channelId);
			let replay: chatApi.ChatReplay;
			try {
				replay = await sinceFn(channelId, since, ctx.signal);
			} catch (err) {
				const status = (err as { status?: unknown; code?: unknown } | null)?.status;
				const code = (err as { code?: unknown } | null)?.code;
				if (status === 403 || status === 404) {
					return { kind: 'scopeRevoked', detail: `chat_http_${String(status)}` };
				}
				if (status === 410 || code === 'tombstoneFloorExceeded' || code === 'resync') {
					return { kind: 'tombstoneFloorExceeded', detail: String(code ?? status) };
				}
				throw err;
			}
			// Write barrier: if scope_revoked or session reset landed during fetch,
			// abort synchronously before writing any message or advancing cursor.
			ctx.fence.assertCommitAllowed();
			if (replay.resync) {
				return { kind: 'tombstoneFloorExceeded', detail: 'chat_resync_sentinel' };
			}
			if (replay.messages.length > 0) {
				// Apply incremental messages without re-sorting; store handles upsert.
				const existing = store.messagesByChannel[channelId] ?? [];
				const byId = new Map(existing.map((m) => [m.messageId, m]));
				const merged = [...existing];
				for (const msg of replay.messages) {
					const prev = byId.get(msg.messageId);
					if (prev) {
						const idx = merged.findIndex((r) => r.messageId === msg.messageId);
						if (idx >= 0) merged[idx] = { ...prev, ...msg, status: 'sent' };
					} else {
						merged.push({ ...msg, status: 'sent' });
					}
				}
				store.replaceChannelSnapshot(channelId, merged, replay.cursor);
			} else if (replay.cursor > since) {
				store.replaceChannelSnapshot(channelId, store.messagesByChannel[channelId] ?? [], replay.cursor);
			}
			if (refreshConversations) {
				await store.loadConversations();
				ctx.fence.assertCommitAllowed();
			}
			return {
				kind: 'complete',
				recordsProcessed: replay.messages.length,
				appliedSeq: replay.cursor,
			};
		},

		async runFullResyncStep(ctx: SyncStepContext): Promise<StepOutcome> {
			return this.reconcileScopeMembership!(ctx);
		},

		async reconcileScopeMembership(ctx: SyncStepContext): Promise<StepOutcome> {
			ctx.fence.assertCommitAllowed();
			const page = await listFn(channelId, { limit: ctx.budget.maxRecords, signal: ctx.signal });
			ctx.fence.assertCommitAllowed();
			// Non-additive replacement preserving server-authoritative ordering
			// (listMessages is newest-first DESC → reverse once to ASC, zero TS sort).
			const asc = page.slice().reverse();
			store.replaceChannelSnapshot(channelId, asc);
			if (refreshConversations) {
				await store.loadConversations();
				ctx.fence.assertCommitAllowed();
			}
			const maxSeq = asc.reduce((m, row) => (row.seq > m ? row.seq : m), 0);
			return {
				kind: 'complete',
				recordsProcessed: asc.length,
				appliedSeq: maxSeq,
			};
		},

		purgeScopeCache(event: ScopeRevokedEvent): void {
			if (event.scopeKind !== 'channel' || event.scopeId !== String(channelId)) return;
			store.revokeChannelScope(channelId);
		},
	};
}
