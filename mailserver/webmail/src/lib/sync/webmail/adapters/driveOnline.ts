// Drive online listing SyncScopeAdapter (Wave 2.8, #555).
//
// Coordinates online Drive space delta wakeups, reconnect catch-up, HTTP 409 /
// `cannotCalculateChanges` full-listing resync, and `scope_revoked` eviction
// (clearing view state on full space revoke, or reloading server-authoritatively
// on `subtreeAnchorId` revocation per ARCH-020).

import type { ScopeRevokedEvent, StepOutcome, SyncScopeAdapter, SyncStepContext } from '../../core/types.js';

export interface DriveChangesResponse {
	cannotCalculateChanges?: boolean;
	changed?: unknown[];
	newState?: number | string | null;
}

export interface DriveOnlineSyncAdapterOptions {
	spaceId: number;
	consumerId?: string;
	getSinceSeq: () => number;
	setSinceSeq: (seq: number) => void;
	fetchChanges: (spaceId: number, sinceSeq: number, signal: AbortSignal) => Promise<DriveChangesResponse>;
	reloadListing: (signal?: AbortSignal) => Promise<void>;
	clearSpaceView: () => void;
}

export function createDriveOnlineSyncAdapter(options: DriveOnlineSyncAdapterOptions): SyncScopeAdapter {
	const { spaceId } = options;

	return {
		consumerId: options.consumerId ?? `drive-online:${spaceId}`,
		scope: { kind: 'space', id: String(spaceId) },
		lane: 'foreground',
		debounceMs: 0,

		async runDeltaStep(ctx: SyncStepContext): Promise<StepOutcome> {
			ctx.fence.assertCommitAllowed();
			const since = options.getSinceSeq();
			let res: DriveChangesResponse;
			try {
				res = await options.fetchChanges(spaceId, since, ctx.signal);
			} catch (err) {
				const status = (err as { status?: unknown } | null)?.status;
				if (status === 409) {
					return { kind: 'cannotCalculateChanges', detail: 'drive_http_409' };
				}
				if (status === 403 || status === 404) {
					return { kind: 'scopeRevoked', detail: `drive_http_${String(status)}` };
				}
				throw err;
			}
			ctx.fence.assertCommitAllowed();
			if (res.cannotCalculateChanges) {
				return { kind: 'cannotCalculateChanges', detail: 'drive_cannot_calculate_changes' };
			}
			if (res.changed && res.changed.length > 0) {
				if (typeof res.newState === 'number' && Number.isFinite(res.newState)) {
					options.setSinceSeq(res.newState);
				}
				await options.reloadListing(ctx.signal);
				ctx.fence.assertCommitAllowed();
				return { kind: 'complete', recordsProcessed: res.changed.length };
			}
			if (ctx.trigger === 'reconnect') {
				await options.reloadListing(ctx.signal);
				ctx.fence.assertCommitAllowed();
			}
			return { kind: 'complete', recordsProcessed: 0 };
		},

		async runFullResyncStep(ctx: SyncStepContext): Promise<StepOutcome> {
			ctx.fence.assertCommitAllowed();
			options.setSinceSeq(0);
			await options.reloadListing(ctx.signal);
			ctx.fence.assertCommitAllowed();
			return { kind: 'complete', recordsProcessed: 1 };
		},

		async purgeScopeCache(event: ScopeRevokedEvent): Promise<void> {
			if (event.scopeKind !== 'space' || event.scopeId !== String(spaceId)) return;
			if (event.subtreeAnchorId !== undefined) {
				// ARCH-020: subtree revocation reloads server-authoritative view.
				await options.reloadListing();
				return;
			}
			options.setSinceSeq(0);
			options.clearSpaceView();
		},
	};
}
