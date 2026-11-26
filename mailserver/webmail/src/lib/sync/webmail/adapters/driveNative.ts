// Native Drive SyncScopeAdapters (Wave 2.8, #555):
// - P3 `VaultStore` adapter: single-space `scope_revoked` purges ALL
//   `dc_manifests` + unreferenced `dc_chunks` belonging to that space via
//   `dc_manifest_spaces` WITHOUT touching sibling spaces or calling `db.wipe('drive')`.
// - P2 `SyncEngine` + `FolderMirror` adapter:
//   * `ARCH-020`: `subtreeAnchorId` revocations ALWAYS run server-authoritative
//     `engine.reconcileVisibility()` (`fullVisibilityReconcile()`) before
//     advancing `aclEpoch` — local `dc_nodes` closure is never authoritative.
//   * `'busy'` pending-revocation retry queue: drains `dc_pending_revocations`
//     on every tick until every revoked file resolves to 'purged' | 'quarantined' | 'absent'.

import type { VaultStore } from '$lib/drive/sync/vaultstore';
import type { SyncEngine } from '$lib/drive/sync/engine';
import { DriveApiError } from '$lib/drive/sync/protocol';
import type { ScopeRevokedEvent, StepOutcome, SyncScopeAdapter, SyncStepContext } from '../../core/types.js';

export interface DriveVaultSyncAdapterOptions {
	spaceId: number;
	vaultStore: VaultStore;
	/** Optional server-authoritative visibility reconciler for subtree revocations (ARCH-020). */
	reconcileVisibility?: () => Promise<void>;
	/** Optional delta sync hook when a space wakeup arrives. */
	onWakeupSync?: (ctx: SyncStepContext) => Promise<StepOutcome>;
	consumerId?: string;
}

export function createDriveVaultSyncAdapter(options: DriveVaultSyncAdapterOptions): SyncScopeAdapter {
	const { spaceId, vaultStore } = options;

	return {
		consumerId: options.consumerId ?? `drive-vault:${spaceId}`,
		scope: { kind: 'space', id: String(spaceId) },
		lane: 'offline-native',
		debounceMs: 0,

		async runDeltaStep(ctx: SyncStepContext): Promise<StepOutcome> {
			ctx.fence.assertCommitAllowed();
			if (options.onWakeupSync) {
				const out = await options.onWakeupSync(ctx);
				ctx.fence.assertCommitAllowed();
				return out;
			}
			return { kind: 'complete', recordsProcessed: 0 };
		},

		async reconcileScopeMembership(ctx: SyncStepContext): Promise<StepOutcome> {
			ctx.fence.assertCommitAllowed();
			if (options.reconcileVisibility) {
				await options.reconcileVisibility();
				ctx.fence.assertCommitAllowed();
			}
			return { kind: 'complete', recordsProcessed: 1 };
		},

		async purgeScopeCache(event: ScopeRevokedEvent): Promise<void> {
			if (event.scopeKind !== 'space' || event.scopeId !== String(spaceId)) return;
			if (event.subtreeAnchorId !== undefined) {
				// Optional immediate local eviction of the anchor node, ALWAYS followed
				// by server-authoritative fullVisibilityReconcile() (ARCH-020).
				const anchorId = Number(event.subtreeAnchorId);
				if (Number.isSafeInteger(anchorId) && anchorId > 0) {
					await vaultStore.revoke(anchorId, false);
				}
				if (options.reconcileVisibility) {
					await options.reconcileVisibility();
				}
				return;
			}
			// Full single-space purge: removes ONLY this space's manifests +
			// unreferenced chunks; sibling spaces and 'mail' DB stay untouched.
			await vaultStore.purgeSpace(spaceId);
		},
	};
}

export interface DriveMirrorSyncAdapterOptions {
	spaceId: number;
	engine: SyncEngine;
	consumerId?: string;
	/** Retry interval (ms) for draining `'busy'` revocations even after scope detach (default 5_000ms). */
	busyRetryMs?: number;
	/** Optional local immediate anchor eviction before server-authoritative reconcile. */
	evictLocalAnchor?: (anchorNodeId: number) => Promise<void>;
	/** Optional hook called when `purgeSpaceLocal` leaves `'busy'` files pending retry. */
	onPendingBusyRevocations?: (remaining: number) => void;
}

export function createDriveMirrorSyncAdapter(options: DriveMirrorSyncAdapterOptions): SyncScopeAdapter {
	const { spaceId, engine } = options;
	const busyRetryMs = options.busyRetryMs ?? 5_000;
	let busyRetryTimer: ReturnType<typeof setTimeout> | null = null;

	const scheduleBusyDrain = (): void => {
		if (busyRetryTimer !== null) return;
		busyRetryTimer = setTimeout(() => {
			busyRetryTimer = null;
			void engine
				.drainPendingRevocations()
				.then((drained) => {
					if (drained.remaining > 0) {
						options.onPendingBusyRevocations?.(drained.remaining);
						scheduleBusyDrain();
					}
				})
				.catch(() => {
					scheduleBusyDrain();
				});
		}, busyRetryMs);
	};

	return {
		consumerId: options.consumerId ?? `drive-mirror:${spaceId}`,
		scope: { kind: 'space', id: String(spaceId) },
		lane: 'offline-native',
		debounceMs: 0,

		async runDeltaStep(ctx: SyncStepContext): Promise<StepOutcome> {
			ctx.fence.assertCommitAllowed();
			try {
				const res = await engine.syncOnce({ signal: ctx.signal, fence: ctx.fence });
				ctx.fence.assertCommitAllowed();
				return { kind: 'complete', recordsProcessed: res.uploaded + res.downloaded };
			} catch (err) {
				if (err instanceof DriveApiError && err.status === 409) {
					return { kind: 'cannotCalculateChanges', detail: 'drive_mirror_http_409' };
				}
				throw err;
			}
		},

		async runFullResyncStep(ctx: SyncStepContext): Promise<StepOutcome> {
			ctx.fence.assertCommitAllowed();
			const res = await engine.reconcileVisibility({ signal: ctx.signal, fence: ctx.fence });
			ctx.fence.assertCommitAllowed();
			return { kind: 'complete', recordsProcessed: res.downloaded };
		},

		async reconcileScopeMembership(ctx: SyncStepContext): Promise<StepOutcome> {
			ctx.fence.assertCommitAllowed();
			const res = await engine.reconcileVisibility({ signal: ctx.signal, fence: ctx.fence });
			ctx.fence.assertCommitAllowed();
			return { kind: 'complete', recordsProcessed: res.downloaded };
		},

		async purgeScopeCache(event: ScopeRevokedEvent): Promise<void> {
			if (event.scopeKind !== 'space' || event.scopeId !== String(spaceId)) return;
			if (event.subtreeAnchorId !== undefined) {
				const anchorId = Number(event.subtreeAnchorId);
				if (options.evictLocalAnchor && Number.isSafeInteger(anchorId) && anchorId > 0) {
					await options.evictLocalAnchor(anchorId);
				}
				// ARCH-020: server-authoritative fullVisibilityReconcile() before advancing aclEpoch.
				await engine.reconcileVisibility();
				return;
			}
			const result = await engine.purgeSpaceLocal();
			if (result.busy > 0) {
				options.onPendingBusyRevocations?.(result.busy);
				// Scope is detached on full-space revoke; keep draining pending
				// busy revocations on a bounded timer until every handle closes (#555 4d).
				scheduleBusyDrain();
			}
		},
	};
}
