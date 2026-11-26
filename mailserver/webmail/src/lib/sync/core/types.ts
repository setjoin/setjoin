// Pure, framework-free TypeScript types for the shared SyncCoordinator
// (Wave 2.8, #555). Strictly ESM with `.js`-relative imports; zero Svelte,
// `$lib`, `$app`, DOM, or Node-only dependencies so both webmail Vite and
// Electron (`tsc --noEmit` + `esbuild`) import it directly.

import type { NativeDbAppKey } from '../../native/types.js';

export const SCOPE_KINDS = ['mailbox', 'space', 'channel'] as const;
export type ScopeKind = (typeof SCOPE_KINDS)[number];

export interface ScopeKey {
	readonly kind: ScopeKind;
	readonly id: string;
}

/** Canonical Map key for a `(kind, id)` scope pair. */
export function scopeKeyString(scope: ScopeKey): string {
	return `${scope.kind}:${scope.id}`;
}

export interface SyncWakeup {
	readonly scopeKind: ScopeKind;
	readonly scopeId: string;
	readonly seq: number;
	readonly dataTypes?: readonly string[];
	readonly changed?: Record<string, string>;
	readonly reason?: string;
}

export interface ScopeRevokedEvent {
	readonly scopeKind: ScopeKind;
	readonly scopeId: string;
	/** Optional Drive subtree anchor node id; when set, the space stays attached
	 *  and runs server-authoritative `fullVisibilityReconcile()` (ARCH-020). */
	readonly subtreeAnchorId?: string;
	readonly reason?: string;
}

export interface OfflineWipeEvent {
	readonly appKey?: NativeDbAppKey;
	readonly deviceId?: number;
	readonly reason?: string;
}

export const DEFAULT_SYNC_BUDGET_RECORDS = 64;
export const DEFAULT_SYNC_BUDGET_BYTES = 2 * 1024 * 1024; // 2 MiB
export const DEFAULT_SYNC_BUDGET_MS = 5_000;

export interface SyncBudget {
	readonly maxRecords: number;
	readonly maxBytes: number;
	readonly deadlineMonoMs: number;
}

export type StepOutcomeKind =
	| 'complete'
	| 'partial'
	| 'cannotCalculateChanges'
	| 'tombstoneFloorExceeded'
	| 'scopeRevoked'
	| 'capacityExceeded';

export interface StepOutcome {
	readonly kind: StepOutcomeKind;
	readonly recordsProcessed?: number;
	readonly bytesProcessed?: number;
	/** Optional cursor token after this step (used for zero-progress detection). */
	readonly cursor?: string | null;
	/** Highest confirmed sequence applied by this step (for monotonic skip). */
	readonly appliedSeq?: number;
	/** Optional structured diagnostic detail (e.g. quota/capacity reason). */
	readonly detail?: string;
}

/**
 * Synchronous write barrier passed to every adapter step. Adapters call
 * `assertCommitAllowed()` immediately before committing cached rows or
 * advancing a durable cursor so a late-settling post-`fetch()` promise can
 * NEVER write revoked data after a `scope_revoked`, `offline.wipe`, or
 * session teardown.
 */
export interface RevocationFence {
	readonly revocationEpoch: number;
	readonly sessionGeneration: number;
	isCommitAllowed(): boolean;
	assertCommitAllowed(): void;
}

/**
 * Execution lane determining preemption under `CriticalActivityCounter` (ARCH-023):
 * - `'foreground'`: interactive view loads; NEVER preempted by critical activity.
 * - `'background' | 'opportunistic' | 'offline-native'`: optional work preempted
 *   immediately whenever `criticalActivity > 0`.
 */
export type SyncLane = 'foreground' | 'background' | 'opportunistic' | 'offline-native';

export function isPreemptibleLane(lane: SyncLane): boolean {
	return lane !== 'foreground';
}

export type SyncTriggerKind = 'wakeup' | 'reconnect' | 'manual' | 'fullResync' | 'reconcile';

export interface SyncStepContext {
	readonly scope: ScopeKey;
	readonly signal: AbortSignal;
	readonly budget: SyncBudget;
	readonly fence: RevocationFence;
	readonly trigger: SyncTriggerKind;
	readonly wakeup?: SyncWakeup;
}

export interface ScopeSyncState {
	readonly consumerId: string;
	readonly scope: ScopeKey;
	readonly inFlight: boolean;
	readonly dirty: boolean;
	readonly reconnectPending: boolean;
	readonly storageFull: boolean;
	readonly storageFullDetail: string | null;
	readonly lastAppliedSeq: number;
	readonly revocationEpoch: number;
	readonly detached: boolean;
	readonly backoffAttempt: number;
	readonly deferredByCritical: boolean;
}

export interface SyncScopeAdapter {
	readonly consumerId: string;
	readonly scope: ScopeKey;
	/** Execution lane (default `'foreground'`). */
	readonly lane?: SyncLane;
	/** Coalescing debounce window in ms (default `0`). */
	readonly debounceMs?: number;
	/** Optional current cursor reader. Returning `null` routes the cycle to
	 *  `runFullResyncStep` when implemented. */
	getCursor?: () => string | null | Promise<string | null>;
	/** Bounded incremental delta step. */
	runDeltaStep(ctx: SyncStepContext): Promise<StepOutcome>;
	/** Bounded full-resync step (on `cannotCalculateChanges`, HTTP 409, Chat
	 *  `resync`, or `cursor === null`). */
	runFullResyncStep?(ctx: SyncStepContext): Promise<StepOutcome>;
	/** Non-additive membership reconciliation (on `tombstoneFloorExceeded` or
	 *  Drive `cursorExpired`) — MUST delete local items absent from server. */
	reconcileScopeMembership?(ctx: SyncStepContext): Promise<StepOutcome>;
	/** Security-lane cache purge on `scope_revoked`. Serialized through the
	 *  coordinator's per-scope purge mutex. */
	purgeScopeCache?(event: ScopeRevokedEvent): Promise<void> | void;
	/** Optional storage-full notification when a step reports `capacityExceeded`. */
	onCapacityExceeded?(detail?: string): void;
	/** Optional state observer. */
	onStateChange?(state: ScopeSyncState): void;
}

export interface WakeupTransport {
	onWakeup(handler: (wakeup: SyncWakeup) => void): () => void;
	onScopeRevoked(handler: (event: ScopeRevokedEvent) => void): () => void;
	onReconnect(handler: () => void): () => void;
	onOfflineWipe?(handler: (event: OfflineWipeEvent) => void): () => void;
	setAttachedScopes?(scopes: readonly ScopeKey[]): void;
	disconnect?(): void;
}

/**
 * Minimal structural interface matching `CriticalActivityCounter`
 * (`$lib/offline/criticalScope.ts`) without coupling pure `sync/core/` to
 * webmail offline modules.
 */
export interface CriticalActivityLike {
	count(): number;
	isActive(): boolean;
	subscribe(listener: (count: number) => void): () => void;
}
