import type { OfflineDbBridge } from '$lib/native/types';
import { makeNativeStore } from './store-native';
import type { CommitMailPage } from './mailPagePersistence';
import type { SyncCheckpoint } from './work-contract';

/** The appKey this store namespaces to. Drive/Calendar/Contacts get their own. */
export const MAIL_APP_KEY = 'mail';

export interface StoredMessage {
	id: string;
	threadId: string;
	receivedAt: number;
	flags: string[];
	hasAttachment: boolean;
	cacheState: 'meta' | 'full';
	syncedAt: number;
	from: string;
	to: string;
	cc: string;
	bcc: string;
	subject: string;
	preview: string;
	tagIds: string[];
	version?: number;       // F4 per-message LWW watermark (defaults 0 on write)
	dirtyFields?: string[]; // F1/F2 columns carrying an un-acked optimistic edit (defaults [])
}

export interface SyncIssue {
	id?: number;
	kind: 'stale' | 'rejected';
	actionType: string;
	payload: unknown;
	error: string;
	at?: number;
}

export interface OfflineStore {
	/** Native mail-owned page/checkpoint composition; absent on the memory adapter. */
	commitMailPage?: CommitMailPage;
	/** Staged step admission reserves the longest resumable checkpoint before writes. */
	reservePageCheckpoint?(checkpoint: SyncCheckpoint): void;
	init(): Promise<void>;
	isOpen(): Promise<boolean>;
	upsertMessage(m: StoredMessage): Promise<void>;
	getMessage(id: string): Promise<StoredMessage | null>;
	listByReceivedDesc(limit: number, offset?: number): Promise<StoredMessage[]>;
	deleteOutOfWindow(cutoffMs: number): Promise<number>;
	/** Single-id evict (messages+tags+bodies+fts) — #3 delta destroyed-ids. */
	deleteMessage(id: string): Promise<void>;
	// F1 + F4: column-level LWW merge of an inbound server delta. Updates ONLY the
	// fields in `changed`, never a whole-record overwrite; applies ONLY if
	// serverVersion >= the row's watermark AND only for columns NOT in dirtyFields
	// (an un-acked local edit wins until its op acks → F2/F1).
	mergeServerDelta(
		id: string,
		changed: Partial<StoredMessage>,
		serverVersion: number
	): Promise<'merged' | 'skipped' | 'absent'>;
	/**
	 * E4-I r11 Astra correction: atomic per-field conditional restore — the
	 * ONLY write path the staged-page rollback uses. For every key K of
	 * `fieldRestore`, the CURRENT value of K is compared to `expectedState[K]`
	 * and `fieldRestore[K]` is written ONLY when they are equal, inside ONE
	 * synchronous store operation (in-memory: a single locked compare-and-
	 * restore mutation with no intervening await; native: one UPDATE whose
	 * every SET is a CASE-WHEN-current-equals-expected predicate, plus the
	 * conditional tag-set restore in the SAME transaction when tags are
	 * restored). A field a concurrent local edit rewrote after the caller's
	 * snapshot — to any other value, or to the same value under a dirty claim
	 * — therefore fails its predicate at write time and survives; a field
	 * still holding its staged value is restored. Returns false when the row
	 * does not exist (nothing written). `id` in `fieldRestore` is ignored; a
	 * field the row's current `dirtyFields` claims is never restored.
	 * E4-I r12: the native implementation fails closed — a typed
	 * `RestoreAtomicityUnavailableError` with nothing written — when the
	 * shell's bridge lacks the atomic `transactionBatch` seam and a
	 * multi-statement restore is required; a no-op restore still succeeds.
	 */
	restoreFieldsIfUnchanged(
		id: string,
		expectedState: Partial<StoredMessage>,
		fieldRestore: Partial<StoredMessage>
	): Promise<boolean>;
	/**
	 * E4-I r15 Astra correction: whether `restoreFieldsIfUnchanged` executes
	 * ATOMICALLY on this store — the staged-page rollback capability. The
	 * in-memory store is always true (the compare-and-restore is one
	 * synchronous mutation); the native store is true only while the shell's
	 * bridge exposes the atomic `transactionBatch` seam. `flushAllOrNothing`
	 * consults this BEFORE applying any page statement: a page that could not
	 * be rolled back after a failed checkpoint half must never be applied
	 * (never apply-then-discover-no-undo) — a store reporting false makes the
	 * composed page/checkpoint commit fail up front with the typed
	 * `PageRollbackUnavailableError`, nothing written.
	 */
	hasAtomicRestore(): boolean;
	getVersion(id: string): Promise<number>;                                      // F4
	bumpLocalVersion(id: string, fields: (keyof StoredMessage)[]): Promise<number>; // F4/F1
	clearDirty(id: string): Promise<void>; // F1: op acked → lift the per-field barrier
	// F5 transactional outbox (native): apply the optimistic per-field cache edit
	// AND enqueue its replayable op in ONE SQLCipher transaction.
	enqueueOptimisticEdit(
		id: string,
		patch: Partial<StoredMessage>,
		action: { type: string; payload: unknown }
	): Promise<void>;
	/** F2: message ids with an un-acked op in the outbound action_queue. The sync
	 *  engine holds deltas for these so optimistic edits aren't clobbered by an
	 *  in-flight server response (Task 13/F2 seam). */
	pendingMessageIds(): Promise<Set<string>>;
	/** Replay: all pending ops in FIFO order (full action objects for the replay loop). */
	listPendingOps(): Promise<Array<{ id: number; type: string; payload: Record<string, unknown> }>>;
	/** Replay: remove an acknowledged op (DELETE from action_queue). */
	ackOp(id: number): Promise<void>;
	/** Replay: increment attempts; drops to 'failed' after 3 (mirrors IndexedDB retry logic). */
	failOp(id: number, error: string): Promise<void>;
	searchBody(query: string, limit?: number): Promise<string[]>;
	getMeta(key: string): Promise<string | null>;
	setMeta(key: string, value: string): Promise<void>;
	recordSyncIssue(i: Omit<SyncIssue, 'id' | 'at'>): Promise<void>;
	listSyncIssues(): Promise<SyncIssue[]>;
	clearSyncIssue(id: number): Promise<void>;
	wipe(): Promise<void>;
}

function nativeDb(): OfflineDbBridge | null {
	if (typeof window === 'undefined') return null;
	return window.setjoinNative?.db ?? null;
}

/** True only in a native shell that injected the db bridge. Browser => false. */
export function isOfflineAvailable(): boolean {
	return nativeDb() !== null;
}

// ponytail: module-level singleton — one store per page lifetime (the appKey is fixed).
// Reset path: wipe() + page reload (logout); vi.resetModules() resets it in tests.
let cached: OfflineStore | null = null;

/** The active store, or null on a plain browser (offline disabled). */
export function getStore(): OfflineStore | null {
	if (!isOfflineAvailable()) return null;
	if (!cached) cached = makeNativeStore(nativeDb()!);
	return cached;
}
