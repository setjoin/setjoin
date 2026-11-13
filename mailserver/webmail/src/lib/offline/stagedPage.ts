/**
 * E4-I Astra correction (finding: "Page/checkpoint writes are not atomic"):
 * a write-staging wrapper around the `OfflineStore` used by the coordinator's
 * bounded steps.
 *
 * A step's page writes (merge/upsert/delete) are STAGED instead of applied
 * immediately; the coordinator then commits the staged page and the durable
 * checkpoint as ONE unit through `JobPersistence.commitCheckpoint(..., {
 * compose })`. The flush is all-or-nothing: every applied operation first
 * captures the prior row so a failure rolls the page back completely — a
 * crash/failure between the page and the checkpoint exposes NEITHER, and a
 * successful commit exposes both. This honors the TS integration contract
 * independently of the deferred SQLCipher-side transactional page commit.
 *
 * E4-I r6 Astra correction: the rollback is MERGE-based. The underlying
 * store's `upsertMessage` is a whole-row replace, so restoring the pre-page
 * row wholesale clobbered a concurrent local edit that landed on the same row
 * between the page's apply and its rollback (local edits pass through to the
 * underlying store by design). The rollback instead restores only the fields
 * the staged page touched, and only while they still hold their staged
 * value — the current row is read at rollback time and anything a concurrent
 * edit rewrote survives.
 *
 * E4-I r9 Astra correction: a staged field is additionally skipped when the
 * CURRENT row lists it in `dirtyFields` (the row's dirty generation).
 * Comparison-by-value cannot distinguish an untouched field from one a
 * concurrent local edit rewrote to the SAME value, so the dirty generation —
 * not the value alone — is the ownership record: a field claimed by a local
 * edit always survives the rollback, while an untouched row (same values, no
 * dirty claims, watermark still at the staged post-image) rolls back fully.
 *
 * E4-I r11 Astra correction: the rollback no longer READS the row and then
 * WRITES a merged whole row through `upsertMessage` — a local optimistic edit
 * committing between that snapshot and the write was still clobbered by the
 * whole-row replace. The restore instead runs through the store seam's
 * ATOMIC per-field conditional primitive (`restoreFieldsIfUnchanged`): the
 * per-field expected-value comparison now executes INSIDE one synchronous
 * store operation together with the write, so the interleaving window no
 * longer exists. The r6/r9 semantics are preserved by the primitive (a field
 * still holding its staged value is restored; a rewritten field — any value,
 * or the same value under a dirty claim — is skipped), while the caller keeps
 * the r9 dirty-generation filter over its snapshot and the structural guards
 * (vacant-slot deletion restore, vanished row, page-created row).
 *
 * E4-I r15 Astra correction: the rollback capability is required BEFORE the
 * page is written, not discovered missing afterwards. `flushAllOrNothing`
 * refuses a non-empty page up front with `PageRollbackUnavailableError` when
 * the underlying store cannot restore atomically (`hasAtomicRestore()`,
 * false on native shells without the `transactionBatch` seam) — the old
 * apply-then-discover-no-undo sequence left the applied page exposed under
 * the old cursor when the checkpoint half failed, and `undoApplied`'s
 * swallow-then-clear destroyed the only evidence. On such a shell the
 * composed commit now fails before ANY page statement; nothing is applied,
 * and a refused undo propagates with the undo log retained. The memory store
 * and batch-capable native stores are unchanged.
 *
 * Reads consult the staged overlay so intra-page semantics (F2 barrier set,
 * F4 watermarks, merge-delta results) stay honest without exposing the page
 * to the durable store early.
 */

import type { OfflineStore, StoredMessage } from './store';
import { PageRollbackUnavailableError, RestoreAtomicityUnavailableError } from './storeErrors';

export type StagedOp =
	| { kind: 'merge-delta'; id: string; changed: Partial<StoredMessage>; serverVersion: number; postImage: StoredMessage }
	| { kind: 'upsert'; message: StoredMessage; postImage: StoredMessage }
	| { kind: 'delete'; id: string; postImage: null; expectedVersion?: number | null };

/** Undo entry of one APPLIED operation (r6 merge-based rollback). */
interface AppliedUndoEntry {
	id: string;
	/** The row as it was BEFORE the operation applied (null when absent). */
	prior: StoredMessage | null;
	/** The applied operation; its `postImage` is the intact-staged-value
	 * reference the rollback compares against. */
	op: StagedOp;
}

export interface StagedOfflineStore extends OfflineStore {
	readonly stagedOperations: readonly StagedOp[];
	/** Number of staged operations awaiting the composed commit. */
	readonly stagedCount: number;
	/**
	 * Apply every staged operation to the real store all-or-nothing: on the
	 * first failure the already-applied prefix is rolled back in reverse and
	 * the error rethrown, leaving neither the page nor (via the composed
	 * commit) the checkpoint visible. Naturally idempotent: a flushed (or
	 * discarded) store stages nothing, so a repeated flush is a no-op.
	 *
	 * E4-I Astra correction: the undo log of a SUCCESSFUL flush is retained
	 * until the composed commit settles — `rollbackAppliedPage()` undoes an
	 * applied page when the checkpoint half of the composition fails, so the
	 * page can never stay visible under the old cursor.
	 *
	 * E4-I r15 Astra correction: a non-empty page REFUSES with the typed
	 * `PageRollbackUnavailableError` before any statement when the underlying
	 * store reports no atomic rollback capability — a page that could not be
	 * undone after a failed checkpoint half is never applied at all.
	 */
	flushAllOrNothing(): Promise<void>;
	/**
	 * Undo a page already applied by a successful `flushAllOrNothing` (the
	 * checkpoint half of its composition failed). Idempotent: with no retained
	 * undo log — nothing flushed, already rolled back, or discarded — this is
	 * a no-op.
	 *
	 * E4-I r15 Astra correction: a restore the store refuses for missing
	 * atomic capability is never swallowed — the error propagates and the
	 * undo log is retained for a later attempt, so the caller can never
	 * mistake a refused rollback for a completed one.
	 */
	rollbackAppliedPage(): Promise<void>;
	/** Drop the staged page without applying it (stale writer / aborted). */
	discard(): void;
}

function clone(message: StoredMessage): StoredMessage {
	return { ...message, flags: [...message.flags], tagIds: [...message.tagIds], dirtyFields: [...(message.dirtyFields ?? [])] };
}

/** The columns a merge-delta op writes (mergeServerDelta never touches the
 * dirty-field/tag bookkeeping; `version` IS the applied watermark). */
function mergeOwnedKeys(changed: Partial<StoredMessage>): string[] {
	return Object.keys(changed)
		.filter((key) => key !== 'version' && key !== 'dirtyFields' && key !== 'tagIds')
		.concat('version');
}

/** Value equality that treats equal-content arrays as equal (the store clones
 * flag/tag arrays, so identity comparison would always differ). Shared with
 * the in-memory store's `restoreFieldsIfUnchanged` so both layers compare a
 * field's current value to its staged expectation identically. */
export function fieldValueEqual(a: unknown, b: unknown): boolean {
	if (Array.isArray(a) && Array.isArray(b)) {
		return a.length === b.length && a.every((value, index) => value === b[index]);
	}
	return a === b;
}

export function createStagedStore(underlying: OfflineStore, admit?: (operations: readonly StagedOp[]) => void): StagedOfflineStore {
	const ops: StagedOp[] = [];
	// Undo log of APPLIED operations: retained after a successful flush until
	// the composed commit settles, so a failed checkpoint half can roll the
	// applied page back (E4-I Astra correction).
	let appliedUndo: Array<AppliedUndoEntry> = [];
	// Overlay of staged effects for honest reads/write-result computation.
	const overlay = new Map<string, StoredMessage | null>();

	async function effective(id: string): Promise<StoredMessage | null> {
		if (overlay.has(id)) return overlay.get(id) ? clone(overlay.get(id)!) : null;
		return underlying.getMessage(id);
	}

	/**
	 * Restore ONE applied operation (r6 Astra correction: merge-based
	 * rollback). The native `upsertMessage` is a whole-row replace, so
	 * restoring the pre-page row wholesale clobbered any concurrent local
	 * edit that landed on the row between the page's apply and its rollback.
	 * The rollback therefore restores only the fields the operation staged.
	 *
	 * r9 Astra correction: a field the CURRENT row claims through its dirty
	 * generation is never restored, even when it still holds the staged
	 * value — a concurrent local rewrite to the SAME value is
	 * indistinguishable from "untouched" by value comparison alone, so the
	 * row's dirty generation is the ownership record for that ABA case. The
	 * filter over the snapshot's dirty claims stays HERE, at the caller.
	 *
	 * r11 Astra correction: the restore is no longer a read-then-whole-row-
	 * write. The per-field expectations (staged post-image) and the prior
	 * values are handed to the store seam's ATOMIC conditional primitive —
	 * `restoreFieldsIfUnchanged` re-compares every field's CURRENT value
	 * against the post-image INSIDE the same synchronous store operation that
	 * writes, so a concurrent edit committing after the snapshot read above
	 * fails its predicate at write time and survives. The caller no longer
	 * compares values itself: the rollback's comparison lives behind the
	 * store boundary, shared with the in-memory store through the exported
	 * `fieldValueEqual`.
	 */
	async function restoreRow(entry: AppliedUndoEntry): Promise<void> {
		const current = await underlying.getMessage(entry.id);
		if (entry.op.postImage === null) {
			// Deletion: a concurrently (re)created row is no longer ours to
			// remove — restore the prior row only into a still-vacant slot.
			if (!current && entry.prior) await underlying.upsertMessage(entry.prior);
			return;
		}
		if (!current) {
			// The row vanished after the page applied: nothing concurrent
			// remains to preserve, so the prior row is restored wholesale.
			if (entry.prior) await underlying.upsertMessage(entry.prior);
			return;
		}
		if (!entry.prior) {
			// The page created this row and a concurrent writer now edits it:
			// deleting it would destroy that edit, so the created row stays
			// (replay re-applies the page idempotently under the uncommitted
			// checkpoint).
			return;
		}
		const owned = entry.op.kind === 'merge-delta'
			? mergeOwnedKeys(entry.op.changed)
			: Object.keys(entry.op.postImage);
		const postImage = entry.op.postImage as unknown as Record<string, unknown>;
		const prior = entry.prior as unknown as Record<string, unknown>;
		// E4-I r9 Astra correction: fields the SNAPSHOT claims through its
		// dirty generation are a concurrent local edit's property — a same-
		// value rewrite would pass the post-image comparison, so the dirty
		// claim, not the value, decides ownership for them. (A row-level
		// watermark gate alone cannot express this: the r6 contract keeps
		// rolling a staged field back when a concurrent edit bumped the
		// watermark but touched only OTHER fields.) The primitive re-applies
		// this guard against the row's CURRENT dirty generation at write time.
		const dirty = new Set(current.dirtyFields ?? []);
		const expectedState: Record<string, unknown> = {};
		const fieldRestore: Record<string, unknown> = {};
		for (const key of owned) {
			if (key === 'id' || dirty.has(key)) continue;
			if (postImage[key] === undefined || prior[key] === undefined) continue;
			expectedState[key] = postImage[key];
			fieldRestore[key] = prior[key];
		}
		await underlying.restoreFieldsIfUnchanged(entry.id, expectedState, fieldRestore);
	}

	async function undoApplied(): Promise<void> {
		for (const entry of appliedUndo) {
			try {
				await restoreRow(entry);
			} catch (error) {
				// E4-I r15 Astra correction: a restore the store REFUSED for
				// missing atomic capability (RestoreAtomicityUnavailableError)
				// is never swallowed into a fake "rolled back". Swallowing it
				// used to clear the undo log too, destroying the only record
				// that an applied page was left un-rollbackable. The refusal
				// propagates to the caller and the undo log is retained, so a
				// later attempt (e.g. on a store whose batch seam returned)
				// can still undo the page. Other failures stay best-effort.
				if (error instanceof RestoreAtomicityUnavailableError) throw error;
				// Best-effort rollback: surface the original failure.
			}
		}
		appliedUndo = [];
		ops.length = 0;
		overlay.clear();
	}

	const staged: StagedOfflineStore = {
		async init() {
			await underlying.init();
		},
		isOpen: () => underlying.isOpen(),
		async upsertMessage(m) {
			admit?.([...ops, { kind: 'upsert', message: clone(m), postImage: clone(m) }]);
			ops.push({ kind: 'upsert', message: clone(m), postImage: clone(m) });
			overlay.set(m.id, clone(m));
		},
		async getMessage(id) {
			return effective(id);
		},
		async listByReceivedDesc(limit, offset = 0) {
			const base = await underlying.listByReceivedDesc(limit + overlay.size, offset);
			const merged = new Map<string, StoredMessage>();
			for (const row of base) merged.set(row.id, row);
			for (const [id, row] of overlay) {
				if (row === null) merged.delete(id);
				else merged.set(id, clone(row));
			}
			return [...merged.values()]
				.sort((a, b) => b.receivedAt - a.receivedAt)
				.slice(offset, offset + limit);
		},
		async deleteOutOfWindow(cutoffMs) {
			// Never staged: retention is not part of a step page.
			return underlying.deleteOutOfWindow(cutoffMs);
		},
		async deleteMessage(id) {
			const expectedVersion = admit ? (await effective(id))?.version ?? null : undefined;
			admit?.([...ops, { kind: 'delete', id, postImage: null, expectedVersion }]);
			ops.push({ kind: 'delete', id, postImage: null, expectedVersion });
			overlay.set(id, null);
		},
		async mergeServerDelta(id, changed, serverVersion) {
			const existing = await effective(id);
			if (!existing) return 'absent';
			if (serverVersion < (existing.version ?? 0)) return 'skipped';
			const dirty = new Set(existing.dirtyFields ?? []);
			const next: StoredMessage = clone(existing);
			for (const key of Object.keys(changed) as (keyof StoredMessage)[]) {
				if (key === 'version' || key === 'dirtyFields' || key === 'tagIds') continue;
				if (dirty.has(key as string)) continue; // F1: an un-acked local edit wins
				(next as unknown as Record<string, unknown>)[key] = changed[key];
			}
			next.version = serverVersion;
			admit?.([...ops, { kind: 'merge-delta', id, changed: { ...changed }, serverVersion, postImage: clone(next) }]);
			ops.push({ kind: 'merge-delta', id, changed: { ...changed }, serverVersion, postImage: clone(next) });
			overlay.set(id, next);
			return 'merged';
		},
		async getVersion(id) {
			const row = await effective(id);
			return row?.version ?? 0;
		},
		// r11: the atomic per-field conditional restore passes straight through
		// to the underlying store — the rollback deliberately writes BEHIND the
		// staged overlay (it is undoing an already-applied page).
		async restoreFieldsIfUnchanged(id, expectedState, fieldRestore) {
			return underlying.restoreFieldsIfUnchanged(id, expectedState, fieldRestore);
		},
		// r15: the staged page inherits the underlying store's rollback
		// capability verbatim — the gate in flushAllOrNothing and
		// rollbackAppliedPage's undo both run against THIS store.
		hasAtomicRestore: () => underlying.hasAtomicRestore(),
		async bumpLocalVersion(id, fields) {
			return underlying.bumpLocalVersion(id, fields);
		},
		async clearDirty(id) {
			return underlying.clearDirty(id);
		},
		async enqueueOptimisticEdit(id, patch, action) {
			return underlying.enqueueOptimisticEdit(id, patch, action);
		},
		async pendingMessageIds() {
			return underlying.pendingMessageIds();
		},
		async listPendingOps() {
			return underlying.listPendingOps();
		},
		async ackOp(id) {
			return underlying.ackOp(id);
		},
		async failOp(id, error) {
			return underlying.failOp(id, error);
		},
		async searchBody(query, limit) {
			return underlying.searchBody(query, limit);
		},
		async getMeta(key) {
			return underlying.getMeta(key);
		},
		async setMeta(key, value) {
			return underlying.setMeta(key, value);
		},
		async recordSyncIssue(i) {
			return underlying.recordSyncIssue(i);
		},
		async listSyncIssues() {
			return underlying.listSyncIssues();
		},
		async clearSyncIssue(id) {
			return underlying.clearSyncIssue(id);
		},
		async wipe() {
			await underlying.wipe();
		},
		get stagedCount() {
			return ops.length;
		},
		get stagedOperations() { return ops; },
		async flushAllOrNothing(): Promise<void> {
			if (ops.length === 0) return;
			// E4-I r15 Astra correction: rollback capability is verified BEFORE
			// any page statement. The composed page/checkpoint commit is
			// all-or-nothing only while a failed checkpoint half can undo the
			// applied page; on a store without the atomic restore capability
			// (a native shell lacking the `transactionBatch` seam) applying
			// first and discovering "no undo" on checkpoint failure left the
			// page exposed under the old cursor. A non-empty page therefore
			// FAILS CLOSED up front with the typed error — nothing is written,
			// the staged page stays staged (discardable by the caller), and
			// neither the page nor the checkpoint is ever partially exposed.
			// The memory store and batch-capable native stores are unchanged:
			// their capability is true and this gate never fires.
			if (!underlying.hasAtomicRestore()) {
				throw new PageRollbackUnavailableError(ops.length);
			}
			const undo: Array<AppliedUndoEntry> = [];
			try {
				for (const op of ops) {
					const id = op.kind === 'upsert' ? op.message.id : op.id;
					const prior = await underlying.getMessage(id);
					// E4-I r5 Astra correction: the undo is registered BEFORE the
					// operation runs, never after it. A merge can mutate the row and
					// THEN fail inside the same awaited call (the native path updates
					// the message before its FTS work, which can fail) — an undo
					// registered after the await would miss exactly that failure and
					// leave the partially applied mutation exposed.
					undo.unshift({ id, prior, op });
					if (op.kind === 'merge-delta') {
						await underlying.mergeServerDelta(op.id, op.changed, op.serverVersion);
					} else if (op.kind === 'upsert') {
						await underlying.upsertMessage(op.message);
					} else {
						await underlying.deleteMessage(op.id);
					}
				}
				ops.length = 0;
				overlay.clear();
				// The flush succeeded, but the composed commit has not settled:
				// retain the undo log until the checkpoint half commits or the
				// page is rolled back / discarded.
				appliedUndo = undo;
			} catch (error) {
				// Roll the applied prefix back in reverse; the composed commit then
				// writes no checkpoint, so neither page nor checkpoint is exposed.
				appliedUndo = undo;
				await undoApplied();
				throw error;
			}
		},
		async rollbackAppliedPage(): Promise<void> {
			if (appliedUndo.length === 0) return;
			await undoApplied();
		},
		discard(): void {
			ops.length = 0;
			overlay.clear();
			appliedUndo = [];
		},
	};
	return staged;
}
