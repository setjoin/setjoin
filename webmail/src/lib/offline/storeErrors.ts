/**
 * Typed capability refusals shared by the offline restore / staged-page
 * primitives, in a leaf module with no offline imports. The classes live
 * apart from `store-native` so `mailPagePersistence` and `stagedPage` can
 * reference them without importing `store-native` back (P2-1, Opus-5
 * second-voice r1: the store-native → mailPagePersistence edge stays
 * one-directional, and a future top-level use of either class can never hit
 * a TDZ `ReferenceError` under either evaluation order). `store-native`
 * re-exports both, so existing importers are untouched and the `instanceof`
 * identity stays single-sourced.
 */

/**
 * E4-I r12 Astra correction: thrown by `restoreFieldsIfUnchanged` when the
 * shell's native bridge lacks the atomic `transactionBatch` entry and a
 * multi-statement restore (column CASE-WHEN UPDATE, FTS recompute,
 * conditional tag swap) would otherwise replay statement-by-statement through
 * `exec`. A failure or a concurrent operation landing between those
 * individually awaited statements could expose a PARTIALLY restored row, so
 * the primitive refuses before issuing any statement — the caller's
 * best-effort rollback then leaves the row exactly as it was (leave-state-
 * alone), which is the safe direction. The message names the missing seam so
 * shell diagnostics point at the upgrade requirement.
 */
export class RestoreAtomicityUnavailableError extends Error {
	constructor(statementCount: number) {
		super(
			`restoreFieldsIfUnchanged refused a non-atomic restore: this shell's native bridge does not expose the atomic batch seam ` +
				`(db.transactionBatch; ${statementCount} statements would have replayed through exec); ` +
				`the native shell must project transactionBatch from the shared offline-core export before staged-page rollback can run`,
		);
		this.name = 'RestoreAtomicityUnavailableError';
	}
}

/**
 * E4-I r15 Astra correction: thrown by the staged page's `flushAllOrNothing`
 * BEFORE any page statement when the underlying store reports no atomic
 * rollback capability (`hasAtomicRestore() === false`, i.e. the shell's
 * bridge lacks the `transactionBatch` seam). A page applied ahead of an
 * uncommitted checkpoint on such a shell could not be undone if the
 * checkpoint half failed — the old apply-then-discover-no-undo sequence left
 * the page exposed under the old cursor with the undo swallowed. The
 * composed commit therefore fails UP FRONT: nothing is applied, the staged
 * page stays staged, and the typed error (a `RestoreAtomicityUnavailableError`
 * variant, so existing capability handling matches) names the missing seam.
 */
export class PageRollbackUnavailableError extends RestoreAtomicityUnavailableError {
	constructor(stagedOpCount: number) {
		super(stagedOpCount);
		this.name = 'PageRollbackUnavailableError';
		this.message =
			`staged page commit refused BEFORE any page statement: this shell's native bridge does not expose the atomic batch seam ` +
				`(db.transactionBatch), so a checkpoint failure could not roll the applied page back ` +
				`(${stagedOpCount} staged operations remain unapplied); ` +
				`the native shell must project transactionBatch from the shared offline-core export before staged pages can commit`;
	}
}
