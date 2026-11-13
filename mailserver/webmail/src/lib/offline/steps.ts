/**
 * E4-I bounded sync steps: the frozen E0 step contract
 * (`SyncStepOptions`/`SyncStepResult` in `work-contract.ts`) made executable.
 *
 * One step accepts an AbortSignal, an injected resource budget and the prior
 * durable checkpoint, performs at most one query/changes page of at most 64
 * metadata records (or stops at the remaining byte/time quantum), returns a
 * versioned checkpoint, and never advances the server state cursor before its
 * local page has committed. The scheduler/coordinator calls ONLY these
 * branded steps — the unbounded `syncDelta`/`syncWindow` wrappers remain
 * compatibility surfaces and are refused as scheduled work
 * (`isBoundedSyncStep`).
 *
 * E4-I Astra corrections:
 * - The byte budget is a hard per-call ceiling: a record whose metadata would
 *   exceed the remaining budget is never applied (a one-byte budget accepts
 *   nothing), and the fetches stop once the budget is exhausted — an
 *   exhausted allowance issues NO network call at all (r6 correction: the
 *   Email/changes and Email/query round-trips used to precede the zero-budget
 *   check, spinning repeated fetches after the byte allowance was spent; r9
 *   correction: the initial Email/get re-anchor is such a round-trip too and
 *   now runs AFTER the abort/deadline/zero-byte guards, so an aborted,
 *   expired, or exhausted dispatch — even one with no committed anchor —
 *   issues no network call at all).
 * - Every result reports its APPLIED byte charge (`progress.appliedBytes`) so
 *   the coordinator can deduct each call's consumption from its dispatch's
 *   ONE byte budget — a partial step never re-spends the full allowance.
 * - Cancellation crosses the client boundary: every JMAP request receives the
 *   step's AbortSignal, and a signal aborted during `Email/changes` prevents
 *   the follow-up `Email/get` from launching at all.
 * - The default intra-page clock is the monotonic `performance.now()` —
 *   never `Date.now()`, which sits on a different origin than the injected
 *   monotonic deadlines and produced immediate no-progress steps.
 * - A server `cannotCalculateChanges` answer maps to the `blocked` outcome so
 *   the coordinator's bounded window resync can replace the unanchored delta
 *   walk; it is never allowed to surface as a terminal failure.
 *
 * JMAP application logic is reused from `sync.ts` (F1/F2/F4 seam), never
 * duplicated.
 */

import {
	MAX_RECORDS_PER_STEP,
	YIELD_MAX_BYTES,
	type SyncCheckpoint,
	type SyncStep,
	type SyncStepResult,
} from './work-contract';
import { applyRecord, METADATA_PROPS, pendingMessageIds, serverVersion, toStored } from './sync';
import type { Email } from '$lib/types/jmap';
import type { OfflineStore } from './store';
import { MailPageCapacityError } from './mailPagePersistence';

/** Cancellation carrier passed into every JMAP request. */
export interface StepCancellation {
	signal: AbortSignal;
}

/** JMAP Email/changes surface consumed by the delta step (matches sync.ts). */
export type DeltaChangesClient = {
	emailChanges(args: { sinceState: string; maxChanges: number }, cancellation?: StepCancellation): Promise<{
		newState: string;
		hasMoreChanges: boolean;
		created: string[];
		updated: string[];
		destroyed: string[];
	}>;
	emailGet(args: { ids: string[]; properties: string[] }, cancellation?: StepCancellation): Promise<{ list: Email[]; state: string }>;
};

/**
 * JMAP Email/query surface consumed by the window step. Position-based
 * pagination over the existing client (sort receivedAt desc); a mid-walk
 * server change can only re-apply rows (F1/F4 idempotent), never corrupt.
 */
export type WindowQueryClient = {
	emailQuery(
		filter: Record<string, unknown>,
		sort: ReadonlyArray<{ property: string; isAscending: boolean }>,
		limit: number,
		position?: number,
		cancellation?: StepCancellation,
	): Promise<{ ids: string[]; total?: number }>;
	emailGet(args: { ids: string[]; properties: string[] }, cancellation?: StepCancellation): Promise<{ list: Email[]; state: string }>;
};

const BOUNDED_STEPS = new WeakSet<SyncStep>();

/**
 * Brand a step so the coordinator can refuse unbounded wrappers at
 * registration time. Only `createSyncDeltaStep`/`createSyncWindowStep`
 * products may be scheduled.
 */
export function markBoundedSyncStep<T extends SyncStep>(step: T): T {
	BOUNDED_STEPS.add(step);
	return step;
}

export function isBoundedSyncStep(value: unknown): value is SyncStep {
	return typeof value === 'function' && BOUNDED_STEPS.has(value as SyncStep);
}

const DELTA_CURSOR_PREFIX = 'delta:state:';
const DELTA_PAGE_PREFIX = 'delta:page:';
const WINDOW_CURSOR_PREFIX = 'window:page:';

interface WindowCursor {
	windowCutoffMs: number;
	/** Next absolute position in the newest-first ordering. */
	position: number;
}

/**
 * A PARTIALLY applied changes page (E4-I Astra correction): when the byte or
 * time budget stops a page mid-application, the checkpoint rides a page cursor
 * holding the NOT-YET-APPLIED record ids. The next call resumes from exactly
 * that frontier — the applied prefix is never fetched or charged again (the
 * original cursor used to stay put, so every retry re-applied the same fitting
 * prefix and the walk starved behind its own budget).
 */
interface DeltaPageCursor {
	/** The server state this page was minted from (advanced ONLY when fully applied). */
	state: string;
	/** Whether more changes pages follow the completed one. */
	hasMoreChanges: boolean;
	/** Created/updated record ids not yet applied. */
	pending: string[];
	/** Destroyed record ids not yet applied. */
	destroyed: string[];
}

function encodeDeltaCursor(newState: string): string {
	return DELTA_CURSOR_PREFIX + newState;
}

function decodeDeltaCursor(cursor: string): string | null {
	return cursor.startsWith(DELTA_CURSOR_PREFIX)
		? cursor.slice(DELTA_CURSOR_PREFIX.length)
		: null;
}

function encodeDeltaPageCursor(page: DeltaPageCursor): string {
	return DELTA_PAGE_PREFIX + JSON.stringify(page);
}

function decodeDeltaPageCursor(cursor: string): DeltaPageCursor | null {
	if (!cursor.startsWith(DELTA_PAGE_PREFIX)) return null;
	try {
		const parsed = JSON.parse(cursor.slice(DELTA_PAGE_PREFIX.length)) as DeltaPageCursor;
		if (
			typeof parsed.state !== 'string' ||
			typeof parsed.hasMoreChanges !== 'boolean' ||
			!Array.isArray(parsed.pending) ||
			!Array.isArray(parsed.destroyed) ||
			!parsed.pending.every((id) => typeof id === 'string') ||
			!parsed.destroyed.every((id) => typeof id === 'string')
		) return null;
		return parsed;
	} catch {
		return null;
	}
}

function encodeWindowCursor(cursor: WindowCursor): string {
	return WINDOW_CURSOR_PREFIX + JSON.stringify(cursor);
}

function decodeWindowCursor(cursor: string): WindowCursor | null {
	if (!cursor.startsWith(WINDOW_CURSOR_PREFIX)) return null;
	try {
		const parsed = JSON.parse(cursor.slice(WINDOW_CURSOR_PREFIX.length)) as WindowCursor;
		if (
			typeof parsed.windowCutoffMs !== 'number' ||
			typeof parsed.position !== 'number' ||
			!Number.isSafeInteger(parsed.position) ||
			parsed.position < 0
		) return null;
		return parsed;
	} catch {
		return null;
	}
}

/** Default intra-page clock: monotonic performance time, never wall time. */
export function defaultStepClock(): () => number {
	return typeof performance !== 'undefined' && typeof performance.now === 'function'
		? () => performance.now()
		: () => Date.now();
}

const textEncoder = new TextEncoder();

/** Approximate applied byte charge of one fetched metadata record. */
function recordByteCount(email: Email): number {
	return textEncoder.encode(JSON.stringify(email)).length;
}

/**
 * A server answer that the delta state cannot be anchored from. Surfaced as
 * the `blocked` outcome (never a thrown terminal failure) so the
 * coordinator's bounded window resync replaces the walk.
 */
function isCannotCalculateChanges(error: unknown): boolean {
	const typed = error as { type?: string; workCode?: string } | null;
	if (typed !== null && typeof typed === 'object') {
		if (typed.type === 'cannotCalculateChanges' || typed.workCode === 'cannotCalculateChanges') return true;
	}
	const message = error instanceof Error ? error.message : String(error);
	return /cannotCalculateChanges/i.test(message);
}

export interface DeltaStepFactoryOptions {
	/**
	 * Monotonic clock for intra-page budget checks (defaults to monotonic
	 * performance time — never `Date.now()`, whose wall-clock origin does not
	 * match the injected monotonic deadlines). Injected for deterministic
	 * tests.
	 */
	nowMonoMs?: () => number;
}

/**
 * One bounded Email/changes page: at most `maxChanges: 64`, applied through
 * the F1/F2/F4 seam, cursor advanced only after every local write resolved.
 * A mid-page budget/signal stop rides a `delta:page:` cursor carrying the
 * NOT-YET-APPLIED record ids, so the next call resumes behind the applied
 * frontier — the prefix is applied and charged exactly once (replay stays
 * idempotent via the F4 watermark).
 */
export function createSyncDeltaStep(
	client: DeltaChangesClient,
	options: DeltaStepFactoryOptions = {},
): SyncStep {
	const nowMonoMs = options.nowMonoMs ?? defaultStepClock();
	const step: SyncStep = async (opts) => {
		const { store, accountId, signal, budget, checkpoint } = opts;
		void accountId;
		// E4-I r9 Astra correction: the abort/deadline guard precedes EVERY
		// network call — including the initial Email/get re-anchor below,
		// which used to run before these checks and paid one round-trip on an
		// aborted or expired dispatch.
		const remainingMs = budget.deadlineMonoMs - nowMonoMs();
		if (signal.aborted || remainingMs <= 0) {
			return {
				checkpoint: checkpoint ?? { version: 1, cursor: null },
				progress: { done: 0, chargedUnits: 0, appliedBytes: 0 },
				outcome: 'partial',
			};
		}
		// E4-I r6 Astra correction: the byte allowance is checked BEFORE any
		// network call. An exhausted budget performs no Email/changes (and no
		// Email/get — including the re-anchor) at all — the prior call's
		// checkpoint already carries the unapplied remainder (a state cursor
		// stays put; a page cursor keeps riding its pending ids), so
		// re-fetching metadata with nothing appliable only spun the dispatch
		// until the time deadline. With no anchor committed yet, the returned
		// null cursor makes the next refilled dispatch re-anchor.
		if (budget.maxBytes <= 0) {
			return {
				checkpoint: checkpoint ?? { version: 1, cursor: null },
				progress: { done: 0, chargedUnits: 0, appliedBytes: 0 },
				outcome: 'partial',
			};
		}
		const priorCursor = checkpoint?.cursor ?? null;
		let sinceState = priorCursor !== null ? decodeDeltaCursor(priorCursor) : null;
		const page = priorCursor !== null ? decodeDeltaPageCursor(priorCursor) : null;
		if (sinceState === null && page === null) {
			// No valid delta anchor in the checkpoint: re-anchor from the
			// server's current Email state (ids=[] reads state without
			// records). The abort/deadline/zero-byte guards above ran first:
			// an aborted, expired, or exhausted call never reaches this
			// round-trip (E4-I r9 Astra correction).
			const anchored = await client.emailGet({ ids: [], properties: [] }, { signal });
			sinceState = anchored.state;
			const committed: SyncCheckpoint = {
				version: checkpoint?.version ?? 1,
				cursor: encodeDeltaCursor(sinceState),
			};
			return {
				checkpoint: committed,
				progress: { done: 0, chargedUnits: 0, appliedBytes: 0 },
				outcome: 'partial',
			};
		}

		// Resolve this call's work list: a partially applied page resumes from
		// its recorded frontier WITHOUT another Email/changes round-trip; a
		// state-anchored cursor fetches the next changes page.
		let newState: string;
		let hasMoreChanges: boolean;
		let fetchIds: string[];
		let destroyedIds: string[];
		if (page) {
			newState = page.state;
			hasMoreChanges = page.hasMoreChanges;
			fetchIds = page.pending.slice(0, MAX_RECORDS_PER_STEP);
			destroyedIds = page.destroyed;
		} else {
			let changes;
			try {
				changes = await client.emailChanges({ sinceState: sinceState as string, maxChanges: MAX_RECORDS_PER_STEP }, { signal });
			} catch (error) {
				if (isCannotCalculateChanges(error)) {
					// The server cannot anchor this delta state: report the blocked
					// outcome so the coordinator's one bounded window resync replaces
					// the unanchored walk. Never a thrown terminal failure.
					return {
						checkpoint: checkpoint ?? { version: 1, cursor: null },
						progress: { done: 0, chargedUnits: 0, appliedBytes: 0 },
						outcome: 'blocked',
					};
				}
				throw error;
			}
			// Cancellation observed while Email/changes was in flight: the follow-up
			// Email/get must never launch.
			if (signal.aborted) {
				return {
					checkpoint: checkpoint ?? { version: 1, cursor: null },
					progress: { done: 0, chargedUnits: 0, appliedBytes: 0 },
					outcome: 'partial',
				};
			}
			newState = changes.newState;
			hasMoreChanges = changes.hasMoreChanges;
			fetchIds = [...changes.created, ...changes.updated].slice(0, MAX_RECORDS_PER_STEP);
			destroyedIds = changes.destroyed;
		}
		let done = 0;
		let chargedUnits = 0;
		let bytesApplied = 0;
		// Reserve the longest checkpoint of this page. Applying a prefix only removes IDs.
		store.reservePageCheckpoint?.({ version: checkpoint?.version ?? 1,
			cursor: encodeDeltaPageCursor({ state: newState, hasMoreChanges, pending: fetchIds, destroyed: destroyedIds }) });
		if (fetchIds.length > 0) {
			// The byte budget was already verified positive at the top of the
			// call, so the fetch below cannot run on an exhausted allowance
			// (E4-I r6 Astra correction); the per-record ceiling still bounds
			// what the page may apply.
			const pending = await pendingMessageIds(store);
			const got = await client.emailGet({ ids: fetchIds, properties: METADATA_PROPS }, { signal });
			let appliedIndex = 0;
			for (const email of got.list) {
				if (signal.aborted || nowMonoMs() >= budget.deadlineMonoMs) {
					// Budget/signal exhausted mid-page: the applied prefix is charged
					// once and the REMAINING records ride the page cursor, so the
					// next call resumes behind them instead of re-applying the same
					// prefix forever (E4-I Astra correction).
					break;
				}
				const recordBytes = recordByteCount(email);
				if (recordBytes > YIELD_MAX_BYTES) throw new MailPageCapacityError(false);
				// The byte budget is a hard ceiling: a record that would exceed it
				// is never applied and the walk stops at this frontier.
				if (bytesApplied + recordBytes > budget.maxBytes) {
					break;
				}
				if (pending.has(email.id)) {
					bytesApplied += recordBytes;
					done += 1;
					appliedIndex += 1;
					continue;
				}
				const full = toStored(email);
				try {
					const res = await store.mergeServerDelta(
						email.id,
						{
							threadId: full.threadId,
							receivedAt: full.receivedAt,
							flags: full.flags,
							hasAttachment: full.hasAttachment,
							from: full.from,
							to: full.to,
							cc: full.cc,
							bcc: full.bcc,
							subject: full.subject,
							preview: full.preview,
							cacheState: 'full',
						},
						Number.isFinite(Number(newState)) ? Number(newState) : serverVersion(email),
					);
					if (res === 'absent') {
						await store.upsertMessage({ ...full, version: Number.isFinite(Number(newState)) ? Number(newState) : full.version });
					}
				} catch (error) {
					if (error instanceof MailPageCapacityError && error.canYield) break;
					throw error;
				}
				bytesApplied += recordBytes;
				done += 1;
				chargedUnits += 1;
				appliedIndex += 1;
			}
			const remaining = got.list.slice(appliedIndex).map((email) => email.id);
			if (remaining.length > 0 || destroyedIds.length > 0) {
				// Not every record of this changes page resolved: carry the
				// remainder forward on the page cursor.
				return {
					checkpoint: {
						version: checkpoint?.version ?? 1,
						cursor: encodeDeltaPageCursor({
							state: newState,
							hasMoreChanges,
							pending: remaining,
							destroyed: destroyedIds,
						}),
					},
					progress: { done, chargedUnits, appliedBytes: bytesApplied },
					outcome: 'partial',
				};
			}
		}
		for (const id of destroyedIds) {
			if (signal.aborted || nowMonoMs() >= budget.deadlineMonoMs) {
				break;
			}
			const idBytes = textEncoder.encode(id).length;
			if (idBytes > YIELD_MAX_BYTES) throw new MailPageCapacityError(false);
			if (bytesApplied + idBytes > budget.maxBytes) {
				break;
			}
			try { await store.deleteMessage(id); } catch (error) {
				if (error instanceof MailPageCapacityError && error.canYield) break;
				throw error;
			}
			bytesApplied += idBytes;
			done += 1;
			chargedUnits += 1;
			destroyedIds = destroyedIds.slice(1);
		}
		if (destroyedIds.length > 0) {
			return {
				checkpoint: {
					version: checkpoint?.version ?? 1,
					cursor: encodeDeltaPageCursor({
						state: newState,
						hasMoreChanges,
						pending: [],
						destroyed: destroyedIds,
					}),
				},
				progress: { done, chargedUnits, appliedBytes: bytesApplied },
				outcome: 'partial',
			};
		}

		// Every local write resolved: only now may the cursor advance.
		const checkpointLocal: SyncCheckpoint = {
			version: checkpoint?.version ?? 1,
			cursor: encodeDeltaCursor(newState),
		};
		const progress = { done, chargedUnits, appliedBytes: bytesApplied };
		return {
			checkpoint: checkpointLocal,
			progress,
			outcome: hasMoreChanges ? 'partial' : 'complete',
		};
	};
	return markBoundedSyncStep(step);
}

export interface WindowStepFactoryOptions extends DeltaStepFactoryOptions {
	/** Window cutoff epoch ms (from `window.ts cutoffMillis`) fixed at factory time. */
	windowCutoffMs: number | null;
	/**
	 * Injected Email/query surface; `anchor`/`anchorOffset` tie-safe pagination
	 * is used so equal-timestamp records are never skipped across pages.
	 */
}

/**
 * One bounded window page: at most 64 metadata records, newest-first, paged by
 * absolute position. The checkpoint records the next position plus the window
 * cutoff it was minted under; a changed window invalidates the cursor and the
 * page walk restarts (idempotent re-apply).
 */
export function createSyncWindowStep(
	client: WindowQueryClient,
	options: WindowStepFactoryOptions,
): SyncStep {
	const nowMonoMs = options.nowMonoMs ?? defaultStepClock();
	const sort = [{ property: 'receivedAt', isAscending: false }] as const;
	const step: SyncStep = async (opts) => {
		const { store, accountId, signal, budget, checkpoint } = opts;
		void accountId;
		if (signal.aborted || budget.deadlineMonoMs - nowMonoMs() <= 0) {
			return {
				checkpoint: checkpoint ?? { version: 1, cursor: null },
				progress: { done: 0, chargedUnits: 0, appliedBytes: 0 },
				outcome: 'partial',
			};
		}
		// E4-I r6 Astra correction: the byte allowance is checked BEFORE the
		// Email/query — an exhausted budget issues no network call at all (the
		// query used to run before the zero-budget check, so an exhausted or
		// non-fitting remainder re-queried every dispatch loop until the time
		// deadline). The unchanged position cursor carries the remainder.
		if (budget.maxBytes <= 0) {
			return {
				checkpoint: checkpoint ?? { version: 1, cursor: null },
				progress: { done: 0, chargedUnits: 0, appliedBytes: 0 },
				outcome: 'partial',
			};
		}

		let cursor: WindowCursor | null = checkpoint?.cursor ? decodeWindowCursor(checkpoint.cursor) : null;
		if (cursor && cursor.windowCutoffMs !== (options.windowCutoffMs ?? -1)) {
			// Window changed since this checkpoint: restart the page walk.
			cursor = null;
		}

		const filter: Record<string, unknown> = {};
		if (options.windowCutoffMs !== null) filter.after = new Date(options.windowCutoffMs).toISOString();
		const { ids } = await client.emailQuery(
			filter,
			sort as never,
			MAX_RECORDS_PER_STEP,
			cursor?.position ?? 0,
			{ signal },
		);
		if (ids.length === 0) {
			const committed: SyncCheckpoint = {
				version: checkpoint?.version ?? 1,
				cursor: encodeWindowCursor({
					windowCutoffMs: options.windowCutoffMs ?? -1,
					position: cursor?.position ?? 0,
				}),
			};
			return { checkpoint: committed, progress: { done: 0, chargedUnits: 0, appliedBytes: 0 }, outcome: 'complete' };
		}
		// Cancellation observed while Email/query was in flight: the follow-up
		// Email/get must never launch.
		if (signal.aborted) {
			return {
				checkpoint: checkpoint ?? { version: 1, cursor: null },
				progress: { done: 0, chargedUnits: 0, appliedBytes: 0 },
				outcome: 'partial',
			};
		}

		const pending = await pendingMessageIds(store);
		const emails = await client.emailGet({ ids, properties: METADATA_PROPS }, { signal });
		store.reservePageCheckpoint?.({ version: checkpoint?.version ?? 1,
			cursor: encodeWindowCursor({ windowCutoffMs: options.windowCutoffMs ?? -1,
				position: (cursor?.position ?? 0) + ids.length }) });
		// Email/get need not preserve query order. Only the query's order defines a valid
		// absolute-position prefix; absent IDs consume their position without a write.
		const byId = new Map(emails.list.map((email) => [email.id, email]));
		let done = 0;
		let chargedUnits = 0;
		let bytesApplied = 0;
		let appliedIndex = 0;
		for (const id of ids) {
			if (signal.aborted || nowMonoMs() >= budget.deadlineMonoMs) {
				break;
			}
			const email = byId.get(id);
			if (!email) { appliedIndex += 1; continue; }
			const recordBytes = recordByteCount(email);
			if (recordBytes > YIELD_MAX_BYTES) throw new MailPageCapacityError(false);
			if (bytesApplied + recordBytes > budget.maxBytes) {
				break;
			}
			let applied;
			try { applied = await applyRecord(store, email, pending); } catch (error) {
				if (error instanceof MailPageCapacityError && error.canYield) break;
				throw error;
			}
			bytesApplied += recordBytes;
			appliedIndex += 1;
			if (applied !== 'skip') {
				done += 1;
				chargedUnits += 1;
			}
		}
		if (appliedIndex < ids.length) {
			// Budget/signal stop mid-page: the position advances past the applied
			// prefix so the next call fetches the records BEHIND the frontier
			// instead of re-fetching and re-charging the same prefix forever
			// (E4-I Astra correction — the original cursor used to be returned,
			// starving the walk behind its own byte budget).
			return {
				checkpoint: {
					version: checkpoint?.version ?? 1,
					cursor: encodeWindowCursor({
						windowCutoffMs: options.windowCutoffMs ?? -1,
						position: (cursor?.position ?? 0) + appliedIndex,
					}),
				},
				progress: { done, chargedUnits, appliedBytes: bytesApplied },
				outcome: 'partial',
			};
		}

		const committed: SyncCheckpoint = {
			version: checkpoint?.version ?? 1,
			cursor: encodeWindowCursor({
				windowCutoffMs: options.windowCutoffMs ?? -1,
				position: (cursor?.position ?? 0) + ids.length,
			}),
		};
		return {
			checkpoint: committed,
			progress: { done, chargedUnits, appliedBytes: bytesApplied },
			outcome: ids.length < MAX_RECORDS_PER_STEP ? 'complete' : 'partial',
		};
	};
	return markBoundedSyncStep(step);
}

/** Re-exported for consumers that need to validate a step result shape. */
export type { SyncStepResult };
