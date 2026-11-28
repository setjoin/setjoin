// Offline-aware JMAP client wrapper.
// Automatically queues actions when offline and replays them when back online.
//
// b1r2-011: every queued op serializes the originating account override
// (payload.acct, null = primary); replay re-issues against that account. Pre-fix
// queue rows without the key are quarantined to sync_issues, never defaulted to
// the primary account.
//
// b1r2-011 round 2: replay inspects the per-item failure buckets of a RESOLVED
// setResponse (notCreated/notUpdated/notDestroyed hold only failures, RFC 8620
// §5.3) BEFORE acknowledging, and error classification is structured — the
// closed JMAP error-type vocabulary in normalized token shape — never free
// description prose (see classifyJmapError below).
//
// Native: offline writes route through the SQLCipher transactional outbox
// (store-native.ts enqueueOptimisticEdit) — one atomic tx per op (BEGIN +
// optional cache UPDATE + action_queue INSERT + COMMIT; rolls back on failure).
// Browser: online-only by design; $lib/db/offline is kept for isOnline /
// onNetworkChange only — the IndexedDB action_queue is dead for this path.
// ponytail: SyncIssuesInspector still calls queueAction (IndexedDB) for retry;
// fix that to use the store's enqueueOptimisticEdit when native pre-#2b.

import { isOnline, onNetworkChange } from '$lib/db/offline';
import {
	emailSet as onlineEmailSet,
	emailSubmissionSet as onlineEmailSubmissionSet,
	loadSession,
	JmapMethodError
} from './client';
import { resolveId, recordSyncIssue, newIdempotencyKey } from '$lib/offline/reconcile';
import { getStore } from '$lib/offline/store';
import { jmapSession } from '$lib/stores/session';
import { logger } from '$lib/logger';
import type { JmapMethodResponse, Email } from '$lib/types/jmap';

let replayInProgress = false;

// ── b1r2-011: structured error classification (adjudication A1) ──────────────
// The structured error type lives in the JMAP response. Per-item SetErrors
// (notCreated/notUpdated/notDestroyed) carry `type` directly and are classified
// from that field with zero text matching. Method-level errors reach replay as
// client.ts's JmapMethodError (r3: the thrown Error carries resp.type +
// description STRUCTURALLY instead of flattening them into one prose string),
// so classification reads err.jmapType — the CLOSED JMAP error-type vocabulary
// — with zero description matching (an innocent or hostile description can
// never steer classification; a forbidden whose description omits the token
// still classifies from its type). The normalized token match below survives
// ONLY as the transport-error fallback: errors without a structured type
// (httpRequest's "JMAP error: <status>", network failures) are matched against
// the same closed vocabulary in normalized token shape, never the old open
// prose regex (/state|reject|conflict|exists|notfound/i), which both misread
// arbitrary descriptions and missed spaced tokens. Unknown text classifies to
// null = transient retry.

type IssueKind = 'rejected' | 'stale';

// token → kind. Family members are covered by their base token (*NotFound ⊆
// notFound — including accountNotFound/emailNotFound/mailboxNotFound and the
// wrong-account serverNotFound convention — requestTooLarge ⊆ tooLarge,
// rateLimited ⊆ rateLimit). Extend the table if the gateway adds new types.
const JMAP_ERROR_KINDS: ReadonlyArray<readonly [token: string, kind: IssueKind]> = [
	['notFound', 'rejected'],
	['forbidden', 'rejected'],
	['accountReadOnly', 'rejected'],
	['alreadyExists', 'rejected'],
	['singleton', 'rejected'],
	['willDestroy', 'rejected'],
	['invalidProperties', 'rejected'],
	['invalidPatch', 'rejected'],
	['invalidArguments', 'rejected'],
	['tooLarge', 'rejected'],
	['stateMismatch', 'stale'],
	['cannotCalculateChanges', 'stale'],
	['overQuota', 'stale'],
	['rateLimit', 'stale'],
	['serverFail', 'stale']
];

// One canonical token shape so camelCase types, spaced prose and snake_case all
// compare equal: 'notFound' → 'notfound', 'Email not found' → 'emailnotfound'.
function normalizeErrorToken(s: string): string {
	return s.toLowerCase().replace(/[^a-z0-9]/g, '');
}

function classifyJmapErrorToken(text: string): IssueKind | null {
	const norm = normalizeErrorToken(text);
	for (const [token, kind] of JMAP_ERROR_KINDS) {
		if (norm.includes(normalizeErrorToken(token))) return kind;
	}
	return null;
}

/**
 * b1r2-011 r3: a method-level JMAP error classifies from its STRUCTURED type
 * (JmapMethodError.jmapType) — never from the message prose. Errors without a
 * structured type (transport failures) fall back to the closed-vocabulary
 * token match over the message; unknown text → null = transient retry.
 */
function classifyJmapError(err: unknown): IssueKind | null {
	if (err instanceof JmapMethodError) {
		return classifyJmapErrorToken(err.jmapType);
	}
	return classifyJmapErrorToken((err as Error)?.message ?? '');
}

// ── b1r2-011: per-item setResponse failure buckets ───────────────────────────
// A RESOLVED setResponse can still fail per item: the notCreated/notUpdated/
// notDestroyed maps hold ONLY failures (RFC 8620 §5.3) — e.g. the gateway folds
// destroyed-already-gone ids into notDestroyed as {"type":"notFound"} and
// rejected snooze patches into notUpdated as invalidArguments. Acknowledging
// without inspecting them clears dirty state and deletes the queued op without
// a sync issue — the user's edit is silently dropped.

interface ItemFailure {
	bucket: 'notCreated' | 'notUpdated' | 'notDestroyed';
	id: string;
	type: string;
	description?: string;
}

type SetErrorMap = Record<string, { type: string; description: string }>;

function perItemFailures(resp: JmapMethodResponse | null | undefined): ItemFailure[] {
	if (!resp) return [];
	const failures: ItemFailure[] = [];
	const buckets: Array<readonly [ItemFailure['bucket'], SetErrorMap | undefined]> = [
		['notCreated', resp.notCreated],
		['notUpdated', resp.notUpdated],
		['notDestroyed', resp.notDestroyed]
	];
	for (const [bucket, map] of buckets) {
		if (!map) continue;
		for (const [id, err] of Object.entries(map)) {
			failures.push({ bucket, id, type: err?.type ?? 'unknown', description: err?.description });
		}
	}
	return failures;
}

function issueKindForFailure(f: ItemFailure): IssueKind {
	// Classification reads the STRUCTURED type field (A1) — never the description.
	// (Per-item SetErrors carry the type string directly; the token classifier
	// consumes it with zero text matching. classifyJmapError is for THROWN errors.)
	return classifyJmapErrorToken(f.type) ?? 'stale'; // unknown structured type: surfaced, retryable
}

// Disposition mirrors the method-level rejection path: sync issue + drain from
// the queue; the per-field dirty barrier stays up (clearDirty is skipped) so the
// unsynced edit keeps barrier protection until the user resolves the issue.
async function recordPerItemFailures(
	action: { type: string; payload: Record<string, unknown> },
	failures: ItemFailure[]
): Promise<void> {
	for (const f of failures) {
		await recordSyncIssue({
			kind: issueKindForFailure(f),
			actionType: action.type,
			payload: action.payload,
			error: `${f.bucket}[${f.id}] ${f.type}${f.description ? `: ${f.description}` : ''}`
		});
	}
}

export async function emailSet(
	create: Record<string, unknown> | null,
	update: Record<string, unknown> | null,
	destroy: string[] | null,
	acct?: string | null
): Promise<JmapMethodResponse | { offline: true }> {
	if (isOnline()) {
		return onlineEmailSet(
			create as Record<string, Partial<Email>> | null,
			update as Record<string, Partial<Email>> | null,
			destroy,
			acct
		);
	}
	// Offline: route through the SQLCipher transactional outbox (native).
	// ponytail: browser is online-only — no offline queue on browser (returns { offline: true }).
	const store = getStore();
	if (store) {
		// b1r2-011: every fresh enqueue persists the originating account override, even
	// when null (primary) — the key's PRESENCE distinguishes fresh rows from legacy
	// pre-fix rows, which must never be defaulted to the primary account at replay.
	if (update) {
			for (const [id, patch] of Object.entries(update)) {
				// patch={} → no cache UPDATE (no StoredMessage-level translation yet);
				// the action_queue INSERT is still atomic in the same tx.
				// ponytail: add jmapPatchToStoredMessage translation pre-#2b for full optimistic UI.
				await store.enqueueOptimisticEdit(id, {}, { type: 'emailSetUpdate', payload: { id, patch, acct: acct ?? null } });
			}
		}
		if (destroy) {
			for (const id of destroy) {
				await store.enqueueOptimisticEdit(id, {}, { type: 'emailSetDestroy', payload: { id, acct: acct ?? null } });
			}
		}
		if (create) {
			for (const [key, msg] of Object.entries(create)) {
				await store.enqueueOptimisticEdit('', {}, { type: 'emailSetCreate', payload: { key, msg, acct: acct ?? null } });
			}
		}
	}
	return { offline: true };
}

export async function emailSubmissionSet(
	create: Record<string, unknown>,
	acct?: string | null
): Promise<JmapMethodResponse | { offline: true }> {
	if (isOnline()) {
		return onlineEmailSubmissionSet(create, acct);
	}
	const store = getStore();
	if (store) {
		for (const [key, sub] of Object.entries(create)) {
			await store.enqueueOptimisticEdit('', {}, {
				type: 'emailSubmissionSet',
				payload: { key, sub, idempotencyKey: newIdempotencyKey(), acct: acct ?? null }
			});
		}
	}
	return { offline: true };
}

// Replay all pending actions when coming back online.
// b1r2-011: queued ops carry the originating account override (payload.acct, null
// = primary). Rows WITHOUT the key are legacy pre-fix entries — never defaulted to
// the primary account (that repeats the defect); they are quarantined into
// sync_issues as non-executable for explicit user re-confirmation or discard.
export async function replayPendingActions(): Promise<void> {
	if (replayInProgress) return;
	const store = getStore();
	if (!store) return; // browser: online-only, no SQLCipher queue to replay
	replayInProgress = true;
	try {
		await loadSession();
		const actions = await store.listPendingOps();
		for (const action of actions) {
			try {
				if (!('acct' in action.payload)) {
					// Legacy pre-fix row: non-executable, never against the primary account.
					await quarantineLegacyNoAccount(action);
					await store.ackOp(action.id); // out of queue; user re-confirms or discards
					continue;
				}
				const acct = action.payload.acct as string | null;
				switch (action.type) {
					case 'emailSetUpdate': {
						const id = await resolveId(action.payload.id as string);
						const resp = await onlineEmailSet(null, { [id]: action.payload.patch as Partial<Email> }, null, acct);
						const failures = perItemFailures(resp);
						if (failures.length > 0) {
							// b1r2-011: per-item failure → sync issue; NO clearDirty.
							await recordPerItemFailures(action, failures);
							break;
						}
						await store.clearDirty(id); // F1: op acked → lift the per-field barrier
						break;
					}
					case 'emailSetDestroy': {
						const id = await resolveId(action.payload.id as string);
						const resp = await onlineEmailSet(null, null, [id], acct);
						const failures = perItemFailures(resp);
						if (failures.length > 0) {
							await recordPerItemFailures(action, failures);
							break;
						}
						await store.clearDirty(id); // F1: op acked
						break;
					}
					case 'emailSetCreate': {
						const resp = await onlineEmailSet(
							{ [action.payload.key as string]: action.payload.msg as Partial<Email> },
							null,
							null,
							acct
						);
						const failures = perItemFailures(resp);
						if (failures.length > 0) await recordPerItemFailures(action, failures);
						break;
					}
					case 'emailSubmissionSet': {
						const resp = await onlineEmailSubmissionSet({
							[action.payload.key as string]: {
								...(action.payload.sub as Record<string, unknown>),
								idempotencyKey: (action.payload.idempotencyKey as string) ?? newIdempotencyKey()
							}
						}, acct);
						const failures = perItemFailures(resp);
						if (failures.length > 0) await recordPerItemFailures(action, failures);
						break;
					}
				}
				await store.ackOp(action.id);
			} catch (err) {
				const msg = (err as Error).message;
				// b1r2-011 r3: classify on the STRUCTURED error type, not description
				// prose — a method-level notFound with an innocent description
				// ("Message was deleted") is a permanent rejection via
				// JmapMethodError.jmapType, and a description that OMITS the token
				// (forbidden → 'fixed:access denied') still classifies from its
				// type. Transport errors (no structured type) fall back to the
				// closed-vocabulary token match; unknown text stays transient.
				const kind = classifyJmapError(err);
				if (kind) {
					// Stale/rejected: record in sync_issues so user can resolve; drain from queue.
					await recordSyncIssue({
						kind,
						actionType: action.type,
						payload: action.payload,
						error: msg
					});
					await store.ackOp(action.id); // out of queue; user resolves via sync_issues
				} else {
					await store.failOp(action.id, msg); // transient: retry (≤3 per action_queue.attempts)
				}
			}
		}
	} finally {
		replayInProgress = false;
	}
}

// b1r2-011: a legacy offline op queued before account persistence carries no acct.
// It is surfaced in sync_issues with its original payload so the user can explicitly
// re-confirm (re-issue under the right account) or discard it — the CTA choice is a
// UX decision that stays open; the no-primary-default disposition here is settled.
async function quarantineLegacyNoAccount(
	action: { type: string; payload: Record<string, unknown> }
): Promise<void> {
	await recordSyncIssue({
		kind: 'rejected',
		actionType: action.type,
		payload: action.payload,
		error: 'legacy offline op without serialized account — not replayed; re-confirm or discard'
	});
}

// ── A8 drain wiring: replay is INVOKED, never manual ─────────────────────────
// Owner decision A8: the drain runs at (a) app bootstrap after the first
// successful JMAP Session acquisition and (b) each reconnect transition. These
// triggers are the only invocations; there is no manual-UI replay.
//
// Fire-and-forget: a drain failure (session fetch while the network is still
// flaky) must never surface as an unhandled rejection from a module-init
// listener — replay is resumable (acked ops are gone; transient failures stay
// queued per action_queue.attempts), so the next trigger picks it up.
export function drainPendingActions(): void {
	replayPendingActions().catch((err) => logger.error('offline-client: drain failed', err));
}

// Bootstrap fires once per page lifetime; reconnect triggers own every later
// drain. Overlapping triggers of any kind collapse on the in-flight guard
// inside replayPendingActions.
let bootstrapDrainDone = false;

// The identity-generation fence lives INSIDE replay, not in the triggers: each
// op re-issues under the identity that queued it (payload.acct passthrough,
// b1r2-011; legacy no-account rows quarantined, never defaulted), and
// client.ts's authGeneration fences session discovery across auth teardown —
// so a trigger firing under a freshly acquired session cannot retarget an
// in-flight drain's queued ops.
if (typeof window !== 'undefined') {
	// (a) Bootstrap: checkAuth → loadSessionStore sets jmapSession at app startup;
	// the first acquisition drains whatever a killed prior session left queued.
	// Online-gated: an offline boot drains via the reconnect trigger below.
	jmapSession.subscribe((session) => {
		if (!session || bootstrapDrainDone) return;
		bootstrapDrainDone = true;
		if (isOnline()) drainPendingActions();
	});

	// (b) Reconnect: the browser online/offline transition (existing seam).
	onNetworkChange((online) => {
		if (online) drainPendingActions();
	});
}
