import { emailQuery, emailGet, getAccountId } from "$lib/jmap/client";
import { withSyncOwnership } from "./leader";
import { getStore, type StoredMessage, type OfflineStore } from "./store";
import { resolveId } from "./reconcile";
import {
  cutoffMillis,
  type OfflineWindow,
  DEFAULT_OFFLINE_WINDOW,
} from "./window";
import type { Email } from "$lib/types/jmap";

export const METADATA_PROPS = [
  "id",
  "threadId",
  "mailboxIds",
  "keywords",
  "receivedAt",
  "hasAttachment",
  "preview",
  "subject",
  "from",
  "to",
  "cc",
  "bcc",
];

function addr(list?: { email?: string }[]): string {
  return (list ?? []).map((a) => a.email ?? "").join(", ");
}

// F4: the server-derived watermark for a freshly-fetched record. receivedAt is a
// monotonic, server-authored value that only advances on a real change to the
// message in this windowed (no-journal) path; #3's delta path uses the journal
// state_seq instead (a strictly better monotonic clock — see #3 Task 15/A5).
// E4-I: exported for the bounded syncWindowStep/syncDeltaStep factories
// (steps.ts) so the scheduler reuses this exact application logic instead of
// duplicating JMAP mapping.
export function serverVersion(e: Email): number {
  return e.receivedAt ? Date.parse(e.receivedAt) : 0;
}

export function toStored(e: Email): StoredMessage {
  return {
    id: e.id,
    threadId: e.threadId ?? "",
    receivedAt: e.receivedAt ? Date.parse(e.receivedAt) : 0,
    flags: Object.entries(e.keywords ?? {})
      .filter(([, v]) => v)
      .map(([k]) => k),
    hasAttachment: !!e.hasAttachment,
    cacheState: "full",
    syncedAt: Date.now(),
    from: addr(e.from),
    to: addr(e.to),
    cc: addr(e.cc),
    bcc: addr(e.bcc),
    subject: e.subject ?? "",
    preview: e.preview ?? "",
    tagIds: Object.keys(e.mailboxIds ?? {}),
    version: serverVersion(e),
    dirtyFields: [],
  };
}

async function captureOptedInRecovery(
  ids: string[],
  accountId: string,
): Promise<void> {
  const native =
    typeof window === "undefined" ? undefined : window.setjoinNative;
  if (!native?.db || !native.recoveryBlob || ids.length === 0) return;
  const { captureRecoveryMessages, recoveryOptedIn } =
    await import("./recovery");
  if (!(await recoveryOptedIn(native.db))) return;
  for (let offset = 0; offset < ids.length; offset += 64) {
    await captureRecoveryMessages(ids.slice(offset, offset + 64), accountId);
  }
}

// F2 write-barrier: the set of message ids with an un-acked op in the outbound
// action_queue (temp-ids resolved to server ids). A resync/delta must NOT write a
// cache row in this set — the optimistic row is authoritative until its op acks;
// those ids resync on the next pass after the queue drains.
// Reads from the SQLCipher action_queue (the native encrypted transactional outbox).
// syncWindow() already guards !store → null, so this always has a non-null store.
// E4-I: exported for steps.ts (the bounded coordinator step consumes the same
// SQLCipher action_queue barrier set).
export async function pendingMessageIds(
  store: OfflineStore,
): Promise<Set<string>> {
  const raw = await store.pendingMessageIds();
  const resolved = new Set<string>();
  for (const id of raw) resolved.add(await resolveId(id));
  return resolved;
}

// Columns whose auto-resolution we surface as a quiet "synced" confirmation
// (UI-UX-PRO-MAX 2026-06-23). F1 column-level LWW auto-merges these — the user
// never sees them in the SyncIssuesInspector (which now shows only genuine
// whole-body/draft conflicts), so without a confirmation a silent auto-merge could
// read as "did my flag/move stick?".
const AUTOMERGE_COLUMNS = ["flags", "mailboxIds", "keywords"] as const;

// F1 + F2 + F4: apply one freshly-fetched record to the cache. Skip if pending
// (F2 barrier); merge per-column if cached (F1, watermark-gated F4); full upsert
// only when absent. Returns 'skip' (F2 barrier), 'automerged' (a cached row whose
// dirty flag/keyword/mailbox edit was auto-reconciled with this inbound delta),
// or 'applied' (plain upsert/merge/absent-fill — nothing to confirm).
// E4-I: exported for steps.ts — the bounded scheduler steps reuse this exact
// F1/F2/F4 application seam; JMAP mapping is never duplicated.
export async function applyRecord(
  store: OfflineStore,
  e: Email,
  pending: Set<string>,
): Promise<"skip" | "automerged" | "applied"> {
  if (pending.has(e.id)) return "skip"; // F2: hold behind the drained-queue checkpoint
  const full = toStored(e);
  // Snapshot the row's dirty set BEFORE the merge: a non-empty intersection with
  // AUTOMERGE_COLUMNS means F1 auto-reconciled a real flag/keyword/mailbox conflict
  // on this record (local edit kept, server change folded in — no inspector entry).
  const before = await store.getMessage(e.id);
  const hadDirtyAutoMerge =
    !!before &&
    before.dirtyFields!.some((f) =>
      (AUTOMERGE_COLUMNS as readonly string[]).includes(f),
    );
  const res = await store.mergeServerDelta(
    e.id,
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
      cacheState: "full",
    },
    serverVersion(e),
  );
  if (res === "absent") {
    await store.upsertMessage(full);
    return "applied";
  } // first cache of this id
  return res === "merged" && hadDirtyAutoMerge ? "automerged" : "applied";
}

export async function syncWindow(opts: {
  window: OfflineWindow;
  now?: number;
}) {
  const store = getStore();
  if (!store) return null; // browser: offline disabled
  return withSyncOwnership(async () => {
    // Drive the OfflineStatus phase machine: first-ever sync (no lastSyncAt
    // meta) is "provisioning" (determinate Progress, first-time arc); a return
    // sync is "syncing" (Syncing N of M). On throw → 'error' (status shows an
    // inline retry). On success → 'idle'. Imported lazily to keep sync.ts
    // runes-free (state.svelte.ts owns the runes).
    const { offline } = await import("./state.svelte");
    const firstRun = (await store.getMeta("lastSyncAt")) === null;
    offline.setSyncPhase(firstRun ? "provisioning" : "syncing");
    try {
      await store.init();
      const continuityAccount = await getAccountId();
      if (continuityAccount) {
        try {
          const { observeContinuity } = await import("./continuity");
          await observeContinuity(continuityAccount);
        } catch {
          // Receipts remain independently gated and OFF by default. A continuity
          // endpoint/key issue must never block ordinary offline mail sync.
        }
      }
      const cutoff = cutoffMillis(opts.window, opts.now);
      const filter: Record<string, unknown> = {};
      if (cutoff !== null) filter.after = new Date(cutoff).toISOString();
      const { ids } = await emailQuery(
        filter,
        [{ property: "receivedAt", isAscending: false }],
        500,
      );
      offline.setSyncProgress(0, ids.length);
      let upserted = 0;
      let autoMerged = 0; // UI-UX-PRO-MAX: F1 auto-resolved flag/keyword/mailbox conflicts this pass
      if (ids.length) {
        const pending = await pendingMessageIds(store); // F2: barrier set for this pass
        const emails = await emailGet(ids, METADATA_PROPS, undefined);
        for (const e of emails) {
          // F1/F2/F4: per-column merge, pending-barrier skip, watermark gate.
          const r = await applyRecord(store, e, pending);
          if (r !== "skip") upserted++;
          if (r === "automerged") autoMerged++;
          offline.setSyncProgress(upserted, ids.length);
        }
        await store.setMeta("lastSyncAt", String(opts.now ?? Date.now()));
        // ponytail: windowed cursor (receivedAt epoch ms) ≠ JMAP state token —
        // the two watermark domains are incomparable. Clear emailState so syncDelta
        // re-anchors from the server's current Email state on its next call instead
        // of comparing a windowed cursor to a delta token and silently skipping merges.
        await store.setMeta("emailState", "");
        if (continuityAccount) {
          // Recovery capture is opt-in and best-effort. It owns a separate
          // encrypted byte plane and must never fail ordinary offline sync.
          void captureOptedInRecovery(ids, continuityAccount).catch(
            () => undefined,
          );
        }
      }
      const evicted =
        cutoff === null ? 0 : await store.deleteOutOfWindow(cutoff);
      offline.setSyncPhase("idle");
      // Quiet, aggregate confirmation that silent auto-resolution worked (NOT a
      // per-item entry; the inspector stays for genuine conflicts only). No-op on 0.
      offline.notifyAutoMerged(autoMerged);
      return { upserted, evicted, autoMerged };
    } catch (err) {
      offline.setSyncError((err as Error).message);
      throw err;
    }
  });
}

let debounceTimer: ReturnType<typeof setTimeout> | null = null;
let pendingWindow: OfflineWindow = DEFAULT_OFFLINE_WINDOW;

// Debounced/coalesced owner-gated resync (review P2). Bound to the window;
// "All" leans on open-time caching, not full prefetch.
// ponytail: module-level timer — single debounce slot; multi-caller coalesce is
// the intent. Reset path: page reload (no cancel API needed for now).
export function requestSync(window: OfflineWindow = pendingWindow): void {
  pendingWindow = window;
  if (debounceTimer) clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => {
    debounceTimer = null;
    void syncWindow({ window: pendingWindow });
  }, 250);
}

// JmapClient shape consumed by syncDelta — matches Part B's real Email/changes endpoint.
// ponytail: inline rather than a separate file; only syncDelta consumes it.
export interface JmapClient {
  emailChanges(args: { sinceState: string; maxChanges: number }): Promise<{
    newState: string;
    hasMoreChanges: boolean;
    created: string[];
    updated: string[];
    destroyed: string[];
  }>;
  // state is the server's current Email state (always present in JMAP method responses).
  // Pass ids=[] to read state without fetching records (used by reAnchorDeltaState).
  emailGet(args: {
    ids: string[];
    properties: string[];
  }): Promise<{ list: Email[]; state: string }>;
}

// §8.5 step 3: after any windowed resync, re-establish the delta watermark from the
// server's current Email state so the next emailChanges is incremental from a correct base.
// Email/get with ids=[] returns state without fetching records.
// ponytail: called by both the BZ011 catch and the start-of-syncDelta re-anchor guard —
// implement once, used by both (Fix 1 + Fix 2 share the same seam).
async function reAnchorDeltaState(
  client: JmapClient,
  store: OfflineStore,
): Promise<string> {
  const { state } = await client.emailGet({ ids: [], properties: [] });
  await store.setMeta("emailState", state);
  return state;
}

// syncDelta: incremental Email/changes apply path (offline #3 §8.5).
// Replaces the full windowed re-query for the primary sync path.
// On cannotCalculateChanges (BZ011/pruned sinceState) falls back to syncWindow.
// All writes/evicts go through the OfflineStore interface (SQLCipher on native).
export async function syncDelta(
  client: JmapClient,
  store: OfflineStore,
): Promise<void> {
  let sinceState = (await store.getMeta("emailState")) ?? "";
  if (!sinceState) {
    // No valid delta anchor: first run or post-windowed-resync (syncWindow sets emailState=''
    // to signal the domain switch). Re-establish from the server's current Email state so
    // the first emailChanges call is incremental from a correct base, not from '0'/pruned.
    sinceState = await reAnchorDeltaState(client, store);
  }
  try {
    for (;;) {
      const res = await client.emailChanges({ sinceState, maxChanges: 500 });
      const fetchIds = [...res.created, ...res.updated];
      if (fetchIds.length) {
        // F2 write-barrier: reads SQLCipher action_queue via the store interface —
        // covers both native (real encrypted outbox) and browser (no-op stub).
        const pending = await pendingMessageIds(store);
        const got = await client.emailGet({
          ids: fetchIds,
          properties: METADATA_PROPS,
        });
        // F4: journal newState (state_seq) is the monotonic per-account clock —
        // strictly better than receivedAt (the windowed-resync fallback watermark).
        const serverVersion = Number(res.newState);
        for (const e of got.list) {
          if (pending.has(e.id)) continue; // F2: held behind drained-queue checkpoint
          const full = toStored(e);
          // F1: per-column LWW merge — only changed fields, never whole-record;
          // skips dirty (un-acked local) columns; watermark-gated by serverVersion.
          const r = await store.mergeServerDelta(
            e.id,
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
              cacheState: "full",
            },
            serverVersion,
          );
          if (r === "absent")
            await store.upsertMessage({ ...full, version: serverVersion });
        }
      }
      for (const id of res.destroyed) {
        await store.deleteMessage(id);
      }
      await store.setMeta("emailState", res.newState);
      sinceState = res.newState;
      if (!res.hasMoreChanges) break;
    }
  } catch (e: unknown) {
    if ((e as { jmapType?: string })?.jmapType === "cannotCalculateChanges") {
      // ponytail: BZ011 = cannotCalculateChanges (pruned sinceState); fall back to
      // the #1a windowed full-resync. Dynamic self-import routes through the module
      // namespace so vi.spyOn(syncMod, 'syncWindow') intercepts it in tests.
      const { syncWindow: sw } = await import("./sync");
      await sw({ window: pendingWindow });
      // §8.5 step 3: sw() sets emailState='' (or is mocked in tests). Either way,
      // re-anchor immediately so the NEXT syncDelta is incremental — without this,
      // every subsequent call hits BZ011 again (permanent full-resync loop).
      await reAnchorDeltaState(client, store);
      return;
    }
    throw e;
  }
}
