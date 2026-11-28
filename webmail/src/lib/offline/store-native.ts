import type { NativeBatchStatement, NativeDbAppKey, OfflineDbBridge } from "$lib/native/types";
import {
  MAIL_APP_KEY,
  type OfflineStore,
  type StoredMessage,
  type SyncIssue,
} from "./store";
import { fetchCryptoProfile } from "./profile";
import { applyMailMigrations, detectMailSchemaVersion } from "./migrations";
import { executeBatch } from "./nativeBatch";
import { RestoreAtomicityUnavailableError } from "./storeErrors";
import { createNativeMailPageCommit } from "./mailPagePersistence";

// E4-I: the single best-effort MAIL_SCHEMA block is replaced by versioned,
// transactional TS-owned migrations (`migrations.ts`). The one-shot authorized
// init seam still applies the SAME statements for shells without the E4-I
// native entries (idempotent IF NOT EXISTS; the U6 dev-store upgrade replays
// inside the same authorized batch), while shells exposing the native batch /
// migration entries get atomic per-step commits with version rows. Ordinary
// `exec` still refuses multi-statement payloads, so this can never ride the
// renderer-reachable statement path.

interface MsgRow {
  id: string;
  thread_id: string;
  received_at: number;
  flags: string;
  has_attachment: number;
  cache_state: "meta" | "full";
  synced_at: number;
  from_: string;
  to_: string;
  cc: string;
  bcc: string;
  subject: string;
  preview: string;
  version: number;
  dirty_fields: string;
  tag_ids?: string;
}

function rowToMessage(r: MsgRow): StoredMessage {
  return {
    id: r.id,
    threadId: r.thread_id,
    receivedAt: r.received_at,
    flags: r.flags ? JSON.parse(r.flags) : [],
    hasAttachment: !!r.has_attachment,
    cacheState: r.cache_state,
    syncedAt: r.synced_at,
    from: r.from_ ?? "",
    to: r.to_ ?? "",
    cc: r.cc ?? "",
    bcc: r.bcc ?? "",
    subject: r.subject ?? "",
    preview: r.preview ?? "",
    tagIds: r.tag_ids ? r.tag_ids.split(",").filter(Boolean) : [],
    version: r.version ?? 0,
    dirtyFields: r.dirty_fields ? JSON.parse(r.dirty_fields) : [],
  };
}

// F1: map a StoredMessage field name → its messages column. Drives the targeted
// per-column UPDATE in mergeServerDelta (no whole-row SET). fts-affecting fields
// (subject/preview/from/to/cc) trigger an FTS row recompute after the merge.
const FIELD_TO_COLUMN: Partial<Record<keyof StoredMessage, string>> = {
  threadId: "thread_id",
  receivedAt: "received_at",
  flags: "flags",
  hasAttachment: "has_attachment",
  cacheState: "cache_state",
  syncedAt: "synced_at",
  from: "from_",
  to: "to_",
  cc: "cc",
  bcc: "bcc",
  subject: "subject",
  preview: "preview",
};
const FTS_FIELDS = new Set<keyof StoredMessage>([
  "subject",
  "preview",
  "from",
  "to",
  "cc",
]);

function encodeField(field: keyof StoredMessage, v: unknown): unknown {
  if (field === "flags" || field === "dirtyFields") return JSON.stringify(v ?? []);
  if (field === "hasAttachment") return v ? 1 : 0;
  return v;
}

async function upsertFts(
  db: OfflineDbBridge,
  A: NativeDbAppKey,
  m: StoredMessage,
): Promise<void> {
  await db.exec(A, `DELETE FROM messages_fts WHERE id = ?`, [m.id]);
  await db.exec(
    A,
    `INSERT INTO messages_fts (id, subject, body, addrs) VALUES (?,?,?,?)`,
    [
      m.id,
      m.subject,
      m.preview,
      [m.from, m.to, m.cc].filter(Boolean).join(" "),
    ],
  );
}

/**
 * E4-I r11 Astra correction: conditional tag-set restore statements — the
 * message_tags translation of "restore this field only while it still holds
 * its staged value". Tags are a child table, so the set comparison and the
 * restore are carried by a marker row inside ONE atomic batch: the marker
 * (tag_id = '') is planted only when the CURRENT tag set equals the staged
 * expectation (set equality, both directions, plus no dirty `tagIds` claim
 * and a live row), and both halves of the restore — deleting the staged tags
 * and inserting the prior ones — run only under that marker. A concurrent
 * rewrite of the tag set therefore plants nothing and restores nothing. The
 * marker row is invisible to every reader (`rowToMessage` drops empty
 * segments) and is cleared first and last, so it never outlives the batch.
 * All statements are single-statement parameterized DML — no DDL, no
 * transaction control (N66).
 *
 * E4-I r16 Astra correction: the expected ⊆ current plant guard builds its
 * VALUES table with ONE ROW PER EXPECTED TAG. The old single N-column row
 * was read back through `column1` only, so with expected {a, b} a concurrent
 * removal of b still planted the marker (only a was validated) and the
 * restore half re-inserted the stale prior set — resurrecting b.
 */
function tagRestoreStatements(
  id: string,
  expected: string[],
  prior: string[],
): NativeBatchStatement[] {
  const placeholders = (n: number) => Array.from({ length: n }, () => "?").join(", ");
  const statements: NativeBatchStatement[] = [
    { sql: `DELETE FROM message_tags WHERE message_id = ? AND tag_id = ''`, params: [id] },
  ];
  const plantGuards = [
    `EXISTS (SELECT 1 FROM messages WHERE id = ? AND dirty_fields NOT LIKE '%"tagIds"%')`,
  ];
  const plantParams: unknown[] = [id];
  if (expected.length > 0) {
    // current ⊆ expected: no current tag may fall outside the expectation.
    plantGuards.push(
      `NOT EXISTS (SELECT 1 FROM message_tags WHERE message_id = ? AND tag_id NOT IN (${placeholders(expected.length)}))`,
    );
    plantParams.push(id, ...expected);
    // expected ⊆ current: no expected tag may be missing from the row. One
    // VALUES ROW per expected tag (r16 Astra correction): the row set is read
    // back through `column1`, so a single N-column row validated only the
    // FIRST expected tag — a concurrent removal of any later tag planted the
    // marker and let the rollback resurrect stale tags. N one-column rows
    // check every expected tag.
    plantGuards.push(
      `NOT EXISTS (SELECT 1 FROM (VALUES ${expected.map(() => "(?)").join(", ")}) WHERE column1 NOT IN (SELECT tag_id FROM message_tags WHERE message_id = ? AND tag_id != ''))`,
    );
    plantParams.push(...expected, id);
  } else {
    // The staged set was empty: equality means the row currently holds no tags.
    plantGuards.push(`NOT EXISTS (SELECT 1 FROM message_tags WHERE message_id = ? AND tag_id != '')`);
    plantParams.push(id);
  }
  statements.push({
    sql: `INSERT INTO message_tags (message_id, tag_id, received_at) SELECT * FROM (VALUES (?, '', 0)) WHERE ${plantGuards.join(" AND ")}`,
    params: [id, ...plantParams],
  });
  if (expected.length > 0) {
    statements.push({
      sql: `DELETE FROM message_tags WHERE message_id = ? AND tag_id IN (${placeholders(expected.length)}) AND EXISTS (SELECT 1 FROM message_tags WHERE message_id = ? AND tag_id = '')`,
      params: [id, ...expected, id],
    });
  }
  if (prior.length > 0) {
    statements.push({
      sql: `INSERT INTO message_tags (message_id, tag_id, received_at) SELECT ?, column1, (SELECT received_at FROM messages WHERE id = ?) FROM (VALUES ${prior.map(() => "(?)").join(", ")}) WHERE EXISTS (SELECT 1 FROM message_tags WHERE message_id = ? AND tag_id = '') AND EXISTS (SELECT 1 FROM messages WHERE id = ?)`,
      params: [id, id, ...prior, id, id],
    });
  }
  statements.push({ sql: `DELETE FROM message_tags WHERE message_id = ? AND tag_id = ''`, params: [id] });
  return statements;
}

// P2-1 (Opus-5 second-voice r1): the typed capability refusals moved verbatim
// to `./storeErrors`, a leaf module, so `mailPagePersistence` and `stagedPage`
// reference them without importing this module back — the
// store-native → mailPagePersistence import edge stays one-directional. Both
// are re-exported here so existing importers are untouched and the
// `instanceof` identity remains single-sourced.
export { PageRollbackUnavailableError, RestoreAtomicityUnavailableError } from "./storeErrors";

export function makeNativeStore(db: OfflineDbBridge): OfflineStore {
  const A = MAIL_APP_KEY;
  return {
    commitMailPage: createNativeMailPageCommit(db),
    async init() {
      if (!(await db.isOpen(A))) {
        const profile = await fetchCryptoProfile();
        await db.open(A, profile);
      }
      // E4-I: apply the versioned TS-owned migrations through an authorized
      // path only — native `migrateStore` (bundled manifest), else the
      // historical one-shot `execSchemaInit` seam with the same composed
      // statements. DDL never rides `transactionBatch` (the frozen N66 batch
      // contract prohibits it), and an already-current store re-opens without
      // consuming the one-shot seam. The detection query is a plain SELECT
      // over sqlite_master — the store's own schema metadata — because PRAGMA
      // reads were rejected by every shell gate (med-offcore-sqlguard-001 r4).
      // Shells without any authorized seam fail closed BEFORE any statement
      // is issued.
      if (db.execSchemaInit || db.transactionBatch || db.migrateStore) {
        await applyMailMigrations(db);
      } else {
        // Keep the exact historical failure contract for shells that have
        // not projected any authorized seam.
        throw new Error(
          "offline store init: this shell does not expose the authorized schema-init seam " +
            "(db.execSchemaInit) nor the E4-I native migration entries; the versioned " +
            "mail migrations cannot run through exec (refused by the sql guard). The " +
            "native shell must project db_exec_schema_init from the shared native_impl.rs.",
        );
      }
    },

    isOpen: () => db.isOpen(A),

    // E4-I r15 Astra correction: the staged-page rollback capability. The
    // restore primitive is atomic only while the shell projects the native
    // `transactionBatch` entry; the composed page/checkpoint commit consults
    // this BEFORE applying any page statement and refuses a non-empty page
    // otherwise (PageRollbackUnavailableError, nothing written).
    hasAtomicRestore: () => typeof db.transactionBatch === "function",

    async upsertMessage(m: StoredMessage) {
      await db.exec(
        A,
        `INSERT OR REPLACE INTO messages
				 (id, thread_id, received_at, flags, has_attachment, cache_state, synced_at,
				  from_, to_, cc, bcc, subject, preview, version, dirty_fields)
				 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [
          m.id,
          m.threadId,
          m.receivedAt,
          JSON.stringify(m.flags),
          m.hasAttachment ? 1 : 0,
          m.cacheState,
          m.syncedAt,
          m.from,
          m.to,
          m.cc,
          m.bcc,
          m.subject,
          m.preview,
          m.version ?? 0,
          JSON.stringify(m.dirtyFields ?? []),
        ],
      );
      await db.exec(A, `DELETE FROM message_tags WHERE message_id = ?`, [m.id]);
      for (const tag of m.tagIds) {
        await db.exec(
          A,
          `INSERT OR REPLACE INTO message_tags (message_id, tag_id, received_at) VALUES (?,?,?)`,
          [m.id, tag, m.receivedAt],
        );
      }
      await upsertFts(db, A, m);
    },

    async getMessage(id: string) {
      const rows = await db.query<MsgRow>(
        A,
        `SELECT m.*, GROUP_CONCAT(t.tag_id) AS tag_ids
				 FROM messages m
				 LEFT JOIN message_tags t ON t.message_id = m.id
				 WHERE m.id = ?
				 GROUP BY m.id`,
        [id],
      );
      return rows.length ? rowToMessage(rows[0]) : null;
    },

    async getVersion(id: string) {
      const rows = await db.query<{ version: number }>(
        A,
        `SELECT version FROM messages WHERE id = ?`,
        [id],
      );
      return rows.length ? (rows[0].version ?? 0) : 0;
    },

    // F4/F1: an optimistic local edit bumps the watermark and marks the
    // touched columns dirty so an inbound server delta cannot lower-stamp or
    // overwrite them until the op acks (the dirty set is cleared on ack by the
    // replay path). Bump is monotonic (current+1) — order-insensitive.
    async bumpLocalVersion(id: string, fields: (keyof StoredMessage)[]) {
      const cur = await db.query<{ version: number; dirty_fields: string }>(
        A,
        `SELECT version, dirty_fields FROM messages WHERE id = ?`,
        [id],
      );
      if (!cur.length) return 0;
      const next = (cur[0].version ?? 0) + 1;
      const dirty = new Set<string>(
        cur[0].dirty_fields ? JSON.parse(cur[0].dirty_fields) : [],
      );
      for (const f of fields) dirty.add(f as string);
      await db.exec(
        A,
        `UPDATE messages SET version = ?, dirty_fields = ? WHERE id = ?`,
        [next, JSON.stringify([...dirty]), id],
      );
      return next;
    },

    async clearDirty(id: string) {
      // F1: the optimistic op acked → clear the per-field barrier so future
      // server deltas may win those columns again.
      await db.exec(A, `UPDATE messages SET dirty_fields = '[]' WHERE id = ?`, [
        id,
      ]);
    },

    // F2: message ids that have an un-acked op in the outbound action_queue.
    // The sync engine reads this set before applying an inbound server delta —
    // if the id is pending, the engine holds the delta until the op acks.
    async pendingMessageIds() {
      const rows = await db.query<{ payload: string }>(
        A,
        `SELECT payload FROM action_queue WHERE status = 'pending'`,
      );
      const ids = new Set<string>();
      for (const r of rows) {
        try {
          const p = JSON.parse(r.payload);
          if (p?.id) ids.add(p.id as string);
        } catch {
          /* malformed payload — skip */
        }
      }
      return ids;
    },

    async listPendingOps() {
      const rows = await db.query<{
        id: number;
        type: string;
        payload: string;
      }>(
        A,
        `SELECT id, type, payload FROM action_queue WHERE status = 'pending' ORDER BY created_at`,
        [],
      );
      return rows.map((r) => ({
        id: r.id,
        type: r.type,
        payload: JSON.parse(r.payload || "{}") as Record<string, unknown>,
      }));
    },

    async ackOp(id: number) {
      await db.exec(A, `DELETE FROM action_queue WHERE id = ?`, [id]);
    },

    async failOp(id: number, error: string) {
      // Mirror the IndexedDB retry logic: stay 'pending' until 3 attempts, then 'failed'.
      await db.exec(
        A,
        `UPDATE action_queue SET attempts = attempts + 1, last_error = ?,
				 status = CASE WHEN attempts + 1 >= 3 THEN 'failed' ELSE 'pending' END WHERE id = ?`,
        [error, id],
      );
    },

    // ponytail: SQLCipher transactional outbox — THE native offline outbox.
    // F5 transactional outbox: the optimistic per-field cache edit AND its
    // replayable op land in ONE SQLCipher transaction on offline-core's single
    // per-appKey connection (every db.exec hits the same conn). E4-I: shells
    // exposing the native atomic batch entry take that path (validated,
    // native-owned transaction); the historical BEGIN/COMMIT exec path remains
    // only for shells without the batch entry until the native flip. Rolls
    // back on any failure so the two writes are all-or-nothing.
    async enqueueOptimisticEdit(id, patch, action) {
      if (db.transactionBatch) {
        const sets: string[] = [];
        const params: unknown[] = [];
        const fields: string[] = [];
        for (const key of Object.keys(patch) as (keyof StoredMessage)[]) {
          const col = FIELD_TO_COLUMN[key];
          if (!col) continue;
          sets.push(`${col} = ?`);
          params.push(encodeField(key, patch[key]));
          fields.push(key as string);
        }
        const statements: NativeBatchStatement[] = [];
        if (sets.length) {
          sets.push("version = version + 1");
          params.push(JSON.stringify(fields));
          params.push(id);
          statements.push({
            sql: `UPDATE messages SET ${sets.join(", ")}, dirty_fields = ? WHERE id = ?`,
            params,
          });
        }
        statements.push({
          sql: `INSERT INTO action_queue (type, payload, status, attempts, created_at) VALUES (?,?,?,0,?)`,
          params: [action.type, JSON.stringify(action.payload), "pending", Date.now()],
        });
        await executeBatch(db, A, statements);
        return;
      }
      await db.exec(A, "BEGIN");
      try {
        // per-column UPDATE of only the patched fields (never whole-row, F1)
        const sets: string[] = [];
        const params: unknown[] = [];
        const fields: string[] = [];
        for (const key of Object.keys(patch) as (keyof StoredMessage)[]) {
          const col = FIELD_TO_COLUMN[key];
          if (!col) continue;
          sets.push(`${col} = ?`);
          params.push(encodeField(key, patch[key]));
          fields.push(key as string);
        }
        if (sets.length) {
          // bump watermark + mark patched fields dirty in the SAME statement (F1/F4)
          sets.push("version = version + 1");
          params.push(JSON.stringify(fields)); // dirty_fields
          params.push(id);
          await db.exec(
            A,
            `UPDATE messages SET ${sets.join(", ")}, dirty_fields = ? WHERE id = ?`,
            params,
          );
        }
        await db.exec(
          A,
          `INSERT INTO action_queue (type, payload, status, attempts, created_at) VALUES (?,?,?,0,?)`,
          [action.type, JSON.stringify(action.payload), "pending", Date.now()],
        );
        await db.exec(A, "COMMIT");
      } catch (e) {
        await db.exec(A, "ROLLBACK");
        throw e;
      }
    },

    // F1 + F4: column-level LWW merge of an inbound server delta. NEVER a
    // whole-row overwrite — builds a targeted UPDATE over ONLY the columns
    // in `changed`, skips any column in dirty_fields (an un-acked local edit
    // wins → the mark-read-offline-while-tag-added-server case keeps BOTH), and
    // applies only if serverVersion >= the row watermark (idempotent, replay-
    // /reorder-safe). FTS is recomputed only when a body/subject/addr column
    // actually changed. Returns 'absent' (caller upserts the full record),
    // 'skipped' (stale delta), or 'merged'.
    async mergeServerDelta(id, changed, serverVersion) {
      const rows = await db.query<MsgRow>(
        A,
        `SELECT * FROM messages WHERE id = ?`,
        [id],
      );
      if (!rows.length) return "absent";
      const row = rowToMessage(rows[0]);
      if (serverVersion < row.version!) return "skipped"; // F4 watermark
      const dirty = new Set(row.dirtyFields);
      const sets: string[] = [];
      const params: unknown[] = [];
      let ftsTouched = false;
      for (const key of Object.keys(changed) as (keyof StoredMessage)[]) {
        const col = FIELD_TO_COLUMN[key];
        if (!col) continue; // tagIds/version/dirtyFields handled elsewhere
        if (dirty.has(key as string)) continue; // F1/F2: local optimistic edit wins
        sets.push(`${col} = ?`);
        params.push(encodeField(key, changed[key]));
        if (FTS_FIELDS.has(key)) ftsTouched = true;
      }
      // Always advance the watermark to the (>=) server version, even if every
      // changed column was dirty — keeps the row monotonic.
      sets.push("version = ?");
      params.push(serverVersion);
      params.push(id);
      await db.exec(
        A,
        `UPDATE messages SET ${sets.join(", ")} WHERE id = ?`,
        params,
      );
      if (ftsTouched) {
        const updated = await db.query<MsgRow>(
          A,
          `SELECT * FROM messages WHERE id = ?`,
          [id],
        );
        if (updated.length) await upsertFts(db, A, rowToMessage(updated[0]));
      }
      return "merged";
    },

    // E4-I r11 Astra correction: the staged-page rollback's atomic per-field
    // conditional restore. Every column field is restored by ONE UPDATE whose
    // SET expression is a CASE-WHEN-current-equals-expected predicate (plus a
    // dirty-claim guard), so the compare and the write happen inside the
    // statement itself — a concurrent local edit that commits after the
    // caller's snapshot read fails its predicate at write time and survives
    // the restore, where the old whole-row `INSERT OR REPLACE` clobbered it.
    // Tag sets ride the same transaction through the marker-guarded
    // conditional swap, and FTS is recomputed when an FTS-affecting column is
    // in play — the same derived-index effect the whole-row write used to
    // have. The batch entry is DML-only (no DDL, no transaction control —
    // N66).
    //
    // E4-I r12 Astra correction: the restore is inherently multi-statement
    // whenever a field or tag set is in play, so a shell whose bridge lacks
    // the atomic `transactionBatch` entry FAILS CLOSED — a typed error is
    // thrown before ANY statement is issued instead of replaying the
    // statements individually through `exec`, where a failure or concurrent
    // operation could expose a partial restore. A no-op restore (nothing to
    // write) still succeeds without the seam. Callers treat primitive failure
    // as leave-state-alone: the staged rollback catches the error per row and
    // the flush rethrows the original failure, so no checkpoint commits over
    // an unrestored page.
    async restoreFieldsIfUnchanged(id, expectedState, fieldRestore) {
      const expected = expectedState as unknown as Record<string, unknown>;
      const restore = fieldRestore as unknown as Record<string, unknown>;
      const rows = await db.query<{ id: string }>(
        A,
        `SELECT id FROM messages WHERE id = ?`,
        [id],
      );
      if (!rows.length) return false;
      const sets: string[] = [];
      const setParams: unknown[] = [];
      let restoreTags: { expected: string[]; prior: string[] } | null = null;
      let ftsTouched = false;
      for (const key of Object.keys(restore) as (keyof StoredMessage)[]) {
        if (key === "id") continue;
        const expectedValue = expected[key as string];
        const restoreValue = restore[key as string];
        if (expectedValue === undefined || restoreValue === undefined) continue;
        if (key === "tagIds") {
          restoreTags = {
            expected: Array.isArray(expectedValue) ? expectedValue.map(String) : [],
            prior: Array.isArray(restoreValue) ? restoreValue.map(String) : [],
          };
          continue;
        }
        const column =
          key === "version"
            ? "version"
            : key === "dirtyFields"
              ? "dirty_fields"
              : FIELD_TO_COLUMN[key];
        if (!column) continue; // no messages column: never fabricated (F1 posture)
        if (FTS_FIELDS.has(key)) ftsTouched = true;
        sets.push(
          `${column} = CASE WHEN ${column} IS ? AND dirty_fields NOT LIKE ? THEN ? ELSE ${column} END`,
        );
        setParams.push(
          encodeField(key, expectedValue),
          `%"${key}"%`,
          encodeField(key, restoreValue),
        );
      }
      const statements: NativeBatchStatement[] = [];
      if (sets.length > 0) {
        statements.push({
          sql: `UPDATE messages SET ${sets.join(", ")} WHERE id = ?`,
          params: [...setParams, id],
        });
      }
      if (ftsTouched) {
        statements.push(
          { sql: `DELETE FROM messages_fts WHERE id = ?`, params: [id] },
          {
            sql: `INSERT INTO messages_fts (id, subject, body, addrs)
						 SELECT id, subject, preview, TRIM(COALESCE(from_, '') || ' ' || COALESCE(to_, '') || ' ' || COALESCE(cc, ''))
						 FROM messages WHERE id = ?`,
            params: [id],
          },
        );
      }
      if (restoreTags) {
        statements.push(...tagRestoreStatements(id, restoreTags.expected, restoreTags.prior));
      }
      if (statements.length === 0) return true;
      if (typeof db.transactionBatch !== "function") {
        // E4-I r12 Astra correction: fail closed — never replay a multi-
        // statement restore through individually awaited exec calls.
        throw new RestoreAtomicityUnavailableError(statements.length);
      }
      await executeBatch(db, A, statements);
      return true;
    },

    async listByReceivedDesc(limit: number, offset = 0) {
      const rows = await db.query<MsgRow>(
        A,
        `SELECT m.*, GROUP_CONCAT(t.tag_id) AS tag_ids
				 FROM messages m
				 LEFT JOIN message_tags t ON t.message_id = m.id
				 GROUP BY m.id
				 ORDER BY m.received_at DESC LIMIT ? OFFSET ?`,
        [limit, offset],
      );
      return rows.map(rowToMessage);
    },

    async deleteOutOfWindow(cutoffMs: number) {
      const before = await db.query<{ n: number }>(
        A,
        `SELECT COUNT(*) AS n FROM messages WHERE received_at < ?`,
        [cutoffMs],
      );
      await db.exec(
        A,
        `DELETE FROM message_tags WHERE message_id IN (SELECT id FROM messages WHERE received_at < ?)`,
        [cutoffMs],
      );
      await db.exec(
        A,
        `DELETE FROM messages_fts WHERE id IN (SELECT id FROM messages WHERE received_at < ?)`,
        [cutoffMs],
      );
      await db.exec(A, `DELETE FROM messages WHERE received_at < ?`, [
        cutoffMs,
      ]);
      return before[0]?.n ?? 0;
    },

    async deleteMessage(id: string) {
      // Single-id evict: removes row + tags + body + FTS in one pass.
      await db.exec(A, `DELETE FROM message_tags WHERE message_id = ?`, [id]);
      await db.exec(A, `DELETE FROM messages_fts WHERE id = ?`, [id]);
      await db.exec(A, `DELETE FROM bodies WHERE id = ?`, [id]);
      await db.exec(A, `DELETE FROM messages WHERE id = ?`, [id]);
    },

    async searchBody(query: string, limit = 100) {
      const q = query.trim();
      if (!q) return [];
      const rows = await db.query<{ id: string }>(
        A,
        `SELECT id FROM messages_fts WHERE messages_fts MATCH ? LIMIT ?`,
        [q, limit],
      );
      return rows.map((r) => r.id);
    },

    async getMeta(key: string) {
      const rows = await db.query<{ value: string }>(
        A,
        `SELECT value FROM meta_mail WHERE key = ?`,
        [key],
      );
      return rows.length ? rows[0].value : null;
    },

    async setMeta(key: string, value: string) {
      await db.exec(
        A,
        `INSERT OR REPLACE INTO meta_mail (key, value) VALUES (?, ?)`,
        [key, value],
      );
    },

    async recordSyncIssue(i: Omit<SyncIssue, "id" | "at">) {
      await db.exec(
        A,
        `INSERT INTO sync_issues (kind, action_type, payload, error, created_at) VALUES (?,?,?,?,?)`,
        [i.kind, i.actionType, JSON.stringify(i.payload), i.error, Date.now()],
      );
    },

    async listSyncIssues() {
      const rows = await db.query<{
        id: number;
        kind: "stale" | "rejected";
        action_type: string;
        payload: string;
        error: string;
        created_at: number;
      }>(
        A,
        `SELECT id, kind, action_type, payload, error, created_at FROM sync_issues ORDER BY created_at DESC`,
      );
      return rows.map((r) => ({
        id: r.id,
        kind: r.kind,
        actionType: r.action_type,
        payload: JSON.parse(r.payload || "{}"),
        error: r.error,
        at: r.created_at,
      }));
    },

    async clearSyncIssue(id: number) {
      await db.exec(A, `DELETE FROM sync_issues WHERE id = ?`, [id]);
    },

    async wipe() {
      await db.wipe(A);
    },
  };
}
