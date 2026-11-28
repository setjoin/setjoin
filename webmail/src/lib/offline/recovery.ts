import type { OfflineDbBridge, RecoveryBlobBridge } from "$lib/native/types";
import {
  fetchRecoveryBytes,
  recoveryReceiptGet,
  recoveryUploadAbort,
  recoveryUploadBegin,
  recoveryUploadChunk,
  recoveryUploadCommit,
  recoveryUploadFinalize,
  type RecoveryIncidentOffer,
} from "$lib/jmap/client";
import { MAIL_APP_KEY } from "./store";

export const RECOVERY_CHUNK_BYTES = 256 * 1024;
export const MAX_RECOVERY_ARTIFACT_BYTES = 8 * 1024 * 1024 * 1024;

export type RecoverableArtifactKind = "received" | "sent-terminal";

export interface RecoveryReceipt {
  artifactIdentity: string;
  installationId: string;
  accountId: string;
  mailboxId: string;
  originalMessageId: string;
  rawMimeSha256: string;
  rawMimeSize: string;
  timelineGeneration: string;
  bootEpoch: string;
  stateWatermark: string;
  blobs: Array<{ blobId: string; sha256: string; size: string }>;
  token: string;
}

export interface RecoveryByteSource {
  itemId: string;
  role: "raw" | "attachment" | "inline";
  sha256: string;
  size: number;
  bytes: AsyncIterable<Uint8Array>;
}

export interface RecoveryArtifactInput {
  kind: RecoverableArtifactKind;
  messageId: string;
  receivedAt: number;
  receipt: RecoveryReceipt;
  sources: RecoveryByteSource[];
  retainedUntil?: number;
}

export interface RecoveryCoverage {
  count: number;
  bytes: number;
  oldestAt: number | null;
  newestAt: number | null;
}

export interface RecoverableArtifactSummary {
  artifactIdentity: string;
  messageId: string;
  accountId: string;
  receivedAt: number;
  bytes: number;
  status: string;
}

function exactDecimal(value: string): boolean {
  return /^(0|[1-9][0-9]*)$/.test(value);
}

function validDigest(value: string): boolean {
  return /^[0-9a-f]{64}$/.test(value);
}

function validate(input: RecoveryArtifactInput): void {
  if (!["received", "sent-terminal"].includes(input.kind))
    throw new Error("artifact is mutable");
  if (!input.messageId || input.messageId !== input.receipt.originalMessageId) {
    throw new Error("receipt message scope mismatch");
  }
  if (
    !validDigest(input.receipt.artifactIdentity) ||
    !validDigest(input.receipt.rawMimeSha256)
  ) {
    throw new Error("invalid receipt digest");
  }
  for (const value of [
    input.receipt.accountId,
    input.receipt.mailboxId,
    input.receipt.rawMimeSize,
    input.receipt.timelineGeneration,
    input.receipt.stateWatermark,
  ]) {
    if (!exactDecimal(value)) throw new Error("non-canonical receipt decimal");
  }
  if (!input.receipt.token || input.receipt.token.length > 16 * 1024) {
    throw new Error("missing or oversized receipt token");
  }
  const raw = input.sources.filter((source) => source.role === "raw");
  if (raw.length !== 1)
    throw new Error("exactly one raw MIME source is required");
  if (
    raw[0].sha256 !== input.receipt.rawMimeSha256 ||
    raw[0].size !== Number(input.receipt.rawMimeSize)
  ) {
    throw new Error("raw MIME does not match receipt");
  }
  const receiptBlobs = new Map(
    input.receipt.blobs.map((blob) => [blob.blobId, blob]),
  );
  const seenItems = new Set<string>();
  for (const source of input.sources) {
    if (
      !source.itemId ||
      source.itemId.length > 256 ||
		/[/\u0000-\u001f]/.test(source.itemId) ||
      seenItems.has(source.itemId) ||
      !validDigest(source.sha256) ||
      !Number.isSafeInteger(source.size) ||
      source.size <= 0
    ) {
      throw new Error("invalid recovery byte source");
    }
    seenItems.add(source.itemId);
    if (source.size > MAX_RECOVERY_ARTIFACT_BYTES)
      throw new Error("recovery source too large");
    if (source.role === "raw" && source.itemId !== "raw")
      throw new Error("raw recovery item id is invalid");
    if (source.role !== "raw") {
      const receiptBlob = receiptBlobs.get(source.itemId);
      if (
        !receiptBlob ||
        receiptBlob.sha256 !== source.sha256 ||
        receiptBlob.size !== String(source.size)
      ) {
        throw new Error("blob does not match receipt");
      }
    }
  }
  if (input.sources.length - 1 !== receiptBlobs.size)
    throw new Error("receipt blob inventory incomplete");
}

async function streamSource(
  bridge: RecoveryBlobBridge,
  source: RecoveryByteSource,
): Promise<string> {
  const begun = await bridge.writeBegin(source.sha256, source.size);
  let sourceOffset = 0;
  let acknowledged = begun.nextOffset;
  if (
    !Number.isSafeInteger(acknowledged) ||
    acknowledged < 0 ||
    acknowledged > source.size
  ) {
    throw new Error("invalid native resume offset");
  }
  for await (const supplied of source.bytes) {
    if (!(supplied instanceof Uint8Array) || supplied.length === 0) continue;
    let at = 0;
    if (sourceOffset + supplied.length <= acknowledged) {
      sourceOffset += supplied.length;
      continue;
    }
    if (sourceOffset < acknowledged) at = acknowledged - sourceOffset;
    while (at < supplied.length) {
      const end = Math.min(supplied.length, at + RECOVERY_CHUNK_BYTES);
      const chunk = supplied.subarray(at, end);
      acknowledged = await bridge.writeChunk(begun.handle, acknowledged, chunk);
      at = end;
    }
    sourceOffset += supplied.length;
  }
  if (sourceOffset !== source.size || acknowledged !== source.size) {
    throw new Error("recovery source ended before its declared size");
  }
  return begun.handle;
}

/**
 * Stream exact bytes first, then publish blobs, refs, and receipt metadata in
 * one SQLCipher transaction. `cacheState: full` is intentionally unrelated;
 * only a covered row returned by this module is disaster recoverable.
 */
export async function captureRecoveryArtifact(
  db: OfflineDbBridge,
  bridge: RecoveryBlobBridge,
  input: RecoveryArtifactInput,
): Promise<"covered" | "already-covered"> {
  validate(input);
  const existing = await db.query<{ artifact_identity: string }>(
    MAIL_APP_KEY,
    "SELECT artifact_identity FROM recovery_artifacts WHERE artifact_identity = ?",
    [input.receipt.artifactIdentity],
  );
  if (existing.length) return "already-covered";

  const pending: Array<{ source: RecoveryByteSource; handle: string }> = [];
  try {
    for (const source of input.sources) {
      pending.push({ source, handle: await streamSource(bridge, source) });
    }
    await db.exec(MAIL_APP_KEY, "BEGIN");
    try {
      for (const item of pending) {
        const committed = await bridge.writeCommit(item.handle);
        if (committed !== item.source.sha256)
          throw new Error("native blob commit mismatch");
        await bridge.ref(committed);
      }
      await db.exec(
        MAIL_APP_KEY,
        `INSERT INTO recovery_artifacts
				 (artifact_identity,message_id,account_id,mailbox_id,installation_id,raw_sha256,
				  raw_size,received_at,timeline_generation,boot_epoch,state_watermark,receipt,eligibility,
				  verified_at,retained_until,status)
				 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [
          input.receipt.artifactIdentity,
          input.messageId,
          input.receipt.accountId,
          input.receipt.mailboxId,
          input.receipt.installationId,
          input.receipt.rawMimeSha256,
          Number(input.receipt.rawMimeSize),
          input.receivedAt,
          input.receipt.timelineGeneration,
          input.receipt.bootEpoch,
          input.receipt.stateWatermark,
          JSON.stringify(input.receipt),
          input.kind,
          Date.now(),
          input.retainedUntil ?? null,
          "covered",
        ],
      );
      for (const source of input.sources) {
        await db.exec(
          MAIL_APP_KEY,
          `INSERT INTO recovery_artifact_items
					 (artifact_identity,item_id,sha256,size,role) VALUES (?,?,?,?,?)`,
          [
            input.receipt.artifactIdentity,
            source.itemId,
            source.sha256,
            source.size,
            source.role,
          ],
        );
      }
      await db.exec(MAIL_APP_KEY, "COMMIT");
      return "covered";
    } catch (error) {
      await db.exec(MAIL_APP_KEY, "ROLLBACK");
      throw error;
    }
  } catch (error) {
    await Promise.allSettled(
      pending.map((item) => bridge.writeAbort(item.handle)),
    );
    throw error;
  }
}

export async function recoveryCoverage(
  db: OfflineDbBridge,
): Promise<RecoveryCoverage> {
  const rows = await db.query<{
    count: number;
    bytes: number | null;
    oldest_at: number | null;
    newest_at: number | null;
  }>(
    MAIL_APP_KEY,
    `SELECT COUNT(DISTINCT a.artifact_identity) AS count,
		        SUM(b.size) AS bytes, MIN(a.received_at) AS oldest_at, MAX(a.received_at) AS newest_at
		 FROM recovery_artifacts a
		 JOIN recovery_artifact_items b ON b.artifact_identity=a.artifact_identity
		 WHERE a.status='covered'`,
  );
  const row = rows[0];
  return {
    count: Number(row?.count ?? 0),
    bytes: Number(row?.bytes ?? 0),
    oldestAt: row?.oldest_at ?? null,
    newestAt: row?.newest_at ?? null,
  };
}

export async function recoverableArtifacts(
  db: OfflineDbBridge,
  incident?: RecoveryIncidentOffer,
): Promise<RecoverableArtifactSummary[]> {
  const params: unknown[] = [];
  let accountFilter = "";
  if (incident) {
    accountFilter =
      " AND a.account_id=? AND CAST(a.timeline_generation AS INTEGER) BETWEEN CAST(? AS INTEGER) AND CAST(? AS INTEGER)";
    params.push(
      incident.mailboxId,
      incident.minimumTimeline,
      incident.maximumTimeline,
    );
  }
  return db.query<RecoverableArtifactSummary>(
    MAIL_APP_KEY,
    `SELECT a.artifact_identity AS artifactIdentity,a.message_id AS messageId,
		        a.account_id AS accountId,a.received_at AS receivedAt,SUM(item.size) AS bytes,a.status
		   FROM recovery_artifacts a
		   JOIN recovery_artifact_items item ON item.artifact_identity=a.artifact_identity
		  WHERE a.status='covered'${accountFilter}
		  GROUP BY a.artifact_identity,a.message_id,a.account_id,a.received_at,a.status
		  ORDER BY a.received_at DESC LIMIT 100`,
    params,
  );
}

const RECOVERY_OPT_IN_KEY = "recovery.optedIn.v1";

export async function recoveryOptedIn(db: OfflineDbBridge): Promise<boolean> {
  const rows = await db.query<{ value: string }>(
    MAIL_APP_KEY,
    "SELECT value FROM meta_mail WHERE key=?",
    [RECOVERY_OPT_IN_KEY],
  );
  return rows[0]?.value === "true";
}

export async function setRecoveryOptIn(
  db: OfflineDbBridge,
  enabled: boolean,
): Promise<void> {
  await db.exec(
    MAIL_APP_KEY,
    "INSERT INTO meta_mail(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
    [RECOVERY_OPT_IN_KEY, enabled ? "true" : "false"],
  );
}

async function* responseChunks(response: Response): AsyncIterable<Uint8Array> {
  if (!response.body) throw new Error("recovery response has no body");
  const reader = response.body.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return;
      if (value?.length) yield value;
    }
  } finally {
    reader.releaseLock();
  }
}

/** Fetch and capture eligible messages only after an explicit opt-in caller asks. */
export async function captureRecoveryMessages(
  ids: string[],
  accountId: string,
): Promise<Array<{ id: string; status: "covered" | "already-covered" }>> {
  const native =
    typeof window === "undefined" ? undefined : window.setjoinNative;
  if (!native?.db || !native.recoveryBlob)
    throw new Error("native recovery vault unavailable");
  const response = await recoveryReceiptGet(ids, accountId);
  const out: Array<{ id: string; status: "covered" | "already-covered" }> = [];
  for (const item of response.list) {
    const rawResponse = await fetchRecoveryBytes(item.raw.url);
    const sources: RecoveryByteSource[] = [
      {
        itemId: "raw",
        role: "raw",
        sha256: item.raw.sha256,
        size: Number(item.raw.size),
        bytes: responseChunks(rawResponse),
      },
    ];
    for (const blob of item.blobs) {
      const blobResponse = await fetchRecoveryBytes(
        `/jmap/download/${encodeURIComponent(accountId)}/${encodeURIComponent(blob.blobId)}/recovery.bin?type=application/octet-stream`,
      );
      sources.push({
        itemId: blob.blobId,
        role: blob.role,
        sha256: blob.sha256,
        size: Number(blob.size),
        bytes: responseChunks(blobResponse),
      });
    }
    const claims = item.receipt.claims;
    const status = await captureRecoveryArtifact(
      native.db,
      native.recoveryBlob,
      {
        kind: item.eligibility,
        messageId: item.id,
        receivedAt: Date.parse(item.receivedAt),
        receipt: {
          artifactIdentity: item.artifactIdentity,
          installationId: claims.installationId,
          accountId: claims.accountId,
          mailboxId: claims.accountId,
          originalMessageId: claims.originalMessageId,
          rawMimeSha256: claims.rawMimeSha256,
          rawMimeSize: claims.rawMimeSize,
          timelineGeneration: claims.timelineGeneration,
          bootEpoch: claims.bootEpoch,
          stateWatermark: claims.stateWatermark,
          blobs: claims.blobs.map((blob) => ({
            blobId: blob.blobId,
            sha256: blob.sha256,
            size: blob.size,
          })),
          token: JSON.stringify(item.receipt),
        },
        sources,
      },
    );
    out.push({ id: item.id, status });
  }
  return out;
}

interface LocalRecoveryBlob {
  item_id: string;
  sha256: string;
  size: number;
  role: "raw" | "attachment" | "inline";
}

function newUUID(): string {
  if (!globalThis.crypto?.randomUUID)
    throw new Error("secure UUID generation unavailable");
  return globalThis.crypto.randomUUID();
}

const cancelledOffers = new Set<string>();

export function cancelRecoveryOffer(artifactIdentity: string): void {
  cancelledOffers.add(artifactIdentity);
}

async function recoveryDeviceId(): Promise<string> {
  const native = window.setjoinNative;
  if (!native) throw new Error("native recovery vault unavailable");
  const key = "recovery_device_id_v1";
  const existing = await native.secureStore.get(key);
  if (existing && /^[0-9a-f-]{36}$/i.test(existing)) return existing;
  const created = newUUID();
  await native.secureStore.set(key, created);
  return created;
}

/**
 * Explicit, resumable user-consented upload. Calling again with the same
 * incident reuses the locally persisted session and asks the server for exact
 * acknowledged offsets before reading any bytes.
 */
export async function offerRecoveryArtifact(
  artifactIdentity: string,
  incidentId: string,
): Promise<{ id: string; status: string; replayed?: boolean }> {
  const native = window.setjoinNative;
  if (!native?.db || !native.recoveryBlob)
    throw new Error("native recovery vault unavailable");
  const db = native.db;
  const artifacts = await db.query<{
    account_id: string;
    eligibility: RecoverableArtifactKind;
    receipt: string;
    status: string;
  }>(
    MAIL_APP_KEY,
    "SELECT account_id,eligibility,receipt,status FROM recovery_artifacts WHERE artifact_identity=?",
    [artifactIdentity],
  );
  if (artifacts.length !== 1 || artifacts[0].status !== "covered")
    throw new Error("recoverable artifact unavailable");
  const blobs = await db.query<LocalRecoveryBlob>(
    MAIL_APP_KEY,
    "SELECT item_id,sha256,size,role FROM recovery_artifact_items WHERE artifact_identity=? ORDER BY CASE role WHEN 'raw' THEN 0 ELSE 1 END,item_id",
    [artifactIdentity],
  );
  if (!blobs.length) throw new Error("recoverable artifact has no bytes");
  const receipt = JSON.parse(artifacts[0].receipt) as {
    claims: unknown;
    signature: string;
  };
  let uploads = await db.query<{
    session_id: string;
    idempotency_key: string;
    device_id: string;
    status: string;
  }>(
    MAIL_APP_KEY,
    "SELECT session_id,idempotency_key,device_id,status FROM recovery_uploads WHERE artifact_identity=? AND incident_id=?",
    [artifactIdentity, incidentId],
  );
  if (!uploads.length) {
    uploads = [
      {
        session_id: newUUID(),
        idempotency_key: newUUID(),
        device_id: await recoveryDeviceId(),
        status: "pending",
      },
    ];
    await db.exec(
      MAIL_APP_KEY,
      "INSERT INTO recovery_uploads(artifact_identity,incident_id,session_id,idempotency_key,device_id,status,updated_at) VALUES (?,?,?,?,?,?,?)",
      [
        artifactIdentity,
        incidentId,
        uploads[0].session_id,
        uploads[0].idempotency_key,
        uploads[0].device_id,
        "pending",
        Date.now(),
      ],
    );
  } else if (
    uploads[0].status === "aborted" ||
    uploads[0].status === "expired"
  ) {
    const replacement = {
      session_id: newUUID(),
      idempotency_key: newUUID(),
      device_id: uploads[0].device_id,
      status: "pending",
    };
    await db.exec(
      MAIL_APP_KEY,
      "UPDATE recovery_uploads SET session_id=?,idempotency_key=?,status=?,updated_at=? WHERE artifact_identity=? AND incident_id=? AND session_id=?",
      [
        replacement.session_id,
        replacement.idempotency_key,
        "pending",
        Date.now(),
        artifactIdentity,
        incidentId,
        uploads[0].session_id,
      ],
    );
    uploads = [replacement];
  } else if (
    ["quarantined", "deduplicated", "rejected"].includes(uploads[0].status)
  ) {
    return {
      id: uploads[0].session_id,
      status: uploads[0].status,
      replayed: true,
    };
  } else if (!["pending", "uploading"].includes(uploads[0].status)) {
    throw new Error("invalid local recovery upload status");
  }
  const upload = uploads[0];
  cancelledOffers.delete(artifactIdentity);
  try {
    const inventory = blobs.map((blob) => ({
      itemId: blob.item_id,
      role: blob.role,
      sha256: blob.sha256,
      size: String(blob.size),
    }));
    const session = await recoveryUploadBegin(
      {
        sessionId: upload.session_id,
        incidentId,
        accountId: artifacts[0].account_id,
        deviceId: upload.device_id,
        artifactIdentity,
        eligibility: artifacts[0].eligibility,
        receipt,
        inventory,
        consentedAt: new Date().toISOString(),
        idempotencyKey: upload.idempotency_key,
      },
      upload.idempotency_key,
    );
    await db.exec(
      MAIL_APP_KEY,
      "UPDATE recovery_uploads SET status=?,updated_at=? WHERE session_id=?",
      ["uploading", Date.now(), upload.session_id],
    );
    const acknowledged = new Map(
      session.items.map((item) => [item.itemId, item]),
    );
    for (const blob of blobs) {
      if (cancelledOffers.has(artifactIdentity)) {
        await recoveryUploadAbort(upload.session_id);
        await db.exec(
          MAIL_APP_KEY,
          "UPDATE recovery_uploads SET status=?,updated_at=? WHERE session_id=?",
          ["aborted", Date.now(), upload.session_id],
        );
        throw new Error("recovery upload cancelled");
      }
      const item = acknowledged.get(blob.item_id);
      if (!item) throw new Error("server recovery inventory differs");
      let offset = Number(item.nextOffset);
      if (!Number.isSafeInteger(offset) || offset < 0 || offset > blob.size)
        throw new Error("invalid recovery upload offset");
      if (item.status !== "verified") {
        const opened = await native.recoveryBlob.readOpen(blob.sha256);
        try {
          if (opened.size !== blob.size)
            throw new Error("native recovery blob size differs");
          while (offset < blob.size) {
            if (cancelledOffers.has(artifactIdentity)) {
              await recoveryUploadAbort(upload.session_id);
              await db.exec(
                MAIL_APP_KEY,
                "UPDATE recovery_uploads SET status=?,updated_at=? WHERE session_id=?",
                ["aborted", Date.now(), upload.session_id],
              );
              throw new Error("recovery upload cancelled");
            }
            const length = Math.min(RECOVERY_CHUNK_BYTES, blob.size - offset);
            const chunk = await native.recoveryBlob.readChunk(
              opened.handle,
              offset,
              length,
            );
            if (chunk.byteLength !== length)
              throw new Error("native recovery blob ended early");
            await recoveryUploadChunk(
              upload.session_id,
              blob.item_id,
              offset,
              blob.size,
              chunk,
            );
            offset += chunk.byteLength;
          }
        } finally {
          await native.recoveryBlob.readClose(opened.handle);
        }
        await recoveryUploadCommit(upload.session_id, blob.item_id);
      }
    }
    const result = await recoveryUploadFinalize(upload.session_id);
    await db.exec(
      MAIL_APP_KEY,
      "UPDATE recovery_uploads SET status=?,updated_at=? WHERE session_id=?",
      [result.status, Date.now(), upload.session_id],
    );
    return result;
  } finally {
    cancelledOffers.delete(artifactIdentity);
  }
}
