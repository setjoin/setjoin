import { beforeEach, describe, expect, it, vi } from "vitest";
import type {
  OfflineDbBridge,
  RecoveryBlobBridge,
  SetjoinNativeBridge,
} from "$lib/native/types";

const api = vi.hoisted(() => ({
  recoveryUploadBegin: vi.fn(),
  recoveryUploadAbort: vi.fn(),
  recoveryUploadChunk: vi.fn(),
  recoveryUploadCommit: vi.fn(),
  recoveryUploadFinalize: vi.fn(),
}));

vi.mock("$lib/jmap/client", () => ({
  fetchRecoveryBytes: vi.fn(),
  recoveryReceiptGet: vi.fn(),
  ...api,
}));

import { offerRecoveryArtifact } from "./recovery";

describe("resumable recovery upload", () => {
  beforeEach(() => vi.clearAllMocks());

  it("reuses acknowledged offsets, skips verified items, and finalizes only bounded chunks", async () => {
    const raw = new Uint8Array([1, 2, 3, 4, 5]);
    const inserted: unknown[][] = [];
    const db: OfflineDbBridge = {
      open: vi.fn(),
      isOpen: vi.fn(async () => true),
      wipe: vi.fn(),
      exec: vi.fn(async (_app, sql, params = []) => {
        if (sql.includes("INSERT INTO recovery_uploads")) inserted.push(params);
        return 1;
      }),
      query: vi.fn(async (_app, sql) => {
        if (sql.includes("FROM recovery_artifacts"))
          return [
            {
              account_id: "7",
              eligibility: "received",
              status: "covered",
              receipt: JSON.stringify({
                claims: { accountId: "7" },
                signature: "signed",
              }),
            },
          ];
        if (sql.includes("FROM recovery_artifact_items"))
          return [
            { item_id: "raw", sha256: "a".repeat(64), size: 5, role: "raw" },
            {
              item_id: "blob-1",
              sha256: "b".repeat(64),
              size: 3,
              role: "attachment",
            },
          ];
        if (sql.includes("FROM recovery_uploads")) return [];
        return [];
      }) as OfflineDbBridge["query"],
    };
    const bridge: RecoveryBlobBridge = {
      writeBegin: vi.fn(),
      writeChunk: vi.fn(),
      writeCommit: vi.fn(),
      writeAbort: vi.fn(),
      readOpen: vi.fn(async () => ({ handle: "read-raw", size: 5 })),
      readChunk: vi.fn(async (_handle, offset, length) =>
        raw.slice(offset, offset + length),
      ),
      readClose: vi.fn(),
      ref: vi.fn(),
      unref: vi.fn(),
    };
    const secure = new Map<string, string>();
    window.setjoinNative = {
      db,
      recoveryBlob: bridge,
      secureStore: {
        get: vi.fn(async (key) => secure.get(key) ?? null),
        set: vi.fn(async (key, value) => {
          secure.set(key, value);
        }),
        remove: vi.fn(),
      },
    } as unknown as SetjoinNativeBridge;
    api.recoveryUploadBegin.mockResolvedValue({
      sessionId: "session",
      status: "uploading",
      expiresAt: new Date().toISOString(),
      replayed: true,
      items: [
        { itemId: "raw", nextOffset: "2", size: "5", status: "uploading" },
        { itemId: "blob-1", nextOffset: "3", size: "3", status: "verified" },
      ],
    });
    api.recoveryUploadFinalize.mockResolvedValue({
      id: "quarantine",
      status: "quarantined",
    });

    await expect(
      offerRecoveryArtifact("f".repeat(64), crypto.randomUUID()),
    ).resolves.toEqual({
      id: "quarantine",
      status: "quarantined",
    });
    expect(inserted).toHaveLength(1);
    expect(api.recoveryUploadChunk).toHaveBeenCalledTimes(1);
    expect(api.recoveryUploadChunk.mock.calls[0][2]).toBe(2);
    expect(api.recoveryUploadChunk.mock.calls[0][4]).toEqual(
      new Uint8Array([3, 4, 5]),
    );
    expect(api.recoveryUploadCommit).toHaveBeenCalledTimes(1);
    expect(api.recoveryUploadCommit.mock.calls[0][1]).toBe("raw");
    expect(bridge.readOpen).toHaveBeenCalledTimes(1);
    expect(bridge.readClose).toHaveBeenCalledWith("read-raw");
  });

  it("rotates an aborted session before retry and does not replay a terminal upload", async () => {
    const updates: unknown[][] = [];
    let uploadStatus = "aborted";
    const db: OfflineDbBridge = {
      open: vi.fn(),
      isOpen: vi.fn(async () => true),
      wipe: vi.fn(),
      exec: vi.fn(async (_app, sql, params = []) => {
        if (sql.includes("SET session_id=")) updates.push(params);
        return 1;
      }),
      query: vi.fn(async (_app, sql) => {
        if (sql.includes("FROM recovery_artifacts"))
          return [
            {
              account_id: "7",
              eligibility: "received",
              status: "covered",
              receipt: JSON.stringify({
                claims: { accountId: "7" },
                signature: "signed",
              }),
            },
          ];
        if (sql.includes("FROM recovery_artifact_items"))
          return [
            { item_id: "raw", sha256: "a".repeat(64), size: 5, role: "raw" },
          ];
        if (sql.includes("FROM recovery_uploads"))
          return [
            {
              session_id: "old-session",
              idempotency_key: "old-key",
              device_id: crypto.randomUUID(),
              status: uploadStatus,
            },
          ];
        return [];
      }) as OfflineDbBridge["query"],
    };
    window.setjoinNative = {
      db,
      recoveryBlob: {
        writeBegin: vi.fn(),
        writeChunk: vi.fn(),
        writeCommit: vi.fn(),
        writeAbort: vi.fn(),
        readOpen: vi.fn(),
        readChunk: vi.fn(),
        readClose: vi.fn(),
        ref: vi.fn(),
        unref: vi.fn(),
      },
      secureStore: { get: vi.fn(), set: vi.fn(), remove: vi.fn() },
    } as unknown as SetjoinNativeBridge;
    api.recoveryUploadBegin.mockResolvedValue({
      sessionId: "replacement",
      status: "uploading",
      expiresAt: new Date().toISOString(),
      replayed: false,
      items: [
        { itemId: "raw", nextOffset: "5", size: "5", status: "verified" },
      ],
    });
    api.recoveryUploadFinalize.mockResolvedValue({
      id: "quarantine",
      status: "quarantined",
    });

    await expect(
      offerRecoveryArtifact("f".repeat(64), crypto.randomUUID()),
    ).resolves.toEqual({
      id: "quarantine",
      status: "quarantined",
    });
    expect(updates).toHaveLength(1);
    expect(updates[0][0]).not.toBe("old-session");
    expect(updates[0][1]).not.toBe("old-key");
    expect(api.recoveryUploadBegin.mock.calls[0][0].sessionId).toBe(
      updates[0][0],
    );

    uploadStatus = "deduplicated";
    api.recoveryUploadBegin.mockClear();
    await expect(
      offerRecoveryArtifact("f".repeat(64), crypto.randomUUID()),
    ).resolves.toEqual({
      id: "old-session",
      status: "deduplicated",
      replayed: true,
    });
    expect(api.recoveryUploadBegin).not.toHaveBeenCalled();
  });
});
