import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import type { OfflineDbBridge, RecoveryBlobBridge } from "$lib/native/types";
import {
  captureRecoveryArtifact,
  RECOVERY_CHUNK_BYTES,
  type RecoveryArtifactInput,
} from "./recovery";

function digest(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

async function* chunks(
  bytes: Uint8Array,
  step: number,
): AsyncIterable<Uint8Array> {
  for (let at = 0; at < bytes.length; at += step)
    yield bytes.subarray(at, at + step);
}

function input(
  raw: Uint8Array,
  attachment?: Uint8Array,
): RecoveryArtifactInput {
  const rawHash = digest(raw);
  const blobs = attachment
    ? [
        {
          blobId: "blob-1",
          sha256: digest(attachment),
          size: String(attachment.length),
        },
      ]
    : [];
  return {
    kind: "received",
    messageId: "42",
    receivedAt: 123,
    receipt: {
      artifactIdentity: "f".repeat(64),
      installationId: "83c3b85c-91fd-4302-96f5-91bbd8d789a4",
      accountId: "7",
      mailboxId: "9",
      originalMessageId: "42",
      rawMimeSha256: rawHash,
      rawMimeSize: String(raw.length),
      timelineGeneration: "2",
      bootEpoch: "13a84d44-d5ab-48b3-9649-8718fd9b4bd9",
      stateWatermark: "99",
      blobs,
      token: "signed-receipt",
    },
    sources: [
      {
        itemId: "raw",
        role: "raw",
        sha256: rawHash,
        size: raw.length,
        bytes: chunks(raw, 300_000),
      },
      ...(attachment
        ? [
            {
              itemId: "blob-1",
              role: "attachment" as const,
              sha256: digest(attachment),
              size: attachment.length,
              bytes: chunks(attachment, 71_000),
            },
          ]
        : []),
    ],
  };
}

function fakes() {
  const writes = new Map<string, Uint8Array[]>();
  const expected = new Map<string, string>();
  const bridge: RecoveryBlobBridge = {
    writeBegin: vi.fn(async (sha256) => {
      const handle = `h-${writes.size}`;
      writes.set(handle, []);
      expected.set(handle, sha256);
      return { handle, nextOffset: 0 };
    }),
    writeChunk: vi.fn(async (handle, offset, bytes) => {
      const list = writes.get(handle)!;
      const current = list.reduce((sum, part) => sum + part.length, 0);
      if (offset !== current) throw new Error("offset mismatch");
      list.push(bytes.slice());
      return current + bytes.length;
    }),
    writeCommit: vi.fn(async (handle) => expected.get(handle)!),
    writeAbort: vi.fn(async () => {}),
    readOpen: vi.fn(),
    readChunk: vi.fn(),
    readClose: vi.fn(),
    ref: vi.fn(async () => 1),
    unref: vi.fn(async () => 0),
  };
  const statements: string[] = [];
  const db: OfflineDbBridge = {
    open: vi.fn(),
    isOpen: vi.fn(async () => true),
    exec: vi.fn(async (_app, sql) => {
      statements.push(sql);
      return 1;
    }),
    query: vi.fn(async () => []),
    wipe: vi.fn(),
  };
  return { bridge, db, statements };
}

describe("recoverable offline artifacts", () => {
  it("streams oversized supplied chunks as bounded native chunks and commits metadata atomically", async () => {
    const raw = new Uint8Array(600_000).fill(1);
    const attachment = new Uint8Array(300_000).fill(2);
    const { bridge, db, statements } = fakes();
    expect(
      await captureRecoveryArtifact(db, bridge, input(raw, attachment)),
    ).toBe("covered");
    for (const call of vi.mocked(bridge.writeChunk).mock.calls) {
      expect(call[2].length).toBeLessThanOrEqual(RECOVERY_CHUNK_BYTES);
    }
    expect(statements[0]).toBe("BEGIN");
    expect(statements.at(-1)).toBe("COMMIT");
    expect(bridge.ref).toHaveBeenCalledTimes(2);
  });

  it("never treats metadata or mutable outbound state as recoverable", async () => {
    const { bridge, db } = fakes();
    const candidate = input(new Uint8Array([1]));
    candidate.kind = "sent-terminal";
    expect(await captureRecoveryArtifact(db, bridge, candidate)).toBe(
      "covered",
    );
    for (const mutable of [
      "draft",
      "queued",
      "scheduled",
      "metadata",
    ] as const) {
      const next = input(new Uint8Array([1]));
      (next as { kind: string }).kind = mutable;
      await expect(captureRecoveryArtifact(db, bridge, next)).rejects.toThrow(
        /mutable/,
      );
    }
  });

  it("rolls back and aborts native handles when metadata insertion fails", async () => {
    const { bridge, db, statements } = fakes();
    vi.mocked(db.exec).mockImplementation(async (_app, sql) => {
      statements.push(sql);
      if (sql.includes("INSERT INTO recovery_artifacts"))
        throw new Error("disk full");
      return 1;
    });
    await expect(
      captureRecoveryArtifact(db, bridge, input(new Uint8Array([1, 2]))),
    ).rejects.toThrow(/disk full/);
    expect(statements).toContain("ROLLBACK");
    expect(bridge.writeAbort).toHaveBeenCalled();
  });

  it("refuses receipt scope and incomplete byte inventory mismatches", async () => {
    const { bridge, db } = fakes();
    const wrongMessage = input(new Uint8Array([1]));
    wrongMessage.messageId = "other";
    await expect(
      captureRecoveryArtifact(db, bridge, wrongMessage),
    ).rejects.toThrow(/scope mismatch/);

    const missing = input(new Uint8Array([1]), new Uint8Array([2]));
    missing.sources.pop();
    await expect(captureRecoveryArtifact(db, bridge, missing)).rejects.toThrow(
      /inventory incomplete/,
    );
  });
});
