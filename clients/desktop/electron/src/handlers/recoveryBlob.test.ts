import { describe, expect, it, vi } from "vitest";
import type { NativeBinding } from "../native";
import { makeRecoveryBlobHandlers } from "./recoveryBlob";

function nativeRecovery(): NativeBinding {
  return {
    recoveryBlobWriteBegin: vi.fn(() => '{"handle":"w","nextOffset":0}'),
    recoveryBlobWriteChunk: vi.fn(() => 3),
    recoveryBlobWriteCommit: vi.fn(() => "a".repeat(64)),
    recoveryBlobWriteAbort: vi.fn(),
    recoveryBlobReadOpen: vi.fn(() => '{"handle":"r","size":3}'),
    recoveryBlobReadChunk: vi.fn(() => Buffer.from([1, 2, 3])),
    recoveryBlobReadClose: vi.fn(),
    recoveryBlobRef: vi.fn(() => 1),
    recoveryBlobUnref: vi.fn(() => 0),
  } as unknown as NativeBinding;
}

describe("recovery blob handlers", () => {
  it("hard-binds mail and preserves bounded byte chunks", () => {
    const native = nativeRecovery();
    const h = makeRecoveryBlobHandlers(native);
    expect(h.recovery_blob_write_begin("a".repeat(64), 3)).toEqual({
      handle: "w",
      nextOffset: 0,
    });
    expect(h.recovery_blob_write_chunk("w", 0, new Uint8Array([1, 2, 3]))).toBe(
      3,
    );
    expect(native.recoveryBlobWriteBegin).toHaveBeenCalledWith(
      "mail",
      "a".repeat(64),
      3,
    );
    expect(native.recoveryBlobWriteChunk).toHaveBeenCalledWith(
      "mail",
      "w",
      0,
      expect.any(Buffer),
    );
    expect(h.recovery_blob_read_open("a".repeat(64))).toEqual({
      handle: "r",
      size: 3,
    });
    expect(h.recovery_blob_read_chunk("r", 0, 3)).toEqual(
      new Uint8Array([1, 2, 3]),
    );
  });

  it("rejects empty, oversized, and oversized-read bridge payloads", () => {
    const h = makeRecoveryBlobHandlers(nativeRecovery());
    expect(() => h.recovery_blob_write_chunk("w", 0, new Uint8Array())).toThrow(
      /1\.\.262144/,
    );
    expect(() =>
      h.recovery_blob_write_chunk("w", 0, new Uint8Array(262145)),
    ).toThrow(/1\.\.262144/);
    expect(() => h.recovery_blob_read_chunk("r", 0, 262145)).toThrow(
      /1\.\.262144/,
    );
  });

  it("fails closed when the native addon is too old", () => {
    expect(() => makeRecoveryBlobHandlers({} as NativeBinding)).toThrow(
      /missing/,
    );
  });
});
