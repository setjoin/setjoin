//! Generic bounded recovery-blob handlers. The app key is hard-bound to mail;
//! the renderer can move at most one 256 KiB chunk per call and never receives
//! a SQLCipher key or a path.

import type { NativeBinding } from "../native";
import type { HandlerMap } from "./db";

const APP = "mail";
const MAX_CHUNK = 256 * 1024;
type RecoveryNative = Required<
  Pick<
    NativeBinding,
    | "recoveryBlobWriteBegin"
    | "recoveryBlobWriteChunk"
    | "recoveryBlobWriteCommit"
    | "recoveryBlobWriteAbort"
    | "recoveryBlobReadOpen"
    | "recoveryBlobReadChunk"
    | "recoveryBlobReadClose"
    | "recoveryBlobRef"
    | "recoveryBlobUnref"
  >
>;

function requireRecoveryNative(native: NativeBinding): RecoveryNative {
  for (const name of [
    "recoveryBlobWriteBegin",
    "recoveryBlobWriteChunk",
    "recoveryBlobWriteCommit",
    "recoveryBlobWriteAbort",
    "recoveryBlobReadOpen",
    "recoveryBlobReadChunk",
    "recoveryBlobReadClose",
    "recoveryBlobRef",
    "recoveryBlobUnref",
  ] as const) {
    if (typeof native[name] !== "function")
      throw new Error(`desktop-native is missing ${name}`);
  }
  return native as RecoveryNative;
}

function bytesFrom(value: unknown): Buffer {
  const bytes = Buffer.isBuffer(value)
    ? value
    : value instanceof Uint8Array
      ? Buffer.from(value)
      : Buffer.from([]);
  if (bytes.length === 0 || bytes.length > MAX_CHUNK) {
    throw new Error("recovery blob chunk must be 1..262144 bytes");
  }
  return bytes;
}

export function makeRecoveryBlobHandlers(native: NativeBinding): HandlerMap {
  const recovery = requireRecoveryNative(native);
  return {
    recovery_blob_write_begin: (sha256: unknown, size: unknown) =>
      JSON.parse(
        recovery.recoveryBlobWriteBegin(APP, String(sha256), Number(size)),
      ),
    recovery_blob_write_chunk: (
      handle: unknown,
      offset: unknown,
      bytes: unknown,
    ) =>
      recovery.recoveryBlobWriteChunk(
        APP,
        String(handle),
        Number(offset),
        bytesFrom(bytes),
      ),
    recovery_blob_write_commit: (handle: unknown) =>
      recovery.recoveryBlobWriteCommit(APP, String(handle)),
    recovery_blob_write_abort: (handle: unknown) =>
      recovery.recoveryBlobWriteAbort(APP, String(handle)),
    recovery_blob_read_open: (sha256: unknown) =>
      JSON.parse(recovery.recoveryBlobReadOpen(APP, String(sha256))),
    recovery_blob_read_chunk: (
      handle: unknown,
      offset: unknown,
      length: unknown,
    ) => {
      const n = Number(length);
      if (!Number.isInteger(n) || n < 1 || n > MAX_CHUNK) {
        throw new Error("recovery blob read length must be 1..262144");
      }
      return new Uint8Array(
        recovery.recoveryBlobReadChunk(APP, String(handle), Number(offset), n),
      );
    },
    recovery_blob_read_close: (handle: unknown) =>
      recovery.recoveryBlobReadClose(APP, String(handle)),
    recovery_blob_ref: (sha256: unknown) =>
      recovery.recoveryBlobRef(APP, String(sha256)),
    recovery_blob_unref: (sha256: unknown) =>
      recovery.recoveryBlobUnref(APP, String(sha256)),
  } as HandlerMap;
}
