//! The `window.setjoinNative` provider shape — the Electron equivalent of Tauri
//! `bridge_js.rs`'s init-script template. Kept electron-free (takes an `invoke`
//! function) so the contract shape is unit-testable without a renderer.
//!
//! Implements the FULL current `SetjoinNativeBridge` from
//! `mailserver/webmail/src/lib/native/types.ts` — including the drift the Tauri
//! shell never implemented: vault.unlockPassphrase (aliases unlock),
//! vault.unlockBiometric → honest false, vault.isEnrolled → honest false.

export const BRIDGE_VERSION = 1;

/** Version of the `vault.*` sub-shape, independent of BRIDGE_VERSION (C2 Task 2 Step 3b —
 *  mirrors `mailserver/webmail/src/lib/native/types.ts` VAULT_VERSION). */
export const VAULT_VERSION = 1;

/**
 * Capabilities the desktop shell advertises — a subset of C0's
 * NATIVE_CAPABILITIES (no mobile push/biometric on desktop). Matches Tauri's
 * DESKTOP_CAPABILITIES.
 */
export const DESKTOP_CAPABILITIES = [
  "secureStore",
  "vault",
  "share",
  "pickFile",
  "notify",
  "openExternal",
  "mailDb",
  "deviceProof",
  "driveMirror",
  "drive",
  "recoveryBlob",
] as const;

/** Drive P2's FolderMirror sub-shape version (mirrors DRIVE_MIRROR_VERSION in
 *  mailserver/webmail/src/lib/native/types.ts). */
export const DRIVE_MIRROR_VERSION = 3;

export type Invoke = (channel: string, ...args: unknown[]) => Promise<unknown>;

interface SharePayload {
  title?: string;
  text?: string;
  url?: string;
}
interface NotifyPayload {
  title: string;
  body?: string;
  tag?: string;
}
interface PickedFile {
  name: string;
  type: string;
  dataBase64: string;
}

/** Reconstruct a `File` from the main-process picked-file result. */
function reconstructFile(res: PickedFile): File {
  const bytes = Uint8Array.from(atob(res.dataBase64), (c) => c.charCodeAt(0));
  return new File([bytes], res.name, { type: res.type });
}

/** Build the `window.setjoinNative` object over an `invoke` transport. */
export function buildBridge(invoke: Invoke) {
  return {
    version: BRIDGE_VERSION,
    capabilities: [...DESKTOP_CAPABILITIES],

    // Desktop has no mobile push / platform biometric — honest answers.
    pushRegister: async (): Promise<string | null> => null,
    // No push capability on desktop, so the push-MFA ECDH key is never
    // registered — honest null (the crate exports it for the mobile shells).
    pushDevicePublicKey: async (): Promise<string | null> => null,
    biometricUnlock: async (_reason: string): Promise<boolean> => false,

    secureStore: {
      get: (key: string) =>
        invoke("secure_store_get", key) as Promise<string | null>,
      set: (key: string, value: string) =>
        invoke("secure_store_set", key, value) as Promise<void>,
      remove: (key: string) =>
        invoke("secure_store_remove", key) as Promise<void>,
    },

    vault: {
      version: VAULT_VERSION,
      unlock: (passphrase: string) =>
        invoke("vault_unlock", passphrase) as Promise<boolean>,
      isUnlocked: () => invoke("vault_is_unlocked") as Promise<boolean>,
      listTotp: () =>
        invoke("vault_list_totp") as Promise<
          Array<{ id: string; label: string; issuer: string }>
        >,
      generateTotp: (id: string) =>
        invoke("vault_generate_totp", id) as Promise<string>,
      // Drift closure (Tauri never implemented these):
      unlockPassphrase: (passphrase: string) =>
        invoke("vault_unlock", passphrase) as Promise<boolean>, // alias of unlock
      unlockBiometric: async (): Promise<boolean> => false, // no desktop biometric API
      isEnrolled: async (): Promise<boolean> => false, // no desktop biometric enrolment
    },

    // Desktop share → mailto fallback via the openExternal bridge.
    share: (payload: SharePayload): Promise<void> => {
      const text = [payload?.text, payload?.url].filter(Boolean).join(" ");
      const subject = payload?.title ?? "";
      const url = `mailto:?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(text)}`;
      return invoke("open_external", url) as Promise<void>;
    },

    pickFile: async (accept?: string): Promise<File | null> => {
      const res = (await invoke("pick_file", accept)) as PickedFile | null;
      return res ? reconstructFile(res) : null;
    },

    notify: (payload: NotifyPayload): Promise<void> =>
      invoke("notify", payload.title, payload.body) as Promise<void>,

    openExternal: (url: string): Promise<void> =>
      invoke("open_external", url) as Promise<void>,

    db: {
      open: (appKey: string, profile?: string) =>
        invoke("db_open", appKey, profile ?? "standard") as Promise<void>,
      isOpen: (appKey: string) =>
        invoke("db_is_open", appKey) as Promise<boolean>,
      exec: (appKey: string, sql: string, params: unknown[] = []) =>
        invoke("db_exec", appKey, sql, params) as Promise<number>,
      // Authorized one-shot schema-init seam (med-offcore-sqlguard-001 r3):
      // the only channel a multi-statement batch (MAIL_SCHEMA) may traverse.
      execSchemaInit: (appKey: string, sql: string) =>
        invoke("db_exec_schema_init", appKey, sql) as Promise<number>,
      // E4-I native transaction freeze: the authorized atomic job batch. The
      // webmail pre-admits through $lib/offline/nativeBatch; the native
      // validator inside offline-core re-validates everything before its ONE
      // transaction opens and resolves with the total changed-row count.
      transactionBatch: (appKey: string, statements: unknown[], budget: unknown) =>
        invoke(
          "db_transaction_batch",
          appKey,
          statements,
          budget,
        ) as Promise<number>,
      // E4-I versioned store migration: native drives its own bundled
      // manifest copy (installer/application-update trust path) and answers
      // {"version":N}; parsed here like db_query's JSON array.
      migrateStore: async (appKey: string, targetVersion: number) =>
        JSON.parse(
          (await invoke("db_migrate_store", appKey, targetVersion)) as string,
        ) as { version: number },
      query: (appKey: string, sql: string, params: unknown[] = []) =>
        (invoke("db_query", appKey, sql, params) as Promise<string>).then(
          (s) => JSON.parse(s) as unknown[],
        ),
      wipe: (appKey: string) => invoke("db_wipe", appKey) as Promise<void>,
    },

    recoveryBlob: {
      writeBegin: (sha256: string, size: number) =>
        invoke("recovery_blob_write_begin", sha256, size) as Promise<{
          handle: string;
          nextOffset: number;
        }>,
      writeChunk: (handle: string, offset: number, bytes: Uint8Array) =>
        invoke(
          "recovery_blob_write_chunk",
          handle,
          offset,
          bytes,
        ) as Promise<number>,
      writeCommit: (handle: string) =>
        invoke("recovery_blob_write_commit", handle) as Promise<string>,
      writeAbort: (handle: string) =>
        invoke("recovery_blob_write_abort", handle) as Promise<void>,
      readOpen: (sha256: string) =>
        invoke("recovery_blob_read_open", sha256) as Promise<{
          handle: string;
          size: number;
        }>,
      readChunk: (handle: string, offset: number, length: number) =>
        invoke(
          "recovery_blob_read_chunk",
          handle,
          offset,
          length,
        ) as Promise<Uint8Array>,
      readClose: (handle: string) =>
        invoke("recovery_blob_read_close", handle) as Promise<void>,
      ref: (sha256: string) =>
        invoke("recovery_blob_ref", sha256) as Promise<number>,
      unref: (sha256: string) =>
        invoke("recovery_blob_unref", sha256) as Promise<number>,
    },

    // HMAC secret is native-side only — JS receives { hmac } or null.
    deviceProof: (args: { deviceId: string; timestamp: string }) =>
      invoke("device_proof", args.deviceId, args.timestamp) as Promise<{
        hmac: string;
      } | null>,

    // Drive P2's FolderMirror control surface — see native/types.ts's
    // DriveMirrorBridge doc for the auth story (bytes/secrets never cross
    // this bridge; only status/config JSON and the renderer-minted token).
    driveMirror: {
      version: DRIVE_MIRROR_VERSION,
      status: () => invoke("drive_mirror_status") as Promise<unknown>,
      configure: (cfg: unknown) =>
        invoke("drive_mirror_configure", cfg) as Promise<void>,
      refreshToken: (token: string, expiresAt: string) =>
        invoke("drive_mirror_refresh_token", token, expiresAt) as Promise<void>,
      setPaused: (paused: boolean) =>
        invoke("drive_mirror_set_paused", paused) as Promise<void>,
      resync: (spaceId?: number) =>
        invoke("drive_mirror_resync", spaceId) as Promise<void>,
      openRoot: (spaceId: number) =>
        invoke("drive_mirror_open_root", spaceId) as Promise<void>,
      officeChoices: () =>
        invoke("drive_mirror_office_choices") as Promise<unknown>,
      openOffice: (spaceId: number, nodeId: number, appId: string) =>
        invoke("drive_mirror_open_office", spaceId, nodeId, appId) as Promise<void>,
    },

    // Drive P3 secure-vault byte plane (ARCH-017) — control/metadata ONLY
    // (URLs, hashes, tickets); bytes move natively or over the loopback
    // render server. `serveStop` is deliberately NOT exposed here — revoke
    // + wipe cover the shell's needs (plan's self-review: "resist scope
    // creep"); it stays a Rust/test-facing member of native.ts's contract.
    //
    // Privileged-parameter discipline (ER5 occ_84092b66054634ea88d3b489 /
    // occ_f10aa5892bfc1a7769b17b49): the renderer-supplied arguments of the
    // byte plane are NOT authoritative on the native side — the main-process
    // handlers (handlers/drive.ts) origin-gate chunk URLs, confine
    // drive_import_file to registered mirror files, and ignore this
    // parameter position for the bearer (the drive token lives in main's
    // DriveTokenOwner). The bridge therefore never even puts a
    // renderer-supplied bearer on the wire: the parameter stays (the
    // renderer contract shape in webmail's types.ts is fixed) but `null` is
    // forwarded, so a renderer credential is structurally unable to reach
    // the native http agent.
    drive: {
      importFile: (srcPath: string) =>
        invoke("drive_import_file", srcPath) as Promise<unknown>,
      fetchChunk: (url: string, _bearer: string, sha256: string, size: number) =>
        invoke("drive_fetch_chunk", url, null, sha256, size) as Promise<void>,
      pushChunk: (url: string, _bearer: string, sha256: string) =>
        invoke("drive_push_chunk", url, null, sha256) as Promise<number>,
      hasChunk: (sha256: string) =>
        invoke("drive_has_chunk", sha256) as Promise<boolean>,
      deleteChunks: (sha256s: string[]) =>
        invoke("drive_delete_chunks", sha256s) as Promise<number>,
      serveStart: () =>
        invoke("drive_serve_start") as Promise<{ port: number }>,
      serveGrant: (manifest: unknown) =>
        invoke("drive_serve_grant", manifest) as Promise<string>,
      serveRevoke: (ticket: string) =>
        invoke("drive_serve_revoke", ticket) as Promise<void>,
    },
  };
}
