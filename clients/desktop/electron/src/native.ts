//! The FIXED contract implemented by the napi-rs crate at
//! `clients/rust/desktop-native/` (a SEPARATE agent owns that Rust code; this
//! is the TS view of its exports — do not change these names/arities). The
//! crate also exports `pushDevicePublicKey`, intentionally omitted here: desktop
//! has no `push` capability, so `bridge.ts` answers it `null` without a binding.
//!
//! All native state (vault unlocked, offline engine, MAM cache) lives inside
//! the Rust module as process-global, exactly as Tauri held it in managed
//! state. The Electron main process is one long-lived Node process, so this
//! matches the same lifetime shape.
//!
//! The binding is loaded once and INJECTED into every handler factory, so unit
//! tests pass a fake implementing this same interface — the suite never blocks
//! on the Rust crate actually compiling.

export interface NativeBinding {
  vaultUnlock(dbPath: string, passphrase: string): boolean;
  vaultIsUnlocked(): boolean;
  vaultListTotp(): Array<{ id: string; label: string; issuer: string }>;
  vaultGenerateTotp(id: string): string;
  secureStoreGet(key: string): string | null;
  secureStoreSet(key: string, value: string): void;
  secureStoreRemove(key: string): void;
  dbOpen(dbPath: string, appKey: string, profile: string): void;
  dbIsOpen(appKey: string): boolean;
  dbExec(appKey: string, sql: string, paramsJson: string): number;
  /**
   * Authorized schema-initialization seam (med-offcore-sqlguard-001 r3): the
   * ONLY way a multi-statement batch (e.g. MAIL_SCHEMA) executes. Ordinary
   * `dbExec` refuses multi-statement payloads; the batch is validated
   * statement-by-statement inside offline-core and the path is one-shot per
   * open store connection. Required member: the shared native_impl.rs exports
   * `db_exec_schema_init` in both napi twins — like `driveSetConfinement`, an
   * optional projection could never supply the missing native export.
   */
  dbExecSchemaInit(appKey: string, sql: string): number;
  /**
   * E4-I native transaction freeze (docs/verification/
   * 2026-09-08-connectivity-native-transaction-freeze.md): the authorized
   * atomic job batch — the ONLY entry that owns transaction control.
   * `statementsJson` is a JSON array of `{sql, params?}`; `budgetJson` is
   * `{maxStatements, maxParamBytes}`. Validation (parameterized reads/DML
   * only; transaction control, DDL and side-effecting statements refused) and
   * the aggregate budget check happen INSIDE offline-core before the
   * transaction opens; the batch then executes in ONE transaction and either
   * commits entirely or applies nothing. Resolves with the total changed-row
   * count; throws on refusal or failure. Required member: the shared
   * native_impl.rs exports `db_transaction_batch` in both napi twins — like
   * `dbExecSchemaInit`/`driveSetConfinement`, an optional projection could
   * never supply the missing native export.
   */
  dbTransactionBatch(appKey: string, statementsJson: string, budgetJson: string): number;
  /**
   * E4-I versioned store migration entry: drives the offline-core BUNDLED
   * per-app migration manifest (the installer/application-update trust-path
   * copy; no runtime register entry exists). Refuses apps the manifest does
   * not cover and unknown/ahead/downgrade targets, then commits each declared
   * transactional step plus its version row atomically. Returns a
   * `{"version":N}` JSON string. Required member (same rationale as
   * `dbTransactionBatch`).
   */
  dbMigrateStore(appKey: string, targetVersion: number): string;
  dbQuery(appKey: string, sql: string, paramsJson: string): string;
  dbWipe(appKey: string): void;
  recoveryBlobWriteBegin?(appKey: string, sha256: string, size: number): string;
  recoveryBlobWriteChunk?(
    appKey: string,
    handle: string,
    offset: number,
    bytes: Buffer,
  ): number;
  recoveryBlobWriteCommit?(appKey: string, handle: string): string;
  recoveryBlobWriteAbort?(appKey: string, handle: string): void;
  recoveryBlobReadOpen?(appKey: string, sha256: string): string;
  recoveryBlobReadChunk?(
    appKey: string,
    handle: string,
    offset: number,
    length: number,
  ): Buffer;
  recoveryBlobReadClose?(appKey: string, handle: string): void;
  recoveryBlobRef?(appKey: string, sha256: string): number;
  recoveryBlobUnref?(appKey: string, sha256: string): number;
  // Drive P3 secure-vault byte plane (ARCH-017). The four that stream a whole
  // file/chunk are `AsyncTask`s on the Rust side — they resolve as real
  // Promises here, unlike every sync member above/below (a sync call would
  // freeze the renderer for the duration of a multi-chunk transfer).
  // `driveServeStop` mirrors the full Rust export set (like
  // `pushDevicePublicKey` above) but is intentionally NOT wired into
  // `bridge.ts`'s DriveBridge — revoke + wipe cover the shell's needs; stop
  // stays Rust/test-facing (plan's self-review: "resist scope creep").
  driveImportFile(appKey: string, srcPath: string): Promise<string>;
  driveFetchChunk(
    appKey: string,
    url: string,
    bearer: string,
    sha256: string,
    size: number,
  ): Promise<void>;
  drivePushChunk(
    appKey: string,
    url: string,
    bearer: string,
    sha256: string,
  ): Promise<number>;
  driveHasChunk(appKey: string, sha256: string): boolean;
  driveDeleteChunks(appKey: string, sha256sJson: string): number;
  // Astra desktop-drive-bridge-unconfined r2 item 1: the trusted-policy seam
  // is a REQUIRED member of the binding contract (the shared native_impl.rs
  // exports drive_set_confinement) — main.ts installs the import roots +
  // approved chunk origins through it, non-optionally. An optional projection
  // could never supply the missing native export, so this is deliberately not
  // `?`.
  driveSetConfinement(importRoots: string[], approvedOrigins: string[]): void;
  driveServeStart(appKey: string): Promise<string>;
  driveServeGrant(appKey: string, manifestJson: string): string;
  driveServeRevoke(appKey: string, ticket: string): void;
  driveServeStop(appKey: string): void;
  mamStoreDeviceId(deviceId: string): void;
  mamStorePolicy(policyJson: string): void;
  mamGetPolicy(): string | null;
  mamMarkWiped(): void;
  mamIsWiped(): boolean;
  mamClearWiped(): void;
}

/**
 * Load the built napi-rs module (`index.js` glue + platform `.node` produced by
 * `napi build` in `clients/rust/desktop-native/`). Throws a clear error when
 * the crate hasn't been built; handler code takes the binding as an injected
 * parameter, so tests never reach here.
 */
export function loadNativeBinding(baseDirOverride?: string): NativeBinding {
  // Packaged: the napi glue (`index.js` + platform `.node`) is shipped as an
  // electron-builder extraResource at `<resources>/desktop-native/`; main.ts
  // passes that path. Dev: __dirname-anchored — src/ and dist/ sit at the same
  // depth under clients/desktop/electron/, so three levels up reaches clients/
  // from either. (A bare relative require resolved against dist/ landed short.)
  const modulePath =
    baseDirOverride ??
    require("node:path").resolve(
      __dirname,
      "..",
      "..",
      "..",
      "rust",
      "desktop-native",
    );
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    return require(modulePath) as NativeBinding;
  } catch (e) {
    throw new Error(
      `desktop-native module not loadable from ${modulePath}: run \`napi build\` in clients/rust/desktop-native (${String(e)})`,
    );
  }
}
