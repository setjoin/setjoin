// NativeBinding — thin ArkTS wrapper over `libohos_native.so` (the ohos-rs
// NAPI crate at clients/rust/ohos-native wrapping guard-core + offline-core).
//
// Mirrors clients/desktop/electron/src/native.ts's `NativeBinding` interface
// 1:1 (same 18 method names/arities — the napi-rs/napi-ohos `#[napi]` macro
// converts each Rust `snake_case` export to a JS `camelCase` method, same
// convention both crates rely on). No business logic here: the SQL statement
// allowlist, appKey→path resolution, and MAM HTTP/HMAC all live one layer up
// (DbAllowlist.ets / Mam.ets / BridgeProxy.ets) — mirrors the native.ts vs
// handlers/*.ts split on Electron.

// The napi-ohos module registered under the crate's cdylib name (`ohos_native`
// → `libohos_native.so`), loaded the same way every ohos-rs example loads its
// compiled crate: a bare `import <name> from 'lib<name>.so'`.
import ohosNative from 'libohos_native.so';

interface OhosNativeModule {
  vaultUnlock(dbPath: string, passphrase: string): boolean;
  vaultIsUnlocked(): boolean;
  vaultListTotp(): Array<TotpEntryNative>;
  vaultGenerateTotp(id: string): string;
  pushDevicePublicKey(): string;
  secureStoreGet(key: string): string | null;
  secureStoreSet(key: string, value: string): void;
  secureStoreRemove(key: string): void;
  dbOpen(dbPath: string, appKey: string, profile: string): void;
  dbIsOpen(appKey: string): boolean;
  dbExec(appKey: string, sql: string, paramsJson: string): number;
  dbQuery(appKey: string, sql: string, paramsJson: string): string;
  dbWipe(appKey: string): void;
  // Drive P3 secure-vault byte plane (ARCH-017). The four that stream a whole
  // file/chunk are napi `AsyncTask`s on the Rust side — napi-ohos surfaces
  // them as real Promises here too (registered on BridgeProxy's
  // `asyncMethodList`, not `methodList` — see BridgeProxy's doc comment).
  // `driveServeStop` mirrors the full Rust export set (like
  // `pushDevicePublicKey` above) but is intentionally not wired into
  // BridgeProxy/BridgeShim — revoke + wipe cover the shell's needs.
  driveImportFile(appKey: string, srcPath: string): Promise<string>;
  driveFetchChunk(appKey: string, url: string, bearer: string, sha256: string, size: number): Promise<void>;
  drivePushChunk(appKey: string, url: string, bearer: string, sha256: string): Promise<number>;
  driveHasChunk(appKey: string, sha256: string): boolean;
  driveDeleteChunks(appKey: string, sha256sJson: string): number;
  // Astra desktop-drive-bridge-unconfined r2 item 1: the trusted-policy seam
  // is a REQUIRED member of the binding contract (the shared native_impl.rs
  // exports drive_set_confinement in both napi twins) — BridgeProxy.ets
  // installs the import roots + approved chunk origins through it,
  // non-optionally. An optional projection could never supply the missing
  // native export, so this is deliberately not `?`.
  driveSetConfinement(importRoots: Array<string>, approvedOrigins: Array<string>): void;
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

export interface TotpEntryNative {
  id: string;
  label: string;
  issuer: string;
}

const native = ohosNative as OhosNativeModule;

export class NativeBinding {
  // ── Vault (guard-core) ─────────────────────────────────────────────────
  static vaultUnlock(dbPath: string, passphrase: string): boolean {
    return native.vaultUnlock(dbPath, passphrase);
  }
  static vaultIsUnlocked(): boolean {
    return native.vaultIsUnlocked();
  }
  static vaultListTotp(): Array<TotpEntryNative> {
    return native.vaultListTotp();
  }
  static vaultGenerateTotp(id: string): string {
    return native.vaultGenerateTotp(id);
  }

  // ── Push MFA device key (guard-core ECDH) ──────────────────────────────────
  /** Raw 65-byte uncompressed SEC1 P-256 public key, hex — POSTed as
   *  `device_public_key` to `/auth/device/register` (see PUSH_ECIES_CONTRACT.md). */
  static pushDevicePublicKey(): string {
    return native.pushDevicePublicKey();
  }

  // ── Secure store ─────────────────────────────────────────────────────────
  static secureStoreGet(key: string): string | null {
    return native.secureStoreGet(key);
  }
  static secureStoreSet(key: string, value: string): void {
    native.secureStoreSet(key, value);
  }
  static secureStoreRemove(key: string): void {
    native.secureStoreRemove(key);
  }

  // ── Offline encrypted store ──────────────────────────────────────────────
  static dbOpen(dbPath: string, appKey: string, profile: string): void {
    native.dbOpen(dbPath, appKey, profile);
  }
  static dbIsOpen(appKey: string): boolean {
    return native.dbIsOpen(appKey);
  }
  static dbExec(appKey: string, sql: string, paramsJson: string): number {
    return native.dbExec(appKey, sql, paramsJson);
  }
  static dbQuery(appKey: string, sql: string, paramsJson: string): string {
    return native.dbQuery(appKey, sql, paramsJson);
  }
  static dbWipe(appKey: string): void {
    native.dbWipe(appKey);
  }

  // ── Drive P3 secure-vault byte plane (ARCH-017) ──────────────────────────
  static driveImportFile(appKey: string, srcPath: string): Promise<string> {
    return native.driveImportFile(appKey, srcPath);
  }
  static driveFetchChunk(appKey: string, url: string, bearer: string, sha256: string, size: number): Promise<void> {
    return native.driveFetchChunk(appKey, url, bearer, sha256, size);
  }
  static drivePushChunk(appKey: string, url: string, bearer: string, sha256: string): Promise<number> {
    return native.drivePushChunk(appKey, url, bearer, sha256);
  }
  static driveHasChunk(appKey: string, sha256: string): boolean {
    return native.driveHasChunk(appKey, sha256);
  }
  static driveDeleteChunks(appKey: string, sha256sJson: string): number {
    return native.driveDeleteChunks(appKey, sha256sJson);
  }
  // Astra desktop-drive-bridge-unconfined r2 item 1: required seam — see the
  // OhosNativeModule declaration above.
  static driveSetConfinement(importRoots: Array<string>, approvedOrigins: Array<string>): void {
    native.driveSetConfinement(importRoots, approvedOrigins);
  }
  static driveServeStart(appKey: string): Promise<string> {
    return native.driveServeStart(appKey);
  }
  static driveServeGrant(appKey: string, manifestJson: string): string {
    return native.driveServeGrant(appKey, manifestJson);
  }
  static driveServeRevoke(appKey: string, ticket: string): void {
    native.driveServeRevoke(appKey, ticket);
  }

  // ── MAM device-trust value cache ─────────────────────────────────────────
  static mamStoreDeviceId(deviceId: string): void {
    native.mamStoreDeviceId(deviceId);
  }
  static mamStorePolicy(policyJson: string): void {
    native.mamStorePolicy(policyJson);
  }
  static mamGetPolicy(): string | null {
    return native.mamGetPolicy();
  }
  static mamMarkWiped(): void {
    native.mamMarkWiped();
  }
  static mamIsWiped(): boolean {
    return native.mamIsWiped();
  }
  static mamClearWiped(): void {
    native.mamClearWiped();
  }
}
