export const BRIDGE_VERSION = 1;

/**
 * Version of the `window.setjoinNative.vault.*` sub-shape, independent of
 * `BRIDGE_VERSION`. The whole-bridge version covers the outer contract; a
 * `guard-core` vault API change (e.g. a new unlock mode) can drift from the
 * webmail's expectation without touching anything else the bridge exposes, so
 * `vault` gets its own version the webmail can assert and degrade against.
 */
export const VAULT_VERSION = 1;

export const NATIVE_CAPABILITIES = [
  "push",
  "biometric",
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
export type NativeCapability = (typeof NATIVE_CAPABILITIES)[number];

export interface SecureStore {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  remove(key: string): Promise<void>;
}

export interface VaultBridge {
  /** Version of this sub-shape. Bump `VAULT_VERSION` on a breaking change; callers should
   *  assert it matches and degrade gracefully (not mis-call a changed API) on mismatch. */
  readonly version: number;
  unlock(passphrase: string): Promise<boolean>;
  isUnlocked(): Promise<boolean>;
  listTotp(): Promise<Array<{ id: string; label: string; issuer: string }>>;
  generateTotp(id: string): Promise<string>;
  /** Prompt the OS biometric sheet to unlock the mail store key. Returns true on success. */
  unlockBiometric(): Promise<boolean>;
  /** Verify a passphrase against the mail store key. Returns true on success. */
  unlockPassphrase(passphrase: string): Promise<boolean>;
  /** Whether the device has a biometric enrolled (Face/Touch ID or equivalent). */
  isEnrolled(): Promise<boolean>;
}

export interface SharePayload {
  title?: string;
  text?: string;
  url?: string;
}
export interface NotifyPayload {
  title: string;
  body?: string;
  tag?: string;
}

/**
 * Version of the `window.setjoinNative.driveMirror` sub-shape (Drive P2's
 * FolderMirror), independent of `BRIDGE_VERSION` — same rationale as
 * `VAULT_VERSION`.
 */
export const DRIVE_MIRROR_VERSION = 3;

export interface DriveMirrorSpaceStatus {
  spaceId: number;
  name: string;
  state: "idle" | "syncing" | "error" | "vault-locked" | "auth-expired" | "policy-blocked";
  lastSyncMs: number | null;
  pendingUploads: number;
  issues: number;
  aclMode?: "legacy" | "shadow" | "acl";
  unmanagedAclRiskAccepted?: boolean;
}
export interface DriveMirrorStatus {
  running: boolean;
  paused: boolean;
  perSpace: DriveMirrorSpaceStatus[];
  issues: Array<{
    code: string;
    relPath: string;
    detail: string;
    atMs: number;
  }>;
}

/**
 * The Electron main-process FolderMirror's renderer-facing control surface
 * (Drive P2). Bytes never cross this bridge (spec §4.1 R1) — the renderer
 * sees only status/config JSON; every hash/transfer/disk-write happens in
 * main.
 *
 * **Auth (batch-2 C3, resolved by batch-3 C14/C15 — P1 owns
 * `POST /drive/native-token`):** the packaged shell's main process has no
 * server-origin cookie (`main.ts` loads `file://`), so it authenticates its
 * own fetches with a short-lived drive-scoped bearer token instead. Only the
 * renderer holds the SPA's cookie session, so only the renderer can MINT
 * that token — it does so and hands it over via `refreshToken`, never the
 * reverse, and the token itself never round-trips back out to web content.
 * Main slides the token forward on its own after that (re-POSTing
 * native-token with its current still-valid token as `Authorization:
 * Bearer` — P1's sliding-renewal contract), so sync keeps working across a
 * TTL boundary with the window closed; the renderer only needs to call
 * `refreshToken` again after the session is revoked or the token fully
 * lapses, surfaced as the per-space `'auth-expired'` state (never a
 * `transfer-failed` retry loop).
 */
export interface DriveMirrorBridge {
  /** Version of this sub-shape. Bump `DRIVE_MIRROR_VERSION` on a breaking change; callers should
   *  assert it matches and degrade gracefully (not mis-call a changed API) on mismatch. */
  readonly version: number;
  status(): Promise<DriveMirrorStatus>;
  configure(cfg: {
    serverOrigin: string;
    spaces: Array<{
      spaceId: number;
      excludes: string[];
      /** FolderMirror writes plaintext copies outside managed storage. ACL-mode
       * spaces therefore require an explicit per-space residual-copy acceptance. */
      acceptUnmanagedAclRisk?: boolean;
    }>;
  }): Promise<void>;
  /** Hand main a freshly-minted drive-native token (renderer-minted via its own cookie session). */
  refreshToken(token: string, expiresAt: string): Promise<void>;
  setPaused(paused: boolean): Promise<void>;
  resync(spaceId?: number): Promise<void>;
  openRoot(spaceId: number): Promise<void>;
  /** Installed desktop editors detected by the Electron main process. */
  officeChoices(): Promise<Array<{
    id: "microsoft-office" | "wps-office" | "libreoffice" | "collabora-office";
    label: string;
  }>>;
  /** Open only a server-identified, already-mirrored file; renderer paths and credentials are never accepted. */
  openOffice(
    spaceId: number,
    nodeId: number,
    appId: "microsoft-office" | "wps-office" | "libreoffice" | "collabora-office",
  ): Promise<void>;
}

/** Chunk reference inside a Drive manifest (4 MiB fixed chunks, spec §3.1). */
export interface DriveChunkRef {
  sha256: string;
  size: number;
}
export interface DriveManifest {
  contentSha256: string;
  size: number;
  contentType?: string;
  chunks: DriveChunkRef[];
}

/**
 * Drive secure-vault byte plane (ARCH-017, Drive P3). Control/metadata ONLY
 * crosses this bridge — URLs, hashes, tickets; file bytes move natively
 * (S3↔SQLCipher) or over the local loopback render server. The shell
 * hard-binds every call to the `'drive'` appKey — the renderer never chooses
 * the appKey for byte ops. Distinct from `DriveMirrorBridge` (P2's
 * FolderMirror OS-folder sync); this is the secure/gxp in-app-render path.
 */
export interface DriveBridge {
  /** Import a local plaintext file into the vault; returns its manifest. Source deletion is the caller's decision. */
  importFile(srcPath: string): Promise<DriveManifest>;
  /** Native GET url (Bearer) → verify sha256/size → vault. Idempotent (already-present chunk = no network). */
  fetchChunk(
    url: string,
    bearer: string,
    sha256: string,
    size: number,
  ): Promise<void>;
  /** Native PUT of the vault chunk to url (Bearer). Resolves to the HTTP status. */
  pushChunk(url: string, bearer: string, sha256: string): Promise<number>;
  hasChunk(sha256: string): Promise<boolean>;
  /** Eviction primitive; LRU/pin policy lives in TS. Returns the count of chunks deleted. */
  deleteChunks(sha256s: string[]): Promise<number>;
  /** Start (idempotent) the 127.0.0.1 loopback render server. */
  serveStart(): Promise<{ port: number }>;
  /** Register a one-open ticket for a manifest; returns the ticket path "/t/<hex>". */
  serveGrant(manifest: DriveManifest): Promise<string>;
  serveRevoke(ticket: string): Promise<void>;
}

/**
 * Closed appKey namespace for the per-app SQLCipher stores. The shells enforce
 * this same two-value ceiling natively (one store per app, apps cannot read
 * each other's store); narrowing the renderer-facing contract to the same
 * union keeps the renderer from naming an arbitrary store — including
 * `wipe()` on one (SJ-NATIVE-BRIDGE-RENDERER-CHOSEN-APPKEY hardening).
 * Adding an app store requires extending this union AND the shell's native
 * allowlist together.
 */
export const NATIVE_DB_APP_KEYS = ["mail", "drive"] as const;
export type NativeDbAppKey = (typeof NATIVE_DB_APP_KEYS)[number];

/**
 * One parameterized statement inside an authorized native atomic batch
 * (E4-I native transaction freeze). Statements are single-statement,
 * parameterized DML/read only; transaction control, schema DDL, ATTACH/DETACH
 * and arbitrary PRAGMA are refused before mutation, natively and in TS
 * pre-admission (`$lib/offline/nativeBatch`).
 */
export interface NativeBatchStatement {
  sql: string;
  params?: unknown[];
}

/** Aggregate admission budget for one bounded native batch. */
export interface NativeBatchBudget {
  /** Maximum statement count for the whole batch. */
  maxStatements: number;
  /** Maximum aggregate UTF-8 bytes across statement text plus params. */
  maxParamBytes: number;
}

/** Generic per-appKey encrypted SQLCipher store, exposed as `window.setjoinNative.db`. */
export interface OfflineDbBridge {
  /** Open (or create) the SQLCipher store for `appKey`. Key is provisioned in-process — never reaches JS.
   *  `profile` selects the cipher: `'standard'` (AES-256, default) or `'SMx'` (SM4 page cipher). */
  open(appKey: NativeDbAppKey, profile?: "standard" | "SMx"): Promise<void>;
  /** Whether the named store is currently open. */
  isOpen(appKey: NativeDbAppKey): Promise<boolean>;
  /** Execute a mutating SQL statement (allowlisted keywords; params as JSON array). Returns rows changed. */
  exec(appKey: NativeDbAppKey, sql: string, params?: unknown[]): Promise<number>;
  /**
   * Authorized schema-initialization seam (med-offcore-sqlguard-001 r3): the
   * ONLY way a multi-statement batch (e.g. MAIL_SCHEMA) may execute. Ordinary
   * `exec` refuses multi-statement payloads unconditionally; a batch sent here
   * is validated statement-by-statement inside offline-core (PRAGMA/ATTACH/
   * DETACH/VACUUM, reads and transaction control are never batch-valid) and
   * the path is ONE-SHOT per open store connection — a replayed batch is
   * refused. Optional while shells adopt the shared r3 export
   * (`db_exec_schema_init` in native_impl.rs): `init()` must fail closed with
   * a clear error when a shell has not wired it yet, never fall back to
   * sending the batch through `exec`.
   */
  execSchemaInit?(appKey: NativeDbAppKey, sql: string): Promise<number>;
  /**
   * E4-I native transaction freeze (retired-docs:verification/2026-09-08-connectivity-native-transaction-freeze.md):
   * the ONLY entry that owns transaction control. Native holds one
   * connection/transaction for the whole bounded batch, validates every
   * statement and the aggregate budget before execution, refuses transaction
   * control/DDL/cross-app handles and partial admission, and either commits
   * the entire batch atomically or applies nothing. Resolves with the total
   * changed-row count; throws on refusal or failure. No JS callback, network
   * wait, nested transaction or second caller interleaves the batch.
   * Optional until shells adopt the shared offline-core export; TS callers
   * fail closed to non-atomic replay-safe paths when it is absent, and the
   * durable coordinator job store requires it before it will persist.
   */
  transactionBatch?(
    appKey: NativeDbAppKey,
    statements: readonly NativeBatchStatement[],
    budget: NativeBatchBudget,
  ): Promise<number>;
  /**
   * E4-I versioned store migration entry. Accepts only a target version
   * present in the bundled, trusted per-app migration manifest
   * (`$lib/offline/migrations`); the manifest itself is loaded native-side
   * through the installer/application-update trust path — never from a
   * WebView request, arbitrary URL, filesystem path or runtime register
   * call. Under the same per-store serialization it checks the current
   * version, refuses unknown/ahead/downgrade/digest-mismatch targets, and
   * commits each declared transactional migration plus its version
   * atomically. Jobs cannot interleave migration.
   */
  migrateStore?(appKey: NativeDbAppKey, targetVersion: number): Promise<{ version: number }>;
  /** Run a SELECT and return typed results. The native bridge JSON-parses before resolving. */
  query<T = Record<string, unknown>>(
    appKey: NativeDbAppKey,
    sql: string,
    params?: unknown[],
  ): Promise<T[]>;
  /** Close + delete this appKey's store file. Used on logout. */
  wipe(appKey: NativeDbAppKey): Promise<void>;
}

/** Generic bounded content-addressed byte plane for disaster-recovery cache data. */
export interface RecoveryBlobBridge {
  writeBegin(
    sha256: string,
    size: number,
  ): Promise<{ handle: string; nextOffset: number }>;
  writeChunk(
    handle: string,
    offset: number,
    bytes: Uint8Array,
  ): Promise<number>;
  writeCommit(handle: string): Promise<string>;
  writeAbort(handle: string): Promise<void>;
  readOpen(sha256: string): Promise<{ handle: string; size: number }>;
  readChunk(
    handle: string,
    offset: number,
    length: number,
  ): Promise<Uint8Array>;
  readClose(handle: string): Promise<void>;
  ref(sha256: string): Promise<number>;
  unref(sha256: string): Promise<number>;
}
/** The contract a native shell injects as `window.setjoinNative`. Versioned: bump BRIDGE_VERSION on breaking change. */
export interface SetjoinNativeBridge {
  readonly version: number;
  readonly capabilities: readonly NativeCapability[];
  pushRegister(): Promise<string | null>;
  /**
   * The device's push-MFA ECDH public key as raw 65-byte uncompressed SEC1
   * (0x04‖X‖Y) hex — POSTed as `device_public_key` to `/auth/device/register`
   * so the server can ECIES-encrypt push-MFA challenges only this device can
   * decrypt. Null on shells without the `push` capability or a locked vault.
   */
  pushDevicePublicKey(): Promise<string | null>;
  biometricUnlock(reason: string): Promise<boolean>;
  secureStore: SecureStore;
  vault: VaultBridge;
  share(payload: SharePayload): Promise<void>;
  pickFile(accept?: string): Promise<File | null>;
  notify(payload: NotifyPayload): Promise<void>;
  openExternal(url: string): Promise<void>;
  db?: OfflineDbBridge;
  /** Present only on native shells that ship encrypted, resumable recovery bytes. */
  recoveryBlob?: RecoveryBlobBridge;
  /** Drive P2's FolderMirror control surface — advertised ONLY by the
   *  Electron desktop shell (honest-subset rule; Tauri-mobile/HarmonyOS do
   *  not define this optional subshape, so their conformance guards need no
   *  change). See `DriveMirrorBridge`'s doc comment for the auth story. */
  driveMirror?: DriveMirrorBridge;
  /** Drive P3's secure-vault byte plane — advertised by shells that ship the
   *  offline-core vault (Electron/Tauri-mobile/HarmonyOS); plain browser has
   *  neither, same optionality as `db`. */
  drive?: DriveBridge;
  /**
   * E6 harness-only connectivity seam (clients/desktop/electron
   * src/connectivity/rollout.ts `connectivityBridgeModeFor`): the ONE bridge
   * field the composed webmail coordinator reads
   * (`$lib/offline/boot.ts`) to learn the harness pair member's rollout mode
   * — the member session document cannot carry the device-gated
   * `offline_effective_policy` block. Absent on every production shell (the
   * env seam is unset → the Electron preload attaches nothing). Additive,
   * optional, not a capability: no BRIDGE_VERSION bump.
   */
  connectivity?: { rolloutMode: 'off' | 'observe' | 'execute' };
  /**
   * Compute the device-proof HMAC for an outgoing request. The HMAC secret
   * lives native-side only (like the SQLCipher key — never returned to JS).
   * Returns null when the device is not enrolled or the vault is locked.
   */
  deviceProof(args: {
    deviceId: string;
    timestamp: string;
  }): Promise<{ hmac: string } | null>;
}

declare global {
  interface Window {
    setjoinNative?: SetjoinNativeBridge;
  }
}
export {};
