// BridgeProxy — the flat ArkTS object registered via
// `WebviewController.registerJavaScriptProxy` (ArkWeb only supports a flat
// method list per registration, not the nested `SetjoinNativeBridge` shape —
// same reason Electron needs `bridge.ts` to reshape a flat `invoke(channel,
// ...)` into the nested contract; `BridgeShim.ets` does that reshaping here).
//
// Most methods here are registered SYNCHRONOUS (`methodList`). Two families
// are genuinely asynchronous natively and cannot return their result
// synchronously:
//   - `openExternal`/`share`: fire-and-forget is an honest fit — the SPA's
//     contract only needs eventual `Promise<void>`, so the method kicks the
//     OS action off in the background and returns immediately.
//   - `pickFile`: the SPA needs the actual chosen file back, which the
//     picker cannot produce synchronously. Resolved via a correlation-id +
//     `WebviewController.runJavaScript()` callback (confirmed API — see
//     `MainPage.ets`): `pickFile()` returns a request id immediately; once
//     the picker resolves, the result is delivered by running a small script
//     that calls back into a pending-promise map the shim maintains. This is
//     unverified end-to-end without a device (flagged in the plan).
//   - Drive P3's `driveImportFile`/`driveFetchChunk`/`drivePushChunk`/
//     `driveServeStart` (ARCH-017): these stream a whole file/chunk and are
//     napi `AsyncTask`s on the Rust side (batch-1 #4 — never block the JS/UI
//     thread), so they genuinely return a Promise. Unlike pickFile, ArkWeb
//     has a real mechanism for this — `registerJavaScriptProxy`'s
//     `asyncMethodList` (MainPage.ets), which awaits a Promise-returning
//     proxy method and resolves it on the page side — so these four are
//     registered there instead of needing the correlation-id/callback dance.

import { fileIo } from '@kit.CoreFileKit';
import { picker } from '@kit.CoreFileKit';
import { common, Want } from '@kit.AbilityKit';
import { util } from '@kit.ArkTS';
import { webview } from '@kit.ArkWeb';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { BusinessError } from '@kit.BasicServicesKit';
import { NativeBinding, TotpEntryNative } from './NativeBinding';
import { checkStmtAllowed, appKeyDbFile, normalizeProfile } from './DbAllowlist';
import { Mam } from './Mam';
import { PushService } from '../common/PushService';

const TAG: string = 'BridgeProxy';
const DOMAIN: number = 0x0001;

/** Schemes the shell will hand to the OS opener — mirrors `externalUrlAllowed`
 *  in `clients/desktop/electron/src/handlers/os.ts`. */
const ALLOWED_EXTERNAL_SCHEMES: Set<string> = new Set<string>(['https', 'http', 'mailto']);

function externalUrlAllowed(url: string): boolean {
  const idx: number = url.indexOf(':');
  if (idx <= 0) {
    return false;
  }
  const scheme: string = url.slice(0, idx).toLowerCase();
  return ALLOWED_EXTERNAL_SCHEMES.has(scheme);
}

// ── Renderer-boundary confinement (deep-scan package desktop-drive-bridge-───
// unconfined; Astra HOLD 1–2). The Electron shell enforces the same three
// bounds in `handlers/securestore.ts` + `handlers/drive.ts`; the offline-core
// native floor (drive.rs) backs both shells. ArkTS coverage here mirrors
// Electron:
//   - SECRET: secureStore is the renderer's only secure-store surface; the
//     `mam:` namespace (MAM enrolment secrets written by trusted `Mam.ets`
//     only) and the `meet-capture:` namespace (MEET M5 slice 2: the local-
//     capture consent records + capture device id — a renderer able to write
//     `meet-capture:consent` could grant itself recording consent past the
//     non-dismissible consent machine) are native-host-only for renderer
//     calls, mirroring Electron's `RENDERER_DENIED_PREFIXES` in
//     `handlers/securestore.ts`. No Meet substrate carrier exists on this
//     shell yet, so nothing legitimately writes `meet-capture:*` here today —
//     the denial lands with the boundary so this mirror can never lag the
//     desktop twin.
//   - NETWORK: chunk fetch/push URLs must be absolute http(s) whose origin is
//     in the approved set (default EMPTY = deny — the composition root widens
//     it with the configured server origin via `setApprovedDriveChunkOrigins`).
//     Widening also forwards the origins into the offline-core floor
//     (drive_set_confinement) through the REQUIRED NativeBinding.ets seam
//     (Astra r2 item 1), so both native bindings inherit the trusted
//     approved-origin policy.
//   - FILE: driveImportFile rejects relative/`..` paths at this layer too,
//     and (package med-shard2-013) authorizes srcPath INSIDE the sandbox:
//     only the designated import root is import-eligible — private app
//     stores (preference stores, caches, databases) and the vault/secret
//     files are denied even though they sit inside the app sandbox, closing
//     the in-sandbox disclosure the boundary check alone leaves readable.
//     TRUSTED mirror-index membership (registered dc_mirror content, import
//     roots, ancestor-symlink escapes) is enforced at the native read
//     boundary by the SHARED offline-core implementation — fail-closed unless
//     a shell composition root installs a policy — so this binding inherits
//     it byte-identically with the desktop binding (Astra item 1: the
//     ArkTS-only path-shape check was not the boundary). This shell now
//     installs its policy natively too: the ohos-native crate exports
//     `driveSetConfinement` (med-shard2-013), so the forward below activates
//     the process-wide floor, and the native layer re-validates every
//     src_path/URL even if an ArkTS check ever slips through.
/** Key namespaces the renderer may never read or write (native-host-only
 *  main-process state) — the ArkTS twin of Electron `handlers/securestore.ts`'s
 *  `RENDERER_DENIED_PREFIXES`. */
const RENDERER_DENIED_SECURE_STORE_PREFIXES: Set<string> =
  new Set<string>(['mam:', 'meet-capture:']);

const approvedDriveChunkOrigins: Set<string> = new Set<string>();

/** Trusted import-eligible roots (package med-shard2-013): absolute
 *  directories a renderer-driven `driveImportFile` srcPath may resolve
 *  inside. Default empty = every import is denied at this layer too (the
 *  native floor independently denies unregistered content). The BridgeProxy
 *  composition installs the shell's designated import directory. */
const approvedImportRoots: Array<string> = new Array<string>();

/** Push the current trusted policy (import roots + approved chunk origins)
 *  into the shared native floor. Astra desktop-drive-bridge-unconfined r2
 *  item 1: `driveSetConfinement` is a REQUIRED member of the binding contract
 *  (declared in `NativeBinding.ets`, exported by the shared native_impl.rs in
 *  both napi twins) — the call is direct, never an optional projection, so a
 *  build whose .so somehow predates the export fails loudly here instead of
 *  silently running the whole session against the native fail-closed floor
 *  while the ArkTS gate looks wide. */
function forwardDriveConfinementToNative(): void {
  try {
    const origins: Array<string> = new Array<string>();
    approvedDriveChunkOrigins.forEach((origin: string): void => {
      origins.push(origin);
    });
    NativeBinding.driveSetConfinement(approvedImportRoots.slice(), origins);
  } catch (e) {
    hilog.error(DOMAIN, TAG, `driveSetConfinement forward failed: ${JSON.stringify(e)}`);
  }
}

/** Composition-root seam: widen the approved chunk-URL origin set (exact
 *  `scheme://host:port` strings, compared case-insensitively). Default empty
 *  denies every chunk fetch/push — fail-closed, like the Electron handler. */
export function setApprovedDriveChunkOrigins(origins: Array<string>): void {
  approvedDriveChunkOrigins.clear();
  for (const origin of origins) {
    approvedDriveChunkOrigins.add(origin.toLowerCase());
  }
  // Mirror the whole policy (roots AND origins) into the shared native floor
  // (defense-in-depth for both layers) — the native policy REPLACES both
  // fields, so each seam forwards the combined state.
  forwardDriveConfinementToNative();
}

/** Composition-root seam (med-shard2-013): set the trusted import-eligible
 *  roots for `driveImportFile` — the BridgeProxy composition installs the
 *  shell's designated import directory; empty reverts to deny-all imports. */
export function setDriveImportRoots(roots: Array<string>): void {
  approvedImportRoots.length = 0;
  for (const root of roots) {
    approvedImportRoots.push(root);
  }
  forwardDriveConfinementToNative();
}

/** Host portion of a URL authority (port stripped; a bracketed IPv6 literal
 *  keeps its inner colons) — mirrors offline-core's `parse_http_origin`. */
function hostFromAuthority(authority: string): string {
  if (authority.charAt(0) === '[') {
    const end: number = authority.indexOf(']');
    return end >= 0 ? authority.slice(1, end) : authority;
  }
  const colon: number = authority.lastIndexOf(':');
  return colon >= 0 ? authority.slice(0, colon) : authority;
}

/** Loopback hosts where cleartext http is tolerated — mirrors offline-core's
 *  `is_loopback_host` so this gate and the native floor agree. */
function isLoopbackHost(host: string): boolean {
  const h: string = host.toLowerCase();
  return h === '127.0.0.1' || h === '::1' || h === 'localhost' || h.endsWith('.localhost');
}

function driveChunkUrlAllowed(url: string): boolean {
  const schemeEnd: number = url.indexOf('://');
  if (schemeEnd <= 0) {
    return false; // relative or scheme-less URLs never leave this shell
  }
  const scheme: string = url.slice(0, schemeEnd).toLowerCase();
  if (scheme !== 'https' && scheme !== 'http') {
    return false;
  }
  const afterScheme: string = url.slice(schemeEnd + 3);
  let boundary: number = afterScheme.length;
  for (const ch of ['/', '?', '#']) {
    const idx: number = afterScheme.indexOf(ch);
    if (idx >= 0 && idx < boundary) {
      boundary = idx;
    }
  }
  let authority: string = afterScheme.slice(0, boundary);
  const at: number = authority.lastIndexOf('@'); // strip userinfo
  if (at >= 0) {
    authority = authority.slice(at + 1);
  }
  if (authority.length === 0) {
    return false;
  }
  // med-shard2-013: no plain-http dialing in the fetch path — cleartext http
  // is loopback-only, byte-matching the native transport floor in drive.rs
  // (the drive bearer must never leave the box unencrypted). Approved origins
  // therefore only ever relax to a loopback http anchor, never the LAN.
  if (scheme === 'http' && !isLoopbackHost(hostFromAuthority(authority))) {
    return false;
  }
  return approvedDriveChunkOrigins.has(`${scheme}://${authority.toLowerCase()}`);
}

function assertSecureStoreKeyRendererAllowed(key: string): void {
  RENDERER_DENIED_SECURE_STORE_PREFIXES.forEach((prefix: string): void => {
    if (key.indexOf(prefix) === 0) {
      // For `mam:` this stays byte-identical to the pre-MEET message the
      // mam-renderer-denial inspection artifact pins.
      throw new Error(
        `secureStore: ${prefix}* keys are native-host-only and not renderer-accessible`);
    }
  });
}

function assertImportPathConstrained(srcPath: string): void {
  // OHOS is POSIX: absolute means a leading '/'. `..` segments are a traversal
  // shape — callers send resolved paths, exactly like the offline-core floor.
  if (srcPath.length === 0 || srcPath.charAt(0) !== '/') {
    throw new Error('driveImportFile: src_path must be absolute');
  }
  if (srcPath.indexOf('/../') >= 0 || srcPath.endsWith('/..')) {
    throw new Error('driveImportFile: src_path must not contain `..` traversal segments');
  }
}

function pathIsInsideDir(child: string, dir: string): boolean {
  if (dir.length === 0) {
    return false;
  }
  const withSep: string = dir.charAt(dir.length - 1) === '/' ? dir : `${dir}/`;
  return child.indexOf(withSep) === 0;
}

/** In-sandbox import authorization (med-shard2-013, D-CLIENTS-HARMONYOS-ENTRY-
 *  004): the path-shape and sandbox-boundary checks alone leave every private
 *  file INSIDE the app sandbox readable into the vault — preference stores
 *  holding server_url, cached attachments, webview caches, the SQLCipher vault
 *  and its WAL/journal siblings. So authorize srcPath against an ALLOWLIST of
 *  import-eligible locations (the designated import root the composition
 *  installs), and deny the private stores explicitly even though they are
 *  inside the sandbox. Rejection messages never echo the path (the renderer
 *  must not learn the sandbox layout). The native floor re-validates beneath
 *  this: trusted-root containment + dc_mirror content membership, fail-closed. */
function assertImportPathAuthorized(
  srcPath: string, importRoot: string, deniedPrivateDirs: Array<string>, vaultDbPath: string): void {
  for (const privateDir of deniedPrivateDirs) {
    if (pathIsInsideDir(srcPath, privateDir)) {
      throw new Error(
        'driveImportFile: src_path resolves into a private app store (preferences, caches, ' +
        'databases) — only import-eligible locations may be imported');
    }
  }
  // The vault and its SQLite siblings (guard.db-wal / -shm / -journal) live in
  // filesDir, outside the private dirs above — deny them by path prefix so the
  // secret store can never be chunked into the vault via the import plane.
  if (srcPath.indexOf(vaultDbPath) === 0) {
    throw new Error('driveImportFile: src_path resolves into the vault — importing it is denied');
  }
  if (importRoot.length === 0 || !pathIsInsideDir(srcPath, importRoot)) {
    throw new Error('driveImportFile: src_path is outside the import-eligible locations');
  }
}

export class BridgeProxy {
  private context: common.UIAbilityContext;
  private controller: webview.WebviewController;
  private vaultDbPath: string;
  private importRoot: string;
  private importDeniedPrivateDirs: Array<string>;
  private mam: Mam;
  private pickFileRequestSeq: number = 0;

  constructor(context: common.UIAbilityContext, controller: webview.WebviewController, mam: Mam) {
    this.context = context;
    this.controller = controller;
    this.vaultDbPath = `${context.filesDir}/guard.db`;
    // med-shard2-013: the designated import directory is this shell's only
    // import-eligible location (picker-granted documents reach the SPA via
    // pickFile's byte transfer, never through this path-based primitive).
    this.importRoot = `${context.filesDir}/imports`;
    // Private stores denied even inside the sandbox (defense-in-depth beneath
    // the allowlist): caches, temp, databases, preference stores. Empty or
    // missing dir entries are skipped so a narrow SDK surface never broadens
    // the denial.
    this.importDeniedPrivateDirs = new Array<string>();
    const privateDirs: Array<string> =
      [context.cacheDir, context.tempDir, context.databaseDir, context.preferencesDir];
    for (const dir of privateDirs) {
      if (dir !== undefined && dir !== null && dir.length > 0) {
        this.importDeniedPrivateDirs.push(dir);
      }
    }
    // Install the trusted import root into the ArkTS gate AND the native floor
    // (the ohos-native crate's driveSetConfinement export — see forwardDrive-
    // ConfinementToNative). Native enforcement stays fail-closed regardless:
    // unregistered content is denied by the mirror-index gate until a mirror
    // layer ever runs on this shell.
    setDriveImportRoots([this.importRoot]);
    this.mam = mam;
  }

  // ── Smoke / version ──────────────────────────────────────────────────────
  ping(): string {
    return 'pong';
  }

  // ── Vault ────────────────────────────────────────────────────────────────
  vaultUnlock(passphrase: string): boolean {
    return NativeBinding.vaultUnlock(this.vaultDbPath, passphrase);
  }
  vaultIsUnlocked(): boolean {
    return NativeBinding.vaultIsUnlocked();
  }
  /** Returns a JSON-stringified `TotpEntryNative[]` — every non-primitive
   *  crossing the ArkWeb bridge is JSON, not relying on object marshalling. */
  vaultListTotp(): string {
    const entries: Array<TotpEntryNative> = NativeBinding.vaultListTotp();
    return JSON.stringify(entries);
  }
  vaultGenerateTotp(id: string): string {
    return NativeBinding.vaultGenerateTotp(id);
  }

  // ── Secure store ─────────────────────────────────────────────────────────
  // The mam:* and meet-capture:* namespaces are native-host-only (see the
  // confinement note above): the same exports legitimately carry mam:* for
  // trusted `Mam.ets`, so the renderer boundary is THIS check, exactly like
  // Electron's securestore.ts.
  secureStoreGet(key: string): string | null {
    assertSecureStoreKeyRendererAllowed(key);
    return NativeBinding.secureStoreGet(key);
  }
  secureStoreSet(key: string, value: string): void {
    assertSecureStoreKeyRendererAllowed(key);
    NativeBinding.secureStoreSet(key, value);
  }
  secureStoreRemove(key: string): void {
    assertSecureStoreKeyRendererAllowed(key);
    NativeBinding.secureStoreRemove(key);
  }

  // ── Offline encrypted store ──────────────────────────────────────────────
  dbOpen(appKey: string, profile: string): void {
    const dbPath: string = `${this.context.filesDir}/${appKeyDbFile(appKey)}`;
    NativeBinding.dbOpen(dbPath, appKey, normalizeProfile(profile));
  }
  dbIsOpen(appKey: string): boolean {
    return NativeBinding.dbIsOpen(appKey);
  }
  dbExec(appKey: string, sql: string, paramsJson: string): number {
    checkStmtAllowed(sql);
    return NativeBinding.dbExec(appKey, sql, paramsJson);
  }
  dbQuery(appKey: string, sql: string, paramsJson: string): string {
    checkStmtAllowed(sql);
    return NativeBinding.dbQuery(appKey, sql, paramsJson);
  }
  dbWipe(appKey: string): void {
    NativeBinding.dbWipe(appKey);
  }

  // ── Drive P3 secure-vault byte plane (ARCH-017) ──────────────────────────
  // appKey is hard-bound to 'drive' HERE — the page never chooses the appKey
  // for byte ops (mirrors dbOpen's split above). The four that stream a whole
  // file/chunk are registered on `asyncMethodList` (MainPage.ets) — genuinely
  // async, unlike every other method in this class — so they may return a
  // Promise here without violating the class doc's "everything else is
  // synchronous" rule. The three that carry a renderer-supplied PATH or URL
  // confine it HERE (rejected promise, never reaching the native sink) —
  // import-path authorization (in-sandbox allowlist + private-store denial)
  // and chunk-origin/transport gates at this layer — and the offline-core
  // native floor both shells share re-validates beneath it: mirror-index
  // membership + import roots for the file read, the transport floor + the
  // approved-origin allowlist for the credentialed GET/PUT (fail-closed until
  // the composition seams install the policy, which this shell now does).
  driveImportFile(srcPath: string): Promise<string> {
    try {
      assertImportPathConstrained(srcPath);
      assertImportPathAuthorized(
        srcPath, this.importRoot, this.importDeniedPrivateDirs, this.vaultDbPath);
    } catch (e) {
      return Promise.reject(e as Error);
    }
    return NativeBinding.driveImportFile('drive', srcPath);
  }
  driveFetchChunk(url: string, bearer: string, sha256: string, size: number): Promise<void> {
    if (!driveChunkUrlAllowed(url)) {
      return Promise.reject(new Error(`driveFetchChunk: url origin is not approved: ${url}`));
    }
    return NativeBinding.driveFetchChunk('drive', url, bearer, sha256, size);
  }
  drivePushChunk(url: string, bearer: string, sha256: string): Promise<number> {
    if (!driveChunkUrlAllowed(url)) {
      return Promise.reject(new Error(`drivePushChunk: url origin is not approved: ${url}`));
    }
    return NativeBinding.drivePushChunk('drive', url, bearer, sha256);
  }
  driveHasChunk(sha256: string): boolean {
    return NativeBinding.driveHasChunk('drive', sha256);
  }
  driveDeleteChunks(sha256sJson: string): number {
    return NativeBinding.driveDeleteChunks('drive', sha256sJson);
  }
  driveServeStart(): Promise<string> {
    return NativeBinding.driveServeStart('drive');
  }
  driveServeGrant(manifestJson: string): string {
    return NativeBinding.driveServeGrant('drive', manifestJson);
  }
  driveServeRevoke(ticket: string): void {
    NativeBinding.driveServeRevoke('drive', ticket);
  }

  // ── MAM / device trust ───────────────────────────────────────────────────
  mamGetPolicy(): string | null {
    return NativeBinding.mamGetPolicy();
  }
  mamIsWiped(): boolean {
    return NativeBinding.mamIsWiped();
  }
  /** `{deviceId, timestamp}` args are passed as two strings (flat proxy
   *  methods only marshal primitives reliably — see the class doc comment). */
  deviceProof(deviceId: string, timestampSeconds: string): string | null {
    return Mam.deviceProof(deviceId, timestampSeconds);
  }

  // ── Push (real on HarmonyOS via HMS Push Kit — unlike desktop's honest-false) ──
  pushRegister(): string | null {
    const svc: PushService = PushService.getInstance();
    const token: string = svc.getToken();
    return token.length > 0 ? token : null;
  }

  /** Device push-MFA ECDH public key (raw-65 SEC1 hex) the SPA registers with
   *  the server so it can ECIES-encrypt challenges. Returns null when the vault
   *  is locked (guard-core throws — caught + normalized here). */
  pushDevicePublicKey(): string | null {
    try {
      return NativeBinding.pushDevicePublicKey();
    } catch (e) {
      hilog.error(DOMAIN, TAG, `pushDevicePublicKey failed: ${JSON.stringify(e)}`);
      return null;
    }
  }

  // ── OS capabilities ──────────────────────────────────────────────────────
  notify(title: string, body: string): void {
    // ponytail: HarmonyOS local notifications need `@ohos.notificationManager`
    // + a publish() call with a NotificationRequest; kept a thin, best-effort
    // wrapper (never throws to the bridge caller) since a missing runtime
    // notification permission must not break other bridge calls.
    // D-CLIENTS-HARMONYOS-ENTRY-006: `title`/`body` originate from page script,
    // so no payload text is interpolated into hilog — fixed marker + payload
    // lengths only, mirroring PushService's length-only pattern.
    try {
      hilog.info(DOMAIN, TAG, `notify: title length=${title.length} body length=${body.length}`);
    } catch (e) {
      hilog.error(DOMAIN, TAG, `notify failed: ${JSON.stringify(e)}`);
    }
  }

  /** Fire-and-forget: hands `url` to the OS via an implicit `want`. Gated by
   *  the same scheme allowlist as Electron's `open_external`. */
  openExternal(url: string): void {
    if (!externalUrlAllowed(url)) {
      throw new Error('openExternal: URL scheme not allowed (only http/https/mailto)');
    }
    const want: Want = {
      action: 'ohos.want.action.viewData',
      entities: ['entity.system.browsable'],
      uri: url,
    };
    this.context.startAbility(want).catch((e: BusinessError) => {
      hilog.error(DOMAIN, TAG, `openExternal startAbility failed: ${e.code} ${e.message}`);
    });
  }

  /** Fire-and-forget best-effort share via an implicit `want` (unverified
   *  without a device — see the plan's device-gated scope). */
  share(title: string, text: string, url: string): void {
    const summary: string = [text, url].filter((s: string) => s.length > 0).join(' ');
    const want: Want = {
      action: 'ohos.want.action.sendData',
      parameters: { 'ohos.extra.param.key.title': title, 'ohos.extra.param.key.content': summary },
    };
    this.context.startAbility(want).catch((e: BusinessError) => {
      hilog.error(DOMAIN, TAG, `share startAbility failed: ${e.code} ${e.message}`);
    });
  }

  /**
   * Kick off the document picker asynchronously; returns a request id
   * immediately. Once the user picks (or cancels), the result is delivered
   * back into the page via `runJavaScript` calling
   * `window.__setjoinResolvePickFile(id, fileJsonOrNull)` (see
   * `BridgeShim.ets`'s `pickFile` wrapper for the matching Promise map).
   */
  pickFile(_accept: string): string {
    this.pickFileRequestSeq += 1;
    const requestId: string = `pf${this.pickFileRequestSeq}`;
    this.runPickFile(requestId);
    return requestId;
  }

  private async runPickFile(requestId: string): Promise<void> {
    try {
      const documentPicker = new picker.DocumentViewPicker(this.context);
      const uris: Array<string> = await documentPicker.select();
      if (uris.length === 0) {
        this.resolvePickFile(requestId, null);
        return;
      }
      const uri: string = uris[0];
      const file = fileIo.openSync(uri, fileIo.OpenMode.READ_ONLY);
      const stat = fileIo.statSync(file.fd);
      const buf = new ArrayBuffer(stat.size);
      fileIo.readSync(file.fd, buf);
      fileIo.closeSync(file.fd);

      const bytes: Uint8Array = new Uint8Array(buf);
      const base64: string = new util.Base64Helper().encodeToStringSync(bytes);
      const name: string = uri.substring(uri.lastIndexOf('/') + 1) || 'file';
      const json: string = JSON.stringify({ name, type: 'application/octet-stream', dataBase64: base64 });
      this.resolvePickFile(requestId, json);
    } catch (e) {
      hilog.error(DOMAIN, TAG, `pickFile failed: ${JSON.stringify(e)}`);
      this.resolvePickFile(requestId, null);
    }
  }

  private resolvePickFile(requestId: string, fileJson: string | null): void {
    const arg: string = fileJson === null ? 'null' : fileJson;
    const script: string = `window.__setjoinResolvePickFile && window.__setjoinResolvePickFile(${JSON.stringify(requestId)}, ${arg});`;
    this.controller.runJavaScript(script).catch((e: BusinessError) => {
      hilog.error(DOMAIN, TAG, `pickFile callback delivery failed: ${e.code} ${e.message}`);
    });
  }
}
