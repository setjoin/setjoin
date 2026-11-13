// BridgeShim — the JS injected at document-start (`Web.javaScriptOnDocumentStart`)
// that reshapes the flat `window.ohosNative` proxy (BridgeProxy, registered via
// `registerJavaScriptProxy`) into the nested `window.setjoinNative` contract
// the SPA expects (`mailserver/webmail/src/lib/native/types.ts`). Mirrors
// Electron's `bridge.ts`/`preload.ts` split: `registerJavaScriptProxy` is the
// transport (like `ipcRenderer`), this shim is the shape-builder (like
// `buildBridge`).
//
// Most `ohosNative.<method>()` calls are synchronous (see BridgeProxy's doc
// comment on why); wrapping each in `Promise.resolve(...)` gives the SPA the
// Promise-returning interface it expects without needing `asyncMethodList`.
// The four Drive P3 streaming methods (`drive.importFile`/`fetchChunk`/
// `pushChunk`/`serveStart`) ARE registered on `asyncMethodList` (MainPage.ets)
// and already return a real Promise — `Promise.resolve(aPromise)` flattens
// transparently, so `ok(...)` still works unchanged for those too.

const CAPABILITIES_JSON = JSON.stringify([
  'secureStore', 'vault', 'pickFile', 'notify', 'openExternal', 'mailDb', 'deviceProof', 'push', 'drive',
  // 'biometric' and 'share' are deliberately NOT advertised: no hardware-wrap
  // key custody exists yet (ARCH-015 gap — matches desktop/mobile's honest
  // unlockBiometric->false), and `share` is a best-effort implicit-want call
  // unverified without a device.
]);

export function buildBridgeShimScript(): string {
  return `
(function () {
  var native = window.ohosNative;
  if (!native) { return; }

  function ok(v) { return Promise.resolve(v); }

  var pendingPickFile = {};
  window.__setjoinResolvePickFile = function (id, fileJson) {
    var resolve = pendingPickFile[id];
    if (!resolve) { return; }
    delete pendingPickFile[id];
    if (!fileJson) { resolve(null); return; }
    var meta = JSON.parse(fileJson);
    var binary = atob(meta.dataBase64);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) { bytes[i] = binary.charCodeAt(i); }
    resolve(new File([bytes], meta.name, { type: meta.type }));
  };

  window.setjoinNative = {
    version: 1,
    capabilities: ${CAPABILITIES_JSON},

    pushRegister: function () { return ok(native.pushRegister()); },
    pushDevicePublicKey: function () { return ok(native.pushDevicePublicKey()); },
    // No hardware-wrap key custody on this shell yet — honest false, matching
    // every other shell (ARCH-015).
    biometricUnlock: function () { return ok(false); },

    secureStore: {
      get: function (key) { return ok(native.secureStoreGet(key)); },
      set: function (key, value) { native.secureStoreSet(key, value); return ok(undefined); },
      remove: function (key) { native.secureStoreRemove(key); return ok(undefined); },
    },

    vault: {
      version: 1,
      unlock: function (passphrase) { return ok(native.vaultUnlock(passphrase)); },
      isUnlocked: function () { return ok(native.vaultIsUnlocked()); },
      listTotp: function () { return ok(JSON.parse(native.vaultListTotp())); },
      generateTotp: function (id) { return ok(native.vaultGenerateTotp(id)); },
      unlockPassphrase: function (passphrase) { return ok(native.vaultUnlock(passphrase)); },
      unlockBiometric: function () { return ok(false); },
      isEnrolled: function () { return ok(false); },
    },

    share: function (payload) {
      native.share(payload && payload.title ? payload.title : '',
                   payload && payload.text ? payload.text : '',
                   payload && payload.url ? payload.url : '');
      return ok(undefined);
    },

    pickFile: function (accept) {
      return new Promise(function (resolve) {
        var id = native.pickFile(accept || '');
        pendingPickFile[id] = resolve;
      });
    },

    notify: function (payload) {
      native.notify(payload.title, payload.body || '');
      return ok(undefined);
    },

    openExternal: function (url) {
      native.openExternal(url);
      return ok(undefined);
    },

    db: {
      open: function (appKey, profile) { native.dbOpen(appKey, profile || 'standard'); return ok(undefined); },
      isOpen: function (appKey) { return ok(native.dbIsOpen(appKey)); },
      exec: function (appKey, sql, params) { return ok(native.dbExec(appKey, sql, JSON.stringify(params || []))); },
      query: function (appKey, sql, params) { return ok(JSON.parse(native.dbQuery(appKey, sql, JSON.stringify(params || [])))); },
      wipe: function (appKey) { native.dbWipe(appKey); return ok(undefined); },
    },

    deviceProof: function (args) {
      var hex = native.deviceProof(args.deviceId, args.timestamp);
      return ok(hex === null ? null : { hmac: hex });
    },

    // Drive P3 secure-vault byte plane (ARCH-017) — control/metadata ONLY
    // (URLs, hashes, tickets); bytes move natively or over the loopback
    // render server. 'serveStop' is deliberately NOT exposed here — revoke
    // + wipe cover the shell's needs, same decision as the other two shells.
    drive: {
      importFile: function (srcPath) { return native.driveImportFile(srcPath).then(JSON.parse); },
      fetchChunk: function (url, bearer, sha256, size) { return native.driveFetchChunk(url, bearer, sha256, size); },
      pushChunk: function (url, bearer, sha256) { return native.drivePushChunk(url, bearer, sha256); },
      hasChunk: function (sha256) { return ok(native.driveHasChunk(sha256)); },
      deleteChunks: function (sha256s) { return ok(native.driveDeleteChunks(JSON.stringify(sha256s || []))); },
      serveStart: function () { return native.driveServeStart().then(JSON.parse); },
      serveGrant: function (manifest) { return ok(native.driveServeGrant(JSON.stringify(manifest))); },
      serveRevoke: function (ticket) { native.driveServeRevoke(ticket); return ok(undefined); },
    },
  };

  window.dispatchEvent(new Event('setjoin-native-ready'));
})();
`;
}
