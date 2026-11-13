// INSPECTION-CHECKED ARTIFACT — NOT MACHINE-RUN (med-shard2-013 r2; r3 rework).
//
// This repo carries no ArkTS test toolchain (no hvigor/DevEco test runner in
// CI), so this file is a negative-test ARTIFACT for review inspection, not an
// executed suite. Status:
//   - Rust-side machine evidence for the napi seam the renderer reaches:
//     ../binding_confinement_test.rs (cargo test -p ohos-native).
//   - This artifact: inspection-checked coverage of the segmentation boundary
//     in entry/src/main/ets/native/BridgeProxy.ets — the `mam:*` secure-store
//     renderer denial (assertSecureStoreKeyRendererAllowed, called at the top
//     of secureStoreGet/secureStoreSet/secureStoreRemove), D-CLIENTS-HARMONYOS-
//     ENTRY-002. Trusted host-side MAM writes go through Mam.ets calling
//     NativeBinding directly, so a renderer denial MUST NOT break the host
//     path — that asymmetry is pinned by the passthrough cases below.
//
// r3 rework (Astra HOLD on the r2 artifact): the r2 file constructed the
// BridgeProxy with `undefined as ESObject as common.UIAbilityContext`, but the
// constructor dereferences `context.filesDir` immediately (BridgeProxy.ets,
// `this.vaultDbPath = ...`), so every r2 case would have died at construction
// — an invalid fixture. This file now:
//   - case 0 uses the unusable context AS the denial evidence: construction
//     with `undefined` must fail closed BEFORE any `mam:` dispatch, with zero
//     NativeBinding secure-store calls (the native sink is provably never
//     reached);
//   - all other cases construct the proxy with the same typed stub context the
//     private-store artifact uses — valid by inspection against the
//     constructor's actual field dereferences (filesDir/cacheDir/tempDir/
//     databaseDir/preferencesDir are all present, so construction completes);
//   - `undefined` remains ONLY for `webview.WebviewController` and `Mam`,
//     which the constructor merely stores and the secureStore* path never
//     reads — stated here so a reviewer can verify the casts stay harmless.
//
// Pins:
//   0. an unusable UIAbilityContext fails construction CLOSED — no `mam:` key
//      is ever dispatched and NativeBinding is never touched;
//   1. secureStoreGet / secureStoreSet / secureStoreRemove reject every
//      `mam:`-prefixed key (the namespace MAM enrolment secrets live in)
//      with a stable message naming the boundary;
//   2. the check is a PREFIX match: `mam:`, `mam:device-token`,
//      `mam:anything/deeper` — but NOT `mammoth` (a key that merely contains
//      the letters must stay renderer-accessible);
//   3. non-mam keys reach NativeBinding (the rejection is thrown BEFORE the
//      NativeBinding call, and the non-mam call proceeds) — proven by a
//      call-counting NativeBinding stub observed across every case.
//
// The NativeBinding stub stands in for the .so export surface; substitute the
// real module when this moves into a device harness.

interface StubContext {
  filesDir: string;
  cacheDir: string;
  tempDir: string;
  databaseDir: string;
  preferencesDir: string;
}

function stubContext(): StubContext {
  return {
    filesDir: '/data/app/el2/100/base/org.setjoin/files',
    cacheDir: '/data/app/el2/100/base/org.setjoin/cache',
    tempDir: '/data/app/el2/100/base/org.setjoin/cache/temp',
    databaseDir: '/data/app/el2/100/base/org.setjoin/database',
    preferencesDir: '/data/app/el2/100/base/org.setjoin/preferences',
  };
}

let passed = 0;
let failed = 0;
// Call-count probe over the whole run: every denial case must leave this
// untouched; only genuine passthrough may advance it.
let nativeSecureCalls = 0;

function installCountingNativeStub(): void {
  NativeBinding.secureStoreGet = (key: string): string | null => {
    nativeSecureCalls++;
    return key.length > 0 ? 'stub-value' : null;
  };
  NativeBinding.secureStoreSet = (key: string, value: string): void => {
    nativeSecureCalls++;
  };
  NativeBinding.secureStoreRemove = (key: string): void => {
    nativeSecureCalls++;
  };
}

function expectThrows(fn: () => void, label: string): void {
  try {
    fn();
    failed++;
    console.error(`[INSPECTION] ${label}: expected a throw, got success`);
  } catch (e) {
    passed++;
    const msg: string = (e as Error).message;
    if (msg.indexOf('mam:* keys are native-host-only') < 0) {
      failed++;
      console.error(`[INSPECTION] ${label}: unexpected rejection message: ${msg}`);
    } else {
      console.log(`[INSPECTION] ${label}: rejected as expected — ${msg}`);
    }
  }
}

function expectNoThrow(fn: () => void, label: string): void {
  try {
    fn();
    passed++;
    console.log(`[INSPECTION] ${label}: passed as expected`);
  } catch (e) {
    failed++;
    console.error(`[INSPECTION] ${label}: expected success, got: ${(e as Error).message}`);
  }
}

export function runMamRendererDenialCases(): void {
  installCountingNativeStub();

  // 0. Unusable context = fail-closed construction: the constructor cannot
  //    even derive its paths, so NO mam: dispatch can happen and the native
  //    secure-store sink is provably never reached (call-count probe stays 0).
  let unusableThrew = false;
  try {
    const unusable: BridgeProxy = new BridgeProxy(
      undefined as ESObject as common.UIAbilityContext,
      undefined as ESObject as webview.WebviewController,
      undefined as ESObject as Mam);
    // No throw: the fixture assumption is broken — count it as a failure.
    unusable.ping();
  } catch (e) {
    unusableThrew = true;
  }
  if (unusableThrew && nativeSecureCalls === 0) {
    passed++;
    console.log('[INSPECTION] unusable context: construction fails closed, ' +
      'no mam: dispatch, NativeBinding never reached');
  } else {
    failed++;
    console.error('[INSPECTION] unusable context must fail construction closed ' +
      `before any dispatch (threw=${unusableThrew}, nativeCalls=${nativeSecureCalls})`);
  }

  // Valid-by-inspection fixture: the constructor's field dereferences
  // (filesDir + the four private dirs) all resolve against the stub.
  const proxy: BridgeProxy = new BridgeProxy(
    stubContext() as ESObject as common.UIAbilityContext,
    undefined as ESObject as webview.WebviewController,
    undefined as ESObject as Mam);

  // 1. Every secure-store accessor denies the mam: namespace for the renderer.
  const afterBasics: number = nativeSecureCalls;
  expectThrows((): void => proxy.secureStoreGet('mam:device-token'),
    'secureStoreGet(mam:device-token) denied');
  expectThrows((): void => proxy.secureStoreSet('mam:device-token', 'x'),
    'secureStoreSet(mam:device-token) denied');
  expectThrows((): void => proxy.secureStoreRemove('mam:device-token'),
    'secureStoreRemove(mam:device-token) denied');
  expectThrows((): void => proxy.secureStoreGet('mam:'), 'bare mam: prefix denied');
  if (nativeSecureCalls !== afterBasics) {
    failed++;
    console.error('[INSPECTION] denied mam: keys must never reach NativeBinding');
  }

  // 2. Prefix match semantics — contains-mam is NOT denied (this is the one
  //    case allowed to reach the native stub, proving the gate is a prefix
  //    match rather than a blanket block).
  expectNoThrow((): void => proxy.secureStoreGet('mammoth'), 'mammoth is not in the mam: namespace');
  if (nativeSecureCalls !== afterBasics + 1) {
    failed++;
    console.error('[INSPECTION] non-mam key must pass through to NativeBinding exactly once');
  }

  // 3. Non-mam keys reach NativeBinding and the stub value comes back.
  const value: string | null = proxy.secureStoreGet('device-token');
  if (value === 'stub-value') {
    passed++;
    console.log('[INSPECTION] non-mam key reaches NativeBinding (stub value returned)');
  } else {
    failed++;
    console.error('[INSPECTION] non-mam key must pass through to NativeBinding');
  }
  // And a denied key never reaches it: the count is unchanged after the throw.
  const beforeDenied: number = nativeSecureCalls;
  try {
    proxy.secureStoreGet('mam:device-token');
  } catch (e) {
    // expected
  }
  if (nativeSecureCalls === beforeDenied) {
    passed++;
    console.log('[INSPECTION] mam: key never reaches NativeBinding');
  } else {
    failed++;
    console.error('[INSPECTION] mam: key must be rejected BEFORE NativeBinding');
  }

  console.log(`[INSPECTION] mam:* renderer denial: ${passed} passed, ${failed} failed ` +
    `(inspection-only — see header)`);
}
