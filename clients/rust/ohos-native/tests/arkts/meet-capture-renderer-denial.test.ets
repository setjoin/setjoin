// INSPECTION-CHECKED ARTIFACT — NOT MACHINE-RUN (MEET M5 slice-2 named
// follow-up).
//
// This repo carries no ArkTS test toolchain (no hvigor/DevEco test runner in
// CI), so this file is a negative-test ARTIFACT for review inspection, not an
// executed suite — stated up front exactly like the mam: precedent this file
// follows (mam-renderer-denial.test.ets, same directory). Status:
//   - Electron twin with machine evidence: clients/desktop/electron/src/
//     handlers/securestore.test.ts pins the same boundary for the desktop
//     shell (vitest, run in CI).
//   - This artifact: inspection-checked coverage of the SAME boundary on the
//     ArkTS side of entry/src/main/ets/native/BridgeProxy.ets — the
//     `meet-capture:*` secure-store renderer denial added to
//     assertSecureStoreKeyRendererAllowed (called at the top of
//     secureStoreGet/secureStoreSet/secureStoreRemove).
//
// Why the namespace is denied even though no Meet substrate carrier exists on
// HarmonyOS yet: `meet-capture:` holds the desktop local-capture consent
// records and capture device id (src/meet/localCapture.ts composition); a
// renderer able to write `meet-capture:consent` could grant itself recording
// consent past the non-dismissible consent machine. The denial lands with the
// boundary so the HarmonyOS mirror enforces the identical renderer limit from
// the start and can never lag the desktop twin if a carrier ever lands here.
//
// Fixture note (r3 lesson from the mam artifact): all cases construct the
// proxy with the same valid-by-inspection typed stub context the mam artifact
// settled on — the constructor dereferences filesDir/cacheDir/tempDir/
// databaseDir/preferencesDir, all present on the stub, so construction
// completes. `undefined` remains ONLY for `webview.WebviewController` and
// `Mam`, which the constructor merely stores and the secureStore* path never
// reads.
//
// Pins:
//   0. secureStoreGet / secureStoreSet / secureStoreRemove reject every
//      `meet-capture:`-prefixed key with a stable message naming the boundary;
//   1. the check is a PREFIX match: `meet-capture:`, `meet-capture:consent`,
//      `meet-capture:device-id/deeper` — but NOT `meet-capture-notes` (a key
//      that merely contains the letters must stay renderer-accessible);
//   2. the twin namespace `mam:` is STILL denied by the now multi-namespace
//      gate, with its pre-MEET message preserved byte-identically (the mam
//      artifact's pin keeps holding);
//   3. denied keys (both namespaces) never reach NativeBinding; a non-denied
//      key passes through exactly once — proven by a call-counting
//      NativeBinding stub observed across every case.
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

function expectThrows(fn: () => void, label: string, messageFragment: string): void {
  try {
    fn();
    failed++;
    console.error(`[INSPECTION] ${label}: expected a throw, got success`);
  } catch (e) {
    const msg: string = (e as Error).message;
    if (msg.indexOf(messageFragment) < 0) {
      failed++;
      console.error(`[INSPECTION] ${label}: unexpected rejection message: ${msg}`);
    } else {
      passed++;
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

export function runMeetCaptureRendererDenialCases(): void {
  installCountingNativeStub();

  // Valid-by-inspection fixture (see the header's r3-lesson note): the
  // constructor's field dereferences all resolve against the stub.
  const proxy: BridgeProxy = new BridgeProxy(
    stubContext() as ESObject as common.UIAbilityContext,
    undefined as ESObject as webview.WebviewController,
    undefined as ESObject as Mam);

  // 0. Every secure-store accessor denies the meet-capture: namespace for the
  //    renderer, with the boundary named in the message.
  const startCalls: number = nativeSecureCalls;
  expectThrows((): void => proxy.secureStoreGet('meet-capture:consent'),
    'secureStoreGet(meet-capture:consent) denied',
    'meet-capture:* keys are native-host-only');
  expectThrows((): void => proxy.secureStoreSet('meet-capture:consent', 'granted'),
    'secureStoreSet(meet-capture:consent) denied',
    'meet-capture:* keys are native-host-only');
  expectThrows((): void => proxy.secureStoreRemove('meet-capture:device-id'),
    'secureStoreRemove(meet-capture:device-id) denied',
    'meet-capture:* keys are native-host-only');
  expectThrows((): void => proxy.secureStoreGet('meet-capture:device-id/deeper'),
    'deeper meet-capture: key denied',
    'meet-capture:* keys are native-host-only');
  expectThrows((): void => proxy.secureStoreGet('meet-capture:'),
    'bare meet-capture: prefix denied',
    'meet-capture:* keys are native-host-only');
  if (nativeSecureCalls !== startCalls) {
    failed++;
    console.error('[INSPECTION] denied meet-capture: keys must never reach NativeBinding');
  }

  // 1. Prefix match semantics — contains-meet-capture is NOT denied (this is
  //    the one case allowed to reach the native stub, proving the gate is a
  //    prefix match rather than a blanket block).
  expectNoThrow((): void => proxy.secureStoreGet('meet-capture-notes'),
    'meet-capture-notes is not in the meet-capture: namespace');
  if (nativeSecureCalls !== startCalls + 1) {
    failed++;
    console.error('[INSPECTION] non-namespaced key must pass through to NativeBinding exactly once');
  }

  // 2. Twin coexistence: mam: is STILL denied by the multi-namespace gate,
  //    with the pre-MEET message byte-identical (mam-renderer-denial pins it).
  const afterPrefix: number = nativeSecureCalls;
  expectThrows((): void => proxy.secureStoreGet('mam:hmac_secret'),
    'mam:hmac_secret still denied by the twin gate',
    'mam:* keys are native-host-only');
  if (nativeSecureCalls !== afterPrefix) {
    failed++;
    console.error('[INSPECTION] denied mam: keys must never reach NativeBinding');
  }

  // 3. A genuinely non-denied key reaches NativeBinding and the stub value
  //    comes back; the denial is thrown BEFORE the native sink (the probe
  //    count is unchanged after the denied re-dispatch below).
  const value: string | null = proxy.secureStoreGet('device-token');
  if (value === 'stub-value') {
    passed++;
    console.log('[INSPECTION] non-denied key reaches NativeBinding (stub value returned)');
  } else {
    failed++;
    console.error('[INSPECTION] non-denied key must pass through to NativeBinding');
  }
  const beforeDenied: number = nativeSecureCalls;
  try {
    proxy.secureStoreGet('meet-capture:consent');
  } catch (e) {
    // expected
  }
  if (nativeSecureCalls === beforeDenied) {
    passed++;
    console.log('[INSPECTION] meet-capture: key never reaches NativeBinding');
  } else {
    failed++;
    console.error('[INSPECTION] meet-capture: key must be rejected BEFORE NativeBinding');
  }

  console.log(`[INSPECTION] meet-capture:* renderer denial: ${passed} passed, ${failed} failed ` +
    `(inspection-only — see header)`);
}
