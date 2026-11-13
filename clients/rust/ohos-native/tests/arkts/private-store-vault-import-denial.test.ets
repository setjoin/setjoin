// INSPECTION-CHECKED ARTIFACT — NOT MACHINE-RUN (med-shard2-013 r2; r3 rework).
//
// This repo carries no ArkTS test toolchain (no hvigor/DevEco test runner in
// CI), so this file is a negative-test ARTIFACT for review inspection, not an
// executed suite. Status:
//   - Rust-side machine evidence for the native half of the seam:
//     ../binding_confinement_test.rs (cargo test -p ohos-native).
//   - This artifact: inspection-checked coverage of the ArkTS gate in
//     entry/src/main/ets/native/BridgeProxy.ets (assertImportPathConstrained +
//     assertImportPathAuthorized, driven by BridgeProxy.driveImportFile) —
//     D-CLIENTS-HARMONYOS-ENTRY-004. A reviewer walks each case against the
//     source; wiring this into a device/simulator harness is future work of
//     the same class as the HAP itself.
//
// r3 rework (Astra HOLD on the r2 artifact): the r2 `expectRejects` counted ANY
// downstream rejection as success — a failing NativeBinding call, a typo'd
// path, or any unrelated throw would have "passed". This file now asserts, for
// EVERY denial case:
//   a. the SPECIFIC denial reason — the rejection message must contain the
//      exact fragment BridgeProxy's matching guard emits (private-store
//      denial, vault-prefix denial, outside-import-root denial, or the shape
//      check), not merely "some error";
//   b. the native sink is never reached — a call-counting NativeBinding
//      .driveImportFile stub is captured synchronously around each gate call
//      (the ArkTS gate and the native call both happen at call time, not at
//      promise-settle time), and every denial case must observe ZERO native
//      calls (the r2 file asserted nothing about NativeBinding, so native
//      confinement could silently substitute for the missing ArkTS-boundary
//      coverage);
//   c. the sandbox layout is never echoed — no rejection message contains the
//      `/data/app` root or the offending path.
// The one positive control (inside the designated import root) must resolve
// AND must be observed as exactly one native call carrying appKey 'drive' and
// the submitted src_path — proving the gate genuinely forwards the authorized
// case instead of denying everything.
//
// Pins:
//   1. private app stores are denied even inside the sandbox: cacheDir,
//      tempDir, databaseDir, preferencesDir (the dirs the constructor pushes
//      into importDeniedPrivateDirs);
//   2. the SQLCipher vault and its SQLite siblings (guard.db, -wal, -shm,
//      -journal) are denied by path prefix;
//   3. a src_path outside the designated import root (${filesDir}/imports) is
//      denied by the allowlist;
//   4. relative and `..`-traversal shapes are denied at the shape check;
//   5. a path inside the designated import root PASSES the ArkTS gate (the
//      native floor still re-validates mirror-index membership — fail-closed,
//      machine-run in Rust).

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

function installCountingNativeStub(): void {
  NativeBinding.driveImportFile = (appKey: string, srcPath: string): Promise<string> => {
    // Recorded so the positive control can verify WHAT reached the sink; the
    // count itself is captured synchronously around each gate call below.
    nativeImportCalls++;
    lastImportAppKey = appKey;
    lastImportSrcPath = srcPath;
    return Promise.resolve('{}');
  };
}

// Module-level probe bookkeeping the stub writes (never touched by the gate).
let nativeImportCalls = 0;
let lastImportAppKey = '';
let lastImportSrcPath = '';

function assertNoLayoutEcho(message: string, mustNotEcho: string, label: string): boolean {
  // The renderer must never learn the sandbox layout: neither the sandbox
  // root nor the specific offending path may appear in a rejection.
  if (message.indexOf('/data/app') >= 0
    || (mustNotEcho.length > 0 && message.indexOf(mustNotEcho) >= 0)) {
    failed++;
    console.error(`[INSPECTION] ${label}: rejection message must not echo the path: ${message}`);
    return false;
  }
  return true;
}

export function runPrivateStoreVaultImportDenialCases(): void {
  installCountingNativeStub();
  const ctx: StubContext = stubContext();
  const proxy: BridgeProxy = new BridgeProxy(
    ctx as ESObject as common.UIAbilityContext,
    undefined as ESObject as webview.WebviewController,
    undefined as ESObject as Mam);
  const pending: Array<Promise<void>> = [];

  // Denial case: the native-call delta is captured SYNCHRONOUSLY around the
  // gate call (the gate runs and — if it wrongly forwards — the native stub
  // runs, both before this function returns). The async assertions then check
  // the promise outcome against that already-settled fact.
  function expectRejects(
    srcPath: string, mustContain: string, mustNotEcho: string, label: string): Promise<void> {
    const before: number = nativeImportCalls;
    const promise: Promise<string> = proxy.driveImportFile(srcPath);
    const nativeCallsAtGate: number = nativeImportCalls - before;
    return promise.then((): void => {
      failed++;
      console.error(`[INSPECTION] ${label}: expected rejection, got success`);
    }).catch((e: Error): void => {
      const message: string = e.message;
      if (message.indexOf(mustContain) < 0) {
        failed++;
        console.error(`[INSPECTION] ${label}: rejection must name the specific denial reason ` +
          `"${mustContain}", got: ${message}`);
        return;
      }
      if (!assertNoLayoutEcho(message, mustNotEcho, label)) {
        return;
      }
      if (nativeCallsAtGate !== 0) {
        failed++;
        console.error(`[INSPECTION] ${label}: rejected src_path reached NativeBinding — ` +
          'the ArkTS denial must happen BEFORE the native sink');
        return;
      }
      passed++;
      console.log(`[INSPECTION] ${label}: rejected as expected — ${message}`);
    });
  }

  // Positive control: the gate must forward exactly one native call carrying
  // ('drive', srcPath), observed at call time.
  function expectResolves(srcPath: string, label: string): Promise<void> {
    const before: number = nativeImportCalls;
    const promise: Promise<string> = proxy.driveImportFile(srcPath);
    const nativeCallsAtGate: number = nativeImportCalls - before;
    const appKeyAtGate: string = lastImportAppKey;
    const srcAtGate: string = lastImportSrcPath;
    return promise.then((): void => {
      if (nativeCallsAtGate !== 1) {
        failed++;
        console.error(`[INSPECTION] ${label}: authorized src_path must reach NativeBinding ` +
          `exactly once, saw ${nativeCallsAtGate}`);
        return;
      }
      if (appKeyAtGate !== 'drive' || srcAtGate !== srcPath) {
        failed++;
        console.error(`[INSPECTION] ${label}: native sink must receive ('drive', srcPath), ` +
          `saw ('${appKeyAtGate}', '${srcAtGate}')`);
        return;
      }
      passed++;
      console.log(`[INSPECTION] ${label}: passed the ArkTS gate and reached NativeBinding once`);
    }).catch((e: Error): void => {
      failed++;
      console.error(`[INSPECTION] ${label}: expected the gate to pass, got: ${e.message}`);
    });
  }

  // 1. Private app stores — every denied dir, one case each. The expected
  //    fragment is the message assertImportPathAuthorized emits for this class.
  pending.push(expectRejects(`${ctx.preferencesDir}/setjoin_shell`, 'private app store',
    ctx.preferencesDir, 'preferences store import denied'));
  pending.push(expectRejects(`${ctx.cacheDir}/webview/Cache/data_1`, 'private app store',
    ctx.cacheDir, 'webview cache import denied'));
  pending.push(expectRejects(`${ctx.tempDir}/tmpfile.bin`, 'private app store',
    ctx.tempDir, 'temp store import denied'));
  pending.push(expectRejects(`${ctx.databaseDir}/entry.db`, 'private app store',
    ctx.databaseDir, 'database store import denied'));

  // 2. The vault and its SQLite siblings — the vault-prefix denial.
  pending.push(expectRejects(`${ctx.filesDir}/guard.db`, 'resolves into the vault',
    `${ctx.filesDir}/guard.db`, 'vault db import denied'));
  pending.push(expectRejects(`${ctx.filesDir}/guard.db-wal`, 'resolves into the vault',
    '', 'vault WAL import denied'));
  pending.push(expectRejects(`${ctx.filesDir}/guard.db-shm`, 'resolves into the vault',
    '', 'vault SHM import denied'));
  pending.push(expectRejects(`${ctx.filesDir}/guard.db-journal`, 'resolves into the vault',
    '', 'vault journal import denied'));

  // 3. Outside the designated import root (inside filesDir but not imports/).
  pending.push(expectRejects(`${ctx.filesDir}/docs/report.pdf`,
    'outside the import-eligible locations', '', 'outside the designated import root denied'));

  // 4. Path-shape denials — the shape check's own messages.
  pending.push(expectRejects('relative/mirror-file.bin', 'src_path must be absolute',
    '', 'relative src_path denied'));
  pending.push(expectRejects(`${ctx.filesDir}/imports/sub/../mirror-file.bin`,
    'must not contain `..` traversal segments', '', '`..` traversal src_path denied'));

  // 5. The designated import root passes the ArkTS gate and is forwarded to
  //    the (stubbed) native sink exactly once as ('drive', srcPath). The
  //    native floor still re-validates mirror-index membership — machine-run
  //    in Rust (binding_confinement_test.rs).
  pending.push(expectResolves(`${ctx.filesDir}/imports/mirror-file.bin`,
    'designated import root passes the ArkTS gate'));

  // The counters above settle with the promises — report only after all do.
  Promise.allSettled(pending).then((): void => {
    console.log(`[INSPECTION] private-store/vault import denial: ${passed} passed, ` +
      `${failed} failed (inspection-only — see header)`);
  });
}
