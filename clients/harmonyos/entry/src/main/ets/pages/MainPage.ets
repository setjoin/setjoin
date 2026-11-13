// MainPage — the ArkWeb host page. Replaces the pre-decision `InboxPage.ets`
// (deleted, Task 8): decoupled from `MailCore.ets` (also deleted) since the
// WebView now does JMAP directly, per client-unification. Hosts the
// responsive webmail SPA in a single `Web` component and wires the
// `window.setjoinNative` bridge — see clients/AGENTS.md's HarmonyOS section
// and retired-docs:superpowers/plans/archive/2026-07-04-client-unification-harmonyos-arkweb.md.

import router from '@ohos.router';
import { webview } from '@kit.ArkWeb';
import ohosUrl from '@ohos.url';
import { common } from '@kit.AbilityKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { ThemeColors } from '../common/Theme';
import { BridgeProxy } from '../native/BridgeProxy';
import { buildBridgeShimScript } from '../native/BridgeShim';
import { Mam } from '../native/Mam';
import {
  DEFAULT_MAM_ROLLOUT_MODE,
  MamLifecycleComposition,
  MamLifecycleOwner,
} from '../native/MamLifecycleOwner';

const TAG: string = 'MainPage';
const DOMAIN: number = 0x0001;
const PROXY_NAME: string = 'ohosNative';
const PROXY_METHODS: Array<string> = [
  'ping',
  'vaultUnlock', 'vaultIsUnlocked', 'vaultListTotp', 'vaultGenerateTotp',
  'secureStoreGet', 'secureStoreSet', 'secureStoreRemove',
  'dbOpen', 'dbIsOpen', 'dbExec', 'dbQuery', 'dbWipe',
  'mamGetPolicy', 'mamIsWiped', 'deviceProof',
  'pushRegister', 'pushDevicePublicKey', 'notify', 'openExternal', 'share', 'pickFile',
  // Drive P3 secure-vault byte plane (ARCH-017) — the four in-memory/single-row
  // ops stay synchronous; the four that stream a whole file/chunk are below.
  'driveHasChunk', 'driveDeleteChunks', 'driveServeGrant', 'driveServeRevoke',
];
// Drive P3's streaming ops are genuinely async on the Rust side (napi
// `AsyncTask`s, batch-1 #4) — registered here, not in PROXY_METHODS above, so
// ArkWeb awaits the native Promise instead of serializing it as a plain value.
const PROXY_ASYNC_METHODS: Array<string> = [
  'driveImportFile', 'driveFetchChunk', 'drivePushChunk', 'driveServeStart',
];

interface MainPageParams {
  serverUrl?: string;
}

/** Build the `registerJavaScriptProxy` `permission` grammar (ground-truthed
 *  against the official ArkWeb sample — see the plan doc) scoping every
 *  registered method to the configured server origin only. */
function buildOriginPermission(serverUrl: string): string {
  const parsed = new ohosUrl.URL(serverUrl);
  const scheme: string = parsed.protocol.replace(':', '');
  const host: string = parsed.hostname;
  const port: string = parsed.port;
  // ponytail: built via string concatenation, not JSON.stringify(objectLiteral)
  // — matches the official ArkWeb sample's own pattern (arkts-no-untyped-obj-
  // literals rejects ad-hoc `{scheme,host,...}` object literals with no
  // declared interface; a hand-typed JSON string sidesteps that cleanly for
  // a one-off permission payload).
  return '{"javascriptProxyPermission":{"urlPermissionList":[{"scheme":"' + scheme +
    '","host":"' + host + '","port":"' + port + '","path":""}]}}';
}

@Entry
@Component
struct MainPage {
  @State serverUrl: string = '';
  controller: webview.WebviewController = new webview.WebviewController();
  private mam: Mam | null = null;
  private mamLifecycleOwner: MamLifecycleOwner | null = null;
  private registered: boolean = false;

  aboutToAppear(): void {
    const params = router.getParams() as MainPageParams;
    this.serverUrl = (params && params.serverUrl) ? params.serverUrl : '';
    if (this.serverUrl.length === 0) {
      router.replaceUrl({ url: 'pages/ServerConfigPage' }).catch((e: Error) => {
        hilog.error(DOMAIN, TAG, `no serverUrl, back to ServerConfigPage: ${e.message}`);
      });
    }
  }

  aboutToDisappear(): void {
    if (this.mamLifecycleOwner !== null) {
      MamLifecycleComposition.uninstall(this.mamLifecycleOwner);
      this.mamLifecycleOwner = null;
    }
  }

  private registerBridge(): void {
    if (this.registered || this.serverUrl.length === 0) {
      return;
    }
    const context = getContext(this) as common.UIAbilityContext;
    this.mam = new Mam(this.serverUrl, async (): Promise<void> => {
      await this.controller.runJavaScript(`
        try {
          localStorage.clear();
          sessionStorage.clear();
          if (window.indexedDB && indexedDB.databases) {
            indexedDB.databases().then(dbs =>
              dbs.forEach(d => d.name && indexedDB.deleteDatabase(d.name))
            ).catch(() => {});
          }
          if (window.caches && caches.keys) {
            caches.keys().then(ks => ks.forEach(k => caches.delete(k))).catch(() => {});
          }
          window.dispatchEvent(new Event('setjoin-mam-wiped'));
        } catch (_e) {}
      `);
    });
    this.mamLifecycleOwner = new MamLifecycleOwner(
      DEFAULT_MAM_ROLLOUT_MODE,
      async (): Promise<void> => { await this.mam?.checkin(); },
    );
    MamLifecycleComposition.install(this.mamLifecycleOwner);
    const proxy = new BridgeProxy(context, this.controller, this.mam);
    try {
      this.controller.registerJavaScriptProxy(
        proxy, PROXY_NAME, PROXY_METHODS,
        PROXY_ASYNC_METHODS, // Drive P3's four streaming ops — see the const's doc comment.
        buildOriginPermission(this.serverUrl),
      );
      this.registered = true;
    } catch (e) {
      MamLifecycleComposition.uninstall(this.mamLifecycleOwner);
      this.mamLifecycleOwner = null;
      hilog.error(DOMAIN, TAG, `registerJavaScriptProxy failed: ${JSON.stringify(e)}`);
    }
  }

  /** Origin gate (ADR-013 invariant, ArkWeb analogue of Electron's
   *  `will-navigate` deny-off-origin check): deny any main-frame navigation
   *  whose origin isn't the configured server's. Defense in depth alongside
   *  the `permission` grammar scoping the bridge itself. */
  private isNavigationAllowed(requestUrl: string): boolean {
    try {
      const target = new ohosUrl.URL(requestUrl);
      const configured = new ohosUrl.URL(this.serverUrl);
      return target.protocol === configured.protocol
        && target.hostname === configured.hostname
        && target.port === configured.port;
    } catch (e) {
      return false; // unparseable URL — deny by default.
    }
  }

  build() {
    Column() {
      if (this.serverUrl.length > 0) {
        Web({ src: this.serverUrl, controller: this.controller })
          .width('100%')
          .height('100%')
          .javaScriptAccess(true)
          .domStorageAccess(true)
          .fileAccess(false)
          .onControllerAttached(() => this.registerBridge())
          .javaScriptOnDocumentStart([{ script: buildBridgeShimScript(), scriptRules: ['*'] }])
          .onLoadIntercept((event: OnLoadInterceptEvent): boolean => {
            const requestUrl: string = event.data.getRequestUrl();
            if (event.data.isMainFrame() && !this.isNavigationAllowed(requestUrl)) {
              hilog.warn(DOMAIN, TAG, `blocked off-origin navigation: ${requestUrl}`);
              return true; // block
            }
            return false; // allow
          })
      }
    }
    .width('100%')
    .height('100%')
    .backgroundColor(ThemeColors.bg())
  }
}
