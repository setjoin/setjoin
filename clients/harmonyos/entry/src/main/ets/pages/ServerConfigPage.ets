// ServerConfigPage — first-run server address entry. NOT a login screen (the
// hosted SPA does login); this is only the server origin the `Web` component
// will point at and the bridge will origin-gate against. Persisted via
// `@ohos.data.preferences` so it's skipped on subsequent launches.
//
// Project convention: "No hardcoded server URLs in client source" — every
// other shell resolves the server from user input; this page is that input
// for the HarmonyOS shell.

import preferences from '@ohos.data.preferences';
import router from '@ohos.router';
import { ThemeColors } from '../common/Theme';
import { hilog } from '@kit.PerformanceAnalysisKit';

const TAG: string = 'ServerConfigPage';
const DOMAIN: number = 0x0001;
const PREFS_NAME: string = 'setjoin_shell';
const KEY_SERVER_URL: string = 'server_url';

/** https-scheme minimum (med-shard2-013, D-CLIENTS-HARMONYOS-ENTRY-003):
 *  normalize user input into the server origin the shell will trust — the Web
 *  src, the bridge permission grammar, the navigation gate, and MAM checkin
 *  all anchor on it. An explicit scheme is accepted ONLY when it is https://;
 *  a scheme-less host defaults to https://. Returns null when the input
 *  cannot become a trust anchor (empty, or any cleartext/unknown scheme such
 *  as http:// — the previous `startsWith('http')` rule let plain-http origins
 *  anchor the shell, putting SPA, credentials, and the bridge grant in
 *  cleartext reach of an on-path attacker). */
export function httpsTrustAnchorFromInput(input: string): string | null {
  const trimmed: string = input.trim();
  if (trimmed.length === 0) {
    return null;
  }
  const schemeMatch: RegExpExecArray | null = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\//.exec(trimmed);
  if (schemeMatch !== null) {
    if (schemeMatch[1].toLowerCase() !== 'https') {
      return null;
    }
    // An authority-less anchor ("https://") names no host — never a trust anchor.
    return trimmed.slice(schemeMatch[0].length).length > 0 ? trimmed : null;
  }
  return `https://${trimmed}`;
}

@Entry
@Component
struct ServerConfigPage {
  @State serverUrl: string = '';
  @State error: string = '';

  aboutToAppear(): void {
    const prefs = preferences.getPreferencesSync(getContext(this), { name: PREFS_NAME });
    const saved: string = prefs.getSync(KEY_SERVER_URL, '') as string;
    // Same https minimum applies to the persisted value: a stale http://
    // anchor saved by an older build must not auto-navigate past this control.
    const anchor: string | null = saved.length > 0 ? httpsTrustAnchorFromInput(saved) : null;
    if (anchor !== null) {
      router.replaceUrl({ url: 'pages/MainPage', params: { serverUrl: anchor } }).catch((e: Error) => {
        hilog.error(DOMAIN, TAG, `auto-navigate to MainPage failed: ${e.message}`);
      });
    }
  }

  connect(): void {
    const trimmed: string = this.serverUrl.trim();
    if (trimmed.length === 0) {
      this.error = 'Server address is required.';
      return;
    }
    const anchor: string | null = httpsTrustAnchorFromInput(trimmed);
    if (anchor === null) {
      this.error = 'Server address must use https:// — plain http is not accepted.';
      return;
    }
    const prefs = preferences.getPreferencesSync(getContext(this), { name: PREFS_NAME });
    prefs.putSync(KEY_SERVER_URL, anchor);
    prefs.flush().catch((e: Error) => hilog.error(DOMAIN, TAG, `flush failed: ${e.message}`));
    router.replaceUrl({ url: 'pages/MainPage', params: { serverUrl: anchor } }).catch((e: Error) => {
      hilog.error(DOMAIN, TAG, `navigate to MainPage failed: ${e.message}`);
    });
  }

  build() {
    Column() {
      Column() {
        Text('SetJoin')
          .fontSize(28)
          .fontWeight(700)
          .fontColor(ThemeColors.text())
        Text('Enter your organization\'s server address.')
          .fontSize(14)
          .fontColor(ThemeColors.textDim())
          .margin({ top: 8 })
      }
      .margin({ top: 96, bottom: 32 })

      Column() {
        if (this.error.length > 0) {
          Text(this.error)
            .fontSize(13)
            .fontColor(ThemeColors.Danger)
            .margin({ bottom: 14 })
        }
        TextInput({ placeholder: 'mail.example.com', text: this.serverUrl })
          .type(InputType.URL)
          .fontSize(16)
          .fontColor(ThemeColors.text())
          .backgroundColor(ThemeColors.glass())
          .borderRadius(10)
          .padding(12)
          .onChange((value: string) => { this.serverUrl = value; })

        Button('Connect')
          .width('100%')
          .height(44)
          .fontSize(16)
          .fontWeight(600)
          .fontColor('#FFFFFF')
          .backgroundColor(ThemeColors.Accent)
          .borderRadius(10)
          .margin({ top: 20 })
          .onClick(() => this.connect())
      }
      .width('100%')
      .constraintSize({ maxWidth: 400 })
      .padding(24)
      .backgroundColor(ThemeColors.glass())
      .borderRadius(16)
      .border({ width: 1, color: ThemeColors.hairline() })
    }
    .width('100%')
    .height('100%')
    .backgroundColor(ThemeColors.bg())
    .padding({ left: 16, right: 16 })
  }
}
