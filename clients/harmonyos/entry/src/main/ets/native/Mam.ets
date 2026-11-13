// Mam — MAM (Mobile Application Management) device-trust lifecycle. ArkTS
// port of clients/desktop/electron/src/mam.ts / clients/desktop/src-tauri/src/mam.rs
// for the HarmonyOS NEXT shell: HMAC-signed device checkin, policy caching,
// remote wipe, and screenshot block. Absorbs the pre-decision
// `MAMEnforcer.ets`'s policy-enforcement logic (screenshot block via window
// privacy mode) — that file is deleted once merged (Task 8).
//
// Wire contract (must stay byte-identical to authserver's `VerifyDeviceRequest`):
//   X-Device-HMAC      = hex(HMAC-SHA256(secret, "{device_id}:{ts}"))
//   X-Device-Timestamp = unix seconds
//
// ponytail: HMAC is computed here in ArkTS via `@kit.CryptoArchitectureKit`
// (HarmonyOS's stdlib-equivalent crypto API — `cryptoFramework.createMac`
// has fully synchronous `initSync`/`updateSync`/`doFinalSync` variants), not
// added to the `ohos-native` Rust crate — mirrors Electron's choice to use
// Node's built-in `crypto` rather than round-tripping through Rust for a
// computation the trusted host layer already does natively. The secret
// crosses from guard-core into ArkTS (the trusted app layer, analogous to
// Electron's main process) but never into the web content the bridge serves.

import http from '@ohos.net.http';
import { window } from '@kit.ArkUI';
import { pasteboard } from '@kit.BasicServicesKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { NativeBinding } from './NativeBinding';
import {
  buildCheckinRequest,
  deviceHmac,
  knownPolicyVersion,
  reduceCheckinResponse,
  MamCheckinRequest,
  MamCheckinResponse,
  MamEffectIntent,
  MamPolicyDto,
} from './MamLifecycle';

export { policyFromMap } from './MamLifecycle';
export type { MamPolicyDto } from './MamLifecycle';

const TAG: string = 'Mam';
const DOMAIN: number = 0x0001;

export class Mam {
  private serverUrl: string = '';
  private clearWebStorage: () => Promise<void>;

  constructor(serverUrl: string, clearWebStorage: () => Promise<void>) {
    this.serverUrl = serverUrl;
    this.clearWebStorage = clearWebStorage;
  }

  /** Cache enrolment credentials + reset the wipe latch. Mirrors `mam_enroll`. */
  enroll(deviceId: string, hmacSecret: string): void {
    NativeBinding.secureStoreSet('mam:device_id', deviceId);
    NativeBinding.secureStoreSet('mam:hmac_secret', hmacSecret);
    NativeBinding.mamStoreDeviceId(deviceId);
    NativeBinding.mamClearWiped();
  }

  /** Device-proof HMAC for an outgoing request — the secret never leaves ArkTS. */
  static deviceProof(deviceId: string, timestampSeconds: string): string | null {
    const secret: string | null = NativeBinding.secureStoreGet('mam:hmac_secret');
    if (secret === null) {
      return null;
    }
    const deviceIdNumber: number = Number.parseInt(deviceId, 10);
    return Number.isNaN(deviceIdNumber) ? null : deviceHmac(secret, deviceIdNumber, timestampSeconds);
  }

  /** One checkin round trip: POST device fingerprint, apply the returned policy. */
  async checkin(): Promise<void> {
    const deviceId: string | null = NativeBinding.secureStoreGet('mam:device_id');
    const secret: string | null = NativeBinding.secureStoreGet('mam:hmac_secret');
    if (deviceId === null || secret === null) {
      return; // not enrolled yet
    }

    const deviceIdNumber: number = Number.parseInt(deviceId, 10);
    if (Number.isNaN(deviceIdNumber)) {
      hilog.error(DOMAIN, TAG, 'checkin skipped: invalid enrolled device id');
      return;
    }

    const ts: string = Math.floor(Date.now() / 1000).toString();
    const cachedVersion: number = knownPolicyVersion(NativeBinding.mamGetPolicy());
    const request: MamCheckinRequest = buildCheckinRequest(
      this.serverUrl, deviceIdNumber, secret, ts, cachedVersion);

    const req = http.createHttp();
    try {
      const response = await req.request(request.url, {
        method: http.RequestMethod.POST,
        header: request.headers,
        extraData: JSON.stringify(request.body),
        connectTimeout: 15000,
        readTimeout: 15000,
      });

      const body: MamCheckinResponse | null = response.responseCode === 304 ||
        response.responseCode < 200 || response.responseCode >= 300 ? null :
          JSON.parse(response.result as string) as MamCheckinResponse;
      const transition = reduceCheckinResponse(response.responseCode, cachedVersion, deviceIdNumber, body);
      for (const effect of transition.effects) {
        await this.executeEffect(effect);
      }
    } catch (e) {
      hilog.error(DOMAIN, TAG, `checkin failed: ${JSON.stringify(e)}`);
    } finally {
      req.destroy();
    }
  }

  private async executeEffect(effect: MamEffectIntent): Promise<void> {
    if (effect.type === 'latch_wipe') {
      NativeBinding.mamMarkWiped();
      hilog.warn(DOMAIN, TAG, 'remote wipe latched');
      return;
    }
    if (effect.type === 'clear_web_storage') {
      await this.clearWebStorage();
      return;
    }
    if (effect.type === 'cache_device' && effect.device_id !== undefined) {
      NativeBinding.mamStoreDeviceId(effect.device_id);
      return;
    }
    if (effect.type === 'cache_policy' && effect.policy !== undefined) {
      NativeBinding.mamStorePolicy(JSON.stringify(effect.policy));
      return;
    }
    if (effect.type === 'enforce_policy' && effect.policy !== undefined) {
      this.applyPolicy(effect.policy);
    }
  }

  /**
   * Apply a MAM policy: screenshot block (window privacy mode) + pasteboard policy.
   *
   * D-CLIENTS-HARMONYOS-ENTRY-007 — per-policy enforcement honesty. This shell
   * genuinely enforces `screen_capture: block` (setWindowPrivacyMode(true)).
   * It CANNOT enforce `copy_paste: block_external` today (the pasteboard API
   * exposes no block/clear hook drivable from the shell — the `update`
   * listener only OBSERVES), and `encryption` / `watermark` /
   * `notification_profile` / `max_offline_days` have no shell-side
   * implementation at all yet. None of these may pass silently: every
   * accepted-but-unenforced value is logged as NOT ENFORCED so the
   * under-enforcement is visible to the policy source, and the pasteboard hook
   * is explicitly observe-only — it must never be read as a `block`. MAM is
   * not execute-mode for these values until real enforcement lands.
   */
  private applyPolicy(policy: MamPolicyDto): void {
    if (policy.screen_capture === 'block') {
      window.getLastWindow(getContext()).then((win: window.Window): void => {
        win.setWindowPrivacyMode(true);
      }).catch((e: Error) => hilog.error(DOMAIN, TAG, `setWindowPrivacyMode: ${e.message}`));
    }
    if (policy.copy_paste === 'block_external') {
      hilog.warn(DOMAIN, TAG, 'copy_paste=block_external NOT ENFORCED on HarmonyOS: pasteboard hook is observe-only, not a block');
      try {
        pasteboard.getSystemPasteboard().on('update', (): void => {
          hilog.warn(DOMAIN, TAG, 'pasteboard access observed (observe-only; block_external NOT enforced)');
        });
      } catch (e) {
        hilog.error(DOMAIN, TAG, `pasteboard watch: ${JSON.stringify(e)}`);
      }
    }
    // Accepted policy dimensions with no shell-side enforcement yet — never
    // pass silently (D-CLIENTS-HARMONYOS-ENTRY-007).
    if (policy.encryption !== '') {
      hilog.warn(DOMAIN, TAG, `encryption=${policy.encryption} NOT ENFORCED on HarmonyOS (no shell-side implementation)`);
    }
    if (policy.watermark) {
      hilog.warn(DOMAIN, TAG, 'watermark=true NOT ENFORCED on HarmonyOS (no shell-side implementation)');
    }
    if (policy.notification_profile !== '') {
      hilog.warn(DOMAIN, TAG, `notification_profile=${policy.notification_profile} NOT ENFORCED on HarmonyOS (no shell-side implementation)`);
    }
    if (policy.max_offline_days > 0) {
      hilog.warn(DOMAIN, TAG, `max_offline_days=${policy.max_offline_days} NOT ENFORCED on HarmonyOS (no shell-side implementation)`);
    }
  }

  isWiped(): boolean {
    return NativeBinding.mamIsWiped();
  }

  getPolicy(): string | null {
    return NativeBinding.mamGetPolicy();
  }
}
