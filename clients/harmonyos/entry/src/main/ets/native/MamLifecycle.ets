// Pure MAM lifecycle transitions for the trusted Harmony native host.
// HTTP, secure-state writes, ArkWeb storage clearing and platform enforcement
// remain effects executed by Mam.ets. The HMAC secret never enters ArkWeb.

import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import { util } from '@kit.ArkTS';

export interface MamPolicyDto {
  policy_version: number;
  copy_paste: string;
  screen_capture: string;
  encryption: string;
  watermark: boolean;
  notification_profile: string;
  max_offline_days: number;
}

export interface MamCheckinBody {
  device_id: number;
  policy_version: number;
}

export interface MamCheckinRequest {
  url: string;
  headers: Record<string, string>;
  body: MamCheckinBody;
}

export interface MamCheckinResponse {
  policy_version?: number;
  policy?: Record<string, string>;
  wipe_requested?: boolean;
}

export interface MamCheckinOutcome {
  ran: boolean;
  policy_version: number;
  wiped: boolean;
}

export interface MamEffectIntent {
  type: string;
  device_id?: string;
  policy?: MamPolicyDto;
}

export interface MamCheckinTransition {
  outcome: MamCheckinOutcome;
  effects: Array<MamEffectIntent>;
}

export function policyFromMap(version: number, map: Record<string, string>): MamPolicyDto {
  const maxOfflineDays: number = Number.parseInt(map.max_offline_days ?? '', 10);
  return {
    policy_version: version,
    copy_paste: map.copy_paste ?? '',
    screen_capture: map.screen_capture ?? '',
    encryption: map.encryption ?? '',
    watermark: map.watermark === 'true',
    notification_profile: map.notification_profile ?? '',
    max_offline_days: Number.isNaN(maxOfflineDays) ? 0 : maxOfflineDays,
  };
}

export function knownPolicyVersion(rawPolicy: string | null): number {
  if (rawPolicy === null) {
    return 0;
  }
  try {
    const parsed = JSON.parse(rawPolicy) as MamPolicyDto;
    return typeof parsed.policy_version === 'number' ? parsed.policy_version : 0;
  } catch (_e) {
    return 0;
  }
}

function bytesToHex(bytes: Uint8Array): string {
  let out: string = '';
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
}

export function deviceHmac(secret: string, deviceId: number, timestamp: string): string {
  const encoder = new util.TextEncoder();
  const generator = cryptoFramework.createSymKeyGenerator('HMAC');
  const symKey = generator.convertKeySync({ data: encoder.encode(secret) });
  const mac = cryptoFramework.createMac('SHA256');
  mac.initSync(symKey);
  mac.updateSync({ data: encoder.encode(`${deviceId}:${timestamp}`) });
  return bytesToHex(mac.doFinalSync().data);
}

export function buildCheckinRequest(serverUrl: string, deviceId: number, secret: string,
  timestamp: string, knownVersion: number): MamCheckinRequest {
  return {
    url: `${serverUrl.replace(/\/+$/, '')}/device/checkin`,
    headers: {
      'Content-Type': 'application/json',
      'X-Device-HMAC': deviceHmac(secret, deviceId, timestamp),
      'X-Device-Timestamp': timestamp,
      'If-None-Match': knownVersion.toString(),
    },
    body: { device_id: deviceId, policy_version: knownVersion },
  };
}

export function reduceCheckinResponse(status: number, knownVersion: number, deviceId: number,
  body: MamCheckinResponse | null): MamCheckinTransition {
  if (status === 304) {
    return {
      outcome: { ran: true, policy_version: knownVersion, wiped: false },
      effects: [],
    };
  }
  if (status < 200 || status >= 300) {
    throw new Error(`mam checkin: server returned ${status}`);
  }
  if (body === null) {
    throw new Error('mam checkin: bad response');
  }
  const version: number = body.policy_version ?? 0;
  if (body.wipe_requested === true) {
    return {
      outcome: { ran: true, policy_version: version, wiped: true },
      effects: [{ type: 'latch_wipe' }, { type: 'clear_web_storage' }],
    };
  }
  const policy: MamPolicyDto = policyFromMap(version, body.policy ?? {});
  return {
    outcome: { ran: true, policy_version: version, wiped: false },
    effects: [
      { type: 'cache_device', device_id: deviceId.toString() },
      { type: 'cache_policy', policy: policy },
      { type: 'enforce_policy', policy: policy },
    ],
  };
}
