//! Pure MAM lifecycle transitions for the Electron native host.
//!
//! This module performs deterministic request construction and response
//! reduction only. `mam.ts` remains the adapter that owns HTTP and executes
//! native/storage effects. It is main-process code: enrolment secrets must
//! never be imported by preload, bridge, or renderer modules.

import { createHmac } from 'node:crypto';

export interface MamPolicy {
	policy_version: number;
	copy_paste: string;
	screen_capture: string;
	encryption: string;
	watermark: boolean;
	notification_profile: string;
	max_offline_days: number;
}

export interface CheckinRequest {
	url: string;
	headers: Record<string, string>;
	body: { device_id: number; policy_version: number };
}

export interface CheckinOutcome {
	ran: boolean;
	policy_version: number;
	wiped: boolean;
}

export type MamEffectIntent =
	| { type: 'latch_wipe' }
	| { type: 'clear_web_storage' }
	| { type: 'cache_device'; deviceId: string }
	| { type: 'cache_policy'; policy: MamPolicy }
	| { type: 'enforce_policy'; policy: MamPolicy };

export interface CheckinTransition {
	outcome: CheckinOutcome;
	effects: MamEffectIntent[];
}

interface CheckinResponse {
	policy_version?: number;
	policy?: Record<string, string>;
	wipe_requested?: boolean;
}

export function defaultPolicy(version: number): MamPolicy {
	return {
		policy_version: version,
		copy_paste: '',
		screen_capture: '',
		encryption: '',
		watermark: false,
		notification_profile: '',
		max_offline_days: 0,
	};
}

export function policyFromMap(version: number, map: Record<string, string>): MamPolicy {
	const policy = defaultPolicy(version);
	if (map.copy_paste !== undefined) policy.copy_paste = map.copy_paste;
	if (map.screen_capture !== undefined) policy.screen_capture = map.screen_capture;
	if (map.encryption !== undefined) policy.encryption = map.encryption;
	if (map.watermark !== undefined) policy.watermark = map.watermark === 'true';
	if (map.notification_profile !== undefined) policy.notification_profile = map.notification_profile;
	if (map.max_offline_days !== undefined) {
		const days = Number.parseInt(map.max_offline_days, 10);
		if (!Number.isNaN(days)) policy.max_offline_days = days;
	}
	return policy;
}

export function deviceHmac(secret: string, deviceId: number | string, timestamp: string): string {
	return createHmac('sha256', secret).update(`${deviceId}:${timestamp}`).digest('hex');
}

export function knownPolicyVersion(rawPolicy: string | null): number {
	if (!rawPolicy) return 0;
	try {
		const version = (JSON.parse(rawPolicy) as Partial<MamPolicy>).policy_version;
		return typeof version === 'number' ? version : 0;
	} catch {
		return 0;
	}
}

export function buildCheckinRequest(
	serverUrl: string,
	deviceId: number,
	secret: string,
	timestamp: string,
	knownVersion: number,
): CheckinRequest {
	return {
		url: `${serverUrl.replace(/\/+$/, '')}/device/checkin`,
		headers: {
			'Content-Type': 'application/json',
			'X-Device-HMAC': deviceHmac(secret, deviceId, timestamp),
			'X-Device-Timestamp': timestamp,
			'If-None-Match': String(knownVersion),
		},
		body: { device_id: deviceId, policy_version: knownVersion },
	};
}

export function reduceCheckinResponse(
	status: number,
	knownVersion: number,
	deviceId: number,
	body: CheckinResponse | null,
): CheckinTransition {
	if (status === 304) {
		return {
			outcome: { ran: true, policy_version: knownVersion, wiped: false },
			effects: [],
		};
	}
	if (status < 200 || status >= 300) {
		throw new Error(`mam checkin: server returned ${status}`);
	}
	if (body === null || typeof body !== 'object') {
		throw new Error('mam checkin: bad response');
	}

	const version = typeof body.policy_version === 'number' ? body.policy_version : 0;
	if (body.wipe_requested === true) {
		return {
			outcome: { ran: true, policy_version: version, wiped: true },
			effects: [{ type: 'latch_wipe' }, { type: 'clear_web_storage' }],
		};
	}

	const policy = policyFromMap(version, body.policy ?? {});
	return {
		outcome: { ran: true, policy_version: version, wiped: false },
		effects: [
			{ type: 'cache_device', deviceId: String(deviceId) },
			{ type: 'cache_policy', policy },
			{ type: 'enforce_policy', policy },
		],
	};
}
