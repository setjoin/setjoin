// Fail-closed validator for untrusted WS / SSE / Electron renderer IPC frames
// entering SyncCoordinator (Wave 2.8, #555). Never throws into the coordinator
// loop — malformed or abusable frames are dropped with a structured warning.

import { NATIVE_DB_APP_KEYS, type NativeDbAppKey } from '../../native/types.js';
import {
	SCOPE_KINDS,
	scopeKeyString,
	type OfflineWipeEvent,
	type ScopeKey,
	type ScopeKind,
	type ScopeRevokedEvent,
	type SyncWakeup,
} from './types.js';

export const MAX_ATTACHED_SCOPES = 512;
export const MAX_SCOPE_ID_LENGTH = 128;

const SCOPE_KIND_SET: ReadonlySet<string> = new Set(SCOPE_KINDS);
const APP_KEY_SET: ReadonlySet<string> = new Set(NATIVE_DB_APP_KEYS);
const FORBIDDEN_KEYS: ReadonlySet<string> = new Set(['__proto__', 'constructor', 'prototype']);
const SAFE_SCOPE_ID_RE = /^[A-Za-z0-9._:@/-]{1,128}$/;

export type ValidationWarnFn = (reason: string, detail?: Record<string, unknown>) => void;

function isPlainObject(value: unknown): value is Record<string, unknown> {
	if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
	if (
		Object.prototype.hasOwnProperty.call(value, '__proto__') ||
		Object.prototype.hasOwnProperty.call(value, 'constructor') ||
		Object.prototype.hasOwnProperty.call(value, 'prototype')
	) {
		return false;
	}
	return true;
}

export function isValidScopeKind(raw: unknown): raw is ScopeKind {
	return typeof raw === 'string' && SCOPE_KIND_SET.has(raw);
}

export function isValidScopeId(raw: unknown): raw is string {
	if (typeof raw !== 'string') return false;
	if (raw.length === 0 || raw.length > MAX_SCOPE_ID_LENGTH) return false;
	if (FORBIDDEN_KEYS.has(raw)) return false;
	if (raw.includes('..')) return false;
	return SAFE_SCOPE_ID_RE.test(raw);
}

export function isValidSeq(raw: unknown): raw is number {
	return typeof raw === 'number' && Number.isFinite(raw) && Number.isSafeInteger(raw) && raw >= 0;
}

export function isValidAppKey(raw: unknown): raw is NativeDbAppKey {
	return typeof raw === 'string' && APP_KEY_SET.has(raw);
}

function reject(onReject: ValidationWarnFn | undefined, reason: string, detail?: Record<string, unknown>): null {
	onReject?.(reason, detail);
	return null;
}

/**
 * Validates an untrusted `SyncWakeup` frame fail-closed.
 * Accepts canonical `{ scopeKind, scopeId, seq }` and optional string `reason` / `dataTypes` / `changed`.
 */
export function validateSyncWakeup(raw: unknown, onReject?: ValidationWarnFn): SyncWakeup | null {
	if (!isPlainObject(raw)) return reject(onReject, 'sync_wakeup: non-object or forbidden keys');
	if (!isValidScopeKind(raw.scopeKind)) {
		return reject(onReject, 'sync_wakeup: invalid scopeKind', { scopeKind: String(raw.scopeKind) });
	}
	if (!isValidScopeId(raw.scopeId)) {
		return reject(onReject, 'sync_wakeup: invalid scopeId');
	}
	if (!isValidSeq(raw.seq)) {
		return reject(onReject, 'sync_wakeup: invalid seq', { seq: String(raw.seq) });
	}

	let dataTypes: string[] | undefined;
	if (raw.dataTypes !== undefined) {
		if (!Array.isArray(raw.dataTypes) || raw.dataTypes.length > 64) {
			return reject(onReject, 'sync_wakeup: invalid dataTypes');
		}
		dataTypes = [];
		for (const item of raw.dataTypes) {
			if (typeof item !== 'string' || item.length === 0 || item.length > 64 || FORBIDDEN_KEYS.has(item)) {
				return reject(onReject, 'sync_wakeup: invalid dataType entry');
			}
			dataTypes.push(item);
		}
	}

	let changed: Record<string, string> | undefined;
	if (raw.changed !== undefined) {
		if (!isPlainObject(raw.changed)) {
			return reject(onReject, 'sync_wakeup: invalid changed map');
		}
		const out: Record<string, string> = Object.create(null) as Record<string, string>;
		const entries = Object.entries(raw.changed);
		if (entries.length > 64) return reject(onReject, 'sync_wakeup: changed map too large');
		for (const [k, v] of entries) {
			if (FORBIDDEN_KEYS.has(k) || k.length === 0 || k.length > 64 || typeof v !== 'string' || v.length > 256) {
				return reject(onReject, 'sync_wakeup: invalid changed entry');
			}
			out[k] = v;
		}
		changed = out;
	}

	let reason: string | undefined;
	if (raw.reason !== undefined) {
		if (typeof raw.reason !== 'string' || raw.reason.length > 128) {
			return reject(onReject, 'sync_wakeup: invalid reason');
		}
		reason = raw.reason;
	}

	return {
		scopeKind: raw.scopeKind,
		scopeId: raw.scopeId,
		seq: raw.seq,
		...(dataTypes !== undefined ? { dataTypes } : {}),
		...(changed !== undefined ? { changed } : {}),
		...(reason !== undefined ? { reason } : {}),
	};
}

/**
 * Validates an untrusted `ScopeRevoked` / `scope_revoked` frame fail-closed.
 */
export function validateScopeRevoked(raw: unknown, onReject?: ValidationWarnFn): ScopeRevokedEvent | null {
	if (!isPlainObject(raw)) return reject(onReject, 'scope_revoked: non-object or forbidden keys');
	if (!isValidScopeKind(raw.scopeKind)) {
		return reject(onReject, 'scope_revoked: invalid scopeKind', { scopeKind: String(raw.scopeKind) });
	}
	if (!isValidScopeId(raw.scopeId)) {
		return reject(onReject, 'scope_revoked: invalid scopeId');
	}

	let subtreeAnchorId: string | undefined;
	if (raw.subtreeAnchorId !== undefined && raw.subtreeAnchorId !== null) {
		if (!isValidScopeId(raw.subtreeAnchorId)) {
			return reject(onReject, 'scope_revoked: invalid subtreeAnchorId');
		}
		subtreeAnchorId = raw.subtreeAnchorId;
	}

	let reason: string | undefined;
	if (raw.reason !== undefined && raw.reason !== null) {
		if (typeof raw.reason !== 'string' || raw.reason.length > 128) {
			return reject(onReject, 'scope_revoked: invalid reason');
		}
		reason = raw.reason;
	}

	return {
		scopeKind: raw.scopeKind,
		scopeId: raw.scopeId,
		...(subtreeAnchorId !== undefined ? { subtreeAnchorId } : {}),
		...(reason !== undefined ? { reason } : {}),
	};
}

/**
 * Validates a `ScopeAttach` / `ScopeDetach` scope list fail-closed.
 * Rejects non-arrays, lists exceeding `MAX_ATTACHED_SCOPES` (512), or any malformed entry.
 */
export function validateScopeAttachList(raw: unknown, onReject?: ValidationWarnFn): ScopeKey[] | null {
	if (!Array.isArray(raw)) return reject(onReject, 'scope_attach: expected array');
	if (raw.length > MAX_ATTACHED_SCOPES) {
		return reject(onReject, 'scope_attach: exceeds max scopes', { count: raw.length, max: MAX_ATTACHED_SCOPES });
	}
	const seen = new Set<string>();
	const out: ScopeKey[] = [];
	for (const entry of raw) {
		if (!isPlainObject(entry)) return reject(onReject, 'scope_attach: non-object scope entry');
		const kind = entry.kind ?? entry.scopeKind;
		const id = entry.id ?? entry.scopeId;
		if (!isValidScopeKind(kind) || !isValidScopeId(id)) {
			return reject(onReject, 'scope_attach: invalid scope entry');
		}
		const scope: ScopeKey = { kind, id };
		const key = scopeKeyString(scope);
		if (!seen.has(key)) {
			seen.add(key);
			out.push(scope);
		}
	}
	return out;
}

/**
 * Validates an untrusted `offline.wipe` control frame fail-closed.
 * Enforces `appKey` against `NATIVE_DB_APP_KEYS` when present.
 */
export function validateOfflineWipe(raw: unknown, onReject?: ValidationWarnFn): OfflineWipeEvent | null {
	if (!isPlainObject(raw)) return reject(onReject, 'offline.wipe: non-object or forbidden keys');

	let appKey: NativeDbAppKey | undefined;
	if (raw.appKey !== undefined && raw.appKey !== null) {
		if (!isValidAppKey(raw.appKey)) {
			return reject(onReject, 'offline.wipe: invalid appKey', { appKey: String(raw.appKey) });
		}
		appKey = raw.appKey;
	}

	let deviceId: number | undefined;
	if (raw.deviceId !== undefined && raw.deviceId !== null) {
		if (!isValidSeq(raw.deviceId)) {
			return reject(onReject, 'offline.wipe: invalid deviceId');
		}
		deviceId = raw.deviceId;
	}

	let reason: string | undefined;
	if (raw.reason !== undefined && raw.reason !== null) {
		if (typeof raw.reason !== 'string' || raw.reason.length > 128) {
			return reject(onReject, 'offline.wipe: invalid reason');
		}
		reason = raw.reason;
	}

	return {
		...(appKey !== undefined ? { appKey } : {}),
		...(deviceId !== undefined ? { deviceId } : {}),
		...(reason !== undefined ? { reason } : {}),
	};
}
