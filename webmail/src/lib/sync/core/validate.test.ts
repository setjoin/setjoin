import { describe, expect, it, vi } from 'vitest';
import {
	MAX_ATTACHED_SCOPES,
	MAX_SCOPE_ID_LENGTH,
	isValidAppKey,
	isValidScopeId,
	isValidScopeKind,
	isValidSeq,
	validateOfflineWipe,
	validateScopeAttachList,
	validateScopeRevoked,
	validateSyncWakeup,
} from './validate.js';

describe('sync/core/validate — fail-closed untrusted frame validation', () => {
	it('validates canonical scopeKind, scopeId, seq, and appKey primitives', () => {
		expect(isValidScopeKind('mailbox')).toBe(true);
		expect(isValidScopeKind('space')).toBe(true);
		expect(isValidScopeKind('channel')).toBe(true);
		expect(isValidScopeKind('drive')).toBe(false);
		expect(isValidScopeKind('__proto__')).toBe(false);
		expect(isValidScopeKind(42)).toBe(false);

		expect(isValidScopeId('42')).toBe(true);
		expect(isValidScopeId('primary')).toBe(true);
		expect(isValidScopeId('org:123/node_4')).toBe(true);
		expect(isValidScopeId('')).toBe(false);
		expect(isValidScopeId('a'.repeat(MAX_SCOPE_ID_LENGTH + 1))).toBe(false);
		expect(isValidScopeId('__proto__')).toBe(false);
		expect(isValidScopeId('constructor')).toBe(false);
		expect(isValidScopeId('prototype')).toBe(false);
		expect(isValidScopeId('../etc/passwd')).toBe(false);
		expect(isValidScopeId('bad space')).toBe(false);
		expect(isValidScopeId('ctrl\nchar')).toBe(false);

		expect(isValidSeq(0)).toBe(true);
		expect(isValidSeq(42)).toBe(true);
		expect(isValidSeq(-1)).toBe(false);
		expect(isValidSeq(1.5)).toBe(false);
		expect(isValidSeq(Number.NaN)).toBe(false);
		expect(isValidSeq(Number.POSITIVE_INFINITY)).toBe(false);
		expect(isValidSeq(Number.MAX_SAFE_INTEGER + 1)).toBe(false);
		expect(isValidSeq('10')).toBe(false);

		expect(isValidAppKey('mail')).toBe(true);
		expect(isValidAppKey('drive')).toBe(true);
		expect(isValidAppKey('calendar')).toBe(false);
		expect(isValidAppKey('__proto__')).toBe(false);
		expect(isValidAppKey(null)).toBe(false);
	});

	it('accepts well-formed SyncWakeup and rejects malformed/abusable frames fail-closed', () => {
		const warn = vi.fn();
		const valid = validateSyncWakeup(
			{
				scopeKind: 'channel',
				scopeId: '77',
				seq: 12,
				dataTypes: ['Message'],
				changed: { Email: 's1' },
				reason: 'message_created',
			},
			warn,
		);
		expect(valid).toEqual({
			scopeKind: 'channel',
			scopeId: '77',
			seq: 12,
			dataTypes: ['Message'],
			changed: Object.assign(Object.create(null), { Email: 's1' }),
			reason: 'message_created',
		});
		expect(warn).not.toHaveBeenCalled();

		const badInputs: unknown[] = [
			null,
			'string',
			[],
			JSON.parse('{"__proto__":{"polluted":true},"scopeKind":"mailbox","scopeId":"1","seq":1}'),
			{ scopeKind: 'unknown', scopeId: '1', seq: 1 },
			{ scopeKind: 'mailbox', scopeId: '', seq: 1 },
			{ scopeKind: 'mailbox', scopeId: 'x'.repeat(200), seq: 1 },
			{ scopeKind: 'mailbox', scopeId: '1', seq: -1 },
			{ scopeKind: 'mailbox', scopeId: '1', seq: Number.NaN },
			{ scopeKind: 'mailbox', scopeId: '1', seq: Number.POSITIVE_INFINITY },
			{ scopeKind: 'mailbox', scopeId: '1', seq: 1.25 },
			{ scopeKind: 'mailbox', scopeId: '1', seq: 1, dataTypes: ['__proto__'] },
			{ scopeKind: 'mailbox', scopeId: '1', seq: 1, changed: { Email: 123 } },
			{ scopeKind: 'mailbox', scopeId: '1', seq: 1, reason: 'r'.repeat(200) },
		];
		for (const bad of badInputs) {
			warn.mockClear();
			expect(validateSyncWakeup(bad, warn)).toBeNull();
			expect(warn).toHaveBeenCalled();
		}
	});

	it('validates ScopeRevoked including optional subtreeAnchorId and rejects malformed frames', () => {
		const warn = vi.fn();
		expect(
			validateScopeRevoked(
				{ scopeKind: 'space', scopeId: '5', subtreeAnchorId: '99', reason: 'acl_revoked' },
				warn,
			),
		).toEqual({
			scopeKind: 'space',
			scopeId: '5',
			subtreeAnchorId: '99',
			reason: 'acl_revoked',
		});
		expect(warn).not.toHaveBeenCalled();

		expect(validateScopeRevoked({ scopeKind: 'space', scopeId: '5', subtreeAnchorId: '../bad' }, warn)).toBeNull();
		expect(validateScopeRevoked({ scopeKind: 'bogus', scopeId: '5' }, warn)).toBeNull();
		expect(validateScopeRevoked({ scopeKind: 'space', scopeId: '' }, warn)).toBeNull();
		expect(warn).toHaveBeenCalledTimes(3);
	});

	it('caps ScopeAttach lists at 512 scopes and rejects oversized/malformed entries fail-closed', () => {
		const warn = vi.fn();
		const exact512 = Array.from({ length: MAX_ATTACHED_SCOPES }, (_, i) => ({
			kind: 'channel',
			id: String(i + 1),
		}));
		const accepted = validateScopeAttachList(exact512, warn);
		expect(accepted).toHaveLength(MAX_ATTACHED_SCOPES);
		expect(warn).not.toHaveBeenCalled();

		// Deduplicates identical entries within limit
		expect(
			validateScopeAttachList([
				{ kind: 'space', id: '1' },
				{ scopeKind: 'space', scopeId: '1' },
			]),
		).toEqual([{ kind: 'space', id: '1' }]);

		// 513 scopes rejected fail-closed
		const overLimit = [...exact512, { kind: 'channel', id: '9999' }];
		expect(validateScopeAttachList(overLimit, warn)).toBeNull();
		expect(validateScopeAttachList('not-array', warn)).toBeNull();
		expect(validateScopeAttachList([{ kind: 'bad', id: '1' }], warn)).toBeNull();
		expect(warn).toHaveBeenCalledTimes(3);
	});

	it('validates offline.wipe against NATIVE_DB_APP_KEYS and rejects unknown appKey or bad deviceId', () => {
		const warn = vi.fn();
		expect(validateOfflineWipe({ appKey: 'mail', deviceId: 7 }, warn)).toEqual({
			appKey: 'mail',
			deviceId: 7,
		});
		expect(validateOfflineWipe({ appKey: 'drive' }, warn)).toEqual({ appKey: 'drive' });
		expect(validateOfflineWipe({}, warn)).toEqual({});
		expect(warn).not.toHaveBeenCalled();

		expect(validateOfflineWipe({ appKey: 'secrets' }, warn)).toBeNull();
		expect(validateOfflineWipe({ appKey: 'mail', deviceId: -3 }, warn)).toBeNull();
		expect(validateOfflineWipe({ appKey: 'mail', deviceId: Number.NaN }, warn)).toBeNull();
		expect(warn).toHaveBeenCalledTimes(3);
	});
});
