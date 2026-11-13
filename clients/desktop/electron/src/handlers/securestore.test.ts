import { describe, it, expect, vi } from 'vitest';
import { assertSecureStoreKeyRendererAllowed, makeSecureStoreHandlers } from './securestore';
import type { NativeBinding } from '../native';

function fakeNative(over: Partial<NativeBinding> = {}): NativeBinding {
	return {
		vaultUnlock: () => true,
		vaultIsUnlocked: () => true,
		vaultListTotp: () => [],
		vaultGenerateTotp: () => '000000',
		secureStoreGet: vi.fn(() => null),
		secureStoreSet: vi.fn(),
		secureStoreRemove: vi.fn(),
		dbOpen: () => {},
		dbIsOpen: () => true,
		dbExec: () => 0,
		dbExecSchemaInit: () => 0,
		dbTransactionBatch: () => 0,
		dbMigrateStore: () => '{"version":2}',
		dbQuery: () => '[]',
		dbWipe: () => {},
		driveImportFile: async () => '{}',
		driveFetchChunk: async () => {},
		drivePushChunk: async () => 200,
		driveHasChunk: () => true,
		driveDeleteChunks: () => 0,
		driveSetConfinement: () => {},
		driveServeStart: async () => '{"port":1}',
		driveServeGrant: () => '/t/x',
		driveServeRevoke: () => {},
		driveServeStop: () => {},
		mamStoreDeviceId: () => {},
		mamStorePolicy: () => {},
		mamGetPolicy: () => null,
		mamMarkWiped: () => {},
		mamIsWiped: () => false,
		mamClearWiped: () => {},
		...over,
	};
}

// The exact keys main-process mam.ts uses for enrolment credentials
// (SS_SERVER_URL / SS_DEVICE_ID / SS_HMAC_SECRET). A renderer read of
// mam:hmac_secret while the vault is unlocked would let renderer-level code
// execution mint valid device-proof HMACs indefinitely (re-enrollment does NOT
// rotate the stored secret — authserver identity.go's ON CONFLICT preserves it).
const MAM_KEYS = ['mam:hmac_secret', 'mam:device_id', 'mam:server_url'];

describe('secure store SECRET confinement — renderer calls deny the mam:* namespace', () => {
	it('secure_store_get denies every mam:* key before the native invoke', () => {
		const native = fakeNative();
		const h = makeSecureStoreHandlers(native);
		for (const key of MAM_KEYS) {
			expect(() => h.secure_store_get(key)).toThrow(/native-host-only/);
		}
		expect(native.secureStoreGet).not.toHaveBeenCalled();
	});

	it('secure_store_set denies every mam:* key before the native invoke', () => {
		const native = fakeNative();
		const h = makeSecureStoreHandlers(native);
		for (const key of MAM_KEYS) {
			expect(() => h.secure_store_set(key, 'attacker-value')).toThrow(/native-host-only/);
		}
		expect(() => h.secure_store_set('mam:', 'attacker-value')).toThrow(/native-host-only/);
		expect(native.secureStoreSet).not.toHaveBeenCalled();
	});

	it('secure_store_remove denies every mam:* key before the native invoke', () => {
		const native = fakeNative();
		const h = makeSecureStoreHandlers(native);
		for (const key of MAM_KEYS) {
			expect(() => h.secure_store_remove(key)).toThrow(/native-host-only/);
		}
		expect(native.secureStoreRemove).not.toHaveBeenCalled();
	});

	it('the namespace boundary is the exact lowercase mam: prefix', () => {
		const native = fakeNative();
		const h = makeSecureStoreHandlers(native);
		// Distinct keys that merely CONTAIN the substring are a different
		// namespace — they pass through to native rather than being denied:
		expect(() => h.secure_store_set('sub/mam:hmac_secret', 'x')).not.toThrow();
		expect(() => h.secure_store_get('xmam:hmac_secret')).not.toThrow();
		// ...while every true member of the namespace (even odd spellings that
		// still start with it) is denied:
		expect(() => h.secure_store_get('mam:')).toThrow(/native-host-only/);
		expect(() => h.secure_store_get('mam:hmac_secret ')).toThrow(/native-host-only/);
	});

	it('non-mam renderer keys still delegate to the native module unchanged', () => {
		const native = fakeNative();
		const h = makeSecureStoreHandlers(native);
		h.secure_store_get('webpush:subscription');
		expect(native.secureStoreGet).toHaveBeenCalledWith('webpush:subscription');
		h.secure_store_set('ui:sidebar', 'open');
		expect(native.secureStoreSet).toHaveBeenCalledWith('ui:sidebar', 'open');
		h.secure_store_remove('ui:sidebar');
		expect(native.secureStoreRemove).toHaveBeenCalledWith('ui:sidebar');
	});

	it('the denial helper pins the exact namespace boundary (lowercase prefix only)', () => {
		expect(() => assertSecureStoreKeyRendererAllowed('mam:hmac_secret')).toThrow();
		expect(() => assertSecureStoreKeyRendererAllowed('MAM:hmac_secret')).not.toThrow(); // distinct key, distinct namespace
		expect(() => assertSecureStoreKeyRendererAllowed('mamx:secret')).not.toThrow();
	});

	// MEET M5 slice 2: the local-capture composition keeps consent records
	// and the capture device id under meet-capture:* — a renderer write
	// there could grant itself recording consent past the non-dismissible
	// consent machine, so the namespace joins the mam:* denial.
	it('renderer calls deny the meet-capture:* namespace before the native invoke', () => {
		const native = fakeNative();
		const h = makeSecureStoreHandlers(native);
		for (const key of ['meet-capture:consent', 'meet-capture:device']) {
			expect(() => h.secure_store_get(key)).toThrow(/native-host-only/);
			expect(() => h.secure_store_set(key, 'attacker-grant')).toThrow(/native-host-only/);
			expect(() => h.secure_store_remove(key)).toThrow(/native-host-only/);
		}
		expect(() => assertSecureStoreKeyRendererAllowed('meet-capture:')).toThrow();
		expect(() => assertSecureStoreKeyRendererAllowed('xmeet-capture:consent')).not.toThrow();
		expect(native.secureStoreGet).not.toHaveBeenCalled();
		expect(native.secureStoreSet).not.toHaveBeenCalled();
		expect(native.secureStoreRemove).not.toHaveBeenCalled();
	});
});
