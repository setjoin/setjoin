import { describe, it, expect, vi } from 'vitest';
import { checkStmtAllowed, appKeyDbFile, makeDbHandlers } from './db';
import type { NativeBinding } from '../native';

function fakeNative(over: Partial<NativeBinding> = {}): NativeBinding {
	return {
		vaultUnlock: () => true,
		vaultIsUnlocked: () => true,
		vaultListTotp: () => [],
		vaultGenerateTotp: () => '000000',
		secureStoreGet: () => null,
		secureStoreSet: () => {},
		secureStoreRemove: () => {},
		dbOpen: vi.fn(),
		dbIsOpen: () => true,
		dbExec: vi.fn(() => 1),
		dbExecSchemaInit: vi.fn(() => 0),
		dbTransactionBatch: vi.fn(() => 2),
		dbMigrateStore: vi.fn(() => '{"version":2}'),
		dbQuery: vi.fn(() => '[]'),
		dbWipe: vi.fn(),
		driveImportFile: vi.fn(async () => '{"contentSha256":"","size":0,"chunks":[]}'),
		driveFetchChunk: vi.fn(async () => {}),
		drivePushChunk: vi.fn(async () => 200),
		driveHasChunk: () => false,
		driveDeleteChunks: () => 0,
		driveSetConfinement: () => {},
		driveServeStart: vi.fn(async () => '{"port":0}'),
		driveServeGrant: () => '/t/fake',
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

describe('check_stmt_allowed (ported from bridge.rs)', () => {
	it('permits the allowlisted leading keywords incl. transaction keywords', () => {
		for (const kw of [
			'SELECT',
			'INSERT',
			'UPDATE',
			'DELETE',
			'CREATE',
			'DROP',
			'WITH',
			'BEGIN',
			'COMMIT',
			'ROLLBACK',
			'SAVEPOINT',
			'RELEASE',
		]) {
			expect(() => checkStmtAllowed(kw), `${kw} must be allowed`).not.toThrow();
		}
	});

	it('blocks ATTACH and PRAGMA (incl. lowercase + rekey)', () => {
		expect(() => checkStmtAllowed("ATTACH DATABASE 'x'")).toThrow();
		expect(() => checkStmtAllowed('PRAGMA key')).toThrow();
		expect(() => checkStmtAllowed('pragma key')).toThrow();
		expect(() => checkStmtAllowed('PRAGMA rekey="newkey"')).toThrow();
	});

	it('is case-insensitive on the leading keyword', () => {
		expect(() => checkStmtAllowed('select 1')).not.toThrow();
		expect(() => checkStmtAllowed('  insert into t values (1)')).not.toThrow();
	});
});

describe('appKeyDbFile (ported store_db_path allowlist)', () => {
	it('maps mail → mail-cache.db', () => {
		expect(appKeyDbFile('mail')).toBe('mail-cache.db');
	});
	it('maps drive → drive-meta.db (Drive P2 dc_* mirror-metadata store)', () => {
		expect(appKeyDbFile('drive')).toBe('drive-meta.db');
	});
	it('rejects unknown appKeys', () => {
		expect(() => appKeyDbFile('evil')).toThrow(/unknown appKey/);
	});
});

describe('db handlers', () => {
	it('db_open resolves <userData>/mail-cache.db and normalises SMx→smx', () => {
		const native = fakeNative();
		const h = makeDbHandlers(native, '/data');
		h.db_open('mail', 'SMx');
		expect(native.dbOpen).toHaveBeenCalledWith('/data/mail-cache.db', 'mail', 'smx');
		h.db_open('mail', undefined);
		expect(native.dbOpen).toHaveBeenCalledWith('/data/mail-cache.db', 'mail', 'standard');
	});

	it('db_exec/db_query enforce the statement allowlist before touching native', () => {
		const native = fakeNative();
		const h = makeDbHandlers(native, '/data');
		expect(() => h.db_exec('mail', 'PRAGMA key', [])).toThrow();
		expect(native.dbExec).not.toHaveBeenCalled();
		h.db_exec('mail', 'INSERT INTO t VALUES (?)', [1]);
		expect(native.dbExec).toHaveBeenCalledWith('mail', 'INSERT INTO t VALUES (?)', '[1]');
	});

	it('db_exec_schema_init forwards the batch verbatim (per-statement authority is native)', () => {
		// med-offcore-sqlguard-001 r3: the schema-init channel deliberately runs
		// no TS keyword gate — a TS-side copy of the batch vocabulary would be
		// the divergent per-shell allowlist the r2 contract rejected, while the
		// native validator is strictly stronger (per-statement allowlist +
		// one-shot gate per store connection).
		const native = fakeNative();
		const h = makeDbHandlers(native, '/data');
		const batch = 'CREATE TABLE a(x); CREATE TABLE b(y);';
		expect(h.db_exec_schema_init('mail', batch)).toBe(0);
		expect(native.dbExecSchemaInit).toHaveBeenCalledWith('mail', batch);
		// Args are coerced to strings (the WebView sends raw values).
		h.db_exec_schema_init(123, batch);
		expect(native.dbExecSchemaInit).toHaveBeenLastCalledWith('123', batch);
		// Native rejections (unbatchable keyword, one-shot replay) propagate.
		(native.dbExecSchemaInit as ReturnType<typeof vi.fn>).mockImplementation(() => {
			throw new Error('multi-statement batch rejected');
		});
		expect(() => h.db_exec_schema_init('mail', batch)).toThrow(/multi-statement/);
	});

	it('db_transaction_batch forwards statements/budget as JSON (per-statement authority is native)', () => {
		// E4-I native transaction freeze: the same no-TS-keyword-gate discipline
		// as db_exec_schema_init — the webmail pre-admits through
		// $lib/offline/nativeBatch and the native validator inside offline-core
		// is the authority; a TS keyword copy here would be the divergent
		// allowlist the r2/r3 contract rejected.
		const native = fakeNative();
		const h = makeDbHandlers(native, '/data');
		const statements = [
			{ sql: 'UPDATE messages SET subject = ? WHERE id = ?', params: ['hi', 'm1'] },
			{ sql: 'INSERT INTO action_queue (type, payload, status, attempts, created_at) VALUES (?,?,?,?,?)' },
		];
		const budget = { maxStatements: 64, maxParamBytes: 1_048_576 };
		const changed = h.db_transaction_batch('mail', statements, budget);
		expect(changed).toBe(2);
		expect(native.dbTransactionBatch).toHaveBeenCalledWith(
			'mail',
			JSON.stringify(statements),
			JSON.stringify(budget),
		);
		// Native refusals (transaction control, DDL, budget) propagate verbatim.
		(native.dbTransactionBatch as ReturnType<typeof vi.fn>).mockImplementation(() => {
			throw new Error('batch rejected: statement 1 keyword \'BEGIN\' is not allowed');
		});
		expect(() => h.db_transaction_batch('mail', [{ sql: 'BEGIN' }], budget)).toThrow(
			/batch rejected/,
		);
	});

	it('db_migrate_store forwards the target version and returns the version JSON', () => {
		const native = fakeNative();
		const h = makeDbHandlers(native, '/data');
		expect(h.db_migrate_store('mail', 2)).toBe('{"version":2}');
		expect(native.dbMigrateStore).toHaveBeenCalledWith('mail', 2);
		// Version is coerced to a number (the WebView sends raw values); native
		// refusals (foreign app, ahead/downgrade) propagate.
		h.db_migrate_store('2', '1');
		expect(native.dbMigrateStore).toHaveBeenLastCalledWith('2', 1);
		(native.dbMigrateStore as ReturnType<typeof vi.fn>).mockImplementation(() => {
			throw new Error('migration refused: downgrade');
		});
		expect(() => h.db_migrate_store('mail', 1)).toThrow(/downgrade/);
	});

	it('db_open rejects an unknown appKey (never reaches native)', () => {
		const native = fakeNative();
		const h = makeDbHandlers(native, '/data');
		expect(() => h.db_open('evil', 'standard')).toThrow(/unknown appKey/);
		expect(native.dbOpen).not.toHaveBeenCalled();
	});
});
