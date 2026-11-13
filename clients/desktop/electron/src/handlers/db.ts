//! Offline encrypted store handlers (window.setjoinNative.db). Ported 1:1 from
//! Tauri `bridge.rs`: the SQL statement allowlist (`check_stmt_allowed`), the
//! appKey→file allowlist (`store_db_path`), and the open/is_open/exec/query/wipe
//! commands. The SQLCipher key is provisioned inside the native module and never
//! crosses this boundary.
//!
//! Electron-free by construction: the userData dir is injected so these are unit
//! testable with a fake NativeBinding and no display.

import * as path from 'node:path';
import type { NativeBinding } from '../native';

/**
 * Statement allowlist: the WebView may only run SQL whose leading keyword is in
 * this set. Blocks arbitrary cross-app SQL, ATTACH, and PRAGMA key probing.
 * CREATE is allowed so TS migrations can apply the per-app schema on first open;
 * BEGIN/COMMIT/ROLLBACK/SAVEPOINT/RELEASE enable the transactional outbox.
 * Ported verbatim from `bridge.rs::check_stmt_allowed`.
 */
const ALLOWED_STATEMENTS = new Set([
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
]);

/** Throws when `sql`'s leading keyword is not allowlisted (mirrors the Rust `Result`). */
export function checkStmtAllowed(sql: string): void {
	const head = (sql.trim().split(/\s+/)[0] ?? '').toUpperCase();
	if (!ALLOWED_STATEMENTS.has(head)) {
		throw new Error(`statement not allowed: ${head}`);
	}
}

/**
 * Resolve the on-disk store filename for `appKey`. One file per app.
 * Rejects unknown appKeys (forward-compat allowlist — add 'drive'/'calendar'
 * here as those apps ship). Ported from `bridge.rs::store_db_path`.
 */
export function appKeyDbFile(appKey: string): string {
	switch (appKey) {
		case 'mail':
			return 'mail-cache.db';
		case 'drive':
			// Drive P2's dc_* mirror-metadata store (schema.ts) — one shared file,
			// space_id columns distinguish rows per space.
			return 'drive-meta.db';
		// ponytail: allowlist ceiling — add appKeys as feature modules ship.
		default:
			throw new Error(`unknown appKey: ${appKey}`);
	}
}

/** JS sends 'SMx'; normalise to the native "smx" tag. Missing → "standard". */
function normalizeProfile(profile: string | undefined): string {
	if (profile === 'SMx') return 'smx';
	return profile ?? 'standard';
}

export type HandlerMap = Record<string, (...args: unknown[]) => unknown>;

export function makeDbHandlers(native: NativeBinding, userDataDir: string): HandlerMap {
	return {
		db_open: (appKey: unknown, profile: unknown) => {
			const dbPath = path.join(userDataDir, appKeyDbFile(String(appKey)));
			native.dbOpen(dbPath, String(appKey), normalizeProfile(profile as string | undefined));
		},
		db_is_open: (appKey: unknown) => native.dbIsOpen(String(appKey)),
		db_exec: (appKey: unknown, sql: unknown, params: unknown) => {
			checkStmtAllowed(String(sql));
			return native.dbExec(String(appKey), String(sql), JSON.stringify(params ?? []));
		},
		// Authorized schema-init seam (med-offcore-sqlguard-001 r3): the ONLY
		// channel a multi-statement batch may traverse. No TS keyword gate here
		// by design: a TS-side copy of the batch vocabulary would be the
		// divergent per-shell allowlist the r2 contract rejected, while the
		// native validator is strictly stronger — it validates EVERY statement
		// against the batch allowlist before anything runs, and the one-shot
		// gate refuses any replay on an initialized store connection.
		db_exec_schema_init: (appKey: unknown, sql: unknown) =>
			native.dbExecSchemaInit(String(appKey), String(sql)),
		// E4-I authorized atomic job batch + bundled-migration migration entry.
		// Same no-TS-keyword-gate discipline as db_exec_schema_init: the webmail
		// pre-admits through $lib/offline/nativeBatch (its own fail-closed TS
		// layer), and the native validator inside offline-core is the authority
		// — a TS copy here would be exactly the divergent allowlist the r2/r3
		// contract rejected. Statements/budget cross as JSON strings; the
		// migrate result comes back as a {"version":N} JSON string the shell
		// bridge parses.
		db_transaction_batch: (appKey: unknown, statements: unknown, budget: unknown) =>
			native.dbTransactionBatch(
				String(appKey),
				JSON.stringify(statements ?? []),
				JSON.stringify(budget ?? {}),
			),
		db_migrate_store: (appKey: unknown, targetVersion: unknown) =>
			native.dbMigrateStore(String(appKey), Number(targetVersion)),
		db_query: (appKey: unknown, sql: unknown, params: unknown) => {
			checkStmtAllowed(String(sql));
			return native.dbQuery(String(appKey), String(sql), JSON.stringify(params ?? []));
		},
		db_wipe: (appKey: unknown) => native.dbWipe(String(appKey)),
	} as HandlerMap;
}
