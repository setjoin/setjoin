// DbAllowlist — SQL statement allowlist + appKey→file resolution for the
// generic offline encrypted store (window.setjoinNative.db). Ported verbatim
// from clients/desktop/electron/src/handlers/db.ts's `checkStmtAllowed` /
// `appKeyDbFile` — the SQL trust boundary lives here (in ArkTS, the trusted
// host layer), never in the injected web content. See `check_stmt_allowed`
// in offline-core's C API for the canonical Rust-side copy of this same list.

const ALLOWED_STATEMENTS: Set<string> = new Set<string>([
  'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'WITH',
  'BEGIN', 'COMMIT', 'ROLLBACK', 'SAVEPOINT', 'RELEASE',
]);

/** Throws when `sql`'s leading keyword is not allowlisted. */
export function checkStmtAllowed(sql: string): void {
  const trimmed: string = sql.trim();
  const parts: string[] = trimmed.split(/\s+/);
  const head: string = (parts.length > 0 ? parts[0] : '').toUpperCase();
  if (!ALLOWED_STATEMENTS.has(head)) {
    throw new Error(`statement not allowed: ${head}`);
  }
}

/**
 * Resolve the on-disk store filename for `appKey`. One file per app.
 * Rejects unknown appKeys (forward-compat allowlist — add 'drive'/'calendar'
 * here as those apps ship). Mirrors `appKeyDbFile` in db.ts.
 */
export function appKeyDbFile(appKey: string): string {
  if (appKey === 'mail') {
    return 'mail-cache.db';
  }
  if (appKey === 'drive') {
    // Drive P3's secure-vault byte plane (ARCH-017): Rust owns a `dc_chunks`
    // table inside this same SQLCipher file, created lazily on first drive_* call.
    return 'drive-vault.db';
  }
  // ponytail: allowlist ceiling — add appKeys as feature modules ship.
  throw new Error(`unknown appKey: ${appKey}`);
}

/** JS sends 'SMx'; normalise to the native "smx" tag. Missing/empty → "standard". */
export function normalizeProfile(profile: string): string {
  if (profile === 'SMx') {
    return 'smx';
  }
  if (profile.length === 0) {
    return 'standard';
  }
  return profile;
}
