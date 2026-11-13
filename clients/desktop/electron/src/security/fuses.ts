//! ADR-013 invariant 1: Electron Fuses, build-gated.
//!
//! The exact locked fuse set. Flipped at package time (electron-builder
//! `afterPack` → scripts/flip-fuses.mjs) and asserted in CI by reading the
//! packaged binary's fuse wire (`@electron/fuses` getCurrentFuseWire) — that
//! read-back is the real gate and runs where electron-builder packages, not in
//! this sandbox. The unit test here pins the config truth table so a drift in
//! intent fails at review.

// ponytail: @electron/fuses is ESM-only with an exports map — statically
// importing its types from this CommonJS module trips TS's ESM/CJS interop
// rules, but Node 26 `require()` loads it fine at runtime. So we require it
// untyped (require → any) and pin the numeric fuse keys via fuses.test.ts, which
// imports the REAL FuseV1Options enum (under esbuild) and asserts each key —
// that test is the drift guard, so no key is silently hardcoded wrong.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const fuses = require('@electron/fuses');
const O: Record<string, number> = fuses.FuseV1Options;

type FuseConfigLike = {
	version: string;
	resetAdHocDarwinSignature: boolean;
	[fuseIndex: number]: boolean;
};

/**
 * The locked fuse configuration (ADR-013 decision 4):
 *  DISABLE runAsNode, nodeOptions, nodeCliInspect, grantFileProtocolExtraPrivileges;
 *  ENABLE  embeddedAsarIntegrityValidation + onlyLoadAppFromAsar (together),
 *          cookieEncryption, loadBrowserProcessSpecificV8Snapshot.
 */
export const FUSE_CONFIG: FuseConfigLike = {
	version: fuses.FuseVersion.V1,
	resetAdHocDarwinSignature: false,
	[O.RunAsNode]: false,
	[O.EnableNodeOptionsEnvironmentVariable]: false,
	[O.EnableNodeCliInspectArguments]: false,
	[O.GrantFileProtocolExtraPrivileges]: false,
	[O.EnableEmbeddedAsarIntegrityValidation]: true,
	[O.OnlyLoadAppFromAsar]: true,
	[O.EnableCookieEncryption]: true,
	[O.LoadBrowserProcessSpecificV8Snapshot]: true,
};

/** Flip the locked fuse set on the packaged Electron binary at `appPath`. */
export async function flipAppFuses(appPath: string): Promise<void> {
	await fuses.flipFuses(appPath, FUSE_CONFIG);
}
