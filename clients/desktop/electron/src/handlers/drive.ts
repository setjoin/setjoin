//! Drive P3 secure-vault byte-plane handlers (window.setjoinNative.drive,
//! ARCH-017). appKey is hard-bound to 'drive' HERE — the renderer never
//! chooses the appKey for byte ops (mirrors `handlers/db.ts`'s division of
//! labor: allowlist/shape here, transport in `native.ts`).
//!
//! Privileged-parameter confinement (deep-scan package
//! desktop-drive-bridge-unconfined; Astra HOLD items 1–3): the renderer's
//! `srcPath` and chunk `url` arguments reach a native arbitrary-file read
//! (`std::fs::File::open`) and a credentialed native GET/PUT (`ureq` with the
//! drive bearer) — all three are confined HERE, in the main process, before
//! the native invoke:
//!   - FILE: `drive_import_file` accepts only an existing regular file whose
//!     realpath resolves inside one of the configured mirror import roots
//!     (realpath on BOTH sides so ancestor-symlink layouts like macOS /tmp
//!     keep working while a symlink escaping the root is rejected) AND whose
//!     content is a REGISTERED mirrored file — `isTrustedMirrorFile`, the
//!     composition-root-backed mirror-index (dc_mirror) membership check.
//!     Directory membership alone was not enough: an unindexed absolute file
//!     inside the root stayed importable. A configured root without a
//!     membership checker imports NOTHING (fail-closed).
//!   - NETWORK: `drive_fetch_chunk`/`drive_push_chunk` accept only absolute
//!     http(s) URLs whose parsed origin (scheme+host+port exact) is in the
//!     approved-origin allowlist — the same shape as the IPC sender gate.
//!   - BEARER: the drive bearer is owned by the composition root
//!     (`DriveTokenOwner`), never taken from the renderer: the renderer's
//!     bearer argument is IGNORED, and the handlers use only the token main
//!     received via `drive_mirror_refresh_token` / native-token renewal. No
//!     owner or no token = fail closed.
//! The default policy is FAIL-CLOSED (no import roots, no approved origins,
//! no token owner); the composition root (main.ts, the
//! `configureAllowedOrigins` pattern) widens it with the values it already
//! owns (mirror base dir + configured server origin + the mirror token).
//! offline-core (drive.rs) independently enforces a transport/path floor PLUS
//! the same trusted mirror-index/origin policy so every native consumer
//! (desktop-native AND ohos-native via include!) inherits a second boundary
//! even if a shell layer is ever bypassed.
//!
//! Four of the nine native members are `AsyncTask`s on the Rust side and
//! resolve as real Promises (`driveImportFile`/`driveFetchChunk`/
//! `drivePushChunk`/`driveServeStart`) — handlers just return the native
//! call's promise, same as any other async IPC handler; `registerHandler`
//! (ipc.ts) already awaits whatever `handler(...)` returns.
//!
//! Electron-free by construction (no `import 'electron'`): unit-testable with
//! a fake NativeBinding, same convention as db.ts.

import * as fs from 'node:fs';
import * as path from 'node:path';
import type { NativeBinding } from '../native';
import type { HandlerMap } from './db';

const APP = 'drive';

/**
 * Main-process ownership of the drive bearer (the approved token-owner
 * pattern, C3/C14/C15): the renderer mints the first token through its own
 * session and hands it to main via `drive_mirror_refresh_token`; main (and
 * MirrorService's native-token renewal) keeps it alive. Chunk transfers draw
 * from this owner only — a renderer-supplied bearer is never forwarded.
 */
export interface DriveTokenOwner {
	/** The current drive bearer, or null when none is held (fail closed). */
	readonly getBearer: () => Promise<string | null>;
}

/**
 * Privileged-parameter confinement for the renderer-reachable Drive byte
 * plane. Injected by the composition root; all lists are empty by default so
 * an unwired shell denies imports and chunk network I/O outright (fail-closed)
 * rather than inheriting the historical unconfined behavior.
 */
export interface DriveConfinement {
	/**
	 * Absolute directories containing the ONLY files `drive_import_file` may
	 * read (the FolderMirror base dir in production). Empty = deny all imports.
	 */
	readonly importRoots: readonly string[];
	/**
	 * Exact http(s) origins (scheme+host+port, parsed-origin equality — same
	 * matching discipline as the IPC sender gate) a renderer-supplied chunk
	 * fetch/push URL must belong to. Empty = deny all chunk network I/O.
	 */
	readonly approvedOrigins: readonly string[];
	/**
	 * Trusted mirror-INDEX membership (Astra item 1): resolves to true only
	 * when `srcPath` is a registered mirrored file — the composition root
	 * backs it with the mirror service's dc_mirror index (per-space root +
	 * `findByPathCI`). REQUIRED whenever `importRoots` is non-empty: a root
	 * without a checker imports nothing (fail-closed — directory membership
	 * alone is not the trusted boundary).
	 */
	readonly isTrustedMirrorFile?: (srcPath: string) => Promise<boolean>;
}

/** Fail-closed default: a renderer-reachable arbitrary-file read and a
 * credentialed native GET/PUT must both be widened explicitly by the shell,
 * never on by default. */
export const DEFAULT_DRIVE_CONFINEMENT: DriveConfinement = {
	importRoots: [],
	approvedOrigins: [],
};

/**
 * True when `srcPath` is an existing regular file whose fully-resolved
 * (realpath) location lies strictly inside one of `roots`' resolved
 * locations. Both sides are realpath'd, so a mirror root reached through a
 * legal ancestor symlink (macOS /tmp → /private/tmp) keeps working while a
 * symlink pointing OUT of the root — including via any path component —
 * resolves outside and is rejected. Missing paths, directories, and relative
 * paths all fail closed.
 */
export function isPathInsideRoots(srcPath: string, roots: readonly string[]): boolean {
	if (!path.isAbsolute(srcPath)) return false;
	let real: string;
	try {
		real = fs.realpathSync(srcPath); // throws when missing; resolves every symlink hop
	} catch {
		return false;
	}
	let stat: fs.Stats;
	try {
		stat = fs.statSync(real);
	} catch {
		return false;
	}
	if (!stat.isFile()) return false;
	for (const root of roots) {
		let realRoot: string;
		try {
			realRoot = fs.realpathSync(root);
		} catch {
			continue; // a broken configured root approves nothing
		}
		const rel = path.relative(realRoot, real);
		if (rel.length > 0 && rel !== '..' && !rel.startsWith(`..${path.sep}`) && !path.isAbsolute(rel)) {
			return true;
		}
	}
	return false;
}

/**
 * True when `rawUrl` is an absolute http(s) URL whose parsed origin equals one
 * of `origins` (parsed-origin equality, port-exact — `https://gw:443` never
 * matches `https://gw:8443`). Relative paths, unparseable strings, and
 * non-http(s) schemes (file:/ftp:/data:) all fail closed. This is the same
 * matching discipline as the IPC sender gate for http(s) senders.
 */
export function isUrlApproved(rawUrl: string, origins: readonly string[]): boolean {
	let parsed: URL;
	try {
		parsed = new URL(rawUrl);
	} catch {
		return false;
	}
	if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return false;
	for (const origin of origins) {
		try {
			if (new URL(origin).origin === parsed.origin) return true;
		} catch {
			// unparseable configured origin — never matches
		}
	}
	return false;
}

/**
 * Resolve the confinement for one call: a plain `DriveConfinement` is used
 * as-is; a provider is consulted per call so the composition root can widen
 * the policy after registration (the server origin arrives via the
 * `drive_mirror_configure` IPC event, after handlers are registered once).
 */
export type DriveConfinementSource = DriveConfinement | (() => DriveConfinement);

function resolveConfinement(source: DriveConfinementSource): DriveConfinement {
	return typeof source === 'function' ? source() : source;
}

export function makeDriveHandlers(
	native: NativeBinding,
	confinement: DriveConfinementSource = DEFAULT_DRIVE_CONFINEMENT,
	tokenOwner?: DriveTokenOwner,
): HandlerMap {
	return {
		drive_import_file: async (srcPath: unknown) => {
			const p = String(srcPath);
			const policy = resolveConfinement(confinement);
			if (!isPathInsideRoots(p, policy.importRoots)) {
				throw new Error(
					`drive_import_file: src_path is not an importable mirrored file (root/symlink/absolute escapes rejected): ${p}`,
				);
			}
			// Trusted mirror-index membership (Astra item 1): root containment is
			// necessary but not sufficient — the file must also be a REGISTERED
			// mirrored file. A configured root without a checker imports nothing
			// (fail-closed), so directory membership alone can never regress into
			// the boundary.
			if (!policy.isTrustedMirrorFile) {
				throw new Error(
					`drive_import_file: no trusted mirror-index membership checker is configured (fail-closed): ${p}`,
				);
			}
			if (!(await policy.isTrustedMirrorFile(p))) {
				throw new Error(
					`drive_import_file: src_path is not a registered mirrored file (mirror-index membership required): ${p}`,
				);
			}
			return native.driveImportFile(APP, p).then((json) => JSON.parse(json));
		},
		drive_fetch_chunk: async (
			url: unknown,
			_rendererBearer: unknown,
			sha256: unknown,
			size: unknown,
		) => {
			const u = String(url);
			const policy = resolveConfinement(confinement);
			if (!isUrlApproved(u, policy.approvedOrigins)) {
				throw new Error(`drive_fetch_chunk: url origin is not approved: ${u}`);
			}
			// Bearer ownership stays in main (Astra item 3): the renderer-supplied
			// bearer argument is IGNORED — only the composition root's token owner
			// credentials the native GET. The parameter keeps its channel position
			// because bridge.ts/preload shapes are fixed outside this delta.
			const bearer = tokenOwner ? await tokenOwner.getBearer() : null;
			if (bearer == null || bearer === '') {
				throw new Error(
					'drive_fetch_chunk: no drive bearer is available from the main-process token owner (renderer-supplied bearers are ignored)',
				);
			}
			return native.driveFetchChunk(APP, u, bearer, String(sha256), Number(size));
		},
		drive_push_chunk: async (url: unknown, _rendererBearer: unknown, sha256: unknown) => {
			const u = String(url);
			const policy = resolveConfinement(confinement);
			if (!isUrlApproved(u, policy.approvedOrigins)) {
				throw new Error(`drive_push_chunk: url origin is not approved: ${u}`);
			}
			const bearer = tokenOwner ? await tokenOwner.getBearer() : null;
			if (bearer == null || bearer === '') {
				throw new Error(
					'drive_push_chunk: no drive bearer is available from the main-process token owner (renderer-supplied bearers are ignored)',
				);
			}
			return native.drivePushChunk(APP, u, bearer, String(sha256));
		},
		drive_has_chunk: (sha256: unknown) => native.driveHasChunk(APP, String(sha256)),
		drive_delete_chunks: (sha256s: unknown) =>
			native.driveDeleteChunks(APP, JSON.stringify(sha256s ?? [])),
		drive_serve_start: () => native.driveServeStart(APP).then((json) => JSON.parse(json)),
		drive_serve_grant: (manifest: unknown) => native.driveServeGrant(APP, JSON.stringify(manifest)),
		drive_serve_revoke: (ticket: unknown) => native.driveServeRevoke(APP, String(ticket)),
	} as HandlerMap;
}

/**
 * Cross-platform-consistent mirror space-folder name — the exact mapping
 * `drive/service.ts` uses to turn a space's remote name into its on-disk
 * folder under the mirror base dir (service.ts's private `sanitizeFolderName`;
 * duplicated here, not moved, because service.ts is outside this delta's write
 * scope). The composition root's mirror-index membership checker uses it to
 * pair a `drive_mirror_status` space with its root directory.
 */
export function sanitizeMirrorSpaceFolder(name: string): string {
	// Stripping control characters out of on-disk folder names is the point
	// (same regex as drive/service.ts, where the rule is disabled config-side).
	// biome-ignore lint/suspicious/noControlCharactersInRegex: deliberate control-char stripping
	const cleaned = name.replace(/[<>:"/\\|?*\x00-\x1f]/g, '_').trim();
	return cleaned || 'space';
}
