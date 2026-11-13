//! OS-capability handlers: notify, pick_file, open_external. Ported from Tauri
//! `bridge.rs`, including the `external_url_allowed` scheme allowlist (verbatim).
//!
//! The platform effects (show a notification, open a file dialog, hand a URL to
//! the OS opener) are INJECTED so this module is electron-free and unit testable.
//! main.ts supplies the electron-backed implementations.

import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import type { HandlerMap } from './db';

/**
 * Schemes the desktop shell will hand to the OS opener. Restricting to these
 * stops a caller (e.g. app code following an email-derived link) from making the
 * OS open a local `file://` path or launch a handler for an arbitrary scheme
 * (`smb:`, `ms-excel:`, `javascript:`, …). Ported from `bridge.rs`.
 */
const ALLOWED_EXTERNAL_SCHEMES = ['https', 'http', 'mailto'];

/**
 * True when `url`'s scheme is one the shell will open externally. Scheme compare
 * is case-insensitive (RFC 3986); a URL with no scheme is rejected. Ported
 * verbatim from `bridge.rs::external_url_allowed`.
 */
export function externalUrlAllowed(url: string): boolean {
	const idx = url.indexOf(':');
	if (idx <= 0) return false; // no scheme (or leading ':')
	const scheme = url.slice(0, idx).toLowerCase();
	return ALLOWED_EXTERNAL_SCHEMES.includes(scheme);
}

// ponytail: Node has no stdlib mime lookup; a tiny extension map covers the
// common attachment types a file dialog returns. Unknown → octet-stream (the
// renderer's File just needs a plausible type; the bytes are what matter).
const MIME_BY_EXT: Record<string, string> = {
	'.pdf': 'application/pdf',
	'.png': 'image/png',
	'.jpg': 'image/jpeg',
	'.jpeg': 'image/jpeg',
	'.gif': 'image/gif',
	'.txt': 'text/plain',
	'.csv': 'text/csv',
	'.json': 'application/json',
	'.zip': 'application/zip',
	'.doc': 'application/msword',
	'.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
	'.xls': 'application/vnd.ms-excel',
	'.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
};

export function mimeForFile(name: string): string {
	return MIME_BY_EXT[path.extname(name).toLowerCase()] ?? 'application/octet-stream';
}

/** The file-dialog result the renderer reconstructs into a `File`. */
export interface PickedFile {
	name: string;
	type: string;
	dataBase64: string;
}

/** Platform effects injected by main.ts (electron-backed in production). */
export interface OsDeps {
	showNotification(title: string, body: string): void;
	/** Open the native file picker; resolve to the chosen path or null on cancel. */
	pickFilePath(): Promise<string | null>;
	/** Hand an already-allowlisted URL to the OS opener. */
	openExternalUrl(url: string): Promise<void>;
}

export function makeOsHandlers(deps: OsDeps): HandlerMap {
	return {
		notify: (title: unknown, body: unknown) =>
			deps.showNotification(String(title), body == null ? '' : String(body)),

		pick_file: async (): Promise<PickedFile | null> => {
			const filePath = await deps.pickFilePath();
			if (!filePath) return null;
			const buf = await fs.readFile(filePath);
			const name = path.basename(filePath) || 'file';
			return { name, type: mimeForFile(name), dataBase64: buf.toString('base64') };
		},

		open_external: async (url: unknown) => {
			const u = String(url);
			if (!externalUrlAllowed(u)) {
				throw new Error('open_external: URL scheme not allowed (only http/https/mailto)');
			}
			await deps.openExternalUrl(u);
		},
	} as HandlerMap;
}
