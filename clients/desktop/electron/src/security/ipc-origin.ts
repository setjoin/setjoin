//! ADR-013 invariant 2 (pure half): IPC sender-origin validation.
//! Every IPC handler validates `event.senderFrame.url` against an exact
//! allowlist of the bundled app origin before acting. This module holds the pure
//! matching logic so it is unit-testable with no Electron; `ipc.ts` is the thin
//! wrapper that reads the real event and calls in here.

/**
 * True when `url` belongs to an allowed app origin.
 *  - `file://` origins (prod: the bundled index.html URL) match by prefix so
 *    hash/query on the SPA route still passes, but a different file path fails.
 *  - http(s) origins (dev server) match by parsed origin, so `localhost:5173`
 *    does not accidentally match `localhost:51735`.
 * Anything else (no url, off-origin, opaque scheme) is rejected.
 */
export function isSenderAllowed(url: string | undefined | null, origins: string[]): boolean {
	if (!url) return false;
	for (const origin of origins) {
		if (origin.startsWith('file://')) {
			if (url === origin || url.startsWith(origin)) return true;
		} else {
			try {
				if (new URL(url).origin === origin) return true;
			} catch {
				// not a parseable absolute URL — no match
			}
		}
	}
	return false;
}
