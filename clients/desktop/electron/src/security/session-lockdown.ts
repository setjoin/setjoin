//! ADR-013 invariant 4: session lockdown (defense in depth over the SPA meta-CSP).
//! On the Electron session: a session-level CSP, window.open denied, off-origin
//! navigation denied, and deny-by-default permission handler. The pure decision
//! predicates live here (unit-testable); `applySessionLockdown` wires them onto
//! the real electron objects from main.ts. A full Playwright-Electron e2e is a
//! documented follow-up (needs a display).

import type { Session, WebContents } from 'electron';

/**
 * The session-level CSP layered on the SvelteKit `<meta>` CSP.
 *
 * Drive P3 (batch-1 #2 + batch-3 #2): img-src/media-src/connect-src gain
 * blob:/loopback so the SecureViewer's RAM-blob renders (<img src="blob:">,
 * pdf.js's blob-URL fetch) and the loopback <video src="http://127.0.0.1:*">
 * aren't refused by the bare "default-src 'self'" fallback. script-src stays
 * ABSENT deliberately (falls back to default-src 'self') — no regression to
 * the M9 inline-script lockdown. Mirror any change here in svelte.config.js's
 * meta CSP: onHeadersReceived only fires for HTTP(S) responses, so in
 * packaged `loadFile` mode this header never applies and the meta CSP is the
 * only document policy in effect.
 *
 * A4: img-src also carries https: — the trusted-sender remote-image opt-in
 * (sanitize.ts allowRemoteImages) needs it here too. This policy is the one
 * in effect wherever the shell is the only CSP (no-upstream loads; packaged
 * loadFile mode never reaches onHeadersReceived at all). When an upstream
 * server ships its own CSP, the shell defers to it — see
 * shouldInjectSessionCsp (the E6 gateway-served webmail carries a
 * deliberate inline-script allowance its hydration bootstrap needs;
 * wholesale replacement broke hydration into a white page).
 *
 * B5 (2026-07-11 codebase review): object-src (not img-src/media-src) gates
 * <object>/<embed>/<applet> resource loading, and SecureViewer.svelte renders
 * PDF/ready-office previews via <embed type="application/pdf" src={blob:...}>.
 * A bare 'none' silently blanked every such preview here too — 'self' + blob:
 * only (never a remote origin); script-src is untouched.
 *
 * Meet B1 Task 16b (locked triple-lock delta, gateway header + the SvelteKit
 * meta CSP + this file, one commit): background blur's WASM segmentation
 * model fails WebAssembly.instantiate under Chromium's CSP without an
 * explicit script-src carrying 'wasm-unsafe-eval' — script-src previously
 * had no entry here at all (falling back to default-src 'self'), so it
 * gains its own explicit directive now rather than loosening default-src;
 * 'unsafe-inline' is still absent (no regression to the M9 lockdown).
 */
export const SESSION_CSP =
	"default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; frame-ancestors 'none'; object-src 'self' blob:; base-uri 'self'; " +
	"img-src 'self' data: blob: https:; media-src 'self' blob: http://127.0.0.1:*; connect-src 'self' blob: https: wss:";

/**
 * True when navigating to `targetUrl` should be DENIED (it is off the bundled
 * app origin). Same-origin (by the `file://` prefix or parsed http origin) is
 * allowed; everything else is denied.
 */
export function shouldDenyNavigation(targetUrl: string, appOrigins: string[]): boolean {
	for (const origin of appOrigins) {
		if (origin.startsWith('file://')) {
			if (targetUrl === origin || targetUrl.startsWith(origin)) return false;
		} else {
			try {
				if (new URL(targetUrl).origin === origin) return false;
			} catch {
				// unparseable → deny
			}
		}
	}
	return true;
}

/** Deny-by-default permission handler decision (no permission is auto-granted). */
export function allowPermission(_permission: string): boolean {
	// ponytail: nothing the shell needs today; flip specific perms on when a
	// feature requires one (each addition is an explicit review point).
	return false;
}

/**
 * Whether the session-level CSP should be INJECTED into this response. The
 * shell's session CSP is the document policy for loads that have NO upstream
 * CSP of their own (a vite dev server; error bodies) — onHeadersReceived only
 * fires for HTTP(S) responses, so in packaged `loadFile` mode it never fires
 * and the meta CSP is the only document policy in effect.
 *
 * E6 app-origin fix (2026-09-21): when the upstream server ships its OWN
 * Content-Security-Policy, we now DEFER to it instead of replacing it
 * wholesale. The gateway-served webmail's header is the authoritative
 * document policy for the served app (it deliberately carries the
 * inline-script allowance for SvelteKit's pre-meta hydration bootstrap, whose
 * per-build hash a static header cannot track — see the gateway's
 * middleware/security.go for the documented split between header CSP and the
 * strict hash-mode meta CSP); wholesale replacement broke hydration and
 * rendered a white page (the exact defect this lockout's injection existed to
 * complement, not to override a first-party server). Multiple CSP headers
 * intersect, so appending would not fix it — the choice was replace-vs-defer,
 * and defer is strictly NARROWER than the old behavior: the shell never
 * loosens a first-party server's policy anymore. The runtime XSS barrier for
 * the served app is the document's own hash-mode meta CSP, unchanged.
 */
export function shouldInjectSessionCsp(responseHeaders: Record<string, string[]> | undefined): boolean {
	if (responseHeaders === undefined) return true;
	for (const [name, values] of Object.entries(responseHeaders)) {
		if (name.toLowerCase() === 'content-security-policy' && values !== undefined && values.length > 0) {
			return false;
		}
	}
	return true;
}

/**
 * Wire the lockdown onto a real session + webContents. Called from main.ts after
 * window creation. `appOrigins` is the same allowlist the IPC gate uses.
 */
export function applySessionLockdown(
	session: Session,
	webContents: WebContents,
	appOrigins: string[],
): void {
	// Deny all window.open — external links go through the openExternal bridge.
	webContents.setWindowOpenHandler(() => ({ action: 'deny' }));

	// Deny navigation off the bundled app origin.
	webContents.on('will-navigate', (event, url) => {
		if (shouldDenyNavigation(url, appOrigins)) event.preventDefault();
	});

	// Session-level CSP layered on the SvelteKit meta CSP — only where the
	// response has no upstream CSP of its own (see shouldInjectSessionCsp).
	session.webRequest.onHeadersReceived((details, callback) => {
		if (!shouldInjectSessionCsp(details.responseHeaders)) {
			callback({});
			return;
		}
		callback({
			responseHeaders: {
				...details.responseHeaders,
				'Content-Security-Policy': [SESSION_CSP],
			},
		});
	});

	// Deny-by-default permissions (geolocation/media/etc.).
	session.setPermissionRequestHandler((_wc, permission, cb) => cb(allowPermission(permission)));
}
