import { describe, it, expect } from 'vitest';
import { shouldDenyNavigation, allowPermission, SESSION_CSP, shouldInjectSessionCsp } from './session-lockdown';

describe('session lockdown decisions', () => {
	const fileOrigin = ['file:///app/build/index.html'];
	const devOrigin = ['http://localhost:5173'];

	it('allows same-origin navigation (file + dev), denies off-origin', () => {
		expect(shouldDenyNavigation('file:///app/build/index.html#/x', fileOrigin)).toBe(false);
		expect(shouldDenyNavigation('http://localhost:5173/app', devOrigin)).toBe(false);
		expect(shouldDenyNavigation('https://evil.example', fileOrigin)).toBe(true);
		expect(shouldDenyNavigation('file:///etc/passwd', fileOrigin)).toBe(true);
		expect(shouldDenyNavigation('not a url', devOrigin)).toBe(true);
	});

	it('permission handler is deny-by-default', () => {
		for (const p of ['geolocation', 'media', 'notifications', 'clipboard-read']) {
			expect(allowPermission(p)).toBe(false);
		}
	});

	it('exposes a restrictive session CSP', () => {
		expect(SESSION_CSP).toContain("default-src 'self'");
		expect(SESSION_CSP).toContain("frame-ancestors 'none'");
	});

	// Drive P3 (batch-3 #2, extends batch-1 #2): the SecureViewer's RAM-blob
	// path (<img src="blob:">, pdf.js fed a blob URL) and the loopback <video>
	// were BOTH refused under the bare "default-src 'self'" fallback in
	// Electron's dev-server/served-origin mode (onHeadersReceived only fires
	// for HTTP(S) — in packaged loadFile mode the meta CSP governs instead).
	it('adds the Drive P3 fetch directives — img/media/connect gain blob:/loopback', () => {
		expect(SESSION_CSP).toContain("img-src 'self' data: blob:");
		expect(SESSION_CSP).toContain("media-src 'self' blob: http://127.0.0.1:*");
		expect(SESSION_CSP).toContain("connect-src 'self' blob: https: wss:");
	});

	// Meet B1 Task 16b (locked triple-lock delta): background blur's WASM
	// segmentation model needs 'wasm-unsafe-eval' to compile under Chromium's
	// CSP, so script-src now carries its OWN explicit directive here (it used
	// to be absent, falling back to default-src 'self'). The invariant that
	// matters is unchanged: no 'unsafe-inline' anywhere, no broader grant.
	it("script-src is 'self' + 'wasm-unsafe-eval' ONLY -- no 'unsafe-inline', no broader grant", () => {
		expect(SESSION_CSP).toContain("script-src 'self' 'wasm-unsafe-eval'");
		expect(SESSION_CSP).not.toContain('unsafe-inline');
	});

	// A4 (Drive P3 precedent, CLAUDE.md): the trusted-sender remote-image
	// opt-in (sanitize.ts allowRemoteImages) needs img-src https: in ALL THREE
	// CSP homes -- gateway header + SvelteKit meta CSP (both already fixed,
	// commit 9fe991bb) + this Electron SESSION_CSP. This policy is enforced
	// standalone wherever the shell is the ONLY header (no-upstream loads,
	// where applySessionLockdown injects SESSION_CSP) — missing https: here
	// would block the opt-in even though the other two homes allow it.
	it('img-src allows https: for the remote-image opt-in (parity with gateway header + meta CSP)', () => {
		expect(SESSION_CSP).toContain("img-src 'self' data: blob: https:");
	});

	// B5 (2026-07-11 codebase review): a bare object-src 'none' blocks the
	// SecureViewer's <embed type="application/pdf" src={blob:...}> PDF/office
	// preview render (object-src, not img-src/media-src, gates <object>/
	// <embed>/<applet>). Fixed in all three CSP homes; this is the Electron one.
	it("object-src allows self + blob: (the SecureViewer <embed> PDF preview), not 'none'", () => {
		expect(SESSION_CSP).not.toContain("object-src 'none'");
		expect(SESSION_CSP).toContain("object-src 'self' blob:");
	});

	// E6 app-origin fix (2026-09-21): the gateway-served webmail ships its OWN
	// authoritative header CSP (with the deliberate inline-script allowance
	// SvelteKit's pre-meta hydration bootstrap needs). Replacing it wholesale
	// blocked hydration and rendered a white page; the shell now DEFERS to any
	// upstream CSP and injects SESSION_CSP only where none exists.
	describe('shouldInjectSessionCsp (defer to an upstream document policy)', () => {
		it('injects when the response carries no CSP header', () => {
			expect(shouldInjectSessionCsp(undefined)).toBe(true);
			expect(shouldInjectSessionCsp({ 'Content-Type': ['text/html'] })).toBe(true);
			expect(shouldInjectSessionCsp({})).toBe(true);
		});

		it('defers when the upstream server ships its own CSP (exact or cased)', () => {
			const gateway = {
				'Content-Security-Policy': [
					"default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; frame-ancestors 'none'",
				],
			};
			expect(shouldInjectSessionCsp(gateway)).toBe(false);
			expect(shouldInjectSessionCsp({ 'content-security-policy': ["default-src 'self'"] })).toBe(false);
		});

		it('an empty upstream CSP value still admits the injection', () => {
			expect(shouldInjectSessionCsp({ 'Content-Security-Policy': [] })).toBe(true);
		});
	});
});
