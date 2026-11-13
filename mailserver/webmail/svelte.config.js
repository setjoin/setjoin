import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	preprocess: vitePreprocess(),
	kit: {
		adapter: adapter({
			fallback: 'index.html'
		}),
		paths: {
			base: ''
		},
		// mode 'hash' (adapter-static prerenders everything): SvelteKit emits a
		// <meta> CSP that sha256-hashes its inline hydration bootstrap, so script-src
		// drops 'unsafe-inline'. A <meta> CSP only governs content AFTER it, and
		// SvelteKit injects it (via %sveltekit.head%) AFTER app.html's pre-paint
		// theme script — so this meta hash-locks the bootstrap + anything the app
		// injects at runtime (the real XSS surface), while the small static pre-paint
		// theme script (which runs before the meta, before first paint) is governed
		// only by the gateway response-header CSP (mailserver/internal/middleware/
		// security.go, which keeps 'unsafe-inline' since the header can't track the
		// per-build bootstrap hash). style-src KEEPS 'unsafe-inline': inline style=""
		// attributes (SplitPane ratios, avatar colors, progress bars) are pervasive
		// and hash mode covers <style> elements, not style attributes.
		csp: {
			mode: 'hash',
			directives: {
				'default-src': ['self'],
				// Meet B1 Task 16b (locked triple-lock delta, gateway header +
				// this meta CSP + Electron SESSION_CSP, one commit): background
				// blur's WASM segmentation model fails WebAssembly.instantiate
				// under Chromium's CSP without 'wasm-unsafe-eval' — the narrow
				// CSP source that permits ONLY wasm compilation, never textual
				// eval/new Function (so it does NOT reopen the 'unsafe-inline'
				// lockdown csp.test.ts guards below). No other directive changes.
				'script-src': ['self', 'wasm-unsafe-eval'],
				'style-src': ['self', 'unsafe-inline'],
				// https: is required for the reading-pane remote-image opt-in
				// (sanitize.ts allowRemoteImages, trusted-sender + "Load images"): the
				// ReadingPane iframe is a srcdoc iframe with no own `csp` attribute, so
				// it inherits this meta CSP — without https: here the opt-in was
				// silently dead (DOMPurify let the <img src="https://…"> through, the
				// browser's own CSP enforcement dropped the fetch anyway).
				'img-src': ['self', 'data:', 'blob:', 'https:'],
				'font-src': ['self'],
				// Drive P3 loopback delta (spec §8.2, locked minimal — batch-1 #1 / batch-3
				// #2): the SecureViewer renders native AV from the ticketed 127.0.0.1
				// render server + blob: URLs (RAM-blob images/pdf.js). connect-src and
				// media-src gain the loopback here — script-src stays hash-locked (see
				// csp.test.ts's "Drive loopback CSP delta" guard + e2e/csp.spec.ts).
				'connect-src': ['self', 'wss:', 'https:', 'ws:', 'http:', 'blob:'],
				'media-src': ['self', 'blob:', 'http://127.0.0.1:*'],
				// 'self' + blob: only (never a remote origin): object-src, not
				// img-src/media-src, gates <object>/<embed>/<applet> resource loading,
				// and SecureViewer.svelte renders PDF/ready-office previews via
				// <embed type="application/pdf" src={blob:...}>. A bare 'none' left
				// every such preview silently blank (B5, 2026-07-11 codebase review).
				'object-src': ['self', 'blob:'],
				'base-uri': ['self'],
				'form-action': ['self']
			}
		}
	}
};

export default config;
