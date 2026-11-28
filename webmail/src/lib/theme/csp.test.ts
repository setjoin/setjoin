import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

// CSP hardening guard (M9). SvelteKit (csp mode 'hash') emits a <meta> CSP that
// sha256-hashes its inline hydration bootstrap, so script-src must NOT carry
// 'unsafe-inline' — that is the whole point of the lockdown, and the easiest thing
// to silently regress (e.g. someone re-adds it to fix an unrelated inline-script
// error). This asserts the invariant at the source. style-src deliberately KEEPS
// 'unsafe-inline' (pervasive inline style="" attributes; hash mode does not cover
// style attributes). The live browser proof that the strict policy doesn't break
// hydration is e2e/csp.spec.ts.
const here = dirname(fileURLToPath(import.meta.url)); // src/lib/theme
const root = join(here, '../../..'); // webmail/
const read = (rel: string): string => readFileSync(join(root, rel), 'utf-8');

function directive(config: string, name: string): string {
	const m = config.match(new RegExp(`'${name}':\\s*\\[([^\\]]*)\\]`));
	expect(m, `svelte.config.js must define a ${name} directive`).toBeTruthy();
	return m![1];
}

describe('CSP script-src lockdown (M9 hardening)', () => {
	const config = read('svelte.config.js');

	it("script-src does NOT allow 'unsafe-inline'", () => {
		expect(directive(config, 'script-src')).not.toContain('unsafe-inline');
	});

	it("style-src intentionally keeps 'unsafe-inline' (inline style attributes)", () => {
		// Documents the deliberate asymmetry so a future reader does not "fix" it.
		expect(directive(config, 'style-src')).toContain('unsafe-inline');
	});

	// A4: img-src omitted https: entirely, so sanitize.ts's allowRemoteImages
	// opt-in (trusted-sender / "Load images") let an <img src="https://…"> through
	// DOMPurify only for the browser's own CSP to still block the fetch — the
	// opt-in was dead. script-src must NOT gain anything from this fix.
	it('img-src allows https: (the remote-image opt-in needs it to actually load)', () => {
		expect(directive(config, 'img-src')).toContain('https:');
	});

	it("img-src fix does not loosen script-src away from the hash lockdown", () => {
		expect(directive(config, 'script-src')).not.toContain('unsafe-inline');
		expect(directive(config, 'script-src')).not.toContain('https:');
	});
});

describe('Drive loopback CSP delta (P3 — locked minimal, spec §8.2)', () => {
	const config = read('svelte.config.js');

	it('media-src gains the loopback (native AV streaming needs it)', () => {
		expect(directive(config, 'media-src')).toContain('http://127.0.0.1:*');
	});

	it('connect-src gains blob: (pdf.js blob-URL fetch, batch-3 #2)', () => {
		expect(directive(config, 'connect-src')).toContain('blob:');
	});

	it('NO other directive references the loopback — the delta is media-src ONLY', () => {
		for (const d of ['default-src', 'script-src', 'style-src', 'img-src', 'font-src', 'connect-src']) {
			expect(directive(config, d), `${d} must not gain the loopback`).not.toContain('127.0.0.1');
		}
	});

	it("script-src STILL has no 'unsafe-inline' (the delta may not regress the M9 lockdown)", () => {
		expect(directive(config, 'script-src')).not.toContain('unsafe-inline');
	});
});

// B5 (2026-07-11 codebase review): object-src (not img-src/media-src) is what
// gates <object>/<embed>/<applet> resource loading. SecureViewer.svelte renders
// PDF/ready-office-rendition previews via <embed type="application/pdf"
// src={blob:...}>, so a bare "object-src 'none'" silently blanked every such
// preview -- no console error a user would report, just nothing rendered.
describe('SecureViewer preview render (B5 — object-src must not block it)', () => {
	const config = read('svelte.config.js');

	it("object-src is NOT 'none' (that would block every <embed> PDF/office preview)", () => {
		expect(directive(config, 'object-src')).not.toContain('none');
	});

	it('object-src allows self + blob: (the RAM-blob URL SecureViewer always uses), nothing broader', () => {
		const objectSrc = directive(config, 'object-src');
		expect(objectSrc).toContain('self');
		expect(objectSrc).toContain('blob:');
		expect(objectSrc).not.toMatch(/https:|http:|\*/);
	});

	it("script-src is untouched by this fix (still hash-locked, no 'unsafe-inline')", () => {
		expect(directive(config, 'script-src')).not.toContain('unsafe-inline');
	});
});

// Meet B1 Task 16b (locked triple-lock delta): background blur's WASM
// segmentation model needs 'wasm-unsafe-eval' in script-src to compile under
// Chromium's CSP. This is pinned as the ONLY addition — 'unsafe-inline' stays
// banned (the M9 invariant above), and no other directive gains anything.
describe("Background-blur CSP delta (Task 16b — 'wasm-unsafe-eval' only)", () => {
	const config = read('svelte.config.js');

	it("script-src gains 'wasm-unsafe-eval'", () => {
		expect(directive(config, 'script-src')).toContain('wasm-unsafe-eval');
	});

	it("script-src STILL does not carry 'unsafe-inline' (wasm-unsafe-eval is not a backdoor to it)", () => {
		expect(directive(config, 'script-src')).not.toContain('unsafe-inline');
	});

	it("script-src is exactly 'self' + 'wasm-unsafe-eval' — no third value snuck in", () => {
		const values = directive(config, 'script-src')
			.split(',')
			.map((v) => v.trim().replace(/^'|'$/g, ''));
		expect(values.sort()).toEqual(['self', 'wasm-unsafe-eval'].sort());
	});
});
