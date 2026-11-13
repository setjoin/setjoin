import { test, expect } from '@playwright/test';

// M9 CSP confirmation — live browser proof that the SvelteKit <meta> CSP locks
// script-src to hashes WITHOUT breaking hydration.
//
// What the meta governs: a <meta> CSP only applies to content AFTER it, and
// SvelteKit injects it after app.html's pre-paint theme <script>. So the meta
// hash-locks the inline hydration bootstrap + anything the app injects at runtime
// (the real XSS surface); the pre-paint theme script is governed by the gateway
// response-header CSP. The live gateway run checks that header too; the standalone
// static build deliberately has no response header and checks the meta policy only.
// This test therefore checks the properties that matter:
//   1. The served meta CSP's script-src has NO 'unsafe-inline' (teeth: re-adding it
//      to svelte.config.js makes this fail) and DOES pin a sha256 hash.
//   2. The app boots UNDER that strict meta: the hash-locked inline bootstrap
//      executed ⇔ it imported the entry modules (/_app/immutable/entry/*.js). If the
//      bootstrap hash were wrong/missing the bootstrap would be blocked and nothing
//      would load.
// Assertions use the raw response + network events, not page.evaluate, which is
// unreliable here (the standalone build has no backend → the SPA auth flow spins).
//
// Run standalone (static build, no backend): npm run build && npm run test:e2e:csp
// Also runs in the full e2e harness (playwright.config.ts) against the live gateway.

test.describe('CSP — script-src hash lockdown (M9)', () => {
	test('meta locks script-src to hashes and the app still boots', async ({ page }) => {
		const entryModules: number[] = [];
		page.on('response', (res) => {
			if (/\/_app\/immutable\/entry\/.*\.js(\?|$)/.test(res.url())) entryModules.push(res.status());
		});
		// Keep the no-backend SPA from spinning on session probes.
		await page.route(/\/(\.well-known\/jmap|jmap(\/|$)|auth\/)/, (route) =>
			route.fulfill({ status: 401, contentType: 'application/json', body: '{}' }).catch(() => {}),
		);

		const resp = await page.goto('/', { waitUntil: 'domcontentloaded', timeout: 15_000 });
		expect(resp, 'navigation response').toBeTruthy();

		// 1) The served meta CSP hash-locks script-src — no 'unsafe-inline', has a hash.
		const html = await resp!.text();
		const meta = html.match(/http-equiv="content-security-policy"\s+content="([^"]*)"/i)?.[1] ?? '';
		const scriptSrc = meta.match(/script-src([^;]*)/)?.[1] ?? '';
		expect(scriptSrc, `meta CSP had no script-src directive; meta="${meta}"`).not.toBe('');
		expect(scriptSrc, `meta script-src must not allow unsafe-inline: "${scriptSrc}"`).not.toContain(
			'unsafe-inline',
		);
		expect(scriptSrc, `meta script-src must pin a sha256 hash: "${scriptSrc}"`).toContain('sha256-');

		// A static http.server cannot provide the gateway's defense-in-depth
		// header. The live browser lane sets this switch and must fail if the
		// browser-visible response did not carry the real header.
		const gatewayCsp = resp!.headers()['content-security-policy'] ?? '';
		if (process.env.E2E_CSP_REQUIRE_GATEWAY_HEADER === '1' || gatewayCsp !== '') {
			const gatewayScriptSrc = gatewayCsp.match(/script-src([^;]*)/)?.[1] ?? '';
			expect(gatewayCsp, 'gateway response must carry Content-Security-Policy').not.toBe('');
			expect(gatewayScriptSrc, `gateway CSP had no script-src directive: "${gatewayCsp}"`).not.toBe('');
			expect(gatewayScriptSrc, `gateway CSP must retain same-origin scripts: "${gatewayScriptSrc}"`).toContain(
				"'self'",
			);
			expect(
				gatewayScriptSrc,
				`gateway CSP must retain the Meet WASM allowance: "${gatewayScriptSrc}"`,
			).toContain('wasm-unsafe-eval');
		}

		// 2) The hash-locked inline bootstrap executed under that meta → entry
		//    modules loaded (200). A blocked bootstrap imports nothing.
		await expect
			.poll(() => entryModules.filter((status) => status === 200).length, {
				timeout: 15_000,
				message: 'SvelteKit entry module never loaded — bootstrap may be CSP-blocked',
			})
			.toBeGreaterThan(0);
		const loaded = entryModules.filter((s) => s === 200);
		expect(
			loaded.length,
			`SvelteKit entry module never loaded — bootstrap may be CSP-blocked. statuses: ${entryModules.join(', ') || '(none)'}`,
		).toBeGreaterThan(0);

		// 3) Drive P3 loopback delta (spec §8.2, locked minimal): the served meta
		//    still carries media-src's 127.0.0.1 token, and script-src is unaffected
		//    (still no 'unsafe-inline', still hash-locked) — the delta is media-src
		//    (+ connect-src blob:) only, never a regression to the M9 lockdown.
		const mediaSrc = meta.match(/media-src([^;]*)/)?.[1] ?? '';
		expect(mediaSrc, `meta CSP media-src must carry the Drive loopback: "${mediaSrc}"`).toContain(
			'http://127.0.0.1:*',
		);
		expect(scriptSrc, `meta script-src regressed after the Drive P3 delta: "${scriptSrc}"`).not.toContain(
			'unsafe-inline',
		);
	});
});
