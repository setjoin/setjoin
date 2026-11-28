import { defineConfig, devices } from '@playwright/test';

const CSP_PORT = Number(process.env.E2E_CSP_PORT ?? '8199');
if (!Number.isInteger(CSP_PORT) || CSP_PORT < 1024 || CSP_PORT > 65535) {
	throw new Error('E2E_CSP_PORT must be a decimal port from 1024 through 65535');
}
const BASE_URL = process.env.E2E_CSP_BASE_URL ?? `http://127.0.0.1:${CSP_PORT}`;
const JSON_REPORT = process.env.PLAYWRIGHT_JSON_OUTPUT_FILE ?? './test-results/playwright-csp.json';
let cspURL: URL;
try {
	cspURL = new URL(BASE_URL);
} catch {
	throw new Error('E2E_CSP_BASE_URL must be a valid loopback http(s) origin');
}
if (
	!['http:', 'https:'].includes(cspURL.protocol) ||
	!['127.0.0.1', 'localhost', '[::1]'].includes(cspURL.hostname) ||
	cspURL.username ||
	cspURL.password ||
	cspURL.pathname !== '/' ||
	cspURL.search ||
	cspURL.hash ||
	Number(cspURL.port) !== CSP_PORT
) {
	throw new Error('E2E_CSP_BASE_URL must be an exact loopback origin whose port matches E2E_CSP_PORT');
}

// Self-contained CSP confirmation config: serves the static build and runs only
// e2e/csp.spec.ts. No backend/auth required — the <meta> CSP lives in the
// prerendered HTML, so the inline-script enforcement is fully exercised against
// the static build. (The full e2e harness in playwright.config.ts runs the same
// spec against the live gateway, adding the gateway response-header CSP.)
//
//   npm run build && npx playwright test --config playwright.csp.config.ts
export default defineConfig({
	testDir: './e2e',
	testMatch: 'csp.spec.ts',
	outputDir: './test-results/playwright-csp-artifacts',
	timeout: 30_000,
	retries: 0,
	reporter: [
		['list'],
		['json', { outputFile: JSON_REPORT }],
	],
	use: {
		baseURL: BASE_URL,
		headless: true,
		trace: 'off',
	},
	projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
	webServer: {
		command: `python3 -m http.server ${CSP_PORT} --bind 127.0.0.1 --directory build`,
		url: `${BASE_URL}/`,
		// A pre-existing process may serve an older build. Failing on a bound port
		// keeps this static CSP lane source/build-bound instead of silently reusing it.
		reuseExistingServer: false,
		timeout: 30_000,
		stderr: 'ignore',
	},
});
