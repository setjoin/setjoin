import { defineConfig, devices } from '@playwright/test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Dedicated config for the retained-prior-artifact update rehearsal
// (scripts/verify-webmail-performance.sh rehearsal). It is deliberately NOT
// discoverable by the default `playwright test` run: testDir points at
// ./rehearsal only, so the ordinary e2e and CSP lanes never execute or skip
// this spec. The rehearsal is a separate command from the timing run and must
// never be passable as one.
//
//   bash scripts/verify-webmail-performance.sh rehearsal
const BASE_URL = process.env.E2E_SERVER ?? 'http://localhost:8080';
const AUTH_USER = join(__dirname, 'playwright/.auth/user.json');
const JSON_REPORT = process.env.PLAYWRIGHT_JSON_OUTPUT_FILE ?? './test-results/playwright-rehearsal.json';

for (const [name, value] of [
	['PERF_REHEARSAL_PRIOR_BUILD_ID', process.env.PERF_REHEARSAL_PRIOR_BUILD_ID],
	['PERF_REHEARSAL_CANDIDATE_BUILD_ID', process.env.PERF_REHEARSAL_CANDIDATE_BUILD_ID],
	['PERF_REHEARSAL_CONTROL_DIR', process.env.PERF_REHEARSAL_CONTROL_DIR],
] as const) {
	if (!value) throw new Error(`${name} is required: the rehearsal binds each phase to its retained artifact build`);
}

export default defineConfig({
	testDir: './rehearsal',
	outputDir: './test-results/playwright-rehearsal-artifacts',
	// One test spans the prior acknowledgment, the mid-rehearsal gateway flip
	// (up to PERF_REHEARSAL_FLIP window), and the candidate acknowledgment.
	timeout: 600_000,
	expect: { timeout: 15_000 },
	retries: 0,
	reporter: [
		['list'],
		['json', { outputFile: JSON_REPORT }],
	],
	workers: 1,
	use: {
		baseURL: BASE_URL,
		headless: true,
		trace: 'retain-on-failure',
		screenshot: 'only-on-failure',
	},
	projects: [
		{
			name: 'setup',
			testDir: '../e2e',
			testMatch: /global\.setup\.ts/,
			teardown: 'teardown',
		},
		{
			name: 'teardown',
			testDir: '../e2e',
			testMatch: /global\.teardown\.ts/,
		},
		{
			name: 'chromium',
			testDir: './rehearsal',
			dependencies: ['setup'],
			use: {
				...devices['Desktop Chrome'],
				storageState: AUTH_USER,
				// The update path under rehearsal is the service-worker generation
				// flow; worker participation is the point of this lane.
				serviceWorkers: 'allow',
			},
		},
	],
});
