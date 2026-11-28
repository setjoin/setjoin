import { defineConfig } from '@playwright/test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const AUTH_USER  = join(__dirname, 'playwright/.auth/user.json');
const AUTH_ADMIN = join(__dirname, 'playwright/.auth/admin.json');
const BASE_URL = process.env.E2E_SERVER ?? 'http://localhost:8080';
const JSON_REPORTER: ['json', { outputFile: string }] = process.env.PLAYWRIGHT_JSON_OUTPUT_FILE
  ? ['json', { outputFile: process.env.PLAYWRIGHT_JSON_OUTPUT_FILE }]
  : ['json', { outputFile: './test-results/playwright.json' }];

export default defineConfig({
  testDir: './e2e',
  outputDir: './test-results/playwright-artifacts',
  // Visual baselines intentionally omit the host OS. The release browser lane
  // may execute on macOS, a supported Ubuntu host, or through the version-
  // matched remote browser seam; self-hosted fonts plus a small antialiasing
  // tolerance keep the baseline portable while still catching layout drift.
  snapshotPathTemplate: '{testDir}/{testFilePath}-snapshots/{arg}-{projectName}{ext}',
  expect: {
    toHaveScreenshot: {
      animations: 'disabled',
      caret: 'hide',
      maxDiffPixelRatio: 0.015,
      threshold: 0.25,
    },
  },
  reporter: [
    ['list'],
    JSON_REPORTER,
  ],
  timeout: 60000,
  // The browser projects intentionally exercise the same seeded Alice/Admin
  // accounts and one live database. Cross-file workers therefore are not
  // isolated: a fired calendar reminder can cover another spec's controls,
  // and concurrent delegation/calendar mutations can observe each other's
  // state. Keep the canonical full run serial until fixtures provide a unique
  // account/database namespace per worker.
  workers: 1,
  // CI gets retries so a flake yields a trace instead of a red build; locally
  // flakes should FAIL loudly (a local retry-pass hides a real race).
  retries: process.env.CI ? 2 : 0,
  use: {
    baseURL: BASE_URL,
    ignoreHTTPSErrors: true,
    headless: true,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  // webServer removed — gateway started manually with /tmp/e2e-gateway
  projects: [
    {
      name: 'setup',
      testMatch: /global\.setup\.ts/,
      teardown: 'teardown',
    },
    {
      name: 'teardown',
      testMatch: /global\.teardown\.ts/,
    },
    // Project routing is declarative: specs tag their top-level describe with
    // @user or @admin and run under exactly that project (untagged specs run
    // under both — shared surfaces like smoke/a11y/csp/welcome-tour). This
    // replaces per-file test.skip guards, whose beforeEach still EXECUTED under
    // the skipped project — 80+ wasted logins/psql arranges per run and
    // same-account concurrency (two alice sessions mutating shared fixtures).
    {
      name: 'chromium',
      grepInvert: /@admin\b/,
      // Feature journeys are isolated from first-install clients.claim(). The
      // real SW cold/warm navigation and cache audit run in the dedicated
      // webmail-performance context, which explicitly uses the browser default.
      use: { storageState: AUTH_USER, serviceWorkers: 'block' },
      dependencies: ['setup'],
    },
    {
      name: 'admin-chromium',
      grepInvert: /@user\b/,
      use: { storageState: AUTH_ADMIN, serviceWorkers: 'block' },
      dependencies: ['setup'],
    },
  ],
});
