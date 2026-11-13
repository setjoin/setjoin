import { defineConfig } from '@playwright/test';

const BASE_URL = process.env.E2E_BASE_URL;
const JSON_REPORT = process.env.PLAYWRIGHT_JSON_OUTPUT_FILE ?? './test-results/playwright-onboarding.json';
if (!BASE_URL || !/^https?:\/\/[^\s]+$/.test(BASE_URL)) {
  throw new Error('E2E_BASE_URL must be one explicit http(s) origin for onboarding');
}

export default defineConfig({
  testDir: './e2e',
  testMatch: /onboarding\.spec\.ts/,
  timeout: 60_000,
  workers: 1,
  fullyParallel: false,
  // Keep local failures immediate, but let CI recover from a browser-process
  // crash before treating the first-boot product journey as failed. Assertion
  // failures still have to pass cleanly on the retry.
  retries: process.env.CI ? 2 : 0,
  reporter: [
    ['list'],
    ['json', { outputFile: JSON_REPORT }],
  ],
  outputDir: './test-results/playwright-onboarding-artifacts',
  use: {
    baseURL: BASE_URL,
    ignoreHTTPSErrors: true,
    headless: true,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [{ name: 'onboarding-chromium', use: { browserName: 'chromium' } }],
});
