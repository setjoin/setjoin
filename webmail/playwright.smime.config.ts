import { defineConfig, devices } from '@playwright/test';

// Self-contained E2E for the SP1 S/MIME web functions (compose encrypt fail-closed,
// inbox decrypt-on-read states, settings contacts'-certs). Unlike the main config
// (manual live gateway at :8080, currently bit-rotted per TODOS), this serves the
// built SPA via `vite preview` (adapter-static + index.html fallback → client
// routing works) and mocks ALL backend traffic with page.route. No DB / gateway / S3.
export default defineConfig({
  testDir: './e2e',
  testMatch: 'smime-encryption.spec.ts',
  timeout: 60_000,
  retries: 0,
  use: {
    baseURL: 'http://localhost:4178',
    headless: true,
    trace: 'off',
    screenshot: 'only-on-failure',
    viewport: { width: 1600, height: 1000 },
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'npm run preview -- --port 4178 --strictPort',
    url: 'http://localhost:4178/',
    reuseExistingServer: true,
    timeout: 120_000,
  },
});
