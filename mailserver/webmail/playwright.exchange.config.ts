import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  testMatch: /exchange-replacement\.spec\.ts/,
  outputDir: './test-results/exchange-replacement-playwright',
  timeout: 60_000,
  workers: 1,
  reporter: [['list'], ['json',{outputFile:'./test-results/exchange-replacement-playwright.json'}]],
  use: { baseURL:'http://127.0.0.1:4178',headless:true,serviceWorkers:'block',trace:'retain-on-failure',screenshot:'only-on-failure' },
  webServer: { command:'npm run build && node scripts/serve-static-spa.mjs build 4178',url:'http://127.0.0.1:4178',reuseExistingServer:false,timeout:120_000 },
  projects:[{name:'exchange-chromium',use:{browserName:'chromium'}}],
});
