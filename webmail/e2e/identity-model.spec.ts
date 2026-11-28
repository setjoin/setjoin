import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { test, expect } from '@playwright/test';
import { loginAsAdmin, psql } from './helpers';

const EVIDENCE_DIR = resolve(
  process.env.IDENTITY_E2E_EVIDENCE ?? 'test-results/identity-e2e-evidence',
);

test.describe('Identity model modernization @admin', () => {
  test.beforeAll(() => mkdirSync(EVIDENCE_DIR, { recursive: true }));

  test('renders normalized evidence responsively while all behavior flags remain off', async ({ page }) => {
    const flags = JSON.parse(psql(`
      SELECT jsonb_object_agg(key, enabled)::text
        FROM feature_toggles
       WHERE key IN (
         'feature.identity_model_v2',
         'feature.identity_normalized_reads',
         'feature.identity_transitions'
       )
    `)) as Record<string, boolean>;
    expect(flags).toEqual({
      'feature.identity_model_v2': false,
      'feature.identity_normalized_reads': false,
      'feature.identity_transitions': false,
    });

    await loginAsAdmin(page);
    const listResponses = [
      'sources', 'people', 'conflicts', 'transitions', 'events',
    ].map((kind) => page.waitForResponse(
      (response) => response.url().endsWith(`/api/admin/identity/v2/${kind}`)
        && response.status() === 200,
    ));
    await page.goto('/admin/identity');
    await page.getByRole('tab', { name: 'Identity model' }).click();
    await Promise.all(listResponses);

    await expect(page.getByRole('tab', { name: 'Identity model' })).toHaveAttribute('aria-selected', 'true');
    await expect(page.getByRole('heading', { name: 'Identity', level: 1 })).toBeVisible();
    await expect(page.getByText('Production admission off')).toBeVisible();
    const flagState = page.getByRole('status', { name: 'Identity feature and read-path status' });
    await expect(flagState).toContainText('Identity model OFF');
    await expect(flagState).toContainText('Normalized reads OFF');
    await expect(flagState).toContainText('Transitions OFF');
    await expect(page.getByRole('row', { name: /Alice Test alice@test\.local.*[0-9]+ active.*[0-9]+ detached/i })).toBeVisible();
    await expect(page.getByText('No unresolved identity conflicts')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Preview' })).toBeDisabled();

    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.screenshot({
      path: resolve(EVIDENCE_DIR, 'identity-model-desktop.png'),
      fullPage: true,
    });

    const sourcesResponse = page.waitForResponse(
      (response) => response.url().endsWith('/api/admin/identity/v2/sources')
        && response.status() === 200,
    );
    await page.goto('/admin/identity/sources');
    await sourcesResponse;
    await expect(page.getByRole('link', { name: /Legacy Active Directory/i })).toBeVisible();
    await expect(page.getByRole('link', { name: /Legacy LDAP directory/i })).toBeVisible();
    await expect(page.getByRole('link', { name: /Setjoin local accounts/i })).toBeVisible();

    const adDetailResponse = page.waitForResponse(
      (response) => response.url().endsWith('/api/admin/identity/v2/sources/legacy%3Aad')
        && response.status() === 200,
    );
    await page.getByRole('link', { name: /Legacy Active Directory/i }).click();
    await adDetailResponse;
    await expect(page.getByRole('heading', { name: 'Legacy Active Directory' })).toBeVisible();
    await expect(page.getByText('Source authority')).toBeVisible();
    await expect(page.getByText('Canonical non-secret configuration')).toBeVisible();
    await page.screenshot({
      path: resolve(EVIDENCE_DIR, 'identity-source-detail-desktop.png'),
      fullPage: true,
    });

    const peopleResponse = page.waitForResponse(
      (response) => response.url().endsWith('/api/admin/identity/v2/people')
        && response.status() === 200,
    );
    await page.goto('/admin/identity/people');
    await peopleResponse;
    await expect(page.getByRole('link', { name: /Alice Test/i })).toBeVisible();

    const aliceID = aliceIDFromDB();
    const personDetailResponse = page.waitForResponse(
      (response) => response.url().endsWith(`/api/admin/identity/v2/people/${aliceID}`)
        && response.status() === 200,
    );
    await page.getByRole('link', { name: /Alice Test/i }).click();
    await personDetailResponse;
    await expect(page.getByText('Lifecycle and recovery')).toBeVisible();
    await expect(page.getByText('Authentication links')).toBeVisible();
    await expect(page.getByText('Field authority', { exact: true })).toBeVisible();

    const conflictsResponse = page.waitForResponse(
      (response) => response.url().endsWith('/api/admin/identity/v2/conflicts')
        && response.status() === 200,
    );
    await page.goto('/admin/identity/conflicts');
    await conflictsResponse;
    await expect(page.getByText('No unresolved identity conflicts')).toBeVisible();

    const transitionsResponse = page.waitForResponse(
      (response) => response.url().endsWith('/api/admin/identity/v2/transitions')
        && response.status() === 200,
    );
    await page.goto('/admin/identity/transitions');
    await transitionsResponse;
    await expect(page.getByText('No identity transitions. Preview is required before any directory account is detached.')).toBeVisible();

    const auditResponse = page.waitForResponse(
      (response) => response.url().endsWith('/api/admin/identity/v2/events')
        && response.status() === 200,
    );
    await page.goto('/admin/identity/audit');
    await auditResponse;
    await expect(page.getByRole('heading', { name: 'Audit inventory' })).toBeVisible();

    const mobileOverviewResponses = [
      'sources', 'people', 'conflicts', 'transitions', 'events',
    ].map((kind) => page.waitForResponse(
      (response) => response.url().endsWith(`/api/admin/identity/v2/${kind}`)
        && response.status() === 200,
    ));
    await page.setViewportSize({ width: 375, height: 812 });
    await page.goto('/admin/identity');
    await page.getByRole('tab', { name: 'Identity model' }).click();
    await Promise.all(mobileOverviewResponses);
    await expect.poll(
      () => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
      { message: 'identity console must not overflow the mobile viewport' },
    ).toBe(true);
    await page.screenshot({
      path: resolve(EVIDENCE_DIR, 'identity-model-mobile.png'),
      fullPage: true,
    });
  });

  test('transition preview is fail-closed while admission is off', async ({ page }) => {
    const aliceID = psql(`SELECT id::text FROM users WHERE email='alice@test.local'`);
    expect(aliceID).toMatch(/^[1-9][0-9]*$/);

    await loginAsAdmin(page);
    await page.goto('/admin/identity/transitions');
    await page.getByLabel('Person ID for new preview').fill(aliceID);
    await page.getByLabel('Audited reason').fill('E2E verify transition admission remains off');

    const previewResponse = page.waitForResponse(
      (response) => response.url().endsWith('/api/admin/identity/v2/transitions/preview')
        && response.request().method() === 'POST',
    );
    await page.getByRole('button', { name: 'Preview' }).click();
    const response = await previewResponse;
    expect(response.status()).toBe(409);
    expect(await response.json()).toMatchObject({
      code: 'BZ234',
      retryable: false,
      remediation: 'enable and verify identity model, transition admission, and live revocation enforcement',
    });
    await expect(page.getByRole('button', { name: 'Execute exact preview' })).toHaveCount(0);
  });
});

function aliceIDFromDB(): string {
  const id = psql(`SELECT id::text FROM users WHERE email='alice@test.local'`);
  expect(id).toMatch(/^[1-9][0-9]*$/);
  return id;
}
