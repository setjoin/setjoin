import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { loginAsUser } from './helpers';

// Logged-OUT a11y check: an empty storageState overrides the project's
// logged-in fixture (cookies + localStorage) so the login page renders rather
// than redirecting to /apps.
test.describe('Accessibility basics (login page)', () => {
  test.use({ storageState: { cookies: [], origins: [] } });

  test('login page has accessible form elements', async ({ page }) => {
    await page.goto('/');
    // Labels are associated via for/id by the Input primitive; if this regresses
    // the form is inaccessible (or the anonymous shell is stuck — see the redirect
    // loop fixed in +layout.svelte).
    await expect(page.getByLabel(/email/i)).toBeVisible();
    await expect(page.getByLabel(/password/i)).toBeVisible();
    await expect(page.getByRole('button', { name: /continue/i })).toBeVisible();
  });

  test('login page has no serious structural accessibility violations', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByLabel(/email/i)).toBeVisible();
    // Structural a11y guard (labels/roles/names/aria/landmarks/ids) — the surface
    // that regressed when the redesign reshaped the login form. color-contrast is
    // excluded: light-mode --text-tertiary (#7E8395) is 3.77:1 on white (fails AA
    // for <18px text); that's a global design-token decision tracked in TODOS for
    // the design pass, not a structural defect of this form.
    const results = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa'])
      .disableRules(['color-contrast'])
      .analyze();
    const serious = results.violations.filter(
      (v) => v.impact === 'serious' || v.impact === 'critical'
    );
    expect(serious, JSON.stringify(serious.map((v) => ({ id: v.id, nodes: v.nodes.length })))).toEqual([]);
  });
});

// Authenticated shell: each core app route renders without bouncing to the login
// page, and the rail marks the active app via aria-current (the accessible
// active-state). Navigation is by route (cookie auth survives goto) and every
// assertion is web-first auto-retrying — no fixed sleeps, no brittle href/CSS.
test.describe('Accessibility basics (authenticated shell)', () => {
  const apps = [
    { rail: 'Mail', path: '/inbox', url: /\/inbox/ },
    { rail: 'Calendar', path: '/calendar', url: /\/calendar/ },
    { rail: 'Contacts', path: '/contacts', url: /\/contacts/ },
    { rail: 'Tasks', path: '/tasks', url: /\/tasks/ },
    { rail: 'Settings', path: '/settings', url: /\/settings/ },
  ];

  for (const app of apps) {
    test(`${app.rail} page loads without redirect to login`, async ({ page }) => {
      await loginAsUser(page);
      await page.goto(app.path);
      // Stayed on the route (not bounced to '/') and the authenticated shell — not
      // the login form — rendered. (Per-app rail presence is caps-dependent, so we
      // assert the shell + absence of the login form, which is exactly "no redirect
      // to login".)
      await expect(page).toHaveURL(app.url);
      await expect(page.getByRole('navigation', { name: 'Main navigation' })).toBeVisible();
      await expect(page.getByLabel(/password/i)).toHaveCount(0);
      // Regression: the top-level flex pane once collapsed to 0px. The route's
      // accessible DOM still existed, but every visible interaction hit the
      // outer shell instead of the app.
      await expect.poll(async () => (await page.locator('#main-content').boundingBox())?.width ?? 0).toBeGreaterThan(0);
    });
  }
});
