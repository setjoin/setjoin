import { expect, test, type Page } from '@playwright/test';

const disclosure = {
  org_name: '示例协作空间',
  invited_email: 'guest@partner.example',
  channels: ['产品发布', '外部协作'],
  disclosure_text:
    '你的消息、文件和活动将按照组织的数据保留政策保存，并可能由授权管理员审查。',
  disclosure_version: 'v1',
  expires_at: '2026-08-05T12:00:00Z',
};

async function installGuestMocks(page: Page) {
  await page.route('**/auth/me', async (route) => {
    await route.fulfill({ status: 401, contentType: 'application/json', body: '{}' });
  });
  await page.route('**/auth/guest-invite/accept?*', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(disclosure),
    });
  });
  await page.route('**/auth/password-policy', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        minLength: 12,
        maxBytes: 72,
        requireUppercase: true,
        requireLowercase: true,
        requireDigit: true,
        requireSpecial: true,
      }),
    });
  });
}

test.describe('Guest invitation acceptance UI @user', () => {
  test.use({
    storageState: { cookies: [], origins: [] },
    viewport: { width: 375, height: 812 },
    locale: 'zh-CN',
    timezoneId: 'UTC',
    colorScheme: 'light',
    reducedMotion: 'reduce',
  });

  test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem('locale', 'zh'));
    await installGuestMocks(page);
  });

  test('renders a stable mobile disclosure and exposes a complete activation path', async ({ page }) => {
    await page.goto('/guest-invite/accept?token=visual-regression-secret');

    await expect(page).toHaveURL(/\/guest-invite\/accept$/);
    await expect(page.getByRole('heading', { name: '加入 示例协作空间' })).toBeVisible();
    await expect(page.getByText('外部来宾')).toBeVisible();
    await expect(page.getByLabel('创建密码')).toHaveAttribute('minlength', '12');
    await expect(page.getByRole('button', { name: '激活来宾账号' })).toBeDisabled();
    await page.evaluate(() => document.fonts.ready);

    // The app shell owns scrolling, so capture the complete content column rather
    // than only the current scroll-container viewport. Locator.screenshot() cannot
    // fit an element taller than its nested 100dvh scroller and silently clips its
    // top edge, so expand the viewport to the measured column before capture.
    const column = page.locator('.guest-accept-column');
    const columnHeight = await column.evaluate((element) => Math.ceil(element.getBoundingClientRect().height));
    await page.setViewportSize({ width: 375, height: columnHeight + 24 });
    await expect(column).toHaveScreenshot(
      'guest-invite-accept-zh-mobile.png',
    );

    await page.getByLabel('创建密码').fill('lowercase-only');
    await page.getByLabel('确认密码').fill('lowercase-only');
    await page.getByText('我理解并接受数据保留和监控说明。').click();
    await expect(page.getByText('密码必须包含大写字母')).toBeVisible();
    await expect(page.getByRole('button', { name: '激活来宾账号' })).toBeDisabled();

    await page.getByLabel('创建密码').fill('StrongGuestPassword1!');
    await page.getByLabel('确认密码').fill('StrongGuestPassword1!');
    await expect(page.getByRole('button', { name: '激活来宾账号' })).toBeEnabled();
  });

  test('keeps long production disclosure controls reachable without authenticated bootstrap noise', async ({
    page,
  }) => {
    await page.unroute('**/auth/guest-invite/accept?*');
    await page.route('**/auth/guest-invite/accept?*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          ...disclosure,
          org_name: 'setjoin-verify.local',
          invited_email: 'guest@ubuntu-live-20260731170221.test',
          disclosure_text:
            '你将以外部来宾身份加入 setjoin-verify.local，并可访问组织中的聊天频道。你的消息、文件和活动将依照组织的数据保留政策保存。授权管理员可以使用组织的合规工具访问、导出和审查你的内容。你的内容将在组织的本地环境中归档。继续即表示你同意此归档和监控。',
        }),
      });
    });
    const requestedPaths: string[] = [];
    page.on('request', (request) => requestedPaths.push(new URL(request.url()).pathname));

    await page.goto('/guest-invite/accept?token=long-production-disclosure');
    const scroller = page.locator('.sj-unauthenticated-content');
    await expect
      .poll(() => scroller.evaluate((element) => element.scrollHeight > element.clientHeight))
      .toBe(true);

    const acceptanceInput = page.getByLabel('我理解并接受数据保留和监控说明。');
    const acceptance = page.getByText('我理解并接受数据保留和监控说明。', { exact: true });
    await acceptance.scrollIntoViewIfNeeded();
    await expect(acceptance).toBeVisible();
    await expect.poll(() => scroller.evaluate((element) => element.scrollTop)).toBeGreaterThan(0);

    await page.getByLabel('创建密码').fill('StrongGuestPassword1!');
    await page.getByLabel('确认密码').fill('StrongGuestPassword1!');
    await acceptance.click();
    await expect(acceptanceInput).toBeChecked();
    await expect(page.getByRole('button', { name: '激活来宾账号' })).toBeEnabled();
    expect(requestedPaths).not.toContain('/user/offline/caps');
    expect(requestedPaths).not.toContain('/api/user/offline/caps');
  });
});

test.describe('Guest invitation desktop and responsive layout @user', () => {
  test.use({
    storageState: { cookies: [], origins: [] },
    viewport: { width: 1440, height: 1000 },
    locale: 'en-US',
    timezoneId: 'UTC',
    colorScheme: 'dark',
    reducedMotion: 'reduce',
  });

  test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => {
      localStorage.setItem('locale', 'en');
      localStorage.setItem('sj-theme', 'dark');
    });
    await installGuestMocks(page);
  });

  test('renders a stable dark desktop hierarchy', async ({ page }) => {
    await page.goto('/guest-invite/accept?token=desktop-visual-secret');
    await expect(page.getByRole('heading', { name: 'Join 示例协作空间' })).toBeVisible();
    // The visual contract fixes the rendered theme explicitly. Theme
    // persistence/boot is covered separately; the static preview has no
    // gateway response-header CSP and is not that integration boundary.
    await page.evaluate(() => { document.documentElement.dataset.theme = 'dark'; });
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.evaluate(() => document.fonts.ready);

    await expect(page).toHaveScreenshot('guest-invite-accept-en-dark-desktop.png', {
      fullPage: true,
    });
  });

  test('keeps the complete click path inside 360, 768, and 1024 pixel layouts', async ({ page }) => {
    await page.goto('/guest-invite/accept?token=responsive-layouts');
    for (const width of [360, 768, 1024]) {
      await page.setViewportSize({ width, height: 900 });
      await expect(page.getByRole('heading', { name: 'Join 示例协作空间' })).toBeVisible();
      await expect(page.getByLabel('Create password')).toBeVisible();
      await expect(page.getByText('I understand and accept the data retention and monitoring disclosure.')).toBeVisible();
      await expect(page.getByRole('button', { name: 'Activate guest account' })).toBeVisible();
      await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);

      for (const locator of [
        page.getByLabel('Create password'),
        page.getByLabel('Confirm password'),
        page.getByRole('button', { name: 'Activate guest account' }),
      ]) {
        const box = await locator.boundingBox();
        expect(box, `control must have layout at ${width}px`).not.toBeNull();
        expect(box!.x, `control starts inside ${width}px viewport`).toBeGreaterThanOrEqual(0);
        expect(box!.x + box!.width, `control ends inside ${width}px viewport`).toBeLessThanOrEqual(width);
      }
    }
  });
});
