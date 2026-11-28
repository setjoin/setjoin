import { expect, test, type Page } from '@playwright/test';
import { reloadAfterServiceWorkerControl } from './helpers';

type UpgradeState =
  | 'awaiting_approval' | 'approved' | 'scheduled' | 'claimed' | 'preflight'
  | 'recovery_point' | 'staged' | 'maintenance' | 'migrations' | 'switched'
  | 'readiness' | 'committed' | 'verified' | 'cancel_requested'
  | 'rolling_back' | 'rolled_back' | 'failed' | 'recovery_required'
  | 'cancelled' | 'expired';

const labels: Record<'en' | 'zh', Record<UpgradeState, string>> = {
  en: {
    awaiting_approval: 'awaiting approval', approved: 'approved', scheduled: 'scheduled',
    claimed: 'claimed', preflight: 'preflight', recovery_point: 'recovery point',
    staged: 'staged', maintenance: 'maintenance', migrations: 'migrations',
    switched: 'switched', readiness: 'readiness', committed: 'committed',
    verified: 'verified', cancel_requested: 'cancel requested', rolling_back: 'rolling back',
    rolled_back: 'rolled back', failed: 'failed', recovery_required: 'recovery required',
    cancelled: 'cancelled', expired: 'expired',
  },
  zh: {
    awaiting_approval: '等待审批', approved: '已批准', scheduled: '已计划',
    claimed: '已领取', preflight: '预检', recovery_point: '创建恢复点', staged: '已暂存',
    maintenance: '维护模式', migrations: '数据库迁移', switched: '已切换',
    readiness: '就绪验证', committed: '已提交', verified: '已验证',
    cancel_requested: '已请求取消', rolling_back: '正在回滚', rolled_back: '已回滚',
    failed: '失败', recovery_required: '需要恢复', cancelled: '已取消', expired: '已过期',
  },
};

const states = Object.keys(labels.en) as UpgradeState[];
const cancellable = new Set<UpgradeState>([
  'awaiting_approval', 'approved', 'scheduled', 'claimed', 'preflight', 'recovery_point', 'staged',
]);

function intent(state: UpgradeState) {
  return {
    intentId: '42', releaseId: 'enterprise-9-4-1', manifestDigest: 'a'.repeat(64),
    recoverySetId: '11111111-1111-4111-8111-111111111111', recoverySetDigest: 'b'.repeat(64),
    state, stateGeneration: '9', reason: 'Apply a verified Setjoin release', scheduleAt: null,
    expiresAt: '2099-08-02T00:00:00Z', result: null,
    events: [{ generation: '9', from: null, to: state, occurredAt: '2099-08-01T10:02:00Z' }],
  };
}

function model(state: UpgradeState, execution = true, dangerousEvidence = false) {
  return {
    schemaVersion: 1,
    flags: { catalog: true, execution },
    releases: [{
      releaseId: 'enterprise-9-4-1', version: '9.4.1', channel: 'enterprise',
      manifestDigest: 'a'.repeat(64), metadataExpiresAt: '2099-08-03T00:00:00Z',
      entitlementGraceUntil: '2099-08-04T00:00:00Z',
      status: dangerousEvidence ? 'withdrawn' : 'available',
      readiness: {
        status: dangerousEvidence ? 'blocked' : 'ready', generation: '4',
        checks: { disk: !dangerousEvidence }, blockerCount: dangerousEvidence ? 1 : 0,
        expiresAt: '2099-08-02T00:00:00Z',
      },
    }],
    recoverySet: {
      recoverySetId: '11111111-1111-4111-8111-111111111111', manifestDigest: 'b'.repeat(64),
      status: 'verified', createdAt: '2099-08-01T09:00:00Z', expiresAt: '2099-08-02T09:00:00Z',
      fresh: !dangerousEvidence,
      restoreProof: {
        proofId: '22222222-2222-4222-8222-222222222222', targetId: 'isolated-1',
        provedAt: '2099-08-01T09:30:00Z', staleWarning: dangerousEvidence,
      },
    },
    intent: intent(state),
  };
}

async function installMocks(page: Page, current: { value: ReturnType<typeof model> }) {
  await page.addInitScript(() => {
    localStorage.setItem('sj-welcome-tour:admin@test.local', '1');
  });
  await page.route(/^https?:\/\/[^/]+\/(auth|jmap|api)\b/, (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: '{}' }));
  await page.route(/\/auth\/me(?:\?|$)/, (route) => route.fulfill({
    status: 200, contentType: 'application/json',
    body: JSON.stringify({
      email: 'admin@test.local', display_name: 'Admin', is_admin: true,
      has_mailbox: true, totp_enabled: true, delegates: [], impersonating: false,
    }),
  }));
  const session = {
    apiUrl: '/jmap', downloadUrl: '/blobs/{blobId}', uploadUrl: '/upload',
    eventSourceUrl: '/events', state: 'state-1', username: 'admin@test.local',
    accounts: { admin: { name: 'admin@test.local', isPersonal: true, accountCapabilities: {} } },
    primaryAccounts: { 'urn:ietf:params:jmap:mail': 'admin' },
    capabilities: {
      'urn:setjoin:params:jmap:mail': {
        admin: { consoles: ['system'], permissions: ['system.upgrade'] },
      },
    },
  };
  await page.route(/(?:\.well-known\/jmap|\/jmap\/session)(?:\?|$)/, (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(session) }));
  await page.route(/\/api\/user\/offline\/caps(?:\?|$)/, (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: '{"allowed":false}' }));
  await page.route(/\/api\/admin\/system\/upgrades\/intents\/42(?:\?|$)/, (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(current.value.intent) }));
  await page.route(/\/api\/admin\/system\/upgrades(?:\?|$)/, (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(current.value) }));
}

async function show(page: Page, current: { value: ReturnType<typeof model> }, locale: 'en' | 'zh', state: UpgradeState) {
  current.value = model(state);
  await page.goto('/admin/updates/server');
  await page.evaluate((nextLocale) => localStorage.setItem('locale', nextLocale), locale);
  page = await reloadAfterServiceWorkerControl(page);
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(locale === 'en' ? 'Server updates' : '服务器更新');
  await expect(page.getByText(labels[locale][state], { exact: true }).first()).toBeVisible();
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  const cancel = page.getByRole('button', { name: locale === 'en' ? 'Cancel safely' : '安全取消' });
  await expect(cancel).toHaveCount(cancellable.has(state) ? 1 : 0);
  if (state === 'recovery_required') {
    await expect(page.locator('.transaction[aria-live="assertive"]')).toBeVisible();
  }
  await page.evaluate(() => document.fonts.ready);
}

test.describe('Transactional updater dangerous-state visual matrix @admin', () => {
  test.use({
    storageState: { cookies: [], origins: [] },
    timezoneId: 'UTC',
    reducedMotion: 'reduce',
    serviceWorkers: 'block',
  });

  test('covers every durable state in English desktop and Chinese mobile', async ({ page }) => {
    const current = { value: model('approved') };
    await installMocks(page, current);
    for (const [locale, viewport] of [
      ['en', { width: 1440, height: 900 }],
      ['zh', { width: 375, height: 812 }],
    ] as const) {
      await page.setViewportSize(viewport);
      for (const state of states) await show(page, current, locale, state);
    }
  });

  test('pins the materially distinct visual equivalence classes', async ({ page }) => {
    const current = { value: model('recovery_required') };
    await installMocks(page, current);

    await page.setViewportSize({ width: 1440, height: 900 });
    await show(page, current, 'en', 'recovery_required');
    await expect(page).toHaveScreenshot('updater-recovery-required-en-desktop.png', { fullPage: true });

    await page.setViewportSize({ width: 375, height: 812 });
    await show(page, current, 'zh', 'recovery_required');
    await expect(page).toHaveScreenshot('updater-recovery-required-zh-mobile.png', { fullPage: true });

    current.value = model('rolled_back', false);
    await page.evaluate(() => localStorage.setItem('locale', 'en'));
    page = await reloadAfterServiceWorkerControl(page);
    await expect(page.getByText('Transactional execution is off.')).toBeVisible();
    await expect(page.getByText('rolled back', { exact: true }).first()).toBeVisible();
    await expect(page).toHaveScreenshot('updater-execution-off-rolled-back-en-mobile.png', { fullPage: true });

    await page.setViewportSize({ width: 1440, height: 900 });
    current.value = model('failed', true, true);
    await page.evaluate(() => localStorage.setItem('locale', 'zh'));
    page = await reloadAfterServiceWorkerControl(page);
    await page.getByText('enterprise-9-4-1', { exact: true }).click();
    await expect(page.getByText('已撤回', { exact: true })).toHaveCount(2);
    await expect(page.getByText(/Enterprise 制品访问宽限期结束时间/)).toBeVisible();
    await expect(page).toHaveScreenshot('updater-stale-withdrawn-zh-desktop.png', { fullPage: true });
  });
});
