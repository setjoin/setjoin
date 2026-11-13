import { Page, type APIRequestContext } from '@playwright/test';
import { execFileSync } from 'node:child_process';

const BASE = process.env.E2E_SERVER ?? 'http://localhost:8080';
const DB_DSN = process.env.E2E_DB_DSN ?? 'postgres://mail:mail@127.0.0.1:5432/mailserver_e2e';

/**
 * Run SQL against the live e2e DB and return trimmed stdout. Used by CA specs to
 * arrange/reset fixtures deterministically (e.g. clear a ToU acceptance so the
 * spec is re-runnable, re-assert an elevated risk row against the 15-min risk
 * cron). Real rows the real endpoints read — never a mock. Throws on SQL error.
 * execFileSync (no shell) so SQL quoting is never an issue.
 */
export function psql(sql: string): string {
  return execFileSync('psql', [DB_DSN, '-X', '-v', 'ON_ERROR_STOP=1', '-tAc', sql], {
    encoding: 'utf-8',
  }).trim();
}

/** Mint a Bearer access token for `email` via the real /auth/login. */
export async function apiToken(request: APIRequestContext, email: string, password: string): Promise<string> {
  const resp = await request.post(`${BASE}/auth/login`, { data: { email, password } });
  if (!resp.ok()) {
    throw new Error(`login failed for ${email}: ${resp.status()} ${await resp.text()}`);
  }
  const body = (await resp.json()) as { access_token?: string };
  if (!body.access_token) {
    throw new Error(`login for ${email} returned no access_token: ${JSON.stringify(body)}`);
  }
  return body.access_token;
}

/**
 * Flip a feature toggle via the real admin API (PUT /admin/features/{key}); the
 * feature_toggles trigger (trg_feature_notify → config_changed) hot-reloads the
 * running gateway. Caller should briefly settle (~1s) before relying on the flip.
 */
export async function setFeature(
  request: APIRequestContext,
  adminToken: string,
  key: string,
  enabled: boolean
): Promise<void> {
  const resp = await request.put(`${BASE}/api/admin/features/${key}`, {
    headers: {
      Authorization: `Bearer ${adminToken}`,
      'Content-Type': 'application/json',
      'X-Audit-Reason': `E2E toggle ${key} ${enabled ? 'on' : 'off'}`,
    },
    data: { enabled },
  });
  if (!resp.ok()) {
    throw new Error(`set feature ${key}=${enabled} failed: ${resp.status()} ${await resp.text()}`);
  }
}

/** Decode the `email` (or `sub`) claim from a JWT without verifying it. */
function jwtEmail(token: string): string | null {
  try {
    const part = token.split('.')[1];
    const json = Buffer.from(part.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf-8');
    const payload = JSON.parse(json) as { email?: string; sub?: string };
    return payload.email ?? payload.sub ?? null;
  } catch {
    return null;
  }
}

/**
 * Authenticate `page`'s browser context as `email` via the real /auth/login API
 * and install the access_token cookie the SPA reads (credentials:'include').
 *
 * This is the same path global.setup.ts uses — deterministic, and it never drives
 * the brittle login <form> (whose label wiring shifts with the redesign). It is
 * also identity-aware: if the context cookie already belongs to `email` (the
 * project storageState usually carries it) it is reused, so we don't re-hit the
 * rate-limited /auth/login or silently run an admin test under a user session.
 *
 * Returns the raw access_token (a Bearer JWT) for callers that need it (mailctl,
 * device-proof requests).
 */
export async function apiLogin(page: Page, email: string, password: string): Promise<string> {
  const cookies = await page.context().cookies();
  const existing = cookies.find((c) => c.name === 'access_token')?.value;
  if (existing && jwtEmail(existing) === email) {
    return existing;
  }

  const resp = await page.request.post(`${BASE}/auth/login`, { data: { email, password } });
  if (!resp.ok()) {
    throw new Error(`login failed for ${email}: ${resp.status()} ${await resp.text()}`);
  }
  const body = (await resp.json()) as { access_token?: string };
  const token = body.access_token;
  if (!token) {
    // 200 without a token means an MFA / force-password-change challenge — a seed
    // problem, surfaced loudly rather than masked as an unauthenticated session.
    throw new Error(`login for ${email} returned no access_token (mfa/force-change?): ${JSON.stringify(body)}`);
  }

  await page.context().clearCookies();
  await page.context().addCookies([
    {
      name: 'access_token',
      value: token,
      url: new URL(BASE).origin,
      httpOnly: false,
      sameSite: 'Lax' as const,
    },
  ]);
  return token;
}

/**
 * Log in as `email` and land on the app shell so the SPA's auth state is live.
 * For users behind a blocking CA policy (terms/risk) the /apps heading never
 * resolves — those specs should call {@link apiLogin} directly and assert their
 * own interstitial instead.
 */
export async function loginAs(page: Page, email: string, password: string) {
  await apiLogin(page, email, password);
  await page.goto('/apps');
  await page.getByRole('heading', { name: /apps/i }).waitFor({ timeout: 15000 });
}

export async function loginAsUser(page: Page) {
  await loginAs(page, 'alice@test.local', 'TestPass123!');
}

export async function loginAsAdmin(page: Page) {
  await loginAs(page, 'admin@test.local', 'AdminPass123!');
}

/**
 * Reload after the first installed service worker has taken control and can
 * serve a same-origin request. The readiness fetch closes the small gap between
 * `controllerchange` and completion of `clients.claim()` without replacing the
 * Page (which would lose page-scoped routes, init scripts, and emulation).
 */
export async function reloadAfterServiceWorkerControl(
  page: Page,
  beforeNavigate?: (page: Page) => void | Promise<void>,
): Promise<Page> {
  await waitForServiceWorkerControl(page);
  await beforeNavigate?.(page);
  await page.reload();
  return page;
}

async function waitForServiceWorkerControl(page: Page): Promise<void> {
  await page.evaluate(async () => {
    if (!('serviceWorker' in navigator)) return;
    const registration = await navigator.serviceWorker.getRegistration();
    if (!registration) return;
    await navigator.serviceWorker.ready;
    if (!navigator.serviceWorker.controller) {
      await new Promise<void>((resolve) => {
        const controlled = () => {
          navigator.serviceWorker.removeEventListener('controllerchange', controlled);
          resolve();
        };
        navigator.serviceWorker.addEventListener('controllerchange', controlled);
        if (navigator.serviceWorker.controller) controlled();
      });
    }
    const response = await fetch('/health', { cache: 'no-store' });
    if (!response.ok) throw new Error(`service-worker readiness returned ${response.status}`);
  });
}
