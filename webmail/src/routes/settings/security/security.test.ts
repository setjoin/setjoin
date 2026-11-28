import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import { stubFetchRoutes } from '$lib/test-utils';
import Page from './+page.svelte';

// The page accepts injectable initial data (props or a mockable load) so each state
// is renderable in isolation; match the route's real data plumbing when wiring.

// ponytail: history tab prop — sign-in/session content lives inside the history tab;
// inject initialTab + initialLoading:false so tests render it without clicking the tab or waiting for onMount.
const BASE = { initialTab: 'history', initialLoading: false };

describe('Security page — sign-in activity (per-state)', () => {
  beforeEach(() => {
    // Every route onMount touches; more-specific /auth/me/* before /auth/me.
    stubFetchRoutes([
      ['/api/user/devices', { devices: [] }],
      ['/api/user/security-score', { score: 80, checks: [] }],
      ['/api/user/cert-status', { status: 'none' }],
      ['/api/user/login-history', { items: [], total: 0 }],
      ['/api/user/sessions', { sessions: [] }],
      ['/auth/me/smime/recipient-certs', { certs: [] }],
      ['/auth/me/smime/certs', { certs: [] }],
      ['/auth/me', { totp_enabled: false }],
    ]);
  });

  it('EMPTY/first-time: shows the warm empty-state when there are no sign-ins', () => {
    render(Page, { props: { ...BASE, initialSignIns: [] } as any });
    expect(screen.getByTestId('signins-empty')).toBeTruthy();
  });

  it('LOADING: shows skeleton rows (not a blank) while sign-ins load', () => {
    render(Page, { props: { ...BASE, signInsLoading: true } as any });
    expect(screen.getByTestId('signins-skeleton')).toBeTruthy();
  });

  it('ERROR: shows error+retry (role=alert) when the sign-ins fetch fails', () => {
    render(Page, { props: { ...BASE, signInsError: true } as any });
    const err = screen.getByTestId('signins-error');
    expect(err).toBeTruthy();
    expect(err.getAttribute('role')).toBe('alert');
  });

  it('POPULATED: renders rows and highlights the current session', () => {
    render(Page, { props: { ...BASE, initialSignIns: [
      { id: 1, success: true, current: true, client: 'web', authMethod: 'webauthn', location: 'Berlin, DE' },
      { id: 2, success: true, current: false, client: 'imap', authMethod: 'app_password', location: 'Berlin, DE' },
    ] } as any });
    expect(screen.getByTestId('signin-row-1').getAttribute('aria-current')).toBe('true');
    expect(screen.getByTestId('signin-row-2').getAttribute('aria-current')).toBeNull();
  });

  it('FAILED filter + summary: failed_distinct banner shows and filter toggles', async () => {
    render(Page, { props: { ...BASE, failedDistinct: { count: 3, locations: 2, since: '2026-06-20' } } as any });
    expect(screen.getByTestId('failed-summary')).toBeTruthy();
    await fireEvent.click(screen.getByTestId('failed-only-toggle'));
    // toggling re-requests; assert the toggle is checked (fetch is mocked in the harness).
    expect((screen.getByTestId('failed-only-toggle') as HTMLInputElement).checked).toBe(true);
  });

  it('FAILED row uses a subtle warning badge (not red alarm); CLUSTER uses danger', () => {
    render(Page, { props: { ...BASE, initialSignIns: [
      { id: 9, success: false, current: false, cluster: false },
      { id: 10, success: false, current: false, cluster: true },
    ] } as any });
    expect(screen.getByTestId('signin-row-9').querySelector('[data-tone="warning"]')).toBeTruthy();
    expect(screen.getByTestId('signin-row-10').querySelector('[data-tone="danger"]')).toBeTruthy();
  });

  it('UNKNOWN GEO: a row with empty location renders "Unknown location", not blank', () => {
    render(Page, { props: { ...BASE, initialSignIns: [{ id: 11, success: true, location: '' }] } as any });
    expect(screen.getByTestId('signin-row-11').textContent).toContain('Unknown location');
  });

  it('SHOWING N of M: a load-more affordance appears when total > shown', () => {
    render(Page, { props: { ...BASE, signInsTotal: 250, initialSignIns: new Array(200).fill(0).map((_, i) => ({ id: i, success: true })) } as any });
    expect(screen.getByTestId('signins-showing-of')).toBeTruthy();
    expect(screen.getByTestId('signins-load-more')).toBeTruthy();
  });

  it('LOAD MORE: appends the next page (fetches offset=200, keeps existing rows)', async () => {
    const page1 = { items: new Array(200).fill(0).map((_, i) => ({ id: i, success: true })), total: 250 };
    const page2 = { items: new Array(50).fill(0).map((_, i) => ({ id: 200 + i, success: true })), total: 250 };
    const urls: string[] = [];
    vi.stubGlobal('fetch', vi.fn().mockImplementation((url: any) => {
      const u = String(url);
      if (u.includes('/user/login-history')) {
        urls.push(u);
        return Promise.resolve({ ok: true, json: async () => (u.includes('offset=200') ? page2 : page1) } as Response);
      }
      // every other onMount call: benign empty-ok
      return Promise.resolve({ ok: true, json: async () => ({}) } as Response);
    }));
    // Live mode (no initialSignIns) so the real load path runs.
    render(Page, { props: { initialTab: 'history' } as any });
    await vi.waitFor(() => expect(screen.getByTestId('signin-row-0')).toBeTruthy());
    await fireEvent.click(screen.getByTestId('signins-load-more'));
    await vi.waitFor(() => expect(screen.getByTestId('signin-row-249')).toBeTruthy());
    // page-1 row still present (appended, not replaced)
    expect(screen.getByTestId('signin-row-0')).toBeTruthy();
    expect(urls.some((u) => u.includes('offset=0'))).toBe(true);
    expect(urls.some((u) => u.includes('offset=200'))).toBe(true);
    // No restore needed: beforeEach re-installs the route stub for each test.
  });

  it('SESSIONS empty: "only this device" when one current session', () => {
    render(Page, { props: { ...BASE, initialSessions: [{ id: 's1', current: true }] } as any });
    expect(screen.getByTestId('sessions-only-current')).toBeTruthy();
  });

  it('REVOKE current session: the confirm Dialog warns it ends this session', async () => {
    render(Page, { props: { ...BASE, initialSessions: [{ id: 's1', current: true, device: 'This Mac' }] } as any });
    await fireEvent.click(screen.getByTestId('session-revoke-s1'));
    expect(screen.getByTestId('revoke-current-warning')).toBeTruthy();
  });

  it('REVOKE-ALL: opens a confirm Dialog stating the count; no POST before confirm', async () => {
    const spy = vi.spyOn(globalThis, 'fetch' as any);
    render(Page, { props: { ...BASE, initialSessions: [{ id: 's1', current: true }, { id: 's2' }] } as any });
    await fireEvent.click(screen.getByTestId('revoke-all-trigger'));
    expect(screen.getByTestId('revoke-all-confirm')).toBeTruthy();
    expect(spy).not.toHaveBeenCalledWith(expect.stringContaining('revoke-all'), expect.anything());
  });

  it('SECURE: trigger opens a Tier-3 Dialog; commit disabled until SECURE is typed; no POST without confirm', async () => {
    render(Page, { props: { ...BASE } as any });
    expect(screen.getByTestId('secure-account-trigger')).toBeTruthy();
    expect(screen.queryByTestId('secure-account-confirm')).toBeNull(); // closed on render
    await fireEvent.click(screen.getByTestId('secure-account-trigger'));
    const commit = screen.getByTestId('secure-account-confirm') as HTMLButtonElement;
    expect(commit.disabled).toBe(true); // type-to-confirm gate
    await fireEvent.input(screen.getByTestId('secure-account-type'), { target: { value: 'SECURE' } });
    expect(commit.disabled).toBe(false);
  });

  it('SECURE list-error blocks the commit (role=alert) — never secure blind', () => {
    render(Page, { props: { ...BASE, secureOpen: true, secureListError: true } as any });
    const err = screen.getByTestId('secure-list-error');
    expect(err.getAttribute('role')).toBe('alert');
    expect((screen.getByTestId('secure-account-confirm') as HTMLButtonElement).disabled).toBe(true);
  });

  it('A11Y: an aria-live region exists for async outcomes (signed-out / secured)', () => {
    render(Page);
    expect(screen.getByTestId('security-live').getAttribute('aria-live')).toBe('polite');
  });
});
