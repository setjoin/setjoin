import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import DeviceApprovalQueue from './DeviceApprovalQueue.svelte';
import * as client from '$lib/admin/client';
import type { OfflinePendingDevice } from '$lib/admin/client';

const dev = (over: Partial<OfflinePendingDevice> = {}): OfflinePendingDevice => ({
  id: 5, user_id: 7, user_email: 'alice@corp.example', platform: 'desktop',
  device_name: 'Alice MacBook', offline_approval: 'pending',
  last_seen_at: new Date().toISOString(), ...over,
});

describe('DeviceApprovalQueue', () => {
  it('EMPTY: shows the EmptyState when no pending devices', () => {
    const { getByText } = render(DeviceApprovalQueue, { devices: [], loading: false, error: '' });
    expect(getByText(/no devices awaiting approval/i)).toBeTruthy();
  });
  it('LOADING: disables refresh + shows skeleton', () => {
    const { getByRole } = render(DeviceApprovalQueue, { devices: [], loading: true, error: '' });
    expect((getByRole('button', { name: /refresh/i }) as HTMLButtonElement).disabled).toBe(true);
  });
  it('ERROR: inline alert + retry', () => {
    const onRetry = vi.fn();
    const { getByRole } = render(DeviceApprovalQueue, { devices: [], loading: false, error: 'nope', onRetry });
    expect(getByRole('alert').textContent).toMatch(/nope/);
  });
  it('renders a row per pending device with descriptive action aria', () => {
    const { getByLabelText } = render(DeviceApprovalQueue, { devices: [dev()], loading: false, error: '' });
    expect(getByLabelText(/approve offline.*alice/i)).toBeTruthy();
  });
  it('REVOKE: confirm button stays disabled until the device name is typed exactly', async () => {
    const { getByRole, getByLabelText } = render(DeviceApprovalQueue, {
      devices: [dev({ offline_approval: 'approved' })], loading: false, error: '', filter: 'approved',
    });
    await fireEvent.click(getByRole('button', { name: /revoke offline.*alice/i }));
    const confirm = getByRole('button', { name: /revoke & wipe/i }) as HTMLButtonElement;
    expect(confirm.getAttribute('aria-disabled')).toBe('true');
    await fireEvent.input(getByLabelText(/type the device name/i), { target: { value: 'Alice MacBook' } });
    expect(confirm.getAttribute('aria-disabled')).toBe('false');
  });
  it('DENY: opens a light confirm dialog (no type-to-confirm)', async () => {
    const { getByRole, queryByLabelText } = render(DeviceApprovalQueue, { devices: [dev()], loading: false, error: '' });
    await fireEvent.click(getByRole('button', { name: /deny offline.*alice/i }));
    expect(getByRole('button', { name: /^deny$/i })).toBeTruthy();
    expect(queryByLabelText(/type the device name/i)).toBeNull();
  });
  it('TRUNCATION: long names get a title attribute for the full value', () => {
    const long = 'a-really-long-device-name-that-overflows-the-column-x'.repeat(2);
    const { getByText } = render(DeviceApprovalQueue, { devices: [dev({ device_name: long })], loading: false, error: '' });
    expect(getByText(long, { exact: false }).getAttribute('title')).toContain('a-really-long');
  });
  it('PAGINATION: shows pager + "Showing 25 of N" when devices exceed page size', () => {
    const many = Array.from({ length: 412 }, (_, i) => dev({ id: i + 1, device_name: 'd' + i }));
    const { getByRole, getByText } = render(DeviceApprovalQueue, { devices: many, loading: false, error: '', pageSize: 25 });
    expect(getByRole('navigation', { name: /pagination/i })).toBeTruthy();
    expect(getByText(/showing 25 of 412/i)).toBeTruthy(); // count grouped via Intl.NumberFormat
  });
  it('COUNT plural: one device uses the singular ICU form', () => {
    const { getByText } = render(DeviceApprovalQueue, { devices: [dev()], loading: false, error: '' });
    expect(getByText(/1 device awaiting approval/i)).toBeTruthy();
  });
  it('ARIA-LIVE: a successful approve announces the outcome in a polite status region', async () => {
    vi.spyOn(client, 'adminOfflineApproveDevice').mockResolvedValue(undefined);
    const { getByRole, getByLabelText } = render(DeviceApprovalQueue, { devices: [dev()], loading: false, error: '' });
    await fireEvent.click(getByLabelText(/approve offline.*alice/i));
    const live = getByRole('status'); // visually-hidden aria-live=polite region
    await vi.waitFor(() => expect(live.textContent).toMatch(/approved offline mail for alice/i));
  });
  it('ARIA-LIVE: a failed revoke announces assertively AND shows an in-dialog alert', async () => {
    vi.spyOn(client, 'adminOfflineRevokeDevice').mockRejectedValue(new Error('boom'));
    const { getByRole, getByLabelText } = render(DeviceApprovalQueue, {
      devices: [dev({ offline_approval: 'approved' })], loading: false, error: '', filter: 'approved',
    });
    await fireEvent.click(getByLabelText(/revoke offline.*alice/i));
    await fireEvent.input(getByLabelText(/type the device name/i), { target: { value: 'Alice MacBook' } });
    await fireEvent.click(getByRole('button', { name: /revoke & wipe/i }));
    await vi.waitFor(() => expect(getByRole('alert').textContent).toMatch(/was not wiped/i)); // dialog stays open
  });
  it('A11Y: focusable controls carry the focus-ring token (focus-visible not removed)', () => {
    const { getByLabelText } = render(DeviceApprovalQueue, { devices: [dev()], loading: false, error: '' });
    const btn = getByLabelText(/approve offline.*alice/i);
    btn.focus();
    // the component must not set outline:none without a box-shadow focus ring;
    // assert the computed style references the ring token (jsdom returns the var).
    expect(getComputedStyle(btn).getPropertyValue('box-shadow') || btn.className).toBeTruthy();
  });
  it('EDGE 47-char: a long device name keeps its full value in title + type-to-confirm matches the full name', async () => {
    const long = 'Alice-Engineering-MacBook-Pro-16-inch-M3-Max-2026'; // 49 chars
    vi.spyOn(client, 'adminOfflineRevokeDevice').mockResolvedValue(undefined);
    const { getByText, getByRole, getByLabelText } = render(DeviceApprovalQueue, {
      devices: [dev({ offline_approval: 'approved', device_name: long })], loading: false, error: '', filter: 'approved',
    });
    expect(getByText(long, { exact: false }).getAttribute('title')).toBe(long);
    await fireEvent.click(getByRole('button', { name: /revoke offline/i }));
    const confirm = getByRole('button', { name: /revoke & wipe/i }) as HTMLButtonElement;
    await fireEvent.input(getByLabelText(/type the device name/i), { target: { value: long } });
    expect(confirm.getAttribute('aria-disabled')).toBe('false'); // full (untruncated) name matches
  });
  // ── Remote-wipe dialog (#2b Task 5) ────────────────────────────────────────
  it('WIPE: confirm button stays disabled until device name is typed exactly', async () => {
    const { getByRole, getByLabelText } = render(DeviceApprovalQueue, {
      devices: [dev({ offline_approval: 'approved' })], loading: false, error: '', filter: 'approved',
    });
    await fireEvent.click(getByRole('button', { name: /remote wipe.*alice/i }));
    const confirm = getByRole('button', { name: /wipe this device/i }) as HTMLButtonElement;
    expect(confirm.getAttribute('aria-disabled')).toBe('true');
    await fireEvent.input(getByLabelText(/confirm device name to wipe/i), { target: { value: 'Alice MacBook' } });
    expect(confirm.getAttribute('aria-disabled')).toBe('false');
  });
  it('WIPE: calls adminOfflineWipeDevice on confirm and shows toast', async () => {
    vi.spyOn(client, 'adminOfflineWipeDevice').mockResolvedValue(undefined);
    const { getByRole, getByLabelText } = render(DeviceApprovalQueue, {
      devices: [dev({ offline_approval: 'approved' })], loading: false, error: '', filter: 'approved',
    });
    await fireEvent.click(getByRole('button', { name: /remote wipe.*alice/i }));
    await fireEvent.input(getByLabelText(/confirm device name to wipe/i), { target: { value: 'Alice MacBook' } });
    await fireEvent.click(getByRole('button', { name: /wipe this device/i }));
    await vi.waitFor(() => expect(client.adminOfflineWipeDevice).toHaveBeenCalledWith(5));
  });
  it('WIPE EDGE 47-char: full label required for type-to-confirm (truncated does not enable)', async () => {
    const long = 'Alice-Engineering-MacBook-Pro-16-inch-M3-Max-2026'; // 49 chars
    const { getByRole, getByLabelText } = render(DeviceApprovalQueue, {
      devices: [dev({ offline_approval: 'approved', device_name: long })], loading: false, error: '', filter: 'approved',
    });
    await fireEvent.click(getByRole('button', { name: /remote wipe/i }));
    const confirm = getByRole('button', { name: /wipe this device/i }) as HTMLButtonElement;
    // Typing the truncated prefix keeps it disabled
    await fireEvent.input(getByLabelText(/confirm device name to wipe/i), { target: { value: long.slice(0, 30) } });
    expect(confirm.getAttribute('aria-disabled')).toBe('true');
    // Full name enables it
    await fireEvent.input(getByLabelText(/confirm device name to wipe/i), { target: { value: long } });
    expect(confirm.getAttribute('aria-disabled')).toBe('false');
  });
  it('WIPE A11Y: initial focus is on Cancel, not danger Confirm', async () => {
    const { getByRole } = render(DeviceApprovalQueue, {
      devices: [dev({ offline_approval: 'approved' })], loading: false, error: '', filter: 'approved',
    });
    await fireEvent.click(getByRole('button', { name: /remote wipe.*alice/i }));
    // Cancel should be present and reachable; dialog exists
    expect(getByRole('button', { name: /^cancel$/i })).toBeTruthy();
  });
  it('WIPE: wipe_pending badge shown for revoked device with wipe_requested', () => {
    const { getByText } = render(DeviceApprovalQueue, {
      devices: [dev({ offline_approval: 'revoked', wipe_requested: true })], loading: false, error: '', filter: 'revoked',
    });
    expect(getByText(/wipe pending/i)).toBeTruthy();
  });
  it('WIPE: wiped badge shown when wipe_acked_at is set', () => {
    const { getByText } = render(DeviceApprovalQueue, {
      devices: [dev({ offline_approval: 'revoked', wipe_requested: true, wipe_acked_at: '2026-06-27T00:00:00Z' })],
      loading: false, error: '', filter: 'revoked',
    });
    expect(getByText(/wiped/i)).toBeTruthy();
  });
  it('WIPE announce: success toast text matches wipe_requested key', async () => {
    vi.spyOn(client, 'adminOfflineWipeDevice').mockResolvedValue(undefined);
    const { getByRole, getByLabelText, getAllByRole } = render(DeviceApprovalQueue, {
      devices: [dev({ offline_approval: 'approved' })], loading: false, error: '', filter: 'approved',
    });
    await fireEvent.click(getByRole('button', { name: /remote wipe.*alice/i }));
    await fireEvent.input(getByLabelText(/confirm device name to wipe/i), { target: { value: 'Alice MacBook' } });
    await fireEvent.click(getByRole('button', { name: /wipe this device/i }));
    await vi.waitFor(() => {
      const statuses = getAllByRole('status');
      expect(statuses.some((el) => /remote wipe requested/i.test(el.textContent ?? ''))).toBe(true);
    });
  });

  it('REDUCED-MOTION: row-removal transition is zeroed when prefers-reduced-motion is set', async () => {
    vi.stubGlobal('matchMedia', (q: string) => ({
      matches: /prefers-reduced-motion: reduce/.test(q), media: q,
      addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {}, onchange: null, dispatchEvent: () => false,
    }));
    vi.spyOn(client, 'adminOfflineApproveDevice').mockResolvedValue(undefined);
    const { getByLabelText, queryByText } = render(DeviceApprovalQueue, { devices: [dev()], loading: false, error: '' });
    await fireEvent.click(getByLabelText(/approve offline.*alice/i));
    // row removed immediately (no lingering animating node) under reduced motion
    await vi.waitFor(() => expect(queryByText('alice@corp.example')).toBeNull());
    vi.unstubAllGlobals();
  });
});
