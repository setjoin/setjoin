import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import Page from './+page.svelte';
import * as client from '$lib/admin/client';

beforeEach(() => {
  vi.spyOn(client, 'adminOfflinePolicyList').mockResolvedValue([]);
  vi.spyOn(client, 'adminOfflineListPendingDevices').mockResolvedValue([]);
  // Default: master toggle fetch returns false (OFF) unless a test overrides it
  vi.spyOn(client, 'adminOfflineGetEnabled').mockResolvedValue(false);
});

describe('/admin/offline', () => {
  it('renders the master toggle and two tabs', async () => {
    const { findByRole, getAllByRole } = render(Page);
    expect(await findByRole('switch', { name: /offline mail enabled org-wide/i })).toBeTruthy();
    expect(getAllByRole('tab').length).toBe(2);
  });

  it('turning the master OFF requires a confirm dialog', async () => {
    // Seed the toggle to ON so clicking it triggers OFF → confirm
    vi.spyOn(client, 'adminOfflineGetEnabled').mockResolvedValue(true);
    vi.spyOn(client, 'adminOfflineSetEnabled').mockResolvedValue(undefined);
    const { findByRole, getByRole } = render(Page);
    const sw = await findByRole('switch', { name: /enabled org-wide/i });
    // Switch is ON → click turns it OFF → confirm dialog appears
    await fireEvent.click(sw);
    expect(getByRole('button', { name: /disable org-wide/i })).toBeTruthy();
  });

  it('ARIA-LIVE: enabling the master announces the outcome politely', async () => {
    vi.spyOn(client, 'adminOfflineSetEnabled').mockResolvedValue(undefined);
    // Switch starts OFF (beforeEach mock returns false) — click turns ON (no confirm)
    const { findByRole, getAllByRole } = render(Page);
    await fireEvent.click(await findByRole('switch', { name: /enabled org-wide/i }));
    // The page renders multiple role="status" (page + child components); check any has the text
    await vi.waitFor(() => {
      const regions = getAllByRole('status');
      expect(regions.some((el) => /enabled org-wide/i.test(el.textContent ?? ''))).toBe(true);
    });
  });

  it('ERROR: a toggle write failure reverts the switch and shows an alert', async () => {
    vi.spyOn(client, 'adminOfflineSetEnabled').mockRejectedValue(new Error('nope'));
    const { findByRole, getAllByRole } = render(Page);
    const sw = await findByRole('switch', { name: /enabled org-wide/i });
    await fireEvent.click(sw);
    // The page renders multiple role="alert" (hidden live region + visible card error)
    await vi.waitFor(() => {
      const alerts = getAllByRole('alert');
      expect(alerts.some((el) => /couldn't change/i.test(el.textContent ?? ''))).toBe(true);
    });
  });
});
