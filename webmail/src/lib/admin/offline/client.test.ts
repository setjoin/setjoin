import { describe, it, expect } from 'vitest';
import * as client from '$lib/admin/client';
import { CONSOLES } from '$lib/admin/consoles';

describe('offline admin client', () => {
  it('exposes the offline policy + device functions', () => {
    expect(typeof client.adminOfflinePolicyList).toBe('function');
    expect(typeof client.adminOfflineListPendingDevices).toBe('function');
    expect(typeof client.adminOfflineRevokeDevice).toBe('function');
    expect(typeof client.adminOfflineWipeDevice).toBe('function');
    expect(typeof client.adminOfflineSetEnabled).toBe('function');
  });
  it('registers the /admin/offline nav item in the system console', () => {
    const sys = CONSOLES.find((c) => c.id === 'system');
    expect(sys?.items.some((i) => i.path === '/admin/offline')).toBe(true);
  });
});
