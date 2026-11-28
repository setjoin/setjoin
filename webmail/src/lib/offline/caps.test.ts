import { describe, it, expect } from 'vitest';
import { offlineAllowed, offlineReason, cappedWindow, type OfflineCaps } from './caps';

const approved: OfflineCaps = {
  allowed: true, approvalState: 'approved', maxOfflineDays: 7,
  wipeOnLogout: 'admin_default', requireApproval: true,
};

describe('offline caps gate', () => {
  it('absent block denies (deny-by-default), even on native', () => {
    expect(offlineAllowed(undefined, true)).toBe(false);
    expect(offlineReason(undefined, true)).toBe('settings.offline.reason.no_caps');
  });
  it('allowed block activates ON NATIVE (bridge present)', () => {
    expect(offlineAllowed(approved, true)).toBe(true);
    expect(offlineReason(approved, true)).toBe(''); // allowed = no reason
  });
  it('PLAIN BROWSER denies even when server allows (no native bridge)', () => {
    // Native-offline pivot: offline is native-only; absent window.setjoinNative
    // ⇒ no SQLCipher backend ⇒ offline disabled regardless of server caps.
    expect(offlineAllowed(approved, false)).toBe(false);
    expect(offlineReason(approved, false)).toBe('settings.offline.reason.no_bridge');
  });
  it('pending device explains why off', () => {
    const pending = { ...approved, allowed: false, approvalState: 'pending' as const };
    expect(offlineAllowed(pending, true)).toBe(false);
    expect(offlineReason(pending, true)).toBe('settings.offline.reason.pending');
  });
  it('caps the user window to maxOfflineDays', () => {
    expect(cappedWindow(30, approved)).toBe(7);
    expect(cappedWindow(3, approved)).toBe(3);
  });
});
