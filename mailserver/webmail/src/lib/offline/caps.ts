// Offline capability gate (#2a). NATIVE-OFFLINE PIVOT: offline is native-only.
// The webmail offline layer activates ONLY when (a) the server-resolved offline
// policy allows it AND (b) the native window.setjoinNative SQLCipher storage
// bridge is present (a plain browser has no backend). Otherwise it explains why.
// The window is hard-capped to the server's maxOfflineDays (the client cannot
// widen it — the server is the authority; F5). `bridgePresent` is injected by
// #1a's storage layer (the real detector probes window.setjoinNative); keeping
// it a parameter keeps these functions pure + unit-testable.
export type OfflineApprovalState = 'pending' | 'approved' | 'denied' | 'revoked';

export interface OfflineCaps {
  allowed: boolean;
  approvalState: OfflineApprovalState;
  maxOfflineDays: number;
  wipeOnLogout: 'always' | 'admin_default' | 'never';
  requireApproval: boolean;
  /** MAM-tier watermark policy: show the identity/timestamp tiled overlay in native shell. */
  watermark?: boolean;
}

// offlineAllowed: true only when the server allows it AND a native storage
// bridge is present. Absent caps block ⇒ false; no native bridge ⇒ false.
export function offlineAllowed(
  caps: OfflineCaps | undefined,
  bridgePresent: boolean,
): boolean {
  return caps?.allowed === true && bridgePresent === true;
}

// offlineReason: returns the i18n key explaining why offline is off (UX honesty, §9).
// Empty string = no reason needed (allowed & approved). The caller passes the key to t().
// The native-bridge precondition is checked FIRST: a plain browser is told
// offline needs a native client, not that its device is unapproved.
export function offlineReason(
  caps: OfflineCaps | undefined,
  bridgePresent: boolean,
): string {
  if (!bridgePresent) return 'settings.offline.reason.no_bridge';
  if (!caps) return 'settings.offline.reason.no_caps';
  if (caps.allowed) return '';
  switch (caps.approvalState) {
    case 'pending':  return 'settings.offline.reason.pending';
    case 'denied':   return 'settings.offline.reason.denied';
    case 'revoked':  return 'settings.offline.reason.revoked';
    default:         return 'settings.offline.reason.default';
  }
}

// cappedWindow: the effective sync window = min(user choice, server cap).
// A zero cap means no cache at all.
export function cappedWindow(userWindowDays: number, caps: OfflineCaps | undefined): number {
  const cap = caps?.maxOfflineDays ?? 0;
  return Math.max(0, Math.min(userWindowDays, cap));
}
