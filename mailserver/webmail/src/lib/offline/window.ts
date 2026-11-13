// Single-sourced offline-window enum (spec #1a §7). Bounds the NATIVE SQLCipher
// offline cache (native-offline pivot): cache + keep-fresh messages with
// receivedAt >= now()-N. 'all' = unbounded. The plain browser has no cache, so
// this enum only affects native shells.
export type OfflineWindow = '7d' | '30d' | '90d' | '180d' | '365d' | 'all';
export const OFFLINE_WINDOWS: OfflineWindow[] = ['7d', '30d', '90d', '180d', '365d', 'all'];
export const DEFAULT_OFFLINE_WINDOW: OfflineWindow = '30d';

const DAYS: Record<Exclude<OfflineWindow, 'all'>, number> = {
	'7d': 7,
	'30d': 30,
	'90d': 90,
	'180d': 180,
	'365d': 365
};

export function windowDays(w: OfflineWindow): number | null {
	return w === 'all' ? null : DAYS[w];
}

export function windowLabelKey(w: OfflineWindow): string {
	return `settings.storage.window.${w}`;
}

export function isOfflineWindow(v: unknown): v is OfflineWindow {
	return typeof v === 'string' && (OFFLINE_WINDOWS as string[]).includes(v);
}

/** null = "all" (no cutoff). now defaults to Date.now(). */
export function cutoffMillis(w: OfflineWindow, now = Date.now()): number | null {
	const d = windowDays(w);
	return d === null ? null : now - d * 86_400_000;
}

// ponytail: effectiveWindowDays removed — cappedWindow (caps.ts) is the single
// source; callers use that directly. See Fix 3 in offline #2b review.
