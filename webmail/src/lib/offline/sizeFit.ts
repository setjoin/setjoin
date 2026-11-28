import { OFFLINE_WINDOWS, type OfflineWindow } from './window';

export interface SizeBucket {
	window: OfflineWindow;
	messageCount: number;
	bodyBytes: number;
}

export interface SizeEstimate {
	buckets: SizeBucket[];
}

export function bytesForWindow(est: SizeEstimate, w: OfflineWindow): number {
	return est.buckets.find((b) => b.window === w)?.bodyBytes ?? 0;
}

export function fitWindowToSpace(est: SizeEstimate, freeBytes: number): OfflineWindow {
	// Walk largest → smallest; pick the first that is present in the estimate AND fits.
	for (let i = OFFLINE_WINDOWS.length - 1; i >= 0; i--) {
		const w = OFFLINE_WINDOWS[i];
		if (est.buckets.some((b) => b.window === w) && bytesForWindow(est, w) <= freeBytes) return w;
	}
	// ponytail: fallback to '7d' — smallest window; callers should always have it in est.
	return '7d';
}

// formatBytes lives in $lib/utils/display (more call sites); re-exported here so
// existing importers of this module keep working. ponytail: dedup, one impl.
export { formatBytes } from '$lib/utils/display';
