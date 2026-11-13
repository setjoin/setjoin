// Offline storage API client. Size estimate is its own (platform-independent)
// endpoint — the server-side "needed on disk" preview; the window preference
// lives in users.view_prefs (key `offlineWindow`), reached via the existing
// canonical /api/settings/view GET/PUT pair (read-modify-write to preserve siblings). The
// on-DEVICE store/free sizes come from the native offline-core bridge ('mail'
// store), not here — see lib/offline/storeFacade.ts (native-offline pivot).
import { httpRequest, typedFetch } from '$lib/http';
import type { SizeEstimate } from '$lib/offline/sizeFit';
import { DEFAULT_OFFLINE_WINDOW, isOfflineWindow, type OfflineWindow } from '$lib/offline/window';

export async function getOfflineSizeEstimate(): Promise<SizeEstimate> {
	return typedFetch<SizeEstimate>('/api/offline/size-estimate', {
		loginRedirect: null,
		onError: () => 'Failed to load offline size estimate'
	});
}

// getMailboxQuota returns this user's own mailbox storage total (used/quota,
// summed across their mailboxes) for the Settings Cloud storage bar. Server
// scopes by user_id from auth (GET /user/quota).
export async function getMailboxQuota(): Promise<{ usedBytes: number; quotaBytes: number }> {
	return typedFetch<{ usedBytes: number; quotaBytes: number }>('/api/user/quota', {
		loginRedirect: null,
		onError: () => 'Failed to load mailbox quota'
	});
}

export async function getOfflineWindow(): Promise<OfflineWindow> {
	const prefs = await typedFetch<Record<string, unknown>>('/api/settings/view', {
		loginRedirect: null,
		onError: () => 'Failed to load view preferences'
	});
	const w = prefs.offlineWindow;
	return isOfflineWindow(w) ? w : DEFAULT_OFFLINE_WINDOW;
}

export async function saveOfflineWindow(w: OfflineWindow): Promise<void> {
	const prefs = await typedFetch<Record<string, unknown>>('/api/settings/view', {
		loginRedirect: null,
		onError: () => 'Failed to load view preferences'
	});
	await httpRequest('/api/settings/view', {
		method: 'PUT',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ ...prefs, offlineWindow: w }),
		loginRedirect: null,
		onError: () => 'Failed to save offline window'
	});
}
