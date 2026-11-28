// Offline storage API client. Size estimate is its own (platform-independent)
// endpoint — the server-side "needed on disk" preview; the window preference
// lives in users.view_prefs (key `offlineWindow`), reached via the existing
// canonical /api/settings/view GET/PUT pair (read-modify-write to preserve siblings). The
// on-DEVICE store/free sizes come from the native offline-core bridge ('mail'
// store), not here — see lib/offline/storeFacade.ts (native-offline pivot).
import { createEdgeClient } from '$lib/edge/client';
import type { SizeEstimate } from '$lib/offline/sizeFit';
import { DEFAULT_OFFLINE_WINDOW, isOfflineWindow, type OfflineWindow } from '$lib/offline/window';

const sizeEstimateClient = createEdgeClient({
	loginRedirect: null,
	onError: () => 'Failed to load offline size estimate'
});
const quotaClient = createEdgeClient({
	loginRedirect: null,
	onError: () => 'Failed to load mailbox quota'
});
const viewLoadClient = createEdgeClient({
	loginRedirect: null,
	onError: () => 'Failed to load view preferences'
});
const viewSaveClient = createEdgeClient({
	loginRedirect: null,
	onError: () => 'Failed to save offline window'
});

export async function getOfflineSizeEstimate(): Promise<SizeEstimate> {
	const { data, error, response } = await sizeEstimateClient.GET('/api/offline/size-estimate');
	if (!response.ok || error !== undefined || data === undefined) {
		throw new Error('Failed to load offline size estimate');
	}
	return data;
}

// getMailboxQuota returns this user's own mailbox storage total (used/quota,
// summed across their mailboxes) for the Settings Cloud storage bar. Server
// scopes by user_id from auth (GET /user/quota).
export async function getMailboxQuota(): Promise<{ usedBytes: number; quotaBytes: number }> {
	const { data, error, response } = await quotaClient.GET('/api/user/quota');
	if (!response.ok || error !== undefined || data === undefined) {
		throw new Error('Failed to load mailbox quota');
	}
	return data;
}

export async function getOfflineWindow(): Promise<OfflineWindow> {
	const { data, error, response } = await viewLoadClient.GET('/api/settings/view');
	if (!response.ok || error !== undefined || data === undefined) {
		throw new Error('Failed to load view preferences');
	}
	const w = data.offlineWindow;
	return isOfflineWindow(w) ? w : DEFAULT_OFFLINE_WINDOW;
}

export async function saveOfflineWindow(w: OfflineWindow): Promise<void> {
	const {
		data: prefs,
		error: loadError,
		response: loadResponse
	} = await viewLoadClient.GET('/api/settings/view');
	if (!loadResponse.ok || loadError !== undefined || prefs === undefined) {
		throw new Error('Failed to load view preferences');
	}
	const { error: saveError, response: saveResponse } = await viewSaveClient.PUT(
		'/api/settings/view',
		{
			body: { ...prefs, offlineWindow: w },
			parseAs: 'text'
		}
	);
	if (!saveResponse.ok || saveError !== undefined) {
		throw new Error('Failed to save offline window');
	}
}
