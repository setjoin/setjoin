// mirrorBridge.svelte.ts — renderer-facing runes store over
// window.setjoinNative.driveMirror (Drive P2's Electron FolderMirror). Absent
// on a plain browser / mobile shell — `available` degrades honestly rather
// than throwing (mirrors the offline/vault VAULT_VERSION lesson: a sub-shape
// version mismatch degrades too, never mis-calls a changed API).
//
// Also owns the C3/C14/C15 auth handoff: only the renderer holds the SPA's
// cookie session, so only it can mint the short-lived drive-scoped bearer
// token main authenticates with — POST /api/drive/native-token, then hand it
// to main via driveMirror.refreshToken. Main slides the token forward itself
// after that; this store only needs to re-mint when a space reports
// 'auth-expired' (session revoked / token fully lapsed with the window
// closed) or once at startup.
import { getNative, hasCapability } from '$lib/native';
import { typedFetch } from '$lib/http';
import { DRIVE_MIRROR_VERSION, type DriveMirrorStatus } from '$lib/native/types';

const EMPTY_STATUS: DriveMirrorStatus = { running: false, paused: false, perSpace: [], issues: [] };

interface NativeTokenResponse {
	token: string;
	expiresAt: string;
}

class MirrorBridgeState {
	// Computed once — the bridge is injected before this module loads and is
	// stable for the page lifetime (same pattern as offline/state.svelte.ts's
	// nativeAvailable).
	readonly available: boolean =
		hasCapability('driveMirror') && getNative().driveMirror?.version === DRIVE_MIRROR_VERSION;

	status = $state<DriveMirrorStatus>(EMPTY_STATUS);

	private pollHandle: ReturnType<typeof setInterval> | null = null;
	private mintedOnce = false;

	private get bridge() {
		return getNative().driveMirror;
	}

	async refresh(): Promise<void> {
		if (!this.available || !this.bridge) return;
		try {
			this.status = await this.bridge.status();
			if (this.status.perSpace.some((s) => s.state === 'auth-expired')) {
				await this.mintAndSendToken();
			}
		} catch {
			/* transient -- next poll retries */
		}
	}

	/** Mints a fresh drive-scoped bearer token via the SPA's own cookie session
	 *  and hands it to main. Called on first poll and whenever a space reports
	 *  'auth-expired'. */
	async mintAndSendToken(): Promise<void> {
		if (!this.available || !this.bridge) return;
		try {
			const res = await typedFetch<NativeTokenResponse>('/api/drive/native-token', { method: 'POST' });
			await this.bridge.refreshToken(res.token, res.expiresAt);
		} catch {
			/* not logged in yet / transient -- next poll retries */
		}
	}

	startPolling(intervalMs = 5000): void {
		if (!this.available || this.pollHandle) return;
		if (!this.mintedOnce) {
			this.mintedOnce = true;
			void this.mintAndSendToken().then(() => this.refresh());
		} else {
			void this.refresh();
		}
		this.pollHandle = setInterval(() => void this.refresh(), intervalMs);
	}

	stopPolling(): void {
		if (this.pollHandle) clearInterval(this.pollHandle);
		this.pollHandle = null;
	}

	async configure(spaces: Array<{ spaceId: number; excludes: string[]; acceptUnmanagedAclRisk?: boolean }>): Promise<void> {
		if (!this.available || !this.bridge) return;
		await this.bridge.configure({ serverOrigin: window.location.origin, spaces });
		await this.mintAndSendToken();
		await this.refresh();
	}

	async setPaused(paused: boolean): Promise<void> {
		if (!this.bridge) return;
		await this.bridge.setPaused(paused);
		await this.refresh();
	}

	async resync(spaceId?: number): Promise<void> {
		if (!this.bridge) return;
		await this.bridge.resync(spaceId);
		await this.refresh();
	}

	async openRoot(spaceId: number): Promise<void> {
		await this.bridge?.openRoot(spaceId);
	}
}

export const mirrorBridge = new MirrorBridgeState();
