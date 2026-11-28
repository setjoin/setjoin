// Native-offline pivot (2026-06-23): the offline mail cache is the app-agnostic
// offline-core crate's encrypted 'mail' store (a native SQLCipher DB file, one per
// app), exposed over the GENERIC window.setjoinNative.db bridge (open/exec/query/
// wipe, all appKey-scoped; built in #1a). offline-core obtains the per-store key
// from guard-core (security-only). This facade is #1b's single seam onto that
// store: it tells the Storage page whether offline is available (native shell +
// `mailDb` capability) and reports on-disk store/free bytes FROM THE NATIVE BRIDGE
// for the 'mail' appKey — never navigator.storage.estimate() (that browser quota
// API measured the now-deleted IndexedDB cache and is gone). On a plain browser
// every call is a safe stub (false / 0 / no-op) so the page renders only the Cloud
// card.
//
// #1a owns the real lib/offline/store.ts storage interface (the offline-core
// 'mail' store); if/when it merges, these helpers delegate to it. Until then the
// generic `db` bridge box is read directly. Keep this the ONLY #1b → #1a coupling
// surface.
import { getNative } from '$lib/native';
// Single source of truth: store.ts checks window.setjoinNative?.db — no divergent impl here.
export { isOfflineAvailable } from './store';
import { isOfflineAvailable } from './store';

// The mail store's appKey namespace on the generic offline-core bridge (one
// encrypted DB file per app; apps cannot read each other's store).
const MAIL_APP_KEY = 'mail';

// The generic `db` bridge box #1a adds to window.setjoinNative (offline-core).
// Typed loosely here to avoid a hard dependency on #1a's exact type export; #1a's
// store.ts is the authoritative interface. Every method is appKey-scoped.
interface OfflineCoreDbBridge {
	sizeBytes?(appKey: string): Promise<number>;
	freeBytes?(): Promise<number>;
	wipe?(appKey: string): Promise<void>;
}

function db(): OfflineCoreDbBridge | null {
	if (!isOfflineAvailable()) return null;
	const bridge = getNative() as unknown as { db?: OfflineCoreDbBridge };
	return bridge.db ?? null;
}

/** Current on-disk size of the offline-core 'mail' store (0 when unavailable). */
export async function getCacheSizeBytes(): Promise<number> {
	const bridge = db();
	if (!bridge?.sizeBytes) return 0;
	try {
		return await bridge.sizeBytes(MAIL_APP_KEY);
	} catch {
		return 0;
	}
}

/** Free space on the device volume holding the store (0 when unavailable). */
export async function getFreeSpaceBytes(): Promise<number> {
	const bridge = db();
	if (!bridge?.freeBytes) return 0;
	try {
		return await bridge.freeBytes();
	} catch {
		return 0;
	}
}

/** Wipe the offline-core 'mail' store (db.wipe('mail') — drops the store + destroys its key); no-op when unavailable. */
export async function clearOfflineCache(): Promise<void> {
	const bridge = db();
	if (!bridge?.wipe) return;
	await bridge.wipe(MAIL_APP_KEY);
}

/** Trigger a manual sync via #1a's mail-sync engine; no-op when unavailable. */
export async function syncNow(): Promise<void> {
	if (!isOfflineAvailable()) return;
	// #1a's mail-sync engine (TS, JMAP over the offline-core 'mail' store) exposes a
	// manual-sync entrypoint; imported dynamically so #1b builds standalone. Until
	// #1a merges this is a safe no-op.
	try {
		const mod = (await import('./sync')) as { requestSync?: () => void };
		mod.requestSync?.();
	} catch {
		// #1a mail-sync engine not present yet — no-op.
	}
}
