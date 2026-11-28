// Offline state machine — Svelte 5 $state singleton.
// Consumed by: sync.ts (dynamic import, runes-free), BiometricUnlock.svelte,
// OfflineStatus.svelte, SyncIssuesInspector.svelte, readpath.
//
// Class upgraded from a plain $state object (Task 14) to add the full gate
// (featureEnabled + capsAllowed + nativeAvailable), lock arc, aria-live channel,
// and auto-merge quiet confirmation (UI-UX-PRO-MAX 2026-06-23).
import { isOfflineAvailable } from './store';
import { listSyncIssues } from './reconcile';

export type LockState = 'unlocked' | 'locked' | 'unlocking' | 'failed' | 'cancelled';
export type SyncPhase = 'idle' | 'provisioning' | 'syncing' | 'stale' | 'error';

// ponytail: live-region keys are a union so callers get a typo-check at the
// call site; the UI resolves via t(key, liveParams). Ceiling: extract to
// i18n/keys.ts if the set grows past ~10.
type LiveKey =
	| 'offline.live.synced'
	| 'offline.live.sync_failed'
	| 'offline.live.unlocked'
	| 'offline.live.unlock_failed'
	| 'offline.live.relocked'
	| 'offline.live.blocked'
	| 'offline.live.automerged'
	| 'offline.live.automerged_plural';

class OfflineState {
	// --- Gate ---
	featureEnabled = $state(false);
	capsAllowed = $state(false); // caps.offline.allowed — absent (false) until #2a
	workOffline = $state(false);
	watermarkEnabled = $state(false); // caps.offline.watermark — MAM tiled overlay in native shell
	syncIssueCount = $state(0);

	// nativeAvailable: computed once at construction (module is fresh-imported per
	// test via vi.resetModules(); no need to re-check window mid-session).
	// ponytail: plain $state, not a reactive $derived of window — the bridge is
	// injected once before the module loads, stable for the page lifetime.
	readonly nativeAvailable: boolean = isOfflineAvailable();

	// --- Lock arc (drives BiometricUnlock.svelte) ---
	// Declared before the $derived fields that reference lockState (TS init order).
	// ponytail: single source of truth; callers use lockState === 'unlocked' directly.
	lockState = $state<LockState>('unlocked');
	enrolled = $state(false); // biometric/passphrase set up — first-time vs return

	controlsActive = $derived(this.featureEnabled && this.capsAllowed && this.nativeAvailable);
	effectiveOffline = $derived(
		this.workOffline || (typeof navigator !== 'undefined' && !navigator.onLine)
	);
	// BiometricUnlock blocks the inbox iff offline-active and not yet unlocked.
	needsUnlock = $derived(
		this.controlsActive && this.effectiveOffline && this.lockState !== 'unlocked'
	);

	// --- Sync phase machine (drives OfflineStatus.svelte; never success-only) ---
	syncPhase = $state<SyncPhase>('idle');
	syncProgress = $state<{ done: number; total: number }>({ done: 0, total: 0 });
	syncError = $state<string | null>(null);
	lastSyncAt = $state<number | null>(null);

	// --- Aria-live channel ---
	// The UI mounts one <span aria-live> bound to liveMessage; announce() updates it
	// so a screen reader hears every async outcome, not just a visual icon swap.
	// ponytail: store the KEY; UI resolves via t(key, liveParams) — stays i18n-correct.
	liveMessage = $state<string>('');
	liveParams = $state<Record<string, number> | undefined>(undefined);

	// --- Auto-merge quiet confirmation (UI-UX-PRO-MAX 2026-06-23) ---
	// F1 column-level LWW auto-resolves flag/keyword/mailbox conflicts on reconnect.
	// sync.ts calls notifyAutoMerged(n) with the count of deltas that auto-merged a
	// dirty column; surfaces ONE aggregate dismissible toast + a polite live
	// announcement — NOT per-item. Never fires on 0.
	autoMergedCount = $state(0);

	// --- Methods ---

	setWorkOffline(v: boolean) { this.workOffline = v; }

	setLockState(s: LockState) { this.lockState = s; }

	setSyncPhase(p: SyncPhase) {
		const wasSyncing = this.syncPhase === 'syncing' || this.syncPhase === 'provisioning';
		this.syncPhase = p;
		if (p !== 'error') this.syncError = null;
		if (p === 'idle') {
			this.lastSyncAt = Date.now();
			if (wasSyncing) this.announce('offline.live.synced'); // AT: "Mail is up to date."
		}
	}

	setSyncProgress(done: number, total: number) {
		this.syncProgress = { done, total };
	}

	setSyncError(e: string) {
		this.syncError = e;
		this.syncPhase = 'error';
		this.announce('offline.live.sync_failed');
	}

	announce(key: LiveKey, params?: Record<string, number>): void {
		this.liveMessage = key;
		this.liveParams = params;
	}

	notifyAutoMerged(n: number): void {
		if (n <= 0) return;
		this.autoMergedCount = n;
		this.announce(
			n === 1 ? 'offline.live.automerged' : 'offline.live.automerged_plural',
			{ n }
		);
	}

	async refreshIssueCount(): Promise<void> {
		const prev = this.syncIssueCount;
		this.syncIssueCount = (await listSyncIssues()).length;
		if (this.syncIssueCount > prev) this.announce('offline.live.blocked');
	}
}

export const offline = new OfflineState();
