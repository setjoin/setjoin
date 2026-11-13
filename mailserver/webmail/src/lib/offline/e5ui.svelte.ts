// E5 UI runtime state (Svelte 5 $state singleton) — the consumer-parity seam's
// only surface-facing reader. Every axis here is the Phase 2 orthogonal-axes
// contract: connectivity / freshness / scheduler / blocking / manual mode are
// independent; transfer progress is separate.
//
// DEFAULT IS OFF: `featureEnabled` mirrors `feature.connectivity_aware_sync`
// and `mode` mirrors the winning policy rollout mode through
// `configureE5FromPolicy`. The shipped default (`createOffPolicySource()`)
// reports flagEnabled:false / mode:'off', so `active` is false and every
// wired surface renders exactly what it rendered before E5. Nothing here can
// enable production behavior — a surface gate is display-only.
//
// Scheduler activity NEVER enters this state except through
// `schedulerStateFromJobResult` applied to a `Coordinator.readJobResult`
// outcome: an unknown read maps to idle, never to an invented completion.
import {
	projectStatus,
	schedulerStateFromJobResult,
	type BlockingReason,
	type Freshness,
	type StatusProjection,
} from './statusProjection';
import type { BlockingIssue, BridgeNetworkCost, PauseReason, RolloutMode, SchedulerState } from './work-contract';
import type { ReadJobOutcome } from './coordinator';
import {
	createAdminPreviewController,
	type E5AdminPreviewController,
} from './e5AdminPreview';
import {
	createE5SettingsController,
	type E5SettingsController,
} from './e5Settings';
import {
	createSaveAllGroup,
	type E5SaveAllChildPatch,
	type E5SaveAllGroupView,
	type E5SaveAllTick,
} from './e5SaveAll';

type E5Announcement = { key: string; params?: Record<string, string>; seq: number };

export interface E5TransferRowObservation {
	state: import('./e5.uiProjection').E5TransferRowState;
	pauseReason?: PauseReason;
	committedBytes?: number;
	totalBytes?: number;
}

class E5UiState {
	// --- Gate (OFF until a policy source says otherwise; shipped source is OFF) ---
	featureEnabled = $state(false);
	mode = $state<RolloutMode>('off');
	/** Durable-transfer capability truth: false until a shell proves it. */
	durableTransferAvailable = $state(false);

	/** Surfaces render E5 additions only while the program is observable
	 * (observe|execute). 'off' — the shipped default — renders nothing new. */
	active = $derived(this.featureEnabled && this.mode !== 'off');

	// --- Orthogonal status axes (never collapsed into one phase) ---
	freshness = $state<Freshness>('unknown');
	cached = $state(false);
	scheduler = $state<SchedulerState>({ kind: 'idle' });
	blockingIssue = $state<BlockingIssue>('none');
	blockingReason = $state<BlockingReason | undefined>(undefined);
	networkCost = $state<BridgeNetworkCost>('unmetered');
	lastCurrentAt = $state<number | null>(null);
	lastUsefulProgressAt = $state<number | null>(null);

	// --- One polite announcer channel; the visual container is NOT live ---
	announcement = $state<E5Announcement | null>(null);
	#announcementSeq = 0;

	// --- Transfer action dispatch (native wiring injects the handler; null ---
	// --- default keeps every action inert until the shell proves the capability) ---
	transferActionHandler = $state<((key: string, action: 'resume' | 'cancel' | 'retry') => void) | null>(null);

	transferAction(key: string, action: 'resume' | 'cancel' | 'retry'): void {
		this.transferActionHandler?.(key, action);
	}

	// --- Per-transfer durable rows (opaque keys; never content, never names) ---
	#transfers = $state<Record<string, E5TransferRowObservation>>({});

	// --- Settings (requested-vs-effective) and admin preview controllers ---
	readonly settings: E5SettingsController = createE5SettingsController();
	readonly adminPreview: E5AdminPreviewController = createAdminPreviewController();

	/**
	 * The authoritative preference saver. NULL (the shipped default) keeps the
	 * save control disabled with an honest reason — no invented endpoint, no
	 * fake success. Native/server wiring injects it when the preference path is
	 * actually available.
	 */
	settingsSaver = $state<import('./e5Settings').E5SettingsSaver | null>(null);
	/** Reactive revision: the settings controller is a pure closure, so every
	 * mutating call bumps this to refresh derived views. */
	settingsRevision = $state(0);

	/** Bind the REAL lifecycle identity: the auth store's account identity and
	 * the native secure store's device id (null = this client has none — a
	 * plain browser; never a placeholder constant). Any change invalidates a
	 * pending settings response. */
	bindSettingsAccount(accountId: string, deviceId: string | null): void {
		const changed = this.settings.bindAccount(accountId, deviceId);
		if (changed) this.settingsRevision += 1;
	}

	editSettings(patch: Partial<import('./e5Settings').E5RequestedPrefs>): void {
		this.settings.edit(patch);
		this.settingsRevision += 1;
	}

	/** Race-safe save: duplicate submissions are refused; only the authoritative
	 * response updates effective state; failure preserves drafts.
	 *
	 * Single-announcer contract: a SUCCESSFUL save is announced only by the
	 * owning surface's one polite live region (the settings page's offlineLive).
	 * This channel used to re-announce the save globally, and OfflineStatus
	 * relays the retained message into its own region on a later mount — a
	 * second announcer for one outcome (Astra r3 P2), so the success path is
	 * silent here. Failure keeps the channel: the settings page's inline
	 * role=alert remedy is page-local, so this carries the outcome to any
	 * surface relaying E5 announcements. */
	async submitSettings(): Promise<boolean> {
		const saver = this.settingsSaver;
		if (saver === null) return false;
		const outcome = await this.settings.submit(saver);
		this.settingsRevision += 1;
		if (!outcome.ok && outcome.reason === 'save-failed') this.announce('offline.e5.settings.announce_failed');
		return outcome.ok;
	}

	configureE5FromPolicy(policy: { flagEnabled: boolean; rolloutMode: RolloutMode }): void {
		this.featureEnabled = policy.flagEnabled;
		this.mode = policy.rolloutMode;
	}

	setDurableTransferAvailable(available: boolean): void {
		this.durableTransferAvailable = available;
	}

	announce(key: string, params?: Record<string, string>): void {
		this.#announcementSeq += 1;
		this.announcement = { key, params, seq: this.#announcementSeq };
	}

	/**
	 * The ONLY path scheduler activity takes into the UI: one coordinator job
	 * outcome through the shared E4-I mapping. Unknown (null / no committed
	 * result) becomes idle — a surface can never display an invented completion.
	 */
	applyJobOutcome(outcome: ReadJobOutcome): SchedulerState {
		const next = schedulerStateFromJobResult(outcome.kind === 'committed' ? outcome.result : null);
		this.scheduler = next;
		return next;
	}

	/** Read one job result through the coordinator seam and project it. */
	async refreshFromCoordinator(
		readJobResult: (jobId: string) => Promise<ReadJobOutcome>,
		jobId: string,
	): Promise<SchedulerState> {
		const outcome = await readJobResult(jobId);
		return this.applyJobOutcome(outcome);
	}

	setStatusAxes(input: {
		freshness: Freshness;
		cached: boolean;
		blockingIssue: BlockingIssue;
		blockingReason?: BlockingReason;
		networkCost: BridgeNetworkCost;
		scheduler?: SchedulerState;
	}): void {
		this.freshness = input.freshness;
		this.cached = input.cached;
		this.blockingIssue = input.blockingIssue;
		this.blockingReason = input.blockingReason;
		this.networkCost = input.networkCost;
		if (input.scheduler) this.scheduler = input.scheduler;
	}

	/** The full E4-I status projection for the current axes. Display data is
	 * derived convenience; the axes remain the source of truth. */
	projection(manualMode: 'online' | 'workOffline', rolloutMode: RolloutMode = this.mode): StatusProjection {
		return projectStatus({
			connectivity: { networkCost: this.networkCost },
			freshness: this.freshness,
			cached: this.cached,
			scheduler: this.scheduler,
			blockingIssue: this.blockingIssue,
			...(this.blockingReason === undefined ? {} : { blockingReason: this.blockingReason }),
			manualMode,
			automaticWork: {
				rolloutMode,
				executionMode: 'foregroundReconnectOnly',
				backgroundExecution: false,
			},
		});
	}

	// --- Durable transfer rows ---

	setTransferRow(key: string, row: E5TransferRowObservation): void {
		this.#transfers = { ...this.#transfers, [key]: { ...row } };
	}

	clearTransferRow(key: string): void {
		const next = { ...this.#transfers };
		delete next[key];
		this.#transfers = next;
	}

	transferRow(key: string): E5TransferRowObservation | null {
		return this.#transfers[key] ?? null;
	}

	get transferRowCount(): number {
		return Object.keys(this.#transfers).length;
	}

	// --- Save-all groups (per press; one group announcement replaces bursts) ---
	#groups = new Map<string, ReturnType<typeof createSaveAllGroup>>();

	createSaveAllGroup(messageId: string, childIds: readonly string[]): E5SaveAllGroupView {
		if (this.#groups.has(messageId)) throw new Error(`save-all group "${messageId}" already exists`);
		const group = createSaveAllGroup(messageId, childIds);
		this.#groups.set(messageId, group);
		return group.view;
	}

	applySaveAllChild(messageId: string, childId: string, patch: E5SaveAllChildPatch): E5SaveAllTick | null {
		const group = this.#groups.get(messageId);
		if (!group) return null;
		return group.applyChild(childId, patch);
	}

	saveAllGroup(messageId: string): E5SaveAllGroupView | null {
		const group = this.#groups.get(messageId);
		return group ? group.view : null;
	}

	retrySaveAll(messageId: string): string[] {
		return this.#groups.get(messageId)?.retryIds() ?? [];
	}

	cancelSaveAll(messageId: string): { toCancel: string[]; preserved: string[] } | null {
		return this.#groups.get(messageId)?.cancelPlan() ?? null;
	}

	/** ONE group announcement replaces the per-child burst (R4). Callers apply
	 * child patches in a batch, then announce the settled summary once. */
	announceSaveAllGroup(messageId: string): void {
		const view = this.saveAllGroup(messageId);
		if (view === null) return;
		this.announce('offline.e5.saveall.announce', {
			completed: String(view.summary.completed),
			total: String(view.summary.total),
			failed: String(view.summary.failed),
			cancelled: String(view.summary.cancelled),
			expired: String(view.summary.expired),
		});
	}

	disposeSaveAllGroup(messageId: string): void {
		this.#groups.delete(messageId);
	}

	/** Test isolation ONLY: the singleton persists across suites. */
	__resetForTests(): void {
		this.featureEnabled = false;
		this.mode = 'off';
		this.durableTransferAvailable = false;
		this.freshness = 'unknown';
		this.cached = false;
		this.scheduler = { kind: 'idle' };
		this.blockingIssue = 'none';
		this.blockingReason = undefined;
		this.networkCost = 'unmetered';
		this.lastCurrentAt = null;
		this.lastUsefulProgressAt = null;
		this.announcement = null;
		this.transferActionHandler = null;
		this.settingsSaver = null;
		this.settingsRevision = 0;
		this.#transfers = {};
		this.#groups.clear();
	}
}

export const e5ui = new E5UiState();

/**
 * Production wiring: read the coordinator policy source once and mirror its
 * gate. With the shipped `createOffPolicySource()` this leaves every surface
 * inert — the OFF default is enforced by construction, not by discipline.
 */
export async function configureE5FromPolicySource(
	policySource: { readPolicy(): Promise<{ flagEnabled: boolean; rolloutMode: RolloutMode }> },
): Promise<void> {
	const policy = await policySource.readPolicy();
	e5ui.configureE5FromPolicy(policy);
}
