// E5 UI display projection (Phase 2 Design, passes 1/3/5; R4 "E5 complete
// states"). Pure module: no DOM, no network, no time — surfaces translate the
// stable i18n KEYS and compose the data; nothing here decides authorization,
// scheduling, or policy, and nothing invents a completion the coordinator
// never committed.
//
// Consumer-parity seam: scheduler activity ALWAYS arrives through
// `schedulerStateFromJobResult` (statusProjection.ts) applied to a
// `Coordinator.readJobResult` outcome. An unknown read maps to idle — "no
// committed result" is never displayed as a completion or as currentness.
import {
	type PauseReason,
	type SchedulerState,
	type JobResult,
	PAUSE_REASONS,
} from './work-contract';
import {
	schedulerStateFromJobResult,
	type Freshness,
	type StatusProjection,
	type UserActionHint,
} from './statusProjection';

/** The one E4-I seam E5 surfaces consume (kept as a named call site so a
 * surface cannot re-implement the mapping). Identity, not redefinition. */
export function e5SchedulerFromJobResult(result: JobResult | null): SchedulerState {
	return schedulerStateFromJobResult(result);
}

// ── Honest freshness phrasing (R4 "E5 complete states") ─────────────────────

/** `neverSynced` means "Not synced on this device" — never an empty mailbox. */
export const E5_FRESHNESS_NEVER_SYNCED_KEY = 'offline.e5.status.never_synced';
/** `unknown` means "Sync status unavailable" — never an empty server mailbox
 * and never currentness. */
export const E5_FRESHNESS_UNKNOWN_KEY = 'offline.e5.status.unknown';

// ── Status text keys (stable reason categories; the UI owns wording) ────────

export type E5SecondaryText =
	| { kind: 'offline'; key: string }
	| { kind: 'metered'; key: string }
	| { kind: 'runningIndeterminate'; key: string }
	| { kind: 'runningProgress'; key: string; params: Record<string, string> }
	| { kind: 'paused'; key: string; pauseReason: PauseReason }
	| { kind: 'backoff'; key: string; pauseReason: PauseReason; retryAt: number };

export interface E5StatusText {
	primaryKey: string;
	primaryParams?: Record<string, string>;
	secondary?: E5SecondaryText;
	action?: { hint: UserActionHint['kind']; key: string };
	/** role=alert is reserved for user-action-required failures (Pass 5). */
	alert: boolean;
}

const ACTION_KEYS: Readonly<Record<UserActionHint['kind'], string>> = {
	retry: 'offline.e5.action.retry',
	goOnline: 'offline.e5.action.go_online',
	syncNow: 'offline.e5.action.sync_now',
	signIn: 'offline.e5.action.sign_in',
	freeStorage: 'offline.e5.action.free_storage',
	unlock: 'offline.e5.action.unlock',
	viewSettings: 'offline.e5.action.view_settings',
	resolve: 'offline.e5.action.resolve',
};

/**
 * Every PauseReason gets its own key — a pause reason is preserved VERBATIM
 * through the whole chain (committed job result → schedulerStateFromJobResult
 * → this key) and never collapsed into a generic message.
 */
export function pauseReasonKey(reason: PauseReason): string {
	return `offline.e5.pause.${reason}`;
}

/** Compile-time proof that the pause-key map covers every contract reason. */
export const E5_PAUSE_REASON_KEYS: readonly string[] = PAUSE_REASONS.map(pauseReasonKey);

/** Project an E4-I status projection onto stable display text keys. */
export function e5StatusText(projection: StatusProjection): E5StatusText {
	const text: E5StatusText = { primaryKey: '', alert: projection.display.primary === 'actionRequired' };
	switch (projection.display.primary) {
		case 'current':
			text.primaryKey = 'offline.e5.status.current';
			break;
		case 'notCurrent':
			text.primaryKey = 'offline.e5.status.not_current';
			break;
		case 'neverSynced':
			text.primaryKey = E5_FRESHNESS_NEVER_SYNCED_KEY;
			break;
		case 'unknown':
			text.primaryKey = E5_FRESHNESS_UNKNOWN_KEY;
			break;
		case 'actionRequired':
			text.primaryKey = 'offline.e5.status.action_required';
			break;
		case 'locked':
			text.primaryKey = 'offline.e5.status.locked';
			break;
	}

	const secondary = projection.display.secondary;
	if (secondary) {
		switch (secondary.kind) {
			case 'offline':
				text.secondary = { kind: 'offline', key: 'offline.e5.secondary.offline' };
				break;
			case 'metered':
				text.secondary = { kind: 'metered', key: 'offline.e5.secondary.metered' };
				break;
			case 'running':
				text.secondary = secondary.progress === undefined
					? { kind: 'runningIndeterminate', key: 'offline.e5.secondary.running_indeterminate' }
					: {
						kind: 'runningProgress',
						key: 'offline.e5.secondary.running_progress',
						params: {
							done: String(secondary.progress.done),
							total: String(secondary.progress.total ?? ''),
						},
					};
				break;
			case 'paused':
				// The exact reason travels to the key; no collapsing, no invention.
				text.secondary = { kind: 'paused', key: pauseReasonKey(secondary.reason), pauseReason: secondary.reason };
				break;
			case 'backoff':
				text.secondary = {
					kind: 'backoff',
					key: pauseReasonKey(secondary.reason),
					pauseReason: secondary.reason,
					retryAt: secondary.retryAt,
				};
				break;
		}
	}

	const action = projection.display.action;
	if (action) text.action = { hint: action.kind, key: ACTION_KEYS[action.kind] };
	return text;
}

/** Honest freshness label keys, independent of the full projection. */
export function freshnessLabelKey(freshness: Freshness): string | null {
	if (freshness === 'neverSynced') return E5_FRESHNESS_NEVER_SYNCED_KEY;
	if (freshness === 'unknown') return E5_FRESHNESS_UNKNOWN_KEY;
	return null;
}

// ── Per-transfer row display (Phase 2 Pass 3 controller shape) ──────────────

/** The durable transfer controller row states E5 displays (Pass 3), plus the
 * three R4 terminal mappings. These are UI states, not new E3 states. */
export const E5_TRANSFER_ROW_STATES = [
	'queued',
	'transferring',
	'waitingForNetwork',
	'resourcePaused',
	'verifying',
	'validatorRestart',
	'recoverableError',
	'complete',
	'cancelled',
	// R4 E5 complete states:
	'downloadExpired', // terminal transfer expiry → "Download expired" + newly authorized restart
	'contentUnavailable', // authorized confirmed classification → "Attachment unavailable" without retry
	'verificationFailed', // integrity failure → "Verification failed" without Open/Save
] as const;
export type E5TransferRowState = (typeof E5_TRANSFER_ROW_STATES)[number];

export interface E5TransferRowInput {
	state: E5TransferRowState;
	/** Resource pauses carry their exact scheduler pause reason (verbatim). */
	pauseReason?: PauseReason;
	committedBytes?: number;
	/** Absent totalBytes means the aggregate/row progress is indeterminate. */
	totalBytes?: number;
}

export interface E5TransferDisplay {
	state: E5TransferRowState;
	/** Stable i18n key for the row state. */
	key: string;
	pauseReasonKey?: string;
	progress?: { done: number; total?: number };
	actions: {
		/** Resume once only when eligibility re-arrives (Pass 3). */
		resume: boolean;
		/** Cancel stops this transfer; it never deletes completed bytes. */
		cancel: boolean;
		/** Retry restarts an eligible failed/expired transfer under CURRENT authorization. */
		retry: boolean;
		/** Open/Save the finished download. Verification failure never offers these. */
		open: boolean;
		save: boolean;
	};
	alert: boolean;
}

function baseActions(): E5TransferDisplay['actions'] {
	return { resume: false, cancel: false, retry: false, open: false, save: false };
}

/** Map one durable transfer row onto its display contract. */
export function e5TransferDisplay(input: E5TransferRowInput): E5TransferDisplay {
	const actions = baseActions();
	const display: E5TransferDisplay = { state: input.state, key: '', actions, alert: false };
	switch (input.state) {
		case 'queued':
			display.key = 'offline.e5.transfer.queued';
			actions.cancel = true;
			break;
		case 'transferring':
			display.key = 'offline.e5.transfer.transferring';
			actions.cancel = true;
			if (input.committedBytes !== undefined) {
				display.progress = input.totalBytes === undefined
					? { done: input.committedBytes }
					: { done: input.committedBytes, total: input.totalBytes };
			}
			break;
		case 'waitingForNetwork':
			display.key = 'offline.e5.transfer.waiting_for_network';
			actions.resume = true;
			actions.cancel = true;
			break;
		case 'resourcePaused':
			display.key = 'offline.e5.transfer.resource_paused';
			actions.resume = true;
			actions.cancel = true;
			break;
		case 'verifying':
			display.key = 'offline.e5.transfer.verifying';
			actions.cancel = true;
			break;
		case 'validatorRestart':
			// A changed validator announces a safe restart; committed bytes purged,
			// so the row is explicit instead of silently rewinding.
			display.key = 'offline.e5.transfer.validator_restart';
			actions.cancel = true;
			break;
		case 'recoverableError':
			display.key = 'offline.e5.transfer.recoverable_error';
			actions.retry = true;
			actions.cancel = true;
			break;
		case 'complete':
			display.key = 'offline.e5.transfer.complete';
			actions.open = true;
			actions.save = true;
			break;
		case 'cancelled':
			display.key = 'offline.e5.transfer.cancelled';
			actions.retry = true;
			break;
		case 'downloadExpired':
			// R4: existing terminal expiry displays "Download expired" with a
			// newly authorized restart (a fresh, current-authorization attempt).
			display.key = 'offline.e5.transfer.download_expired';
			actions.retry = true;
			break;
		case 'contentUnavailable':
			// R4: authorized content-unavailable classification displays
			// "Attachment unavailable" WITHOUT retry (never raw 404/410 text).
			display.key = 'offline.e5.transfer.content_unavailable';
			break;
		case 'verificationFailed':
			// R4: integrity failure displays "Verification failed" without
			// Open/Save — unverified bytes are never offered to the user.
			display.key = 'offline.e5.transfer.verification_failed';
			display.alert = true;
			break;
	}
	if (input.pauseReason !== undefined) display.pauseReasonKey = pauseReasonKey(input.pauseReason);
	return display;
}

/** Map a scheduler pause reason onto the matching transfer row state. */
export function transferRowStateForPause(reason: PauseReason): E5TransferRowState {
	switch (reason) {
		case 'networkUnavailable':
		case 'meteredNetwork':
			return 'waitingForNetwork';
		case 'lowPower':
		case 'notCharging':
		case 'thermal':
		case 'storagePressure':
		case 'criticalActivity':
		case 'capabilityUnavailable':
		case 'authExpired':
		case 'backgroundGrantExpired':
		case 'policyDenied':
		case 'observeOnly':
		case 'backoff':
		case 'deadlineExceeded':
		case 'statePruned':
		case 'cancelled':
			return 'resourcePaused';
		case 'validatorChanged':
			return 'validatorRestart';
	}
}

// ── Save-all group semantics (R4) ───────────────────────────────────────────

export interface E5SaveAllChildInput {
	/** Independent child identity (opaque transfer id) — never an index. */
	id: string;
	state: E5TransferRowState;
	totalBytes?: number;
	committedBytes?: number;
}

export interface E5SaveAllGroupSummary {
	total: number;
	completed: number;
	failed: number;
	cancelled: number;
	expired: number;
	unavailable: number;
	active: number;
	/** Success requires EVERY requested child complete — partial is not success. */
	allComplete: boolean;
	/** Unknown child sizes make aggregate progress genuinely indeterminate. */
	indeterminate: boolean;
	bytes: { done: number; total?: number };
}

const ACTIVE_STATES: ReadonlySet<E5TransferRowState> = new Set([
	'queued',
	'transferring',
	'waitingForNetwork',
	'resourcePaused',
	'verifying',
	'validatorRestart',
] as E5TransferRowState[]);

/** Group roll-up: completed/total plus failed/cancelled/expired children. */
export function summarizeSaveAll(children: readonly E5SaveAllChildInput[]): E5SaveAllGroupSummary {
	const summary: E5SaveAllGroupSummary = {
		total: children.length,
		completed: 0,
		failed: 0,
		cancelled: 0,
		expired: 0,
		unavailable: 0,
		active: 0,
		allComplete: children.length > 0,
		indeterminate: false,
		bytes: { done: 0 },
	};
	let knownTotal = 0;
	let knownAll = true;
	for (const child of children) {
		switch (child.state) {
			case 'complete':
				summary.completed += 1;
				break;
			case 'recoverableError':
			case 'verificationFailed':
				summary.failed += 1;
				break;
			case 'cancelled':
				summary.cancelled += 1;
				break;
			case 'downloadExpired':
				summary.expired += 1;
				break;
			case 'contentUnavailable':
				summary.unavailable += 1;
				break;
			default:
				if (ACTIVE_STATES.has(child.state)) summary.active += 1;
				break;
		}
		const committed = child.committedBytes ?? 0;
		summary.bytes.done += committed;
		if (child.totalBytes === undefined) knownAll = false;
		else knownTotal += child.totalBytes;
	}
	summary.allComplete = summary.completed === children.length && children.length > 0;
	summary.indeterminate = !knownAll;
	if (knownAll) summary.bytes.total = knownTotal;
	return summary;
}

/**
 * Group Retry selects ONLY eligible failed children with current
 * authorization: recoverable errors always; expired transfers carry a newly
 * authorized restart. Content-unavailable never retries (R4); a verification
 * failure needs an explicit fresh download, not a blind group retry; a
 * cancelled child stays cancelled until the user re-requests it.
 */
export function saveAllRetryIds(children: readonly E5SaveAllChildInput[]): string[] {
	return children
		.filter((child) => child.state === 'recoverableError' || child.state === 'downloadExpired')
		.map((child) => child.id);
}

/**
 * Group Cancel stops every unfinished child WITHOUT deleting completed
 * downloads (R4). Returns the opaque ids so the caller cancels exactly those.
 */
export function saveAllCancelPlan(children: readonly E5SaveAllChildInput[]): {
	toCancel: string[];
	preserved: string[];
} {
	const toCancel: string[] = [];
	const preserved: string[] = [];
	for (const child of children) {
		if (child.state === 'complete') preserved.push(child.id);
		else toCancel.push(child.id);
	}
	return { toCancel, preserved };
}

// ── Announcer policy (Phase 2 Pass 5) ───────────────────────────────────────

/**
 * Announce phase changes and 10% transfer thresholds — never chunks or flaps.
 * `previousPercent === null` is the idle→running phase change; completion is a
 * phase change to 100. Progress never announces a decrease unless the caller
 * models an announced validator restart (handled by the row state, not here).
 */
export function shouldAnnounceTransferProgress(
	previousPercent: number | null,
	nextPercent: number | null,
): boolean {
	if (nextPercent === null) return previousPercent !== null;
	if (previousPercent === null) return true;
	if (nextPercent >= 100 && previousPercent < 100) return true;
	const band = (value: number): number => Math.min(9, Math.floor(value / 10));
	return band(nextPercent) > band(previousPercent);
}

export interface E5GroupAnnouncement {
	key: string;
	params: Record<string, string>;
}

/**
 * ONE accessible group announcement replaces per-child bursts: it is emitted
 * when the completed count changes and carries the failure counts. Returns
 * null when nothing audible changed.
 */
export function groupAnnouncement(
	previous: E5SaveAllGroupSummary | null,
	next: E5SaveAllGroupSummary,
): E5GroupAnnouncement | null {
	if (previous !== null && previous.completed === next.completed && previous.failed === next.failed
		&& previous.cancelled === next.cancelled && previous.expired === next.expired) {
		return null;
	}
	if (previous === null && next.completed === 0 && next.failed === 0 && next.cancelled === 0
		&& next.expired === 0) {
		return null;
	}
	const params: Record<string, string> = {
		completed: String(next.completed),
		total: String(next.total),
		failed: String(next.failed),
		cancelled: String(next.cancelled),
		expired: String(next.expired),
	};
	return { key: 'offline.e5.saveall.announce', params };
}
