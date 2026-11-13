// E5 Save-all group controller (R4): Save all is a GROUPED interactive job
// with resumable children — not an unresumable ZIP stream — in this release.
// One controller per Save-all press; children keep their independent opaque
// identities, cancel preserves completed downloads, retry selects only
// eligible failed children, and ONE group announcement replaces bursts.
//
// The controller owns NO transfer I/O: row states are fed in by the durable
// transfer registry (`e5ui.svelte.ts`) from the E3/E4 controller shape. While
// the connectivity-aware-sync flag is OFF no group exists and the existing
// browser anchor path is untouched.
import {
	E5_TRANSFER_ROW_STATES,
	groupAnnouncement,
	saveAllCancelPlan,
	saveAllRetryIds,
	shouldAnnounceTransferProgress,
	summarizeSaveAll,
	type E5GroupAnnouncement,
	type E5SaveAllChildInput,
	type E5SaveAllGroupSummary,
	type E5TransferRowState,
} from './e5.uiProjection';

export interface E5SaveAllChildPatch {
	state?: E5TransferRowState;
	committedBytes?: number;
	totalBytes?: number;
}

export interface E5SaveAllChildView extends E5SaveAllChildInput {
	/** Last announced whole-percent band, for the 10%-threshold policy. */
	announcedPercent: number | null;
}

export interface E5SaveAllGroupView {
	messageId: string;
	children: readonly E5SaveAllChildView[];
	summary: E5SaveAllGroupSummary;
}

export interface E5SaveAllTick {
	view: E5SaveAllGroupView;
	/** At most ONE announcement per tick — never a burst of per-child calls. */
	announcement: E5GroupAnnouncement | null;
	/** Child ids whose 10% threshold (or phase) crossed since the last tick. */
	thresholdAnnouncement: boolean;
}

function percentOf(child: E5SaveAllChildView): number | null {
	if (child.state === 'complete') return 100;
	if (child.state !== 'transferring') return null;
	if (child.totalBytes === undefined || child.totalBytes <= 0) return null;
	const committed = child.committedBytes ?? 0;
	return Math.max(0, Math.min(100, Math.floor((committed / child.totalBytes) * 100)));
}

export function createSaveAllGroup(messageId: string, childIds: readonly string[]): {
	view: E5SaveAllGroupView;
	applyChild(id: string, patch: E5SaveAllChildPatch): E5SaveAllTick;
	retryIds(): string[];
	cancelPlan(): { toCancel: string[]; preserved: string[] };
	summary(): E5SaveAllGroupSummary;
} {
	if (childIds.length === 0) throw new Error('a save-all group requires at least one child');
	const seen = new Set<string>();
	for (const id of childIds) {
		if (seen.has(id)) throw new Error(`duplicate save-all child id "${id}"`);
		seen.add(id);
	}
	const children = new Map<string, E5SaveAllChildView>();
	for (const id of childIds) {
		children.set(id, { id, state: 'queued', announcedPercent: null });
	}
	const snapshot = (): E5SaveAllGroupView => {
		const list = [...children.values()];
		return { messageId, children: list, summary: summarizeSaveAll(list) };
	};
	let previousSummary: E5SaveAllGroupSummary | null = null;

	return {
		// Live view: always the CURRENT roll-up, never a creation-time snapshot.
		get view(): E5SaveAllGroupView { return snapshot(); },
		applyChild(id: string, patch: E5SaveAllChildPatch): E5SaveAllTick {
			const child = children.get(id);
			if (!child) throw new Error(`unknown save-all child "${id}"`);
			if (patch.state !== undefined) child.state = patch.state;
			if (patch.committedBytes !== undefined) child.committedBytes = patch.committedBytes;
			if (patch.totalBytes !== undefined) child.totalBytes = patch.totalBytes;
			const nextPercent = percentOf(child);
			const thresholdAnnouncement = shouldAnnounceTransferProgress(child.announcedPercent, nextPercent);
			if (thresholdAnnouncement) child.announcedPercent = nextPercent;
			const view = snapshot();
			const announcement = groupAnnouncement(previousSummary, view.summary);
			previousSummary = view.summary;
			return { view, announcement, thresholdAnnouncement };
		},
		retryIds(): string[] {
			return saveAllRetryIds([...children.values()]);
		},
		cancelPlan(): { toCancel: string[]; preserved: string[] } {
			return saveAllCancelPlan([...children.values()]);
		},
		summary(): E5SaveAllGroupSummary {
			return summarizeSaveAll([...children.values()]);
		},
	};
}

/** Compile-time guard: the controller only emits contract row states. */
export const E5_SAVE_ALL_ROW_STATES = E5_TRANSFER_ROW_STATES;
