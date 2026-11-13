// uploadOrchestrator.svelte.ts — Task 14 (candidate C7 part 2): single owner
// of the upload-tray bookkeeping that 2 of DriveApp's 5 uploadFile call sites
// (new-file upload, new-version upload) each re-implemented in a near-
// identical ~15-line block: push a progress entry, wire uploadFile's
// onProgress callback to it, flip its status to 'done'/'error' on
// settle, and map the error to a display string.
//
// The other 3 uploadFile call sites (restore-as-of-version, confirm-save-
// as-branch, restore-as-new-version) never pushed a progress entry in the
// first place — they're a bare `await uploadFile(...)` followed by a
// listing/version reload, with failures going straight to the page-level
// banner. There's no tray bookkeeping there to extract, so they stay direct
// uploadFile calls at the call site (see task-14-report.md).
import { uploadFile, type UploadOptions } from './upload';
import { DriveError, type PutVersionResult } from './api';
import { driveErrorMessage } from './errors';
import { t } from '$lib/i18n';
import type { UploadItem } from '$lib/components/drive/uploads';

/** BZ148 gets the upload-specific phrasing (quota OR upload-size-limit,
 *  spec §7); every other code/fallback routes through the shared map. */
export function uploadErrorMessage(e: unknown): string {
	if (e instanceof DriveError && e.code === 'BZ148') return t('drive.upload.quotaExceeded');
	return driveErrorMessage(e, 'drive.upload.failed');
}

export type UploadOutcome =
	| { ok: true; id: string; result: PutVersionResult }
	| { ok: false; id: string; error: unknown };

export class UploadOrchestrator {
	uploads = $state<UploadItem[]>([]);

	/** Drop a tray entry — the user's dismiss-x, and the BZ149 save-as-branch
	 *  path (the failed entry gets replaced by the saveAsBranchPrompt dialog
	 *  instead of sitting in the tray as an error). */
	remove(id: string): void {
		this.uploads = this.uploads.filter((u) => u.id !== id);
	}

	/** Push a progress entry, run uploadFile wired to it, settle the entry's
	 *  status, and return the outcome instead of throwing — callers branch on
	 *  `.ok` for their own site-specific follow-up (surfaceWormPending, a
	 *  listing/version reload, or DriveError-specific handling like BZ149)
	 *  without needing a try/catch around the shared bookkeeping. */
	async start(spaceId: number, nodeId: number, file: File, opts: Omit<UploadOptions, 'onProgress'>): Promise<UploadOutcome> {
		const id = `${Date.now()}-${file.name}`;
		this.uploads = [...this.uploads, { id, name: file.name, sent: 0, total: file.size, status: 'uploading' }];
		try {
			const result = await uploadFile(spaceId, nodeId, file, {
				...opts,
				onProgress: (sent, total) => {
					this.uploads = this.uploads.map((u) => (u.id === id ? { ...u, sent, total } : u));
				},
			});
			this.uploads = this.uploads.map((u) => (u.id === id ? { ...u, status: 'done' } : u));
			return { ok: true, id, result };
		} catch (e) {
			const msg = uploadErrorMessage(e);
			this.uploads = this.uploads.map((u) => (u.id === id ? { ...u, status: 'error', errorMessage: msg } : u));
			return { ok: false, id, error: e };
		}
	}
}

/** Shared process-wide instance — mirrors locks.svelte.ts / watches.svelte.ts's singleton pattern. */
export const uploadOrchestrator = new UploadOrchestrator();
