// versionSave.svelte.ts — Task 16 (candidate C7, part 4): the version-save
// state machine DriveApp used to own inline — the gxp change-control note
// gate (spec §2.1: a gxp space requires a change `note` on every save) and
// the P4 Task 14 save-as-branch offer (BZ149 hard-lock: "keep the base
// version's edits as a new branch" instead of clobbering/losing them).
//
// Both flows share one shape (intercept a save → collect user input via a
// prompt → resume the save) and both mutate the same downstream state
// (versions list, tree listing, worm-pending banner), so they're one unit
// here rather than two. DriveApp keeps the dialog markup (ChangeNoteDialog
// mount + the save-as-branch Dialog — both stay declared in DriveApp's
// template since they're a handful of lines and templates read better next
// to the component tree they belong to) and passes in getters/callbacks for
// the bits that stay DriveApp's own concern (which space/file is selected,
// reloading the tree, the shared bannerNotice).
import * as api from './api';
import { DriveError, type DriveNode, type DriveVersion, type PutVersionResult } from './api';
import { uploadFile } from './upload';
import { uploadOrchestrator, uploadErrorMessage } from './uploadOrchestrator.svelte';
import { driveErrorMessage } from './errors';

export type PendingGxpUpload = { kind: 'new'; files: File[] } | { kind: 'version'; file: File };

export interface SaveAsBranchPrompt {
	file: File;
	nodeId: number;
	holderLabel: string;
}

export interface VersionSaveDeps {
	getSpaceId: () => number | null;
	getSelectedFile: () => DriveNode | null;
	isGxpSpace: () => boolean;
	/** DriveApp's own new-file upload (creates the node, hands off to the
	 *  orchestrator) — fire-and-forget, same as the pre-extraction call site. */
	startNewUpload: (file: File, note?: string) => void;
	onVersionsUpdated: (versions: DriveVersion[]) => void;
	reloadListing: () => void | Promise<void>;
	onWormPending: (result: PutVersionResult) => void;
	onError: (message: string) => void;
}

export class VersionSaveFlow {
	pendingGxpUpload = $state<PendingGxpUpload | null>(null);
	showChangeNote = $state(false);
	saveAsBranchPrompt = $state<SaveAsBranchPrompt | null>(null);

	constructor(private deps: VersionSaveDeps) {}

	/** DriveApp's file-input onchange: gate new uploads on the gxp note too. */
	handleFilePicked(files: File[]): void {
		if (this.deps.isGxpSpace()) {
			this.pendingGxpUpload = { kind: 'new', files };
			this.showChangeNote = true;
			return;
		}
		for (const f of files) this.deps.startNewUpload(f);
	}

	/** gxp gate: intercept VersionDrawer's "upload new version" click and
	 *  collect a change note first when the space requires it (spec §2.1). */
	requestUploadNewVersion(file: File): void {
		if (this.deps.isGxpSpace()) {
			this.pendingGxpUpload = { kind: 'version', file };
			this.showChangeNote = true;
			return;
		}
		void this.handleUploadNewVersion(file);
	}

	async submitChangeNote(note: string): Promise<void> {
		this.showChangeNote = false;
		const pending = this.pendingGxpUpload;
		this.pendingGxpUpload = null;
		if (!pending) return;
		if (pending.kind === 'new') {
			for (const f of pending.files) this.deps.startNewUpload(f, note);
		} else {
			await this.handleUploadNewVersion(pending.file, note);
		}
	}

	cancelChangeNote(): void {
		this.showChangeNote = false;
		this.pendingGxpUpload = null;
	}

	async handleUploadNewVersion(file: File, note?: string): Promise<void> {
		const spaceId = this.deps.getSpaceId();
		const node = this.deps.getSelectedFile();
		if (spaceId === null || !node) return;
		const outcome = await uploadOrchestrator.start(spaceId, node.id, file, {
			baseVersionId: node.headVersionId ?? null,
			contentType: file.type || null,
			note,
		});
		if (!outcome.ok) {
			if (outcome.error instanceof DriveError && outcome.error.code === 'BZ149') {
				// A hard lock: drop the tray entry (it's not a real error — the
				// user gets the save-as-branch prompt instead) and offer it.
				uploadOrchestrator.remove(outcome.id);
				this.saveAsBranchPrompt = {
					file,
					nodeId: node.id,
					holderLabel: outcome.error.extensions.holderId ? `#${outcome.error.extensions.holderId}` : '',
				};
				return;
			}
			this.deps.onError(uploadErrorMessage(outcome.error));
			return;
		}
		this.deps.onWormPending(outcome.result);
		this.deps.onVersionsUpdated(await api.listVersions(node.id));
		await this.deps.reloadListing();
	}

	dismissSaveAsBranch(): void {
		this.saveAsBranchPrompt = null;
	}

	async confirmSaveAsBranch(): Promise<void> {
		const prompt = this.saveAsBranchPrompt;
		const spaceId = this.deps.getSpaceId();
		const node = this.deps.getSelectedFile();
		if (!prompt || spaceId === null || !node || node.id !== prompt.nodeId) {
			this.saveAsBranchPrompt = null;
			return;
		}
		const { file, nodeId } = prompt;
		this.saveAsBranchPrompt = null;
		try {
			const branchName = `web ${new Date().toISOString().slice(0, 10)}`;
			const { branchId } = await api.createBranch(nodeId, branchName, node.headVersionId ?? 0);
			await uploadFile(spaceId, nodeId, file, {
				baseVersionId: node.headVersionId ?? null,
				contentType: file.type || null,
				branchId,
			});
			this.deps.onVersionsUpdated(await api.listVersions(nodeId));
			await this.deps.reloadListing();
		} catch (e) {
			this.deps.onError(driveErrorMessage(e));
		}
	}
}
