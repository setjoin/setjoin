import { describe, it, expect, vi, beforeEach } from 'vitest';
import { VersionSaveFlow, type VersionSaveDeps } from './versionSave.svelte';
import { DriveError, type DriveNode, type DriveVersion, type PutVersionResult } from './api';

const listVersions = vi.fn();
const createBranch = vi.fn();
const uploadFile = vi.fn();
const uploadOrchestratorStart = vi.fn();
const uploadOrchestratorRemove = vi.fn();

vi.mock('./api', async () => {
	const actual = await vi.importActual<typeof import('./api')>('./api');
	return {
		...actual,
		listVersions: (...a: unknown[]) => listVersions(...a),
		createBranch: (...a: unknown[]) => createBranch(...a),
	};
});

vi.mock('./upload', async () => {
	const actual = await vi.importActual<typeof import('./upload')>('./upload');
	return {
		...actual,
		uploadFile: (...a: unknown[]) => uploadFile(...a),
	};
});

vi.mock('./uploadOrchestrator.svelte', async () => {
	const actual = await vi.importActual<typeof import('./uploadOrchestrator.svelte')>('./uploadOrchestrator.svelte');
	return {
		...actual,
		uploadOrchestrator: {
			start: (...a: unknown[]) => uploadOrchestratorStart(...a),
			remove: (...a: unknown[]) => uploadOrchestratorRemove(...a),
		},
	};
});

const RESULT: PutVersionResult = { versionId: 1, conflict: false, branchId: null, headVersionId: 1, wormPending: false };

function file(name: string): File {
	return new File([new Uint8Array(10)], name);
}

function node(overrides: Partial<DriveNode> = {}): DriveNode {
	return { id: 42, name: 'a.txt', kind: 'file', headVersionId: 5, ...overrides } as DriveNode;
}

function makeDeps(overrides: Partial<VersionSaveDeps> = {}) {
	return {
		getSpaceId: () => 1,
		getSelectedFile: () => node(),
		isGxpSpace: () => false,
		startNewUpload: vi.fn(),
		onVersionsUpdated: vi.fn(),
		reloadListing: vi.fn(),
		onWormPending: vi.fn(),
		onError: vi.fn(),
		...overrides,
	};
}

describe('VersionSaveFlow', () => {
	beforeEach(() => {
		listVersions.mockReset().mockResolvedValue([{ id: 5 } as DriveVersion]);
		createBranch.mockReset().mockResolvedValue({ branchId: 7 });
		uploadFile.mockReset().mockResolvedValue(RESULT);
		uploadOrchestratorStart.mockReset().mockResolvedValue({ ok: true, id: 'u1', result: RESULT });
		uploadOrchestratorRemove.mockReset();
	});

	it('handleFilePicked: non-gxp space starts the upload directly, no note prompt', () => {
		const deps = makeDeps({ isGxpSpace: () => false });
		const flow = new VersionSaveFlow(deps);

		flow.handleFilePicked([file('a.txt'), file('b.txt')]);

		expect(deps.startNewUpload).toHaveBeenCalledTimes(2);
		expect(flow.showChangeNote).toBe(false);
		expect(flow.pendingGxpUpload).toBeNull();
	});

	it('handleFilePicked: gxp space holds the files and opens the note prompt', () => {
		const deps = makeDeps({ isGxpSpace: () => true });
		const flow = new VersionSaveFlow(deps);
		const files = [file('a.txt')];

		flow.handleFilePicked(files);

		expect(deps.startNewUpload).not.toHaveBeenCalled();
		expect(flow.showChangeNote).toBe(true);
		expect(flow.pendingGxpUpload).toEqual({ kind: 'new', files });
	});

	it('requestUploadNewVersion: gxp space holds the file and opens the note prompt instead of saving', () => {
		const deps = makeDeps({ isGxpSpace: () => true });
		const flow = new VersionSaveFlow(deps);
		const f = file('v2.txt');

		flow.requestUploadNewVersion(f);

		expect(uploadOrchestratorStart).not.toHaveBeenCalled();
		expect(flow.showChangeNote).toBe(true);
		expect(flow.pendingGxpUpload).toEqual({ kind: 'version', file: f });
	});

	it('submitChangeNote: "new" kind starts every held file with the note, then clears the prompt', async () => {
		const deps = makeDeps({ isGxpSpace: () => true });
		const flow = new VersionSaveFlow(deps);
		const files = [file('a.txt'), file('b.txt')];
		flow.handleFilePicked(files);

		await flow.submitChangeNote('QA-1234 sign-off');

		expect(deps.startNewUpload).toHaveBeenCalledWith(files[0], 'QA-1234 sign-off');
		expect(deps.startNewUpload).toHaveBeenCalledWith(files[1], 'QA-1234 sign-off');
		expect(flow.pendingGxpUpload).toBeNull();
		expect(flow.showChangeNote).toBe(false);
	});

	it('submitChangeNote: "version" kind runs the held save-new-version with the note', async () => {
		const deps = makeDeps({ isGxpSpace: () => true });
		const flow = new VersionSaveFlow(deps);
		const f = file('v2.txt');
		flow.requestUploadNewVersion(f);

		await flow.submitChangeNote('change note');

		expect(uploadOrchestratorStart).toHaveBeenCalledWith(1, 42, f, expect.objectContaining({ note: 'change note' }));
		expect(deps.onVersionsUpdated).toHaveBeenCalled();
		expect(deps.reloadListing).toHaveBeenCalled();
	});

	it('cancelChangeNote: drops the held upload without starting anything', () => {
		const deps = makeDeps({ isGxpSpace: () => true });
		const flow = new VersionSaveFlow(deps);
		flow.handleFilePicked([file('a.txt')]);

		flow.cancelChangeNote();

		expect(deps.startNewUpload).not.toHaveBeenCalled();
		expect(flow.showChangeNote).toBe(false);
		expect(flow.pendingGxpUpload).toBeNull();
	});

	it('handleUploadNewVersion: BZ149 hard lock drops the tray entry and offers save-as-branch instead of erroring', async () => {
		const lockErr = new DriveError({ status: 423, code: 'BZ149', detail: 'locked', extensions: { holderId: 9 } });
		uploadOrchestratorStart.mockResolvedValueOnce({ ok: false, id: 'u1', error: lockErr });
		const deps = makeDeps();
		const flow = new VersionSaveFlow(deps);
		const f = file('v2.txt');

		await flow.handleUploadNewVersion(f);

		expect(uploadOrchestratorRemove).toHaveBeenCalledWith('u1');
		expect(flow.saveAsBranchPrompt).toEqual({ file: f, nodeId: 42, holderLabel: '#9' });
		expect(deps.onError).not.toHaveBeenCalled();
	});

	it('handleUploadNewVersion: a non-BZ149 failure surfaces the mapped error banner, no branch offer', async () => {
		const err = new DriveError({ status: 500, code: 'BZ999', detail: 'boom' });
		uploadOrchestratorStart.mockResolvedValueOnce({ ok: false, id: 'u1', error: err });
		const deps = makeDeps();
		const flow = new VersionSaveFlow(deps);

		await flow.handleUploadNewVersion(file('v2.txt'));

		expect(flow.saveAsBranchPrompt).toBeNull();
		expect(deps.onError).toHaveBeenCalled();
	});

	it('handleUploadNewVersion: success reloads versions + listing and surfaces worm-pending', async () => {
		const deps = makeDeps();
		const flow = new VersionSaveFlow(deps);

		await flow.handleUploadNewVersion(file('v2.txt'));

		expect(deps.onWormPending).toHaveBeenCalledWith(RESULT);
		expect(deps.onVersionsUpdated).toHaveBeenCalledWith([{ id: 5 }]);
		expect(deps.reloadListing).toHaveBeenCalled();
	});

	it('confirmSaveAsBranch: creates a branch, re-saves onto it, and refreshes versions + listing', async () => {
		const deps = makeDeps();
		const flow = new VersionSaveFlow(deps);
		const lockErr = new DriveError({ status: 423, code: 'BZ149', detail: 'locked', extensions: { holderId: 9 } });
		uploadOrchestratorStart.mockResolvedValueOnce({ ok: false, id: 'u1', error: lockErr });
		const f = file('v2.txt');
		await flow.handleUploadNewVersion(f);
		expect(flow.saveAsBranchPrompt).not.toBeNull();

		await flow.confirmSaveAsBranch();

		expect(createBranch).toHaveBeenCalledWith(42, expect.any(String), 5);
		expect(uploadFile).toHaveBeenCalledWith(1, 42, f, expect.objectContaining({ branchId: 7 }));
		expect(flow.saveAsBranchPrompt).toBeNull();
		expect(deps.onVersionsUpdated).toHaveBeenCalled();
		expect(deps.reloadListing).toHaveBeenCalled();
	});

	it('confirmSaveAsBranch: a stale prompt (selection moved to a different file) is dropped silently', async () => {
		const deps = makeDeps({ getSelectedFile: () => node({ id: 999 }) });
		const flow = new VersionSaveFlow(deps);
		flow.saveAsBranchPrompt = { file: file('v2.txt'), nodeId: 42, holderLabel: '#9' };

		await flow.confirmSaveAsBranch();

		expect(createBranch).not.toHaveBeenCalled();
		expect(flow.saveAsBranchPrompt).toBeNull();
	});

	it('dismissSaveAsBranch: clears the prompt', () => {
		const deps = makeDeps();
		const flow = new VersionSaveFlow(deps);
		flow.saveAsBranchPrompt = { file: file('v2.txt'), nodeId: 42, holderLabel: '' };

		flow.dismissSaveAsBranch();

		expect(flow.saveAsBranchPrompt).toBeNull();
	});
});
