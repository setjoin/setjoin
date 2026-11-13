import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import DriveApp from '$lib/components/drive/DriveApp.svelte';
import { t } from '$lib/i18n';
import type { DriveNode, DriveSpace, DriveVersion } from '$lib/drive/api';

const ALL_CAPABILITIES = [
	'traverse', 'list_children', 'read_metadata', 'preview', 'download',
	'create_child', 'modify_content', 'rename', 'move', 'delete', 'manage_acl', 'view_audit',
] as const;

const SPACES: DriveSpace[] = [
	{ id: 1, name: 'My Drive', isPersonal: true, classification: 'regular', role: 'manager', usedBytes: 100, quotaBytes: null, changeSeq: 0, rootCapabilities: [...ALL_CAPABILITIES] },
	{ id: 2, name: 'Compliance', isPersonal: false, classification: 'secure', role: 'manager', usedBytes: 500, quotaBytes: 1000, changeSeq: 0, rootCapabilities: [...ALL_CAPABILITIES] },
	{ id: 3, name: 'Quality Records', isPersonal: false, classification: 'gxp', role: 'manager', usedBytes: 0, quotaBytes: null, changeSeq: 0, rootCapabilities: [...ALL_CAPABILITIES] },
];

const FOLDER_NODES: DriveNode[] = [{ id: 601, parentId: null, kind: 'folder', name: 'Docs', branchCount: 0, lock: null, capabilities: [...ALL_CAPABILITIES], traverseOnly: false }];

const LISTING: DriveNode[] = [
	{ id: 601, parentId: null, kind: 'folder', name: 'Docs', branchCount: 0, lock: null },
	{
		id: 501,
		parentId: null,
		kind: 'file',
		name: 'report.pdf',
		size: 2048,
		contentType: 'application/pdf',
		headVersionId: 701,
		branchCount: 0,
		lock: null,
		capabilities: [...ALL_CAPABILITIES],
		traverseOnly: false,
	},
];

const VERSIONS: DriveVersion[] = [
	{ id: 702, parentVersionId: 701, conflictOf: 701, sha256: 'b'.repeat(64), size: 120, author: 2, previewStatus: 'ready', createdAt: new Date().toISOString(), branchId: null, labels: [] },
	{ id: 701, parentVersionId: null, conflictOf: null, sha256: 'a'.repeat(64), size: 100, author: 1, previewStatus: 'ready', createdAt: new Date().toISOString(), branchId: null, labels: [] },
];

vi.mock('$lib/drive/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/drive/api')>('$lib/drive/api');
	return {
		...actual,
		listSpaces: vi.fn(async () => SPACES),
		createSpace: vi.fn(),
		patchSpace: vi.fn(),
		listMembers: vi.fn(async () => []),
		grantMember: vi.fn(),
		revokeMember: vi.fn(),
		// DriveTree calls tree(spaceId, {}) / ({parent}); DriveApp always passes
		// an explicit `deleted` key — that's the cheapest way to tell the two
		// call sites apart from a single mock.
		tree: vi.fn(async (_spaceId: number, opts: { parent?: number | null; deleted?: boolean }) =>
			'deleted' in opts ? LISTING : FOLDER_NODES,
		),
		changes: vi.fn(async () => ({ changed: [] })),
		createNode: vi.fn(async () => ({ id: 999 })),
		renameNode: vi.fn(),
		moveNode: vi.fn(),
		trashNode: vi.fn(),
		restoreNode: vi.fn(),
		destroyNode: vi.fn(),
		headChunk: vi.fn(async () => false),
		putChunk: vi.fn(async () => undefined),
		putVersion: vi.fn(async () => ({ versionId: 703, conflict: false, branchId: null, headVersionId: 703, wormPending: false })),
		listVersions: vi.fn(async () => VERSIONS),
		// P4: BranchPanel/VersionDrawer self-fetch branches on mount.
		listBranches: vi.fn(async () => []),
		createBranch: vi.fn(async () => ({ branchId: 42 })),
		setWatch: vi.fn(),
		removeWatch: vi.fn(),
		listWatches: vi.fn(async () => []),
	};
});

vi.mock('$lib/drive/upload', () => ({
	uploadFile: vi.fn(),
}));

describe('Drive App', () => {
	// ponytail: real timers — DriveApp's 30s change-poll interval is cleared
	// on unmount by its own $effect cleanup (testing-library unmounts after
	// each test), so there's no dangling-timer risk here; fake timers would
	// only fight waitFor's own internal setTimeout-based polling loop.
	beforeEach(async () => {
		resetStores();
		// vi.restoreAllMocks() (afterEach, below) does not clear call history for
		// a plain vi.fn() with no spied original — only mockClear()/mockReset()
		// do. These four are asserted on with toHaveBeenCalledTimes/Nth in the
		// P4 save-as-branch tests, so their call history must not leak across
		// `it` blocks; mockClear (not mockReset) so createBranch/uploadFile keep
		// their module-init default implementations.
		const { uploadFile } = await import('$lib/drive/upload');
		const { createBranch, setWatch, removeWatch } = await import('$lib/drive/api');
		vi.mocked(uploadFile).mockClear();
		vi.mocked(createBranch).mockClear();
		vi.mocked(setWatch).mockClear();
		vi.mocked(removeWatch).mockClear();
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it('renders the space list with the personal space pinned first and a classification badge (icon + text)', async () => {
		const { container } = await renderAsUser(DriveApp);
		await waitFor(() => expect(container.querySelector('.sp-list__items')).toBeTruthy());
		const rows = container.querySelectorAll('.sp-row__name');
		expect(rows[0]).toHaveTextContent('My Drive');
		expect(rows[1]).toHaveTextContent('Compliance');
		// classification badge: icon + TEXT together, never color alone.
		expect(screen.getByText(t('drive.space.classification.secure'))).toBeInTheDocument();
	});

	it('the folder tree exposes role=tree / role=treeitem with aria-expanded', async () => {
		const { container } = await renderAsUser(DriveApp);
		const tree = await waitFor(() => {
			const el = container.querySelector('[role="tree"]');
			expect(el).toBeTruthy();
			return el as HTMLElement;
		});
		const items = tree.querySelectorAll('[role="treeitem"]');
		expect(items.length).toBeGreaterThan(0);
		const docsRow = Array.from(items).find((el) => el.textContent?.includes('Docs'));
		expect(docsRow?.getAttribute('aria-expanded')).toBe('false');
	});

	it('selecting a file opens the VersionDrawer listing versions, with a conflict badge on the conflicting one', async () => {
		await renderAsUser(DriveApp);
		await waitFor(() => expect(screen.getByText('report.pdf')).toBeInTheDocument());
		fireEvent.click(screen.getByText('report.pdf'));
		await waitFor(() => expect(screen.getByText(t('drive.version.conflict'))).toBeInTheDocument());
		// Only the conflicting version (id 702) carries the badge — the earlier
		// clean version (701) shows Current instead (it renders first in the
		// mocked newest-first list).
		expect(screen.getByText(t('drive.version.current'))).toBeInTheDocument();
	});

	it('renders a quota bar with aria-valuenow when a space has quotaBytes set', async () => {
		const { container } = await renderAsUser(DriveApp);
		await waitFor(() => expect(screen.getByText('Compliance')).toBeInTheDocument());
		const bars = container.querySelectorAll('[role="progressbar"]');
		const quotaBar = Array.from(bars).find((b) => b.getAttribute('aria-valuenow') === '500');
		expect(quotaBar).toBeTruthy();
	});

	it('a BZ148 quota-exceeded upload error surfaces drive.upload.quotaExceeded in an aria-live=polite region', async () => {
		const { uploadFile } = await import('$lib/drive/upload');
		const { DriveError } = await vi.importActual<typeof import('$lib/drive/api')>('$lib/drive/api');
		vi.mocked(uploadFile).mockRejectedValue(new DriveError({ status: 413, code: 'BZ148', detail: 'space quota exceeded' }));

		const { container } = await renderAsUser(DriveApp);
		await waitFor(() => expect(container.querySelector('input[type="file"][multiple]')).toBeTruthy());

		const fileInput = container.querySelector('input[type="file"][multiple]') as HTMLInputElement;
		expect(fileInput).toBeTruthy();
		const file = new File(['x'.repeat(10)], 'big.bin', { type: 'application/octet-stream' });
		Object.defineProperty(fileInput, 'files', { value: [file], configurable: true });
		await fireEvent.change(fileInput);

		// The message surfaces in TWO places by design (the aria-live banner AND
		// the per-file upload-tray item) — scope to the live region specifically.
		const liveRegion = container.querySelector('.drive-app__banner[aria-live="polite"]') as HTMLElement;
		expect(liveRegion).toBeTruthy();
		await waitFor(() => expect(liveRegion).toHaveTextContent(t('drive.upload.quotaExceeded')));
	});

	it('a BZ149 hard-lock error on "upload new version" offers save-as-branch; confirming creates a branch then re-uploads with its id', async () => {
		const { uploadFile } = await import('$lib/drive/upload');
		const { DriveError, createBranch } = await import('$lib/drive/api');
		vi.mocked(uploadFile)
			.mockRejectedValueOnce(new DriveError({ status: 423, code: 'BZ149', detail: 'file is locked', extensions: { holderId: 9 } }))
			.mockResolvedValueOnce({ versionId: 900, conflict: false, branchId: 42, headVersionId: 703, wormPending: false });

		const { container } = await renderAsUser(DriveApp);
		await waitFor(() => expect(screen.getByText('report.pdf')).toBeInTheDocument());
		fireEvent.click(screen.getByText('report.pdf'));
		await waitFor(() => expect(container.querySelector('.vd__file-input')).toBeTruthy());

		const versionInput = container.querySelector('.vd__file-input') as HTMLInputElement;
		const file = new File(['x'], 'report.pdf', { type: 'application/pdf' });
		Object.defineProperty(versionInput, 'files', { value: [file], configurable: true });
		await fireEvent.change(versionInput);

		await waitFor(() => expect(screen.getByText(t('drive.lock.saveAsBranchPrompt', { name: '#9' }))).toBeInTheDocument());
		await fireEvent.click(screen.getByRole('button', { name: t('drive.lock.saveAsBranch') }));

		await waitFor(() => expect(createBranch).toHaveBeenCalledWith(501, expect.any(String), 701));
		await waitFor(() => expect(uploadFile).toHaveBeenCalledTimes(2));
		expect(uploadFile).toHaveBeenLastCalledWith(1, 501, file, expect.objectContaining({ branchId: 42 }));
		expect(screen.queryByText(t('drive.lock.saveAsBranchPrompt', { name: '#9' }))).not.toBeInTheDocument();
	});

	it('canceling the save-as-branch prompt sends nothing further', async () => {
		const { uploadFile } = await import('$lib/drive/upload');
		const { DriveError, createBranch } = await import('$lib/drive/api');
		vi.mocked(uploadFile).mockRejectedValueOnce(new DriveError({ status: 423, code: 'BZ149', detail: 'file is locked', extensions: { holderId: 9 } }));

		const { container } = await renderAsUser(DriveApp);
		await waitFor(() => expect(screen.getByText('report.pdf')).toBeInTheDocument());
		fireEvent.click(screen.getByText('report.pdf'));
		await waitFor(() => expect(container.querySelector('.vd__file-input')).toBeTruthy());

		const versionInput = container.querySelector('.vd__file-input') as HTMLInputElement;
		const file = new File(['x'], 'report.pdf', { type: 'application/pdf' });
		Object.defineProperty(versionInput, 'files', { value: [file], configurable: true });
		await fireEvent.change(versionInput);

		await waitFor(() => expect(screen.getByText(t('drive.lock.saveAsBranchPrompt', { name: '#9' }))).toBeInTheDocument());
		await fireEvent.click(screen.getByRole('button', { name: t('common.cancel') }));

		expect(createBranch).not.toHaveBeenCalled();
		expect(uploadFile).toHaveBeenCalledTimes(1); // only the original failed attempt
	});

	it('P5: a gxp space requires a change note before a new-file upload proceeds, then uploads with it', async () => {
		const { uploadFile } = await import('$lib/drive/upload');
		vi.mocked(uploadFile).mockResolvedValue({ versionId: 900, conflict: false, branchId: null, headVersionId: 900, wormPending: false });

		const { container } = await renderAsUser(DriveApp);
		await waitFor(() => expect(screen.getByText('Quality Records')).toBeInTheDocument());
		await fireEvent.click(screen.getByText('Quality Records'));
		await waitFor(() => expect(container.querySelector('input[type="file"][multiple]')).toBeTruthy());

		const fileInput = container.querySelector('input[type="file"][multiple]') as HTMLInputElement;
		const file = new File(['x'], 'protocol.pdf', { type: 'application/pdf' });
		Object.defineProperty(fileInput, 'files', { value: [file], configurable: true });
		await fireEvent.change(fileInput);

		// The upload must NOT start until the note is supplied — the dialog gates it.
		expect(uploadFile).not.toHaveBeenCalled();
		await fireEvent.input(screen.getByLabelText(t('drive.version.changeNotePrompt')), {
			target: { value: 'Initial protocol upload' },
		});
		await fireEvent.click(screen.getByRole('button', { name: t('drive.version.changeNoteSave') }));

		await waitFor(() =>
			expect(uploadFile).toHaveBeenCalledWith(3, 999, file, expect.objectContaining({ note: 'Initial protocol upload' })),
		);
	});

	it('P5: cancelling the change-note dialog uploads nothing', async () => {
		const { uploadFile } = await import('$lib/drive/upload');
		const { container } = await renderAsUser(DriveApp);
		await waitFor(() => expect(screen.getByText('Quality Records')).toBeInTheDocument());
		await fireEvent.click(screen.getByText('Quality Records'));
		await waitFor(() => expect(container.querySelector('input[type="file"][multiple]')).toBeTruthy());

		const fileInput = container.querySelector('input[type="file"][multiple]') as HTMLInputElement;
		const file = new File(['x'], 'protocol.pdf', { type: 'application/pdf' });
		Object.defineProperty(fileInput, 'files', { value: [file], configurable: true });
		await fireEvent.change(fileInput);

		await waitFor(() => expect(screen.getByLabelText(t('drive.version.changeNotePrompt'))).toBeInTheDocument());
		await fireEvent.click(screen.getByRole('button', { name: t('common.cancel') }));

		expect(screen.queryByLabelText(t('drive.version.changeNotePrompt'))).not.toBeInTheDocument();
		expect(uploadFile).not.toHaveBeenCalled();
	});

	it('P5: a wormPending:true save result shows a passive notice, never an error', async () => {
		const { uploadFile } = await import('$lib/drive/upload');
		vi.mocked(uploadFile).mockResolvedValue({ versionId: 900, conflict: false, branchId: null, headVersionId: 900, wormPending: true });

		const { container } = await renderAsUser(DriveApp);
		await waitFor(() => expect(screen.getByText('Quality Records')).toBeInTheDocument());
		await fireEvent.click(screen.getByText('Quality Records'));
		await waitFor(() => expect(container.querySelector('input[type="file"][multiple]')).toBeTruthy());

		const fileInput = container.querySelector('input[type="file"][multiple]') as HTMLInputElement;
		const file = new File(['x'], 'protocol.pdf', { type: 'application/pdf' });
		Object.defineProperty(fileInput, 'files', { value: [file], configurable: true });
		await fireEvent.change(fileInput);
		await fireEvent.input(screen.getByLabelText(t('drive.version.changeNotePrompt')), { target: { value: 'note' } });
		await fireEvent.click(screen.getByRole('button', { name: t('drive.version.changeNoteSave') }));

		await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(t('drive.version.wormPendingBanner')));
	});
});
