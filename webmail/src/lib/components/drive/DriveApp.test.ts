import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/svelte/svelte5';
import DriveApp from './DriveApp.svelte';

const h = vi.hoisted(() => ({
	listSpaces: vi.fn(), tree: vi.fn(), listVersions: vi.fn(), changes: vi.fn(), createSpace: vi.fn(), createNode: vi.fn(),
	renameNode: vi.fn(), trashNode: vi.fn(), restoreNode: vi.fn(), destroyNode: vi.fn(), spaceAsOf: vi.fn(),
	fetchVersionContent: vi.fn(), searchNodes: vi.fn(), listBranches: vi.fn(), lockFile: vi.fn(), unlockFile: vi.fn(),
	watch: vi.fn(), unwatch: vi.fn(), loadWatches: vi.fn(), showToast: vi.fn(), subscribeEvent: vi.fn(),
	watchHandler: undefined as undefined | ((event: { nodeId?: number; op?: string }) => void),
}));

vi.mock('$lib/drive/api', async () => ({
	...(await vi.importActual<typeof import('$lib/drive/api')>('$lib/drive/api')),
	listSpaces: h.listSpaces, tree: h.tree, listVersions: h.listVersions, changes: h.changes,
	createSpace: h.createSpace, createNode: h.createNode, renameNode: h.renameNode, trashNode: h.trashNode,
	restoreNode: h.restoreNode, destroyNode: h.destroyNode, spaceAsOf: h.spaceAsOf,
	fetchVersionContent: h.fetchVersionContent, searchNodes: h.searchNodes, listBranches: h.listBranches,
	lockFile: h.lockFile, unlockFile: h.unlockFile,
}));
vi.mock('$lib/drive/watches.svelte', () => ({
	driveWatches: { load: h.loadWatches, watch: h.watch, unwatch: h.unwatch, toggle: h.watch, isWatched: (nodeId: number) => nodeId === 12, list: () => [{ nodeId: 12, nodeName: 'Roadmap.docx' }] },
}));
vi.mock('$lib/jmap/websocket', () => ({ subscribeEvent: h.subscribeEvent }));
vi.mock('$lib/components/ui', async () => ({ ...(await vi.importActual<typeof import('$lib/components/ui')>('$lib/components/ui')), showToast: h.showToast }));
vi.mock('$lib/drive/uploadOrchestrator.svelte', () => ({
	uploadOrchestrator: { uploads: [], start: vi.fn(), remove: vi.fn() }, uploadErrorMessage: () => 'Upload failed',
}));
vi.mock('$lib/drive/versionSave.svelte', () => ({
	VersionSaveFlow: class {
		saveAsBranchPrompt = null; showChangeNote = false;
		handleFilePicked = vi.fn(); requestUploadNewVersion = vi.fn(); dismissSaveAsBranch = vi.fn(); confirmSaveAsBranch = vi.fn();
		submitChangeNote = vi.fn(); cancelChangeNote = vi.fn();
	},
}));
vi.mock('$lib/drive/opener.svelte', () => ({ inAppRenderer: { current: null, open: vi.fn(), close: vi.fn() } }));

const allCaps = ['traverse', 'list_children', 'read_metadata', 'preview', 'download', 'create_child', 'modify_content', 'rename', 'move', 'delete', 'manage_acl', 'view_audit'] as const;
const space = { id: 7, name: 'Product', isPersonal: false, classification: 'regular' as const, role: 'manager' as const, usedBytes: 2048, quotaBytes: 10240, changeSeq: 2, rootCapabilities: [...allCaps] };
const folder = { id: 11, spaceId: 7, parentId: null, kind: 'folder' as const, name: 'Plans', size: null, branchCount: 0, lock: null, capabilities: [...allCaps], traverseOnly: false };
const file = { id: 12, spaceId: 7, parentId: null, kind: 'file' as const, name: 'Roadmap.docx', size: 4096, headVersionId: 21, branchCount: 1, lock: null, capabilities: [...allCaps], traverseOnly: false };
const version = { id: 21, parentVersionId: null, conflictOf: null, sha256: 'a'.repeat(64), size: 4096, contentType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', author: 1, createdAt: '2026-07-20T10:00:00Z', note: 'Initial', previewStatus: 'ready', branchId: null, labels: [] };

describe('DriveApp', () => {
	beforeEach(() => {
		for (const mock of Object.values(h)) if (typeof mock === 'function' && 'mockReset' in mock) (mock as ReturnType<typeof vi.fn>).mockReset();
		h.listSpaces.mockResolvedValue([space]); h.tree.mockResolvedValue([folder, file]); h.listVersions.mockResolvedValue([version]);
		h.changes.mockResolvedValue({ changed: [], newState: 2 }); h.createSpace.mockResolvedValue({ id: 8 }); h.createNode.mockResolvedValue({ id: 30 });
		h.renameNode.mockResolvedValue(undefined); h.trashNode.mockResolvedValue(undefined); h.restoreNode.mockResolvedValue(undefined); h.destroyNode.mockResolvedValue(undefined);
		h.spaceAsOf.mockResolvedValue({ items: [] }); h.searchNodes.mockResolvedValue({ items: [] }); h.listBranches.mockResolvedValue([]);
		h.lockFile.mockResolvedValue({ status: 'acquired', mode: 'soft' }); h.unlockFile.mockResolvedValue(undefined);
		h.watch.mockResolvedValue(undefined); h.unwatch.mockResolvedValue(undefined); h.loadWatches.mockResolvedValue(undefined);
		h.subscribeEvent.mockImplementation((_type, handler) => { h.watchHandler = handler; return vi.fn(); });
	});
	afterEach(() => vi.useRealTimers());

	it('loads a writable space and performs folder, rename, trash, and watch journeys', async () => {
		render(DriveApp);
		await vi.waitFor(() => expect(screen.getByText('Roadmap.docx')).toBeTruthy());
		expect(h.listSpaces).toHaveBeenCalled();
		expect(h.tree).toHaveBeenCalledWith(7, { parent: null, deleted: false });

		await fireEvent.click(screen.getByRole('button', { name: 'New folder' }));
		await fireEvent.input(screen.getAllByLabelText('New folder').at(-1)!, { target: { value: 'Evidence' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
		await vi.waitFor(() => expect(h.createNode).toHaveBeenCalledWith({ spaceId: 7, parentId: null, kind: 'folder', name: 'Evidence' }));

		await fireEvent.click(screen.getAllByLabelText('Rename')[1]);
		const rename = document.querySelector('.fl-row__rename') as HTMLInputElement;
		await fireEvent.input(rename, { target: { value: 'Roadmap-final.docx' } });
		await fireEvent.keyDown(rename, { key: 'Enter' });
		await vi.waitFor(() => expect(h.renameNode).toHaveBeenCalledWith(12, 'Roadmap-final.docx'));

		await fireEvent.click(screen.getAllByLabelText('Move to trash')[1]);
		await vi.waitFor(() => expect(h.trashNode).toHaveBeenCalledWith(12));
		await fireEvent.click(screen.getAllByLabelText('Watch this')[0]);
		await vi.waitFor(() => expect(h.watch).toHaveBeenCalledWith(11));
		expect(h.showToast).toHaveBeenCalledWith(expect.stringContaining('Plans'), expect.objectContaining({ actionLabel: 'Undo' }));
	});

	it('creates a classified space through the warning dialog', async () => {
		render(DriveApp);
		await vi.waitFor(() => expect(screen.getAllByText('Product').length).toBeGreaterThan(0));
		await fireEvent.click(screen.getByRole('button', { name: 'New space' }));
		await fireEvent.input(screen.getByLabelText('Name'), { target: { value: 'Regulated' } });
		const selects = screen.getAllByLabelText('Spaces');
		await fireEvent.change(selects.at(-1)!, { target: { value: 'gxp' } });
		expect(screen.getByRole('alert').textContent).toMatch(/never be lowered/i);
		const buttons = screen.getAllByRole('button', { name: 'New space' });
		await fireEvent.click(buttons.at(-1)!);
		await vi.waitFor(() => expect(h.createSpace).toHaveBeenCalledWith({ name: 'Regulated', classification: 'gxp' }));
	});

	it('switches to deleted items and restores and permanently deletes rows', async () => {
		render(DriveApp);
		await vi.waitFor(() => expect(screen.getByText('Roadmap.docx')).toBeTruthy());
		await fireEvent.click(screen.getByRole('button', { name: 'Trash' }));
		await vi.waitFor(() => expect(h.tree).toHaveBeenLastCalledWith(7, { parent: null, deleted: true }));
		await fireEvent.click(screen.getAllByLabelText('Restore')[0]);
		await fireEvent.click(screen.getAllByLabelText('Delete permanently')[0]);
		await vi.waitFor(() => expect(h.restoreNode).toHaveBeenCalledWith(11));
		expect(h.destroyNode).toHaveBeenCalledWith(11);
	});

	it('runs a scoped search, opens a file result, and clears the search', async () => {
		h.searchNodes.mockResolvedValue({ items: [{ id: 12, spaceId: 7, parentId: null, kind: 'file', name: 'Roadmap.docx', sizeBytes: 4096 }] });
		render(DriveApp);
		await vi.waitFor(() => expect(screen.getByText('Roadmap.docx')).toBeTruthy());
		await fireEvent.input(screen.getByRole('searchbox', { name: 'Search files' }), { target: { value: 'road' } });
		await new Promise((resolve) => setTimeout(resolve, 320));
		await vi.waitFor(() => expect(h.searchNodes).toHaveBeenCalledWith('road', expect.objectContaining({ spaceId: 7 })));
		await fireEvent.click(document.querySelector('.drive-app__search-row') as HTMLButtonElement);
		await vi.waitFor(() => expect(h.listVersions).toHaveBeenCalledWith(12));
		expect((screen.getByRole('searchbox', { name: 'Search files' }) as HTMLInputElement).value).toBe('');
	});

	it('enters and exits an as-of view and reports API failures', async () => {
		h.spaceAsOf.mockResolvedValue({ items: [{ id: 12, parentId: null, kind: 'file', name: 'Historic roadmap', versionId: 21, versionCreatedAt: '2026-07-01T00:00:00Z', sizeBytes: 4096, contentType: 'application/pdf', liveNow: false }] });
		render(DriveApp);
		await vi.waitFor(() => expect(screen.getAllByText('Product').length).toBeGreaterThan(0));
		await fireEvent.click(screen.getByRole('button', { name: 'View as of…' }));
		const asOfInputs = screen.getAllByLabelText('View as of…');
		await fireEvent.input(asOfInputs.at(-1)!, { target: { value: '2026-07-01T12:00' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
		await vi.waitFor(() => expect(screen.getByText('Historic roadmap')).toBeTruthy());
		expect(screen.getByText('Not in current space')).toBeTruthy();
		await fireEvent.click(screen.getByRole('button', { name: 'Exit' }));
		expect(screen.queryByText('Historic roadmap')).toBeNull();

		h.tree.mockRejectedValueOnce(new Error('tree failed'));
		await fireEvent.click(screen.getByRole('button', { name: 'Product' }));
		await vi.waitFor(() => expect(screen.getByRole('alert').textContent).toContain('An error occurred'));
	});

	it('announces named and generic live watch events', async () => {
		render(DriveApp);
		await vi.waitFor(() => expect(h.watchHandler).toBeTypeOf('function'));
		h.watchHandler?.({ nodeId: 12, op: 'updated' });
		h.watchHandler?.({ nodeId: 999, op: 'updated' });
		h.watchHandler?.({ nodeId: 0, op: 'updated' });
		expect(h.showToast).toHaveBeenCalledTimes(2);
		expect(h.showToast.mock.calls[0][0]).not.toBe('Something changed in a watched location.');
	});
});
