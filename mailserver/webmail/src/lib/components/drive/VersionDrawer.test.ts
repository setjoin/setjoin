import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import VersionDrawer from './VersionDrawer.svelte';
import type { DriveNode, DriveVersion, DriveBranch } from '$lib/drive/api';
import { driveWatches } from '$lib/drive/watches.svelte';

const listBranches = vi.fn();
const history = vi.fn();
const officeChoices = vi.fn();
const officeLaunch = vi.fn();
const setLabel = vi.fn();
const removeLabel = vi.fn();
const setWatch = vi.fn();
const removeWatch = vi.fn();
const listWatches = vi.fn();

vi.mock('$lib/drive/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/drive/api')>('$lib/drive/api');
	return {
		...actual,
		listBranches: (...a: unknown[]) => listBranches(...a),
		history: (...a: unknown[]) => history(...a),
		officeChoices: (...a: unknown[]) => officeChoices(...a),
		officeLaunch: (...a: unknown[]) => officeLaunch(...a),
		setLabel: (...a: unknown[]) => setLabel(...a),
		removeLabel: (...a: unknown[]) => removeLabel(...a),
		setWatch: (...a: unknown[]) => setWatch(...a),
		removeWatch: (...a: unknown[]) => removeWatch(...a),
		listWatches: (...a: unknown[]) => listWatches(...a),
	};
});

const openForEdit = vi.fn();
const checkOut = vi.fn();
const closeLock = vi.fn();
let mockMode: 'soft' | 'hard' | null = null;

vi.mock('$lib/drive/locks.svelte', () => ({
	driveLocks: {
		get mode() {
			return mockMode;
		},
		openForEdit: (...a: unknown[]) => {
			// Mirrors the real store's escalation-only rule: an existing 'hard'
			// hold is never silently downgraded by a routine soft (re-)open.
			if (mockMode === null) mockMode = 'soft';
			return openForEdit(...a);
		},
		checkOut: (...a: unknown[]) => {
			mockMode = 'hard';
			return checkOut(...a);
		},
		close: (...a: unknown[]) => {
			mockMode = null;
			return closeLock(...a);
		},
	},
}));

const nativeOffice = vi.hoisted(() => ({
	enabled: false,
	choices: vi.fn(),
	open: vi.fn(),
}));

vi.mock('$lib/native', () => ({
	hasCapability: () => nativeOffice.enabled,
	getNative: () => ({
		driveMirror: {
			version: 3,
			officeChoices: (...a: unknown[]) => nativeOffice.choices(...a),
			openOffice: (...a: unknown[]) => nativeOffice.open(...a),
		},
	}),
}));

function node(overrides: Partial<DriveNode> = {}): DriveNode {
	return { id: 5, parentId: null, kind: 'file', name: 'report.xlsx', branchCount: 1, lock: null, headVersionId: 20, ...overrides };
}

function version(overrides: Partial<DriveVersion> = {}): DriveVersion {
	return {
		id: 20,
		parentVersionId: 19,
		conflictOf: null,
		sha256: 'x',
		size: 1024,
		author: 1,
		previewStatus: 'none',
		createdAt: '2026-07-10T00:00:00Z',
		branchId: null,
		labels: [],
		...overrides,
	};
}

function branch(overrides: Partial<DriveBranch> = {}): DriveBranch {
	return {
		id: 3,
		name: 'budget-redo',
		status: 'open',
		autoCreated: false,
		headVersionId: 21,
		forkedFromVersionId: 19,
		createdBy: 1,
		createdAt: '2026-07-09T00:00:00Z',
		resolvedBy: null,
		resolvedAt: null,
		ffEligible: true,
		...overrides,
	};
}

const noop = vi.fn();

describe('VersionDrawer — P4 lanes + labels', () => {
	beforeEach(() => {
		listBranches.mockReset();
		history.mockReset();
		setLabel.mockReset();
		removeLabel.mockReset();
		setWatch.mockReset();
		removeWatch.mockReset();
		listWatches.mockReset();
		listWatches.mockResolvedValue([]); // driveWatches store's mount-time load()
		history.mockRejectedValue(new Error('history unavailable'));
		officeChoices.mockReset();
		officeLaunch.mockReset();
		officeChoices.mockRejectedValue({ status: 404 });
		nativeOffice.enabled = false;
		nativeOffice.choices.mockReset();
		nativeOffice.open.mockReset();
		driveWatches.rows = []; // the shared store singleton — reset between tests
		openForEdit.mockReset();
		checkOut.mockReset();
		closeLock.mockReset();
		mockMode = null;
	});

	it('discovers an available web editor and submits the WOPI launch form without exposing the token in the URL', async () => {
		listBranches.mockResolvedValue([]);
		officeChoices.mockResolvedValue({
			choices: [{ providerId: 'collabora', kind: 'web', available: true, reason: null }],
			localOpenAllowed: false,
		});
		officeLaunch.mockResolvedValue({
			launchId: 'launch-1', editorUrl: 'https://office.test/browser/editor.html',
			accessToken: 'opaque-token', expiresAt: '2026-08-25T00:00:00Z',
		});
		const submit = vi.spyOn(HTMLFormElement.prototype, 'submit').mockImplementation(() => undefined);
		render(VersionDrawer, {
			node: node(), spaceId: 8, versions: [version()], loading: false, classification: 'regular', canWrite: true,
			onClose: noop, onRestoreAsNew: noop, onUploadNewVersion: noop, onView: noop,
		});
		const edit = await screen.findByRole('button', { name: /collabora/i });
		await fireEvent.click(edit);
		await vi.waitFor(() => expect(officeLaunch).toHaveBeenCalledWith(5, expect.objectContaining({
			baseVersionId: 20, providerId: 'collabora', cohortKey: 'file-5',
		})));
		expect(submit).toHaveBeenCalledOnce();
		expect(document.querySelector('form[action="https://office.test/browser/editor.html"]')).toBeNull();
	});

	it('surfaces web launch errors and keeps the existing version actions available', async () => {
		listBranches.mockResolvedValue([]);
		officeChoices.mockResolvedValue({
			choices: [{ providerId: 'collabora', kind: 'web', available: true, reason: null }],
			localOpenAllowed: false,
		});
		officeLaunch.mockRejectedValue(new Error('provider unavailable'));
		render(VersionDrawer, {
			node: node(), versions: [version()], loading: false, classification: 'regular', canWrite: true,
			onClose: noop, onRestoreAsNew: noop, onUploadNewVersion: noop, onView: noop,
		});
		await fireEvent.click(await screen.findByRole('button', { name: /collabora/i }));
		await vi.waitFor(() => expect(screen.getByText('An error occurred')).toBeTruthy());
		expect(screen.getByText('Download')).toBeTruthy();
	});

	it('uses the native Drive mirror for desktop Office choices and local open', async () => {
		listBranches.mockResolvedValue([]);
		nativeOffice.enabled = true;
		officeChoices.mockResolvedValue({ choices: [], localOpenAllowed: true });
		nativeOffice.choices.mockResolvedValue([{ id: 'wps-office', label: 'WPS Office' }]);
		nativeOffice.open.mockResolvedValue({ status: 'opened' });
		render(VersionDrawer, {
			node: node(), spaceId: 8, versions: [version()], loading: false, classification: 'regular', canWrite: true,
			onClose: noop, onRestoreAsNew: noop, onUploadNewVersion: noop, onView: noop,
		});
		await fireEvent.click(await screen.findByRole('button', { name: /WPS Office/i }));
		await vi.waitFor(() => expect(nativeOffice.open).toHaveBeenCalledWith(8, 5, 'wps-office'));
		expect(officeChoices).toHaveBeenCalledWith(5, 'electron');
	});

	it('rejects local open when the Drive space identity is unavailable', async () => {
		listBranches.mockResolvedValue([]);
		nativeOffice.enabled = true;
		officeChoices.mockResolvedValue({ choices: [], localOpenAllowed: true });
		nativeOffice.choices.mockResolvedValue([{ id: 'libreoffice', label: 'LibreOffice' }]);
		render(VersionDrawer, {
			node: node(), versions: [version()], loading: false, classification: 'regular', canWrite: true,
			onClose: noop, onRestoreAsNew: noop, onUploadNewVersion: noop, onView: noop,
		});
		await fireEvent.click(await screen.findByRole('button', { name: /LibreOffice/i }));
		await vi.waitFor(() => expect(screen.getByText('The desktop editor could not be opened.')).toBeTruthy());
		expect(nativeOffice.open).not.toHaveBeenCalled();
	});

	it('groups the head version into a Main lane and a branch version into its own named lane', async () => {
		listBranches.mockResolvedValue([branch()]);
		render(VersionDrawer, {
			node: node(),
			versions: [version({ id: 21, branchId: 3, createdAt: '2026-07-10T01:00:00Z' }), version({ id: 20 })],
			loading: false,
			classification: 'regular',
			canWrite: true,
			onClose: noop,
			onRestoreAsNew: noop,
			onUploadNewVersion: noop,
			onView: noop,
		});
		expect(screen.getByText('Main')).toBeTruthy();
		await vi.waitFor(() => expect(screen.getByText('budget-redo')).toBeTruthy());
	});

	it('marks the version whose id matches node.headVersionId as Current, not merely the newest row', async () => {
		listBranches.mockResolvedValue([]);
		render(VersionDrawer, {
			node: node({ headVersionId: 20 }),
			versions: [version({ id: 21, branchId: 3, createdAt: '2026-07-10T01:00:00Z' }), version({ id: 20 })],
			loading: false,
			classification: 'regular',
			canWrite: true,
			onClose: noop,
			onRestoreAsNew: noop,
			onUploadNewVersion: noop,
			onView: noop,
		});
		await vi.waitFor(() => expect(listBranches).toHaveBeenCalled());
		expect(screen.getAllByText('Current')).toHaveLength(1);
	});

	it('renders label chips and removes one via the remove button', async () => {
		listBranches.mockResolvedValue([]);
		removeLabel.mockResolvedValue(undefined);
		const onLabelsChanged = vi.fn();
		render(VersionDrawer, {
			node: node(),
			versions: [version({ labels: ['Approved v2'] })],
			loading: false,
			classification: 'regular',
			canWrite: true,
			onClose: noop,
			onRestoreAsNew: noop,
			onUploadNewVersion: noop,
			onView: noop,
			onLabelsChanged,
		});
		await vi.waitFor(() => expect(screen.getByText('Approved v2')).toBeTruthy());
		await fireEvent.click(screen.getByRole('button', { name: 'Remove label Approved v2' }));
		await vi.waitFor(() => expect(removeLabel).toHaveBeenCalledWith(20, 'Approved v2'));
		await vi.waitFor(() => expect(onLabelsChanged).toHaveBeenCalled());
	});

	it('adds a label via the inline add-label input', async () => {
		listBranches.mockResolvedValue([]);
		setLabel.mockResolvedValue(undefined);
		render(VersionDrawer, {
			node: node(),
			versions: [version()],
			loading: false,
			classification: 'regular',
			canWrite: true,
			onClose: noop,
			onRestoreAsNew: noop,
			onUploadNewVersion: noop,
			onView: noop,
		});
		await vi.waitFor(() => expect(listBranches).toHaveBeenCalled());
		await fireEvent.click(screen.getByRole('button', { name: 'Add label' }));
		const input = screen.getByPlaceholderText('e.g. Approved v2');
		await fireEvent.input(input, { target: { value: 'Final' } });
		await fireEvent.keyDown(input, { key: 'Enter' });
		await vi.waitFor(() => expect(setLabel).toHaveBeenCalledWith(20, 'Final'));
	});

	it('offers a Compare button on a non-current row (never on the current one) that opens CompareView against the current version', async () => {
		listBranches.mockResolvedValue([]);
		render(VersionDrawer, {
			node: node({ headVersionId: 20 }),
			versions: [
				version({ id: 21, size: 2048, sha256: 'y', createdAt: '2026-07-10T01:00:00Z' }),
				version({ id: 20, size: 1024, sha256: 'x' }),
			],
			loading: false,
			classification: 'regular',
			canWrite: true,
			onClose: noop,
			onRestoreAsNew: noop,
			onUploadNewVersion: noop,
			onView: noop,
		});
		await vi.waitFor(() => expect(listBranches).toHaveBeenCalled());
		const compareButtons = screen.getAllByRole('button', { name: 'Compare' });
		expect(compareButtons).toHaveLength(1);
		await fireEvent.click(compareButtons[0]);
		expect(screen.getByText('Compare versions')).toBeTruthy();
		expect(screen.getByText('Content differs')).toBeTruthy();
	});

	it('soft auto-opens the lock store for an office file type on mount when canWrite', async () => {
		listBranches.mockResolvedValue([]);
		render(VersionDrawer, {
			node: node({ name: 'report.xlsx' }),
			versions: [version()],
			loading: false,
			classification: 'regular',
			canWrite: true,
			onClose: noop,
			onRestoreAsNew: noop,
			onUploadNewVersion: noop,
			onView: noop,
		});
		await vi.waitFor(() => expect(openForEdit).toHaveBeenCalledWith(5, { name: 'report.xlsx', versionId: 20, branchId: null }));
	});

	it('does not open the lock store when the caller cannot write', async () => {
		listBranches.mockResolvedValue([]);
		render(VersionDrawer, {
			node: node({ name: 'report.xlsx' }),
			versions: [version()],
			loading: false,
			classification: 'regular',
			canWrite: false,
			onClose: noop,
			onRestoreAsNew: noop,
			onUploadNewVersion: noop,
			onView: noop,
		});
		await vi.waitFor(() => expect(listBranches).toHaveBeenCalled());
		expect(openForEdit).not.toHaveBeenCalled();
	});

	it('shows "Check out" when not holding a lock; clicking it escalates to hard', async () => {
		listBranches.mockResolvedValue([]);
		mockMode = null;
		render(VersionDrawer, {
			node: node({ name: 'report.xlsx' }),
			versions: [version()],
			loading: false,
			classification: 'regular',
			canWrite: true,
			onClose: noop,
			onRestoreAsNew: noop,
			onUploadNewVersion: noop,
			onView: noop,
		});
		await vi.waitFor(() => expect(openForEdit).toHaveBeenCalled());
		await fireEvent.click(screen.getByRole('button', { name: 'Check out' }));
		expect(checkOut).toHaveBeenCalled();
	});

	it('shows "Check in" when holding a lock; clicking it releases', async () => {
		listBranches.mockResolvedValue([]);
		mockMode = 'hard';
		render(VersionDrawer, {
			node: node({ name: 'report.xlsx' }),
			versions: [version()],
			loading: false,
			classification: 'regular',
			canWrite: true,
			onClose: noop,
			onRestoreAsNew: noop,
			onUploadNewVersion: noop,
			onView: noop,
		});
		await vi.waitFor(() => expect(listBranches).toHaveBeenCalled());
		await fireEvent.click(screen.getByRole('button', { name: 'Check in' }));
		expect(closeLock).toHaveBeenCalled();
	});

	it('watch toggle: calls setWatch then removeWatch, flipping aria-pressed (via the shared driveWatches store)', async () => {
		listBranches.mockResolvedValue([]);
		setWatch.mockResolvedValue(undefined);
		removeWatch.mockResolvedValue(undefined);
		// mount load() -> [], post-setWatch refresh -> [watched], post-removeWatch refresh -> []
		listWatches
			.mockResolvedValueOnce([])
			.mockResolvedValueOnce([{ nodeId: 5, nodeName: 'notes.txt', kind: 'file', ops: null }])
			.mockResolvedValueOnce([]);
		render(VersionDrawer, {
			node: node({ name: 'notes.txt' }),
			versions: [version()],
			loading: false,
			classification: 'regular',
			canWrite: true,
			onClose: noop,
			onRestoreAsNew: noop,
			onUploadNewVersion: noop,
			onView: noop,
		});
		await vi.waitFor(() => expect(listBranches).toHaveBeenCalled());
		const watchBtn = screen.getByRole('button', { name: 'Watch' });
		expect(watchBtn.getAttribute('aria-pressed')).toBe('false');
		await fireEvent.click(watchBtn);
		await vi.waitFor(() => expect(setWatch).toHaveBeenCalledWith(5, undefined));
		await vi.waitFor(() => expect(watchBtn.getAttribute('aria-pressed')).toBe('true'));
		await fireEvent.click(watchBtn);
		await vi.waitFor(() => expect(removeWatch).toHaveBeenCalledWith(5));
		await vi.waitFor(() => expect(watchBtn.getAttribute('aria-pressed')).toBe('false'));
	});

	it('watch toggle propagates to a second independent reader of the same store (Task 13 behavior fix)', async () => {
		listBranches.mockResolvedValue([]);
		setWatch.mockResolvedValue(undefined);
		listWatches
			.mockResolvedValueOnce([])
			.mockResolvedValueOnce([{ nodeId: 5, nodeName: 'notes.txt', kind: 'file', ops: null }]);
		render(VersionDrawer, {
			node: node({ name: 'notes.txt' }),
			versions: [version()],
			loading: false,
			classification: 'regular',
			canWrite: true,
			onClose: noop,
			onRestoreAsNew: noop,
			onUploadNewVersion: noop,
			onView: noop,
		});
		await vi.waitFor(() => expect(listBranches).toHaveBeenCalled());
		expect(driveWatches.isWatched(5)).toBe(false);
		await fireEvent.click(screen.getByRole('button', { name: 'Watch' }));
		// A second, independent reader of the SAME store (no fetch of its own) sees the change.
		await vi.waitFor(() => expect(driveWatches.isWatched(5)).toBe(true));
	});

	it('P5: a gxp version row offers export/print requests instead of a plain download link', async () => {
		listBranches.mockResolvedValue([]);
		render(VersionDrawer, {
			node: node(),
			versions: [version()],
			loading: false,
			classification: 'gxp',
			canWrite: true,
			onClose: noop,
			onRestoreAsNew: noop,
			onUploadNewVersion: noop,
			onView: noop,
		});
		await vi.waitFor(() => expect(listBranches).toHaveBeenCalled());
		expect(screen.getByRole('button', { name: 'Request download' })).toBeTruthy();
		expect(screen.getByRole('button', { name: 'Request print' })).toBeTruthy();
		expect(screen.queryByRole('link', { name: /download/i })).toBeNull();
	});

	it('renders H0 Current/Timeline/Details tabs, coverage, and cursor pagination', async () => {
		listBranches.mockResolvedValue([]);
		const firstPage = {
			items: [{
				occurredAt: '2026-07-10T02:00:00Z',
				sourceRank: 1,
				sourceId: 'v-20',
				source: 'versions',
				kind: 'version_created',
				details: { summary: 'Saved from the desktop client' },
			}],
			hasMore: true,
			nextCursor: 'next/1',
			coverage: { mode: 'partial', freshnessSeconds: 45, coveredSources: ['versions'], omissions: ['audit'] },
			generatedAt: '2026-07-10T02:00:01Z',
		};
		history.mockResolvedValueOnce(firstPage).mockResolvedValueOnce({
			...firstPage,
			items: [{
				occurredAt: '2026-07-09T02:00:00Z',
				sourceRank: 2,
				sourceId: 'a-19',
				source: 'audit',
				kind: 'rename',
				details: { name: 'report.xlsx' },
			}],
			hasMore: false,
			nextCursor: null,
		});
		render(VersionDrawer, {
			node: node(),
			versions: [version()],
			loading: false,
			classification: 'regular',
			canWrite: true,
			onClose: noop,
			onRestoreAsNew: noop,
			onUploadNewVersion: noop,
			onView: noop,
		});

		await vi.waitFor(() => expect(screen.getByRole('tab', { name: 'Timeline' })).toBeTruthy());
		expect(screen.getByRole('tab', { name: 'Current' })).toBeTruthy();
		expect(screen.getByRole('tab', { name: 'Details' })).toBeTruthy();
		await fireEvent.click(screen.getByRole('tab', { name: 'Timeline' }));
		expect(screen.getByText('Saved version')).toBeTruthy();
		expect(screen.getByText('History is 45 seconds behind.')).toBeTruthy();
		expect(screen.getByText('Unavailable sources: audit.')).toBeTruthy();
		expect(screen.getByText('Saved from the desktop client')).toBeTruthy();

		await fireEvent.click(screen.getByRole('button', { name: 'Load more' }));
		await vi.waitFor(() => expect(history).toHaveBeenLastCalledWith(5, { limit: 50, cursor: 'next/1' }));
		await vi.waitFor(() => expect(screen.getByText('Renamed')).toBeTruthy());
		await fireEvent.click(screen.getByRole('tab', { name: 'Details' }));
		expect(screen.getAllByText('Source ID').length).toBeGreaterThan(0);
		expect(screen.getByText('a-19')).toBeTruthy();
	});

	it('hides history tabs when the endpoint is not available', async () => {
		listBranches.mockResolvedValue([]);
		history.mockRejectedValue({ status: 404 });
		render(VersionDrawer, {
			node: node(),
			versions: [version()],
			loading: false,
			classification: 'regular',
			canWrite: true,
			onClose: noop,
			onRestoreAsNew: noop,
			onUploadNewVersion: noop,
			onView: noop,
		});
		await vi.waitFor(() => expect(history).toHaveBeenCalled());
		expect(screen.queryByRole('tab', { name: 'Timeline' })).toBeNull();
		expect(screen.queryByRole('tab', { name: 'Details' })).toBeNull();
		expect(screen.getByText('Current')).toBeTruthy();
	});

	it('shows a retryable history error without removing version actions', async () => {
		listBranches.mockResolvedValue([]);
		const result = {
			items: [],
			hasMore: false,
			nextCursor: null,
			coverage: { mode: 'complete', freshnessSeconds: 0, coveredSources: [], omissions: [] },
			generatedAt: '2026-07-10T02:00:01Z',
		};
		history.mockRejectedValueOnce(new Error('history down')).mockResolvedValueOnce(result);
		render(VersionDrawer, {
			node: node(),
			versions: [version()],
			loading: false,
			classification: 'regular',
			canWrite: true,
			onClose: noop,
			onRestoreAsNew: noop,
			onUploadNewVersion: noop,
			onView: noop,
		});
		await vi.waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Could not load file history.'));
		expect(screen.getByText('Download')).toBeTruthy();
		await fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
		await vi.waitFor(() => expect(screen.getByRole('tab', { name: 'Timeline' })).toBeTruthy());
	});
});
