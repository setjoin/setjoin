// PresentationPicker.test.ts — MEET plan M3 picker states: Drive skeleton →
// supported-file list → version select → rendition prepare (progress) →
// private preview with the fidelity-warning banner → Present; plus the
// supported-files empty state and the named conversion failure.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/svelte/svelte5';
import PresentationPicker from './PresentationPicker.svelte';
import { PresentationStore } from '$lib/meet/presentationStore.svelte';
import type { PresentationApi, PresentationManifest, PresentationPage } from '$lib/meet/presentationApi';
import type { PresentationCheckpoint } from '$lib/meet/presentationCheckpoint';
import type { MeetRoom } from '$lib/meet/room.svelte';
import { clearToasts } from '$lib/components/ui';

vi.mock('$lib/drive/api', () => ({
	listSpaces: vi.fn(),
	tree: vi.fn(),
	listVersions: vi.fn(),
}));

import * as driveApi from '$lib/drive/api';

const SPACES = [{ id: 1, name: 'Acme', isPersonal: false, classification: 'regular', role: 'editor', usedBytes: 0, quotaBytes: null, changeSeq: 1 }];
const NODES = [
	{ id: 11, parentId: null, kind: 'folder', name: 'Decks', branchCount: 0, lock: null },
	{ id: 12, parentId: null, kind: 'file', name: 'launch.pdf', headVersionId: 3, branchCount: 0, lock: null },
	{ id: 13, parentId: null, kind: 'file', name: 'notes.docx', headVersionId: 1, branchCount: 0, lock: null },
];
const VERSIONS = [
	{ id: 1, parentVersionId: null, conflictOf: null, sha256: 'a', size: 10, author: 1, previewStatus: 'ready', createdAt: '2026-01-01T00:00:00Z', branchId: null, labels: [] },
	{ id: 3, parentVersionId: 1, conflictOf: null, sha256: 'b', size: 12, author: 1, previewStatus: 'ready', createdAt: '2026-01-02T00:00:00Z', branchId: null, labels: [] },
];

const assetRef = {
	path: '/api/meet/42/presentation/p1/pages/0/full',
	mimeType: 'image/png',
	byteSize: 1024,
	sha256: 'a'.repeat(64),
	expiresAt: '2026-09-18T01:00:00Z',
	ttlMs: 60_000,
};

function page(index: number): PresentationPage {
	return { index, id: `pg-${index}`, widthPx: 100, heightPx: 100, contentSha256: 'b'.repeat(64), byteSize: 1, mimeType: 'image/png', thumbnail: assetRef, fullPage: assetRef };
}

function manifest(warnings: string[] = []): PresentationManifest {
	return {
		schema: 'meet-pages-v1',
		driveNodeId: 12,
		driveVersionId: 3,
		sourceSha256: 'c'.repeat(64),
		pages: [page(0), page(1)],
		warnings: warnings as never,
		rendererId: 'r',
		rendererVersion: '1',
		fontPackDigest: 'd'.repeat(64),
		integrityDigest: 'e'.repeat(64),
		completedAt: '2026-09-18T00:00:00Z',
	};
}

function checkpoint(over: Partial<PresentationCheckpoint> = {}): PresentationCheckpoint {
	return {
		presentationId: 9,
		status: 'ACTIVE',
		checkpointSeq: 1,
		presenterGeneration: 1,
		presenterParticipantId: 7,
		pageIndex: 0,
		manifestGeneration: 1,
		manifestDigest: 'd1',
		driveNodeId: 12,
		driveVersionId: 3,
		myParticipantId: 7,
		amPresenter: true,
		...over,
	};
}

function fakeApi(over: Partial<PresentationApi> = {}): PresentationApi {
	return {
		prepare: vi.fn(async () => ({ presentationId: 9, status: 'PREPARING', checkpointSeq: 0 })),
		start: vi.fn(async () => ({ presentationId: 9, status: 'ACTIVE', checkpointSeq: 2, presenterGeneration: 1, pageIndex: 0, manifestGeneration: 1 })),
		getCheckpoint: vi.fn(async () => checkpoint({ status: 'READY' })),
		getManifest: vi.fn(async () => manifest(['animation_unsupported'])),
		changePage: vi.fn(),
		grantPresenter: vi.fn(),
		end: vi.fn(async () => undefined),
		fetchText: vi.fn(),
		...over,
	};
}

async function mountedPicker(api: Partial<PresentationApi> = {}) {
	const store = new PresentationStore(fakeApi(api), { sleep: () => Promise.resolve() });
	store.enabled = true;
	store.bind(42, () => null);
	store.attach({
		setPresentationContext: vi.fn(),
		onPresentation: vi.fn(),
		onStage: vi.fn(),
		sendPresentationFrame: vi.fn(() => true),
		sendStageEvent: vi.fn(() => true),
	} as unknown as MeetRoom);
	store.pickerOpen = true;
	render(PresentationPicker, { presentation: store, onClose: vi.fn() });
	return store;
}

beforeEach(() => {
	vi.mocked(driveApi.listSpaces).mockResolvedValue(SPACES as never);
	vi.mocked(driveApi.tree).mockResolvedValue(NODES as never);
	vi.mocked(driveApi.listVersions).mockResolvedValue(VERSIONS as never);
	clearToasts();
});
afterEach(() => cleanup());

describe('PresentationPicker — browse', () => {
	it('lists spaces and ONLY the supported launch-mode files (unsupported extensions filtered)', async () => {
		await mountedPicker();
		await waitFor(() => expect(screen.getByTestId('picker-file-12')).toBeTruthy());
		expect(screen.queryByTestId('picker-file-13')).toBeNull(); // .docx is post-launch
		expect(screen.getByTestId('picker-file-12').textContent).toContain('launch.pdf');
	});

	it('an unsupported tree shows the explanatory empty state with the Drive action', async () => {
		vi.mocked(driveApi.tree).mockResolvedValue([{ id: 13, parentId: null, kind: 'file', name: 'notes.docx', branchCount: 0, lock: null }] as never);
		await mountedPicker();
		await waitFor(() => expect(screen.getAllByText(/Pick a PDF or slide deck/).length).toBeGreaterThan(0));
		expect(screen.getByText('Open Drive')).toBeTruthy();
	});

	it('a tree failure offers retry, which re-reads Drive', async () => {
		vi.mocked(driveApi.tree).mockRejectedValueOnce(new Error('down')).mockResolvedValue(NODES as never);
		await mountedPicker();
		await waitFor(() => expect(screen.getByTestId('picker-retry')).toBeTruthy());
		await fireEvent.click(screen.getByTestId('picker-retry'));
		await waitFor(() => expect(screen.getByTestId('picker-file-12')).toBeTruthy());
	});
});

describe('PresentationPicker — prepare → preview → present', () => {
	it('closing during PREPARING drains the accepted preparation and ignores its pending checkpoint', async () => {
		let resolveCheckpoint!: (value: PresentationCheckpoint) => void;
		const getCheckpoint = vi.fn(() => new Promise<PresentationCheckpoint>((resolve) => { resolveCheckpoint = resolve; }));
		const end = vi.fn(async () => undefined);
		const store = await mountedPicker({ getCheckpoint, end });
		await fireEvent.click(await screen.findByTestId('picker-file-12'));
		await fireEvent.click(await screen.findByTestId('picker-prepare'));
		await waitFor(() => expect(getCheckpoint).toHaveBeenCalledWith(42, 9));
		expect(store.prep?.status).toBe('PREPARING');
		await fireEvent.click(screen.getByRole('button', { name: 'Close' }));
		resolveCheckpoint(checkpoint({ status: 'READY' }));
		await waitFor(() => expect(end).toHaveBeenCalledWith(42, 9));
		expect(store.pickerOpen).toBe(false);
		expect(store.prep).toBeNull();
		expect(store.checkpoint).toBeNull();
		expect(getCheckpoint).toHaveBeenCalledTimes(1);
		store.reset();
	});

	it('dismissing the dialog does not cancel an already ACTIVE presentation', async () => {
		const end = vi.fn(async () => undefined);
		const store = await mountedPicker({ getCheckpoint: vi.fn(async () => checkpoint()), end });
		store.bind(42, () => checkpoint());
		await store.sync();
		await fireEvent.click(screen.getByRole('button', { name: 'Close' }));
		expect(store.isLive).toBe(true);
		expect(store.checkpoint?.presentationId).toBe(9);
		expect(end).not.toHaveBeenCalled();
		store.reset();
	});

	it('preparing shows progress; READY lands the private preview with the warning banner', async () => {
		const store = await mountedPicker();
		await waitFor(() => fireEvent.click(screen.getByTestId('picker-file-12')));
		await waitFor(() => expect(screen.getByTestId('picker-prepare')).toBeTruthy());
		await fireEvent.click(screen.getByTestId('picker-prepare'));
		await waitFor(() => expect(store.isPreviewing).toBe(true));
		expect(screen.getByTestId('picker-warnings').textContent).toContain('Animations are not supported');
		expect(screen.getByTestId('picker-present')).toBeTruthy();
	});

	it('Present commits the session and closes the picker', async () => {
		const store = await mountedPicker();
		await waitFor(() => fireEvent.click(screen.getByTestId('picker-file-12')));
		await fireEvent.click(await screen.findByTestId('picker-prepare'));
		await waitFor(() => expect(store.isPreviewing).toBe(true));
		await fireEvent.click(screen.getByTestId('picker-present'));
		await waitFor(() => expect(store.isLive).toBe(true));
		expect(store.pickerOpen).toBe(false);
	});

	it('a rejected prepare surfaces the named failure copy', async () => {
		await mountedPicker({ prepare: vi.fn(async () => { throw { code: 'documentProtected' }; }) });
		await waitFor(() => fireEvent.click(screen.getByTestId('picker-file-12')));
		await fireEvent.click(await screen.findByTestId('picker-prepare'));
		await waitFor(() => expect(screen.getByTestId('picker-failure').textContent).toContain('Remove protection locally'));
	});
});
