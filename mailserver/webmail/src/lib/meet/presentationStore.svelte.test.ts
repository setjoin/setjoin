// presentationStore.svelte.test.ts — MEET plan M3 store behavior against a
// fake PresentationApi + a fake room (the RoomWhiteboardOps structural-fake
// genre), wired to the LANDED M2 shapes (`./presentationCheckpoint`). Locks
// the plan's central rules: state promotes ONLY from API responses (frames
// and presentation_state pushes are hints fed to the frozen
// CheckpointRefresher), the presenter render gate uses the server-derived
// amPresenter and never issues unauthorized mutations, reauthorization goes
// through the join/read summary + the authorized checkpoint read, teardown
// fails the frame classifier closed, and the ephemeral stage plane
// (pointer/ink) is TTL'd, capped, cleared on transitions, and never rendered
// outside a live session.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { PresentationStore, manifestPages } from './presentationStore.svelte';
import type { PresentationMutationResponse, PresentationCheckpoint } from './presentationCheckpoint';
import type {
	PresentationApi,
	PresentationManifest,
	PresentationPage,
} from './presentationApi';
import type { MeetingPresentationSummary } from './api';
import type { MeetRoom, StageEvent } from './room.svelte';
import { POINTER_TTL_MS } from './presentationClient';
import { clearToasts } from '$lib/components/ui';

// ── fixtures (the M2 wire shapes) ─────────────────────────────────────────

const assetRef = {
	path: '/api/meet/42/presentation/1/pages/0/full',
	mimeType: 'image/png',
	byteSize: 1024,
	sha256: 'a'.repeat(64),
	expiresAt: '2026-09-18T01:00:00Z',
	ttlMs: 60_000,
};

function page(index: number): PresentationPage {
	return {
		index,
		id: `pg-${index}`,
		widthPx: 1024,
		heightPx: 768,
		contentSha256: 'b'.repeat(64),
		byteSize: 2048,
		mimeType: 'image/png',
		thumbnail: assetRef,
		fullPage: assetRef,
		accessibleRepresentation: assetRef,
	};
}

function manifest(over: Partial<PresentationManifest> = {}): PresentationManifest {
	return {
		schema: 'meet-pages-v1',
		driveNodeId: 7,
		driveVersionId: 9,
		sourceSha256: 'c'.repeat(64),
		pages: [page(0), page(1), page(2)],
		notes: { ...assetRef, requiresPresenterPermission: true },
		warnings: [],
		rendererId: 'renderer',
		rendererVersion: '1',
		fontPackDigest: 'd'.repeat(64),
		integrityDigest: 'e'.repeat(64),
		completedAt: '2026-09-18T00:00:00Z',
		...over,
	};
}

function checkpoint(over: Partial<PresentationCheckpoint> = {}): PresentationCheckpoint {
	return {
		presentationId: 1,
		status: 'ACTIVE',
		checkpointSeq: 10,
		presenterGeneration: 3,
		presenterParticipantId: 7,
		pageIndex: 0,
		manifestGeneration: 1,
		manifestDigest: 'd1',
		driveNodeId: 7,
		driveVersionId: 9,
		myParticipantId: 7,
		amPresenter: true,
		...over,
	};
}

function fact(over: Partial<PresentationMutationResponse> = {}): PresentationMutationResponse {
	return { presentationId: 1, status: 'ACTIVE', checkpointSeq: 11, presenterGeneration: 3, pageIndex: 1, manifestGeneration: 1, ...over };
}

function summary(over: Partial<MeetingPresentationSummary> = {}): MeetingPresentationSummary {
	return {
		presentationId: 1,
		status: 'ACTIVE',
		checkpointSeq: 10,
		presenterGeneration: 3,
		presenterParticipantId: 7,
		pageIndex: 0,
		manifestGeneration: 1,
		manifestDigest: 'd1',
		driveNodeId: 7,
		driveVersionId: 9,
		...over,
	};
}

/** Structural fake of the MeetRoom subset the store touches. */
function fakeRoom() {
	return {
		contexts: [] as { presentationId: string | null; confirmedSeq: number; knownGeneration: number }[],
		presentationCb: null as ((seq: number) => void) | null,
		stageCb: null as ((event: StageEvent, from: string) => void) | null,
		sentFrames: [] as Record<string, unknown>[],
		sentStage: [] as StageEvent[],
		setPresentationContext(ctx: { presentationId: string | null; confirmedSeq: number; knownGeneration: number }): void {
			this.contexts.push(ctx);
		},
		onPresentation(cb: ((seq: number) => void) | null): void {
			this.presentationCb = cb;
		},
		onStage(cb: ((event: StageEvent, from: string) => void) | null): void {
			this.stageCb = cb;
		},
		sendPresentationFrame(envelope: Record<string, unknown>): boolean {
			this.sentFrames.push(envelope);
			return true;
		},
		sendStageEvent(event: StageEvent): boolean {
			this.sentStage.push(event);
			return true;
		},
		fireHint(seq: number): void {
			this.presentationCb?.(seq);
		},
	};
}

type Room = ReturnType<typeof fakeRoom>;
type Api = Record<string, ReturnType<typeof vi.fn>>;

function fakeApi(): Api {
	return {
		prepare: vi.fn(),
		start: vi.fn(),
		getCheckpoint: vi.fn(),
		getManifest: vi.fn(),
		changePage: vi.fn(),
		grantPresenter: vi.fn(),
		end: vi.fn(),
		fetchText: vi.fn(),
	};
}

function build(api: Api = fakeApi(), room: Room | null = null, live: MeetingPresentationSummary | null = summary()): { store: PresentationStore; room: Room } {
	const r = room ?? fakeRoom();
	const store = new PresentationStore(api as unknown as PresentationApi, { sleep: () => Promise.resolve() });
	store.enabled = true;
	store.bind(42, () => live);
	store.attach(r as unknown as MeetRoom);
	return { store, room: r };
}

const flush = (): Promise<void> => new Promise((r) => setTimeout(r, 0));

beforeEach(() => {
	clearToasts();
});

afterEach(() => {
	vi.useRealTimers();
});

// ── manifest gate ─────────────────────────────────────────────────────────

describe('manifestPages gate', () => {
	it('accepts dense non-empty manifests and rejects zero-page / sparse ones', () => {
		expect(manifestPages(manifest())?.length).toBe(3);
		expect(manifestPages(manifest({ pages: [] }))).toBeNull();
		const sparse = manifest();
		(sparse.pages as PresentationPage[])[1].index = 5;
		expect(manifestPages(sparse)).toBeNull();
	});
});

// ── reauthorization (sync) ────────────────────────────────────────────────

describe('sync — reauthorization from the join/read projection', () => {
	it('promotes the authorized checkpoint read and sets the frame context (M2 seam)', async () => {
		const api = fakeApi();
		api.getCheckpoint.mockResolvedValue(checkpoint());
		api.getManifest.mockResolvedValue(manifest());
		const { store, room } = build(api);
		await store.sync();
		expect(api.getCheckpoint).toHaveBeenCalledWith(42, 1);
		expect(store.isLive).toBe(true);
		expect(store.pageCount).toBe(3);
		expect(store.amPresenter).toBe(true);
		expect(room.contexts.at(-1)).toEqual({ presentationId: '1', confirmedSeq: 10, knownGeneration: 3 });
	});

	it('a null summary CLEARS local state — no cached grant survives', async () => {
		const api = fakeApi();
		api.getCheckpoint.mockResolvedValue(checkpoint());
		api.getManifest.mockResolvedValue(manifest());
		const { store, room } = build(api, null, summary());
		await store.sync();
		expect(store.isLive).toBe(true);
		// the meeting projection withdrew the session (ended / non-participant)
		store.bind(42, () => null);
		await store.sync();
		expect(store.isLive).toBe(false);
		expect(store.checkpoint).toBeNull();
		expect(room.contexts.at(-1)).toEqual({ presentationId: null, confirmedSeq: 0, knownGeneration: 0 });
	});

	it('a terminal promoted checkpoint clears the session; REVOKED asserts', async () => {
		const api = fakeApi();
		api.getCheckpoint.mockResolvedValueOnce(checkpoint({ status: 'ENDED' })).mockResolvedValue(checkpoint({ status: 'REVOKED' }));
		api.getManifest.mockResolvedValue(manifest());
		const { store, room } = build(api);
		await store.sync();
		expect(store.isLive).toBe(false);
		expect(store.assertiveMessage.length).toBeGreaterThan(0);
		expect(room.contexts.at(-1)).toEqual({ presentationId: null, confirmedSeq: 0, knownGeneration: 0 });
		// revocation re-syncs through the same path and asserts again
		store.bind(42, () => summary());
		await store.sync();
		expect(store.assertiveMessage.length).toBeGreaterThan(0);
	});

	it('checkpoint-read failure keeps the last validated page marked stale, never infers ended', async () => {
		const api = fakeApi();
		api.getCheckpoint.mockResolvedValueOnce(checkpoint()).mockRejectedValueOnce(new Error('down'));
		api.getManifest.mockResolvedValue(manifest());
		const { store } = build(api);
		await store.sync();
		await store.sync();
		expect(store.isLive).toBe(true); // last truth kept
		expect(store.pageState).toBe('stale');
	});

	it('a manifest-read failure fails VISIBLY (generic failure), never fabricated pages', async () => {
		const api = fakeApi();
		api.getCheckpoint.mockResolvedValue(checkpoint());
		api.getManifest.mockRejectedValue(new Error('manifest serving not wired (M1)'));
		const { store } = build(api);
		await store.sync();
		expect(store.manifest).toBeNull();
		expect(store.failure).toEqual({ code: null });
	});

	it('does nothing while disabled (the default-OFF flag posture)', async () => {
		const api = fakeApi();
		const { store } = build(api);
		store.enabled = false;
		await store.sync();
		expect(api.getCheckpoint).not.toHaveBeenCalled();
		expect(store.checkpoint).toBeNull();
	});
});

// ── hints → bounded checkpoint refresh ────────────────────────────────────

describe('checkpoint-invalidation hints (frames + presentation_state pushes)', () => {
	it('a fresh-sequence hint triggers exactly one authorized getCheckpoint and promotes its response', async () => {
		const api = fakeApi();
		api.getCheckpoint.mockResolvedValue(checkpoint({ checkpointSeq: 12, pageIndex: 2 }));
		api.getManifest.mockResolvedValue(manifest());
		const { store, room } = build(api);
		await store.sync();
		const callsAfterSync = api.getCheckpoint.mock.calls.length;
		room.fireHint(12);
		await vi.waitFor(() => expect(store.pageIndex).toBe(2));
		// exactly ONE coalesced refresh for the hint (plus the initial sync)
		expect(api.getCheckpoint.mock.calls.length).toBe(callsAfterSync + 1);
		expect(room.contexts.at(-1)).toEqual({ presentationId: '1', confirmedSeq: 12, knownGeneration: 3 });
	});

	it('the public hint() (the presentation_state push path) feeds the same refresher', async () => {
		const api = fakeApi();
		api.getCheckpoint.mockResolvedValue(checkpoint({ checkpointSeq: 14 }));
		api.getManifest.mockResolvedValue(manifest());
		const { store, room } = build(api);
		await store.sync();
		store.hint();
		await vi.waitFor(() => expect(room.contexts.at(-1)?.confirmedSeq).toBe(14));
	});

	it('a burst of hints collapses into at most one in-flight + one pending refresh', async () => {
		const api = fakeApi();
		api.getCheckpoint.mockImplementation((...args: unknown[]) => {
			void args;
			return new Promise((res) => setTimeout(() => res(checkpoint({ checkpointSeq: 14 })), 5));
		});
		api.getManifest.mockResolvedValue(manifest());
		const { store, room } = build(api);
		await store.sync();
		room.fireHint(11);
		room.fireHint(12);
		room.fireHint(13);
		room.fireHint(14);
		await vi.waitFor(() => expect(store.checkpoint?.checkpointSeq).toBe(14));
		// ONE in-flight + ONE pending — the burst of 4 hints never queues 4 reads.
		await flush();
		expect(api.getCheckpoint.mock.calls.length).toBeLessThanOrEqual(3); // 1 sync + refresher coalescing
	});

	it('a throttled refresh marks stale and parks further hints for the backoff window', async () => {
		vi.useFakeTimers();
		const api = fakeApi();
		api.getCheckpoint.mockResolvedValueOnce(checkpoint()).mockRejectedValue({ code: 'checkpointRefreshThrottled', extensions: { retryAfterMs: 30_000 } });
		api.getManifest.mockResolvedValue(manifest());
		const { store, room } = build(api);
		await store.sync();
		room.fireHint(11);
		await vi.advanceTimersByTimeAsync(10);
		expect(store.pageState).toBe('stale');
		// 1 sync + 1 throttled refresh; inside Retry-After nothing more fires
		const calls = api.getCheckpoint.mock.calls.length;
		room.fireHint(12);
		await vi.advanceTimersByTimeAsync(1_000);
		expect(api.getCheckpoint.mock.calls.length).toBe(calls);
	});
});

// ── prepare → private preview → present ───────────────────────────────────

describe('prepare / preview / present', () => {
	it('polls the authorized read to READY, then promotes the private preview', async () => {
		const api = fakeApi();
		api.prepare.mockResolvedValue({ presentationId: 9, status: 'PREPARING', checkpointSeq: 0 });
		api.getCheckpoint.mockResolvedValueOnce(checkpoint({ presentationId: 9, status: 'PREPARING', amPresenter: true })).mockResolvedValue(checkpoint({ presentationId: 9, status: 'READY' }));
		api.getManifest.mockResolvedValue(manifest({ warnings: ['font_substituted'] }));
		const { store } = build(api, null, null);
		await store.prepare(7, 9, 'digest');
		expect(api.prepare).toHaveBeenCalledWith(42, { nodeId: 7, versionId: 9, manifestDigest: 'digest' });
		expect(store.prep).toBeNull();
		expect(store.isPreviewing).toBe(true);
		expect(store.manifest?.warnings).toEqual(['font_substituted']);
	});

	it('a FAILED rendition surfaces the failure state and clears prep', async () => {
		const api = fakeApi();
		api.prepare.mockResolvedValue({ presentationId: 9, status: 'PREPARING', checkpointSeq: 0 });
		api.getCheckpoint.mockResolvedValue(checkpoint({ presentationId: 9, status: 'FAILED' }));
		const { store } = build(api, null, null);
		await store.prepare(7, 9);
		expect(store.failure).toEqual({ code: null });
		expect(store.prep).toBeNull();
		expect(store.isPreviewing).toBe(false);
	});

	it('present commits READY → ACTIVE from the reducer fact and closes the picker', async () => {
		const api = fakeApi();
		api.getCheckpoint.mockResolvedValueOnce(checkpoint({ status: 'READY' })).mockResolvedValue(checkpoint({ status: 'READY' }));
		api.getManifest.mockResolvedValue(manifest());
		api.start.mockResolvedValue(fact({}));
		const { store, room } = build(api);
		await store.sync();
		await store.present();
		expect(api.start).toHaveBeenCalledWith(42, 1, 3);
		expect(store.isLive).toBe(true);
		expect(store.isPreviewing).toBe(false);
		expect(store.pickerOpen).toBe(false);
	});
});

// ── presenter mutations ───────────────────────────────────────────────────

describe('presenter mutations', () => {
	it('changePage sends the generation+sequence fence, promotes the fact, clears ink, broadcasts the hint', async () => {
		const api = fakeApi();
		api.getCheckpoint.mockResolvedValue(checkpoint());
		api.getManifest.mockResolvedValue(manifest());
		api.changePage.mockResolvedValue(fact({ pageIndex: 1, checkpointSeq: 11 }));
		const { store, room } = build(api);
		await store.sync();
		store.inkStrokes = [{ id: 'x', identity: 'self', points: [0.1, 0.1, 0.2, 0.2] }];
		await store.changePage(1);
		expect(api.changePage).toHaveBeenCalledWith(42, 1, { presenterGeneration: 3, checkpointSeq: 10 }, 1);
		expect(store.pageIndex).toBe(1);
		expect(store.inkStrokes).toEqual([]); // R5.5: transitions clear ephemeral ink
		expect(room.sentFrames.at(-1)).toMatchObject({ kind: 'page.changed', payload: { pageIndex: 1 }, checkpointSeq: 11 });
		expect(room.contexts.at(-1)?.confirmedSeq).toBe(11);
	});

	it('changePage is refused client-side for a non-presenter (render gate only)', async () => {
		const api = fakeApi();
		api.getCheckpoint.mockResolvedValue(checkpoint({ amPresenter: false }));
		api.getManifest.mockResolvedValue(manifest());
		const { store } = build(api);
		await store.sync();
		await store.changePage(1);
		expect(api.changePage).not.toHaveBeenCalled();
	});

	it('changePage clamps out-of-range targets into the manifest range', async () => {
		const api = fakeApi();
		api.getCheckpoint.mockResolvedValue(checkpoint());
		api.getManifest.mockResolvedValue(manifest());
		api.changePage.mockResolvedValue(fact({ pageIndex: 2, checkpointSeq: 12 }));
		const { store } = build(api);
		await store.sync();
		await store.changePage(99);
		expect(api.changePage).toHaveBeenCalledWith(42, 1, { presenterGeneration: 3, checkpointSeq: 10 }, 2);
	});

	it('a stalePresenterGeneration rejection refreshes the checkpoint (rescue registry)', async () => {
		const api = fakeApi();
		api.getCheckpoint
			.mockResolvedValueOnce(checkpoint()) // the initial sync
			.mockResolvedValue(checkpoint({ presenterGeneration: 9, amPresenter: false })); // the rescue read
		api.getManifest.mockResolvedValue(manifest());
		api.changePage.mockRejectedValue({ code: 'stalePresenterGeneration' });
		const { store } = build(api);
		await store.sync();
		await store.changePage(1);
		await vi.waitFor(() => expect(api.getCheckpoint.mock.calls.length).toBe(2));
		// controls adopt the CURRENT presenter: the local gate flips off
		expect(store.amPresenter).toBe(false);
	});

	it('grantPresenter targets a participant id and promotes; the old presenter is read-only at once', async () => {
		const api = fakeApi();
		api.getCheckpoint.mockResolvedValueOnce(checkpoint()).mockResolvedValueOnce(checkpoint());
		api.getManifest.mockResolvedValue(manifest());
		api.grantPresenter.mockResolvedValue(fact({ presenterGeneration: 4 }));
		const { store } = build(api);
		await store.sync();
		// simulate the promoted grant fact making someone else the presenter
		api.grantPresenter.mockResolvedValueOnce(fact({ presenterGeneration: 4 }));
		await store.grantPresenter(11);
		expect(api.grantPresenter).toHaveBeenCalledWith(42, 1, { targetParticipantId: 11, takeover: false, presenterGeneration: 3 });
		expect(store.pendingGrant).toBeNull();
		expect(store.politeMessage.length).toBeGreaterThan(0);
	});

	it('a rejected handoff surfaces the named reason and re-syncs', async () => {
		const api = fakeApi();
		api.getCheckpoint.mockResolvedValue(checkpoint());
		api.getManifest.mockResolvedValue(manifest());
		api.grantPresenter.mockRejectedValue({ code: 'stalePresenterGeneration' });
		const { store } = build(api);
		await store.sync();
		await store.grantPresenter(11);
		expect(store.handoffReason.length).toBeGreaterThan(0);
		expect(store.pendingGrant).toBeNull();
	});

	it('takeoverPresenter targets SELF via myParticipantId with takeover=true', async () => {
		const api = fakeApi();
		api.getCheckpoint.mockResolvedValueOnce(checkpoint({ amPresenter: false, myParticipantId: 12 })).mockResolvedValueOnce(checkpoint({ amPresenter: false, myParticipantId: 12 }));
		api.getManifest.mockResolvedValue(manifest());
		api.grantPresenter.mockResolvedValue(fact({ presenterGeneration: 5 }));
		const { store } = build(api);
		await store.sync();
		await store.takeoverPresenter();
		expect(api.grantPresenter).toHaveBeenCalledWith(42, 1, { targetParticipantId: 12, takeover: true, presenterGeneration: 3 });
		expect(store.politeMessage.length).toBeGreaterThan(0);
	});

	it('end is a drain verb: fire-and-recover, then the session clears fail-closed', async () => {
		const api = fakeApi();
		api.getCheckpoint.mockResolvedValue(checkpoint());
		api.getManifest.mockResolvedValue(manifest());
		const { store, room } = build(api);
		await store.sync();
		await store.end();
		expect(api.end).toHaveBeenCalledWith(42, 1, 3);
		expect(store.isLive).toBe(false);
		expect(room.contexts.at(-1)).toEqual({ presentationId: null, confirmedSeq: 0, knownGeneration: 0 });
	});
});

// ── notes (presenter-gated) ───────────────────────────────────────────────

describe('speaker notes', () => {
	it('loads notes only for the presenter; never for attendees', async () => {
		const api = fakeApi();
		api.getCheckpoint.mockResolvedValue(checkpoint());
		api.getManifest.mockResolvedValue(manifest());
		api.fetchText.mockResolvedValue('the secret notes');
		const { store } = build(api);
		await store.sync();
		await store.loadNotes();
		expect(api.fetchText).toHaveBeenCalledWith(manifest().notes);
		expect(store.notesState).toBe('ready');

		const api2 = fakeApi();
		api2.getCheckpoint.mockResolvedValue(checkpoint({ amPresenter: false }));
		api2.getManifest.mockResolvedValue(manifest());
		const s2 = build(api2).store;
		await s2.sync();
		await s2.loadNotes();
		expect(api2.fetchText).not.toHaveBeenCalled();
		expect(s2.notesState).toBe('idle');
	});

	it('a rendition without notes renders the explicit unavailable state', async () => {
		const api = fakeApi();
		api.getCheckpoint.mockResolvedValue(checkpoint());
		api.getManifest.mockResolvedValue(manifest({ notes: null }));
		const { store } = build(api);
		await store.sync();
		await store.loadNotes();
		expect(store.notesState).toBe('unavailable');
		expect(store.notesText).toBeNull();
	});
});

// ── ephemeral stage plane ─────────────────────────────────────────────────

describe('ephemeral stage plane', () => {
	it('pointer frames upsert per sender and TTL-sweep away', async () => {
		vi.useFakeTimers();
		const api = fakeApi();
		api.getCheckpoint.mockResolvedValue(checkpoint());
		api.getManifest.mockResolvedValue(manifest());
		const { store, room } = build(api);
		await store.sync();
		room.stageCb?.({ t: 'stage', v: 1, kind: 'pointer', seq: 1, x: 0.25, y: 0.75 }, 'u:2');
		room.stageCb?.({ t: 'stage', v: 1, kind: 'pointer', seq: 2, x: 0.5, y: 0.5 }, 'u:2');
		expect(store.remotePointers).toHaveLength(1);
		expect(store.remotePointers[0]).toMatchObject({ identity: 'u:2', x: 0.5 });
		await vi.advanceTimersByTimeAsync(POINTER_TTL_MS + 1_500);
		expect(store.remotePointers).toHaveLength(0);
	});

	it('ink strokes append per sender, ring-cap, and clear per sender on ink_clear', async () => {
		const api = fakeApi();
		api.getCheckpoint.mockResolvedValue(checkpoint());
		api.getManifest.mockResolvedValue(manifest());
		const { store, room } = build(api);
		await store.sync();
		for (let i = 0; i < 70; i++) {
			room.stageCb?.({ t: 'stage', v: 1, kind: 'ink', seq: i, points: [0.1, 0.1, 0.2, 0.2] }, 'u:2');
		}
		expect(store.inkStrokes.length).toBe(64); // INK_STROKE_CAP
		room.stageCb?.({ t: 'stage', v: 1, kind: 'ink_clear', seq: 100 }, 'u:2');
		expect(store.inkStrokes).toHaveLength(0);
	});

	it('stage frames never render outside a live session', async () => {
		const { store, room } = build(fakeApi(), null, null);
		room.stageCb?.({ t: 'stage', v: 1, kind: 'pointer', seq: 1, x: 0.5, y: 0.5 }, 'u:2');
		expect(store.remotePointers).toHaveLength(0);
	});

	it('commitInk echoes locally and broadcasts; clearInk filters own strokes and broadcasts', async () => {
		const api = fakeApi();
		api.getCheckpoint.mockResolvedValue(checkpoint());
		api.getManifest.mockResolvedValue(manifest());
		const { store, room } = build(api);
		await store.sync();
		store.commitInk([0.1, 0.9, 0.5, 0.5]);
		expect(store.inkStrokes).toHaveLength(1);
		expect(room.sentStage.at(-1)).toMatchObject({ kind: 'ink', points: [0.1, 0.9, 0.5, 0.5] });
		store.clearInk();
		expect(store.inkStrokes).toHaveLength(0);
		expect(room.sentStage.at(-1)?.kind).toBe('ink_clear');
	});

	it('sendPointer is leading-edge throttled and presenter-gated', async () => {
		vi.useFakeTimers();
		const api = fakeApi();
		api.getCheckpoint.mockResolvedValue(checkpoint());
		api.getManifest.mockResolvedValue(manifest());
		const { store, room } = build(api);
		await store.sync();
		for (let i = 0; i < 10; i++) store.sendPointer(0.1 * i, 0.2);
		expect(room.sentStage.filter((e) => e.kind === 'pointer')).toHaveLength(1);
		await vi.advanceTimersByTimeAsync(200);
		store.sendPointer(0.9, 0.9);
		expect(room.sentStage.filter((e) => e.kind === 'pointer')).toHaveLength(2);
		// a non-presenter never sends
		const api2 = fakeApi();
		api2.getCheckpoint.mockResolvedValue(checkpoint({ amPresenter: false }));
		api2.getManifest.mockResolvedValue(manifest());
		const { store: s2, room: r2 } = build(api2);
		await s2.sync();
		s2.sendPointer(0.5, 0.5);
		expect(r2.sentStage.filter((e) => e.kind === 'pointer')).toHaveLength(0);
	});

	it('suspend clears the ephemeral plane but keeps durable session truth', async () => {
		const api = fakeApi();
		api.getCheckpoint.mockResolvedValue(checkpoint());
		api.getManifest.mockResolvedValue(manifest());
		const { store, room } = build(api);
		await store.sync();
		room.stageCb?.({ t: 'stage', v: 1, kind: 'ink', seq: 1, points: [0.1, 0.1, 0.2, 0.2] }, 'u:2');
		store.inkTool = true;
		store.suspend();
		expect(store.inkStrokes).toHaveLength(0);
		expect(store.inkTool).toBe(false);
		expect(store.isLive).toBe(true); // durable state kept; sync() reloads on return
	});
});

// ── teardown ──────────────────────────────────────────────────────────────

describe('reset — teardown', () => {
	it('unregisters room seams, fails the classifier closed, and clears every field', async () => {
		const api = fakeApi();
		api.getCheckpoint.mockResolvedValue(checkpoint());
		api.getManifest.mockResolvedValue(manifest());
		const { store, room } = build(api);
		await store.sync();
		store.zoom = 2;
		store.pickerOpen = true;
		store.reset();
		expect(room.presentationCb).toBeNull();
		expect(room.stageCb).toBeNull();
		expect(room.contexts.at(-1)).toEqual({ presentationId: null, confirmedSeq: 0, knownGeneration: 0 });
		expect(store.checkpoint).toBeNull();
		expect(store.manifest).toBeNull();
		expect(store.pickerOpen).toBe(false);
		expect(store.zoom).toBe(1);
		expect(store.remotePointers).toHaveLength(0);
		// a hint after reset never reaches the api (listener unregistered)
		room.fireHint(99);
		await flush();
		expect(api.getCheckpoint.mock.calls.length).toBe(1); // the initial sync only
	});
});

// ── reading view ──────────────────────────────────────────────────────────

describe('reading view', () => {
	it('loads the qualified accessible representation of the page', async () => {
		const api = fakeApi();
		api.getCheckpoint.mockResolvedValue(checkpoint());
		api.getManifest.mockResolvedValue(manifest());
		api.fetchText.mockResolvedValue('page text');
		const { store } = build(api);
		await store.sync();
		await store.loadReading();
		expect(store.readingState).toBe('ready');
		expect(store.readingText).toBe('page text');
	});

	it('absence of the accessible representation is an explicit limitation, never fabricated text', async () => {
		const api = fakeApi();
		const m = manifest();
		delete (m.pages[0] as Partial<PresentationPage>).accessibleRepresentation;
		api.getCheckpoint.mockResolvedValue(checkpoint());
		api.getManifest.mockResolvedValue(m);
		const { store } = build(api);
		await store.sync();
		await store.loadReading();
		expect(store.readingState).toBe('unavailable');
		expect(store.readingText).toBeNull();
	});
});

// MEET-DP1: resolve/reject each transport operation explicitly. No wall-clock
// races: every stale completion happens after the replacement is observable.
function defer<T>(method: ReturnType<typeof vi.fn>) {
	let resolve!: (value: T) => void;
	let reject!: (reason: unknown) => void;
	const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
	method.mockReturnValueOnce(promise);
	return { resolve, reject };
}
async function microtasks(): Promise<void> {
	for (let i = 0; i < 12; i++) await Promise.resolve();
}

describe('MEET-DP1 presentation lifetime', () => {
	beforeEach(() => vi.useFakeTimers());

	function ready() {
		const api = fakeApi();
		api.getCheckpoint.mockResolvedValue(checkpoint());
		api.getManifest.mockResolvedValue(manifest());
		api.end.mockResolvedValue(undefined);
		return { api, ...build(api) };
	}

	async function replace(store: PresentationStore, api: Api) {
		store.reset();
		store.bind(84, () => summary({ presentationId: 2 }));
		api.getCheckpoint.mockResolvedValue(checkpoint({ presentationId: 2 }));
		await store.sync();
		await microtasks();
	}

	it('drains a late accepted preparation with original IDs after cancel and rebind, without mixed-ID reads', async () => {
		const { api, store } = ready();
		const pending = defer<{ presentationId: number; status: string }>(api.prepare);
		const work = store.prepare(7, 9, 'digest');
		store.cancelPrepare();
		await replace(store, api);
		const reads = api.getCheckpoint.mock.calls.length;
		pending.resolve({ presentationId: 9, status: 'READY' });
		await work;
		expect(api.end).toHaveBeenCalledWith(42, 9);
		expect(api.getCheckpoint).toHaveBeenCalledTimes(reads);
		expect(store.checkpoint?.presentationId).toBe(2);
		expect(store.prep).toBeNull();
		expect(store.pickerOpen).toBe(false);
	});

	it('retains failed original-identity cleanup for explicit retry without altering the replacement', async () => {
		const { api, store } = ready();
		const pending = defer<{ presentationId: number; status: string }>(api.prepare);
		api.end.mockRejectedValueOnce(new Error('offline'));
		const work = store.prepare(7, 9);
		store.cancelPrepare();
		await replace(store, api);
		pending.resolve({ presentationId: 9, status: 'READY' });
		await work;
		expect(store.cleanupFailures).toEqual([{ meetingId: 42, presentationId: 9 }]);
		await vi.advanceTimersByTimeAsync(90_000);
		expect(api.end).toHaveBeenCalledTimes(1); // no automatic retry loop
		const retry = defer<void>(api.end);
		const retryWork = store.retryCleanup(store.cleanupFailures[0]);
		const duplicate = store.retryCleanup(store.cleanupFailures[0]);
		expect(api.end).toHaveBeenCalledTimes(2);
		retry.reject(new Error('permission denied'));
		await Promise.all([retryWork, duplicate]);
		expect(store.cleanupFailures).toEqual([{ meetingId: 42, presentationId: 9 }]);
		await store.retryCleanup(store.cleanupFailures[0]);
		expect(api.end.mock.calls).toEqual([[42, 9], [42, 9], [42, 9]]);
		expect(store.cleanupFailures).toEqual([]);
		expect(store.checkpoint?.presentationId).toBe(2);
	});

	it('ignores late preparation rejection after cancellation', async () => {
		const { api, store } = ready();
		const pending = defer(api.prepare);
		const work = store.prepare(7, 9);
		store.cancelPrepare();
		await replace(store, api);
		pending.reject({ code: 'rendererTimeout' });
		await work;
		expect(store.failure).toBeNull();
		expect(store.checkpoint?.presentationId).toBe(2);
	});

	for (const outcome of ['resolve', 'reject'] as const) {
		it(`fences a superseded resync ${outcome} and finally while a new resync is pending`, async () => {
			const { api, store } = ready();
			await store.sync();
			const old = defer<PresentationCheckpoint>(api.getCheckpoint);
			const oldWork = store.resync();
			await replace(store, api);
			const current = defer<PresentationCheckpoint>(api.getCheckpoint);
			const currentWork = store.resync();
			if (outcome === 'resolve') old.resolve(checkpoint({ pageIndex: 2 }));
			else old.reject({ code: 'checkpointRefreshThrottled' });
			await oldWork;
			expect(store.resyncing).toBe(true);
			expect(store.checkpoint?.presentationId).toBe(2);
			expect(store.pageState).toBe('current');
			current.resolve(checkpoint({ presentationId: 2, checkpointSeq: 11, pageIndex: 1 }));
			await currentWork;
			expect(store.resyncing).toBe(false);
			expect(store.pageIndex).toBe(1);
		});

		it(`fences a late manifest ${outcome} across source generations`, async () => {
			const { api, store } = ready();
			const old = defer<PresentationManifest>(api.getManifest);
			await store.sync();
			api.getCheckpoint.mockResolvedValue(checkpoint({ checkpointSeq: 11, manifestGeneration: 2, driveVersionId: 10 }));
			api.getManifest.mockResolvedValue(manifest({ driveVersionId: 10 }));
			await store.sync();
			await microtasks();
			if (outcome === 'resolve') old.resolve(manifest());
			else old.reject(new Error('old manifest failed'));
			await microtasks();
			expect(store.manifest?.driveVersionId).toBe(10);
			expect(store.failure).toBeNull();
		});

		for (const kind of ['reading', 'notes'] as const) {
			it(`fences old ${kind} ${outcome} after page/source/presenter change`, async () => {
				const { api, store } = ready();
				await store.sync();
				await microtasks();
				const pending = defer<string>(api.fetchText);
				const work = kind === 'reading' ? store.loadReading() : store.loadNotes();
				api.getCheckpoint.mockResolvedValue(checkpoint({ checkpointSeq: 11, pageIndex: 1, presenterGeneration: 4, amPresenter: false }));
				await store.refreshCheckpoint();
				if (outcome === 'resolve') pending.resolve('old protected text');
				else pending.reject(new Error('old text failed'));
				await work;
				expect(store.readingText).toBeNull();
				expect(store.notesText).toBeNull();
				expect(store.readingState).toBe('idle');
				expect(store.notesState).toBe('idle');
			});
		}

		for (const operation of ['present', 'changePage', 'grantPresenter', 'takeoverPresenter', 'end'] as const) {
			it(`fences old ${operation} ${outcome}, messages, refresh and finally after rebind`, async () => {
				const { api, store, room } = ready();
				await store.sync();
				await microtasks();
				const method = operation === 'present' ? 'start' : operation === 'takeoverPresenter' ? 'grantPresenter' : operation;
				const pending = defer<PresentationMutationResponse | undefined>(api[method]);
				const work = operation === 'changePage' ? store.changePage(1) : operation === 'grantPresenter' ? store.grantPresenter(11) : store[operation]();
				await replace(store, api);
				const newGrant = defer<PresentationMutationResponse>(api.grantPresenter);
				const newWork = store.grantPresenter(22);
				const reads = api.getCheckpoint.mock.calls.length;
				const beforeMessage = store.politeMessage;
				if (outcome === 'resolve') pending.resolve(operation === 'end' ? undefined : fact({ presenterGeneration: 4 }));
				else pending.reject({ code: 'stalePresenterGeneration' });
				await work;
				expect(store.checkpoint?.presentationId).toBe(2);
				expect(store.pendingGrant).toBe(22);
				expect(store.politeMessage).toBe(beforeMessage);
				expect(store.handoffReason).toBe('');
				expect(api.getCheckpoint).toHaveBeenCalledTimes(reads);
				expect(room.sentFrames).toEqual([]);
				newGrant.resolve(fact({ presentationId: 2, presenterGeneration: 4 }));
				await newWork;
				expect(store.pendingGrant).toBeNull();
			});
		}
	}

	it('does not regress a checkpoint when authorized reads settle out of order', async () => {
		const { api, store } = ready();
		await store.sync();
		const old = defer<PresentationCheckpoint>(api.getCheckpoint);
		const work = store.refreshCheckpoint();
		api.getCheckpoint.mockResolvedValue(checkpoint({ checkpointSeq: 12, pageIndex: 2 }));
		await store.refreshCheckpoint();
		old.resolve(checkpoint({ checkpointSeq: 11, pageIndex: 1 }));
		await work;
		expect(store.pageIndex).toBe(2);
	});

	it('ignores an older committed page result and its message/hint after a newer checkpoint', async () => {
		const { api, store, room } = ready();
		await store.sync();
		await microtasks();
		const pending = defer<PresentationMutationResponse>(api.changePage);
		const work = store.changePage(1);
		api.getCheckpoint.mockResolvedValue(checkpoint({ checkpointSeq: 12, pageIndex: 2 }));
		await store.refreshCheckpoint();
		const message = store.politeMessage;
		pending.resolve(fact({ checkpointSeq: 11, pageIndex: 1 }));
		await work;
		expect(store.pageIndex).toBe(2);
		expect(store.politeMessage).toBe(message);
		expect(room.sentFrames).toEqual([]);
	});

	it('preserves a later committed page result within the same presentation', async () => {
		const { api, store, room } = ready();
		await store.sync();
		await microtasks();
		const pending = defer<PresentationMutationResponse>(api.changePage);
		const work = store.changePage(1);
		api.getCheckpoint.mockResolvedValue(checkpoint({ checkpointSeq: 11, pageIndex: 2 }));
		await store.refreshCheckpoint();
		pending.resolve(fact({ checkpointSeq: 12, pageIndex: 1 }));
		await work;
		expect(store.pageIndex).toBe(1);
		expect(store.politeMessage).toContain('2');
		expect(room.sentFrames).toHaveLength(1);
	});

	it('cancels parked refresh timers on reset and gives the next session a fresh refresher', async () => {
		const { api, store, room } = ready();
		await store.sync();
		api.getCheckpoint.mockRejectedValue({ code: 'checkpointRefreshThrottled', extensions: { retryAfterMs: 30_000 } });
		room.fireHint(11);
		await microtasks();
		room.fireHint(12);
		expect(vi.getTimerCount()).toBeGreaterThan(0);
		store.reset();
		expect(vi.getTimerCount()).toBe(0);
		await replace(store, api);
		const reads = api.getCheckpoint.mock.calls.length;
		store.hint();
		await microtasks();
		expect(api.getCheckpoint).toHaveBeenCalledTimes(reads + 1);
		await vi.advanceTimersByTimeAsync(30_000);
		expect(api.getCheckpoint).toHaveBeenCalledTimes(reads + 1);
	});
});

describe('MEET-DP1 preparation ownership and same-binding replacement', () => {
	beforeEach(() => vi.useFakeTimers());

	it('drains a recovered READY preview when cancelled', async () => {
		const api = fakeApi();
		api.getCheckpoint.mockResolvedValue(checkpoint({ status: 'READY' }));
		api.getManifest.mockResolvedValue(manifest());
		api.end.mockResolvedValue(undefined);
		const { store } = build(api);
		await store.sync();
		store.cancelPrepare();
		await microtasks();
		expect(api.end).toHaveBeenCalledWith(42, 1);
	});

	it('replacing preparation drains only the old preview and leaves the new preview usable', async () => {
		const api = fakeApi();
		api.prepare.mockResolvedValueOnce({ presentationId: 9, status: 'READY' }).mockResolvedValueOnce({ presentationId: 10, status: 'READY' });
		api.getCheckpoint.mockResolvedValueOnce(checkpoint({ presentationId: 9, status: 'READY' })).mockResolvedValueOnce(checkpoint({ presentationId: 10, status: 'READY' }));
		api.getManifest.mockResolvedValue(manifest());
		api.end.mockResolvedValue(undefined);
		const { store } = build(api);
		await store.prepare(7, 9);
		await store.prepare(7, 10);
		expect(api.end.mock.calls).toEqual([[42, 9]]);
		expect(store.isPreviewing).toBe(true);
		expect(store.checkpoint?.presentationId).toBe(10);
	});

	it('teardown cancels the production rendition-poll timer and drains its accepted preparation', async () => {
		const api = fakeApi();
		api.prepare.mockResolvedValue({ presentationId: 9, status: 'PREPARING' });
		api.end.mockResolvedValue(undefined);
		const store = new PresentationStore(api as unknown as PresentationApi);
		store.bind(42, () => null);
		const work = store.prepare(7, 9);
		await microtasks();
		expect(vi.getTimerCount()).toBe(1);
		store.reset();
		await work;
		expect(vi.getTimerCount()).toBe(0);
		expect(api.end).toHaveBeenCalledWith(42, 9);
		expect(api.getCheckpoint).not.toHaveBeenCalled();
	});

	it('does not end a live session on leave after an authorized checkpoint confirms start', async () => {
		const api = fakeApi();
		api.prepare.mockResolvedValue({ presentationId: 9, status: 'READY' });
		api.getCheckpoint.mockResolvedValueOnce(checkpoint({ presentationId: 9, status: 'READY' })).mockResolvedValueOnce(checkpoint({ presentationId: 9, status: 'ACTIVE', checkpointSeq: 11 }));
		api.getManifest.mockResolvedValue(manifest());
		api.end.mockResolvedValue(undefined);
		const { store } = build(api);
		await store.prepare(7, 9);
		await store.refreshCheckpoint();
		store.reset();
		expect(api.end).not.toHaveBeenCalled();
	});

	it('finishes preview on an ACTIVE checkpoint before an older start reply without promoting the old fact', async () => {
		const api = fakeApi();
		api.getManifest.mockResolvedValue(manifest());
		api.end.mockResolvedValue(undefined);
		const { store, room } = build(api);
		api.prepare.mockResolvedValue({ presentationId: 9, status: 'READY' });
		api.getCheckpoint.mockResolvedValue(checkpoint({ presentationId: 9, status: 'READY' }));
		store.pickerOpen = true;
		await store.prepare(7, 9);
		expect(store.isPreviewing).toBe(true);
		expect(store.pickerOpen).toBe(true);
		const started = defer<PresentationMutationResponse>(api.start);
		const presenting = store.present();
		const current = checkpoint({ presentationId: 9, checkpointSeq: 12, pageIndex: 2, presenterGeneration: 4, amPresenter: false });
		api.getCheckpoint.mockResolvedValue(current);
		await store.refreshCheckpoint();
		expect(store.pickerOpen).toBe(false);
		store.politeMessage = 'Current authorized session';
		started.resolve(fact({ presentationId: 9, checkpointSeq: 11, pageIndex: 0 }));
		await presenting;
		expect(store.checkpoint).toEqual(current);
		expect(store.pickerOpen).toBe(false);
		expect(store.politeMessage).toBe('Current authorized session');
		expect(room.sentFrames).toEqual([]);
		store.reset();
		expect(api.end).not.toHaveBeenCalled();
	});

	it('a late end cannot clear a new presentation within the same Meeting binding', async () => {
		const api = fakeApi();
		api.getCheckpoint.mockResolvedValue(checkpoint());
		api.getManifest.mockResolvedValue(manifest());
		const { store } = build(api);
		await store.sync();
		const stopped = defer<void>(api.end);
		const work = store.end();
		store.bind(42, () => summary({ presentationId: 2 }));
		api.getCheckpoint.mockResolvedValue(checkpoint({ presentationId: 2 }));
		await store.sync();
		stopped.resolve();
		await work;
		expect(store.checkpoint?.presentationId).toBe(2);
	});

	it('suspension fences pending text and checkpoints but reconnect reauthorizes normally', async () => {
		const api = fakeApi();
		api.getCheckpoint.mockResolvedValue(checkpoint());
		api.getManifest.mockResolvedValue(manifest());
		const { store } = build(api);
		await store.sync();
		await microtasks();
		const text = defer<string>(api.fetchText);
		const read = store.loadNotes();
		const checkpointRead = defer<PresentationCheckpoint>(api.getCheckpoint);
		const refresh = store.refreshCheckpoint();
		store.suspend();
		text.resolve('old notes');
		checkpointRead.resolve(checkpoint({ pageIndex: 2, checkpointSeq: 11 }));
		await Promise.all([read, refresh]);
		expect(store.notesText).toBeNull();
		expect(store.pageIndex).toBe(0);
		api.getCheckpoint.mockResolvedValue(checkpoint({ pageIndex: 1, checkpointSeq: 12 }));
		await store.sync();
		expect(store.pageIndex).toBe(1);
	});
});
