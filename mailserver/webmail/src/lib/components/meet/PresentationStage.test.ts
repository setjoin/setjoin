// PresentationStage.test.ts — MEET plan M3 named states: presenter vs
// attendee control surfaces, the stale/partial truth (last validated page +
// resync), the authorized-takeover affordance, the handoff dialog's empty
// state, polite keyboard page navigation scoped to the stage, the
// temporary-ink notice, and the two-interaction screen-share fallback.
// Wired to the LANDED M2 shapes (`./presentationCheckpoint`: server-derived
// amPresenter, participant-id presenter identity).
import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, fireEvent, cleanup } from '@testing-library/svelte/svelte5';
import PresentationStage from './PresentationStage.svelte';
import { PresentationStore } from '$lib/meet/presentationStore.svelte';
import type { PresentationApi, PresentationManifest, PresentationPage } from '$lib/meet/presentationApi';
import type { PresentationCheckpoint } from '$lib/meet/presentationCheckpoint';
import type { MeetRoom } from '$lib/meet/room.svelte';

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
	};
}

function manifest(): PresentationManifest {
	return {
		schema: 'meet-pages-v1',
		driveNodeId: 7,
		driveVersionId: 9,
		sourceSha256: 'c'.repeat(64),
		pages: [page(0), page(1), page(2)],
		warnings: [],
		rendererId: 'r',
		rendererVersion: '1',
		fontPackDigest: 'd'.repeat(64),
		integrityDigest: 'e'.repeat(64),
		completedAt: '2026-09-18T00:00:00Z',
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

function fakeRoom(): MeetRoom {
	return {
		setPresentationContext: vi.fn(),
		onPresentation: vi.fn(),
		onStage: vi.fn(),
		sendPresentationFrame: vi.fn(() => true),
		sendStageEvent: vi.fn(() => true),
	} as unknown as MeetRoom;
}

function fakeApi(over: Partial<PresentationApi> = {}): PresentationApi {
	return {
		prepare: vi.fn(),
		start: vi.fn(),
		getCheckpoint: vi.fn(async () => checkpoint()),
		getManifest: vi.fn(async () => manifest()),
		changePage: vi.fn(async (_m: number, _p: number, _f: { checkpointSeq: number }, i: number) => ({
			presentationId: 1,
			status: 'ACTIVE',
			checkpointSeq: _f.checkpointSeq + 1,
			presenterGeneration: 3,
			pageIndex: i,
			manifestGeneration: 1,
		})),
		grantPresenter: vi.fn(),
		end: vi.fn(async () => undefined),
		fetchText: vi.fn(async () => 'notes'),
		...over,
	};
}

async function mountedStage(opts: {
	api?: Partial<PresentationApi>;
	handoffTargets?: { participantId: number; displayName: string }[];
} = {}) {
	const store = new PresentationStore(fakeApi(opts.api) as PresentationApi);
	store.enabled = true;
	// a LIVE summary: the store's sync() then reauthorizes through the
	// authorized checkpoint read — the component only ever sees promoted
	// state, exactly the rule under test.
	store.bind(42, () => ({ presentationId: 1, status: 'ACTIVE', checkpointSeq: 10, presenterGeneration: 3, presenterParticipantId: 7, pageIndex: 0, manifestGeneration: 1, manifestDigest: 'd1', driveNodeId: 7, driveVersionId: 9 }));
	store.attach(fakeRoom());
	await store.sync();
	const onFallback = vi.fn();
	render(PresentationStage, {
		presentation: store,
		presenterLabel: '',
		handoffTargets: opts.handoffTargets ?? [],
		onFallback,
	});
	// the page renders once the manifest read lands — wait for it so the
	// controls are out of their in-flight disabled state
	await screen.findByTestId('stage-page', {}, { timeout: 2_000 });
	return { store, onFallback };
}

afterEach(() => cleanup());

describe('PresentationStage — attendee surface', () => {
	it('shows page indicator + presenter line + fallback + takeover; hides presenter-only controls', async () => {
		await mountedStage({ api: { getCheckpoint: vi.fn(async () => checkpoint({ amPresenter: false })) } });
		expect(screen.getByTestId('stage-page-indicator').textContent).toContain('Page 1 of 3');
		expect(screen.getByTestId('stage-presenter').textContent).toContain('7'); // participant-id fallback, never a fabricated name
		expect(screen.queryByTestId('stage-prev')).toBeNull();
		expect(screen.queryByTestId('stage-next')).toBeNull();
		expect(screen.queryByTestId('stage-ink')).toBeNull();
		expect(screen.queryByTestId('stage-end')).toBeNull();
		expect(screen.getByTestId('stage-fallback')).toBeTruthy();
		// the authorized takeover affordance stays reachable for non-presenters
		expect(screen.getByTestId('stage-takeover')).toBeTruthy();
	});

	it('takeover targets SELF via myParticipantId with takeover=true (server-fenced)', async () => {
		const grant = vi.fn(async () => ({
			presentationId: 1,
			status: 'ACTIVE',
			checkpointSeq: 20,
			presenterGeneration: 9,
			pageIndex: 0,
			manifestGeneration: 1,
		}));
		await mountedStage({
			api: {
				getCheckpoint: vi.fn(async () => checkpoint({ amPresenter: false, myParticipantId: 12 })),
				grantPresenter: grant,
			},
		});
		await fireEvent.click(screen.getByTestId('stage-takeover'));
		expect(grant).toHaveBeenCalledWith(42, 1, { targetParticipantId: 12, takeover: true, presenterGeneration: 3 });
	});

	it('the fallback delegates to the existing screen-share mechanism', async () => {
		const { onFallback } = await mountedStage({});
		await fireEvent.click(screen.getByTestId('stage-fallback'));
		expect(onFallback).toHaveBeenCalledTimes(1);
	});
});

describe('PresentationStage — presenter surface', () => {
	it('prev/next navigate through the store (reducer-promoted pages only)', async () => {
		const { store } = await mountedStage({});
		await fireEvent.click(screen.getByTestId('stage-next'));
		await vi.waitFor(() => expect(store.pageIndex).toBe(1));
		await fireEvent.click(screen.getByTestId('stage-prev'));
		await vi.waitFor(() => expect(store.pageIndex).toBe(0));
	});

	it('arrow keys navigate only within the stage region', async () => {
		const { store } = await mountedStage({});
		const stage = screen.getByTestId('presentation-stage');
		await fireEvent.keyDown(stage, { key: 'ArrowRight' });
		await vi.waitFor(() => expect(store.pageIndex).toBe(1));
	});

	it('the temporary-ink tool advertises its ephemerality before first use', async () => {
		const { store } = await mountedStage({});
		const ink = screen.getByTestId('stage-ink');
		expect(ink.getAttribute('title')).toContain('not saved');
		await fireEvent.click(ink);
		expect(store.inkTool).toBe(true);
		expect(screen.getByRole('note').textContent).toContain('not saved');
		// putting the pen away clears own ink
		await fireEvent.click(ink);
		expect(store.inkTool).toBe(false);
	});

	it('the rail toggle opens the presenter rail', async () => {
		await mountedStage({});
		expect(screen.queryByTestId('presentation-rail')).toBeNull();
		await fireEvent.click(screen.getByTestId('stage-rail-thumbs'));
		expect(screen.getByTestId('presentation-rail')).toBeTruthy();
	});

	it('stop presenting ends the session', async () => {
		const { store } = await mountedStage({});
		await fireEvent.click(screen.getByTestId('stage-end'));
		await vi.waitFor(() => expect(store.isLive).toBe(false));
	});
});

describe('PresentationStage — handoff dialog', () => {
	it('grants to a picked participant-id target and announces the handoff', async () => {
		const grant = vi.fn(async () => ({
			presentationId: 1,
			status: 'ACTIVE',
			checkpointSeq: 21,
			presenterGeneration: 4,
			pageIndex: 0,
			manifestGeneration: 1,
		}));
		const { store } = await mountedStage({
			api: {
				grantPresenter: grant,
				// the post-grant authorized read: the OLD presenter's gate flips off
				getCheckpoint: vi
					.fn()
					.mockResolvedValueOnce(checkpoint())
					.mockResolvedValue(checkpoint({ checkpointSeq: 21, presenterGeneration: 4, amPresenter: false, presenterParticipantId: 11 })),
			},
			handoffTargets: [{ participantId: 11, displayName: 'Bob' }],
		});
		await fireEvent.click(screen.getByTestId('stage-handoff'));
		await fireEvent.click(screen.getByTestId('handoff-grant-11'));
		expect(grant).toHaveBeenCalledWith(42, 1, { targetParticipantId: 11, takeover: false, presenterGeneration: 3 });
		await vi.waitFor(() => expect(store.amPresenter).toBe(false)); // promoted truth flips the gate
	});

	it('an empty target list shows the explanatory empty state (no fabricated roster)', async () => {
		await mountedStage({});
		await fireEvent.click(screen.getByTestId('stage-handoff'));
		expect(screen.getByTestId('handoff-empty').textContent).toContain('No one is available');
	});
});

describe('PresentationStage — partial / degraded truth', () => {
	it('a stale session keeps the page, names the state, and offers resync', async () => {
		// the checkpoint read succeeds on sync, then every refresh fails —
		// the last validated page stays visible and marked stale, never
		// inferred as ended
		const { store } = await mountedStage({
			api: {
				getCheckpoint: vi.fn().mockResolvedValueOnce(checkpoint()).mockRejectedValue(new Error('presentation api down')),
			},
		});
		await store.refreshCheckpoint().catch(() => undefined);
		expect(store.pageState).toBe('stale');
		expect(screen.getByTestId('stage-stale').textContent).toContain('last validated page');
		// resync still failing → the banner persists (truthful, no false fresh state)
		await fireEvent.click(screen.getByText('Resync'));
		expect(screen.getByTestId('stage-stale')).toBeTruthy();
		expect(store.isLive).toBe(true);
	});

	it('a DEGRADED session names the renderer state', async () => {
		await mountedStage({
			api: {
				getCheckpoint: vi.fn().mockResolvedValueOnce(checkpoint({ status: 'DEGRADED' })).mockRejectedValue(new Error('down')),
			},
		});
		expect(screen.getByText('The presentation is degraded — trying to recover.')).toBeTruthy();
	});
});
