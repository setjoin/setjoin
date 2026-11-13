// presentationStore.svelte.ts — MEET plan M3: the presentation session store
// (a rune class instantiated fresh per MeetStore/MeetApp mount, the MeetStore
// genre). Owns the client-side presentation slice: the Drive picker/prepare/
// preview flow, the promoted checkpoint + manifest, local-only controls
// (zoom, reading view), the presenter-gated rail (thumbnails/notes), presenter
// handoff, and the ephemeral stage plane (pointer/ink).
//
// THE central M0 rule this store encodes: durable presentation frames and
// `presentation_state` push facts are UNTRUSTED checkpoint-invalidation
// hints. Nothing received over the data channel or the push rail promotes
// state — `CheckpointRefresher` (presentation.ts, frozen) coalesces hints
// into bounded authorized checkpoint reads, and only an API response (the
// checkpoint read or a mutation's own committed fact) ever moves
// `checkpoint`, page or generation state. The room's `setPresentationContext`
// seam is fed exclusively through M2's `presentationFrameContextFromCheckpoint`
// (terminal sessions collapse to a null context — every late frame fails
// closed) and is reset fail-closed on every teardown.
//
// Authority posture: `amPresenter` is SERVER truth from the authorized read
// (the reducer derives it from presenter_participant_id). The client-side
// gate only avoids issuing requests that cannot succeed — the reducer
// re-checks verb-specific rights and the generation/checkpoint-seq fences on
// every mutation — so a stale local view can only under-trigger, never
// over-trigger. Returning participants reauthorize through `sync()`'s fresh
// summary + checkpoint read; no cached grant ever survives a reconnect, a
// breakout return, or a meeting switch (reset-on-teardown, the D4 genre).
import { untrack } from 'svelte';
import { CheckpointRefresher, PRESENTATION_VERSION, PRESENTATION_TOPIC } from './presentation';
import {
	frameFromCommittedFact,
	presentationFrameContextFromCheckpoint,
	type PresentationCheckpoint,
	type PresentationMutationResponse,
} from './presentationCheckpoint';
import type { MeetingPresentationSummary } from './api';
import {
	httpPresentationApi,
	type PresentationApi,
	type PresentationManifest,
	type PresentationPage,
	type PresentationStatus,
} from './presentationApi';
import {
	clampPageIndex,
	clampUnit,
	normalizeThrottleError,
	pointerFresh,
	prefetchPlan,
	presentationFailureKey,
	POINTER_TTL_MS,
	throttleLeading,
} from './presentationClient';
import type { MeetRoom, StageEvent } from './room.svelte';
import { MAX_PAGE_INDEX } from './presentation';
import { t } from '$lib/i18n';

/** A remote presenter's pointer dot, TTL-expired client-side (ephemeral by
 *  definition — nothing here is ever recovered). */
export interface PresentationRemotePointer {
	identity: string;
	x: number;
	y: number;
	expiresAt: number;
}

/** One committed temporary-ink stroke (local echo or remote), in normalized
 *  flat x,y pairs. Cleared on page/source transitions and reconnect — never
 *  persisted, never saved to the document or a replay. */
export interface PresentationInkStroke {
	id: string;
	identity: string;
	points: number[];
}

/** Cleanup is separate from the current Meeting: failures survive reset until
 * an explicit retry succeeds using current server authorization. */
export interface PresentationCleanup {
	meetingId: number;
	presentationId: number;
}

type SessionWork = { lifetime: number; meetingId: number; presentationId: number | null };
type Preparation = { work: SessionWork; presentationId: number | null; cleanupStarted: boolean };

export interface RenditionPrepState {
	presentationId: number;
	status: PresentationStatus;
}

/** Ink strokes on the overlay are ring-capped: temporary ink is a pointer
 *  aid, not a canvas, and the ephemeral plane never grows unbounded. */
const INK_STROKE_CAP = 64;
/** Rendition readiness poll: 1s interval, bounded at ~90s — the plan's
 *  newly-accepted-rendition start budget — then the named failure. */
const RENDITION_POLL_MS = 1_000;
const RENDITION_POLL_MAX = 90;

function isTerminalFailureStatus(s: string): boolean {
	return s === 'FAILED' || s === 'CANCELLED' || s === 'ENDED' || s === 'REVOKED';
}

/** Client-side manifest sanity gate before the pages render: dense indexes,
 *  non-empty, inside the frozen page bound. A producer failure (the
 *  zero-page artifact the plan rejects) surfaces as a named failure, never
 *  a blank successful canvas. */
export function manifestPages(manifest: PresentationManifest | null): PresentationPage[] | null {
	if (!manifest || !Array.isArray(manifest.pages) || manifest.pages.length === 0) return null;
	if (manifest.pages.length > MAX_PAGE_INDEX + 1) return null;
	for (let i = 0; i < manifest.pages.length; i++) {
		if (manifest.pages[i].index !== i) return null;
	}
	return manifest.pages;
}

export class PresentationStore {
	// ── gate + session truth (promoted from API responses only) ────────────
	/** Client visibility gate, seeded from the meeting projection's
	 *  presentationEnabled (feature.meet_document_presentation AND
	 *  feature.drive — the M2 projection). Everything hangs behind it. */
	enabled = $state(false);
	pickerOpen = $state(false);
	/** The promoted checkpoint (M2's authorized-read shape, with
	 *  server-derived amPresenter/myParticipantId). */
	checkpoint = $state<PresentationCheckpoint | null>(null);
	manifest = $state<PresentationManifest | null>(null);
	/** The manifest generation currently loaded — a generation change on the
	 *  promoted checkpoint triggers a manifest re-read. */
	#manifestGenerationLoaded: number | null = null;
	/** 'loading' — page asset in flight; 'current' — promoted page rendered;
	 *  'stale' — the last validated page stays visible while resync waits
	 *  (controls disabled until resync, the plan's partial/degraded row). */
	pageState = $state<'loading' | 'current' | 'stale'>('loading');
	resyncing = $state(false);
	/** Named failure registry code (or null = the generic unavailable copy). */
	failure = $state<{ code: string | null } | null>(null);

	// ── preparation + private preview ──────────────────────────────────────
	prep = $state<RenditionPrepState | null>(null);
	cleanupFailures = $state<PresentationCleanup[]>([]);
	previewPageIndex = $state(0);

	// ── presenter rail (presenter-gated; notes never render for others) ────
	railOpen = $state(false);
	railMode = $state<'thumbnails' | 'notes'>('thumbnails');
	notesState = $state<'idle' | 'loading' | 'ready' | 'unavailable'>('idle');
	notesText = $state<string | null>(null);

	// ── local-only controls ────────────────────────────────────────────────
	zoom = $state(1);
	readingView = $state(false);
	readingState = $state<'idle' | 'loading' | 'ready' | 'unavailable'>('idle');
	readingText = $state<string | null>(null);
	pointerTool = $state(false);
	inkTool = $state(false);

	// ── ephemeral stage plane ──────────────────────────────────────────────
	remotePointers = $state<PresentationRemotePointer[]>([]);
	inkStrokes = $state<PresentationInkStroke[]>([]);

	// ── handoff + live regions ─────────────────────────────────────────────
	/** Target participant id a grant is currently in flight for. */
	pendingGrant = $state<number | null>(null);
	/** Rejected/stale-generation handoff reason (translated copy), cleared on
	 *  the next attempt or successful promote. */
	handoffReason = $state('');
	politeMessage = $state('');
	assertiveMessage = $state('');

	// Plain (non-reactive) machinery — the openGeneration genre.
	#api: PresentationApi;
	#room: MeetRoom | null = null;
	#meetingId: number | null = null;
	/** The live-summary provider — MeetStore's own meeting projection (the
	 *  join/read surface the plan routes reauthorization through). Set once
	 *  by the owning MeetStore; read inside sync(), never reactively. */
	#summaryProvider: (() => MeetingPresentationSummary | null) | null = null;
	#refresher: CheckpointRefresher;
	#syncGeneration = 0;
	#lifetime = 0;
	#suspended = false;
	#preparation: Preparation | null = null;
	#cleanupInFlight = new Map<string, Promise<void>>();
	#refreshTimers = new Set<ReturnType<typeof setTimeout>>();
	#cancelSleeps = new Set<() => void>();
	#readingRequest = 0;
	#notesRequest = 0;
	#stageSeq = 0;
	#sleep: (ms: number) => Promise<void>;
	#sweepTimer: ReturnType<typeof setInterval> | null = null;
	#pointerSend: (() => void) | null = null;
	#pendingPointer: { x: number; y: number } | null = null;

	constructor(api: PresentationApi = httpPresentationApi, opts: { sleep?: (ms: number) => Promise<void> } = {}) {
		this.#api = api;
		this.#sleep = opts.sleep ?? ((ms) => new Promise((resolve) => {
			const cancel = (): void => { clearTimeout(timer); this.#cancelSleeps.delete(cancel); resolve(); };
			const timer = setTimeout(cancel, ms);
			this.#cancelSleeps.add(cancel);
		}));
		// ONE refresh in flight plus ONE pending, bounded admission and
		// Retry-After backoff — all inside the frozen refresher; the store
		// only supplies the authorized read.
		this.#refresher = this.#makeRefresher();
	}

	/** Binds the owning MeetStore's live-summary provider + meeting scope. */
	bind(meetingId: number, summaryProvider: () => MeetingPresentationSummary | null): void {
		if (this.#meetingId !== null && this.#meetingId !== meetingId) this.reset();
		this.#meetingId = meetingId;
		this.#summaryProvider = summaryProvider;
	}

	/** All async continuations capture their original Meeting and lifetime.
	 * Source/page/presenter checks below additionally bind individual assets. */
	#work(presentationId: number | null = this.checkpoint?.presentationId ?? null): SessionWork | null {
		return this.#meetingId === null || this.#suspended ? null : {
			lifetime: this.#lifetime, meetingId: this.#meetingId, presentationId,
		};
	}

	#owns(work: SessionWork): boolean {
		return !this.#suspended && work.lifetime === this.#lifetime && work.meetingId === this.#meetingId &&
			(work.presentationId === null || work.presentationId === this.checkpoint?.presentationId);
	}

	#makeRefresher(): CheckpointRefresher {
		const lifetime = this.#lifetime;
		return new CheckpointRefresher(
			() => lifetime === this.#lifetime ? this.refreshCheckpoint() : Promise.resolve(),
			{ schedule: (ms, fn) => {
				if (lifetime !== this.#lifetime) return () => {};
				const timer = setTimeout(() => {
					this.#refreshTimers.delete(timer);
					if (lifetime === this.#lifetime) fn();
				}, ms);
				this.#refreshTimers.add(timer);
				return () => { clearTimeout(timer); this.#refreshTimers.delete(timer); };
			} },
		);
	}

	#retireWork(): void {
		this.#lifetime++;
		this.#syncGeneration++;
		for (const timer of this.#refreshTimers) clearTimeout(timer);
		this.#refreshTimers.clear();
		for (const cancel of this.#cancelSleeps) cancel();
		this.#refresher = this.#makeRefresher();
		this.resyncing = false;
		this.pendingGrant = null;
		const preparing = this.#preparation;
		this.#preparation = null;
		if (preparing) void this.#drainPreparation(preparing);
	}

	#drainPreparation(preparing: Preparation): Promise<void> {
		if (preparing.presentationId === null || preparing.cleanupStarted) return Promise.resolve();
		preparing.cleanupStarted = true;
		return this.#cleanup({ meetingId: preparing.work.meetingId, presentationId: preparing.presentationId });
	}

	#cleanup(target: PresentationCleanup): Promise<void> {
		const key = `${target.meetingId}/${target.presentationId}`;
		const pending = this.#cleanupInFlight.get(key);
		if (pending) return pending;
		// One attempt per cancellation/retry; no background retry loop or
		// saved credentials. A denied/offline drain remains explicitly actionable.
		const work = this.#api.end(target.meetingId, target.presentationId)
			.then(() => {
				this.cleanupFailures = this.cleanupFailures.filter((f) => `${f.meetingId}/${f.presentationId}` !== key);
			})
			.catch(() => {
				this.cleanupFailures = [...this.cleanupFailures.filter((f) => `${f.meetingId}/${f.presentationId}` !== key), { ...target }];
			})
			.finally(() => this.#cleanupInFlight.delete(key));
		this.#cleanupInFlight.set(key, work);
		return work;
	}

	retryCleanup(target: PresentationCleanup): Promise<void> {
		const retained = this.cleanupFailures.find((f) => f.meetingId === target.meetingId && f.presentationId === target.presentationId);
		return retained ? this.#cleanup(retained) : Promise.resolve();
	}

	// ── derived projections ─────────────────────────────────────────────────
	/** A session the stage renders: ACTIVE, or DEGRADED (renderer lost —
	 *  last validated page stays visible). READY sessions render only as the
	 *  private preview inside the picker. */
	isLive = $derived(this.checkpoint !== null && (this.checkpoint.status === 'ACTIVE' || this.checkpoint.status === 'DEGRADED'));
	/** Private preview truth: a READY session awaiting the presenter's
	 *  Present commit. */
	isPreviewing = $derived(this.checkpoint !== null && this.checkpoint.status === 'READY');
	/** SERVER truth from the authorized read — never a client identity
	 *  comparison. The gate for the render-side presenter affordances. */
	amPresenter = $derived(this.checkpoint?.amPresenter === true);
	pageCount = $derived(manifestPages(this.manifest)?.length ?? 0);
	pageIndex = $derived(this.checkpoint?.pageIndex ?? 0);
	/** The current page's authorized full-asset reference, or null while
	 *  unknown/invalid (the canvas renders its skeleton, never a blank OK). */
	currentPage = $derived(manifestPages(this.manifest)?.[this.pageIndex] ?? null);
	/** Bounded prefetch plan: current + next two pages (plan budget). */
	prefetchPages = $derived(prefetchPlan(this.pageIndex, this.pageCount));

	// ── wiring (component-lifecycle calls; no $effect in a class — the
	// MeetStore posture) ─────────────────────────────────────────────────────

	/** Registers the room seams: durable-frame hints feed the frozen
	 *  refresher; stage frames feed the ephemeral plane. */
	attach(room: MeetRoom): void {
		this.#room = room;
		room.onPresentation(() => this.hint());
		room.onStage((event, from) => this.#applyStageEvent(event, from));
	}

	/** Unregisters room seams and fails the frame classifier closed. */
	detach(): void {
		this.#room?.onPresentation(null);
		this.#room?.onStage(null);
		this.#room?.setPresentationContext({ presentationId: null, confirmedSeq: 0, knownGeneration: 0 });
		this.#room = null;
	}

	/** Full teardown (meeting switch / leave / ended): drop everything, no
	 *  session truth may leak into the next meeting (the D4 genre). A
	 *  departing presenter deliberately does NOT auto-end the session here —
	 *  the plan's posture is "hand off or leave controls unavailable until
	 *  authorized takeover", and the reducer owns the real lifecycle. */
	reset(): void {
		this.#retireWork();
		this.#suspended = false;
		this.detach();
		this.#meetingId = null;
		this.#summaryProvider = null;
		if (this.#sweepTimer !== null) {
			clearInterval(this.#sweepTimer);
			this.#sweepTimer = null;
		}
		this.#pointerSend = null;
		this.pickerOpen = false;
		this.checkpoint = null;
		this.manifest = null;
		this.#manifestGenerationLoaded = null;
		this.pageState = 'loading';
		this.resyncing = false;
		this.failure = null;
		this.prep = null;
		this.previewPageIndex = 0;
		this.railOpen = false;
		this.railMode = 'thumbnails';
		this.notesState = 'idle';
		this.notesText = null;
		this.zoom = 1;
		this.readingView = false;
		this.readingState = 'idle';
		this.readingText = null;
		this.pointerTool = false;
		this.inkTool = false;
		this.remotePointers = [];
		this.inkStrokes = [];
		this.pendingGrant = null;
		this.handoffReason = '';
		this.politeMessage = '';
		this.assertiveMessage = '';
	}

	// ── reauthorization + checkpoint reads ────────────────────────────────

	/** The bounded checkpoint-invalidation entry points: data-channel hints
	 *  (room seam) and `presentation_state` push facts (MeetStore.applyEvent)
	 *  both land here — coalesced by the frozen refresher, never promoting
	 *  anything by themselves. */
	hint(): void {
		if (!this.#suspended && this.checkpoint) this.#refresher.hint();
	}

	/** Reauthorize from scratch: the join/read projection (meeting_get's
	 *  `presentation` summary, via the owning MeetStore) decides WHETHER a
	 *  live session exists; the authorized checkpoint read provides the full
	 *  truth (amPresenter included). Called on room connect, reconnect,
	 *  breakout return and whiteboard return. No cached grant ever
	 *  substitutes — if the server says there is no live session, local
	 *  state clears. */
	async sync(): Promise<void> {
		if (!this.enabled || this.#meetingId == null || this.#summaryProvider === null) return;
		this.#suspended = false;
		const work = this.#work(null)!;
		const gen = ++this.#syncGeneration;
		// This snapshot only fences a failed read. Local preview promotion must
		// not retrigger the caller's reauthorization effect against an old summary.
		const priorCheckpoint = untrack(() => this.checkpoint);
		const summary = this.#summaryProvider();
		if (!summary) {
			this.#clearSession(null);
			return;
		}
		try {
			const cp = await this.#api.getCheckpoint(work.meetingId, summary.presentationId);
			if (!this.#owns(work) || gen !== this.#syncGeneration) return; // superseded by a newer sync/reset
			this.#promote(cp);
		} catch {
			// Presentation API loss disables mutations (the independent
			// connection-truth contract); the last validated page stays
			// visible and marked stale — never inferred as ended.
			if (!this.#owns(work) || gen !== this.#syncGeneration) return;
			if (this.checkpoint && this.checkpoint === priorCheckpoint) this.pageState = 'stale';
		}
	}

	/** The authorized checkpoint read backing the frozen CheckpointRefresher
	 *  (hints) and the manual resync. Re-throws with the normalized throttle
	 *  shape so the refresher's bounded Retry-After backoff applies;
	 *  non-throttled failures recover immediately. */
	async refreshCheckpoint(): Promise<void> {
		const cp = this.checkpoint;
		const work = this.#work();
		if (!cp || !work) return;
		try {
			const next = await this.#api.getCheckpoint(work.meetingId, cp.presentationId);
			if (!this.#owns(work)) return;
			this.#promote(next);
		} catch (err) {
			if (!this.#owns(work) || this.checkpoint?.checkpointSeq !== cp.checkpointSeq) return;
			this.pageState = 'stale';
			throw normalizeThrottleError(err);
		}
	}

	/** Manual resync (the stale banner's affordance): marks in flight,
	 *  refreshes, restores controls on success. */
	async resync(): Promise<void> {
		const work = this.#work();
		if (this.resyncing || !work) return;
		this.resyncing = true;
		try {
			await this.refreshCheckpoint();
			if (!this.#owns(work)) return;
			if (this.checkpoint?.status === 'ACTIVE') {
				this.pageState = 'current';
				this.handoffReason = '';
			}
		} catch {
			// stays stale; the refresher's own backoff governs automatic retries
		} finally {
			if (this.#owns(work)) this.resyncing = false;
		}
	}

	// ── promotion (the ONLY state-mutation surfaces) ──────────────────────

	#promote(cp: PresentationCheckpoint): void {
		const previous = this.checkpoint;
		if (previous?.presentationId === cp.presentationId && cp.checkpointSeq < previous.checkpointSeq) return;
		if (previous && previous.presentationId !== cp.presentationId) this.#retireWork();
		const sourceChanged =
			this.checkpoint !== null &&
			(cp.driveVersionId !== this.checkpoint.driveVersionId || cp.presentationId !== this.checkpoint.presentationId);
		const generationChanged = sourceChanged || cp.manifestGeneration !== this.#manifestGenerationLoaded;
		if (sourceChanged || previous?.pageIndex !== cp.pageIndex || previous?.presenterGeneration !== cp.presenterGeneration || previous?.amPresenter !== cp.amPresenter || previous?.manifestGeneration !== cp.manifestGeneration) {
			this.#readingRequest++;
			this.#notesRequest++;
			this.readingText = null;
			this.readingState = 'idle';
			this.notesText = null;
			this.notesState = 'idle';
		}
		this.checkpoint = cp;
		// Once committed ACTIVE, teardown must preserve the reducer-owned live
		// session (handoff/takeover), not mistake it for abandoned preparation.
		if (cp.status === 'ACTIVE') {
			if (this.#preparation?.presentationId === cp.presentationId) this.#preparation = null;
			// The authorized read may confirm start before its mutation reply.
			// Finish preview now; an older reply must not promote or announce.
			this.pickerOpen = false;
		}
		if (generationChanged) { this.manifest = null; this.#manifestGenerationLoaded = null; }
		// Session truth feeds the frame classifier through M2's own seam:
		// terminal sessions collapse to a null context (every late frame
		// rejects); live sessions admit fresh-sequence hints only.
		this.#room?.setPresentationContext(presentationFrameContextFromCheckpoint(cp));
		if (isTerminalFailureStatus(cp.status)) {
			this.#clearSession(cp.status === 'REVOKED' ? 'revoked' : cp.status === 'ENDED' ? 'ended' : null);
			return;
		}
		if (sourceChanged) {
			// Source/version switch: ephemeral ink never crosses a transition
			// (R5.5) and the page state reloads from the new manifest.
			this.inkStrokes = [];
			this.readingView = false;
			this.readingText = null;
			this.readingState = 'idle';
		}
		this.pageState = 'loading';
		// The page renders only once the manifest for THIS generation is in
		// hand (the async load finishing re-evaluates the page state) — a
		// fresh ACTIVE session is never mis-marked stale while the manifest
		// read is still in flight.
		if (generationChanged) {
			const work = this.#work()!;
			void this.#loadManifest().then(() => {
				if (!this.#owns(work) || !this.#sameSource(cp)) return;
				this.#loadCurrentPage();
				this.#prefetchAhead();
			});
		} else {
			this.#loadCurrentPage();
			this.#prefetchAhead();
		}
	}

	/** Merges a committed mutation fact INTO the promoted checkpoint — the
	 *  reducer's own response is the only writer besides the checkpoint
	 *  read. Publishes the canonical page.changed peer hint for a page
	 *  change (the one client-publishable durable kind; grant/takeover/end
	 *  frames are server-authority events). */
	#promoteFact(fact: PresentationMutationResponse, kind: 'page.changed' | null): boolean {
		const cp = this.checkpoint;
		if (!cp || fact.presentationId !== cp.presentationId || fact.checkpointSeq < cp.checkpointSeq) return false;
		const pageChanged = kind === 'page.changed' && fact.pageIndex !== cp.pageIndex;
		this.#promote({
			...cp,
			status: fact.status,
			checkpointSeq: fact.checkpointSeq,
			presenterGeneration: fact.presenterGeneration,
			pageIndex: fact.pageIndex,
			manifestGeneration: fact.manifestGeneration,
		});
		if (pageChanged) {
			// R5.5: page transitions clear ephemeral ink for everyone.
			this.inkStrokes = [];
			// The peer-hint broadcast: a durable frame about ALREADY-COMMITTED
			// state, re-encoded from the fact through M2's frozen seam (never
			// forwarded bytes). Peers treat it as an untrusted hint; a
			// server-side duplicate is a sequence no-op.
			const encoded = frameFromCommittedFact(fact, 'page.changed', new Date().toISOString());
			if (encoded.ok) {
				this.#room?.sendPresentationFrame({
					t: PRESENTATION_TOPIC,
					v: PRESENTATION_VERSION,
					presentationId: String(fact.presentationId),
					checkpointSeq: fact.checkpointSeq,
					presenterGeneration: fact.presenterGeneration,
					kind: 'page.changed',
					payload: { pageIndex: fact.pageIndex },
					sentAt: new Date().toISOString(),
				});
			}
		}
		return true;
	}

	/** Loads the meet-pages-v1 manifest for the promoted checkpoint. The
	 *  manifest read is the M1 serving seam — until it exists on the wire
	 *  this fails VISIBLY (generic failure + fallback offered), never with
	 *  fabricated pages. */
	#sameSource(cp: PresentationCheckpoint): boolean {
		const current = this.checkpoint;
		return current?.presentationId === cp.presentationId && current.manifestGeneration === cp.manifestGeneration &&
			current.driveNodeId === cp.driveNodeId && current.driveVersionId === cp.driveVersionId && current.manifestDigest === cp.manifestDigest;
	}

	async #loadManifest(): Promise<void> {
		const cp = this.checkpoint;
		const work = this.#work();
		if (!cp || !work) return;
		try {
			const manifest = await this.#api.getManifest(work.meetingId, cp.presentationId);
			if (!this.#owns(work) || !this.#sameSource(cp)) return;
			const pages = manifestPages(manifest);
			if (!pages) {
				this.failure = { code: 'unsupportedDocument' };
				return;
			}
			this.manifest = manifest;
			this.#manifestGenerationLoaded = cp.manifestGeneration;
		} catch {
			if (this.#owns(work) && this.#sameSource(cp)) this.failure = { code: null };
		}
	}

	#loadCurrentPage(): void {
		if (!this.currentPage) {
			this.pageState = this.checkpoint?.status === 'ACTIVE' ? 'stale' : 'loading';
			return;
		}
		this.pageState = 'current';
		if (this.readingView) void this.loadReading();
	}

	#prefetchAhead(): void {
		const pages = manifestPages(this.manifest);
		if (!pages || typeof navigator === 'undefined') return;
		// Data-saver users opt out of prefetch (the plan's constrained-
		// connectivity reduction); prefetch is warmup only — a failed warmup
		// is silent because the real render still fetches authoritatively.
		const conn = (navigator as Navigator & { connection?: { saveData?: boolean } }).connection;
		if (conn?.saveData) return;
		for (const i of prefetchPlan(this.pageIndex, this.pageCount)) {
			if (i === this.pageIndex) continue;
			const img = new Image();
			img.src = pages[i].fullPage.path;
		}
	}

	#clearSession(reason: 'ended' | 'revoked' | null): void {
		this.#retireWork();
		this.checkpoint = null;
		this.manifest = null;
		this.#manifestGenerationLoaded = null;
		this.pageState = 'loading';
		this.failure = null;
		this.prep = null;
		this.railOpen = false;
		this.railMode = 'thumbnails';
		this.notesState = 'idle';
		this.notesText = null;
		this.readingView = false;
		this.readingText = null;
		this.readingState = 'idle';
		this.pointerTool = false;
		this.inkTool = false;
		this.remotePointers = [];
		this.inkStrokes = [];
		this.pendingGrant = null;
		this.handoffReason = '';
		if (this.#sweepTimer !== null) {
			clearInterval(this.#sweepTimer);
			this.#sweepTimer = null;
		}
		// Fail the frame classifier closed — a dead session's frames reject.
		this.#room?.setPresentationContext({ presentationId: null, confirmedSeq: 0, knownGeneration: 0 });
		if (reason === 'revoked') {
			this.assertiveMessage = t('meet.presentation.failureAccessRevoked');
		} else if (reason === 'ended') {
			this.assertiveMessage = t('meet.presentation.stage.ended');
		}
	}

	// ── picker: prepare → private preview → present ───────────────────────

	/** Requests a rendition for the picked Drive node/version and polls the
	 *  authorized checkpoint read to readiness (bounded); READY lands in the
	 *  private preview. The manifest digest is pinned by the M1 rendition
	 *  pipeline — a client without it sends an empty digest and surfaces the
	 *  reducer's named rejection (never a fabricated digest). */
	async prepare(nodeId: number, versionId: number, manifestDigest = ''): Promise<void> {
		if (this.#meetingId == null || this.#suspended) return;
		const pickerOpen = this.pickerOpen;
		this.cancelPrepare();
		this.pickerOpen = pickerOpen;
		const preparing: Preparation = { work: this.#work(null)!, presentationId: null, cleanupStarted: false };
		this.#preparation = preparing;
		this.failure = null;
		this.handoffReason = '';
		try {
			const created = await this.#api.prepare(preparing.work.meetingId, { nodeId, versionId, manifestDigest });
			preparing.presentationId = created.presentationId;
			if (!this.#owns(preparing.work)) { await this.#drainPreparation(preparing); return; }
			this.previewPageIndex = 0;
			this.prep = { presentationId: created.presentationId, status: created.status };
			await this.#pollRendition(preparing);
		} catch (err) {
			if (this.#owns(preparing.work)) this.#prepFailure(err);
		}
	}

	async #pollRendition(preparing: Preparation): Promise<void> {
		const { work, presentationId } = preparing;
		if (presentationId === null) return;
		for (let attempt = 0; attempt < RENDITION_POLL_MAX; attempt++) {
			if (!this.#owns(work)) return;
			const p = this.prep;
			if (!p || p.presentationId !== presentationId) return;
			if (isTerminalFailureStatus(p.status)) { this.#prepFailure(null); return; }
			const preview = p.status === 'READY';
			if (!preview) await this.#sleep(RENDITION_POLL_MS);
			if (!this.#owns(work)) return;
			try {
				const cp = await this.#api.getCheckpoint(work.meetingId, presentationId);
				if (!this.#owns(work)) return;
				if (preview) {
					this.prep = null;
					if (isTerminalFailureStatus(cp.status)) { this.#prepFailure(null); return; }
					this.pickerOpen = true;
					this.#promote(cp);
					return;
				}
				this.prep = { presentationId, status: cp.status };
			} catch (err) {
				if (this.#owns(work)) this.#prepFailure(err);
				return;
			}
		}
		if (this.#owns(work)) this.#prepFailure({ code: 'rendererTimeout' });
	}

	#prepFailure(err: unknown): void {
		const code = (err as { code?: string } | null)?.code;
		this.failure = { code: typeof code === 'string' ? code : null };
		this.prep = null;
	}

	/** Cancel during prepare/preview: drop the local flow and fire a
	 *  best-effort end (the drain posture — a cancelled preparation must
	 *  never strand an accepted rendition session). */
	cancelPrepare(): void {
		// Retirement drains a known preparation now, or its eventual accepted
		// response later. A READY preview remains owned until Present commits.
		const preview = this.isPreviewing && this.#meetingId !== null && this.#preparation === null
			? { meetingId: this.#meetingId, presentationId: this.checkpoint!.presentationId } : null;
		this.pickerOpen = false;
		this.#clearSession(null);
		if (preview) void this.#cleanup(preview);
	}

	/** Commits READY → ACTIVE. The reducer response is the only promoter. */
	async present(): Promise<void> {
		const cp = this.checkpoint;
		const work = this.#work();
		if (!cp || !work) return;
		try {
			const fact = await this.#api.start(work.meetingId, cp.presentationId, cp.presenterGeneration);
			if (!this.#owns(work)) return;
			if (!this.#promoteFact(fact, null)) return;
			this.#preparation = null;
			this.pickerOpen = false;
			this.politeMessage = t('meet.presentation.stage.presenterYou');
		} catch (err) {
			if (!this.#owns(work)) return;
			this.#mutationFailure(err);
		}
	}

	// ── presenter mutations ────────────────────────────────────────────────

	/** Presenter page change: bounded, presenter-gated (render gate only —
	 *  the reducer re-checks + fences on generation/sequence), promoted only
	 *  from the committed fact. */
	async changePage(pageIndex: number): Promise<void> {
		const cp = this.checkpoint;
		const work = this.#work();
		if (cp === null || !cp.amPresenter || cp.status !== 'ACTIVE' || !work) return;
		const target = clampPageIndex(pageIndex, this.pageCount);
		if (target === cp.pageIndex) return;
		try {
			const fact = await this.#api.changePage(
				work.meetingId,
				cp.presentationId,
				{ presenterGeneration: cp.presenterGeneration, checkpointSeq: cp.checkpointSeq },
				target,
			);
			if (!this.#owns(work)) return;
			if (!this.#promoteFact(fact, 'page.changed')) return;
			this.politeMessage = t('meet.presentation.stage.pageChanged', {
				n: String(fact.pageIndex + 1),
				total: String(this.pageCount),
			});
		} catch (err) {
			if (!this.#owns(work)) return;
			this.#mutationFailure(err);
		}
	}

	navigate(delta: number): void {
		if (this.checkpoint) void this.changePage(this.checkpoint.pageIndex + delta);
	}

	/** Hands the presenter grant to `targetParticipantId` (a meeting_attendee
	 *  row id — the M2 wire's participant identity). The old presenter
	 *  becomes read-only the moment the promoted truth says so — never a
	 *  local optimistic flip. */
	async grantPresenter(targetParticipantId: number): Promise<void> {
		const cp = this.checkpoint;
		const work = this.#work();
		if (cp === null || !cp.amPresenter || cp.status !== 'ACTIVE' || !work || this.pendingGrant !== null) {
			return;
		}
		this.pendingGrant = targetParticipantId;
		this.handoffReason = '';
		try {
			const fact = await this.#api.grantPresenter(work.meetingId, cp.presentationId, {
				targetParticipantId,
				takeover: false,
				presenterGeneration: cp.presenterGeneration,
			});
			if (!this.#owns(work)) return;
			if (!this.#promoteFact(fact, null)) return;
			this.politeMessage = t('meet.presentation.stage.announceHandoff', { name: String(targetParticipantId) });
			// The fact does not carry amPresenter: re-read so the OLD presenter
			// becomes read-only immediately (the plan's handoff row), never
			// one refresh late.
			await this.refreshCheckpoint().catch(() => undefined);
		} catch (err) {
			if (!this.#owns(work)) return;
			this.#handoffFailure(err);
		} finally {
			if (this.#owns(work)) this.pendingGrant = null;
		}
	}

	/** Authorized takeover — the path when the presenter departed and left
	 *  controls unavailable. Targets SELF via the checkpoint's own
	 *  myParticipantId; verb-specific authority is re-checked server-side. */
	async takeoverPresenter(): Promise<void> {
		const cp = this.checkpoint;
		const work = this.#work();
		if (cp === null || !work || this.pendingGrant !== null || cp.myParticipantId == null) return;
		this.pendingGrant = cp.myParticipantId;
		this.handoffReason = '';
		try {
			const fact = await this.#api.grantPresenter(work.meetingId, cp.presentationId, {
				targetParticipantId: cp.myParticipantId,
				takeover: true,
				presenterGeneration: cp.presenterGeneration,
			});
			if (!this.#owns(work)) return;
			if (!this.#promoteFact(fact, null)) return;
			this.politeMessage = t('meet.presentation.stage.presenterYou');
			// confirm the new presenter state from the authorized read
			await this.refreshCheckpoint().catch(() => undefined);
		} catch (err) {
			if (!this.#owns(work)) return;
			this.#handoffFailure(err);
		} finally {
			if (this.#owns(work)) this.pendingGrant = null;
		}
	}

	/** Ends the session (presenter/host authority, enforced server-side).
	 *  Unconditional drain posture: always issuable, best-effort locally. */
	async end(): Promise<void> {
		const cp = this.checkpoint;
		const work = this.#work();
		if (!cp || !work) return;
		this.pickerOpen = false;
		try {
			await this.#api.end(work.meetingId, cp.presentationId, cp.presenterGeneration);
			if (!this.#owns(work)) return;
		} catch {
			// idempotent drain — the promoted clear below never waits on it
		}
		if (this.#owns(work)) this.#clearSession('ended');
	}

	/** Suspends the stage (whiteboard opens, breakout move): ephemeral ink
	 *  never survives a transition (R5.5) and tools reset; durable state is
	 *  kept and reloaded by sync() on return. */
	suspend(): void {
		this.#retireWork();
		this.#suspended = true;
		this.readingText = null;
		this.readingState = 'idle';
		this.notesText = null;
		this.notesState = 'idle';
		this.pointerTool = false;
		this.inkTool = false;
		this.remotePointers = [];
		this.inkStrokes = [];
	}

	#handoffFailure(err: unknown): void {
		const code = (err as { code?: string } | null)?.code;
		this.handoffReason = t(presentationFailureKey(typeof code === 'string' ? code : null));
		void this.refreshCheckpoint().catch(() => undefined);
	}

	#mutationFailure(err: unknown): void {
		const code = (err as { code?: string } | null)?.code;
		if (code === 'stalePresenterGeneration') {
			// The rescue registry: refresh the checkpoint so controls adopt
			// the current presenter, and say so.
			void this.refreshCheckpoint().catch(() => undefined);
			this.politeMessage = t('meet.presentation.failureStaleGeneration');
			return;
		}
		this.politeMessage = t(presentationFailureKey(typeof code === 'string' ? code : null));
	}

	// ── local-only controls ────────────────────────────────────────────────

	zoomIn(): void {
		this.#setZoom(this.zoom * 1.25);
	}

	zoomOut(): void {
		this.#setZoom(this.zoom / 1.25);
	}

	resetZoom(): void {
		this.#setZoom(1);
	}

	#setZoom(z: number): void {
		const next = Math.min(3, Math.max(0.5, Number.isFinite(z) ? z : 1));
		if (next === this.zoom) return;
		this.zoom = next;
		// Local zoom is announced as local and never changes shared state.
		this.politeMessage = t('meet.presentation.stage.zoomLocalNote');
	}

	toggleReading(): void {
		this.readingView = !this.readingView;
		if (this.readingView) void this.loadReading();
	}

	/** Loads the current page's qualified accessible representation. Absence
	 *  is an explicit accessibility limitation — never fabricated text. */
	async loadReading(): Promise<void> {
		const work = this.#work();
		const cp = this.checkpoint;
		if (!work || !cp) return;
		const request = ++this.#readingRequest;
		const current = (): boolean => this.#owns(work) && this.#sameSource(cp) &&
			this.checkpoint?.pageIndex === cp.pageIndex && this.checkpoint?.presenterGeneration === cp.presenterGeneration &&
			this.checkpoint?.amPresenter === cp.amPresenter && request === this.#readingRequest;
		const page = this.currentPage;
		if (!page) return;
		const ref = page.accessibleRepresentation;
		if (!ref) {
			this.readingState = 'unavailable';
			this.readingText = null;
			return;
		}
		this.readingState = 'loading';
		try {
			const text = await this.#api.fetchText(ref);
			if (!current()) return;
			this.readingText = text;
			this.readingState = 'ready';
		} catch {
			if (!current()) return;
			this.readingState = 'unavailable';
			this.readingText = null;
		}
	}

	// ── presenter rail: notes ──────────────────────────────────────────────

	openRail(mode: 'thumbnails' | 'notes'): void {
		this.railMode = mode;
		this.railOpen = true;
		if (mode === 'notes') void this.loadNotes();
	}

	closeRail(): void {
		this.railOpen = false;
	}

	/** Speaker notes: presenter-gated on EVERY fetch (the store refuses
	 *  client-side without the gate) and never rendered for anyone else. */
	async loadNotes(): Promise<void> {
		const work = this.#work();
		const cp = this.checkpoint;
		if (!work || !cp) return;
		const request = ++this.#notesRequest;
		const current = (): boolean => this.#owns(work) && this.#sameSource(cp) &&
			this.checkpoint?.pageIndex === cp.pageIndex && this.checkpoint?.presenterGeneration === cp.presenterGeneration &&
			this.checkpoint?.amPresenter === cp.amPresenter && request === this.#notesRequest;
		if (!this.amPresenter) return;
		const notes = this.manifest?.notes;
		if (!notes) {
			this.notesState = 'unavailable';
			this.notesText = null;
			return;
		}
		this.notesState = 'loading';
		try {
			const text = await this.#api.fetchText(notes);
			if (!current()) return;
			this.notesText = text;
			this.notesState = 'ready';
		} catch {
			if (!current()) return;
			this.notesState = 'unavailable';
			this.notesText = null;
		}
	}

	// ── ephemeral stage plane ──────────────────────────────────────────────

	/** Sends the local pointer position (normalized); leading-edge throttled
	 *  so a flood of pointermove events cannot flood the channel. */
	sendPointer(x: number, y: number): void {
		if (!this.amPresenter) return;
		this.#pendingPointer = { x: clampUnit(x), y: clampUnit(y) };
		if (!this.#pointerSend) {
			this.#pointerSend = throttleLeading(
				() => {
					const p = this.#pendingPointer;
					if (!p || !this.#room) return;
					this.#room.sendStageEvent({ t: 'stage', v: 1, kind: 'pointer', seq: ++this.#stageSeq, x: p.x, y: p.y });
				},
				80,
			);
		}
		this.#pointerSend();
	}

	/** Commits one temporary-ink stroke: local echo + ephemeral broadcast. */
	commitInk(points: number[]): void {
		if (!this.amPresenter || points.length < 2 || !this.#room) return;
		const bounded = points.slice(0, 1024).map((n) => clampUnit(n));
		this.inkStrokes = capInk([...this.inkStrokes, { id: `local-${Date.now()}-${this.#stageSeq}`, identity: 'self', points: bounded }]);
		this.#room.sendStageEvent({ t: 'stage', v: 1, kind: 'ink', seq: ++this.#stageSeq, points: bounded });
	}

	/** Clears the local participant's ink and tells peers. */
	clearInk(): void {
		if (!this.#room) return;
		this.inkStrokes = this.inkStrokes.filter((s) => s.identity !== 'self');
		this.#room.sendStageEvent({ t: 'stage', v: 1, kind: 'ink_clear', seq: ++this.#stageSeq });
	}

	#applyStageEvent(event: StageEvent, from: string): void {
		if (!this.isLive) return; // the stage plane only renders during a live session
		if (event.kind === 'pointer') {
			const next = this.remotePointers.filter((p) => p.identity !== from);
			next.push({ identity: from, x: clampUnit(event.x), y: clampUnit(event.y), expiresAt: Date.now() + POINTER_TTL_MS });
			this.remotePointers = next;
			this.#ensureSweeper();
			return;
		}
		if (event.kind === 'ink') {
			this.inkStrokes = capInk([...this.inkStrokes, { id: `${from}-${event.seq}`, identity: from, points: event.points }]);
			return;
		}
		this.inkStrokes = this.inkStrokes.filter((s) => s.identity !== from);
	}

	#ensureSweeper(): void {
		if (this.#sweepTimer !== null) return;
		this.#sweepTimer = setInterval(() => {
			const now = Date.now();
			const next = this.remotePointers.filter((p) => pointerFresh(p.expiresAt, now));
			if (next.length !== this.remotePointers.length) this.remotePointers = next;
			if (this.remotePointers.length === 0) {
				if (this.#sweepTimer !== null) clearInterval(this.#sweepTimer);
				this.#sweepTimer = null;
			}
		}, 1_000);
	}
}

function capInk(strokes: PresentationInkStroke[]): PresentationInkStroke[] {
	return strokes.length > INK_STROKE_CAP ? strokes.slice(strokes.length - INK_STROKE_CAP) : strokes;
}
