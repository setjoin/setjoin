// presentationClient.ts — MEET plan M3 pure client-side presentation logic:
// local zoom bounds, page navigation bounds, the bounded prefetch plan, the
// ephemeral pointer normalization/TTL, the leading-edge pointer throttle, and
// the frozen warning/failure vocabularies' i18n key mapping. Plain
// data-in/data-out functions, fully testable in jsdom with no Svelte/LiveKit/
// HTTP dependency (the whiteboard.ts split precedent: protocol logic here,
// state in presentationStore.svelte.ts, markup in the components).
import type { PresentationCheckpoint } from './presentationCheckpoint';
import type { RenditionWarningCode } from './presentationApi';
import { MAX_PAGE_INDEX } from './presentation';

// ── local zoom ────────────────────────────────────────────────────────────
// Local zoom is announced as local and never changes shared state (plan
// "Responsive and accessibility contract"). Bounds chosen to keep a 4K page
// legible at the low end and a fine-print region readable at the high end.
export const MIN_ZOOM = 0.5;
export const MAX_ZOOM = 3;
export const ZOOM_STEP = 1.25;

export function clampZoom(z: number): number {
	if (!Number.isFinite(z)) return 1;
	return Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, z));
}

export function nextZoomIn(z: number): number {
	return clampZoom(z * ZOOM_STEP);
}

export function nextZoomOut(z: number): number {
	return clampZoom(z / ZOOM_STEP);
}

// ── page navigation ───────────────────────────────────────────────────────

/** Clamps a requested page index into the manifest's dense page range AND
 *  the frozen MAX_PAGE_INDEX bound ([0, 499], presentation.ts) — a manifest
 *  can never carry more pages than the wire bound admits, but the client
 *  never trusts that alone. */
export function clampPageIndex(i: number, pageCount: number): number {
	const bound = Math.min(Math.max(pageCount, 0) - 1, MAX_PAGE_INDEX);
	if (!Number.isFinite(i)) return 0;
	return Math.min(Math.max(Math.trunc(i), 0), Math.max(bound, 0));
}

/** The client-side render gate for durable presenter mutations (page
 *  change): the session is LIVE and the authorized checkpoint read says the
 *  caller IS the presenter (server-derived amPresenter — never a client
 *  claim). The reducer re-checks everything server-side and fences on the
 *  generation/checkpoint sequence; this gate only avoids issuing requests
 *  that cannot succeed, and NEVER confers authority — a stale local view
 *  can only under-trigger, never over-trigger. */
export function canMutateAsPresenter(
	checkpoint: Pick<PresentationCheckpoint, 'status' | 'amPresenter'> | null,
): boolean {
	if (!checkpoint) return false;
	if (checkpoint.status !== 'ACTIVE') return false;
	return checkpoint.amPresenter === true;
}

// ── bounded prefetch ──────────────────────────────────────────────────────
// "Default prefetch is current + next two pages" (plan Performance budgets).
export const PREFETCH_AHEAD = 2;

export function prefetchPlan(pageIndex: number, pageCount: number): number[] {
	const plan: number[] = [];
	for (let i = pageIndex; i <= pageIndex + PREFETCH_AHEAD && i < pageCount && i <= MAX_PAGE_INDEX; i++) {
		if (i >= 0) plan.push(i);
	}
	return plan;
}

// ── ephemeral pointer plane ───────────────────────────────────────────────

export function clampUnit(n: number): number {
	if (!Number.isFinite(n)) return 0;
	return Math.min(1, Math.max(0, n));
}

/** Remote pointers expire client-side after this TTL — a participant who
 *  stops moving (or leaves) stops rendering a stale dot. Ephemeral by
 *  definition: nothing here is ever recovered. */
export const POINTER_TTL_MS = 4000;

export function pointerFresh(expiresAt: number, now: number): boolean {
	return expiresAt > now;
}

/** Leading-edge throttle: the FIRST call in every `windowMs` fires
 *  immediately (pointer response), further calls inside the window are
 *  dropped (never queued — the next move after the window supersedes). The
 *  returned handle carries `cancel()` for teardown. Pure timing logic,
 *  testable with an injected clock. */
export function throttleLeading(fn: () => void, windowMs: number, now: () => number = Date.now): (() => void) & { cancel: () => void } {
	let last = -Infinity;
	const wrapped = (): void => {
		const t = now();
		if (t - last < windowMs) return;
		last = t;
		fn();
	};
	wrapped.cancel = (): void => {
		last = Infinity;
	};
	return wrapped;
}

// ── frozen vocabularies → i18n keys ───────────────────────────────────────
// Static literal-key maps (never dynamic `t(\`…${code}\`)` construction):
// the i18n dead/missing-key guards scan for quoted key literals, and a
// client must be able to render every code the frozen vocabularies admit.

const WARNING_KEYS: Record<RenditionWarningCode, string> = {
	font_substituted: 'meet.presentation.warningFont',
	animation_unsupported: 'meet.presentation.warningAnimation',
	embedded_media: 'meet.presentation.warningMedia',
	truncated: 'meet.presentation.warningTruncated',
	password_protected: 'meet.presentation.warningProtected',
	partial_conversion: 'meet.presentation.warningPartial',
};

export function renditionWarningKey(code: RenditionWarningCode): string {
	return WARNING_KEYS[code] ?? 'meet.presentation.warningPartial';
}

/** The plan's named failure registry, M3-relevant subset. Keys are quoted
 *  literals here so the dead/missing-key scans resolve them; an unknown
 *  code falls back to the generic failure copy (fail closed, never raw). */
const FAILURE_KEYS: Record<string, string> = {
	sourceVersionGone: 'meet.presentation.failureSourceVersionGone',
	unsupportedDocument: 'meet.presentation.failureUnsupportedDocument',
	documentProtected: 'meet.presentation.failureDocumentProtected',
	rendererTimeout: 'meet.presentation.failureRendererTimeout',
	presentationAccessRevoked: 'meet.presentation.failureAccessRevoked',
	stalePresenterGeneration: 'meet.presentation.failureStaleGeneration',
	presentationSequenceGap: 'meet.presentation.failureSequenceGap',
	checkpointRefreshThrottled: 'meet.presentation.failureThrottled',
};

export function presentationFailureKey(code: string | null | undefined): string {
	if (!code) return 'meet.presentation.failureGeneric';
	return FAILURE_KEYS[code] ?? 'meet.presentation.failureGeneric';
}

// ── throttle-contract normalization ───────────────────────────────────────

/** Adapts a ProblemError-shaped rejection into the object shape
 *  `throttledRefreshBackoffMs` (presentation.ts) reads: the 429's
 *  `checkpointRefreshThrottled` problem code rides `.code` and its
 *  `retryAfterMs` rides `.extensions` on our transport. Anything else passes
 *  through unchanged (non-throttled failures recover immediately). */
export function normalizeThrottleError(err: unknown): unknown {
	const e = err as { code?: unknown; extensions?: Record<string, unknown> } | null;
	if (!e || typeof e !== 'object' || e.code !== 'checkpointRefreshThrottled') return err;
	const retryAfterMs = e.extensions?.retryAfterMs;
	return {
		problem: 'checkpointRefreshThrottled',
		retryAfterMs: typeof retryAfterMs === 'number' ? retryAfterMs : undefined,
	};
}
