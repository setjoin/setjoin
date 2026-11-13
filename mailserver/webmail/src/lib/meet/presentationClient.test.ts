// presentationClient.test.ts — MEET plan M3 pure client logic: local zoom
// bounds, page navigation bounds (incl. the frozen MAX_PAGE_INDEX), the
// presenter render gate, departed-presenter detection, the bounded prefetch
// plan, the ephemeral pointer plane (normalization/TTL/throttle), and the
// frozen warning/failure vocabularies' i18n key mapping + throttle-error
// normalization.
import { describe, it, expect } from 'vitest';
import {
	MAX_PAGE_INDEX,
} from './presentation';
import {
	canMutateAsPresenter,
	clampPageIndex,
	clampUnit,
	clampZoom,
	MAX_ZOOM,
	MIN_ZOOM,
	normalizeThrottleError,
	nextZoomIn,
	nextZoomOut,
	prefetchPlan,
	PREFETCH_AHEAD,
	presentationFailureKey,
	POINTER_TTL_MS,
	pointerFresh,
	renditionWarningKey,
	throttleLeading,
	ZOOM_STEP,
} from './presentationClient';
import type { PresentationCheckpoint } from './presentationCheckpoint';

function checkpoint(over: Partial<PresentationCheckpoint> = {}): PresentationCheckpoint {
	return {
		presentationId: 1,
		status: 'ACTIVE',
		checkpointSeq: 40,
		presenterGeneration: 3,
		presenterParticipantId: 7,
		pageIndex: 4,
		manifestGeneration: 1,
		manifestDigest: 'd1',
		driveNodeId: 7,
		driveVersionId: 9,
		myParticipantId: 7,
		amPresenter: true,
		...over,
	};
}

describe('local zoom', () => {
	it('clamps into [MIN_ZOOM, MAX_ZOOM]; non-finite falls back to 1', () => {
		expect(clampZoom(0.1)).toBe(MIN_ZOOM);
		expect(clampZoom(99)).toBe(MAX_ZOOM);
		expect(clampZoom(1.4)).toBe(1.4);
		expect(clampZoom(Number.NaN)).toBe(1);
		expect(clampZoom(Number.POSITIVE_INFINITY)).toBe(1);
	});

	it('steps multiply by ZOOM_STEP and stay clamped', () => {
		expect(nextZoomIn(1)).toBeCloseTo(ZOOM_STEP);
		expect(nextZoomIn(MAX_ZOOM)).toBe(MAX_ZOOM);
		expect(nextZoomOut(1)).toBeCloseTo(1 / ZOOM_STEP);
		expect(nextZoomOut(MIN_ZOOM)).toBe(MIN_ZOOM);
	});
});

describe('page navigation', () => {
	it('clamps into the manifest range AND the frozen MAX_PAGE_INDEX', () => {
		expect(clampPageIndex(0, 10)).toBe(0);
		expect(clampPageIndex(-5, 10)).toBe(0);
		expect(clampPageIndex(50, 10)).toBe(9);
		expect(clampPageIndex(MAX_PAGE_INDEX + 50, MAX_PAGE_INDEX + 50)).toBe(MAX_PAGE_INDEX);
	});

	it('an empty manifest degenerates to page 0, never a negative bound', () => {
		expect(clampPageIndex(3, 0)).toBe(0);
		expect(clampPageIndex(Number.NaN, 10)).toBe(0);
		expect(clampPageIndex(2.7, 10)).toBe(2);
	});
});

describe('presenter render gate', () => {
	it('admits only the ACTIVE session where the server says amPresenter', () => {
		expect(canMutateAsPresenter(checkpoint())).toBe(true);
		expect(canMutateAsPresenter(checkpoint({ amPresenter: false }))).toBe(false);
		expect(canMutateAsPresenter(checkpoint({ status: 'READY' }))).toBe(false);
		expect(canMutateAsPresenter(checkpoint({ status: 'DEGRADED' }))).toBe(false);
		expect(canMutateAsPresenter(null)).toBe(false);
	});
});

describe('bounded prefetch plan', () => {
	it('plans current + next two pages, inside the manifest range', () => {
		expect(prefetchPlan(0, 10)).toEqual([0, 1, 2]);
		expect(prefetchPlan(8, 10)).toEqual([8, 9]);
		expect(prefetchPlan(9, 10)).toEqual([9]);
		expect(prefetchPlan(0, 0)).toEqual([]);
		expect(PREFETCH_AHEAD).toBe(2);
	});

	it('never plans beyond MAX_PAGE_INDEX even for a huge manifest', () => {
		const plan = prefetchPlan(MAX_PAGE_INDEX, MAX_PAGE_INDEX + 1);
		expect(plan).toEqual([MAX_PAGE_INDEX]);
	});
});

describe('ephemeral pointer plane', () => {
	it('clampUnit clamps into [0,1]', () => {
		expect(clampUnit(-1)).toBe(0);
		expect(clampUnit(0.5)).toBe(0.5);
		expect(clampUnit(2)).toBe(1);
		expect(clampUnit(Number.NaN)).toBe(0);
	});

	it('pointerFresh honors the TTL', () => {
		expect(pointerFresh(1000 + POINTER_TTL_MS, 1000)).toBe(true);
		expect(pointerFresh(1000, 1000 + POINTER_TTL_MS)).toBe(false);
	});
});

describe('throttleLeading', () => {
	it('fires the first call immediately, drops calls inside the window, recovers after', () => {
		let now = 1_000;
		let calls = 0;
		const throttled = throttleLeading(
			() => {
				calls++;
			},
			80,
			() => now,
		);
		throttled();
		now += 10;
		throttled();
		now += 10;
		throttled();
		expect(calls).toBe(1);
		now += 200;
		throttled();
		expect(calls).toBe(2);
		// cancel permanently suppresses (teardown path)
		throttled.cancel();
		now += 200;
		throttled();
		expect(calls).toBe(2);
	});
});

describe('frozen vocabularies → i18n keys', () => {
	it('every rendition warning maps to its literal key; unknown falls back', () => {
		expect(renditionWarningKey('font_substituted')).toBe('meet.presentation.warningFont');
		expect(renditionWarningKey('animation_unsupported')).toBe('meet.presentation.warningAnimation');
		expect(renditionWarningKey('embedded_media')).toBe('meet.presentation.warningMedia');
		expect(renditionWarningKey('truncated')).toBe('meet.presentation.warningTruncated');
		expect(renditionWarningKey('password_protected')).toBe('meet.presentation.warningProtected');
		expect(renditionWarningKey('partial_conversion')).toBe('meet.presentation.warningPartial');
	});

	it('failure codes map to literal keys; unknown/null fail closed to generic copy', () => {
		expect(presentationFailureKey('sourceVersionGone')).toBe('meet.presentation.failureSourceVersionGone');
		expect(presentationFailureKey('stalePresenterGeneration')).toBe('meet.presentation.failureStaleGeneration');
		expect(presentationFailureKey('mysteryCode')).toBe('meet.presentation.failureGeneric');
		expect(presentationFailureKey(null)).toBe('meet.presentation.failureGeneric');
		expect(presentationFailureKey(undefined)).toBe('meet.presentation.failureGeneric');
	});
});

describe('normalizeThrottleError', () => {
	it('adapts the ProblemError shape into the throttle contract', () => {
		const adapted = normalizeThrottleError({
			code: 'checkpointRefreshThrottled',
			extensions: { retryAfterMs: 5_000 },
		}) as { problem: string; retryAfterMs: number };
		expect(adapted.problem).toBe('checkpointRefreshThrottled');
		expect(adapted.retryAfterMs).toBe(5_000);
	});

	it('passes non-throttled errors through untouched', () => {
		const err = new Error('boom');
		expect(normalizeThrottleError(err)).toBe(err);
		const throttledNoHeader = { code: 'checkpointRefreshThrottled', extensions: {} };
		const adapted = normalizeThrottleError(throttledNoHeader) as { retryAfterMs: unknown };
		expect(adapted.retryAfterMs).toBeUndefined();
	});
});
