/**
 * Presentation contract edge branches (coverage round r2).
 *
 * Complementary real-behavior tests for the M0 presentation family: the
 * send-path shape rejections the happy-path suite skips, the receive-path
 * door checks, the RAW wire-payload extractor's malformed-document and
 * escape handling (including \u-escaped member keys and nested array
 * payloads), the throttle backoff's non-object guard, and the refresher's
 * default setTimeout schedule.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
	CheckpointRefresher,
	MAX_PAGE_INDEX,
	PRESENTATION_VERSION,
	classifyPresentationFrame,
	encodePresentationEnvelope,
	throttledRefreshBackoffMs,
	type PresentationEnvelope,
	type PresentationFrameContext,
} from './presentation';

function frame(overrides: Partial<PresentationEnvelope> = {}): PresentationEnvelope {
	return {
		t: 'presentation',
		v: PRESENTATION_VERSION,
		presentationId: 'p-1',
		checkpointSeq: 42,
		presenterGeneration: 3,
		kind: 'page.changed',
		payload: { pageIndex: 7 },
		sentAt: '2026-09-18T00:00:00Z',
		...overrides,
	};
}

const liveCtx: PresentationFrameContext = { presentationId: 'p-1', confirmedSeq: 40, knownGeneration: 3 };
const textEncoder = new TextEncoder();

describe('encode shape rejections', () => {
	it('rejects a frame on the wrong topic', () => {
		const r = encodePresentationEnvelope({ ...frame(), t: 'chat' } as unknown as PresentationEnvelope);
		expect(r.ok).toBe(false);
		if (!r.ok) expect(r.error).toContain('topic');
	});

	it('rejects an envelope without a presentation id', () => {
		const r = encodePresentationEnvelope(frame({ presentationId: '' }));
		expect(r.ok).toBe(false);
		if (!r.ok) expect(r.error).toContain('presentation id');
	});

	it('rejects a negative or fractional checkpointSeq', () => {
		for (const checkpointSeq of [-1, 1.5]) {
			const r = encodePresentationEnvelope(frame({ checkpointSeq }));
			expect(r.ok).toBe(false);
			if (!r.ok) expect(r.error).toContain('checkpointSeq');
		}
	});

	it('rejects a negative or fractional presenterGeneration', () => {
		for (const presenterGeneration of [-1, 2.5]) {
			const r = encodePresentationEnvelope(frame({ presenterGeneration }));
			expect(r.ok).toBe(false);
			if (!r.ok) expect(r.error).toContain('presenterGeneration');
		}
	});

	it('rejects an envelope without sentAt', () => {
		const r = encodePresentationEnvelope(frame({ sentAt: '' }));
		expect(r.ok).toBe(false);
		if (!r.ok) expect(r.error).toContain('sentAt');
	});

	it('rejects a page.changed payload at the page bound and past it', () => {
		for (const pageIndex of [MAX_PAGE_INDEX + 1, -2, 3.5]) {
			const r = encodePresentationEnvelope(frame({ payload: { pageIndex } }));
			expect(r.ok).toBe(false);
		}
	});
});

describe('receive-path door checks', () => {
	it('rejects a frame that is not an object at all', () => {
		expect(classifyPresentationFrame('not-an-object', liveCtx)).toBe('reject');
		expect(classifyPresentationFrame(42, liveCtx)).toBe('reject');
		expect(classifyPresentationFrame(null, liveCtx)).toBe('reject');
	});

	it('rejects a frame whose checkpointSeq is not a non-negative integer', () => {
		for (const checkpointSeq of [1.5, -3, '40']) {
			const verdict = classifyPresentationFrame(
				{ ...frame(), checkpointSeq: checkpointSeq as unknown as number },
				liveCtx,
			);
			expect(verdict).toBe('reject');
		}
	});
});

describe('raw wire payload extraction edges (receive path)', () => {
	const pageChanged = (payload: unknown, extra = '') => ({
		...frame(),
		kind: 'page.changed' as const,
		payload,
		...{}, // serialization is fully controlled by the raw doc below
	}) as unknown as PresentationEnvelope;

	it('a \\u-escaped member KEY still measures as the raw payload member', () => {
		// `payloa\u0064` decodes to `payload`: the extractor decodes keys before
		// matching, so the raw member is found in its original encoding.
		const doc = '{"v":1,"payloa\\u0064":{"pageIndex":7},"kind":"page.changed","t":"presentation","presentationId":"p-1","checkpointSeq":42,"presenterGeneration":3,"sentAt":"x"}';
		const verdict = classifyPresentationFrame(
			JSON.parse(doc.replace(/\\u0064/g, 'd')) as unknown,
			liveCtx,
			textEncoder.encode(doc),
		);
		// Well-formed and under target: a fresh sequence is a hint.
		expect(verdict).toBe('invalidate-checkpoint');
	});

	it('every simple key escape decodes during the raw key scan', () => {
		// Keys carrying \", \\, \/, \b, \f, \n, \r and \t are all decoded by the
		// key scanner before it matches them against 'payload'; none match, so
		// extraction falls back and the well-formed frame still walks.
		const doc = '{"a\\"b":1,"a\\\\b":1,"a\\/b":1,"a\\bb":1,"a\\fb":1,"a\\nb":1,"a\\rb":1,"a\\tb":1,"payload":{"pageIndex":7}}';
		const verdict = classifyPresentationFrame(
			{ t: 'presentation', v: 1, kind: 'page.changed', presentationId: 'p-1', checkpointSeq: 41, presenterGeneration: 3, payload: { pageIndex: 7 } },
			liveCtx,
			textEncoder.encode(doc),
		);
		expect(verdict).toBe('invalidate-checkpoint');
	});

	it('a key with a malformed \\u hex escape aborts raw extraction and falls back', () => {
		const doc = '{"payloa\\uZZZZ":1,"payload":{"pageIndex":7}}';
		const verdict = classifyPresentationFrame(
			{ t: 'presentation', v: 1, kind: 'page.changed', presentationId: 'p-1', checkpointSeq: 41, presenterGeneration: 3, payload: { pageIndex: 7 } },
			liveCtx,
			textEncoder.encode(doc),
		);
		expect(verdict).toBe('invalidate-checkpoint');
	});

	it('a key with a simple escape decodes and still matches', () => {
		const doc = '{"payl\\u006f\\u0061d": 9}';
		// JSON.parse yields key 'payload' with scalar 9 — the frame then fails
		// payload validation (no integer pageIndex) rather than the extractor
		// missing the member.
		const verdict = classifyPresentationFrame(
			{ t: 'presentation', v: 1, kind: 'page.changed', presentationId: 'p-1', checkpointSeq: 41, presenterGeneration: 3, payload: 9 },
			liveCtx,
			textEncoder.encode(doc),
		);
		expect(verdict).toBe('reject');
	});

	it('a malformed key escape falls back to the re-serialized measure (no crash)', () => {
		const doc = '{"paylo\\q":1}';
		const verdict = classifyPresentationFrame(
			{ t: 'presentation', v: 1, kind: 'page.changed', presentationId: 'p-1', checkpointSeq: 41, presenterGeneration: 3, payload: { pageIndex: 7 } },
			liveCtx,
			textEncoder.encode(doc),
		);
		// The extractor found no usable raw member; the frame itself is
		// well-formed so the walk proceeds on the parsed payload measure.
		expect(verdict).toBe('invalidate-checkpoint');
	});

	it('documents that are not JSON objects yield no raw member and fall back', () => {
		for (const doc of ['[1,2,3]', '"a string"', '{}']) {
			const verdict = classifyPresentationFrame(
				{ t: 'presentation', v: 1, kind: 'page.changed', presentationId: 'p-1', checkpointSeq: 41, presenterGeneration: 3, payload: { pageIndex: 7 } },
				liveCtx,
				textEncoder.encode(doc),
			);
			expect(verdict).toBe('invalidate-checkpoint');
		}
	});

	it('truncated keys, missing colons and truncated values fall back instead of throwing', () => {
		const docs = [
			'{"payload', // key never closes
			'{"payload" 1}', // missing colon
			'{"payload":{"pageIndex":7', // value never closes
			'{"payload":"never-closes', // string value never closes
			'{"payload":1,', // separator with no trailing member or close
		];
		for (const doc of docs) {
			const verdict = classifyPresentationFrame(
				{ t: 'presentation', v: 1, kind: 'page.changed', presentationId: 'p-1', checkpointSeq: 41, presenterGeneration: 3, payload: { pageIndex: 7 } },
				liveCtx,
				textEncoder.encode(doc),
			);
			expect(verdict).toBe('invalidate-checkpoint');
		}
	});

	it('a nested-array payload measures its FULL raw extent (escapes-free arrays included)', () => {
		const rawPayload = '{"pages":[[1],[2]],"pageIndex":1}';
		const doc = `{"t":"presentation","payload":${rawPayload}}`;
		const verdict = classifyPresentationFrame(
			{ t: 'presentation', v: 1, kind: 'page.changed', presentationId: 'p-1', checkpointSeq: 41, presenterGeneration: 3, payload: JSON.parse(rawPayload) },
			liveCtx,
			textEncoder.encode(doc),
		);
		expect(verdict).toBe('invalidate-checkpoint');
	});
});

describe('throttledRefreshBackoffMs guards', () => {
	it('non-object failures recover immediately (null backoff)', () => {
		expect(throttledRefreshBackoffMs(null)).toBeNull();
		expect(throttledRefreshBackoffMs('boom')).toBeNull();
		expect(throttledRefreshBackoffMs(42)).toBeNull();
	});
});

describe('CheckpointRefresher default schedule', () => {
	beforeEach(() => {
		vi.useFakeTimers();
	});
	afterEach(() => {
		vi.useRealTimers();
	});

	it('constructs without an injected schedule and parks through real setTimeout when tokens run out', async () => {
		const refreshes: number[] = [];
		// No injected clock/schedule: production defaults (Date.now + setTimeout).
		const refresher = new CheckpointRefresher(async () => {
			refreshes.push(1);
		});
		// Drain the whole burst allowance immediately.
		refresher.hint();
		await vi.advanceTimersByTimeAsync(0);
		refresher.hint();
		await vi.advanceTimersByTimeAsync(0);
		expect(refreshes).toHaveLength(2);
		// The burst is exhausted: the third hint parks on the DEFAULT schedule
		// until the next token refills (~200 ms at 5 tokens/s).
		refresher.hint();
		expect(refreshes).toHaveLength(2);
		await vi.advanceTimersByTimeAsync(250);
		expect(refreshes).toHaveLength(3);
	});
});
