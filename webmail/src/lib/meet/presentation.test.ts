// presentation.test.ts — MEET plan M0 contract tests for the frozen
// `t:'presentation'` data-channel family ("Svelte/Vitest: envelope
// validation, resync" verification-matrix row, owned by M0 for the envelope
// contract). Pure data-in/data-out: no LiveKit, no store.
import { describe, it, expect, vi } from 'vitest';
import {
	CHECKPOINT_REFRESH_BURST,
	CHECKPOINT_REFRESH_PER_SECOND,
	MAX_ENVELOPE_BYTES,
	MAX_PAGE_INDEX,
	PRESENTATION_VERSION,
	TARGET_PAGE_CHANGE_PAYLOAD_BYTES,
	CheckpointRefresher,
	classifyPresentationFrame,
	encodePresentationEnvelope,
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

// ── encodePresentationEnvelope ──────────────────────────────────────────
describe('encodePresentationEnvelope', () => {
	it('encodes a well-formed frame under the wire budget', () => {
		const r = encodePresentationEnvelope(frame());
		expect(r.ok).toBe(true);
		if (r.ok) expect(r.bytes.length).toBeLessThanOrEqual(MAX_ENVELOPE_BYTES);
	});

	it('rejects unknown versions (fail closed)', () => {
		const r = encodePresentationEnvelope(frame({ v: 2 }));
		expect(r.ok).toBe(false);
		if (!r.ok) expect(r.error).toContain('fails closed');
	});

	it('rejects unknown kinds (fail closed)', () => {
		const r = encodePresentationEnvelope(frame({ kind: 'brand.new.kind' as PresentationEnvelope['kind'] }));
		expect(r.ok).toBe(false);
	});

	it('M4 admission: annotation kinds encode when they carry the admitted payload shapes', () => {
		// A committed snapshot carries the bounded reference triple; a clear
		// carries no payload. (admitted-path semantics — the shapes stay
		// closed; the payload refusals live in the dedicated cases below.)
		const committed = encodePresentationEnvelope(
			frame({
				kind: 'annotation.committed',
				payload: { snapshotRef: 'annotations/p7-s3.json', sha256: 'ab'.repeat(32), byteSize: 256 },
			}),
		);
		expect(committed.ok).toBe(true);
		const cleared = encodePresentationEnvelope(frame({ kind: 'annotation.cleared', payload: undefined }));
		expect(cleared.ok).toBe(true);
	});

	it('rejects unadmitted annotation payloads on the send path (admitted-path semantics)', () => {
		const good = { snapshotRef: 'annotations/p7-s3.json', sha256: 'ab'.repeat(32), byteSize: 256 };
		// a commit without the typed reference payload
		expect(encodePresentationEnvelope(frame({ kind: 'annotation.committed', payload: {} })).ok).toBe(false);
		// a foreign snapshot reference
		expect(
			encodePresentationEnvelope(frame({ kind: 'annotation.committed', payload: { ...good, snapshotRef: '../../etc/passwd' } }))
				.ok,
		).toBe(false);
		// a bad digest
		expect(
			encodePresentationEnvelope(frame({ kind: 'annotation.committed', payload: { ...good, sha256: 'nothex' } })).ok,
		).toBe(false);
		// an over-bound byte size
		expect(
			encodePresentationEnvelope(frame({ kind: 'annotation.committed', payload: { ...good, byteSize: 16385 } })).ok,
		).toBe(false);
		// a clear carrying a payload
		expect(encodePresentationEnvelope(frame({ kind: 'annotation.cleared', payload: good })).ok).toBe(false);
	});

	it('rejects a page.changed payload without an integer pageIndex', () => {
		expect(encodePresentationEnvelope(frame({ payload: {} })).ok).toBe(false);
		expect(encodePresentationEnvelope(frame({ payload: { pageIndex: 1.5 } })).ok).toBe(false);
	});

	it('rejects page indexes outside the manifest bound', () => {
		expect(encodePresentationEnvelope(frame({ payload: { pageIndex: -1 } })).ok).toBe(false);
		expect(encodePresentationEnvelope(frame({ payload: { pageIndex: MAX_PAGE_INDEX + 1 } })).ok).toBe(false);
		expect(encodePresentationEnvelope(frame({ payload: { pageIndex: MAX_PAGE_INDEX } })).ok).toBe(true);
	});

	it('rejects page-change payloads over the 1 KiB target', () => {
		const fat = 'x'.repeat(TARGET_PAGE_CHANGE_PAYLOAD_BYTES + 1);
		const r = encodePresentationEnvelope(frame({ payload: { pageIndex: 0, note: fat } }));
		expect(r.ok).toBe(false);
		if (!r.ok) expect(r.error).toContain('target');
	});

	it('measures the page-change payload budget in UTF-8 wire bytes, not string length', () => {
		// M0/M1 review regression: 'α' is 1 UTF-16 unit but 2 UTF-8 bytes, so
		// 600 of them stringify to 623 "length" (the old check passed) while
		// occupying 1223 bytes on the wire. The budget is measured with
		// TextEncoder byte lengths.
		const sneaky = 'α'.repeat(600);
		expect(sneaky.length).toBeLessThanOrEqual(TARGET_PAGE_CHANGE_PAYLOAD_BYTES);
		const r = encodePresentationEnvelope(frame({ payload: { pageIndex: 0, note: sneaky } }));
		expect(r.ok).toBe(false);
		if (!r.ok) expect(r.error).toContain('target');
		// A multibyte payload genuinely under the 1 KiB wire budget encodes.
		const withinBudget = 'α'.repeat(400);
		expect(encodePresentationEnvelope(frame({ payload: { pageIndex: 0, note: withinBudget } })).ok).toBe(true);
	});

	it('rejects an envelope whose complete serialized size exceeds 14000 bytes', () => {
		const pad = 'y'.repeat(MAX_ENVELOPE_BYTES);
		// A legal (non-page.changed) kind carrying an oversized snapshot —
		// the plan's remedy is the authorized bounded reference/read path,
		// never implicit fragmentation.
		const r = encodePresentationEnvelope(frame({ kind: 'ready', payload: { pad } }));
		expect(r.ok).toBe(false);
		if (!r.ok) expect(r.error).toContain('14000');
	});

	it('byte budget is the serialization truth: a frame under the bound encodes', () => {
		const near = 'z'.repeat(6000);
		const r = encodePresentationEnvelope(frame({ kind: 'ready', payload: { pad: near } }));
		expect(r.ok).toBe(true);
	});
});

// ── classifyPresentationFrame (receive side) ─────────────────────────────
describe('classifyPresentationFrame', () => {
	it('fresh sequence invalidates the checkpoint (a hint, never direct promotion)', () => {
		expect(classifyPresentationFrame(frame({ checkpointSeq: 41 }), liveCtx)).toBe('invalidate-checkpoint');
		expect(classifyPresentationFrame(frame({ checkpointSeq: 999 }), liveCtx)).toBe('invalidate-checkpoint');
	});

	it('duplicate and old sequences are no-ops', () => {
		expect(classifyPresentationFrame(frame({ checkpointSeq: 40 }), liveCtx)).toBe('noop');
		expect(classifyPresentationFrame(frame({ checkpointSeq: 3 }), liveCtx)).toBe('noop');
	});

	it('rejects unknown family versions and non-presentation topics', () => {
		expect(classifyPresentationFrame(frame({ v: 2 }), liveCtx)).toBe('reject');
		expect(classifyPresentationFrame({ ...frame(), t: 'wb' }, liveCtx)).toBe('reject');
	});

	it('rejects unknown kinds and the wrong presentation id', () => {
		expect(classifyPresentationFrame(frame({ kind: 'nope' as PresentationEnvelope['kind'] }), liveCtx)).toBe('reject');
		expect(classifyPresentationFrame(frame({ presentationId: 'other' }), liveCtx)).toBe('reject');
	});

	it('rejects frames from a stale presenter generation', () => {
		expect(classifyPresentationFrame(frame({ presenterGeneration: 2 }), liveCtx)).toBe('reject');
	});

	it('rejects invalid page indexes on page.changed frames', () => {
		expect(classifyPresentationFrame(frame({ checkpointSeq: 41, payload: { pageIndex: -3 } }), liveCtx)).toBe('reject');
		expect(classifyPresentationFrame(frame({ checkpointSeq: 41, payload: { pageIndex: 500 } }), liveCtx)).toBe('reject');
	});

	it('rejects oversized frames outright', () => {
		const fat = frame({ kind: 'ready', payload: { pad: 'q'.repeat(MAX_ENVELOPE_BYTES) } });
		expect(classifyPresentationFrame(fat, liveCtx)).toBe('reject');
	});

	it('rejects an oversized DUPLICATE frame: door checks precede sequence dedup', () => {
		// M0/M1 r2 regression: sequence matching ran before the wire check, so
		// a frame whose seq was already confirmed returned 'noop' and the
		// oversized bytes never rejected. Wire/payload validation is the door.
		const raw =
			'{"t":"presentation","v":1,"presentationId":"p-1","checkpointSeq":40,"presenterGeneration":3,"kind":"ready","payload":{"pad":"' +
			'\\u0041'.repeat(4000) +
			'"}}';
		const parsed: unknown = JSON.parse(raw);
		const wire = new TextEncoder().encode(raw);
		expect(wire.length).toBeGreaterThan(MAX_ENVELOPE_BYTES);
		expect(parsed).toMatchObject({ checkpointSeq: 40 }); // duplicate of confirmedSeq
		expect(classifyPresentationFrame(parsed, liveCtx, wire)).toBe('reject');
	});

	it('rejects a page.changed payload over the 1 KiB target on the receive path (fresh or duplicate)', () => {
		// M0/M1 r2 regression: only the send path measured the payload target,
		// so an over-target payload arrived, validated, and was forwarded as a
		// checkpoint-invalidation hint.
		const fat = 'x'.repeat(TARGET_PAGE_CHANGE_PAYLOAD_BYTES + 1);
		expect(classifyPresentationFrame(frame({ checkpointSeq: 41, payload: { pageIndex: 0, note: fat } }), liveCtx)).toBe(
			'reject',
		);
		expect(classifyPresentationFrame(frame({ checkpointSeq: 40, payload: { pageIndex: 0, note: fat } }), liveCtx)).toBe(
			'reject',
		);
	});

	it('measures the receive payload target in UTF-8 wire bytes, not string length', () => {
		const sneaky = 'α'.repeat(600); // 600 UTF-16 units stringify under the target; 1223 UTF-8 bytes do not
		expect(sneaky.length).toBeLessThanOrEqual(TARGET_PAGE_CHANGE_PAYLOAD_BYTES);
		expect(classifyPresentationFrame(frame({ checkpointSeq: 41, payload: { pageIndex: 0, note: sneaky } }), liveCtx)).toBe(
			'reject',
		);
	});

	it('rejects a MALFORMED duplicate instead of laundering it as a noop; well-formed duplicates still noop', () => {
		// Mirrors the Go Classify order (r2 correction 6): payload admission
		// happens before seq matching, so a malformed duplicate rejects.
		expect(classifyPresentationFrame(frame({ checkpointSeq: 40, payload: { pageIndex: 500 } }), liveCtx)).toBe('reject');
		expect(classifyPresentationFrame(frame({ checkpointSeq: 3, payload: {} }), liveCtx)).toBe('reject');
		expect(classifyPresentationFrame(frame({ checkpointSeq: 40 }), liveCtx)).toBe('noop');
		expect(classifyPresentationFrame(frame({ checkpointSeq: 3 }), liveCtx)).toBe('noop');
	});

	it('measures the wire bound on the ORIGINAL received bytes, not a re-serialization', () => {
		// M0/M1 review regression: re-serializing a parsed frame is not the
		// frame the peer sent. A ~24KB wire frame padded with `\u0041` escapes
		// parses and re-serializes to ~4KB — the old check admitted it and the
		// frame reached checkpoint invalidation. With the original bytes the
		// frame rejects; the same bytes within the bound still hint.
		const raw =
			'{"t":"presentation","v":1,"presentationId":"p-1","checkpointSeq":41,"presenterGeneration":3,"kind":"ready","payload":{"pad":"' +
			'\\u0041'.repeat(4000) +
			'"}}';
		const parsed: unknown = JSON.parse(raw);
		expect(new TextEncoder().encode(JSON.stringify(parsed)).length).toBeLessThanOrEqual(MAX_ENVELOPE_BYTES);
		const wire = new TextEncoder().encode(raw);
		expect(wire.length).toBeGreaterThan(MAX_ENVELOPE_BYTES);
		expect(classifyPresentationFrame(parsed, liveCtx, wire)).toBe('reject');
		const slim = new TextEncoder().encode(JSON.stringify(frame({ checkpointSeq: 41 })));
		expect(classifyPresentationFrame(frame({ checkpointSeq: 41 }), liveCtx, slim)).toBe('invalidate-checkpoint');
	});

	it('rejects the exact r3 trace: 1,382-byte frame, 1,225-byte raw payload laundering to 225 bytes', () => {
		// Astra r3 P2: the frame passes the 14KB envelope bound, its raw
		// page.changed payload is 1,225 bytes (over the 1 KiB target), but
		// re-serializing the PARSED payload collapses the 200 `\u0030` escapes
		// to 225 bytes — the old measure admitted the frame and the fresh
		// sequence reached checkpoint invalidation (a duplicate was laundered
		// to noop). What the sender actually sent is the payload member's raw
		// wire encoding within the frame — the Go mirror's json.RawMessage
		// length — and THAT is what the 1 KiB target bounds.
		const rawPayload = '{"pageIndex":3,"blob":"' + '\\u0030'.repeat(200) + '"}';
		const raw =
			'{"t":"presentation","v":1,"presentationId":"pr-1","checkpointSeq":9,"presenterGeneration":0,"kind":"page.changed","payload":' +
			rawPayload +
			',"sentAt":"2026-09-09T00:00:00Z"}';
		const wire = new TextEncoder().encode(raw);
		const parsed: unknown = JSON.parse(raw);
		// The exact trace dimensions.
		expect(wire.length).toBe(1382);
		expect(new TextEncoder().encode(rawPayload).length).toBe(1225);
		const reserialized = JSON.stringify((parsed as PresentationEnvelope).payload);
		expect(new TextEncoder().encode(reserialized).length).toBe(225);
		expect(new TextEncoder().encode(reserialized).length).toBeLessThanOrEqual(TARGET_PAGE_CHANGE_PAYLOAD_BYTES);
		expect(wire.length).toBeLessThanOrEqual(MAX_ENVELOPE_BYTES);
		// Fresh sequence: reject — never the invalidation hint the laundered
		// measure produced.
		const freshCtx: PresentationFrameContext = { presentationId: 'pr-1', confirmedSeq: 8, knownGeneration: 0 };
		expect(classifyPresentationFrame(parsed, freshCtx, wire)).toBe('reject');
		// Duplicate sequence: the door rejects BEFORE dedup — never noop.
		const dupCtx: PresentationFrameContext = { presentationId: 'pr-1', confirmedSeq: 9, knownGeneration: 0 };
		expect(classifyPresentationFrame(parsed, dupCtx, wire)).toBe('reject');
	});

	it('measures the raw payload member even when the sender padded it with whitespace, not escapes', () => {
		// The raw substring is measured as sent: whitespace BETWEEN the
		// payload member's tokens is part of its wire encoding but collapses
		// on parse+stringify, so pretty-printing cannot park over-target
		// bytes in structural padding the parse would discard.
		const pad = ' '.repeat(600);
		const rawPayload = `{${pad}"note":"x"${pad},${pad}"pageIndex":3${pad}}`;
		const raw =
			'{"t":"presentation","v":1,"presentationId":"p-1","checkpointSeq":41,"presenterGeneration":3,"kind":"page.changed","payload":' +
			rawPayload +
			'}';
		const wire = new TextEncoder().encode(raw);
		const parsed: unknown = JSON.parse(raw);
		// Raw over target, laundered re-serialization under it.
		expect(new TextEncoder().encode(rawPayload).length).toBeGreaterThan(TARGET_PAGE_CHANGE_PAYLOAD_BYTES);
		expect(new TextEncoder().encode(JSON.stringify((parsed as PresentationEnvelope).payload)).length).toBeLessThanOrEqual(
			TARGET_PAGE_CHANGE_PAYLOAD_BYTES,
		);
		expect(classifyPresentationFrame(parsed, liveCtx, wire)).toBe('reject');
	});

	it('a compact payload our own encoder emits passes the raw member measure (send/receive symmetry)', () => {
		// encodePresentationEnvelope serializes with JSON.stringify, so the
		// payload member's raw wire encoding IS the re-serialization the send
		// path measured: a frame we legitimately published can never be
		// rejected on receive for payload size.
		const r = encodePresentationEnvelope(frame({ checkpointSeq: 41, payload: { pageIndex: 3, note: 'x'.repeat(200) } }));
		expect(r.ok).toBe(true);
		if (r.ok) {
			const parsed: unknown = JSON.parse(new TextDecoder().decode(r.bytes));
			expect(classifyPresentationFrame(parsed, liveCtx, r.bytes)).toBe('invalidate-checkpoint');
		}
	});

	it('fails closed when no presentation session is live', () => {
		const none: PresentationFrameContext = { presentationId: null, confirmedSeq: 0, knownGeneration: 0 };
		expect(classifyPresentationFrame(frame(), none)).toBe('reject');
	});
});

// ── CheckpointRefresher (one in-flight + one pending) ────────────────────
describe('CheckpointRefresher', () => {
	it('coalesces a burst of hints into at most one pending refresh', async () => {
		let resolveRefresh!: () => void;
		const refresh = vi.fn(
			() => new Promise<void>((resolve) => {
				resolveRefresh = resolve;
			}),
		);
		const r = new CheckpointRefresher(refresh);
		r.hint();
		// A spray of fresh sequences cannot queue an unbounded catch-up loop.
		for (let i = 0; i < 50; i++) r.hint();
		expect(refresh).toHaveBeenCalledTimes(1);
		expect(r.inFlight).toBe(true);
		expect(r.pending).toBe(true);
		resolveRefresh();
		await vi.waitFor(() => expect(refresh).toHaveBeenCalledTimes(2));
		expect(r.pending).toBe(false);
	});

	it('runs immediately and serially when no refresh is outstanding', async () => {
		const refresh = vi.fn(async () => undefined);
		const r = new CheckpointRefresher(refresh);
		r.hint();
		await vi.waitFor(() => expect(refresh).toHaveBeenCalledTimes(1));
		r.hint();
		await vi.waitFor(() => expect(refresh).toHaveBeenCalledTimes(2));
		expect(r.inFlight).toBe(false);
		expect(r.pending).toBe(false);
	});

	it('a rejecting refresh still drains the pending slot (recovery converges)', async () => {
		const refresh = vi.fn(async () => {
			throw new Error('checkpointRefreshThrottled');
		});
		const r = new CheckpointRefresher(refresh);
		r.hint();
		r.hint();
		await vi.waitFor(() => expect(refresh).toHaveBeenCalledTimes(2));
		expect(r.inFlight).toBe(false);
		expect(r.pending).toBe(false);
	});

	// ── M0/M1 review regressions: admission bounds ─────────────────────────
	// The refresher previously ONLY coalesced. These pin the plan's
	// "Checkpoint refresh | One in flight plus one pending; ≤5/s/client,
	// burst 2" budget and the bounded Retry-After backoff, deterministically
	// via an injected clock (no real timers).

	interface ParkedWakeup {
		at: number;
		fn: () => void;
	}

	function clockedRefresh() {
		let t = 0;
		const wakeups: ParkedWakeup[] = [];
		const clock = {
			now: () => t,
			schedule: (ms: number, fn: () => void) => {
				wakeups.push({ at: t + ms, fn });
				return () => undefined;
			},
		};
		const advance = async (to: number) => {
			t = to;
			for (let i = wakeups.length - 1; i >= 0; i--) {
				if (wakeups[i].at <= t) {
					const { fn } = wakeups.splice(i, 1)[0];
					fn();
					await flush();
				}
			}
		};
		return { clock, wakeups, advance, now: () => t };
	}

	const flush = async (): Promise<void> => {
		for (let i = 0; i < 10; i++) await Promise.resolve();
	};

	it('admits burst 2 immediately and parks further hints until the next 5/s token', async () => {
		const { clock, wakeups, advance } = clockedRefresh();
		const refresh = vi.fn(async () => undefined);
		const r = new CheckpointRefresher(refresh, clock);
		r.hint();
		await flush();
		r.hint();
		await flush();
		expect(refresh).toHaveBeenCalledTimes(2); // the burst allowance, exhausted
		r.hint();
		expect(refresh).toHaveBeenCalledTimes(2); // parked, not queued
		expect(r.pending).toBe(true);
		expect(wakeups.length).toBe(1);
		// ~201ms to the next token at 5/s — one wakeup, never a per-hint chain.
		expect(wakeups[0].at).toBeGreaterThan(195);
		await advance(wakeups[0].at);
		expect(refresh).toHaveBeenCalledTimes(3);
		expect(r.pending).toBe(false);
	});

	it('never exceeds ≤5/s sustained: at most burst 2 + 5 starts in any full second', async () => {
		const { clock, advance } = clockedRefresh();
		const refresh = vi.fn(async () => undefined);
		const r = new CheckpointRefresher(refresh, clock);
		for (let step = 0; step <= 20; step++) {
			await advance(step * 50);
			r.hint();
			await flush();
		}
		// 2 burst tokens + 5 tokens accrued across the second — a coalescing-
		// only loop would have run 21 refreshes.
		expect(refresh.mock.calls.length).toBeLessThanOrEqual(CHECKPOINT_REFRESH_BURST + CHECKPOINT_REFRESH_PER_SECOND);
		expect(refresh.mock.calls.length).toBeGreaterThanOrEqual(4); // liveness: the bucket actually grants
	});

	it('honors the bounded Retry-After (clamped 1–30s) after a throttled refresh', async () => {
		const { clock, wakeups, advance } = clockedRefresh();
		const refresh = vi.fn(async () => {
			throw Object.assign(new Error('checkpointRefreshThrottled'), {
				problem: 'checkpointRefreshThrottled',
				retryAfterMs: 45_000, // beyond the 30s bound → clamped
			});
		});
		const r = new CheckpointRefresher(refresh, clock);
		r.hint();
		await flush();
		expect(refresh).toHaveBeenCalledTimes(1);
		r.hint();
		expect(r.pending).toBe(true);
		// Parked until the clamped Retry-After expires, not before.
		expect(wakeups[0].at).toBe(30_000);
		await advance(29_999);
		expect(refresh).toHaveBeenCalledTimes(1);
		await advance(30_000);
		expect(refresh).toHaveBeenCalledTimes(2);
	});

	it('clamps a too-short Retry-After up to 1s', async () => {
		const { clock, wakeups } = clockedRefresh();
		const refresh = vi.fn(async () => {
			throw Object.assign(new Error('checkpointRefreshThrottled'), { problem: 'checkpointRefreshThrottled', retryAfterMs: 50 });
		});
		const r = new CheckpointRefresher(refresh, clock);
		r.hint();
		await flush();
		r.hint();
		expect(wakeups[0].at).toBe(1_000);
	});

	it('a throttle without Retry-After takes the bounded jittered default; other failures do not back off', async () => {
		const { clock, wakeups } = clockedRefresh();
		const throttled = Object.assign(new Error('throttled'), { problem: 'checkpointRefreshThrottled' });
		const refresh = vi.fn(async () => {
			throw throttled;
		});
		const r = new CheckpointRefresher(refresh, clock);
		r.hint();
		await flush();
		r.hint();
		// 1s default + up to 20% jitter, in park position.
		expect(wakeups[0].at).toBeGreaterThanOrEqual(1_000);
		expect(wakeups[0].at).toBeLessThanOrEqual(1_200);

		const plain = clockedRefresh();
		const failing = vi.fn(async () => {
			throw new Error('network hiccup'); // NOT a throttle: no backoff
		});
		const r2 = new CheckpointRefresher(failing, plain.clock);
		r2.hint();
		r2.hint();
		await flush();
		expect(failing).toHaveBeenCalledTimes(2);
		expect(r2.pending).toBe(false);
		expect(plain.wakeups.length).toBe(0);
	});

	// ── M0/M1 r2 regressions: the parked slot belongs to the newest hint ──
	// The parked wakeup used to clear the pending slot unconditionally when
	// it fired, so a hint that landed behind a token-admitted in-flight
	// refresh was erased and the required follow-up refresh never ran.

	it('a newer hint parked behind an in-flight refresh survives the parked timer firing', async () => {
		const gates: Array<() => void> = [];
		const refresh = vi.fn(
			() => new Promise<void>((resolve) => {
				gates.push(resolve);
			}),
		);
		const { clock, wakeups, advance } = clockedRefresh();
		const r = new CheckpointRefresher(refresh, clock);

		// Drain the burst 2 allowance.
		r.hint();
		await flush();
		gates.shift()?.();
		await flush();
		r.hint();
		await flush();
		gates.shift()?.();
		await flush();
		expect(refresh).toHaveBeenCalledTimes(2);

		// The next hint parks until the next token (wakeup at ~201ms).
		r.hint();
		expect(r.pending).toBe(true);
		expect(wakeups.length).toBe(1);

		// One token refills just before the wakeup fires; the hint it admits
		// starts a refresh while the parked wakeup is still scheduled.
		await advance(wakeups[0].at - 1);
		r.hint();
		expect(r.inFlight).toBe(true);
		// A NEWER hint lands behind that in-flight refresh.
		r.hint();
		expect(r.pending).toBe(true);

		// The parked timer fires mid-refresh — it must NOT erase the pending
		// slot (the old implementation cleared it here and dropped the
		// required follow-up refresh).
		await advance(wakeups[0].at);
		expect(r.pending).toBe(true);

		// Completing the in-flight refresh drains the slot into the follow-up.
		gates.shift()?.();
		await flush();
		expect(r.pending).toBe(true);
		expect(wakeups.length).toBe(1);
		await advance(wakeups[0].at);
		expect(refresh).toHaveBeenCalledTimes(4);
		expect(r.pending).toBe(false);
	});

	it('a hint landing behind an in-flight refresh drains into exactly one follow-up, then stops', async () => {
		// Astra r3 #5 contract: the pending slot is owned by the mid-refresh
		// hint until the FOLLOW-UP refresh starts — the only clear is the
		// refresh-start clear in #admit. The completion's admission must
		// never erase the slot (a double-clear would drop the required
		// follow-up), and with no further hint no spurious refresh runs.
		const gates: Array<() => void> = [];
		const refresh = vi.fn(
			() => new Promise<void>((resolve) => {
				gates.push(resolve);
			}),
		);
		const { clock, wakeups, advance } = clockedRefresh();
		const r = new CheckpointRefresher(refresh, clock);

		r.hint();
		await flush();
		expect(refresh).toHaveBeenCalledTimes(1);
		expect(r.pending).toBe(false);

		// The hint arrives WHILE the refresh runs: exactly one follow-up parks.
		r.hint();
		expect(r.pending).toBe(true);
		expect(r.inFlight).toBe(true);

		// Completing the in-flight refresh admits the follow-up; the
		// follow-up's own START clears the slot.
		gates.shift()?.();
		await flush();
		expect(refresh).toHaveBeenCalledTimes(2);
		expect(r.inFlight).toBe(true);
		expect(r.pending).toBe(false);

		// No further hint: the follow-up completes and nothing else runs.
		gates.shift()?.();
		await flush();
		expect(refresh).toHaveBeenCalledTimes(2);
		expect(r.inFlight).toBe(false);
		expect(r.pending).toBe(false);
		expect(wakeups.length).toBe(0);
		await advance(60_000);
		expect(refresh).toHaveBeenCalledTimes(2);
	});

	it('a parked wakeup outliving its served hint never starts a hintless refresh', async () => {
		const gates: Array<() => void> = [];
		const refresh = vi.fn(
			() => new Promise<void>((resolve) => {
				gates.push(resolve);
			}),
		);
		const { clock, wakeups, advance } = clockedRefresh();
		const r = new CheckpointRefresher(refresh, clock);

		// Drain burst 2, park on the third hint, then admit a refresh from the
		// refilled token just before the wakeup fires.
		r.hint();
		await flush();
		gates.shift()?.();
		await flush();
		r.hint();
		await flush();
		gates.shift()?.();
		await flush();
		r.hint();
		await advance(wakeups[0].at - 1);
		r.hint();
		expect(r.inFlight).toBe(true);
		// The refresh completes with NO further hint pending; the stale wakeup
		// must be inert — a refresh only ever runs to serve a hint.
		gates.shift()?.();
		await flush();
		expect(r.pending).toBe(false);
		await advance(wakeups[0].at);
		expect(refresh).toHaveBeenCalledTimes(3);
		expect(r.pending).toBe(false);
	});
});
