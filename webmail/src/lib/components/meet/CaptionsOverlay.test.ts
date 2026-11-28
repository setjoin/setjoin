// CaptionsOverlay.test.ts — Meet B3 Task 15.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, within } from '@testing-library/svelte/svelte5';
import CaptionsOverlay from './CaptionsOverlay.svelte';
import type { CaptionSegment } from '$lib/meet/room.svelte';

function seg(over: Partial<CaptionSegment>): CaptionSegment {
	return { sid: 's1', identity: 'u:1', text: 'hello', final: false, ...over };
}

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

describe('CaptionsOverlay — a11y live region (always mounted, finals-only, append-only, D7)', () => {
	it('mounts the role=log region even while captions are off (empty)', () => {
		render(CaptionsOverlay, { captionsOn: false, segments: [], finalsLog: [] });
		const log = screen.getByRole('log', { hidden: true });
		expect(log).toBeTruthy();
		expect(log.textContent).toBe('');
	});

	it('an interim segment does NOT change the region; its finalization inserts exactly one entry', async () => {
		const { rerender } = render(CaptionsOverlay, {
			captionsOn: true,
			segments: [seg({ text: 'Hel', final: false })],
			finalsLog: [],
		});
		const log = screen.getByRole('log', { hidden: true });
		expect(within(log).queryAllByText(/Hel/, { exact: false })).toHaveLength(0);

		await rerender({ captionsOn: true, segments: [seg({ text: 'Hello', final: false })], finalsLog: [] });
		expect(log.children.length).toBe(0); // still interim — region untouched (finalsLog unchanged too)

		await rerender({
			captionsOn: true,
			segments: [seg({ text: 'Hello', final: true })],
			finalsLog: [seg({ text: 'Hello', final: true })],
		});
		expect(log.children.length).toBe(1);
		expect(log.textContent).toContain('Hello');
	});

	// B3 retro fix (eng finding #13 / design D7-break): the region reads
	// finalsLog, a SEPARATE source decoupled from the small visual ring
	// (segments) — an interim frame that evicts an old entry from that ring
	// must never mutate or shrink the region.
	it('an interim append that would evict an old entry from the visual ring does not mutate the region (finalsLog is decoupled)', async () => {
		const finals = ['a', 'b', 'c', 'd', 'e', 'f'].map((sid) => seg({ sid, text: `line-${sid}`, final: true }));
		const { rerender } = render(CaptionsOverlay, { captionsOn: true, segments: finals, finalsLog: finals });
		const log = screen.getByRole('log', { hidden: true });
		expect(log.children.length).toBe(6);
		const firstRowText = log.children[0].textContent;

		// a 7th, ring-evicting entry lands in the VISUAL ring (segments) — an
		// unrelated interim frame, per the finding's own repro — but
		// finalsLog (the region's own source) is untouched by this update.
		await rerender({
			captionsOn: true,
			segments: [...finals.slice(1), seg({ sid: 'interim', text: 'g', final: false })],
			finalsLog: finals,
		});
		expect(log.children.length).toBe(6); // unchanged
		expect(log.children[0].textContent).toBe(firstRowText); // untouched, not rewritten
	});

	// B3 retro fix: keyed by sid (a stable per-utterance identity), not array
	// index — a new final inserts exactly one new node; existing nodes' DOM
	// identity (and therefore their text) is untouched, no SR re-announcement
	// flood on a window shift.
	it('keys each region row by sid — a new final inserts one node, existing nodes are the SAME DOM node (untouched)', async () => {
		const finals = ['a', 'b'].map((sid) => seg({ sid, text: `line-${sid}`, final: true }));
		const { rerender } = render(CaptionsOverlay, { captionsOn: true, segments: finals, finalsLog: finals });
		const log = screen.getByRole('log', { hidden: true });
		const firstNode = log.children[0];

		const withThird = [...finals, seg({ sid: 'c', text: 'line-c', final: true })];
		await rerender({ captionsOn: true, segments: withThird, finalsLog: withThird });

		expect(log.children.length).toBe(3);
		expect(log.children[0]).toBe(firstNode); // same DOM node, not recreated
	});
});

describe('CaptionsOverlay — styled transcript (interim replace-in-place, finals persist, per-speaker attribution)', () => {
	it('renders segments verbatim from the store — F8 attestation already happened upstream (room.svelte.ts)', () => {
		render(CaptionsOverlay, { captionsOn: true, segments: [seg({ identity: 'u:9', text: 'attested line' })] });
		expect(screen.getByText('attested line')).toBeTruthy();
	});

	it('an interim update for the same sid replaces the visible line in place, not a second line', async () => {
		const { rerender } = render(CaptionsOverlay, { captionsOn: true, segments: [seg({ sid: 's1', text: 'Hel', final: false })] });
		expect(screen.getByText('Hel')).toBeTruthy();
		await rerender({ captionsOn: true, segments: [seg({ sid: 's1', text: 'Hello', final: false })] });
		expect(screen.queryByText('Hel')).toBeNull();
		expect(screen.getByText('Hello')).toBeTruthy();
	});

	it('a finalized line supersedes its own interim ghost entry — one visible line, not two', async () => {
		const { rerender } = render(CaptionsOverlay, { captionsOn: true, segments: [seg({ sid: 's1', text: 'Hel', final: false })] });
		// room.svelte.ts's ring keeps BOTH the stale interim entry and the new
		// final entry after finalization (#addCaption always appends on
		// final:true) — the overlay must dedupe by sid to the latest.
		await rerender({
			captionsOn: true,
			segments: [seg({ sid: 's1', text: 'Hel', final: false }), seg({ sid: 's1', text: 'Hello world', final: true })],
		});
		expect(screen.queryByText('Hel')).toBeNull();
		expect(screen.getByText('Hello world')).toBeTruthy();
	});

	it('attributes each line to the speaker via the participant name map', () => {
		render(CaptionsOverlay, {
			captionsOn: true,
			segments: [seg({ identity: 'u:9', text: 'hi there' })],
			participantNames: { 'u:9': 'Alice Chen' },
		});
		expect(screen.getByText('Alice Chen')).toBeTruthy();
	});

	it('falls back to the raw identity when no display name is mapped', () => {
		render(CaptionsOverlay, { captionsOn: true, segments: [seg({ identity: 'u:9', text: 'hi' })] });
		expect(screen.getByText('u:9')).toBeTruthy();
	});

	it('caps the visible transcript at 2 lines even with more distinct sids in the ring', () => {
		const segments = ['a', 'b', 'c', 'd'].map((sid) => seg({ sid, text: `line-${sid}`, final: true }));
		render(CaptionsOverlay, { captionsOn: true, segments });
		expect(screen.queryByText('line-a')).toBeNull();
		expect(screen.queryByText('line-b')).toBeNull();
		expect(screen.getByText('line-c')).toBeTruthy();
		expect(screen.getByText('line-d')).toBeTruthy();
	});

	it('renders nothing styled while captionsOn is false', () => {
		render(CaptionsOverlay, { captionsOn: false, segments: [seg({})] });
		expect(screen.queryByText('hello')).toBeNull();
		expect(screen.queryByRole('status')).toBeNull();
	});

	// B3 retro fix (design finding #10): the whiteboard's 96px-tall video
	// filmstrip left no room for the 2-line transcript, which bled over it.
	it('hideTranscript hides only the transcript block — the chip and the sr-only log region stay', () => {
		render(CaptionsOverlay, {
			captionsOn: true,
			segments: [seg({ text: 'hi there' })],
			finalsLog: [seg({ text: 'hi there' })],
			hideTranscript: true,
		});
		expect(screen.queryByText('hi there')).toBeNull(); // the styled transcript line
		expect(screen.getByText('Live captions on')).toBeTruthy(); // the chip
		expect(screen.getByRole('log', { hidden: true }).textContent).toContain('hi there'); // sr-only region
	});
});

describe('CaptionsOverlay — chip (server state, degrade/fade, D8)', () => {
	it('shows the "on" chip immediately once captionsOn flips true, with no frames yet', () => {
		render(CaptionsOverlay, { captionsOn: true, segments: [] });
		expect(screen.getByText('Live captions on')).toBeTruthy();
	});

	it('degrades to the unavailable status line after 15s with no attested frame', async () => {
		render(CaptionsOverlay, { captionsOn: true, segments: [] });
		expect(screen.getByText('Live captions on')).toBeTruthy();
		await vi.advanceTimersByTimeAsync(15000);
		expect(screen.queryByText('Live captions on')).toBeNull();
		expect(screen.getByText('Live captions are not available')).toBeTruthy();
	});

	it('a new attested frame (even an in-place interim replace) resets the degrade timer', async () => {
		const { rerender } = render(CaptionsOverlay, { captionsOn: true, segments: [seg({ text: 'a' })] });
		await vi.advanceTimersByTimeAsync(10000);
		expect(screen.getByText('Live captions on')).toBeTruthy(); // not degraded yet

		// same sid, new text — an in-place interim replace, still a fresh
		// array reference from room.svelte.ts's #addCaption.
		await rerender({ captionsOn: true, segments: [seg({ text: 'ab' })] });
		await vi.advanceTimersByTimeAsync(10000); // 20s total elapsed, but only 10s since the reset
		expect(screen.getByText('Live captions on')).toBeTruthy();

		await vi.advanceTimersByTimeAsync(5000); // now 15s since the reset
		expect(screen.getByText('Live captions are not available')).toBeTruthy();
	});

	// B3 retro fix (design finding #5a): a heartbeat-only tick never touches
	// `segments` — it must still reset the degrade timer via lastAttestedCcAt.
	it('a lastAttestedCcAt bump with NO segments change (the hb-only case) still resets the degrade timer', async () => {
		const { rerender } = render(CaptionsOverlay, { captionsOn: true, segments: [], lastAttestedCcAt: 1000 });
		await vi.advanceTimersByTimeAsync(10000);
		expect(screen.getByText('Live captions on')).toBeTruthy(); // not degraded yet

		// segments unchanged ([]) — only lastAttestedCcAt moved, the hb shape.
		await rerender({ captionsOn: true, segments: [], lastAttestedCcAt: 2000 });
		await vi.advanceTimersByTimeAsync(10000); // 20s total elapsed, only 10s since the hb reset
		expect(screen.getByText('Live captions on')).toBeTruthy();

		await vi.advanceTimersByTimeAsync(5000); // now 15s since the hb reset
		expect(screen.getByText('Live captions are not available')).toBeTruthy();
	});

	it('member surface (fadeOnDegrade=false, default): stays visible with the unavailable status line once degraded', async () => {
		render(CaptionsOverlay, { captionsOn: true, segments: [] });
		await vi.advanceTimersByTimeAsync(15000);
		expect(screen.getByRole('status')).toBeTruthy();
		expect(screen.getByText('Live captions are not available')).toBeTruthy();
	});

	it('guest surface (fadeOnDegrade=true, D8): the whole chip fades to nothing once degraded', async () => {
		render(CaptionsOverlay, { captionsOn: true, segments: [], fadeOnDegrade: true });
		expect(screen.getByText('Live captions on')).toBeTruthy();
		await vi.advanceTimersByTimeAsync(15000);
		expect(screen.queryByText('Live captions on')).toBeNull();
		expect(screen.queryByText('Live captions are not available')).toBeNull();
		expect(screen.queryByRole('status')).toBeNull();
	});

	it('a fresh frame after fading (guest surface) brings the chip back on', async () => {
		const { rerender } = render(CaptionsOverlay, { captionsOn: true, segments: [], fadeOnDegrade: true });
		await vi.advanceTimersByTimeAsync(15000);
		expect(screen.queryByRole('status')).toBeNull();

		await rerender({ captionsOn: true, segments: [seg({ text: 'still going' })], fadeOnDegrade: true });
		expect(screen.getByText('Live captions on')).toBeTruthy();
	});

	it('flipping captionsOn off clears degraded state and hides the chip', async () => {
		const { rerender } = render(CaptionsOverlay, { captionsOn: true, segments: [] });
		await vi.advanceTimersByTimeAsync(15000);
		expect(screen.getByText('Live captions are not available')).toBeTruthy();

		await rerender({ captionsOn: false, segments: [] });
		expect(screen.queryByRole('status')).toBeNull();
	});
});
