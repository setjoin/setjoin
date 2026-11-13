// semanticReplay.test.ts — MEET plan M4: the deterministic replay
// contract's vitest mirror of the Go presentation/replay.go tests: explicit
// gap stops (R5.4), named unavailable segments, local-only provenance, the
// fenced-package refusal, deterministic seek states, and export bounds
// with exact exclusions.
import { describe, it, expect } from 'vitest';
import {
	buildSemanticReplay,
	seekReplay,
	replayExportBounds,
	replayFactRail,
	replayFidelityNotice,
	gapAnnouncement,
	type SemanticPackageRead,
	type ReplayPresentationLink,
} from './semanticReplay';

function fidelityLink(overrides: Partial<ReplayPresentationLink> = {}): ReplayPresentationLink {
	return {
		presentationId: 1,
		status: 'ENDED',
		driveNodeId: 11,
		driveVersionId: 22,
		manifestDigest: 'e'.repeat(64),
		manifestGeneration: 3,
		startedAt: null,
		endedAt: null,
		annotationSnapshotRef: null,
		...overrides,
	};
}

function pkg(overrides: Partial<SemanticPackageRead> = {}): SemanticPackageRead {
	return {
		recordingId: 3,
		meetingId: 7,
		captureMode: 'server_audio',
		recState: 'stopped',
		packageState: 'ACTIVE',
		localOnly: false,
		policyMode: 'server_only',
		manifestDigest: 'a'.repeat(64),
		timelineSha256: 'b'.repeat(64),
		timelineRecords: 4,
		startedAt: '2026-09-18T00:00:00Z',
		stoppedAt: '2026-09-18T00:01:00Z',
		segments: [
			seg(1, 'verified', 0, 1000),
			seg(2, 'interrupted', 1000, 2000, 'producer crashed'),
			seg(3, 'verified', 2000, 3000),
		],
		children: [],
		exports: [],
		...overrides,
	};
}

function seg(
	seq: number,
	state: SemanticPackageRead['segments'][number]['state'],
	startMs: number,
	endMs: number,
	interruptReason: string | null = null,
): SemanticPackageRead['segments'][number] {
	return {
		seq,
		state,
		ack: state === 'verified' ? 'acknowledged' : 'lost',
		contentSha256: state === 'verified' ? 'a'.repeat(64) : null,
		byteSize: state === 'verified' ? 100 : null,
		mimeType: 'audio/webm',
		codec: 'opus',
		container: 'webm',
		startMs,
		endMs,
		wallStartUnixMs: startMs + 1,
		wallEndUnixMs: endMs + 1,
		interruptReason,
	};
}

describe('buildSemanticReplay', () => {
	it('builds media runs with explicit gap stops between them', () => {
		const m = buildSemanticReplay(pkg());
		const runs = m.entries.filter((e) => e.kind === 'media');
		const gaps = m.entries.filter((e) => e.kind === 'gap');
		expect(runs.map((r) => [r.startMs, r.endMs])).toEqual([
			[0, 1000],
			[2000, 3000],
		]);
		expect(gaps).toHaveLength(1);
		expect(gaps[0]).toMatchObject({ startMs: 1000, endMs: 2000, nextAvailableMs: 2000 });
	});

	it('names interrupted/failed segments with their reasons, never silence', () => {
		const m = buildSemanticReplay(pkg());
		expect(m.unavailableSegments).toEqual([
			{ seq: 2, state: 'interrupted', reason: 'producer crashed', startMs: 1000, endMs: 2000 },
		]);
	});

	it('offers continue-at-next only when a later interval exists', () => {
		const trailing = pkg({
			segments: [seg(1, 'verified', 0, 1000), seg(2, 'failed', 1000, 3000, 'revoke')],
		});
		const m = buildSemanticReplay(trailing);
		const gaps = m.entries.filter((e) => e.kind === 'gap');
		expect(gaps).toHaveLength(1);
		expect(gaps[0].nextAvailableMs).toBeUndefined();
	});

	it('merges adjacent verified runs into one interval', () => {
		const m = buildSemanticReplay(pkg({ segments: [seg(1, 'verified', 0, 1000), seg(2, 'verified', 1000, 2000)] }));
		expect(m.entries.filter((e) => e.kind === 'media')).toHaveLength(1);
		expect(m.entries.filter((e) => e.kind === 'gap')).toHaveLength(0);
	});

	it('a fenced package replays nothing but still explains itself', () => {
		for (const state of ['DELETE_PENDING', 'HELD_COMPLETE', 'HELD_PARTIAL', 'DELETED'] as const) {
			const m = buildSemanticReplay(pkg({ packageState: state }));
			expect(m.entries).toHaveLength(0);
			expect(m.unavailableSegments).toHaveLength(1);
			expect(m.packageState).toBe(state);
		}
	});

	it('local-only provenance is visible, never implied centrally retained', () => {
		const m = buildSemanticReplay(pkg({ localOnly: true, captureMode: 'local_registered' }));
		expect(m.localOnly).toBe(true);
	});

	it('is deterministic: identical facts build an identical model', () => {
		const a = JSON.stringify(buildSemanticReplay(pkg()));
		const b = JSON.stringify(buildSemanticReplay(pkg()));
		expect(a).toBe(b);
	});
});

describe('seekReplay', () => {
	const m = buildSemanticReplay(pkg());

	it('resolves inside a verified run', () => {
		const r = seekReplay(m, 500);
		expect(r.ok).toBe(true);
		if (r.ok) expect(r.entry).toMatchObject({ kind: 'media', startMs: 0, endMs: 1000, segmentSeq: 1 });
	});

	it('shows unavailable inside a gap with bounds and the next interval', () => {
		const r = seekReplay(m, 1500);
		expect(r).toMatchObject({
			ok: false,
			outcome: 'gap',
			startMs: 1000,
			endMs: 2000,
			nextAvailableMs: 2000,
		});
	});

	it('announces past-end instead of the nearest stale entry', () => {
		expect(seekReplay(m, 99_999)).toEqual({ ok: false, outcome: 'past-end' });
	});

	it('a trailing gap offers no continue', () => {
		const m2 = buildSemanticReplay(pkg({ segments: [seg(1, 'verified', 0, 1000), seg(2, 'failed', 1000, 3000, 'revoke')] }));
		const r = seekReplay(m2, 2000);
		expect(r).toMatchObject({ ok: false, outcome: 'gap', nextAvailableMs: null });
	});
});

describe('replayExportBounds', () => {
	it('confirms exact bounds AND exclusions', () => {
		const b = replayExportBounds(buildSemanticReplay(pkg()));
		expect(b.bounds).toEqual([
			{ startMs: 0, endMs: 1000 },
			{ startMs: 2000, endMs: 3000 },
		]);
		expect(b.exclusions).toEqual([{ startMs: 1000, endMs: 2000 }]);
		expect(b.exportable).toBe(true);
	});

	it('disables export when nothing verified exists', () => {
		const b = replayExportBounds(
			buildSemanticReplay(pkg({ segments: [seg(1, 'interrupted', 0, 1000, 'crash')] })),
		);
		expect(b.exportable).toBe(false);
	});
});

describe('gapAnnouncement', () => {
	it('announces bounds, the named unavailable facts, and the next interval', () => {
		const m = buildSemanticReplay(pkg());
		const text = gapAnnouncement(m, { startMs: 1000, endMs: 2000, nextAvailableMs: 2000 });
		expect(text).toContain('1000–2000');
		expect(text).toContain('producer crashed');
		expect(text).toContain('Continue at 2000 ms');
	});

	it('states when no later interval exists', () => {
		const text = gapAnnouncement(buildSemanticReplay(pkg()), {
			startMs: 1000,
			endMs: 2000,
			nextAvailableMs: null,
		});
		expect(text).toContain('No later available interval exists');
	});
});

// ── M4 replay feed: the deterministic fact rail + feed riders ─────────────

describe('replayFactRail', () => {
	it('aligns media-aligned facts onto the media axis, ordered by mediaMs then seq', () => {
		const p = pkg({
			facts: [
				{ presentationId: 1, checkpointSeq: 3, kind: 'page.changed', payload: null, atMs: 3000, mediaMs: 900 },
				{ presentationId: 1, checkpointSeq: 1, kind: 'start', payload: null, atMs: 1000, mediaMs: 100 },
				{ presentationId: 1, checkpointSeq: 2, kind: 'page.changed', payload: null, atMs: 2000, mediaMs: 100 },
			],
		});
		const rail = replayFactRail(p);
		expect(rail.map((f) => f.checkpointSeq)).toEqual([1, 2, 3]);
	});

	it('keeps unaligned facts (mediaMs < 0) in the rail ordered by wall time', () => {
		const p = pkg({
			facts: [
				{ presentationId: 1, checkpointSeq: 2, kind: 'end', payload: null, atMs: 500, mediaMs: -1 },
				{ presentationId: 1, checkpointSeq: 1, kind: 'start', payload: null, atMs: 100, mediaMs: -1 },
			],
		});
		expect(replayFactRail(p).map((f) => f.checkpointSeq)).toEqual([1, 2]);
	});

	it('sorts aligned facts before unaligned ones; a feed without facts is empty', () => {
		const aligned = { presentationId: 1, checkpointSeq: 9, kind: 'page.changed', payload: null, atMs: 9999, mediaMs: 5 };
		const unaligned = { presentationId: 1, checkpointSeq: 8, kind: 'end', payload: null, atMs: 1, mediaMs: -1 };
		expect(replayFactRail(pkg({ facts: [unaligned, aligned] })).map((f) => f.checkpointSeq)).toEqual([9, 8]);
		expect(replayFactRail(pkg())).toEqual([]);
	});
});

describe('replay feed riders', () => {
	it('treats a plain package read (no riders) as the truthful empty state', () => {
		const m = buildSemanticReplay(pkg());
		expect(m.entries.length).toBeGreaterThan(0); // the model still builds
		expect(replayFactRail(pkg())).toEqual([]);
	});

	it('builds deterministically with riders present', () => {
		const ridden = pkg({
			presentationLinks: [
				{
					presentationId: 1,
					status: 'ENDED',
					driveNodeId: 11,
					driveVersionId: 22,
					manifestDigest: 'c'.repeat(64),
					manifestGeneration: 2,
					startedAt: '2026-09-18T00:00:10Z',
					endedAt: '2026-09-18T00:00:50Z',
					annotationSnapshotRef: 'annotations/p1-s5.json',
				},
			],
			annotations: [
				{
					presentationId: 1,
					checkpointSeq: 5,
					presenterGeneration: 1,
					snapshotPath: 'annotations/p1-s5.json',
					sha256: 'd'.repeat(64),
					byteSize: 128,
					createdAt: '2026-09-18T00:00:20Z',
				},
			],
			captions: [],
		});
		expect(ridden.presentationLinks).toHaveLength(1);
		expect(ridden.annotations?.[0]?.snapshotPath).toBe('annotations/p1-s5.json');
		// deterministic: same facts in, same model out
		expect(buildSemanticReplay(ridden)).toEqual(buildSemanticReplay(ridden));
	});
});

describe('replayFidelityNotice (M6 slice 1)', () => {
	it('surfaces the word/text producer-pagination warning and its fallback', () => {
		const notice = replayFidelityNotice(
			fidelityLink({
				documentMode: 'word_text_paginated',
				fidelityClass: 'producer_pagination',
				fallback: 'office_editor_or_screen_share',
			}),
		);
		expect(notice).not.toBeNull();
		expect(notice?.warningKey).toBe('meet.replay.fidelityProducerPagination');
		expect(notice?.fallbackKey).toBe('meet.replay.fallbackOfficeEditorOrScreenShare');
	});

	it('surfaces the spreadsheet static-print warning and its fallback', () => {
		const notice = replayFidelityNotice(
			fidelityLink({
				documentMode: 'spreadsheet_print_static',
				fidelityClass: 'static_print_layout',
				fallback: 'screen_share_or_office_editor',
			}),
		);
		expect(notice).toEqual({
			warningKey: 'meet.replay.fidelityStaticPrint',
			fallbackKey: 'meet.replay.fallbackScreenShareOrOfficeEditor',
		});
	});

	it('surfaces nothing for a launch-vocabulary link — no new fidelity promise', () => {
		expect(replayFidelityNotice(fidelityLink())).toBeNull();
	});

	it('surfaces nothing for a partial capability triple — never a half-stated warning', () => {
		expect(
			replayFidelityNotice(
				fidelityLink({ documentMode: 'word_text_paginated', fidelityClass: 'producer_pagination' }),
			),
		).toBeNull();
		expect(replayFidelityNotice(fidelityLink({ documentMode: 'spreadsheet_print_static' }))).toBeNull();
		expect(
			replayFidelityNotice(fidelityLink({ fidelityClass: 'static_print_layout', fallback: 'screen_share_or_office_editor' })),
		).toBeNull();
	});

	it('is deterministic: same link in, same notice out', () => {
		const link = fidelityLink({
			documentMode: 'spreadsheet_print_static',
			fidelityClass: 'static_print_layout',
			fallback: 'screen_share_or_office_editor',
		});
		expect(replayFidelityNotice(link)).toEqual(replayFidelityNotice(link));
	});
});
