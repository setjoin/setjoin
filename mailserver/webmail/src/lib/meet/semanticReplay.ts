// semanticReplay.ts — MEET plan M4: the deterministic replay contract built
// from the `meeting_semantic_package_read` projection
// (retired-docs:superpowers/plans/2026-08-25-meet-document-presentation-semantic-
// recording.md, M4; the TS mirror of internal/meet/presentation/replay.go).
//
// R5.4 verbatim: replay gaps are EXPLICIT stops — playback stops at an
// unavailable interval, its bounds and unavailable tracks/facts are
// announced, stale pages are never treated as current, silence is never
// synthesized, and "continue at next available interval" is offered ONLY
// when one exists. Seeking into a gap shows unavailable; seeking into a
// valid interval resolves the verified media run. Export bounds confirm
// exact bounds AND exclusions; a package with no available interval has
// export disabled.
//
// Pure data-in/data-out: the same package facts always produce the same
// model — no clock, no randomness. Local-only provenance is visible, never
// implied centrally retained.

/** Segment capture states (the M4 segment binding contract). */
export type SegmentState = 'capturing' | 'verified' | 'interrupted' | 'failed';

/** The `.sjrec` package lifecycle (lifecycle.go PackageState). */
export type PackageState = 'ACTIVE' | 'DELETE_PENDING' | 'HELD_COMPLETE' | 'HELD_PARTIAL' | 'DELETED';

/** The shape of the authorized package read (meeting_semantic_package_read).
 *  Segment/child/export facts arrive exactly as the reducer projects them;
 *  this module derives the replay model deterministically.
 *
 *  The M4 replay feed (meeting_semantic_replay_read) composes this package
 *  projection with the recorded-fact rails: `presentationLinks`,
 *  `annotations`, `facts` and `captions`. All four are OPTIONAL here so a
 *  plain package read still parses — the replay surface treats their
 *  absence as the truthful empty state, never a fabricated track. */
export interface SemanticPackageRead {
	recordingId: number;
	meetingId: number;
	captureMode: string;
	recState: string;
	packageState: PackageState;
	localOnly: boolean;
	policyMode: string;
	manifestDigest: string | null;
	timelineSha256: string | null;
	timelineRecords: number | null;
	startedAt: string | null;
	stoppedAt: string | null;
	segments: Array<{
		seq: number;
		state: SegmentState;
		ack: string;
		contentSha256: string | null;
		byteSize: number | null;
		mimeType: string;
		codec: string;
		container: string;
		startMs: number;
		endMs: number;
		wallStartUnixMs: number;
		wallEndUnixMs: number;
		interruptReason: string | null;
	}>;
	children: Array<{
		child: string;
		childState: string;
		required: boolean;
		released: boolean;
		releaseGeneration: number | null;
	}>;
	exports: Array<{
		generation: number;
		state: string;
		attempts: number;
		bounds: Array<{ startMs: number; endMs: number }> | null;
		exclusions: Array<{ startMs: number; endMs: number }> | null;
		error: string | null;
		driveNodeId: number | null;
		driveVersionId: number | null;
	}>;
	/** Replay-feed riders (replay_read only). Version links are NEVER
	 *  hidden (M4: "presentation version links visible"); captions are an
	 *  explicitly empty list until a binding producer lands — named
	 *  absence, never a fabricated track. */
	presentationLinks?: ReplayPresentationLink[];
	annotations?: ReplayAnnotationRef[];
	captions?: ReplayCaptionRef[];
	facts?: ReplayFact[];
}

/** One visible source-version binding: which Drive version a stretch of
 *  replayed pages came from (the session's own lifecycle status rides
 *  along — never a fabricated claim about retained bytes V1 has not
 *  retained). */
export interface ReplayPresentationLink {
	presentationId: number;
	status: string;
	driveNodeId: number;
	driveVersionId: number;
	manifestDigest: string;
	manifestGeneration: number;
	startedAt: string | null;
	endedAt: string | null;
	annotationSnapshotRef: string | null;
	/** M6 document-mode fidelity surface (the TS mirror of replay.go's
	 *  AttachDocumentModeCapability): set only when the pinned rendition
	 *  manifest carried a document-mode capability. Absent/empty = the
	 *  launch vocabulary — no fidelity promise is implied, and a partial
	 *  triple (mode without class or fallback) surfaces NOTHING, never a
	 *  half-stated warning. */
	documentMode?: ReplayDocumentMode;
	fidelityClass?: ReplayFidelityClass;
	fallback?: ReplayFallbackRule;
}

/** M6 document-mode vocabulary (the mirror of docmode.go): word/text pages
 *  by the producer's own pagination; spreadsheets are the static print
 *  layout, never an interactive grid. */
export type ReplayDocumentMode = 'word_text_paginated' | 'spreadsheet_print_static';
export type ReplayFidelityClass = 'producer_pagination' | 'static_print_layout';
export type ReplayFallbackRule = 'office_editor_or_screen_share' | 'screen_share_or_office_editor';

/** One committed durable annotation snapshot inside the recording window,
 *  bound by stable reference + the server-derived content identity (the
 *  bytes themselves ride the authorized bounded annotation read). */
export interface ReplayAnnotationRef {
	presentationId: number;
	checkpointSeq: number;
	presenterGeneration: number;
	snapshotPath: string;
	sha256: string;
	byteSize: number;
	createdAt: string;
}

/** One visible caption binding (by reference; empty until the binding
 *  producer lands). */
export interface ReplayCaptionRef {
	language: string;
	state: string;
	path?: string;
}

/** One recorded presentation fact with BOTH clocks: atMs (wall) and
 *  mediaMs (media-aligned; -1 = no verified media base — the fact renders
 *  in the fact rail, never silently on the media axis). */
export interface ReplayFact {
	presentationId: number;
	checkpointSeq: number;
	kind: string;
	payload: unknown;
	atMs: number;
	mediaMs: number;
}

export type ReplayEntryKind = 'media' | 'gap';

export interface ReplayEntry {
	kind: ReplayEntryKind;
	startMs: number;
	endMs: number;
	/** Media facts: the verified segment serving this interval. */
	segmentSeq?: number;
	mimeType?: string;
	/** Gap facts: continue-at-next is offered ONLY when one exists. */
	nextAvailableMs?: number;
}

export interface UnavailableSegment {
	seq: number;
	state: SegmentState;
	reason: string;
	startMs: number;
	endMs: number;
}

export interface ReplayModel {
	recordingId: number;
	packageState: PackageState;
	/** Local-only provenance is a visible label, never a silent downgrade:
	 *  these bytes were never centrally retained. */
	localOnly: boolean;
	/** Empty when the package is fenced (delete/hold/deleted) — replay of a
	 *  fenced package is refused at the boundary, and the model explains
	 *  itself via packageState instead of playing. */
	entries: ReplayEntry[];
	unavailableSegments: UnavailableSegment[];
	/** Total media span (0..endMs) the timeline renders. */
	spanMs: number;
}

interface Interval {
	startMs: number;
	endMs: number;
}

function overlaps(a: Interval, b: Interval): boolean {
	return a.startMs < b.endMs && b.startMs < a.endMs;
}

/** Builds the deterministic replay model from the package facts. Verified
 *  segments only ever contribute availability; every hole between them is
 *  an explicit gap entry with its exact bounds; interrupted/failed
 *  segments are named unavailable, never silence. */
export function buildSemanticReplay(pkg: SemanticPackageRead): ReplayModel {
	const model: ReplayModel = {
		recordingId: pkg.recordingId,
		packageState: pkg.packageState,
		localOnly: pkg.localOnly,
		entries: [],
		unavailableSegments: [],
		spanMs: 0,
	};

	for (const s of pkg.segments) {
		if (s.state !== 'verified') {
			model.unavailableSegments.push({
				seq: s.seq,
				state: s.state,
				reason: s.interruptReason ?? '',
				startMs: s.startMs,
				endMs: s.endMs,
			});
		}
		if (s.endMs > model.spanMs) model.spanMs = s.endMs;
	}

	// A fenced package replays nothing — the boundary state IS the model.
	if (pkg.packageState !== 'ACTIVE') {
		return model;
	}

	const verified = pkg.segments
		.filter((s) => s.state === 'verified')
		.sort((a, b) => a.startMs - b.startMs);
	const available: Interval[] = [];
	for (const s of verified) {
		const last = available[available.length - 1];
		if (last && last.endMs === s.startMs) {
			last.endMs = s.endMs; // adjacent runs merge into one interval
		} else {
			available.push({ startMs: s.startMs, endMs: s.endMs });
		}
	}
	for (const a of available) {
		const seg = verified.find((s) => s.startMs <= a.startMs && s.endMs >= a.endMs);
		model.entries.push({
			kind: 'media',
			startMs: a.startMs,
			endMs: a.endMs,
			segmentSeq: seg?.seq,
			mimeType: seg?.mimeType,
		});
	}
	for (let i = 0; i < available.length; i++) {
		const cursor = i === 0 ? 0 : available[i - 1].endMs;
		if (available[i].startMs > cursor) {
			const next = available[i].startMs;
			model.entries.push({
				kind: 'gap',
				startMs: cursor,
				endMs: next,
				nextAvailableMs: next, // a later run exists — "continue" is lawful
			});
		}
	}
	const end = available.length > 0 ? available[available.length - 1].endMs : 0;
	if (model.spanMs > end) {
		// Trailing gap: nothing later exists, so NO continue affordance.
		model.entries.push({ kind: 'gap', startMs: end, endMs: model.spanMs });
	}
	// Deterministic order: by start, gaps BEFORE the media run they stop.
	model.entries.sort((a, b) =>
		a.startMs !== b.startMs ? a.startMs - b.startMs : (a.kind === 'gap' ? -1 : 1) - (b.kind === 'gap' ? -1 : 1),
	);
	return model;
}

export type SeekResult =
	| { ok: true; entry: ReplayEntry }
	| { ok: false; outcome: 'gap'; startMs: number; endMs: number; nextAvailableMs: number | null }
	| { ok: false; outcome: 'past-end' };

/** Deterministic seeking: inside a verified run resolves it; inside a gap
 *  announces the gap's bounds and the next available interval ONLY when one
 *  exists; past every entry is a named state — never the nearest stale
 *  entry, never synthesized silence. */
export function seekReplay(model: ReplayModel, positionMs: number): SeekResult {
	for (const e of model.entries) {
		if (positionMs < e.startMs || positionMs >= e.endMs) continue;
		if (e.kind === 'media') return { ok: true, entry: e };
		return {
			ok: false,
			outcome: 'gap',
			startMs: e.startMs,
			endMs: e.endMs,
			nextAvailableMs: e.nextAvailableMs ?? null,
		};
	}
	return { ok: false, outcome: 'past-end' };
}

export interface ReplayExportBounds {
	bounds: Interval[];
	exclusions: Interval[];
	/** Export is disabled when no verified interval exists — a pages-only
	 *  package exports nothing (never a fabricated video). */
	exportable: boolean;
}

/** The exact export bounds AND exclusions the export confirm must show
 *  (R5.4: invalidated or changed intervals require reselection, never
 *  silent clipping). */
export function replayExportBounds(model: ReplayModel): ReplayExportBounds {
	const bounds = model.entries
		.filter((e) => e.kind === 'media')
		.map((e) => ({ startMs: e.startMs, endMs: e.endMs }));
	const covered = (i: Interval): boolean =>
		bounds.some((b) => overlaps(i, b) || (i.startMs >= b.startMs && i.endMs <= b.endMs));
	const exclusions = model.entries
		.filter((e) => e.kind === 'gap')
		.map((e) => ({ startMs: e.startMs, endMs: e.endMs }))
		.filter((i) => !covered(i));
	return { bounds, exclusions, exportable: bounds.length > 0 };
}

/** The human summary a screen reader announces when playback stops at a
 *  gap (polite live region): bounds plus the named unavailable facts. */
export function gapAnnouncement(model: ReplayModel, gap: { startMs: number; endMs: number; nextAvailableMs: number | null }): string {
	const unavailable = model.unavailableSegments.filter((s) => s.startMs < gap.endMs && s.endMs > gap.startMs);
	const tracks = unavailable.map((s) => `segment ${s.seq}: ${s.reason || s.state}`).join('; ');
	const base = `Unavailable interval ${gap.startMs}–${gap.endMs} ms`;
	const facts = tracks ? `; unavailable: ${tracks}` : '';
	const next = gap.nextAvailableMs !== null ? `. Continue at ${gap.nextAvailableMs} ms` : '. No later available interval exists';
	return base + facts + next;
}

/** The fidelity notice a version link must show honestly beside itself
 *  (M6 "retain explicit fidelity warnings and fallback"): the warning class
 *  names what the rendition is NOT, and the fallback names the way out.
 *  Deterministic and total: launch-vocabulary links (no capability) and
 *  partial capability triples return null — nothing is implied. */
export interface ReplayFidelityNotice {
	warningKey: 'meet.replay.fidelityProducerPagination' | 'meet.replay.fidelityStaticPrint';
	fallbackKey: 'meet.replay.fallbackOfficeEditorOrScreenShare' | 'meet.replay.fallbackScreenShareOrOfficeEditor';
}

export function replayFidelityNotice(link: ReplayPresentationLink): ReplayFidelityNotice | null {
	if (!link.documentMode || !link.fidelityClass || !link.fallback) return null;
	return {
		warningKey:
			link.fidelityClass === 'producer_pagination'
				? 'meet.replay.fidelityProducerPagination'
				: 'meet.replay.fidelityStaticPrint',
		fallbackKey:
			link.fallback === 'office_editor_or_screen_share'
				? 'meet.replay.fallbackOfficeEditorOrScreenShare'
				: 'meet.replay.fallbackScreenShareOrOfficeEditor',
	};
}

/** Deterministic fact-rail projection (the M4 replay feed's `facts`): a
 *  fact with a verified media alignment (mediaMs >= 0) sorts ONTO the media
 *  axis by its media position; a fact without one (mediaMs < 0 — no
 *  verified media base exists) stays in the rail ordered by wall time.
 *  Same facts in, same list out — no clock, no randomness. */
export function replayFactRail(pkg: SemanticPackageRead): ReplayFact[] {
	return [...(pkg.facts ?? [])].sort((a, b) => {
		const aAligned = a.mediaMs >= 0;
		const bAligned = b.mediaMs >= 0;
		if (aAligned !== bAligned) return aAligned ? -1 : 1;
		if (aAligned) return a.mediaMs !== b.mediaMs ? a.mediaMs - b.mediaMs : a.checkpointSeq - b.checkpointSeq;
		return a.atMs !== b.atMs ? a.atMs - b.atMs : a.checkpointSeq - b.checkpointSeq;
	});
}
