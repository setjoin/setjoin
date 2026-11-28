// presentationApi.ts — MEET plan M3 client transport for the presentation
// session surface, aligned with the LANDED M2 routes
// (mailserver/internal/meet/presentation.go) and their TS seam
// (`./presentationCheckpoint` — the checkpoint/mutation-response shapes and
// the frame/throttle helpers M2 froze for exactly this consumer).
//
// Route map (verbatim from the M2 handler registrations):
//   POST /meet/{id}/presentation                     → prepare
//   POST /meet/{id}/presentation/{pid}/ready         → rendition ready (M1 rider)
//   POST /meet/{id}/presentation/{pid}/start         → READY → ACTIVE
//   POST /meet/{id}/presentation/{pid}/page          → presenter page change
//   POST /meet/{id}/presentation/{pid}/presenter     → grant / takeover
//   POST /meet/{id}/presentation/{pid}/end           → drain (not flag-gated)
//   GET  /meet/{id}/presentation/{pid}/checkpoint    → the authorized read
//
// NOT yet on the wire: the meet-pages-v1 MANIFEST read (the rendition
// pipeline that produces manifests/pages is M1's, wired separately — M2 pins
// identity + digest only). `getManifest` is the typed seam for that serving
// path; until it lands, callers fail visibly with the generic failure copy
// and the screen-share fallback — never fabricated pages.
//
// The reducer owns every mutation; this module is translation only. Page
// assets and speaker notes travel as separately authorized AssetRef fetches
// (the M1 rendition profile's relative references), never as envelope
// payloads.
import { problemFetch } from '$lib/http';
import type { SerializedAnnotationSnapshot } from './annotationSnapshots';
import type { PresentationCheckpoint, PresentationMutationResponse } from './presentationCheckpoint';
import type { SemanticPackageRead } from './semanticReplay';

const BASE = '/api/meet';
const { fetch: presentationFetch, fetchVoid: presentationFetchVoid } = problemFetch(BASE);

const JSON_HEADERS = { 'Content-Type': 'application/json' };

// ── M1 rendition projection types (client-side mirror of internal/meet/
// presentation/rendition.go; the manifest BODY arrives via the manifest
// read, the digest alone rides the M2 checkpoint) ─────────────────────────

export type PresentationStatus = string; // the M0 lifecycle vocabulary; the M2 seam keeps it a string

/** A SHORT-LIVED AUTHORIZED FETCH reference (rendition.go AssetRef): a
 *  relative fetch path, never an absolute/object-store URL. */
export interface PresentationAssetRef {
	path: string;
	mimeType: string;
	byteSize: number;
	sha256: string;
	expiresAt: string;
	ttlMs: number;
}

export interface PresentationPage {
	index: number; // 0-based, dense, manifest-ordered
	id: string;
	widthPx: number;
	heightPx: number;
	contentSha256: string;
	byteSize: number;
	mimeType: string;
	thumbnail: PresentationAssetRef;
	fullPage: PresentationAssetRef;
	/** Separately qualified, bounded visible-page accessible representation —
	 *  bound to THIS page capability, optional; absence is an explicit
	 *  accessibility limitation, never fabricated text. */
	accessibleRepresentation?: PresentationAssetRef | null;
}

/** The closed rendition-warning vocabulary (rendition.go RenditionWarning).
 *  Unknown codes fail closed server-side; this frozen list is exactly what a
 *  client must be able to display. */
export type RenditionWarningCode =
	| 'font_substituted'
	| 'animation_unsupported'
	| 'embedded_media'
	| 'truncated'
	| 'password_protected'
	| 'partial_conversion';

export interface PresentationManifest {
	schema: string; // always 'meet-pages-v1'
	driveNodeId: number;
	driveVersionId: number;
	sourceSha256: string;
	pages: PresentationPage[];
	/** Speaker-notes reference. Notes NEVER enter attendee manifests and
	 *  gate on current presenter permission on every fetch; the reference
	 *  being present grants nothing by itself. */
	notes?: (PresentationAssetRef & { requiresPresenterPermission: boolean }) | null;
	warnings: RenditionWarningCode[];
	rendererId: string;
	rendererVersion: string;
	fontPackDigest: string;
	integrityDigest: string;
	completedAt: string;
}

// ── the transport seam (structurally faked in tests, like RoomWhiteboardOps) ──

export interface PresentationApi {
	/** POST /meet/{id}/presentation — pin an authorized Drive version +
	 *  rendition manifest digest (M2 pins identity + digest; the rendition
	 *  pipeline that PRODUCES the manifest is M1's). Requires current Drive
	 *  source rights — enforced server-side, never request-owned. */
	prepare(
		meetingId: number,
		source: { nodeId: number; versionId: number; manifestDigest: string },
	): Promise<{ presentationId: number; status: PresentationStatus; checkpointSeq: number }>;
	/** GET /meet/{id}/presentation/{pid}/checkpoint — the authorized read
	 *  (meeting_presentation_checkpoint): the ONLY surface that promotes
	 *  client state alongside a mutation's own committed fact. Carries
	 *  `amPresenter`/`myParticipantId` (server-derived, never client
	 *  claims). May reject `checkpointRefreshThrottled` (429). */
	getCheckpoint(meetingId: number, presentationId: number): Promise<PresentationCheckpoint>;
	/** The meet-pages-v1 manifest read — the M1 authorized serving seam.
	 *  Absent on the wire today: callers must degrade visibly, never
	 *  synthesize pages. */
	getManifest(meetingId: number, presentationId: number): Promise<PresentationManifest>;
	/** POST .../{pid}/start — commit READY → ACTIVE. */
	start(meetingId: number, presentationId: number, presenterGeneration?: number | null): Promise<PresentationMutationResponse>;
	/** POST .../{pid}/page — presenter page change; the body fences on the
	 *  presenter generation AND checkpoint sequence the client holds (the
	 *  stale-presenter-overwrite prevention, enforced by the reducer). */
	changePage(
		meetingId: number,
		presentationId: number,
		fence: { presenterGeneration: number; checkpointSeq: number },
		pageIndex: number,
	): Promise<PresentationMutationResponse>;
	/** POST .../{pid}/presenter — grant to `targetParticipantId`, or
	 *  authorized takeover when `takeover` is true (the departing-presenter
	 *  rescue; verb-specific authority is re-checked by the reducer). */
	grantPresenter(
		meetingId: number,
		presentationId: number,
		body: { targetParticipantId: number; takeover: boolean; presenterGeneration?: number | null },
	): Promise<PresentationMutationResponse>;
	/** POST .../{pid}/end — ACTIVE → ENDED. A DRAIN verb: not flag-gated.
	 *  The session's local truth is cleared by the caller's own policy; the
	 *  reducer fact needs no promotion (the response is fire-and-recover). */
	end(meetingId: number, presentationId: number, presenterGeneration?: number | null): Promise<void>;
	/** Fetches a text AssetRef (speaker notes / accessible representation)
	 *  through its own authorized path. Notes calls require current
	 *  presenter permission server-side; the store never issues one
	 *  client-side without the presenter gate. */
	fetchText(ref: PresentationAssetRef): Promise<string>;
}

export const httpPresentationApi: PresentationApi = {
	prepare: (meetingId, source) =>
		presentationFetch<{ presentationId: number; status: PresentationStatus; checkpointSeq: number }>(
			`/${meetingId}/presentation`,
			{ method: 'POST', headers: JSON_HEADERS, body: JSON.stringify(source) },
		),
	getCheckpoint: (meetingId, presentationId) =>
		presentationFetch<PresentationCheckpoint>(`/${meetingId}/presentation/${presentationId}/checkpoint`),
	getManifest: (meetingId, presentationId) =>
		presentationFetch<PresentationManifest>(`/${meetingId}/presentation/${presentationId}/manifest`),
	start: (meetingId, presentationId, presenterGeneration) =>
		presentationFetch<PresentationMutationResponse>(`/${meetingId}/presentation/${presentationId}/start`, {
			method: 'POST',
			headers: JSON_HEADERS,
			body: JSON.stringify({ presenterGeneration: presenterGeneration ?? null }),
		}),
	changePage: (meetingId, presentationId, fence, pageIndex) =>
		presentationFetch<PresentationMutationResponse>(`/${meetingId}/presentation/${presentationId}/page`, {
			method: 'POST',
			headers: JSON_HEADERS,
			body: JSON.stringify({
				presenterGeneration: fence.presenterGeneration,
				checkpointSeq: fence.checkpointSeq,
				pageIndex,
			}),
		}),
	grantPresenter: (meetingId, presentationId, body) =>
		presentationFetch<PresentationMutationResponse>(`/${meetingId}/presentation/${presentationId}/presenter`, {
			method: 'POST',
			headers: JSON_HEADERS,
			body: JSON.stringify({
				targetParticipantId: body.targetParticipantId,
				takeover: body.takeover,
				presenterGeneration: body.presenterGeneration ?? null,
			}),
		}),
	end: (meetingId, presentationId, presenterGeneration) =>
		presentationFetchVoid(`/${meetingId}/presentation/${presentationId}/end`, {
			method: 'POST',
			headers: JSON_HEADERS,
			body: JSON.stringify({ presenterGeneration: presenterGeneration ?? null }),
		}),
	fetchText: (ref) => presentationFetch<string>(ref.path),
};

// ── M4 durable annotation admission + semantic replay reads ───────────────
// Standalone transport functions (the annotation commit and the replay
// reads are M4 surfaces; they deliberately do NOT extend the PresentationApi
// interface — that contract is the M2/M3 session verbs, and its existing
// fakes stay untouched).


/** The committed fact of an annotation mutation (the reducer fact plus the
 *  commit's bounded reference rider; a clear carries no rider). */
export interface AnnotationMutationResponse extends PresentationMutationResponse {
	annotation?: { snapshotRef: string; sha256: string; byteSize: number };
}

/** The authorized bounded read of the CURRENT committed snapshot
 *  (meeting_presentation_annotation_read): `snapshot` is null when none is
 *  committed — truthful absence, never an error. */
export interface AnnotationSnapshotRead {
	presentationId: number;
	snapshot: {
		snapshotRef: string;
		sha256: string;
		byteSize: number;
		checkpointSeq: number;
		presenterGeneration: number;
		content: string;
		createdAt: string;
	} | null;
}

/** POST …/{pid}/annotation — the durable annotation commit (presenter,
 *  fenced on the presenter generation AND checkpoint sequence the client
 *  holds) or clear. The snapshot rides as the exact serialized text whose
 *  sha256/byteSize were derived by `serializeAnnotationSnapshot` — the
 *  server re-derives both from the received bytes and refuses a mismatch
 *  (BZ277 admitted-path semantics). */
export function commitAnnotation(
	meetingId: number,
	presentationId: number,
	body: { presenterGeneration: number; checkpointSeq: number } & ({ clear: true } | { clear: false; snapshot: SerializedAnnotationSnapshot }),
): Promise<AnnotationMutationResponse> {
	return presentationFetch<AnnotationMutationResponse>(`/${meetingId}/presentation/${presentationId}/annotation`, {
		method: 'POST',
		headers: JSON_HEADERS,
		body: JSON.stringify(
			body.clear
				? { presenterGeneration: body.presenterGeneration, checkpointSeq: body.checkpointSeq, clear: true }
				: {
						presenterGeneration: body.presenterGeneration,
						checkpointSeq: body.checkpointSeq,
						snapshot: body.snapshot.text,
					},
		),
	});
}

/** GET …/{pid}/annotation — the authorized bounded reference/read path the
 *  envelope contract names for durable snapshots (reconnect convergence:
 *  the checkpoint read names WHAT is current, this serves its bytes). */
export function fetchAnnotationSnapshot(meetingId: number, presentationId: number): Promise<AnnotationSnapshotRead> {
	return presentationFetch<AnnotationSnapshotRead>(`/${meetingId}/presentation/${presentationId}/annotation`);
}

/** GET …/semantic/{rid}/package — the `.sjrec` package projection
 *  (meeting_semantic_package_read): manifest facts, truthful segment
 *  state, receipt ledger. */
export function fetchSemanticPackage(meetingId: number, recordingId: number): Promise<SemanticPackageRead> {
	return presentationFetch<SemanticPackageRead>(`/${meetingId}/semantic/${recordingId}/package`);
}

/** GET …/semantic/{rid}/replay — the deterministic replay feed
 *  (meeting_semantic_replay_read): the package projection composed with the
 *  presentation version links, committed annotation references and the
 *  fact rail. */
export function fetchSemanticReplay(meetingId: number, recordingId: number): Promise<SemanticPackageRead> {
	return presentationFetch<SemanticPackageRead>(`/${meetingId}/semantic/${recordingId}/replay`);
}
