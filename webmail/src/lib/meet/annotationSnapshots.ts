// annotationSnapshots.ts — MEET plan M4: the client-side durable annotation
// commit binding (retired-docs:superpowers/plans/2026-08-25-meet-document-
// presentation-semantic-recording.md, M4 "annotation snapshots"; the mirror
// of internal/meet/presentation/annotation.go and the V267 reducer's
// admitted-shape gate).
//
// A durable annotation snapshot is the EXACT serialized JSON of the
// presenter's committed ink. This module owns the send-side contract only:
//
//   · the byte bound (MaxAnnotationSnapshotBytes = the stored-object 16 KiB
//     limit — a larger snapshot is NOT admitted; it needs the separately
//     designed reference-storage contract, never implicit fragmentation),
//   · canonical serialization (stable key order — the same snapshot always
//     serializes to the same bytes, so the server-derived content identity
//     is reproducible),
//   · the content identity (sha256 over the exact serialized UTF-8 bytes —
//     derived from the bytes, never claimed by a caller, mirroring the R2
//     posture and the V267 in-database re-derivation that will refuse a
//     mismatch),
//   · the JSON shape the admitted path carries (an object; arrays/scalars
//     are not snapshots).
//
// Pure data-in/data-out; the transport lives in presentationApi.ts.

export const MAX_ANNOTATION_SNAPSHOT_BYTES = 16384;

export interface SerializedAnnotationSnapshot {
	/** The exact serialized snapshot text — the bytes that are hashed,
	 *  transported and stored (never re-serialized downstream). */
	text: string;
	/** Lowercase hex sha256 over the exact UTF-8 bytes of `text`. */
	sha256: string;
	/** UTF-8 byte length of `text`. */
	byteSize: number;
}

export type SerializeResult =
	| { ok: true; snapshot: SerializedAnnotationSnapshot }
	| { ok: false; error: 'not-an-object' | 'over-bound' };

const utf8Encoder = new TextEncoder();

/** Hex-encodes a digest buffer (crypto.subtle is async; this stays pure). */
function toHex(buf: ArrayBuffer): string {
	const view = new Uint8Array(buf);
	let out = '';
	for (const b of view) out += b.toString(16).padStart(2, '0');
	return out;
}

/** Canonicalizes one snapshot object's key order (recursively, sorted) so
 *  the serialization is a pure function of the snapshot's DATA — a
 *  Map<→Object> rebuild or a property re-ordering can never change the
 *  committed bytes or the identity derived from them. */
function canonicalize(value: unknown): unknown {
	if (Array.isArray(value)) return value.map(canonicalize);
	if (value !== null && typeof value === 'object') {
		const out: Record<string, unknown> = {};
		for (const k of Object.keys(value as Record<string, unknown>).sort()) {
			out[k] = canonicalize((value as Record<string, unknown>)[k]);
		}
		return out;
	}
	return value;
}

/** Serializes a durable annotation snapshot for the admitted commit path.
 *  Fails closed on a non-object payload and on anything over the byte
 *  bound — both are unadmitted shapes (BZ277 admitted-path semantics), and
 *  the caller must never ship one to the server. */
export async function serializeAnnotationSnapshot(snapshot: unknown): Promise<SerializeResult> {
	if (snapshot === null || typeof snapshot !== 'object' || Array.isArray(snapshot)) {
		return { ok: false, error: 'not-an-object' };
	}
	const text = JSON.stringify(canonicalize(snapshot));
	const byteSize = utf8Encoder.encode(text).length;
	if (byteSize < 1 || byteSize > MAX_ANNOTATION_SNAPSHOT_BYTES) {
		return { ok: false, error: 'over-bound' };
	}
	const digest = await crypto.subtle.digest('SHA-256', utf8Encoder.encode(text));
	return { ok: true, snapshot: { text, sha256: toHex(digest), byteSize } };
}

/** The committed reference the server derives for a snapshot bound to
 *  (presentation, checkpoint) — the `.sjrec` StableRef path grammar. Used
 *  by the replay view to reconcile a feed annotation row with the snapshot
 *  its presentation binds. */
export function annotationSnapshotRef(presentationId: number, checkpointSeq: number): string {
	return `annotations/p${presentationId}-s${checkpointSeq}.json`;
}
