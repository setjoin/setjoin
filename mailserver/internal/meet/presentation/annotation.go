package presentation

import (
	"encoding/json"
	"fmt"
	"regexp"
)

// M4 — durable annotation admission (the BZ277 flip). The M0/M2 reservation
// ("Reserved for M4 admission — valid to PARSE, invalid to commit durably")
// gained its admitting writer: the reducer meeting_presentation_annotation_commit
// commits a presenter annotation snapshot as a durable `annotation.committed`
// event plus the checkpoint's annotation_snapshot_ref, fenced on the same
// four axes as every presentation verb. The GUARD WAS NOT REMOVED — it
// narrowed to admitted-path semantics, and this file freezes the admitted
// shape so the send path, the receive path and the reducer all refuse the
// same malformed/oversized annotation frames (envelope.go's closed-payload
// contract, the page.changed genre).
//
// Wire discipline (frozen by M0, honored here): the versioned envelope NEVER
// carries snapshot bytes — its payload is the bounded stable REFERENCE
// {snapshotRef, sha256, byteSize} ("larger durable snapshots use an
// authorized bounded reference/read path, not implicit fragmentation"). The
// snapshot's exact serialized bytes travel the commit request and live in
// the durable ledger (V267), bounded by MaxAnnotationSnapshotBytes — the
// stored-object 16 KiB limit, which is NOT the wire allowance but IS the
// durable-snapshot bound: a larger snapshot has no admitted home and needs
// the separately designed reference-storage contract, never fragmentation.
const (
	// MaxAnnotationSnapshotBytes bounds the exact serialized snapshot bytes
	// a durable commit may carry (the stored-object 16 KiB limit).
	MaxAnnotationSnapshotBytes = 16 << 10
	// TargetAnnotationPayloadBytes is the closed envelope payload's target
	// (the page-change genre): a reference payload is tiny by construction.
	TargetAnnotationPayloadBytes = 1024
)

// annotationSnapshotRefRe is the reducer-derived StableRef path grammar
// (`annotations/p<id>-s<seq>.json`, the V266 child literal
// `annotations/<snapshot>.json`'s concrete shape). Package-relative,
// server-derived, never request-owned.
var annotationSnapshotRefRe = regexp.MustCompile(`^annotations/p[0-9]+-s[0-9]+\.json$`)

// ValidAnnotationSnapshotRef reports whether ref is a well-formed committed
// snapshot reference.
func ValidAnnotationSnapshotRef(ref string) bool {
	return annotationSnapshotRefRe.MatchString(ref)
}

// AnnotationPayload is the closed annotation event payload carried by the
// versioned envelope (commit only — a clear carries no payload).
type AnnotationPayload struct {
	SnapshotRef string `json:"snapshotRef"`
	SHA256      string `json:"sha256"`
	ByteSize    int64  `json:"byteSize"`
}

// validSHA256 is shared with sjrec.go's digest checks.
func validAnnotationPayload(payload json.RawMessage) error {
	var p AnnotationPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return fmt.Errorf("annotation.committed payload is not a typed annotation payload: %w", err)
	}
	if !ValidAnnotationSnapshotRef(p.SnapshotRef) {
		return fmt.Errorf("annotation.committed payload snapshotRef %q is not an admitted snapshot reference", p.SnapshotRef)
	}
	if err := validSHA256(p.SHA256); err != nil {
		return fmt.Errorf("annotation.committed payload digest: %w", err)
	}
	if p.ByteSize < 1 || p.ByteSize > MaxAnnotationSnapshotBytes {
		return fmt.Errorf("annotation.committed payload byte size %d outside [1,%d]", p.ByteSize, MaxAnnotationSnapshotBytes)
	}
	if len(payload) > TargetAnnotationPayloadBytes {
		return fmt.Errorf("annotation payload of %d bytes exceeds the %d-byte target", len(payload), TargetAnnotationPayloadBytes)
	}
	return nil
}

// validateAnnotationEvent is the closed payload contract for the annotation
// kinds, shared by the send path (Envelope.Encode) and the receive path
// (Classify): a commit carries exactly the typed reference payload; a clear
// carries no payload at all. Anything else is a producer failure on send and
// a reject verdict on receive — the admitted-path guard at the wire layer.
func validateAnnotationEvent(kind EventKind, payload json.RawMessage) error {
	switch kind {
	case KindAnnotationCommitted:
		return validAnnotationPayload(payload)
	case KindAnnotationCleared:
		if len(payload) != 0 && string(payload) != "null" {
			return fmt.Errorf("annotation.cleared carries no payload")
		}
		return nil
	default:
		return nil
	}
}
