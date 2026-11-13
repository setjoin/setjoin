package presentation

import "fmt"

// State is the durable presentation checkpoint state machine ("Presentation
// state"). Transitions are reducer-owned; this is the frozen vocabulary and
// legality table both the reducer (M2) and clients validate against.
type State string

const (
	StatePreparing State = "PREPARING"
	StateReady     State = "READY"
	StateActive    State = "ACTIVE"
	StateFailed    State = "FAILED"
	StateCancelled State = "CANCELLED"
	StateEnded     State = "ENDED"
	StateRevoked   State = "REVOKED"
	StateDegraded  State = "DEGRADED"
)

var stateTransitions = map[State][]State{
	StatePreparing: {StateReady, StateFailed, StateCancelled},
	StateReady:     {StateActive, StateFailed, StateCancelled},
	StateActive:    {StateEnded, StateRevoked, StateDegraded},
	StateDegraded:  {StateActive}, // recover
	// Terminal states have no outgoing transitions. Invalid:
	// ENDED/REVOKED → ACTIVE is unreachable BY CONSTRUCTION here — a
	// resurrect attempt is a programming error, caught by CanTransition.
	StateFailed:    {},
	StateCancelled: {},
	StateEnded:     {},
	StateRevoked:   {},
}

// CanTransition reports whether from→to is legal.
func CanTransition(from, to State) bool {
	for _, next := range stateTransitions[from] {
		if next == to {
			return true
		}
	}
	return false
}

// Checkpoint is the durable checkpoint field set ("Presentation state").
// The reducer commits it atomically with audit and state bump; pointers and
// in-progress ink never appear here.
type Checkpoint struct {
	MeetingID              string
	PresentationID         string
	DriveNodeID            int64
	DriveVersionID         int64
	ManifestDigest         string
	ManifestGeneration     int64
	Status                 State
	PresenterParticipantID string
	PresenterGeneration    int64
	PageIndex              int
	CheckpointSeq          int64
	StartedAt              int64 // unix millis; 0 = not started
	EndedAt                int64 // unix millis; 0 = not ended
	AnnotationSnapshotRef  string
	RecordingCaptureMode   string
	InitiatorUserID        int64
	LastActorUserID        int64
	ReducerStateVersion    int64
}

// SJRecChild names one logical child of a `.sjrec` package ("Semantic
// recording format"). The package is a logical Drive recording package —
// not a user-editable directory and not necessarily one physical archive
// object.
type SJRecChild string

const (
	SJRecManifest             SJRecChild = "manifest.json"
	SJRecTimeline             SJRecChild = "timeline.ndjson"
	SJRecPresentations        SJRecChild = "presentations/<presentation-id>.json"
	SJRecCaptions             SJRecChild = "captions/<language>.vtt"
	SJRecMediaAudio           SJRecChild = "media/audio-<segment>"
	SJRecLegacyVideoReference SJRecChild = "media/legacy-video-reference.json"
	SJRecAnnotations          SJRecChild = "annotations/<snapshot>.json"
	SJRecIntegrity            SJRecChild = "integrity/sha256.json"
)

// ChildState records embedded/retained/absent/expired for every child, as
// the manifest records per-child state.
type ChildState string

const (
	ChildEmbedded ChildState = "embedded" // bytes inside this recording package
	ChildRetained ChildState = "retained" // copied under the recording's own retention policy
	ChildAbsent   ChildState = "absent"   // never captured (e.g. page never presented)
	ChildExpired  ChildState = "expired"  // retained once, retention since lapsed
)

// PackageState is the logical `.sjrec` deletion lifecycle ("Semantic
// recording format"):
//
//	ACTIVE ──reducer marks──▶ DELETE_PENDING ──worker sweeps children──▶ DELETED
//	                                │ hold fences remaining releases         │
//	                                ▼                        orphan audit ◀──┘
//	                     HELD_COMPLETE or HELD_PARTIAL
//
// Restore is only legal from HELD_COMPLETE with every required reference
// still protected. In V1, any already-released required child makes the
// package HELD_PARTIAL and INELIGIBLE for restore — a current HEAD/read
// seeing bytes does not defeat concurrent physical GC.
type PackageState string

const (
	PackageActive        PackageState = "ACTIVE"
	PackageDeletePending PackageState = "DELETE_PENDING"
	PackageHeldComplete  PackageState = "HELD_COMPLETE"
	PackageHeldPartial   PackageState = "HELD_PARTIAL"
	PackageDeleted       PackageState = "DELETED"
)

var packageTransitions = map[PackageState][]PackageState{
	PackageActive:        {PackageDeletePending},
	PackageDeletePending: {PackageHeldComplete, PackageHeldPartial, PackageDeleted},
	PackageHeldComplete:  {PackageActive}, // restore: locks package/receipt, verifies required live refs, cancels the deletion generation atomically
	PackageHeldPartial:   {},              // V1: ineligible for restore, even if a read currently sees bytes
	PackageDeleted:       {},
}

// CanTransitionPackage reports whether from→to is legal at the logical
// package boundary. Delete/hold are reducer-atomic at this boundary, never
// object-store-atomic.
func CanTransitionPackage(from, to PackageState) bool {
	for _, next := range packageTransitions[from] {
		if next == to {
			return true
		}
	}
	return false
}

// ReleaseReceipt is the idempotent per-child release record the worker
// requests through the OWNING reducer. The worker never writes
// `blobs.ref_count` directly: under the same package/receipt lock the
// reducer rechecks current hold, deletion generation and the exact child,
// removes its logical reference once, and records the result; triggers
// maintain blob counts. Retries cannot double-release a child.
type ReleaseReceipt struct {
	Child             SJRecChild
	ReleaseGeneration int64 // deletion generation the release executed under
	AlreadyReleased   bool  // idempotent replay marker
	HeldBeforeRelease bool  // a hold linearized before the release fences it
}

// FinalizeAllowed reports whether the expected child set is exhausted so the
// sweep may finalize to DELETED. Finalization requires the expected set to
// be exhausted; a later hold suspends the remainder but cannot recall
// already reclaimed bytes.
func FinalizeAllowed(expected, released int, holdsRemaining int) error {
	if holdsRemaining > 0 {
		return fmt.Errorf("%d hold(s) fence remaining releases; finalize suspended", holdsRemaining)
	}
	if released < expected {
		return fmt.Errorf("expected child set not exhausted (%d/%d released)", released, expected)
	}
	if released > expected {
		return fmt.Errorf("release count %d exceeds expected set %d — receipt replay corruption", released, expected)
	}
	return nil
}
