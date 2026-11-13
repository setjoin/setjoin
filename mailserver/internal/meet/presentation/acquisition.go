package presentation

import (
	"context"
	"errors"
	"fmt"
	"regexp"
)

// M4 — the server-audio acquisition adapter, FAIL-CLOSED by design.
//
// The plan gates the public recording contract on "real pinned service
// evidence" (M4 bullet 1): "Freeze its exact supported Egress/API/container/
// codec behavior with real pinned service evidence before implementing the
// public recording contract; current B2 RoomComposite MP4 does not prove an
// audio-only or WebM path exists." That evidence is acceptance case
// MP-AUDIO-001 and it has NOT run: livekit-server v1.13's fileToOutputType
// maps RoomComposite file recordings to MP4+H.264+AAC only (proven live in
// B2 and ratified 2026-07-16), and an audio-only/WebM file path is
// unproven.
//
// This file therefore defines ONLY the adapter seam, the typed provider
// classification, and the version-pin rule. There is NO live Egress audio
// call anywhere, and the ONLY implementation shipped is the fail-closed
// one: it classifies the audio path evidence_pending and refuses every
// capture. Nothing here claims an audio path exists.

// ProviderClass is the typed qualification classification of an audio
// acquisition provider. Only Qualified admits capture — ever.
type ProviderClass string

const (
	// ProviderQualified — real pinned service evidence exists (MP-AUDIO-001
	// style: exact producer/API/container/codec proven against the pinned
	// service) and the profile may admit capture.
	ProviderQualified ProviderClass = "qualified"
	// ProviderEvidencePending — no disproof, no proof: the qualification
	// evidence has not been produced. Fails closed (the CURRENT state of
	// server audio in this repo).
	ProviderEvidencePending ProviderClass = "evidence_pending"
	// ProviderUnsupported — real evidence proves the path does NOT exist
	// (e.g. the B2 container-reality proof for RoomComposite WebM). Also
	// fails closed, with a stronger message.
	ProviderUnsupported ProviderClass = "unsupported"
)

// ErrAudioPathEvidencePending is the sentinel every unqualified capture
// refusal wraps. Callers (and tests) match on it with errors.Is; the wire
// surface projects it as a named fail-closed refusal, never as a silent
// fallback to another recording mode.
var ErrAudioPathEvidencePending = errors.New("server audio acquisition is evidence-pending: no qualified audio-only producer profile exists (MP-AUDIO-001 unrun); capture fails closed")

// evidenceRefDigest pins the EvidenceRef form for QUALIFIED profiles: the
// qualification record reference must carry the sha256 of the exact receipt
// it points at (`<path>#sha256=<64 hex>`; the MP-AUDIO-001 evidence harness
// prints that digest with every receipt). A plain-string reference with no
// digest is not a verifiable pin — the wave-1 B4 test-contract row 32
// amendment requires the digest binding (same posture as provider.go's
// hex64 digests). Pending/unsupported profiles still carry NO evidence at
// all.
var evidenceRefDigest = regexp.MustCompile(`^[^#\s]+#sha256=[0-9a-f]{64}$`)

// CaptureProfile is the version-pinned producer identity of one audio
// acquisition profile. Every field comes from qualification evidence —
// NOTHING in this repo invents a value (the ProviderIdentity posture,
// provider.go). The zero value with Class evidence_pending is the honest
// shape this slice ships.
type CaptureProfile struct {
	Class ProviderClass `json:"class"`
	// ProducerID/ProducerVersion pin the media producer (e.g. the egress
	// sidecar identity) — from evidence, never drafted.
	ProducerID      string `json:"producerId,omitempty"`
	ProducerVersion string `json:"producerVersion,omitempty"`
	// EgressAPIVersion pins the Egress/API surface the producer used.
	EgressAPIVersion string `json:"egressApiVersion,omitempty"`
	// Container/Codec pin the actual output identity (e.g. audio/webm +
	// opus). Actual observed media identity is re-bound per segment
	// (MediaSegment.MIMEType/Codec); the profile is what NEW capture is
	// admitted against.
	Container    string `json:"container,omitempty"`
	Codec        string `json:"codec,omitempty"`
	SampleRateHz int    `json:"sampleRateHz,omitempty"`
	// EvidenceRef points at the qualification record that produced every
	// value above — `<record-path>#sha256=<64 hex>` of the exact receipt
	// bytes (MP-AUDIO-001 harness receipt or an equivalent owner-retained
	// record). Admission fails closed without the digest-bearing reference.
	EvidenceRef string `json:"evidenceRef,omitempty"`
}

// Validate checks a profile's internal completeness FOR ITS CLASS: only a
// qualified profile may carry an evidence reference; pending/unsupported
// profiles must not fabricate one.
func (p CaptureProfile) Validate() error {
	switch p.Class {
	case ProviderQualified:
		if p.ProducerID == "" || p.ProducerVersion == "" {
			return errors.New("qualified capture profile missing producer identity/version")
		}
		if p.EgressAPIVersion == "" || p.Container == "" || p.Codec == "" {
			return errors.New("qualified capture profile missing egress/container/codec pins")
		}
		if p.SampleRateHz <= 0 {
			return errors.New("qualified capture profile missing sample rate")
		}
		if p.EvidenceRef == "" {
			return errors.New("qualified capture profile without qualification evidence fails closed")
		}
		if !evidenceRefDigest.MatchString(p.EvidenceRef) {
			return fmt.Errorf("qualified capture profile evidence %q is not a digest-bearing reference (<path>#sha256=<64 hex>); an unverifiable pin fails closed", p.EvidenceRef)
		}
	case ProviderEvidencePending, ProviderUnsupported:
		if p.EvidenceRef != "" {
			return fmt.Errorf("%s profile must not claim qualification evidence", p.Class)
		}
	default:
		return fmt.Errorf("unknown provider class %q fails closed", p.Class)
	}
	return nil
}

// RequalificationRequired implements the 2026-09-06 composition amendment
// (M4): "a producer/Egress/codec provider version change re-qualifies the
// pinned profile before new capture." Any change to the pinned producer,
// Egress API, container or codec identity — even a plausible upgrade —
// requires explicit requalification; there is no silent in-place swap (the
// EvaluateRebind posture, provider.go, applied to capture profiles).
func RequalificationRequired(pinned, candidate CaptureProfile) bool {
	return pinned.ProducerID != candidate.ProducerID ||
		pinned.ProducerVersion != candidate.ProducerVersion ||
		pinned.EgressAPIVersion != candidate.EgressAPIVersion ||
		pinned.Container != candidate.Container ||
		pinned.Codec != candidate.Codec
}

// AdmitCaptureProfile is the capture-side admission gate: the candidate
// profile must be qualified with evidence AND, when a profile is already
// pinned (an in-flight recording or the deployed profile), byte-identical
// to it. Anything else fails closed with ErrAudioPathEvidencePending (or a
// named unsupported error) — never a best-effort capture.
func AdmitCaptureProfile(pinned, candidate CaptureProfile) error {
	if err := candidate.Validate(); err != nil {
		return err
	}
	switch candidate.Class {
	case ProviderEvidencePending:
		return fmt.Errorf("%w: candidate profile %q/%q", ErrAudioPathEvidencePending, candidate.ProducerID, candidate.ProducerVersion)
	case ProviderUnsupported:
		return fmt.Errorf("audio acquisition provider is unsupported by qualification evidence (no audio-only/WebM path): %s/%s",
			candidate.ProducerID, candidate.ProducerVersion)
	case ProviderQualified:
		if pinned.Class == ProviderEvidencePending || pinned.Class == ProviderUnsupported {
			return fmt.Errorf("%w: pinned profile is %s; a qualified candidate needs explicit requalification, not capture",
				ErrAudioPathEvidencePending, pinned.Class)
		}
		if RequalificationRequired(pinned, candidate) {
			return fmt.Errorf("capture profile changed (producer/egress/container/codec); the pinned profile must be re-qualified before new capture")
		}
		return nil
	default:
		return fmt.Errorf("unknown provider class %q fails closed", candidate.Class)
	}
}

// CaptureLease is the short-lived, reducer-issued authority a capture runs
// under (the recording policy invariants: reducer-commit-before-capture,
// shared BZ199 lifecycle). V1 carries only what the contract needs; the
// lease lifecycle reducers own its truth.
type CaptureLease struct {
	RecordingID     int64
	MeetingID       int64
	Generation      int64
	ExpiresAtUnixMs int64
}

// CaptureStart is one admitted capture request bound to its lease.
type CaptureStart struct {
	Lease   CaptureLease
	Room    string
	Profile CaptureProfile
}

// CaptureHandle identifies a live producer-side capture.
type CaptureHandle struct {
	EgressID   string
	SegmentSeq int64
}

// CaptureResult is the truthful producer-side stop result: what actually
// got produced (observed identity + interval + completeness), never a
// success claim. Interrupted is mandatory for any non-clean stop.
type CaptureResult struct {
	Segment      MediaSegment
	ProducerInfo string
}

// AudioAcquirer is the M4 acquisition seam (the RoomController /
// EgressController / CaptionsController genre, DES-011): the peripheral
// that starts/stops real audio capture, never the authority. Reducers own
// the recording lifecycle; this adapter only translates.
type AudioAcquirer interface {
	// Qualify reports the provider's current typed classification. It never
	// starts anything.
	Qualify(ctx context.Context) (CaptureProfile, error)
	// Start begins one segment capture under a valid lease. Unqualified
	// providers MUST refuse with an error wrapping
	// ErrAudioPathEvidencePending.
	Start(ctx context.Context, req CaptureStart) (CaptureHandle, error)
	// Stop ends a capture and returns the truthful result.
	Stop(ctx context.Context, handle CaptureHandle, req CaptureStart) (CaptureResult, error)
}

// FailClosedAcquirer is the ONLY implementation this slice ships: it
// classifies the server-audio path as evidence_pending and refuses every
// Start. It exists so the wiring, tests and future qualification land on a
// seam that already fails closed — the audio path is admitted by replacing
// this with a qualified, evidence-backed provider, never by flipping a
// boolean.
type FailClosedAcquirer struct {
	// Reason optionally names WHY (tests use it to assert the message).
	Reason string
}

// Qualify reports the honest classification: evidence_pending.
func (FailClosedAcquirer) Qualify(context.Context) (CaptureProfile, error) {
	return CaptureProfile{Class: ProviderEvidencePending}, nil
}

// Start always fails closed.
func (a FailClosedAcquirer) Start(context.Context, CaptureStart) (CaptureHandle, error) {
	if a.Reason == "" {
		return CaptureHandle{}, ErrAudioPathEvidencePending
	}
	return CaptureHandle{}, fmt.Errorf("%w: %s", ErrAudioPathEvidencePending, a.Reason)
}

// Stop is unreachable after a failed Start; it still fails closed so a
// buggy caller cannot read success out of it.
func (a FailClosedAcquirer) Stop(context.Context, CaptureHandle, CaptureStart) (CaptureResult, error) {
	return CaptureResult{}, ErrAudioPathEvidencePending
}
