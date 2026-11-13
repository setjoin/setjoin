package presentation

import (
	"errors"
	"fmt"
	"regexp"
)

// M1(a) — version-pinned rendition/provider lifecycle. The M0-qualified
// renderer/font/provider identities pin every build, update and removal
// boundary; a provider or manifest version change re-qualifies affected
// pinned sessions through the owning authority instead of silently swapping
// providers. Acceptance: a pinned session survives a provider version
// change ONLY via explicit requalification/rebind, never an in-place silent
// provider swap.

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ProviderIdentity is the frozen qualified delivery profile ("M1 — Drive
// paged renditions", first bullet): every field exists so qualification can
// fill it; NOTHING in this plan invents a value. An identity with an empty
// evidence reference is not admittable.
type ProviderIdentity struct {
	RendererID           string // provider-neutral renderer identity
	RendererVersion      string // from qualification evidence, never drafted here
	FontPackDigest       string // hex sha256 of the pinned font pack
	LocaleProfile        string
	OutputProfileVersion string // RenditionProfileVersion for meet-pages-v1
	SupportedOSArch      string // e.g. "linux/amd64" — the qualified delivery target
	ArtifactFormat       string // build/package artifact format
	ArtifactSHA256       string // hex sha256 of the exact qualified artifact
	LicenseSPDX          string // redistributable license identifier
	ProvenanceRef        string // build/provenance + signature verification evidence reference
	SandboxPolicy        string // sandbox policy identity the artifact runs under
	HealthProtocol       string // health protocol identity
	// EvidenceRef points at the qualification record that produced every
	// value above. Admission fails closed without it.
	EvidenceRef string
}

// AdmitProviderIdentity is the fail-closed admission gate for the compiled
// catalog: a missing/unverified/incompatible identity leaves Meet rendering
// UNAVAILABLE — it never degrades to an unqualified best effort, never
// weakens sandboxing or Core readiness.
func AdmitProviderIdentity(id ProviderIdentity) error {
	if id.RendererID == "" || id.RendererVersion == "" {
		return errors.New("renderer identity and version are required from qualification evidence")
	}
	if !hex64.MatchString(id.FontPackDigest) {
		return fmt.Errorf("font pack digest %q is not a 64-hex digest", id.FontPackDigest)
	}
	if id.LocaleProfile == "" || id.OutputProfileVersion != RenditionProfileVersion {
		return errors.New("locale profile required and output profile must be " + RenditionProfileVersion)
	}
	if id.SupportedOSArch == "" || id.ArtifactFormat == "" {
		return errors.New("qualified OS/arch and artifact format are required")
	}
	if !hex64.MatchString(id.ArtifactSHA256) {
		return fmt.Errorf("artifact sha256 %q is not a 64-hex digest", id.ArtifactSHA256)
	}
	if id.LicenseSPDX == "" {
		return errors.New("redistributable license (SPDX) is required")
	}
	if id.ProvenanceRef == "" || id.EvidenceRef == "" {
		return errors.New("provenance and qualification evidence references are required; identities are never invented")
	}
	if id.SandboxPolicy == "" || id.HealthProtocol == "" {
		return errors.New("sandbox policy and health protocol identities are required")
	}
	return nil
}

// RebindDecision is the ONLY way a pinned session survives an identity
// change: explicit requalification/rebind through the owning authority.
// There is no silent-swap path — a version change never mutates an existing
// pin in place.
type RebindDecision int

const (
	RebindUnchanged RebindDecision = iota // candidate == pin: session continues pinned
	RebindRequired                        // candidate differs: session stays pinned until explicit rebind
)

// EvaluateRebind compares a session's pinned identity against a candidate
// identity (e.g. after a provider/manifest version change). Any component
// difference returns RebindRequired; the pinned session is never silently
// moved onto the candidate. Update semantics ride the same contract: update
// blocks new admissions and drains accepted jobs while live sessions retain
// their pinned manifests/assets.
func EvaluateRebind(pinned, candidate ProviderIdentity) RebindDecision {
	if pinned == candidate {
		return RebindUnchanged
	}
	return RebindRequired
}

// SubscriptionKind enumerates the continuity subscriptions M1(b) owns:
// presentation/continuity subscriptions bound to a meeting, presentation
// and authorization generation.
type SubscriptionKind string

const (
	SubscriptionContinuity   SubscriptionKind = "continuity"
	SubscriptionPresentation SubscriptionKind = "presentation"
)

// Subscription is one live subscription the owning authority tracks.
type Subscription struct {
	ID                      string
	Kind                    SubscriptionKind
	MeetingID               string
	PresentationID          string
	AuthorizationGeneration int64
}

// AuthorityState is the current truth the OWNING authority (reducer
// projections) exposes when a subscription is evaluated for cleanup.
type AuthorityState struct {
	MeetingActive     bool
	CurrentGeneration int64
	MeetingEnded      bool
	GrantRevoked      bool
	// PresentationEnded reports that the presentation a subscription
	// follows has ENDED while its meeting remains active — the M1(b)
	// presentation-scoped stale case a meeting-only view cannot express.
	PresentationEnded bool
	// CurrentPresentationID is the meeting's live presentation identity
	// per the owning authority. A subscription following a DIFFERENT
	// presentation is stale (its presentation was replaced/superseded).
	// Empty means the authority tracks no live presentation.
	CurrentPresentationID string
}

// StaleReason names why a subscription is stale.
type StaleReason string

const (
	StaleMeetingEnded      StaleReason = "meeting_ended"
	StalePresentationEnded StaleReason = "presentation_ended"
	StaleGeneration        StaleReason = "stale_generation"
	StaleGrantRevoked      StaleReason = "grant_revoked"
)

// ClassifyStale applies M1(b): a subscription that outlives its meeting,
// presentation or authorization generation is stale. A stale subscription
// is reaped by its owning authority, never resurrects state. Presentation
// scope follows the subscription's own PresentationID: an ended or replaced
// presentation makes a presentation-following subscription stale even while
// its meeting stays active.
func ClassifyStale(sub Subscription, authority AuthorityState) (StaleReason, bool) {
	switch {
	case authority.MeetingEnded || !authority.MeetingActive:
		return StaleMeetingEnded, true
	case sub.PresentationID != "" &&
		(authority.PresentationEnded ||
			(authority.CurrentPresentationID != "" && authority.CurrentPresentationID != sub.PresentationID)):
		return StalePresentationEnded, true
	case sub.AuthorizationGeneration < authority.CurrentGeneration:
		return StaleGeneration, true
	case authority.GrantRevoked:
		return StaleGrantRevoked, true
	default:
		return "", false
	}
}

// ReapScope is the complete set of effects a stale-subscription cleanup can
// express. The type is the boundary: there is no member, constant, or
// constructor that could delete an admitted recording or rendition
// reference, and none that could cancel accepted rendition work — cleanup
// reaps the subscription itself, "without stranding accepted work".
type ReapScope string

// ReapScopeSubscriptionOnly is the ONLY reaping scope. Admitted recordings,
// rendition references, and accepted work items are protected by the owning
// authorities (Drive removal/staging boundary, MR-04/MR-05) — a stale
// subscription cannot authorize their deletion.
const ReapScopeSubscriptionOnly ReapScope = "subscription_only"

// Reap returns the cleanup effect for a stale subscription. The return of a
// fixed scope (not a boolean/permission) makes "cleaned up, never
// resurrects state, cannot authorize deletion of an admitted recording or
// rendition reference" a compile-time property M2+ workers inherit.
func Reap(sub Subscription, authority AuthorityState) (ReapScope, StaleReason, error) {
	reason, stale := ClassifyStale(sub, authority)
	if !stale {
		return "", "", fmt.Errorf("subscription %s is not stale; refusing to reap live authorization", sub.ID)
	}
	return ReapScopeSubscriptionOnly, reason, nil
}
