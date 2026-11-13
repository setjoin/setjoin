package presentation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// M4 — the `.sjrec` logical manifest + integrity index ("Semantic
// recording format"). `.sjrec` is a logical Drive recording package, NOT a
// user-editable directory and NOT necessarily one physical archive object.
// This file freezes the versioned manifest grammar, the per-child stable
// references (annotation snapshots and caption references bind by stable
// reference, the captions.go genre), and the integrity index that pins
// every child's bytes.
//
// Reuse, not restatement: the delete/hold/restore semantics are the
// `.sjrec` lifecycle state machine already frozen in lifecycle.go
// (PackageState, CanTransitionPackage, ReleaseReceipt, FinalizeAllowed).
// This manifest CARRIES that state; it does not redefine it.

// SJRecFormatVersion freezes the manifest schema. Consumers reject other
// versions fail-closed.
const SJRecFormatVersion = "sjrec-v1"

// Manifest bounds (frozen here so producers, the reducer-side twins and
// replay all agree; larger metadata paginates like the rendition manifest).
const (
	MaxSJRecPresentations = 16    // one per source version switched to during the recording
	MaxSJRecCaptions      = 8     // caption languages bound by reference
	MaxSJRecAnnotations   = 1000  // durable annotation snapshots
	MaxSJRecChildren      = 64    // child entries tracked for deletion/hold
	MaxSJRecSegments      = 10000 // media segment bindings referenced
)

// StableRef is a stable, package-relative reference to retained bytes: a
// relative path plus the content identity that pins it. It is deliberately
// NOT an AssetRef (rendition.go): retained recording children are NOT
// short-lived authorized fetches — they live under the recording's own
// retention policy — but they are ALSO never long-lived object-store URLs:
// serving always goes through an authorized fetch minted at read time.
type StableRef struct {
	Path     string `json:"path"` // package-relative, no scheme/host
	SHA256   string `json:"sha256"`
	ByteSize int64  `json:"byteSize"`
}

func (r StableRef) validate(what string) error {
	if r.Path == "" {
		return fmt.Errorf("%s reference missing its package-relative path", what)
	}
	if strings.HasPrefix(r.Path, "/") || strings.HasPrefix(r.Path, "../") ||
		strings.Contains(r.Path, "://") {
		return fmt.Errorf("%s reference %q must be package-relative", what, r.Path)
	}
	if err := validSHA256(r.SHA256); err != nil {
		return fmt.Errorf("%s reference digest: %w", what, err)
	}
	if r.ByteSize <= 0 {
		return fmt.Errorf("%s reference carries no byte size", what)
	}
	return nil
}

// SJRecPresentationBinding binds one presented Drive version into the
// recording: the immutable source identity, the rendition profile the pages
// came from, and the manifest digest the checkpoint pinned. Copy-on-write:
// the recording retains an authorized snapshot of the rendition under its
// OWN retention policy — moving/deleting/revoking the source later never
// silently breaks the retained recording, and a source switch re-authorizes
// the CURRENT version before its switch event commits.
type SJRecPresentationBinding struct {
	PresentationID   string     `json:"presentationId"`
	DriveNodeID      int64      `json:"driveNodeId"`
	DriveVersionID   int64      `json:"driveVersionId"`
	SourceSHA256     string     `json:"sourceSha256"`
	RenditionProfile string     `json:"renditionProfile"` // meet-pages-v1
	ManifestDigest   string     `json:"manifestDigest"`
	State            ChildState `json:"state"` // embedded/retained/absent/expired
	RetainedSnapshot *StableRef `json:"retainedSnapshot,omitempty"`
}

// SJRecCaptionBinding binds one caption language by stable reference (the
// captions.go genre: identity + language — never inline transcript bytes).
type SJRecCaptionBinding struct {
	Language string     `json:"language"` // BCP-47
	State    ChildState `json:"state"`
	Ref      *StableRef `json:"ref,omitempty"`
}

// SJRecAnnotationBinding binds one durable annotation snapshot: the exact
// presentation checkpoint (id + checkpoint seq + presenter generation) the
// snapshot rendered, by stable reference. Qualified retained annotations
// carry a distinct recording-owned identity — they never imply edits to the
// original Drive document.
type SJRecAnnotationBinding struct {
	PresentationID      string     `json:"presentationId"`
	CheckpointSeq       int64      `json:"checkpointSeq"`
	PresenterGeneration int64      `json:"presenterGeneration"`
	State               ChildState `json:"state"`
	Ref                 *StableRef `json:"ref,omitempty"`
}

// SJRecLegacyVideoReference records — never copies — an already-retained,
// independently authorized B2 MP4 identity. It is a companion INDEX, not an
// M4 audio package: no second recorder started, no re-encode, no combined
// multi-track export promised.
type LegacyVideoRef struct {
	B2RecordingID  int64      `json:"b2RecordingId"`
	DriveNodeID    int64      `json:"driveNodeId"`
	DriveVersionID int64      `json:"driveVersionId"`
	ContentSHA256  string     `json:"contentSha256"`
	State          ChildState `json:"state"` // retained | absent | expired
}

// SJRecChildEntry is one tracked package child for the delete/hold sweep.
// Child is the lifecycle.go SJRecChild vocabulary; the expected set these
// rows form is what the reducer records at DELETE_PENDING time and what
// finalization requires to be exhausted.
type SJRecChildEntry struct {
	Child SJRecChild `json:"child"`
	State ChildState `json:"state"`
	// Required children fence restore: HELD_COMPLETE requires zero released
	// REQUIRED references; an optional child's release never downgrades a
	// hold to HELD_PARTIAL.
	Required bool       `json:"required"`
	Ref      *StableRef `json:"ref,omitempty"`
}

// TimelineRef pins the ordered event timeline: the record count and the
// integrity digest replay verifies before trusting anything else.
type TimelineRef struct {
	Records  int    `json:"records"`
	SHA256   string `json:"sha256"`
	ByteSize int64  `json:"byteSize"`
}

// CaptureMode names how the recording's media was acquired (the recording
// policy matrix's semantic column). V1 admits exactly one server mode,
// and it stays evidence-gated (acquisition.go).
type CaptureMode string

const (
	CaptureServerAudio     CaptureMode = "server_audio"       // M4 qualified server audio (evidence-gated)
	CaptureLocalRegistered CaptureMode = "local_registered"   // local_only: truthful local registration only
	CaptureCompanionIndex  CaptureMode = "b2_companion_index" // retained B2 MP4 referenced, not captured
)

// RecordingManifest is the versioned `.sjrec` logical manifest.
type RecordingManifest struct {
	Schema          string       `json:"schema"` // always SJRecFormatVersion
	RecordingID     int64        `json:"recordingId"`
	MeetingID       int64        `json:"meetingId"`
	PackageState    PackageState `json:"packageState"` // the lifecycle.go machine's CURRENT state
	CaptureMode     CaptureMode  `json:"captureMode"`
	PolicyMode      PolicyMode   `json:"policyMode"` // the typed recording-policy snapshot at start
	StartedAtUnixMs int64        `json:"startedAtUnixMs"`
	EndedAtUnixMs   int64        `json:"endedAtUnixMs,omitempty"`
	CompletedAt     time.Time    `json:"completedAt,omitempty"`

	// ProducerIdentity is the version-pinned capture profile the recording
	// ran under (acquisition.go). A producer/Egress/codec version change
	// re-qualifies the pinned profile BEFORE new capture — an existing
	// recording keeps the identity it was actually produced with.
	ProducerIdentity *CaptureProfile `json:"producerIdentity,omitempty"`

	Timeline      *TimelineRef               `json:"timeline,omitempty"`
	Presentations []SJRecPresentationBinding `json:"presentations,omitempty"`
	Captions      []SJRecCaptionBinding      `json:"captions,omitempty"`
	Annotations   []SJRecAnnotationBinding   `json:"annotations,omitempty"`
	Segments      []MediaSegment             `json:"segments,omitempty"`
	LegacyVideo   *LegacyVideoRef            `json:"legacyVideo,omitempty"`
	Children      []SJRecChildEntry          `json:"children,omitempty"`

	// IntegrityDigest is the sha256 over the canonical manifest payload
	// (Digest()); the integrity index pins each child's bytes under it.
	IntegrityDigest string `json:"integrityDigest,omitempty"`
}

// Validate enforces the manifest invariants: version, identity, bounds,
// per-binding cross-checks (a binding claimed embedded/retained MUST carry
// its stable reference; an absent/expired one MUST NOT), the media
// contract's coverage rules, and the lifecycle-truth rules (a DELETED
// package advertises no live children).
func (m *RecordingManifest) Validate() error {
	if m.Schema != SJRecFormatVersion {
		return fmt.Errorf("sjrec schema %q is not %s", m.Schema, SJRecFormatVersion)
	}
	if m.RecordingID <= 0 || m.MeetingID <= 0 {
		return errors.New("sjrec manifest missing recording/meeting identity")
	}
	switch m.PackageState {
	case PackageActive, PackageDeletePending, PackageHeldComplete, PackageHeldPartial, PackageDeleted:
		// the lifecycle.go vocabulary — no second state machine here.
	default:
		return fmt.Errorf("unknown .sjrec package state %q fails closed", m.PackageState)
	}
	switch m.CaptureMode {
	case CaptureServerAudio, CaptureLocalRegistered, CaptureCompanionIndex:
	default:
		return fmt.Errorf("unknown capture mode %q fails closed", m.CaptureMode)
	}
	switch m.PolicyMode {
	case PolicyLocalPreferred, PolicyServerOnly, PolicyLocalOnly, PolicyDisabled:
	default:
		return fmt.Errorf("unknown policy mode %q fails closed", m.PolicyMode)
	}
	if m.CaptureMode == CaptureServerAudio && m.PolicyMode == PolicyLocalOnly {
		// local_only denies M4 server audio and central page/caption
		// retention — a manifest claiming both is a policy violation.
		return errors.New("local_only policy cannot carry a server_audio capture")
	}
	if m.CaptureMode == CaptureServerAudio {
		if m.ProducerIdentity == nil {
			return errors.New("server_audio capture must pin its producer identity")
		}
		if err := m.ProducerIdentity.Validate(); err != nil {
			return fmt.Errorf("producer identity: %w", err)
		}
	}
	if m.StartedAtUnixMs <= 0 {
		return errors.New("sjrec manifest missing start time")
	}
	if m.EndedAtUnixMs != 0 && m.EndedAtUnixMs < m.StartedAtUnixMs {
		return errors.New("sjrec manifest ends before it starts")
	}

	if len(m.Presentations) > MaxSJRecPresentations {
		return fmt.Errorf("sjrec binds %d presentations over the %d cap", len(m.Presentations), MaxSJRecPresentations)
	}
	seenPres := map[string]struct{}{}
	for i := range m.Presentations {
		p := &m.Presentations[i]
		if p.PresentationID == "" {
			return errors.New("presentation binding missing id")
		}
		if _, dup := seenPres[p.PresentationID]; dup {
			return fmt.Errorf("duplicate presentation binding %q", p.PresentationID)
		}
		seenPres[p.PresentationID] = struct{}{}
		if p.DriveNodeID <= 0 || p.DriveVersionID <= 0 {
			return fmt.Errorf("presentation %q binding missing source identity", p.PresentationID)
		}
		if err := validSHA256(p.SourceSHA256); err != nil {
			return fmt.Errorf("presentation %q source hash: %w", p.PresentationID, err)
		}
		if p.RenditionProfile != RenditionProfileVersion {
			return fmt.Errorf("presentation %q rendition profile %q is not %s", p.PresentationID, p.RenditionProfile, RenditionProfileVersion)
		}
		if err := validSHA256(p.ManifestDigest); err != nil {
			return fmt.Errorf("presentation %q manifest digest: %w", p.PresentationID, err)
		}
		if err := validateChildState(p.State, p.RetainedSnapshot, "presentation snapshot"); err != nil {
			return fmt.Errorf("presentation %q: %w", p.PresentationID, err)
		}
	}

	if len(m.Captions) > MaxSJRecCaptions {
		return fmt.Errorf("sjrec binds %d caption languages over the %d cap", len(m.Captions), MaxSJRecCaptions)
	}
	seenLang := map[string]struct{}{}
	for i := range m.Captions {
		c := &m.Captions[i]
		if c.Language == "" {
			return errors.New("caption binding missing language")
		}
		if _, dup := seenLang[c.Language]; dup {
			return fmt.Errorf("duplicate caption binding for %q", c.Language)
		}
		seenLang[c.Language] = struct{}{}
		if err := validateChildState(c.State, c.Ref, "caption"); err != nil {
			return fmt.Errorf("caption %q: %w", c.Language, err)
		}
	}

	if len(m.Annotations) > MaxSJRecAnnotations {
		return fmt.Errorf("sjrec binds %d annotations over the %d cap", len(m.Annotations), MaxSJRecAnnotations)
	}
	for i := range m.Annotations {
		a := &m.Annotations[i]
		if a.PresentationID == "" {
			return errors.New("annotation binding missing presentation id")
		}
		if a.CheckpointSeq < 1 || a.PresenterGeneration < 1 {
			return fmt.Errorf("annotation binding on %q missing checkpoint/generation binding", a.PresentationID)
		}
		if _, ok := seenPres[a.PresentationID]; !ok {
			return fmt.Errorf("annotation binding names unbound presentation %q", a.PresentationID)
		}
		if err := validateChildState(a.State, a.Ref, "annotation snapshot"); err != nil {
			return fmt.Errorf("annotation on %q: %w", a.PresentationID, err)
		}
	}

	if len(m.Segments) > MaxSJRecSegments {
		return fmt.Errorf("sjrec binds %d segments over the %d cap", len(m.Segments), MaxSJRecSegments)
	}
	for i := range m.Segments {
		if m.Segments[i].RecordingID != m.RecordingID || m.Segments[i].MeetingID != m.MeetingID {
			return fmt.Errorf("segment %d binds a foreign recording/meeting", m.Segments[i].Seq)
		}
		if err := m.Segments[i].Validate(); err != nil {
			return fmt.Errorf("segment %d: %w", m.Segments[i].Seq, err)
		}
	}
	// Truthful coverage: verified segments must not overlap (duplicate media
	// fails closed at the manifest boundary too, not only in ComputeCoverage).
	window := MediaInterval{StartMs: 0, EndMs: 1<<62 - 1}
	if _, err := ComputeCoverage(m.Segments, window); err != nil {
		return err
	}

	if m.LegacyVideo != nil {
		if m.LegacyVideo.B2RecordingID <= 0 || m.LegacyVideo.DriveNodeID <= 0 || m.LegacyVideo.DriveVersionID <= 0 {
			return errors.New("legacy video reference missing its retained identity")
		}
		if err := validSHA256(m.LegacyVideo.ContentSHA256); err != nil {
			return fmt.Errorf("legacy video digest: %w", err)
		}
		switch m.LegacyVideo.State {
		case ChildRetained, ChildAbsent, ChildExpired:
		default:
			return fmt.Errorf("legacy video state %q is not a reference state", m.LegacyVideo.State)
		}
	}

	if len(m.Children) > MaxSJRecChildren {
		return fmt.Errorf("sjrec tracks %d children over the %d cap", len(m.Children), MaxSJRecChildren)
	}
	seenChild := map[SJRecChild]struct{}{}
	for i := range m.Children {
		c := &m.Children[i]
		if _, dup := seenChild[c.Child]; dup {
			return fmt.Errorf("duplicate child entry %q", c.Child)
		}
		seenChild[c.Child] = struct{}{}
		if err := validateChildState(c.State, c.Ref, "child"); err != nil {
			return fmt.Errorf("child %q: %w", c.Child, err)
		}
	}

	// Lifecycle truth at the package boundary: a DELETED package has had
	// every child released — it must not advertise live (embedded/retained)
	// children. HELD_PARTIAL must show at least one released required child
	// (that is what makes it partial, not complete).
	live := 0
	releasedRequired := 0
	required := 0
	for _, c := range m.Children {
		if c.State == ChildEmbedded || c.State == ChildRetained {
			live++
		}
		if c.Required {
			required++
			if c.State == ChildAbsent || c.State == ChildExpired {
				releasedRequired++
			}
		}
	}
	switch m.PackageState {
	case PackageDeleted:
		if live > 0 {
			return errors.New("DELETED package still advertises live children")
		}
	case PackageHeldPartial:
		if releasedRequired == 0 {
			return errors.New("HELD_PARTIAL package shows no released required child — it would be HELD_COMPLETE")
		}
	case PackageHeldComplete:
		if releasedRequired > 0 {
			return errors.New("HELD_COMPLETE package shows a released required child — it is HELD_PARTIAL under the V1 rule")
		}
	}

	if m.Timeline != nil {
		if err := validSHA256(m.Timeline.SHA256); err != nil {
			return fmt.Errorf("timeline digest: %w", err)
		}
		if m.Timeline.Records < 1 || m.Timeline.Records > MaxTimelineEvents {
			return fmt.Errorf("timeline record count %d outside [1,%d]", m.Timeline.Records, MaxTimelineEvents)
		}
		if m.Timeline.ByteSize <= 0 {
			return errors.New("timeline byte size missing")
		}
	}
	if err := validSHA256(m.IntegrityDigest); err != nil {
		return fmt.Errorf("manifest integrity digest: %w", err)
	}
	serialized, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("sjrec manifest does not serialize: %w", err)
	}
	if len(serialized) > MaxManifestBytes {
		return fmt.Errorf("serialized sjrec manifest is %d bytes over the %d-byte metadata page", len(serialized), MaxManifestBytes)
	}
	return nil
}

// validateChildState is the per-binding cross-check: embedded/retained
// children must pin their stable reference; absent/expired children must
// not pretend to bytes.
func validateChildState(state ChildState, ref *StableRef, what string) error {
	switch state {
	case ChildEmbedded, ChildRetained:
		if ref == nil {
			return fmt.Errorf("%s in state %s carries no stable reference", what, state)
		}
		return ref.validate(what)
	case ChildAbsent, ChildExpired:
		if ref != nil {
			return fmt.Errorf("%s in state %s must not carry a live reference", what, state)
		}
		return nil
	default:
		return fmt.Errorf("unknown child state %q fails closed", state)
	}
}

// Digest computes the canonical manifest integrity digest: sha256 over the
// deterministic JSON of the manifest WITH the digest field cleared, so the
// digest pins everything else. Field order is struct-fixed and child lists
// are sorted by their natural key first, so equal manifests digest equal.
func (m *RecordingManifest) Digest() (string, error) {
	cp := *m
	cp.IntegrityDigest = ""
	sortManifest(&cp)
	b, err := json.Marshal(&cp)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Seal sorts, digests and stamps the manifest in place.
func (m *RecordingManifest) Seal() error {
	d, err := m.Digest()
	if err != nil {
		return err
	}
	sortManifest(m)
	m.IntegrityDigest = d
	return nil
}

func sortManifest(m *RecordingManifest) {
	sort.Slice(m.Presentations, func(i, j int) bool { return m.Presentations[i].PresentationID < m.Presentations[j].PresentationID })
	sort.Slice(m.Captions, func(i, j int) bool { return m.Captions[i].Language < m.Captions[j].Language })
	sort.Slice(m.Annotations, func(i, j int) bool {
		if m.Annotations[i].PresentationID != m.Annotations[j].PresentationID {
			return m.Annotations[i].PresentationID < m.Annotations[j].PresentationID
		}
		return m.Annotations[i].CheckpointSeq < m.Annotations[j].CheckpointSeq
	})
	sort.Slice(m.Segments, func(i, j int) bool { return m.Segments[i].Seq < m.Segments[j].Seq })
	sort.Slice(m.Children, func(i, j int) bool { return m.Children[i].Child < m.Children[j].Child })
}

// IntegrityIndex is the `integrity/sha256.json` member: package-relative
// path → sha256 of that child's exact bytes. Replay and export verify it
// before trusting any object (the integrityMismatch rescue: refuse the
// affected objects/export, never skip).
type IntegrityIndex map[string]string

// BuildIntegrityIndex pins the timeline ndjson and every referenced child
// bytes blob by their stable refs. Keys are package-relative paths.
func BuildIntegrityIndex(timelineNDJSON []byte, m *RecordingManifest) IntegrityIndex {
	idx := IntegrityIndex{}
	if len(timelineNDJSON) > 0 {
		sum := sha256.Sum256(timelineNDJSON)
		idx["timeline.ndjson"] = hex.EncodeToString(sum[:])
	}
	add := func(ref *StableRef) {
		if ref != nil {
			idx[ref.Path] = ref.SHA256
		}
	}
	for i := range m.Presentations {
		add(m.Presentations[i].RetainedSnapshot)
	}
	for i := range m.Captions {
		add(m.Captions[i].Ref)
	}
	for i := range m.Annotations {
		add(m.Annotations[i].Ref)
	}
	for i := range m.Children {
		add(m.Children[i].Ref)
	}
	return idx
}

// Verify checks observed child digests against the index. It returns the
// set of problems (missing objects, mismatches) rather than failing on the
// first: replay must name EVERY unavailable segment/object, not just the
// first one. An empty problem set means the package verified.
func (idx IntegrityIndex) Verify(observed map[string]string) []string {
	paths := make([]string, 0, len(idx))
	for p := range idx {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var problems []string
	for _, p := range paths {
		got, ok := observed[p]
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("object %q missing from observed set", p))
		case got != idx[p]:
			problems = append(problems, fmt.Sprintf("object %q digest mismatch (integrityMismatch): pinned %s, observed %s", p, idx[p], got))
		}
	}
	return problems
}
