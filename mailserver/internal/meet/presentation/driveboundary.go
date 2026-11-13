package presentation

import "errors"

// M1 Drive-side boundary — REUSE, do not rebuild ("What already exists"):
// Drive owns originals, versions, ACLs, history and retention. Meet
// references Drive identities and never creates a second file store.
// Delivered contracts Meet reuses verbatim:
//
//   - version identity: drive_file_versions + chunk CAS (drive_version_chunks /
//     drive_chunks) — the same identity PreviewWorker already pins;
//   - Office save/version contracts: office_launch_begin / office_launch_revoke /
//     office_choice_query (internal/drive/office.go) — Meet never becomes a
//     WOPI host and never interprets provider callbacks;
//   - capability authority: drive_runtime_has_node_capability(...,'preview')
//     style checks remain Drive's; a Meet page grant adds nothing to the
//     source Drive ACL;
//   - storage: attachments are SHA-256 content-addressed; blobs.ref_count is
//     trigger-maintained and Meet never writes it directly.
//
// This file freezes the typed reference/capability shapes M2+ translators
// pass through; it intentionally contains no SQL and no routes.

// SourceRef is the immutable Drive source identity a presentation pins.
// Presenting pins an immutable version: a source edit creates a NEW Drive
// version while the active presentation stays pinned until the presenter
// explicitly switches (durable source.switched event).
type SourceRef struct {
	DriveNodeID    int64
	DriveVersionID int64
	SourceSHA256   string // lowercase hex sha256 of the pinned version bytes
}

// Validate enforces identity completeness. Zero/negative Drive identities or
// a malformed source hash can never anchor a rendition or a checkpoint.
func (s SourceRef) Validate() error {
	if s.DriveNodeID <= 0 || s.DriveVersionID <= 0 {
		return errors.New("source reference missing Drive node/version identity")
	}
	return validSHA256(s.SourceSHA256)
}

// ErrMeetNeverWopiHost is a compile-time documentation sentinel: no Meet
// route may register WOPI endpoints or interpret provider callbacks. Office
// sessions continue through Drive's launch/revoke contracts.
var ErrMeetNeverWopiHost = errors.New("meet never acts as a WOPI host; office sessions ride Drive's office_launch_begin/revoke contracts")

// PageCapability is a meeting-scoped, view-only page capability issued to
// current admitted participants (including admitted guests) when a
// presentation starts. The struct deliberately has NO field that could grant
// the original bytes, speaker notes, document-wide search text/index access,
// or future versions — the exclusion is a property of the type, not a
// flag callers can flip. Capabilities expire at end/revocation and are
// re-evaluated on late join; starting a presentation never changes the
// source Drive ACL.
type PageCapability struct {
	PresentationID string
	MeetingID      string
	PageID         string // bound to exactly one manifest page
	ManifestDigest string
	// ViewOnly is a constant by construction; presenters mutate through
	// reducer verbs, never through a page capability.
	ViewOnly bool
	// ExpiresAt bounds the fetch; the serving layer mints the short-lived
	// authorized URL from this capability.
	ExpiresAtUnixMilli int64
}

// NewPageCapability is the only constructor: it forces view-only.
func NewPageCapability(presentationID, meetingID, pageID, manifestDigest string, expiresAtUnixMilli int64) PageCapability {
	return PageCapability{
		PresentationID:     presentationID,
		MeetingID:          meetingID,
		PageID:             pageID,
		ManifestDigest:     manifestDigest,
		ViewOnly:           true,
		ExpiresAtUnixMilli: expiresAtUnixMilli,
	}
}

// Validate fails on a capability whose view-only or binding invariants were
// somehow bypassed (e.g. a zero-value struct received over a wire).
func (c PageCapability) Validate() error {
	if !c.ViewOnly {
		return errors.New("page capabilities are view-only by construction; presenter verbs go through the reducer")
	}
	if c.PresentationID == "" || c.MeetingID == "" || c.PageID == "" || c.ManifestDigest == "" {
		return errors.New("page capability missing presentation/meeting/page/manifest binding")
	}
	if c.ExpiresAtUnixMilli <= 0 {
		return errors.New("page capability must expire; capabilities outlive neither end nor revocation")
	}
	return nil
}
