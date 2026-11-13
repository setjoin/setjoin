package presentation

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// gapExpiry returns a short-lived expiry well inside the authorized fetch
// window, for building individually-invalid AssetRef variants.
func gapExpiry() time.Time { return time.Now().Add(10 * time.Minute) }

// TestManifestRejectsDuplicatePageID covers the duplicate page-id arm: a
// dense-indexed page carrying an ALREADY-SEEN stable id fails closed.
func TestManifestRejectsDuplicatePageID(t *testing.T) {
	m := validManifest()
	dup := m.Pages[0]
	dup.Index = 1
	dup.ID = m.Pages[0].ID // same stable id as page 0
	m.Pages = append(m.Pages, dup)
	err := m.Validate()
	if err == nil || !strings.Contains(err.Error(), "duplicate page id") {
		t.Fatalf("duplicate page id: got %v, want a duplicate-id error", err)
	}
}

// TestManifestAcceptsPageWithAccessibleRepresentation covers the optional
// accessible-representation arm on a well-formed manifest: the bounded
// visible-page ref joins the auxiliary refs and the manifest still passes.
func TestManifestAcceptsPageWithAccessibleRepresentation(t *testing.T) {
	m := validManifest()
	acc := validAssetRef("/api/meet/renditions/p-1/pages/0/accessible", gapExpiry())
	m.Pages[0].AccessibleRepresentation = &acc
	if err := m.Validate(); err != nil {
		t.Fatalf("manifest with accessible representation rejected: %v", err)
	}
}

// TestManifestRejectsInvalidAuxiliaryAssetRef covers the auxiliary-ref
// validation arm: an invalid thumbnail — and an invalid accessible
// representation — surface as a page asset error from the refs loop.
func TestManifestRejectsInvalidAuxiliaryAssetRef(t *testing.T) {
	thumbBad := validManifest()
	thumbBad.Pages[0].Thumbnail = validAssetRef("/api/meet/renditions/p-1/pages/0/thumbnail", gapExpiry())
	thumbBad.Pages[0].Thumbnail.SHA256 = "short"
	if err := thumbBad.Validate(); err == nil || !strings.Contains(err.Error(), "page 0 asset") {
		t.Fatalf("invalid thumbnail: got %v, want a page asset error", err)
	}

	accessibleBad := validManifest()
	bad := validAssetRef("/api/meet/renditions/p-1/pages/0/accessible", gapExpiry())
	bad.TTL = 0 // declared lifetime outside (0, MaxAssetRefTTL]
	accessibleBad.Pages[0].AccessibleRepresentation = &bad
	if err := accessibleBad.Validate(); err == nil || !strings.Contains(err.Error(), "page 0 asset") {
		t.Fatalf("invalid accessible representation: got %v, want a page asset error", err)
	}
}

// TestManifestCountsTheLargerOfPageBodyAndFullPage covers the aggregate
// accounting arm where the full-page ref is LARGER than the declared page
// body: the manifest passes with the larger size counted exactly once.
func TestManifestCountsTheLargerOfPageBodyAndFullPage(t *testing.T) {
	m := validManifest()
	m.Pages[0].FullPage.ByteSize = 4096 // > the 2048-byte page body
	if err := m.Validate(); err != nil {
		t.Fatalf("manifest whose full-page ref exceeds the page body rejected: %v", err)
	}
}

// TestManifestRejectsInvalidNotesReference covers the notes-validation arm:
// a presenter-gated notes reference carrying a malformed digest fails the
// AssetRef contract with a notes-wrapped error.
func TestManifestRejectsInvalidNotesReference(t *testing.T) {
	m := validManifest()
	notes := validAssetRef("/api/meet/renditions/p-1/notes", gapExpiry())
	notes.SHA256 = strings.Repeat("zz", 32) // 64 chars, not hex
	m.Notes = &NotesReference{AssetRef: notes, RequiresPresenterPermission: true}
	err := m.Validate()
	if err == nil || !strings.Contains(err.Error(), "notes reference") {
		t.Fatalf("invalid notes reference: got %v, want a notes reference error", err)
	}
}

// TestManifestSearchableTextReferenceValidation covers both arms of the
// searchable-text contract: a valid reference joins the aggregate and the
// manifest passes; a malformed one fails with a searchable-text error.
func TestManifestSearchableTextReferenceValidation(t *testing.T) {
	valid := validManifest()
	valid.SearchableText = &SearchableTextReference{
		AssetRef: validAssetRef("/api/meet/renditions/p-1/searchable", gapExpiry()),
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid searchable-text reference rejected: %v", err)
	}

	invalid := validManifest()
	bad := validAssetRef("/api/meet/renditions/p-1/searchable", gapExpiry())
	bad.ByteSize = 0 // outside (0, MaxEncodedPageBytes]
	invalid.SearchableText = &SearchableTextReference{AssetRef: bad}
	err := invalid.Validate()
	if err == nil || !strings.Contains(err.Error(), "searchable text reference") {
		t.Fatalf("invalid searchable-text reference: got %v, want a searchable-text error", err)
	}
}

// TestManifestRejectsNonSerializableManifest covers the serialize-failure
// arm: a manifest whose completion timestamp cannot serialize (year beyond
// the RFC3339 range) fails closed instead of admitting an unencodable page.
func TestManifestRejectsNonSerializableManifest(t *testing.T) {
	if _, err := json.Marshal(time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Skip("time.Time serializes out-of-range years on this toolchain; serialize arm unreachable")
	}
	m := validManifest()
	m.CompletedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	err := m.Validate()
	if err == nil || !strings.Contains(err.Error(), "does not serialize") {
		t.Fatalf("non-serializable manifest: got %v, want a serialize error", err)
	}
}

// TestManifestRejectsAssetRefWithMalformedDigest covers the AssetRef digest
// arm: a full-page reference whose sha256 is not 64 hex chars fails.
func TestManifestRejectsAssetRefWithMalformedDigest(t *testing.T) {
	m := validManifest()
	m.Pages[0].FullPage.SHA256 = "short"
	if err := m.Validate(); err == nil {
		t.Fatal("asset reference with a malformed sha256 accepted")
	}
}

// TestManifestRejectsAssetPathControlCharacters covers the control-character
// arm: newline-bearing fetch paths are rejected before URL parsing.
func TestManifestRejectsAssetPathControlCharacters(t *testing.T) {
	m := validManifest()
	m.Pages[0].FullPage.Path = "/api/meet/renditions/p-1/pages/0/full\nescaped"
	err := m.Validate()
	if err == nil || !strings.Contains(err.Error(), "control characters") {
		t.Fatalf("control-character path: got %v, want a control-character error", err)
	}
}

// TestManifestRejectsAssetPathThatIsNotAParsableReference covers the
// parse-failure arm: a path carrying a control character OUTSIDE the explicit
// \x00\r\n set (here a tab) survives the pre-filter and fails url.Parse.
func TestManifestRejectsAssetPathThatIsNotAParsableReference(t *testing.T) {
	m := validManifest()
	m.Pages[0].FullPage.Path = "/api/meet/renditions/p-1/pages/0/full\tid"
	err := m.Validate()
	if err == nil || !strings.Contains(err.Error(), "relative fetch reference") {
		t.Fatalf("unparsable path: got %v, want a parse error", err)
	}
}

// TestManifestKeyValidateFailsClosedOnIncompleteTuple covers the rendition
// cache-key validation arms the binding test cannot reach: with the manifest
// body well-formed, a key missing its drive version, renderer identity or
// font-pack digest fails key.validate() on its own terms.
func TestManifestKeyValidateFailsClosedOnIncompleteTuple(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Manifest)
		want   string
	}{
		"key version zero": {
			mutate: func(m *Manifest) { m.Key.DriveVersionID = 0 },
			want:   "cache key missing drive version identity",
		},
		"key renderer stripped": {
			mutate: func(m *Manifest) { m.Key.RendererID = "" },
			want:   "cache key missing qualified renderer/provider identity",
		},
		"key font digest malformed": {
			mutate: func(m *Manifest) { m.Key.FontPackDigest = "nope" },
			want:   "cache key font pack digest",
		},
	}
	for name, tc := range cases {
		m := validManifest()
		tc.mutate(&m)
		err := m.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", name, err, tc.want)
		}
	}
}

// TestManifestSourceHashMustBeHex covers the hex-decode arm of the shared
// sha256 validator: a 64-character NON-hex digest is malformed, not merely
// short.
func TestManifestSourceHashMustBeHex(t *testing.T) {
	m := validManifest()
	m.SourceSHA256 = strings.Repeat("zz", 32)
	err := m.Validate()
	if err == nil || !strings.Contains(err.Error(), "is not hex") {
		t.Fatalf("non-hex source hash: got %v, want a not-hex error", err)
	}
}

// TestEnvelopeEncodeRejectsUnserializablePayload covers the Encode marshal
// arm: a well-shaped envelope whose raw payload is not valid JSON fails the
// byte-budget serialization instead of publishing a corrupt frame.
func TestEnvelopeEncodeRejectsUnserializablePayload(t *testing.T) {
	e := NewEnvelope("p-1", 1, 1, KindReady, json.RawMessage("not-json"), "t")
	if _, err := e.Encode(); err == nil {
		t.Fatal("envelope with an unserializable payload accepted")
	}
}

// TestEnvelopeEncodeRejectsForeignTopicAndUnknownVersion covers the shape
// gate's family/version arms on the send path: a frame outside the
// presentation family, and a frame at an unknown version, fail closed.
func TestEnvelopeEncodeRejectsForeignTopicAndUnknownVersion(t *testing.T) {
	foreign := NewEnvelope("p-1", 1, 1, KindReady, nil, "t")
	foreign.Topic = "chat"
	if _, err := foreign.Encode(); err == nil || !strings.Contains(err.Error(), "topic") {
		t.Fatalf("foreign topic: got %v, want a topic error", err)
	}

	unknownVersion := NewEnvelope("p-1", 1, 1, KindReady, nil, "t")
	unknownVersion.Version = 2
	if _, err := unknownVersion.Encode(); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("unknown version: got %v, want a version error", err)
	}
}
