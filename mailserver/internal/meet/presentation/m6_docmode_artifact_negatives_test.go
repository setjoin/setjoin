package presentation

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// M6 slice 4 — the word/sheet cells' missing ARTIFACT-LEVEL negatives
// (plan L865 `m6-word-pagination-neg` "corrupt/oversized text layer", L866
// `m6-sheet-printpages-neg` "malformed formula cache"). The docmode gate's
// existing negatives (docmode_test.go) are all manifest-GRAMMAR-level: they
// prove unknown/mismatched mode/format/class/rule stamps fail closed. This
// file proves the gate at the ARTIFACT level: a rendition whose converted
// artifact is corrupt (truncated page table, garbage text-layer identity) or
// oversized (beyond the profile's frozen bounds) is refused at admission —
// with the mode's named warning/fallback tokens still pinned — and never
// becomes admissible by silently losing its document mode.
//
// Scope decision (contract-level, honestly): no conversion RUNS in this
// package — the recipes are committed contract data (docmode.go), and the
// gate docmode.go names for a converted artifact is "the SAME meet-pages-v1
// manifest grammar (rendition.go's Manifest.Validate), never a parallel
// manifest". So the artifact-level admission exercised here IS that grammar,
// over document-mode manifests whose artifact content shapes are the named
// corruptions:
//   - word text layer  → the rendition's searchable-text reference and its
//     page table (the artifact where extracted document text and producer
//     pagination land).
//   - sheet formula cache → an input-internal structure this package never
//     parses; at the artifact admission it can only present as a structurally
//     broken static-print artifact, so the refused shapes are the broken
//     print-page forms such an input produces. The mode's escape hatch is
//     asserted as the explicit post-refusal state (rendition_unavailable with
//     the real fallback), never a silent substitute.
//
// Every asserted marker is the artifact admission's own wording
// (rendition.go), so each test fails for exactly its named reason. All shapes
// are pure data over the frozen envelope constants: deterministic, flag-OFF,
// no migrations, no bytes rendered.

// m6daCapableManifest is a document-mode manifest with its profile-table
// warning stamped (the m6WithCapability fixture), carrying the named tokens
// every artifact test refuses WITH.
func m6daCapableManifest(t *testing.T, mode DocumentMode, format string) Manifest {
	t.Helper()
	m := m6WithCapability(t, mode, format)
	if m.DocumentMode == nil {
		t.Fatal("fixture lost the capability section")
	}
	return m
}

// m6daAssertModePinned proves the manifest under refusal kept its named
// tokens: the mode is intact (the gate never silently de-modes) and the
// mandated warning token is still attached (never stripped to silence the
// fidelity claim).
func m6daAssertModePinned(t *testing.T, m Manifest, mode DocumentMode, warning RenditionWarning, fallback FallbackRule) {
	t.Helper()
	if m.DocumentMode == nil {
		t.Fatal("the gate silently de-moded the manifest")
	}
	if m.DocumentMode.Mode != mode {
		t.Fatalf("mode drifted to %q", m.DocumentMode.Mode)
	}
	if m.DocumentMode.Fallback != fallback {
		t.Fatalf("fallback token drifted to %q, want %q", m.DocumentMode.Fallback, fallback)
	}
	if !containsWarning(m.Warnings, warning) {
		t.Fatalf("mandated warning token %q was stripped from the refused manifest", warning)
	}
}

// m6daTextLayer attaches a well-formed searchable-text layer (the word
// artifact's extracted document text) to a manifest.
func m6daTextLayer(m *Manifest) {
	m.SearchableText = &SearchableTextReference{AssetRef{
		Path:      "/api/meet/renditions/p-1/searchable-text",
		MIMEType:  "text/plain",
		ByteSize:  4096,
		SHA256:    strings.Repeat("33", 32),
		ExpiresAt: time.Now().Add(10 * time.Minute),
		TTL:       10 * time.Minute,
	}}
}

// m6daSecondPage appends one more valid page (a two-page artifact gives the
// truncation arm a page table to corrupt).
func m6daSecondPage(m *Manifest) {
	p := m.Pages[0]
	p.Index = 1
	p.ID = "p1"
	m.Pages = append(m.Pages, p)
}

// m6daRefuseWithCapability runs the artifact-level admission on the capable
// manifest, requiring the named artifact reason; the launch twin (capability
// silently dropped) must fail with the SAME reason — de-moding launders
// nothing. name labels the corruption in every failure message.
func m6daRefuseWithCapability(t *testing.T, m Manifest, name, marker string) string {
	t.Helper()
	err := m.Validate()
	if err == nil {
		t.Fatalf("%s: artifact admitted, want the %q refusal", name, marker)
	}
	if !strings.Contains(err.Error(), marker) {
		t.Fatalf("%s: refusal is not the named artifact reason %q: %v", name, marker, err)
	}
	twin := m
	twin.DocumentMode = nil
	twinErr := twin.Validate()
	if twinErr == nil || !strings.Contains(twinErr.Error(), marker) {
		t.Fatalf("%s: the de-moded twin admitted the artifact or shifted the reason: got %v, want the same %q refusal", name, marker, twinErr)
	}
	return err.Error()
}

// ── Word/text: the corrupt text layer (plan L865) ─────────────────────────

func TestM6DocmodeArtifactWordCorruptTextLayerRefused(t *testing.T) {
	// A word_text_paginated rendition whose extracted text layer is CORRUPT —
	// garbage where the pinned content identity should be, an empty layer,
	// and a page table truncated mid-document (the pagination the mode pins
	// its fidelity to) — is refused at the artifact admission, each for its
	// named reason, while the mode keeps its named tokens.
	cases := map[string]struct {
		corrupt func(*Manifest)
		marker  string
	}{
		"text-layer identity is garbage, not a digest": {
			corrupt: func(m *Manifest) {
				m6daTextLayer(m)
				m.SearchableText.SHA256 = strings.Repeat("zz", 32)
			},
			marker: "is not hex",
		},
		"text layer empty where structured text is expected": {
			corrupt: func(m *Manifest) {
				m6daTextLayer(m)
				m.SearchableText.ByteSize = 0
			},
			marker: "asset byte size 0 outside",
		},
		"page table truncated mid-document": {
			corrupt: func(m *Manifest) {
				m6daSecondPage(m)
				m.Pages[1].Index = 9 // the dense page order lies
			},
			marker: "page 1 carries dense index 9",
		},
	}
	for name, tc := range cases {
		m := m6daCapableManifest(t, DocumentModeWordText, "docx")
		tc.corrupt(&m)
		m6daAssertModePinned(t, m, DocumentModeWordText, WarnProducerPagination, FallbackOfficeEditorOrScreenShare)
		m6daRefuseWithCapability(t, m, name, tc.marker)
	}

	// The exact wording, asserted once by name: the corrupt identity is
	// refused AS a searchable-text identity failure (never reinterpreted as a
	// mode failure).
	m := m6daCapableManifest(t, DocumentModeWordText, "docx")
	m6daTextLayer(&m)
	m.SearchableText.SHA256 = strings.Repeat("zz", 32)
	err := m.Validate()
	if err == nil || !strings.Contains(err.Error(), "searchable text reference") ||
		!strings.Contains(err.Error(), "is not hex") {
		t.Fatalf("corrupt text-layer identity: got %v, want a searchable-text digest refusal", err)
	}

	// Post-refusal posture: the mode's escape hatch is the named fallback —
	// a word rendition that cannot be admitted falls back explicitly, never
	// into a silent substitute.
	unavailable, err := UnavailableAdmission("docx")
	if err != nil || unavailable.Fidelity != FidelityUnavailable ||
		unavailable.Fallback != FallbackOfficeEditorOrScreenShare {
		t.Fatalf("post-refusal state %+v (%v), want rendition_unavailable with the word fallback", unavailable, err)
	}
}

// ── Word/text: the oversized text layer (plan L865) ───────────────────────

func TestM6DocmodeArtifactWordOversizedTextLayerRefused(t *testing.T) {
	// The profile's frozen bounds are admission bounds, not suggestions: a
	// text layer or page asset past the encoded-page ceiling, and an
	// aggregate output over the rendition ceiling, are refused by the named
	// numbers — with the capability attached, and equally without it.
	pageBound := fmt.Sprintf("asset byte size %d outside (0,%d]", MaxEncodedPageBytes+1, MaxEncodedPageBytes)
	m := m6daCapableManifest(t, DocumentModeWordText, "odt")
	m6daTextLayer(&m)
	m.SearchableText.ByteSize = MaxEncodedPageBytes + 1
	m6daAssertModePinned(t, m, DocumentModeWordText, WarnProducerPagination, FallbackOfficeEditorOrScreenShare)
	m6daRefuseWithCapability(t, m, "oversized text layer", pageBound)

	// One oversized page body is the same refusal at the page bound.
	m = m6daCapableManifest(t, DocumentModeWordText, "odt")
	m.Pages[0].ByteSize = MaxEncodedPageBytes + 1
	m6daRefuseWithCapability(t, m, "oversized page body",
		fmt.Sprintf("page 0 encoded size %d outside (0,%d]", MaxEncodedPageBytes+1, MaxEncodedPageBytes))

	// The AGGREGATE ceiling: 33 maximally-sized page bodies are individually
	// admissible but together breach the 512 MiB rendition ceiling — the
	// declared sizes alone refuse, deterministically, no bytes rendered.
	m = m6daCapableManifest(t, DocumentModeWordText, "docx")
	for i := 0; i <= 32; i++ {
		if i > 0 {
			p := m.Pages[0]
			p.Index = i
			p.ID = fmt.Sprintf("p%d", i)
			m.Pages = append(m.Pages, p)
		}
		m.Pages[i].FullPage.ByteSize = MaxEncodedPageBytes
	}
	over := m6daRefuseWithCapability(t, m, "aggregate over the rendition ceiling", "aggregate output bytes over the")
	if !strings.Contains(over, fmt.Sprint(MaxAggregateOutputBytes)) {
		t.Fatalf("aggregate refusal did not name the ceiling %d: %s", MaxAggregateOutputBytes, over)
	}

	// Post-refusal posture: the named fallback, per docmode's profile table.
	unavailable, err := UnavailableAdmission("odt")
	if err != nil || unavailable.Fallback != FallbackOfficeEditorOrScreenShare {
		t.Fatalf("post-refusal state %+v (%v), want the word fallback", unavailable, err)
	}
}

// ── Spreadsheet: the malformed formula cache (plan L866) ──────────────────

func TestM6DocmodeArtifactSheetMalformedArtifactRefused(t *testing.T) {
	// A spreadsheet_print_static rendition produced from a malformed-input
	// source presents at the admission as a structurally broken static-print
	// artifact: collapsed print pages (zero dimensions, zero encoded bytes),
	// page assets without a live short-lived fetch identity, empty asset
	// refs. Every shape is refused for its named reason; the static-print
	// warning token and the screen-share fallback stay pinned on the refused
	// manifest; de-moding launders nothing.
	//
	// Limitation (binding-review P2 disclosure): these arms prove refusal of
	// malformed print-page MANIFEST shapes at the artifact gate; a converter
	// that ACCEPTS a malformed formula cache and emits a valid-looking
	// artifact is undetectable here — that formula-cache fixture leg remains
	// outstanding (recorded in the M6 matrix reconciliation receipt).
	cases := map[string]struct {
		malformed func(*Manifest)
		marker    string
	}{
		"print page collapsed to zero width": {
			malformed: func(m *Manifest) { m.Pages[0].WidthPx = 0 },
			marker:    fmt.Sprintf("dimensions 0x%d outside (0,%d]x(0,%d]", 720, MaxPageWidthPx, MaxPageHeightPx),
		},
		"print page carries zero encoded bytes": {
			malformed: func(m *Manifest) { m.Pages[0].ByteSize = 0 },
			marker:    "page 0 encoded size 0 outside",
		},
		"print page asset lost its live fetch identity": {
			malformed: func(m *Manifest) { m.Pages[0].FullPage.ExpiresAt = time.Time{} },
			marker:    "must carry a live short-lived expiry",
		},
		"thumbnail reference is an empty asset": {
			malformed: func(m *Manifest) { m.Pages[0].Thumbnail.ByteSize = 0 },
			marker:    "page 0 asset: asset byte size 0 outside",
		},
	}
	for name, tc := range cases {
		m := m6daCapableManifest(t, DocumentModeSpreadsheetPrint, "xlsx")
		tc.malformed(&m)
		m6daAssertModePinned(t, m, DocumentModeSpreadsheetPrint, WarnStaticPrintLayout, FallbackScreenShareOrOfficeEditor)
		m6daRefuseWithCapability(t, m, name, tc.marker)
	}

	// Post-refusal posture: an xlsx source that cannot yield an admissible
	// static-print artifact surfaces the explicit unavailable fidelity with
	// the sheet's real escape hatch — the interactive grid is reachable only
	// through the NAMED fallback, never as a silent re-mode.
	unavailable, err := UnavailableAdmission("xlsx")
	if err != nil || unavailable.Fidelity != FidelityUnavailable ||
		unavailable.Fallback != FallbackScreenShareOrOfficeEditor {
		t.Fatalf("post-refusal state %+v (%v), want rendition_unavailable with the sheet fallback", unavailable, err)
	}
}
