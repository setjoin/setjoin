package presentation

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// M6 slice 1 exit discipline (plan M6: "every supported document mode and
// cross-feature combination has a named positive, negative, and recovery
// test"). The supported combinations this slice ships are exactly the five
// (mode, format) pairs of the mode gate table: docx/odt/txt under
// word_text_paginated, xlsx/ods under spreadsheet_print_static.

// m6WithCapability stamps a document-mode capability (built through the only
// constructor) and its class's mandated warning onto a well-formed manifest.
func m6WithCapability(t *testing.T, mode DocumentMode, format string) Manifest {
	t.Helper()
	cap, err := NewDocumentModeCapability(mode, format)
	if err != nil {
		t.Fatalf("NewDocumentModeCapability(%q, %q): %v", mode, format, err)
	}
	m := validManifest()
	m.DocumentMode = cap
	switch cap.Fidelity {
	case FidelityProducerPagination:
		m.Warnings = append(m.Warnings, WarnProducerPagination)
	case FidelityStaticPrintLayout:
		m.Warnings = append(m.Warnings, WarnStaticPrintLayout)
	default:
		t.Fatalf("unexpected fidelity class %q", cap.Fidelity)
	}
	return m
}

// --- Positive: every supported combination renders under the SAME manifest ---

func TestM6WordTextCombosValidateUnderSameManifest(t *testing.T) {
	for _, format := range []string{"docx", "odt", "txt"} {
		m := m6WithCapability(t, DocumentModeWordText, format)
		if err := m.Validate(); err != nil {
			t.Errorf("word_text_paginated %s manifest rejected: %v", format, err)
		}
		if m.Schema != RenditionProfileVersion {
			t.Errorf("word %s manifest drifted off the meet-pages-v1 profile: %q", format, m.Schema)
		}
		if m.DocumentMode.Fidelity != FidelityProducerPagination {
			t.Errorf("word %s fidelity class %q, want producer_pagination", format, m.DocumentMode.Fidelity)
		}
		if m.DocumentMode.Fallback != FallbackOfficeEditorOrScreenShare {
			t.Errorf("word %s fallback %q, want office_editor_or_screen_share", format, m.DocumentMode.Fallback)
		}
	}
}

func TestM6SpreadsheetCombosValidateUnderSameManifest(t *testing.T) {
	for _, format := range []string{"xlsx", "ods"} {
		m := m6WithCapability(t, DocumentModeSpreadsheetPrint, format)
		if err := m.Validate(); err != nil {
			t.Errorf("spreadsheet_print_static %s manifest rejected: %v", format, err)
		}
		if m.DocumentMode.Fidelity != FidelityStaticPrintLayout {
			t.Errorf("sheet %s fidelity class %q, want static_print_layout", format, m.DocumentMode.Fidelity)
		}
		if m.DocumentMode.Fallback != FallbackScreenShareOrOfficeEditor {
			t.Errorf("sheet %s fallback %q, want screen_share_or_office_editor", format, m.DocumentMode.Fallback)
		}
	}
}

func TestM6WordTextPagesByProducerPagination(t *testing.T) {
	// The mode's semantic: page breaks are the PRODUCER'S OWN print
	// pagination (frozen default theme for txt) — the recipe exports through
	// the writer filter whose pagination the producer owns, and the mandated
	// warning names that fidelity class before presenting.
	for _, format := range []string{"docx", "odt", "txt"} {
		recipe, err := ConversionRecipeFor(DocumentModeWordText, format)
		if err != nil {
			t.Fatalf("%s recipe: %v", format, err)
		}
		if recipe.PrintLayout != "producer_print_pagination" {
			t.Errorf("%s print layout %q, want producer_print_pagination", format, recipe.PrintLayout)
		}
		if !strings.Contains(strings.Join(recipe.EngineArgs, " "), "pdf:writer_pdf_Export") {
			t.Errorf("%s recipe does not export through the writer print filter: %v", format, recipe.EngineArgs)
		}
	}
	m := m6WithCapability(t, DocumentModeWordText, "docx")
	if !containsWarning(m.Warnings, WarnProducerPagination) {
		t.Fatal("word manifest lacks the mandated producer_pagination warning")
	}
}

func TestM6SpreadsheetNeverPromisesAnInteractiveGrid(t *testing.T) {
	// The mode's semantic: the STATIC PRINT LAYOUT (print area/scale as the
	// producer resolves them) — the recipe exports through the calc filter
	// WITHOUT any single-page-sheet/interactive override, and the mandated
	// warning names static-print-only before presenting.
	for _, format := range []string{"xlsx", "ods"} {
		recipe, err := ConversionRecipeFor(DocumentModeSpreadsheetPrint, format)
		if err != nil {
			t.Fatalf("%s recipe: %v", format, err)
		}
		if recipe.PrintLayout != "producer_print_area_scale" {
			t.Errorf("%s print layout %q, want producer_print_area_scale", format, recipe.PrintLayout)
		}
		joined := strings.Join(recipe.EngineArgs, " ")
		if !strings.Contains(joined, "pdf:calc_pdf_Export") {
			t.Errorf("%s recipe does not export through the calc print filter: %v", format, recipe.EngineArgs)
		}
		if strings.Contains(joined, "SinglePageSheets") {
			t.Errorf("%s recipe overrides the print layout with a single-page-sheet mode: %v", format, recipe.EngineArgs)
		}
	}
	m := m6WithCapability(t, DocumentModeSpreadsheetPrint, "xlsx")
	if !containsWarning(m.Warnings, WarnStaticPrintLayout) {
		t.Fatal("spreadsheet manifest lacks the mandated static_print_layout warning")
	}
}

func TestM6CapabilityRoundTripsTheWireContract(t *testing.T) {
	m := m6WithCapability(t, DocumentModeSpreadsheetPrint, "ods")
	data, err := json.Marshal(&m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Manifest
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := back.Validate(); err != nil {
		t.Fatalf("round-tripped manifest rejected: %v", err)
	}
	if back.DocumentMode == nil || back.DocumentMode.Mode != DocumentModeSpreadsheetPrint || back.DocumentMode.SourceFormat != "ods" {
		t.Fatalf("capability did not survive the round trip: %+v", back.DocumentMode)
	}
}

// --- Negative: malformed/unsupported mode refused, fail closed ---

func TestM6UnknownDocumentModeFailsClosed(t *testing.T) {
	m := m6WithCapability(t, DocumentModeSpreadsheetPrint, "xlsx")
	m.DocumentMode.Mode = "interactive_grid"
	if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "unknown document mode") {
		t.Fatalf("unknown mode: got %v, want an unknown-document-mode failure", err)
	}
	if _, err := NewDocumentModeCapability("interactive_grid", "xlsx"); err == nil {
		t.Fatal("constructor admitted an unknown mode")
	}
}

func TestM6FormatModeMismatchFailsClosed(t *testing.T) {
	cases := map[string]struct {
		mode   DocumentMode
		format string
	}{
		"xlsx under the word mode":        {DocumentModeWordText, "xlsx"},
		"ods under the word mode":         {DocumentModeWordText, "ods"},
		"docx under the spreadsheet mode": {DocumentModeSpreadsheetPrint, "docx"},
		"txt under the spreadsheet mode":  {DocumentModeSpreadsheetPrint, "txt"},
	}
	for name, tc := range cases {
		_, err := NewDocumentModeCapability(tc.mode, tc.format)
		if err == nil || !strings.Contains(err.Error(), "not admitted") {
			t.Errorf("%s: got %v, want a not-admitted failure", name, err)
		}
		// A hand-stamped mismatch on an otherwise valid manifest also fails.
		m := m6WithCapability(t, DocumentModeWordText, "docx")
		m.DocumentMode.SourceFormat = "xlsx"
		if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "not admitted") {
			t.Errorf("%s (hand-stamped): got %v, want a not-admitted failure", name, err)
		}
	}
}

func TestM6NonCanonicalSourceFormatRefused(t *testing.T) {
	// The constructor normalizes case/dot prefixes, but a capability cannot
	// VALIDATE with a non-canonical stored format: the manifest grammar pins
	// the canonical lowercase spelling.
	for _, bad := range []string{"DOCX", ".docx", " docx", ""} {
		_, err := NewDocumentModeCapability(DocumentModeWordText, bad)
		if bad != "" && err != nil {
			t.Errorf("constructor should normalize %q, got %v", bad, err)
		}
	}
	m := m6WithCapability(t, DocumentModeWordText, "docx")
	m.DocumentMode.SourceFormat = "DOCX"
	if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "canonical admitted format") {
		t.Fatalf("non-canonical format: got %v, want a canonical-format failure", err)
	}
	m = m6WithCapability(t, DocumentModeWordText, "docx")
	m.DocumentMode.SourceFormat = ""
	if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "canonical admitted format") {
		t.Fatalf("empty format: got %v, want a canonical-format failure", err)
	}
}

func TestM6UnadvertisedFormatsRefusedEverywhere(t *testing.T) {
	// Unadvertised format support is a named plan anti-goal: this slice
	// supports exactly the six admitted formats and refuses the rest —
	// including the launch formats (pdf/pptx/odp), which simply carry NO
	// capability section, and every unadvertised extension.
	for _, format := range []string{"doc", "rtf", "md", "csv", "et", "html", "pdf", "pptx", "odp", "dps", "xyz", ".docx.exe"} {
		if mode, ok := DocumentModeForFormat(format); ok {
			t.Errorf("format %q classified as %q; want refused", format, mode)
		}
		if _, err := NewDocumentModeCapability(DocumentModeWordText, format); err == nil && format != "pdf" && format != "pptx" && format != "odp" {
			t.Errorf("constructor admitted unadvertised format %q", format)
		}
		if _, err := UnavailableAdmission(format); err == nil {
			t.Errorf("unavailable admission named a state for unadvertised format %q", format)
		}
	}
	// Launch formats stay launch vocabulary: no capability, manifest valid.
	m := validManifest()
	if err := m.Validate(); err != nil {
		t.Fatalf("launch-vocabulary manifest (nil capability) rejected: %v", err)
	}
	if m.DocumentMode != nil {
		t.Fatal("launch manifest grew a capability section")
	}
}

func TestM6FidelityFallbackPairsArePinnedPerMode(t *testing.T) {
	// Mix-and-match refused: each mode admits exactly its pinned
	// (fidelity, fallback) pair — including FidelityUnavailable, which can
	// NEVER be stamped onto a manifest because the unavailable state has no
	// rendition to stamp.
	cases := map[string]func(*Manifest){
		"unknown fidelity class": func(m *Manifest) { m.DocumentMode.Fidelity = FidelityClass("livewire") },
		"unavailable fidelity stamped onto a manifest": func(m *Manifest) {
			m.DocumentMode.Fidelity = FidelityUnavailable
			m.Warnings = append(m.Warnings, WarnStaticPrintLayout)
		},
		"unknown fallback rule": func(m *Manifest) { m.DocumentMode.Fallback = FallbackRule("wishful_thinking") },
		"wrong mode family fidelity": func(m *Manifest) {
			m.DocumentMode.Fidelity = FidelityStaticPrintLayout
			m.Warnings = append(m.Warnings, WarnStaticPrintLayout)
		},
		"wrong mode family fallback": func(m *Manifest) { m.DocumentMode.Fallback = FallbackScreenShareOrOfficeEditor },
	}
	for name, mutate := range cases {
		m := m6WithCapability(t, DocumentModeWordText, "docx")
		mutate(&m)
		if err := m.Validate(); err == nil {
			t.Errorf("%s: manifest accepted a capability outside the pinned pair", name)
		}
	}
}

func TestM6CapabilityWithoutMandatedWarningRefused(t *testing.T) {
	// A capability whose fidelity warning was stripped is a silent fidelity
	// promise — the exact thing the plan forbids.
	m := m6WithCapability(t, DocumentModeWordText, "txt")
	m.Warnings = nil
	err := m.Validate()
	if err == nil || !strings.Contains(err.Error(), "mandates warning") {
		t.Fatalf("stripped warning: got %v, want a mandates-warning failure", err)
	}
}

func TestM6CapabilityZeroPagesStillRefused(t *testing.T) {
	// The new modes ride the SAME grammar: a zero-page artifact is refused
	// even with a capability attached.
	m := m6WithCapability(t, DocumentModeSpreadsheetPrint, "xlsx")
	m.Pages = nil
	if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "zero-page") {
		t.Fatalf("zero-page document-mode manifest: got %v, want a zero-page failure", err)
	}
}

// --- Recovery: producer-absent fallback and requalification ---

func TestM6ProducerAbsentYieldsExplicitUnavailableFidelity(t *testing.T) {
	// The pinned producer is absent/unqualified: admission fails closed
	// wrapping the sentinel, and the surfaced state is the explicit
	// rendition_unavailable fidelity with the mode's REAL fallback — never a
	// silent substitute, and never a capability (there is no manifest).
	for _, format := range []string{"docx", "odt", "txt", "xlsx", "ods"} {
		_, err := UnavailableAdmission(format)
		if err != nil {
			t.Fatalf("%s unavailable admission: %v", format, err)
		}
	}
	if _, err := UnavailableAdmission(""); err == nil {
		t.Fatal("empty format has no unavailable state")
	}
	absent := DocModeProducer{}
	if err := AdmitDocModeProducer(absent, absent); !errors.Is(err, ErrDocModeProducerUnavailable) {
		t.Fatalf("absent producer admission: got %v, want ErrDocModeProducerUnavailable", err)
	}
	state, err := UnavailableAdmission("xlsx")
	if err != nil {
		t.Fatalf("xlsx unavailable admission: %v", err)
	}
	if state.Fidelity != FidelityUnavailable {
		t.Errorf("unavailable fidelity class %q, want rendition_unavailable", state.Fidelity)
	}
	if state.Fallback != FallbackScreenShareOrOfficeEditor {
		t.Errorf("unavailable fallback %q, want the mode's real escape hatch", state.Fallback)
	}
}

func TestM6ProducerIdentityChangeRequiresRequalification(t *testing.T) {
	qualified := DocModeProducer{
		EngineID:      DocModeProducerEngineID,
		EngineVersion: "25.2",
		EvidenceRef:   "retired-docs:verification/meet-m1-qualification.md#run",
	}
	if err := qualified.Validate(); err != nil {
		t.Fatalf("qualified producer rejected: %v", err)
	}
	if err := AdmitDocModeProducer(qualified, qualified); err != nil {
		t.Fatalf("byte-identical pinned producer refused: %v", err)
	}
	upgraded := qualified
	upgraded.EngineVersion = "26.0"
	err := AdmitDocModeProducer(qualified, upgraded)
	if err == nil || !strings.Contains(err.Error(), "re-qualified") {
		t.Fatalf("engine version change: got %v, want a requalification refusal", err)
	}
	foreign := DocModeProducer{EngineID: "some-other-suite", EngineVersion: "1", EvidenceRef: "x"}
	if err := AdmitDocModeProducer(qualified, foreign); !errors.Is(err, ErrDocModeProducerUnavailable) {
		t.Fatalf("foreign engine: got %v, want ErrDocModeProducerUnavailable", err)
	}
	noEvidence := DocModeProducer{EngineID: DocModeProducerEngineID, EngineVersion: "25.2"}
	if err := AdmitDocModeProducer(qualified, noEvidence); !errors.Is(err, ErrDocModeProducerUnavailable) {
		t.Fatalf("evidence-less producer: got %v, want ErrDocModeProducerUnavailable", err)
	}
	if RequalificationRequiredDocMode(qualified, qualified) {
		t.Fatal("identical profiles flagged for requalification")
	}
	// Evidence-validate arms on the pinned engine id: a version-less and an
	// evidence-less profile each fail their own named rule.
	noVersion := DocModeProducer{EngineID: DocModeProducerEngineID, EvidenceRef: "x"}
	if err := noVersion.Validate(); err == nil || !strings.Contains(err.Error(), "never invented") {
		t.Fatalf("version-less producer: got %v, want a never-invented refusal", err)
	}
	if err := noEvidence.Validate(); err == nil || !strings.Contains(err.Error(), "fails closed") {
		t.Fatalf("evidence-less validate: got %v, want a fails-closed refusal", err)
	}
	wrongEngine := DocModeProducer{EngineID: "other", EngineVersion: "1", EvidenceRef: "x"}
	if err := wrongEngine.Validate(); err == nil || !strings.Contains(err.Error(), "pinned one-suite engine") {
		t.Fatalf("foreign-engine validate: got %v, want a pinned-engine refusal", err)
	}
}

func TestM6QualifiedProducerAdmitsConversionRecipes(t *testing.T) {
	qualified := DocModeProducer{
		EngineID:      DocModeProducerEngineID,
		EngineVersion: "25.2",
		EvidenceRef:   "retired-docs:verification/meet-m1-qualification.md#run",
	}
	if err := AdmitDocModeProducer(DocModeProducer{}, qualified); err != nil {
		t.Fatalf("first qualification against an absent pin refused: %v", err)
	}
	// Every supported combination admits a recipe bound to the pinned engine.
	for _, format := range []string{"docx", "odt", "txt", "xlsx", "ods"} {
		mode, ok := DocumentModeForFormat(format)
		if !ok {
			t.Fatalf("supported format %q has no mode", format)
		}
		recipe, err := ConversionRecipeFor(mode, format)
		if err != nil {
			t.Fatalf("%s recipe: %v", format, err)
		}
		if recipe.EngineID != DocModeProducerEngineID {
			t.Errorf("%s recipe engine %q, want the pinned one-suite engine", format, recipe.EngineID)
		}
		if recipe.Mode != mode || recipe.SourceFormat != format {
			t.Errorf("%s recipe identity drifted: %+v", format, recipe)
		}
	}
}

func TestM6ConversionRecipesAreDeterministicAndCommitted(t *testing.T) {
	// The recipes are contract data: the same (mode, format) yields a
	// deep-equal recipe every call, with the literal operand placeholders the
	// committed script mirrors verbatim.
	for _, format := range []string{"docx", "odt", "txt", "xlsx", "ods"} {
		mode, _ := DocumentModeForFormat(format)
		a, err := ConversionRecipeFor(mode, format)
		if err != nil {
			t.Fatalf("%s recipe: %v", format, err)
		}
		b, err := ConversionRecipeFor(mode, "."+strings.ToUpper(format))
		if err != nil {
			t.Fatalf("%s normalized recipe: %v", format, err)
		}
		if !reflect.DeepEqual(a, b) {
			t.Errorf("%s recipe is input-spelling dependent: %+v vs %+v", format, a, b)
		}
		joined := strings.Join(a.EngineArgs, " ")
		for _, want := range []string{"--headless", "--norestore", "--outdir <outdir> <source>"} {
			if !strings.Contains(joined, want) {
				t.Errorf("%s recipe missing %q: %v", format, want, a.EngineArgs)
			}
		}
	}
	txt, _ := ConversionRecipeFor(DocumentModeWordText, "txt")
	if !strings.Contains(strings.Join(txt.EngineArgs, " "), "--infilter=Text (encoded):UTF8") {
		t.Errorf("txt recipe lost the UTF-8 import pin: %v", txt.EngineArgs)
	}
	if _, err := ConversionRecipeFor("interactive_grid", "xlsx"); err == nil {
		t.Fatal("recipe admitted an unknown mode")
	}
	if _, err := ConversionRecipeFor(DocumentModeSpreadsheetPrint, "csv"); err == nil {
		t.Fatal("recipe admitted an unadvertised format")
	}
}

func TestM6ReplayLinkAttachesFidelityOnlyForThePinnedManifest(t *testing.T) {
	m := m6WithCapability(t, DocumentModeWordText, "odt")
	m.IntegrityDigest = strings.Repeat("77", 32)
	link := PresentationVersionLink{
		PresentationID: "p-1",
		DriveNodeID:    5,
		DriveVersionID: 42,
		ManifestDigest: m.IntegrityDigest,
		State:          ChildRetained,
	}
	got := link.AttachDocumentModeCapability(&m)
	if got.DocumentMode != DocumentModeWordText ||
		got.FidelityClass != FidelityProducerPagination ||
		got.Fallback != FallbackOfficeEditorOrScreenShare {
		t.Fatalf("pinned manifest fidelity not attached: %+v", got)
	}

	// A digest mismatch attaches nothing — one rendition's fidelity claims
	// are never cross-attached to another binding.
	other := m
	other.IntegrityDigest = strings.Repeat("88", 32)
	if got := link.AttachDocumentModeCapability(&other); got.DocumentMode != "" || got.FidelityClass != "" || got.Fallback != "" {
		t.Fatalf("mismatched manifest leaked fidelity claims: %+v", got)
	}
	// A launch-vocabulary manifest attaches nothing new.
	launch := validManifest()
	launch.IntegrityDigest = m.IntegrityDigest
	launch.CompletedAt = time.Now()
	if got := link.AttachDocumentModeCapability(&launch); got.DocumentMode != "" {
		t.Fatalf("launch manifest produced a fidelity claim: %+v", got)
	}
	if got := link.AttachDocumentModeCapability(nil); got != link {
		t.Fatal("nil manifest mutated the link")
	}
}

func containsWarning(warnings []RenditionWarning, want RenditionWarning) bool {
	for _, w := range warnings {
		if w == want {
			return true
		}
	}
	return false
}
