package presentation

import (
	"errors"
	"fmt"
	"strings"
)

// M6 slice 1 — Word/text pagination + spreadsheet static print pages under
// the SAME meet-pages-v1 manifest (MEET plan M6: "Add Word/text pagination
// and spreadsheet static print pages under the same manifest; retain
// explicit fidelity warnings and fallback").
//
// The plan's "Supported document modes" table assigns the post-launch rows:
// DOC/DOCX/ODT/RTF paginate as a "Paginated print rendition", TXT/Markdown
// is a "Frozen-theme paginated snapshot", and XLS/XLSX/ODS/CSV/ET render as
// "Static print-area/pages only". This file freezes the CONTRACT for the two
// mode families this slice supports, each as an explicit typed pair of a
// fidelity warning class and a fallback rule:
//
//   - word_text_paginated — the document pages by the PRODUCER'S OWN
//     pagination (the print-layout pagination the pinned producer resolves;
//     a .txt pages under the producer's frozen default theme). The shared
//     page canvas never re-paginates, reflows, or re-fits a word/text
//     source: whatever the producer printed is every attendee's truth.
//   - spreadsheet_print_static — the spreadsheet renders the STATIC PRINT
//     LAYOUT (print area and scale exactly as the producer resolves them) —
//     never an interactive-grid promise. No live cells, no filters, no
//     sorting, no scrolling: a spreadsheet that never configured a print
//     layout gets the producer's resolved default, not a grid.
//
// Honesty rules, enforced fail-closed:
//
//   - The vocabulary is VERSIONED through the manifest's own
//     RenditionProfileVersion and CLOSED: an unknown mode, an unknown
//     fidelity class, an unknown fallback rule, or a format/mode mismatch
//     fails manifest validation — a consumer must be able to render every
//     capability it reads.
//   - Every capability MANDATES its fidelity warning token in the same
//     manifest's Warnings: a capability without its warning is a silent
//     fidelity promise, which the plan forbids.
//   - The gate is the SAME meet-pages-v1 manifest grammar (rendition.go's
//     Manifest.Validate), never a parallel manifest or a side table: nil
//     capability = the launch vocabulary (PDF native pages, PPT/PPTX/ODP
//     office-to-PDF pages) — absence implies nothing new.
//   - Producer-absent is an EXPLICIT fidelity state
//     (FidelityUnavailable + the mode's fallback rule), never a silent
//     substitute: with the pinned producer unqualified the rendition does
//     not exist and nothing pretends to stand in for it.
//
// All types are inert data and pure functions. No conversion RUNS here: the
// recipes are the committed, deterministic command contracts the pinned
// producer executes (scripts/meet-m6-convert-doc-modes.sh mirrors them
// verbatim), and everything stays behind the existing OFF flags.

// DocumentMode is the closed M6 vocabulary of document presentation modes
// that render under the same meet-pages-v1 manifest. Unknown modes fail
// closed (DocumentModeCapability.validate).
type DocumentMode string

const (
	// DocumentModeWordText — DOCX/ODT word-processor documents and TXT text
	// sources: pages by the producer's own pagination (print layout as the
	// producer resolves it; TXT under the producer's frozen default theme).
	DocumentModeWordText DocumentMode = "word_text_paginated"
	// DocumentModeSpreadsheetPrint — XLSX/ODS spreadsheets: the static print
	// layout (print area/scale as the producer resolves them), never an
	// interactive-grid promise.
	DocumentModeSpreadsheetPrint DocumentMode = "spreadsheet_print_static"
)

// FidelityClass is the explicit fidelity-warning class a document mode
// carries. Classes are paired to modes by the profile table below — a
// capability naming the wrong class for its mode fails closed.
type FidelityClass string

const (
	// FidelityProducerPagination — word/text: page breaks are the producer's
	// own print pagination. Mandates the WarnProducerPagination warning.
	FidelityProducerPagination FidelityClass = "producer_pagination"
	// FidelityStaticPrintLayout — spreadsheet: a static print snapshot only.
	// Mandates the WarnStaticPrintLayout warning.
	FidelityStaticPrintLayout FidelityClass = "static_print_layout"
	// FidelityUnavailable — the producer-absent state: the pinned producer is
	// not qualified, so NO rendition exists. This class NEVER appears on a
	// manifest (no manifest is produced); it is the typed state admission
	// surfaces so an unavailability is named, never silently substituted.
	FidelityUnavailable FidelityClass = "rendition_unavailable"
)

// FallbackRule is the closed vocabulary of fidelity escape hatches (the
// plan's "Fidelity escape hatch" column). Every admission — qualified or
// unavailable — carries its mode's fallback so users always have the named
// way out.
type FallbackRule string

const (
	// FallbackOfficeEditorOrScreenShare — word/text escape hatch ("Open in
	// Office editor or screen share"). For a plain .txt the editor leg
	// degenerates to screen share; the rule names the ordered hatch for the
	// mode family, and screen share is always available.
	FallbackOfficeEditorOrScreenShare FallbackRule = "office_editor_or_screen_share"
	// FallbackScreenShareOrOfficeEditor — spreadsheet escape hatch ("Screen
	// share or Office editor for live cells, filters, and scrolling").
	FallbackScreenShareOrOfficeEditor FallbackRule = "screen_share_or_office_editor"
)

// documentModeProfile is the pinned mode gate table: one row per supported
// mode, joining the admitted source formats, the fidelity class, the warning
// tokens the class mandates in the manifest, the fallback rule, the
// print-layout identity the conversion recipe pins, and the EXPLICIT export
// filter the recipe converts through. This table IS the mode gate —
// capability validation and recipe construction both read it, so a new mode
// is admitted by adding ONE audited row, never a parallel path.
type documentModeProfile struct {
	formats  []string
	fidelity FidelityClass
	warnings []RenditionWarning
	fallback FallbackRule
	// printLayout names the print-layout identity the conversion pins.
	printLayout string
	// exportFilter is the explicit --convert-to filter the recipe pins:
	// the word filter paginates by the producer's own print layout; the
	// calc filter prints the document's print ranges/scale and never
	// overrides them with a single-page-sheet mode.
	exportFilter string
}

var documentModeProfiles = map[DocumentMode]documentModeProfile{
	DocumentModeWordText: {
		formats:  []string{"docx", "odt", "txt"},
		fidelity: FidelityProducerPagination,
		warnings: []RenditionWarning{WarnProducerPagination},
		fallback: FallbackOfficeEditorOrScreenShare,
		// The producer's own print pagination; TXT imports under the
		// producer's frozen default theme (UTF-8 input pinned by the recipe).
		printLayout:  "producer_print_pagination",
		exportFilter: "pdf:writer_pdf_Export",
	},
	DocumentModeSpreadsheetPrint: {
		formats:  []string{"xlsx", "ods"},
		fidelity: FidelityStaticPrintLayout,
		warnings: []RenditionWarning{WarnStaticPrintLayout},
		fallback: FallbackScreenShareOrOfficeEditor,
		// Print area/scale exactly as the producer resolves them from the
		// document's own print settings — static pages, never the grid.
		printLayout:  "producer_print_area_scale",
		exportFilter: "pdf:calc_pdf_Export",
	},
}

// inputFilterForFormat pins the deterministic INPUT filter for formats whose
// import must be pinned for a frozen result (TXT imports under the
// producer's frozen default theme with UTF-8 fixed); every other admitted
// format imports by its type's engine default.
func inputFilterForFormat(format string) string {
	if format == "txt" {
		return "--infilter=Text (encoded):UTF8"
	}
	return ""
}

// DocumentModeForFormat reports the M6 document mode a source format renders
// under. ok is false for EVERY format outside this slice's vocabulary —
// including the launch formats (pdf/pptx/odp), whose renditions carry no
// capability section, and unadvertised extensions (doc/rtf/md/csv/et/...),
// which this slice deliberately does not support (unadvertised format
// support is a named plan anti-goal).
func DocumentModeForFormat(format string) (DocumentMode, bool) {
	format = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(format), "."))
	if format == "" {
		return "", false
	}
	for mode, prof := range documentModeProfiles {
		for _, f := range prof.formats {
			if f == format {
				return mode, true
			}
		}
	}
	return "", false
}

// DocumentModeCapability is the M6 capability section a meet-pages-v1
// manifest carries for a word/text or spreadsheet static-print rendition. It
// rides INSIDE the existing manifest grammar — the same schema, key tuple,
// page bounds and warning vocabulary — never a second manifest.
type DocumentModeCapability struct {
	Mode DocumentMode `json:"mode"`
	// SourceFormat is the canonical admitted source format (e.g. "docx").
	// It is checked against the mode's admitted set: an xlsx manifest can
	// never claim the word mode, and an empty format never validates.
	SourceFormat string `json:"sourceFormat"`
	// Fidelity is the explicit warning class; it must equal the mode's
	// pinned class.
	Fidelity FidelityClass `json:"fidelityClass"`
	// Fallback is the fidelity escape hatch; it must equal the mode's
	// pinned rule.
	Fallback FallbackRule `json:"fallback"`
}

// NewDocumentModeCapability builds the capability from the mode gate table —
// the ONLY constructor, so a producer cannot invent a fidelity class or
// fallback that disagrees with the audited profile. Fails closed for
// formats outside the M6 vocabulary.
func NewDocumentModeCapability(mode DocumentMode, sourceFormat string) (*DocumentModeCapability, error) {
	prof, ok := documentModeProfiles[mode]
	if !ok {
		return nil, fmt.Errorf("unknown document mode %q fails closed", mode)
	}
	format := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(sourceFormat), "."))
	for _, f := range prof.formats {
		if f == format {
			return &DocumentModeCapability{
				Mode:         mode,
				SourceFormat: format,
				Fidelity:     prof.fidelity,
				Fallback:     prof.fallback,
			}, nil
		}
	}
	return nil, fmt.Errorf("format %q is not admitted for document mode %q", sourceFormat, mode)
}

// validate checks the capability against the mode gate table AND the
// manifest's own warnings: unknown mode/format/class/rule pairs fail closed,
// and the class's mandated warning tokens must be present in the SAME
// manifest's Warnings (a capability without its warning is a silent
// promise).
func (c *DocumentModeCapability) validate(warnings []RenditionWarning) error {
	prof, ok := documentModeProfiles[c.Mode]
	if !ok {
		return fmt.Errorf("unknown document mode %q fails closed", c.Mode)
	}
	format := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(c.SourceFormat), "."))
	if format == "" || c.SourceFormat != format {
		return fmt.Errorf("document mode %q source format %q is not a canonical admitted format", c.Mode, c.SourceFormat)
	}
	admitted := false
	for _, f := range prof.formats {
		if f == format {
			admitted = true
			break
		}
	}
	if !admitted {
		return fmt.Errorf("format %q is not admitted for document mode %q", c.SourceFormat, c.Mode)
	}
	if c.Fidelity != prof.fidelity {
		return fmt.Errorf("document mode %q requires fidelity class %q, got %q", c.Mode, prof.fidelity, c.Fidelity)
	}
	if c.Fallback != prof.fallback {
		return fmt.Errorf("document mode %q requires fallback rule %q, got %q", c.Mode, prof.fallback, c.Fallback)
	}
	for _, want := range prof.warnings {
		found := false
		for _, w := range warnings {
			if w == want {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("document mode %q mandates warning %q in the same manifest; a capability without its warning is a silent fidelity promise", c.Mode, want)
		}
	}
	return nil
}

// DocModeProducerEngineID is the D3 one-suite producer identity for
// server-side Office-format → PDF conversion (docs/verification/
// 2026-09-19-owner-consolidated-decisions.md §D3; the corpus manifest's
// producerPinning.engine.id). One office engine covers office-invocation
// needs; a future engine swap is a version-pin requalification through the
// owning authority, never a silent provider swap.
const DocModeProducerEngineID = "libreoffice-headless-soffice"

// DocModeProducer is the version-pinned conversion producer identity. Every
// field comes from evidence — EngineVersion is captured verbatim from
// `soffice --version` at qualification time, never invented (the M0 corpus
// pinning posture).
type DocModeProducer struct {
	EngineID string `json:"engineId"`
	// EngineVersion is the verbatim engine version string from evidence.
	EngineVersion string `json:"engineVersion,omitempty"`
	// EvidenceRef points at the qualification record that produced the
	// identity. A producer without evidence is unqualified, full stop.
	EvidenceRef string `json:"evidenceRef,omitempty"`
}

// ErrDocModeProducerUnavailable is the sentinel every producer-absent
// refusal wraps. Its honest reading: the rendition state is
// rendition_unavailable for that source — named, surfaced, and never
// replaced by a silent substitute (a raw text dump, a skipped document, a
// different engine's best effort).
var ErrDocModeProducerUnavailable = errors.New("document-mode conversion producer is unavailable: the pinned LibreOffice headless engine is not qualified on this host; the fidelity state is rendition_unavailable — never a silent substitute")

// Validate fails closed unless the producer IS the pinned D3 engine with an
// evidence-backed version. A zero-value profile (engine absent) is the
// honest unqualified shape.
func (p DocModeProducer) Validate() error {
	if p.EngineID != DocModeProducerEngineID {
		return fmt.Errorf("conversion engine %q is not the pinned one-suite engine %q", p.EngineID, DocModeProducerEngineID)
	}
	if p.EngineVersion == "" {
		return errors.New("conversion producer version is required verbatim from evidence; versions are never invented")
	}
	if p.EvidenceRef == "" {
		return errors.New("conversion producer without qualification evidence fails closed")
	}
	return nil
}

// RequalificationRequiredDocMode reports a producer identity change (engine
// or version). Any change re-qualifies the pinned profile before new
// conversion — the version-pinned lifecycle, never an in-place swap.
func RequalificationRequiredDocMode(pinned, candidate DocModeProducer) bool {
	return pinned.EngineID != candidate.EngineID ||
		pinned.EngineVersion != candidate.EngineVersion
}

// AdmitDocModeProducer is the conversion-side admission gate: the candidate
// must be the qualified pinned engine, byte-identical to any already-pinned
// profile. Unqualified or changed identities fail closed wrapping
// ErrDocModeProducerUnavailable (or the requalification error) — never a
// best-effort conversion on a different engine.
func AdmitDocModeProducer(pinned, candidate DocModeProducer) error {
	if err := candidate.Validate(); err != nil {
		return fmt.Errorf("%w: %s", ErrDocModeProducerUnavailable, err)
	}
	if pinned.EngineID == DocModeProducerEngineID && RequalificationRequiredDocMode(pinned, candidate) {
		return fmt.Errorf("conversion producer changed (engine/version); the pinned producer must be re-qualified before new conversion")
	}
	return nil
}

// DocModeUnavailable is the EXPLICIT producer-absent fidelity state for one
// document-mode source: the mode and its escape hatch are known, the
// rendition does not exist, and nothing stands in for it. Capability is
// deliberately absent — there is no manifest to stamp.
type DocModeUnavailable struct {
	Mode         DocumentMode  `json:"mode"`
	SourceFormat string        `json:"sourceFormat"`
	Fidelity     FidelityClass `json:"fidelityClass"` // always FidelityUnavailable
	Fallback     FallbackRule  `json:"fallback"`
}

// UnavailableAdmission returns the named unavailable state for a source
// format. Formats outside the M6 vocabulary have no state here — they fail
// closed like always.
func UnavailableAdmission(format string) (DocModeUnavailable, error) {
	mode, ok := DocumentModeForFormat(format)
	if !ok {
		return DocModeUnavailable{}, fmt.Errorf("source format %q is outside every admitted document-mode vocabulary", format)
	}
	return DocModeUnavailable{
		Mode:         mode,
		SourceFormat: strings.ToLower(strings.TrimPrefix(strings.TrimSpace(format), ".")),
		Fidelity:     FidelityUnavailable,
		Fallback:     documentModeProfiles[mode].fallback,
	}, nil
}

// ProducerConversionRecipe is the committed, deterministic command recipe
// the pinned producer executes to turn one document-mode source into the
// paged PDF input, using the mode's print-layout settings. The recipe is a
// CONTRACT (data), not an execution: no conversion runs in this package,
// nothing is rendered, and every behavior stays behind the existing OFF
// flags. scripts/meet-m6-convert-doc-modes.sh mirrors these argv verbatim;
// the two must agree, and the tests pin the agreement.
type ProducerConversionRecipe struct {
	Mode         DocumentMode `json:"mode"`
	SourceFormat string       `json:"sourceFormat"`
	// EngineID is always DocModeProducerEngineID — the D3 one-suite engine.
	EngineID string `json:"engineId"`
	// EngineArgs is the deterministic argv AFTER the engine binary, with
	// "<outdir>" and "<source>" as the literal operand placeholders.
	EngineArgs []string `json:"engineArgs"`
	// PrintLayout names the print-layout identity the conversion pins (the
	// profile table's printLayout — the producer's own pagination for
	// word/text, the producer-resolved print area/scale for spreadsheets).
	PrintLayout string `json:"printLayout"`
}

// ConversionRecipeFor returns the committed recipe for one admitted
// (mode, format) combination. The argv is deterministic and identical for
// every combination of a mode (format only selects the source operand and,
// for txt, the UTF-8 input filter pin): isolated user profile, no restore,
// the mode's EXPLICIT export filter from the mode gate table (writer_pdf_
// Export paginates by the producer's own print layout; calc_pdf_Export
// resolves the document's print areas/scale), and no network. Unknown
// combinations fail closed.
func ConversionRecipeFor(mode DocumentMode, sourceFormat string) (*ProducerConversionRecipe, error) {
	prof, ok := documentModeProfiles[mode]
	if !ok {
		return nil, fmt.Errorf("unknown document mode %q fails closed", mode)
	}
	format := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(sourceFormat), "."))
	admitted := false
	for _, f := range prof.formats {
		if f == format {
			admitted = true
			break
		}
	}
	if !admitted {
		return nil, fmt.Errorf("format %q is not admitted for document mode %q", sourceFormat, mode)
	}
	// Shared flags: headless, no crash-restore, ISOLATED user profile
	// (deterministic: no shared mutable profile state between runs).
	args := []string{"--headless", "--norestore", "-env:UserInstallation=file://<profile>"}
	if infilter := inputFilterForFormat(format); infilter != "" {
		args = append(args, infilter)
	}
	args = append(args, "--convert-to", prof.exportFilter, "--outdir", "<outdir>", "<source>")
	return &ProducerConversionRecipe{
		Mode:         mode,
		SourceFormat: format,
		EngineID:     DocModeProducerEngineID,
		EngineArgs:   args,
		PrintLayout:  prof.printLayout,
	}, nil
}
