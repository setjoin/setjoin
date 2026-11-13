package presentation

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The frozen M0 corpus manifest lives beside the other verification
// receipts; the corpus bytes live in this package's testdata/corpus.
const (
	m0ManifestPath  = "../../../../docs/verification/meet-m0-corpus.json"
	m0CorpusTestDir = "testdata/corpus"
)

func loadFrozenM0Manifest(t *testing.T) (*M0CorpusManifest, []byte) {
	t.Helper()
	raw, err := os.ReadFile(m0ManifestPath)
	if err != nil {
		t.Fatalf("read frozen m0 corpus manifest: %v", err)
	}
	m, err := ParseM0CorpusManifest(raw)
	if err != nil {
		t.Fatalf("parse frozen m0 corpus manifest: %v", err)
	}
	return m, raw
}

// TestM0CorpusFrozenManifestVerifies is the freeze gate: the committed
// corpus bytes must re-derive every digest, byte size and intrinsic count
// the frozen manifest pins, and the corpus directory must hold nothing the
// manifest does not claim.
func TestM0CorpusFrozenManifestVerifies(t *testing.T) {
	m, _ := loadFrozenM0Manifest(t)
	if m.CorpusID != "meet-m0-corpus" || m.Revision < 1 {
		t.Fatalf("unexpected corpus identity: id=%q revision=%d", m.CorpusID, m.Revision)
	}
	if err := VerifyM0CorpusDir(m0CorpusTestDir, m); err != nil {
		t.Fatalf("frozen corpus does not verify: %v", err)
	}

	// Producer/format coverage: every office+pdf format has at least one
	// synthetic-seed instance, so no format cell depends on pending
	// acquisition to have a benchmarkable fixture.
	formats := map[string]bool{"pdf": false, "pptx": false, "docx": false, "xlsx": false, "odp": false}
	roles := map[string]bool{
		"small-deck": false, "medium-deck": false, "large-500p": false,
		"asset-heavy": false, "annotation-heavy-ref20": false,
		"reference20-shape": false, "caption-dense": false,
		"format-coverage-docx": false, "format-coverage-xlsx": false,
		"format-coverage-odp": false,
	}
	synthetic, pendingPinned, frozenPinned := 0, 0, 0
	for _, e := range m.Entries {
		switch e.Class {
		case M0CorpusClassSyntheticSeed:
			synthetic++
			if _, ok := formats[e.Format]; ok {
				formats[e.Format] = true
			}
		case M0CorpusClassProducerPinned:
			switch e.Status {
			case M0CorpusStatusAcquisitionPending:
				pendingPinned++
			case M0CorpusStatusFrozen:
				frozenPinned++
			}
			if e.Recipe == "" || e.SourceEntry == "" {
				t.Errorf("producer-pinned entry %s must carry recipe + sourceEntry", e.File)
			}
		default:
			t.Errorf("entry %s: unknown class %q", e.File, e.Class)
		}
		if e.BenchmarkRole != "" {
			if _, ok := roles[e.BenchmarkRole]; !ok {
				t.Errorf("entry %s: benchmarkRole %q is not a frozen R2 cell", e.File, e.BenchmarkRole)
			}
			roles[e.BenchmarkRole] = true
		}
	}
	// Freeze shape: the synthetic-seed set is always present; after the D3
	// acquisition (2026-09-20 qualification run) all five producer-pinned
	// entries are frozen and digest-bearing — an acquisition-pending pinned
	// entry in THIS manifest would regress the acquisition.
	if synthetic == 0 || frozenPinned != 5 || pendingPinned != 0 {
		t.Fatalf("freeze shape wrong: synthetic=%d frozenPinned=%d pendingPinned=%d",
			synthetic, frozenPinned, pendingPinned)
	}
	for format, covered := range formats {
		if !covered {
			t.Errorf("no synthetic-seed fixture covers format %q", format)
		}
	}
	for role, covered := range roles {
		if !covered {
			t.Errorf("no fixture binds benchmark role %q", role)
		}
	}

	// The budget-critical cells are pinned, not accidental.
	for _, e := range m.Entries {
		switch e.File {
		case "m0corpus-pdf-large-500p.pdf":
			if e.Count != 500 {
				t.Errorf("large fixture: count %d, want the 500-page manifest-budget cell", e.Count)
			}
		case "m0corpus-pdf-annotation-heavy-ref20.pdf", "m0corpus-pptx-reference20.pptx":
			if e.Count != 20 {
				t.Errorf("%s: count %d, want the 20-page reference-deck shape", e.File, e.Count)
			}
		case "m0corpus-pdf-asset-heavy-9x3mib.pdf":
			if e.ByteSize <= 24<<20 {
				t.Errorf("asset-heavy fixture: %d bytes must cross the 24 MiB client cap to exercise bounding", e.ByteSize)
			}
		}
	}
}

// TestM0CorpusDetectsDigestAndCountDrift proves the freeze actually bites:
// any drift between manifest and bytes fails verification.
func TestM0CorpusDetectsDigestAndCountDrift(t *testing.T) {
	m, _ := loadFrozenM0Manifest(t)

	// Each variant deep-copies the Entries slice: the copies mutate entries
	// in place and must not share a backing array.
	drift := func(mutate func(e *M0CorpusEntry)) *M0CorpusManifest {
		variant := *m
		variant.Entries = append([]M0CorpusEntry(nil), m.Entries...)
		for i := range variant.Entries {
			if variant.Entries[i].File == "m0corpus-pdf-small-deck.pdf" {
				mutate(&variant.Entries[i])
			}
		}
		return &variant
	}

	err := VerifyM0CorpusDir(m0CorpusTestDir, drift(func(e *M0CorpusEntry) {
		e.SHA256 = strings.Repeat("cd", 32)
	}))
	if err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("digest drift not detected: %v", err)
	}

	err = VerifyM0CorpusDir(m0CorpusTestDir, drift(func(e *M0CorpusEntry) { e.Count++ }))
	if err == nil || !strings.Contains(err.Error(), "count") {
		t.Fatalf("count drift not detected: %v", err)
	}

	err = VerifyM0CorpusDir(m0CorpusTestDir, drift(func(e *M0CorpusEntry) { e.ByteSize += 1 }))
	if err == nil || !strings.Contains(err.Error(), "byte size") {
		t.Fatalf("size drift not detected: %v", err)
	}
}

// TestM0CorpusRefusesFabricatedProducerBytes is the honesty guard: bytes
// parked under an acquisition-pending producer-pinned name — synthetic or
// hand-made — fail verification instead of standing in for the pinned engine.
func TestM0CorpusRefusesFabricatedProducerBytes(t *testing.T) {
	dir := t.TempDir()
	seed := []byte("synthetic bytes pretending to be a pinned engine output")
	manifest := &M0CorpusManifest{
		SchemaVersion: M0CorpusSchemaVersion,
		CorpusID:      "meet-m0-corpus-test",
		Revision:      1,
		FrozenAt:      "2026-09-19T00:00:00Z",
		Entries: []M0CorpusEntry{
			{
				File: "m0corpus-pdf-lo-ref20.pdf", Format: "pdf",
				Class: M0CorpusClassProducerPinned, Status: M0CorpusStatusAcquisitionPending,
				CountKind: "pages",
			},
		},
	}
	if err := os.WriteFile(filepath.Join(dir, "m0corpus-pdf-lo-ref20.pdf"), seed, 0o600); err != nil {
		t.Fatal(err)
	}
	err := VerifyM0CorpusDir(dir, manifest)
	if err == nil || !strings.Contains(err.Error(), "fabricated") {
		t.Fatalf("fabricated producer bytes not refused: %v", err)
	}
	// The honest state (absent bytes) verifies.
	if err := os.Remove(filepath.Join(dir, "m0corpus-pdf-lo-ref20.pdf")); err != nil {
		t.Fatal(err)
	}
	if err := VerifyM0CorpusDir(dir, manifest); err != nil {
		t.Fatalf("acquisition-pending entry with absent bytes must verify: %v", err)
	}
}

// TestM0CorpusRefusesUnmanifestedFiles keeps the freeze exact: the corpus
// directory may not gain files the manifest does not claim.
func TestM0CorpusRefusesUnmanifestedFiles(t *testing.T) {
	dir := t.TempDir()
	payload := []byte("%PDF-1.4\n/Type /Page\n")
	manifest := &M0CorpusManifest{
		SchemaVersion: M0CorpusSchemaVersion,
		CorpusID:      "meet-m0-corpus-test",
		Revision:      1,
		FrozenAt:      "2026-09-19T00:00:00Z",
		Entries: []M0CorpusEntry{
			{
				File: "m0corpus-pdf-small-deck.pdf", Format: "pdf",
				Class: M0CorpusClassSyntheticSeed, Status: M0CorpusStatusFrozen,
				SHA256:    "da565d844399c1298395e1731041d88c803184142732f33bd06810ce92312745",
				ByteSize:  int64(len(payload)),
				CountKind: "pages", Count: 1,
			},
		},
	}
	// Manifest digest must match the crafted payload, or the wrong failure
	// would fire first.
	sum := sha256Sum(payload)
	manifest.Entries[0].SHA256 = sum
	if err := os.WriteFile(filepath.Join(dir, manifest.Entries[0].File), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyM0CorpusDir(dir, manifest); err != nil {
		t.Fatalf("exact corpus must verify: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "unmanifested.bin"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := VerifyM0CorpusDir(dir, manifest)
	if err == nil || !strings.Contains(err.Error(), "unmanifested") {
		t.Fatalf("unmanifested file not refused: %v", err)
	}
}

// TestMeasureM0CorpusCountFormats pins each format's intrinsic measurer
// against tiny in-memory fixtures.
func TestMeasureM0CorpusCountFormats(t *testing.T) {
	pdf := []byte("%PDF-1.4 trailer /Type /Catalog /Pages 2 0 R " +
		"/Type /Pages /Kids [4 0 R 5 0 R 6 0 R] " +
		"/Type /Page /Parent 2 0 R /Type /Page /Parent 2 0 R /Type /Page /Parent 2 0 R")
	wantCount(t, "pdf", pdf, 3)

	// LibreOffice — the D3 pinned producer — writes the page token unspaced
	// ("/Type/Page"); the page-tree token still prefixes it and must be
	// subtracted. Mirrors the captured m0corpus-pdf-lo-*.pdf corpus rows.
	loPDF := []byte("%PDF-1.4 trailer /Type/Pages /Kids [4 0 R 5 0 R] " +
		"/Type/Page /Parent 2 0 R /Type/Page /Parent 2 0 R")
	wantCount(t, "pdf", loPDF, 2)

	pptx := m0TestZip(t, map[string]string{
		"[Content_Types].xml":              "<Types/>",
		"ppt/presentation.xml":             "<p:presentation/>",
		"ppt/slides/slide1.xml":            "<p:sld/>",
		"ppt/slides/slide2.xml":            "<p:sld/>",
		"ppt/slides/_rels/slide1.xml.rels": "<Relationships/>",
		"ppt/notesSlides/notesSlide1.xml":  "<p:notes/>",
	})
	wantCount(t, "pptx", pptx, 2)

	xlsx := m0TestZip(t, map[string]string{
		"xl/workbook.xml":            "<workbook/>",
		"xl/worksheets/sheet1.xml":   "<worksheet/>",
		"xl/worksheets/sheet2.xml":   "<worksheet/>",
		"xl/worksheets/sheet3.xml":   "<worksheet/>",
		"xl/_rels/workbook.xml.rels": "<Relationships/>",
	})
	wantCount(t, "xlsx", xlsx, 3)

	odp := m0TestZip(t, map[string]string{
		"mimetype":    "application/vnd.oasis.opendocument.presentation",
		"content.xml": `<office:presentation><draw:page draw:name="a"/><draw:page draw:name="b"/></office:presentation>`,
	})
	wantCount(t, "odp", odp, 2)

	docx := m0TestZip(t, map[string]string{
		"docProps/app.xml": `<Properties><Application>x</Application><Pages>7</Pages></Properties>`,
	})
	wantCount(t, "docx", docx, 7)

	vtt := []byte("WEBVTT\n\ncue-1\n00:00:00.000 --> 00:00:03.000\nhi\n\ncue-2\n00:00:03.000 --> 00:00:06.000\nho\n")
	wantCount(t, "vtt", vtt, 2)

	if _, err := MeasureM0CorpusCount("doc", pdf); err == nil {
		t.Fatal("format without a measurer must error")
	}
}

// TestM0CorpusManifestValidation walks the manifest contract's refusal
// cases; every invalid shape must be refused at parse time.
func TestM0CorpusManifestValidation(t *testing.T) {
	valid := M0CorpusManifest{
		SchemaVersion: M0CorpusSchemaVersion,
		CorpusID:      "meet-m0-corpus-test",
		Revision:      1,
		FrozenAt:      "2026-09-19T00:00:00Z",
		Entries: []M0CorpusEntry{
			{
				File: "m0corpus-pdf-small-deck.pdf", Format: "pdf",
				Class: M0CorpusClassSyntheticSeed, Status: M0CorpusStatusFrozen,
				SHA256: strings.Repeat("ab", 32), ByteSize: 10,
				CountKind: "pages", Count: 1,
			},
		},
	}

	validPending := func() M0CorpusManifest {
		m := valid
		m.Entries = []M0CorpusEntry{
			{
				File: "m0corpus-pdf-lo-ref20.pdf", Format: "pdf",
				Class: M0CorpusClassProducerPinned, Status: M0CorpusStatusAcquisitionPending,
				CountKind: "pages", Recipe: "soffice ...", SourceEntry: "m0corpus-pptx-reference20.pptx",
			},
		}
		return m
	}

	cases := []struct {
		name    string
		pending bool
		mutate  func(*M0CorpusManifest)
		wantErr string
	}{
		{"valid synthetic", false, func(*M0CorpusManifest) {}, ""},
		{"valid pending pinned", true, func(*M0CorpusManifest) {}, ""},
		{"bad schemaVersion", false, func(m *M0CorpusManifest) { m.SchemaVersion = "other/9" }, "schemaVersion"},
		{"empty corpusId", false, func(m *M0CorpusManifest) { m.CorpusID = "" }, "corpusId"},
		{"bad frozenAt", false, func(m *M0CorpusManifest) { m.FrozenAt = "yesterday" }, "frozenAt"},
		{"no entries", false, func(m *M0CorpusManifest) { m.Entries = nil }, "no entries"},
		{"duplicate file", false, func(m *M0CorpusManifest) { m.Entries = append(m.Entries, m.Entries[0]) }, "duplicate"},
		{"bad format", false, func(m *M0CorpusManifest) { m.Entries[0].Format = "keynote" }, "format"},
		{"bad class", false, func(m *M0CorpusManifest) { m.Entries[0].Class = "producer" }, "class"},
		{"bad status", false, func(m *M0CorpusManifest) { m.Entries[0].Status = "draft" }, "status"},
		{"path escape", false, func(m *M0CorpusManifest) { m.Entries[0].File = "../evil.pdf" }, "bare corpus-dir filename"},
		{"synthetic without sha", false, func(m *M0CorpusManifest) { m.Entries[0].SHA256 = "" }, "without sha256"},
		{"bad sha hex", false, func(m *M0CorpusManifest) { m.Entries[0].SHA256 = strings.Repeat("zz", 32) }, "hex"},
		{"uppercase sha", false, func(m *M0CorpusManifest) { m.Entries[0].SHA256 = strings.Repeat("AB", 32) }, "hex"},
		{"short sha", false, func(m *M0CorpusManifest) { m.Entries[0].SHA256 = "abcd" }, "64 lowercase hex"},
		{"zero size", false, func(m *M0CorpusManifest) { m.Entries[0].ByteSize = 0 }, "byteSize"},
		{"zero count", false, func(m *M0CorpusManifest) { m.Entries[0].Count = 0 }, "count"},
		{"missing countKind", false, func(m *M0CorpusManifest) { m.Entries[0].CountKind = "" }, "countKind"},
		{"pending non-producer", true, func(m *M0CorpusManifest) {
			m.Entries[0].Status = M0CorpusStatusAcquisitionPending
			m.Entries[0].Class = M0CorpusClassSyntheticSeed
		}, "without sha256"},
		{"pending claiming bytes", true, func(m *M0CorpusManifest) {
			m.Entries[0].SHA256 = ""
			m.Entries[0].ByteSize = 10
		}, "claims captured bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Deep-copy the Entries slice: cases mutate entries in place and
			// must not poison each other through a shared backing array.
			m := valid
			if tc.pending {
				m = validPending()
			}
			m.Entries = append([]M0CorpusEntry(nil), m.Entries...)
			tc.mutate(&m)
			raw, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			_, err = ParseM0CorpusManifest(raw)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected valid, got: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

// TestM0CorpusParseRefusesMalformedJSON covers the json.Unmarshal arm:
// bytes that are not JSON at all fail as a parser-attributed error instead
// of surfacing as a misleading schema or entry-shape refusal.
func TestM0CorpusParseRefusesMalformedJSON(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte("{not json"),
		[]byte(`{"schemaVersion":"setjoin.meet.m0-corpus/1",`),
	} {
		m, err := ParseM0CorpusManifest(raw)
		if err == nil {
			t.Fatalf("malformed manifest %q parsed as %v", raw, m)
		}
		if !strings.Contains(err.Error(), "m0 corpus manifest") {
			t.Fatalf("malformed manifest error not attributed to the parser: %v", err)
		}
	}
}

// TestVerifyM0CorpusDirErrorArms walks the fail-closed arms of directory
// verification that the freeze gate and the digest/size/count drift tests do
// not reach: a stat error that is not plain byte-absence, frozen bytes
// missing from disk, bytes on disk that the format measurer refuses despite
// a self-consistent manifest, an unreadable corpus directory, and a
// subdirectory smuggled into it.
func TestVerifyM0CorpusDirErrorArms(t *testing.T) {
	payload := []byte("%PDF-1.4\n/Type /Page\n")

	pendingPinned := func(file string) M0CorpusEntry {
		return M0CorpusEntry{
			File: file, Format: "pdf",
			Class: M0CorpusClassProducerPinned, Status: M0CorpusStatusAcquisitionPending,
			CountKind: "pages",
		}
	}
	frozen := func(file, format string, data []byte) M0CorpusEntry {
		return M0CorpusEntry{
			File: file, Format: format,
			Class: M0CorpusClassSyntheticSeed, Status: M0CorpusStatusFrozen,
			SHA256: sha256Sum(data), ByteSize: int64(len(data)),
			CountKind: "pages", Count: 1,
		}
	}
	manifest := func(entries ...M0CorpusEntry) *M0CorpusManifest {
		return &M0CorpusManifest{
			SchemaVersion: M0CorpusSchemaVersion,
			CorpusID:      "meet-m0-corpus-test",
			Revision:      1,
			FrozenAt:      "2026-09-19T00:00:00Z",
			Entries:       entries,
		}
	}

	cases := []struct {
		name    string
		setup   func(t *testing.T) (dir string, m *M0CorpusManifest)
		wantErr string
	}{
		{
			// Byte-absence on an acquisition-pending entry has two stat
			// shapes: a plain missing file (covered by the fabricated-bytes
			// test) and a stat error that is not fs.ErrNotExist — here
			// ENOTDIR because the corpus "directory" is a regular file. The
			// latter must be reported, never mistaken for honest absence.
			name: "pending entry stat error is not not-exist",
			setup: func(t *testing.T) (string, *M0CorpusManifest) {
				blocker := filepath.Join(t.TempDir(), "corpus")
				if err := os.WriteFile(blocker, []byte("not a dir"), 0o600); err != nil {
					t.Fatal(err)
				}
				return blocker, manifest(pendingPinned("m0corpus-pdf-lo-ref20.pdf"))
			},
			wantErr: "not a directory",
		},
		{
			name: "frozen bytes missing from disk",
			setup: func(t *testing.T) (string, *M0CorpusManifest) {
				return t.TempDir(), manifest(frozen("m0corpus-pdf-small-deck.pdf", "pdf", payload))
			},
			wantErr: "no such file",
		},
		{
			name: "measurer refuses frozen bytes",
			setup: func(t *testing.T) (string, *M0CorpusManifest) {
				dir := t.TempDir()
				if err := os.WriteFile(filepath.Join(dir, "m0corpus-pptx-small.pptx"), payload, 0o600); err != nil {
					t.Fatal(err)
				}
				// Digest and byte size match the bytes on disk; the pptx
				// measurer still refuses non-zip bytes, so a self-consistent
				// manifest cannot buy verification.
				return dir, manifest(frozen("m0corpus-pptx-small.pptx", "pptx", payload))
			},
			wantErr: "not a readable zip",
		},
		{
			name: "corpus dir unreadable",
			setup: func(t *testing.T) (string, *M0CorpusManifest) {
				absent := filepath.Join(t.TempDir(), "absent-corpus")
				return absent, manifest(pendingPinned("m0corpus-pdf-lo-ref20.pdf"))
			},
			wantErr: "corpus dir",
		},
		{
			name: "subdirectory in corpus dir",
			setup: func(t *testing.T) (string, *M0CorpusManifest) {
				dir := t.TempDir()
				if err := os.WriteFile(filepath.Join(dir, "m0corpus-pdf-small-deck.pdf"), payload, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(dir, "smuggled"), 0o700); err != nil {
					t.Fatal(err)
				}
				return dir, manifest(frozen("m0corpus-pdf-small-deck.pdf", "pdf", payload))
			},
			wantErr: "subdirectory",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, m := tc.setup(t)
			err := VerifyM0CorpusDir(dir, m)
			if err == nil {
				t.Fatal("expected verification to fail closed, got nil error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

// TestMeasureM0CorpusCountFailClosed exercises every measurer's refusal arms
// with corrupt or incomplete fixtures: malformed bytes, packages missing the
// counted part, packages with zero countable parts, and app.xml page
// declarations that are absent, unterminated or not a positive count. Each
// arm must return an error and never a fabricated count.
func TestMeasureM0CorpusCountFailClosed(t *testing.T) {
	notZip := []byte("definitely not a zip archive")

	contentTypesOnly := m0TestZip(t, map[string]string{
		"[Content_Types].xml": "<Types/>",
	})
	odpNoContent := m0TestZip(t, map[string]string{
		"mimetype":   "application/vnd.oasis.opendocument.presentation",
		"styles.xml": "<office:styles/>",
	})
	docxNoApp := m0TestZip(t, map[string]string{
		"word/document.xml": "<w:document/>",
	})
	validODP := m0TestZip(t, map[string]string{
		"mimetype":    "application/vnd.oasis.opendocument.presentation",
		"content.xml": `<office:presentation><draw:page draw:name="a"/></office:presentation>`,
	})

	appXML := "<Properties><Application>x</Application>" +
		strings.Repeat("<Comment>pad</Comment>", 12) +
		"<Pages>3</Pages></Properties>"

	cases := []struct {
		name    string
		format  string
		data    []byte
		wantErr string
	}{
		{"odp not a zip", "odp", notZip, "not a readable zip"},
		{"odp without content.xml", "odp", odpNoContent, "part content.xml absent"},
		{"docx not a zip", "docx", notZip, "not a readable zip"},
		{"docx without app.xml", "docx", docxNoApp, "part docProps/app.xml absent"},
		{"pptx not a zip", "pptx", notZip, "not a readable zip"},
		{"xlsx not a zip", "xlsx", notZip, "not a readable zip"},
		{"pptx without slide parts", "pptx", contentTypesOnly, "no ppt/slides/slide* parts"},
		{"xlsx without sheet parts", "xlsx", contentTypesOnly, "no xl/worksheets/sheet* parts"},
		{"docx app.xml without Pages", "docx", m0TestZip(t, map[string]string{
			"docProps/app.xml": `<Properties><Application>x</Application></Properties>`,
		}), "no <Pages> declaration"},
		{"docx Pages unterminated", "docx", m0TestZip(t, map[string]string{
			"docProps/app.xml": `<Properties><Pages>3</Properties>`,
		}), "unterminated"},
		{"docx Pages not a number", "docx", m0TestZip(t, map[string]string{
			"docProps/app.xml": `<Properties><Pages>many</Pages></Properties>`,
		}), "not a positive page count"},
		{"docx Pages zero", "docx", m0TestZip(t, map[string]string{
			"docProps/app.xml": `<Properties><Pages>0</Pages></Properties>`,
		}), "not a positive page count"},
		{"docx Pages negative", "docx", m0TestZip(t, map[string]string{
			"docProps/app.xml": `<Properties><Pages>-2</Pages></Properties>`,
		}), "not a positive page count"},
		{"format without a measurer", "ods", validODP, "no intrinsic count measurer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n, err := MeasureM0CorpusCount(tc.format, tc.data)
			if err == nil {
				t.Fatalf("%s: measurer accepted corrupt fixture, count=%d", tc.name, n)
			}
			if n != 0 {
				t.Fatalf("%s: error path must not report a count, got %d", tc.name, n)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("%s: want error containing %q, got: %v", tc.name, tc.wantErr, err)
			}
		})
	}

	// A part whose local file header is corrupted still lists in the central
	// directory, so package open and part lookup succeed and only reading
	// the part fails at header validation.
	docx := m0TestZip(t, map[string]string{"docProps/app.xml": appXML})
	if _, err := MeasureM0CorpusCount("docx", m0CorruptZipLocalHeader(t, docx)); err == nil ||
		!strings.Contains(err.Error(), "part docProps/app.xml:") {
		t.Fatalf("corrupt local header not refused at part open: %v", err)
	}

	// A part whose compressed payload is corrupted opens fine and fails only
	// while its bytes are read.
	if _, err := MeasureM0CorpusCount("docx", m0CorruptZipPayload(t, docx)); err == nil ||
		!strings.Contains(err.Error(), "part docProps/app.xml:") {
		t.Fatalf("corrupt payload not refused while reading the part: %v", err)
	}
}

// TestIsM0SHA256Hex pins the digest shape gate: exactly 64 lowercase hex
// chars, nothing else.
func TestIsM0SHA256Hex(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"valid", strings.Repeat("ab", 32), true},
		{"empty", "", false},
		{"too short", "abcd", false},
		{"too long", strings.Repeat("ab", 33), false},
		{"not hex", strings.Repeat("zz", 32), false},
		{"uppercase", strings.Repeat("AB", 32), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isM0SHA256Hex(tc.in); got != tc.want {
				t.Fatalf("isM0SHA256Hex(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// m0CorruptZipLocalHeader flips one byte of the first local file header
// signature: the central directory still lists the part, so package open and
// part lookup succeed, but reading the part fails when the local header is
// validated.
func m0CorruptZipLocalHeader(t *testing.T, data []byte) []byte {
	t.Helper()
	if !bytes.HasPrefix(data, []byte("PK\x03\x04")) {
		t.Fatalf("fixture does not start with a zip local header: % x", data[:4])
	}
	out := append([]byte(nil), data...)
	out[3] ^= 0xff
	return out
}

// m0CorruptZipPayload flips one byte inside the compressed payload of the
// first (only) local entry, leaving the local header, central directory and
// end-of-central-directory intact so the package still opens and the part is
// still found — it fails only once its bytes are decompressed.
func m0CorruptZipPayload(t *testing.T, data []byte) []byte {
	t.Helper()
	if !bytes.HasPrefix(data, []byte("PK\x03\x04")) {
		t.Fatalf("fixture does not start with a zip local header: % x", data[:4])
	}
	nameLen := int(binary.LittleEndian.Uint16(data[26:28]))
	extraLen := int(binary.LittleEndian.Uint16(data[28:30]))
	start := 30 + nameLen + extraLen
	if start+8 >= len(data) {
		t.Fatalf("fixture too small to hold a corruptible payload byte: len=%d", len(data))
	}
	out := append([]byte(nil), data...)
	out[start+8] ^= 0xff
	return out
}

func wantCount(t *testing.T, format string, data []byte, want int) {
	t.Helper()
	got, err := MeasureM0CorpusCount(format, data)
	if err != nil {
		t.Fatalf("%s: %v", format, err)
	}
	if got != want {
		t.Fatalf("%s: count %d, want %d", format, got, want)
	}
}

func m0TestZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sha256Sum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
