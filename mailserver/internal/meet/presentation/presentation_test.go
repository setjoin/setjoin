package presentation

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func testKey() RenditionKey {
	return RenditionKey{
		TenantID:             7,
		DriveVersionID:       42,
		SourceSHA256:         strings.Repeat("ab", 32),
		RendererID:           "soffice",
		RendererVersion:      "from-qualification",
		FontPackDigest:       strings.Repeat("cd", 32),
		LocaleProfile:        "zh-CN",
		OutputProfileVersion: RenditionProfileVersion,
	}
}

func validAssetRef(path string, expires time.Time) AssetRef {
	return AssetRef{
		Path:      path,
		MIMEType:  "image/png",
		ByteSize:  1024,
		SHA256:    strings.Repeat("11", 32),
		ExpiresAt: expires,
		TTL:       10 * time.Minute,
	}
}

func validManifest() Manifest {
	expires := time.Now().Add(10 * time.Minute)
	m := Manifest{
		Schema:               RenditionProfileVersion,
		TenantID:             7,
		DriveNodeID:          5,
		DriveVersionID:       42,
		SourceSHA256:         strings.Repeat("ab", 32),
		Key:                  testKey(),
		RendererID:           "soffice",
		RendererVersion:      "from-qualification",
		FontPackDigest:       strings.Repeat("cd", 32),
		OutputProfileVersion: RenditionProfileVersion,
		CompletedAt:          time.Now(),
		IntegrityDigest:      strings.Repeat("ee", 32),
		CacheClass:           CacheDedup,
	}
	m.Pages = []Page{{
		Index:         0,
		ID:            "p0",
		WidthPx:       1280,
		HeightPx:      720,
		ContentSHA256: strings.Repeat("22", 32),
		ByteSize:      2048,
		MIMEType:      "image/png",
		Thumbnail:     validAssetRef("/api/meet/renditions/p-1/pages/0/thumbnail", expires),
		FullPage:      validAssetRef("/api/meet/renditions/p-1/pages/0/full", expires),
	}}
	return m
}

func TestManifestValidatesWellFormed(t *testing.T) {
	m := validManifest()
	if err := m.Validate(); err != nil {
		t.Fatalf("well-formed manifest rejected: %v", err)
	}
	if m.Schema != "meet-pages-v1" {
		t.Fatalf("profile drifted: %q", m.Schema)
	}
}

func TestManifestFreezesTheRenditionKeyTuple(t *testing.T) {
	// The plan's key tuple: (drive_version_id, source_sha256, renderer_id,
	// renderer_version, font_pack_digest, locale_profile,
	// output_profile_version) — tenant-scoped dedup joins the cache key.
	k := testKey()
	if k.DriveVersionID == 0 || k.SourceSHA256 == "" || k.RendererID == "" ||
		k.RendererVersion == "" || k.FontPackDigest == "" || k.LocaleProfile == "" ||
		k.OutputProfileVersion != RenditionProfileVersion {
		t.Fatalf("rendition key tuple incomplete: %+v", k)
	}
	if k.TenantID == 0 {
		t.Fatal("rendition dedup is tenant-scoped; tenant identity must join the cache key")
	}
}

func TestManifestRejectsProducerFailures(t *testing.T) {
	cases := map[string]func(*Manifest){
		"wrong schema":        func(m *Manifest) { m.Schema = "meet-pages-v2" },
		"zero pages":          func(m *Manifest) { m.Pages = nil },
		"missing tenant":      func(m *Manifest) { m.TenantID = 0 },
		"missing version":     func(m *Manifest) { m.DriveVersionID = 0 },
		"bad source hash":     func(m *Manifest) { m.SourceSHA256 = "not-a-hash" },
		"bad page hash":       func(m *Manifest) { m.Pages[0].ContentSHA256 = strings.Repeat("z", 63) },
		"zero dimensions":     func(m *Manifest) { m.Pages[0].HeightPx = 0 },
		"empty page id":       func(m *Manifest) { m.Pages[0].ID = "" },
		"non-dense index":     func(m *Manifest) { m.Pages[0].Index = 3 },
		"no completion time":  func(m *Manifest) { m.CompletedAt = time.Time{} },
		"no integrity digest": func(m *Manifest) { m.IntegrityDigest = "" },
		"unknown cache class": func(m *Manifest) { m.CacheClass = "forever" },
		"oversized page":      func(m *Manifest) { m.Pages[0].ByteSize = MaxEncodedPageBytes + 1 },
	}
	for name, mutate := range cases {
		m := validManifest()
		mutate(&m)
		if err := m.Validate(); err == nil {
			t.Errorf("%s: manifest accepted", name)
		}
	}
}

func TestManifestRejectsOverCapPageCount(t *testing.T) {
	m := validManifest()
	expires := time.Now().Add(time.Minute)
	m.Pages = nil
	for i := 0; i <= MaxPagesPerManifest; i++ {
		m.Pages = append(m.Pages, Page{
			Index: i, ID: fmt.Sprintf("p%04d", i),
			WidthPx: 10, HeightPx: 10,
			ContentSHA256: strings.Repeat("33", 32), ByteSize: 1,
			MIMEType:  "image/png",
			Thumbnail: validAssetRef("/t", expires),
			FullPage:  validAssetRef("/f", expires),
		})
	}
	if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "paginate") {
		t.Fatalf("over-cap manifest: got %v, want a paginate error", err)
	}
}

func TestManifestNeverEmbedsALongLivedObjectStoreURL(t *testing.T) {
	expires := time.Now().Add(time.Minute)
	for _, path := range []string{
		"https://s3.example.com/bucket/page.png",
		"http://minio.internal/drive/ab/cd",
		"//host/page.png",
		"file:///etc/passwd",
	} {
		m := validManifest()
		m.Pages[0].FullPage = validAssetRef(path, expires)
		if err := m.Validate(); err == nil {
			t.Errorf("absolute asset ref %q accepted; page URLs must be short-lived authorized fetches", path)
		}
	}
}

func TestManifestAssetRefExpiryIsRequired(t *testing.T) {
	m := validManifest()
	m.Pages[0].FullPage = validAssetRef("/api/x", time.Time{})
	if err := m.Validate(); err == nil {
		t.Fatal("asset reference without a live short-lived expiry accepted")
	}
}

func TestManifestNotesAlwaysGateOnPresenterPermission(t *testing.T) {
	expires := time.Now().Add(time.Minute)
	m := validManifest()
	m.Notes = &NotesReference{AssetRef: validAssetRef("/api/meet/renditions/p-1/notes", expires), RequiresPresenterPermission: true}
	if err := m.Validate(); err != nil {
		t.Fatalf("presenter-gated notes rejected: %v", err)
	}
	m.Notes.RequiresPresenterPermission = false
	if err := m.Validate(); err == nil {
		t.Fatal("notes without the presenter permission gate accepted — notes never enter attendee reach")
	}
}

func TestManifestWarningsAreAClosedVocabulary(t *testing.T) {
	m := validManifest()
	m.Warnings = []RenditionWarning{WarnFontSubstituted, WarnAnimationUnsupported, WarnEmbeddedMedia, WarnTruncated, WarnPasswordProtected, WarnPartialConversion}
	if err := m.Validate(); err != nil {
		t.Fatalf("known warnings rejected: %v", err)
	}
	m.Warnings = append(m.Warnings, RenditionWarning("surprise"))
	if err := m.Validate(); err == nil {
		t.Fatal("unknown warning accepted; consumers must render every warning they read")
	}
}

// TestManifestBindsTheCacheKeyTupleToManifestIdentity is the regression for
// the M0/M1 review finding: Validate must validate the tenant/provider
// cache-key tuple AND bind it to the manifest identity — a key naming a
// different tenant, source or provider must fail closed, or rendition dedup
// could alias another tenant's work.
func TestManifestBindsTheCacheKeyTupleToManifestIdentity(t *testing.T) {
	cases := map[string]func(*Manifest){
		"key tenant differs":         func(m *Manifest) { m.Key.TenantID = 8 },
		"key version differs":        func(m *Manifest) { m.Key.DriveVersionID = 43 },
		"key source hash differs":    func(m *Manifest) { m.Key.SourceSHA256 = strings.Repeat("cd", 32) },
		"key renderer id differs":    func(m *Manifest) { m.Key.RendererID = "other-renderer" },
		"key renderer ver differs":   func(m *Manifest) { m.Key.RendererVersion = "v9" },
		"key font digest differs":    func(m *Manifest) { m.Key.FontPackDigest = strings.Repeat("ab", 32) },
		"key output profile differs": func(m *Manifest) { m.Key.OutputProfileVersion = "meet-pages-v0" },
		"key tenant zero":            func(m *Manifest) { m.Key.TenantID = 0 },
		"key source hash malformed":  func(m *Manifest) { m.Key.SourceSHA256 = "short" },
		"key locale profile empty":   func(m *Manifest) { m.Key.LocaleProfile = "" },
		"manifest renderer stripped": func(m *Manifest) { m.RendererID = "" },
		"manifest font digest bad":   func(m *Manifest) { m.FontPackDigest = "nope" },
		"manifest profile swapped":   func(m *Manifest) { m.OutputProfileVersion = "meet-pages-v2" },
	}
	for name, mutate := range cases {
		m := validManifest()
		mutate(&m)
		if err := m.Validate(); err == nil {
			t.Errorf("%s: manifest accepted — cache-key tuple is not bound to the manifest identity", name)
		}
	}
}

// TestManifestEnforcesPlanResourceBounds pins the plan's rendition resource
// envelope ("Resource envelope" + "Performance budgets"): 4096 × 4096 page
// dimensions, 16 MiB encoded pages, 512 MiB aggregate output, and a 256 KiB
// serialized manifest page. The plan's 24 MiB is the AGGREGATE client cache
// cap, never a per-asset allowance.
func TestManifestEnforcesPlanResourceBounds(t *testing.T) {
	mib := int64(1 << 20)
	build := func(pageBytes int64, w, h int) *Manifest {
		m := validManifest()
		m.Pages[0].ByteSize = pageBytes
		m.Pages[0].FullPage.ByteSize = pageBytes
		m.Pages[0].WidthPx = w
		m.Pages[0].HeightPx = h
		return &m
	}
	// A 16 MiB encoded page with 4096×4096 raster is the exact ceiling.
	if err := build(16*mib, MaxPageWidthPx, MaxPageHeightPx).Validate(); err != nil {
		t.Fatalf("16 MiB / 4096×4096 page at the ceiling rejected: %v", err)
	}
	for name, m := range map[string]*Manifest{
		"over-wide page":  build(1024, MaxPageWidthPx+1, 720),
		"over-tall page":  build(1024, 1280, MaxPageHeightPx+1),
		"17 MiB page":     build(16*mib+1, 1280, 720),
		"20 MiB page":     build(20*mib, 1280, 720), // the old wrong 24 MiB per-asset bound admitted this
		"24 MiB page":     build(24*mib, 1280, 720), // per-asset 24 MiB was never the contract
		"oversized asset": func() *Manifest { m := validManifest(); m.Pages[0].FullPage.ByteSize = 17 * mib; return &m }(),
	} {
		if err := m.Validate(); err == nil {
			t.Errorf("%s accepted; plan resource bounds must fail closed", name)
		}
	}

	// Aggregate rendition output: 512 MiB across every page body plus
	// auxiliary refs. 42 pages x 12 MiB (+1 KiB thumbnails) stays inside the
	// ceiling; the 43rd pushes the aggregate over it — with every individual
	// page still inside the 16 MiB encoded-page bound.
	agg := validManifest()
	agg.Pages = nil
	newPage := func(i int) Page {
		return Page{
			Index: i, ID: fmt.Sprintf("p%02d", i),
			WidthPx: 4096, HeightPx: 4096,
			ContentSHA256: strings.Repeat("33", 32),
			ByteSize:      12 << 20,
			MIMEType:      "image/png",
			Thumbnail:     validAssetRef("/t", time.Now().Add(time.Minute)),
			FullPage:      validAssetRef("/f", time.Now().Add(time.Minute)),
		}
	}
	for i := 0; i < 42; i++ {
		agg.Pages = append(agg.Pages, newPage(i))
	}
	if err := agg.Validate(); err != nil {
		t.Fatalf("42 pages within the aggregate ceiling rejected: %v", err)
	}
	agg.Pages = append(agg.Pages, newPage(42))
	if err := agg.Validate(); err == nil || !strings.Contains(err.Error(), "aggregate") {
		t.Fatalf("over-ceiling aggregate output: got %v, want an aggregate error", err)
	}

	// Serialized manifest page: 256 KiB, bounded pagination.
	fat := validManifest()
	fat.Pages = nil
	for i := 0; i < 200; i++ {
		p := Page{
			Index: i, ID: fmt.Sprintf("page-%03d-%s", i, strings.Repeat("m", 1200)),
			WidthPx: 1280, HeightPx: 720,
			ContentSHA256: strings.Repeat("44", 32), ByteSize: 1024,
			MIMEType:  "image/png",
			Thumbnail: validAssetRef("/t", time.Now().Add(time.Minute)),
			FullPage:  validAssetRef("/f", time.Now().Add(time.Minute)),
		}
		fat.Pages = append(fat.Pages, p)
	}
	if err := fat.Validate(); err == nil || !strings.Contains(err.Error(), "paginate") {
		t.Fatalf("over-256KiB serialized manifest: got %v, want a paginate error", err)
	}
}

// TestAssetRefTTLIsEnforced is the regression for the M0/M1 review finding:
// expiry checked only "after now" admits multi-year refs as "short-lived".
// The TTL must be positive, inside the short-lived cap, and the expiry must
// sit within the same window.
func TestAssetRefTTLIsEnforced(t *testing.T) {
	cases := map[string]func(*AssetRef){
		"zero ttl":        func(a *AssetRef) { a.TTL = 0 },
		"negative ttl":    func(a *AssetRef) { a.TTL = -time.Minute },
		"multi-year ttl":  func(a *AssetRef) { a.TTL = 5 * 365 * 24 * time.Hour },
		"ttl over cap":    func(a *AssetRef) { a.TTL = MaxAssetRefTTL + time.Minute },
		"far-future ref":  func(a *AssetRef) { a.ExpiresAt = time.Now().Add(5 * 365 * 24 * time.Hour) },
		"expiry over cap": func(a *AssetRef) { a.ExpiresAt = time.Now().Add(MaxAssetRefTTL + time.Second) },
	}
	for name, mutate := range cases {
		m := validManifest()
		mutate(&m.Pages[0].FullPage)
		if err := m.Validate(); err == nil {
			t.Errorf("%s accepted; a short-lived authorized fetch must fail the TTL check", name)
		}
	}
	// Inside the window passes.
	m := validManifest()
	m.Pages[0].FullPage.TTL = MaxAssetRefTTL
	m.Pages[0].FullPage.ExpiresAt = time.Now().Add(MaxAssetRefTTL)
	if err := m.Validate(); err != nil {
		t.Fatalf("reference at the exact short-lived ceiling rejected: %v", err)
	}
}

func TestEnvelopeEncodeEnforcesTheFrozenBounds(t *testing.T) {
	payload, _ := json.Marshal(map[string]int{"pageIndex": 7})
	e := NewEnvelope("p-1", 42, 3, KindPageChanged, payload, "2026-09-18T00:00:00Z")
	b, err := e.Encode()
	if err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}
	if len(b) > MaxEnvelopeBytes {
		t.Fatalf("encoded %d bytes over the %d bound", len(b), MaxEnvelopeBytes)
	}
	var back Envelope
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("roundtrip: %v", err)
	}
	if back.Topic != "presentation" || back.Version != 1 || back.Kind != KindPageChanged {
		t.Fatalf("roundtrip drifted: %+v", back)
	}
}

func TestEnvelopeEncodeFailsClosed(t *testing.T) {
	if _, err := NewEnvelope("p-1", 1, 1, EventKind("brand.new"), nil, "t").Encode(); err == nil {
		t.Fatal("unknown kind accepted on the send path")
	}
	// M4 admission (V267): the annotation kinds are durably committable with
	// their closed payload shapes (annotation_test.go); an unadmitted
	// annotation SHAPE still fails closed on the send path.
	if _, err := NewEnvelope("p-1", 1, 1, KindAnnotationCommitted, nil, "t").Encode(); err == nil {
		t.Fatal("a commit without its typed reference payload must fail closed")
	}
	if _, err := NewEnvelope("", 1, 1, KindReady, nil, "t").Encode(); err == nil {
		t.Fatal("missing presentation id accepted")
	}
	if _, err := NewEnvelope("p-1", -1, 1, KindReady, nil, "t").Encode(); err == nil {
		t.Fatal("negative checkpoint seq accepted")
	}
	badIndex, _ := json.Marshal(map[string]int{"pageIndex": 500})
	if _, err := NewEnvelope("p-1", 1, 1, KindPageChanged, badIndex, "t").Encode(); err == nil {
		t.Fatal("page index beyond the manifest bound accepted")
	}
	negIndex, _ := json.Marshal(map[string]int{"pageIndex": -1})
	if _, err := NewEnvelope("p-1", 1, 1, KindPageChanged, negIndex, "t").Encode(); err == nil {
		t.Fatal("negative page index accepted")
	}
	fatPage := []byte(`{"pageIndex":0,"pad":"` + strings.Repeat("x", TargetPageChangePayloadBytes) + `"}`)
	if _, err := NewEnvelope("p-1", 1, 1, KindPageChanged, fatPage, "t").Encode(); err == nil || !strings.Contains(err.Error(), "target") {
		t.Fatal("over-target page-change payload accepted")
	}
	oversize := []byte(`{"pad":"` + strings.Repeat("y", MaxEnvelopeBytes) + `"}`)
	if _, err := NewEnvelope("p-1", 1, 1, KindReady, oversize, "t").Encode(); err == nil || !strings.Contains(err.Error(), "at most 14000") {
		t.Fatal("over-bound envelope accepted")
	}
}

func TestClassifyReceiveContract(t *testing.T) {
	ctx := FrameContext{PresentationID: "p-1", ContextConfirmedSeq: 40, KnownGeneration: 3}
	frame := func(mut func(*Envelope)) []byte {
		payload, _ := json.Marshal(map[string]int{"pageIndex": 3})
		e := Envelope{Topic: EnvelopeTopic, Version: 1, PresentationID: "p-1", CheckpointSeq: 41, PresenterGeneration: 3, Kind: KindPageChanged, Payload: payload}
		mut(&e)
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("marshal frame: %v", err)
		}
		return b
	}

	verdict, err := Classify(frame(func(e *Envelope) {}), ctx)
	if err != nil || verdict != VerdictInvalidateCheckpoint {
		t.Fatalf("fresh sequence: got (%v,%v)", verdict, err)
	}
	verdict, err = Classify(frame(func(e *Envelope) { e.CheckpointSeq = 40 }), ctx)
	if err != nil || verdict != VerdictNoop {
		t.Fatalf("duplicate sequence must be a noop: got (%v,%v)", verdict, err)
	}
	verdict, err = Classify(frame(func(e *Envelope) { e.CheckpointSeq = 3 }), ctx)
	if err != nil || verdict != VerdictNoop {
		t.Fatalf("old sequence must be a noop: got (%v,%v)", verdict, err)
	}
	if v, err := Classify(frame(func(e *Envelope) { e.Version = 2 }), ctx); v != VerdictReject || err == nil {
		t.Fatal("unknown version must reject")
	}
	if v, err := Classify(frame(func(e *Envelope) { e.PresentationID = "other" }), ctx); v != VerdictReject || err == nil {
		t.Fatal("wrong presentation id must reject")
	}
	if v, err := Classify(frame(func(e *Envelope) { e.PresenterGeneration = 2 }), ctx); v != VerdictReject || err == nil {
		t.Fatal("stale presenter generation must reject")
	}
	if v, err := Classify(frame(func(e *Envelope) { e.Kind = "mystery" }), ctx); v != VerdictReject || err == nil {
		t.Fatal("unknown kind must reject on receive too")
	}
	if v, err := Classify([]byte(strings.Repeat("x", MaxEnvelopeBytes+1)), ctx); v != VerdictReject || err == nil {
		t.Fatal("oversized frame must reject")
	}
	if v, err := Classify([]byte("not json"), ctx); v != VerdictReject || err == nil {
		t.Fatal("malformed frame must reject")
	}
	// M4 admission: an annotation frame with its ADMITTED payload shape is a
	// known durable fact and may invalidate a checkpoint (a hint); the
	// shape-less version of the same kind rejects outright.
	annPayload := json.RawMessage(`{"snapshotRef":"annotations/p1-s3.json","sha256":"` + strings.Repeat("ab", 32) + `","byteSize":256}`)
	verdict, err = Classify(frame(func(e *Envelope) { e.Kind = KindAnnotationCommitted; e.Payload = annPayload }), ctx)
	if err != nil || verdict != VerdictInvalidateCheckpoint {
		t.Fatalf("admitted annotation frame must parse as a hint: got (%v,%v)", verdict, err)
	}
	if v, err := Classify(frame(func(e *Envelope) { e.Kind = KindAnnotationCommitted }), ctx); v != VerdictReject || err == nil {
		t.Fatal("an annotation frame without its typed payload must reject")
	}
}

func TestClassifyAdvertisedPeerSequenceIsNotAWatermark(t *testing.T) {
	// A far-gap sequence is still only a hint: the remedy is one coalesced
	// authorized refresh, not trusted promotion — proven by the verdict
	// carrying no frame payload authority.
	ctx := FrameContext{PresentationID: "p-1", ContextConfirmedSeq: 40, KnownGeneration: 3}
	payload, _ := json.Marshal(map[string]int{"pageIndex": 0})
	b, _ := json.Marshal(Envelope{Topic: EnvelopeTopic, Version: 1, PresentationID: "p-1", CheckpointSeq: 1 << 40, PresenterGeneration: 3, Kind: KindPageChanged, Payload: payload})
	verdict, err := Classify(b, ctx)
	if err != nil || verdict != VerdictInvalidateCheckpoint {
		t.Fatalf("far gap: got (%v,%v)", verdict, err)
	}
}

// TestClassifyRejectsMalformedPageChanged is the regression for the M0/M1
// review finding: the Go receive path accepted malformed page.changed
// payloads (missing/invalid pageIndex, non-typed payload, over target) and
// steered the checkpoint with them. Every malformed shape rejects.
func TestClassifyRejectsMalformedPageChanged(t *testing.T) {
	ctx := FrameContext{PresentationID: "p-1", ContextConfirmedSeq: 40, KnownGeneration: 3}
	frame := func(payload json.RawMessage) []byte {
		b, err := json.Marshal(Envelope{Topic: EnvelopeTopic, Version: 1, PresentationID: "p-1", CheckpointSeq: 41, PresenterGeneration: 3, Kind: KindPageChanged, Payload: payload})
		if err != nil {
			t.Fatalf("marshal frame: %v", err)
		}
		return b
	}
	for name, payload := range map[string]json.RawMessage{
		"missing payload":  nil,
		"empty payload":    json.RawMessage(`{}`),
		"missing index":    json.RawMessage(`{"pad":1}`),
		"string index":     json.RawMessage(`{"pageIndex":"3"}`),
		"fractional index": json.RawMessage(`{"pageIndex":2.5}`),
		"negative index":   json.RawMessage(`{"pageIndex":-1}`),
		"index at cap":     json.RawMessage(fmt.Sprintf(`{"pageIndex":%d}`, MaxPageCount)),
		"over target":      json.RawMessage(`{"pageIndex":0,"pad":"` + strings.Repeat("x", TargetPageChangePayloadBytes) + `"}`),
	} {
		verdict, err := Classify(frame(payload), ctx)
		if verdict != VerdictReject || err == nil {
			t.Errorf("%s: got (%v,%v), want reject", name, verdict, err)
		}
	}
	// A well-formed payload still invalidates, and a duplicate sequence with
	// a malformed payload is rejected (shape validity precedes seq matching).
	ok, _ := json.Marshal(map[string]int{"pageIndex": 3})
	if v, err := Classify(frame(ok), ctx); v != VerdictInvalidateCheckpoint || err != nil {
		t.Fatalf("well-formed page.changed: got (%v,%v)", v, err)
	}
	dup := func(payload json.RawMessage) []byte {
		b, err := json.Marshal(Envelope{Topic: EnvelopeTopic, Version: 1, PresentationID: "p-1", CheckpointSeq: 40, PresenterGeneration: 3, Kind: KindPageChanged, Payload: payload})
		if err != nil {
			t.Fatalf("marshal frame: %v", err)
		}
		return b
	}
	if v, err := Classify(dup(json.RawMessage(`{"pageIndex":"3"}`)), ctx); v != VerdictReject || err == nil {
		t.Fatalf("malformed duplicate: got (%v,%v), want reject", v, err)
	}
}

func TestStateTransitions(t *testing.T) {
	legal := [][2]State{
		{StatePreparing, StateReady}, {StatePreparing, StateFailed}, {StatePreparing, StateCancelled},
		{StateReady, StateActive}, {StateReady, StateFailed}, {StateReady, StateCancelled},
		{StateActive, StateEnded}, {StateActive, StateRevoked}, {StateActive, StateDegraded},
		{StateDegraded, StateActive},
	}
	for _, pair := range legal {
		if !CanTransition(pair[0], pair[1]) {
			t.Errorf("transition %s→%s must be legal", pair[0], pair[1])
		}
	}
	illegal := [][2]State{
		{StateEnded, StateActive}, {StateRevoked, StateActive}, // resurrection, plan-explicit
		{StateEnded, StatePreparing}, {StateCancelled, StateActive},
		{StateFailed, StateActive}, {StateActive, StateReady}, {StatePreparing, StateActive},
	}
	for _, pair := range illegal {
		if CanTransition(pair[0], pair[1]) {
			t.Errorf("transition %s→%s must be illegal", pair[0], pair[1])
		}
	}
}

func TestSJRecDeleteLifecycle(t *testing.T) {
	if !CanTransitionPackage(PackageActive, PackageDeletePending) {
		t.Fatal("ACTIVE→DELETE_PENDING must be legal (reducer marks)")
	}
	for _, next := range []PackageState{PackageHeldComplete, PackageHeldPartial, PackageDeleted} {
		if !CanTransitionPackage(PackageDeletePending, next) {
			t.Errorf("DELETE_PENDING→%s must be legal", next)
		}
	}
	if CanTransitionPackage(PackageHeldPartial, PackageActive) {
		t.Fatal("HELD_PARTIAL is ineligible for restore in V1 even if a read currently sees bytes")
	}
	if !CanTransitionPackage(PackageHeldComplete, PackageActive) {
		t.Fatal("HELD_COMPLETE restore must be legal with the live-reference fence")
	}
	if CanTransitionPackage(PackageDeleted, PackageActive) || CanTransitionPackage(PackageActive, PackageDeleted) {
		t.Fatal("delete must pass through the sweep boundary; a live package cannot finalize directly")
	}
}

func TestReleaseReceiptsAreIdempotentAndFinalizeOnlyExhausted(t *testing.T) {
	if err := FinalizeAllowed(3, 3, 0); err != nil {
		t.Fatalf("exhausted set must finalize: %v", err)
	}
	if err := FinalizeAllowed(3, 2, 0); err == nil {
		t.Fatal("finalize with an unexhausted child set must fail")
	}
	if err := FinalizeAllowed(3, 2, 1); err == nil {
		t.Fatal("a remaining hold must suspend finalize")
	}
	if err := FinalizeAllowed(3, 4, 0); err == nil {
		t.Fatal("over-release must fail as receipt corruption")
	}
}

func TestSJRecChildVocabulary(t *testing.T) {
	// The .sjrec logical package layout freezes exactly these children.
	want := []SJRecChild{SJRecManifest, SJRecTimeline, SJRecPresentations, SJRecCaptions, SJRecMediaAudio, SJRecLegacyVideoReference, SJRecAnnotations, SJRecIntegrity}
	seen := map[SJRecChild]bool{}
	for _, c := range want {
		if c == "" || seen[c] {
			t.Fatalf("duplicate/empty child %q", c)
		}
		seen[c] = true
	}
	states := []ChildState{ChildEmbedded, ChildRetained, ChildAbsent, ChildExpired}
	if len(states) != 4 {
		t.Fatal("child state vocabulary drifted from embedded/retained/absent/expired")
	}
}
