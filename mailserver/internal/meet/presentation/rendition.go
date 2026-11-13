package presentation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// RenditionProfileVersion freezes the protected paged-rendition profile name
// (MEET plan, "Drive rendition profile"). This is a Meet/Drive contract owned
// by the MEET plan: Office production qualification is NOT a prerequisite —
// only immutable Drive version identity and provider-neutral rendition inputs
// are dependencies.
const RenditionProfileVersion = "meet-pages-v1"

// Manifest bounds frozen by M0 ("Resource envelope" + "Performance
// budgets"), enforced together before admission:
//   - 500 pages per manifest; larger metadata paginates.
//   - One manifest metadata page is at most 256 KiB (bounded pagination).
//   - A full-page decoded raster is at most 4096 × 4096 pixels and ONE
//     encoded page asset is at most 16 MiB ("Full-page decoded raster /
//     encoded page").
//   - The AGGREGATE rendition output referenced by one manifest is at most
//     512 MiB.
//   - 24 MiB is the AGGREGATE encoded client cache cap ("Encoded client
//     assets: 24 MiB total including thumbnails/prefetch; evict before
//     allocation") — a client fetch/eviction budget for the serving layer,
//     NEVER a per-asset manifest bound; larger outputs use the optional
//     zoom tiles, not a bigger page asset.
//   - Page fetches are SHORT-LIVED authorized fetches: an asset reference's
//     TTL and expiry both stay inside MaxAssetRefTTL; raising these limits
//     changes a versioned profile and requires review.
const (
	MaxPagesPerManifest = 500
	MaxManifestBytes    = 256 << 10 // 256 KiB, bounded-pagination manifest page
	MaxPageWidthPx      = 4096
	MaxPageHeightPx     = 4096
	// MaxEncodedPageBytes bounds ONE encoded page asset (full page, zoom
	// tile, thumbnail): a single output never exceeds the 16 MiB encoded-
	// page ceiling.
	MaxEncodedPageBytes = 16 << 20 // 16 MiB
	// MaxAggregateOutputBytes bounds the SUM of every asset byte size one
	// manifest references (pages, thumbnails, accessible representations,
	// notes and searchable-text refs).
	MaxAggregateOutputBytes = 512 << 20 // 512 MiB aggregate rendition output
	// MaxEncodedClientAssetsBytes is the AGGREGATE client cache cap — 24 MiB
	// total including thumbnails/prefetch. It budgets the CLIENT's resident
	// encoded assets; it is not a per-asset or per-manifest producer bound.
	MaxEncodedClientAssetsBytes = 24 << 20 // 24 MiB total
	// MaxAssetRefTTL is the longest lifetime a "short-lived authorized
	// fetch" reference may carry — in either TTL or ExpiresAt distance.
	MaxAssetRefTTL = time.Hour
)

// RenditionKey is the immutable, tenant-scoped rendition profile key. The
// same tuple deduplicates rendition work ONLY within the authenticated
// tenant — tenant identity joins the rendition cache key and never bypasses
// the admission/visibility boundary.
type RenditionKey struct {
	TenantID             int64  // authenticated tenant scope; part of the cache key
	DriveVersionID       int64  // immutable Drive version identity (drive_file_versions)
	SourceSHA256         string // lowercase hex sha256 of the pinned source bytes
	RendererID           string // qualified renderer identity (ProviderIdentity.RendererID)
	RendererVersion      string // qualified renderer version — never invented, only admitted
	FontPackDigest       string // qualified font-pack digest
	LocaleProfile        string
	OutputProfileVersion string // e.g. RenditionProfileVersion for meet-pages-v1 output
}

// RenditionWarning is the closed vocabulary of fidelity warnings a producer
// may attach to a manifest. Unknown warnings fail manifest validation: a
// consumer must be able to render every warning it reads.
type RenditionWarning string

const (
	WarnFontSubstituted      RenditionWarning = "font_substituted"
	WarnAnimationUnsupported RenditionWarning = "animation_unsupported"
	WarnEmbeddedMedia        RenditionWarning = "embedded_media"
	WarnTruncated            RenditionWarning = "truncated"
	WarnPasswordProtected    RenditionWarning = "password_protected"
	WarnPartialConversion    RenditionWarning = "partial_conversion"
	// M6 document-mode fidelity warnings (docmode.go): the explicit classes
	// the word/text pagination and spreadsheet static-print modes MANDATE in
	// the same manifest's Warnings — a document-mode capability without its
	// warning is a silent fidelity promise and fails validation.
	WarnProducerPagination RenditionWarning = "producer_pagination"
	WarnStaticPrintLayout  RenditionWarning = "static_print_layout"
)

var renditionWarnings = map[RenditionWarning]struct{}{
	WarnFontSubstituted:      {},
	WarnAnimationUnsupported: {},
	WarnEmbeddedMedia:        {},
	WarnTruncated:            {},
	WarnPasswordProtected:    {},
	WarnPartialConversion:    {},
	WarnProducerPagination:   {},
	WarnStaticPrintLayout:    {},
}

// CacheClass is the expiry/cache classification attached to a manifest.
type CacheClass string

const (
	CacheDedup     CacheClass = "dedup" // content-hash deduplicated within the tenant
	CacheEphemeral CacheClass = "ephemeral"
)

// AssetRef is a SHORT-LIVED AUTHORIZED FETCH reference. The manifest never
// embeds a long-lived object-store URL: every reference is a relative,
// separately-authorized fetch path (path + minted capability token handled by
// the serving layer), validated to reject absolute/remote URLs.
type AssetRef struct {
	Path      string        `json:"path"` // relative fetch path, no scheme/host
	MIMEType  string        `json:"mimeType"`
	ByteSize  int64         `json:"byteSize"`
	SHA256    string        `json:"sha256"`
	ExpiresAt time.Time     `json:"expiresAt"` // short-lived; zero means producer error
	TTL       time.Duration `json:"ttl"`       // declared lifetime; validated against MaxAssetRefTTL
}

// Page is one ordered, deterministic output page.
type Page struct {
	Index         int      `json:"index"` // 0-based, dense, manifest-ordered
	ID            string   `json:"id"`    // stable within the rendition
	WidthPx       int      `json:"widthPx"`
	HeightPx      int      `json:"heightPx"`
	ContentSHA256 string   `json:"contentSha256"`
	ByteSize      int64    `json:"byteSize"`
	MIMEType      string   `json:"mimeType"`
	Thumbnail     AssetRef `json:"thumbnail"`
	FullPage      AssetRef `json:"fullPage"`
	// AccessibleRepresentation is the separately qualified, bounded
	// visible-page accessible representation. It is bound to THIS page
	// capability — never the document search/text-index capability — and is
	// optional: absence is an explicit accessibility limitation, never
	// fabricated text.
	AccessibleRepresentation *AssetRef `json:"accessibleRepresentation,omitempty"`
}

// NotesReference points at the separately protected speaker-notes object.
// Notes require current presenter permission on EVERY fetch and never enter
// attendee manifests or shared event payloads; the reference itself being
// present in a presenter-scoped manifest grants nothing.
type NotesReference struct {
	AssetRef
	RequiresPresenterPermission bool `json:"requiresPresenterPermission"`
}

// SearchableTextReference exists only when policy permits document-wide
// text extraction for THIS rendition; nil elsewhere.
type SearchableTextReference struct {
	AssetRef
}

// Manifest is the immutable meet-pages-v1 rendition manifest: authorized,
// deterministic outputs only.
type Manifest struct {
	Schema         string                   `json:"schema"` // always RenditionProfileVersion
	TenantID       int64                    `json:"tenantId"`
	DriveNodeID    int64                    `json:"driveNodeId"`
	DriveVersionID int64                    `json:"driveVersionId"`
	SourceSHA256   string                   `json:"sourceSha256"`
	Key            RenditionKey             `json:"key"`
	Pages          []Page                   `json:"pages"`
	Notes          *NotesReference          `json:"notes,omitempty"`
	SearchableText *SearchableTextReference `json:"searchableText,omitempty"`
	Warnings       []RenditionWarning       `json:"warnings,omitempty"`
	// DocumentMode is the optional M6 capability section (docmode.go) for a
	// word/text pagination or spreadsheet static-print rendition. nil is the
	// launch vocabulary (PDF native pages, PPT/PPTX/ODP office-to-PDF pages)
	// — absence implies nothing new. A non-nil section must carry one of the
	// closed modes with its pinned fidelity class + fallback rule, an
	// admitted source format, and its mandated fidelity warning in Warnings.
	DocumentMode         *DocumentModeCapability `json:"documentMode,omitempty"`
	RendererID           string                  `json:"rendererId"`
	RendererVersion      string                  `json:"rendererVersion"`
	FontPackDigest       string                  `json:"fontPackDigest"`
	OutputProfileVersion string                  `json:"outputProfileVersion"`
	CompletedAt          time.Time               `json:"completedAt"`
	IntegrityDigest      string                  `json:"integrityDigest"` // hex sha256 over the canonical manifest payload
	CacheClass           CacheClass              `json:"cacheClass"`
}

// Canonical validates-with-no-side-effects: well-formed manifests pass,
// everything the plan names as a producer failure fails closed.
func (m *Manifest) Validate() error {
	if m.Schema != RenditionProfileVersion {
		return fmt.Errorf("manifest schema %q is not %s", m.Schema, RenditionProfileVersion)
	}
	if m.TenantID <= 0 {
		return errors.New("manifest tenant scope missing")
	}
	if m.DriveVersionID <= 0 || m.DriveNodeID <= 0 {
		return errors.New("manifest source identity incomplete")
	}
	if err := validSHA256(m.SourceSHA256); err != nil {
		return fmt.Errorf("manifest source hash: %w", err)
	}
	if m.RendererID == "" || m.RendererVersion == "" {
		return errors.New("manifest renderer/provider identity incomplete")
	}
	if !hex64.MatchString(m.FontPackDigest) {
		return fmt.Errorf("manifest font pack digest %q is not a 64-hex digest", m.FontPackDigest)
	}
	if m.OutputProfileVersion != RenditionProfileVersion {
		return fmt.Errorf("manifest output profile %q is not %s", m.OutputProfileVersion, RenditionProfileVersion)
	}
	if err := m.Key.validate(); err != nil {
		return fmt.Errorf("rendition cache key: %w", err)
	}
	// The tenant/provider cache-key tuple is BOUND to the manifest identity:
	// dedup joins the authenticated tenant and the pinned provider identity,
	// so a key that names a different tenant/source/provider than the
	// manifest body could dedup or alias another tenant's rendition.
	if m.Key.TenantID != m.TenantID ||
		m.Key.DriveVersionID != m.DriveVersionID ||
		m.Key.SourceSHA256 != m.SourceSHA256 ||
		m.Key.RendererID != m.RendererID ||
		m.Key.RendererVersion != m.RendererVersion ||
		m.Key.FontPackDigest != m.FontPackDigest ||
		m.Key.OutputProfileVersion != m.OutputProfileVersion {
		return errors.New("rendition cache key tuple does not bind to the manifest identity")
	}
	if len(m.Pages) == 0 {
		// "Zero-page artifact rejected" (interaction states, rendition row).
		return errors.New("zero-page artifact rejected")
	}
	if len(m.Pages) > MaxPagesPerManifest {
		return fmt.Errorf("manifest carries %d pages; larger metadata must paginate at %d", len(m.Pages), MaxPagesPerManifest)
	}
	var aggregate int64
	seen := make(map[string]struct{}, len(m.Pages))
	for i := range m.Pages {
		p := &m.Pages[i]
		if p.Index != i {
			return fmt.Errorf("page %d carries dense index %d", i, p.Index)
		}
		if p.ID == "" {
			return fmt.Errorf("page %d has no stable id", i)
		}
		if _, dup := seen[p.ID]; dup {
			return fmt.Errorf("duplicate page id %q", p.ID)
		}
		seen[p.ID] = struct{}{}
		// Full-page decoded raster ceiling: dimensions are explicitly bounded
		// (4096 × 4096) — no unlimited-dimension page passes validation.
		if p.WidthPx <= 0 || p.WidthPx > MaxPageWidthPx || p.HeightPx <= 0 || p.HeightPx > MaxPageHeightPx {
			return fmt.Errorf("page %d dimensions %dx%d outside (0,%d]x(0,%d]", i, p.WidthPx, p.HeightPx, MaxPageWidthPx, MaxPageHeightPx)
		}
		if p.ByteSize <= 0 || p.ByteSize > MaxEncodedPageBytes {
			return fmt.Errorf("page %d encoded size %d outside (0,%d]", i, p.ByteSize, MaxEncodedPageBytes)
		}
		if err := validSHA256(p.ContentSHA256); err != nil {
			return fmt.Errorf("page %d content hash: %w", i, err)
		}
		// Aggregate output: the page body (the full-page ref IS the encoded
		// page, so the larger of the two declared sizes counts once — never
		// zero, never double-counted) plus thumbnail/zoom/accessible refs.
		refs := []AssetRef{p.Thumbnail}
		if p.AccessibleRepresentation != nil {
			refs = append(refs, *p.AccessibleRepresentation)
		}
		for _, ref := range refs {
			if err := ref.validate(); err != nil {
				return fmt.Errorf("page %d asset: %w", i, err)
			}
			aggregate += ref.ByteSize
		}
		if err := p.FullPage.validate(); err != nil {
			return fmt.Errorf("page %d asset: %w", i, err)
		}
		if p.FullPage.ByteSize > p.ByteSize {
			aggregate += p.FullPage.ByteSize
		} else {
			aggregate += p.ByteSize
		}
	}
	if m.Notes != nil {
		if !m.Notes.RequiresPresenterPermission {
			// Notes NEVER enter attendee manifests and always gate on current
			// presenter permission; a producer that strips the flag fails.
			return errors.New("notes reference without presenter permission gate")
		}
		if err := m.Notes.validate(); err != nil {
			return fmt.Errorf("notes reference: %w", err)
		}
		aggregate += m.Notes.ByteSize
	}
	if m.SearchableText != nil {
		if err := m.SearchableText.validate(); err != nil {
			return fmt.Errorf("searchable text reference: %w", err)
		}
		aggregate += m.SearchableText.ByteSize
	}
	if aggregate > MaxAggregateOutputBytes {
		return fmt.Errorf("manifest references %d aggregate output bytes over the %d ceiling", aggregate, MaxAggregateOutputBytes)
	}
	// Manifest metadata page: 256 KiB, bounded pagination — the serialized
	// manifest is measured, not assumed.
	serialized, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("manifest does not serialize: %w", err)
	}
	if len(serialized) > MaxManifestBytes {
		return fmt.Errorf("serialized manifest is %d bytes over the %d-byte metadata page; larger metadata must paginate", len(serialized), MaxManifestBytes)
	}
	// M6 document-mode capability: the SAME manifest grammar gates the new
	// modes — unknown mode/format/class/rule combinations and a capability
	// missing its mandated fidelity warning fail closed here (docmode.go),
	// never through a parallel manifest.
	if m.DocumentMode != nil {
		if err := m.DocumentMode.validate(m.Warnings); err != nil {
			return fmt.Errorf("document mode capability: %w", err)
		}
	}
	for _, w := range m.Warnings {
		if _, ok := renditionWarnings[w]; !ok {
			return fmt.Errorf("unknown rendition warning %q fails closed", w)
		}
	}
	if m.CompletedAt.IsZero() {
		return errors.New("manifest missing completion timestamp")
	}
	if err := validSHA256(m.IntegrityDigest); err != nil {
		return fmt.Errorf("manifest integrity digest: %w", err)
	}
	if m.CacheClass != CacheDedup && m.CacheClass != CacheEphemeral {
		return fmt.Errorf("unknown cache classification %q", m.CacheClass)
	}
	return nil
}

func (a *AssetRef) validate() error {
	if a.ByteSize <= 0 || a.ByteSize > MaxEncodedPageBytes {
		return fmt.Errorf("asset byte size %d outside (0,%d]", a.ByteSize, MaxEncodedPageBytes)
	}
	if err := validSHA256(a.SHA256); err != nil {
		return err
	}
	if a.ExpiresAt.IsZero() || !a.ExpiresAt.After(time.Now()) {
		// Short-lived authorized fetch: a reference without a live expiry is
		// a producer failure — never a long-lived URL in disguise.
		return errors.New("asset reference must carry a live short-lived expiry")
	}
	// The TTL is enforced, not decorative: the expiry must sit inside the
	// short-lived window AND the declared TTL must be a positive lifetime
	// within the same cap. A ref expiring years out (or declaring a
	// multi-year TTL) is a long-lived URL wearing a short-lived label.
	if until := time.Until(a.ExpiresAt); until > MaxAssetRefTTL {
		return fmt.Errorf("asset expiry in %s exceeds the %s short-lived window", until, MaxAssetRefTTL)
	}
	if a.TTL <= 0 || a.TTL > MaxAssetRefTTL {
		return fmt.Errorf("asset ttl %s outside (0,%s]", a.TTL, MaxAssetRefTTL)
	}
	if strings.ContainsAny(a.Path, "\x00\r\n") {
		return errors.New("asset path contains control characters")
	}
	parsed, err := url.Parse(a.Path)
	if err != nil {
		return fmt.Errorf("asset path is not a relative fetch reference: %w", err)
	}
	// The manifest never embeds a long-lived object-store URL: anything with
	// a scheme or host (https://bucket..., //host/...) is rejected here so a
	// producer cannot launder object-store identity through the manifest.
	if parsed.IsAbs() || parsed.Host != "" || parsed.Scheme != "" || strings.HasPrefix(a.Path, "//") {
		return fmt.Errorf("asset path %q must be a relative authorized fetch reference, never an absolute URL", a.Path)
	}
	return nil
}

// validate checks the rendition key tuple itself: tenant-scoped dedup joins
// every component, so an incomplete or malformed key can never enter a
// manifest or a cache lookup.
func (k RenditionKey) validate() error {
	if k.TenantID <= 0 {
		return errors.New("rendition dedup is tenant-scoped; tenant identity must join the cache key")
	}
	if k.DriveVersionID <= 0 {
		return errors.New("cache key missing drive version identity")
	}
	if err := validSHA256(k.SourceSHA256); err != nil {
		return fmt.Errorf("cache key source hash: %w", err)
	}
	if k.RendererID == "" || k.RendererVersion == "" {
		return errors.New("cache key missing qualified renderer/provider identity")
	}
	if !hex64.MatchString(k.FontPackDigest) {
		return fmt.Errorf("cache key font pack digest %q is not a 64-hex digest", k.FontPackDigest)
	}
	if k.LocaleProfile == "" {
		return errors.New("cache key missing locale profile")
	}
	if k.OutputProfileVersion != RenditionProfileVersion {
		return fmt.Errorf("cache key output profile %q is not %s", k.OutputProfileVersion, RenditionProfileVersion)
	}
	return nil
}

func validSHA256(s string) error {
	if len(s) != sha256.Size*2 {
		return fmt.Errorf("sha256 %q is not 64 hex chars", s)
	}
	if _, err := hex.DecodeString(s); err != nil {
		return fmt.Errorf("sha256 %q is not hex: %w", s, err)
	}
	return nil
}
