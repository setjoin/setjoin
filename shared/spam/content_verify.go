package spam

import (
	"bytes"
	"strings"
)

// magicSignature maps a MIME type (lowercase) to its magic bytes prefix.
// Only types that are commonly abused in phishing/spam are listed.
// Types without magic bytes (text/plain, etc.) are omitted — they always pass.
var magicSignature = map[string][]byte{
	// Documents
	"application/pdf":               {0x25, 0x50, 0x44, 0x46},                         // %PDF
	"application/msword":            {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, // OLE2
	"application/vnd.ms-excel":      {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, // OLE2
	"application/vnd.ms-powerpoint": {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, // OLE2

	// Archives
	"application/zip":              {0x50, 0x4B, 0x03, 0x04},             // PK\x03\x04
	"application/x-rar-compressed": {'R', 'a', 'r', '!', 0x1a, 0x07},     // Rar!\x1a\x07
	"application/x-7z-compressed":  {0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, // 7z\xBC\xAF\x27\x1C
	"application/gzip":             {0x1F, 0x8B},                         // gzip
	"application/x-bzip2":          {0x42, 0x5A, 0x68},                   // BZh
	"application/x-xz":             {0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, // xz

	// Images
	"image/png":  {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, // \x89PNG\r\n\x1a\n
	"image/jpeg": {0xFF, 0xD8, 0xFF},                               // JPEG SOI
	"image/gif":  {0x47, 0x49, 0x46, 0x38},                         // GIF8
	"image/webp": {0x52, 0x49, 0x46, 0x46},                         // RIFF

	// Executables / scripts
	"application/x-msdownload":    {0x4D, 0x5A},             // MZ (PE/EXE)
	"application/x-msdos-program": {0x4D, 0x5A},             // MZ
	"application/x-msi":           {0xD0, 0xCF, 0x11, 0xE0}, // OLE2 (MSI is OLE)
	"application/x-elf":           {0x7F, 0x45, 0x4C, 0x46}, // \x7FELF
	"application/x-mach-binary":   {0xCF, 0xFA, 0xED, 0xFE}, // Mach-O 32-bit
	"application/x-mach-binary64": {0xCF, 0xFA, 0xED, 0xFE}, // Mach-O

	// Audio/video
	"audio/mpeg": {0xFF, 0xFB},                                     // MP3 frame sync
	"video/mp4":  {0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70}, // ....ftyp
}

// ooxmlPrefixes lists MIME types that are ZIP-based OOXML formats.
// These share the PK\x03\x04 magic with application/zip.
var ooxmlPrefixes = []string{
	"application/vnd.openxmlformats-officedocument.",
	"application/vnd.ms-office.",
}

// typeDetector maps a MIME type to its magic byte signature for reverse lookup.
type typeDetector struct {
	mime  string
	magic []byte
}

// actualTypeDetectors performs reverse lookup: given header bytes, returns
// the most likely MIME type. Used when a claimed type does not match the bytes.
var actualTypeDetectors = []typeDetector{
	{"application/x-msdownload", []byte{0x4D, 0x5A}},                            // MZ
	{"application/x-elf", []byte{0x7F, 0x45, 0x4C, 0x46}},                       // ELF
	{"application/x-mach-binary", []byte{0xCF, 0xFA, 0xED, 0xFE}},               // Mach-O
	{"application/pdf", []byte{0x25, 0x50, 0x44, 0x46}},                         // %PDF
	{"image/png", []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}},       // PNG
	{"image/jpeg", []byte{0xFF, 0xD8, 0xFF}},                                    // JPEG
	{"image/gif", []byte{0x47, 0x49, 0x46, 0x38}},                               // GIF8
	{"application/zip", []byte{0x50, 0x4B, 0x03, 0x04}},                         // PK ZIP
	{"application/x-rar-compressed", []byte{'R', 'a', 'r', '!', 0x1a, 0x07}},    // RAR
	{"application/x-7z-compressed", []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}}, // 7z
	{"application/gzip", []byte{0x1F, 0x8B}},                                    // gzip
	{"application/x-bzip2", []byte{0x42, 0x5A, 0x68}},                           // BZh
	{"audio/mpeg", []byte{0xFF, 0xFB}},                                          // MP3
}

// ContentVerdict is the tri-state outcome of VerifyContentType. It exists so
// "verified" and "unverifiable" are not conflated into one boolean: the old
// (match bool, actual string) contract returned match=true for unregistered
// claimed types — including bytes that were actually executable — silently
// folding "nothing was checked" into "the claim checked out"
// (D-SHARED-SPAM-006, allowlist-by-omission).
type ContentVerdict int

const (
	// ContentUnverifiable: no registered signature for the claimed type, so
	// nothing was verified either way. NOT a pass — consumers must treat it
	// distinctly (e.g. a small additive score), never as verified content.
	// Zero value, so a defaulted verdict fails toward "unverified".
	ContentUnverifiable ContentVerdict = iota
	// ContentVerified: the claimed type is consistent with the header bytes.
	ContentVerified
	// ContentMismatch: the header bytes contradict the claimed type (the
	// disguised-attachment signal).
	ContentMismatch
)

// String returns a stable, lowercase name for the verdict, for logs.
func (v ContentVerdict) String() string {
	switch v {
	case ContentVerified:
		return "verified"
	case ContentMismatch:
		return "mismatch"
	default:
		return "unverifiable"
	}
}

// VerifyContentType checks whether the first bytes of a file match the claimed
// MIME type. It uses magic byte signatures to detect discrepancies.
//
// Returns (verdict, actualType):
//   - ContentVerified if the claimed type is consistent with the header bytes.
//   - ContentMismatch if the bytes contradict the claimed type (or a known
//     signature type was given too few bytes to verify).
//   - ContentUnverifiable if the claimed type (or an empty claim) has no
//     registered verification: magic verification of truly unknown types is
//     impossible in principle, so pass-through is unavoidable — but it is now
//     an explicit verdict, never a verified one. Consumers must score or gate
//     the unverifiable class explicitly rather than read it as a pass.
//   - actualType is the claimed type unless a mismatch identified a different
//     concrete type.
//
// This is used to detect disguised attachments: executables renamed to .pdf,
// scripts disguised as documents, etc. A mismatch adds 3.0 to the spam score.
func VerifyContentType(claimedType string, headerBytes []byte) (ContentVerdict, string) {
	claimedLower := strings.ToLower(strings.TrimSpace(claimedType))
	if claimedLower == "" {
		return ContentUnverifiable, "unknown"
	}

	// Check for exact magic bytes match.
	magic, known := magicSignature[claimedLower]
	if known {
		// Empty or insufficient data for a known magic type: mismatch.
		// A claimed type with a known signature must have enough bytes
		// to verify the full magic sequence.
		if len(headerBytes) < len(magic) {
			if len(headerBytes) == 0 {
				return ContentMismatch, "empty"
			}
			// Check if the available bytes at least match the magic prefix.
			// Fewer than 4 bytes total is too little — reject as mismatch.
			if len(headerBytes) < 4 {
				return ContentMismatch, "too_short"
			}
			if !bytes.Equal(headerBytes, magic[:len(headerBytes)]) {
				actual := detectActualType(headerBytes)
				return ContentMismatch, actual
			}
			// Prefix matches but truncated — pass through cautiously.
			return ContentVerified, claimedType
		}
		if bytes.Equal(headerBytes[:len(magic)], magic) {
			return ContentVerified, claimedType
		}
		// Magic mismatch — try to identify the actual type.
		actual := detectActualType(headerBytes)
		return ContentMismatch, actual
	}

	// OOXML formats (docx, xlsx, pptx, etc.) are ZIP-based.
	for _, prefix := range ooxmlPrefixes {
		if strings.HasPrefix(claimedLower, prefix) {
			if len(headerBytes) >= 4 && headerBytes[0] == 0x50 && headerBytes[1] == 0x4B {
				return ContentVerified, claimedType
			}
			actual := detectActualType(headerBytes)
			return ContentMismatch, actual
		}
	}

	// Text-based formats: check for common content patterns.
	switch {
	case strings.HasPrefix(claimedLower, "text/html"):
		if isHTMLContent(headerBytes) {
			return ContentVerified, claimedType
		}
		// Check if it's some other known binary format pretending to be HTML.
		actual := detectActualType(headerBytes)
		if actual != "unknown" {
			return ContentMismatch, actual
		}
		// Neither HTML nor a known binary format — treat as mismatch.
		// Plain text is not text/html.
		return ContentMismatch, "text/plain"

	case strings.HasPrefix(claimedLower, "application/json"):
		if isJSONContent(headerBytes) {
			return ContentVerified, claimedType
		}
		actual := detectActualType(headerBytes)
		if actual != "unknown" {
			return ContentMismatch, actual
		}
		return ContentMismatch, "text/plain"

	case strings.HasPrefix(claimedLower, "application/xml"),
		strings.HasPrefix(claimedLower, "text/xml"):
		if isXMLContent(headerBytes) {
			return ContentVerified, claimedType
		}
		actual := detectActualType(headerBytes)
		if actual != "unknown" {
			return ContentMismatch, actual
		}
		return ContentMismatch, "text/plain"
	}

	// Unknown claimed type: no registered signature — an explicit
	// unverifiable verdict, never a verified one.
	return ContentUnverifiable, claimedType
}

// detectActualType tries to identify the file type from header bytes.
// Returns "unknown" if no known signature matches.
func detectActualType(headerBytes []byte) string {
	if len(headerBytes) < 2 {
		return "unknown"
	}
	for _, d := range actualTypeDetectors {
		if len(headerBytes) >= len(d.magic) && bytes.Equal(headerBytes[:len(d.magic)], d.magic) {
			return d.mime
		}
	}
	return "unknown"
}

// isHTMLContent checks if the bytes look like HTML content.
func isHTMLContent(data []byte) bool {
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	s := strings.ToLower(string(trimmed))
	return strings.HasPrefix(s, "<!doctype html") ||
		strings.HasPrefix(s, "<html") ||
		strings.HasPrefix(s, "<head") ||
		strings.HasPrefix(s, "<body") ||
		strings.HasPrefix(s, "<meta") ||
		strings.HasPrefix(s, "<title") ||
		strings.HasPrefix(s, "<div") ||
		strings.HasPrefix(s, "<p") ||
		strings.HasPrefix(s, "<span") ||
		strings.HasPrefix(s, "<a ") ||
		strings.HasPrefix(s, "<table") ||
		strings.HasPrefix(s, "<!doctype")
}

// isJSONContent checks if the bytes look like JSON content.
func isJSONContent(data []byte) bool {
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) == 0 {
		return false
	}
	first := trimmed[0]
	return first == '{' || first == '[' || first == '"'
}

// isXMLContent checks if the bytes look like XML content.
func isXMLContent(data []byte) bool {
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	s := strings.ToLower(string(trimmed))
	return strings.HasPrefix(s, "<?xml") ||
		strings.HasPrefix(s, "<!doctype") ||
		strings.HasPrefix(s, "<rss") ||
		strings.HasPrefix(s, "<feed") ||
		strings.HasPrefix(s, "<svg")
}
