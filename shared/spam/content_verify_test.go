package spam

import "testing"

func TestVerifyContentType_PDF(t *testing.T) {
	verdict, actual := VerifyContentType("application/pdf", []byte("%PDF-1.4\n%..."))
	if verdict != ContentVerified {
		t.Errorf("expected verified for PDF, got %v with actual=%q", verdict, actual)
	}
}

func TestVerifyContentType_PDF_WrongMagic(t *testing.T) {
	verdict, actual := VerifyContentType("application/pdf", []byte("Not a PDF file"))
	if verdict != ContentMismatch {
		t.Errorf("expected mismatch for fake PDF, got %v with actual=%q", verdict, actual)
	}
}

func TestVerifyContentType_ZIP(t *testing.T) {
	verdict, actual := VerifyContentType("application/zip", []byte{0x50, 0x4B, 0x03, 0x04, 0x00, 0x00})
	if verdict != ContentVerified {
		t.Errorf("expected verified for ZIP (PK\\x03\\x04), got %v with actual=%q", verdict, actual)
	}
}

func TestVerifyContentType_ZIP_WrongMagic(t *testing.T) {
	verdict, actual := VerifyContentType("application/zip", []byte("Not a ZIP"))
	if verdict != ContentMismatch {
		t.Errorf("expected mismatch for fake ZIP, got %v with actual=%q", verdict, actual)
	}
}

func TestVerifyContentType_RAR(t *testing.T) {
	verdict, actual := VerifyContentType("application/x-rar-compressed", []byte{'R', 'a', 'r', '!', 0x1a, 0x07, 0x01, 0x00})
	if verdict != ContentVerified {
		t.Errorf("expected verified for RAR, got %v with actual=%q", verdict, actual)
	}
}

func TestVerifyContentType_7z(t *testing.T) {
	verdict, actual := VerifyContentType("application/x-7z-compressed", []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C})
	if verdict != ContentVerified {
		t.Errorf("expected verified for 7z, got %v with actual=%q", verdict, actual)
	}
}

func TestVerifyContentType_7z_WrongMagic(t *testing.T) {
	verdict, actual := VerifyContentType("application/x-7z-compressed", []byte("not 7z"))
	if verdict != ContentMismatch {
		t.Errorf("expected mismatch for fake 7z, got %v with actual=%q", verdict, actual)
	}
}

func TestVerifyContentType_PNG(t *testing.T) {
	verdict, actual := VerifyContentType("image/png", []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A})
	if verdict != ContentVerified {
		t.Errorf("expected verified for PNG, got %v with actual=%q", verdict, actual)
	}
}

func TestVerifyContentType_JPEG(t *testing.T) {
	verdict, actual := VerifyContentType("image/jpeg", []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10})
	if verdict != ContentVerified {
		t.Errorf("expected verified for JPEG, got %v with actual=%q", verdict, actual)
	}
}

func TestVerifyContentType_GIF(t *testing.T) {
	verdict, actual := VerifyContentType("image/gif", []byte("GIF89a..............."))
	if verdict != ContentVerified {
		t.Errorf("expected verified for GIF, got %v with actual=%q", verdict, actual)
	}
}

func TestVerifyContentType_WebP(t *testing.T) {
	verdict, actual := VerifyContentType("image/webp", []byte{0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x45, 0x42, 0x50})
	if verdict != ContentVerified {
		t.Errorf("expected verified for WebP, got %v with actual=%q", verdict, actual)
	}
}

func TestVerifyContentType_Executable_MZ(t *testing.T) {
	verdict, actual := VerifyContentType("application/x-msdownload", []byte{0x4D, 0x5A, 0x90, 0x00}) // MZ header
	if verdict != ContentVerified {
		t.Errorf("expected verified for PE/EXE (MZ), got %v with actual=%q", verdict, actual)
	}
}

func TestVerifyContentType_OLE(t *testing.T) {
	verdict, actual := VerifyContentType("application/msword", []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})
	if verdict != ContentVerified {
		t.Errorf("expected verified for OLE (DOC), got %v with actual=%q", verdict, actual)
	}
}

func TestVerifyContentType_OOXML(t *testing.T) {
	verdict, actual := VerifyContentType("application/vnd.openxmlformats-officedocument.wordprocessingml.document", []byte{0x50, 0x4B, 0x03, 0x04, 0x00, 0x00})
	if verdict != ContentVerified {
		t.Errorf("expected verified for OOXML DOCX (PK header), got %v with actual=%q", verdict, actual)
	}
}

func TestVerifyContentType_EmptyData(t *testing.T) {
	verdict, actual := VerifyContentType("application/pdf", nil)
	if verdict != ContentMismatch {
		t.Errorf("expected mismatch for nil data, got %v with actual=%q", verdict, actual)
	}
	verdict, actual = VerifyContentType("application/pdf", []byte{})
	if verdict != ContentMismatch {
		t.Errorf("expected mismatch for empty data, got %v with actual=%q", verdict, actual)
	}
}

func TestVerifyContentType_ShortData(t *testing.T) {
	// Only 2 bytes, not enough for any signature
	verdict, actual := VerifyContentType("application/pdf", []byte("%P"))
	if verdict != ContentMismatch {
		t.Errorf("expected mismatch for short data, got %v with actual=%q", verdict, actual)
	}
}

// TestVerifyContentType_UnknownType pins the explicit unverifiable verdict
// (D-SHARED-SPAM-006): an unregistered claimed type is no longer folded into
// the boolean pass ("match=true") that previously also covered verified
// content — including when the bytes were actually executable. Unverifiable is
// its own verdict so the attachment wiring can score/gate it explicitly.
func TestVerifyContentType_UnknownType(t *testing.T) {
	verdict, actual := VerifyContentType("application/x-custom-unknown", []byte("hello"))
	if verdict != ContentUnverifiable {
		t.Errorf("expected unverifiable for unknown type (no magic bytes known), got %v with actual=%q", verdict, actual)
	}
	if actual != "application/x-custom-unknown" {
		t.Errorf("expected claimed type echoed back, got actual=%q", actual)
	}

	// Residual, pinned deliberately: magic verification of truly unknown
	// formats is impossible in principle, so unregistered claims carrying
	// executable bytes also land on unverifiable (not mismatch). The
	// ContentVerdict distinction exists precisely so consumers never read
	// this class as verified.
	verdict, _ = VerifyContentType("application/x-unregistered-type", []byte{0x4D, 0x5A, 0x90, 0x00})
	if verdict != ContentUnverifiable {
		t.Errorf("expected unverifiable for unregistered claim with MZ bytes, got %v", verdict)
	}
}

func TestVerifyContentType_EmptyClaim(t *testing.T) {
	verdict, actual := VerifyContentType("", []byte("anything"))
	if verdict != ContentUnverifiable {
		t.Errorf("expected unverifiable for empty claim, got %v with actual=%q", verdict, actual)
	}
}

func TestVerifyContentType_TextPlain(t *testing.T) {
	// text/plain has no magic bytes — unverifiable, never "verified".
	verdict, actual := VerifyContentType("text/plain", []byte("any text data here"))
	if verdict != ContentUnverifiable {
		t.Errorf("expected unverifiable for text/plain (no magic bytes), got %v with actual=%q", verdict, actual)
	}
}

func TestVerifyContentType_HTML(t *testing.T) {
	verdict, actual := VerifyContentType("text/html", []byte("<!DOCTYPE html><html>"))
	if verdict != ContentVerified {
		t.Errorf("expected verified for HTML, got %v with actual=%q", verdict, actual)
	}
}

func TestVerifyContentType_HTML_Wrong(t *testing.T) {
	verdict, actual := VerifyContentType("text/html", []byte("Not HTML content at all"))
	if verdict != ContentMismatch {
		t.Errorf("expected mismatch for fake HTML, got %v with actual=%q", verdict, actual)
	}
}

func TestVerifyContentType_DisguisedExecutable(t *testing.T) {
	// PDF claim but actual content is an executable (MZ header)
	verdict, actual := VerifyContentType("application/pdf", []byte{0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00})
	if verdict != ContentMismatch {
		t.Errorf("expected mismatch for PDF claim with MZ executable bytes, got %v", verdict)
	}
	if actual != "application/x-msdownload" {
		t.Errorf("expected actual=%q, got %q", "application/x-msdownload", actual)
	}
}

func TestVerifyContentType_CaseInsensitive(t *testing.T) {
	verdict, actual := VerifyContentType("Application/PDF", []byte("%PDF-1.4"))
	if verdict != ContentVerified {
		t.Errorf("expected verified for case-insensitive MIME type, got %v with actual=%q", verdict, actual)
	}
}

func TestVerifyContentType_ImageTypeMismatch(t *testing.T) {
	// Claims PNG but is actually JPEG
	verdict, actual := VerifyContentType("image/png", []byte{0xFF, 0xD8, 0xFF, 0xE0})
	if verdict != ContentMismatch {
		t.Errorf("expected mismatch for PNG claim with JPEG data, got %v", verdict)
	}
	if actual != "image/jpeg" {
		t.Errorf("expected actual=%q, got %q", "image/jpeg", actual)
	}
}

func TestVerifyContentType_JSON(t *testing.T) {
	verdict, actual := VerifyContentType("application/json", []byte(`{"key":"value"}`))
	if verdict != ContentVerified {
		t.Errorf("expected verified for JSON (looks like JSON), got %v with actual=%q", verdict, actual)
	}
}

func TestVerifyContentType_XML(t *testing.T) {
	verdict, actual := VerifyContentType("application/xml", []byte("<?xml version=\"1.0\"?>"))
	if verdict != ContentVerified {
		t.Errorf("expected verified for XML, got %v with actual=%q", verdict, actual)
	}
}

func TestContentVerdictString(t *testing.T) {
	for v, want := range map[ContentVerdict]string{
		ContentUnverifiable: "unverifiable",
		ContentVerified:     "verified",
		ContentMismatch:     "mismatch",
		ContentVerdict(99):  "unverifiable",
	} {
		if got := v.String(); got != want {
			t.Errorf("ContentVerdict(%d).String() = %q, want %q", int(v), got, want)
		}
	}
}

// --- Straggler-wave gap tests: mismatch arms and truncated-magic pass-through ---

func TestVerifyContentType_TruncatedMagicPrefixPasses(t *testing.T) {
	// 7z magic is 6 bytes; 4 correct prefix bytes with no contradiction
	// pass through cautiously as verified (never scored as a mismatch).
	verdict, actual := VerifyContentType("application/x-7z-compressed", []byte{0x37, 0x7A, 0xBC, 0xAF})
	if verdict != ContentVerified {
		t.Errorf("expected verified for truncated 7z prefix, got %v with actual=%q", verdict, actual)
	}
}

func TestVerifyContentType_OOXML_NonZipHeader(t *testing.T) {
	// A claimed OOXML document whose bytes are not a ZIP container.
	verdict, actual := VerifyContentType(
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		[]byte("just text, not a docx"))
	if verdict != ContentMismatch {
		t.Errorf("expected mismatch for non-ZIP docx bytes, got %v with actual=%q", verdict, actual)
	}
}

func TestVerifyContentType_HTMLClaim_BinaryActual(t *testing.T) {
	verdict, actual := VerifyContentType("text/html", []byte("%PDF-1.4 fake"))
	if verdict != ContentMismatch {
		t.Errorf("expected mismatch, got %v", verdict)
	}
	if actual != "application/pdf" {
		t.Errorf("actual = %q, want application/pdf", actual)
	}
}

func TestVerifyContentType_JSONClaim_BinaryActual(t *testing.T) {
	verdict, actual := VerifyContentType("application/json", []byte{0x4D, 0x5A, 0x90, 0x00})
	if verdict != ContentMismatch {
		t.Errorf("expected mismatch for MZ bytes claiming JSON, got %v", verdict)
	}
	if actual != "application/x-msdownload" {
		t.Errorf("actual = %q, want application/x-msdownload", actual)
	}
}

func TestVerifyContentType_JSONClaim_PlainText(t *testing.T) {
	verdict, actual := VerifyContentType("application/json", []byte("hello, not json"))
	if verdict != ContentMismatch {
		t.Errorf("expected mismatch, got %v", verdict)
	}
	if actual != "text/plain" {
		t.Errorf("actual = %q, want text/plain", actual)
	}
}

func TestVerifyContentType_XMLClaim_BinaryActual(t *testing.T) {
	verdict, actual := VerifyContentType("application/xml", []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A})
	if verdict != ContentMismatch {
		t.Errorf("expected mismatch for PNG bytes claiming XML, got %v", verdict)
	}
	if actual != "image/png" {
		t.Errorf("actual = %q, want image/png", actual)
	}
}

func TestVerifyContentType_XMLClaim_PlainText(t *testing.T) {
	verdict, actual := VerifyContentType("text/xml", []byte("plain words only"))
	if verdict != ContentMismatch {
		t.Errorf("expected mismatch, got %v", verdict)
	}
	if actual != "text/plain" {
		t.Errorf("actual = %q, want text/plain", actual)
	}
}
