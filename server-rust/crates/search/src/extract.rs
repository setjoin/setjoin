//! Bounded pure-Rust permissive content extraction (`Wave 3.2`, `#557`).
//!
//! 100% permissive MIT/Apache-2.0/BSD dependencies (zero GPL, zero JVM/Tika,
//! zero C bindings, `#![forbid(unsafe_code)]`).
//!
//! Safety bounds:
//! - Input byte cap: [`MAX_EXTRACT_INPUT_BYTES`] (20 MiB)
//! - Decompressed ZIP cap: [`MAX_ZIP_DECOMPRESSED_BYTES`] (32 MiB)
//! - Zip-bomb ratio cap: [`MAX_ZIP_COMPRESSION_RATIO`] (`<= 100:1` above 64 KiB)
//! - Max ZIP entries: [`MAX_ZIP_ENTRIES`] (`<= 256`)
//! - Extracted text output cap: [`MAX_EXTRACTED_TEXT_BYTES`] (512 KiB, UTF-8 boundary safe)
//!
//! Every encrypted, unsupported, oversized, or corrupt input produces a structured
//! [`ExtractionResult`] with an explicit non-`Extracted` [`ExtractionStatus`] and
//! short non-PII `error_code` — NEVER panicking and NEVER aborting an indexing batch.

use encoding_rs::{Encoding, GB18030, SHIFT_JIS, UTF_16BE, UTF_16LE, WINDOWS_1252};
use flate2::read::ZlibDecoder;
use mail_parser::{MessageParser, MimeHeaders};
use quick_xml::events::Event;
use quick_xml::Reader as XmlReader;
use scraper::Html;
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read};
use zip::result::ZipError;
use zip::ZipArchive;

/// Current schema extractor version stamped into `public.search_extracted_text`.
pub const EXTRACTOR_VERSION: i16 = 1;

/// Hard input payload cap (20 MiB). Inputs larger than this yield `TruncatedLimit`.
pub const MAX_EXTRACT_INPUT_BYTES: usize = 20 * 1024 * 1024;

/// Hard decompressed byte cap across all inspected ZIP entries (32 MiB).
pub const MAX_ZIP_DECOMPRESSED_BYTES: usize = 32 * 1024 * 1024;

/// Maximum permitted decompression ratio (`decompressed / compressed`) above 64 KiB.
pub const MAX_ZIP_COMPRESSION_RATIO: usize = 100;

/// Minimum decompressed bytes before enforcing the compression-ratio zip-bomb check
/// (avoids false positives on tiny legitimate XML boilerplate inside small OOXML files).
const ZIP_BOMB_RATIO_MIN_BYTES: usize = 64 * 1024;

/// Maximum ZIP directory entries inspected in a single archive.
pub const MAX_ZIP_ENTRIES: usize = 256;

/// Hard extracted UTF-8 text output cap (512 KiB).
pub const MAX_EXTRACTED_TEXT_BYTES: usize = 512 * 1024;

/// Hard limit on PDF streams scanned in one document.
const MAX_PDF_STREAMS: usize = 512;

/// Hard cap on aggregate decompressed PDF content-stream bytes (16 MiB).
const MAX_PDF_DECOMPRESSED_BYTES: usize = 16 * 1024 * 1024;

/// OLE2 Compound File Binary magic header (`D0 CF 11 E0 A1 B1 1A E1`).
const OLE2_MAGIC: &[u8] = &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// Storage plane discriminator for `public.search_extracted_text`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractionStoragePlane {
    Blob,
    DriveFileVersion,
}

impl ExtractionStoragePlane {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Blob => "blob",
            Self::DriveFileVersion => "drive_file_version",
        }
    }

    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "blob" => Some(Self::Blob),
            "drive_file_version" => Some(Self::DriveFileVersion),
            _ => None,
        }
    }
}

/// Terminal classification recorded in `public.search_extracted_text.extraction_status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractionStatus {
    Extracted,
    Encrypted,
    Unsupported,
    TruncatedLimit,
    Failed,
}

impl ExtractionStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Extracted => "extracted",
            Self::Encrypted => "encrypted",
            Self::Unsupported => "unsupported",
            Self::TruncatedLimit => "truncated_limit",
            Self::Failed => "failed",
        }
    }

    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "extracted" => Some(Self::Extracted),
            "encrypted" => Some(Self::Encrypted),
            "unsupported" => Some(Self::Unsupported),
            "truncated_limit" => Some(Self::TruncatedLimit),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }

    /// Returns `true` when extracted text is eligible to be indexed into Tantivy.
    #[must_use]
    pub const fn has_indexable_text(self) -> bool {
        matches!(self, Self::Extracted | Self::TruncatedLimit)
    }
}

/// Result of running the bounded content extractor over raw file bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtractionResult {
    pub status: ExtractionStatus,
    pub extractor_version: i16,
    pub extracted_text: Option<String>,
    pub extracted_bytes: usize,
    pub detected_mime: Option<String>,
    pub error_code: Option<String>,
}

impl ExtractionResult {
    #[must_use]
    pub fn extracted(text: String, detected_mime: Option<String>) -> Self {
        let cleaned = sanitize_extracted_text(&text);
        let (final_text, truncated) = truncate_utf8_owned(cleaned, MAX_EXTRACTED_TEXT_BYTES);
        let len = final_text.len();
        if truncated {
            Self {
                status: ExtractionStatus::TruncatedLimit,
                extractor_version: EXTRACTOR_VERSION,
                extracted_text: Some(final_text),
                extracted_bytes: len,
                detected_mime,
                error_code: Some("extracted_text_truncated".to_owned()),
            }
        } else {
            Self {
                status: ExtractionStatus::Extracted,
                extractor_version: EXTRACTOR_VERSION,
                extracted_text: Some(final_text),
                extracted_bytes: len,
                detected_mime,
                error_code: None,
            }
        }
    }

    #[must_use]
    pub fn encrypted(detected_mime: Option<String>, code: &'static str) -> Self {
        Self {
            status: ExtractionStatus::Encrypted,
            extractor_version: EXTRACTOR_VERSION,
            extracted_text: None,
            extracted_bytes: 0,
            detected_mime,
            error_code: Some(code.to_owned()),
        }
    }

    #[must_use]
    pub fn unsupported(detected_mime: Option<String>, code: &'static str) -> Self {
        Self {
            status: ExtractionStatus::Unsupported,
            extractor_version: EXTRACTOR_VERSION,
            extracted_text: None,
            extracted_bytes: 0,
            detected_mime,
            error_code: Some(code.to_owned()),
        }
    }

    #[must_use]
    pub fn truncated_input(detected_mime: Option<String>, code: &'static str) -> Self {
        Self {
            status: ExtractionStatus::TruncatedLimit,
            extractor_version: EXTRACTOR_VERSION,
            extracted_text: None,
            extracted_bytes: 0,
            detected_mime,
            error_code: Some(code.to_owned()),
        }
    }

    #[must_use]
    pub fn truncated_text(text: String, detected_mime: Option<String>, code: &'static str) -> Self {
        let cleaned = sanitize_extracted_text(&text);
        let (final_text, _) = truncate_utf8_owned(cleaned, MAX_EXTRACTED_TEXT_BYTES);
        let len = final_text.len();
        Self {
            status: ExtractionStatus::TruncatedLimit,
            extractor_version: EXTRACTOR_VERSION,
            extracted_text: Some(final_text),
            extracted_bytes: len,
            detected_mime,
            error_code: Some(code.to_owned()),
        }
    }

    #[must_use]
    pub fn failed(detected_mime: Option<String>, code: &'static str) -> Self {
        Self {
            status: ExtractionStatus::Failed,
            extractor_version: EXTRACTOR_VERSION,
            extracted_text: None,
            extracted_bytes: 0,
            detected_mime,
            error_code: Some(code.to_owned()),
        }
    }
}

/// Extract searchable text from raw bytes using strict memory, ratio, and output caps.
#[must_use]
pub fn extract_bytes(
    bytes: &[u8],
    content_type: Option<&str>,
    filename: Option<&str>,
) -> ExtractionResult {
    let base_mime = normalize_mime(content_type);
    let ext = filename_extension(filename);

    // 1. S/MIME encrypted payloads are immediately classified Encrypted (V029 C7).
    if is_smime_encrypted_hint(base_mime.as_deref(), ext.as_deref()) {
        return ExtractionResult::encrypted(
            base_mime.or_else(|| Some("application/pkcs7-mime".to_owned())),
            "smime_encrypted",
        );
    }

    // 2. Hard 20 MiB input cap -> TruncatedLimit (filename/headers remain indexed).
    if bytes.len() > MAX_EXTRACT_INPUT_BYTES {
        return ExtractionResult::truncated_input(base_mime, "input_size_limit_exceeded");
    }

    if bytes.is_empty() {
        return ExtractionResult::extracted(String::new(), base_mime);
    }

    // 3. OLE2 Compound File -> detect EncryptedPackage vs unsupported legacy binary.
    if bytes.starts_with(OLE2_MAGIC) {
        if contains_ole2_encryption_marker(bytes) {
            return ExtractionResult::encrypted(
                base_mime.or_else(|| Some("application/x-ole-storage".to_owned())),
                "ole2_encrypted",
            );
        }
        return ExtractionResult::unsupported(
            base_mime.or_else(|| Some("application/x-ole-storage".to_owned())),
            "ole2_unsupported",
        );
    }

    // 4. PDF by magic or MIME/extension.
    if has_pdf_header(bytes)
        || base_mime.as_deref() == Some("application/pdf")
        || ext.as_deref() == Some("pdf")
    {
        return extract_pdf(bytes, base_mime);
    }

    // 5. ZIP / OOXML / ODF by magic or MIME/extension.
    if looks_like_zip_magic(bytes) || is_ooxml_or_odf_or_zip(base_mime.as_deref(), ext.as_deref()) {
        return extract_zip_container(bytes, base_mime, ext.as_deref());
    }

    // 6. RFC 5322 `.eml` messages.
    if base_mime.as_deref() == Some("message/rfc822") || ext.as_deref() == Some("eml") {
        return extract_eml(bytes, base_mime);
    }

    // 7. HTML / XHTML.
    if matches!(
        base_mime.as_deref(),
        Some("text/html" | "application/xhtml+xml")
    ) || matches!(ext.as_deref(), Some("html" | "htm" | "xhtml"))
    {
        let decoded = decode_text_bytes(bytes, content_type);
        let text = extract_html_text(&decoded);
        return ExtractionResult::extracted(
            text,
            base_mime.or_else(|| Some("text/html".to_owned())),
        );
    }

    // 8. Known unsupported binary media/executables.
    if is_known_binary(bytes, base_mime.as_deref(), ext.as_deref()) {
        return ExtractionResult::unsupported(
            base_mime.or_else(|| sniff_binary_mime(bytes)),
            "unsupported_binary_format",
        );
    }

    // 9. XML documents.
    if matches!(base_mime.as_deref(), Some("application/xml" | "text/xml"))
        || ext.as_deref() == Some("xml")
    {
        let decoded = decode_text_bytes(bytes, content_type);
        let text = extract_generic_xml_text(&decoded).unwrap_or(decoded);
        return ExtractionResult::extracted(
            text,
            base_mime.or_else(|| Some("application/xml".to_owned())),
        );
    }

    // 10. Plain text / Markdown / CSV / TSV / JSON / source files.
    if is_text_like_hint(base_mime.as_deref(), ext.as_deref()) {
        if looks_binary_payload(bytes) {
            return ExtractionResult::unsupported(
                base_mime.or_else(|| Some("application/octet-stream".to_owned())),
                "binary_payload_in_text_hint",
            );
        }
        let decoded = decode_text_bytes(bytes, content_type);
        return ExtractionResult::extracted(
            decoded,
            base_mime.or_else(|| Some("text/plain".to_owned())),
        );
    }

    ExtractionResult::unsupported(
        base_mime.or_else(|| Some("application/octet-stream".to_owned())),
        "unsupported_format",
    )
}

/// UTF-8 char-boundary safe truncation returning `(text, was_truncated)`.
#[must_use]
pub fn truncate_utf8_owned(mut input: String, max_bytes: usize) -> (String, bool) {
    if input.len() <= max_bytes {
        return (input, false);
    }
    let mut end = max_bytes;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    input.truncate(end);
    (input, true)
}

fn sanitize_extracted_text(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().min(MAX_EXTRACTED_TEXT_BYTES + 256));
    let mut last_was_space = true;
    for ch in raw.chars() {
        if ch == '\0' {
            continue;
        }
        if ch == '\n' || ch == '\r' {
            if !last_was_space {
                out.push('\n');
                last_was_space = true;
            }
        } else if ch.is_whitespace() {
            if !last_was_space {
                out.push(' ');
                last_was_space = true;
            }
        } else if !ch.is_control() {
            out.push(ch);
            last_was_space = false;
        }
        // Early stop slightly past cap so callers still know truncation occurred.
        if out.len() > MAX_EXTRACTED_TEXT_BYTES + 64 {
            break;
        }
    }
    out.trim().to_owned()
}

fn normalize_mime(content_type: Option<&str>) -> Option<String> {
    content_type
        .and_then(|ct| ct.split(';').next())
        .map(|base| base.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
}

fn extract_charset_param(content_type: Option<&str>) -> Option<String> {
    let ct = content_type?;
    for part in ct.split(';').skip(1) {
        let trimmed = part.trim();
        if let Some((k, v)) = trimmed.split_once('=') {
            if k.trim().eq_ignore_ascii_case("charset") {
                let val = v.trim().trim_matches('"').trim_matches('\'');
                if !val.is_empty() {
                    return Some(val.to_owned());
                }
            }
        }
    }
    None
}

fn filename_extension(filename: Option<&str>) -> Option<String> {
    let name = filename?.trim();
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let (_, ext) = base.rsplit_once('.')?;
    let lowered = ext.trim().to_ascii_lowercase();
    if lowered.is_empty() {
        None
    } else {
        Some(lowered)
    }
}

fn is_smime_encrypted_hint(mime: Option<&str>, ext: Option<&str>) -> bool {
    matches!(
        mime,
        Some(
            "application/pkcs7-mime"
                | "application/x-pkcs7-mime"
                | "application/pkcs7-enveloped"
                | "smime-encrypted"
        )
    ) || matches!(ext, Some("p7m" | "p7e"))
}

fn contains_ole2_encryption_marker(bytes: &[u8]) -> bool {
    const UTF16_ENCRYPTED_PACKAGE: &[u8] = b"E\0n\0c\0r\0y\0p\0t\0e\0d\0P\0a\0c\0k\0a\0g\0e\0";
    const UTF16_ENCRYPTION_INFO: &[u8] = b"E\0n\0c\0r\0y\0p\0t\0i\0o\0n\0I\0n\0f\0o\0";
    find_subslice(bytes, UTF16_ENCRYPTED_PACKAGE).is_some()
        || find_subslice(bytes, UTF16_ENCRYPTION_INFO).is_some()
}

fn looks_like_zip_magic(bytes: &[u8]) -> bool {
    bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || bytes.starts_with(b"PK\x07\x08")
}

fn is_ooxml_or_odf_or_zip(mime: Option<&str>, ext: Option<&str>) -> bool {
    matches!(
        ext,
        Some("docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp" | "zip")
    ) || matches!(
        mime,
        Some(
            "application/zip"
                | "application/x-zip-compressed"
                | "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                | "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                | "application/vnd.openxmlformats-officedocument.presentationml.presentation"
                | "application/vnd.oasis.opendocument.text"
                | "application/vnd.oasis.opendocument.spreadsheet"
                | "application/vnd.oasis.opendocument.presentation"
        )
    )
}

fn is_known_binary(bytes: &[u8], mime: Option<&str>, ext: Option<&str>) -> bool {
    if let Some(m) = mime {
        if m.starts_with("image/")
            || m.starts_with("video/")
            || m.starts_with("audio/")
            || m.starts_with("font/")
            || matches!(
                m,
                "application/wasm"
                    | "application/x-executable"
                    | "application/x-mach-binary"
                    | "application/x-dosexec"
                    | "application/gzip"
                    | "application/x-tar"
                    | "application/x-7z-compressed"
                    | "application/vnd.rar"
            )
        {
            return true;
        }
    }
    if matches!(
        ext,
        Some(
            "png"
                | "jpg"
                | "jpeg"
                | "gif"
                | "webp"
                | "bmp"
                | "ico"
                | "tif"
                | "tiff"
                | "mp4"
                | "mov"
                | "avi"
                | "mkv"
                | "webm"
                | "mp3"
                | "wav"
                | "flac"
                | "ogg"
                | "exe"
                | "dll"
                | "so"
                | "dylib"
                | "wasm"
                | "bin"
                | "gz"
                | "tar"
                | "7z"
                | "rar"
                | "woff"
                | "woff2"
                | "ttf"
                | "otf"
        )
    ) {
        return true;
    }
    sniff_binary_mime(bytes).is_some()
}

fn sniff_binary_mime(bytes: &[u8]) -> Option<String> {
    if bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        return Some("image/png".to_owned());
    }
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some("image/jpeg".to_owned());
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return Some("image/gif".to_owned());
    }
    if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return Some("image/webp".to_owned());
    }
    if bytes.len() >= 12 && &bytes[4..8] == b"ftyp" {
        return Some("video/mp4".to_owned());
    }
    if bytes.starts_with(b"\x7fELF") {
        return Some("application/x-elf".to_owned());
    }
    if bytes.starts_with(b"MZ") && bytes.len() >= 64 && bytes.iter().take(64).any(|b| *b == 0) {
        return Some("application/x-dosexec".to_owned());
    }
    if bytes.starts_with(b"\x00asm") {
        return Some("application/wasm".to_owned());
    }
    None
}

fn is_text_like_hint(mime: Option<&str>, ext: Option<&str>) -> bool {
    if let Some(m) = mime {
        if m.starts_with("text/")
            || matches!(
                m,
                "application/json"
                    | "application/ld+json"
                    | "application/javascript"
                    | "application/ecmascript"
                    | "application/yaml"
                    | "application/x-yaml"
                    | "application/toml"
                    | "application/sql"
                    | "application/csv"
            )
        {
            return true;
        }
    }
    matches!(
        ext,
        Some(
            "txt"
                | "md"
                | "markdown"
                | "csv"
                | "tsv"
                | "json"
                | "jsonl"
                | "yaml"
                | "yml"
                | "toml"
                | "ini"
                | "cfg"
                | "conf"
                | "log"
                | "rs"
                | "py"
                | "js"
                | "ts"
                | "tsx"
                | "jsx"
                | "go"
                | "java"
                | "c"
                | "h"
                | "cpp"
                | "hpp"
                | "sh"
                | "bash"
                | "sql"
                | "css"
                | "scss"
                | "svg"
                | "ics"
                | "vcf"
        )
    )
}

fn looks_binary_payload(bytes: &[u8]) -> bool {
    // Allow UTF-16 BOM payloads through to decode_text_bytes.
    if bytes.starts_with(&[0xFF, 0xFE]) || bytes.starts_with(&[0xFE, 0xFF]) {
        return false;
    }
    let sample = &bytes[..bytes.len().min(4096)];
    if sample.is_empty() {
        return false;
    }
    let nul_count = sample.iter().filter(|&&b| b == 0).count();
    if nul_count > 0 {
        return true;
    }
    let ctrl_count = sample
        .iter()
        .filter(|&&b| b < 0x09 || (b > 0x0D && b < 0x20))
        .count();
    ctrl_count * 10 > sample.len()
}

/// Decode raw text bytes supporting UTF-8, UTF-16LE/BE BOM, explicit `charset=`,
/// GB18030, Shift-JIS, and Windows-1252.
#[must_use]
pub fn decode_text_bytes(bytes: &[u8], content_type: Option<&str>) -> String {
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8_lossy(rest).into_owned();
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        let (cow, _, _) = UTF_16LE.decode(rest);
        return cow.into_owned();
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        let (cow, _, _) = UTF_16BE.decode(rest);
        return cow.into_owned();
    }
    if let Some(label) = extract_charset_param(content_type) {
        if let Some(enc) = Encoding::for_label(label.as_bytes()) {
            let (cow, _, _) = enc.decode(bytes);
            return cow.into_owned();
        }
    }
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_owned();
    }
    let (gb_cow, _, gb_had_errors) = GB18030.decode(bytes);
    if !gb_had_errors {
        return gb_cow.into_owned();
    }
    let (sjis_cow, _, sjis_had_errors) = SHIFT_JIS.decode(bytes);
    if !sjis_had_errors {
        return sjis_cow.into_owned();
    }
    let (win_cow, _, _) = WINDOWS_1252.decode(bytes);
    win_cow.into_owned()
}

/// Extract visible text from HTML, stripping `<script>`, `<style>`, `<noscript>`, `<template>`.
#[must_use]
pub fn extract_html_text(html: &str) -> String {
    let doc = Html::parse_document(html);
    let mut out = String::with_capacity(html.len().min(MAX_EXTRACTED_TEXT_BYTES + 256));
    let mut stack = vec![(doc.tree.root(), false)];
    while let Some((node, closing)) = stack.pop() {
        if out.len() > MAX_EXTRACTED_TEXT_BYTES + 256 {
            break;
        }
        match node.value() {
            scraper::Node::Element(el) => {
                let name = el.name();
                if name.eq_ignore_ascii_case("script")
                    || name.eq_ignore_ascii_case("style")
                    || name.eq_ignore_ascii_case("noscript")
                    || name.eq_ignore_ascii_case("template")
                {
                    continue;
                }
                let is_block = matches!(
                    name.to_ascii_lowercase().as_str(),
                    "p" | "div"
                        | "br"
                        | "li"
                        | "tr"
                        | "td"
                        | "th"
                        | "h1"
                        | "h2"
                        | "h3"
                        | "h4"
                        | "h5"
                        | "h6"
                        | "section"
                        | "article"
                        | "header"
                        | "footer"
                );
                if closing {
                    if is_block && !out.is_empty() && !out.ends_with('\n') {
                        out.push('\n');
                    }
                    continue;
                }
                if is_block && !out.is_empty() && !out.ends_with('\n') {
                    out.push('\n');
                }
                stack.push((node, true));
                let children: Vec<_> = node.children().collect();
                for child in children.into_iter().rev() {
                    stack.push((child, false));
                }
            }
            scraper::Node::Text(t) => {
                out.push_str(&t.text);
                out.push(' ');
            }
            _ => {
                if !closing {
                    let children: Vec<_> = node.children().collect();
                    for child in children.into_iter().rev() {
                        stack.push((child, false));
                    }
                }
            }
        }
    }
    sanitize_extracted_text(&out)
}

fn extract_eml(bytes: &[u8], base_mime: Option<String>) -> ExtractionResult {
    let mime = base_mime.or_else(|| Some("message/rfc822".to_owned()));
    let Some(msg) = MessageParser::default().parse(bytes) else {
        return ExtractionResult::failed(mime, "eml_parse_failed");
    };

    // Check top-level S/MIME encryption content types.
    if let Some(ct) = msg.content_type() {
        let full_ct = match ct.subtype() {
            Some(sub) => format!("{}/{}", ct.ctype(), sub).to_ascii_lowercase(),
            None => ct.ctype().to_ascii_lowercase(),
        };
        if full_ct == "application/pkcs7-mime"
            || full_ct == "application/x-pkcs7-mime"
            || full_ct == "multipart/encrypted"
        {
            return ExtractionResult::encrypted(Some(full_ct), "smime_encrypted");
        }
    }

    let mut out = String::new();
    if let Some(subj) = msg.subject() {
        out.push_str(subj);
        out.push('\n');
    }
    if let Some(text) = msg.body_text(0) {
        out.push_str(text.as_ref());
        out.push('\n');
    } else if let Some(html) = msg.body_html(0) {
        out.push_str(&extract_html_text(html.as_ref()));
        out.push('\n');
    }
    ExtractionResult::extracted(out, mime)
}

fn zip_eocd_entry_count(bytes: &[u8]) -> Option<usize> {
    // End-of-Central-Directory (EOCD) is 22 bytes + up to 65,535 bytes comment.
    // Match zip-9.2.2's backward scan even when trailing bytes follow the EOCD
    // (`pos + EOCD_MIN_LEN + comment_len <= bytes.len()`), and inspect ZIP64 EOCD
    // (`PK\x06\x07` / `PK\x06\x06`) whenever 16-bit counters hold the 0xFFFF sentinel.
    const EOCD_MIN_LEN: usize = 22;
    const ZIP64_LOCATOR_LEN: usize = 20;
    const MAX_EOCD_SCAN: usize = EOCD_MIN_LEN + 65_535;
    if bytes.len() < EOCD_MIN_LEN {
        return None;
    }
    let start = bytes.len().saturating_sub(MAX_EOCD_SCAN);
    let mut pos = bytes.len() - EOCD_MIN_LEN;
    loop {
        if &bytes[pos..pos + 4] == b"PK\x05\x06" {
            let comment_len = u16::from_le_bytes([bytes[pos + 20], bytes[pos + 21]]) as usize;
            if pos.saturating_add(EOCD_MIN_LEN).saturating_add(comment_len) <= bytes.len() {
                let disk_entries = u16::from_le_bytes([bytes[pos + 8], bytes[pos + 9]]) as usize;
                let total_entries = u16::from_le_bytes([bytes[pos + 10], bytes[pos + 11]]) as usize;
                let mut count = disk_entries.max(total_entries);
                // ZIP64 sentinel (0xFFFF) or preceding ZIP64 EOCD locator (`PK\x06\x07`).
                if count == 0xFFFF
                    || (pos >= ZIP64_LOCATOR_LEN
                        && &bytes[pos - ZIP64_LOCATOR_LEN..pos - ZIP64_LOCATOR_LEN + 4]
                            == b"PK\x06\x07")
                {
                    if pos >= ZIP64_LOCATOR_LEN
                        && &bytes[pos - ZIP64_LOCATOR_LEN..pos - ZIP64_LOCATOR_LEN + 4]
                            == b"PK\x06\x07"
                    {
                        let loc = pos - ZIP64_LOCATOR_LEN;
                        let z64_off = u64::from_le_bytes([
                            bytes[loc + 8],
                            bytes[loc + 9],
                            bytes[loc + 10],
                            bytes[loc + 11],
                            bytes[loc + 12],
                            bytes[loc + 13],
                            bytes[loc + 14],
                            bytes[loc + 15],
                        ]) as usize;
                        if z64_off.saturating_add(40) <= bytes.len()
                            && &bytes[z64_off..z64_off + 4] == b"PK\x06\x06"
                        {
                            let z64_disk = u64::from_le_bytes([
                                bytes[z64_off + 24],
                                bytes[z64_off + 25],
                                bytes[z64_off + 26],
                                bytes[z64_off + 27],
                                bytes[z64_off + 28],
                                bytes[z64_off + 29],
                                bytes[z64_off + 30],
                                bytes[z64_off + 31],
                            ]);
                            let z64_total = u64::from_le_bytes([
                                bytes[z64_off + 32],
                                bytes[z64_off + 33],
                                bytes[z64_off + 34],
                                bytes[z64_off + 35],
                                bytes[z64_off + 36],
                                bytes[z64_off + 37],
                                bytes[z64_off + 38],
                                bytes[z64_off + 39],
                            ]);
                            count = z64_disk.max(z64_total).min(usize::MAX as u64) as usize;
                        } else if count == 0xFFFF {
                            count = MAX_ZIP_ENTRIES.saturating_add(1);
                        }
                    } else if count == 0xFFFF {
                        count = MAX_ZIP_ENTRIES.saturating_add(1);
                    }
                }
                return Some(count);
            }
        }
        if pos == start {
            break;
        }
        pos -= 1;
    }
    None
}

fn extract_zip_container(
    bytes: &[u8],
    base_mime: Option<String>,
    ext: Option<&str>,
) -> ExtractionResult {
    // Quick check for encrypted local file header bit 0 (flag & 0x0001).
    if bytes.len() >= 8 && bytes.starts_with(b"PK\x03\x04") {
        let flags = u16::from_le_bytes([bytes[6], bytes[7]]);
        if (flags & 0x0001) != 0 {
            return ExtractionResult::encrypted(
                base_mime.or_else(|| Some("application/zip".to_owned())),
                "zip_encrypted",
            );
        }
    }

    // Inspect ZIP EOCD entry count BEFORE ZipArchive::new parses the central directory.
    if let Some(eocd_entries) = zip_eocd_entry_count(bytes) {
        if eocd_entries > MAX_ZIP_ENTRIES {
            return ExtractionResult::failed(
                base_mime.or_else(|| Some("application/zip".to_owned())),
                "zip_too_many_entries",
            );
        }
    }

    let mut archive = match ZipArchive::new(Cursor::new(bytes)) {
        Ok(a) => a,
        Err(ZipError::UnsupportedArchive(msg))
            if msg.to_ascii_lowercase().contains("password")
                || msg.to_ascii_lowercase().contains("encrypt") =>
        {
            return ExtractionResult::encrypted(
                base_mime.or_else(|| Some("application/zip".to_owned())),
                "zip_encrypted",
            );
        }
        Err(_) => {
            return ExtractionResult::failed(
                base_mime.or_else(|| Some("application/zip".to_owned())),
                "zip_corrupt",
            );
        }
    };

    let entry_count = archive.len();
    if entry_count > MAX_ZIP_ENTRIES {
        return ExtractionResult::failed(
            base_mime.or_else(|| Some("application/zip".to_owned())),
            "zip_too_many_entries",
        );
    }

    let mut names: Vec<String> = Vec::with_capacity(entry_count);
    let mut declared_total: u64 = 0;
    for idx in 0..entry_count {
        match archive.by_index_raw(idx) {
            Ok(raw) => {
                if raw.encrypted() {
                    return ExtractionResult::encrypted(
                        base_mime.or_else(|| Some("application/zip".to_owned())),
                        "zip_encrypted",
                    );
                }
                let raw_size = raw.size();
                let comp_size = raw.compressed_size();
                declared_total = declared_total.saturating_add(raw_size);
                if declared_total > MAX_ZIP_DECOMPRESSED_BYTES as u64 {
                    return ExtractionResult::failed(
                        base_mime.or_else(|| Some("application/zip".to_owned())),
                        "zip_bomb_declared_size",
                    );
                }
                if raw_size > ZIP_BOMB_RATIO_MIN_BYTES as u64
                    && (comp_size == 0
                        || raw_size > comp_size.saturating_mul(MAX_ZIP_COMPRESSION_RATIO as u64))
                {
                    return ExtractionResult::failed(
                        base_mime.or_else(|| Some("application/zip".to_owned())),
                        "zip_bomb_ratio",
                    );
                }
                let entry_name = match raw.name() {
                    Ok(n) => n.into_owned(),
                    Err(_) => {
                        return ExtractionResult::failed(
                            base_mime.or_else(|| Some("application/zip".to_owned())),
                            "zip_corrupt_entry_name",
                        );
                    }
                };
                names.push(entry_name);
            }
            Err(_) => {
                return ExtractionResult::failed(
                    base_mime.or_else(|| Some("application/zip".to_owned())),
                    "zip_corrupt_entry",
                );
            }
        }
    }

    // Share ONE decompression budget across META-INF/manifest.xml AND content entries.
    let mut remaining_budget = MAX_ZIP_DECOMPRESSED_BYTES;

    // ODF encryption check (`META-INF/manifest.xml` containing `encryption-data`).
    if names.iter().any(|n| n == "META-INF/manifest.xml") {
        let odf_mime = base_mime
            .clone()
            .or_else(|| Some("application/vnd.oasis.opendocument.text".to_owned()));
        match read_zip_entry_bounded(&mut archive, "META-INF/manifest.xml", &mut remaining_budget) {
            Ok(manifest_bytes) => {
                if find_subslice(&manifest_bytes, b"encryption-data").is_some() {
                    return ExtractionResult::encrypted(odf_mime, "odf_encrypted");
                }
            }
            Err(ZipReadFailure::Encrypted) => {
                return ExtractionResult::encrypted(odf_mime, "odf_encrypted");
            }
            Err(ZipReadFailure::Bomb(code)) => {
                return ExtractionResult::failed(odf_mime, code);
            }
            Err(ZipReadFailure::Corrupt) => {
                return ExtractionResult::failed(odf_mime, "zip_corrupt_manifest");
            }
        }
    }

    // Dispatch OOXML / ODF based on internal structure.
    let has_docx = names.iter().any(|n| n == "word/document.xml");
    let has_xlsx = names.iter().any(|n| {
        n == "xl/sharedStrings.xml" || (n.starts_with("xl/worksheets/") && n.ends_with(".xml"))
    });
    let has_pptx = names
        .iter()
        .any(|n| n.starts_with("ppt/slides/slide") && n.ends_with(".xml"));
    let has_odf = names.iter().any(|n| n == "content.xml");

    if has_docx {
        let mut targets: Vec<String> = names
            .iter()
            .filter(|n| {
                *n == "word/document.xml"
                    || (n.starts_with("word/header") && n.ends_with(".xml"))
                    || (n.starts_with("word/footer") && n.ends_with(".xml"))
                    || *n == "word/footnotes.xml"
            })
            .cloned()
            .collect();
        targets.sort();
        targets.dedup();
        return extract_xml_entries(
            &mut archive,
            &targets,
            &mut remaining_budget,
            base_mime.or_else(|| {
                Some(
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                        .to_owned(),
                )
            }),
            extract_ooxml_word_text,
        );
    }

    if has_xlsx {
        let mut targets: Vec<String> = Vec::new();
        if names.iter().any(|n| n == "xl/sharedStrings.xml") {
            targets.push("xl/sharedStrings.xml".to_owned());
        }
        let mut sheets: Vec<String> = names
            .iter()
            .filter(|n| n.starts_with("xl/worksheets/") && n.ends_with(".xml"))
            .cloned()
            .collect();
        sheets.sort();
        sheets.dedup();
        targets.extend(sheets);
        return extract_xml_entries(
            &mut archive,
            &targets,
            &mut remaining_budget,
            base_mime.or_else(|| {
                Some("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet".to_owned())
            }),
            extract_ooxml_xlsx_text,
        );
    }

    if has_pptx {
        let mut slides: Vec<String> = names
            .iter()
            .filter(|n| n.starts_with("ppt/slides/slide") && n.ends_with(".xml"))
            .cloned()
            .collect();
        slides.sort();
        slides.dedup();
        return extract_xml_entries(
            &mut archive,
            &slides,
            &mut remaining_budget,
            base_mime.or_else(|| {
                Some(
                    "application/vnd.openxmlformats-officedocument.presentationml.presentation"
                        .to_owned(),
                )
            }),
            extract_ooxml_pptx_text,
        );
    }

    if has_odf {
        let targets = vec!["content.xml".to_owned()];
        return extract_xml_entries(
            &mut archive,
            &targets,
            &mut remaining_budget,
            base_mime.or_else(|| Some("application/vnd.oasis.opendocument.text".to_owned())),
            extract_odf_content_text,
        );
    }

    // If caller declared an OOXML/ODF extension but archive lacked expected parts, fail cleanly.
    if matches!(ext, Some("docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp")) {
        return ExtractionResult::failed(base_mime, "office_container_missing_content");
    }

    // Generic unencrypted ZIP archive: mark unsupported.
    ExtractionResult::unsupported(
        base_mime.or_else(|| Some("application/zip".to_owned())),
        "zip_archive_unsupported",
    )
}

enum ZipReadFailure {
    Encrypted,
    Bomb(&'static str),
    Corrupt,
}

fn read_zip_entry_bounded(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    name: &str,
    remaining_budget: &mut usize,
) -> Result<Vec<u8>, ZipReadFailure> {
    let file = match archive.by_name(name) {
        Ok(f) => f,
        Err(ZipError::UnsupportedArchive(msg))
            if msg.to_ascii_lowercase().contains("password")
                || msg.to_ascii_lowercase().contains("encrypt") =>
        {
            return Err(ZipReadFailure::Encrypted);
        }
        Err(_) => return Err(ZipReadFailure::Corrupt),
    };
    if file.encrypted() {
        return Err(ZipReadFailure::Encrypted);
    }
    let compressed_size = file.compressed_size() as usize;
    let limit = (*remaining_budget).saturating_add(1) as u64;
    let mut limited = file.take(limit);
    let mut buf = Vec::new();
    if limited.read_to_end(&mut buf).is_err() {
        return Err(ZipReadFailure::Corrupt);
    }
    if buf.len() > *remaining_budget {
        return Err(ZipReadFailure::Bomb("zip_bomb_decompressed_limit"));
    }
    if buf.len() > ZIP_BOMB_RATIO_MIN_BYTES
        && (compressed_size == 0
            || buf.len() > compressed_size.saturating_mul(MAX_ZIP_COMPRESSION_RATIO))
    {
        return Err(ZipReadFailure::Bomb("zip_bomb_ratio"));
    }
    *remaining_budget = remaining_budget.saturating_sub(buf.len());
    Ok(buf)
}

fn extract_xml_entries(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    targets: &[String],
    remaining_budget: &mut usize,
    detected_mime: Option<String>,
    parser: fn(&[u8], &mut String) -> Result<(), ()>,
) -> ExtractionResult {
    let mut out = String::new();
    for name in targets {
        match read_zip_entry_bounded(archive, name, remaining_budget) {
            Ok(xml_bytes) => {
                if parser(&xml_bytes, &mut out).is_err() {
                    return ExtractionResult::failed(detected_mime, "xml_parse_failed");
                }
                if !out.ends_with('\n') {
                    out.push('\n');
                }
                if out.len() > MAX_EXTRACTED_TEXT_BYTES + 256 {
                    break;
                }
            }
            Err(ZipReadFailure::Encrypted) => {
                return ExtractionResult::encrypted(detected_mime, "zip_encrypted");
            }
            Err(ZipReadFailure::Bomb(code)) => {
                return ExtractionResult::failed(detected_mime, code);
            }
            Err(ZipReadFailure::Corrupt) => {
                return ExtractionResult::failed(detected_mime, "zip_corrupt_entry");
            }
        }
    }
    ExtractionResult::extracted(out, detected_mime)
}

fn xml_local_name(raw: &[u8]) -> &[u8] {
    match raw.iter().rposition(|&b| b == b':') {
        Some(pos) => &raw[pos + 1..],
        None => raw,
    }
}

fn extract_ooxml_word_text(xml: &[u8], out: &mut String) -> Result<(), ()> {
    let mut reader = XmlReader::from_reader(xml);
    let mut buf = Vec::new();
    let mut in_text = false;
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let qname = e.name();
                let local = xml_local_name(qname.as_ref());
                if local == b"t" || local == b"instrText" {
                    in_text = true;
                } else if local == b"p" && !out.is_empty() && !out.ends_with('\n') {
                    out.push('\n');
                }
            }
            Ok(Event::Empty(e)) => {
                let qname = e.name();
                let local = xml_local_name(qname.as_ref());
                if local == b"tab" {
                    out.push(' ');
                } else if local == b"br" || local == b"cr" {
                    out.push('\n');
                }
            }
            Ok(Event::End(e)) => {
                let qname = e.name();
                let local = xml_local_name(qname.as_ref());
                if local == b"t" || local == b"instrText" {
                    in_text = false;
                } else if local == b"p" && !out.ends_with('\n') {
                    out.push('\n');
                }
            }
            Ok(Event::Text(e)) if in_text => {
                if let Ok(text) = e.decode() {
                    out.push_str(&text);
                }
            }
            Ok(Event::CData(e)) if in_text => {
                if let Ok(text) = std::str::from_utf8(e.as_ref()) {
                    out.push_str(text);
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return Err(()),
            _ => {}
        }
        buf.clear();
        if out.len() > MAX_EXTRACTED_TEXT_BYTES + 256 {
            break;
        }
    }
    Ok(())
}

fn extract_ooxml_xlsx_text(xml: &[u8], out: &mut String) -> Result<(), ()> {
    let mut reader = XmlReader::from_reader(xml);
    let mut buf = Vec::new();
    let mut in_text = false;
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let qname = e.name();
                let local = xml_local_name(qname.as_ref());
                if local == b"t" || local == b"v" {
                    in_text = true;
                }
            }
            Ok(Event::End(e)) => {
                let qname = e.name();
                let local = xml_local_name(qname.as_ref());
                if local == b"t" || local == b"v" {
                    in_text = false;
                    out.push(' ');
                } else if local == b"row" || local == b"si" {
                    out.push('\n');
                }
            }
            Ok(Event::Text(e)) if in_text => {
                if let Ok(text) = e.decode() {
                    out.push_str(&text);
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return Err(()),
            _ => {}
        }
        buf.clear();
        if out.len() > MAX_EXTRACTED_TEXT_BYTES + 256 {
            break;
        }
    }
    Ok(())
}

fn extract_ooxml_pptx_text(xml: &[u8], out: &mut String) -> Result<(), ()> {
    let mut reader = XmlReader::from_reader(xml);
    let mut buf = Vec::new();
    let mut in_text = false;
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let qname = e.name();
                let local = xml_local_name(qname.as_ref());
                if local == b"t" {
                    in_text = true;
                }
            }
            Ok(Event::End(e)) => {
                let qname = e.name();
                let local = xml_local_name(qname.as_ref());
                if local == b"t" {
                    in_text = false;
                    out.push(' ');
                } else if local == b"p" {
                    out.push('\n');
                }
            }
            Ok(Event::Text(e)) if in_text => {
                if let Ok(text) = e.decode() {
                    out.push_str(&text);
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return Err(()),
            _ => {}
        }
        buf.clear();
        if out.len() > MAX_EXTRACTED_TEXT_BYTES + 256 {
            break;
        }
    }
    Ok(())
}

fn extract_odf_content_text(xml: &[u8], out: &mut String) -> Result<(), ()> {
    let mut reader = XmlReader::from_reader(xml);
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::End(e)) => {
                let qname = e.name();
                let local = xml_local_name(qname.as_ref());
                if matches!(local, b"p" | b"h" | b"table-row") {
                    out.push('\n');
                } else if local == b"table-cell" {
                    out.push(' ');
                }
            }
            Ok(Event::Empty(e)) => {
                let qname = e.name();
                let local = xml_local_name(qname.as_ref());
                if local == b"s" || local == b"tab" {
                    out.push(' ');
                } else if local == b"line-break" {
                    out.push('\n');
                }
            }
            Ok(Event::Text(e)) => {
                if let Ok(text) = e.decode() {
                    let trimmed = text.trim();
                    if !trimmed.is_empty() {
                        out.push_str(trimmed);
                        out.push(' ');
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return Err(()),
            _ => {}
        }
        buf.clear();
        if out.len() > MAX_EXTRACTED_TEXT_BYTES + 256 {
            break;
        }
    }
    Ok(())
}

fn extract_generic_xml_text(xml: &str) -> Result<String, ()> {
    let mut reader = XmlReader::from_str(xml);
    let mut out = String::new();
    loop {
        match reader.read_event() {
            Ok(Event::Text(e)) => {
                if let Ok(text) = e.decode() {
                    let trimmed = text.trim();
                    if !trimmed.is_empty() {
                        out.push_str(trimmed);
                        out.push(' ');
                    }
                }
            }
            Ok(Event::CData(e)) => {
                if let Ok(text) = std::str::from_utf8(e.as_ref()) {
                    out.push_str(text);
                    out.push(' ');
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return Err(()),
            _ => {}
        }
        if out.len() > MAX_EXTRACTED_TEXT_BYTES + 256 {
            break;
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Bounded pure-Rust PDF text extractor (zero GPL / zero C bindings)
// ---------------------------------------------------------------------------

fn has_pdf_header(bytes: &[u8]) -> bool {
    let head = &bytes[..bytes.len().min(1024)];
    find_subslice(head, b"%PDF-").is_some()
}

fn has_pdf_encrypt_dict(bytes: &[u8]) -> bool {
    let mut pos = 0usize;
    let mut scan = 0usize;
    let mut in_comment = false;
    while let Some(idx) = find_subslice(&bytes[pos..], b"/Encrypt") {
        let abs = pos + idx;
        for &b in &bytes[scan..abs] {
            if b == b'\n' || b == b'\r' {
                in_comment = false;
            } else if b == b'%' {
                in_comment = true;
            }
        }
        scan = abs;
        let after = abs + b"/Encrypt".len();
        // Ensure `/Encrypt` is a full PDF name token (not `/EncryptedSomething`).
        let boundary_ok = bytes.get(after).is_none_or(|b| {
            b.is_ascii_whitespace() || matches!(*b, b'<' | b'[' | b'/' | b'(' | b')' | b'>')
        });
        if boundary_ok && !in_comment {
            return true;
        }
        pos = after;
    }
    false
}

fn extract_pdf(bytes: &[u8], base_mime: Option<String>) -> ExtractionResult {
    let mime = base_mime.or_else(|| Some("application/pdf".to_owned()));
    if !has_pdf_header(bytes) {
        return ExtractionResult::failed(mime, "pdf_invalid_header");
    }
    if has_pdf_encrypt_dict(bytes) {
        return ExtractionResult::encrypted(mime, "pdf_encrypted");
    }

    let looks_valid_pdf = find_subslice(bytes, b"endobj").is_some()
        || find_subslice(bytes, b"%%EOF").is_some()
        || find_subslice(bytes, b"stream").is_some();
    if !looks_valid_pdf {
        return ExtractionResult::failed(mime, "pdf_malformed");
    }

    let mut out = String::new();
    let mut pos = 0usize;
    let mut streams_scanned = 0usize;
    let mut remaining_decompressed = MAX_PDF_DECOMPRESSED_BYTES;
    let mut hit_limit = false;

    while pos < bytes.len() {
        let Some(rel) = find_subslice(&bytes[pos..], b"stream") else {
            break;
        };
        let kw_pos = pos + rel;
        // Skip `endstream` false matches.
        if kw_pos >= 3 && &bytes[kw_pos - 3..kw_pos] == b"end" {
            pos = kw_pos + 6;
            continue;
        }
        let mut data_start = kw_pos + 6;
        if bytes.get(data_start) == Some(&b'\r') && bytes.get(data_start + 1) == Some(&b'\n') {
            data_start += 2;
        } else if bytes.get(data_start) == Some(&b'\n') {
            data_start += 1;
        } else {
            pos = kw_pos + 6;
            continue;
        }
        let Some(end_rel) = find_subslice(&bytes[data_start..], b"endstream") else {
            break;
        };
        if streams_scanned >= MAX_PDF_STREAMS {
            hit_limit = true;
            break;
        }
        let mut data_end = data_start + end_rel;
        if data_end > data_start && bytes[data_end - 1] == b'\n' {
            data_end -= 1;
        }
        if data_end > data_start && bytes[data_end - 1] == b'\r' {
            data_end -= 1;
        }
        let raw_stream = &bytes[data_start..data_end];
        let dict_start = kw_pos.saturating_sub(512);
        let dict_window = &bytes[dict_start..kw_pos];
        let is_flate = find_subslice(dict_window, b"/FlateDecode").is_some()
            || find_subslice(dict_window, b"/Fl ").is_some();
        let is_image = find_subslice(dict_window, b"/Subtype /Image").is_some()
            || find_subslice(dict_window, b"/Subtype/Image").is_some();

        streams_scanned += 1;
        pos = data_start + end_rel + 9;

        if is_image {
            continue;
        }

        if is_flate {
            if remaining_decompressed == 0 {
                hit_limit = true;
                break;
            }
            let limit = remaining_decompressed.min(4 * 1024 * 1024);
            let mut decoder = ZlibDecoder::new(raw_stream).take((limit + 1) as u64);
            let mut decoded = Vec::new();
            let read_ok = decoder.read_to_end(&mut decoded).is_ok();
            // Always deduct decompressed bytes even on limit blowup or error.
            remaining_decompressed = remaining_decompressed.saturating_sub(decoded.len());
            if decoded.len() > limit {
                hit_limit = true;
                continue;
            }
            if read_ok {
                parse_pdf_content_stream(&decoded, &mut out);
            }
        } else {
            parse_pdf_content_stream(raw_stream, &mut out);
        }

        if out.len() > MAX_EXTRACTED_TEXT_BYTES + 256 {
            break;
        }
    }

    let cleaned = sanitize_extracted_text(&out);
    if hit_limit {
        if cleaned.is_empty() {
            return ExtractionResult::truncated_input(mime, "pdf_stream_limit_exceeded");
        }
        return ExtractionResult::truncated_text(cleaned, mime, "pdf_stream_limit_exceeded");
    }
    if cleaned.is_empty() {
        return ExtractionResult::unsupported(mime, "pdf_no_text_layer");
    }
    ExtractionResult::extracted(cleaned, mime)
}

fn parse_pdf_content_stream(stream: &[u8], out: &mut String) {
    // Only scan streams that contain PDF text-object markers or text-showing operators.
    if find_subslice(stream, b"BT").is_none()
        && find_subslice(stream, b"Tj").is_none()
        && find_subslice(stream, b"TJ").is_none()
    {
        return;
    }

    let mut i = 0usize;
    let n = stream.len();
    let mut in_text_obj = false;
    let mut pending_strings: Vec<String> = Vec::new();

    while i < n && out.len() <= MAX_EXTRACTED_TEXT_BYTES + 256 {
        let b = stream[i];
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        // Single-line PDF comment `% ...`
        if b == b'%' {
            while i < n && stream[i] != b'\n' && stream[i] != b'\r' {
                i += 1;
            }
            continue;
        }
        // Literal string `(...)`
        if b == b'(' {
            let (decoded, next) = parse_pdf_literal_string(stream, i);
            if in_text_obj && !decoded.is_empty() {
                pending_strings.push(decoded);
            }
            i = next;
            continue;
        }
        // Hex string `<...>` (not dictionary `<<`)
        if b == b'<' && stream.get(i + 1) != Some(&b'<') {
            let (decoded, next) = parse_pdf_hex_string(stream, i);
            if in_text_obj && !decoded.is_empty() {
                pending_strings.push(decoded);
            }
            i = next;
            continue;
        }
        // Array `[...]` (for `TJ` operator)
        if b == b'[' {
            i += 1;
            while i < n && stream[i] != b']' {
                if stream[i] == b'(' {
                    let (decoded, next) = parse_pdf_literal_string(stream, i);
                    if in_text_obj && !decoded.is_empty() {
                        pending_strings.push(decoded);
                    }
                    i = next;
                } else if stream[i] == b'<' && stream.get(i + 1) != Some(&b'<') {
                    let (decoded, next) = parse_pdf_hex_string(stream, i);
                    if in_text_obj && !decoded.is_empty() {
                        pending_strings.push(decoded);
                    }
                    i = next;
                } else {
                    i += 1;
                }
            }
            if i < n && stream[i] == b']' {
                i += 1;
            }
            continue;
        }
        // Single-quote / double-quote text operators
        if b == b'\'' || b == b'"' {
            if in_text_obj && !pending_strings.is_empty() {
                for s in pending_strings.drain(..) {
                    out.push_str(&s);
                }
                out.push('\n');
            }
            i += 1;
            continue;
        }
        // Operator / keyword token
        if b.is_ascii_alphabetic() || b == b'*' {
            let start = i;
            while i < n
                && (stream[i].is_ascii_alphanumeric() || stream[i] == b'*' || stream[i] == b'_')
            {
                i += 1;
            }
            match &stream[start..i] {
                b"BT" => {
                    in_text_obj = true;
                    pending_strings.clear();
                }
                b"ET" => {
                    in_text_obj = false;
                    pending_strings.clear();
                    if !out.is_empty() && !out.ends_with('\n') {
                        out.push('\n');
                    }
                }
                b"Tj" | b"TJ" => {
                    if in_text_obj && !pending_strings.is_empty() {
                        for s in pending_strings.drain(..) {
                            out.push_str(&s);
                        }
                        out.push(' ');
                    }
                }
                b"Td" | b"TD" | b"T*" => {
                    pending_strings.clear();
                    if in_text_obj && !out.is_empty() && !out.ends_with('\n') {
                        out.push('\n');
                    }
                }
                _ => {
                    pending_strings.clear();
                }
            }
            continue;
        }
        i += 1;
    }
}

fn parse_pdf_literal_string(stream: &[u8], start: usize) -> (String, usize) {
    let mut raw = Vec::new();
    let mut i = start + 1;
    let mut depth = 1usize;
    let n = stream.len();
    while i < n && depth > 0 {
        let b = stream[i];
        if b == b'\\' && i + 1 < n {
            let next = stream[i + 1];
            match next {
                b'n' => {
                    raw.push(b'\n');
                    i += 2;
                }
                b'r' => {
                    raw.push(b'\r');
                    i += 2;
                }
                b't' => {
                    raw.push(b'\t');
                    i += 2;
                }
                b'b' => {
                    raw.push(0x08);
                    i += 2;
                }
                b'f' => {
                    raw.push(0x0C);
                    i += 2;
                }
                b'(' | b')' | b'\\' => {
                    raw.push(next);
                    i += 2;
                }
                b'\r' => {
                    i += if stream.get(i + 2) == Some(&b'\n') {
                        3
                    } else {
                        2
                    };
                }
                b'\n' => {
                    i += 2;
                }
                b'0'..=b'7' => {
                    let mut val = (next - b'0') as u16;
                    let mut consumed = 2;
                    for k in 0..2 {
                        if let Some(&d) = stream.get(i + 2 + k) {
                            if (b'0'..=b'7').contains(&d) {
                                val = val * 8 + (d - b'0') as u16;
                                consumed += 1;
                            } else {
                                break;
                            }
                        }
                    }
                    raw.push((val & 0xFF) as u8);
                    i += consumed;
                }
                _ => {
                    raw.push(next);
                    i += 2;
                }
            }
        } else if b == b'(' {
            depth += 1;
            raw.push(b);
            i += 1;
        } else if b == b')' {
            depth -= 1;
            if depth > 0 {
                raw.push(b);
            }
            i += 1;
        } else {
            raw.push(b);
            i += 1;
        }
    }
    (decode_pdf_string_bytes(&raw), i)
}

fn parse_pdf_hex_string(stream: &[u8], start: usize) -> (String, usize) {
    let mut hex_digits = Vec::new();
    let mut i = start + 1;
    let n = stream.len();
    while i < n && stream[i] != b'>' {
        let b = stream[i];
        if b.is_ascii_hexdigit() {
            hex_digits.push(b);
        }
        i += 1;
    }
    if i < n && stream[i] == b'>' {
        i += 1;
    }
    if hex_digits.len() % 2 == 1 {
        hex_digits.push(b'0');
    }
    let mut raw = Vec::with_capacity(hex_digits.len() / 2);
    let (pairs, _) = hex_digits.as_chunks::<2>();
    for pair in pairs {
        if let (Some(hi), Some(lo)) = (hex_nibble(pair[0]), hex_nibble(pair[1])) {
            raw.push((hi << 4) | lo);
        }
    }
    (decode_pdf_string_bytes(&raw), i)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn decode_pdf_string_bytes(raw: &[u8]) -> String {
    if let Some(rest) = raw.strip_prefix(&[0xFE, 0xFF]) {
        let (cow, _, _) = UTF_16BE.decode(rest);
        return cow.into_owned();
    }
    if let Ok(s) = std::str::from_utf8(raw) {
        return s.to_owned();
    }
    let (cow, _, _) = WINDOWS_1252.decode(raw);
    cow.into_owned()
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut cur = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut cur);
            let opts =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
            for (name, data) in entries {
                writer.start_file(*name, opts).expect("start_file");
                writer.write_all(data).expect("write");
            }
            writer.finish().expect("finish");
        }
        cur.into_inner()
    }

    fn make_minimal_pdf(content_stream: &[u8], compress: bool) -> Vec<u8> {
        let (filter, body) = if compress {
            let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
            enc.write_all(content_stream).expect("zlib write");
            ("/Filter /FlateDecode ", enc.finish().expect("zlib finish"))
        } else {
            ("", content_stream.to_vec())
        };
        let mut pdf = Vec::new();
        pdf.extend_from_slice(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n2 0 obj\n<< ");
        pdf.extend_from_slice(filter.as_bytes());
        pdf.extend_from_slice(format!("/Length {} >>\nstream\n", body.len()).as_bytes());
        pdf.extend_from_slice(&body);
        pdf.extend_from_slice(b"\nendstream\nendobj\n%%EOF\n");
        pdf
    }

    #[test]
    fn extracts_docx_xlsx_pptx_and_odf() {
        let docx = make_zip(&[(
            "word/document.xml",
            br#"<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Quarterly Budget Alpha</w:t></w:r></w:p></w:body></w:document>"#,
        )]);
        let r = extract_bytes(&docx, None, Some("budget.docx"));
        assert_eq!(r.status, ExtractionStatus::Extracted);
        assert!(r
            .extracted_text
            .as_deref()
            .unwrap_or("")
            .contains("Quarterly Budget Alpha"));

        let xlsx = make_zip(&[
            (
                "xl/sharedStrings.xml",
                br#"<?xml version="1.0"?><sst><si><t>RevenueQ4</t></si><si><t>Forecast2027</t></si></sst>"#,
            ),
            (
                "xl/worksheets/sheet1.xml",
                br#"<?xml version="1.0"?><worksheet><sheetData><row><c><v>98765</v></c></row></sheetData></worksheet>"#,
            ),
        ]);
        let r = extract_bytes(&xlsx, None, Some("sheet.xlsx"));
        assert_eq!(r.status, ExtractionStatus::Extracted);
        let txt = r.extracted_text.as_deref().unwrap_or("");
        assert!(txt.contains("RevenueQ4") && txt.contains("Forecast2027") && txt.contains("98765"));

        let pptx = make_zip(&[(
            "ppt/slides/slide1.xml",
            br#"<?xml version="1.0"?><p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><a:p><a:r><a:t>Architecture Roadmap</a:t></a:r></a:p></p:sld>"#,
        )]);
        let r = extract_bytes(&pptx, None, Some("deck.pptx"));
        assert_eq!(r.status, ExtractionStatus::Extracted);
        assert!(r
            .extracted_text
            .as_deref()
            .unwrap_or("")
            .contains("Architecture Roadmap"));

        let odt = make_zip(&[(
            "content.xml",
            br#"<?xml version="1.0"?><office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"><office:body><office:text><text:p>OpenDocument Compliance Memo</text:p></office:text></office:body></office:document-content>"#,
        )]);
        let r = extract_bytes(&odt, None, Some("memo.odt"));
        assert_eq!(r.status, ExtractionStatus::Extracted);
        assert!(r
            .extracted_text
            .as_deref()
            .unwrap_or("")
            .contains("OpenDocument Compliance Memo"));
    }

    #[test]
    fn extracts_html_text_csv_gb18030_eml_and_pdf() {
        let html = b"<html><head><style>body{color:red}</style><script>evil()</script></head><body><h1>Notice</h1><p>Hello <b>World</b></p></body></html>";
        let r = extract_bytes(html, Some("text/html; charset=utf-8"), Some("note.html"));
        assert_eq!(r.status, ExtractionStatus::Extracted);
        let txt = r.extracted_text.as_deref().unwrap_or("");
        assert!(txt.contains("Notice") && txt.contains("Hello") && txt.contains("World"));
        assert!(!txt.contains("evil") && !txt.contains("color:red"));

        let csv = b"col1,col2\nalpha,beta\n";
        let r = extract_bytes(csv, Some("text/csv"), Some("data.csv"));
        assert_eq!(r.status, ExtractionStatus::Extracted);
        assert!(r
            .extracted_text
            .as_deref()
            .unwrap_or("")
            .contains("alpha,beta"));

        // GB18030 Chinese plain text without BOM or charset header.
        let (gb_bytes, _, _) = GB18030.encode("合同审批流程报告");
        let r = extract_bytes(&gb_bytes, Some("text/plain"), Some("report.txt"));
        assert_eq!(r.status, ExtractionStatus::Extracted);
        assert!(r
            .extracted_text
            .as_deref()
            .unwrap_or("")
            .contains("合同审批流程报告"));

        let eml = b"From: a@example.com\r\nTo: b@example.com\r\nSubject: Attached RFC822\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nForwarded message body content.";
        let r = extract_bytes(eml, Some("message/rfc822"), Some("fwd.eml"));
        assert_eq!(r.status, ExtractionStatus::Extracted);
        let txt = r.extracted_text.as_deref().unwrap_or("");
        assert!(txt.contains("Attached RFC822") && txt.contains("Forwarded message body content."));

        let pdf = make_minimal_pdf(b"BT /F1 12 Tf (Quarterly Invoice 2026) Tj ET", true);
        let r = extract_bytes(&pdf, Some("application/pdf"), Some("invoice.pdf"));
        assert_eq!(r.status, ExtractionStatus::Extracted);
        assert!(r
            .extracted_text
            .as_deref()
            .unwrap_or("")
            .contains("Quarterly Invoice 2026"));

        // Scanned/image-only PDF yields Unsupported cleanly without failing batch.
        let scanned_pdf = make_minimal_pdf(b"q 100 0 0 100 0 0 cm /Im0 Do Q", false);
        let r = extract_bytes(&scanned_pdf, Some("application/pdf"), Some("scan.pdf"));
        assert_eq!(r.status, ExtractionStatus::Unsupported);
        assert_eq!(r.extracted_text, None);
    }

    #[test]
    fn classifies_encrypted_zip_pdf_ole2_and_smime() {
        // Encrypted ZIP (bit 0 set in general purpose flag).
        let mut fake_enc_zip = b"PK\x03\x04\x14\x00\x01\x00".to_vec();
        fake_enc_zip.extend_from_slice(&[0u8; 32]);
        let r = extract_bytes(&fake_enc_zip, Some("application/zip"), Some("secret.docx"));
        assert_eq!(r.status, ExtractionStatus::Encrypted);
        assert_eq!(r.extracted_text, None);

        // Encrypted PDF with /Encrypt dictionary.
        let enc_pdf = b"%PDF-1.7\n1 0 obj\n<< /Encrypt 2 0 R /Root 3 0 R >>\nendobj\n%%EOF";
        let r = extract_bytes(enc_pdf, Some("application/pdf"), Some("locked.pdf"));
        assert_eq!(r.status, ExtractionStatus::Encrypted);
        assert_eq!(r.extracted_text, None);

        // Encrypted OLE2 OOXML (EncryptedPackage).
        let mut ole2 = OLE2_MAGIC.to_vec();
        ole2.extend_from_slice(b"E\0n\0c\0r\0y\0p\0t\0e\0d\0P\0a\0c\0k\0a\0g\0e\0");
        let r = extract_bytes(&ole2, None, Some("locked.docx"));
        assert_eq!(r.status, ExtractionStatus::Encrypted);
        assert_eq!(r.extracted_text, None);

        // S/MIME encrypted attachment.
        let r = extract_bytes(
            b"opaque-pkcs7-bytes",
            Some("application/pkcs7-mime"),
            Some("smime.p7m"),
        );
        assert_eq!(r.status, ExtractionStatus::Encrypted);
        assert_eq!(r.extracted_text, None);
    }

    #[test]
    fn enforces_zip_bomb_output_truncation_binary_and_corrupt_safely() {
        // Zip bomb: 512 KiB of repeated 'A' compresses to ~600 bytes (> 800:1 ratio > 100:1).
        let bomb_payload = vec![b'A'; 512 * 1024];
        let bomb_zip = make_zip(&[("word/document.xml", &bomb_payload)]);
        let r = extract_bytes(&bomb_zip, None, Some("bomb.docx"));
        assert_eq!(r.status, ExtractionStatus::Failed);
        assert_eq!(r.extracted_text, None);
        assert!(r
            .error_code
            .as_deref()
            .unwrap_or("")
            .starts_with("zip_bomb"));

        // > 512 KiB UTF-8 CJK text safely truncates at char boundary -> TruncatedLimit.
        let huge_cjk = "测试".repeat(120_000); // 720 KB UTF-8
        assert!(huge_cjk.len() > MAX_EXTRACTED_TEXT_BYTES);
        let r = extract_bytes(huge_cjk.as_bytes(), Some("text/plain"), Some("big.txt"));
        assert_eq!(r.status, ExtractionStatus::TruncatedLimit);
        let out = r.extracted_text.as_deref().unwrap_or("");
        assert!(out.len() <= MAX_EXTRACTED_TEXT_BYTES);
        assert!(out.len() >= MAX_EXTRACTED_TEXT_BYTES - 6);
        assert_eq!(r.extracted_bytes, out.len());

        // Binary PNG -> Unsupported.
        let png = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13];
        let r = extract_bytes(&png, Some("image/png"), Some("photo.png"));
        assert_eq!(r.status, ExtractionStatus::Unsupported);
        assert_eq!(r.extracted_text, None);

        // Corrupt DOCX bytes -> Failed (never panics).
        let r = extract_bytes(b"not-a-real-zip-file", None, Some("broken.docx"));
        assert_eq!(r.status, ExtractionStatus::Failed);
        assert_eq!(r.extracted_text, None);
    }

    #[test]
    fn enforces_pdf_flate_bomb_budget_zip_eocd_cap_and_odf_shared_budget() {
        // 1. PDF with > 4 MiB FlateDecode stream hits per-stream budget -> TruncatedLimit (never Unsupported/Extracted).
        let huge_stream = vec![b' '; 5 * 1024 * 1024];
        let bomb_pdf = make_minimal_pdf(&huge_stream, true);
        let r = extract_bytes(&bomb_pdf, Some("application/pdf"), Some("flate_bomb.pdf"));
        assert_eq!(r.status, ExtractionStatus::TruncatedLimit);
        assert_eq!(r.error_code.as_deref(), Some("pdf_stream_limit_exceeded"));

        // 2. ZIP EOCD declaring > MAX_ZIP_ENTRIES is rejected before ZipArchive::new
        //    (both exact-end EOCD and EOCD followed by trailing bytes).
        let mut fake_eocd = b"PK\x03\x04\x14\x00\x00\x00".to_vec();
        fake_eocd.extend_from_slice(&[0u8; 24]);
        // EOCD header: sig(4) + disk(2) + cd_disk(2) + disk_entries(2) + total_entries(2) + cd_size(4) + cd_off(4) + comment_len(2)
        fake_eocd.extend_from_slice(b"PK\x05\x06");
        fake_eocd.extend_from_slice(&0u16.to_le_bytes());
        fake_eocd.extend_from_slice(&0u16.to_le_bytes());
        fake_eocd.extend_from_slice(&((MAX_ZIP_ENTRIES as u16) + 5).to_le_bytes());
        fake_eocd.extend_from_slice(&((MAX_ZIP_ENTRIES as u16) + 5).to_le_bytes());
        fake_eocd.extend_from_slice(&0u32.to_le_bytes());
        fake_eocd.extend_from_slice(&0u32.to_le_bytes());
        fake_eocd.extend_from_slice(&0u16.to_le_bytes());
        let r = extract_bytes(&fake_eocd, Some("application/zip"), Some("many.docx"));
        assert_eq!(r.status, ExtractionStatus::Failed);
        assert_eq!(r.error_code.as_deref(), Some("zip_too_many_entries"));

        let mut trailing_eocd = fake_eocd.clone();
        trailing_eocd.extend_from_slice(b"TRAILING_GARBAGE_BYTES_AFTER_EOCD");
        let r = extract_bytes(
            &trailing_eocd,
            Some("application/zip"),
            Some("many_trailing.docx"),
        );
        assert_eq!(r.status, ExtractionStatus::Failed);
        assert_eq!(r.error_code.as_deref(), Some("zip_too_many_entries"));

        // 3. ODF with encrypted META-INF/manifest.xml -> Encrypted.
        let odf_enc = make_zip(&[
            (
                "META-INF/manifest.xml",
                br#"<manifest><file-entry><encryption-data/></file-entry></manifest>"#,
            ),
            ("content.xml", br#"<office:document-content/>"#),
        ]);
        let r = extract_bytes(&odf_enc, None, Some("secret.odt"));
        assert_eq!(r.status, ExtractionStatus::Encrypted);
        assert_eq!(r.error_code.as_deref(), Some("odf_encrypted"));

        // 4. ODF with zip-bomb in META-INF/manifest.xml -> Failed (not silently ignored!).
        let manifest_bomb = vec![b' '; 256 * 1024];
        let odf_bomb = make_zip(&[
            ("META-INF/manifest.xml", &manifest_bomb),
            (
                "content.xml",
                br#"<office:document-content><text:p>ok</text:p></office:document-content>"#,
            ),
        ]);
        let r = extract_bytes(&odf_bomb, None, Some("manifest_bomb.odt"));
        assert_eq!(r.status, ExtractionStatus::Failed);
        assert!(r
            .error_code
            .as_deref()
            .unwrap_or("")
            .starts_with("zip_bomb"));
    }
}
