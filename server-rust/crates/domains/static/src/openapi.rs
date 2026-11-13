//! `mailserver/api` (package `apispec`): the embedded OpenAPI documents.
//!
//! The public YAML/JSON and the full JSON are what Go derives at startup from
//! `openapi.yaml` (visibility filter, `yaml.Marshal`, `json.Marshal`); they are
//! committed as generated assets recorded from the frozen Go binary, because
//! Go's emitter output cannot be reproduced byte for byte by another YAML
//! library. The full YAML is the Go source file itself.

pub const PUBLIC_YAML: &[u8] = include_bytes!("../assets/openapi.public.yaml");
pub const PUBLIC_JSON: &[u8] = include_bytes!("../assets/openapi.public.json");
pub const FULL_JSON: &[u8] = include_bytes!("../assets/openapi.full.json");
pub const FULL_YAML: &[u8] = include_bytes!("../../../../../mailserver/api/openapi.yaml");
pub const REDOC_JS: &[u8] = include_bytes!("../../../../../mailserver/api/redoc.standalone.js");
pub const LOGO_SVG: &[u8] = include_bytes!("../../../../../mailserver/api/logo.svg");
pub const FONT_REGULAR: &[u8] =
    include_bytes!("../../../../../mailserver/api/ibm-plex-sans-400.woff2");
pub const FONT_MEDIUM: &[u8] =
    include_bytes!("../../../../../mailserver/api/ibm-plex-sans-500.woff2");

/// `apispec.redocHTML`.
pub const DOCS_HTML: &str = include_str!("redoc.html");

/// `HandleFont`: medium only for a path ending in the 500 face.
pub fn font(path: &str) -> &'static [u8] {
    if path.ends_with("ibm-plex-sans-500.woff2") {
        FONT_MEDIUM
    } else {
        FONT_REGULAR
    }
}
