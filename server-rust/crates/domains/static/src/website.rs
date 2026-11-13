//! Frozen `cmd/mailserverd/static_responder.go`: operator build validation and
//! representation negotiation. HTTP framing belongs to the gateway.
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};

pub const MANIFEST: &str = "static-representations.v1.json";
#[derive(Clone, Deserialize, Default)]
pub struct Sidecar {
    pub path: String,
    pub bytes: i64,
    pub sha256: String,
}
#[derive(Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Asset {
    pub path: String,
    pub identity_bytes: i64,
    pub identity_sha256: String,
    #[serde(default)]
    pub representations: Option<HashMap<String, Sidecar>>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    schema_version: i64,
    build_id: String,
    assets: Vec<Asset>,
}
pub struct Website {
    pub root: PathBuf,
    assets: HashMap<String, Asset>,
}
impl Website {
    pub fn load(root: &Path) -> Result<Self, String> {
        let root = std::path::absolute(root).map_err(|e| e.to_string())?;
        if !root.is_dir() {
            return Err("webmail root is not a directory".into());
        }
        let bytes = std::fs::read(root.join(MANIFEST))
            .map_err(|e| format!("read static representation manifest: {e}"))?;
        let manifest: Manifest = serde_json::from_slice(&bytes)
            .map_err(|e| format!("decode static representation manifest: {e}"))?;
        let version: serde_json::Value = serde_json::from_slice(
            &std::fs::read(root.join("_app/version.json"))
                .map_err(|e| format!("read webmail build version: {e}"))?,
        )
        .map_err(|e| e.to_string())?;
        if manifest.schema_version != 1
            || manifest.build_id.is_empty()
            || version["version"].as_str() != Some(&manifest.build_id)
        {
            return Err("static representation manifest does not match the webmail build".into());
        }
        let mut assets = HashMap::new();
        let mut declared = HashSet::new();
        for mut asset in manifest.assets {
            let path = contained(&asset.path).ok_or("invalid static identity path")?;
            if path == format!("/{MANIFEST}") || assets.contains_key(&path) {
                return Err("invalid or duplicate static identity path".into());
            }
            verify(
                &root.join(&path[1..]),
                asset.identity_bytes,
                &asset.identity_sha256,
            )?;
            asset.path = path.clone();
            if let Some(representations) = asset.representations.as_mut() {
                for (coding, sidecar) in representations {
                    let suffix = match coding.as_str() {
                        "br" => ".br",
                        "gzip" => ".gz",
                        _ => return Err("unsupported static encoding".into()),
                    };
                    let side_path =
                        contained(&sidecar.path).ok_or("invalid static sidecar path")?;
                    if side_path != format!("{path}{suffix}")
                        || sidecar.bytes >= asset.identity_bytes
                    {
                        return Err("misbound static sidecar".into());
                    }
                    verify(&root.join(&side_path[1..]), sidecar.bytes, &sidecar.sha256)?;
                    sidecar.path = side_path.clone();
                    declared.insert(side_path);
                }
            }
            assets.insert(path, asset);
        }
        fn walk(
            root: &Path,
            path: &Path,
            assets: &HashMap<String, Asset>,
            declared: &HashSet<String>,
        ) -> Result<(), String> {
            let meta = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
            if meta.file_type().is_symlink() {
                return Err("webmail build contains symlink".into());
            }
            if meta.is_dir() {
                for entry in std::fs::read_dir(path).map_err(|e| e.to_string())? {
                    walk(
                        root,
                        &entry.map_err(|e| e.to_string())?.path(),
                        assets,
                        declared,
                    )?;
                }
                return Ok(());
            }
            let url = format!(
                "/{}",
                path.strip_prefix(root)
                    .map_err(|e| e.to_string())?
                    .to_string_lossy()
            );
            if url.ends_with(".br") || url.ends_with(".gz") {
                if !declared.contains(&url) {
                    return Err(format!("undeclared static sidecar {url}"));
                }
            } else if url != format!("/{MANIFEST}") && !assets.contains_key(&url) {
                return Err(format!("undeclared static identity {url}"));
            }
            Ok(())
        }
        walk(&root, &root, &assets, &declared)?;
        Ok(Self { root, assets })
    }
    pub fn record(&self, path: &str) -> Asset {
        self.assets.get(path).cloned().unwrap_or_default()
    }
}
fn verify(path: &Path, size: i64, hash: &str) -> Result<(), String> {
    if size < 0 || hash.len() != 64 {
        return Err("invalid size or SHA-256".into());
    }
    let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut digest = Sha256::new();
    let mut count = 0;
    let mut bytes = [0; 65536];
    loop {
        let n = file.read(&mut bytes).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        digest.update(&bytes[..n]);
        count += n as i64;
    }
    if count != size || format!("{:x}", digest.finalize()) != hash {
        return Err("static size or SHA-256 mismatch".into());
    }
    Ok(())
}
/// Go rejects NUL, backslash and decoded parent segments before cleaning.
pub fn contained(path: &str) -> Option<String> {
    if path.is_empty() || path.contains(['\0', '\\']) || path.split('/').any(|p| p == "..") {
        return None;
    }
    Some(format!(
        "/{}",
        path.split('/')
            .filter(|p| !p.is_empty() && *p != ".")
            .collect::<Vec<_>>()
            .join("/")
    ))
}
#[derive(Clone)]
pub struct Representation {
    pub coding: &'static str,
    pub path: String,
    pub hash: String,
}
pub fn choose(asset: &Asset, header: &str, range: bool) -> Option<Representation> {
    let mut values: HashMap<String, f64> = HashMap::new();
    for item in header.to_lowercase().split(',') {
        let mut parts = item.trim().split(';');
        let name = parts.next().unwrap_or("").trim();
        if name.is_empty() {
            continue;
        }
        let mut q = 1.;
        for p in parts {
            if let Some((key, value)) = p.trim().split_once('=') {
                if key.trim() == "q" {
                    q = value
                        .trim()
                        .parse::<f64>()
                        .ok()
                        .filter(|q| !(*q < 0. || *q > 1.))
                        .unwrap_or(0.);
                }
            }
        }
        match values.get_mut(name) {
            Some(old) => {
                if q > *old {
                    *old = q;
                }
            }
            None => {
                values.insert(name.into(), q);
            }
        }
    }
    let quality = |name: &str| -> f64 {
        if let Some(q) = values.get(name) {
            *q
        } else if name != "identity" {
            *values.get("*").unwrap_or(&0.)
        } else if header.trim().is_empty() {
            1.
        } else if values.get("*") == Some(&0.) {
            0.
        } else {
            0.000001
        }
    };
    let identity = Representation {
        coding: "identity",
        path: asset.path.clone(),
        hash: asset.identity_sha256.clone(),
    };
    if range {
        return (quality("identity") > 0.).then_some(identity);
    }
    let mut choices = vec![(quality("identity"), 1, identity)];
    for (coding, rank) in [("br", 3), ("gzip", 2)] {
        if let Some(sidecar) = asset.representations.as_ref().and_then(|r| r.get(coding)) {
            choices.push((
                quality(coding),
                rank,
                Representation {
                    coding,
                    path: sidecar.path.clone(),
                    hash: sidecar.sha256.clone(),
                },
            ));
        }
    }
    choices.sort_by(|a, b| {
        if a.0 == b.0 {
            b.1.cmp(&a.1)
        } else {
            b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal)
        }
    });
    let (q, _, choice) = choices.remove(0);
    if q <= 0. {
        None
    } else {
        Some(choice)
    }
}
pub fn cache(path: &str) -> &'static str {
    if path.starts_with("/_app/immutable/") {
        "public, max-age=31536000, immutable"
    } else if matches!(
        path,
        "/index.html"
            | "/service-worker.js"
            | "/critical-shell.v1.json"
            | "/static-representations.v1.json"
            | "/manifest.webmanifest"
            | "/_app/version.json"
    ) {
        "no-cache"
    } else {
        "public, max-age=3600"
    }
}
/// Go's standard MIME builtins, its static responder's three overrides, then
/// the host MIME database used by Go itself. Unknown extensions are sniffed.
pub fn content_type(path: &str) -> Option<String> {
    let ext = Path::new(path).extension()?.to_str()?.to_lowercase();
    let mime = match ext.as_str() {
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "webmanifest" => "application/manifest+json",
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        "xml" => "text/xml; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "pdf" => "application/pdf",
        "wasm" => "application/wasm",
        "gz" => "application/gzip",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        _ => "",
    };
    if !mime.is_empty() {
        return Some(mime.into());
    }
    for file in [
        "/etc/mime.types",
        "/etc/apache2/mime.types",
        "/etc/apache/mime.types",
    ] {
        if let Ok(text) = std::fs::read_to_string(file) {
            for line in text.lines() {
                let mut parts = line.split('#').next().unwrap_or("").split_whitespace();
                let mime = parts.next().unwrap_or("");
                if parts.any(|p| p == ext) {
                    return Some(if mime.starts_with("text/") {
                        format!("{mime}; charset=utf-8")
                    } else {
                        mime.into()
                    });
                }
            }
        }
    }
    None
}

/// The existing public first-boot predicate: disclose only whether setup is
/// required, never an identity row. Go serves normally on a database error.
pub async fn needs_setup(exec: &setjoin_pg::ScopedExecutor) -> bool {
    exec.read("SELECT COUNT(*) FROM users", &[])
        .await
        .is_ok_and(|rows| rows[0].get::<_, i64>(0) == 0)
}

/// The listener's table precedes the representation fallback, even for SPA
/// shells served under an old API path. Preserve those frozen Go cache quirks.
pub fn request_cache(original: &str, resolved: &str) -> &'static str {
    let prefix = |p: &str| {
        original == p
            || original
                .strip_prefix(p)
                .is_some_and(|tail| p.ends_with('/') || tail.starts_with('/'))
    };
    for (p, value, exact, suffix) in [
        (
            "/favicon.ico",
            "public, max-age=604800, immutable",
            false,
            "",
        ),
        (
            "/chat/unfurl/image/",
            "private, max-age=31536000, immutable",
            false,
            "",
        ),
        (
            "/jmap/download/",
            "private, max-age=31536000, immutable, no-transform",
            false,
            "",
        ),
        ("/blobs/", "private, max-age=31536000, immutable", false, ""),
        (
            "/api/fonts/",
            "public, max-age=31536000, immutable",
            false,
            "",
        ),
        (
            "/.well-known/autoconfig/",
            "public, max-age=86400",
            false,
            "",
        ),
        ("/.well-known/setjoin", "public, max-age=3600", false, ""),
        ("/updates/appcast", "public, max-age=300", true, ""),
        ("/downloads", "public, max-age=3600", true, ""),
        ("/api/openapi.yaml", "public, max-age=300", true, ""),
        ("/api/openapi.json", "public, max-age=300", true, ""),
        (
            "/api/redoc.standalone.js",
            "public, max-age=86400",
            true,
            "",
        ),
        ("/api/logo.svg", "public, max-age=86400", true, ""),
        ("/jmap/eventsource", "no-cache", false, ""),
        (
            "/mail-attachment/",
            "private, max-age=31536000, immutable, no-transform",
            false,
            "",
        ),
        ("/jmap/recovery-raw/", "private, no-store", false, ""),
        (
            "/admin/identity/v2/diagnostics/",
            "private, no-store",
            false,
            "/download",
        ),
        ("/admin/identity/v2/", "private, no-cache", false, ""),
    ] {
        if (if exact { original == p } else { prefix(p) }) && original.ends_with(suffix) {
            return value;
        }
    }
    cache(resolved)
}
