//! `mailserver/internal/downloads` and the `/downloads/asset/{asset}` closure
//! in `registerPublicRoutes`.

/// `downloads.DesktopPlatforms`: (name, slug, ext). `store_url` is always empty.
pub const PLATFORMS: [(&str, &str, &str); 7] = [
    ("macOS (Apple Silicon)", "macos-arm64", "dmg"),
    ("macOS (Intel)", "macos-x86_64", "dmg"),
    ("Windows (x64)", "windows-x86_64", "msi"),
    ("Windows (ARM64)", "windows-arm64", "msi"),
    ("Linux (x64 AppImage)", "linux-x86_64", "AppImage"),
    ("Linux (deb)", "linux-x86_64-deb", "deb"),
    ("Linux (rpm)", "linux-x86_64-rpm", "rpm"),
];

/// `GET /downloads` body: `json.Encoder` output (trailing newline), struct
/// field order `name, slug, ext, store_url`.
pub fn page() -> String {
    let platforms: Vec<_> = PLATFORMS
        .iter()
        .map(|(name, slug, ext)| {
            format!(
                "{{\"name\":{},\"slug\":{},\"ext\":{},\"store_url\":\"\"}}",
                crate::wellknown::go_json_string(name),
                crate::wellknown::go_json_string(slug),
                crate::wellknown::go_json_string(ext)
            )
        })
        .collect();
    format!(
        "{{\"platforms\":[{}],\"versions\":{{}}}}\n",
        platforms.join(",")
    )
}

/// `GET /downloads/{platform}`: the redirect target for a known slug.
pub fn platform_target(slug: &str) -> Option<String> {
    PLATFORMS
        .iter()
        .find(|(_, s, _)| *s == slug)
        .map(|(_, slug, ext)| format!("/downloads/asset/SetJoin_latest_{slug}.{ext}"))
}

/// `network.ResolveDownloadURL` primary mirror for a Go `NetworkMode`.
/// Unknown modes use the global mirror, as Go does.
pub fn mirror_url(mode: &str, asset: &str) -> String {
    let base = match mode {
        "china" => "https://gitee.com/setjoin/setjoin/releases/download",
        "airgap" => "/updates",
        _ => "https://github.com/setjoin/setjoin/releases/download",
    };
    format!("{base}/{asset}")
}

/// The asset-name rule of the inline `/downloads/asset/{asset}` handler:
/// path separators and `..` are refused.
pub fn asset_is_valid(asset: &str) -> bool {
    !asset.contains(['/', '\\']) && !asset.contains("..")
}
