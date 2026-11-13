use super::*;
use serde::Serialize;
use std::path::Path;

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct Collabora {
    profile: String,
    profile_source: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    repository: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    source_kind: String,
    explicit_override: bool,
    allows_public_network: bool,
    writes_host: bool,
    fallbacks: Option<Vec<String>>,
    diagnostics: Option<Vec<Diagnostic>>,
}
#[derive(Serialize)]
struct Diagnostic {
    code: String,
    severity: String,
    detail: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    remediation: String,
}
fn diagnostic(code: &str, severity: &str, detail: &str, remediation: &str) -> Diagnostic {
    Diagnostic {
        code: code.into(),
        severity: severity.into(),
        detail: detail.into(),
        remediation: remediation.into(),
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Provider {
    kind: String,
    provider: String,
    state: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    endpoint_host: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    model: String,
    credential_configured: bool,
    authority: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    detail: String,
}
fn provider(kind: &str, name: &str, state: &str, credential: bool, authority: &str) -> Provider {
    Provider {
        kind: kind.into(),
        provider: name.into(),
        state: state.into(),
        endpoint_host: String::new(),
        model: String::new(),
        credential_configured: credential,
        authority: authority.into(),
        detail: String::new(),
    }
}
#[derive(Serialize)]
struct Source {
    #[serde(rename = "type")]
    kind: String,
    path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    location: String,
    ownership: String,
    status: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Plan {
    mutates_host: bool,
    steps: Vec<String>,
}
#[derive(Serialize)]
struct Host {
    supported: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    distribution: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    release: String,
    architecture: String,
    sources: Vec<Source>,
    diagnostics: Vec<Diagnostic>,
    plan: Plan,
}
#[derive(Serialize)]
struct Report {
    collabora: Collabora,
    #[serde(rename = "externalProviders")]
    external: Vec<Provider>,
    host: Host,
    healthy: bool,
    checks: Vec<Diagnostic>,
}

pub async fn execute(action: &str, args: &[String]) -> Result<(), String> {
    if !matches!(action, "status" | "doctor") {
        return Err(format!(
            "unknown sources action: {action} (try: status, doctor)"
        ));
    }
    let usage=format!("usage: mailctl sources {action} [--json] [--profile global|china|isolated|custom] [--collabora-registry HOST/REPO]");
    let parsed = parse_silent(
        args,
        &[
            "root",
            "profile",
            "collabora-registry",
            "china-registry",
            "isolated-registry",
            "custom-registry",
        ],
        &["json", "isolated-registry-approved"],
    );
    let (fs, positional) = match parsed {
        Ok(v) => v,
        Err(e) => {
            if e != "flag: help requested" {
                eprintln!("{e}");
            }
            let helps: BTreeMap<String, String> =
                serde_json::from_str(include_str!("../flags_help.json")).unwrap();
            eprint!("{}", helps[&format!("sources {action}")]);
            return Err(usage);
        }
    };
    if !positional.is_empty() {
        return Err(usage);
    }
    let root = fs.get("root").map(String::as_str).unwrap_or("/");
    let host = inspect(Path::new(root));
    let (external, ai_check) = external().await;
    let (collabora, resolution_error) = resolve(&fs);
    let mut report = Report {
        collabora,
        external,
        host,
        healthy: resolution_error.is_none(),
        checks: resolution_error.into_iter().collect(),
    };
    if !report.host.supported {
        report.checks.push(diagnostic(
            "host_inventory_unsupported",
            "warning",
            "host inventory is read-only and currently limited to Ubuntu",
            "",
        ));
    }
    for row in &report.external {
        if row.state == "misconfigured" {
            report.healthy = false;
            report.checks.push(diagnostic(
                &format!("{}_misconfigured", row.kind),
                "blocker",
                &row.detail,
                "",
            ));
        }
    }
    if let Some(check) = ai_check {
        report.checks.push(check);
    }
    if truth(value(&fs, "json")) {
        let raw = serde_json::to_string_pretty(&report).unwrap();
        println!(
            "{}",
            raw.replace('<', "\\u003c")
                .replace('>', "\\u003e")
                .replace('&', "\\u0026")
                .replace('\u{2028}', "\\u2028")
                .replace('\u{2029}', "\\u2029")
        );
    } else {
        print_report(&report);
    }
    if action == "doctor" && !report.healthy {
        return Err("sources doctor found one or more blocking deployment-source checks".into());
    }
    Ok(())
}

fn option(fs: &BTreeMap<String, String>, key: &str, variable: &str) -> String {
    fs.get(key).cloned().unwrap_or_else(|| env(variable))
}
fn resolve(fs: &BTreeMap<String, String>) -> (Collabora, Option<Diagnostic>) {
    let explicit = option(fs, "profile", "SETJOIN_CONNECTIVITY_PROFILE");
    let legacy = env("NETWORK_MODE");
    let (profile, source) = if !explicit.trim().is_empty() {
        let raw = explicit.trim().to_lowercase();
        if !matches!(raw.as_str(), "global" | "china" | "isolated" | "custom") {
            return (
                Collabora::default(),
                Some(diagnostic(
                    "invalid_profile",
                    "blocker",
                    &format!("unknown connectivity profile {explicit:?}"),
                    "choose global, china, isolated, or custom",
                )),
            );
        }
        (raw, "explicit")
    } else {
        let profile = match legacy.trim().to_lowercase().as_str() {
            "" | "global" => "global",
            "china" => "china",
            "airgap" | "isolated" => "isolated",
            "manual" | "custom" => "custom",
            _ => {
                return (
                    Collabora::default(),
                    Some(diagnostic(
                        "invalid_legacy_network_mode",
                        "blocker",
                        &format!("unknown NETWORK_MODE {legacy:?}"),
                        "unset NETWORK_MODE or use global, china, airgap, or manual",
                    )),
                )
            }
        };
        (
            profile.to_owned(),
            if legacy.is_empty() {
                "default"
            } else {
                "NETWORK_MODE"
            },
        )
    };
    let mut out = Collabora {
        profile: profile.clone(),
        profile_source: source.into(),
        allows_public_network: profile != "isolated",
        fallbacks: Some(vec![]),
        diagnostics: Some(vec![]),
        ..Default::default()
    };
    let explicit_repository = option(fs, "collabora-registry", "COLLABORA_REGISTRY_OVERRIDE");
    let repository = if !explicit_repository.trim().is_empty() {
        out.explicit_override = true;
        out.source_kind = "explicit_override".into();
        explicit_repository.trim().to_owned()
    } else {
        let (flag, var, kind) = match profile.as_str() {
            "china" => (
                "china-registry",
                "COLLABORA_CHINA_REGISTRY",
                "configured_china_registry",
            ),
            "isolated" => (
                "isolated-registry",
                "COLLABORA_ISOLATED_REGISTRY",
                "approved_local_registry",
            ),
            "custom" => (
                "custom-registry",
                "COLLABORA_CUSTOM_REGISTRY",
                "configured_custom_registry",
            ),
            _ => ("", "", "shipped_upstream"),
        };
        out.source_kind = kind.into();
        if profile == "global" {
            "docker.io/collabora/code".into()
        } else {
            option(fs, flag, var).trim().to_owned()
        }
    };
    if repository.is_empty() {
        let (code,detail,remedy)=match profile.as_str() {
            "china"=>("china_mirror_required","China profile has no approved Collabora registry","configure a Setjoin-controlled or customer registry; no public accelerator is selected automatically"),
            "isolated"=>("offline_artifact_unavailable","isolated profile has no approved local Collabora registry","configure and approve a reachable local registry containing the pinned artifact"),
            "custom"=>("custom_source_required","custom profile has no Collabora repository","configure the custom Collabora repository"),
            _=>("source_required","the selected connectivity profile has no Collabora repository","configure the profile's Collabora repository")};
        return (out, Some(diagnostic(code, "blocker", detail, remedy)));
    }
    let clean = repository.trim_end_matches('/').trim();
    let error = if clean.is_empty()
        || clean.contains([' ', '\t', '\r', '\n', '?', '#', '@'])
        || clean.contains("://")
    {
        Some("Collabora repository contains a scheme, credentials, whitespace, query, or fragment")
    } else if clean
        .split_once('/')
        .is_none_or(|(host, path)| host.is_empty() || path.is_empty())
    {
        Some("Collabora repository must include both registry host and repository path")
    } else {
        let (host, path) = clean.split_once('/').unwrap();
        if host.contains(':') && !host.starts_with('[') && host.matches(':').count() != 1 {
            Some("Collabora repository has an invalid registry host or port")
        } else if path.contains([':', '@']) {
            Some("Collabora repository must not contain a mutable tag or digest")
        } else {
            None
        }
    };
    if let Some(detail) = error {
        return (out,Some(diagnostic("invalid_repository","blocker",detail,"use a registry/repository such as registry.example/collabora/code without a scheme, credentials, tag, digest, query, or fragment")));
    }
    let approved = fs
        .get("isolated-registry-approved")
        .map(|s| truth(s))
        .unwrap_or_else(|| {
            matches!(
                env("COLLABORA_ISOLATED_REGISTRY_APPROVED")
                    .trim()
                    .to_lowercase()
                    .as_str(),
                "1" | "true" | "yes" | "on"
            )
        });
    if profile == "isolated" && !approved {
        return (out,Some(diagnostic("isolated_source_unapproved","blocker","isolated Collabora repository is not marked as operator-approved","set the isolated-registry approval only after confirming the local pinned artifact source")));
    }
    out.repository = clean.into();
    (out, None)
}
async fn external() -> (Vec<Provider>, Option<Diagnostic>) {
    let safe = !env("SAFEBROWSING_API_KEY").is_empty();
    let mut ai = provider(
        "ai",
        "openai_compatible",
        "not_configured",
        false,
        "system_config",
    );
    let mut check = None;
    let data = if env("DB_DSN").is_empty() {
        check = Some(diagnostic(
            "assist_posture_unavailable",
            "warning",
            "DB_DSN is not set, so the read-only assist system_config posture was not inspected",
            "",
        ));
        None
    } else {
        match database(false).await {
        Ok(db)=>db.query("SELECT COALESCE(get_system_config('assist.provider_url') #>> '{}',''), COALESCE(get_system_config('assist.model') #>> '{}',''), COALESCE(NULLIF(get_system_config('assist.api_key') #>> '{}',''),'') <> ''",&[]).await.ok(),Err(_)=>None}
    };
    if let Some(rows) = data {
        let endpoint = rows[0].get::<_, &str>(0).trim();
        ai.model = rows[0].get::<_, String>(1).trim().into();
        ai.credential_configured = rows[0].get(2);
        if !endpoint.is_empty() || !ai.model.is_empty() {
            if let Ok(u) = url::Url::parse(endpoint) {
                if matches!(u.scheme(), "http" | "https")
                    && u.host_str().is_some()
                    && !ai.model.is_empty()
                {
                    ai.state = "configured".into();
                    ai.endpoint_host = u.host_str().unwrap().to_owned();
                    if let Some(port) = u.port() {
                        ai.endpoint_host = format!("{}:{port}", ai.endpoint_host);
                    }
                } else {
                    ai.state = "misconfigured".into();
                }
            } else {
                ai.state = "misconfigured".into();
            }
            if ai.state == "misconfigured" {
                ai.detail =
                    "assist.provider_url must be HTTP(S) and assist.model must be non-empty".into();
            }
        }
    } else if check.is_none() {
        check = Some(diagnostic(
            "assist_posture_unavailable",
            "warning",
            "assist system_config posture could not be inspected",
            "",
        ));
    }
    (
        vec![
            ai,
            provider(
                "url_reputation",
                "google_safe_browsing",
                if safe { "configured" } else { "not_configured" },
                safe,
                "gateway_config",
            ),
            provider(
                "url_reputation",
                "spamhaus_dbl",
                "configured",
                false,
                "gateway_runtime",
            ),
        ],
        check,
    )
}
fn print_report(r: &Report) {
    println!(
        "connectivity: profile={} source={} publicNetwork={} writesHost={}",
        r.collabora.profile,
        r.collabora.profile_source,
        r.collabora.allows_public_network,
        r.collabora.writes_host
    );
    if !r.collabora.repository.is_empty() {
        println!(
            "collabora: {} ({})",
            r.collabora.repository, r.collabora.source_kind
        );
    }
    for row in &r.external {
        print!(
            "provider: {:<16} {:<20} {}",
            row.kind, row.provider, row.state
        );
        if !row.endpoint_host.is_empty() {
            print!(" host={}", row.endpoint_host);
        }
        println!();
    }
    println!(
        "host: distro={} release={} arch={} supported={} writesHost={}",
        r.host.distribution,
        r.host.release,
        r.host.architecture,
        r.host.supported,
        r.host.plan.mutates_host
    );
    for row in &r.host.sources {
        println!(
            "  {:<15} {:<18} {:<20} {}",
            row.kind, row.ownership, row.status, row.location
        );
    }
    for check in &r.checks {
        print!(
            "[{}] {}: {}",
            check.severity.to_uppercase(),
            check.code,
            check.detail
        );
        if !check.remediation.is_empty() {
            print!("; remedy: {}", check.remediation);
        }
        println!();
    }
}

fn read(path: &Path) -> (String, &'static str) {
    let info = match std::fs::symlink_metadata(path) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (String::new(), "missing"),
        Err(_) => return (String::new(), "unreadable"),
    };
    if info.is_symlink() {
        return (String::new(), "symlink_ignored");
    }
    if !info.is_file() {
        return (String::new(), "non_regular_ignored");
    }
    if info.len() > 1 << 20 {
        return (String::new(), "oversized_ignored");
    }
    match std::fs::read(path) {
        Ok(v) => (String::from_utf8_lossy(&v).into_owned(), "ok"),
        Err(_) => (String::new(), "unreadable"),
    }
}
fn inspect(root: &Path) -> Host {
    let (raw, state) = read(&root.join("etc/os-release"));
    let fields: BTreeMap<_, _> = raw
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim(), v.trim().trim_matches(['\'', '"'])))
        .collect();
    let mut host = Host {
        supported: fields.get("ID") == Some(&"ubuntu"),
        distribution: fields.get("ID").unwrap_or(&"").to_string(),
        release: fields.get("VERSION_ID").unwrap_or(&"").to_string(),
        architecture: match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            "loongarch64" => "loong64",
            v => v,
        }
        .into(),
        sources: vec![],
        diagnostics: vec![],
        plan: Plan {
            mutates_host: false,
            steps: vec![
                "inspect /etc/os-release".into(),
                "inspect APT source definitions without changing them".into(),
                "inspect Docker registry mirrors without changing them".into(),
            ],
        },
    };
    if state != "ok" {
        host.diagnostics.push(diagnostic(
            &format!("os_release_{state}"),
            "warning",
            "Ubuntu source inspection could not identify /etc/os-release",
            "",
        ));
    }
    if !host.supported {
        host.diagnostics.push(diagnostic(
            "unsupported_host",
            "warning",
            "managed host-source inventory currently supports Ubuntu only",
            "use the external-host operator workflow",
        ));
    }
    let mut paths = vec!["/etc/apt/sources.list".to_owned()];
    let dir = root.join("etc/apt/sources.list.d");
    if std::fs::symlink_metadata(&dir).is_ok_and(|v| v.is_dir() && !v.is_symlink()) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.ends_with(".list") || name.ends_with(".sources") {
                    paths.push(format!("/etc/apt/sources.list.d/{name}"));
                }
            }
        }
    }
    for path in paths {
        let (raw, state) = read(&root.join(path.trim_start_matches('/')));
        if state != "ok" {
            host.sources.push(source("apt", &path, "", state));
        } else if path.ends_with(".sources") {
            for block in raw.replace("\r\n", "\n").split("\n\n") {
                let fields: BTreeMap<_, _> = block
                    .lines()
                    .filter_map(|l| l.split_once(':'))
                    .map(|(k, v)| (k.trim().to_lowercase(), v.trim()))
                    .collect();
                let status = if fields
                    .get("enabled")
                    .is_some_and(|s| s.eq_ignore_ascii_case("no"))
                {
                    "disabled"
                } else {
                    "active"
                };
                for uri in fields.get("uris").unwrap_or(&"").split_whitespace() {
                    host.sources
                        .push(source("apt", &path, &redact(uri), status));
                }
            }
        } else {
            host.sources.extend(apt(&path, &raw));
        }
    }
    let path = "/etc/docker/daemon.json";
    let (raw, state) = read(&root.join(path.trim_start_matches('/')));
    if state != "missing" {
        if state != "ok" {
            host.sources
                .push(source("docker_registry", path, "", state));
        } else {
            #[derive(serde::Deserialize)]
            struct Docker {
                #[serde(rename = "registry-mirrors")]
                mirrors: Option<Vec<String>>,
            }
            match serde_json::from_str::<Docker>(&raw) {
                Err(_) => host
                    .sources
                    .push(source("docker_registry", path, "", "malformed")),
                Ok(doc) => {
                    let mirrors = doc.mirrors.unwrap_or_default();
                    if mirrors.is_empty() {
                        host.sources
                            .push(source("docker_registry", path, "", "no_mirrors"));
                    } else {
                        for uri in mirrors {
                            host.sources.push(source(
                                "docker_registry",
                                path,
                                &redact(&uri),
                                "active",
                            ));
                        }
                    }
                }
            }
        }
    }
    host.sources
        .sort_by_key(|r| format!("{}{}{}{}", r.kind, r.path, r.location, r.status));
    host
}
fn source(kind: &str, path: &str, location: &str, status: &str) -> Source {
    Source {
        kind: kind.into(),
        path: path.into(),
        location: location.into(),
        ownership: if Path::new(path)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase()
            .starts_with("setjoin.")
            || Path::new(path)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_lowercase()
                .starts_with("setjoin-")
        {
            "setjoin_managed"
        } else {
            "external"
        }
        .into(),
        status: status.into(),
    }
}
fn apt(path: &str, raw: &str) -> Vec<Source> {
    let mut rows = vec![];
    for line in raw.lines() {
        let line = line.trim();
        let (line, status) = if let Some(v) = line.strip_prefix('#') {
            (v.trim(), "disabled")
        } else {
            (line, "active")
        };
        if !line.starts_with("deb ") && !line.starts_with("deb-src ") {
            continue;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let mut i = 1;
        if fields.get(i).is_some_and(|v| v.starts_with('[')) {
            while i < fields.len() && !fields[i].ends_with(']') {
                i += 1;
            }
            i += 1;
        }
        rows.push(source(
            "apt",
            path,
            &fields.get(i).map(|v| redact(v)).unwrap_or_default(),
            if i < fields.len() {
                status
            } else {
                "malformed"
            },
        ));
    }
    rows
}
fn redact(raw: &str) -> String {
    if let Ok(mut u) = url::Url::parse(raw) {
        if u.host_str().is_some() {
            u.set_username("").ok();
            u.set_password(None).ok();
            u.set_query(None);
            u.set_fragment(None);
            return u.to_string();
        }
    }
    let raw = raw.trim();
    if let Some((_, after)) = raw.split_once('@') {
        return format!(
            "[redacted]@{}",
            after.split(['?', '#']).next().unwrap_or_default()
        );
    }
    let raw = raw.split(['?', '#']).next().unwrap_or_default();
    if raw.is_empty() || raw.contains('%') {
        "[invalid]".into()
    } else {
        raw.into()
    }
}
