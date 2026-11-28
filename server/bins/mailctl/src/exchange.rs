//! Frozen Exchange assessment package, available without a server.
use crate::client::{go_json, Failure};
use serde_json::{json, Value};
const PHASE: &str = "V1A assessment only — replacement readiness not established";
const REGISTRY: &[u8] = include_bytes!("exchange_registry_v1.json");

pub fn run(action: &str, args: &[String]) -> Result<(), Failure> {
    if action != "assess" || args.is_empty() {
        return Err(Failure::from("usage: mailctl exchange assess preflight|sample|collect|inspect|report|import|diagnose").exit(2));
    }
    let verb = &args[0];
    let a = &args[1..];
    if verb == "preflight" {
        let f = crate::flags::parse(
            "exchange assess preflight",
            a,
            &["write-config"],
            &["json", "offline", "doctor"],
            false,
        );
        let registry: Value = serde_json::from_slice(REGISTRY).unwrap();
        let runtime = format!(
            "{}/{}",
            std::env::consts::OS,
            match std::env::consts::ARCH {
                "x86_64" => "amd64",
                "aarch64" => "arm64",
                "loongarch64" => "loong64",
                a => a,
            }
        );
        let mut checks = vec![
            json!({"id":"PKG-REGISTRY","status":"pass","detail":format!("registry v{} source {}",registry["registryVersion"],registry["sourceDigest"].as_str().unwrap())}),
            json!({"id":"RUNTIME","status":"pass","detail":runtime}),
            json!({"id":"NETWORK","status":"pass","detail":if f.boolean("offline"){"offline: no network attempted"}else{"connected checks not requested"}}),
        ];
        if f.boolean("doctor") {
            checks.push(json!({"id":"FIXTURE","status":"pass","detail":format!("{} capabilities; embedded sha256 {}",registry["capabilities"].as_array().unwrap().len(),crate::offline::digest(REGISTRY))}));
        }
        if !f.get("write-config").is_empty() {
            crate::offline::private_new(f.get("write-config"),b"schema_version: 1\nexchange:\n  servers: []\ncollection:\n  modules: [topology, identities, delegates, calendars, resources]\n  max_parallel: 4\nredaction:\n  profile: standard\noutput:\n  locale: zh-CN\n  retention_days: 30\n")?;
        }
        if f.boolean("json") {
            println!(
                "{}",
                go_json(
                    &json!({"schemaVersion":"setjoin.exchange.preflight/v1","phase":PHASE,"offline":f.boolean("offline"),"complete":true,"checks":checks}),
                    true
                )
            );
        } else {
            println!("{PHASE}");
            for c in checks {
                println!(
                    "[PASS] {}: {}",
                    c["id"].as_str().unwrap(),
                    c["detail"].as_str().unwrap()
                );
            }
        }
        return Ok(());
    }
    if verb == "sample" {
        let f = crate::flags::parse("exchange assess sample", a, &["output"], &["json"], false);
        if f.get("output").is_empty() {
            return Err(Failure::from(
                "usage: mailctl exchange assess sample --output <new-dir> [--json]",
            )
            .exit(2));
        }
        let r: Value = serde_json::from_slice(REGISTRY).unwrap();
        let cell = &r["supportCells"][0];
        let mut b = Bundle {
            schema_version: "setjoin.exchange.bundle/v1".into(),
            phase: PHASE.into(),
            importable: false,
            registry_version: r["registryVersion"].as_i64().unwrap(),
            registry_digest: r["sourceDigest"].as_str().unwrap().into(),
            catalog_version: r["catalogVersion"].as_i64().unwrap(),
            support_cell_id: cell["id"].as_str().unwrap().into(),
            support_cell_digest: cell["digest"].as_str().unwrap().into(),
            collector_version: cell["collectorVersion"].as_str().unwrap().into(),
            collected_at: "2026-08-23T00:00:00Z".into(),
            origin_digest: String::new(),
            probes: Some(
                r["capabilities"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|c| Probe {
                        capability_id: c["id"].as_str().unwrap().into(),
                        state: "unassessed".into(),
                        diagnostic_id: "SAMPLE-001".into(),
                        safe_facts: Some(std::collections::BTreeMap::from([(
                            "fixture".into(),
                            true.into(),
                        )])),
                    })
                    .collect(),
            ),
        };
        b.origin_digest = crate::offline::digest(serialized(&b).as_bytes());
        mkdir(f.get("output")).map_err(|e| Failure::from(format!("create output: {e}")).exit(2))?;
        crate::offline::private_new(
            &format!("{}/bundle.sja", f.get("output")),
            format!("{}\n", pretty(&b)).as_bytes(),
        )?;
        reports(f.get("output"), &b, &r)?;
        if f.boolean("json") {
            println!(
                "{}",
                go_json(
                    &json!({"output":f.get("output"),"originDigest":b.origin_digest,"complete":true}),
                    true
                )
            );
        } else {
            println!("Sample written to {}\n{PHASE}", f.get("output"));
        }
        return Ok(());
    }
    if verb == "inspect" {
        let (path, a) = if a.first().is_some_and(|s| !s.starts_with('-')) {
            (Some(a[0].as_str()), &a[1..])
        } else {
            (None, a)
        };
        let f = crate::flags::parse("exchange assess inspect", a, &[], &["json"], false);
        let path = path
            .or_else(|| f.positional.first().map(String::as_str))
            .ok_or_else(|| {
                Failure::from("usage: mailctl exchange assess inspect <bundle.sja> [--json]")
                    .exit(2)
            })?;
        let (b, _) = read_bundle(path)?;
        let mut counts = std::collections::BTreeMap::new();
        for p in b.probes.as_deref().unwrap_or_default() {
            *counts.entry(p.state.clone()).or_insert(0) += 1;
        }
        if f.boolean("json") {
            println!(
                "{}",
                go_json(
                    &json!({"phase":b.phase,"importable":b.importable,"originDigest":b.origin_digest,"supportCellId":b.support_cell_id,"collectorVersion":b.collector_version,"counts":counts,"excludedByDefault":["credentials","tokens","message content","raw identities","customer documents"]}),
                    true
                )
            );
        } else {
            println!(
                "{}\nDigest: {}\nSupport cell: {}",
                b.phase, b.origin_digest, b.support_cell_id
            );
            for (k, v) in counts {
                println!("{k}: {v}");
            }
        }
        return Ok(());
    }
    if verb == "report" {
        let (path, a) = if a.first().is_some_and(|s| !s.starts_with('-')) {
            (Some(a[0].as_str()), &a[1..])
        } else {
            (None, a)
        };
        let f = crate::flags::parse(
            "exchange assess report",
            a,
            &["output", "format"],
            &[],
            false,
        );
        let path=path.or_else(||f.positional.first().map(String::as_str)).filter(|_|!f.get("output").is_empty()).ok_or_else(||Failure::from("usage: mailctl exchange assess report <bundle.sja> --output <new-dir> [--format html,json]").exit(2))?;
        let (b, _) = read_bundle(path)?;
        let r = serde_json::from_slice(REGISTRY).unwrap();
        mkdir(f.get("output"))?;
        reports(f.get("output"), &b, &r)?;
        println!("Reports written to {}", f.get("output"));
        return Ok(());
    }
    if verb == "diagnose" {
        let (path, a) = if a.first().is_some_and(|s| !s.starts_with('-')) {
            (Some(a[0].as_str()), &a[1..])
        } else {
            (None, a)
        };
        let f = crate::flags::parse("exchange assess diagnose", a, &["output"], &[], false);
        let path = path
            .or_else(|| f.positional.first().map(String::as_str))
            .filter(|_| !f.get("output").is_empty())
            .ok_or_else(|| {
                Failure::from(
                    "usage: mailctl exchange assess diagnose <bundle.sja> --output <new-file>",
                )
                .exit(2)
            })?;
        let (b, _) = read_bundle(path)?;
        let mut counts = std::collections::BTreeMap::new();
        for p in b.probes.as_deref().unwrap_or_default() {
            *counts.entry(p.diagnostic_id.clone()).or_insert(0) += 1;
        }
        let support = json!({"schemaVersion":"setjoin.exchange.support/v1","originDigest":b.origin_digest,"versions":{"registry":b.registry_version,"catalog":b.catalog_version,"collector":b.collector_version},"diagnosticCounts":counts,"redaction":"raw facts, identities, credentials and documents excluded"});
        crate::offline::private_new(
            f.get("output"),
            format!("{}\n", go_json(&support, true)).as_bytes(),
        )?;
        return Ok(());
    }
    if verb == "collect" {
        let f = crate::flags::parse(
            "exchange assess collect",
            a,
            &["input", "output", "resume"],
            &["non-interactive"],
            false,
        );
        if f.get("input").is_empty() || f.get("output").is_empty() {
            return Err(Failure::from("usage: mailctl exchange assess collect --input collector.json --output DIR [--resume checkpoint.json]").exit(2));
        }
        if !f.get("resume").is_empty() {
            return Err(Failure::from("COLLECT-005: resumable collection is not available in the bounded V1A file-conversion lane; rerun the fixed source collector and collect into a new output directory").exit(2));
        }
        #[derive(Default, serde::Deserialize)]
        #[serde(default, deny_unknown_fields, rename_all = "camelCase")]
        struct Collector {
            schema_version: String,
            support_cell_id: String,
            collected_at: String,
            probes: Option<Vec<Probe>>,
        }
        let raw = crate::offline::bounded(f.get("input"), 16 << 20)
            .map_err(|e| Failure::from(format!("COLLECT-001: {e}")).exit(5))?;
        let c: Collector = crate::offline::strict(&raw)
            .map_err(|e| Failure::from(format!("COLLECT-001: {e}")).exit(5))?;
        if c.schema_version != "setjoin.exchange.collector-output/v1" {
            return Err(Failure::from("COLLECT-001: unsupported collector output schema").exit(7));
        }
        let r: Value = serde_json::from_slice(REGISTRY).unwrap();
        let cell = r["supportCells"]
            .as_array()
            .unwrap()
            .iter()
            .find(|cell| cell["id"] == c.support_cell_id)
            .ok_or_else(|| Failure::from("COLLECT-002: unknown support cell").exit(7))?;
        let mut b = Bundle {
            schema_version: "setjoin.exchange.bundle/v1".into(),
            phase: PHASE.into(),
            importable: true,
            registry_version: r["registryVersion"].as_i64().unwrap(),
            registry_digest: r["sourceDigest"].as_str().unwrap().into(),
            catalog_version: r["catalogVersion"].as_i64().unwrap(),
            support_cell_id: c.support_cell_id,
            support_cell_digest: cell["digest"].as_str().unwrap().into(),
            collector_version: cell["collectorVersion"].as_str().unwrap().into(),
            collected_at: c.collected_at,
            origin_digest: String::new(),
            probes: c.probes,
        };
        b.origin_digest = crate::offline::digest(serialized(&b).as_bytes());
        mkdir(f.get("output"))?;
        let path = format!("{}/bundle.sja", f.get("output"));
        crate::offline::private_new(&path, format!("{}\n", pretty(&b)).as_bytes())?;
        if let Err(e) = read_bundle(&path) {
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_dir(f.get("output"));
            return Err(e);
        }
        reports(f.get("output"), &b, &r)?;
        println!("Importable V1A bundle written to {} on {}/{}; live Exchange evidence remains unassessed until the collector output is captured in an approved support cell.",f.get("output"),std::env::consts::OS,match std::env::consts::ARCH{"x86_64"=>"amd64","aarch64"=>"arm64","loongarch64"=>"loong64",a=>a});
        return Ok(());
    }
    if verb == "import" {
        let (path, a) = if a.first().is_some_and(|s| !s.starts_with('-')) {
            (Some(a[0].as_str()), &a[1..])
        } else {
            (None, a)
        };
        let f = crate::flags::parse(
            "exchange assess import",
            a,
            &["project-id", "server"],
            &["json"],
            false,
        );
        let id = f.get("project-id").parse::<i64>().unwrap_or(0);
        let path=path.or_else(||f.positional.first().map(String::as_str)).filter(|_|id>0).ok_or_else(||Failure::from("usage: mailctl exchange assess import <bundle.sja> --project-id ID [--server URL] [--json]").exit(2))?;
        let (b, raw) = read_bundle(path)?;
        if !b.importable {
            return Err(Failure::from(
                "IMPORT-001: this sample/A0 bundle is explicitly non-importable",
            )
            .exit(5));
        }
        let api = crate::client::Api::load()
            .map_err(|e| Failure::from(e).exit(3))?
            .override_server(f.get("server"));
        let body = json!({"supportCellId":b.support_cell_id,"supportCellDigest":b.support_cell_digest,"registryVersion":b.registry_version,"registryDigest":b.registry_digest,"catalogVersion":b.catalog_version,"collectorVersion":b.collector_version});
        let run = api
            .with_headers(
                "POST",
                &format!("/admin/exchange-replacement/projects/{id}/runs"),
                Some(body),
                true,
                &[
                    (
                        "X-Audit-Reason",
                        "Import verified Exchange assessment bundle".into(),
                    ),
                    ("Idempotency-Key", crate::part_b::new_uuid()?),
                ],
                1 << 20,
            )
            .map_err(api_exit)?;
        let id = run["id"].as_i64().unwrap_or(0);
        let generation = run["generation"].as_i64().unwrap_or(0);
        if id < 1 || generation < 1 {
            return Err(
                Failure::from("IMPORT-004: server returned an invalid run receipt").exit(10),
            );
        }
        let (response, _) = api
            .bytes(
                "PUT",
                &format!("/admin/exchange-replacement/runs/{id}/bundle"),
                Some("application/vnd.setjoin.exchange-bundle+json"),
                Some(raw.clone()),
                &[
                    (
                        "X-Audit-Reason",
                        "Upload verified Exchange assessment bundle".into(),
                    ),
                    ("X-Run-Generation", generation.to_string()),
                    ("X-Content-SHA256", crate::offline::digest(&raw)),
                ],
                1 << 20,
            )
            .map_err(api_exit)?;
        let artifact: Value =
            serde_json::from_slice(&response).map_err(|e| Failure::from(e.to_string()).exit(6))?;
        if f.boolean("json") {
            println!(
                "{}",
                go_json(
                    &json!({"id":id,"generation":generation,"artifact":artifact,"originDigest":b.origin_digest,"importDigestMatch":true}),
                    true
                )
            );
        } else {
            println!("Imported assessment run {id}; encrypted artifact committed; origin digest {} verified",b.origin_digest);
        }
        return Ok(());
    }
    Err(Failure::from(format!("unknown exchange assess action {verb:?}")).exit(2))
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
struct Probe {
    capability_id: String,
    state: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    diagnostic_id: String,
    #[serde(skip_serializing_if = "empty_facts")]
    #[serde(serialize_with = "go_facts")]
    safe_facts: Option<std::collections::BTreeMap<String, Value>>,
}
fn empty_facts(v: &Option<std::collections::BTreeMap<String, Value>>) -> bool {
    v.as_ref().is_none_or(|v| v.is_empty())
}
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
struct Bundle {
    schema_version: String,
    phase: String,
    importable: bool,
    registry_version: i64,
    registry_digest: String,
    catalog_version: i64,
    support_cell_id: String,
    support_cell_digest: String,
    collector_version: String,
    collected_at: String,
    origin_digest: String,
    probes: Option<Vec<Probe>>,
}
fn go_facts<S: serde::Serializer>(
    facts: &Option<std::collections::BTreeMap<String, Value>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let value = serde_json::to_value(facts).map_err(serde::ser::Error::custom)?;
    let raw =
        serde_json::value::RawValue::from_string(crate::client::go_json_generic(&value, false))
            .map_err(serde::ser::Error::custom)?;
    serde::Serialize::serialize(&raw, serializer)
}
fn serialized<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v)
        .unwrap()
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}
fn pretty<T: serde::Serialize>(v: &T) -> String {
    crate::part_b::ordered_pretty(&serialized(v))
}
fn reports(dir: &str, b: &Bundle, r: &Value) -> Result<(), Failure> {
    let probes = b.probes.as_deref().unwrap_or_default();
    let rows=r["capabilities"].as_array().unwrap().iter().map(|c|{
        let p=probes.iter().find(|p|Some(p.capability_id.as_str())==c["id"].as_str());
        json!({"capabilityId":c["id"],"outcome":c["outcome"],"category":c["category"],"mappingMaximum":c["mappingMaximum"],"claimMaximum":c["claimMaximum"],"state":p.map(|p|p.state.as_str()).unwrap_or("unassessed"),"diagnosticId":p.map(|p|p.diagnostic_id.as_str()).unwrap_or("COLLECT-003")})
    }).collect::<Vec<_>>();
    let complete = probes.len() == rows.len()
        && probes
            .iter()
            .all(|p| matches!(p.state.as_str(), "complete" | "complete_zero"));
    let report = json!({"schemaVersion":"setjoin.exchange.report/v1","phase":b.phase,"replacementReady":false,"originDigest":b.origin_digest,"registryDigest":b.registry_digest,"complete":complete,"rows":rows});
    let manifest = json!({"schemaVersion":"setjoin.exchange.manifest/v1","originDigest":b.origin_digest,"registryDigest":b.registry_digest,"included":["report.json","report.html","receipt.json"],"omitted":["raw facts","identities","credentials","customer documents"]});
    let receipt = json!({"schemaVersion":"setjoin.exchange.receipt/v1","kind":"local-report","originDigest":b.origin_digest,"signatureStatus":if b.importable{"integrity_only_sha256"}else{"unsigned_fixture"},"importable":b.importable});
    for (name, v) in [
        ("report.json", report),
        ("manifest.json", manifest),
        ("receipt.json", receipt),
    ] {
        crate::offline::private_new(
            &format!("{dir}/{name}"),
            format!("{}\n", go_json(&v, true)).as_bytes(),
        )?;
    }
    let mut html=String::from("<!doctype html><html lang=\"zh-CN\"><meta charset=\"utf-8\"><title>Exchange replacement assessment</title><style>body{font:16px system-ui;max-width:1100px;margin:40px auto;padding:0 20px;color:#172033}table{width:100%;border-collapse:collapse}th,td{padding:10px;border-bottom:1px solid #ccd3dd;text-align:left}.warning{padding:16px;background:#fff4d6;border-left:4px solid #ad6b00}</style><h1>Exchange 替代评估 / Exchange replacement assessment</h1><p class=\"warning\">");
    html.push_str(&escape(&b.phase));
    html.push_str("。未知不是零；本报告不构成替代就绪声明。</p><p>Origin digest: <code>");
    html.push_str(&escape(&b.origin_digest));
    html.push_str("</code></p><table><thead><tr><th>ID</th><th>Outcome</th><th>State</th></tr></thead><tbody>");
    for row in rows {
        html.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape(row["capabilityId"].as_str().unwrap_or("")),
            escape(row["outcome"]["zh"].as_str().unwrap_or("")),
            escape(row["state"].as_str().unwrap_or(""))
        ));
    }
    html.push_str("</tbody></table></html>");
    crate::offline::private_new(&format!("{dir}/report.html"), html.as_bytes())
}
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&#34;")
        .replace('\'', "&#39;")
        .replace('+', "&#43;")
}
fn mkdir(path: &str) -> Result<(), Failure> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|e| {
            Failure::from(format!("mkdir {path}: {}", crate::flags::go_io_error(&e))).exit(2)
        })
}
fn read_bundle(path: &str) -> Result<(Bundle, Vec<u8>), Failure> {
    let raw = crate::offline::bounded(path, 64 << 20)
        .map_err(|e| Failure::from(format!("IMPORT-003: {e}")).exit(5))?;
    let mut b: Bundle = crate::offline::strict(&raw)
        .map_err(|e| Failure::from(format!("IMPORT-003: {e}")).exit(5))?;
    if b.schema_version != "setjoin.exchange.bundle/v1" {
        return Err(Failure::from("IMPORT-001: unsupported bundle schema").exit(7));
    }
    let digest = std::mem::take(&mut b.origin_digest);
    let expected = crate::offline::digest(serialized(&b).as_bytes());
    b.origin_digest = digest;
    if b.origin_digest != expected {
        return Err(Failure::from("IMPORT-002: bundle digest mismatch").exit(5));
    }
    let r: Value = serde_json::from_slice(REGISTRY).unwrap();
    if b.registry_version != r["registryVersion"].as_i64().unwrap()
        || Some(b.registry_digest.as_str()) != r["sourceDigest"].as_str()
    {
        return Err(Failure::from("IMPORT-001: registry version/digest mismatch").exit(7));
    }
    if b.catalog_version != r["catalogVersion"].as_i64().unwrap() || b.phase != PHASE {
        return Err(Failure::from("IMPORT-001: catalog/phase mismatch").exit(7));
    }
    let cell = r["supportCells"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == b.support_cell_id);
    if cell.is_none_or(|c| {
        c["digest"] != b.support_cell_digest
            || c["collectorVersion"] != b.collector_version
            || c["catalogVersion"] != b.catalog_version
            || c["registryVersion"] != b.registry_version
    }) {
        return Err(Failure::from("IMPORT-001: support-cell/collector tuple mismatch").exit(7));
    }
    if !crate::offline::utc_second(&b.collected_at) {
        return Err(Failure::from("IMPORT-003: collectedAt must be canonical UTC RFC3339").exit(5));
    }
    let known = r["capabilities"].as_array().unwrap();
    let probes = b.probes.as_deref().unwrap_or_default();
    if probes.len() > known.len() {
        return Err(Failure::from("IMPORT-003: probe count exceeds registry denominator").exit(5));
    }
    let mut seen = std::collections::BTreeSet::new();
    for p in probes {
        if !known.iter().any(|c| c["id"] == p.capability_id) {
            return Err(Failure::from("IMPORT-003: unknown capability probe").exit(5));
        }
        if !seen.insert(&p.capability_id) {
            return Err(Failure::from("IMPORT-003: duplicate capability probe").exit(5));
        }
        if !matches!(
            p.state.as_str(),
            "complete" | "complete_zero" | "partial" | "failed" | "unassessed"
        ) {
            return Err(Failure::from("IMPORT-003: invalid terminal probe state").exit(5));
        }
        if !p.diagnostic_id.is_empty() && !diagnostic(&p.diagnostic_id) {
            return Err(Failure::from("IMPORT-003: invalid diagnostic ID").exit(5));
        }
        let facts = serde_json::to_value(&p.safe_facts).unwrap();
        if serialized(&p.safe_facts).len() > 64 << 10 || sensitive(&facts) {
            return Err(Failure::from("IMPORT-003: unsafe or oversized safeFacts").exit(5));
        }
    }
    if b.importable && seen.len() != known.len() {
        return Err(Failure::from(
            "COLLECT-003: importable bundle has an incomplete probe denominator",
        )
        .exit(4));
    }
    Ok((b, raw))
}
fn diagnostic(s: &str) -> bool {
    s.len() >= 2
        && s.len() <= 64
        && s.as_bytes()[0].is_ascii_uppercase()
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-')
}
fn sensitive(v: &Value) -> bool {
    match v {
        Value::Object(m) => m.iter().any(|(k, v)| {
            matches!(
                k.to_lowercase().replace(['_', '-'], "").as_str(),
                "credential"
                    | "password"
                    | "accesstoken"
                    | "refreshtoken"
                    | "privatekey"
                    | "messagebody"
                    | "rawidentity"
            ) || sensitive(v)
        }),
        Value::Array(a) => a.iter().any(sensitive),
        _ => false,
    }
}

fn api_exit(e: Failure) -> Failure {
    let code = match e.status {
        401 | 403 => 3,
        409 => 4,
        429 | 500..=599 => 6,
        0 => 6,
        _ => 10,
    };
    e.exit(code)
}
