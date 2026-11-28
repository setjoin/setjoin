//! Non-importable concierge evidence; no backend is constructed.
use crate::client::Failure;
const REGISTRY: &[u8] = include_bytes!("exchange_a0_registry_v0.json");
pub fn run(action: &str, args: &[String]) -> Result<(), Failure> {
    if action == "registry" {
        let f = crate::flags::parse("exchange-a0 registry", args, &["output"], &[], false);
        if !f.positional.is_empty() || f.get("output").is_empty() {
            return Err("usage: exchange-a0 registry --output <new-file>".into());
        }
        crate::offline::private_new(f.get("output"), REGISTRY)
            .map_err(|e| format!("create new output {}: {e}", f.get("output")))?;
        println!(
            "A0/v0 registry written to {}\nSHA-256: {}",
            f.get("output"),
            crate::offline::digest(REGISTRY)
        );
        return Ok(());
    }
    if action == "validate" {
        let f = crate::flags::parse("exchange-a0 validate", args, &["input"], &[], false);
        if !f.positional.is_empty() || f.get("input").is_empty() {
            return Err("usage: exchange-a0 validate --input <collector.json>".into());
        }
        let (_, digest) = input(f.get("input"))?;
        println!("Valid non-importable A0/v0 input. SHA-256: {digest}");
        return Ok(());
    }
    if action == "report" {
        let f = crate::flags::parse(
            "exchange-a0 report",
            args,
            &["input", "output", "locale", "generated-at"],
            &["pdf"],
            false,
        );
        if !f.positional.is_empty() || f.get("input").is_empty() || f.get("output").is_empty() {
            return Err("usage: exchange-a0 report --input <collector.json> --output <new-dir> [--locale zh-CN|en-US] [--pdf]".into());
        }
        let locale = if f.set("locale") {
            f.get("locale")
        } else {
            "zh-CN"
        };
        if !matches!(locale, "zh-CN" | "en-US") {
            return Err(format!("unsupported locale {locale:?}").into());
        }
        let when = if f.get("generated-at").is_empty() {
            chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
        } else {
            f.get("generated-at").into()
        };
        if !crate::offline::utc_second(&when) {
            return Err("generated-at must be canonical UTC RFC3339".into());
        }
        let (i, digest) = input(f.get("input"))?;
        let registry: serde_json::Value = serde_json::from_slice(REGISTRY).unwrap();
        let mut rows = vec![];
        let mut complete = 0;
        for c in registry["capabilities"].as_array().unwrap() {
            let p = i
                .probes
                .as_deref()
                .unwrap_or_default()
                .iter()
                .find(|p| c["id"] == p.capability_id)
                .cloned()
                .unwrap_or_else(|| Probe {
                    capability_id: c["id"].as_str().unwrap().into(),
                    status: "unassessed".into(),
                    diagnostic_id: "A0-MISSING".into(),
                    detail: "Collector emitted no result for this capability.".into(),
                    facts: Some(serde_json::value::RawValue::from_string("{}".into()).unwrap()),
                });
            if p.status == "observed" {
                complete += 1;
            }
            rows.push(Row {
                capability_id: p.capability_id,
                title: c["title"].as_str().unwrap().into(),
                outcome: c["outcome"].as_str().unwrap().into(),
                status: p.status,
                diagnostic_id: p.diagnostic_id,
                detail: p.detail,
                facts: p.facts,
            });
        }
        let row_digest = crate::offline::digest(json(&rows).as_bytes());
        let report = Report {
            schema_version: "setjoin.exchange.a0.report/v0".into(),
            phase: PHASE.into(),
            importable: false,
            registry_digest: crate::offline::digest(REGISTRY),
            input_digest: digest,
            row_set_digest: row_digest,
            generated_at: when,
            source: i.source,
            complete,
            expected: rows.len() as i64,
            rows: Some(rows),
        };
        return write_report(f.get("output"), locale, &report, f.boolean("pdf"));
    }
    if action == "attest" {
        let f = crate::flags::parse(
            "exchange-a0 attest",
            args,
            &[
                "kind",
                "report",
                "organization",
                "actor",
                "decision",
                "purpose",
                "retention-days",
                "issued-at",
                "output",
            ],
            &[],
            false,
        );
        if !f.positional.is_empty()
            || [
                "report",
                "organization",
                "actor",
                "purpose",
                "output",
                "issued-at",
            ]
            .iter()
            .any(|k| f.get(k).is_empty())
        {
            return Err("usage: exchange-a0 attest --kind handling|decision-use --report report.json --organization TEXT --actor TEXT --decision VALUE --purpose TEXT --retention-days N --issued-at UTC --output <new-file>".into());
        }
        let kind = f.get("kind");
        let decision = f.get("decision");
        if (kind == "handling" && !matches!(decision, "accepted" | "rejected"))
            || (kind == "decision-use" && !matches!(decision, "go" | "no-go" | "defer"))
        {
            return Err("invalid receipt kind or decision".into());
        }
        if !text(f.get("organization"), 256)
            || !text(f.get("actor"), 256)
            || !text(f.get("purpose"), 1024)
        {
            return Err(
                "organization, actor, or purpose contains invalid or excessive text".into(),
            );
        }
        let days = f.get("retention-days").parse::<i64>().unwrap_or(0);
        if !crate::offline::utc_second(f.get("issued-at")) || !(0..=3650).contains(&days) {
            return Err(
                "issued-at must be canonical UTC RFC3339 and retention-days must be 0..3650".into(),
            );
        }
        let raw = crate::offline::bounded(f.get("report"), 16 << 20)?;
        let report: Report = decode(&raw).map_err(|e| format!("decode A0 report: {e}"))?;
        valid_report(&report)
            .map_err(|_| "receipt requires a valid non-importable A0/v0 report")?;
        let mut receipt = Receipt {
            schema_version: "setjoin.exchange.a0.receipt/v0".into(),
            receipt_kind: kind.into(),
            report_digest: crate::offline::digest(&raw),
            organization: f.get("organization").into(),
            actor: f.get("actor").into(),
            decision: decision.into(),
            purpose: f.get("purpose").into(),
            retention_days: days,
            issued_at: f.get("issued-at").into(),
            signature_status: "unsigned_customer_attestation".into(),
            ..Default::default()
        };
        receipt.receipt_id = crate::offline::digest(json(&receipt).as_bytes());
        crate::offline::private_new(
            f.get("output"),
            format!("{}\n", pretty(&receipt)).as_bytes(),
        )
        .map_err(|e| format!("create new output {}: {e}", f.get("output")))?;
        println!(
            "Unsigned, non-importable A0/v0 {kind} receipt written to {}",
            f.get("output")
        );
        return Ok(());
    }
    if action == "verify-receipt" {
        let f = crate::flags::parse(
            "exchange-a0 verify-receipt",
            args,
            &["receipt", "report"],
            &[],
            false,
        );
        if !f.positional.is_empty() || f.get("receipt").is_empty() || f.get("report").is_empty() {
            return Err(
                "usage: exchange-a0 verify-receipt --receipt <receipt.json> --report <report.json>"
                    .into(),
            );
        }
        let raw = crate::offline::bounded(f.get("receipt"), 16 << 20)?;
        let mut receipt: Receipt = decode(&raw).map_err(|e| format!("decode A0 receipt: {e}"))?;
        let valid_decision = (receipt.receipt_kind == "handling"
            && matches!(receipt.decision.as_str(), "accepted" | "rejected"))
            || (receipt.receipt_kind == "decision-use"
                && matches!(receipt.decision.as_str(), "go" | "no-go" | "defer"));
        if receipt.schema_version != "setjoin.exchange.a0.receipt/v0"
            || receipt.importable
            || receipt.signature_status != "unsigned_customer_attestation"
            || !valid_decision
            || !crate::identity_checks::hex(&receipt.receipt_id, 64)
            || !crate::identity_checks::hex(&receipt.report_digest, 64)
            || !text(&receipt.organization, 256)
            || !text(&receipt.actor, 256)
            || !text(&receipt.purpose, 1024)
            || !(0..=3650).contains(&receipt.retention_days)
            || !crate::offline::utc_second(&receipt.issued_at)
        {
            return Err("invalid A0/v0 receipt fields".into());
        }
        let id = std::mem::take(&mut receipt.receipt_id);
        let expected = crate::offline::digest(json(&receipt).as_bytes());
        receipt.receipt_id = id;
        if expected != receipt.receipt_id {
            return Err("A0 receipt ID mismatch".into());
        }
        let raw = crate::offline::bounded(f.get("report"), 16 << 20)?;
        let report: Report = decode(&raw).map_err(|e| format!("decode bound A0 report: {e}"))?;
        valid_report(&report).map_err(|e| format!("validate bound A0 report: {e}"))?;
        if crate::offline::digest(&raw) != receipt.report_digest {
            return Err("A0 receipt report digest mismatch".into());
        }
        println!(
            "Valid unsigned, non-importable A0/v0 {} receipt {}",
            receipt.receipt_kind, receipt.receipt_id
        );
        return Ok(());
    }
    Err(format!("unknown exchange-a0 action {action:?} (expected registry, validate, report, attest, or verify-receipt)").into())
}

#[derive(Default, serde::Serialize, serde::Deserialize, Clone)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
struct Source {
    organization: String,
    topology: String,
    builds: Option<Vec<String>>,
}
#[derive(Default, serde::Serialize, serde::Deserialize, Clone)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
struct Probe {
    capability_id: String,
    status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    diagnostic_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    detail: String,
    #[serde(deserialize_with = "raw_facts")]
    facts: Option<Box<serde_json::value::RawValue>>,
}
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
struct Input {
    schema_version: String,
    artifact_kind: String,
    collector_version: String,
    registry_digest: String,
    collected_at: String,
    source: Source,
    probes: Option<Vec<Probe>>,
}
fn text(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && !s.chars().any(|c| c < '\u{20}' || c == '\u{7f}')
}
fn raw_facts<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<Box<serde_json::value::RawValue>>, D::Error> {
    <Box<serde_json::value::RawValue> as serde::Deserialize>::deserialize(d).map(Some)
}
fn decode<T: serde::de::DeserializeOwned>(raw: &[u8]) -> Result<T, String> {
    // Preserve RawMessage key order on the ordinary path. Go's A0 decoder
    // permits duplicate typed fields (last wins), unlike its V1 successor.
    if let Ok(value) = serde_json::from_slice(raw) {
        return Ok(value);
    }
    let value: serde_json::Value =
        serde_json::from_slice(raw).map_err(|e| crate::offline::json_diagnostic(raw, &e))?;
    serde_json::from_value(value).map_err(|e| crate::offline::json_diagnostic(raw, &e))
}
fn input(path: &str) -> Result<(Input, String), Failure> {
    let raw = crate::offline::bounded(path, 16 << 20)?;
    let i: Input = decode(&raw).map_err(|e| format!("decode A0 input: {e}"))?;
    if i.schema_version != "setjoin.exchange.a0.input/v0"
        || i.artifact_kind != "assessment-input"
        || i.collector_version != "a0-v0"
    {
        return Err("unsupported A0 input schema, kind, or collector version".into());
    }
    let digest = crate::offline::digest(REGISTRY);
    if i.registry_digest != digest {
        return Err(format!(
            "registry digest mismatch: input uses {}; embedded registry is {digest}",
            i.registry_digest
        )
        .into());
    }
    let builds = i.source.builds.as_deref().unwrap_or_default();
    let probes = i.probes.as_deref().unwrap_or_default();
    if i.source.organization.is_empty() || i.source.topology.is_empty() || builds.is_empty() {
        return Err("source organization, topology, and at least one build are required".into());
    }
    let r: serde_json::Value = serde_json::from_slice(REGISTRY).unwrap();
    let caps = r["capabilities"].as_array().unwrap();
    if !text(&i.source.organization, 256)
        || !text(&i.source.topology, 64)
        || builds.len() > 64
        || probes.len() > caps.len()
    {
        return Err("source or probe collection exceeds A0 bounds".into());
    }
    if builds.iter().any(|b| !text(b, 256)) {
        return Err("source build contains invalid text".into());
    }
    if !crate::offline::utc_second(&i.collected_at) {
        return Err("collectedAt must be canonical UTC RFC3339".into());
    }
    let mut seen = std::collections::BTreeSet::new();
    for p in probes {
        if !caps.iter().any(|c| c["id"] == p.capability_id) || !seen.insert(&p.capability_id) {
            return Err(format!("unknown or duplicate capabilityId {:?}", p.capability_id).into());
        }
        if (!p.diagnostic_id.is_empty() && !text(&p.diagnostic_id, 128))
            || (!p.detail.is_empty() && !text(&p.detail, 1024))
            || p.facts.as_ref().is_some_and(|v| v.get().len() > 1 << 20)
        {
            return Err(format!("probe {} exceeds text or fact bounds", p.capability_id).into());
        }
        match p.status.as_str() {
            "observed" => {
                if !p.diagnostic_id.is_empty() {
                    return Err(format!(
                        "observed probe {} must not carry a diagnosticId",
                        p.capability_id
                    )
                    .into());
                }
            }
            "unassessed" | "blocked" | "unsupported" => {
                if p.diagnostic_id.is_empty() || p.detail.is_empty() {
                    return Err(format!(
                        "incomplete probe {} requires diagnosticId and detail",
                        p.capability_id
                    )
                    .into());
                }
            }
            _ => {
                return Err(format!("invalid status {:?} for {}", p.status, p.capability_id).into())
            }
        }
        if p.facts.is_none() {
            return Err(format!("probe {} facts must be valid JSON", p.capability_id).into());
        }
    }
    Ok((i, crate::offline::digest(&raw)))
}
const PHASE: &str = "A0 concierge discovery only — replacement readiness not established";
#[derive(Default, serde::Serialize, serde::Deserialize, Clone)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
struct Row {
    capability_id: String,
    title: String,
    outcome: String,
    status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    diagnostic_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    detail: String,
    #[serde(deserialize_with = "raw_facts")]
    facts: Option<Box<serde_json::value::RawValue>>,
}
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
struct Report {
    schema_version: String,
    phase: String,
    importable: bool,
    registry_digest: String,
    input_digest: String,
    row_set_digest: String,
    generated_at: String,
    source: Source,
    complete: i64,
    expected: i64,
    rows: Option<Vec<Row>>,
}
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct Manifest<'a> {
    schema_version: &'a str,
    registry_digest: &'a str,
    input_digest: &'a str,
    row_set_digest: &'a str,
    artifacts: std::collections::BTreeMap<String, String>,
}
fn json<T: serde::Serialize>(v: &T) -> String {
    crate::part_b::compact_json(&serde_json::to_string(v).unwrap())
        .unwrap()
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}
fn pretty<T: serde::Serialize>(v: &T) -> String {
    crate::part_b::ordered_pretty(&json(v))
}
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&#34;")
        .replace('\'', "&#39;")
        .replace('+', "&#43;")
}
fn html(r: &Report, locale: &str) -> String {
    let template = include_str!("exchange_a0.html");
    let (prefix, rest) = template.split_once("{{range .Report.Rows}}").unwrap();
    let (_, suffix) = rest.split_once("{{end}}</tbody>").unwrap();
    let mut out = prefix
        .replace("{{.Locale}}", &escape(locale))
        .replace("{{.Report.Phase}}", &escape(&r.phase));
    out=out.replace("{{if eq .Locale \"zh-CN\"}}不可作为产品评估导入或替代承诺。{{else}}Not importable as a product assessment or replacement commitment.{{end}}",if locale=="zh-CN"{"不可作为产品评估导入或替代承诺。"}else{"Not importable as a product assessment or replacement commitment."});
    for (k, v) in [
        (
            "{{.Report.Source.Organization}}",
            r.source.organization.clone(),
        ),
        ("{{.Report.Source.Topology}}", r.source.topology.clone()),
        ("{{.Report.Complete}}", r.complete.to_string()),
        ("{{.Report.Expected}}", r.expected.to_string()),
        ("{{.Report.RegistryDigest}}", r.registry_digest.clone()),
        ("{{.Report.RowSetDigest}}", r.row_set_digest.clone()),
    ] {
        out = out.replace(k, &escape(&v));
    }
    for row in r.rows.as_deref().unwrap_or_default() {
        let facts = row
            .facts
            .as_ref()
            .map(|v| crate::part_b::ordered_pretty(v.get()))
            .unwrap_or("{}".into());
        out.push_str(&format!("<tr><td>{}<br>{}</td><td>{}</td><td class=\"{}\">{}{}</td><td>{}<pre>{}</pre></td></tr>",escape(&row.capability_id),escape(&row.title),escape(&row.outcome),escape(&row.status),escape(&row.status),if row.diagnostic_id.is_empty(){String::new()}else{format!("<br>{}",escape(&row.diagnostic_id))},escape(&row.detail),escape(&facts)));
    }
    out.push_str("</tbody>");
    out.push_str(
        &suffix
            .replace("{{.Report.GeneratedAt}}", &escape(&r.generated_at))
            .replace("{{.Report.InputDigest}}", &escape(&r.input_digest)),
    );
    out
}
struct Staging(std::path::PathBuf);
impl Drop for Staging {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn write_report(output: &str, locale: &str, r: &Report, pdf: bool) -> Result<(), Failure> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    if std::fs::metadata(output).is_ok() {
        return Err(format!("refusing to replace existing output directory {output}").into());
    }
    let dest = std::path::Path::new(output);
    let dir = dest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let staging = Staging(dir.join(format!(
        ".exchange-a0-report-{}",
        crate::part_b::new_uuid()?
    )));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&staging.0)
        .map_err(|e| format!("create report staging directory: {e}"))?;
    let report = format!("{}\n", pretty(r));
    let html = html(r, locale);
    for (name, data) in [
        ("report.json", report.as_bytes()),
        ("report.html", html.as_bytes()),
    ] {
        crate::offline::private_new(staging.0.join(name).to_str().unwrap(), data)?;
    }
    if pdf {
        let edge = std::env::var("SETJOIN_A0_EDGE")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| {
                ["msedge", "microsoft-edge", "Microsoft Edge"]
                    .iter()
                    .find_map(|n| {
                        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
                            .map(|d| d.join(n))
                            .find(|p| p.is_file())
                            .map(|p| p.display().to_string())
                    })
            })
            .ok_or("Microsoft Edge not found; omit --pdf or set SETJOIN_A0_EDGE")?;
        let html =
            std::fs::canonicalize(staging.0.join("report.html")).map_err(|e| e.to_string())?;
        let pdf_path = html.parent().unwrap().join("report.pdf");
        let result = std::process::Command::new(edge)
            .args([
                "--headless",
                "--disable-gpu",
                "--no-pdf-header-footer",
                &format!("--print-to-pdf={}", pdf_path.display()),
                url::Url::from_file_path(&html).unwrap().as_str(),
            ])
            .output()
            .map_err(|e| format!("render PDF with Microsoft Edge: {e}"))?;
        if !result.status.success() {
            return Err(format!(
                "render PDF with Microsoft Edge: exit status {}: {}",
                result.status.code().unwrap_or(1),
                String::from_utf8_lossy(&result.stdout).to_string()
                    + &String::from_utf8_lossy(&result.stderr)
            )
            .into());
        }
        if std::fs::metadata(&pdf_path).map_or(true, |m| m.len() == 0) {
            return Err("Microsoft Edge did not produce report.pdf".into());
        }
        std::fs::set_permissions(&pdf_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
    }
    let mut artifacts = std::collections::BTreeMap::new();
    for name in ["report.html", "report.json", "report.pdf"] {
        if let Ok(data) = std::fs::read(staging.0.join(name)) {
            artifacts.insert(name.into(), crate::offline::digest(&data));
        }
    }
    let manifest = Manifest {
        schema_version: "setjoin.exchange.a0.manifest/v0",
        registry_digest: &r.registry_digest,
        input_digest: &r.input_digest,
        row_set_digest: &r.row_set_digest,
        artifacts,
    };
    crate::offline::private_new(
        staging.0.join("manifest.json").to_str().unwrap(),
        format!("{}\n", pretty(&manifest)).as_bytes(),
    )?;
    std::fs::rename(&staging.0, dest).map_err(|e| format!("install report directory: {e}"))?;
    println!(
        "Non-importable A0/v0 report written to {output} ({}/{} observed).",
        r.complete, r.expected
    );
    Ok(())
}
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
struct Receipt {
    schema_version: String,
    receipt_kind: String,
    receipt_id: String,
    report_digest: String,
    organization: String,
    actor: String,
    decision: String,
    purpose: String,
    retention_days: i64,
    issued_at: String,
    signature_status: String,
    importable: bool,
}
fn valid_report(r: &Report) -> Result<(), Failure> {
    let registry: serde_json::Value = serde_json::from_slice(REGISTRY).unwrap();
    let caps = registry["capabilities"].as_array().unwrap();
    let rows = r.rows.as_deref().unwrap_or_default();
    if r.schema_version != "setjoin.exchange.a0.report/v0"
        || r.importable
        || r.registry_digest != crate::offline::digest(REGISTRY)
        || r.phase != PHASE
    {
        return Err("invalid report identity or registry binding".into());
    }
    if r.expected != caps.len() as i64
        || rows.len() != caps.len()
        || r.complete < 0
        || r.complete > r.expected
    {
        return Err("invalid report completeness".into());
    }
    let builds = r.source.builds.as_deref().unwrap_or_default();
    if !text(&r.source.organization, 256)
        || !text(&r.source.topology, 64)
        || builds.is_empty()
        || builds.len() > 64
    {
        return Err("invalid report source".into());
    }
    if builds.iter().any(|s| !text(s, 256)) {
        return Err("invalid report source build".into());
    }
    let mut complete = 0;
    for (i, (c, row)) in caps.iter().zip(rows).enumerate() {
        if c["id"] != row.capability_id || c["title"] != row.title || c["outcome"] != row.outcome {
            return Err(format!("report row {i} does not match registry").into());
        }
        if row.status == "observed" {
            if !row.diagnostic_id.is_empty() {
                return Err(format!(
                    "observed report row {} carries a diagnostic",
                    row.capability_id
                )
                .into());
            }
            complete += 1;
        } else if !matches!(
            row.status.as_str(),
            "unassessed" | "blocked" | "unsupported"
        ) {
            return Err(format!("invalid report row status {:?}", row.status).into());
        } else if !text(&row.diagnostic_id, 128) || !text(&row.detail, 1024) {
            return Err(format!(
                "incomplete report row {} lacks a bounded diagnostic",
                row.capability_id
            )
            .into());
        }
        if row.facts.is_none() {
            return Err(format!("invalid report row facts for {}", row.capability_id).into());
        }
    }
    if complete != r.complete {
        return Err("report complete count does not match rows".into());
    }
    if crate::offline::digest(json(&r.rows).as_bytes()) != r.row_set_digest {
        return Err("report row-set digest mismatch".into());
    }
    if !crate::identity_checks::hex(&r.input_digest, 64) {
        return Err("invalid report input digest".into());
    }
    if !crate::offline::utc_second(&r.generated_at) {
        return Err("invalid report generation time".into());
    }
    Ok(())
}
