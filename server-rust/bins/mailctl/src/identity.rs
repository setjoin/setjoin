//! Identity API client and its frozen-Go bounded response and exit contracts.
use crate::{
    client::{Api, Failure},
    part_b::*,
    Options,
};
use serde_json::Value;
const PREFIX: &str = "/admin/identity/v2";
const LIMIT: u64 = 4 << 20;
pub(super) fn exit(e: Failure) -> Failure {
    if e.status == 0 {
        return e;
    }
    let code = if [401, 403].contains(&e.status) {
        3
    } else if e.status == 409
        || e.problem_code
            .strip_prefix("BZ")
            .filter(|_| e.problem_code.len() == 5)
            .and_then(|n| n.parse::<u32>().ok())
            .is_some_and(|n| (228..=240).contains(&n))
        || [
            "generation-stale",
            "subject-conflict",
            "soft-match-forbidden",
            "auth-link-limit",
            "lifecycle-conflict",
            "transition-preflight",
            "preview-stale",
            "approval-invalid",
            "last-recovery",
            "transition-illegal",
            "account-class-excluded",
            "idempotency-conflict",
        ]
        .iter()
        .any(|name| e.problem_type == format!("https://setjoin.com/problems/identity/{name}"))
    {
        4
    } else {
        1
    };
    e.exit(code)
}
pub(super) fn run(api: &Api, o: &Options, action: &str, args: &[String]) -> Result<(), Failure> {
    if action == "sources" || (action == "source" && args.first().is_some_and(|a| a == "list")) {
        let args = if action == "source" { &args[1..] } else { args };
        let o = read_flags("identity source list", o, args)?;
        let (v, ordered) = wire_request(
            api,
            "identitySourceList",
            "GET",
            &format!("{PREFIX}/sources"),
            None,
            &[],
            LIMIT,
        )?;
        crate::identity_checks::validate("identitySourceList", &v)?;
        if o.json || o.quiet {
            wire_output(&o, &ordered);
        } else {
            table(
                &[
                    "SOURCE KEY",
                    "DISPLAY NAME",
                    "KIND",
                    "STATE",
                    "GENERATION",
                    "ATTENTION",
                ],
                array(&v["items"])
                    .iter()
                    .map(|r| {
                        vec![
                            text(r, "sourceKey").into(),
                            text(r, "displayName").into(),
                            text(r, "kind").into(),
                            text(r, "state").into(),
                            text(r, "generation").into(),
                            number(r, "attentionCount").to_string(),
                        ]
                    })
                    .collect(),
            );
        }
        return Ok(());
    }
    if action == "people" && (args.is_empty() || args[0] == "list") {
        return list(
            api,
            o,
            "people",
            if args.first().is_some_and(|s| s == "list") {
                &args[1..]
            } else {
                args
            },
        );
    }
    if action == "conflicts" || (action == "conflict" && args.first().is_some_and(|s| s == "list"))
    {
        return list(
            api,
            o,
            "conflicts",
            if args.first().is_some_and(|s| s == "list") {
                &args[1..]
            } else {
                args
            },
        );
    }
    if action == "transitions"
        || (action == "transition" && args.first().is_some_and(|s| s == "list"))
    {
        return list(
            api,
            o,
            "transitions",
            if args.first().is_some_and(|s| s == "list") {
                &args[1..]
            } else {
                args
            },
        );
    }
    if action == "events" {
        return list(
            api,
            o,
            "events",
            if args.first().is_some_and(|s| s == "list") {
                &args[1..]
            } else {
                args
            },
        );
    }
    if action == "source" {
        return source(api, o, args);
    }
    if action == "people" {
        return people(api, o, args);
    }
    if action == "conflict" {
        return conflict(api, o, args);
    }
    if action == "transition" {
        return transition(api, o, args);
    }
    if action == "transition-preview" {
        return transition_preview(api, o, args);
    }
    if action == "transition-execute" {
        return transition_authorized(api, o, args, "execute");
    }
    if action == "transition-report" {
        return transition_show(api, o, args);
    }
    if action == "inventory" && args.first().is_some_and(|s| s == "export") {
        return inventory_export(api, o, &args[1..]);
    }
    if action == "inventory" {
        let (v, ordered) = identity_request(
            api,
            "identityInventoryResponse",
            "GET",
            "/admin/identity/inventory",
            None,
            &[],
        )?;
        if number(&v, "schemaVersion") <= 0
            || text(&v, "generatedAt").is_empty()
            || !v["blockers"].is_array()
            || !v["connectorSecrets"].is_object()
            || !v["lifecycleSources"].is_object()
        {
            return Err("identity inventory response is missing required fields".into());
        }
        if o.json {
            wire_output(o, &ordered);
        } else if !o.quiet {
            println!(
                "Identity inventory (schema {}, generated {})",
                number(&v, "schemaVersion"),
                text(&v, "generatedAt")
            );
            let p = &v["people"];
            println!("People: total={} enabled={} disabled={} members={} guests={} unclassified_without_mailbox={}",number(p,"total"),number(p,"enabled"),number(p,"disabled"),number(p,"members"),number(p,"guests"),number(p,"unclassifiedWithoutMailbox"));
            let m = &v["mailboxes"];
            println!(
                "Mailboxes: shared={} resources={}",
                number(m, "shared"),
                number(m, "resources")
            );
            let f = &v["federationPairs"];
            println!("Federation pairs: oidc_complete={} oidc_partial={} saml_complete={} saml_partial={} legacy_inventoried={}",number(f,"oidcComplete"),number(f,"oidcPartial"),number(f,"samlComplete"),number(f,"samlPartial"),number(f,"legacyInventoried"));
            let p = &v["protectedAccounts"];
            println!(
                "Protected accounts: total={} break_glass={} sensitive_role_holders={}",
                number(p, "total"),
                number(p, "breakGlass"),
                number(p, "sensitiveRoleHolders")
            );
            println!(
                "Connector secrets: ad={} ldap={}",
                text(&v["connectorSecrets"], "ad"),
                text(&v["connectorSecrets"], "ldap")
            );
            if array(&v["blockers"]).is_empty() {
                println!("Blockers: none");
            } else {
                println!("Blockers: {}", string_values(&v["blockers"]).join(", "));
            }
        }
        if !array(&v["blockers"]).is_empty() {
            return Err(format!(
                "identity inventory has {} blocker(s)",
                array(&v["blockers"]).len()
            )
            .into());
        }
        return Ok(());
    }
    if action == "doctor" {
        let f = crate::flags::parse(
            "identity doctor",
            args,
            &["source"],
            &["json", "quiet"],
            false,
        );
        let o = output_flags(o, &f);
        let source = f.get("source");
        if !f.positional.is_empty()
            || (!source.is_empty() && (source.trim() != source || source.len() > 64))
        {
            return Err(
                "identity doctor accepts flags only and --source must be a valid source key".into(),
            );
        }
        let path = if source.is_empty() {
            format!("{PREFIX}/doctor")
        } else {
            format!("{PREFIX}/doctor?source={}", escape(source))
        };
        let (v, ordered) = identity_request(api, "identityDoctor", "GET", &path, None, &[])?;
        if o.json || o.quiet {
            wire_output(&o, &ordered);
        } else {
            println!(
                "Identity doctor: passed={} blockers={} generated={}",
                boolean(&v, "passed"),
                number(&v, "blockingCount"),
                text(&v, "generatedAt")
            );
            for c in array(&v["checks"]) {
                println!(
                    "{:<4} {:<7} {} — {}",
                    if boolean(c, "passed") { "PASS" } else { "FAIL" },
                    text(c, "severity"),
                    text(c, "name"),
                    text(c, "nextAction")
                );
            }
        }
        if number(&v, "blockingCount") > 0 {
            return Err(format!(
                "identity doctor found {} blocking check(s)",
                number(&v, "blockingCount")
            )
            .into());
        }
        return Ok(());
    }
    if action == "job" {
        return job(api, o, args);
    }
    if action == "upgrade" {
        return upgrade(api, o, args);
    }
    if action == "upgrade-status" {
        return upgrade_status(api, o, args);
    }
    if action == "upgrade-canary" {
        return canary(api, o, args);
    }
    if action == "upgrade-rollback" {
        return upgrade_rollback(api, o, args);
    }
    if action == "diagnostics" {
        let f = crate::flags::parse(
            "identity diagnostics",
            args,
            &[
                "source",
                "transition",
                "since",
                "reason",
                "output",
                "idempotency-key",
                "timeout",
            ],
            &["json", "quiet", "yes", "y"],
            false,
        );
        let o = output_flags(o, &f);
        let source = f.get("source");
        let transition = f.get("transition");
        if !f.positional.is_empty()
            || (source.is_empty() == transition.is_empty())
            || (!source.is_empty() && (source.trim() != source || source.len() > 64))
            || (!transition.is_empty() && !crate::identity_checks::valid_uuid(transition))
            || f.get("output").trim().is_empty()
        {
            return Err("usage: mailctl identity diagnostics (--source KEY|--transition UUID) --since DURATION --reason TEXT --output FILE".into());
        }
        identity_reason(f.get("reason"), "identity diagnostics")?;
        let since = duration(f.get("since"))
            .filter(|d| d.as_secs_f64() >= 1.0 && d.as_secs_f64() <= 86400.0)
            .ok_or("--since must be a duration from 1s through 24h")?;
        let timeout = watch_timeout(flag_default(&f, "timeout", "30m"))?;
        let key = mutation_key(f.get("idempotency-key"))?;
        let mut body = serde_json::json!({"sinceSeconds":since.as_secs(),"reason":f.get("reason"),"idempotencyKey":key});
        if source.is_empty() {
            body["transitionId"] = transition.into();
        } else {
            body["sourceKey"] = source.into();
        }
        if !o.quiet {
            eprintln!("Idempotency-Key: {key}");
        }
        let (accepted, _) = identity_request(
            api,
            "identityJob",
            "POST",
            &format!("{PREFIX}/diagnostics"),
            Some(body),
            &identity_headers(&key, f.get("reason"), ""),
        )?;
        let (v, ordered) = wait_job(
            api,
            &o,
            text(&accepted, "jobId"),
            &format!("{PREFIX}/diagnostics/"),
            timeout,
        )?;
        if text(&v, "state") != "completed" {
            return Err(terminal_job_error(&v));
        }
        let (raw, headers) = download(
            api,
            &format!(
                "{PREFIX}/diagnostics/{}/download",
                path_escape(text(&v, "jobId"))
            ),
        )?;
        if !header(&headers, "Content-Type").starts_with("application/zip") {
            return Err("identity diagnostic download returned an invalid content type".into());
        }
        if header(&headers, "X-Setjoin-Manifest-Version") != "1" {
            return Err(
                "identity diagnostic download returned an unsupported manifest version".into(),
            );
        }
        verify_digest(&raw, header(&headers, "Digest"))
            .map_err(|e| format!("verify identity diagnostic bundle: {e}"))?;
        if !crate::identity_checks::hex(text(&v, "sha256"), 64) {
            return Err("identity diagnostic job is missing its checksum".into());
        }
        if sha256(&raw) != text(&v, "sha256") {
            return Err("identity diagnostic checksum does not match the completed job".into());
        }
        export_write(&o, f.get("output"), &raw)?;
        if o.json {
            #[derive(serde::Serialize)]
            struct Result<'a> {
                job: Box<serde_json::value::RawValue>,
                output: &'a str,
                sha256: &'a str,
            }
            let result = Result {
                job: serde_json::value::RawValue::from_string(ordered).unwrap(),
                output: f.get("output"),
                sha256: text(&v, "sha256"),
            };
            let text = crate::part_b::ordered_pretty(&serde_json::to_string(&result).unwrap());
            wire_output(&o, &text);
        } else if !o.quiet {
            println!(
                "Sanitized identity diagnostics written to {} (mode 0600).\nJob: {}  SHA-256: {}",
                f.get("output"),
                text(&v, "jobId"),
                text(&v, "sha256")
            );
        }
        return Ok(());
    }
    // identity actions
    Err(format!("unknown identity action {action:?}; run 'mailctl identity --help'").into())
}
fn output_flags(o: &Options, f: &crate::flags::Flags) -> Options {
    Options {
        json: if f.set("json") {
            f.boolean("json")
        } else {
            o.json
        },
        quiet: if f.set("quiet") {
            f.boolean("quiet")
        } else {
            o.quiet
        },
        yes: f.boolean_alias(&["yes", "y"]).unwrap_or(o.yes),
    }
}
fn read_flags(name: &str, o: &Options, args: &[String]) -> Result<Options, Failure> {
    let f = crate::flags::parse(name, args, &[], &["json", "quiet"], false);
    if !f.positional.is_empty() {
        return Err(format!("{name} accepts no positional arguments").into());
    }
    Ok(output_flags(o, &f))
}
fn table(headers: &[&str], rows: Vec<Vec<String>>) {
    let mut all = vec![headers.iter().map(|s| s.to_string()).collect::<Vec<_>>()];
    all.extend(rows);
    let widths = (0..headers.len())
        .map(|i| all.iter().map(|r| r[i].chars().count()).max().unwrap_or(0) + 2)
        .collect::<Vec<_>>();
    for row in all {
        for (i, cell) in row.iter().enumerate() {
            print!("{cell}");
            if i + 1 < row.len() {
                print!(
                    "{}",
                    " ".repeat(widths[i].saturating_sub(cell.chars().count()))
                );
            }
        }
        println!();
    }
}

fn list(api: &Api, o: &Options, group: &str, args: &[String]) -> Result<(), Failure> {
    let singular = match group {
        "sources" => "source",
        "people" => "people",
        "conflicts" => "conflict",
        "transitions" => "transition",
        _ => "events",
    };
    let name = format!("identity {singular} list");
    let o = read_flags(&name, o, args)?;
    let shape = match group {
        "sources" => "identitySourceList",
        "people" => "identityPeopleList",
        "conflicts" => "identityConflictList",
        "transitions" => "identityTransitionList",
        _ => "identityEventList",
    };
    let (v, ordered) = wire_request(
        api,
        shape,
        "GET",
        &format!("{PREFIX}/{group}"),
        None,
        &[],
        LIMIT,
    )?;
    crate::identity_checks::validate(shape, &v)?;
    if o.json || o.quiet {
        wire_output(&o, &ordered);
        return Ok(());
    }
    let (headers, fields): (&[&str], &[&str]) = match group {
        "people" => (
            &[
                "PERSON ID",
                "EMAIL",
                "ENABLED",
                "AUTHORITY",
                "SOURCE",
                "ACTIVE LINKS",
            ],
            &[
                "userId",
                "email",
                "enabled",
                "lifecycleAuthority",
                "sourceKey",
                "activeLinks",
            ],
        ),
        "conflicts" => (
            &[
                "CONFLICT ID",
                "SOURCE",
                "EVIDENCE",
                "STATE",
                "GENERATION",
                "EXPLANATION",
            ],
            &[
                "id",
                "sourceKey",
                "evidenceClass",
                "state",
                "generation",
                "explanation",
            ],
        ),
        "transitions" => (
            &[
                "TRANSITION ID",
                "PERSON ID",
                "KIND",
                "STATE",
                "SOURCE",
                "PROTECTED",
                "PENDING",
            ],
            &[
                "id",
                "userId",
                "kind",
                "state",
                "sourceKey",
                "protected",
                "pendingEffects",
            ],
        ),
        _ => (
            &[
                "EVENT ID",
                "OCCURRED AT",
                "ACTION",
                "TRANSITION ID",
                "REASON",
            ],
            &["id", "occurredAt", "action", "transitionId", "reason"],
        ),
    };
    let rows = array(&v["items"])
        .iter()
        .map(|r| {
            fields
                .iter()
                .map(|f| {
                    if r[*f].is_null() {
                        "-".into()
                    } else {
                        crate::client::go_value(&r[*f])
                    }
                })
                .collect()
        })
        .collect();
    table(headers, rows);
    Ok(())
}

fn identity_request(
    api: &Api,
    shape: &str,
    method: &str,
    path: &str,
    body: Option<Value>,
    headers: &[(&str, String)],
) -> Result<(Value, String), Failure> {
    let result = wire_request(api, shape, method, path, body, headers, LIMIT)?;
    crate::identity_checks::validate(shape, &result.0)?;
    Ok(result)
}
fn source(api: &Api, o: &Options, args: &[String]) -> Result<(), Failure> {
    let a=need(args,1,"usage: mailctl identity source list|show|validate|plan|apply|set-secret|dry-run|activate|pause|resume|retire|rotate-secret")?;
    let sub = a[0].as_str();
    let args = &a[1..];
    if sub == "show" {
        let key = &need(
            args,
            1,
            "usage: mailctl identity source show SOURCE_KEY [--json|--quiet]",
        )?[0];
        if key.is_empty() || key.len() > 64 {
            return Err("SOURCE_KEY must be 1..64 bytes".into());
        }
        let o = read_flags("identity source show", o, &args[1..])?;
        let (v, ordered) = source_detail(api, key)?;
        if o.json || o.quiet {
            wire_output(&o, &ordered);
        } else {
            println!(
                "Source {} ({})\nKind: {}  State: {}  Generation: {}",
                text(&v, "sourceKey"),
                text(&v, "displayName"),
                text(&v, "kind"),
                text(&v, "state"),
                text(&v, "generation")
            );
            if let Some(map) = v["secretConfigured"].as_object() {
                for (k, v) in map {
                    println!("Secret {k} configured: {}", v.as_bool().unwrap_or(false));
                }
            }
        }
        return Ok(());
    }
    if sub == "validate" {
        let f = crate::flags::parse(
            "identity source validate",
            args,
            &["file"],
            &["json", "quiet"],
            false,
        );
        let o = output_flags(o, &f);
        if !f.positional.is_empty() || f.get("file").is_empty() {
            return Err("--file is required".into());
        }
        let raw = source_file(f.get("file"))?;
        let key = crate::identity_source_doc::validate(&raw)?;
        if o.json || o.quiet {
            o.output(
                &serde_json::json!({"valid":true,"sourceKey":key,"apiVersion":"setjoin.io/v1"}),
            );
        } else {
            println!("Identity source {key} is valid for setjoin.io/v1.");
        }
        return Ok(());
    }
    if sub == "plan" {
        let f = crate::flags::parse(
            "identity source plan",
            args,
            &["file"],
            &["json", "quiet"],
            false,
        );
        let o = output_flags(o, &f);
        if !f.positional.is_empty() || f.get("file").is_empty() {
            return Err("--file is required".into());
        }
        let raw = source_file(f.get("file"))?;
        crate::identity_source_doc::validate(&raw)?;
        let (v, ordered) = raw_wire(
            api,
            "identitySourcePlanResult",
            "POST",
            &format!("{PREFIX}/sources/plan"),
            "application/json",
            compact_json(&raw)?.into_bytes(),
            &[],
        )?;
        if o.json || o.quiet {
            wire_output(&o, &ordered);
        } else if boolean(&v, "changed") {
            println!(
                "Identity source {} has changes: {}",
                text(&v, "sourceKey"),
                string_values(&v["operations"]).join(", ")
            );
        } else {
            println!("Identity source {} is unchanged.", text(&v, "sourceKey"));
        }
        if boolean(&v, "changed") {
            return Err(Failure::from("identity source plan contains changes").exit(2));
        }
        return Ok(());
    }
    if sub == "apply" {
        let f = crate::flags::parse(
            "identity source apply",
            args,
            &["file", "reason", "idempotency-key"],
            &["json", "quiet"],
            false,
        );
        let o = output_flags(o, &f);
        if !f.positional.is_empty() || f.get("file").is_empty() {
            return Err("--file is required".into());
        }
        identity_reason(f.get("reason"), "identity source apply")?;
        let raw = source_file(f.get("file"))?;
        let source_key = crate::identity_source_doc::validate(&raw)?;
        let key = mutation_key(f.get("idempotency-key"))?;
        let mut headers = identity_headers(&key, f.get("reason"), "");
        let mut path = format!("{PREFIX}/sources");
        let method = match source_detail(api, &source_key) {
            Ok((detail, _)) => {
                headers.push(("If-Match", format!("\"{}\"", text(&detail, "generation"))));
                path.push_str(&format!("/{}", path_escape(&source_key)));
                "PUT"
            }
            Err(e) if e.status == 404 => "POST",
            Err(e) => return Err(e),
        };
        let body = serde_json::json!({"document":json_arg(&raw,"")?,"reason":f.get("reason"),"idempotencyKey":key});
        if !o.quiet {
            eprintln!("Idempotency-Key: {key}");
        }
        let (v, ordered) = raw_wire(
            api,
            "identitySourceMutationResult",
            method,
            &path,
            "application/json",
            raw_map(&body, &[("document", &raw)])?.into_bytes(),
            &headers,
        )?;
        if o.json || o.quiet {
            wire_output(&o, &ordered);
        } else {
            println!(
                "Identity source {} draft durably accepted at generation {}.",
                text(&v, "sourceKey"),
                text(&v, "generation")
            );
        }
        return Ok(());
    }
    if sub == "dry-run" {
        return source_lifecycle(api, o, sub, args);
    }
    if sub == "activate" {
        return source_lifecycle(api, o, sub, args);
    }
    if sub == "pause" {
        return source_lifecycle(api, o, sub, args);
    }
    if sub == "resume" {
        return source_lifecycle(api, o, sub, args);
    }
    if sub == "retire" {
        return source_lifecycle(api, o, sub, args);
    }
    if sub == "set-secret" {
        return source_secret(api, o, sub, args);
    }
    if sub == "rotate-secret" {
        return source_secret(api, o, sub, args);
    }
    // identity source actions
    Err(format!("unknown identity source action {sub:?}").into())
}
fn path_escape(raw: &str) -> String {
    let mut out = String::new();
    for b in raw.bytes() {
        match b {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~'
            | b'@'
            | b'&'
            | b'='
            | b'+'
            | b'$'
            | b':' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
fn source_detail(api: &Api, key: &str) -> Result<(Value, String), Failure> {
    identity_request(
        api,
        "identitySourceDetail",
        "GET",
        &format!("{PREFIX}/sources/{}", path_escape(key)),
        None,
        &[],
    )
}

fn source_file(path: &str) -> Result<String, Failure> {
    let m = std::fs::metadata(path).map_err(|e| {
        format!(
            "read identity source file: stat {path}: {}",
            crate::flags::go_io_error(&e)
        )
    })?;
    if !m.is_file() || m.len() > 65536 {
        return Err(
            "identity source file must be a regular file no larger than 65536 bytes".into(),
        );
    }
    std::fs::read_to_string(path).map_err(|e| {
        format!(
            "read identity source file: open {path}: {}",
            crate::flags::go_io_error(&e)
        )
        .into()
    })
}

fn raw_wire(
    api: &Api,
    shape: &str,
    method: &str,
    path: &str,
    content_type: &str,
    body: Vec<u8>,
    headers: &[(&str, String)],
) -> Result<(Value, String), Failure> {
    let (raw, _) = api.bytes(method, path, Some(content_type), Some(body), headers, LIMIT)?;
    let result = wire_decode(shape, &raw)?;
    crate::identity_checks::validate(shape, &result.0)?;
    Ok(result)
}
fn string_values(v: &Value) -> Vec<&str> {
    array(v).iter().filter_map(Value::as_str).collect()
}

fn identity_reason(reason: &str, action: &str) -> Result<(), Failure> {
    if reason.trim().is_empty() {
        return Err(format!("--reason is required for {action}").into());
    }
    if reason.len() > 1024 {
        return Err(format!("--reason for {action} must be at most 1024 bytes").into());
    }
    if reason.chars().any(char::is_control) {
        return Err(format!("--reason for {action} must not contain control characters").into());
    }
    Ok(())
}
fn mutation_key(raw: &str) -> Result<String, Failure> {
    if raw.is_empty() {
        new_uuid()
    } else if uuid(raw).is_some() {
        Ok(raw.into())
    } else {
        Err("--idempotency-key must be a UUID".into())
    }
}
fn identity_headers(key: &str, reason: &str, generation: &str) -> Vec<(&'static str, String)> {
    let mut h = vec![
        ("Idempotency-Key", key.into()),
        ("X-Audit-Reason", reason.into()),
    ];
    if !generation.is_empty() {
        h.push(("If-Match", format!("\"{generation}\"")));
    }
    h
}

fn source_lifecycle(api: &Api, o: &Options, action: &str, args: &[String]) -> Result<(), Failure> {
    let key=&need(args,1,&format!("usage: mailctl identity source {action} SOURCE_KEY --reason TEXT [--idempotency-key UUID]"))?[0];
    let f = crate::flags::parse(
        &format!("identity source {action}"),
        &args[1..],
        &["reason", "idempotency-key"],
        &["json", "quiet"],
        false,
    );
    let o = output_flags(o, &f);
    if !f.positional.is_empty() || key.is_empty() || key.len() > 64 {
        return Err("SOURCE_KEY and flags only are accepted".into());
    }
    identity_reason(f.get("reason"), &format!("identity source {action}"))?;
    let (detail, _) = source_detail(api, key)?;
    let mutation = mutation_key(f.get("idempotency-key"))?;
    let headers = identity_headers(&mutation, f.get("reason"), text(&detail, "generation"));
    let body = serde_json::json!({"expectedGeneration":text(&detail,"generation"),"idempotencyKey":mutation,"reason":f.get("reason")});
    if !o.quiet {
        eprintln!("Idempotency-Key: {mutation}");
    }
    let (v, ordered) = identity_request(
        api,
        "identitySourceMutationResult",
        "POST",
        &format!("{PREFIX}/sources/{}/{action}", path_escape(key)),
        Some(body),
        &headers,
    )?;
    if o.json || o.quiet {
        wire_output(&o, &ordered);
    } else if action == "dry-run" {
        println!(
            "Identity source {} validation: valid={} transport={} person_writes={} generation={}",
            text(&v, "sourceKey"),
            boolean(&v, "valid"),
            text(&v, "transport"),
            number(&v, "personWrites"),
            text(&v, "generation")
        );
    } else {
        println!(
            "Identity source {} {action} durably accepted at generation {}.",
            text(&v, "sourceKey"),
            text(&v, "generation")
        );
    }
    if action == "dry-run" && v["valid"] == false {
        return Err("identity source dry-run is blocked".into());
    }
    Ok(())
}

fn source_secret(api: &Api, o: &Options, action: &str, args: &[String]) -> Result<(), Failure> {
    let key=&need(args,1,&format!("usage: mailctl identity source {action} SOURCE_KEY --name KEY (--stdin|--file FILE) --reason TEXT"))?[0];
    let f = crate::flags::parse(
        &format!("identity source {action}"),
        &args[1..],
        &["name", "file", "reason", "idempotency-key"],
        &["json", "quiet", "stdin"],
        false,
    );
    let o = output_flags(o, &f);
    if !f.positional.is_empty()
        || key.is_empty()
        || f.get("name").is_empty()
        || f.boolean("stdin") == !f.get("file").is_empty()
    {
        return Err(
            "SOURCE_KEY, --name, exactly one of --stdin/--file, and flags only are required".into(),
        );
    }
    identity_reason(f.get("reason"), &format!("identity source {action}"))?;
    let mut secret = Vec::new();
    if f.boolean("stdin") {
        use std::io::Read;
        std::io::stdin()
            .take(65537)
            .read_to_end(&mut secret)
            .map_err(|e| format!("read identity source secret: {e}"))?;
    } else {
        use std::os::unix::fs::PermissionsExt;
        let path = f.get("file");
        let m = std::fs::symlink_metadata(path).map_err(|e| {
            format!(
                "read identity source secret file: lstat {path}: {}",
                crate::flags::go_io_error(&e)
            )
        })?;
        if !m.is_file() || m.permissions().mode() & 0o777 != 0o600 || m.len() > 65536 {
            return Err("identity source secret file must be a regular mode-0600 file no larger than 65536 bytes".into());
        }
        secret = std::fs::read(path).map_err(|e| {
            format!(
                "read identity source secret: open {path}: {}",
                crate::flags::go_io_error(&e)
            )
        })?;
    }
    if secret.is_empty() || secret.len() > 65536 {
        secret.fill(0);
        return Err("identity source secret must contain 1..65536 bytes".into());
    }
    let (detail, _) = source_detail(api, key)?;
    let mutation = mutation_key(f.get("idempotency-key"))?;
    let mut headers = identity_headers(&mutation, f.get("reason"), text(&detail, "generation"));
    headers.push(("X-Identity-Reason", f.get("reason").into()));
    let mut path = format!(
        "{PREFIX}/sources/{}/secrets/{}",
        path_escape(key),
        path_escape(f.get("name"))
    );
    let method = if action == "rotate-secret" {
        path.push_str("/rotate");
        "POST"
    } else {
        "PUT"
    };
    if !o.quiet {
        eprintln!("Idempotency-Key: {mutation}");
    }
    let (v, ordered) = raw_wire(
        api,
        "identitySourceMutationResult",
        method,
        &path,
        "application/octet-stream",
        secret,
        &headers,
    )?;
    if o.json || o.quiet {
        wire_output(&o, &ordered);
    } else {
        println!(
            "Identity source {} secret {} durably accepted at generation {}.",
            text(&v, "sourceKey"),
            text(&v, "secretName"),
            text(&v, "generation")
        );
    }
    Ok(())
}

fn people(api: &Api, o: &Options, args: &[String]) -> Result<(), Failure> {
    let a = need(args, 1, "usage: mailctl identity people list|show")?;
    if a[0] != "show" {
        return Err(format!("unknown identity people action {:?}", a[0]).into());
    }
    let args = &a[1..];
    let id = args
        .first()
        .filter(|s| crate::identity_checks::positive(s))
        .ok_or("usage: mailctl identity people show PERSON_ID [--json|--quiet]")?;
    let o = read_flags("identity people show", o, &args[1..])?;
    let (v, ordered) = identity_request(
        api,
        "identityPersonDetail",
        "GET",
        &format!("{PREFIX}/people/{id}"),
        None,
        &[],
    )?;
    if o.json || o.quiet {
        wire_output(&o, &ordered);
    } else {
        println!("Person {} <{}>\nEnabled: {}  Protected: {}  Authority: {} (generation {})\nLinks: {}  Field authorities: {}  Entitlements: {}",text(&v,"userId"),text(&v,"email"),boolean(&v,"enabled"),boolean(&v,"protected"),text(&v["lifecycleAuthority"],"kind"),text(&v["lifecycleAuthority"],"generation"),array(&v["links"]).len(),array(&v["fieldAuthority"]).len(),array(&v["entitlementProvenance"]).len());
    }
    Ok(())
}

fn conflict(api: &Api, o: &Options, args: &[String]) -> Result<(), Failure> {
    let a = need(args, 1, "usage: mailctl identity conflict list|show|decide")?;
    let sub = a[0].as_str();
    let args = &a[1..];
    if sub == "show" {
        let id = args
            .first()
            .filter(|s| crate::identity_checks::valid_uuid(s))
            .ok_or("usage: mailctl identity conflict show CONFLICT_ID [--json|--quiet]")?;
        let o = read_flags("identity conflict show", o, &args[1..])?;
        let (v, ordered) = identity_request(
            api,
            "identityConflictDetail",
            "GET",
            &format!("{PREFIX}/conflicts/{id}"),
            None,
            &[],
        )?;
        if o.json || o.quiet {
            wire_output(&o, &ordered);
        } else {
            println!("Conflict {}  State: {}  Generation: {}\nSource: {}  Evidence: {}  Subject: {}\nAllowed decisions: {}",text(&v,"id"),text(&v,"state"),text(&v,"generation"),text(&v["source"],"sourceKey"),text(&v,"evidenceClass"),text(&v,"subjectFingerprint"),string_values(&v["allowedDecisions"]).join(", "));
        }
        return Ok(());
    }
    if sub == "decide" {
        let id=args.first().filter(|s|crate::identity_checks::valid_uuid(s)).ok_or("usage: mailctl identity conflict decide CONFLICT_ID --decision link|create|reject|defer --generation N --reason TEXT [--person PERSON_ID] [--idempotency-key UUID]")?;
        let f = crate::flags::parse(
            "identity conflict decide",
            &args[1..],
            &[
                "decision",
                "person",
                "generation",
                "reason",
                "idempotency-key",
            ],
            &["json", "quiet"],
            false,
        );
        let o = output_flags(o, &f);
        let decision = f.get("decision");
        if !f.positional.is_empty()
            || !["link", "create", "reject", "defer"].contains(&decision)
            || !crate::identity_checks::positive(f.get("generation"))
        {
            return Err("--decision and a positive --generation are required".into());
        }
        identity_reason(f.get("reason"), "identity conflict decide")?;
        if decision == "link" {
            if !crate::identity_checks::positive(f.get("person")) {
                return Err(
                    "--person is required for link and must be a positive decimal person id".into(),
                );
            }
        } else if !f.get("person").is_empty() {
            return Err("--person is accepted only for link decisions".into());
        }
        let key = mutation_key(f.get("idempotency-key"))?;
        let mut body = serde_json::json!({"decision":decision,"expectedGeneration":f.get("generation"),"reason":f.get("reason"),"idempotencyKey":key});
        if decision == "link" {
            body["personId"] = f.get("person").into();
        }
        let headers = identity_headers(&key, f.get("reason"), f.get("generation"));
        if !o.quiet {
            eprintln!("Idempotency-Key: {key}");
        }
        let (v, ordered) = identity_request(
            api,
            "identityConflictDecisionResult",
            "POST",
            &format!("{PREFIX}/conflicts/{id}/decision"),
            Some(body),
            &headers,
        )?;
        if o.json || o.quiet {
            wire_output(&o, &ordered);
        } else {
            println!(
                "Conflict {} is {} at generation {}.",
                text(&v, "id"),
                text(&v, "state"),
                text(&v, "generation")
            );
        }
        return Ok(());
    }
    // identity conflict actions
    Err(format!("unknown identity conflict action {sub:?}").into())
}

fn transition(api: &Api, o: &Options, args: &[String]) -> Result<(), Failure> {
    let a=need(args,1,"usage: mailctl identity transition list|preview|start|show|export|authorize|approve|deny|watch|retry|rollback-preview|rollback")?;
    let sub = a[0].as_str();
    let args = &a[1..];
    if sub == "preview" {
        return transition_preview(api, o, args);
    }
    if sub == "show" {
        return transition_show(api, o, args);
    }
    if sub == "start" {
        return transition_authorized(api, o, args, "request");
    }
    if sub == "request" {
        return transition_authorized(api, o, args, "request");
    }
    if sub == "execute" {
        return transition_authorized(api, o, args, "execute");
    }
    if sub == "approve" {
        return transition_authorized(api, o, args, "approve");
    }
    if sub == "deny" {
        return transition_authorized(api, o, args, "deny");
    }
    if sub == "rollback" {
        return transition_authorized(api, o, args, "rollback");
    }
    if sub == "authorize" {
        let id = args
            .first()
            .filter(|s| !s.starts_with('-') && crate::identity_checks::valid_uuid(s))
            .ok_or("usage: mailctl identity transition authorize ID --preview-digest DIGEST")?;
        let f = crate::flags::parse(
            "identity transition authorize",
            &args[1..],
            &["preview-digest", "idempotency-key"],
            &["json", "quiet"],
            false,
        );
        let o = output_flags(o, &f);
        if !f.positional.is_empty() || !crate::identity_checks::hex(f.get("preview-digest"), 64) {
            return Err("transition authorize requires one UUID and --preview-digest".into());
        }
        let key = mutation_key(f.get("idempotency-key"))?;
        let headers = identity_headers(&key, "", f.get("preview-digest"));
        let (c, _) = identity_request(
            api,
            "identityTransitionChallenge",
            "POST",
            &format!("{PREFIX}/transitions/{}/step-up/challenge", path_escape(id)),
            Some(serde_json::json!({"previewDigest":f.get("preview-digest"),"idempotencyKey":key})),
            &headers,
        )?;
        if !o.quiet {
            eprintln!("Step-up challenge {} code {} expires {}; completing with the current authenticated session.",text(&c,"challengeId"),text(&c,"displayCode"),text(&c,"expiresAt"));
        }
        let (v, ordered) = identity_request(
            api,
            "identityTransitionElevation",
            "POST",
            &format!("{PREFIX}/transitions/{}/step-up/complete", path_escape(id)),
            Some(
                serde_json::json!({"challengeId":text(&c,"challengeId"),"previewDigest":f.get("preview-digest"),"idempotencyKey":key}),
            ),
            &headers,
        )?;
        if o.json || o.quiet {
            wire_output(&o, &ordered);
        } else {
            println!(
                "Elevation {} expires {} and is valid for one command only.",
                text(&v, "elevationId"),
                text(&v, "expiresAt")
            );
        }
        return Ok(());
    }
    if sub == "watch" {
        let id = args
            .first()
            .filter(|s| !s.starts_with('-') && crate::identity_checks::valid_uuid(s))
            .ok_or("usage: mailctl identity transition watch ID [--timeout 5m]")?;
        let f = crate::flags::parse(
            "identity transition watch",
            &args[1..],
            &["timeout", "interval"],
            &["json", "quiet"],
            false,
        );
        let o = output_flags(o, &f);
        let timeout = duration(flag_default(&f, "timeout", "5m"));
        let interval = duration(flag_default(&f, "interval", "2s"));
        if !f.positional.is_empty()
            || timeout.is_none_or(|d| d.as_secs_f64() < 1.0 || d.as_secs_f64() > 1800.0)
            || interval.is_none_or(|d| d.as_secs_f64() < 0.25 || d.as_secs_f64() > 30.0)
        {
            return Err("watch timeout must be 1s..30m and interval 250ms..30s".into());
        }
        let timeout = timeout.unwrap();
        let interval = interval.unwrap();
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let (v, ordered) = transition_detail(api, id)?;
            let state = text(&v, "state");
            if [
                "completed",
                "failed_precommit",
                "failed_recoverable",
                "rolled_back",
                "cancelled",
                "expired",
            ]
            .contains(&state)
            {
                if o.json || o.quiet {
                    wire_output(&o, &ordered);
                    return Ok(());
                }
                println!(
                    "Transition {id} reached {state} at generation {}.",
                    text(&v, "transitionGeneration")
                );
                if ["failed_precommit", "failed_recoverable"].contains(&state) {
                    return Err("identity transition requires recovery".into());
                }
                return Ok(());
            }
            if std::time::Instant::now() + interval > deadline {
                return Err(Failure::from("identity transition watch timed out").exit(4));
            }
            std::thread::sleep(interval);
        }
    }
    if sub == "cancel" {
        return transition_generation(api, o, args, sub);
    }
    if sub == "rollback-preview" {
        return transition_generation(api, o, args, sub);
    }
    if sub == "retry" {
        return transition_generation(api, o, args, sub);
    }
    if sub == "export" {
        let id = args
            .first()
            .filter(|s| !s.starts_with('-') && crate::identity_checks::valid_uuid(s))
            .ok_or("usage: mailctl identity transition export <UUID> --output <file>")?;
        let f = crate::flags::parse(
            "identity transition export",
            &args[1..],
            &["output"],
            &["json", "quiet", "yes", "y"],
            false,
        );
        let o = output_flags(o, &f);
        if !f.positional.is_empty() || f.get("output").trim().is_empty() {
            return Err("usage: mailctl identity transition export <UUID> --output <file>".into());
        }
        let (_, ordered) = identity_request(
            api,
            "identityTransitionReport",
            "GET",
            &format!("{PREFIX}/transitions/{id}/report"),
            None,
            &[],
        )?;
        let raw = format!("{}\n", escape_json_text(&ordered));
        let checksum = sha256(raw.as_bytes());
        export_write(&o, f.get("output"), raw.as_bytes())?;
        if !o.quiet {
            if o.json {
                o.output(&serde_json::json!({"output":f.get("output"),"sha256":checksum,"transitionId":id}));
            } else {
                println!(
                    "Identity transition report written to {} (mode 0600).\nSHA-256: {checksum}",
                    f.get("output")
                );
            }
        }
        return Ok(());
    }
    // identity transition actions
    Err(format!("unknown identity transition action {sub:?}").into())
}
fn transition_preview(api: &Api, o: &Options, args: &[String]) -> Result<(), Failure> {
    let f = crate::flags::parse(
        "identity transition preview",
        args,
        &["person", "user", "reason", "idempotency-key"],
        &["json", "quiet"],
        false,
    );
    let o = output_flags(o, &f);
    if !f.positional.is_empty() {
        return Err("identity transition preview accepts flags only".into());
    }
    let mut person = f.get("person");
    if !person.is_empty() && !f.get("user").is_empty() && person != f.get("user") {
        return Err("--person and --user must identify the same person".into());
    }
    if person.is_empty() {
        person = f.get("user");
    }
    if !crate::identity_checks::positive(person) {
        return Err("--person must be a positive decimal person id".into());
    }
    identity_reason(f.get("reason"), "identity transition preview")?;
    let key = if f.get("idempotency-key").is_empty() {
        let key = new_uuid()?;
        if !o.quiet {
            eprintln!("Idempotency key: {key}");
        }
        key
    } else {
        if !crate::identity_checks::valid_uuid(f.get("idempotency-key")) {
            return Err("--idempotency-key must be a UUID".into());
        }
        f.get("idempotency-key").into()
    };
    let body = serde_json::json!({"userId":person,"reason":f.get("reason"),"idempotencyKey":key});
    let headers = identity_headers(&key, f.get("reason"), "");
    let (v, ordered) = identity_request(
        api,
        "identityTransitionPreview",
        "POST",
        &format!("{PREFIX}/transitions/preview"),
        Some(body),
        &headers,
    )?;
    if o.json || o.quiet {
        wire_output(&o, &ordered);
    } else {
        println!("Transition preview {}\nDigest: {}\nProtected: {}\nRecovery ready: {}\nSource generation: {}\nLifecycle generation: {}",text(&v,"transitionId"),text(&v,"previewDigest"),boolean(&v,"protected"),boolean(&v,"recoveryReady"),text(&v,"sourceGeneration"),text(&v,"lifecycleGeneration"));
    }
    Err(Failure::from("transition preview contains executable changes").exit(2))
}

fn transition_detail(api: &Api, id: &str) -> Result<(Value, String), Failure> {
    identity_request(
        api,
        "identityTransitionDetail",
        "GET",
        &format!("{PREFIX}/transitions/{}", path_escape(id)),
        None,
        &[],
    )
}
fn transition_show(api: &Api, o: &Options, args: &[String]) -> Result<(), Failure> {
    let id = args
        .first()
        .filter(|s| !s.starts_with('-') && crate::identity_checks::valid_uuid(s))
        .ok_or("usage: mailctl identity transition show <UUID>")?;
    let f = crate::flags::parse(
        "identity transition show",
        &args[1..],
        &[],
        &["json", "quiet"],
        false,
    );
    let o = output_flags(o, &f);
    if !f.positional.is_empty() {
        return Err("usage: mailctl identity transition show <UUID>".into());
    }
    let (v, ordered) = transition_detail(api, id)?;
    if o.json || o.quiet {
        wire_output(&o, &ordered);
    } else {
        println!("Identity transition {}\nState: {}  Generation: {}  Person: {}\nDigest: {}  Protected: {}\nEffects: {}  Rollback boundary: {}",text(&v,"transitionId"),text(&v,"state"),text(&v,"transitionGeneration"),text(&v,"personId"),text(&v,"previewDigest"),boolean(&v,"protected"),array(&v["effects"]).len(),text(&v["rollback"],"boundary"));
    }
    Ok(())
}

fn transition_authorized(
    api: &Api,
    o: &Options,
    args: &[String],
    operation: &str,
) -> Result<(), Failure> {
    let leading = args.first().filter(|s| !s.starts_with('-'));
    let rest = if leading.is_some() { &args[1..] } else { args };
    let f = crate::flags::parse(
        &format!("identity transition {operation}"),
        rest,
        &[
            "id",
            "preview-digest",
            "elevation",
            "reason",
            "approval-request",
            "idempotency-key",
        ],
        &["json", "quiet"],
        false,
    );
    let o = output_flags(o, &f);
    let id = if f.get("id").is_empty() {
        leading.map(String::as_str).unwrap_or("")
    } else {
        f.get("id")
    };
    if !f.positional.is_empty() {
        return Err(format!(
            "identity transition {operation} accepts one transition UUID and flags only"
        )
        .into());
    }
    if !crate::identity_checks::valid_uuid(id)
        || !crate::identity_checks::valid_uuid(f.get("elevation"))
    {
        return Err("transition id and --elevation must be UUIDs".into());
    }
    if !crate::identity_checks::hex(f.get("preview-digest"), 64) {
        return Err("--preview-digest must be exactly 64 lowercase hexadecimal characters".into());
    }
    let approval = f.get("approval-request").parse::<i64>().unwrap_or(0);
    if approval < 0 || (operation == "rollback" && approval == 0) {
        return Err("--approval-request must be a positive decimal id".into());
    }
    let key = mutation_key(f.get("idempotency-key"))?;
    identity_reason(f.get("reason"), &format!("identity transition {operation}"))?;
    let mut body = serde_json::json!({"previewDigest":f.get("preview-digest"),"elevationId":f.get("elevation"),"reason":f.get("reason"),"idempotencyKey":key});
    if approval > 0 {
        body["approvalRequestId"] = approval.to_string().into();
    }
    let headers = identity_headers(&key, f.get("reason"), f.get("preview-digest"));
    let (v, ordered) = identity_request(
        api,
        "identityTransitionDetail",
        "POST",
        &format!("{PREFIX}/transitions/{}/{operation}", path_escape(id)),
        Some(body),
        &headers,
    )?;
    if o.json || o.quiet {
        wire_output(&o, &ordered);
    } else {
        println!(
            "Transition {} {operation} accepted; state={} generation={}.",
            text(&v, "transitionId"),
            text(&v, "state"),
            text(&v, "transitionGeneration")
        );
    }
    Ok(())
}

fn transition_generation(
    api: &Api,
    o: &Options,
    args: &[String],
    operation: &str,
) -> Result<(), Failure> {
    let id = args
        .first()
        .filter(|s| !s.starts_with('-') && crate::identity_checks::valid_uuid(s))
        .ok_or_else(|| format!("identity transition {operation} requires one transition UUID"))?;
    let strings = if operation == "retry" {
        vec!["expected-generation", "reason", "idempotency-key", "effect"]
    } else {
        vec!["expected-generation", "reason", "idempotency-key"]
    };
    let f = crate::flags::parse(
        &format!("identity transition {operation}"),
        &args[1..],
        &strings,
        &["json", "quiet"],
        false,
    );
    let o = output_flags(o, &f);
    if operation == "retry" {
        if !f.positional.is_empty()
            || !crate::identity_checks::valid_uuid(f.get("effect"))
            || !crate::identity_checks::positive(f.get("expected-generation"))
        {
            return Err(
                "--effect must be a UUID and --expected-generation a positive decimal".into(),
            );
        }
    } else if !f.positional.is_empty()
        || !crate::identity_checks::positive(f.get("expected-generation"))
    {
        return Err("--expected-generation must be a positive decimal".into());
    }
    identity_reason(f.get("reason"), &format!("identity transition {operation}"))?;
    let key = mutation_key(f.get("idempotency-key"))?;
    let body = serde_json::json!({"expectedGeneration":f.get("expected-generation"),"reason":f.get("reason"),"idempotencyKey":key});
    let headers = identity_headers(&key, f.get("reason"), f.get("expected-generation"));
    let path = if operation == "retry" {
        format!(
            "{PREFIX}/transitions/{}/effects/{}/retry",
            path_escape(id),
            path_escape(f.get("effect"))
        )
    } else {
        format!("{PREFIX}/transitions/{}/{operation}", path_escape(id))
    };
    let (v, ordered) = identity_request(
        api,
        "identityTransitionDetail",
        "POST",
        &path,
        Some(body),
        &headers,
    )?;
    if o.json || o.quiet {
        wire_output(&o, &ordered);
    } else if operation == "retry" {
        println!(
            "Effect {} exact retry accepted; transition state={} generation={}.",
            f.get("effect"),
            text(&v, "state"),
            text(&v, "transitionGeneration")
        );
    } else {
        println!(
            "Transition {id} {operation} accepted; state={} generation={}.",
            text(&v, "state"),
            text(&v, "transitionGeneration")
        );
    }
    Ok(())
}

fn job(api: &Api, o: &Options, args: &[String]) -> Result<(), Failure> {
    let a = need(
        args,
        1,
        "usage: mailctl identity job show|watch|cancel|results UUID",
    )?;
    let sub = a[0].as_str();
    let args = &a[1..];
    if sub == "show" {
        if args.len() != 1 || !crate::identity_checks::valid_uuid(&args[0]) {
            return Err("usage: mailctl identity job show UUID".into());
        }
        let (v, ordered) = fetch_job(api, &args[0], &format!("{PREFIX}/jobs/"))?;
        print_job(o, &v, &ordered);
        return Ok(());
    }
    if sub == "cancel" {
        if args.len() != 1 || !crate::identity_checks::valid_uuid(&args[0]) {
            return Err("usage: mailctl identity job cancel UUID".into());
        }
        let (v, ordered) = identity_request(
            api,
            "identityJob",
            "POST",
            &format!("{PREFIX}/jobs/{}/cancel", path_escape(&args[0])),
            None,
            &[],
        )?;
        print_job(o, &v, &ordered);
        return Ok(());
    }
    if sub == "watch" {
        let id = args
            .first()
            .filter(|s| crate::identity_checks::valid_uuid(s))
            .ok_or("usage: mailctl identity job watch UUID [--timeout DURATION]")?;
        let f = crate::flags::parse(
            "identity job watch",
            &args[1..],
            &["timeout"],
            &["json", "quiet"],
            false,
        );
        let o = output_flags(o, &f);
        if !f.positional.is_empty() {
            return Err("identity job watch accepts one UUID and flags only".into());
        }
        let timeout = watch_timeout(flag_default(&f, "timeout", "30m"))?;
        let (v, ordered) = wait_job(api, &o, id, &format!("{PREFIX}/jobs/"), timeout)?;
        print_job(&o, &v, &ordered);
        if text(&v, "state") != "completed" {
            return Err(terminal_job_error(&v));
        }
        return Ok(());
    }
    if sub == "results" {
        let id = args
            .first()
            .filter(|s| crate::identity_checks::valid_uuid(s))
            .ok_or("usage: mailctl identity job results UUID [--after N] [--limit N]")?;
        let f = crate::flags::parse(
            "identity job results",
            &args[1..],
            &["after", "limit"],
            &["json", "quiet"],
            false,
        );
        let o = output_flags(o, &f);
        let after = f.get("after").parse::<i64>().unwrap_or(0);
        let limit = flag_default(&f, "limit", "100").parse::<i64>().unwrap_or(0);
        if !f.positional.is_empty() || after < 0 || !(1..=500).contains(&limit) {
            return Err("identity job results requires after >= 0 and limit 1..500".into());
        }
        let (v, ordered) = identity_request(
            api,
            "identityJobResults",
            "GET",
            &format!(
                "{PREFIX}/jobs/{}/results?after={after}&limit={limit}",
                path_escape(id)
            ),
            None,
            &[],
        )?;
        if o.json || o.quiet {
            wire_output(&o, &ordered);
        } else {
            table(
                &["SEQUENCE", "PERSON ID", "STATE", "CREATED AT"],
                array(&v["items"])
                    .iter()
                    .map(|r| {
                        vec![
                            text(r, "sequence").into(),
                            r["userId"].as_str().unwrap_or("-").into(),
                            text(r, "state").into(),
                            text(r, "createdAt").into(),
                        ]
                    })
                    .collect(),
            );
        }
        return Ok(());
    }
    // identity job actions
    Err(format!("unknown identity job action {sub:?}").into())
}
fn fetch_job(api: &Api, id: &str, prefix: &str) -> Result<(Value, String), Failure> {
    identity_request(
        api,
        "identityJob",
        "GET",
        &format!("{prefix}{}", path_escape(id)),
        None,
        &[],
    )
}
fn print_job(o: &Options, v: &Value, ordered: &str) {
    if o.json || o.quiet {
        wire_output(o, ordered);
    } else {
        println!(
            "Identity job {}: kind={} state={} terminal={}\nSnapshot: {}  Expires: {}\nNext: {}",
            text(v, "jobId"),
            text(v, "kind"),
            text(v, "state"),
            boolean(v, "terminal"),
            text(v, "snapshotId"),
            text(v, "expiresAt"),
            text(v, "nextAction")
        );
    }
}

fn watch_timeout(raw: &str) -> Result<std::time::Duration, Failure> {
    duration(raw)
        .filter(|d| d.as_secs_f64() >= 1.0 && d.as_secs_f64() <= 86400.0)
        .ok_or_else(|| Failure::from("--timeout must be a duration from 1s through 24h"))
}
fn wait_job(
    api: &Api,
    o: &Options,
    id: &str,
    prefix: &str,
    timeout: std::time::Duration,
) -> Result<(Value, String), Failure> {
    let deadline = std::time::Instant::now() + timeout;
    let mut delay = std::time::Duration::from_secs(1);
    loop {
        let result = fetch_job(api, id, prefix)?;
        let v = &result.0;
        if boolean(v, "terminal") {
            return Ok(result);
        }
        if std::time::Instant::now() + delay > deadline {
            return Err(format!(
                "identity job {id} did not finish within {}; the server job was not cancelled",
                duration_text(timeout)
            )
            .into());
        }
        if !o.quiet {
            eprintln!(
                "Identity job {id}: {}; next={}",
                text(v, "state"),
                text(v, "nextAction")
            );
        }
        std::thread::sleep(delay);
        delay = (delay * 2).min(std::time::Duration::from_secs(10));
    }
}
fn terminal_job_error(v: &Value) -> Failure {
    Failure::from(format!(
        "identity job {} ended in {}; next: {}",
        text(v, "jobId"),
        text(v, "state"),
        text(v, "nextAction")
    ))
    .exit(if ["cancelled", "expired"].contains(&text(v, "state")) {
        4
    } else {
        1
    })
}

fn upgrade(api: &Api, o: &Options, args: &[String]) -> Result<(), Failure> {
    let a=need(args,1,"usage: mailctl identity upgrade status|canary|rollback|preflight|backfill|shadow|retirement-check")?;
    let sub = a[0].as_str();
    let args = &a[1..];
    if sub == "status" {
        return upgrade_status(api, o, args);
    }
    if sub == "preflight" {
        let f = crate::flags::parse(
            "identity upgrade preflight",
            args,
            &["output"],
            &["json", "quiet", "yes", "y"],
            false,
        );
        let o = output_flags(o, &f);
        if !f.positional.is_empty() {
            return Err("identity upgrade preflight accepts flags only".into());
        }
        let (v, ordered) = identity_request(
            api,
            "identityUpgradePreflight",
            "POST",
            &format!("{PREFIX}/upgrade/preflight"),
            Some(serde_json::json!({})),
            &[],
        )?;
        if !f.get("output").is_empty() {
            export_write(
                &o,
                f.get("output"),
                format!("{}\n", escape_json_text(&ordered)).as_bytes(),
            )?;
        }
        print_preflight(&o, &v, &ordered, f.get("output"));
        if !boolean(&v, "safeToBackfill") {
            return Err(Failure::from(format!(
                "identity upgrade preflight has {} blocking check(s)",
                array(&v["blockers"]).len()
            ))
            .exit(4));
        }
        return Ok(());
    }
    if sub == "backfill" {
        return backfill(api, o, args);
    }
    // Backfill start uses the same durable-job boundary.
    if sub == "shadow" {
        return shadow(api, o, args);
    }
    if sub == "canary" {
        return canary(api, o, args);
    }
    if sub == "rollback" {
        return upgrade_rollback(api, o, args);
    }
    if sub == "retirement-check" {
        let o = read_flags("identity upgrade retirement-check", o, args)?;
        let (v, ordered) = identity_request(
            api,
            "identityUpgradeRetirementCheck",
            "GET",
            &format!("{PREFIX}/upgrade/retirement-check"),
            None,
            &[],
        )?;
        if o.json || o.quiet {
            wire_output(&o, &ordered);
        } else {
            println!("Identity legacy retirement ready: {}", boolean(&v, "ready"));
            for c in array(&v["checks"]) {
                println!(
                    "{:<4} {} — {}",
                    if boolean(c, "passed") { "PASS" } else { "FAIL" },
                    text(c, "name"),
                    text(c, "nextAction")
                );
            }
            println!("Next: {}", text(&v, "nextAction"));
        }
        if !boolean(&v, "ready") {
            return Err(Failure::from("identity legacy retirement remains blocked").exit(4));
        }
        return Ok(());
    }
    // identity upgrade actions
    Err(format!("unknown identity upgrade action {sub:?}").into())
}
fn upgrade_status(api: &Api, o: &Options, args: &[String]) -> Result<(), Failure> {
    let o = read_flags("identity upgrade status", o, args)?;
    let (v, ordered) = identity_request(
        api,
        "identityUpgradeStatus",
        "GET",
        &format!("{PREFIX}/upgrade/status"),
        None,
        &[],
    )?;
    if o.json || o.quiet {
        wire_output(&o, &ordered);
    } else {
        println!("Identity upgrade status (schema {})\nGates: master={} normalized_reads={} transitions={}",number(&v,"schemaVersion"),boolean(&v,"masterEnabled"),boolean(&v,"normalizedReadsEnabled"),boolean(&v,"transitionsEnabled"));
        let s = &v["sources"];
        println!(
            "Sources: total={} shadow={} canary={} normalized={} cohort_members={}",
            number(s, "total"),
            number(s, "shadow"),
            number(s, "canary"),
            number(s, "normalized"),
            number(s, "cohortMembers")
        );
        let b = &v["blockers"];
        println!(
            "Blockers: critical_divergences={} pending_candidates={} pending_effects={}",
            number(b, "criticalDivergences"),
            number(b, "pendingCandidates"),
            number(b, "pendingEffects")
        );
    }
    Ok(())
}

fn print_preflight(o: &Options, v: &Value, ordered: &str, output: &str) {
    if o.json || o.quiet {
        wire_output(o, ordered);
    } else {
        println!(
            "Identity upgrade preflight: safe_to_backfill={} people={}\nSHA-256: {}",
            boolean(v, "safeToBackfill"),
            number(&v["estimates"], "people"),
            text(v, "sha256")
        );
        for c in array(&v["checks"]) {
            println!(
                "{:<4} {:<7} {} — {}",
                if boolean(c, "passed") { "PASS" } else { "FAIL" },
                text(c, "severity"),
                text(c, "name"),
                text(c, "nextAction")
            );
        }
        if !output.is_empty() {
            println!("Evidence: {output} (mode 0600)");
        }
    }
}
fn export_write(o: &Options, path: &str, data: &[u8]) -> Result<(), Failure> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    match std::fs::symlink_metadata(path) {
        Ok(m) => {
            if !m.is_file() {
                return Err(format!("refusing to replace non-regular output path {path}").into());
            }
            o.confirm(&format!("Replace identity export {path}"))?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(format!(
                "inspect output {path}: lstat {path}: {}",
                crate::flags::go_io_error(&e)
            )
            .into())
        }
    };
    let dest = std::path::Path::new(path);
    let dir = dest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let tmp = dir.join(format!(".mailctl-private-artifact-{}", new_uuid()?));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| {
            format!(
                "install identity export: create temporary private artifact: open {}: {}",
                tmp.display(),
                crate::flags::go_io_error(&e)
            )
        })?;
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _cleanup = Cleanup(tmp.clone());
    f.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .map_err(|e| format!("install identity export: chmod temporary private artifact: {e}"))?;
    f.write_all(data)
        .map_err(|e| format!("install identity export: write temporary private artifact: {e}"))?;
    f.sync_all()
        .map_err(|e| format!("install identity export: sync temporary private artifact: {e}"))?;
    drop(f);
    std::fs::rename(&tmp, dest)
        .map_err(|e| format!("install identity export: replace private artifact: {e}"))?;
    std::fs::File::open(dir)
        .and_then(|f| f.sync_all())
        .map_err(|e| format!("install identity export: sync private artifact directory: {e}"))?;
    Ok(())
}

fn backfill(api: &Api, o: &Options, args: &[String]) -> Result<(), Failure> {
    let a = need(
        args,
        1,
        "usage: mailctl identity upgrade backfill plan|start",
    )?;
    if a[0] == "plan" {
        if a.len() != 1 {
            return Err("identity upgrade backfill plan accepts no arguments".into());
        }
        let (v, ordered) = identity_request(
            api,
            "identityUpgradePreflight",
            "POST",
            &format!("{PREFIX}/upgrade/backfill"),
            Some(serde_json::json!({"action":"plan"})),
            &[],
        )?;
        print_preflight(o, &v, &ordered, "");
        if !boolean(&v, "safeToBackfill") {
            return Err(Failure::from("identity backfill plan is blocked").exit(4));
        }
        if number(&v["estimates"], "people") > 0 {
            return Err(Failure::from(format!(
                "identity backfill plan contains up to {} person change(s)",
                number(&v["estimates"], "people")
            ))
            .exit(2));
        }
        return Ok(());
    }
    if a[0] == "start" {
        let f = crate::flags::parse(
            "identity upgrade backfill start",
            &a[1..],
            &["preflight-checksum", "reason", "idempotency-key"],
            &["json", "quiet"],
            false,
        );
        let o = output_flags(o, &f);
        if !f.positional.is_empty() || !crate::identity_checks::hex(f.get("preflight-checksum"), 64)
        {
            return Err("identity upgrade backfill start requires --preflight-checksum HEX".into());
        }
        identity_reason(f.get("reason"), "identity upgrade backfill start")?;
        let key = mutation_key(f.get("idempotency-key"))?;
        let headers = identity_headers(&key, f.get("reason"), "");
        if !o.quiet {
            eprintln!("Idempotency-Key: {key}");
        }
        let (v, ordered) = identity_request(
            api,
            "identityJob",
            "POST",
            &format!("{PREFIX}/upgrade/backfill"),
            Some(
                serde_json::json!({"action":"start","preflightChecksum":f.get("preflight-checksum"),"reason":f.get("reason"),"idempotencyKey":key}),
            ),
            &headers,
        )?;
        if o.json || o.quiet {
            wire_output(&o, &ordered);
        } else {
            println!("Identity backfill durably accepted as job {}.\nNext: mailctl identity job watch {}",text(&v,"jobId"),text(&v,"jobId"));
        }
        return Ok(());
    }
    Err(format!("unknown identity upgrade backfill action {:?}", a[0]).into())
}

fn shadow(api: &Api, o: &Options, args: &[String]) -> Result<(), Failure> {
    let f = crate::flags::parse(
        "identity upgrade shadow",
        args,
        &["source"],
        &["json", "quiet"],
        false,
    );
    let o = output_flags(o, &f);
    if !f.positional.is_empty() || f.get("source").trim().is_empty() || f.get("source").len() > 64 {
        return Err("identity upgrade shadow requires --source KEY".into());
    }
    let (v, ordered) = identity_request(
        api,
        "identityUpgradeShadow",
        "GET",
        &format!(
            "{PREFIX}/upgrade/shadow?sourceKey={}",
            escape(f.get("source"))
        ),
        None,
        &[],
    )?;
    if o.json || o.quiet {
        wire_output(&o, &ordered);
    } else {
        println!("Identity shadow {}: eligible={} syncs={}/{} window={:.2}/{}h\nDivergences: critical={} missing={} ambiguity={}\nNext: {}",text(&v,"sourceKey"),boolean(&v,"eligible"),number(&v,"completedSyncs"),number(&v,"requiredSyncs"),v["windowHours"].as_f64().unwrap_or(0.0),number(&v,"requiredWindowHours"),number(&v,"criticalDivergences"),number(&v,"missingProjections"),number(&v,"undispositionedAmbiguities"),text(&v,"nextAction"));
    }
    if !boolean(&v, "eligible") {
        return Err(Failure::from("identity shadow gate is not eligible").exit(4));
    }
    Ok(())
}

fn canary(api: &Api, o: &Options, args: &[String]) -> Result<(), Failure> {
    if args.first().is_some_and(|s| s == "plan") {
        shadow(api, o, &args[1..])?;
        return Err(Failure::from(
            "identity canary plan is eligible and contains a read-path change",
        )
        .exit(2));
    }
    let mut args = args.to_vec();
    if args.first().is_some_and(|s| !s.starts_with('-')) {
        let sub = args.remove(0);
        match sub.as_str() {
            "enable" => args.push("--enabled".into()),
            "disable" => {}
            _ => {
                return Err(
                    "identity upgrade canary action must be plan, enable, or disable".into(),
                )
            }
        }
    }
    let f = crate::flags::parse(
        "identity upgrade canary",
        &args,
        &["source", "expected-generation", "users", "reason"],
        &["json", "quiet", "enabled"],
        false,
    );
    let o = output_flags(o, &f);
    if !f.positional.is_empty()
        || f.get("source").trim().is_empty()
        || f.get("source").len() > 64
        || !crate::identity_checks::positive(f.get("expected-generation"))
    {
        return Err("--source and a positive --expected-generation are required".into());
    }
    identity_reason(f.get("reason"), "identity upgrade canary")?;
    let users = csv(f.get("users"));
    let mut seen = std::collections::BTreeSet::new();
    for id in &users {
        if !crate::identity_checks::positive(id) {
            return Err("--users must contain positive decimal person ids".into());
        }
        if !seen.insert(id) {
            return Err("--users must not contain duplicate person ids".into());
        }
    }
    if users.len() > 500 {
        return Err("--users accepts at most 500 person ids".into());
    }
    if f.boolean("enabled") && users.is_empty() {
        return Err("--users is required when --enabled is set".into());
    }
    let body = serde_json::json!({"sourceKey":f.get("source"),"expectedGeneration":f.get("expected-generation"),"enabled":f.boolean("enabled"),"userIds":users,"reason":f.get("reason")});
    let (v, ordered) = identity_request(
        api,
        "identityUpgradeCanaryResult",
        "POST",
        &format!("{PREFIX}/upgrade/canary"),
        Some(body),
        &[("X-Audit-Reason", f.get("reason").into())],
    )?;
    if o.json || o.quiet {
        wire_output(&o, &ordered);
    } else {
        println!(
            "Identity source {} is in {} read mode at generation {} (cohort {}).",
            text(&v, "sourceKey"),
            text(&v, "readMode"),
            text(&v, "generation"),
            number(&v, "cohortSize")
        );
    }
    Ok(())
}

fn upgrade_rollback(api: &Api, o: &Options, args: &[String]) -> Result<(), Failure> {
    let f = crate::flags::parse(
        "identity upgrade rollback",
        args,
        &["reason"],
        &["json", "quiet", "yes", "y"],
        false,
    );
    let o = output_flags(o, &f);
    if !f.positional.is_empty() {
        return Err("identity upgrade rollback accepts flags only".into());
    }
    identity_reason(f.get("reason"), "identity upgrade rollback")?;
    o.confirm("Disable normalized identity admission and reads")?;
    let (v, ordered) = identity_request(
        api,
        "identityUpgradeRollbackResult",
        "POST",
        &format!("{PREFIX}/upgrade/rollback"),
        Some(serde_json::json!({"readPath":"legacy","reason":f.get("reason")})),
        &[("X-Audit-Reason", f.get("reason").into())],
    )?;
    if o.json || o.quiet {
        wire_output(&o, &ordered);
    } else {
        println!("Identity admission and normalized reads rolled back; {} committed effect(s) remain draining.",number(&v,"pendingEffects"));
    }
    Ok(())
}

fn sha256(raw: &[u8]) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha256::digest(raw))
}

fn inventory_export(api: &Api, o: &Options, args: &[String]) -> Result<(), Failure> {
    let f = crate::flags::parse(
        "identity inventory export",
        args,
        &["output"],
        &["json", "quiet", "yes", "y"],
        false,
    );
    let o = output_flags(o, &f);
    if !f.positional.is_empty() || f.get("output").trim().is_empty() {
        return Err("usage: mailctl identity inventory export --output <file>".into());
    }
    let (raw, headers) = download(api, &format!("{PREFIX}/inventory/export"))?;
    verify_digest(&raw, header(&headers, "Digest"))
        .map_err(|e| format!("verify identity inventory export: {e}"))?;
    let (v, _) = wire_decode("identityInventoryExport", &raw)
        .map_err(|e| format!("decode identity inventory export: {e}"))?;
    crate::identity_checks::validate("identityInventoryExport", &v)?;
    export_write(&o, f.get("output"), &raw)?;
    let sum = sha256(&raw);
    if o.json {
        o.output(&serde_json::json!({"output":f.get("output"),"sha256":sum,"schemaVersion":number(&v,"schemaVersion")}));
    } else if !o.quiet {
        println!(
            "Identity inventory written to {} (mode 0600).\nSHA-256: {sum}",
            f.get("output")
        );
    }
    Ok(())
}
fn download(api: &Api, path: &str) -> Result<(Vec<u8>, reqwest::header::HeaderMap), Failure> {
    api.bytes("GET", path, None, None, &[], 25 << 20)
        .map_err(|mut e| {
            if e.message == format!("response exceeded the {}-byte client limit", 25 << 20) {
                e.message = format!(
                    "identity download exceeded the {}-byte client limit",
                    25 << 20
                );
            }
            e
        })
}
fn header<'a>(h: &'a reqwest::header::HeaderMap, key: &str) -> &'a str {
    h.get(key).and_then(|h| h.to_str().ok()).unwrap_or("")
}
fn verify_digest(raw: &[u8], digest: &str) -> Result<(), Failure> {
    use base64::Engine;
    let expected = digest
        .strip_prefix("sha-256=")
        .ok_or("response is missing a SHA-256 Digest header")?;
    let expected = base64::engine::general_purpose::STANDARD
        .decode(expected.replace(['\r', '\n'], ""))
        .ok()
        .filter(|b| b.len() == 32)
        .ok_or("response has an invalid SHA-256 Digest header")?;
    use sha2::Digest;
    if &sha2::Sha256::digest(raw)[..] != expected.as_slice() {
        return Err("response SHA-256 Digest does not match its bytes".into());
    }
    Ok(())
}
