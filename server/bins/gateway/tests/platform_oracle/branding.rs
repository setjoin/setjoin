//! Group `branding` cases for the `terms-remaining` oracle: `/admin/branding`. The logo
//! goes to a fake S3 whose PUT requests become part of the observation (`s3`).
use super::terms::Case;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const EFFECTS: &str =
    "SELECT to_jsonb(c)::text FROM system_config c WHERE key LIKE 'brand%' ORDER BY key";
const BOUNDARY: &str = "plat5boundary";

/// What the fake S3 saw of one PUT: method, path, content type and the object bytes (the
/// `aws-chunked` framing minio uses over plain HTTP is removed).
pub fn upload(parts: &hyper::http::request::Parts, raw: &[u8]) -> Value {
    let header = |name: &str| {
        parts
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned()
    };
    let chunked = header("x-amz-content-sha256").starts_with("STREAMING-")
        || header("content-encoding").contains("aws-chunked");
    let body = if chunked {
        let mut out = Vec::new();
        let mut at = 0;
        while let Some(line) = raw[at..].windows(2).position(|w| w == b"\r\n") {
            let size = usize::from_str_radix(
                raw[at..at + line]
                    .split(|b| *b == b';')
                    .next()
                    .map(|b| std::str::from_utf8(b).unwrap_or("0"))
                    .unwrap_or("0"),
                16,
            )
            .unwrap_or(0);
            at += line + 2;
            if size == 0 {
                break;
            }
            out.extend_from_slice(&raw[at..at + size]);
            at += size + 2;
        }
        out
    } else {
        raw.to_vec()
    };
    json!({
        "method": parts.method.as_str(),
        "path": parts.uri.path(),
        "content_type": header("content-type"),
        "bytes": body.len(),
        "sha256": format!("{:x}", Sha256::digest(&body)),
    })
}

fn part(name: &str, file: Option<(&str, Option<&str>)>, body: &str) -> String {
    let mut out = format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"");
    if let Some((filename, kind)) = file {
        out += &format!("; filename=\"{filename}\"");
        if let Some(kind) = kind {
            out += &format!("\r\nContent-Type: {kind}");
        }
    }
    out + &format!("\r\n\r\n{body}\r\n")
}
fn form(parts: &[String]) -> String {
    format!("{}--{BOUNDARY}--\r\n", parts.concat())
}

fn base(method: &'static str, perm: &'static str) -> Case {
    Case {
        method,
        pattern: "/admin/branding",
        fill: vec![],
        query: String::new(),
        perm,
        body: String::new(),
        headers: if method == "POST" {
            vec![(
                "content-type",
                format!("multipart/form-data; boundary={BOUNDARY}"),
            )]
        } else {
            vec![]
        },
        seed: vec!["DELETE FROM system_config WHERE key LIKE 'brand%'".into()],
        cleanup: vec!["DELETE FROM system_config WHERE key LIKE 'brand%'".into()],
        effects: EFFECTS,
        table: "system_config",
        channels: vec![],
        status: 200,
        replace: vec![],
        unshift: vec![],
    }
}

const PNG: &str = "\u{89}PNG-not-really";

pub fn specs(action: &str, label: &str) -> Option<Case> {
    let mut c = match action {
        "branding-get" => base("GET", "domains.read"),
        "branding-set" => base("POST", "mail.pipeline"),
        _ => return None,
    };
    let seed = |c: &mut Case, text: &str| c.seed.push(text.into());
    if action == "branding-get" {
        match label {
            "success" | "denied" | "scoped" => {
                seed(&mut c, "INSERT INTO system_config(key,value,description,updated_at) VALUES ('brand_name','\"Acme <Mail>\"','d','2026-10-01 10:00:00+00'),('brand_logo_url','\"/blob/branding/logo\"','d','2026-10-01 10:00:00+00')");
            }
            "defaults" => {}
            "name-only" => seed(&mut c, "INSERT INTO system_config(key,value,description,updated_at) VALUES ('brand_name','\"Acme\"','d','2026-10-01 10:00:00+00')"),
            "number-name" => seed(&mut c, "INSERT INTO system_config(key,value,description,updated_at) VALUES ('brand_name','42','d','2026-10-01 10:00:00+00')"),
            "null-name" => seed(&mut c, "INSERT INTO system_config(key,value,description,updated_at) VALUES ('brand_name','null','d','2026-10-01 10:00:00+00')"),
            "object-name" => seed(&mut c, "INSERT INTO system_config(key,value,description,updated_at) VALUES ('brand_name','{\"a\":1}','d','2026-10-01 10:00:00+00')"),
            "ignored-query" => c.query = "?x=%zz&name=ignored".into(),
            _ => return None,
        }
    } else {
        c.body = form(&[part("name", None, "\"Acme\"")]);
        match label {
            "success" | "denied" | "scoped" | "repeat" => {}
            "name-bare" => c.body = form(&[part("name", None, "Acme")]),
            "name-number" => c.body = form(&[part("name", None, "42")]),
            "name-null" => c.body = form(&[part("name", None, "null")]),
            "name-empty" => c.body = form(&[part("name", None, "")]),
            "name-twice" => {
                c.body = form(&[
                    part("name", None, "\"first\""),
                    part("name", None, "\"second\""),
                ])
            }
            "name-in-query" => {
                c.query = "?name=%22fromquery%22".into();
                c.body = form(&[part("name", None, "\"fromform\"")]);
            }
            "name-query-only" => {
                c.query = "?name=%22fromquery%22".into();
                c.body = form(&[]);
            }
            "name-unicode" => c.body = form(&[part("name", None, "\"Caf\u{e9} \u{1F600} <b>&\"")]),
            "name-escaped" => c.body = form(&[part("name", None, "\"a\\u0000b\"")]),
            "name-overwrites" => {
                seed(&mut c, "INSERT INTO system_config(key,value,description,updated_at) VALUES ('brand_name','\"Old\"','keep','2026-10-01 10:00:00+00')");
                c.body = form(&[part("name", None, "\"New\"")]);
            }
            "logo" => {
                c.body = form(&[part("logo", Some(("logo.png", Some("image/svg+xml"))), PNG)])
            }
            "logo-default-type" => c.body = form(&[part("logo", Some(("logo.png", None)), PNG)]),
            "logo-and-name" => {
                c.body = form(&[
                    part("name", None, "\"Acme\""),
                    part("logo", Some(("logo.png", Some("image/png"))), PNG),
                ])
            }
            "logo-empty" => {
                c.body = form(&[part("logo", Some(("logo.png", Some("image/png"))), "")])
            }
            "logo-twice" => {
                c.body = form(&[
                    part("logo", Some(("a.png", None)), "first"),
                    part("logo", Some(("b.png", None)), "second"),
                ])
            }
            "logo-no-filename" => c.body = form(&[part("logo", None, "text")]),
            "logo-empty-filename" => c.body = form(&[part("logo", Some(("", None)), "text")]),
            "other-file" => c.body = form(&[part("avatar", Some(("a.png", None)), "x")]),
            "unnamed-part" => {
                c.body = form(&[format!(
                    "--{BOUNDARY}\r\nContent-Disposition: form-data\r\n\r\nx\r\n"
                )])
            }
            "empty-form" => c.body = form(&[]),
            "no-body" => c.body = String::new(),
            "bad-boundary-body" => c.body = "not multipart".into(),
            "wrong-content-type" => {
                c.headers = vec![("content-type", "application/json".into())];
                c.body = "{\"name\":\"x\"}".into();
            }
            "urlencoded" => {
                c.headers = vec![("content-type", "application/x-www-form-urlencoded".into())];
                c.body = "name=%22x%22".into();
            }
            "no-boundary" => {
                c.headers = vec![("content-type", "multipart/form-data".into())];
            }
            "truncated" => {
                c.body = format!(
                    "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\n\"cut"
                )
            }
            "bad-query-escape" => c.query = "?x=%zz".into(),
            "semicolon-query" => c.query = "?a=1;b=2".into(),
            "oversize" => {
                c.body = form(&[part(
                    "logo",
                    Some(("big.png", None)),
                    &"x".repeat((2 << 20) + 16),
                )])
            }
            "just-under" => {
                c.body = form(&[part(
                    "logo",
                    Some(("big.png", None)),
                    &"x".repeat((2 << 20) - 512),
                )])
            }
            _ => return None,
        }
    }
    c.status = if label == "denied" { 403 } else { 0 };
    Some(c)
}
