//! Slice `smime` (#328): the admin trust-anchor routes and the user client-certificate status.
//! `smime_trust_anchors` is global, so a case stashes every row, seeds its own and `teardown`
//! puts the stash back. Certificates are fixed fixtures (`tests/conformance/mail-security/
//! smime-certs`); their validity dates are masked by name so the goldens stay readable.
use super::{Req, Seed};
use crate::common::BoxError;
use serde_json::{json, Value};
use setjoin_conformance::fixture::Account;
use setjoin_mail_security::smime::parse_chain;

const BOUNDARY: &str = "XSMIMEORACLEBOUNDARY";
pub const A: &str = include_str!("../../../../tests/conformance/mail-security/smime-certs/a.pem");
pub const B: &str = include_str!("../../../../tests/conformance/mail-security/smime-certs/b.pem");
pub const C: &str = include_str!("../../../../tests/conformance/mail-security/smime-certs/c.pem");
pub const D: &str = include_str!("../../../../tests/conformance/mail-security/smime-certs/d.pem");
pub const OLD: &str =
    include_str!("../../../../tests/conformance/mail-security/smime-certs/old.pem");
pub const FUTURE: &str =
    include_str!("../../../../tests/conformance/mail-security/smime-certs/future.pem");
pub const NOCN: &str =
    include_str!("../../../../tests/conformance/mail-security/smime-certs/nocn.pem");
const KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgC2pGDY0ZIGMQWFHg\nLCe8vS59NebOjL0n69B7ThNghzuhRANCAARZnvMH3hWt5eo+t7T5G81e9B3bQ8W9\nSlX4YECWE/MESQeca6W/BqfVid4r0iVCnnH1K8f7eQAaC4oVOoOWtNca\n-----END PRIVATE KEY-----\n";

/// Fixed validity dates (certificate fields) replaced by a readable token in every text.
const DATES: [(&str, &str); 4] = [
    ("2095-10-01T00:00:00Z", "<not-after>"),
    ("2090-01-01T00:00:00Z", "<future-not-before>"),
    ("2095-01-01T00:00:00Z", "<future-not-after>"),
    ("2021-01-01T00:00:00Z", "<expired-not-after>"),
];

pub fn mask_text(text: &str) -> String {
    let mut out = text.to_owned();
    for (from, to) in DATES {
        out = out.replace(from, to);
    }
    out
}

/// A label that makes the caller a domain-scoped admin (`scoped` or `scoped-<variant>`).
pub fn is_scoped(label: &str) -> bool {
    label == "scoped" || label.starts_with("scoped-")
}

pub fn route(action: &str) -> (&'static str, &'static str) {
    match action {
        "list" => ("GET", "/admin/smime/trust-anchors"),
        "import" => ("POST", "/admin/smime/trust-anchors"),
        "delete" => ("DELETE", "/admin/smime/trust-anchors/{id}"),
        "cert-status" => ("GET", "/user/cert-status"),
        _ => panic!("unknown smime action {action}"),
    }
}

pub fn granted(action: &str) -> Vec<&'static str> {
    match action {
        "import" | "delete" => vec!["mail.security"],
        _ => vec!["mail.pipeline"],
    }
}

pub fn wanted(action: &str, label: &str) -> Option<u16> {
    if action == "import" {
        if let Some(name) = label.strip_prefix("strict-") {
            let c = super::certificates::cases().into_iter().find(|c| c.name == name).expect("strict case");
            return Some(if c.rejected { 400 } else { 200 });
        }
    }
    Some(match (action, label) {
        (_, "denied") => 403,
        ("import", "success-no-label" | "success-label-trim") => 200,
        (
            "import",
            "expired" | "expired-first" | "not-multipart" | "no-boundary" | "missing-cert"
            | "cert-not-file" | "empty-cert" | "garbage" | "key-block" | "trailing-junk"
            | "bad-base64" | "trailing-der" | "too-large" | "bad-query" | "semicolon-query"
            | "empty-body" | "empty-file-name" | "duplicate-extension",
        ) => 400,
        ("delete", "bad-id" | "overflow-id") => 400,
        (
            "delete",
            "not-found" | "negative-id" | "scoped-global-row" | "scoped-foreign" | "repeat",
        ) => 404,
        _ => 200,
    })
}

/// `(label, certificate, domain: None | Some(true = actor's domain, false = other's), created hour)`.
struct Row {
    label: &'static str,
    pem: &'static str,
    domain: Option<bool>,
    hour: i32,
    null_bounds: bool,
    null_cn: bool,
}
fn row(label: &'static str, pem: &'static str, domain: Option<bool>, hour: i32) -> Row {
    Row {
        label,
        pem,
        domain,
        hour,
        null_bounds: false,
        null_cn: false,
    }
}

async fn insert(
    owner: &tokio_postgres::Client,
    a: &Account,
    b: &Account,
    r: &Row,
) -> Result<i64, BoxError> {
    let cert = parse_chain(r.pem.as_bytes())
        .map_err(|e| format!("{e:?}"))?
        .remove(0);
    let domain: Option<i64> = r.domain.map(|mine| if mine { a.domain } else { b.domain });
    let created = format!("2026-10-01 {:02}:00:00+00", r.hour);
    let row = owner
        .query_one(
            "INSERT INTO smime_trust_anchors(label,cert_pem,subject_cn,fingerprint,domain_id,not_before,not_after,created_at,created_by) \
             VALUES($1,$2,$3,$4,$5,CASE WHEN $6 THEN NULL ELSE to_timestamp($7::bigint) END,CASE WHEN $6 THEN NULL ELSE to_timestamp($8::bigint) END,$9::text::timestamptz,$10) RETURNING id",
            &[
                &r.label,
                &cert.pem,
                &(if r.null_cn { None } else { Some(cert.subject_cn.clone()) }),
                &cert.fingerprint,
                &domain,
                &r.null_bounds,
                &cert.not_before,
                &cert.not_after,
                &created,
                &a.user,
            ],
        )
        .await?;
    Ok(row.get(0))
}

pub async fn seed(
    owner: &tokio_postgres::Client,
    a: &Account,
    b: &Account,
    action: &str,
    label: &str,
) -> Result<Seed, BoxError> {
    let stash: Vec<String> = owner
        .query("SELECT to_jsonb(s)::text FROM smime_trust_anchors s", &[])
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    owner
        .batch_execute("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM smime_trust_anchors; COMMIT;")
        .await?;
    let mut names: Vec<(&'static str, i64, String)> = vec![
        ("domainId", a.domain, "<domain-a>".into()),
        ("domainId", b.domain, "<domain-b>".into()),
    ];
    let mut vars = std::collections::BTreeMap::new();
    let rows: Vec<Row> = match (action, label) {
        ("cert-status", "foreign") => vec![row("ca-c", C, Some(false), 3)],
        ("list", "empty") | ("import", _) | ("cert-status", _) => vec![],
        ("list", "null-bounds") => vec![
            row("ca-a", A, None, 1),
            Row {
                null_bounds: true,
                ..row("no-bounds", D, None, 2)
            },
            row("ca-c", C, Some(false), 3),
        ],
        ("list", "html") => vec![
            row("<&>\"quoted\" label", B, None, 1),
            Row {
                null_cn: true,
                ..row("no-cn", NOCN, Some(true), 2)
            },
            row("cn-last", C, None, 3),
        ],
        ("list", _) => vec![
            row("ca-a", A, None, 1),
            row("ca-b", B, Some(true), 2),
            row("ca-c", C, Some(false), 3),
            row("ca-d", D, None, 4),
        ],
        ("delete", _) => vec![
            row("global", A, None, 1),
            row("actor-domain", B, Some(true), 2),
            row("other-domain", C, Some(false), 3),
        ],
        _ => vec![],
    };
    let mut ids = vec![];
    for r in &rows {
        ids.push(insert(owner, a, b, r).await?);
    }
    if action == "import" && matches!(label, "existing" | "scoped") {
        insert(owner, a, b, &row("old-label", A, None, 1)).await?;
    }
    if action == "import" && label == "scoped-existing" {
        insert(owner, a, b, &row("old-label", A, Some(false), 1)).await?;
    }
    if action == "list" {
        for (i, id) in ids.iter().enumerate() {
            names.push(("id", *id, format!("<anchor-{i}>")));
        }
    }
    if action == "delete" {
        names.push(("id", ids[0], "<anchor-global>".into()));
        names.push(("id", ids[1], "<anchor-actor-domain>".into()));
        names.push(("id", ids[2], "<anchor-other-domain>".into()));
        vars.insert("global", ids[0]);
        vars.insert("actor", ids[1]);
        vars.insert("other", ids[2]);
    }
    Ok(Seed { stash, names, vars })
}

pub async fn teardown(owner: &tokio_postgres::Client, seed: &Seed) -> Result<(), BoxError> {
    owner
        .batch_execute(
            "BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM smime_trust_anchors;",
        )
        .await?;
    for row in &seed.stash {
        owner
            .execute("INSERT INTO smime_trust_anchors SELECT * FROM jsonb_populate_record(NULL::smime_trust_anchors, $1::text::jsonb)", &[row])
            .await?;
    }
    owner.batch_execute("COMMIT;").await?;
    Ok(())
}

fn multipart(parts: &[(&str, Option<&str>, &str)]) -> String {
    let mut out = String::new();
    for (name, file, content) in parts {
        out += &format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"");
        if let Some(file) = file {
            out += &format!("; filename=\"{file}\"");
        }
        out += &format!("\r\n\r\n{content}\r\n");
    }
    out + &format!("--{BOUNDARY}--\r\n")
}

fn certs(parts: &[&str]) -> String {
    parts.concat()
}

pub fn request(action: &str, label: &str, seed: &Seed) -> Req {
    let (_, pattern) = route(action);
    let mut headers: Vec<(String, String)> = vec![];
    let mut recorded_body = String::new();
    let mut query = String::new();
    let mut path = pattern.to_string();
    let form = |headers: &mut Vec<(String, String)>, parts: &[(&str, Option<&str>, &str)]| {
        headers.push((
            "content-type".into(),
            format!("multipart/form-data; boundary={BOUNDARY}"),
        ));
        multipart(parts)
    };
    let body = match (action, label) {
        ("import", l) => match l {
            l if l.starts_with("strict-") => form(&mut headers, &[("cert", Some("strict.pem"), &super::certificates::pem(&l[7..]))]),
            "duplicate-extension" => form(&mut headers, &[("cert", Some("duplicate.pem"), include_str!("../../../../tests/conformance/mail-security/smime-certs/duplicate-extension.pem"))]),
            "success" | "repeat" | "denied" | "scoped" | "existing" | "existing-scoped" => form(
                &mut headers,
                &[("label", None, "Corp CA"), ("cert", Some("ca.pem"), A)],
            ),
            "success-no-label" => form(&mut headers, &[("cert", Some("ca.pem"), A)]),
            "success-label-trim" => form(
                &mut headers,
                &[
                    ("label", None, " \t Spaced Label \r\n"),
                    ("cert", Some("ca.pem"), A),
                ],
            ),
            "blank-label" => form(
                &mut headers,
                &[("label", None, "  "), ("cert", Some("ca.pem"), A)],
            ),
            "label-in-query" => {
                query = "?label=from-query".into();
                form(
                    &mut headers,
                    &[("label", None, "from-body"), ("cert", Some("ca.pem"), A)],
                )
            }
            "label-first-wins" => form(
                &mut headers,
                &[
                    ("label", None, "first"),
                    ("label", None, "second"),
                    ("cert", Some("ca.pem"), A),
                ],
            ),
            "label-html" => form(
                &mut headers,
                &[
                    ("label", None, "<b>&\u{e9}\u{2028}</b>"),
                    ("cert", Some("ca.pem"), B),
                ],
            ),
            "cn-last" => form(
                &mut headers,
                &[("label", None, "cn"), ("cert", Some("c.pem"), C)],
            ),
            "no-cn" => form(
                &mut headers,
                &[("label", None, "nocn"), ("cert", Some("n.pem"), NOCN)],
            ),
            "future" => form(
                &mut headers,
                &[("label", None, "future"), ("cert", Some("f.pem"), FUTURE)],
            ),
            "bundle" => form(
                &mut headers,
                &[
                    ("label", None, "bundle"),
                    ("cert", Some("b.pem"), &certs(&[A, B, C])),
                ],
            ),
            "bundle-expired-last" => form(
                &mut headers,
                &[
                    ("label", None, "bundle"),
                    ("cert", Some("b.pem"), &certs(&[A, OLD])),
                ],
            ),
            "expired" => form(
                &mut headers,
                &[("label", None, "old"), ("cert", Some("o.pem"), OLD)],
            ),
            "expired-first" => form(
                &mut headers,
                &[
                    ("label", None, "old"),
                    ("cert", Some("o.pem"), &certs(&[OLD, A])),
                ],
            ),
            "not-multipart" => "{}".to_string(),
            "no-boundary" => {
                headers.push(("content-type".into(), "multipart/form-data".into()));
                "x".into()
            }
            "empty-body" => {
                headers.push((
                    "content-type".into(),
                    format!("multipart/form-data; boundary={BOUNDARY}"),
                ));
                String::new()
            }
            "missing-cert" => form(
                &mut headers,
                &[("label", None, "x"), ("other", Some("o.pem"), A)],
            ),
            "cert-not-file" => form(&mut headers, &[("cert", None, A)]),
            "empty-file-name" => form(&mut headers, &[("cert", Some(""), A)]),
            "empty-cert" => form(&mut headers, &[("cert", Some("e.pem"), "")]),
            "garbage" => form(
                &mut headers,
                &[("cert", Some("g.pem"), "not a certificate")],
            ),
            "key-block" => form(&mut headers, &[("cert", Some("k.pem"), KEY)]),
            "trailing-junk" => form(
                &mut headers,
                &[("cert", Some("t.pem"), &certs(&[A, "junk after\n"]))],
            ),
            "trailing-space" => form(
                &mut headers,
                &[("cert", Some("t.pem"), &certs(&[A, "\n  \n\t\n"]))],
            ),
            "leading-junk" => form(
                &mut headers,
                &[("cert", Some("l.pem"), &certs(&["leading text\n", A]))],
            ),
            "crlf" => form(
                &mut headers,
                &[("cert", Some("c.pem"), &A.replace('\n', "\r\n"))],
            ),
            "no-final-newline" => form(&mut headers, &[("cert", Some("n.pem"), A.trim_end())]),
            "pem-headers" => form(
                &mut headers,
                &[(
                    "cert",
                    Some("h.pem"),
                    &A.replacen(
                        "-----BEGIN CERTIFICATE-----\n",
                        "-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\n\n",
                        1,
                    ),
                )],
            ),
            "bad-base64" => form(
                &mut headers,
                &[("cert", Some("b.pem"), &A.replacen("MII", "M!I", 1))],
            ),
            "trailing-der" => {
                // A valid base64 body whose DER carries bytes after the certificate.
                let der: Vec<u8> = {
                    use base64::Engine as _;
                    let body: String = A.lines().filter(|l| !l.starts_with("-----")).collect();
                    let mut der = base64::engine::general_purpose::STANDARD
                        .decode(body)
                        .unwrap();
                    der.extend_from_slice(&[0, 1, 2]);
                    der
                };
                let pem = {
                    use base64::Engine as _;
                    format!(
                        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                        base64::engine::general_purpose::STANDARD.encode(der)
                    )
                };
                form(&mut headers, &[("cert", Some("t.pem"), &pem)])
            }
            "other-block-type" => form(
                &mut headers,
                &[(
                    "cert",
                    Some("x.pem"),
                    &A.replace("CERTIFICATE", "X509 CERTIFICATE"),
                )],
            ),
            "too-large" => {
                recorded_body = "<1 MiB + 1 multipart body>".into();
                form(
                    &mut headers,
                    &[("cert", Some("big.pem"), &"A".repeat((1 << 20) + 1))],
                )
            }
            "bad-query" => {
                query = "?x=%zz".into();
                form(&mut headers, &[("cert", Some("ca.pem"), A)])
            }
            "semicolon-query" => {
                query = "?a=1;b=2".into();
                form(&mut headers, &[("cert", Some("ca.pem"), A)])
            }
            _ => form(
                &mut headers,
                &[("label", None, "Corp CA"), ("cert", Some("ca.pem"), A)],
            ),
        },
        ("delete", l) => {
            let id = match l {
                "bad-id" => "abc".to_string(),
                "overflow-id" => "99999999999999999999".to_string(),
                "negative-id" => "-5".to_string(),
                "plus-id" => format!("+{}", seed.vars["global"]),
                "not-found" => "999999999".to_string(),
                "scoped-own" | "other-domain" => seed.vars["other"].to_string(),
                "scoped-foreign" | "global-deletes-scoped" | "actor-domain" => {
                    seed.vars["actor"].to_string()
                }
                _ => seed.vars["global"].to_string(),
            };
            path = format!("/admin/smime/trust-anchors/{id}");
            String::new()
        }
        _ => String::new(),
    };
    if label == "ignored-query" {
        query = "?limit=-1&x=%zz".into();
    }
    Req {
        path,
        query,
        recorded_query: String::new(),
        recorded_body,
        body,
        headers,
    }
}

pub async fn snapshot(
    owner: &tokio_postgres::Client,
    a: &Account,
    b: &Account,
    _seed: &Seed,
) -> Result<Value, BoxError> {
    let mut anchors = vec![];
    for row in owner
        .query(
            "SELECT label, cert_pem, subject_cn, fingerprint, domain_id, extract(epoch FROM not_before)::bigint, extract(epoch FROM not_after)::bigint, created_by FROM smime_trust_anchors ORDER BY fingerprint, domain_id NULLS FIRST",
            &[],
        )
        .await?
    {
        let domain = row.get::<_, Option<i64>>(4).map(|d| {
            if d == a.domain {
                "<domain-a>".to_owned()
            } else if d == b.domain {
                "<domain-b>".to_owned()
            } else {
                d.to_string()
            }
        });
        let creator = row.get::<_, Option<i64>>(7).map(|u| {
            if u == a.user {
                "<actor>".to_owned()
            } else {
                u.to_string()
            }
        });
        anchors.push(json!({
            "label": row.get::<_, String>(0),
            "cert_pem": row.get::<_, String>(1),
            "subject_cn": row.get::<_, Option<String>>(2),
            "fingerprint": row.get::<_, String>(3),
            "domain_id": domain,
            "not_before": row.get::<_, Option<i64>>(5),
            "not_after": row.get::<_, Option<i64>>(6),
            "created_by": creator,
        }));
    }
    Ok(json!({ "anchors": anchors }))
}
