//! Group `federation` cases for the `terms-remaining` oracle: `/admin/federation/peers*`.
//! The anchors are two fixed self-signed certificates (and a private key PEM for the wrong
//! block type). Health ages are time-dependent and masked by the run.
use super::terms::Case;

const CERT1: &str = "-----BEGIN CERTIFICATE-----\nMIIBizCCATGgAwIBAgIUffrna6Jptw7wG6lfDlaYmOelzWQwCgYIKoZIzj0EAwIw\nGzEZMBcGA1UEAwwQcGVlci1vbmUuZXhhbXBsZTAeFw0yNjExMDMwNjQxNDZaFw00\nNjEwMjkwNjQxNDZaMBsxGTAXBgNVBAMMEHBlZXItb25lLmV4YW1wbGUwWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAARisb5vBEVbplZ64RqspOxGF5H0wva8MexzDRRs\nH20AAJl+mVOoTAYCFvjULtPDATtgYY2zqsphocmuuk0eOsuso1MwUTAdBgNVHQ4E\nFgQUGNS+fRqac35aKfuByOZVM1z5XKswHwYDVR0jBBgwFoAUGNS+fRqac35aKfuB\nyOZVM1z5XKswDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEAmfx6\n0XcYdvUg2D0ITVeZxOwb/Rt/lRvZIseQErL+90ACIDNjLZvx2/OiWfkAYTkc1Hmu\niXjroL4h6glyQ1Q33cJV\n-----END CERTIFICATE-----\n";
const CERT2: &str = "-----BEGIN CERTIFICATE-----\nMIIBizCCATGgAwIBAgIUEUi33XEPgUbfAcgtkSM0FY5gnJ8wCgYIKoZIzj0EAwIw\nGzEZMBcGA1UEAwwQcGVlci10d28uZXhhbXBsZTAeFw0yNjExMDMwNjQxNDZaFw00\nNjEwMjkwNjQxNDZaMBsxGTAXBgNVBAMMEHBlZXItdHdvLmV4YW1wbGUwWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAASmJ2JcGhIDsHBS74qqcRfVpz89xcgJQLCJRUgX\nrwKKXJ7OdxaGyTeuRMWnN8uVaBx41Hui2xNzNAOFt6MYrfWmo1MwUTAdBgNVHQ4E\nFgQUrwDtgdHAUerSVGQSl4hgMXGtfcgwHwYDVR0jBBgwFoAUrwDtgdHAUerSVGQS\nl4hgMXGtfcgwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEAlNC/\nirHjgIpy2aRSyVjj2yYwfsHrHjGo18bsWY2jZJQCIGqA440KViZ3Y7s58F0Csz2X\n+sDUqRm4JknhXDveXUm2\n-----END CERTIFICATE-----\n";
const KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgz+v1Z8NBddh+7UI0\nlmtX0ceSvHWr+jZO8t1tsP5GpqihRANCAASmJ2JcGhIDsHBS74qqcRfVpz89xcgJ\nQLCJRUgXrwKKXJ7OdxaGyTeuRMWnN8uVaBx41Hui2xNzNAOFt6MYrfWm\n-----END PRIVATE KEY-----\n";
const EFFECTS: &str = "SELECT j FROM (SELECT 1 k, peer_domain n, to_jsonb(a)::text j FROM federation_allowlist a UNION ALL SELECT 2, peer_domain, to_jsonb(p)::text FROM federation_peers p UNION ALL SELECT 3, peer_domain || peer_seq, to_jsonb(o)::text FROM federation_outbox o) x ORDER BY k, n";
const CLEAR: &str =
    "DELETE FROM federation_outbox; DELETE FROM federation_peers; DELETE FROM federation_allowlist";

fn json_text(text: &str) -> String {
    serde_json::to_string(text).expect("string")
}
fn peer(domain: &str, anchor: &str, scope: &str, enabled: bool) -> String {
    format!(
        "{{\"domain\":{},\"anchorPem\":{},\"scope\":{},\"enabled\":{enabled}}}",
        json_text(domain),
        json_text(anchor),
        json_text(scope)
    )
}
fn allow(domain: &str, anchor: &str, scope: &str, enabled: bool) -> String {
    format!(
        "INSERT INTO federation_allowlist(peer_domain,peer_anchor,scope,enabled,created_at,updated_at) VALUES ('{domain}','{}','{scope}',{enabled},'2026-10-01 10:00:00+00','2026-10-01 10:00:00+00')",
        anchor.replace('\'', "''")
    )
}
const TRANSPORT: &str = "INSERT INTO federation_peers(peer_domain,last_seq,last_acked_seq,created_at,updated_at) VALUES ('alpha.example',5,2,'2026-10-01 10:00:00+00','2026-10-01 10:00:00+00'); INSERT INTO federation_outbox(peer_domain,peer_seq,stanza_id,content_type,payload,created_at,acked_at) VALUES ('alpha.example',1,'s1','m.test','{}','2026-10-01 10:00:00+00','2026-10-01 10:05:00+00'),('alpha.example',3,'s3','m.test','{}','2026-10-01 10:00:00+00',NULL)";

fn base(method: &'static str, pattern: &'static str, status: u16) -> Case {
    Case {
        method,
        pattern,
        fill: vec![],
        query: String::new(),
        perm: "federation.manage",
        body: String::new(),
        headers: vec![],
        seed: vec![
            CLEAR.into(),
            allow("alpha.example", CERT1, "dm", true),
            allow("beta.example", CERT2, "room", false),
        ],
        cleanup: vec![CLEAR.into()],
        effects: EFFECTS,
        table: "federation_allowlist",
        channels: vec!["federation_allowlist_changed"],
        status,
        replace: vec![],
        unshift: vec![],
    }
}

pub fn specs(action: &str, label: &str) -> Option<Case> {
    let mut c = match action {
        "federation-list" => base("GET", "/admin/federation/peers", 200),
        "federation-upsert" => base("POST", "/admin/federation/peers", 204),
        "federation-delete" => base("DELETE", "/admin/federation/peers/{domain}", 204),
        _ => return None,
    };
    match action {
        "federation-list" => match label {
            "success" | "denied" | "scoped" => c.seed.push(TRANSPORT.into()),
            "empty" => c.seed.truncate(1),
            "no-transport" => {}
            "ignored-query" => {
                c.seed.push(TRANSPORT.into());
                c.query = "?x=%zz&limit=1".into();
            }
            _ => return None,
        },
        "federation-upsert" => {
            c.body = peer("gamma.example", CERT1, "dm", true);
            match label {
                "success" | "denied" | "scoped" | "repeat" => {}
                "update-existing" => c.body = peer("alpha.example", CERT2, "room", false),
                "carry-anchor" => c.body = peer("alpha.example", "", "room", false),
                "carry-anchor-blank" => c.body = peer("beta.example", "  \n\t ", "dm", true),
                "disable" => c.body = peer("alpha.example", "", "dm", false),
                "new-without-anchor" => c.body = peer("gamma.example", "", "dm", true),
                "uppercase-domain" => c.body = peer("  GAMMA.Example ", CERT1, "dm", true),
                "scope-room" => c.body = peer("gamma.example", CERT1, "room", false),
                "self-domain" => c.body = peer("self.test", CERT1, "dm", true),
                "self-domain-upper" => c.body = peer(" SELF.test ", CERT1, "dm", true),
                "bad-scope" => c.body = peer("gamma.example", CERT1, "all", true),
                "scope-upper" => c.body = peer("gamma.example", CERT1, "DM", true),
                "scope-empty" => c.body = peer("gamma.example", CERT1, "", true),
                "empty-domain" => c.body = peer("", CERT1, "dm", true),
                "blank-domain" => c.body = peer("   ", CERT1, "dm", true),
                "garbage-anchor" => c.body = peer("gamma.example", "not a certificate", "dm", true),
                "private-key-anchor" => c.body = peer("gamma.example", KEY, "dm", true),
                "truncated-anchor" => c.body = peer("gamma.example", &CERT1[..CERT1.len() / 2], "dm", true),
                "bad-base64-anchor" => c.body = peer("gamma.example", "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n", "dm", true),
                "empty-block-anchor" => c.body = peer("gamma.example", "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n", "dm", true),
                "leading-junk-anchor" => c.body = peer("gamma.example", &format!("notes before\n{CERT1}"), "dm", true),
                "trailing-junk-anchor" => c.body = peer("gamma.example", &format!("{CERT1}trailing text"), "dm", true),
                "crlf-anchor" => c.body = peer("gamma.example", &CERT1.replace('\n', "\r\n"), "dm", true),
                "two-blocks-anchor" => c.body = peer("gamma.example", &format!("{CERT2}{CERT1}"), "dm", true),
                "key-then-cert-anchor" => c.body = peer("gamma.example", &format!("{KEY}{CERT1}"), "dm", true),
                "indented-anchor" => c.body = peer("gamma.example", &format!(" {CERT1}"), "dm", true),
                "folded" => c.body = format!("{{\"DOMAIN\":\"gamma.example\",\"AnchorPEM\":{},\"SCOPE\":\"dm\",\"Enabled\":true}}", json_text(CERT1)),
                "unknown-key" => c.body = format!("{{\"domain\":\"gamma.example\",\"anchorPem\":{},\"scope\":\"dm\",\"x\":[1]}}", json_text(CERT1)),
                "duplicate-key" => c.body = format!("{{\"domain\":\"first.example\",\"domain\":\"gamma.example\",\"anchorPem\":{},\"scope\":\"dm\"}}", json_text(CERT1)),
                "enabled-default" => c.body = format!("{{\"domain\":\"gamma.example\",\"anchorPem\":{},\"scope\":\"dm\"}}", json_text(CERT1)),
                "enabled-string" => c.body = format!("{{\"domain\":\"gamma.example\",\"anchorPem\":{},\"scope\":\"dm\",\"enabled\":\"yes\"}}", json_text(CERT1)),
                "domain-number" => c.body = format!("{{\"domain\":5,\"anchorPem\":{},\"scope\":\"dm\"}}", json_text(CERT1)),
                "trailing-data" => c.body = format!("{} {{\"x\":1}}", peer("gamma.example", CERT1, "dm", true)),
                "bad-json" => c.body = "{\"domain\":".into(),
                "empty-body" => c.body = String::new(),
                "null-body" => c.body = "null".into(),
                "array-body" => c.body = "[1]".into(),
                "oversize" => c.body = format!("{{\"domain\":\"x.example\",\"pad\":\"{}\"}}", "a".repeat((1 << 20) + 16)),
                _ => return None,
            }
        }
        "federation-delete" => {
            c.fill = vec!["alpha.example".into()];
            c.seed.push(TRANSPORT.into());
            match label {
                "success" | "denied" | "scoped" | "repeat" => c.fill = vec!["beta.example".into()],
                "enabled-peer" => {}
                "with-transport" => c.seed.push("UPDATE federation_allowlist SET enabled=false WHERE peer_domain='alpha.example'".into()),
                "missing" => c.fill = vec!["nobody.example".into()],
                "uppercase" => c.fill = vec!["BETA.Example".into()],
                "padded" => c.fill = vec!["%20beta.example%20".into()],
                "blank" => c.fill = vec!["%20".into()],
                _ => return None,
            }
        }
        _ => return None,
    }
    c.status = if label == "denied" { 403 } else { 0 };
    Some(c)
}
