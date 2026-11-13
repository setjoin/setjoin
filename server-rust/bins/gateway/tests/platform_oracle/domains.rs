//! Group `domains` cases for the `terms-remaining` oracle: `/admin/domains*`. The run's
//! two fixture domains are renamed `host-a.test` and `host-b.test` so list ordering is
//! stable; seeded rows take ids from 9301 and the generated-id sequence is pinned at 9400.
use super::terms::Case;

const EFFECTS: &str = "SELECT j FROM (SELECT 1 k, id, to_jsonb(d)::text j FROM domains d UNION ALL SELECT 2, id, (to_jsonb(p)-'id')::text FROM dlp_policies p WHERE domain_id IS NOT NULL) x ORDER BY k, id";
const NEXT_ID: &str = "SELECT setval(pg_get_serial_sequence('domains','id'), 9400, false)";
const RENAME: &str = "UPDATE domains SET name='host-a.test' WHERE id={a_domain}; UPDATE domains SET name='host-b.test' WHERE id={b_domain}";
const COLS: &str = "INSERT INTO domains(id,name,is_primary,is_local,catch_all_mailbox_id,dkim_selector,dkim_key_expires_at,spf_record,dmarc_policy,dmarc_rua,dmarc_ruf,mta_sts_policy,max_message_bytes,quota_bytes,created_at,updated_at) VALUES ";
const FULL: &str = "(9301,'full.test',false,true,{a_mailbox},'sel1','2026-10-05 10:00:00+00','v=spf1 <a> & -all','quarantine','mailto:rua@full.test','mailto:ruf@full.test','testing',1048576,2097152,'2026-10-01 10:00:00+00','2026-10-01 10:00:00+00')";
const PLAIN: &str = "(9302,'plain.test',false,false,NULL,NULL,NULL,NULL,'none',NULL,NULL,'none',52428800,NULL,'2026-10-01 11:00:00+00','2026-10-01 11:00:00+00')";
const PRIMARY: &str = "(9303,'primary.test',true,true,NULL,'sel2',NULL,'v=spf1 -all','reject',NULL,NULL,'enforce',52428800,NULL,'2026-10-01 12:00:00+00','2026-10-01 12:00:00+00')";
const EMPTYSTR: &str = "(9304,'empties.test',false,true,NULL,'','2026-10-06 10:00:00+00','','none','','','none',52428800,NULL,'2026-10-01 13:00:00+00','2026-10-01 13:00:00+00')";

fn base(method: &'static str, pattern: &'static str, perm: &'static str, status: u16) -> Case {
    Case {
        method,
        pattern,
        fill: vec![],
        query: String::new(),
        perm,
        body: String::new(),
        headers: vec![],
        seed: vec![RENAME.into(), NEXT_ID.into()],
        cleanup: vec![
            "DELETE FROM dlp_policies WHERE name LIKE 'p9%'".into(),
            // Only the rows this oracle seeds: the shifted range (see `SHIFTED`), never a
            // neighbour's domain above 9300.
            "UPDATE domains SET catch_all_mailbox_id=NULL WHERE id BETWEEN 9000000000 AND 9000009999".into(),
            "DELETE FROM domains WHERE id BETWEEN 9000000000 AND 9000009999 AND id NOT IN ({a_domain},{b_domain})".into(),
            // Hand the sequence back to where the remaining rows put it, not to a fixed 100.
            "SELECT setval(pg_get_serial_sequence('domains','id'), COALESCE((SELECT max(id) FROM domains WHERE id<9000000000), 1))".into(),
        ],
        effects: EFFECTS,
        table: "domains",
        channels: vec![],
        status,
        replace: vec![],
        unshift: vec![],
    }
}

/// The recorded ids (9301.. seeded, 9400 generated) moved above the parallel lane's sequence
/// offsets, so ordering by id matches on a plain and on a seasoned database; the recorded goldens
/// keep the literals (`Case::unshift` maps them back).
const SHIFTED: [(&str, &str); 5] = [
    ("9301", "9000000301"),
    ("9302", "9000000302"),
    ("9303", "9000000303"),
    ("9304", "9000000304"),
    ("9400", "9000000400"),
];

pub fn specs(action: &str, label: &str) -> Option<Case> {
    let mut c = specs_recorded(action, label)?;
    let shift = |text: &str| SHIFTED.iter().fold(text.to_owned(), |t, (old, new)| t.replace(old, new));
    c.seed = c.seed.iter().map(|t| shift(t)).collect();
    c.cleanup = c.cleanup.iter().map(|t| shift(t)).collect();
    c.fill = c.fill.iter().map(|t| shift(t)).collect();
    c.body = shift(&c.body);
    c.query = shift(&c.query);
    c.unshift = SHIFTED.iter().map(|(old, new)| ((*new).to_owned(), (*old).to_owned())).collect();
    Some(c)
}

fn specs_recorded(action: &str, label: &str) -> Option<Case> {
    let mut c = match action {
        "domains-list" => base("GET", "/admin/domains", "domains.read", 200),
        "domains-get" => base("GET", "/admin/domains/{id}", "domains.read", 200),
        "domains-create" => base("POST", "/admin/domains", "domains.write", 201),
        "domains-update" => base("PUT", "/admin/domains/{id}", "domains.write", 204),
        "domains-delete" => base("DELETE", "/admin/domains/{id}", "domains.write", 204),
        _ => return None,
    };
    let rows = format!("{COLS}{FULL},{PLAIN},{PRIMARY},{EMPTYSTR}");
    match action {
        "domains-list" => {
            c.seed.push(rows);
            match label {
                "success" | "denied" | "scoped" | "scoped-own" => {}
                "ignored-query" => c.query = "?limit=1&x=%zz&q=%00".into(),
                _ => return None,
            }
        }
        "domains-get" => {
            c.seed.push(rows);
            c.fill = vec!["9301".into()];
            match label {
                "success" | "denied" => {}
                "scoped" => c.fill = vec!["9302".into()],
                "scoped-own" => c.fill = vec!["{a_domain}".into()],
                "own-null-columns" => c.fill = vec!["{a_domain}".into()],
                "plain-null-columns" => c.fill = vec!["9302".into()],
                "primary" => c.fill = vec!["9303".into()],
                "empty-strings" => c.fill = vec!["9304".into()],
                "missing" => c.fill = vec!["999999".into()],
                "zero" => c.fill = vec!["0".into()],
                "negative" => c.fill = vec!["-4".into()],
                "plus" => c.fill = vec!["%2B9301".into()],
                "padded" => c.fill = vec!["09301".into()],
                "word" => c.fill = vec!["abc".into()],
                "float" => c.fill = vec!["1.5".into()],
                "huge" => c.fill = vec!["99999999999999999999".into()],
                "ignored-query" => c.query = "?x=%zz".into(),
                _ => return None,
            }
        }
        "domains-create" => {
            let ok = r#"{"name":"new-domain.test","isLocal":true,"isPrimary":false,"dmarcPolicy":"reject","mtaStsPolicy":"enforce","maxMessageBytes":1000,"quotaBytes":5000}"#;
            c.body = ok.into();
            let named = |n: &str| format!("{{\"name\":{n}}}");
            match label {
                "success" | "denied" | "scoped" => {}
                "repeat" => {}
                "defaults" => c.body = named("\"defaults.test\""),
                "primary" => c.body = r#"{"name":"first-primary.test","isPrimary":true}"#.into(),
                "primary-conflict" => {
                    c.seed.push(format!("{COLS}{PRIMARY}"));
                    c.body = r#"{"name":"second-primary.test","isPrimary":true}"#.into();
                }
                "duplicate" => {
                    c.seed.push(format!("{COLS}{PLAIN}"));
                    c.body = named("\"plain.test\"");
                }
                "duplicate-case" => {
                    c.seed.push(format!("{COLS}{PLAIN}"));
                    c.body = named("\"  PLAIN.Test \"");
                }
                "canonical" => c.body = named("\"  Mixed-Case.Example.TEST  \""),
                "folded" => c.body = r#"{"NAME":"folded.test","ISLOCAL":false,"MaxMessageBytes":7,"QUOTABYTES":9}"#.into(),
                "duplicate-key" => c.body = r#"{"name":"first.test","name":"second.test"}"#.into(),
                "null-fields" => c.body = r#"{"name":"nulls.test","isLocal":null,"dmarcPolicy":null,"maxMessageBytes":null,"quotaBytes":null}"#.into(),
                "unknown-key" => c.body = r#"{"name":"unknown.test","extra":{"a":[1]}}"#.into(),
                "max-zero" => c.body = r#"{"name":"zero.test","maxMessageBytes":0}"#.into(),
                "max-negative" => c.body = r#"{"name":"neg.test","maxMessageBytes":-5}"#.into(),
                "empty-policies" => c.body = r#"{"name":"empties.example","dmarcPolicy":"","mtaStsPolicy":""}"#.into(),
                "bad-dmarc" => c.body = r#"{"name":"baddmarc.test","dmarcPolicy":"bogus"}"#.into(),
                "bad-mta" => c.body = r#"{"name":"badmta.test","mtaStsPolicy":"bogus"}"#.into(),
                "numeric-tld" => c.body = named("\"digits.b1\""),
                "bad-json" => c.body = "{\"name\":".into(),
                "empty-body" => c.body = String::new(),
                "null-body" => c.body = "null".into(),
                "array-body" => c.body = "[1]".into(),
                "string-body" => c.body = "\"x\"".into(),
                "missing-name" => c.body = r#"{"isLocal":true}"#.into(),
                "empty-name" => c.body = named("\"\""),
                "blank-name" => c.body = named("\"   \""),
                "name-number" => c.body = named("5"),
                "no-dot" => c.body = named("\"localhost\""),
                "bad-char" => c.body = named("\"un_der.test\""),
                "hyphen-edge" => c.body = named("\"-lead.test\""),
                "hyphen-trail" => c.body = named("\"trail-.test\""),
                "empty-label" => c.body = named("\"a..test\""),
                "trailing-dot" => c.body = named("\"a.test.\""),
                "long-label" => c.body = named(&format!("\"{}.test\"", "a".repeat(64))),
                "long-name" => c.body = named(&format!("\"{}.test\"", vec!["a".repeat(60); 5].join("."))),
                "control-char" => c.body = named("\"a\\u0001b.test\""),
                "unicode" => c.body = named("\"b\\u00fccher.test\""),
                "turkish-dotted-i" => c.body = named("\"\\u0130stanbul.test\""),
                "kelvin" => c.body = named("\"\\u212Aelvin.test\""),
                "bool-string" => c.body = r#"{"name":"x.test","isLocal":"yes"}"#.into(),
                "max-float" => c.body = r#"{"name":"x.test","maxMessageBytes":1.5}"#.into(),
                "max-whole-float" => c.body = r#"{"name":"x.test","maxMessageBytes":1.0}"#.into(),
                "max-string" => c.body = r#"{"name":"x.test","maxMessageBytes":"5"}"#.into(),
                "max-huge" => c.body = r#"{"name":"x.test","maxMessageBytes":99999999999999999999}"#.into(),
                "quota-negative" => c.body = r#"{"name":"quota.test","quotaBytes":-1}"#.into(),
                "trailing-data" => c.body = format!("{ok} {{\"x\":1}}"),
                "trailing-junk" => c.body = format!("{ok} garbage"),
                "oversize" => c.body = format!("{{\"name\":\"n.test\",\"x\":\"{}\"}}", "a".repeat((1 << 20) + 16)),
                _ => return None,
            }
        }
        "domains-update" => {
            c.seed.push(rows);
            c.fill = vec!["9301".into()];
            c.body = r#"{"name":"renamed.test","isLocal":false,"dmarcPolicy":"reject","mtaStsPolicy":"enforce","maxMessageBytes":2000,"quotaBytes":3000}"#.into();
            match label {
                "success" | "denied" | "repeat" => {}
                "scoped" => c.fill = vec!["9302".into()],
                "scoped-own" => c.fill = vec!["{a_domain}".into()],
                "name-only" => c.body = r#"{"name":"  Only-Name.TEST "}"#.into(),
                "is-local" => c.body = r#"{"isLocal":false}"#.into(),
                "primary" => c.body = r#"{"isPrimary":true}"#.into(),
                "primary-conflict" => {
                    c.fill = vec!["9302".into()];
                    c.body = r#"{"isPrimary":true}"#.into();
                }
                "catch-all" => c.body = r#"{"catchAllMailboxId":{a_mailbox}}"#.into(),
                "catch-all-missing" => c.body = r#"{"catchAllMailboxId":999999}"#.into(),
                "catch-all-zero" => c.body = r#"{"catchAllMailboxId":0}"#.into(),
                "policies" => c.body = r#"{"dmarcPolicy":"none","mtaStsPolicy":"none"}"#.into(),
                "bad-dmarc" => c.body = r#"{"dmarcPolicy":"bogus"}"#.into(),
                "bad-mta" => c.body = r#"{"mtaStsPolicy":"bogus"}"#.into(),
                "max-zero" => c.body = r#"{"maxMessageBytes":0}"#.into(),
                "max-negative" => c.body = r#"{"maxMessageBytes":-1}"#.into(),
                "quota-zero" => c.body = r#"{"quotaBytes":0}"#.into(),
                "folded" => c.body = r#"{"NAME":"folded.test","ISLOCAL":false,"catchAllMailboxId":{a_mailbox},"MAXMESSAGEBYTES":9}"#.into(),
                "null-fields" => c.body = r#"{"name":null,"isLocal":null,"quotaBytes":null}"#.into(),
                "null-then-value" => c.body = r#"{"name":null,"maxMessageBytes":11}"#.into(),
                "empty-strings" => c.body = r#"{"dmarcPolicy":"","mtaStsPolicy":""}"#.into(),
                "empty-strings-and-int" => c.body = r#"{"dmarcPolicy":"","quotaBytes":42}"#.into(),
                "no-fields" => c.body = "{}".into(),
                "unknown-only" => c.body = r#"{"extra":1}"#.into(),
                "empty-name" => c.body = r#"{"name":""}"#.into(),
                "invalid-name" => c.body = r#"{"name":"nodot"}"#.into(),
                "invalid-name-first" => c.body = r#"{"name":"bad_.test","maxMessageBytes":5}"#.into(),
                "duplicate-name" => c.body = r#"{"name":"plain.test"}"#.into(),
                "numeric-tld" => c.body = r#"{"name":"digits.b1"}"#.into(),
                "kelvin" => c.body = r#"{"name":"\u212Aelvin.test"}"#.into(),
                "bad-json" => c.body = "{\"name\":".into(),
                "empty-body" => c.body = String::new(),
                "null-body" => c.body = "null".into(),
                "array-body" => c.body = "[1]".into(),
                "bool-string" => c.body = r#"{"isLocal":"no"}"#.into(),
                "max-float" => c.body = r#"{"maxMessageBytes":1.5}"#.into(),
                "missing" => c.fill = vec!["999999".into()],
                "missing-bad-body" => {
                    c.fill = vec!["999999".into()];
                    c.body = "{".into();
                }
                "missing-no-fields" => {
                    c.fill = vec!["999999".into()];
                    c.body = "{}".into();
                }
                "bad-id" => c.fill = vec!["abc".into()],
                "bad-id-bad-json" => {
                    c.fill = vec!["abc".into()];
                    c.body = "{".into();
                }
                "zero-id" => c.fill = vec!["0".into()],
                "negative-id" => c.fill = vec!["-3".into()],
                "plus-id" => c.fill = vec!["%2B9301".into()],
                "padded-id" => c.fill = vec!["09301".into()],
                "huge-id" => c.fill = vec!["99999999999999999999".into()],
                "oversize" => c.body = format!("{{\"name\":\"n.test\",\"x\":\"{}\"}}", "a".repeat((1 << 20) + 16)),
                "others-untouched" => {}
                _ => return None,
            }
        }
        "domains-delete" => {
            c.seed.push(rows);
            c.fill = vec!["9301".into()];
            match label {
                "success" | "denied" | "repeat" | "others-untouched" => {}
                "scoped" => c.fill = vec!["9302".into()],
                "scoped-own" => c.fill = vec!["{a_domain}".into()],
                "missing" => c.fill = vec!["999999".into()],
                "with-users" => c.fill = vec!["{a_domain}".into()],
                "with-cascade-rows" => {
                    c.seed.push(
                        "INSERT INTO dlp_policies(domain_id,name) VALUES (9302,'p9302')".into(),
                    );
                    c.fill = vec!["9302".into()];
                }
                "bad-id" => c.fill = vec!["abc".into()],
                "zero-id" => c.fill = vec!["0".into()],
                "negative-id" => c.fill = vec!["-3".into()],
                "plus-id" => c.fill = vec!["%2B9301".into()],
                "padded-id" => c.fill = vec!["09301".into()],
                "huge-id" => c.fill = vec!["99999999999999999999".into()],
                _ => return None,
            }
        }
        _ => return None,
    }
    match label {
        "denied" => c.status = 403,
        "scoped" => c.status = 0,
        "repeat" => c.status = 0,
        _ => c.status = 0,
    }
    Some(c)
}
