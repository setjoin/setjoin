//! Differential vectors: the same corpus run through frozen Go's `mimeutil`
//! (recorded once into vectors/vectors.json by vectors/dump_go.txt) and through
//! the Rust port. Every field of every case must be identical.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;
use setjoin_mailboxes::mimeutil::{self, ImportFields};

fn b64(v: &Value) -> Vec<u8> {
    STANDARD
        .decode(v.as_str().expect("base64 string"))
        .expect("base64")
}
fn show(b: &[u8]) -> String {
    format!("{:?}", String::from_utf8_lossy(b))
}

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors/vectors.json")).expect("vectors")
}

#[test]
fn message_fields_match_go() {
    let v = vectors();
    let mut failures = Vec::new();
    for case in v["messages"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let raw = b64(&case["raw"]);
        let f = ImportFields::parse(&raw);
        let checks: [(&str, Vec<u8>, Vec<u8>); 11] = [
            ("message_id", f.message_id.clone(), b64(&case["message_id"])),
            ("subject", f.subject.clone(), b64(&case["subject"])),
            ("from_addr", f.from_addr.clone(), b64(&case["from_addr"])),
            ("from_name", f.from_name.clone(), b64(&case["from_name"])),
            ("to", f.to_json.clone().into_bytes(), b64(&case["to"])),
            ("cc", f.cc_json.clone().into_bytes(), b64(&case["cc"])),
            ("bcc", f.bcc_json.clone().into_bytes(), b64(&case["bcc"])),
            (
                "in_reply_to",
                f.in_reply_to.clone(),
                b64(&case["in_reply_to"]),
            ),
            ("references", f.references.clone(), b64(&case["references"])),
            ("body_text", f.body_text.clone(), b64(&case["body_text"])),
            ("body_html", f.body_html.clone(), b64(&case["body_html"])),
        ];
        for (field, got, want) in checks {
            // Address lists are JSON text: compare the parsed value, as the
            // database does (jsonb), but only when both parse.
            let same = if field == "to" || field == "cc" || field == "bcc" {
                let a: Result<Value, _> = serde_json::from_slice(&got);
                let b: Result<Value, _> = serde_json::from_slice(&want);
                matches!((a, b), (Ok(a), Ok(b)) if a == b)
            } else {
                got == want
            };
            if !same {
                failures.push(format!(
                    "{name}.{field}: rust {} go {}",
                    show(&got),
                    show(&want)
                ));
            }
        }
        let want_date = case.get("date").map(|d| {
            (
                d[0].as_i64().unwrap(),
                (d[1].as_i64().unwrap() / 1000) as u32,
            )
        });
        if f.date != want_date {
            failures.push(format!("{name}.date: rust {:?} go {:?}", f.date, want_date));
        }
    }
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn addresses_match_go() {
    let v = vectors();
    let mut failures = Vec::new();
    for case in v["addresses"].as_array().unwrap() {
        let input = b64(&case["input"]);
        let pair = |v: &Value| (b64(&v["Name"]), b64(&v["Address"]));
        let single = mimeutil::parse_address(&input)
            .ok()
            .map(|a| (a.name, a.address));
        let want_single = case.get("single").map(pair);
        if single != want_single {
            failures.push(format!(
                "single {}: rust {single:?} go {want_single:?}",
                show(&input)
            ));
        }
        let list = mimeutil::parse_address_list_raw(&input).ok().map(|l| {
            l.into_iter()
                .map(|a| (a.name, a.address))
                .collect::<Vec<_>>()
        });
        let want_list = case
            .get("list")
            .map(|l| l.as_array().unwrap().iter().map(pair).collect::<Vec<_>>());
        if list != want_list {
            failures.push(format!(
                "list {}: rust {list:?} go {want_list:?}",
                show(&input)
            ));
        }
        let (name, addr) = mimeutil::parse_from(&input);
        let want = (b64(&case["from"]["Name"]), b64(&case["from"]["Address"]));
        if (name, addr) != want {
            failures.push(format!("from {}: differs", show(&input)));
        }
        let got = mimeutil::parse_address_list(&input);
        let want = b64(&case["json"]);
        let a: Value = serde_json::from_str(&got).unwrap();
        let b: Value = serde_json::from_slice(&want).unwrap();
        if a != b {
            failures.push(format!(
                "json {}: rust {got} go {}",
                show(&input),
                show(&want)
            ));
        }
        if mimeutil::extract_addr(&input) != b64(&case["extract_addr"]) {
            failures.push(format!("extract_addr {}: differs", show(&input)));
        }
    }
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn media_types_match_go() {
    let v = vectors();
    let mut failures = Vec::new();
    for case in v["media_types"].as_array().unwrap() {
        let input = b64(&case["input"]);
        let got = mimeutil::parse_media_type(&input);
        let ok = case["ok"].as_bool().unwrap();
        if got.is_ok() != ok {
            failures.push(format!("ok {}: rust {} go {ok}", show(&input), got.is_ok()));
            continue;
        }
        if let Ok((media, params)) = got {
            if media != b64(&case["media"]) {
                failures.push(format!("media {}: differs", show(&input)));
            }
            let want: Vec<(Vec<u8>, Vec<u8>)> = case["params"]
                .as_array()
                .map(|ps| ps.iter().map(|p| (b64(&p[0]), b64(&p[1]))).collect())
                .unwrap_or_default();
            let have: Vec<_> = params.into_iter().collect();
            if have != want {
                failures.push(format!(
                    "params {}: rust {have:?} go {want:?}",
                    show(&input)
                ));
            }
        }
        let probe = mimeutil::decode_charset(b"h\xe9llo \xc3\xa9", &input);
        if probe != b64(&case["decode_charset_probe"]) {
            failures.push(format!(
                "charset probe {}: rust {} go {}",
                show(&input),
                show(&probe),
                show(&b64(&case["decode_charset_probe"]))
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
