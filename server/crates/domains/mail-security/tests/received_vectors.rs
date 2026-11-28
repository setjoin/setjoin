//! `received::parse_trace` against Go's `received.ParseTrace`: every vector was recorded
//! from the frozen Go package (go 1.26.6) with identity {mailserver, mail.test,
//! internal.example}; `ERR` is a marshal error (no body).
use setjoin_mail_security::received::{parse_trace, Identity};

#[test]
fn parse_trace_matches_recorded_go() {
    let vectors: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("received_vectors.json")).expect("vectors");
    assert!(vectors.len() > 250);
    let identity = Identity::from_config("mail.test", "internal.example");
    let mut failures = vec![];
    for v in &vectors {
        let raw = hex(v["raw"].as_str().unwrap());
        let want = v["want"].as_str().unwrap();
        let got = parse_trace(&raw, &identity);
        let got = got.as_deref().unwrap_or("ERR");
        if got != want {
            failures.push(format!(
                "raw {:?}\n want {want}\n got  {got}",
                String::from_utf8_lossy(&raw)
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} differ:\n{}",
        failures.len(),
        vectors.len(),
        failures
            .iter()
            .take(8)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
