//! The recorded DKIM vectors must not rot (#472): Go signs with a near-term `x=`, so a vector
//! that was valid on the day it was recorded flipped to an expired verdict a day later.
//! `oracle/refresh-dkim-validity.py` moves every real instant to 2100; the deliberate
//! `x=2`-style cases (not a plausible instant) stay as recorded.
#[test]
fn recorded_dkim_signatures_do_not_expire_within_a_decade() {
    let horizon = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 10 * 365 * 86_400;
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("oracle");
    let mut checked = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let mut rest = text.as_str();
        while let Some(at) = rest.find("DKIM-Signature:") {
            rest = &rest[at + 15..];
            // Only this header's own tags: stop at the first line break of the header.
            let header = rest.split("\\r\\n").next().unwrap_or("");
            if let Some(x) = header.split("; x=").nth(1) {
                let digits: String = x.chars().take_while(char::is_ascii_digit).collect();
                if let Ok(x) = digits.parse::<u64>() {
                    // A real instant (after 2023) is a rotting vector; tiny values are deliberate.
                    assert!(
                        x < 1_700_000_000 || x > horizon,
                        "{}: DKIM x={x} expires within a decade; run oracle/refresh-dkim-validity.py",
                        path.display()
                    );
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 20, "expected the recorded DKIM vectors, saw {checked}");
}
