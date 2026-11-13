use regex::Regex;
use setjoin_mime as mime;
use std::sync::LazyLock;

/// Go's four enabled deterministic ML signals, in their original additive order.
pub(crate) fn detectors(
    data: &[u8],
    envelope: &str,
    sender: &str,
    recipients: &[String],
    spf: bool,
    dkim: bool,
) -> (f64, Vec<String>) {
    let (mut score, mut symbols) = (0.0f64, Vec::new());
    let norm = |s: &str| mime::go_lossy(&mime::to_lower(mime::trim_space(s.as_bytes())));
    let (envelope, sender) = (norm(envelope), norm(sender));
    if !envelope.is_empty() && !sender.is_empty() && envelope != sender {
        let domain = |s: &str| {
            s.split_once('@')
                .map_or(s.to_owned(), |(_, d)| d.to_owned())
        };
        let cross = domain(&envelope) != domain(&sender);
        let mut s = if cross { 10.0f64 } else { 5.0 };
        if cross && spf {
            s += 2.5;
        }
        if dkim {
            s -= 3.0;
        }
        score += s.clamp(0.0, 15.0);
        symbols.push("ML_SENDER_MISMATCH".into());
    }
    let mut headers = Vec::new();
    for key in ["To", "Cc"] {
        if let Ok(addresses) = mime::parse_address_list_raw(&mime::extract_header(data, key)) {
            headers.extend(
                addresses
                    .into_iter()
                    .map(|a| norm(&mime::go_lossy(&a.address))),
            );
        }
    }
    if !recipients.is_empty() && !headers.is_empty() {
        let missing = recipients
            .iter()
            .filter(|a| !headers.contains(&norm(a)))
            .count();
        if missing > 0 {
            score += missing as f64 / recipients.len() as f64 * 10.0;
            symbols.push("ML_FORGED_RECIPIENTS".into());
        }
    }
    let mut counts = [0usize; 4];
    for r in mime::go_lossy(&mime::extract_body_text(data))
        .chars()
        .map(u32::from)
    {
        let script = match r {
            0x0400..=0x052f => Some(2),
            0x4e00..=0x9fff
            | 0x3400..=0x4dbf
            | 0x20000..=0x2a6df
            | 0x3040..=0x30ff
            | 0xac00..=0xd7af => Some(1),
            0x0600..=0x06ff | 0x0750..=0x077f | 0xfb50..=0xfdff | 0xfe70..=0xfeff => Some(3),
            0x41..=0x5a | 0x61..=0x7a | 0xc0..=0x24f | 0x1e00..=0x1eff => Some(0),
            _ => None,
        };
        if let Some(i) = script {
            counts[i] += 1;
        }
    }
    let total: usize = counts.iter().sum();
    let scripts = counts.iter().filter(|n| **n > 0).count();
    if total >= 5 && scripts >= 2 {
        let mut s = ((scripts - 1) as f64 * 4.0).min(8.0);
        if counts
            .iter()
            .any(|n| *n > 0 && (*n as f64 / total as f64) < 0.1)
        {
            s += 2.0;
        }
        score += s.min(10.0);
        symbols.push("ML_MIXED_CHARSET".into());
    }
    static HIDDEN: LazyLock<Vec<(Regex, usize)>> = LazyLock::new(|| {
        [
            (r"font-size\s*:\s*0\s*(?:px|pt|em|rem)?", 0),
            (r"font-size\s*:\s*[12]px", 1),
            (r"display\s*:\s*none", 2),
            (r"color\s*:\s*white", 3),
            (r"color\s*:\s*#fff(?:fff)?\b", 4),
            (r"opacity\s*:\s*0\b", 5),
            (r"visibility\s*:\s*hidden", 6),
            (r"position\s*:\s*absolute\s*;\s*left\s*:\s*-9999px", 7),
            (r"position\s*:\s*absolute\s*;\s*left\s*:\s*-10000px", 7),
            (r"text-indent\s*:\s*-9999px", 8),
            (r"width\s*:\s*0\b.*height\s*:\s*0\b", 9),
            (r"height\s*:\s*0\b.*width\s*:\s*0\b", 9),
        ]
        .into_iter()
        .map(|(p, i)| {
            (
                Regex::new(&format!(
                    "(?i:{})",
                    p.replace(r"\s", r"[ \t\n\r\x0c]")
                        .replace(r"\b", r"(?-u:\b)")
                ))
                .unwrap(),
                i,
            )
        })
        .collect()
    });
    let html = mime::go_lossy(&mime::extract_body_html(data));
    let mut found = [false; 10];
    for (pattern, i) in HIDDEN.iter() {
        if pattern.is_match(&html) {
            found[*i] = true;
        }
    }
    let hidden = found.iter().filter(|v| **v).count();
    if hidden > 0 {
        score += (hidden as f64 * 2.5).min(10.0);
        symbols.push("ML_FAKE_HTML".into());
    }
    (score, symbols)
}
