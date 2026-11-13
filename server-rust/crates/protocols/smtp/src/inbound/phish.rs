use super::Pipeline;
use crate::submission::Flags;
use setjoin_mime as mime;
use setjoin_pg::{workers::WorkerConnection, Type};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    None,
    Warn,
    Reject,
}
fn lower(s: &str) -> String {
    mime::go_lossy(&mime::to_lower(s.as_bytes()))
}
fn trim(s: &str) -> String {
    mime::go_lossy(mime::trim_space(s.as_bytes()))
}
impl Pipeline {
    /// The detector inputs intentionally carry only the recipient email, as Go's
    /// deliver() does. Its contact-graph detector skips unresolved mailbox ID 0.
    pub async fn phish(
        &self,
        db: &WorkerConnection,
        flags: Option<&dyn Flags>,
        name: &str,
        from: &str,
    ) -> (Verdict, Vec<String>) {
        if !self.config.anti_phish || crate::mutants::on("inbound-no-anti-phish") {
            return (Verdict::None, Vec::new());
        }
        let on = |key: &str| flags.is_some_and(|f| f.enabled(key));
        let mut verdict = Verdict::None;
        let mut evidence = Vec::new();
        let domain = from.rsplit_once('@').map_or("", |(_, d)| d);
        let name = trim(name);
        let internal = self
            .config
            .internal_domains
            .iter()
            .any(|d| lower(&trim(d)) == lower(&trim(domain)).trim_end_matches('>'));
        if self.detectors.get().is_some_and(|d| d[0])
            && on("feature.antiphish_display_name")
            && !name.is_empty()
            && !internal
        {
            let mut names = self.names.lock().await;
            let mut available = true;
            if names
                .as_ref()
                .is_none_or(|(until, _)| *until < std::time::Instant::now())
            {
                match db.query("SELECT lower(display_name) FROM users WHERE enabled=TRUE AND display_name IS NOT NULL AND display_name<>''",&[]).await {
                    Ok(rows)=> *names=Some((std::time::Instant::now()+self.config.user_cache_ttl,rows.iter().map(|r|r.get::<_,String>(0)).collect())),
                    Err(_)=>available=false,
                }
            }
            if available {
                if names
                    .as_ref()
                    .is_some_and(|(_, names)| names.contains(&lower(&name)))
                {
                    evidence.push(format!("display_name_exact_match:{name}"));
                    if on("feature.antiphish_strict_mode") {
                        evidence.push("strict_mode:reject".into());
                    }
                    return (Verdict::Reject, evidence);
                }
                let threshold = if self.config.name_threshold <= 0.0 {
                    0.85
                } else {
                    self.config.name_threshold
                } as f32;
                if let Ok(rows)=db.query("SELECT display_name,similarity(display_name,$1) AS score FROM users WHERE enabled=TRUE AND display_name IS NOT NULL AND display_name<>'' AND similarity(display_name,$1)>=$2 ORDER BY score DESC LIMIT 1",&[(&lower(&name),Type::TEXT),(&threshold,Type::FLOAT4)]).await {
                    if let Some(row)=rows.first() {
                        let matched:String=row.get(0);let score:f32=row.get(1);
                        evidence.push(format!("display_name_fuzzy_match:{}:{:.2}",lower(&matched),f64::from(score)));
                        verdict=Verdict::Warn;
                    }
                }
            }
        }
        if self.detectors.get().is_some_and(|d| d[1])
            && on("feature.antiphish_lookalike")
            && !domain.is_empty()
        {
            let normalized: String = lower(domain).chars().map(confusable).collect();
            let protected: Vec<String> = self
                .config
                .protected_domains
                .iter()
                .map(|d| lower(&trim(d)))
                .filter(|d| !d.is_empty())
                .collect();
            if protected.contains(&normalized) && normalized != lower(domain) {
                evidence.push(format!("homoglyph_domain:{normalized}:{domain}"));
                if on("feature.antiphish_strict_mode") {
                    evidence.push("strict_mode:reject".into());
                }
                return (Verdict::Reject, evidence);
            }
            if !protected.contains(&normalized) {
                for protected in protected {
                    let distance = distance(&normalized, &protected);
                    if distance <= 2 {
                        evidence.push(format!(
                            "lookalike_domain:{normalized}:{protected}:{distance}"
                        ));
                        verdict = Verdict::Warn;
                        break;
                    }
                }
            }
        }
        if verdict == Verdict::Warn && on("feature.antiphish_strict_mode") {
            evidence.push("strict_mode:upgraded_warn_to_reject".into());
            return (Verdict::Reject, evidence);
        }
        (verdict, evidence)
    }
}
fn distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.len().abs_diff(b.len()) > 2 {
        return 3;
    }
    let mut previous: Vec<usize> = (0..=a.len()).collect();
    for (j, b) in b.iter().enumerate() {
        let mut current = vec![j + 1; a.len() + 1];
        for (i, a) in a.iter().enumerate() {
            current[i + 1] = (previous[i + 1] + 1)
                .min(current[i] + 1)
                .min(previous[i] + usize::from(a != b));
        }
        if *current.iter().min().unwrap() > 2 {
            return 3;
        }
        previous = current;
    }
    previous[a.len()]
}
const BANNER:&[u8]=b"[WARNING] This message may be an impersonation attempt. The sender's name matches an internal contact but the email address is unfamiliar. Do not click links or open attachments unless you verify the sender.\r\n\r\n";
pub(crate) fn inject(data: &[u8], evidence: &[String]) -> Vec<u8> {
    let mut value = "warn".to_string();
    if !evidence.is_empty() {
        value.push_str("; ");
        value.push_str(&evidence.join("; "));
    }
    let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") else {
        // Parity: Go does not recognize DATA's LF header separator here. Its
        // fallback creates a new header block and never injects a body banner.
        let mut out = format!("X-AntiPhish: {value}\r\n\r\n").into_bytes();
        out.extend_from_slice(data);
        return out;
    };
    let body = &data[end + 4..];
    let mut warned = Vec::new();
    if body.windows(24).any(|w| w == b"Content-Type: multipart/") {
        let ct = mime::extract_header(body, "Content-Type");
        if mime::parse_media_type(&ct).is_ok_and(|(_, p)| p.contains_key(b"boundary".as_slice())) {
            if let Ok(bytes) = mime::rewrite_parts(&ct, body, &mut |headers, part| {
                let h = mime::to_lower(headers);
                if h.windows(24).any(|w| w == b"content-type: text/plain")
                    || h.windows(23).any(|w| w == b"content-type: text/html")
                {
                    let mut out = BANNER.to_vec();
                    out.extend_from_slice(part);
                    Some(out)
                } else {
                    None
                }
            }) {
                warned = bytes;
            }
        }
    }
    if warned.is_empty() {
        warned.extend_from_slice(BANNER);
        warned.extend_from_slice(body);
    }
    let mut out = data[..end].to_vec();
    out.extend_from_slice(format!("\r\nX-AntiPhish: {value}\r\n\r\n\r\n").as_bytes());
    out.extend_from_slice(&warned);
    out
}
fn confusable(c: char) -> String {
    match u32::from(c) {
        0x0430 => "a".into(),
        0x0435 => "e".into(),
        0x043E => "o".into(),
        0x0440 => "p".into(),
        0x0441 => "c".into(),
        0x0443 => "y".into(),
        0x0445 => "x".into(),
        0x0410 => "A".into(),
        0x0415 => "E".into(),
        0x041E => "O".into(),
        0x0420 => "P".into(),
        0x0421 => "C".into(),
        0x0423 => "Y".into(),
        0x0425 => "X".into(),
        0x041C => "M".into(),
        0x041D => "H".into(),
        0x041A => "K".into(),
        0x0412 => "B".into(),
        0x0422 => "T".into(),
        0x0406 => "I".into(),
        0x0456 => "i".into(),
        0x04BB => "b".into(),
        0x03BF => "o".into(),
        0x03BD => "v".into(),
        0x039F => "O".into(),
        0x0391 => "A".into(),
        0x0395 => "E".into(),
        0x0397 => "H".into(),
        0x0399 => "I".into(),
        0x039A => "K".into(),
        0x039C => "M".into(),
        0x039D => "N".into(),
        0x03A1 => "P".into(),
        0x03A4 => "T".into(),
        0x03A5 => "Y".into(),
        0x03A7 => "X".into(),
        0x0392 => "B".into(),
        0x0396 => "Z".into(),
        0x03B1 => "a".into(),
        0x03B5 => "e".into(),
        0x03B7 => "n".into(),
        0x03B9 => "i".into(),
        0x03BA => "k".into(),
        0x03C1 => "p".into(),
        0x03C4 => "t".into(),
        0x03C5 => "u".into(),
        0x03C7 => "x".into(),
        0x00E0 => "a".into(),
        0x00E1 => "a".into(),
        0x00E2 => "a".into(),
        0x00E3 => "a".into(),
        0x00E4 => "a".into(),
        0x00E5 => "a".into(),
        0x00E8 => "e".into(),
        0x00E9 => "e".into(),
        0x00EA => "e".into(),
        0x00EB => "e".into(),
        0x00EC => "i".into(),
        0x00ED => "i".into(),
        0x00EE => "i".into(),
        0x00EF => "i".into(),
        0x00F2 => "o".into(),
        0x00F3 => "o".into(),
        0x00F4 => "o".into(),
        0x00F5 => "o".into(),
        0x00F6 => "o".into(),
        0x00F9 => "u".into(),
        0x00FA => "u".into(),
        0x00FB => "u".into(),
        0x00FC => "u".into(),
        0x00F1 => "n".into(),
        0x00E7 => "c".into(),
        0x00C0 => "A".into(),
        0x00C1 => "A".into(),
        0x00C2 => "A".into(),
        0x00C3 => "A".into(),
        0x00C4 => "A".into(),
        0x00C5 => "A".into(),
        0x00C8 => "E".into(),
        0x00C9 => "E".into(),
        0x00CA => "E".into(),
        0x00CB => "E".into(),
        0x00CC => "I".into(),
        0x00CD => "I".into(),
        0x00CE => "I".into(),
        0x00CF => "I".into(),
        0x00D2 => "O".into(),
        0x00D3 => "O".into(),
        0x00D4 => "O".into(),
        0x00D5 => "O".into(),
        0x00D6 => "O".into(),
        0x00D9 => "U".into(),
        0x00DA => "U".into(),
        0x00DB => "U".into(),
        0x00DC => "U".into(),
        0x00D1 => "N".into(),
        0x00C7 => "C".into(),
        0x0131 => "i".into(),
        0x0130 => "I".into(),
        0x0132 => "IJ".into(),
        0x0133 => "ij".into(),
        0x0138 => "k".into(),
        0x013F => "L".into(),
        0x0140 => "l".into(),
        0x0141 => "L".into(),
        0x0142 => "l".into(),
        0x0149 => "n".into(),
        0x014A => "N".into(),
        0x014B => "n".into(),
        0x014C => "O".into(),
        0x014D => "o".into(),
        0x014E => "O".into(),
        0x014F => "o".into(),
        0x0152 => "OE".into(),
        0x0153 => "oe".into(),
        0x0160 => "S".into(),
        0x0161 => "s".into(),
        0x0162 => "T".into(),
        0x0163 => "t".into(),
        0x0166 => "T".into(),
        0x0167 => "t".into(),
        0x0168 => "U".into(),
        0x0169 => "u".into(),
        0x016A => "U".into(),
        0x016B => "u".into(),
        0x016E => "U".into(),
        0x016F => "u".into(),
        0x0170 => "U".into(),
        0x0171 => "u".into(),
        0x0172 => "U".into(),
        0x0173 => "u".into(),
        0x0178 => "Y".into(),
        0x0179 => "Z".into(),
        0x017A => "z".into(),
        0x017B => "Z".into(),
        0x017C => "z".into(),
        0x017D => "Z".into(),
        0x017E => "z".into(),
        0x00B9 => "1".into(),
        0x00B2 => "2".into(),
        0x00B3 => "3".into(),
        0x2070 => "0".into(),
        0x2074 => "4".into(),
        0x2075 => "5".into(),
        0x2076 => "6".into(),
        0x2077 => "7".into(),
        0x2078 => "8".into(),
        0x2079 => "9".into(),
        0x2071 => "i".into(),
        0x207F => "n".into(),
        0xFF21 => "A".into(),
        0xFF22 => "B".into(),
        0xFF23 => "C".into(),
        0xFF24 => "D".into(),
        0xFF25 => "E".into(),
        0xFF26 => "F".into(),
        0xFF27 => "G".into(),
        0xFF28 => "H".into(),
        0xFF29 => "I".into(),
        0xFF2A => "J".into(),
        0xFF2B => "K".into(),
        0xFF2C => "L".into(),
        0xFF2D => "M".into(),
        0xFF2E => "N".into(),
        0xFF2F => "O".into(),
        0xFF30 => "P".into(),
        0xFF31 => "Q".into(),
        0xFF32 => "R".into(),
        0xFF33 => "S".into(),
        0xFF34 => "T".into(),
        0xFF35 => "U".into(),
        0xFF36 => "V".into(),
        0xFF37 => "W".into(),
        0xFF38 => "X".into(),
        0xFF39 => "Y".into(),
        0xFF3A => "Z".into(),
        0xFF41 => "a".into(),
        0xFF42 => "b".into(),
        0xFF43 => "c".into(),
        0xFF44 => "d".into(),
        0xFF45 => "e".into(),
        0xFF46 => "f".into(),
        0xFF47 => "g".into(),
        0xFF48 => "h".into(),
        0xFF49 => "i".into(),
        0xFF4A => "j".into(),
        0xFF4B => "k".into(),
        0xFF4C => "l".into(),
        0xFF4D => "m".into(),
        0xFF4E => "n".into(),
        0xFF4F => "o".into(),
        0xFF50 => "p".into(),
        0xFF51 => "q".into(),
        0xFF52 => "r".into(),
        0xFF53 => "s".into(),
        0xFF54 => "t".into(),
        0xFF55 => "u".into(),
        0xFF56 => "v".into(),
        0xFF57 => "w".into(),
        0xFF58 => "x".into(),
        0xFF59 => "y".into(),
        0xFF5A => "z".into(),
        0xFF10 => "0".into(),
        0xFF11 => "1".into(),
        0xFF12 => "2".into(),
        0xFF13 => "3".into(),
        0xFF14 => "4".into(),
        0xFF15 => "5".into(),
        0xFF16 => "6".into(),
        0xFF17 => "7".into(),
        0xFF18 => "8".into(),
        0xFF19 => "9".into(),
        0x212A => "K".into(),
        0x212B => "A".into(),
        0x212C => "B".into(),
        0x212F => "e".into(),
        0x2130 => "E".into(),
        0x2131 => "F".into(),
        0x2133 => "M".into(),
        0x2134 => "o".into(),
        0x2139 => "i".into(),
        0x2113 => "l".into(),
        0x2118 => "P".into(),
        0x2102 => "C".into(),
        0x210D => "H".into(),
        0x2115 => "N".into(),
        0x2119 => "P".into(),
        0x211A => "Q".into(),
        0x211D => "R".into(),
        0x2124 => "Z".into(),
        0x2128 => "Z".into(),
        0x212D => "C".into(),
        0x212E => "e".into(),
        0x0251 => "a".into(),
        0x0259 => "e".into(),
        0x0261 => "g".into(),
        0x026A => "i".into(),
        0x0280 => "R".into(),
        0x028F => "y".into(),
        0x029C => "H".into(),
        0x029F => "L".into(),
        _ => c.to_string(),
    }
}
