//! Frozen Go's vCard 3.0 reader and writer (`internal/carddav/vcard*.go`) and the
//! multi-card splitter of the importer (`internal/migration/vcf_import.go`).
//! The prefix tests are case-insensitive but the trims are exact-case, as in Go.

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Value {
    pub kind: String,
    pub value: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Address {
    pub kind: String,
    pub po_box: String,
    pub ext: String,
    pub street: String,
    pub city: String,
    pub region: String,
    pub code: String,
    pub country: String,
}

#[derive(Clone, Debug, Default)]
pub struct VCard {
    pub uid: String,
    pub fn_: String,
    pub n: String,
    pub org: String,
    pub title: String,
    pub role: String,
    pub photo_uri: String,
    pub categories: Vec<String>,
    pub note: String,
    pub emails: Vec<Value>,
    pub phones: Vec<Value>,
    pub addresses: Vec<Address>,
    pub urls: Vec<Value>,
    pub impps: Vec<Value>,
    /// `YYYY-MM-DD`.
    pub birthday: Option<String>,
    pub anniversary: Option<String>,
}

pub fn unescape(s: &str) -> String {
    s.replace("\\n", "\n")
        .replace("\\r", "\r")
        .replace("\\,", ",")
        .replace("\\;", ";")
        .replace("\\\\", "\\")
}

pub fn escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace(';', "\\;")
        .replace(',', "\\,")
        .replace('\n', "\\n")
}

/// Go's `strings.ToUpper` as far as the ASCII property names can see it.
fn upper(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\u{17f}' => 'S',
            '\u{131}' => 'I',
            c if c.is_ascii() => c.to_ascii_uppercase(),
            c => c,
        })
        .collect()
}

fn unfold(data: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in data.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.starts_with([' ', '\t']) {
            if let Some(last) = out.last_mut() {
                last.push_str(line.trim_start_matches([' ', '\t']));
            }
        } else {
            out.push(line.to_owned());
        }
    }
    out
}

fn param_type(prop: &str) -> String {
    for part in prop.split(';') {
        if upper(part).starts_with("TYPE=") {
            return part.strip_prefix("TYPE=").unwrap_or(part).to_lowercase();
        }
    }
    String::new()
}

fn param_value(line: &str) -> Option<Value> {
    let end = line.find(':')?;
    let mut kind = param_type(&line[..end]);
    if kind.is_empty() {
        kind = "other".into();
    }
    Some(Value {
        kind,
        value: unescape(&line[end + 1..]),
    })
}

fn address(line: &str) -> Option<Address> {
    let end = line.find(':')?;
    let mut kind = param_type(&line[..end]);
    if kind.is_empty() {
        kind = "other".into();
    }
    let value = unescape(&line[end + 1..]);
    let parts: Vec<&str> = value.split(';').collect();
    let at = |i: usize| parts.get(i).copied().unwrap_or("").to_owned();
    Some(Address {
        kind,
        po_box: at(0),
        ext: at(1),
        street: at(2),
        city: at(3),
        region: at(4),
        code: at(5),
        country: at(6),
    })
}

/// Go's `time.Parse("20060102", s)` rendered `YYYY-MM-DD`.
fn day(s: &str) -> Option<String> {
    let b = s.as_bytes();
    if b.len() != 8 || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let (y, m, d): (i32, u32, u32) = (
        s[..4].parse().ok()?,
        s[4..6].parse().ok()?,
        s[6..].parse().ok()?,
    );
    chrono::NaiveDate::from_ymd_opt(y, m, d)?;
    Some(format!("{y:04}-{m:02}-{d:02}"))
}

/// Go's `parseVCard`; `Err` carries the error text.
pub fn parse(data: &str) -> Result<VCard, String> {
    let mut vc = VCard::default();
    for line in unfold(data) {
        let line = line.trim();
        if line == "BEGIN:VCARD" || line == "END:VCARD" {
            continue;
        }
        let up = upper(line);
        let rest = |prefix: &str| line.strip_prefix(prefix).unwrap_or(line);
        if up.starts_with("UID:") {
            vc.uid = unescape(rest("UID:"));
        } else if up.starts_with("FN:") {
            vc.fn_ = unescape(rest("FN:"));
        } else if up.starts_with("N:") {
            vc.n = unescape(rest("N:"));
        } else if up.starts_with("ORG:") {
            vc.org = unescape(rest("ORG:"));
        } else if up.starts_with("TITLE:") {
            vc.title = unescape(rest("TITLE:"));
        } else if up.starts_with("ROLE:") {
            vc.role = unescape(rest("ROLE:"));
        } else if up.starts_with("NOTE:") {
            vc.note = unescape(rest("NOTE:"));
        } else if up.starts_with("BDAY:") {
            if let Some(d) = day(rest("BDAY:")) {
                vc.birthday = Some(d);
            }
        } else if up.starts_with("ANNIVERSARY:") {
            if let Some(d) = day(rest("ANNIVERSARY:")) {
                vc.anniversary = Some(d);
            }
        } else if up.starts_with("NICKNAME:")
            || up.starts_with("GENDER:")
            || up.starts_with("KIND:")
            || up.starts_with("PRODID:")
        {
        } else if up.starts_with("X-IMPP") || up.starts_with("IMPP") {
            if let Some(v) = param_value(line) {
                vc.impps.push(v);
            }
        } else if up.starts_with("EMAIL") {
            if let Some(v) = param_value(line) {
                vc.emails.push(v);
            }
        } else if up.starts_with("TEL") {
            if let Some(v) = param_value(line) {
                vc.phones.push(v);
            }
        } else if up.starts_with("ADR") {
            if let Some(a) = address(line) {
                vc.addresses.push(a);
            }
        } else if up.starts_with("URL") {
            if let Some(v) = param_value(line) {
                vc.urls.push(v);
            }
        }
        if up.starts_with("CATEGORIES:") {
            vc.categories=unescape(rest("CATEGORIES:")).split(',').map(str::trim).filter(|v|!v.is_empty()).map(str::to_owned).collect();
        }else if up.starts_with("PHOTO") && line.contains("/blobs/") {
            let parts=line.split("/blobs/").collect::<Vec<_>>();if parts.len()==2{vc.photo_uri=parts[1].trim().into();}
        }
        // The importer intentionally does not store these three CardDAV fields.
    }
    if vc.fn_.is_empty() && !vc.n.is_empty() {
        let parts: Vec<&str> = vc.n.split(';').collect();
        vc.fn_ = if parts.len() >= 2 {
            format!("{} {}", parts[1], parts[0]).trim().to_owned()
        } else {
            parts[0].trim().to_owned()
        };
    }
    if vc.uid.is_empty() {
        return Err("missing UID".into());
    }
    Ok(vc)
}

/// Go's `splitVCF`: raw text of each `BEGIN:VCARD` .. `END:VCARD` block.
pub fn split(data: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current = String::new();
    let mut depth = 0i32;
    for line in data.split_inclusive('\n') {
        let up = upper(line.trim());
        if up.starts_with("BEGIN:VCARD") {
            current.clear();
            depth += 1;
        }
        if depth > 0 {
            current.push_str(line);
        }
        if up.starts_with("END:VCARD") {
            if !current.is_empty() {
                blocks.push(current.clone());
            }
            depth -= 1;
        }
    }
    blocks
}

/// Go's `vcardValuesToJSON` array text (keys sorted, as `json.Marshal` of a map).
pub fn values_json(values: &[Value], key: &str) -> String {
    let items: Vec<String> = values
        .iter()
        .map(|v| {
            let (a, b) = (go_string(&v.kind), go_string(&v.value));
            if key < "type" {
                format!("{{\"{key}\":{b},\"type\":{a}}}")
            } else {
                format!("{{\"type\":{a},\"{key}\":{b}}}")
            }
        })
        .collect();
    format!("[{}]", items.join(","))
}

pub fn addresses_json(values: &[Address]) -> String {
    let items: Vec<String> = values
        .iter()
        .map(|a| {
            format!(
                "{{\"type\":{},\"street\":{},\"city\":{},\"region\":{},\"code\":{},\"country\":{}}}",
                go_string(&a.kind),
                go_string(&a.street),
                go_string(&a.city),
                go_string(&a.region),
                go_string(&a.code),
                go_string(&a.country)
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

fn go_string(s: &str) -> String {
    crate::problem::go_string(s)
}

/// Go's `parseFirstName`: the Given part of `Family;Given;..`, trimmed.
pub fn first_name(n: &str) -> String {
    let parts: Vec<&str> = n.splitn(3, ';').collect();
    if parts.len() >= 2 {
        return parts[1].trim().to_owned();
    }
    String::new()
}

pub fn last_name(n: &str) -> String {
    n.split(';').next().unwrap_or("").trim().to_owned()
}

// ---- export ----

pub(crate) fn escape_line(s: &str) -> String {
    if s.len() <= 75 {
        return s.to_owned();
    }
    let mut parts: Vec<&str> = Vec::new();
    let mut rest = s;
    while rest.len() > 75 {
        let mut split = 75;
        while split > 0 && split < rest.len() && !rest.is_char_boundary(split) {
            split -= 1;
        }
        if split == 0 {
            split = 75;
        }
        parts.push(&rest[..split]);
        rest = &rest[split..];
    }
    parts.push(rest);
    parts.join("\r\n ")
}

/// Go's JSON decoding of a jsonb array into `[]T` where `T` has the given string
/// fields (matched case-insensitively, other keys ignored). `None` is Go's
/// scan error.
pub fn decode_objects(text: &str, fields: &[&str]) -> Option<Vec<Vec<String>>> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let items = match value {
        serde_json::Value::Null => return Some(Vec::new()),
        serde_json::Value::Array(items) => items,
        _ => return None,
    };
    let mut out = Vec::new();
    for item in items {
        let mut row = vec![String::new(); fields.len()];
        match item {
            serde_json::Value::Null => {}
            serde_json::Value::Object(map) => {
                for (key, value) in map {
                    let folded = crate::guests_input::fold(&key);
                    if let Some(at) = fields.iter().position(|f| *f == folded) {
                        match value {
                            serde_json::Value::Null => {}
                            serde_json::Value::String(s) => row[at] = s,
                            _ => return None,
                        }
                    }
                }
            }
            _ => return None,
        }
        out.push(row);
    }
    Some(out)
}

/// A jsonb array decoded as Go's `[]map[string]any`: every element an object or
/// `null`; `None` is Go's scan error.
pub fn decode_any_objects(text: &str) -> Option<Vec<serde_json::Map<String, serde_json::Value>>> {
    match serde_json::from_str::<serde_json::Value>(text).ok()? {
        serde_json::Value::Null => Some(Vec::new()),
        serde_json::Value::Array(items) => items
            .into_iter()
            .map(|item| match item {
                serde_json::Value::Null => Some(serde_json::Map::new()),
                serde_json::Value::Object(map) => Some(map),
                _ => None,
            })
            .collect(),
        _ => None,
    }
}

/// Go's `contactToVCard`; `None` when a jsonb column does not decode as Go's scan.
pub fn render(c: &setjoin_calendar::contacts::ContactRow) -> Option<String> {
    let value = |text: &str| decode_objects(text, &["type", "value"]);
    let emails = value(&c.emails)?;
    let phones = value(&c.phones)?;
    let urls = value(&c.urls)?;
    let addresses = decode_objects(
        &c.addresses,
        &[
            "type", "pobox", "extaddr", "street", "city", "region", "code", "country",
        ],
    )?;
    value(&c.instant_msgs)?;
    let categories: Vec<String> = serde_json::from_str(&c.categories).ok()?;
    let some = |s: &Option<String>| s.clone().unwrap_or_default();
    let mut b = String::new();
    b.push_str("BEGIN:VCARD\r\nVERSION:3.0\r\n");
    let line2 = |b: &mut String, s: String| {
        b.push_str(&escape_line(&s));
        b.push_str("\r\n");
    };
    line2(&mut b, format!("UID:{}", escape(&c.uid)));
    line2(&mut b, format!("FN:{}", escape(&c.display_name)));
    line2(
        &mut b,
        format!(
            "N:{};{};;;",
            escape(&some(&c.last_name)),
            escape(&some(&c.first_name))
        ),
    );
    if !some(&c.company).is_empty() {
        line2(&mut b, format!("ORG:{}", escape(&some(&c.company))));
    }
    if !some(&c.job_title).is_empty() {
        line2(&mut b, format!("TITLE:{}", escape(&some(&c.job_title))));
    }
    if !some(&c.department).is_empty() {
        line2(&mut b, format!("ROLE:{}", escape(&some(&c.department))));
    }
    if !some(&c.notes).is_empty() {
        line2(&mut b, format!("NOTE:{}", escape(&some(&c.notes))));
    }
    if let Some(d) = &c.birthday {
        b.push_str(&format!("BDAY:{d}\r\n"));
    }
    if let Some(d) = &c.anniversary {
        b.push_str(&format!("ANNIVERSARY:{d}\r\n"));
    }
    if !some(&c.department).is_empty() {
        line2(&mut b, format!("ROLE:{}", escape(&some(&c.department))));
    }
    b.push_str("KIND:individual\r\nPRODID:-//Mailserver//CardDAV//EN\r\n");
    if !some(&c.notes).is_empty() {
        line2(&mut b, format!("NOTE:{}", escape(&some(&c.notes))));
    }
    if let Some(sha) = c.avatar_sha256.as_ref().filter(|s| !s.is_empty()) {
        b.push_str(&format!("PHOTO;VALUE=URI:/blobs/{sha}\r\n"));
    }
    for e in &emails {
        line2(&mut b, format!("EMAIL;TYPE={}:{}", e[0], escape(&e[1])));
    }
    for p in &phones {
        line2(&mut b, format!("TEL;TYPE={}:{}", p[0], escape(&p[1])));
    }
    for a in &addresses {
        let adr = format!(
            "{};{};{};{};{};{};{}",
            a[1], a[2], a[3], a[4], a[5], a[6], a[7]
        );
        line2(&mut b, format!("ADR;TYPE={}:{}", a[0], escape(&adr)));
    }
    for u in &urls {
        line2(&mut b, format!("URL;TYPE={}:{}", u[0], escape(&u[1])));
    }
    if !categories.is_empty() {
        line2(
            &mut b,
            format!("CATEGORIES:{}", escape(&categories.join(","))),
        );
    }
    b.push_str(&format!("REV:{}\r\nEND:VCARD\r\n", c.updated_at));
    Some(b)
}

/// Go's `vcfFilename`: a slug of the display name, `contact.vcf` when empty.
pub fn filename(display_name: &str) -> String {
    let mut b = String::new();
    let mut last_dash = true;
    for c in display_name.chars() {
        let lowered: Vec<char> = if c == '\u{130}' {
            vec!['i']
        } else {
            c.to_lowercase().collect()
        };
        for r in lowered {
            if r.is_ascii_lowercase() || r.is_ascii_digit() {
                b.push(r);
                last_dash = false;
            } else if !last_dash {
                b.push('-');
                last_dash = true;
            }
        }
    }
    let slug = b.trim_matches('-');
    format!("{}.vcf", if slug.is_empty() { "contact" } else { slug })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_like_go() {
        let vc = parse("BEGIN:VCARD\r\nUID:u1\r\nN:Doe;Jane;;;\r\nEMAIL;TYPE=WORK:jane@x.test\r\nuid:ignored\r\nTEL:+1\\;2\r\nEND:VCARD\r\n").unwrap();
        // the lower-case `uid:` line matches case-insensitively but trims nothing
        assert_eq!(vc.uid, "uid:ignored");
        assert_eq!(vc.fn_, "Jane Doe");
        assert_eq!(vc.emails[0].kind, "work");
        assert_eq!(
            vc.phones[0],
            Value {
                kind: "other".into(),
                value: "+1;2".into()
            }
        );
        assert_eq!(parse("FN:x").unwrap_err(), "missing UID");
    }

    #[test]
    fn splits_blocks_and_drops_stray_text() {
        let blocks = split("junk\nBEGIN:VCARD\nUID:a\nEND:VCARD\nBEGIN:VCARD\nUID:b\nEND:VCARD\n");
        assert_eq!(blocks.len(), 2);
    }

    #[test]
    fn filenames_slug() {
        assert_eq!(filename("Jane  Q. Doe"), "jane-q-doe.vcf");
        assert_eq!(filename("***"), "contact.vcf");
        assert_eq!(filename("\u{130}stanbul"), "istanbul.vcf");
    }
}
