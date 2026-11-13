//! The mail the public booking surface sends, byte-for-byte as frozen Go builds
//! it: the booker's verification link and the owner's heads-up (Go's
//! `notify.BuildSystemMIME`), and the iMIP invitation Go's `EnqueueInvite`
//! renders (`caldav.BuildIMip`) for the confirmed event.
//!
//! Every message is stored as a content-addressed object and queued with one
//! plain `INSERT` on the worker credential, the single statement Go issues.
use crate::recovery_worker::ObjectStore;
use setjoin_pg::workers::WorkerDatabase;
use setjoin_pg::Type;
use sha2::{Digest, Sha256};

/// 32 random bytes, base64url without padding, and the SHA-256 hex Go stores.
pub fn token() -> Option<(String, String)> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).ok()?;
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let hash = sha256_hex(&token);
    Some((token, hash))
}

pub fn sha256_hex(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}

static LAST_MESSAGE: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

/// Go's `nextSystemMessageID`: nanoseconds, strictly increasing within the process.
fn next_message_id() -> i64 {
    use std::sync::atomic::Ordering;
    loop {
        let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let last = LAST_MESSAGE.load(Ordering::Relaxed);
        let next = if now <= last { last + 1 } else { now };
        if LAST_MESSAGE
            .compare_exchange(last, next, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
        {
            return next;
        }
    }
}

fn normalize_header(value: &str) -> String {
    value
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .replace('\n', " ")
}

fn normalize_crlf(value: &str) -> String {
    value
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .replace('\n', "\r\n")
}

/// Go's `mime.QEncoding.Encode("utf-8", s)`: unchanged when printable ASCII,
/// otherwise encoded words of at most 75 bytes joined by CRLF + space.
fn q_encode(value: &str) -> String {
    if !value.bytes().any(|b| (b < b' ' || b > b'~') && b != b'\t') {
        return value.to_owned();
    }
    const MAX_CONTENT: usize = 75 - 10 - 2;
    let mut out = String::from("=?utf-8?q?");
    let mut current = 0usize;
    for ch in value.chars() {
        let mut buf = [0u8; 4];
        let bytes = ch.encode_utf8(&mut buf).as_bytes();
        let plain = bytes.len() == 1
            && bytes[0] >= b' '
            && bytes[0] <= b'~'
            && !matches!(bytes[0], b'=' | b'?' | b'_');
        let width = if plain { 1 } else { 3 * bytes.len() };
        if current + width > MAX_CONTENT {
            out.push_str("?=\r\n =?utf-8?q?");
            current = 0;
        }
        for &b in bytes {
            match b {
                b' ' => out.push('_'),
                b'!'..=b'~' if !matches!(b, b'=' | b'?' | b'_') => out.push(b as char),
                _ => out.push_str(&format!("={b:02X}")),
            }
        }
        current += width;
    }
    out.push_str("?=");
    out
}

/// `net/mail.Address.String()` for an empty display name.
fn address_string(address: &str) -> String {
    let (local, domain) = match address.rfind('@') {
        Some(at) => (&address[..at], &address[at + 1..]),
        None => (address, ""),
    };
    let atext = |c: char| c.is_ascii_alphanumeric() || "!#$%&'*+-/=?^_`{|}~".contains(c);
    let chars: Vec<char> = local.chars().collect();
    let plain = chars.iter().enumerate().all(|(i, &c)| {
        atext(c) || (c == '.' && i > 0 && chars[i - 1] != '.' && i < chars.len() - 1)
    });
    let local = if plain && !local.is_empty() {
        local.to_owned()
    } else {
        let mut quoted = String::from("\"");
        for c in local.chars() {
            if c == '"' || c == '\\' {
                quoted.push('\\');
            }
            quoted.push(c);
        }
        quoted.push('"');
        quoted
    };
    format!("<{local}@{domain}>")
}

/// Go's `validateSystemMailInput` address half: it must parse and round-trip.
fn valid_address(value: &str) -> bool {
    if value.contains(['\r', '\n']) {
        return false;
    }
    // Go's parser refuses dot-atom locals with a leading, trailing or doubled dot.
    if let Some((local, _)) = value.rsplit_once('@') {
        if !local.starts_with('"')
            && (local.starts_with('.') || local.ends_with('.') || local.contains(".."))
        {
            return false;
        }
    }
    match mailparse::addrparse(value) {
        Ok(list) if list.len() == 1 => {
            matches!(&list[0], mailparse::MailAddr::Single(a) if a.addr == value)
        }
        _ => false,
    }
}

/// `notify.BuildSystemMIME`: `None` is Go's empty result for invalid input.
pub fn system_mime(
    from: &str,
    to: &str,
    subject: &str,
    body: &str,
    prefix: &str,
) -> Option<(String, String)> {
    if !valid_address(from) || !valid_address(to) {
        return None;
    }
    let domain = from.split_once('@').map_or("", |(_, d)| d);
    let message = format!("<{prefix}{}@{domain}>", next_message_id());
    let subject = q_encode(&normalize_header(subject));
    let body = crate::guest_mail::quoted_printable(&(normalize_crlf(body) + "\r\n"));
    Some((
        format!(
            "From: {}\r\nTo: {}\r\nSubject: {subject}\r\nMessage-ID: {message}\r\nDate: {}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n{body}",
            address_string(from),
            address_string(to),
            chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S +0000"),
        ),
        message,
    ))
}

/// Go's `PublicHandler.enqueue`: content-addressed object, then one queue row.
/// An empty MIME (invalid address) is stored and queued as is, like Go.
pub async fn enqueue(
    store: Option<&dyn ObjectStore>,
    worker: &WorkerDatabase,
    key_prefix: &str,
    mime: &str,
    message: &str,
    from: &str,
    to: &str,
) -> Result<(), String> {
    let Some(store) = store else { return Ok(()) };
    let key = format!("{key_prefix}{}.eml", sha256_hex(mime));
    put(store, &key, mime).await?;
    queue(worker, message, from, &[to.to_owned()], &key).await
}

async fn queue(
    worker: &WorkerDatabase,
    message: &str,
    from: &str,
    to: &[String],
    key: &str,
) -> Result<(), String> {
    let connection = worker.connect().await.map_err(|e| e.to_string())?;
    let to = to.to_vec();
    connection
        .query(
            "INSERT INTO outbound_queue (message_id, from_addr, rcpt_addrs, raw_ref, status) \
             VALUES ($1, $2, $3, $4, 'pending') RETURNING id",
            &[
                (&message, Type::TEXT),
                (&from, Type::TEXT),
                (&to, Type::TEXT_ARRAY),
                (&key, Type::TEXT),
            ],
        )
        .await
        .map(|_| ())
}

/// MinIO's retry cadence on transient storage errors, as the guest delivery keeps.
async fn put(store: &dyn ObjectStore, key: &str, mime: &str) -> Result<(), String> {
    let mut last = String::new();
    for attempt in 0..10 {
        match store.put(key, mime.as_bytes(), "message/rfc822").await {
            Ok(()) => return Ok(()),
            Err(error) => {
                let transient = [
                    "HTTP 408", "HTTP 429", "HTTP 500", "HTTP 502", "HTTP 503", "HTTP 504",
                ]
                .iter()
                .any(|code| error.contains(code));
                last = error;
                if !transient {
                    break;
                }
                let bound = (200_000_000u64 << attempt.min(9)).min(1_000_000_000);
                let mut random = [0; 8];
                let _ = getrandom::getrandom(&mut random);
                let fraction = u64::from_ne_bytes(random) >> 11;
                let delay = bound - ((u128::from(fraction) * u128::from(bound)) >> 53) as u64;
                tokio::time::sleep(std::time::Duration::from_nanos(delay)).await;
            }
        }
    }
    Err(format!("store blob: {last}"))
}

pub async fn verification(
    store: Option<&dyn ObjectStore>,
    worker: &WorkerDatabase,
    public_base: &str,
    owner: &str,
    booker: &str,
    title: &str,
    token: &str,
) {
    let link = format!("{public_base}/book/confirm?token={token}");
    let body = format!(
        "Please confirm your booking for {}.\n\nClick to confirm (valid for 24 hours):\n{link}\n\nIf you didn't request this, ignore this email.\n",
        go_quote(title)
    );
    let (mime, message) = system_mime(
        owner,
        booker,
        &format!("Confirm your booking: {title}"),
        &body,
        "booking-",
    )
    .unwrap_or_default();
    let _ = enqueue(
        store,
        worker,
        "booking/verify/",
        &mime,
        &message,
        owner,
        booker,
    )
    .await;
}

pub async fn owner_notice(
    store: Option<&dyn ObjectStore>,
    worker: &WorkerDatabase,
    owner: &str,
    booker: &str,
    title: &str,
    slot_start: &str,
) {
    let body = format!(
        "{booker} just booked \"{title}\" with you.\n\nWhen: {slot_start}\n\nA calendar invite has been sent separately.\n"
    );
    let (mime, message) = system_mime(
        owner,
        owner,
        &format!("New booking: {title}"),
        &body,
        "booking-",
    )
    .unwrap_or_default();
    let _ = enqueue(
        store,
        worker,
        "booking/notify/",
        &mime,
        &message,
        owner,
        owner,
    )
    .await;
}

/// Go's `%q` for a string: a double-quoted Go string literal.
fn go_quote(text: &str) -> String {
    let mut out = String::from("\"");
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{b}' => out.push_str("\\v"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

// ---- the iMIP invitation (`jmap.buildInviteMIME` + `caldav.BuildIMip`) ----

#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct Attendee {
    email: Option<String>,
    name: Option<String>,
    role: Option<String>,
    #[serde(rename = "participationStatus")]
    status: Option<String>,
    #[serde(rename = "expectReply")]
    rsvp: Option<bool>,
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct Payload {
    uid: Option<String>,
    title: Option<String>,
    description: Option<String>,
    location: Option<String>,
    start: Option<String>,
    end: Option<String>,
    #[serde(rename = "allDay")]
    all_day: Option<bool>,
    timezone: Option<String>,
    status: Option<String>,
    sequence: Option<i64>,
    rrule: Option<String>,
    #[serde(rename = "organizerEmail")]
    organizer_email: Option<String>,
    #[serde(rename = "organizerName")]
    organizer_name: Option<String>,
    attendees: Option<Vec<Attendee>>,
}

/// What the invitation needs to leave the building.
pub struct Invite {
    pub mime: String,
    pub key: String,
    pub recipients: Vec<String>,
    pub uid: String,
    pub organizer: String,
}

fn strip_header(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '\r' | '\n' | '\0'))
        .collect()
}

fn escape_text(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace(';', "\\;")
        .replace(',', "\\,")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
}

/// RFC 5545 line folding at 75 bytes without splitting a UTF-8 sequence.
fn fold(line: &str) -> String {
    let mut s = line.as_bytes();
    if s.len() <= 75 {
        return line.to_owned();
    }
    let mut parts: Vec<&[u8]> = Vec::new();
    while s.len() > 75 {
        let mut split = 75;
        while split > 0 && split < s.len() && s[split] & 0xC0 == 0x80 {
            split -= 1;
        }
        if split == 0 {
            split = 75;
        }
        parts.push(&s[..split]);
        s = &s[split..];
    }
    parts.push(s);
    parts
        .iter()
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .collect::<Vec<_>>()
        .join("\r\n ")
}

fn param_value(s: &str) -> String {
    let s: String = s
        .chars()
        .filter(|c| (*c as u32) >= 0x20 && *c as u32 != 0x7f)
        .collect();
    if s.is_empty() {
        return "\"\"".into();
    }
    if s.contains(['"', ';', ':', ',']) {
        return format!("\"{}\"", s.replace('"', "").replace('\\', "\\\\"));
    }
    s
}

fn cal_address(email: &str) -> Option<String> {
    let (local, domain) = email.split_once('@')?;
    if local.is_empty() || domain.is_empty() {
        return None;
    }
    if !email
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-/=?^_`{|}~.@".contains(c))
    {
        return None;
    }
    if domain.starts_with('-') || domain.ends_with('-') || domain.contains("..") {
        return None;
    }
    Some(format!("mailto:{email}"))
}

fn attendee_line(kind: &str, a: &Attendee) -> Option<String> {
    let email = a.email.clone().unwrap_or_default();
    let address = cal_address(&email)?;
    let mut params = Vec::new();
    let name = a.name.clone().unwrap_or_default();
    if !name.is_empty() && !name.contains('"') {
        params.push(format!("CN={}", param_value(&name)));
    }
    if let Some(role) = match a.role.as_deref().unwrap_or("") {
        "required" | "req-participant" => Some("REQ-PARTICIPANT"),
        "optional" | "opt-participant" => Some("OPT-PARTICIPANT"),
        "resource" | "non-participant" => Some("NON-PARTICIPANT"),
        "chair" => Some("CHAIR"),
        _ => None,
    } {
        params.push(format!("ROLE={role}"));
    }
    let status = a.status.clone().unwrap_or_default();
    if !status.is_empty() {
        params.push(format!(
            "PARTSTAT={}",
            match status.as_str() {
                "accepted" => "ACCEPTED",
                "declined" => "DECLINED",
                "tentative" => "TENTATIVE",
                _ => "NEEDS-ACTION",
            }
        ));
    }
    if a.rsvp.unwrap_or(false) {
        params.push("RSVP=TRUE".into());
    }
    Some(if params.is_empty() {
        format!("{kind}:{address}")
    } else {
        format!("{kind};{}:{address}", params.join(";"))
    })
}

fn zone_known(tzid: &str) -> bool {
    if tzid.is_empty()
        || !tzid
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/_-+.".contains(c))
    {
        return false;
    }
    if tzid == "UTC" {
        return true;
    }
    let mut roots = vec![
        "/usr/share/zoneinfo/".to_owned(),
        "/usr/share/lib/zoneinfo/".to_owned(),
        "/usr/lib/locale/TZ/".to_owned(),
        "/etc/zoneinfo/".to_owned(),
    ];
    if let Ok(dir) = std::env::var("ZONEINFO") {
        roots.insert(0, format!("{dir}/"));
    }
    roots.iter().any(|root| {
        std::fs::read(format!("{root}{tzid}")).is_ok_and(|bytes| bytes.starts_with(b"TZif"))
    })
}

fn describe(time: &chrono::DateTime<chrono::FixedOffset>, all_day: bool, tz: &str) -> String {
    if all_day {
        return time.format("%A, %B %-d, %Y").to_string();
    }
    let base = time.format("%A, %B %-d, %Y at %-I:%M %p").to_string();
    if !tz.is_empty() && tz != "UTC" {
        format!("{base} ({tz})")
    } else {
        format!("{base} UTC")
    }
}

/// `jmap.buildInviteMIME` for a reducer-produced REQUEST payload. `Ok(None)` is
/// "nothing to send" (no attendees); `Err` is Go's logged-and-skipped failure.
pub fn invite(payload: &str) -> Result<Option<Invite>, String> {
    let p: Payload = serde_json::from_str(payload).map_err(|e| e.to_string())?;
    let attendees = p.attendees.unwrap_or_default();
    if attendees.is_empty() {
        return Ok(None);
    }
    let parse = |value: &Option<String>| {
        chrono::DateTime::parse_from_rfc3339(value.as_deref().unwrap_or(""))
            .map_err(|e| format!("parse time: {e}"))
    };
    let start = parse(&p.start)?;
    let end = parse(&p.end)?;
    let uid = p.uid.clone().unwrap_or_default();
    let title = p.title.clone().unwrap_or_default();
    let description = p.description.clone().unwrap_or_default();
    let location = p.location.clone().unwrap_or_default();
    let tz = p.timezone.clone().unwrap_or_default();
    let all_day = p.all_day.unwrap_or(false);
    let organizer_email = p.organizer_email.clone().unwrap_or_default();
    let organizer_name = p.organizer_name.clone().unwrap_or_default();
    let organizer = Attendee {
        email: Some(organizer_email.clone()),
        name: Some(organizer_name.clone()),
        role: Some("organizer".into()),
        ..Default::default()
    };
    let nanos = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let boundary = format!("mailserver-imip-{nanos}");
    let safe_name = strip_header(&organizer_name);
    let safe_email = strip_header(&organizer_email);
    let safe_title = strip_header(&title);

    let mut text = format!(
        "Invitation: {safe_title}\nWhen: {}",
        describe(&start, all_day, &tz)
    );
    if !all_day {
        text += &format!(" - {}", describe(&end, all_day, &tz));
    }
    text.push('\n');
    if !location.is_empty() {
        text += &format!("Where: {location}\n");
    }
    if !organizer_email.is_empty() {
        text += &format!("Organizer: {organizer_name} <{organizer_email}>\n");
    }
    text += "Attendees:\n";
    for a in &attendees {
        text += &format!(
            "  - {} <{}> ({})\n",
            a.name.clone().unwrap_or_default(),
            a.email.clone().unwrap_or_default(),
            a.status.clone().unwrap_or_default()
        );
    }
    if !description.is_empty() {
        text += &format!("\n{description}\n");
    }

    let mut calendar = String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nMETHOD:REQUEST\r\nPRODID:-//Mailserver//iMIP//EN\r\nBEGIN:VEVENT\r\n");
    calendar += &format!(
        "DTSTAMP:{}\r\n",
        chrono::Utc::now().format("%Y%m%dT%H%M%SZ")
    );
    calendar += &format!("SEQUENCE:{}\r\n", p.sequence.unwrap_or(0));
    calendar += &(fold(&format!("UID:{}", escape_text(&uid))) + "\r\n");
    calendar += &(fold(&format!("SUMMARY:{}", escape_text(&title))) + "\r\n");
    if !description.is_empty() {
        calendar += &(fold(&format!("DESCRIPTION:{}", escape_text(&description))) + "\r\n");
    }
    if !location.is_empty() {
        calendar += &(fold(&format!("LOCATION:{}", escape_text(&location))) + "\r\n");
    }
    if all_day {
        calendar += &format!("DTSTART;VALUE=DATE:{}\r\n", start.format("%Y%m%d"));
        calendar += &format!("DTEND;VALUE=DATE:{}\r\n", end.format("%Y%m%d"));
    } else if !tz.is_empty() && tz != "UTC" && zone_known(&tz) {
        calendar += &format!(
            "DTSTART;TZID={}:{}\r\n",
            param_value(&tz),
            start.format("%Y%m%dT%H%M%S")
        );
        calendar += &format!(
            "DTEND;TZID={}:{}\r\n",
            param_value(&tz),
            end.format("%Y%m%dT%H%M%S")
        );
    } else {
        let utc = |t: &chrono::DateTime<chrono::FixedOffset>| {
            t.with_timezone(&chrono::Utc)
                .format("%Y%m%dT%H%M%SZ")
                .to_string()
        };
        calendar += &format!("DTSTART:{}\r\nDTEND:{}\r\n", utc(&start), utc(&end));
    }
    if let Some(status) = p.status.as_deref().filter(|s| !s.is_empty()) {
        calendar += &format!("STATUS:{}\r\n", status.to_uppercase());
    }
    let _ = p.rrule;
    if !organizer_email.is_empty() {
        if let Some(line) = attendee_line("ORGANIZER", &organizer) {
            calendar += &(line + "\r\n");
        }
    }
    for a in &attendees {
        if let Some(line) = attendee_line("ATTENDEE", a) {
            calendar += &(line + "\r\n");
        }
    }
    calendar += "END:VEVENT\r\nEND:VCALENDAR\r\n";

    let mut to = Vec::new();
    for a in &attendees {
        let email = a.email.clone().unwrap_or_default();
        if email != organizer_email {
            to.push(format!(
                "{} <{}>",
                strip_header(&a.name.clone().unwrap_or_default()),
                strip_header(&email)
            ));
        }
    }
    if to.is_empty() {
        to.push(strip_header(&organizer_email));
    }
    let mime = format!(
        "From: {safe_name} <{safe_email}>\r\nTo: {}\r\nSubject: Invitation: {safe_title}\r\nDate: {}\r\nMessage-ID: <{nanos}@mailserver>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary={boundary}\r\n\r\n--{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{text}\r\n--{boundary}\r\nContent-Type: text/calendar; method=REQUEST; component=VEVENT; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{calendar}\r\n--{boundary}--\r\n",
        to.join(", "),
        chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S +0000"),
    );
    let key = format!("imip/{}.eml", sha256_hex(&mime));
    let recipients = attendees
        .iter()
        .filter_map(|a| {
            let email = a.email.clone().unwrap_or_default();
            (email != organizer_email).then_some(email)
        })
        .collect();
    Ok(Some(Invite {
        mime,
        key,
        recipients,
        uid,
        organizer: organizer_email,
    }))
}

/// `serializeAndEnqueueInvite`: best effort, one object and one queue row.
pub async fn send_invite(store: Option<&dyn ObjectStore>, worker: &WorkerDatabase, payload: &str) {
    let Some(store) = store else { return };
    let Ok(Some(invite)) = invite(payload) else {
        return;
    };
    if put(store, &invite.key, &invite.mime).await.is_err() {
        return;
    }
    let _ = queue(
        worker,
        &invite.uid,
        &invite.organizer,
        &invite.recipients,
        &invite.key,
    )
    .await;
}
