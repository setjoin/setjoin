//! Best-effort post-commit iMIP. Calendar business transactions stay in reducers.
use serde_json::json;
use setjoin_pg::{workers::WorkerConnection, Type};

pub(crate) struct Transport<'a> {
    pub envelope: &'a str,
    pub from: &'a str,
    pub spf: bool,
    pub dkim: &'a crate::mail_auth::DkimVerification,
    pub recipients: &'a [String],
    /// The envelope recipient of this delivery (already committed to its mailbox).
    pub to: &'a str,
}
impl Transport<'_> {
    fn dns(&self, role: &str) -> bool {
        let role = role.trim_matches(['<', '>', ' ', '\t']);
        !role.is_empty()
            && ((self.spf && equal(self.envelope.trim_matches(['<', '>', ' ', '\t']), role))
                || (self.dkim.result == "pass"
                    && self.dkim.signed_len == 0
                    && equal(self.from.trim_matches(['<', '>', ' ', '\t']), role)
                    && crate::mail_auth::relaxed_aligned(
                        &self.dkim.domain,
                        self.from.rsplit_once('@').map_or("", |(_, d)| d),
                    )))
    }
}
fn equal(a: &str, b: &str) -> bool {
    setjoin_authz::address::equal_fold(a, b)
}
pub(crate) async fn process(
    pipeline: &super::Pipeline,
    conn: &WorkerConnection,
    msg: &[u8],
    transport: Transport<'_>,
) {
    if crate::mutants::on("inbound-no-imip") {
        return;
    }
    let original = msg;
    let msg = setjoin_mime::go_lossy(msg);
    let lower = msg.to_lowercase();
    if !lower.contains("text/calendar") || !lower.contains("method=") {
        return;
    }
    let mut smime = None;
    let mut verified = String::new();
    if super::smime::is_signed(original) && !crate::mutants::on("inbound-imip-ignore-signed-scope")
    {
        let mut recipient = "";
        for to in transport.recipients {
            let Some((_, domain)) = to.rsplit_once('@') else {
                continue;
            };
            if conn
                .query(
                    "SELECT id FROM domains WHERE lower(name)=lower($1)",
                    &[(&domain, Type::TEXT)],
                )
                .await
                .is_ok_and(|r| !r.is_empty())
            {
                recipient = to;
                break;
            }
        }
        let Some((v, content)) = pipeline
            .smime_checked(
                conn,
                recipient,
                transport.from,
                if crate::mutants::on("inbound-imip-lossy-signed-content") {
                    msg.as_bytes()
                } else {
                    original
                },
                false,
                // #544 (owner-approved security fix 2026-11-05): a revoked or
                // blocklisted signer is graded untrusted, so iMIP stops.
                !crate::mutants::on("inbound-imip-ignore-revocation"),
            )
            .await
        else {
            return;
        };
        if v.status != "valid" {
            return;
        }
        let scope = scope(conn, &v.anchor).await;
        verified = setjoin_mime::go_lossy(&content);
        smime = Some((v, scope));
    }
    let source = if smime.is_some() {
        verified.as_str()
    } else {
        msg.as_str()
    };
    let Some((body, _, _)) = extract(source) else {
        return;
    };
    let Ok((method, event)) = setjoin_calendar_format::parse_itip(body) else {
        return;
    };
    if method == "REPLY" {
        let Some(a) = event.attendees.first() else {
            return;
        };
        let email = a["email"].as_str().unwrap_or("");
        if !transport.dns(email)
            && !smime
                .as_ref()
                .is_some_and(|(v, s)| smime_role(v, s, email, false))
            && !crate::mutants::on("inbound-imip-ignore-role")
        {
            return;
        }
        let name = a["name"].as_str().unwrap_or("");
        let status = match a["participationStatus"].as_str().unwrap_or("") {
            s @ ("accepted" | "tentative" | "declined") => s,
            _ => "needs-action",
        };
        let _ = conn
            .query(
                "SELECT calendar_process_itip_reply($1,$2,$3,$4,0,NULL)",
                &[
                    (&event.uid, Type::TEXT),
                    (&email, Type::TEXT),
                    (&name, Type::TEXT),
                    (&status, Type::TEXT),
                ],
            )
            .await;
        return;
    }
    if method == "CANCEL" {
        let recurrence = event
            .recurrence_id
            .filter(|v| *v != -62_135_596_800)
            .map(|v| timestamp(Some(v)));
        let organizer = event
            .migration
            .get("organizer_email")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let mut mailbox = 0i64;
        if recurrence.is_some() {
            for to in transport.recipients {
                if let Ok(rows)=conn.query("SELECT m.id FROM mailboxes m JOIN aliases a ON a.mailbox_id=m.id WHERE a.email=lower($1) AND mailbox_lifecycle_delivery_mode(m.id)<>'rejecting'",&[(&to,Type::TEXT)]).await {
     if let Some(row)=rows.first(){mailbox=row.get(0);break}
    }
            }
            if mailbox == 0 {
                return;
            }
        }
        let query = if recurrence.is_some() {
            "SELECT ce.organizer_email,lower(d.name) FROM calendar_events ce JOIN calendars c ON c.id=ce.calendar_id JOIN mailboxes m ON m.id=c.mailbox_id LEFT JOIN domains d ON d.id=m.domain_id WHERE ce.uid=$1 AND c.mailbox_id=$2 AND ce.recurrence_override IS NULL LIMIT 1"
        } else {
            "SELECT organizer_email,''::text FROM calendar_events WHERE uid=$1 AND status<>'cancelled' AND $2::bigint=0 LIMIT 1"
        };
        let Ok(rows) = conn
            .query(query, &[(&event.uid, Type::TEXT), (&mailbox, Type::INT8)])
            .await
        else {
            return;
        };
        let Some(db_organizer) = rows.first().and_then(|r| r.get::<_, Option<String>>(0)) else {
            return;
        };
        if organizer.is_empty() || !equal(organizer, &db_organizer) {
            return;
        }
        let dns = transport.dns(&db_organizer);
        let signed = smime
            .as_ref()
            .filter(|(v, s)| smime_role(v, s, &db_organizer, true));
        if !dns && signed.is_none() && !crate::mutants::on("inbound-imip-ignore-role") {
            return;
        }
        let accepts = |domain: &str| dns || signed.is_some_and(|(_, s)| s.covers(domain));
        if let Some(recurrence)=recurrence {
   let domain=rows[0].get::<_,Option<String>>(1).unwrap_or_default();if !accepts(&domain){return}
   let _=conn.query("SELECT rust_smtp_imip_cancel_occurrence($1,$2,$3,$4::text::timestamptz)",&[(&event.uid,Type::TEXT),(&mailbox,Type::INT8),(&db_organizer,Type::TEXT),(&recurrence,Type::TEXT)]).await;
  } else if let Ok(domains)=conn.query("SELECT DISTINCT lower(d.name) FROM calendar_events ce JOIN calendars c ON c.id=ce.calendar_id JOIN mailboxes mb ON mb.id=c.mailbox_id JOIN domains d ON d.id=mb.domain_id WHERE ce.uid=$1 AND lower(ce.organizer_email)=lower($2) AND ce.status<>'cancelled'",&[(&event.uid,Type::TEXT),(&db_organizer,Type::TEXT)]).await {
   for domain in domains {let domain:String=domain.get(0);if !accepts(&domain) {continue} let _=conn.query("SELECT calendar_process_itip_cancel($1,NULL,$2,$3)",&[(&event.uid,Type::TEXT),(&db_organizer,Type::TEXT),(&domain,Type::TEXT)]).await;}
  }
        return;
    }
    if method != "REQUEST" {
        return;
    }
    let attendees = json!(event.attendees).to_string();
    // #544 (owner-approved security fix 2026-11-05): only an attendee that is the
    // owner of this delivery's envelope recipient may receive the event. The mutant
    // restores Go's body-attendee pick by naming the first attendee as the recipient.
    let recipient = if crate::mutants::on("inbound-imip-body-attendee") {
        event
            .attendees
            .iter()
            .find_map(|a| a["email"].as_str().filter(|e| !e.is_empty()))
            .unwrap_or(transport.to)
    } else {
        transport.to
    };
    let Ok(rows) = conn
        .query(
            "SELECT rust_smtp_imip_request_gate($1::jsonb,$2)::text",
            &[(&attendees, Type::TEXT), (&recipient, Type::TEXT)],
        )
        .await
    else {
        return;
    };
    let Some(context) = rows.first().and_then(|r| r.get::<_, Option<String>>(0)) else {
        return;
    };
    let mut obj = json!({"uid":event.uid,"title":event.title,"start":timestamp(event.start),"end":timestamp(event.end),"isAllDay":event.all_day,"timeZone":event.timezone,"status":"tentative"});
    for (name, value) in [
        ("description", event.description),
        ("location", event.location),
        ("recurrenceRule", event.rrule),
    ] {
        if !value.is_empty() {
            obj[name] = json!(value)
        }
    }
    let recurrence = event
        .recurrence_id
        .filter(|v| *v != -62_135_596_800)
        .map(|v| timestamp(Some(v)));
    let obj = obj.to_string();
    let _ = conn
        .query(
            "SELECT rust_smtp_imip_request_apply($1::jsonb,$2::jsonb,$3::text::timestamptz)",
            &[
                (&context, Type::TEXT),
                (&obj, Type::TEXT),
                (&recurrence, Type::TEXT),
            ],
        )
        .await;
}
fn timestamp(value: Option<i64>) -> String {
    chrono::DateTime::from_timestamp(value.unwrap_or(-62_135_596_800), 0)
        .unwrap()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}
// Go intentionally scans substrings rather than transfer-decoding strict MIME.
// ASCII lowercase keeps byte offsets identical to the original (Go slices by bytes); Unicode lowercasing (Kelvin sign, U+0130) shifts them and panicked.
fn extract(scope: &str) -> Option<(&str, usize, usize)> {
    let lower = scope.to_ascii_lowercase();
    let idx = lower.find("content-type: text/calendar")?;
    // MIME syntax before the part is ASCII; retain byte offsets into original.
    let start = scope[..idx].rfind('\n').map_or(0, |n| n + 1);
    let Some(boundary) = lower[..idx].find("boundary=") else {
        let end = scope[idx..].find("\r\n--").map_or(scope.len(), |n| idx + n);
        return Some((&scope[idx..end], idx, end));
    };
    let b = scope[boundary + 9..].trim_matches([' ', '\t', '"', ';']);
    let b = match b.find([' ', '\t', '\r', '\n', ';']) {
        Some(n) if n > 0 => &b[..n],
        _ => b,
    };
    let marker = format!("--{b}--");
    let end = scope[start..]
        .find(&marker)
        .map_or(scope.len(), |n| start + n + marker.len());
    let part = &scope[start..end];
    let offset = part
        .find("\r\n\r\n")
        .map(|n| n + 4)
        .or_else(|| part.find("\n\n").map(|n| n + 2))
        .unwrap_or(0);
    Some((&scope[start + offset..end], start + offset, end))
}

enum Scope {
    None,
    Unrestricted,
    Domains(Vec<String>),
}
impl Scope {
    fn covers(&self, domain: &str) -> bool {
        if domain.is_empty() {
            return false;
        }
        if crate::mutants::on("inbound-imip-ignore-scope") {
            return true;
        }
        match self {
            Self::None => false,
            Self::Unrestricted => true,
            Self::Domains(ds) => ds.iter().any(|d| equal(d, domain)),
        }
    }
}
fn smime_role(v: &super::smime::Verdict, scope: &Scope, role: &str, cancel: bool) -> bool {
    let role = role.trim_matches(['<', '>', ' ', '\t']);
    !role.is_empty()
        && equal(v.email.trim_matches(['<', '>', ' ', '\t']), role)
        && if cancel {
            !matches!(scope, Scope::None)
        } else {
            scope.covers(v.email.rsplit_once('@').map_or("", |(_, d)| d))
        }
}
async fn scope(conn: &WorkerConnection, anchor: &[u8]) -> Scope {
    if anchor.is_empty() {
        return Scope::None;
    }
    let fp = setjoin_certificates::fingerprint(anchor);
    let Ok(rows)=conn.query("SELECT coalesce(bool_or(t.domain_id IS NULL),false),coalesce(array_agg(DISTINCT lower(d.name)) FILTER(WHERE d.name IS NOT NULL),'{}') FROM smime_trust_anchors t LEFT JOIN domains d ON d.id=t.domain_id WHERE t.fingerprint=$1",&[(&fp,Type::TEXT)]).await else{return Scope::None};
    if rows[0].get::<_, bool>(0) {
        return Scope::Unrestricted;
    }
    let domains: Vec<String> = rows[0].get(1);
    if !domains.is_empty() {
        Scope::Domains(domains)
    } else if super::smime::bundled_anchor(anchor) {
        Scope::Unrestricted
    } else {
        Scope::None
    }
}
#[cfg(test)]
mod extract_tests {
    use super::extract;
    #[test]
    fn shifted_offset_landing_mid_character_does_not_panic() {
        // Old code: lowercase offset 1 sliced the 3-byte Kelvin sign (and 2-byte U+0130 at 1).
        for pre in ["\u{212A}", "\u{0130}\u{0130}"] {
            let msg = format!("{pre}Content-Type: text/calendar; method=REQUEST\r\n\r\nBEGIN");
            let (body, s, e) = extract(&msg).expect("part");
            assert_eq!((s, e), (pre.len(), msg.len()));
            assert!(body.starts_with("Content-Type: text/calendar"));
        }
    }
    #[test]
    fn unicode_case_folding_chars_do_not_shift_offsets() {
        for pre in ["\u{212A}", "\u{0130}", "\u{212A}\u{0130}\u{212A}"] {
            let msg = format!("{pre} boundary=XY\r\nContent-Type: text/calendar; method=REQUEST\r\n\r\nBEGIN:VCALENDAR\r\n--XY--\r\n");
            let (body, s, e) = extract(&msg).expect("part");
            let idx = msg.find("Content-Type: text/calendar").unwrap();
            let start = msg[..idx].rfind('\n').map_or(0, |n| n + 1);
            let want_start = start + msg[start..].find("\r\n\r\n").unwrap() + 4;
            assert_eq!(s, want_start);
            assert_eq!(e, msg.find("--XY--").unwrap() + 6);
            assert_eq!(body, &msg[s..e]);
            let nb =
                format!("{pre}\r\nContent-Type: text/calendar; method=REQUEST\r\n\r\nBEGIN\r\n--x");
            let (b, s, e) = extract(&nb).expect("part");
            assert_eq!((s, b), (nb.find("Content-Type").unwrap(), &nb[s..e]));
            assert_eq!(e, nb.find("\r\n--x").unwrap());
        }
    }
}
