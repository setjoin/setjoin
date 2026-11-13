//! F17 slice `calendar-booking` frozen-Go oracle: HTTP wire, committed rows,
//! outbound mail and NOTIFY for the booking, free/busy and subscription routes.
//! Record mode runs the covered Go binary behind the front door; replay serves
//! the same requests from Rust with no Go upstream.
//!
//! Parallel safety: every case shares the booking feature toggle, the
//! `sharing.defaults` toggle and the outbound queue, so each case holds `SERIAL`.
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Map, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{
    calendar::{CalendarRoute, SubscriptionKick},
    Body, BoxFuture, Config, Gateway, Intercept, RequestContext, RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

mod mail;

pub static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Probe {
    inner: CalendarRoute<setjoin_gateway::jmap::jwks::Jwks>,
    changed_status: bool,
}
impl Intercept for Probe {
    fn matches(&self, r: &Request<Body>) -> bool {
        self.inner.matches(r)
    }
    fn admits_member(&self, h: hyper::HeaderMap, s: &'static str) -> BoxFuture<bool> {
        self.inner.admits_member(h, s)
    }
    fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let future = self.inner.handle(r, c);
        let changed = self.changed_status;
        Box::pin(async move {
            let mut response = future.await;
            if changed {
                *response.status_mut() = hyper::StatusCode::IM_A_TEAPOT;
            }
            response
        })
    }
}

/// Counts what the route hands the (absent) first-fetch worker.
#[derive(Default)]
struct Kicks(Mutex<Vec<(i64, i64, String)>>);
impl SubscriptionKick for Kicks {
    fn kick(&self, subscription: i64, calendar: i64, url: String) {
        self.0.lock().unwrap().push((subscription, calendar, url));
    }
}
struct SharedKicks(Arc<Kicks>);
impl SubscriptionKick for SharedKicks {
    fn kick(&self, s: i64, c: i64, u: String) {
        self.0.kick(s, c, u)
    }
}

pub fn sha(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Caller {
    A,
    B,
    Nobody,
}

struct Spec {
    method: &'static str,
    pattern: &'static str,
    path: String,
    query: String,
    /// `(sent, recorded)`: the recorded form never holds run-specific numbers.
    body: Option<(String, String)>,
    caller: Caller,
    wanted: u16,
    /// Sent once before the case is observed (a `repeat` case).
    first: bool,
    /// Outbound queue rows the case commits after it answers.
    mail: usize,
    toggle_off: bool,
    sharing_defaults: bool,
}

const TOKEN_VERIFY: &str = "cal1-verify-token-one";
const TOKEN_VERIFY_UNI: &str = "cal1-verify-token-uni";
const TOKEN_CANCEL: &str = "cal1-cancel-token-one";

struct World {
    a: fixture::Account,
    b: fixture::Account,
    d: String,
    page_a: i64,
    page_off: i64,
    page_b: i64,
    sub_a: i64,
    sub_b: i64,
    cal_a: i64,
    cal_b: i64,
    room: i64,
}

fn spec(route: &str, label: &str, w: &World) -> Spec {
    let d = &w.d;
    let same = |s: &str| Some((s.to_string(), s.to_string()));
    let mut s = Spec {
        method: "GET",
        pattern: "",
        path: String::new(),
        query: String::new(),
        body: None,
        caller: Caller::A,
        wanted: 200,
        first: false,
        mail: 0,
        toggle_off: label == "toggle-off",
        sharing_defaults: false,
    };
    let bad = match label {
        "toggle-off" | "unknown-slug" | "disabled" | "missing-id-foreign" => 404,
        _ => 0,
    };
    match route {
        "pages-list" => {
            s.pattern = "/booking/pages";
            s.path = "/api/booking/pages".into();
            if label == "cross-tenant" {
                s.caller = Caller::B;
            }
            if label == "invalid-input" {
                s.query = "?limit=-1&q=%00".into();
            }
            if label == "toggle-off" {
                s.wanted = 404;
            }
        }
        "pages-put" => {
            s.method = "PUT";
            s.pattern = "/booking/pages";
            s.path = "/api/booking/pages".into();
            let new_page = r#"{"slug":"cal1-new-page","title":"New page","durationMinutes":45,"timezone":"Europe/Berlin"}"#;
            s.body = match label {
                "update" => Some((
                    format!(
                        r#"{{"id":"{}","title":"Renamed page","enabled":false}}"#,
                        w.page_a
                    ),
                    r#"{"id":"<page-a>","title":"Renamed page","enabled":false}"#.into(),
                )),
                "cross-tenant" => Some((
                    format!(r#"{{"id":"{}","title":"Hijacked"}}"#, w.page_b),
                    r#"{"id":"<page-b>","title":"Hijacked"}"#.into(),
                )),
                "invalid-input" => same("{\"slug\":"),
                "empty" => same(""),
                "slug-invalid" => same(r#"{"slug":"X","title":"t"}"#),
                "bad-id" => same(r#"{"id":"abc","title":"t"}"#),
                "scalar" => same("5"),
                "null-body" => same("null"),
                "duplicate-slug" => same(r#"{"slug":"cal1-a-page","title":"dup"}"#),
                "trailing" => same(&format!("{new_page} trailing")),
                "oversize" => Some((
                    format!(r#"{{"slug":"cal1-big","title":"{}"}}"#, "x".repeat(17000)),
                    r#"{"slug":"cal1-big","title":"<17000 x>"}"#.into(),
                )),
                _ => same(new_page),
            };
            s.wanted = match label {
                "cross-tenant" | "toggle-off" => 404,
                "invalid-input" | "empty" | "oversize" => 400,
                "slug-invalid" | "bad-id" | "scalar" | "null-body" | "duplicate-slug" => 500,
                _ => 200,
            };
            s.first = label == "repeat";
            if label == "repeat" {
                s.wanted = 500;
            }
        }
        "pages-delete" => {
            s.method = "DELETE";
            s.pattern = "/booking/pages";
            s.path = "/api/booking/pages".into();
            s.query = match label {
                "invalid-input" => "".into(),
                "bad-id" => "?id=abc".into(),
                "cross-tenant" => format!("?id={}", w.page_b),
                _ => format!("?id={}", w.page_off),
            };
            s.first = label == "repeat";
            s.wanted = match label {
                "invalid-input" | "bad-id" => 400,
                "cross-tenant" | "repeat" | "toggle-off" => 404,
                _ => 200,
            };
        }
        "public-meta" => {
            s.pattern = "/public/booking/{slug}";
            s.caller = Caller::Nobody;
            let slug = match label {
                "unknown-slug" => "cal1-missing",
                "disabled" => "cal1-a-off",
                "folded" => "CAL1-A-PAGE",
                "suffix-quirk" => "slots",
                _ => "cal1-a-page",
            };
            s.path = format!("/api/public/booking/{slug}");
            s.wanted = if label == "suffix-quirk" {
                400
            } else {
                bad.max(200)
            };
            if label == "suffix-quirk" {
                s.wanted = 400;
            }
        }
        "public-slots" => {
            s.pattern = "/public/booking/{slug}/slots";
            s.caller = Caller::Nobody;
            let slug = match label {
                "unknown-slug" => "cal1-missing",
                "disabled" => "cal1-a-off",
                _ => "cal1-a-page",
            };
            s.path = format!("/api/public/booking/{slug}/slots");
            s.query = match label {
                "invalid-input" => "".into(),
                "bad-date" => "?from=nope&to=2026-12-31".into(),
                "range" => format!("?from={d}&to=2030-01-01"),
                "reversed" => format!("?from=2030-01-02&to={d}"),
                _ => format!("?from={d}&to={d}"),
            };
            s.wanted = match label {
                "invalid-input" | "range" | "reversed" => 400,
                "bad-date" => 500,
                "unknown-slug" | "disabled" | "toggle-off" => 404,
                _ => 200,
            };
        }
        "public-book" => {
            s.method = "POST";
            s.pattern = "/public/booking/{slug}/book";
            s.caller = Caller::Nobody;
            let slug = match label {
                "unknown-slug" => "cal1-missing",
                "disabled" => "cal1-a-off",
                "unicode-title" => "cal1-a-uni",
                _ => "cal1-a-page",
            };
            s.path = format!("/api/public/booking/{slug}/book");
            let start = format!("{d}T10:00:00Z");
            let full = |email: &str| {
                format!(
                    r#"{{"start":"{start}","email":"{email}","name":"Booker One","answers":{{"q1":"Roadmap","extra":"<x>"}}}}"#
                )
            };
            s.body = match label {
                "invalid-input" => same("{\"start\":"),
                "missing-answer" => same(&format!(
                    r#"{{"start":"{start}","email":"booker@cal1-external.test","name":"B","answers":{{}}}}"#
                )),
                "honeypot" => same(&format!(
                    r#"{{"start":"{start}","email":"bot@cal1-external.test","website":"http://spam.test","answers":{{"q1":"x"}}}}"#
                )),
                "oversize" => Some((
                    format!(r#"{{"start":"{start}","name":"{}"}}"#, "n".repeat(17000)),
                    format!(r#"{{"start":"{start}","name":"<17000 n>"}}"#),
                )),
                "bad-start" => same(
                    r#"{"start":"tomorrow","email":"booker@cal1-external.test","name":"B","answers":{"q1":"x"}}"#,
                ),
                "no-answers-field" => same(&format!(
                    r#"{{"start":"{d}T11:00:00Z","email":"booker@cal1-external.test","name":"B"}}"#
                )),
                "null-name-folded" => same(&format!(
                    r#"{{"START":"{start}","Email":"booker@cal1-external.test","NAME":null,"answers":{{"q1":null}}}}"#
                )),
                "unparseable-email" => same(&full("weird..dots@cal1-external.test")),
                "type-error" => same(r#"{"start":5}"#),
                "unicode-title" => same(&full("booker@cal1-external.test")),
                _ => same(&full("Booker@Cal1-External.test")),
            };
            s.wanted = match label {
                "invalid-input" | "missing-answer" | "type-error" | "no-answers-field"
                | "null-name-folded" => 400,
                "oversize" => 413,
                "unknown-slug" | "disabled" | "toggle-off" => 404,
                "repeat" | "bad-start" => 409,
                _ => 200,
            };
            s.first = label == "repeat";
        }
        "public-confirm" => {
            s.method = "POST";
            s.pattern = "/public/booking/confirm";
            s.path = "/api/public/booking/confirm".into();
            s.caller = Caller::Nobody;
            let token = if label == "unicode-title" {
                TOKEN_VERIFY_UNI
            } else {
                TOKEN_VERIFY
            };
            s.body = match label {
                "invalid-input" => same("[1,2]"),
                "unknown-token" => same(r#"{"token":"nope"}"#),
                _ => same(&format!(r#"{{"token":"{token}"}}"#)),
            };
            s.first = label == "repeat";
            s.wanted = match label {
                "invalid-input" => 400,
                "unknown-token" | "repeat" => 409,
                "toggle-off" => 404,
                _ => 200,
            };
            s.mail = if matches!(label, "success" | "unicode-title") {
                2
            } else {
                0
            };
        }
        "public-cancel" => {
            s.method = "POST";
            s.pattern = "/public/booking/cancel";
            s.path = "/api/public/booking/cancel".into();
            s.caller = Caller::Nobody;
            s.body = match label {
                "invalid-input" => same("{"),
                "unknown-token" => same(r#"{"token":"nope"}"#),
                _ => same(&format!(r#"{{"token":"{TOKEN_CANCEL}"}}"#)),
            };
            s.first = label == "repeat";
            s.wanted = match label {
                "invalid-input" => 400,
                "unknown-token" | "repeat" => 409,
                "toggle-off" => 404,
                _ => 200,
            };
        }
        "free-busy" => {
            s.method = "POST";
            s.pattern = "/calendar/free-busy";
            s.path = "/api/calendar/free-busy".into();
            let window = format!(r#""start":"{d}T00:00:00Z","end":"{d}T23:59:59Z""#);
            let cal = |id: i64| id.to_string();
            let own = format!(r#"{{"user_ids":[{}],{window}}}"#, cal(w.cal_a));
            let recorded = |t: &str| {
                t.replace(&w.cal_a.to_string(), "<cal-a>")
                    .replace(&w.cal_b.to_string(), "<cal-b>")
                    .replace(&w.room.to_string(), "<room>")
            };
            s.body = match label {
                "cross-tenant" => {
                    s.sharing_defaults = true;
                    let t = format!(r#"{{"user_ids":[{}],{window}}}"#, cal(w.cal_b));
                    Some((t.clone(), recorded(&t)))
                }
                "open-by-default" => {
                    let t = format!(r#"{{"user_ids":[{}],{window}}}"#, cal(w.cal_b));
                    Some((t.clone(), recorded(&t)))
                }
                "rooms" => {
                    let t = format!(
                        r#"{{"user_ids":[{},0],"room_ids":[{}],{window}}}"#,
                        cal(w.cal_a),
                        w.room
                    );
                    Some((t.clone(), recorded(&t)))
                }
                "unknown-ids" => same(&format!(r#"{{"user_ids":[1],{window}}}"#)),
                "invalid-input" => same("{"),
                "no-entities" => same(&format!(r#"{{{window}}}"#)),
                "too-many" => {
                    let ids: Vec<String> = (1..=101).map(|n| n.to_string()).collect();
                    Some((
                        format!(r#"{{"user_ids":[{}],{window}}}"#, ids.join(",")),
                        format!(r#"{{"user_ids":[<101 ids>],{window}}}"#),
                    ))
                }
                "missing-start" => same(r#"{"user_ids":[1],"end":"2030-01-01T00:00:00Z"}"#),
                "missing-end" => same(r#"{"user_ids":[1],"start":"2030-01-01T00:00:00Z"}"#),
                "bad-start" => {
                    same(r#"{"user_ids":[1],"start":"soon","end":"2030-01-01T00:00:00Z"}"#)
                }
                "bad-end" => same(
                    r#"{"user_ids":[1],"start":"2030-01-01T00:00:00Z","end":"2030-13-01T00:00:00Z"}"#,
                ),
                "end-day" => same(
                    r#"{"user_ids":[1],"start":"2030-01-01T00:00:00Z","end":"2030-02-30T00:00:00Z"}"#,
                ),
                "extra-text" => same(
                    r#"{"user_ids":[1],"start":"2030-01-01T00:00:00Zjunk","end":"2031-01-01T00:00:00Z"}"#,
                ),
                "reversed" => same(
                    r#"{"user_ids":[1],"start":"2030-01-02T00:00:00Z","end":"2030-01-01T00:00:00Z"}"#,
                ),
                "window" => same(
                    r#"{"user_ids":[1],"start":"2030-01-01T00:00:00Z","end":"2031-06-01T00:00:00Z"}"#,
                ),
                "type-error" => same(r#"{"user_ids":["a"]}"#),
                "fractional-offset" => same(&format!(
                    r#"{{"user_ids":[{}],"start":"{d}T01:00:00.5+01:00","end":"{d}T23:59:59,25-02:30"}}"#,
                    cal(w.cal_a)
                )),
                _ => Some((own.clone(), recorded(&own))),
            };
            s.wanted = if matches!(
                label,
                "invalid-input"
                    | "no-entities"
                    | "too-many"
                    | "missing-start"
                    | "missing-end"
                    | "bad-start"
                    | "bad-end"
                    | "end-day"
                    | "extra-text"
                    | "reversed"
                    | "window"
                    | "type-error"
            ) {
                400
            } else {
                200
            };
        }
        "subs-list" => {
            s.pattern = "/calendar/subscriptions";
            s.path = "/api/calendar/subscriptions".into();
            if label == "cross-tenant" {
                s.caller = Caller::B;
            }
            if label == "invalid-input" {
                s.query = "?limit=-1&q=%00".into();
            }
        }
        "subs-delete" => {
            s.method = "DELETE";
            s.pattern = "/calendar/subscriptions/{id}";
            let id = match label {
                "invalid-input" => "abc".to_string(),
                "cross-tenant" => w.sub_b.to_string(),
                "missing" => "999999999".into(),
                _ => w.sub_a.to_string(),
            };
            s.path = format!("/api/calendar/subscriptions/{id}");
            s.first = label == "repeat";
            s.wanted = match label {
                "invalid-input" => 400,
                "cross-tenant" | "repeat" | "missing" => 404,
                _ => 204,
            };
        }
        "subs-create" => {
            s.method = "POST";
            s.pattern = "/calendar/subscriptions";
            s.path = "/api/calendar/subscriptions".into();
            s.body = match label {
                "invalid-input" => same("{"),
                // Identity fields in the body name no one: the row is the caller's.
                "cross-tenant" => same(&format!(
                    r#"{{"url":"https://feeds.example.org/c.ics","name":"Mine","user_id":1,"calendar_id":{},"calendarId":"{}"}}"#,
                    w.cal_a, w.cal_a
                )),
                "no-url" => same(r#"{"name":"x"}"#),
                "private-url" => same(r#"{"url":"http://127.0.0.1/cal.ics"}"#),
                "bad-scheme" => same(r#"{"url":"ftp://feeds.example.org/c.ics"}"#),
                "webcal" => same(
                    r#"{"url":"  webcal://feeds.example.org/c.ics?a=1&b=2 ","name":"  <My> feed  "}"#,
                ),
                "long-name" => same(&format!(
                    r#"{{"url":"https://feeds.example.org/c.ics","name":"{}"}}"#,
                    "n".repeat(250)
                )),
                _ => same(r#"{"url":"https://feeds.example.org/c.ics","name":"Team"}"#),
            };
            if label == "cross-tenant" {
                s.caller = Caller::B;
            }
            s.first = label == "repeat";
            s.wanted = match label {
                "invalid-input" | "no-url" | "private-url" | "bad-scheme" => 400,
                _ => 201,
            };
        }
        other => panic!("unknown F17 route {other}"),
    }
    s
}

fn domain_names(a: &str, b: &str) -> [(String, &'static str); 2] {
    [(a.to_owned(), "host-a.test"), (b.to_owned(), "host-b.test")]
}

/// Replace a whole digit run when it is a known run-specific id.
fn mask_ids(text: &str, ids: &[(i64, String)]) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            let run = &text[start..i];
            match run
                .parse::<i64>()
                .ok()
                .filter(|_| run.len() >= 5)
                .and_then(|n| ids.iter().find(|(id, _)| *id == n))
            {
                Some((_, label)) => out.push_str(label),
                None => out.push_str(run),
            }
        } else {
            let ch = text[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

fn mask_numbers(v: &mut Value, ids: &[(i64, String)]) {
    match v {
        Value::Number(n) => {
            if let Some((_, label)) = n
                .as_i64()
                .filter(|n| *n >= 100000)
                .and_then(|n| ids.iter().find(|(id, _)| *id == n))
            {
                *v = Value::String(label.clone());
            }
        }
        Value::Array(xs) => xs.iter_mut().for_each(|x| mask_numbers(x, ids)),
        Value::Object(m) => m.iter_mut().for_each(|(_, x)| mask_numbers(x, ids)),
        _ => {}
    }
}

fn mask_value(v: &mut Value, f: &dyn Fn(&str) -> String) {
    match v {
        Value::String(s) => *s = f(s),
        Value::Array(xs) => xs.iter_mut().for_each(|x| mask_value(x, f)),
        Value::Object(m) => m.iter_mut().for_each(|(_, x)| mask_value(x, f)),
        _ => {}
    }
}

async fn rows(c: &tokio_postgres::Client, sql: &str) -> Result<Vec<Value>, BoxError> {
    c.query(sql, &[])
        .await?
        .iter()
        .map(|r| serde_json::from_str(&r.get::<_, String>(0)).map_err(Into::into))
        .collect()
}

async fn snapshot(c: &tokio_postgres::Client, w: &World) -> Result<Value, BoxError> {
    let mailboxes = format!("({},{})", w.a.mailbox, w.b.mailbox);
    let who = format!(
        "CASE x.mailbox_id WHEN {} THEN 'a' WHEN {} THEN 'b' END",
        w.a.mailbox, w.b.mailbox
    );
    let exp = "CASE WHEN x.verify_expires_at > now() THEN 'future' ELSE 'past' END";
    Ok(json!({
        "booking_pages": rows(c, &format!("SELECT jsonb_build_object('owner',{who},'slug',slug,'title',title,'description',description,'duration',duration_minutes,'buffer',buffer_minutes,'max_per_day',max_per_day,'min_notice',min_notice_minutes,'max_advance',max_advance_days,'availability',availability,'questions',questions,'timezone',timezone,'enabled',enabled)::text FROM booking_pages x WHERE mailbox_id IN {mailboxes} ORDER BY slug")).await?,
        "booking_requests": rows(c, &format!("SELECT jsonb_build_object('owner',{who},'page',(SELECT slug FROM booking_pages p WHERE p.id=x.page_id),'status',status,'email',booker_email,'name',booker_name,'answers',answers,'slot_start',slot_start,'slot_end',slot_end,'verify',CASE WHEN verify_token_hash LIKE 'used:%' THEN 'used' ELSE 'open' END,'expires',{exp},'cancel',CASE WHEN cancel_token_hash IS NULL THEN 'none' WHEN cancel_token_hash LIKE 'used:%' THEN 'used' ELSE 'open' END,'event',event_id IS NOT NULL,'ip',host(created_ip))::text FROM booking_requests x WHERE mailbox_id IN {mailboxes} ORDER BY slot_start, booker_email")).await?,
        "calendar_events": rows(c, &format!("SELECT jsonb_build_object('calendar',(SELECT name FROM calendars c WHERE c.id=e.calendar_id),'title',title,'description',description,'start',start_at,'end',end_at,'timezone',timezone,'status',status,'meeting',is_meeting,'organizer',organizer_email,'organizer_name',organizer_name,'sequence',sequence,'state',jmap_state,'attendees',(SELECT coalesce(jsonb_agg(jsonb_build_object('email',email,'name',name,'role',role,'status',status,'rsvp',rsvp) ORDER BY email),'[]') FROM event_attendees ea WHERE ea.event_id=e.id))::text FROM calendar_events e WHERE calendar_id IN (SELECT id FROM calendars WHERE mailbox_id IN {mailboxes}) ORDER BY title, start_at")).await?,
        "calendars": rows(c, &format!("SELECT jsonb_build_object('owner',{who},'name',name,'color',color,'default',is_default,'state',jmap_state,'timezone',timezone)::text FROM calendars x WHERE mailbox_id IN {mailboxes} ORDER BY name")).await?,
        "calendar_subscriptions": rows(c, &format!("SELECT jsonb_build_object('owner',CASE s.user_id WHEN {} THEN 'a' WHEN {} THEN 'b' END,'calendar',(SELECT name FROM calendars c WHERE c.id=s.calendar_id),'url',url,'refresh',refresh_interval_minutes,'fetched',last_fetch_at IS NOT NULL,'etag',etag)::text FROM calendar_subscriptions s WHERE user_id IN ({},{}) ORDER BY url, calendar_id", w.a.user, w.b.user, w.a.user, w.b.user)).await?,
    }))
}

fn when_text(text: &str, d: &str) -> String {
    text.replace(d, "<D>")
}

pub async fn run(route: &str, label: &str, fault: Option<&str>) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run_inner(route, label, fault).await
}

fn day_after_next_monday() -> String {
    use chrono::Datelike;
    let mut day = chrono::Utc::now().date_naive() + chrono::Duration::days(10);
    while day.weekday() != chrono::Weekday::Mon {
        day += chrono::Duration::days(1);
    }
    day.format("%Y-%m-%d").to_string()
}

async fn run_inner(route: &str, label: &str, fault: Option<&str>) -> Result<(), BoxError> {
    let mutant = label.ends_with("-status-mutant");
    let label = label.strip_suffix("-status-mutant").unwrap_or(label);
    let Some(db) = Db::for_case("cal1-http") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    owner
        .batch_execute("DELETE FROM booking_pages WHERE slug LIKE 'cal1-%'")
        .await?;
    let a = fixture::account(&owner, "cal1-owner").await?;
    let b = fixture::account(&owner, "cal1-other").await?;
    let domain_of = |id: i64| {
        let owner = &owner;
        async move {
            Ok::<String, BoxError>(
                owner
                    .query_one("SELECT name FROM domains WHERE id=$1", &[&id])
                    .await?
                    .get(0),
            )
        }
    };
    let domains = domain_names(&domain_of(a.domain).await?, &domain_of(b.domain).await?);
    let names = |text: &str| {
        let mut out = text.to_owned();
        for (domain, name) in &domains {
            out = out.replace(domain.as_str(), name);
        }
        out
    };
    let d = day_after_next_monday();
    let one = |sql: String| {
        let owner = &owner;
        async move { Ok::<i64, BoxError>(owner.query_one(sql.as_str(), &[]).await?.get(0)) }
    };
    // Fixed ids keep the goldens free of run-specific numbers; new rows draw
    // from sequences moved well past them.
    // Each table gets its own floor so a new calendar and the subscription that
    // created it never share a number (the mask labels ids by value).
    for (n, sequence) in [
        "booking_pages",
        "calendars",
        "calendar_events",
        "booking_requests",
        "calendar_subscriptions",
    ]
    .into_iter()
    .enumerate()
    {
        let floor = 960000 + n * 10000;
        owner.batch_execute(&format!("SELECT setval(pg_get_serial_sequence('{sequence}','id'), greatest({floor}, (SELECT last_value FROM {sequence}_id_seq)))")).await?;
    }
    let cal_a = one(format!("INSERT INTO calendars(id,mailbox_id,name,color,is_default) VALUES(952001,{},'cal1-a-default','#111111',true) RETURNING id", a.mailbox)).await?;
    let cal_b = one(format!("INSERT INTO calendars(id,mailbox_id,name,color,is_default) VALUES(952002,{},'cal1-b-default','#222222',true) RETURNING id", b.mailbox)).await?;
    let room = one(format!("INSERT INTO calendars(id,mailbox_id,name,color,resource_type) VALUES(952003,{},'cal1-room','#333333','room') RETURNING id", a.mailbox)).await?;
    let availability = r#"[{"dow":1,"start":"09:00","end":"12:00"}]"#;
    let page = |id: i64, mailbox: i64, slug: &str, title: &str, enabled: bool| {
        format!("INSERT INTO booking_pages(id,mailbox_id,slug,title,description,duration_minutes,min_notice_minutes,max_advance_days,availability,questions,enabled) VALUES({id},{mailbox},'{slug}','{title}','desc',60,0,365,'{availability}','[{{\"id\":\"q1\",\"label\":\"Topic\",\"required\":true}}]',{enabled}) RETURNING id")
    };
    let page_a = one(page(951001, a.mailbox, "cal1-a-page", "Intro call", true)).await?;
    let page_off = one(page(951002, a.mailbox, "cal1-a-off", "Hidden call", false)).await?;
    let page_b = one(page(951003, b.mailbox, "cal1-b-page", "Other call", true)).await?;
    let page_uni = one(page(
        951004,
        a.mailbox,
        "cal1-a-uni",
        "Caf\u{e9} chat \u{2615}",
        true,
    ))
    .await?;
    let _ = page_uni;
    let sub = |id: i64, user: i64, mailbox: i64, name: &str, url: &str| {
        format!("WITH c AS (INSERT INTO calendars(id,mailbox_id,name,color) VALUES({id}-954001+953001,{mailbox},'{name}','#6366f1') RETURNING id) INSERT INTO calendar_subscriptions(id,user_id,calendar_id,url,last_fetch_at,last_status) OVERRIDING SYSTEM VALUE SELECT {id},{user},id,'{url}','2026-10-01T00:00:00Z','ok' FROM c RETURNING id")
    };
    let sub_a = one(sub(
        954001,
        a.user,
        a.mailbox,
        "cal1-sub-a",
        "https://feeds.example.org/a.ics",
    ))
    .await?;
    let sub_b = one(sub(
        954002,
        b.user,
        b.mailbox,
        "cal1-sub-b",
        "https://feeds.example.org/b.ics",
    ))
    .await?;
    let w = World {
        a: a.clone(),
        b: b.clone(),
        d: d.clone(),
        page_a,
        page_off,
        page_b,
        sub_a,
        sub_b,
        cal_a,
        cal_b,
        room,
    };
    let spec = spec(route, label, &w);

    // Seeds that depend on the route.
    let a_email: String = owner
        .query_one("SELECT email FROM mailboxes WHERE id=$1", &[&a.mailbox])
        .await?
        .get(0);
    let pending = |token: &str, slot: &str, page: i64, mailbox: i64| {
        format!("INSERT INTO booking_requests(page_id,mailbox_id,booker_email,booker_name,slot_start,slot_end,status,verify_token_hash,verify_expires_at) VALUES({page},{mailbox},'booker@cal1-external.test','Booker One','{d}T{slot}Z','{d}T{slot}Z'::timestamptz+interval '1 hour','pending','{}',now()+interval '1 day')", sha(token))
    };
    if route == "public-confirm"
        && label != "unknown-token"
        && label != "invalid-input"
        && label != "toggle-off"
    {
        let (token, page) = if label == "unicode-title" {
            (TOKEN_VERIFY_UNI, page_uni)
        } else {
            (TOKEN_VERIFY, page_a)
        };
        owner
            .batch_execute(&pending(token, "10:00:00", page, a.mailbox))
            .await?;
    }
    if route == "public-cancel"
        && label != "unknown-token"
        && label != "invalid-input"
        && label != "toggle-off"
    {
        owner.batch_execute(&format!("INSERT INTO booking_requests(page_id,mailbox_id,booker_email,booker_name,slot_start,slot_end,status,verify_token_hash,verify_expires_at,cancel_token_hash) VALUES({page_a},{},'booker@cal1-external.test','Booker One','{d}T10:00:00Z','{d}T11:00:00Z','confirmed','used:x',now()+interval '1 day','{}')", a.mailbox, sha(TOKEN_CANCEL))).await?;
        let event = one(format!("INSERT INTO calendar_events(calendar_id,uid,title,start_at,end_at,is_meeting,organizer_email) VALUES({cal_a},'cal1-booked@x','Intro call — Booker One','{d}T10:00:00Z','{d}T11:00:00Z',true,'{a_email}') RETURNING id")).await?;
        owner
            .batch_execute(&format!(
                "UPDATE booking_requests SET event_id={event} WHERE cancel_token_hash='{}'",
                sha(TOKEN_CANCEL)
            ))
            .await?;
    }
    if route == "free-busy" {
        for (cal, uid, title) in [
            (cal_a, "cal1-busy-a@x", "A busy"),
            (cal_b, "cal1-busy-b@x", "B busy"),
            (room, "cal1-busy-room@x", "Room busy"),
        ] {
            owner.batch_execute(&format!("INSERT INTO calendar_events(calendar_id,uid,title,start_at,end_at) VALUES({cal},'{uid}','{title}','{d}T10:00:00Z','{d}T11:30:00Z')")).await?;
        }
    }
    let originals: Vec<(String, bool)> = owner
        .query("SELECT key, enabled FROM feature_toggles WHERE key IN ('feature.booking_pages','sharing.defaults')", &[])
        .await?
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    let set_toggle = |key: &'static str, on: bool| {
        let owner = &owner;
        async move {
            owner.execute("INSERT INTO feature_toggles(key,enabled,description) VALUES($1,$2,'cal1 oracle') ON CONFLICT (key) DO UPDATE SET enabled=EXCLUDED.enabled", &[&key, &on]).await
        }
    };
    set_toggle("feature.booking_pages", !spec.toggle_off).await?;
    set_toggle("sharing.defaults", spec.sharing_defaults).await?;
    let queue_before: i64 = owner
        .query_one("SELECT coalesce(max(id),0) FROM outbound_queue", &[])
        .await?
        .get(0);
    let audit_start: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let receipts = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F17'",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect::<Vec<_>>();
    let saved = fault_plant(&owner, fault).await?;

    let users: Vec<(i64, String)> = vec![
        (a.user, "<user-a>".into()),
        (b.user, "<user-b>".into()),
        (a.mailbox, "<mailbox-a>".into()),
        (b.mailbox, "<mailbox-b>".into()),
    ];
    let kicks = Arc::new(Kicks::default());
    let result = async {
        let (s3, captures) = mail::endpoint().await;
        let go = common::go_oracle::start_named_with_env(
            &db,
            s3,
            "gofree-cal1-http",
            &[
                ("BOOKING_WRITE_RATE_LIMIT", "100000".into()),
                ("BOOKING_READ_RATE_LIMIT", "100000".into()),
            ],
        )
        .await?;
        let recording = go.is_some();
        let patient = std::time::Duration::from_secs(30);
        let make = |dsn: &str| {
            ScopedExecutor::from_dsn_with(
                dsn,
                4,
                setjoin_pg::Timeouts { pool_wait: patient, create: patient, statement: patient },
            )
            .map(|e| e.with_audit_keys("22".repeat(32), String::new()))
            .map_err(|e| e.0)
        };
        let exec = make(db.app.as_deref().unwrap_or(&db.dsn))?;
        let worker = make(&db.dsn)?;
        let route_impl = CalendarRoute {
            exec,
            worker,
            queue: Some(setjoin_pg::workers::WorkerDatabase::new(&db.dsn)?),
            keys: Arc::new(common::recovery_keys()),
            issuer: "mailserver".into(),
            store: Some(Arc::new(setjoin_gateway::recovery_worker::S3Store::new(
                &format!("http://{s3}"),
                "mailblobs",
                "test-access",
                "test-secret",
            )?)),
            public_base: "https://mail.test".into(),
            kick: Some(Arc::new(SharedKicks(kicks.clone()))),
        };
        let adapter = Probe { inner: route_impl, changed_status: mutant };
        let mut inventory: Value = serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().ok_or("routes")? {
            if r["family"] == "F17" && r["slice"] == "calendar-booking" {
                r["state"] = json!(if recording { "OFF" } else { "ON" });
                r["upstream"] = json!(if recording { "go-mail" } else { "local-rust" });
                r["oracle_commands"] = json!([""]);
            }
        }
        let gateway = Gateway::new(
            Config {
                upstream: go.as_ref().map(|g| format!("http://{}", g.address).parse()).transpose()?,
                trusted_proxies: TrustedProxies::parse("")?,
                upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
                edge_limit: None,
            },
            RouteTable::proxy_all().with(adapter),
        )?
        .with_inventory(&inventory.to_string())?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(gateway.serve(listener));
        let token_for = |caller: Caller| match caller {
            Caller::A => Some(common::recovery_token(a.user)),
            Caller::B => Some(common::recovery_token(b.user)),
            Caller::Nobody => None,
        };
        let send = |body: String| {
            let uri = format!("{}{}", spec.path, spec.query);
            let token = token_for(spec.caller);
            let method = spec.method;
            async move {
                let mut request = Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("host", "mail.test")
                    .header("origin", "http://mail.test")
                    .header("content-type", "application/json")
                    .header("x-request-id", "gofree-cal1-oracle");
                if let Some(token) = token {
                    request = request.header("authorization", format!("Bearer {token}"));
                }
                Ok::<_, BoxError>(common::send(address, request.body(common::full(body))?).await)
            }
        };
        let sent = spec.body.as_ref().map(|(s, _)| s.clone()).unwrap_or_default();
        if spec.first {
            let first = send(sent.clone()).await?;
            let status = first.status().as_u16();
            let data = common::body_bytes(first).await;
            // The slot-taken case needs its rival to succeed; a repeated page
            // create keeps its first answer out of the golden.
            let first_wanted = if matches!(route, "public-book") { 200 } else if route == "pages-put" { 200 } else if route == "public-confirm" || route == "public-cancel" || route == "subs-delete" || route == "pages-delete" { if route == "subs-delete" { 204 } else { 200 } } else if route == "subs-create" { 201 } else { 200 };
            if recording && status != first_wanted {
                return Err(format!("initial {route}: {status} {data:?}").into());
            }
            if route == "public-confirm" { mail::settle(&owner, queue_before, 2).await?; }
            if route == "public-book" { /* synchronous mail */ }
        }
        let before = snapshot(&owner, &w).await?;
        let last: i64 = owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[]).await?.get(0);
        let queue_mark: i64 = owner.query_one("SELECT coalesce(max(id),0) FROM outbound_queue", &[]).await?.get(0);
        let capture_mark = captures.lock().unwrap().len();
        let mut notices = db.listen(&format!("calendar:{}", a.mailbox)).await?;
        let mut notices_b = db.listen(&format!("calendar:{}", b.mailbox)).await?;
        let response = send(sent.clone()).await?;
        let status = response.status().as_u16();
        let mut headers = Map::new();
        for name in response.headers().keys() {
            headers.insert(name.to_string(), json!(response.headers().get_all(name).iter().map(|v| v.to_str().unwrap().to_owned()).collect::<Vec<_>>()));
        }
        let raw = String::from_utf8(common::body_bytes(response).await.to_vec())?;
        if recording && status != spec.wanted {
            return Err(format!("Go {route}/{label}: expected {}, got {status}: {raw}", spec.wanted).into());
        }
        // Mail leaves detached from the confirm request.
        let expected_mail = if status == 200 && matches!(route, "public-confirm") { spec.mail } else { 0 };
        if expected_mail > 0 {
            mail::settle(&owner, queue_mark, expected_mail).await?;
        }
        let after = snapshot(&owner, &w).await?;
        let mut audit: Vec<Value> = owner
            .query("SELECT to_jsonb(a)::text FROM admin_audit_log a WHERE id>$1 ORDER BY id", &[&last])
            .await?
            .iter()
            .map(|r| serde_json::from_str(&r.get::<_, String>(0)))
            .collect::<Result<_, _>>()?;
        for row in &mut audit {
            row["id"] = json!("<audit>");
        }
        let mut notify = vec![];
        for (channel, listener) in [("a", &mut notices), ("b", &mut notices_b)] {
            for event in listener.drain(&owner).await? {
                let payload: Value = serde_json::from_str(&event).unwrap_or(Value::String(event));
                notify.push(json!({"mailbox":channel,"payload":payload}));
            }
        }
        // Ids created by this case, labelled by what they are.
        let mut ids: Vec<(i64, String)> = users.clone();
        for (id, label) in [(page_a, "<page-a>"), (page_off, "<page-off>"), (page_b, "<page-b>"), (951004, "<page-uni>"), (sub_a, "<sub-a>"), (sub_b, "<sub-b>"), (953001, "<sub-cal-a>"), (953002, "<sub-cal-b>"), (cal_a, "<cal-a>"), (cal_b, "<cal-b>"), (room, "<room>")] {
            ids.push((id, label.into()));
        }
        for (sql, label) in [
            ("SELECT id FROM booking_pages WHERE slug IN ('cal1-new-page','cal1-big') ORDER BY id", "<new-page>"),
            ("SELECT id FROM booking_requests WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE id IN (SELECT mailbox_id FROM booking_pages WHERE slug LIKE 'cal1-%')) ORDER BY id", "<request>"),
            ("SELECT e.id FROM calendar_events e JOIN calendars c ON c.id=e.calendar_id WHERE c.mailbox_id IN (SELECT mailbox_id FROM booking_pages WHERE slug LIKE 'cal1-%') ORDER BY e.id", "<event>"),
            ("SELECT id FROM calendars WHERE mailbox_id IN (SELECT mailbox_id FROM booking_pages WHERE slug LIKE 'cal1-%') ORDER BY id", "<new-calendar>"),
            ("SELECT id FROM calendar_subscriptions WHERE url LIKE '%example.org/c.ics%' ORDER BY id", "<new-sub>"),
        ] {
            for (n, row) in owner.query(sql, &[]).await?.iter().enumerate() {
                let id: i64 = row.get(0);
                if !ids.iter().any(|(known, _)| *known == id) {
                    ids.push((id, format!("{label}{}", if n == 0 { String::new() } else { format!("-{}", n + 1) })));
                }
            }
        }
        for row in &mut notify {
            mask_numbers(row, &ids);
        }
        let mask = |text: &str| when_text(&names(&mask_ids(text, &ids)), &d);
        let text = mask(&raw);
        // The cancel token is minted per request; its hash is what the row keeps.
        let text = if route == "public-confirm" && status == 200 { mask_cancel_token(&text)? } else { text };
        if let Some(date) = headers.get_mut("date") { *date = json!(["<timestamp>"]); }
        if let Some(length) = headers.get_mut("content-length") {
            if length[0] != raw.len().to_string() { return Err("bad wire length".into()); }
            *length = json!([text.len().to_string()]);
        }
        let mail_observation = mail::observe(&owner, queue_mark, &captures, capture_mark, &names, &d).await?;
        let kick_note = kicks.0.lock().unwrap().iter().map(|(_, _, url)| url.clone()).collect::<Vec<_>>();
        let mut snapshots = (before, after);
        for s in [&mut snapshots.0, &mut snapshots.1] {
            mask_value(s, &mask);
            // Run-specific numbers live under these keys only as text; timestamps of
            // the committed rows are masked by day.
        }
        let effects = json!([{"table":"f17","before":snapshots.0,"after":snapshots.1}]);
        for row in &mut audit {
            mask_value(row, &mask);
        }
        let mut request = json!({"method":spec.method,"path":spec.pattern,"external_path":format!("/api{}",spec.pattern)});
        if let Some((_, recorded)) = &spec.body {
            request["body"] = json!(when_text(recorded, &d));
        }
        if !spec.query.is_empty() {
            request["query"] = json!(mask(&spec.query));
        }
        if let Value::String(path) = json!(spec.path.clone()) {
            let concrete = mask(&path);
            if concrete != format!("/api{}", spec.pattern) {
                request["concrete_path"] = json!(concrete);
            }
        }
        let mut observation = json!({"request":request,"response":{"status":status,"headers":headers,"body":text},"effects":effects,"audit":audit,"notify":notify});
        if !mail_observation.is_empty() {
            observation["mail"] = Value::Array(mail_observation);
        }
        let _ = (audit_start, kick_note);
        if !recording {
            let metrics = common::send(address, Request::get("/_gateway/metrics").body(common::full(""))?).await;
            let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            if !metrics.lines().any(|l| l == "setjoin_gateway_proxied_to_go_by_family_total{family=\"F17\"} 0") {
                return Err(format!("F17 replay forwarded to Go: {metrics}").into());
            }
        }
        server.abort();
        let name = format!("{route}-{label}");
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/calendar/goldens");
        std::fs::create_dir_all(&dir)?;
        let file = dir.join(format!("{name}.json"));
        let row_file = dir.join(format!("{name}-row-effects.json"));
        let route_name = format!("{} {}", spec.method, spec.pattern);
        if recording {
            let source = std::env::var("GOFREE_GO_SOURCE")?;
            record(&file, &json!({"format":1,"route":route_name,"case":label,"go_source":source,"observation":observation}))?;
            if matches!(route, "pages-put" | "pages-delete" | "public-book" | "public-confirm" | "public-cancel" | "subs-delete" | "subs-create") {
            record(&row_file, &json!({"format":1,"route":route_name,"case":format!("{label}-row-effects"),"go_source":source,"effects":observation["effects"]}))?;
            }
        } else {
            let mut expected: Value = serde_json::from_slice(&std::fs::read(&file)?)?;
            // Historical Go recordings omitted the declared fixture-day mask only
            // in request metadata. Keep immutable files and their remaining bytes.
            if let Some(Value::String(body)) = expected.pointer_mut("/observation/request/body") {
                *body = when_text(body, "2026-11-16");
            }
            let compared = golden::compare(&expected["observation"], &observation);
            if mutant {
                let error = compared.err().ok_or("planted status mutant survived")?;
                if !error.contains("/response/status") { return Err(format!("mutant failed outside response status: {error}").into()); }
                eprintln!("MUTANT-REJECTED: {route_name} :: changed-status");
                return Ok(());
            }
            if let Some(fault) = fault {
                compared.err().ok_or("planted family fault survived")?;
                eprintln!("MUTANT-REJECTED: {route_name} :: {fault}");
                return Ok(());
            }
            compared?;
            if row_file.exists() {
                let expected: Value = serde_json::from_slice(&std::fs::read(row_file)?)?;
                golden::compare(&expected["effects"], &observation["effects"])?;
            }
            eprintln!("GOLDEN-REPLAY: {route_name} :: {label}");
        }
        Ok::<_, BoxError>(())
    }
    .await;
    // Cleanup runs on every path and touches only this case's rows.
    fault_restore(&owner, saved).await?;
    for (key, enabled) in &originals {
        owner
            .execute(
                "UPDATE feature_toggles SET enabled=$2 WHERE key=$1",
                &[key, enabled],
            )
            .await?;
    }
    for key in ["feature.booking_pages", "sharing.defaults"] {
        if !originals.iter().any(|(k, _)| k == key) {
            owner
                .execute("DELETE FROM feature_toggles WHERE key=$1", &[&key])
                .await?;
        }
    }
    owner.execute("DELETE FROM rust_operation_receipts WHERE family='F17' AND operation_id::text<>ALL($1)", &[&receipts]).await?;
    owner
        .batch_execute(&format!(
            "DELETE FROM outbound_queue WHERE id>{queue_before};\
         DELETE FROM calendar_subscriptions WHERE user_id IN ({},{});\
         DELETE FROM booking_requests WHERE mailbox_id IN ({},{});\
         DELETE FROM booking_pages WHERE mailbox_id IN ({},{});\
         DELETE FROM calendars WHERE id={room} OR mailbox_id IN ({},{});",
            a.user, b.user, a.mailbox, b.mailbox, a.mailbox, b.mailbox, a.mailbox, b.mailbox
        ))
        .await?;
    for account in [&a, &b] {
        common::remove_blob_account(&owner, account).await?;
    }
    owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE id>{audit_start}; COMMIT;")).await?;
    result
}

fn mask_cancel_token(text: &str) -> Result<String, BoxError> {
    let value: Value = serde_json::from_str(text)?;
    let token = value["cancelToken"].as_str().ok_or("cancelToken")?;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    if URL_SAFE_NO_PAD.decode(token)?.len() != 32 {
        return Err("bad cancel token entropy".into());
    }
    Ok(text.replace(token, "<cancel-token>"))
}

/// A planted fault that a faithful oracle must notice.
async fn fault_plant(
    c: &tokio_postgres::Client,
    fault: Option<&str>,
) -> Result<Vec<(String, String)>, BoxError> {
    let mut saved = vec![];
    let functions = match fault {
        Some("no-tenant-filter") => vec![("booking_page_list(bigint)", "CREATE OR REPLACE FUNCTION booking_page_list(p_mailbox_id BIGINT) RETURNS JSONB AS $$ SELECT COALESCE(jsonb_agg(jsonb_build_object('id', bp.id::TEXT, 'slug', bp.slug, 'title', bp.title, 'description', bp.description, 'durationMinutes', bp.duration_minutes, 'bufferMinutes', bp.buffer_minutes, 'maxPerDay', bp.max_per_day, 'minNoticeMinutes', bp.min_notice_minutes, 'maxAdvanceDays', bp.max_advance_days, 'availability', bp.availability, 'questions', bp.questions, 'timezone', bp.timezone, 'enabled', bp.enabled) ORDER BY bp.created_at), '[]'::JSONB) FROM booking_pages bp WHERE bp.slug LIKE 'cal1-%'; $$ LANGUAGE sql STABLE SECURITY DEFINER")],
        Some("no-notify") => vec![("app_notify(text,text)", "CREATE OR REPLACE FUNCTION app_notify(p_channel TEXT, p_payload TEXT) RETURNS VOID AS $$ BEGIN RETURN; END; $$ LANGUAGE plpgsql")],
        _ => vec![],
    };
    for (signature, replacement) in functions {
        let definition: String = c
            .query_one(
                &format!("SELECT pg_get_functiondef('{signature}'::regprocedure)"),
                &[],
            )
            .await?
            .get(0);
        saved.push((signature.to_owned(), definition));
        c.batch_execute(replacement).await?;
    }
    if fault == Some("double-bump") {
        c.batch_execute("CREATE OR REPLACE FUNCTION cal1_double_bump() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN IF NEW.jmap_state > OLD.jmap_state THEN NEW.jmap_state := NEW.jmap_state + 1; END IF; RETURN NEW; END $f$; CREATE TRIGGER cal1_double_bump BEFORE UPDATE ON calendars FOR EACH ROW EXECUTE FUNCTION cal1_double_bump()").await?;
        saved.push(("trigger".into(), String::new()));
    }
    Ok(saved)
}

async fn fault_restore(
    c: &tokio_postgres::Client,
    saved: Vec<(String, String)>,
) -> Result<(), BoxError> {
    for (signature, definition) in saved {
        if signature == "trigger" {
            c.batch_execute("DROP TRIGGER IF EXISTS cal1_double_bump ON calendars; DROP FUNCTION IF EXISTS cal1_double_bump()").await?;
        } else {
            c.batch_execute(&definition).await?;
        }
    }
    Ok(())
}

/// Verification mode compares immutable Go observations instead of rewriting them.
fn record(path: &std::path::Path, value: &Value) -> Result<(), BoxError> {
    if std::env::var_os("GOFREE_VERIFY_GO").is_some() {
        let mut expected: Value = serde_json::from_slice(&std::fs::read(path)?)?;
        if let Some(Value::String(body)) = expected.pointer_mut("/observation/request/body") {
            *body = when_text(body, "2026-11-16");
        }
        golden::compare(&expected, value)?;
        Ok(())
    } else {
        golden::record(path, value).map_err(Into::into)
    }
}
