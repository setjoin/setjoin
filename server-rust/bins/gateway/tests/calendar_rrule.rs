//! #465: End-to-end JMAP CalendarEvent/set RRULE validation and RFC 5545
//! recurrence expansion via JMAP `CalendarEvent/freeBusy` and HTTP
//! `POST /api/calendar/free-busy`.
mod common;

use common::BoxError;
use futures_util::FutureExt;
use hyper::Request;
use serde_json::{json, Value};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::{
    calendar::CalendarRoute,
    jmap::{JmapCommands, JmapRoute},
    Config, Gateway, RouteTable, TrustedProxies,
};
use std::sync::Arc;
use tokio::sync::Mutex;

static SERIAL: Mutex<()> = Mutex::const_new(());

struct Env {
    owner: Arc<tokio_postgres::Client>,
    addr: std::net::SocketAddr,
    server: tokio::task::JoinHandle<()>,
    account: fixture::Account,
    calendar_id: i64,
    token: String,
}

async fn with_env<F, Fut>(case_name: &str, f: F) -> Result<(), BoxError>
where
    F: FnOnce(Env) -> Fut,
    Fut: std::future::Future<Output = Result<(), BoxError>>,
{
    let _guard = SERIAL.lock().await;
    let Some(db) = Db::for_case(case_name) else {
        return Ok(());
    };
    let owner = Arc::new(db.connect().await?);
    let saved_caldav = owner
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.caldav'",
            &[],
        )
        .await?
        .map(|r| r.get::<_, bool>(0));
    owner
        .execute(
            "INSERT INTO feature_toggles(key,enabled) VALUES('feature.caldav',true) \
             ON CONFLICT(key) DO UPDATE SET enabled=true",
            &[],
        )
        .await?;
    let account = fixture::account(&owner, "cal-rrule-465").await?;
    let calendar_id: i64 = owner
        .query_one(
            "INSERT INTO calendars(mailbox_id,name,timezone,is_default) \
             VALUES($1,'RRULE 465','UTC',true) RETURNING id",
            &[&account.mailbox],
        )
        .await?
        .get(0);

    let exec = common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn), 4)?;
    let worker = common::patient_exec(&db.dsn, 2)?;
    let keys = Arc::new(common::recovery_keys());

    let jmap_route = JmapRoute(Arc::new(JmapCommands {
        services: None,
        worker: None,
        denylist: None,
        exec: exec.clone(),
        keys: keys.clone(),
        issuer: "mailserver".into(),
    }));
    let cal_route = CalendarRoute {
        exec,
        worker,
        queue: None,
        keys,
        issuer: "mailserver".into(),
        store: None,
        public_base: "https://mail.test".into(),
        kick: None,
    };

    let routes = RouteTable::proxy_all().with(jmap_route).with(cal_route);
    let gateway = Gateway::new(
        Config {
            upstream: None,
            trusted_proxies: TrustedProxies::parse("")?,
            upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
            edge_limit: None,
        },
        routes,
    )?
    .with_inventory(setjoin_gateway::inventory::BUNDLED)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(gateway.serve(listener));
    let token = common::recovery_token(account.user);

    let env = Env {
        owner: owner.clone(),
        addr,
        server,
        account: account.clone(),
        calendar_id,
        token,
    };
    let server_handle = env.server.abort_handle();
    let result = std::panic::AssertUnwindSafe(f(env)).catch_unwind().await;
    server_handle.abort();

    let _ = owner
        .execute("DELETE FROM calendars WHERE id=$1", &[&calendar_id])
        .await;
    if let Some(was_enabled) = saved_caldav {
        owner
            .execute(
                "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.caldav'",
                &[&was_enabled],
            )
            .await?;
    } else {
        owner
            .execute(
                "DELETE FROM feature_toggles WHERE key='feature.caldav'",
                &[],
            )
            .await?;
    }
    fixture::remove(&owner, &account).await?;

    match result {
        Ok(inner) => inner,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

async fn jmap_call(
    addr: std::net::SocketAddr,
    token: &str,
    body: Value,
) -> Result<Value, BoxError> {
    let req = Request::builder()
        .method("POST")
        .uri("/jmap")
        .header("host", "mail.test")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(common::full(body.to_string()))?;
    let resp = common::send(addr, req).await;
    let status = resp.status().as_u16();
    let bytes = common::body_bytes(resp).await;
    let text = String::from_utf8(bytes.to_vec())?;
    assert_eq!(status, 200, "JMAP call failed ({status}): {text}");
    Ok(serde_json::from_str(&text)?)
}

async fn http_free_busy(
    addr: std::net::SocketAddr,
    token: &str,
    calendar_id: i64,
    start: &str,
    end: &str,
) -> Result<Vec<String>, BoxError> {
    let req = Request::builder()
        .method("POST")
        .uri("/api/calendar/free-busy")
        .header("host", "mail.test")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(common::full(
            json!({
                "user_ids": [calendar_id],
                "start": start,
                "end": end
            })
            .to_string(),
        ))?;
    let resp = common::send(addr, req).await;
    let status = resp.status().as_u16();
    let bytes = common::body_bytes(resp).await;
    let text = String::from_utf8(bytes.to_vec())?;
    assert_eq!(status, 200, "HTTP free-busy failed ({status}): {text}");
    let doc: Value = serde_json::from_str(&text)?;
    let arr = doc["results"]
        .as_array()
        .ok_or_else(|| format!("expected results array from /api/calendar/free-busy: {doc}"))?;
    assert_eq!(arr.len(), 1, "expected 1 calendar entry: {doc}");
    let starts = arr[0]["intervals"]
        .as_array()
        .ok_or("missing intervals array")?
        .iter()
        .map(|iv| {
            let raw = iv["start"].as_str().unwrap_or("");
            chrono::DateTime::parse_from_rfc3339(raw)
                .map(|dt| {
                    dt.with_timezone(&chrono::Utc)
                        .format("%Y-%m-%dT%H:%M:%SZ")
                        .to_string()
                })
                .unwrap_or_else(|_| raw.to_owned())
        })
        .collect();
    Ok(starts)
}

#[tokio::test]
async fn jmap_calendar_event_set_rejects_unsupported_rrules() -> Result<(), BoxError> {
    with_env("calendar-rrule-465-reject", |env| async move {
        let acct = env.account.mailbox.to_string();
        let cal = env.calendar_id.to_string();

        // 1. CalendarEvent/set create rejects every unsupported FREQ and BY* part.
        let resp = jmap_call(
            env.addr,
            &env.token,
            json!({
                "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:calendars"],
                "methodCalls": [[
                    "CalendarEvent/set",
                    {
                        "accountId": acct,
                        "create": {
                            "c_hourly": {"calendarId": cal, "title": "H", "start": "2026-09-01T09:00:00Z", "end": "2026-09-01T10:00:00Z", "recurrenceRule": "FREQ=HOURLY;COUNT=3"},
                            "c_minutely": {"calendarId": cal, "title": "M", "start": "2026-09-01T09:00:00Z", "end": "2026-09-01T10:00:00Z", "recurrenceRule": "FREQ=MINUTELY;INTERVAL=15"},
                            "c_secondly": {"calendarId": cal, "title": "S", "start": "2026-09-01T09:00:00Z", "end": "2026-09-01T10:00:00Z", "recurrenceRule": "FREQ=SECONDLY;COUNT=2"},
                            "c_byhour": {"calendarId": cal, "title": "BH", "start": "2026-09-01T09:00:00Z", "end": "2026-09-01T10:00:00Z", "recurrenceRule": "FREQ=DAILY;BYHOUR=9"},
                            "c_byminute": {"calendarId": cal, "title": "BM", "start": "2026-09-01T09:00:00Z", "end": "2026-09-01T10:00:00Z", "recurrenceRule": "FREQ=DAILY;BYMINUTE=30"},
                            "c_bysecond": {"calendarId": cal, "title": "BS", "start": "2026-09-01T09:00:00Z", "end": "2026-09-01T10:00:00Z", "recurrenceRule": "FREQ=DAILY;BYSECOND=0"},
                            "c_byeaster": {"calendarId": cal, "title": "BE", "start": "2026-09-01T09:00:00Z", "end": "2026-09-01T10:00:00Z", "recurrenceRule": "FREQ=YEARLY;BYEASTER=1"},
                            "c_valid": {"calendarId": cal, "title": "OK", "start": "2026-09-01T09:00:00Z", "end": "2026-09-01T10:00:00Z", "recurrenceRule": "FREQ=WEEKLY;COUNT=3"}
                        }
                    },
                    "c0"
                ]]
            }),
        )
        .await?;
        let r0 = &resp["methodResponses"][0][1];
        for key in [
            "c_hourly",
            "c_minutely",
            "c_secondly",
            "c_byhour",
            "c_byminute",
            "c_bysecond",
            "c_byeaster",
        ] {
            assert_eq!(
                r0["notCreated"][key]["type"].as_str(),
                Some("invalidArguments"),
                "{key} should be rejected: {r0}"
            );
        }
        let valid_id = r0["created"]["c_valid"]
            .as_str()
            .ok_or("c_valid was not created")?
            .to_owned();

        // 2. CalendarEvent/set update rejects unsupported RRULE into notUpdated.
        let upd = jmap_call(
            env.addr,
            &env.token,
            json!({
                "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:calendars"],
                "methodCalls": [[
                    "CalendarEvent/set",
                    {
                        "accountId": acct,
                        "update": {
                            valid_id.clone(): {"recurrenceRule": "FREQ=HOURLY;COUNT=5"}
                        }
                    },
                    "u0"
                ]]
            }),
        )
        .await?;
        let u0 = &upd["methodResponses"][0][1];
        assert_eq!(
            u0["notUpdated"][&valid_id]["type"].as_str(),
            Some("invalidArguments"),
            "update with FREQ=HOURLY should be in notUpdated: {u0}"
        );

        // 3. CalendarEvent/setOccurrence scope='series' rejects unsupported RRULE.
        let occ = jmap_call(
            env.addr,
            &env.token,
            json!({
                "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:calendars"],
                "methodCalls": [[
                    "CalendarEvent/setOccurrence",
                    {
                        "accountId": acct,
                        "eventId": valid_id,
                        "recurrenceId": "2026-09-01T09:00:00Z",
                        "scope": "series",
                        "patch": {"recurrenceRule": "FREQ=DAILY;BYHOUR=10"}
                    },
                    "o0"
                ]]
            }),
        )
        .await?;
        let o_name = occ["methodResponses"][0][0].as_str().unwrap_or("");
        let o_args = &occ["methodResponses"][0][1];
        assert!(
            o_name == "error" || o_args["type"].as_str() == Some("invalidArguments"),
            "series edit with BYHOUR should be rejected: {occ}"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn freebusy_and_http_api_expand_rfc5545_vectors() -> Result<(), BoxError> {
    with_env("calendar-rrule-465-vectors", |env| async move {
        let acct = env.account.mailbox.to_string();
        let cal = env.calendar_id.to_string();

        struct Vector {
            name: &'static str,
            start: &'static str,
            end: &'static str,
            rrule: &'static str,
            win_start: &'static str,
            win_end: &'static str,
            expected: &'static [&'static str],
        }

        let vectors = [
            Vector {
                name: "testUntilMatching",
                start: "1997-09-02T09:00:00Z",
                end: "1997-09-02T10:00:00Z",
                rrule: "FREQ=DAILY;UNTIL=19970904T090000Z",
                win_start: "1997-09-01T00:00:00Z",
                win_end: "1997-09-10T00:00:00Z",
                expected: &[
                    "1997-09-02T09:00:00Z",
                    "1997-09-03T09:00:00Z",
                    "1997-09-04T09:00:00Z",
                ],
            },
            Vector {
                name: "testUntilWithDate",
                start: "1997-09-02T00:00:00Z",
                end: "1997-09-02T01:00:00Z",
                rrule: "FREQ=DAILY;UNTIL=19970905",
                win_start: "1997-09-01T00:00:00Z",
                win_end: "1997-09-10T00:00:00Z",
                expected: &[
                    "1997-09-02T00:00:00Z",
                    "1997-09-03T00:00:00Z",
                    "1997-09-04T00:00:00Z",
                    "1997-09-05T00:00:00Z",
                ],
            },
            Vector {
                name: "testMonthlyByWeekDay",
                start: "1997-09-02T09:00:00Z",
                end: "1997-09-02T10:00:00Z",
                rrule: "FREQ=MONTHLY;BYDAY=TU,TH;COUNT=3",
                win_start: "1997-09-01T00:00:00Z",
                win_end: "1997-10-01T00:00:00Z",
                expected: &[
                    "1997-09-02T09:00:00Z",
                    "1997-09-04T09:00:00Z",
                    "1997-09-09T09:00:00Z",
                ],
            },
            Vector {
                name: "testMonthlyByMonthDay",
                start: "1997-09-02T09:00:00Z",
                end: "1997-09-02T10:00:00Z",
                rrule: "FREQ=MONTHLY;BYMONTHDAY=1,3;COUNT=3",
                win_start: "1997-09-01T00:00:00Z",
                win_end: "1997-11-01T00:00:00Z",
                expected: &[
                    "1997-09-03T09:00:00Z",
                    "1997-10-01T09:00:00Z",
                    "1997-10-03T09:00:00Z",
                ],
            },
            Vector {
                name: "testMonthlyByNWeekDayLarge",
                start: "1997-09-02T09:00:00Z",
                end: "1997-09-02T10:00:00Z",
                rrule: "FREQ=MONTHLY;BYDAY=3TU,-3TH;COUNT=3",
                win_start: "1997-09-01T00:00:00Z",
                win_end: "1997-11-01T00:00:00Z",
                expected: &[
                    "1997-09-11T09:00:00Z",
                    "1997-09-16T09:00:00Z",
                    "1997-10-16T09:00:00Z",
                ],
            },
            Vector {
                name: "testYearlyByMonth",
                start: "1997-09-02T09:00:00Z",
                end: "1997-09-02T10:00:00Z",
                rrule: "FREQ=YEARLY;BYMONTH=1,3;COUNT=3",
                win_start: "1997-09-01T00:00:00Z",
                win_end: "1998-06-01T00:00:00Z",
                expected: &["1998-01-02T09:00:00Z", "1998-03-02T09:00:00Z"],
            },
            Vector {
                name: "testYearlyByYearDay",
                start: "1997-09-02T09:00:00Z",
                end: "1997-09-02T10:00:00Z",
                rrule: "FREQ=YEARLY;BYYEARDAY=1,100,200,365;COUNT=3",
                win_start: "1997-09-01T00:00:00Z",
                win_end: "1998-06-01T00:00:00Z",
                expected: &[
                    "1997-12-31T09:00:00Z",
                    "1998-01-01T09:00:00Z",
                    "1998-04-10T09:00:00Z",
                ],
            },
            Vector {
                name: "testDailyByWeekNo",
                start: "1997-09-02T09:00:00Z",
                end: "1997-09-02T10:00:00Z",
                rrule: "FREQ=DAILY;BYWEEKNO=20;COUNT=3",
                win_start: "1997-09-01T00:00:00Z",
                win_end: "1998-06-01T00:00:00Z",
                expected: &[
                    "1998-05-11T09:00:00Z",
                    "1998-05-12T09:00:00Z",
                    "1998-05-13T09:00:00Z",
                ],
            },
            Vector {
                name: "testWkStIntervalSU",
                start: "1997-09-02T09:00:00Z",
                end: "1997-09-02T10:00:00Z",
                rrule: "FREQ=WEEKLY;INTERVAL=2;BYDAY=TU,SU;WKST=SU;COUNT=3",
                win_start: "1997-09-01T00:00:00Z",
                win_end: "1997-10-01T00:00:00Z",
                expected: &[
                    "1997-09-02T09:00:00Z",
                    "1997-09-14T09:00:00Z",
                    "1997-09-16T09:00:00Z",
                ],
            },
            Vector {
                name: "testMaxYear",
                start: "1997-09-02T09:00:00Z",
                end: "1997-09-02T10:00:00Z",
                rrule: "FREQ=YEARLY;BYMONTH=2;BYMONTHDAY=31;COUNT=3",
                win_start: "1997-09-01T00:00:00Z",
                win_end: "1998-06-01T00:00:00Z",
                expected: &[],
            },
        ];

        for v in vectors {
            let create = jmap_call(
                env.addr,
                &env.token,
                json!({
                    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:calendars"],
                    "methodCalls": [[
                        "CalendarEvent/set",
                        {
                            "accountId": acct,
                            "create": {
                                "k1": {
                                    "calendarId": cal,
                                    "title": v.name,
                                    "start": v.start,
                                    "end": v.end,
                                    "recurrenceRule": v.rrule
                                }
                            }
                        },
                        "c0"
                    ]]
                }),
            )
            .await?;
            let event_id = create["methodResponses"][0][1]["created"]["k1"]
                .as_str()
                .ok_or_else(|| format!("{}: create failed: {create}", v.name))?
                .to_owned();

            // Verify via JMAP CalendarEvent/freeBusy
            let fb = jmap_call(
                env.addr,
                &env.token,
                json!({
                    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:calendars"],
                    "methodCalls": [[
                        "CalendarEvent/freeBusy",
                        {
                            "accountId": acct,
                            "userIds": [acct],
                            "start": v.win_start,
                            "end": v.win_end
                        },
                        "f0"
                    ]]
                }),
            )
            .await?;
            let jmap_starts: Vec<String> = fb["methodResponses"][0][1][0]["intervals"]
                .as_array()
                .ok_or_else(|| format!("{}: missing JMAP freeBusy intervals: {fb}", v.name))?
                .iter()
                .map(|iv| {
                    let raw = iv["start"].as_str().unwrap_or("");
                    chrono::DateTime::parse_from_rfc3339(raw)
                        .map(|dt| {
                            dt.with_timezone(&chrono::Utc)
                                .format("%Y-%m-%dT%H:%M:%SZ")
                                .to_string()
                        })
                        .unwrap_or_else(|_| raw.to_owned())
                })
                .collect();
            let expected: Vec<String> = v.expected.iter().map(|s| (*s).to_owned()).collect();
            assert_eq!(jmap_starts, expected, "{}: JMAP freeBusy mismatch", v.name);

            // Verify via HTTP POST /api/calendar/free-busy
            let http_starts = http_free_busy(
                env.addr,
                &env.token,
                env.calendar_id,
                v.win_start,
                v.win_end,
            )
            .await?;
            assert_eq!(
                http_starts, expected,
                "{}: HTTP /api/calendar/free-busy mismatch",
                v.name
            );

            // Clean up event before next vector
            let destroy = jmap_call(
                env.addr,
                &env.token,
                json!({
                    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:calendars"],
                    "methodCalls": [[
                        "CalendarEvent/set",
                        {
                            "accountId": acct,
                            "destroy": [event_id]
                        },
                        "d0"
                    ]]
                }),
            )
            .await?;
            assert_eq!(
                destroy["methodResponses"][0][1]["destroyed"]
                    .as_array()
                    .map(Vec::len),
                Some(1),
                "{}: destroy failed: {destroy}",
                v.name
            );
        }

        // Silence unused field warning on owner (kept for DB lifecycle clarity).
        let remaining: i64 = env
            .owner
            .query_one(
                "SELECT count(*) FROM calendar_events WHERE calendar_id=$1",
                &[&env.calendar_id],
            )
            .await?
            .get(0);
        assert_eq!(remaining, 0);
        Ok(())
    })
    .await
}
