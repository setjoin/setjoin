//! #286: F13 sub-router-a routes recorded from frozen Go through the front door.
//! Recording runs Go behind an empty route table against a fake LiveKit/Egress
//! twirp endpoint; replay unsets Go and serves the routes natively against an
//! identical fake. Peripherals are recorded, never authority: every call the
//! routes make to the SFU is part of the observation.
mod common;
#[path = "common/meet_fixture.rs"]
mod meet_fixture;
#[path = "common/meet_peripherals.rs"]
mod peripherals;
use common::BoxError;
use futures_util::FutureExt;
use hyper::{Request, Response};
use meet_fixture::{
    audit_rows, cleanup, events, ledger, normalize_instance, observe, snapshot, token, Ids,
};
use peripherals::{decode_tokens, Fake, KEY, SECRET};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};

macro_rules! cases {
    ($($name:ident = $route:literal, $case:literal;)*) => {$(
        #[tokio::test]
        async fn $name() -> Result<(), BoxError> {
            run($route, $case, Mutant::None).await
        }
    )*};
}
macro_rules! rejects_status {
    ($($name:ident = $route:literal;)*) => {$(
        #[tokio::test]
        async fn $name() -> Result<(), BoxError> {
            reject_status($route).await
        }
    )*};
}

cases! {
    join_success = "join", "success";
    join_foreign = "join", "foreign";
    join_invalid = "join", "invalid";
    join_missing = "join", "missing";
    join_locked = "join", "locked";
    join_banned = "join", "banned";
    join_ended = "join", "ended";
    join_redirect = "join", "redirect";
    join_repeat = "join", "repeat";
    join_livekit_fail = "join", "livekit_fail";
    join_no_asr = "join", "no_asr";
    join_disabled = "join", "disabled";
    join_unconfigured = "join", "unconfigured";
    kick_success = "kick", "success";
    kick_foreign = "kick", "foreign";
    kick_invalid = "kick", "invalid";
    kick_bad_body = "kick", "bad_body";
    kick_missing = "kick", "missing";
    kick_breakout = "kick", "breakout";
    kick_repeat = "kick", "repeat";
    kick_livekit_fail = "kick", "livekit_fail";
    kick_commit_before = "kick", "commit_before";
    kick_commit_after = "kick", "commit_after";
    end_success = "end", "success";
    end_foreign = "end", "foreign";
    end_invalid = "end", "invalid";
    end_repeat = "end", "repeat";
    end_recording = "end", "recording";
    end_breakouts = "end", "breakouts";
    end_livekit_fail = "end", "livekit_fail";
    knock_success = "knock", "success";
    knock_foreign = "knock", "foreign";
    knock_invalid = "knock", "invalid";
    knock_missing = "knock", "missing";
    knock_repeat = "knock", "repeat";
    decide_deny = "decide", "deny";
    decide_success = "decide", "success";
    decide_foreign = "decide", "foreign";
    decide_invalid = "decide", "invalid";
    decide_repeat = "decide", "repeat";
    decide_bad_action = "decide", "bad_action";
    decide_bad_request = "decide", "bad_request";
    decide_missing = "decide", "missing";
    bo_open_success = "bo_open", "success";
    bo_open_foreign = "bo_open", "foreign";
    bo_open_invalid = "bo_open", "invalid";
    bo_open_zero = "bo_open", "zero";
    bo_open_repeat = "bo_open", "repeat";
    bo_open_disabled = "bo_open", "disabled";
    bo_assign_success = "bo_assign", "success";
    bo_assign_foreign = "bo_assign", "foreign";
    bo_assign_invalid = "bo_assign", "invalid";
    bo_assign_unknown = "bo_assign", "unknown";
    bo_assign_main = "bo_assign", "main";
    bo_assign_repeat = "bo_assign", "repeat";
    bo_assign_livekit_fail = "bo_assign", "livekit_fail";
    bo_close_success = "bo_close", "success";
    bo_close_foreign = "bo_close", "foreign";
    bo_close_invalid = "bo_close", "invalid";
    bo_close_repeat = "bo_close", "repeat";
    bo_close_livekit_fail = "bo_close", "livekit_fail";
    bo_join_success = "bo_join", "success";
    bo_join_foreign = "bo_join", "foreign";
    bo_join_invalid = "bo_join", "invalid";
    bo_join_repeat = "bo_join", "repeat";
    bo_join_livekit_fail = "bo_join", "livekit_fail";
    pub_create_success = "pub_create", "success";
    pub_create_foreign = "pub_create", "foreign";
    pub_create_invalid = "pub_create", "invalid";
    pub_create_trailing = "pub_create", "trailing";
    pub_create_oversize = "pub_create", "oversize";
    pub_create_repeat = "pub_create", "repeat";
    pub_create_not_allowed = "pub_create", "not_allowed";
    pub_create_guest_off = "pub_create", "guest_off";
    pub_create_disabled = "pub_create", "disabled";
    pub_poll_success = "pub_poll", "success";
    pub_poll_pending = "pub_poll", "pending";
    pub_poll_denied = "pub_poll", "denied";
    pub_poll_foreign = "pub_poll", "foreign";
    pub_poll_invalid = "pub_poll", "invalid";
    pub_poll_disabled = "pub_poll", "disabled";
    pub_poll_repeat = "pub_poll", "repeat";
    webhook_success = "webhook", "success";
    webhook_foreign = "webhook", "foreign";
    webhook_invalid = "webhook", "invalid";
    webhook_no_auth = "webhook", "no_auth";
    webhook_bad_digest = "webhook", "bad_digest";
    webhook_expired = "webhook", "expired";
    webhook_unknown_event = "webhook", "unknown_event";
    webhook_non_uuid = "webhook", "non_uuid";
    webhook_oversize = "webhook", "oversize";
    webhook_left = "webhook", "left";
    webhook_egress_ended = "webhook", "egress_ended";
    webhook_egress_failed = "webhook", "egress_failed";
    webhook_egress_no_info = "webhook", "egress_no_info";
    webhook_repeat = "webhook", "repeat";
}
rejects_status! {
    join_rejects_status = "join";
    kick_rejects_status = "kick";
    end_rejects_status = "end";
    knock_rejects_status = "knock";
    decide_rejects_status = "decide";
    bo_open_rejects_status = "bo_open";
    bo_assign_rejects_status = "bo_assign";
    bo_close_rejects_status = "bo_close";
    bo_join_rejects_status = "bo_join";
    pub_create_rejects_status = "pub_create";
    pub_poll_rejects_status = "pub_poll";
    webhook_rejects_status = "webhook";
}

/// Routes that call the room controller: a silent peripheral must be caught.
macro_rules! rejects_silent {
    ($($name:ident = $route:literal;)*) => {$(
        #[tokio::test]
        async fn $name() -> Result<(), BoxError> {
            reject_silent($route).await
        }
    )*};
}
rejects_silent! {
    join_rejects_silent = "join";
    kick_rejects_silent = "kick";
    end_rejects_silent = "end";
    bo_open_rejects_silent = "bo_open";
    bo_assign_rejects_silent = "bo_assign";
    bo_close_rejects_silent = "bo_close";
    bo_join_rejects_silent = "bo_join";
}

#[tokio::test]
async fn rejects_no_tenant_filter_kick() -> Result<(), BoxError> {
    reject_shadow("kick", "foreign").await
}
#[tokio::test]
async fn rejects_no_tenant_filter_decide() -> Result<(), BoxError> {
    reject_shadow("decide", "foreign").await
}

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn route_spec(route: &str) -> (&'static str, &'static str) {
    match route {
        "join" => ("POST", "/meet/{id}/join"),
        "kick" => ("POST", "/meet/{id}/kick"),
        "end" => ("POST", "/meet/{id}/end"),
        "knock" => ("POST", "/meet/{id}/knock"),
        "decide" => ("POST", "/meet/{id}/requests/{reqId}"),
        "bo_open" => ("POST", "/meet/{id}/breakouts"),
        "bo_assign" => ("POST", "/meet/{id}/breakouts/assign"),
        "bo_close" => ("POST", "/meet/{id}/breakouts/close"),
        "bo_join" => ("POST", "/meet/{id}/breakouts/join"),
        "pub_create" => ("POST", "/public/meet/{slug}/join-request"),
        "pub_poll" => ("GET", "/public/meet/{slug}/join-request/{id}"),
        "webhook" => ("POST", "/meet/webhook"),
        _ => unreachable!("unknown meet route"),
    }
}

/// The status frozen Go answers for each case; a recording that disagrees
/// is a broken fixture, never a golden.
fn expected_status(route: &str, case: &str) -> u16 {
    match (route, case) {
        (_, "disabled") => 404,
        (_, "unconfigured") => 503,
        (_, "commit_before" | "commit_after") => 503,
        (_, "livekit_fail") => 502,
        ("join", "success" | "foreign" | "redirect" | "no_asr" | "repeat") => 200,
        ("join", "invalid") => 400,
        ("join", "missing" | "ended" | "locked" | "banned") => match case {
            "missing" => 404,
            "ended" => 409,
            _ => 403,
        },
        ("kick" | "end", "invalid") | ("kick", "bad_body") => 400,
        ("kick" | "end", "foreign") => 403,
        ("kick", "missing") => 403,
        ("end", "repeat") => 403,
        ("kick" | "end", _) => 204,
        ("knock", "invalid") => 400,
        ("knock", "missing") => 404,
        ("knock", _) => 201,
        ("decide", "success") => 200,
        ("decide", "deny") => 204,
        ("decide", "invalid" | "bad_action" | "bad_request") => 400,
        ("decide", "repeat" | "missing" | "foreign") => 422,
        ("bo_open", "success") => 201,
        ("bo_open", "foreign") => 403,
        ("bo_open", "invalid") => 400,
        ("bo_open", "zero") => 422,
        ("bo_open", "repeat") => 422,
        ("bo_assign", "foreign") => 403,
        ("bo_assign", "invalid") => 400,
        ("bo_assign", "unknown") => 422,
        ("bo_assign", _) => 204,
        ("bo_close", "foreign") => 403,
        ("bo_close", "invalid") => 400,
        ("bo_close", _) => 204,
        ("bo_join", "success" | "repeat") => 200,
        ("bo_join", "foreign") => 403,
        ("bo_join", "invalid") => 400,
        ("pub_create", "success" | "trailing" | "repeat") => 201,
        ("pub_create", "foreign" | "not_allowed") => 404,
        ("pub_create", "invalid" | "oversize") => 400,
        ("pub_create", "guest_off") => 404,
        ("pub_poll", "success" | "pending" | "denied" | "repeat") => 200,
        ("pub_poll", "foreign") => 404,
        ("pub_poll", "invalid") => 400,
        ("webhook", "no_auth" | "bad_digest" | "expired" | "invalid" | "foreign") => 401,
        ("webhook", "oversize") => 413,
        ("webhook", _) => 200,
        _ => unreachable!("no expected status for {route} {case}"),
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Mutant {
    None,
    /// The adapter answers a status the recording does not.
    Status,
    /// The adapter performs its reducer call but never talks to the SFU.
    Silent,
    /// A private schema makes every actor read as host.
    Shadow,
}

async fn reject_status(route: &str) -> Result<(), BoxError> {
    let err = run(route, "success", Mutant::Status)
        .await
        .expect_err("actual HTTP status mutant must fail");
    assert!(err.to_string().contains("/response/status"), "{err}");
    let (method, canonical) = route_spec(route);
    println!("MUTANT-REJECTED: {method} {canonical} :: changed-status");
    Ok(())
}

async fn reject_silent(route: &str) -> Result<(), BoxError> {
    let err = run(route, "success", Mutant::Silent)
        .await
        .expect_err("a route that never calls the SFU must fail");
    let text = err.to_string();
    assert!(
        text.contains("/peripherals") || text.contains("/response/status"),
        "{err}"
    );
    let (method, canonical) = route_spec(route);
    println!("MUTANT-REJECTED: {method} {canonical} :: silent-peripheral");
    Ok(())
}

async fn reject_shadow(route: &str, case: &str) -> Result<(), BoxError> {
    let err = run(route, case, Mutant::Shadow)
        .await
        .expect_err("actual SQL mutant must fail the immutable recording");
    assert!(err.to_string().contains("/response/status"), "{err}");
    let (method, canonical) = route_spec(route);
    println!("MUTANT-REJECTED: {method} {canonical} :: no-tenant-filter");
    Ok(())
}

struct Wrapped<K: setjoin_authz::token::KeySource + 'static>(
    setjoin_gateway::meet::MeetRoute<K>,
    bool,
);
impl<K: setjoin_authz::token::KeySource + 'static> setjoin_gateway::Intercept for Wrapped<K> {
    fn matches(&self, r: &Request<setjoin_gateway::Body>) -> bool {
        self.0.matches(r)
    }
    fn admits_member(
        &self,
        h: hyper::HeaderMap,
        s: &'static str,
    ) -> setjoin_gateway::BoxFuture<bool> {
        self.0.admits_member(h, s)
    }
    fn handle(
        &self,
        r: Request<setjoin_gateway::Body>,
        c: setjoin_gateway::RequestContext,
    ) -> setjoin_gateway::BoxFuture<Response<setjoin_gateway::Body>> {
        let reply = self.0.handle(r, c);
        let change = self.1;
        Box::pin(async move {
            let mut reply = reply.await;
            if change {
                *reply.status_mut() = hyper::StatusCode::from_u16(599).unwrap();
            }
            reply
        })
    }
}

fn patient(dsn: &str) -> Result<setjoin_pg::ScopedExecutor, BoxError> {
    let wait = std::time::Duration::from_secs(30);
    Ok(setjoin_pg::ScopedExecutor::from_dsn_with(
        dsn,
        2,
        setjoin_pg::Timeouts {
            pool_wait: wait,
            create: wait,
            statement: wait,
        },
    )
    .map_err(|e| e.0)?
    .with_audit_keys("22".repeat(32), String::new()))
}

/// What a case seeds through the canonical reducers and plain fixture rows.
struct Seed {
    own: i64,
    own_slug: String,
    own_room: String,
    foreign: i64,
    breakouts: Vec<i64>,
    request: Option<(i64, String)>,
}

async fn scalar(c: &tokio_postgres::Client, sql: &str) -> Result<Value, BoxError> {
    let raw: String = c.query_one(sql, &[]).await?.get(0);
    Ok(serde_json::from_str(&raw)?)
}

async fn seed(
    c: &tokio_postgres::Client,
    a: &fixture::Account,
    b: &fixture::Account,
    route: &str,
    case: &str,
) -> Result<Seed, BoxError> {
    let mut out = Seed {
        own: 0,
        own_slug: String::new(),
        own_room: String::new(),
        foreign: 0,
        breakouts: vec![],
        request: None,
    };
    let own = scalar(
        c,
        &format!("SELECT meeting_create({},'Meet2 seed owner')::text", a.user),
    )
    .await?;
    let foreign = scalar(
        c,
        &format!(
            "SELECT meeting_create({},'Meet2 seed foreign')::text",
            b.user
        ),
    )
    .await?;
    out.own = own["meetingId"].as_i64().unwrap();
    out.own_slug = own["slug"].as_str().unwrap().to_owned();
    out.foreign = foreign["meetingId"].as_i64().unwrap();
    out.own_room = c
        .query_one(
            "SELECT room_name::text FROM meetings WHERE id=$1",
            &[&out.own],
        )
        .await?
        .get(0);
    let b_participant = matches!(
        (route, case),
        (
            "kick",
            "success" | "breakout" | "livekit_fail" | "commit_before" | "commit_after" | "repeat"
        ) | ("end", "breakouts")
            | ("bo_assign", "success" | "main" | "livekit_fail" | "repeat")
            | ("bo_join", "success" | "livekit_fail" | "repeat")
            | ("join", "redirect")
            | ("webhook", "left" | "success")
    );
    if b_participant {
        c.execute(
            "INSERT INTO meeting_participants(meeting_id,user_id,identity,role) VALUES($1,$2,'u:'||$2::bigint::text,'member')",
            &[&out.own, &b.user],
        )
        .await?;
    }
    match (route, case) {
        ("join", "locked") => {
            c.execute("UPDATE meetings SET locked=true WHERE id=$1", &[&out.own])
                .await?;
        }
        ("join", "banned") => {
            c.execute(
                "INSERT INTO meeting_participants(meeting_id,user_id,identity,role,banned_at) VALUES($1,$2,'u:'||$2::bigint::text,'member',now())",
                &[&out.own, &b.user],
            )
            .await?;
        }
        ("join", "ended") => {
            c.execute(
                "UPDATE meetings SET state='ended', ended_at=now() WHERE id=$1",
                &[&out.own],
            )
            .await?;
        }
        _ => {}
    }
    let wants_breakouts = matches!(
        (route, case),
        ("join", "redirect")
            | ("kick", "breakout")
            | ("end", "breakouts")
            | ("bo_assign", _)
            | (
                "bo_close",
                "success" | "livekit_fail" | "repeat" | "foreign"
            )
            | ("bo_join", _)
    );
    if wants_breakouts {
        let opened = scalar(
            c,
            &format!(
                "SELECT meeting_breakout_open({},{},2,NULL,false)::text",
                a.user, out.own
            ),
        )
        .await?;
        out.breakouts = opened
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["breakoutId"].as_i64().unwrap())
            .collect();
    }
    if matches!(
        (route, case),
        ("join", "redirect")
            | ("kick", "breakout")
            | ("bo_join", "success" | "livekit_fail" | "repeat")
            | ("bo_assign", "main")
    ) {
        // The foreign member already belongs to the first child room.
        c.execute(
            "UPDATE meeting_participants SET breakout_id=$1 WHERE meeting_id=$2 AND user_id=$3",
            &[&out.breakouts[0], &out.own, &b.user],
        )
        .await?;
    }
    if matches!(route, "decide" | "knock")
        && !matches!((route, case), ("knock", "missing" | "invalid"))
    {
        if route == "decide" {
            let made = scalar(
                c,
                &format!(
                    "SELECT meeting_join_request_create('{}','Meet2 member',{})::text",
                    out.own_slug, b.user
                ),
            )
            .await?;
            out.request = Some((
                made["requestId"].as_i64().unwrap(),
                made["secret"].as_str().unwrap().to_owned(),
            ));
        }
    }
    if route == "pub_create" || route == "pub_poll" {
        if !matches!((route, case), ("pub_create", "not_allowed")) {
            c.execute(
                "UPDATE meetings SET settings=jsonb_set(settings,'{guestAllowed}','true') WHERE id=$1",
                &[&out.own],
            )
            .await?;
        }
    }
    if route == "pub_poll" {
        let made = scalar(
            c,
            &format!(
                "SELECT meeting_join_request_create('{}','Meet2 guest')::text",
                out.own_slug
            ),
        )
        .await?;
        let id = made["requestId"].as_i64().unwrap();
        out.request = Some((id, made["secret"].as_str().unwrap().to_owned()));
        match case {
            "success" | "repeat" => {
                // The host admits the guest; the poll then mints a token.
                c.execute(&format!("SELECT meeting_admit({},{id})", a.user), &[])
                    .await?;
            }
            "denied" => {
                c.execute(&format!("SELECT meeting_deny({},{id})", a.user), &[])
                    .await?;
            }
            _ => {}
        }
    }
    if matches!(
        (route, case),
        ("end", "recording")
            | (
                "webhook",
                "egress_ended" | "egress_failed" | "egress_no_info"
            )
    ) {
        let state = if route == "end" { "active" } else { "stopping" };
        c.execute(
            "INSERT INTO meeting_recordings(meeting_id,egress_id,state,started_by,staging_key) VALUES($1,'EG_meet2_seed',$2,$3,'meet-egress/seed.mp4')",
            &[&out.own, &state, &a.user],
        )
        .await?;
    }
    Ok(out)
}

/// What one case sends. The body is a final byte string.
struct Plan {
    path: String,
    body: Vec<u8>,
    /// None sends no user token (public and webhook requests).
    who: Option<bool>,
    headers: Vec<(String, String)>,
}

fn build(route: &str, case: &str, s: &Seed, a: &fixture::Account, b: &fixture::Account) -> Plan {
    let target = match (route, case) {
        (_, "missing") => i64::MAX,
        ("knock", "foreign") => s.foreign,
        _ => s.own,
    };
    let id = target.to_string();
    // Whether the foreign account (a plain member) sends the request.
    let b_acts = match route {
        "join" => matches!(case, "foreign" | "locked" | "banned" | "redirect"),
        "knock" => !matches!(case, "foreign"),
        "bo_join" => true,
        "kick" | "end" | "decide" | "bo_open" | "bo_assign" | "bo_close" => case == "foreign",
        _ => false,
    };
    let mut who = Some(!b_acts);
    let mut headers = vec![];
    let mut path;
    let mut body = String::new();
    let identity_b = format!("u:{}", b.user);
    match route {
        "join" => {
            path = format!("/api/meet/{id}/join");
            if case == "invalid" {
                path = "/api/meet/bad/join".into();
            }
        }
        "kick" => {
            path = format!("/api/meet/{id}/kick");
            body = json!({"identity": identity_b}).to_string();
            match case {
                "invalid" => path = "/api/meet/bad/kick".into(),
                "bad_body" => body = json!({"identity": 5}).to_string(),
                "foreign" => body = json!({"identity": format!("u:{}", a.user)}).to_string(),
                _ => {}
            }
        }
        "end" => {
            path = format!("/api/meet/{id}/end");
            if case == "invalid" {
                path = "/api/meet/bad/end".into();
            }
        }
        "knock" => {
            path = format!("/api/meet/{id}/knock");
            if case == "invalid" {
                path = "/api/meet/bad/knock".into();
            }
        }
        "decide" => {
            let request = s.request.as_ref().map_or(0, |r| r.0);
            let request = if case == "missing" { i64::MAX } else { request };
            path = format!("/api/meet/{id}/requests/{request}");
            let action = match case {
                "deny" => "deny",
                "bad_action" => "approve",
                _ => "admit",
            };
            body = json!({"action": action}).to_string();
            match case {
                "invalid" => body = "{".into(),
                "bad_request" => path = format!("/api/meet/{id}/requests/bad"),
                _ => {}
            }
        }
        "bo_open" => {
            path = format!("/api/meet/{id}/breakouts");
            body = json!({"count": 2, "titles": ["Room A", "Room B"], "autoAssign": false})
                .to_string();
            match case {
                "invalid" => body = "{".into(),
                "zero" => body = json!({"count": 0}).to_string(),
                _ => {}
            }
        }
        "bo_assign" => {
            path = format!("/api/meet/{id}/breakouts/assign");
            let breakout = s.breakouts.first().copied();
            body = json!({"targetUserId": b.user, "breakoutId": breakout}).to_string();
            match case {
                "invalid" => body = "{".into(),
                "unknown" => {
                    body = json!({"targetUserId": b.user, "breakoutId": i64::MAX}).to_string()
                }
                "main" => body = json!({"targetUserId": b.user, "breakoutId": null}).to_string(),
                _ => {}
            }
        }
        "bo_close" => {
            path = format!("/api/meet/{id}/breakouts/close");
            if case == "invalid" {
                path = "/api/meet/bad/breakouts/close".into();
            }
        }
        "bo_join" => {
            path = format!("/api/meet/{id}/breakouts/join");
            body = json!({"breakoutId": s.breakouts.first().copied()}).to_string();
            match case {
                "invalid" => body = "{".into(),
                _ => {}
            }
        }
        "pub_create" => {
            who = None;
            let slug = if case == "foreign" {
                "no-such-slug"
            } else {
                s.own_slug.as_str()
            };
            path = format!("/api/public/meet/{slug}/join-request");
            body = json!({"displayName": "Meet2 <guest> & co"}).to_string();
            match case {
                "invalid" => body = "{".into(),
                "trailing" => {
                    body = r#"{"DISPLAYNAME":"Trailing","unknown":1} trailing garbage"#.into()
                }
                "oversize" => body = format!(r#"{{"displayName":"{}"}}"#, "x".repeat(5000)),
                _ => {}
            }
        }
        "pub_poll" => {
            who = None;
            let (request, secret) = s.request.clone().unwrap();
            let request = if case == "invalid" {
                "bad".to_owned()
            } else {
                request.to_string()
            };
            let slug = if case == "foreign" {
                "no-such-slug"
            } else {
                s.own_slug.as_str()
            };
            path = format!("/api/public/meet/{slug}/join-request/{request}");
            headers.push((
                "x-meet-lobby-secret".into(),
                if case == "foreign" {
                    "wrong".into()
                } else {
                    secret
                },
            ));
        }
        "webhook" => {
            who = None;
            path = "/api/meet/webhook".into();
            let room = |r: &str| json!({"name": r});
            let ev = match case {
                "unknown_event" => json!({"event":"track_published","room":room(&s.own_room)}),
                "non_uuid" => {
                    json!({"event":"participant_joined","room":room("not-a-uuid"),"participant":{"identity":identity_b}})
                }
                "left" => {
                    json!({"event":"participant_left","room":room(&s.own_room),"participant":{"identity":identity_b}})
                }
                "egress_ended" => {
                    json!({"event":"egress_ended","egressInfo":{"egressId":"EG_meet2_seed","roomName":s.own_room,"status":"EGRESS_COMPLETE","fileResults":[{"size":"2048","duration":"3000000000"}]}})
                }
                "egress_failed" => {
                    json!({"event":"egress_ended","egressInfo":{"egressId":"EG_meet2_seed","roomName":s.own_room,"status":"EGRESS_FAILED","error":"encoder stalled"}})
                }
                "egress_no_info" => json!({"event":"egress_started"}),
                "foreign" => {
                    json!({"event":"participant_joined","room":room(&s.own_room),"participant":{"identity":identity_b}})
                }
                _ => {
                    json!({"event":"participant_joined","room":room(&s.own_room),"participant":{"identity":identity_b}})
                }
            };
            body = ev.to_string();
            if case == "invalid" {
                body = r#"{"event":"participant_joined","event":"room_started"}"#.into();
            }
            if case == "oversize" {
                body = format!(
                    r#"{{"event":"room_started","room":{{"name":"{}"}}}}"#,
                    "x".repeat((1 << 20) + 1)
                );
            }
            let signed = |offset: i64, key: &str, secret: &str| {
                peripherals::webhook_token(body.as_bytes(), key, secret, offset)
            };
            match case {
                "no_auth" => {}
                "bad_digest" => headers.push((
                    "authorization".into(),
                    peripherals::webhook_token(b"another body", KEY, SECRET, 0),
                )),
                "expired" => headers.push(("authorization".into(), signed(-3600, KEY, SECRET))),
                "foreign" => headers.push((
                    "authorization".into(),
                    signed(0, KEY, "someone-elses-secret-someone-elses!"),
                )),
                _ => headers.push(("authorization".into(), signed(0, KEY, SECRET))),
            }
        }
        _ => unreachable!(),
    }
    let _ = a;
    Plan {
        path,
        body: body.into_bytes(),
        who,
        headers,
    }
}

async fn run(route: &str, case: &str, mutant: Mutant) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let recording_env = std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
    if (mutant != Mutant::None || case.starts_with("commit_")) && recording_env {
        return Err("cannot record a planted mutant or COMMIT-loss case".into());
    }
    let Some(db) = Db::for_case("meet2") else {
        return Ok(());
    };
    let c = db.connect().await?;
    let a = fixture::account(&c, "meet2-owner").await?;
    let b = fixture::account(&c, "meet2-foreign").await?;
    let toggles = [
        "feature.meet",
        "feature.meet_breakouts",
        "meet.guest_access",
    ];
    let mut saved = Vec::new();
    for key in toggles {
        let v: Option<bool> = c
            .query_opt("SELECT enabled FROM feature_toggles WHERE key=$1", &[&key])
            .await?
            .map(|r| r.get(0));
        saved.push((key, v));
    }
    let mut mutant_schema = None;
    let mut commit_wire = None;
    let fake = Fake::start().await;
    let result = std::panic::AssertUnwindSafe(async {
        let (method, canonical) = route_spec(route);
        for (key, on) in [
            ("feature.meet", case != "disabled" || route == "bo_open"),
            ("feature.meet_breakouts", !(route == "bo_open" && case == "disabled")),
            ("meet.guest_access", !(route == "pub_create" && case == "guest_off")),
        ] {
            c.execute(
                "INSERT INTO feature_toggles(key,enabled) VALUES($1,$2) ON CONFLICT (key) DO UPDATE SET enabled=EXCLUDED.enabled",
                &[&key, &on],
            )
            .await?;
        }
        let seeded = seed(&c, &a, &b, route, case).await?;
        let mut worker_app = db.app.clone();
        if mutant == Mutant::Shadow {
            let schema = format!("gofree_meet2_mutant_{}", a.user);
            ledger(&format!("Plan private no-tenant-filter SQL mutant schema {schema}, assigned DB only"))?;
            c.batch_execute(&format!(
                "CREATE SCHEMA {schema}; GRANT USAGE ON SCHEMA {schema} TO setjoin_app; \
                 CREATE FUNCTION {schema}.meeting_member_role(bigint,bigint) RETURNS text LANGUAGE sql AS $$ SELECT 'host'::text $$;"
            ))
            .await?;
            if route == "decide" {
                // Decide's foreign case is stopped by row-level security on the
                // request row, so the mutant also removes that filter: a view
                // owned by the connecting superuser reads the table unfiltered.
                c.batch_execute(&format!(
                    "CREATE VIEW {schema}.meeting_join_requests AS SELECT * FROM public.meeting_join_requests; \
                     GRANT SELECT, UPDATE ON {schema}.meeting_join_requests TO setjoin_app;"
                ))
                .await?;
            }
            let app = db.app.as_deref().unwrap_or(&db.dsn);
            worker_app = Some(format!(
                "{app}{}options=-csearch_path%3D{schema}%2Cpublic",
                if app.contains('?') { "&" } else { "?" }
            ));
            mutant_schema = Some(schema);
        }
        if let Some(cut) = match case {
            "commit_before" => Some(common::commit::CommitCut::BeforeCommit),
            "commit_after" => Some(common::commit::CommitCut::AfterCommit),
            _ => None,
        } {
            ledger("Plan gofree-meet2 COMMIT-loss proxy on the assigned application DB")?;
            let (dsn, task) =
                common::commit::commit_cut_proxy(db.app.as_deref().unwrap_or(&db.dsn), cut).await;
            worker_app = Some(dsn);
            commit_wire = Some(task);
        }
        let asr = (case != "no_asr").then_some("http://127.0.0.1:1");
        let livekit_url = format!("ws://{}", fake.addr);
        let mut go_env: Vec<(&str, String)> = vec![("MEET_EGRESS_ENABLED", "true".into())];
        if case != "unconfigured" {
            go_env.push(("LIVEKIT_API_KEY", KEY.into()));
            go_env.push(("LIVEKIT_API_SECRET", SECRET.into()));
            go_env.push(("LIVEKIT_URL", livekit_url.clone()));
        }
        if let Some(url) = asr {
            go_env.push(("ASR_URL", url.into()));
            go_env.push(("ASR_TOKEN", "meet2-asr".into()));
        }
        let unused = common::fake_upstream(|_| async { Response::new(common::full("unused")) }).await;
        let oracle_db = Db {
            dsn: db.dsn.clone(),
            direct: db.direct.clone(),
            app: db.app.clone(),
        };
        let oracle = common::go_oracle::start_named_with_env(&oracle_db, unused, "gofree-meet2", &go_env).await?;
        let recording = oracle.is_some();
        // Ignore the oracle's own startup probes.
        let _ = fake.drain();
        fake.fail((case == "livekit_fail").then_some(match route {
            "join" | "bo_join" => "CreateRoom",
            "kick" | "bo_assign" => "RemoveParticipant",
            _ => "DeleteRoom",
        }));
        let audit_start: i64 = c
            .query_one("SELECT coalesce(max(id),0) FROM admin_audit_log", &[])
            .await?
            .get(0);
        let mut listeners = Vec::new();
        for channel in [
            format!("meet:{}", a.user),
            format!("meet:{}", b.user),
            format!("chat:{}", a.user),
            format!("chat:{}", b.user),
        ] {
            listeners.push((channel.clone(), db.listen(&channel).await?));
        }
        let mut baseline = snapshot_a(&c, &a, &b).await?;
        let configured = case != "unconfigured";
        let sfu_url = if mutant == Mutant::Silent {
            "ws://127.0.0.1:1".to_owned()
        } else {
            livekit_url
        };
        let adapter = setjoin_gateway::meet::MeetRoute::new(
            patient(worker_app.as_deref().unwrap_or(&db.dsn))?,
            std::sync::Arc::new(common::recovery_keys()),
            "mailserver".into(),
            if configured {
                setjoin_gateway::meet_livekit::LiveKit::new(KEY, SECRET, &sfu_url, true, asr.is_some())
            } else {
                setjoin_gateway::meet_livekit::LiveKit::unconfigured()
            },
        );
        let routes = if recording {
            RouteTable::proxy_all()
        } else {
            RouteTable::proxy_all().with(Wrapped(adapter, mutant == Mutant::Status))
        };
        let gateway = Gateway::new(
            Config {
                upstream: oracle
                    .as_ref()
                    .map(|o| format!("http://{}", o.address).parse())
                    .transpose()?,
                trusted_proxies: TrustedProxies::parse("")?,
                upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
                edge_limit: None,
            },
            routes,
        )?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let server = tokio::spawn(gateway.serve(listener));
        let plan = build(route, case, &seeded, &a, &b);
        let ids = Ids::load(&c, &a, &b).await?;
        let send = |plan: &Plan| {
            let mut request = Request::builder()
                .method(method)
                .uri(plan.path.clone())
                .header("host", "mail.test")
                .header("origin", "http://mail.test")
                .header("content-type", "application/json")
                .header("x-request-id", "meet2-oracle");
            if let Some(a_acts) = plan.who {
                let user = if a_acts { a.user } else { b.user };
                request = request.header("authorization", format!("Bearer {}", token(user, "meet2-oracle")));
            }
            for (k, v) in &plan.headers {
                request = request.header(k.as_str(), v.as_str());
            }
            let body = plan.body.clone();
            async move { common::send(addr, request.body(common::full(body)).unwrap()).await }
        };
        let first = if case == "repeat" || (route == "pub_poll" && case == "repeat") {
            let mut first = observe(send(&plan).await).await?;
            decode_tokens(&mut first["response"]["body"]);
            first["effects"] = snapshot_a(&c, &a, &b).await?;
            first["audit"] = audit_rows(&c, audit_start, &a, &b).await?;
            first["notify"] = events(&mut listeners, &c).await?;
            first["peripherals"] = json!(fake.drain());
            Some(first)
        } else {
            None
        };
        let mut observed = observe(send(&plan).await).await?;
        decode_tokens(&mut observed["response"]["body"]);
        let status = observed["response"]["status"].as_u64().unwrap() as u16;
        if !recording && mutant == Mutant::None {
            let metrics = common::send(
                addr,
                Request::builder().uri("/_gateway/metrics").body(common::full(""))?,
            )
            .await;
            let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            if !case.starts_with("commit_")
                && (!metrics.contains("setjoin_gateway_proxied_to_go_total 0")
                    || !metrics.contains("setjoin_gateway_proxied_to_go_by_family_total{family=\"F13\"} 0"))
            {
                return Err(format!("native Go proxy counters: {metrics}").into());
            }
        }
        server.abort();
        let _ = server.await;
        if mutant == Mutant::None {
            let want = expected_status(route, case);
            if status != want {
                return Err(format!("HTTP status expected {want}, got {status}: {observed}").into());
            }
        }
        let ids = ids.with_new(&c, &a, &b).await?;
        let mut effects = snapshot_a(&c, &a, &b).await?;
        let mut audit = audit_rows(&c, audit_start, &a, &b).await?;
        let mut notify = events(&mut listeners, &c).await?;
        let mut peripherals = json!(fake.drain());
        let actual_path = plan.path.split('?').next().unwrap().strip_prefix("/api").unwrap().to_owned();
        let canonical_path = canonical.to_owned();
        for v in [
            &mut observed["response"]["body"],
            &mut effects,
            &mut audit,
            &mut notify,
            &mut peripherals,
        ] {
            normalize_instance(v, &actual_path, &canonical_path);
            ids.normalize(v, "", "");
        }
        let mut first = first;
        if let Some(first) = first.as_mut() {
            normalize_instance(&mut first["response"]["body"], &actual_path, &canonical_path);
            ids.normalize(&mut first["response"]["body"], "", "");
            for key in ["effects", "audit", "notify", "peripherals"] {
                ids.normalize(&mut first[key], "", "");
            }
        }
        baseline = {
            let mut v = baseline;
            ids.normalize(&mut v, "", "");
            v
        };
        let mut observation = json!({
            "request": {"method": method, "path": canonical},
            "response": observed["response"],
            "effects": effects, "audit": audit, "notify": notify, "peripherals": peripherals,
        });
        if let Some(first) = first {
            observation["first"] = first;
        }
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../../tests/conformance/meet/goldens/{route}-{case}.json"
        ));
        let rows = |o: &Value| json!([o["effects"], o["audit"], o["notify"]]);
        let label = format!("{method} {canonical}");
        if case.starts_with("commit_") {
            let committed = case == "commit_after";
            let cut = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                commit_wire.take().ok_or("COMMIT proxy")?,
            )
            .await???;
            if (cut == common::commit::CommitCut::AfterCommit) != committed {
                return Err("wrong wire cut".into());
            }
            let operation = observation["response"]["headers"]["x-operation-id"]
                .as_str()
                .ok_or("Unknown lost operation ID")?;
            if operation.len() != 32 || !operation.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("invalid operation ID".into());
            }
            let command = format!("meeting_{route}");
            let receipt: bool = c
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM rust_operation_receipts WHERE operation_id=$1::text::uuid AND family='F13' AND command=$2)",
                    &[&operation, &command],
                )
                .await?
                .get(0);
            if receipt != committed {
                return Err("receipt did not resolve the actual commit".into());
            }
            // The SFU is a peripheral: an unknown outcome never evicts.
            if observation["peripherals"] != json!([]) {
                return Err("an unknown outcome reached the SFU".into());
            }
            if committed {
                let success: Value = serde_json::from_slice(&std::fs::read(path.with_file_name(format!("{route}-success.json")))?)?;
                for key in ["effects", "audit", "notify"] {
                    setjoin_conformance::golden::compare(&success["observation"][key], &observation[key])?;
                }
            } else {
                setjoin_conformance::golden::compare(&baseline, &observation["effects"])?;
                if observation["audit"] != json!([]) || observation["notify"] != json!([]) {
                    return Err("aborted commit left effects".into());
                }
            }
            ledger("Reaped gofree-meet2 COMMIT-loss proxy; HTTP Unknown resolved from receipt without replay")?;
            return Ok(());
        }
        if recording {
            let want = expected_status(route, case);
            if status != want {
                return Err(format!("unexpected Go status {status}, expected {want}: {observation:#}").into());
            }
            setjoin_conformance::golden::record(
                &path.with_file_name(format!("{route}-{case}-row-effects.json")),
                &json!({"format":1,"route":label,"case":format!("{route}-{case}-row-effects"),
                    "go_source":std::env::var("GOFREE_GO_SOURCE")?,"effects":rows(&observation)}),
            )?;
            setjoin_conformance::golden::record(
                &path,
                &json!({"format":1,"route":label,"case":format!("{route}-{case}"),
                    "go_source":std::env::var("GOFREE_GO_SOURCE")?,
                    "normalization":["fixture identities","generated ids, slugs, room names, secrets and timestamps; join tokens replaced by verified claims; chat and core audit chains verified"],
                    "observation":observation}),
            )?;
        } else {
            let expected: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
            setjoin_conformance::golden::compare(&expected["observation"], &observation)?;
            let recorded: Value = serde_json::from_slice(&std::fs::read(
                path.with_file_name(format!("{route}-{case}-row-effects.json")),
            )?)?;
            setjoin_conformance::golden::compare(&recorded["effects"], &rows(&observation))?;
            println!("GOLDEN-REPLAY: {label} :: {route}-{case}");
        }
        Ok::<_, BoxError>(())
    })
    .catch_unwind()
    .await;
    if let Some(task) = commit_wire {
        task.abort();
        let _ = task.await;
        ledger("Reaped failed gofree-meet2 COMMIT proxy")?;
    }
    if let Some(schema) = mutant_schema {
        c.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await?;
        ledger(&format!("Removed private SQL mutant schema {schema}"))?;
    }
    // Public join requests and breakouts cascade with their meetings.
    cleanup(&c, &[&a, &b]).await?;
    for (key, value) in saved {
        match value {
            Some(v) => {
                c.execute(
                    "UPDATE feature_toggles SET enabled=$2 WHERE key=$1",
                    &[&key, &v],
                )
                .await?;
            }
            None => {
                c.execute("DELETE FROM feature_toggles WHERE key=$1", &[&key])
                    .await?;
            }
        }
    }
    match result {
        Ok(r) => r,
        Err(p) => std::panic::resume_unwind(p),
    }
}

/// Base snapshot plus every table the sub-router-a routes can write.
async fn snapshot_a(
    c: &tokio_postgres::Client,
    a: &fixture::Account,
    b: &fixture::Account,
) -> Result<Value, BoxError> {
    let mut out = snapshot(c, a, b).await?;
    let users = vec![a.user, b.user];
    for (name, sql) in [
        ("meeting_breakouts", "SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY meeting_id,idx,id),'[]')::text FROM meeting_breakouts t WHERE meeting_id IN (SELECT id FROM meetings WHERE owner_user_id = ANY($1))"),
        ("meeting_join_requests", "SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY id),'[]')::text FROM meeting_join_requests t WHERE meeting_id IN (SELECT id FROM meetings WHERE owner_user_id = ANY($1))"),
        ("meeting_lobby_mint_fences", "SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY join_request_id,identity),'[]')::text FROM meeting_lobby_mint_fences t WHERE meeting_id IN (SELECT id FROM meetings WHERE owner_user_id = ANY($1))"),
        ("meeting_recordings", "SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY id),'[]')::text FROM meeting_recordings t WHERE meeting_id IN (SELECT id FROM meetings WHERE owner_user_id = ANY($1))"),
    ] {
        let raw: String = c.query_one(sql, &[&users]).await?.get(0);
        out[name] = serde_json::from_str(&raw)?;
    }
    Ok(out)
}
