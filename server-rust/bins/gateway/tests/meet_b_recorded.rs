//! #287: F13 sub-router-b routes (recording, captions, presentation, annotation)
//! recorded from frozen Go through the front door. Recording runs Go behind an
//! empty route table against a fake LiveKit/Egress/ASR; replay unsets Go and
//! serves the routes natively against identical fakes. Peripheral calls are part
//! of every observation.
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
use peripherals::{decode_tokens, Asr, Fake, ASR_TOKEN, KEY, SECRET};
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
macro_rules! rejects {
    ($($name:ident = $route:literal, $kind:ident;)*) => {$(
        #[tokio::test]
        async fn $name() -> Result<(), BoxError> {
            reject($route, Mutant::$kind).await
        }
    )*};
}

cases! {
    rec_start_success = "rec_start", "success";
    rec_start_member = "rec_start", "member";
    rec_start_stranger = "rec_start", "stranger";
    rec_start_invalid_id = "rec_start", "invalid_id";
    rec_start_missing = "rec_start", "missing";
    rec_start_disabled = "rec_start", "disabled";
    rec_start_drive_off = "rec_start", "drive_off";
    rec_start_no_egress = "rec_start", "no_egress";
    rec_start_not_live = "rec_start", "not_live";
    rec_start_repeat = "rec_start", "repeat";
    rec_start_busy = "rec_start", "busy";
    rec_start_egress_fail = "rec_start", "egress_fail";
    rec_start_guest = "rec_start", "guest";
    rec_start_commit_before = "rec_start", "commit_before";
    rec_start_commit_after = "rec_start", "commit_after";
    rec_stop_success = "rec_stop", "success";
    rec_stop_member = "rec_stop", "member";
    rec_stop_stranger = "rec_stop", "stranger";
    rec_stop_invalid_id = "rec_stop", "invalid_id";
    rec_stop_none = "rec_stop", "none";
    rec_stop_no_egress = "rec_stop", "no_egress";
    rec_stop_egress_fail = "rec_stop", "egress_fail";
    rec_stop_flag_off = "rec_stop", "flag_off";
    rec_stop_repeat = "rec_stop", "repeat";
    rec_stop_commit_before = "rec_stop", "commit_before";
    rec_stop_commit_after = "rec_stop", "commit_after";
    cap_start_repeat = "cap_start", "repeat";
    cap_start_success = "cap_start", "success";
    cap_start_already_on = "cap_start", "already_on";
    cap_start_member = "cap_start", "member";
    cap_start_stranger = "cap_start", "stranger";
    cap_start_invalid_id = "cap_start", "invalid_id";
    cap_start_missing = "cap_start", "missing";
    cap_start_disabled = "cap_start", "disabled";
    cap_start_no_asr = "cap_start", "no_asr";
    cap_start_busy = "cap_start", "busy";
    cap_start_asr_fail = "cap_start", "asr_fail";
    cap_start_commit_before = "cap_start", "commit_before";
    cap_start_commit_after = "cap_start", "commit_after";
    cap_stop_repeat = "cap_stop", "repeat";
    cap_stop_success = "cap_stop", "success";
    cap_stop_already_off = "cap_stop", "already_off";
    cap_stop_member = "cap_stop", "member";
    cap_stop_stranger = "cap_stop", "stranger";
    cap_stop_invalid_id = "cap_stop", "invalid_id";
    cap_stop_no_asr = "cap_stop", "no_asr";
    cap_stop_asr_fail = "cap_stop", "asr_fail";
    cap_stop_flag_off = "cap_stop", "flag_off";
    cap_stop_commit_before = "cap_stop", "commit_before";
    cap_stop_commit_after = "cap_stop", "commit_after";
    prepare_repeat = "prepare", "repeat";
    prepare_success = "prepare", "success";
    prepare_member = "prepare", "member";
    prepare_stranger = "prepare", "stranger";
    prepare_invalid_id = "prepare", "invalid_id";
    prepare_bad_json = "prepare", "bad_json";
    prepare_bad_type = "prepare", "bad_type";
    prepare_bad_digest = "prepare", "bad_digest";
    prepare_gone = "prepare", "gone";
    prepare_no_rights = "prepare", "no_rights";
    prepare_duplicate = "prepare", "duplicate";
    prepare_not_live = "prepare", "not_live";
    prepare_ended = "prepare", "ended";
    prepare_missing = "prepare", "missing";
    prepare_disabled = "prepare", "disabled";
    prepare_drive_off = "prepare", "drive_off";
    prepare_commit_before = "prepare", "commit_before";
    prepare_commit_after = "prepare", "commit_after";
    ready_repeat = "ready", "repeat";
    ready_success = "ready", "success";
    ready_null_digest = "ready", "null_digest";
    ready_member = "ready", "member";
    ready_stranger = "ready", "stranger";
    ready_invalid_id = "ready", "invalid_id";
    ready_invalid_pid = "ready", "invalid_pid";
    ready_bad_json = "ready", "bad_json";
    ready_bad_digest = "ready", "bad_digest";
    ready_wrong_state = "ready", "wrong_state";
    ready_missing_pres = "ready", "missing_pres";
    ready_disabled = "ready", "disabled";
    ready_drive_off = "ready", "drive_off";
    start_repeat = "start", "repeat";
    start_success = "start", "success";
    start_stale = "start", "stale";
    start_member = "start", "member";
    start_stranger = "start", "stranger";
    start_wrong_state = "start", "wrong_state";
    start_invalid_id = "start", "invalid_id";
    start_bad_json = "start", "bad_json";
    start_missing_pres = "start", "missing_pres";
    start_disabled = "start", "disabled";
    page_repeat = "page", "repeat";
    page_success = "page", "success";
    page_as_presenter = "page", "as_presenter";
    page_missing_field = "page", "missing_field";
    page_stale_seq = "page", "stale_seq";
    page_stale_gen = "page", "stale_gen";
    page_out_of_range = "page", "out_of_range";
    page_huge = "page", "huge";
    page_member = "page", "member";
    page_stranger = "page", "stranger";
    page_wrong_state = "page", "wrong_state";
    page_invalid_pid = "page", "invalid_pid";
    page_bad_json = "page", "bad_json";
    page_disabled = "page", "disabled";
    presenter_repeat = "presenter", "repeat";
    presenter_grant = "presenter", "grant";
    presenter_takeover = "presenter", "takeover";
    presenter_member = "presenter", "member";
    presenter_stranger = "presenter", "stranger";
    presenter_bad_target = "presenter", "bad_target";
    presenter_stale_gen = "presenter", "stale_gen";
    presenter_bad_json = "presenter", "bad_json";
    presenter_wrong_state = "presenter", "wrong_state";
    presenter_disabled = "presenter", "disabled";
    source_repeat = "source", "repeat";
    source_success = "source", "success";
    source_same_version = "source", "same_version";
    source_no_rights = "source", "no_rights";
    source_gone = "source", "gone";
    source_stale_gen = "source", "stale_gen";
    source_stale_seq = "source", "stale_seq";
    source_member = "source", "member";
    source_stranger = "source", "stranger";
    source_bad_digest = "source", "bad_digest";
    source_bad_json = "source", "bad_json";
    source_disabled = "source", "disabled";
    degrade_repeat = "degrade", "repeat";
    degrade_success = "degrade", "success";
    degrade_no_reason = "degrade", "no_reason";
    degrade_wrong_state = "degrade", "wrong_state";
    degrade_stale_gen = "degrade", "stale_gen";
    degrade_stale_presenter = "degrade", "stale_presenter";
    degrade_member = "degrade", "member";
    degrade_stranger = "degrade", "stranger";
    degrade_bad_json = "degrade", "bad_json";
    degrade_disabled = "degrade", "disabled";
    recover_repeat = "recover", "repeat";
    recover_success = "recover", "success";
    recover_wrong_state = "recover", "wrong_state";
    recover_stale_gen = "recover", "stale_gen";
    recover_member = "recover", "member";
    recover_stranger = "recover", "stranger";
    recover_bad_json = "recover", "bad_json";
    recover_disabled = "recover", "disabled";
    pres_end_repeat = "pres_end", "repeat";
    pres_end_success = "pres_end", "success";
    pres_end_cancel = "pres_end", "cancel";
    pres_end_flag_off = "pres_end", "flag_off";
    pres_end_member = "pres_end", "member";
    pres_end_stranger = "pres_end", "stranger";
    pres_end_stale_gen = "pres_end", "stale_gen";
    pres_end_stale_presenter = "pres_end", "stale_presenter";
    pres_end_already_ended = "pres_end", "already_ended";
    pres_end_degraded = "pres_end", "degraded";
    pres_end_invalid_id = "pres_end", "invalid_id";
    pres_end_bad_json = "pres_end", "bad_json";
    pres_end_missing_pres = "pres_end", "missing_pres";
    revoke_repeat = "revoke", "repeat";
    revoke_success = "revoke", "success";
    revoke_no_reason = "revoke", "no_reason";
    revoke_member = "revoke", "member";
    revoke_stranger = "revoke", "stranger";
    revoke_already_ended = "revoke", "already_ended";
    revoke_flag_off = "revoke", "flag_off";
    revoke_invalid_id = "revoke", "invalid_id";
    revoke_bad_json = "revoke", "bad_json";
    checkpoint_success = "checkpoint", "success";
    checkpoint_ended = "checkpoint", "ended";
    checkpoint_annotated = "checkpoint", "annotated";
    checkpoint_member = "checkpoint", "member";
    checkpoint_stranger = "checkpoint", "stranger";
    checkpoint_invalid_id = "checkpoint", "invalid_id";
    checkpoint_invalid_pid = "checkpoint", "invalid_pid";
    checkpoint_missing_pres = "checkpoint", "missing_pres";
    checkpoint_flag_off = "checkpoint", "flag_off";
    checkpoint_throttled = "checkpoint", "throttled";
    ann_commit_repeat = "ann_commit", "repeat";
    ann_commit_snapshot = "ann_commit", "snapshot";
    ann_commit_unicode = "ann_commit", "unicode";
    ann_commit_clear = "ann_commit", "clear";
    ann_commit_both = "ann_commit", "both";
    ann_commit_neither = "ann_commit", "neither";
    ann_commit_missing_field = "ann_commit", "missing_field";
    ann_commit_empty = "ann_commit", "empty";
    ann_commit_oversize = "ann_commit", "oversize";
    ann_commit_stale_gen = "ann_commit", "stale_gen";
    ann_commit_stale_seq = "ann_commit", "stale_seq";
    ann_commit_member = "ann_commit", "member";
    ann_commit_stranger = "ann_commit", "stranger";
    ann_commit_wrong_state = "ann_commit", "wrong_state";
    ann_commit_bad_json = "ann_commit", "bad_json";
    ann_commit_disabled = "ann_commit", "disabled";
    ann_read_none = "ann_read", "none";
    ann_read_snapshot = "ann_read", "snapshot";
    ann_read_member = "ann_read", "member";
    ann_read_stranger = "ann_read", "stranger";
    ann_read_invalid_id = "ann_read", "invalid_id";
    ann_read_missing_pres = "ann_read", "missing_pres";
    ann_read_flag_off = "ann_read", "flag_off";
}

// Every route's planted mutants: a changed status, a silent peripheral (the
// routes that talk to one) and a missing tenant filter.
rejects! {
    rec_start_rejects_status = "rec_start", Status;
    rec_stop_rejects_status = "rec_stop", Status;
    cap_start_rejects_status = "cap_start", Status;
    cap_stop_rejects_status = "cap_stop", Status;
    prepare_rejects_status = "prepare", Status;
    ready_rejects_status = "ready", Status;
    start_rejects_status = "start", Status;
    page_rejects_status = "page", Status;
    presenter_rejects_status = "presenter", Status;
    source_rejects_status = "source", Status;
    degrade_rejects_status = "degrade", Status;
    recover_rejects_status = "recover", Status;
    pres_end_rejects_status = "pres_end", Status;
    revoke_rejects_status = "revoke", Status;
    checkpoint_rejects_status = "checkpoint", Status;
    ann_commit_rejects_status = "ann_commit", Status;
    ann_read_rejects_status = "ann_read", Status;
    rec_start_rejects_silent = "rec_start", Silent;
    rec_stop_rejects_silent = "rec_stop", Silent;
    cap_start_rejects_silent = "cap_start", Silent;
    cap_stop_rejects_silent = "cap_stop", Silent;
    rec_start_rejects_no_tenant_filter = "rec_start", Shadow;
    rec_stop_rejects_no_tenant_filter = "rec_stop", Shadow;
    cap_start_rejects_no_tenant_filter = "cap_start", Shadow;
    cap_stop_rejects_no_tenant_filter = "cap_stop", Shadow;
    prepare_rejects_no_tenant_filter = "prepare", Shadow;
    ready_rejects_no_tenant_filter = "ready", Shadow;
    start_rejects_no_tenant_filter = "start", Shadow;
    page_rejects_no_tenant_filter = "page", Shadow;
    presenter_rejects_no_tenant_filter = "presenter", Shadow;
    source_rejects_no_tenant_filter = "source", Shadow;
    degrade_rejects_no_tenant_filter = "degrade", Shadow;
    recover_rejects_no_tenant_filter = "recover", Shadow;
    pres_end_rejects_no_tenant_filter = "pres_end", Shadow;
    revoke_rejects_no_tenant_filter = "revoke", Shadow;
    checkpoint_rejects_no_tenant_filter = "checkpoint", Shadow;
    ann_commit_rejects_no_tenant_filter = "ann_commit", Shadow;
    ann_read_rejects_no_tenant_filter = "ann_read", Shadow;
}

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn route_spec(route: &str) -> (&'static str, &'static str) {
    match route {
        "rec_start" => ("POST", "/meet/{id}/recording"),
        "rec_stop" => ("DELETE", "/meet/{id}/recording"),
        "cap_start" => ("POST", "/meet/{id}/captions"),
        "cap_stop" => ("DELETE", "/meet/{id}/captions"),
        "prepare" => ("POST", "/meet/{id}/presentation"),
        "ready" => ("POST", "/meet/{id}/presentation/{pid}/ready"),
        "start" => ("POST", "/meet/{id}/presentation/{pid}/start"),
        "page" => ("POST", "/meet/{id}/presentation/{pid}/page"),
        "presenter" => ("POST", "/meet/{id}/presentation/{pid}/presenter"),
        "source" => ("POST", "/meet/{id}/presentation/{pid}/source"),
        "degrade" => ("POST", "/meet/{id}/presentation/{pid}/degrade"),
        "recover" => ("POST", "/meet/{id}/presentation/{pid}/recover"),
        "pres_end" => ("POST", "/meet/{id}/presentation/{pid}/end"),
        "revoke" => ("POST", "/meet/{id}/presentation/{pid}/revoke"),
        "checkpoint" => ("GET", "/meet/{id}/presentation/{pid}/checkpoint"),
        "ann_commit" => ("POST", "/meet/{id}/presentation/{pid}/annotation"),
        "ann_read" => ("GET", "/meet/{id}/presentation/{pid}/annotation"),
        _ => unreachable!("unknown meet route"),
    }
}

/// Where a presentation is when the request arrives.
#[derive(Clone, Copy, PartialEq, PartialOrd)]
enum Stage {
    /// No session at all.
    None,
    Prepared,
    Ready,
    Active,
    Degraded,
    Ended,
    /// Active with a committed annotation snapshot.
    Annotated,
    /// Active, with the plain member holding the presenter role.
    MemberPresents,
}

fn is_presentation(route: &str) -> bool {
    !matches!(route, "rec_start" | "rec_stop" | "cap_start" | "cap_stop")
}

fn stage(route: &str, case: &str) -> Stage {
    use Stage::*;
    match (route, case) {
        ("prepare", "duplicate") => Prepared,
        ("prepare", _) => None,
        ("ready", "wrong_state") => Active,
        ("ready", _) => Prepared,
        ("start", "wrong_state") => Prepared,
        ("start", _) => Ready,
        ("page", "wrong_state") | ("degrade", "wrong_state") | ("ann_commit", "wrong_state") => {
            Ready
        }
        ("page", "as_presenter") => MemberPresents,
        ("presenter", "wrong_state") | ("pres_end" | "revoke", "already_ended") => Ended,
        ("recover", "wrong_state") => Active,
        ("recover", _) | ("pres_end", "degraded") => Degraded,
        ("pres_end", "cancel") => Prepared,
        ("degrade" | "pres_end", "stale_presenter") => MemberPresents,
        ("checkpoint", "ended") => Ended,
        ("checkpoint" | "ann_read", "annotated" | "snapshot") => Annotated,
        (route, _) if is_presentation(route) => Active,
        _ => None,
    }
}

/// The status frozen Go answers for each case; a recording that disagrees is
/// a broken fixture, never a golden.
fn expected_status(route: &str, case: &str) -> u16 {
    let ok = match route {
        "rec_start" | "prepare" => 201,
        "rec_stop" | "cap_start" | "cap_stop" => 204,
        _ => 200,
    };
    match (route, case) {
        (_, "commit_before" | "commit_after") => 503,
        (_, "disabled" | "drive_off") => 404,
        (_, "invalid_id" | "invalid_pid" | "bad_json" | "bad_type") => 400,
        (_, "member" | "stranger") => match route {
            // A non-participant cannot see the meeting or its presentation at all.
            _ if case == "stranger" && (is_presentation(route) || route == "rec_start") => 404,
            // The meeting row lock is invisible to a plain member (row-level security).
            "prepare" | "rec_start" if case == "member" => 404,
            "checkpoint" | "ann_read" => 200,
            _ => 403,
        },
        (_, "missing_pres") => 404,
        // Host and cohost bypass the generation fence on the authority verbs.
        ("degrade" | "pres_end" | "presenter" | "recover", "stale_gen") => 200,
        (_, "stale" | "stale_gen" | "stale_seq" | "stale_presenter") => 409,
        ("rec_start", "missing") | ("prepare", "missing") => 404,
        ("cap_start", "missing") => 403,
        ("rec_start", "no_egress") | ("rec_stop", "no_egress") | ("cap_start", "no_asr") => 503,
        ("cap_stop", "no_asr") => 204,
        ("rec_start", "not_live" | "repeat") | ("rec_stop", "none" | "repeat") => 409,
        ("rec_start", "busy") => 503,
        ("rec_start", "egress_fail") | ("rec_stop", "egress_fail") => 502,
        ("rec_start", "guest") => 403,
        ("cap_start", "busy") => 503,
        ("cap_start", "asr_fail") | ("cap_stop", "asr_fail") => 502,
        ("prepare", "bad_digest" | "gone") => match case {
            "gone" => 404,
            _ => 422,
        },
        ("prepare", "no_rights") => 404,
        ("prepare", "duplicate" | "not_live" | "ended") => 409,
        ("ready", "bad_digest") => 422,
        ("source", "bad_digest" | "same_version") => 422,
        ("source", "no_rights") => 404,
        ("source", "gone") => 404,
        ("page", "missing_field") => 400,
        ("page", "out_of_range") => 422,
        ("page", "huge") => 500,
        ("presenter", "bad_target") => 403,
        ("cap_start" | "cap_stop", "repeat") => 204,
        ("presenter", "repeat") => 200,
        (_, "repeat" | "wrong_state" | "already_ended" | "degraded") => 409,
        ("ann_commit", "both" | "neither" | "missing_field") => 400,
        ("ann_commit", "empty" | "oversize") => 403,
        ("checkpoint", "throttled") => 429,
        _ => ok,
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Mutant {
    None,
    /// The adapter answers a status the recording does not.
    Status,
    /// The adapter performs its reducer call but never talks to a peripheral.
    Silent,
    /// A private schema makes every actor read as host and attendee.
    Shadow,
}

async fn reject(route: &str, mutant: Mutant) -> Result<(), BoxError> {
    let success = match route {
        "presenter" => "grant",
        "ann_commit" => "snapshot",
        "ann_read" => "none",
        _ => "success",
    };
    let (case, what, kind) = match (route, mutant) {
        (_, Mutant::Status) => (success, "/response/status", "changed-status"),
        (_, Mutant::Silent) => (success, "/peripherals", "silent-peripheral"),
        ("checkpoint" | "ann_read", _) => ("stranger", "/response/status", "no-tenant-filter"),
        // A caller who is only a participant must still be refused.
        _ => ("member", "/response/status", "no-tenant-filter"),
    };
    let err = run(route, case, mutant)
        .await
        .expect_err("a planted mutant must fail the immutable recording");
    let text = err.to_string();
    assert!(
        text.contains(what) || text.contains("/response/status"),
        "{err}"
    );
    let (method, canonical) = route_spec(route);
    println!("MUTANT-REJECTED: {method} {canonical} :: {kind}");
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
    pres: i64,
    generation: i64,
    seq: i64,
    node: i64,
    version: i64,
    other_version: i64,
    member_node: i64,
    member_version: i64,
    member_participant: i64,
}

async fn scalar(c: &tokio_postgres::Client, sql: &str) -> Result<Value, BoxError> {
    let raw: String = c.query_one(sql, &[]).await?.get(0);
    Ok(serde_json::from_str(&raw)?)
}

async fn number(c: &tokio_postgres::Client, sql: &str) -> Result<i64, BoxError> {
    Ok(c.query_one(sql, &[]).await?.get(0))
}

const DIGEST: &str = "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef";

async fn seed(
    c: &tokio_postgres::Client,
    a: &fixture::Account,
    b: &fixture::Account,
    route: &str,
    case: &str,
) -> Result<Seed, BoxError> {
    let mut out = Seed {
        own: 0,
        pres: 0,
        generation: 0,
        seq: 0,
        node: 0,
        version: 0,
        other_version: 0,
        member_node: 0,
        member_version: 0,
        member_participant: 0,
    };
    let guests = if (route, case) == ("rec_start", "guest") {
        ",NULL,NULL,NULL,NULL,true"
    } else {
        ""
    };
    let own = scalar(
        c,
        &format!(
            "SELECT meeting_create({},'Meet3 seed owner'{guests})::text",
            a.user
        ),
    )
    .await?;
    out.own = own["meetingId"].as_i64().unwrap();
    let slug = own["slug"].as_str().unwrap().to_owned();
    let live = !matches!(
        (route, case),
        ("rec_start", "not_live") | ("prepare", "not_live")
    );
    if live {
        c.execute(&format!("SELECT meeting_join({},{})", a.user, out.own), &[])
            .await?;
        // The SFU's room_started fact is what makes a meeting live.
        c.execute(
            &format!(
                "SELECT meeting_participant_event(room_name,'room_started',NULL) FROM meetings WHERE id={}",
                out.own
            ),
            &[],
        )
        .await?;
    }
    if (route, case) == ("prepare", "ended") {
        c.execute(
            "UPDATE meetings SET state='ended', ended_at=now() WHERE id=$1",
            &[&out.own],
        )
        .await?;
    }
    let stranger = case == "stranger";
    let presentation = is_presentation(route);
    let b_member = !stranger
        && (presentation
            || matches!(case, "member")
            || matches!(route, "rec_stop" | "cap_stop") && case == "member");
    if b_member {
        c.execute(
            "INSERT INTO meeting_participants(meeting_id,user_id,identity,role,joined_at) VALUES($1,$2,'u:'||$2::bigint::text,'member',now())",
            &[&out.own, &b.user],
        )
        .await?;
        out.member_participant = number(
            c,
            &format!(
                "SELECT id FROM meeting_participants WHERE meeting_id={} AND user_id={}",
                out.own, b.user
            ),
        )
        .await?;
    }
    if presentation {
        // Drive: a file with two versions for the host, one for the member.
        let space = number(
            c,
            &format!(
                "SELECT drive_space_create({},'meet3-space','regular')",
                a.user
            ),
        )
        .await?;
        out.node = number(
            c,
            &format!(
                "SELECT drive_node_create({},{space},NULL,'file','deck.pdf')",
                a.user
            ),
        )
        .await?;
        out.version = number(
            c,
            &format!("INSERT INTO drive_file_versions (file_node_id, space_id, content_sha256, size_bytes, author_user_id) VALUES ({},{space},repeat('ab',32),1,{}) RETURNING id", out.node, a.user),
        )
        .await?;
        out.other_version = number(
            c,
            &format!("INSERT INTO drive_file_versions (file_node_id, space_id, content_sha256, size_bytes, author_user_id) VALUES ({},{space},repeat('cd',32),1,{}) RETURNING id", out.node, a.user),
        )
        .await?;
        c.execute(
            &format!(
                "UPDATE drive_files SET head_version_id = {} WHERE node_id = {}",
                out.version, out.node
            ),
            &[],
        )
        .await?;
        let mspace = number(
            c,
            &format!(
                "SELECT drive_space_create({},'meet3-member-space','regular')",
                b.user
            ),
        )
        .await?;
        out.member_node = number(
            c,
            &format!(
                "SELECT drive_node_create({},{mspace},NULL,'file','member.pdf')",
                b.user
            ),
        )
        .await?;
        out.member_version = number(
            c,
            &format!("INSERT INTO drive_file_versions (file_node_id, space_id, content_sha256, size_bytes, author_user_id) VALUES ({},{mspace},repeat('12',32),1,{}) RETURNING id", out.member_node, b.user),
        )
        .await?;
        let st = stage(route, case);
        let host = a.user;
        let m = out.own;
        if st >= Stage::Prepared {
            out.pres = number(
                c,
                &format!(
                    "SELECT meeting_presentation_prepare({host},{m},{},{},'{DIGEST}')",
                    out.node, out.version
                ),
            )
            .await?;
        }
        let pid = out.pres;
        let step = |sql: String| {
            let c = &c;
            async move { c.execute(&sql, &[]).await.map(|_| ()) }
        };
        if st >= Stage::Ready {
            step(format!(
                "SELECT meeting_presentation_ready({host},{m},{pid},NULL)"
            ))
            .await?;
        }
        if matches!(
            st,
            Stage::Active
                | Stage::Degraded
                | Stage::Annotated
                | Stage::MemberPresents
                | Stage::Ended
        ) {
            step(format!(
                "SELECT meeting_presentation_start({host},{m},{pid},NULL)"
            ))
            .await?;
        }
        if st == Stage::Degraded {
            step(format!(
                "SELECT meeting_presentation_degrade({host},{m},{pid},NULL,'seed')"
            ))
            .await?;
        }
        if st == Stage::MemberPresents {
            step(format!(
                "SELECT meeting_presentation_presenter({host},{m},{pid},{},false,NULL)",
                out.member_participant
            ))
            .await?;
        }
        if st == Stage::Annotated {
            let (generation, seq) = (
                number(
                    c,
                    &format!(
                        "SELECT presenter_generation FROM meeting_presentations WHERE id={pid}"
                    ),
                )
                .await?,
                number(
                    c,
                    &format!("SELECT checkpoint_seq FROM meeting_presentations WHERE id={pid}"),
                )
                .await?,
            );
            step(format!(
                "SELECT meeting_presentation_annotation_commit({host},{m},{pid},{generation},{seq},false,'{{\"strokes\":[]}}',14)"
            ))
            .await?;
        }
        if st == Stage::Ended {
            step(format!(
                "SELECT meeting_presentation_end({host},{m},{pid},NULL)"
            ))
            .await?;
        }
        if st >= Stage::Prepared {
            out.generation = number(
                c,
                &format!("SELECT presenter_generation FROM meeting_presentations WHERE id={pid}"),
            )
            .await?;
            out.seq = number(
                c,
                &format!("SELECT checkpoint_seq FROM meeting_presentations WHERE id={pid}"),
            )
            .await?;
        }
    }
    match (route, case) {
        ("rec_stop", "success" | "egress_fail" | "flag_off" | "repeat" | "member" | "stranger")
        | ("rec_stop", "commit_before" | "commit_after") => {
            c.execute(
                "INSERT INTO meeting_recordings(meeting_id,egress_id,state,started_by,staging_key) VALUES($1,'EG_meet3_seed','active',$2,'meet-egress/seed.mp4')",
                &[&out.own, &a.user],
            )
            .await?;
        }
        ("cap_start", "already_on")
        | (
            "cap_stop",
            "success" | "asr_fail" | "flag_off" | "repeat" | "commit_before" | "commit_after",
        ) => {
            c.execute(
                "UPDATE meetings SET settings = settings || '{\"captionsOn\":true}'::jsonb WHERE id=$1",
                &[&out.own],
            )
            .await?;
        }
        ("rec_start", "guest") => {
            // An admitted guest: the lobby admits the request.
            let made = scalar(
                c,
                &format!("SELECT meeting_join_request_create('{slug}','Meet3 guest')::text"),
            )
            .await?;
            let id = made["requestId"].as_i64().unwrap();
            c.execute(&format!("SELECT meeting_admit({},{id})", a.user), &[])
                .await?;
        }
        _ => {}
    }
    Ok(out)
}

/// What one case sends. The body is a final byte string.
struct Plan {
    path: String,
    body: Vec<u8>,
    actor_b: bool,
    /// How many times the request is sent; the first is kept apart.
    times: usize,
}

fn build(route: &str, case: &str, s: &Seed) -> Plan {
    let meeting = if case == "missing" { i64::MAX } else { s.own };
    let mut id = meeting.to_string();
    let mut pid = if case == "missing_pres" {
        i64::MAX.to_string()
    } else {
        s.pres.to_string()
    };
    if case == "invalid_id" {
        id = "bad".into();
    }
    if case == "invalid_pid" {
        pid = "bad".into();
    }
    let (_, canonical) = route_spec(route);
    let path = canonical.replace("{id}", &id).replace("{pid}", &pid);
    let path = format!("/api{path}");
    let (generation, seq) = (s.generation, s.seq);
    let stale = |v: i64| v + 41;
    let mut body = Value::Null;
    match route {
        "prepare" => {
            body = json!({"nodeId": s.node, "versionId": s.version, "manifestDigest": DIGEST});
            match case {
                "bad_type" => {
                    body = json!({"nodeId": "x", "versionId": 1, "manifestDigest": DIGEST})
                }
                "bad_digest" => body["manifestDigest"] = json!("nothex"),
                "gone" => body["versionId"] = json!(s.member_version),
                "no_rights" => {
                    body = json!({"nodeId": s.member_node, "versionId": s.member_version, "manifestDigest": DIGEST})
                }
                _ => {}
            }
        }
        "ready" => {
            body = json!({"manifestDigest": DIGEST});
            match case {
                "null_digest" => body = json!({"manifestDigest": null}),
                "bad_digest" => body = json!({"manifestDigest": "nothex"}),
                _ => {}
            }
        }
        "start" => {
            body = json!({"presenterGeneration": generation});
            if case == "stale" {
                body = json!({"presenterGeneration": stale(generation)});
            }
        }
        "page" => {
            body = json!({"presenterGeneration": generation, "checkpointSeq": seq, "pageIndex": 3});
            match case {
                "missing_field" => {
                    body = json!({"presenterGeneration": generation, "pageIndex": 3})
                }
                "stale_seq" => body["checkpointSeq"] = json!(stale(seq)),
                "stale_gen" => body["presenterGeneration"] = json!(stale(generation)),
                "out_of_range" => body["pageIndex"] = json!(500),
                "huge" => body["pageIndex"] = json!(3_000_000_000i64),
                _ => {}
            }
        }
        "presenter" => {
            body = json!({"targetParticipantId": s.member_participant, "takeover": false, "presenterGeneration": generation});
            match case {
                "takeover" => {
                    body = json!({"targetParticipantId": s.member_participant, "takeover": true})
                }
                "bad_target" => body["targetParticipantId"] = json!(0),
                "stale_gen" => body["presenterGeneration"] = json!(stale(generation)),
                _ => {}
            }
        }
        "source" => {
            body = json!({"nodeId": s.node, "versionId": s.other_version, "manifestDigest": DIGEST,
                "presenterGeneration": generation, "checkpointSeq": seq});
            match case {
                "same_version" => body["versionId"] = json!(s.version),
                "no_rights" => {
                    body["nodeId"] = json!(s.member_node);
                    body["versionId"] = json!(s.member_version);
                }
                "gone" => body["versionId"] = json!(s.member_version),
                "stale_gen" => body["presenterGeneration"] = json!(stale(generation)),
                "stale_seq" => body["checkpointSeq"] = json!(stale(seq)),
                "bad_digest" => body["manifestDigest"] = json!("nothex"),
                _ => {}
            }
        }
        "degrade" => {
            body = json!({"presenterGeneration": generation, "reason": "renderer lost <b>"});
            match case {
                "no_reason" => body = json!({"presenterGeneration": generation}),
                "stale_gen" | "stale_presenter" => {
                    body["presenterGeneration"] = json!(stale(generation))
                }
                _ => {}
            }
        }
        "recover" | "pres_end" => {
            body = json!({"presenterGeneration": generation});
            if matches!(case, "stale_gen" | "stale_presenter") {
                body = json!({"presenterGeneration": stale(generation)});
            }
        }
        "revoke" => {
            body = json!({"reason": "policy"});
            if case == "no_reason" {
                body = json!({});
            }
        }
        "ann_commit" => {
            body = json!({"presenterGeneration": generation, "checkpointSeq": seq, "snapshot": "{\"strokes\":[1,2,3]}"});
            match case {
                "unicode" => body["snapshot"] = json!("{\"label\":\"\u{4e2d}\u{6587} \u{1f600}\"}"),
                "clear" => {
                    body = json!({"presenterGeneration": generation, "checkpointSeq": seq, "clear": true})
                }
                "both" => body["clear"] = json!(true),
                "neither" => {
                    body = json!({"presenterGeneration": generation, "checkpointSeq": seq})
                }
                "missing_field" => body = json!({"snapshot": "{}"}),
                "empty" => body["snapshot"] = json!(""),
                "oversize" => body["snapshot"] = json!("x".repeat(16 * 1024 + 1)),
                "stale_gen" => body["presenterGeneration"] = json!(stale(generation)),
                "stale_seq" => body["checkpointSeq"] = json!(stale(seq)),
                _ => {}
            }
        }
        _ => {}
    }
    let mut bytes = if body.is_null() {
        Vec::new()
    } else {
        body.to_string().into_bytes()
    };
    if case == "bad_json" {
        bytes = b"{".to_vec();
    }
    let actor_b = matches!(
        case,
        "member" | "stranger" | "as_presenter" | "stale_presenter"
    );
    Plan {
        path,
        body: bytes,
        actor_b,
        times: if case == "throttled" {
            3
        } else if case == "repeat" {
            2
        } else {
            1
        },
    }
}

/// Base snapshot plus every table the sub-router-b routes can write.
async fn snapshot_b(
    c: &tokio_postgres::Client,
    a: &fixture::Account,
    b: &fixture::Account,
) -> Result<Value, BoxError> {
    let mut out = snapshot(c, a, b).await?;
    let users = vec![a.user, b.user];
    for (name, sql) in [
        ("meeting_recordings", "SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY id),'[]')::text FROM meeting_recordings t WHERE meeting_id IN (SELECT id FROM meetings WHERE owner_user_id = ANY($1))"),
        ("meeting_presentations", "SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY id),'[]')::text FROM meeting_presentations t WHERE meeting_id IN (SELECT id FROM meetings WHERE owner_user_id = ANY($1))"),
        ("meeting_presentation_events", "SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY presentation_id,checkpoint_seq),'[]')::text FROM meeting_presentation_events t WHERE meeting_id IN (SELECT id FROM meetings WHERE owner_user_id = ANY($1))"),
        ("meeting_presentation_annotations", "SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY presentation_id,checkpoint_seq),'[]')::text FROM meeting_presentation_annotations t WHERE meeting_id IN (SELECT id FROM meetings WHERE owner_user_id = ANY($1))"),
    ] {
        let raw: String = c.query_one(sql, &[&users]).await?.get(0);
        out[name] = serde_json::from_str(&raw)?;
    }
    Ok(out)
}

/// Drive objects the presentation cases seed, then the shared meet cleanup.
async fn clean(
    c: &tokio_postgres::Client,
    a: &fixture::Account,
    b: &fixture::Account,
) -> Result<(), BoxError> {
    let users = vec![a.user, b.user];
    c.execute(
        "DELETE FROM meeting_presentations WHERE meeting_id IN (SELECT id FROM meetings WHERE owner_user_id = ANY($1))",
        &[&users],
    )
    .await?;
    c.execute(
        "DELETE FROM drive_nodes WHERE space_id IN (SELECT id FROM drive_spaces WHERE owner_user_id = ANY($1))",
        &[&users],
    )
    .await?;
    c.execute(
        "DELETE FROM drive_audit_log WHERE space_id IN (SELECT id FROM drive_spaces WHERE owner_user_id = ANY($1))",
        &[&users],
    )
    .await
    .ok();
    c.batch_execute(&format!(
        "BEGIN; SET LOCAL session_replication_role=replica; \
         DELETE FROM drive_audit_log WHERE space_id IN (SELECT id FROM drive_spaces WHERE owner_user_id IN ({0},{1})); COMMIT;",
        a.user, b.user
    ))
    .await?;
    c.execute(
        "DELETE FROM drive_spaces WHERE owner_user_id = ANY($1)",
        &[&users],
    )
    .await?;
    cleanup(c, &[a, b]).await
}

async fn run(route: &str, case: &str, mutant: Mutant) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let recording_env = std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
    if (mutant != Mutant::None || case.starts_with("commit_")) && recording_env {
        return Err("cannot record a planted mutant or COMMIT-loss case".into());
    }
    let Some(db) = Db::for_case("meet3") else {
        return Ok(());
    };
    let c = db.connect().await?;
    let a = fixture::account(&c, "meet3-owner").await?;
    let b = fixture::account(&c, "meet3-foreign").await?;
    let toggles = [
        "feature.meet",
        "feature.drive",
        "feature.meet_recording",
        "feature.meet_captions",
        "feature.meet_document_presentation",
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
    let asr = Asr::start().await;
    let result = std::panic::AssertUnwindSafe(async {
        let (method, canonical) = route_spec(route);
        let gate = match route {
            "rec_start" | "rec_stop" => "feature.meet_recording",
            "cap_start" | "cap_stop" => "feature.meet_captions",
            _ => "feature.meet_document_presentation",
        };
        let gate_off = matches!(case, "disabled" | "flag_off");
        for (key, on) in [
            ("feature.meet", true),
            ("feature.drive", case != "drive_off"),
            ("feature.meet_recording", !(gate == "feature.meet_recording" && gate_off)),
            ("feature.meet_captions", !(gate == "feature.meet_captions" && gate_off)),
            (
                "feature.meet_document_presentation",
                !(gate == "feature.meet_document_presentation" && gate_off),
            ),
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
            let schema = format!("gofree_meet3_mutant_{}", a.user);
            ledger(&format!("Plan private no-tenant-filter SQL mutant schema {schema}, assigned DB only"))?;
            c.batch_execute(&format!(
                "CREATE SCHEMA {schema}; GRANT USAGE ON SCHEMA {schema} TO setjoin_app; \
                 CREATE FUNCTION {schema}.meeting_member_role(bigint,bigint) RETURNS text LANGUAGE sql AS $$ SELECT 'host'::text $$; \
                 CREATE FUNCTION {schema}.meeting_attendee_role(bigint,bigint) RETURNS text LANGUAGE sql AS $$ SELECT 'host'::text $$; \
                 CREATE FUNCTION {schema}._meeting_presentation_participant_of(bigint,bigint) RETURNS bigint LANGUAGE sql AS \
                   $$ SELECT presenter_participant_id FROM public.meeting_presentations WHERE meeting_id=$1 ORDER BY id DESC LIMIT 1 $$;"
            ))
            .await?;
            if matches!(route, "rec_start" | "prepare") {
                // A plain member cannot lock the meeting row (row-level security),
                // so the mutant also removes that filter with an unfiltered view.
                c.batch_execute(&format!(
                    "CREATE VIEW {schema}.meetings AS SELECT * FROM public.meetings; \
                     GRANT SELECT, UPDATE ON {schema}.meetings TO setjoin_app;"
                ))
                .await?;
            }
            if matches!(route, "checkpoint" | "ann_read") {
                // Row-level security stops a stranger's read at the table, so the
                // mutant also removes that filter: views owned by the connecting
                // superuser read the tables unfiltered.
                c.batch_execute(&format!(
                    "CREATE VIEW {schema}.meeting_presentations AS SELECT * FROM public.meeting_presentations; \
                     CREATE VIEW {schema}.meeting_presentation_events AS SELECT * FROM public.meeting_presentation_events; \
                     CREATE VIEW {schema}.meeting_presentation_annotations AS SELECT * FROM public.meeting_presentation_annotations; \
                     GRANT SELECT ON {schema}.meeting_presentations, {schema}.meeting_presentation_events, {schema}.meeting_presentation_annotations TO setjoin_app;"
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
            ledger("Plan gofree-meet3 COMMIT-loss proxy on the assigned application DB")?;
            let (dsn, task) =
                common::commit::commit_cut_proxy(db.app.as_deref().unwrap_or(&db.dsn), cut).await;
            worker_app = Some(dsn);
            commit_wire = Some(task);
        }
        let egress = case != "no_egress";
        let asr_on = case != "no_asr";
        let livekit_url = format!("ws://{}", fake.addr);
        let asr_url = format!("http://{}", asr.addr);
        let mut go_env: Vec<(&str, String)> = vec![
            ("LIVEKIT_API_KEY", KEY.into()),
            ("LIVEKIT_API_SECRET", SECRET.into()),
            ("LIVEKIT_URL", livekit_url.clone()),
            ("MEET_EGRESS_ENABLED", egress.to_string()),
            ("S3_ENDPOINT", "http://127.0.0.1:9".into()),
        ];
        if asr_on {
            go_env.push(("ASR_URL", asr_url.clone()));
            go_env.push(("ASR_TOKEN", ASR_TOKEN.into()));
        }
        let unused = common::fake_upstream(|_| async { Response::new(common::full("unused")) }).await;
        let oracle_db = Db {
            dsn: db.dsn.clone(),
            direct: db.direct.clone(),
            app: db.app.clone(),
        };
        let oracle = common::go_oracle::start_named_with_env(&oracle_db, unused, "gofree-meet3", &go_env).await?;
        let recording = oracle.is_some();
        // Ignore the oracle's own startup probes.
        let _ = fake.drain();
        let _ = asr.drain();
        match (route, case) {
            ("rec_start", "busy") => fake.fail_with("StartRoomCompositeEgress", 429, "resource_exhausted"),
            ("rec_start", "egress_fail") => fake.fail_with("StartRoomCompositeEgress", 500, "internal"),
            ("rec_stop", "egress_fail") => fake.fail_with("StopEgress", 500, "internal"),
            _ => {}
        }
        asr.answer(match case {
            "busy" => 409,
            "asr_fail" => 500,
            _ => 200,
        });
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
        let mut baseline = snapshot_b(&c, &a, &b).await?;
        let silent = mutant == Mutant::Silent;
        let sfu_url = if silent { "ws://127.0.0.1:1".to_owned() } else { livekit_url };
        let asr_target = if silent { "http://127.0.0.1:1".to_owned() } else { asr_url };
        let mut livekit = setjoin_gateway::meet_livekit::LiveKit::new(KEY, SECRET, &sfu_url, egress, asr_on)
            .with_s3(setjoin_gateway::meet_livekit::EgressS3::from_values(
                "http://127.0.0.1:9", false, "test-access", "test-secret", "mailblobs",
            ));
        if asr_on {
            livekit = livekit.with_asr(&asr_target, ASR_TOKEN);
        }
        let adapter = setjoin_gateway::meet::MeetRoute::new(
            patient(worker_app.as_deref().unwrap_or(&db.dsn))?,
            std::sync::Arc::new(common::recovery_keys()),
            "mailserver".into(),
            livekit,
        )
        // Three back-to-back checkpoints must exhaust the burst however slowly the host runs.
        .with_pinned_checkpoint_throttle();
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
        let plan = build(route, case, &seeded);
        let ids = Ids::load(&c, &a, &b).await?;
        let send = |plan: &Plan| {
            let user = if plan.actor_b { b.user } else { a.user };
            let request = Request::builder()
                .method(method)
                .uri(plan.path.clone())
                .header("host", "mail.test")
                .header("origin", "http://mail.test")
                .header("content-type", "application/json")
                .header("x-request-id", "meet3-oracle")
                .header("authorization", format!("Bearer {}", token(user, "meet3-oracle")));
            let body = plan.body.clone();
            async move { common::send(addr, request.body(common::full(body)).unwrap()).await }
        };
        let first = if plan.times > 1 {
            let mut first = observe(send(&plan).await).await?;
            decode_tokens(&mut first["response"]["body"]);
            first["effects"] = snapshot_b(&c, &a, &b).await?;
            first["audit"] = audit_rows(&c, audit_start, &a, &b).await?;
            first["notify"] = events(&mut listeners, &c).await?;
            first["peripherals"] = json!(fake.drain());
            first["asr"] = json!(asr.drain());
            for _ in 2..plan.times {
                let _ = observe(send(&plan).await).await?;
            }
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
        let mut effects = snapshot_b(&c, &a, &b).await?;
        let mut audit = audit_rows(&c, audit_start, &a, &b).await?;
        let mut notify = events(&mut listeners, &c).await?;
        let mut peripherals = json!(fake.drain());
        let mut asr_calls = json!(asr.drain());
        let actual_path = plan.path.split('?').next().unwrap().strip_prefix("/api").unwrap().to_owned();
        let canonical_path = canonical.to_owned();
        for v in [
            &mut observed["response"]["body"],
            &mut effects,
            &mut audit,
            &mut notify,
            &mut peripherals,
            &mut asr_calls,
        ] {
            normalize_instance(v, &actual_path, &canonical_path);
            ids.normalize(v, "", "");
        }
        let mut first = first;
        if let Some(first) = first.as_mut() {
            normalize_instance(&mut first["response"]["body"], &actual_path, &canonical_path);
            ids.normalize(&mut first["response"]["body"], "", "");
            for key in ["effects", "audit", "notify", "peripherals", "asr"] {
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
            "effects": effects, "audit": audit, "notify": notify,
            "peripherals": peripherals, "asr": asr_calls,
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
            let command = match route {
                "rec_start" => "meeting_recording_start",
                "rec_stop" => "meeting_recording_stop",
                "cap_start" | "cap_stop" => "meeting_captions_set",
                _ => "meeting_presentation_prepare",
            };
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
            // Peripherals only follow a committed answer: an unknown outcome
            // never reaches them.
            if observation["peripherals"] != json!([]) || observation["asr"] != json!([]) {
                return Err("an unknown outcome reached a peripheral".into());
            }
            if committed && route == "rec_start" {
                // Only the reducer ran: the bind and the egress call never did.
                if observation["effects"]["meeting_recordings"][0]["state"] != "requested" {
                    return Err("a committed start must leave a requested recording".into());
                }
            } else if committed && route == "cap_start" {
                if observation["effects"]["meetings"][0]["settings"]["captionsOn"] != json!(true) {
                    return Err("a committed start must leave captions on".into());
                }
            } else if committed {
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
            ledger("Reaped gofree-meet3 COMMIT-loss proxy; HTTP Unknown resolved from receipt without replay")?;
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
                    "normalization":["fixture identities","generated ids, slugs, room names, secrets and timestamps; minted tokens replaced by verified claims; chat and core audit chains verified"],
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
        ledger("Reaped failed gofree-meet3 COMMIT proxy")?;
    }
    if let Some(schema) = mutant_schema {
        c.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await?;
        ledger(&format!("Removed private SQL mutant schema {schema}"))?;
    }
    clean(&c, &a, &b).await?;
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
