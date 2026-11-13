//! #288: F13 sub-router-c routes (local capture, semantic reads, admin recordings
//! registry) recorded from frozen Go through the front door. Recording runs Go
//! behind an empty route table; replay unsets Go and serves the routes natively.
//! No LiveKit call exists on these routes, so the fake SFU only has to be
//! configured, and any call it saw would be a divergence.
mod common;
#[path = "common/meet_fixture.rs"]
mod meet_fixture;
use common::BoxError;
use futures_util::FutureExt;
use hyper::{Request, Response};
use meet_fixture::{
    audit_rows, cleanup, events, ledger, normalize_instance, observe, snapshot, token, Ids,
};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};
use sha2::{Digest, Sha256};

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
    lease_success = "lease", "success";
    lease_repeat = "lease", "repeat";
    lease_min_seconds = "lease", "min_seconds";
    lease_max_seconds = "lease", "max_seconds";
    lease_null_seconds = "lease", "null_seconds";
    lease_both_surfaces = "lease", "both_surfaces";
    lease_unicode_device = "lease", "unicode_device";
    lease_cohost = "lease", "cohost";
    lease_other_device = "lease", "other_device";
    lease_member = "lease", "member";
    lease_stranger = "lease", "stranger";
    lease_invalid_id = "lease", "invalid_id";
    lease_missing = "lease", "missing";
    lease_not_live = "lease", "not_live";
    lease_ended = "lease", "ended";
    lease_guest = "lease", "guest";
    lease_flag_off = "lease", "flag_off";
    lease_bad_json = "lease", "bad_json";
    lease_bad_type = "lease", "bad_type";
    lease_no_device = "lease", "no_device";
    lease_long_device = "lease", "long_device";
    lease_no_surfaces = "lease", "no_surfaces";
    lease_bad_surface = "lease", "bad_surface";
    lease_dup_surface = "lease", "dup_surface";
    lease_no_producer = "lease", "no_producer";
    lease_no_api = "lease", "no_api";
    lease_low_seconds = "lease", "low_seconds";
    lease_high_seconds = "lease", "high_seconds";
    lease_commit_before = "lease", "commit_before";
    lease_commit_after = "lease", "commit_after";
    heartbeat_success = "heartbeat", "success";
    heartbeat_repeat = "heartbeat", "repeat";
    heartbeat_disk = "heartbeat", "disk";
    heartbeat_default_state = "heartbeat", "default_state";
    heartbeat_stopping = "heartbeat", "stopping";
    heartbeat_stopped_frame = "heartbeat", "stopped_frame";
    heartbeat_regress = "heartbeat", "regress";
    heartbeat_stale_gen = "heartbeat", "stale_gen";
    heartbeat_after_stop = "heartbeat", "after_stop";
    heartbeat_expired = "heartbeat", "expired";
    heartbeat_ended = "heartbeat", "ended";
    heartbeat_member = "heartbeat", "member";
    heartbeat_stranger = "heartbeat", "stranger";
    heartbeat_missing_rec = "heartbeat", "missing_rec";
    heartbeat_invalid_id = "heartbeat", "invalid_id";
    heartbeat_invalid_rid = "heartbeat", "invalid_rid";
    heartbeat_flag_off = "heartbeat", "flag_off";
    heartbeat_bad_json = "heartbeat", "bad_json";
    heartbeat_bad_type = "heartbeat", "bad_type";
    heartbeat_bad_state = "heartbeat", "bad_state";
    heartbeat_zero_seq = "heartbeat", "zero_seq";
    heartbeat_commit_before = "heartbeat", "commit_before";
    heartbeat_commit_after = "heartbeat", "commit_after";
    lstop_success = "lstop", "success";
    lstop_revoked = "lstop", "revoked";
    lstop_gen_match = "lstop", "gen_match";
    lstop_stale_gen = "lstop", "stale_gen";
    lstop_bad_reason = "lstop", "bad_reason";
    lstop_already = "lstop", "already";
    lstop_repeat = "lstop", "repeat";
    lstop_cohost = "lstop", "cohost";
    lstop_member = "lstop", "member";
    lstop_stranger = "lstop", "stranger";
    lstop_missing_rec = "lstop", "missing_rec";
    lstop_invalid_id = "lstop", "invalid_id";
    lstop_invalid_rid = "lstop", "invalid_rid";
    lstop_flag_off = "lstop", "flag_off";
    lstop_bad_json = "lstop", "bad_json";
    lstop_bad_type = "lstop", "bad_type";
    lstop_commit_before = "lstop", "commit_before";
    lstop_commit_after = "lstop", "commit_after";
    register_success = "register", "success";
    register_repeat = "register", "repeat";
    register_reregister = "register", "reregister";
    register_interrupted = "register", "interrupted";
    register_failed_segment = "register", "failed_segment";
    register_registered_state = "register", "registered_state";
    register_no_recording_id = "register", "no_recording_id";
    register_member = "register", "member";
    register_stranger = "register", "stranger";
    register_not_stopped = "register", "not_stopped";
    register_missing_rec = "register", "missing_rec";
    register_invalid_id = "register", "invalid_id";
    register_invalid_rid = "register", "invalid_rid";
    register_flag_off = "register", "flag_off";
    register_bad_json = "register", "bad_json";
    register_bad_type = "register", "bad_type";
    register_array_body = "register", "array_body";
    register_null_body = "register", "null_body";
    register_oversize = "register", "oversize";
    register_schema = "register", "schema";
    register_mode = "register", "mode";
    register_uploaded = "register", "uploaded";
    register_uploaded_absent = "register", "uploaded_absent";
    register_policy = "register", "policy";
    register_meeting_mismatch = "register", "meeting_mismatch";
    register_recording_mismatch = "register", "recording_mismatch";
    register_state_bad = "register", "state_bad";
    register_no_end = "register", "no_end";
    register_no_start = "register", "no_start";
    register_ends_early = "register", "ends_early";
    register_registered_no_time = "register", "registered_no_time";
    register_no_platform = "register", "no_platform";
    register_no_surfaces = "register", "no_surfaces";
    register_bad_surface = "register", "bad_surface";
    register_dup_surface = "register", "dup_surface";
    register_no_segments = "register", "no_segments";
    register_capturing_segment = "register", "capturing_segment";
    register_seq_zero = "register", "seq_zero";
    register_flat_interval = "register", "flat_interval";
    register_wall_backwards = "register", "wall_backwards";
    register_short_sha = "register", "short_sha";
    register_nonhex_sha = "register", "nonhex_sha";
    register_no_size = "register", "no_size";
    register_no_mime = "register", "no_mime";
    register_no_reason = "register", "no_reason";
    register_bad_observed_sha = "register", "bad_observed_sha";
    register_unknown_segment_state = "register", "unknown_segment_state";
    register_fabricated_coverage = "register", "fabricated_coverage";
    register_gap_drift = "register", "gap_drift";
    register_overlap = "register", "overlap";
    register_digest_wrong = "register", "digest_wrong";
    register_digest_absent = "register", "digest_absent";
    register_digest_null = "register", "digest_null";
    register_number_literal = "register", "number_literal";
    register_unicode_text = "register", "unicode_text";
    register_commit_before = "register", "commit_before";
    register_commit_after = "register", "commit_after";
    sem_package_active = "sem_package", "active";
    sem_package_stopped = "sem_package", "stopped";
    sem_package_registered = "sem_package", "registered";
    sem_package_member = "sem_package", "member";
    sem_package_stranger = "sem_package", "stranger";
    sem_package_missing_rec = "sem_package", "missing_rec";
    sem_package_invalid_id = "sem_package", "invalid_id";
    sem_package_invalid_rid = "sem_package", "invalid_rid";
    sem_package_flag_off = "sem_package", "flag_off";
    sem_replay_active = "sem_replay", "active";
    sem_replay_stopped = "sem_replay", "stopped";
    sem_replay_registered = "sem_replay", "registered";
    sem_replay_member = "sem_replay", "member";
    sem_replay_stranger = "sem_replay", "stranger";
    sem_replay_missing_rec = "sem_replay", "missing_rec";
    sem_replay_invalid_id = "sem_replay", "invalid_id";
    sem_replay_invalid_rid = "sem_replay", "invalid_rid";
    sem_replay_flag_off = "sem_replay", "flag_off";
    registry_success = "registry", "success";
    registry_repeat = "registry", "repeat";
    registry_state = "registry", "state";
    registry_meeting = "registry", "meeting";
    registry_both = "registry", "both";
    registry_empty_params = "registry", "empty_params";
    registry_no_match = "registry", "no_match";
    registry_unknown_meeting = "registry", "unknown_meeting";
    registry_semicolon = "registry", "semicolon";
    registry_encoded = "registry", "encoded";
    registry_scoped = "registry", "scoped";
    registry_features_off = "registry", "features_off";
    registry_denied = "registry", "denied";
    registry_non_admin = "registry", "non_admin";
    registry_bad_meeting = "registry", "bad_meeting";
}

// Every route's planted mutants: a changed status and a missing tenant filter
// (the registry's is a missing audit row).
rejects! {
    lease_rejects_status = "lease", Status;
    heartbeat_rejects_status = "heartbeat", Status;
    lstop_rejects_status = "lstop", Status;
    register_rejects_status = "register", Status;
    sem_package_rejects_status = "sem_package", Status;
    sem_replay_rejects_status = "sem_replay", Status;
    registry_rejects_status = "registry", Status;
    lease_rejects_no_tenant_filter = "lease", Shadow;
    heartbeat_rejects_no_tenant_filter = "heartbeat", Shadow;
    lstop_rejects_no_tenant_filter = "lstop", Shadow;
    register_rejects_no_tenant_filter = "register", Shadow;
    sem_package_rejects_no_tenant_filter = "sem_package", Shadow;
    sem_replay_rejects_no_tenant_filter = "sem_replay", Shadow;
    registry_rejects_no_audit = "registry", Shadow;
}

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const KEY: &str = "meet4-key";
const SECRET: &str = "meet4-secret-meet4-secret-meet4-secret";

fn route_spec(route: &str) -> (&'static str, &'static str) {
    match route {
        "lease" => ("POST", "/meet/{id}/local/lease"),
        "heartbeat" => ("POST", "/meet/{id}/local/{rid}/heartbeat"),
        "lstop" => ("POST", "/meet/{id}/local/{rid}/stop"),
        "register" => ("POST", "/meet/{id}/local/{rid}/register"),
        "sem_package" => ("GET", "/meet/{id}/semantic/{rid}/package"),
        "sem_replay" => ("GET", "/meet/{id}/semantic/{rid}/replay"),
        "registry" => ("GET", "/admin/meet/recordings"),
        _ => unreachable!("unknown meet route"),
    }
}

/// Status frozen Go answers per case, learned from recordings (MEET4_LEARN=1
/// prints them instead of asserting). A recording that disagrees is a broken
/// fixture, never a golden.
fn expected_status(route: &str, case: &str) -> u16 {
    if case.starts_with("commit_") {
        return 503;
    }
    match (route, case) {
        ("heartbeat", "after_stop")
        | ("heartbeat", "default_state")
        | ("heartbeat", "disk")
        | ("heartbeat", "ended")
        | ("heartbeat", "expired")
        | ("heartbeat", "repeat")
        | ("heartbeat", "stopped_frame")
        | ("heartbeat", "stopping")
        | ("heartbeat", "success")
        | ("lstop", "already")
        | ("lstop", "cohost")
        | ("lstop", "gen_match")
        | ("lstop", "repeat")
        | ("lstop", "revoked")
        | ("lstop", "success")
        | ("register", "failed_segment")
        | ("register", "interrupted")
        | ("register", "no_recording_id")
        | ("register", "number_literal")
        | ("register", "registered_state")
        | ("register", "repeat")
        | ("register", "success")
        | ("register", "unicode_text")
        | ("registry", "both")
        | ("registry", "empty_params")
        | ("registry", "encoded")
        | ("registry", "features_off")
        | ("registry", "meeting")
        | ("registry", "no_match")
        | ("registry", "repeat")
        | ("registry", "scoped")
        | ("registry", "semicolon")
        | ("registry", "state")
        | ("registry", "success")
        | ("registry", "unknown_meeting")
        | ("sem_package", "active")
        | ("sem_package", "flag_off")
        | ("sem_package", "member")
        | ("sem_package", "registered")
        | ("sem_package", "stopped")
        | ("sem_replay", "active")
        | ("sem_replay", "flag_off")
        | ("sem_replay", "member")
        | ("sem_replay", "registered")
        | ("sem_replay", "stopped") => 200,
        ("lease", "both_surfaces")
        | ("lease", "cohost")
        | ("lease", "max_seconds")
        | ("lease", "min_seconds")
        | ("lease", "null_seconds")
        | ("lease", "repeat")
        | ("lease", "success")
        | ("lease", "unicode_device") => 201,
        ("heartbeat", "bad_json")
        | ("heartbeat", "bad_type")
        | ("heartbeat", "invalid_id")
        | ("heartbeat", "invalid_rid")
        | ("lease", "bad_json")
        | ("lease", "bad_type")
        | ("lease", "invalid_id")
        | ("lstop", "bad_json")
        | ("lstop", "bad_type")
        | ("lstop", "invalid_id")
        | ("lstop", "invalid_rid")
        | ("register", "array_body")
        | ("register", "bad_json")
        | ("register", "bad_type")
        | ("register", "invalid_id")
        | ("register", "invalid_rid")
        | ("registry", "bad_meeting")
        | ("sem_package", "invalid_id")
        | ("sem_package", "invalid_rid")
        | ("sem_replay", "invalid_id")
        | ("sem_replay", "invalid_rid") => 400,
        ("lease", "guest")
        | ("lstop", "member")
        | ("register", "bad_observed_sha")
        | ("register", "bad_surface")
        | ("register", "capturing_segment")
        | ("register", "digest_absent")
        | ("register", "digest_null")
        | ("register", "digest_wrong")
        | ("register", "dup_surface")
        | ("register", "ends_early")
        | ("register", "fabricated_coverage")
        | ("register", "flat_interval")
        | ("register", "gap_drift")
        | ("register", "meeting_mismatch")
        | ("register", "member")
        | ("register", "mode")
        | ("register", "no_end")
        | ("register", "no_mime")
        | ("register", "no_platform")
        | ("register", "no_reason")
        | ("register", "no_segments")
        | ("register", "no_size")
        | ("register", "no_start")
        | ("register", "no_surfaces")
        | ("register", "nonhex_sha")
        | ("register", "null_body")
        | ("register", "overlap")
        | ("register", "policy")
        | ("register", "recording_mismatch")
        | ("register", "registered_no_time")
        | ("register", "reregister")
        | ("register", "schema")
        | ("register", "seq_zero")
        | ("register", "short_sha")
        | ("register", "state_bad")
        | ("register", "unknown_segment_state")
        | ("register", "uploaded")
        | ("register", "uploaded_absent")
        | ("register", "wall_backwards")
        | ("registry", "denied")
        | ("registry", "non_admin") => 403,
        ("heartbeat", "flag_off")
        | ("lease", "flag_off")
        | ("lease", "member")
        | ("lease", "missing")
        | ("lease", "stranger")
        | ("lstop", "flag_off")
        | ("register", "flag_off") => 404,
        ("heartbeat", "member")
        | ("heartbeat", "missing_rec")
        | ("heartbeat", "stale_gen")
        | ("heartbeat", "stranger")
        | ("lease", "ended")
        | ("lease", "not_live")
        | ("lease", "other_device")
        | ("lstop", "missing_rec")
        | ("lstop", "stale_gen")
        | ("lstop", "stranger")
        | ("register", "missing_rec")
        | ("register", "stranger")
        | ("sem_package", "missing_rec")
        | ("sem_package", "stranger")
        | ("sem_replay", "missing_rec")
        | ("sem_replay", "stranger") => 409,
        ("register", "oversize") => 413,
        ("heartbeat", "bad_state")
        | ("heartbeat", "regress")
        | ("heartbeat", "zero_seq")
        | ("lease", "bad_surface")
        | ("lease", "dup_surface")
        | ("lease", "high_seconds")
        | ("lease", "long_device")
        | ("lease", "low_seconds")
        | ("lease", "no_api")
        | ("lease", "no_device")
        | ("lease", "no_producer")
        | ("lease", "no_surfaces")
        | ("lstop", "bad_reason")
        | ("register", "not_stopped") => 422,
        other => panic!("unlearned case {other:?}"),
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Mutant {
    None,
    Status,
    Shadow,
}

async fn reject(route: &str, mutant: Mutant) -> Result<(), BoxError> {
    let (case, kind) = match (route, mutant) {
        (_, Mutant::Status) => (
            match route {
                "sem_package" | "sem_replay" => "stopped",
                "registry" => "success",
                _ => "success",
            },
            "changed-status",
        ),
        ("registry", _) => ("success", "no-audit"),
        ("sem_package" | "sem_replay", _) => ("stranger", "no-tenant-filter"),
        ("heartbeat", _) => ("stranger", "no-tenant-filter"),
        _ => ("member", "no-tenant-filter"),
    };
    let err = run(route, case, mutant)
        .await
        .expect_err("a planted mutant must fail the immutable recording");
    let text = err.to_string();
    assert!(
        text.contains("/response/status") || text.contains("/audit") || text.contains("/effects"),
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

fn admin_token(user: i64, jti: &str) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    let source = token(user, jti);
    let fields = source.split('.').collect::<Vec<_>>();
    let mut claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(fields[1]).unwrap()).unwrap();
    claims["admin"] = json!(true);
    claims["perms"] = json!(["forged.permission"]);
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    let key = SigningKey::from_slice(&[0x11; 32]).unwrap();
    let signature: p256::ecdsa::Signature = key.sign(format!("{}.{payload}", fields[0]).as_bytes());
    format!(
        "{}.{payload}.{}",
        fields[0],
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

async fn scalar(c: &tokio_postgres::Client, sql: &str) -> Result<Value, BoxError> {
    let raw: String = c.query_one(sql, &[]).await?.get(0);
    Ok(serde_json::from_str(&raw)?)
}

const DEVICE: &str = "meet4-device";
const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn is_local(route: &str) -> bool {
    matches!(route, "lease" | "heartbeat" | "lstop" | "register")
}

/// Whether the case needs a lease (and its recording) to exist before the call.
fn needs_lease(route: &str, case: &str) -> bool {
    match route {
        "heartbeat" | "lstop" | "register" | "sem_package" | "sem_replay" => true,
        "lease" => case == "other_device",
        _ => false,
    }
}

/// Whether the seeded lease is already stopped when the request arrives.
fn stopped(route: &str, case: &str) -> bool {
    match route {
        "register" => case != "not_stopped",
        "sem_package" | "sem_replay" => matches!(
            case,
            "stopped"
                | "registered"
                | "member"
                | "stranger"
                | "missing_rec"
                | "invalid_id"
                | "invalid_rid"
                | "flag_off"
        ),
        "heartbeat" => case == "after_stop",
        "lstop" => case == "already",
        _ => false,
    }
}

struct Seed {
    own: i64,
    rec: i64,
    generation: i64,
    b_rec: i64,
}

fn descriptor(meeting: i64, rec: i64, variant: &str) -> Vec<u8> {
    let seg = |seq: i64, start: i64, end: i64, sha: &str| {
        json!({"seq":seq,"state":"verified","contentSha256":sha,"byteSize":1000+seq,
            "mimeType":"audio/webm","codec":"opus","container":"webm",
            "interval":{"startMs":start,"endMs":end},
            "wallStartUnixMs":1700000000000i64+start,"wallEndUnixMs":1700000000000i64+end,
            "interruptReason":null})
    };
    let mut d = json!({
        "schema":"sjrec-local-v1","meetingId":meeting,"recordingId":rec,
        "packageState":"finalized","captureMode":"local_registered","policyMode":"local_only",
        "surfaces":["microphone"],
        "producer":{"platform":"electron","platformVersion":"33","captureApiVersion":"1"},
        "startedAtUnixMs":1700000000000i64,"endedAtUnixMs":1700000060000i64,
        "registeredAtUnixMs":null,
        "segments":[seg(1,0,30000,SHA_A),seg(2,30000,60000,SHA_B)],
        "uploadedToDrive":false,
        "coverage":{"available":[{"startMs":0,"endMs":60000}],"gaps":[]},
        "integrityDigest":null
    });
    let mut seal = true;
    match variant {
        "interrupted" => {
            d["packageState"] = json!("interrupted");
            let mut cut = seg(2, 30000, 45000, SHA_B);
            cut["state"] = json!("interrupted");
            cut["interruptReason"] = json!("device sleep");
            d["segments"] = json!([seg(1, 0, 30000, SHA_A), cut]);
            d["coverage"] = json!({"available":[{"startMs":0,"endMs":30000}],"gaps":[{"startMs":30000,"endMs":45000}]});
        }
        "failed_segment" => {
            let mut cut = seg(2, 30000, 60000, SHA_B);
            cut["state"] = json!("failed");
            cut["contentSha256"] = json!(null);
            cut["byteSize"] = json!(null);
            cut["interruptReason"] = json!("digest mismatch");
            d["segments"] = json!([seg(1, 0, 30000, SHA_A), cut]);
            d["coverage"] = json!({"available":[{"startMs":0,"endMs":30000}],"gaps":[{"startMs":30000,"endMs":60000}]});
        }
        "registered_state" => {
            d["packageState"] = json!("registered");
            d["registeredAtUnixMs"] = json!(1700000070000i64);
        }
        "registered_no_time" => d["packageState"] = json!("registered"),
        "reregister" => d["policyMode"] = json!("server_only"),
        "no_recording_id" => d["recordingId"] = json!(null),
        "schema" => d["schema"] = json!("sjrec-local-v2"),
        "mode" => d["captureMode"] = json!("server_audio"),
        "uploaded" => d["uploadedToDrive"] = json!(true),
        "uploaded_absent" => {
            d.as_object_mut().unwrap().remove("uploadedToDrive");
        }
        "policy" => d["policyMode"] = json!("anything"),
        "meeting_mismatch" => d["meetingId"] = json!(424242),
        "recording_mismatch" => d["recordingId"] = json!(424242),
        "state_bad" => d["packageState"] = json!("open"),
        "no_end" => d["endedAtUnixMs"] = json!(null),
        "no_start" => d["startedAtUnixMs"] = json!(0),
        "ends_early" => d["endedAtUnixMs"] = json!(1600000000000i64),
        "no_platform" => d["producer"]["platform"] = json!(""),
        "no_surfaces" => d["surfaces"] = json!([]),
        "bad_surface" => d["surfaces"] = json!(["camera"]),
        "dup_surface" => d["surfaces"] = json!(["microphone", "microphone"]),
        "no_segments" => {
            d["segments"] = json!([]);
            d["coverage"] = json!({"available":[],"gaps":[]});
        }
        "capturing_segment" => d["segments"][1]["state"] = json!("capturing"),
        "seq_zero" => d["segments"][0]["seq"] = json!(0),
        "flat_interval" => d["segments"][0]["interval"]["endMs"] = json!(0),
        "wall_backwards" => d["segments"][0]["wallEndUnixMs"] = json!(1),
        "short_sha" => d["segments"][0]["contentSha256"] = json!("abc"),
        "nonhex_sha" => d["segments"][0]["contentSha256"] = json!(format!("{}g", &SHA_A[..63])),
        "no_size" => d["segments"][0]["byteSize"] = json!(0),
        "no_mime" => d["segments"][0]["mimeType"] = json!(""),
        "no_reason" => {
            d["segments"][1]["state"] = json!("interrupted");
            d["segments"][1]["interruptReason"] = json!(null);
        }
        "bad_observed_sha" => {
            d["segments"][1]["state"] = json!("failed");
            d["segments"][1]["contentSha256"] = json!("zz");
            d["segments"][1]["interruptReason"] = json!("lost");
        }
        "unknown_segment_state" => d["segments"][1]["state"] = json!("weird"),
        "fabricated_coverage" => d["coverage"]["available"][0]["endMs"] = json!(50000),
        "gap_drift" => d["coverage"]["gaps"] = json!([{"startMs":1,"endMs":2}]),
        "overlap" => {
            d["segments"][1]["interval"]["startMs"] = json!(20000);
            d["coverage"] = json!({"available":[{"startMs":0,"endMs":60000}],"gaps":[]});
        }
        "unicode_text" => {
            d["producer"]["platformVersion"] = json!("33 <&> \u{4e2d}\u{6587} \u{1f600} \u{2028}");
        }
        "digest_absent" => {
            d.as_object_mut().unwrap().remove("integrityDigest");
            seal = false;
        }
        "digest_null" => seal = false,
        "digest_wrong" => {
            seal = false;
            d["integrityDigest"] = json!(SHA_A);
        }
        // A number literal is sealed verbatim: a parser that re-renders -0.0 as -0 breaks the digest.
        "number_literal" => d["extra"] = json!(-0.0),
        _ => {}
    }
    if seal {
        d["integrityDigest"] = json!(null);
        let sum = Sha256::digest(d.to_string().as_bytes());
        d["integrityDigest"] = json!(sum.iter().map(|b| format!("{b:02x}")).collect::<String>());
    }
    d.to_string().into_bytes()
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
        rec: 0,
        generation: 0,
        b_rec: 0,
    };
    if route == "registry" {
        // A double quote or backslash in a title breaks the audit hash cast (bytea): frozen-Go bug, see notes.
        let title = "Meet4 <registry> & 'q'";
        let m1 = scalar(
            c,
            &format!("SELECT meeting_create({},$q${title}$q$)::text", a.user),
        )
        .await?;
        let m2 = scalar(
            c,
            &format!("SELECT meeting_create({},'Meet4 other')::text", b.user),
        )
        .await?;
        out.own = m1["meetingId"].as_i64().unwrap();
        let other = m2["meetingId"].as_i64().unwrap();
        for (meeting, user, state, size, duration, error) in [
            (
                out.own,
                a.user,
                "active",
                None::<i64>,
                None::<i64>,
                None::<&str>,
            ),
            (out.own, a.user, "ready", Some(123456), Some(5000), None),
            (other, b.user, "failed", None, None, Some("<boom> & \"x\"")),
        ] {
            let who = if user == a.user { "owner" } else { "foreign" };
            let egress = format!("EG_meet4_{who}_{state}");
            c.execute(
                "INSERT INTO meeting_recordings(meeting_id,egress_id,state,started_by,staging_key,size_bytes,duration_ms,error,stopped_at) \
                 VALUES($1,$2,$3,$4,'meet-egress/seed.mp4',$5,$6,$7, CASE WHEN $3 IN ('ready','failed') THEN now() END)",
                &[&meeting, &egress, &state, &user, &size, &duration, &error],
            )
            .await?;
        }
        return Ok(out);
    }
    let own = scalar(
        c,
        &format!(
            "SELECT meeting_create({},'Meet4 seed owner'{})::text",
            a.user,
            if (route, case) == ("lease", "guest") {
                ",NULL,NULL,NULL,NULL,true"
            } else {
                ""
            }
        ),
    )
    .await?;
    out.own = own["meetingId"].as_i64().unwrap();
    let slug = own["slug"].as_str().unwrap().to_owned();
    if !matches!((route, case), ("lease", "not_live")) {
        c.execute(&format!("SELECT meeting_join({},{})", a.user, out.own), &[])
            .await?;
        c.execute(
            &format!("SELECT meeting_participant_event(room_name,'room_started',NULL) FROM meetings WHERE id={}", out.own),
            &[],
        )
        .await?;
    }
    if (route, case) == ("lease", "ended") {
        c.execute(
            "UPDATE meetings SET state='ended', ended_at=now() WHERE id=$1",
            &[&out.own],
        )
        .await?;
    }
    let role = match case {
        "cohost" => Some("cohost"),
        "member" => Some("member"),
        _ => None,
    };
    if let Some(role) = role {
        c.execute(
            "INSERT INTO meeting_participants(meeting_id,user_id,identity,role,joined_at) VALUES($1,$2,'u:'||$2::bigint::text,$3,now())",
            &[&out.own, &b.user, &role],
        )
        .await?;
    }
    if (route, case) == ("lease", "guest") {
        let made = scalar(
            c,
            &format!("SELECT meeting_join_request_create('{slug}','Meet4 guest')::text"),
        )
        .await?;
        let id = made["requestId"].as_i64().unwrap();
        c.execute(&format!("SELECT meeting_admit({},{id})", a.user), &[])
            .await?;
    }
    if needs_lease(route, case) {
        let device = if (route, case) == ("lease", "other_device") {
            "meet4-first"
        } else {
            DEVICE
        };
        let lease = scalar(
            c,
            &format!(
                "SELECT meeting_local_capture_lease_acquire({},{},'{device}','[\"microphone\"]','{{\"platform\":\"electron\",\"platformVersion\":\"33\",\"captureApiVersion\":\"1\"}}',10)::text",
                a.user, out.own
            ),
        )
        .await?;
        out.rec = lease["recordingId"].as_i64().unwrap();
        out.generation = lease["leaseGeneration"].as_i64().unwrap();
    }
    if route == "heartbeat" && case == "regress" {
        c.execute(
            &format!(
                "SELECT meeting_local_capture_lease_heartbeat({},{},{},{},5,'capturing',NULL)",
                a.user, out.own, out.rec, out.generation
            ),
            &[],
        )
        .await?;
    }
    if stopped(route, case) {
        c.execute(
            &format!(
                "SELECT meeting_local_capture_lease_stop({},{},{},NULL,'user_stop')",
                a.user, out.own, out.rec
            ),
            &[],
        )
        .await?;
    }
    if case == "registered" && route.starts_with("sem_") {
        let text = String::from_utf8(descriptor(out.own, out.rec, "success"))?;
        c.execute(
            &format!(
                "SELECT meeting_local_capture_register({},{},{},$d${text}$d$::jsonb)",
                a.user, out.own, out.rec
            ),
            &[],
        )
        .await?;
    }
    if (route, case) == ("heartbeat", "expired") {
        c.execute("UPDATE meeting_local_capture_leases SET expires_at = now() - interval '1 minute' WHERE recording_id=$1", &[&out.rec]).await?;
    }
    if (route, case) == ("heartbeat", "ended") {
        c.execute(
            "UPDATE meetings SET state='ended', ended_at=now() WHERE id=$1",
            &[&out.own],
        )
        .await?;
    }
    Ok(out)
}

struct Plan {
    path: String,
    bodies: Vec<Vec<u8>>,
    actor_b: bool,
    admin: bool,
}

fn build(route: &str, case: &str, s: &Seed) -> Plan {
    let meeting = if case == "missing" { i64::MAX } else { s.own };
    let mut id = meeting.to_string();
    let mut rid = if case == "missing_rec" {
        i64::MAX.to_string()
    } else {
        s.rec.to_string()
    };
    if case == "invalid_id" {
        id = "bad".into();
    }
    if case == "invalid_rid" {
        rid = "bad".into();
    }
    let (_, canonical) = route_spec(route);
    let mut path = format!(
        "/api{}",
        canonical.replace("{id}", &id).replace("{rid}", &rid)
    );
    let generation = s.generation;
    let producer = json!({"platform":"electron","platformVersion":"33","captureApiVersion":"1"});
    let mut body = Value::Null;
    match route {
        "lease" => {
            body = json!({"deviceId":DEVICE,"surfaces":["microphone"],"producer":producer});
            match case {
                "min_seconds" => body["heartbeatSeconds"] = json!(5),
                "max_seconds" => body["heartbeatSeconds"] = json!(60),
                "null_seconds" => body["heartbeatSeconds"] = json!(null),
                "both_surfaces" => body["surfaces"] = json!(["microphone", "systemAudio"]),
                "unicode_device" => body["deviceId"] = json!("d\u{e9}v <i>&ce \u{4e2d}"),
                "other_device" => body["deviceId"] = json!("meet4-second"),
                "bad_type" => body["deviceId"] = json!(5),
                "no_device" => body["deviceId"] = json!(""),
                "long_device" => body["deviceId"] = json!("d".repeat(257)),
                "no_surfaces" => body["surfaces"] = json!([]),
                "bad_surface" => body["surfaces"] = json!(["camera"]),
                "dup_surface" => body["surfaces"] = json!(["microphone", "microphone"]),
                "no_producer" => body["producer"] = json!({"platform":"","captureApiVersion":"1"}),
                "no_api" => body["producer"] = json!({"platform":"electron"}),
                "low_seconds" => body["heartbeatSeconds"] = json!(4),
                "high_seconds" => body["heartbeatSeconds"] = json!(61),
                _ => {}
            }
        }
        "heartbeat" => {
            body = json!({"leaseGeneration":generation,"seq":1,"captureState":"capturing"});
            match case {
                "disk" => body["diskFreeBytes"] = json!(123456789),
                "default_state" => body = json!({"leaseGeneration":generation,"seq":1}),
                "stopping" => body["captureState"] = json!("stopping"),
                "stopped_frame" => body["captureState"] = json!("stopped"),
                "regress" => body["seq"] = json!(2),
                "stale_gen" => body["leaseGeneration"] = json!(generation + 41),
                "bad_type" => body["seq"] = json!("x"),
                "bad_state" => body["captureState"] = json!("paused"),
                "zero_seq" => body["seq"] = json!(0),
                _ => {}
            }
        }
        "lstop" => {
            body = json!({});
            match case {
                "revoked" => body = json!({"reason":"revoked"}),
                "gen_match" => body = json!({"leaseGeneration":generation}),
                "stale_gen" => body = json!({"leaseGeneration":generation + 41}),
                "bad_reason" => body = json!({"reason":"because"}),
                "bad_type" => body = json!({"reason":5}),
                _ => {}
            }
        }
        "register" => {
            let variant = match case {
                "repeat" | "member" | "stranger" | "not_stopped" | "invalid_id" | "invalid_rid"
                | "flag_off" | "commit_before" | "commit_after" | "bad_type" | "array_body"
                | "null_body" | "oversize" | "bad_json" => "success",
                "missing_rec" => "no_recording_id",
                other => other,
            };
            let bytes = descriptor(meeting, s.rec, variant);
            let mut text = String::from_utf8(bytes).unwrap();
            match case {
                "bad_type" => text = text.replace("\"seq\":1", "\"seq\":\"1\""),
                "array_body" => text = "[]".into(),
                "null_body" => text = "null".into(),
                "oversize" => text = format!("{{\"padding\":\"{}\"}}", "x".repeat(1 << 20)),
                _ => {}
            }
            body = Value::String(text);
        }
        _ => {}
    }
    let mut bytes = match &body {
        Value::Null => Vec::new(),
        Value::String(text) if route == "register" => text.clone().into_bytes(),
        other => other.to_string().into_bytes(),
    };
    if case == "bad_json" {
        bytes = b"{".to_vec();
    }
    let mut bodies = vec![bytes.clone()];
    if matches!(case, "repeat") {
        bodies.push(bytes.clone());
    }
    if route == "register" && case == "reregister" {
        bodies = vec![descriptor(meeting, s.rec, "success"), bytes];
    }
    if route == "registry" {
        let q = match case {
            "state" => "?state=active",
            "meeting" => format!("?meetingId={}", s.own).leak(),
            "both" => format!("?state=ready&meetingId={}", s.own).leak(),
            "empty_params" => "?state=&meetingId=",
            "no_match" => "?state=pending_ingest",
            "unknown_meeting" => "?meetingId=987654321",
            "semicolon" => "?state=active;ready",
            "encoded" => "?state=%61ctive&x=%zz",
            "bad_meeting" => "?meetingId=abc",
            _ => "",
        };
        path.push_str(q);
        bodies = vec![Vec::new(); if case == "repeat" { 2 } else { 1 }];
    }
    Plan {
        path,
        bodies,
        actor_b: matches!(case, "member" | "stranger") || (route == "lease" && case == "cohost"),
        admin: route == "registry" && !matches!(case, "denied" | "non_admin"),
    }
}

/// Every table the sub-router-c routes can write.
async fn snapshot_c(
    c: &tokio_postgres::Client,
    a: &fixture::Account,
    b: &fixture::Account,
) -> Result<Value, BoxError> {
    let mut out = snapshot(c, a, b).await?;
    let users = vec![a.user, b.user];
    for (name, sql) in [
        ("meeting_recordings", "SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY id),'[]')::text FROM meeting_recordings t WHERE meeting_id IN (SELECT id FROM meetings WHERE owner_user_id = ANY($1))"),
        ("meeting_semantic_recordings", "SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY id),'[]')::text FROM meeting_semantic_recordings t WHERE meeting_id IN (SELECT id FROM meetings WHERE owner_user_id = ANY($1))"),
        ("meeting_semantic_segments", "SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY recording_id,seq),'[]')::text FROM meeting_semantic_segments t WHERE recording_id IN (SELECT id FROM meeting_semantic_recordings WHERE meeting_id IN (SELECT id FROM meetings WHERE owner_user_id = ANY($1)))"),
        ("meeting_local_capture_leases", "SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY id),'[]')::text FROM meeting_local_capture_leases t WHERE meeting_id IN (SELECT id FROM meetings WHERE owner_user_id = ANY($1))"),
    ] {
        let raw: String = c.query_one(sql, &[&users]).await?.get(0);
        out[name] = serde_json::from_str(&raw)?;
    }
    Ok(out)
}

/// Semantic recordings, leases and segments are named by order; epoch
/// milliseconds, seals and generated receipts by their contract.
struct Local {
    recordings: Vec<(i64, String)>,
    users: Vec<(i64, String)>,
    registry: Vec<(i64, String)>,
}
impl Local {
    async fn load(
        c: &tokio_postgres::Client,
        a: &fixture::Account,
        b: &fixture::Account,
    ) -> Result<Self, BoxError> {
        let users = vec![a.user, b.user];
        let recordings = c
            .query(
                "SELECT id FROM meeting_semantic_recordings WHERE meeting_id IN (SELECT id FROM meetings WHERE owner_user_id = ANY($1)) ORDER BY id",
                &[&users],
            )
            .await?
            .iter()
            .enumerate()
            .map(|(n, r)| (r.get(0), format!("<semantic-{}>", n + 1)))
            .collect();
        let registry = c
            .query(
                "SELECT id FROM meeting_recordings WHERE meeting_id IN (SELECT id FROM meetings WHERE owner_user_id = ANY($1)) ORDER BY id",
                &[&users],
            )
            .await?
            .iter()
            .enumerate()
            .map(|(n, r)| (r.get(0), format!("<registry-{}>", n + 1)))
            .collect();
        Ok(Self {
            recordings,
            registry,
            users: vec![(a.user, "<owner>".into()), (b.user, "<foreign>".into())],
        })
    }
    fn refresh_from(&mut self, other: Local) {
        for (id, label) in other.recordings {
            if !self.recordings.iter().any(|(i, _)| *i == id) {
                self.recordings.push((id, label));
            }
        }
        self.registry = other.registry;
    }
    fn normalize(&self, value: &mut Value) {
        match value {
            Value::Object(o) => {
                let registry_row = o.contains_key("meetingTitle");
                let semantic_row = o.contains_key("rec_state") || o.contains_key("package_state");
                let segment_row = o.contains_key("ack_state");
                let lease_row = o.contains_key("lease_state");
                for (k, v) in o.iter_mut() {
                    if let Value::Number(n) = v {
                        let n = n.as_i64();
                        let label = match (k.as_str(), n) {
                            ("recordingId" | "recording_id", Some(n)) => self
                                .recordings
                                .iter()
                                .find(|(i, _)| *i == n)
                                .map(|(_, l)| Value::from(l.clone())),
                            ("id", Some(n)) if semantic_row => self
                                .recordings
                                .iter()
                                .find(|(i, _)| *i == n)
                                .map(|(_, l)| Value::from(l.clone())),
                            ("id", Some(_)) if segment_row || lease_row => {
                                Some(Value::from("<row-id>"))
                            }
                            ("id", Some(n)) if registry_row => self
                                .registry
                                .iter()
                                .find(|(i, _)| *i == n)
                                .map(|(_, l)| Value::from(l.clone())),
                            ("startedBy", Some(n)) => self
                                .users
                                .iter()
                                .find(|(i, _)| *i == n)
                                .map(|(_, l)| Value::from(l.clone())),
                            (k, Some(_)) if k.ends_with("UnixMs") && !k.starts_with("wall") => {
                                Some(Value::from("<unix-ms>"))
                            }
                            // The fixture's timestamp check only inspects strings, so the
                            // epoch receipt is named by a number.
                            ("registeredAt", Some(_)) => Some(Value::from(0)),
                            _ => None,
                        };
                        if let Some(label) = label {
                            *v = label;
                            continue;
                        }
                    }
                    if let Value::String(s) = v {
                        // Go names the bound id and the path id; the path id is generated.
                        if k == "detail" && s.starts_with("descriptor binds ") {
                            if let Some((head, _)) = s.rsplit_once(", not ") {
                                *s = format!("{head}, not <id>");
                            }
                            continue;
                        }
                        if matches!(
                            k.as_str(),
                            "descriptorDigest" | "local_descriptor_digest" | "descriptor_digest"
                        ) {
                            *s = "<digest>".into();
                            continue;
                        }
                    }
                    self.normalize(v);
                }
            }
            Value::Array(items) => items.iter_mut().for_each(|v| self.normalize(v)),
            _ => {}
        }
    }
}

async fn clean(
    c: &tokio_postgres::Client,
    a: &fixture::Account,
    b: &fixture::Account,
) -> Result<(), BoxError> {
    let users = vec![a.user, b.user];
    c.execute(
        "DELETE FROM meeting_local_capture_leases WHERE meeting_id IN (SELECT id FROM meetings WHERE owner_user_id = ANY($1))",
        &[&users],
    )
    .await?;
    c.execute(
        "DELETE FROM meeting_semantic_recordings WHERE meeting_id IN (SELECT id FROM meetings WHERE owner_user_id = ANY($1))",
        &[&users],
    )
    .await?;
    c.execute(
        "DELETE FROM admin_role_assignments WHERE user_id = ANY($1)",
        &[&users],
    )
    .await?;
    c.execute(
        "DELETE FROM admin_role_groups WHERE name LIKE 'meet4-%'",
        &[],
    )
    .await?;
    cleanup(c, &[a, b]).await
}

async fn run(route: &str, case: &str, mutant: Mutant) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let recording_env = std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
    let learn = std::env::var_os("MEET4_LEARN").is_some();
    if (mutant != Mutant::None || case.starts_with("commit_")) && recording_env {
        return Err("cannot record a planted mutant or COMMIT-loss case".into());
    }
    let Some(db) = Db::for_case("meet4") else {
        return Ok(());
    };
    let c = db.connect().await?;
    let a = fixture::account(&c, "meet4-owner").await?;
    let b = fixture::account(&c, "meet4-foreign").await?;
    let toggles = [
        "feature.meet",
        "feature.meet_local_recording",
        "feature.meet_recording",
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
    let result = std::panic::AssertUnwindSafe(async {
        let (method, canonical) = route_spec(route);
        let off = matches!(case, "flag_off");
        let features_off = case == "features_off";
        for (key, on) in [
            ("feature.meet", !features_off),
            ("feature.meet_local_recording", !off),
            ("feature.meet_recording", !features_off),
        ] {
            c.execute(
                "INSERT INTO feature_toggles(key,enabled) VALUES($1,$2) ON CONFLICT (key) DO UPDATE SET enabled=EXCLUDED.enabled",
                &[&key, &on],
            )
            .await?;
        }
        if route == "registry" {
            // The admin holds drive.view through a governed role (or only users.read).
            let (permissions, scope): (Vec<&str>, Option<i64>) = match case {
                "denied" => (vec!["users.read"], None),
                "scoped" => (vec!["drive.view"], Some(b.domain)),
                _ => (vec!["drive.view"], None),
            };
            let role: i64 = c
                .query_one(
                    "INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,$2,$3) RETURNING id",
                    &[&format!("meet4-{}", a.user), &permissions, &scope],
                )
                .await?
                .get(0);
            c.execute(
                "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
                &[&a.user, &role],
            )
            .await?;
        }
        let seeded = seed(&c, &a, &b, route, case).await?;
        let mut app = db.app.clone();
        let mut worker = db.dsn.clone();
        if mutant == Mutant::Shadow {
            let schema = format!("gofree_meet4_mutant_{}", a.user);
            ledger(&format!("Plan private no-tenant-filter SQL mutant schema {schema}, assigned DB only"))?;
            c.batch_execute(&format!(
                "CREATE SCHEMA {schema}; GRANT USAGE ON SCHEMA {schema} TO setjoin_app; \
                 CREATE FUNCTION {schema}.meeting_member_role(bigint,bigint) RETURNS text LANGUAGE sql AS $$ SELECT 'host'::text $$; \
                 CREATE FUNCTION {schema}.meeting_attendee_role(bigint,bigint) RETURNS text LANGUAGE sql AS $$ SELECT 'host'::text $$; \
                 CREATE FUNCTION {schema}.meeting_require_authority(bigint,bigint) RETURNS text LANGUAGE sql AS $$ SELECT 'host'::text $$; \
                 CREATE FUNCTION {schema}._meeting_local_require_owner_or_host(bigint,bigint,bigint) RETURNS void LANGUAGE sql AS $$ SELECT $$; \
                 CREATE FUNCTION {schema}._meeting_local_lease_lock(bigint,bigint) RETURNS public.meeting_local_capture_leases LANGUAGE sql AS $$ \
                   SELECT l.id,l.meeting_id,l.recording_id,l.device_id,l.lease_state,l.generation,l.surfaces,l.producer,l.heartbeat_seconds,l.expires_at,l.last_seq,l.last_seen_at,l.last_disk_free_bytes,l.stop_reason, \
                          NULLIF(current_setting('app.current_user_id',true),'')::bigint,l.started_at,l.stopped_at,l.created_at,l.updated_at \
                     FROM public.meeting_local_capture_leases l WHERE l.meeting_id=$1 AND l.recording_id=$2 ORDER BY l.generation DESC LIMIT 1 $$; \
                 CREATE FUNCTION {schema}.audit_write(bigint,text,text,bigint,jsonb,jsonb,inet,text,text) RETURNS void LANGUAGE sql AS $$ SELECT $$;"
            ))
            .await?;
            if matches!(route, "lease" | "register" | "sem_package" | "sem_replay") {
                c.batch_execute(&format!(
                    "CREATE VIEW {schema}.meetings AS SELECT * FROM public.meetings; \
                     GRANT SELECT, UPDATE ON {schema}.meetings TO setjoin_app; \
                     CREATE VIEW {schema}.meeting_semantic_recordings AS SELECT * FROM public.meeting_semantic_recordings; \
                     GRANT SELECT, INSERT, UPDATE ON {schema}.meeting_semantic_recordings TO setjoin_app;"
                ))
                .await?;
            }
            let base = db.app.as_deref().unwrap_or(&db.dsn);
            let mutated = format!(
                "{base}{}options=-csearch_path%3D{schema}%2Cpublic",
                if base.contains('?') { "&" } else { "?" }
            );
            if route == "registry" {
                let base = &db.dsn;
                worker = format!(
                    "{base}{}options=-csearch_path%3D{schema}%2Cpublic",
                    if base.contains('?') { "&" } else { "?" }
                );
            }
            app = Some(mutated);
            mutant_schema = Some(schema);
        }
        if let Some(cut) = match case {
            "commit_before" => Some(common::commit::CommitCut::BeforeCommit),
            "commit_after" => Some(common::commit::CommitCut::AfterCommit),
            _ => None,
        } {
            ledger("Plan gofree-meet4 COMMIT-loss proxy on the assigned application DB")?;
            let (dsn, task) =
                common::commit::commit_cut_proxy(db.app.as_deref().unwrap_or(&db.dsn), cut).await;
            app = Some(dsn);
            commit_wire = Some(task);
        }
        let go_env: Vec<(&str, String)> = vec![
            ("LIVEKIT_API_KEY", KEY.into()),
            ("LIVEKIT_API_SECRET", SECRET.into()),
            ("LIVEKIT_URL", "ws://127.0.0.1:1".into()),
        ];
        let unused = common::fake_upstream(|_| async { Response::new(common::full("unused")) }).await;
        let oracle_db = Db {
            dsn: db.dsn.clone(),
            direct: db.direct.clone(),
            app: db.app.clone(),
        };
        let oracle = common::go_oracle::start_named_with_env(&oracle_db, unused, "gofree-meet4", &go_env).await?;
        let recording = oracle.is_some();
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
        let mut baseline = snapshot_c(&c, &a, &b).await?;
        let livekit = setjoin_gateway::meet_livekit::LiveKit::new(KEY, SECRET, "ws://127.0.0.1:1", false, false);
        let adapter = setjoin_gateway::meet::MeetRoute::new(
            patient(app.as_deref().unwrap_or(&db.dsn))?,
            std::sync::Arc::new(common::recovery_keys()),
            "mailserver".into(),
            livekit,
        )
        .with_worker(patient(&worker)?);
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
        let mut local = Local::load(&c, &a, &b).await?;
        let send = |plan: &Plan, body: Vec<u8>| {
            let user = if plan.actor_b { b.user } else { a.user };
            let bearer = if plan.admin {
                admin_token(user, "meet4-oracle")
            } else {
                token(user, "meet4-oracle")
            };
            let request = Request::builder()
                .method(method)
                .uri(plan.path.clone())
                .header("host", "mail.test")
                .header("origin", "http://mail.test")
                .header("content-type", "application/json")
                .header("x-request-id", "meet4-oracle")
                .header("authorization", format!("Bearer {bearer}"));
            async move { common::send(addr, request.body(common::full(body)).unwrap()).await }
        };
        let last = plan.bodies.len() - 1;
        let first = if last > 0 {
            let mut first = observe(send(&plan, plan.bodies[0].clone()).await).await?;
            first["effects"] = snapshot_c(&c, &a, &b).await?;
            first["audit"] = audit_rows(&c, audit_start, &a, &b).await?;
            first["notify"] = events(&mut listeners, &c).await?;
            local.refresh_from(Local::load(&c, &a, &b).await?);
            Some(first)
        } else {
            None
        };
        let mut observed = observe(send(&plan, plan.bodies[last].clone()).await).await?;
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
        if learn {
            println!("LEARN {route}-{case} {status}");
            return Ok(());
        }
        if mutant == Mutant::None {
            let want = expected_status(route, case);
            if status != want {
                return Err(format!("HTTP status expected {want}, got {status}: {observed}").into());
            }
        }
        let ids = ids.with_new(&c, &a, &b).await?;
        local.refresh_from(Local::load(&c, &a, &b).await?);
        let mut effects = snapshot_c(&c, &a, &b).await?;
        let mut audit = audit_rows(&c, audit_start, &a, &b).await?;
        let mut notify = events(&mut listeners, &c).await?;
        let actual_path = plan.path.split('?').next().unwrap().strip_prefix("/api").unwrap().to_owned();
        let canonical_path = canonical.to_owned();
        for v in [&mut observed["response"]["body"], &mut effects, &mut audit, &mut notify] {
            normalize_instance(v, &actual_path, &canonical_path);
            local.normalize(v);
            ids.normalize(v, "", "");
        }
        let mut first = first;
        if let Some(first) = first.as_mut() {
            normalize_instance(&mut first["response"]["body"], &actual_path, &canonical_path);
            for key in ["effects", "audit", "notify"] {
                local.normalize(&mut first[key]);
                ids.normalize(&mut first[key], "", "");
            }
            local.normalize(&mut first["response"]["body"]);
            ids.normalize(&mut first["response"]["body"], "", "");
        }
        baseline = {
            let mut v = baseline;
            local.normalize(&mut v);
            ids.normalize(&mut v, "", "");
            v
        };
        let mut observation = json!({
            "request": {"method": method, "path": canonical},
            "response": observed["response"],
            "effects": effects, "audit": audit, "notify": notify,
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
                "lease" => "meeting_local_capture_lease_acquire",
                "heartbeat" => "meeting_local_capture_lease_heartbeat",
                "lstop" => "meeting_local_capture_lease_stop",
                "register" => "meeting_local_capture_register",
                _ => "meet_recordings_list",
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
            if committed {
                let success: Value = serde_json::from_slice(&std::fs::read(
                    path.with_file_name(format!("{route}-success.json")),
                )?)?;
                for key in ["effects", "audit", "notify"] {
                    setjoin_conformance::golden::compare(&success["observation"][key], &observation[key])?;
                }
            } else {
                setjoin_conformance::golden::compare(&baseline, &observation["effects"])?;
                if observation["audit"] != json!([]) || observation["notify"] != json!([]) {
                    return Err("aborted commit left effects".into());
                }
            }
            ledger("Reaped gofree-meet4 COMMIT-loss proxy; HTTP Unknown resolved from receipt without replay")?;
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
                    "normalization":["fixture identities","generated ids, lease and recording numbers, epoch milliseconds, descriptor digests and timestamps; chat and core audit chains verified"],
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
        ledger("Reaped failed gofree-meet4 COMMIT proxy")?;
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
