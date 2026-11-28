//! Immutable frozen-Go LIST/STATUS/EXPUNGE/CLOSE/CREATE/DELETE/RENAME/COPY/MOVE/
//! APPEND/IDLE transcripts (#345) replayed at the listener's TCP boundary: reply
//! bytes, nothing unrecorded behind them, and the recorded row effects (the query
//! text is oracle/session-observe.json, shared with the Go recorder).
use crate::common;
use common::server;
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::watch,
};

/// Wave 2.7 (#554): normalize authenticated `CAPABILITY` (`CONDSTORE QRESYNC`)
/// and RFC 9051 §6.4.8 `MOVE` `* <seq> EXPUNGE` lines (recorded in
/// `oracle/divergences.json`) without mutating immutable frozen-Go goldens.
fn wave27_expected_reply(expected: &str, authed: bool) -> String {
    let mut out = String::with_capacity(expected.len() + 36);
    for line in expected.split_inclusive("\r\n") {
        let is_auth_cap = line.contains("OK [CAPABILITY ")
            && (line.contains("LOGIN completed") || line.contains("AUTHENTICATE completed"));
        let is_post_auth_cap_list = authed && line.starts_with("* CAPABILITY ");
        if (is_auth_cap || is_post_auth_cap_list) && !line.contains("CONDSTORE") {
            out.push_str(&line.replacen(
                "IMAP4rev2 LOGIN-REFERRALS ID ENABLE",
                "IMAP4rev2 LOGIN-REFERRALS ID ENABLE CONDSTORE QRESYNC",
                1,
            ));
        } else {
            out.push_str(line);
        }
    }
    out
}

/// Read until the expected final line arrives (or timeout), so MOVE responses
/// that now include RFC 9051 §6.4.8 `* <seq> EXPUNGE` lines are read cleanly.
async fn read_until_suffix(stream: &mut TcpStream, suffix: &str, wait: Duration) -> Vec<u8> {
    let mut out = Vec::new();
    let deadline = tokio::time::Instant::now() + wait;
    let mut chunk = [0u8; 8192];
    while !out.ends_with(suffix.as_bytes()) {
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => out.extend_from_slice(&chunk[..n]),
        }
    }
    out
}

/// Exact RFC 9051 §6.4.8 `* <seq> EXPUNGE` sequence numbers expected for every
/// MOVE step that moves >= 1 message in `oracle/session-go-sessions.json`.
fn expected_move_expunge_seqs(name: &str, step: usize) -> Option<&'static [i64]> {
    match (name, step) {
        ("move-forms", 2) => Some(&[1]),
        ("move-forms", 4) => Some(&[1]),
        ("move-forms", 5) => Some(&[1]),
        ("move-forms", 6) => Some(&[2, 2]),
        ("move-forms", 29) => Some(&[1]),
        ("uid-move-forms", 2) => Some(&[2]),
        ("uid-move-forms", 3) => Some(&[1, 1, 2]),
        ("uid-move-forms", 5) => Some(&[2]),
        ("uid-move-forms", 15) => Some(&[1, 2, 2, 2]),
        ("copy-move-membership-uid", 6) => Some(&[2]),
        ("copy-move-membership-uid", 7) => Some(&[2, 3, 3]),
        ("copy-move-membership-uid", 8) => Some(&[1]),
        ("copy-move-membership-uid", 16) => Some(&[1, 2]),
        _ => None,
    }
}

/// Exact Wave 2.7 (#554) `mailboxes.jmap_email_state` delta per `(session, mailbox_id)`
/// from `EXPUNGE`/`CLOSE` now calling `jmap_email_purge(..., TRUE)`.
fn expected_expunge_state_delta(name: &str, mailbox_id: i64) -> i64 {
    match (name, mailbox_id) {
        ("expunge-and-close", 9345021) => 3,
        ("expunge-other-folder-and-project", 9345021) => 2,
        ("expunge-membership-uid", 9345021) => 2,
        ("copy-move-read-only-and-isolation", 9345021) => 1,
        ("copy-move-read-only-and-isolation", 9345022) => 1,
        ("copy-move-null-uid-fails-command", 9345021) => 1,
        _ => 0,
    }
}

/// Exact extra `(mailbox_id, entity)` `email`/`destroyed` journal rows emitted
/// by `EXPUNGE`/`CLOSE` in each recorded session (`jmap_email_purge(..., TRUE)`).
fn expected_expunge_journal_extras(name: &str) -> &'static [(i64, i64)] {
    match name {
        "expunge-and-close" => &[
            (9345021, 9345106),
            (9345021, 9345101),
            (9345021, 9345105),
            (9345021, 9345108),
        ],
        "expunge-other-folder-and-project" => {
            &[(9345021, 9345110), (9345021, 9345101), (9345021, 9345106)]
        }
        "expunge-membership-uid" => &[(9345021, 9345102), (9345021, 9345106), (9345021, 9345101)],
        "copy-move-read-only-and-isolation" => &[(9345021, 9345106), (9345022, 9345111)],
        "copy-move-null-uid-fails-command" => &[(9345021, 9345106)],
        _ => &[],
    }
}

/// Strip verified RFC 9051 §6.4.8 `* <seq> EXPUNGE\r\n` lines from a MOVE reply,
/// asserting exact sequence numbers and order against `expected_move_expunge_seqs`.
fn strip_verified_move_expunges(
    actual: &str,
    expected: &str,
    name: &str,
    step: usize,
    at: &str,
) -> String {
    if !expected.contains("] MOVE completed \r\n") {
        return actual.to_string();
    }
    let want_seqs = expected_move_expunge_seqs(name, step).unwrap_or_else(|| {
        panic!("{at}: unmapped MOVE step emitting COPYUID; add exact expected EXPUNGE seqs")
    });
    let mut got_seqs = Vec::new();
    let mut out = String::with_capacity(actual.len());
    for line in actual.split_inclusive("\r\n") {
        if line.starts_with("* ") && line.ends_with(" EXPUNGE\r\n") {
            let num = line
                .strip_prefix("* ")
                .and_then(|s| s.strip_suffix(" EXPUNGE\r\n"))
                .unwrap_or("");
            let seq = num
                .parse::<i64>()
                .unwrap_or_else(|_| panic!("{at}: invalid MOVE EXPUNGE line {line:?}"));
            got_seqs.push(seq);
        } else {
            out.push_str(line);
        }
    }
    assert_eq!(
        got_seqs.as_slice(),
        want_seqs,
        "{at}: MOVE EXPUNGE sequence numbers mismatch: {actual:?}"
    );
    out
}

async fn read_upto(stream: &mut TcpStream, want: usize, wait: Duration) -> Vec<u8> {
    let mut out = Vec::new();
    let deadline = tokio::time::Instant::now() + wait;
    let mut chunk = [0u8; 8192];
    while out.len() < want {
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => out.extend_from_slice(&chunk[..n]),
        }
    }
    out
}

async fn observe(owner: &tokio_postgres::Client, query: &str) -> serde_json::Value {
    let rows = owner
        .query(&format!("SELECT to_jsonb(r)::text FROM ({query}) r"), &[])
        .await
        .unwrap();
    serde_json::Value::Array(
        rows.iter()
            .map(|r| serde_json::from_str(&r.get::<_, String>(0)).unwrap())
            .collect(),
    )
}

async fn replay(only: Option<&str>, case: &str) {
    let Some(db) = setjoin_conformance::harness::Db::for_case(case) else {
        return;
    };
    let owner = db.connect().await.unwrap();
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../oracle/session-go-sessions.json")).unwrap();
    let outcome = {
        use futures_util::FutureExt;
        std::panic::AssertUnwindSafe(run(&db, &owner, &corpus, only))
            .catch_unwind()
            .await
    };
    owner
        .batch_execute(include_str!("../oracle/session-cleanup.sql"))
        .await
        .unwrap();
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic)
    }
}

async fn run(
    db: &setjoin_conformance::harness::Db,
    owner: &tokio_postgres::Client,
    corpus: &serde_json::Value,
    only: Option<&str>,
) {
    let mut ran = 0;
    for session in corpus.as_array().unwrap() {
        let name = session["name"].as_str().unwrap();
        if only.is_some_and(|o| o != name) {
            continue;
        }
        ran += 1;
        for sql in [
            include_str!("../oracle/session-cleanup.sql"),
            include_str!("../oracle/session-seed.sql"),
        ] {
            owner.batch_execute(sql).await.unwrap();
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, rx) = watch::channel(false);
        let task = tokio::spawn(Arc::new(server(db, "plain")).serve(listener, rx));
        let mut conns: Vec<Option<TcpStream>> = vec![None, None];
        let mut conn_authed: Vec<bool> = vec![false, false];
        let mut had_expunge_or_close = false;
        for (i, step) in session["steps"].as_array().unwrap().iter().enumerate() {
            let at = format!("{name} step {i}");
            if let Some(action) = step.get("action") {
                assert_eq!(action["kind"], "sql", "{at}");
                owner
                    .batch_execute(action["sql"].as_str().unwrap())
                    .await
                    .unwrap();
                continue;
            }
            let idx = step.get("conn").and_then(|c| c.as_u64()).unwrap_or(0) as usize;
            if conns[idx].is_none() {
                conns[idx] = Some(TcpStream::connect(addr).await.unwrap());
            }
            let stream = conns[idx].as_mut().unwrap();
            let request = step["request"].as_str().unwrap();
            let req_upper = request.to_uppercase();
            if req_upper.contains(" EXPUNGE") || req_upper.contains(" CLOSE") {
                had_expunge_or_close = true;
            }
            if !request.is_empty() {
                stream.write_all(request.as_bytes()).await.unwrap();
            }
            if step.get("shutdown").is_some_and(|v| v == true) {
                stream.shutdown().await.unwrap();
            }
            let raw_expected = step["response"].as_str().unwrap();
            if raw_expected.contains("LOGIN completed")
                || raw_expected.contains("AUTHENTICATE completed")
            {
                conn_authed[idx] = true;
            }
            let expected_str = wave27_expected_reply(raw_expected, conn_authed[idx]);
            let expected = expected_str.as_bytes();
            let actual = if expected_str.contains("] MOVE completed \r\n") {
                let tail = expected_str
                    .split_inclusive("\r\n")
                    .last()
                    .unwrap_or("MOVE completed\r\n");
                read_until_suffix(stream, tail, Duration::from_secs(5)).await
            } else {
                read_upto(stream, expected.len(), Duration::from_secs(5)).await
            };
            let actual_lossy = String::from_utf8_lossy(&actual);
            let actual_norm =
                strip_verified_move_expunges(&actual_lossy, &expected_str, name, i, &at);
            assert_eq!(actual_norm, expected_str, "{at}: {request:?}");
        }
        for stream in conns.iter_mut().flatten() {
            let extra = read_upto(stream, 1, Duration::from_millis(200)).await;
            assert!(
                extra.is_empty(),
                "{name}: unrecorded output {:?}",
                String::from_utf8_lossy(&extra)
            );
        }
        drop(conns);
        tokio::time::sleep(Duration::from_millis(200)).await;
        stop.send(true).unwrap();
        task.await.unwrap().unwrap();
        let observe_sql: serde_json::Value =
            serde_json::from_str(include_str!("../oracle/session-observe.json")).unwrap();
        for (key, query) in observe_sql.as_object().unwrap() {
            let actual = observe(owner, query.as_str().unwrap()).await;
            let want = &session["effects"][key];
            if &actual != want {
                // Wave 2.7 (#554): EXPUNGE/CLOSE now calls jmap_email_purge(..., TRUE),
                // advancing jmap_email_state and emitting exact 'destroyed' journal rows
                // (frozen Go passed p_notify=FALSE). Verify monotonicity & exact 'destroyed' ops.
                if had_expunge_or_close && key == "mailboxes" {
                    let (Some(act_arr), Some(want_arr)) = (actual.as_array(), want.as_array())
                    else {
                        panic!("{name}: unexpected mailboxes shape");
                    };
                    assert_eq!(act_arr.len(), want_arr.len(), "{name}: mailboxes len");
                    for (a, w) in act_arr.iter().zip(want_arr.iter()) {
                        assert_eq!(a["id"], w["id"], "{name}: mailbox id");
                        assert_eq!(a["used_bytes"], w["used_bytes"], "{name}: used_bytes");
                        assert_eq!(
                            a["jmap_tag_state"], w["jmap_tag_state"],
                            "{name}: jmap_tag_state"
                        );
                        let mb_id = w["id"].as_i64().unwrap();
                        let want_state = w["jmap_email_state"].as_i64().unwrap()
                            + expected_expunge_state_delta(name, mb_id);
                        assert_eq!(
                            a["jmap_email_state"].as_i64().unwrap(),
                            want_state,
                            "{name}: mailbox {mb_id} jmap_email_state mismatch"
                        );
                    }
                    continue;
                }
                if had_expunge_or_close && key == "journal" {
                    let (Some(act_arr), Some(want_arr)) = (actual.as_array(), want.as_array())
                    else {
                        panic!("{name}: unexpected journal shape");
                    };
                    // Every expected frozen-Go journal row must appear in order with
                    // identical (mailbox_id, datatype, entity, op) and state_seq >= recorded
                    // (preceding EXPUNGE/CLOSE purges now also advance state_seq).
                    let mut matched_idx = std::collections::HashSet::with_capacity(want_arr.len());
                    let mut cursor = 0usize;
                    for want_row in want_arr {
                        let found = (cursor..act_arr.len()).find(|&idx| {
                            let a = &act_arr[idx];
                            a["mailbox_id"] == want_row["mailbox_id"]
                                && a["datatype"] == want_row["datatype"]
                                && a["entity"] == want_row["entity"]
                                && a["op"] == want_row["op"]
                                && a["state_seq"].as_i64().unwrap_or(0)
                                    >= want_row["state_seq"].as_i64().unwrap_or(0)
                        });
                        let Some(idx) = found else {
                            panic!(
                                "{name}: missing expected journal row {want_row}; actual={actual}"
                            );
                        };
                        matched_idx.insert(idx);
                        cursor = idx + 1;
                    }
                    // Every extra journal entry beyond frozen Go MUST be an exact 'destroyed'
                    // email entry matching the exact expected (mailbox_id, entity) purge list.
                    let mut got_extras: Vec<(i64, i64)> = Vec::new();
                    for (idx, extra) in act_arr.iter().enumerate() {
                        if matched_idx.contains(&idx) {
                            continue;
                        }
                        assert_eq!(extra["datatype"], "email", "{name}: extra journal datatype");
                        assert_eq!(extra["op"], "destroyed", "{name}: extra journal op");
                        got_extras.push((
                            extra["mailbox_id"].as_i64().unwrap(),
                            extra["entity"].as_i64().unwrap(),
                        ));
                    }
                    got_extras.sort_unstable();
                    let mut want_extras = expected_expunge_journal_extras(name).to_vec();
                    want_extras.sort_unstable();
                    assert_eq!(
                        got_extras, want_extras,
                        "{name}: extra EXPUNGE/CLOSE journal (mailbox_id, entity) rows mismatch"
                    );
                    continue;
                }
                let brief =
                    |v: &serde_json::Value| v.to_string().chars().take(1500).collect::<String>();
                panic!(
                    "{name}: effect {key}\n actual: {}\n recorded: {}",
                    brief(&actual),
                    brief(want)
                );
            }
        }
    }
    assert!(ran > 0, "no recorded session matched");
}

#[tokio::test]
async fn recorded_session_commands() {
    replay(None, "imap-session").await
}

/// Debug aid: `IMAP_SESSION_ONLY=<name>` replays one recorded session.
#[tokio::test]
async fn recorded_session_commands_single() {
    if let Ok(name) = std::env::var("IMAP_SESSION_ONLY") {
        replay(Some(&name), "imap-session-single").await
    }
}
