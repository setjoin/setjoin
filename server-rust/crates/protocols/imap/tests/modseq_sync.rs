//! Live-DB cross-protocol synchronization proofs for Wave 2.7 (#554):
//!
//! - Bijection `imap_modseq = jmap_email_state + 1`: an empty mailbox (`jmap_email_state = 0`)
//!   advertises `HIGHESTMODSEQ 1` and its first delivery gets `MODSEQ 2`, so `CHANGEDSINCE 1`
//!   always surfaces the first delivery (RFC 7162 §3.1.2).
//! - JMAP/webmail mutations (`deliver`, `jmap_email_set_update`, `jmap_email_set_destroy`)
//!   advance IMAP `HIGHESTMODSEQ` identically to `mailboxes.jmap_email_state + 1` and surface
//!   cleanly via `STATUS ... (HIGHESTMODSEQ)`, `SELECT ... (CONDSTORE)` / `(QRESYNC ...)`,
//!   `UID FETCH 1:* (FLAGS MODSEQ) (CHANGEDSINCE <prev> VANISHED)`, and `UID SEARCH MODSEQ <n>`.
//! - IMAP mutations (`UID STORE`, `APPEND`, `UID COPY`, `UID MOVE`, `EXPUNGE`) advance
//!   `mailboxes.jmap_email_state` cleanly and surface via `jmap_email_changes` with exact
//!   `created`/`updated`/`destroyed` IDs and ZERO spurious `BZ011` resyncs.
//! - Conditional `UID STORE ... (UNCHANGEDSINCE <old>)` returns `[MODIFIED <uid>]` after
//!   a concurrent JMAP mutation without overwriting the message flags; `.SILENT` conditional
//!   `STORE` still emits `* <seq> FETCH (UID <uid> MODSEQ (<new>))`; empty or litigation-held
//!   `EXPUNGE` omits `[HIGHESTMODSEQ ...]`; `STATUS (HIGHESTMODSEQ)` activates `CONDSTORE`;
//!   and `QRESYNC` 4th-arg `seq-match-data` validates strictly and bounds lower vanished UIDs.
mod common;
use common::{executor, serial, worker_executor};
use setjoin_imap::{Server, ThreatPolicy, WebhookPolicy};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::watch,
};

const DOMAIN: &str = "modseq554.test";
const USER_ID: i64 = 9554011;
const MAILBOX_ID: i64 = 9554021;
const EMAIL: &str = "alice@modseq554.test";
const PASSWORD: &str = "modseq-pass-554";

async fn send_cmd(stream: &mut TcpStream, cmd: &str, tag: &str) -> String {
    stream.write_all(cmd.as_bytes()).await.unwrap();
    let needle = format!("{tag} ");
    let mut buf = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut chunk = [0u8; 4096];
    loop {
        let s = String::from_utf8_lossy(&buf);
        if s.lines().any(|l| l.starts_with(&needle)) && s.ends_with("\r\n") {
            return s.into_owned();
        }
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {
                panic!(
                    "timeout/eof waiting for tag {tag:?}; got so far: {:?}",
                    String::from_utf8_lossy(&buf)
                );
            }
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

async fn read_greeting(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut chunk = [0u8; 1024];
    loop {
        let s = String::from_utf8_lossy(&buf);
        if s.contains("\r\n") {
            return s.into_owned();
        }
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => buf.extend_from_slice(&chunk[..n]),
            _ => panic!("failed reading IMAP greeting"),
        }
    }
}

async fn cleanup(owner: &tokio_postgres::Client) {
    owner
        .batch_execute(&format!(
            "SET session_replication_role = replica;
             DELETE FROM mailbox_audit_log WHERE mailbox_id = {MAILBOX_ID};
             DELETE FROM auth_event_log WHERE user_id = {USER_ID} OR email = '{EMAIL}';
             RESET session_replication_role;
             DELETE FROM jmap_changes_journal WHERE mailbox_id = {MAILBOX_ID};
             DELETE FROM messages WHERE mailbox_id = {MAILBOX_ID};
             DELETE FROM tags WHERE mailbox_id = {MAILBOX_ID};
             DELETE FROM mailboxes WHERE id = {MAILBOX_ID};
             DELETE FROM users WHERE id = {USER_ID};
             DELETE FROM domains WHERE name = '{DOMAIN}';"
        ))
        .await
        .unwrap();
}

async fn seed_empty_fixture(owner: &tokio_postgres::Client) {
    cleanup(owner).await;
    let hash_row = owner
        .query_one("SELECT crypt($1, gen_salt('bf', 4))", &[&PASSWORD])
        .await
        .unwrap();
    let pw_hash: String = hash_row.get(0);
    owner
        .execute(
            "INSERT INTO domains (name, is_local) VALUES ($1, TRUE)",
            &[&DOMAIN],
        )
        .await
        .unwrap();
    owner
        .execute(
            "INSERT INTO users (id, username, domain_id, email, display_name, password_hash, must_change_password)
             VALUES ($1, 'alice554', (SELECT id FROM domains WHERE name = $2), $3, 'Alice 554', $4, FALSE)",
            &[&USER_ID, &DOMAIN, &EMAIL, &pw_hash],
        )
        .await
        .unwrap();
    owner
        .execute(
            "INSERT INTO mailboxes (id, user_id, domain_id, email, display_name, type, is_primary, jmap_email_state)
             VALUES ($1, $2, (SELECT id FROM domains WHERE name = $3), $4, 'Alice 554', 'personal', TRUE, 0)",
            &[&MAILBOX_ID, &USER_ID, &DOMAIN, &EMAIL],
        )
        .await
        .unwrap();
    owner
        .execute("SELECT create_system_tags($1)", &[&MAILBOX_ID])
        .await
        .unwrap();
    owner
        .execute(
            "UPDATE tags SET imap_uid_validity = 554001 WHERE mailbox_id = $1 AND name = 'Inbox'",
            &[&MAILBOX_ID],
        )
        .await
        .unwrap();
    owner
        .execute(
            "INSERT INTO tags (mailbox_id, name, tag_type, sort_order, imap_expose, imap_uid_validity)
             VALUES ($1, 'Archive554', 'user', 50, TRUE, 554002)",
            &[&MAILBOX_ID],
        )
        .await
        .unwrap();
}

async fn deliver_msg(
    owner: &tokio_postgres::Client,
    raw_ref: &str,
    msg_id: &str,
    from: &str,
    subject: &str,
    body: &str,
) -> i64 {
    owner
        .query_one(
            "SELECT deliver($1, $2, $3, 'Sender', $4,
                            jsonb_build_array($4::text),
                            '[]'::jsonb, '[]'::jsonb, $5, NULL, NULL, $6, NULL,
                            100, FALSE, now(), 'pass', 'pass', 'pass', 0.0, NULL)",
            &[&raw_ref, &msg_id, &from, &EMAIL, &subject, &body],
        )
        .await
        .unwrap()
        .get(0)
}

async fn seed_fixture(owner: &tokio_postgres::Client) -> (i64, i64, i64) {
    seed_empty_fixture(owner).await;
    let m1 = deliver_msg(
        owner,
        "raw-554-1",
        "<m1@modseq554.test>",
        "bob@ext.test",
        "Hello 1",
        "body one",
    )
    .await;
    let m2 = deliver_msg(
        owner,
        "raw-554-2",
        "<m2@modseq554.test>",
        "carol@ext.test",
        "Hello 2",
        "body two",
    )
    .await;
    let state = email_state(owner).await;
    (m1, m2, state)
}

async fn email_state(owner: &tokio_postgres::Client) -> i64 {
    owner
        .query_one(
            "SELECT jmap_email_state FROM mailboxes WHERE id = $1",
            &[&MAILBOX_ID],
        )
        .await
        .unwrap()
        .get(0)
}

fn modseq_of(state: i64) -> i64 {
    state + 1
}

async fn jmap_changes(owner: &tokio_postgres::Client, since: i64) -> serde_json::Value {
    let text: String = owner
        .query_one(
            "SELECT jmap_email_changes($1, $2)::text",
            &[&MAILBOX_ID, &since.to_string()],
        )
        .await
        .unwrap()
        .get(0);
    serde_json::from_str(&text).unwrap()
}

#[tokio::test]
async fn cross_protocol_imap_condstore_qresync_and_jmap_changes_stay_in_single_currency() {
    let Some(db) = setjoin_conformance::harness::Db::for_case("imap-modseq-sync") else {
        return;
    };
    serial().await;
    let owner = db.connect().await.unwrap();
    let outcome = {
        use futures_util::FutureExt;
        std::panic::AssertUnwindSafe(run_sync_scenario(&db, &owner))
            .catch_unwind()
            .await
    };
    cleanup(&owner).await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

async fn run_sync_scenario(db: &setjoin_conformance::harness::Db, owner: &tokio_postgres::Client) {
    // 0. RFC 7162 §3.1.2 empty-mailbox HIGHESTMODSEQ 1 -> first delivery MODSEQ 2 (> 1!).
    seed_empty_fixture(owner).await;
    let srv = Server::new(executor(db), ThreatPolicy::Unwired, WebhookPolicy::Unwired)
        .with_auth_db(worker_executor(db));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(Arc::new(srv).serve(listener, rx));

    let mut conn = TcpStream::connect(addr).await.unwrap();
    let greeting = read_greeting(&mut conn).await;
    assert!(greeting.contains("mailserver ready"));

    let login = send_cmd(&mut conn, &format!("a1 LOGIN {EMAIL} {PASSWORD}\r\n"), "a1").await;
    assert!(login.contains("a1 OK"), "login failed: {login}");
    assert!(
        login.contains("CONDSTORE") && login.contains("QRESYNC"),
        "authenticated LOGIN must advertise CONDSTORE QRESYNC: {login}"
    );
    let cap = send_cmd(&mut conn, "a1b CAPABILITY\r\n", "a1b").await;
    assert!(
        cap.contains("CONDSTORE") && cap.contains("QRESYNC"),
        "authenticated CAPABILITY must advertise CONDSTORE QRESYNC before ENABLE: {cap}"
    );

    // Empty mailbox advertises HIGHESTMODSEQ 1.
    let empty_sel = send_cmd(&mut conn, "a1c SELECT INBOX (CONDSTORE)\r\n", "a1c").await;
    assert!(
        empty_sel.contains("* OK [HIGHESTMODSEQ 1]"),
        "empty mailbox must advertise HIGHESTMODSEQ 1: {empty_sel}"
    );
    // Empty EXPUNGE on empty mailbox must NOT emit [HIGHESTMODSEQ ...] (RFC 7162 §6).
    let empty_exp = send_cmd(&mut conn, "a1d EXPUNGE\r\n", "a1d").await;
    assert!(
        empty_exp.contains("a1d OK EXPUNGE completed") && !empty_exp.contains("HIGHESTMODSEQ"),
        "empty EXPUNGE must not emit [HIGHESTMODSEQ]: {empty_exp}"
    );

    // Deliver first message (state 0 -> 1, MODSEQ 2) and prove CHANGEDSINCE 1 returns it!
    let m1 = deliver_msg(
        owner,
        "raw-554-1",
        "<m1@modseq554.test>",
        "bob@ext.test",
        "Hello 1",
        "body one",
    )
    .await;
    let u1: i64 = owner
        .query_one("SELECT imap_uid FROM messages WHERE id = $1", &[&m1])
        .await
        .unwrap()
        .get(0);
    let first_delta = send_cmd(
        &mut conn,
        "a1e UID FETCH 1:* (FLAGS MODSEQ) (CHANGEDSINCE 1)\r\n",
        "a1e",
    )
    .await;
    assert!(
        first_delta.contains(&format!("UID {u1} FLAGS () MODSEQ (2)")),
        "first delivery in empty mailbox MUST be returned by CHANGEDSINCE 1 with MODSEQ (2): {first_delta}"
    );

    // Deliver second message (state -> 2, MODSEQ 3).
    let m2 = deliver_msg(
        owner,
        "raw-554-2",
        "<m2@modseq554.test>",
        "carol@ext.test",
        "Hello 2",
        "body two",
    )
    .await;
    let u2: i64 = owner
        .query_one("SELECT imap_uid FROM messages WHERE id = $1", &[&m2])
        .await
        .unwrap()
        .get(0);
    let state0 = email_state(owner).await;
    assert_eq!(
        state0, 2,
        "two deliver() calls advance jmap_email_state to 2"
    );
    let ms0 = modseq_of(state0); // 3

    // 1. ENABLE QRESYNC enables both QRESYNC and CONDSTORE.
    let en = send_cmd(&mut conn, "a2 ENABLE QRESYNC\r\n", "a2").await;
    assert!(en.contains("* ENABLED QRESYNC CONDSTORE"), "enable: {en}");

    // 2. STATUS ... (MESSAGES HIGHESTMODSEQ) matches jmap_email_state + 1.
    let st = send_cmd(
        &mut conn,
        "a3 STATUS INBOX (MESSAGES HIGHESTMODSEQ)\r\n",
        "a3",
    )
    .await;
    assert!(
        st.contains(&format!("HIGHESTMODSEQ {ms0}")),
        "STATUS HIGHESTMODSEQ must equal jmap_email_state + 1 ({ms0}): {st}"
    );

    // 3. SELECT INBOX (CONDSTORE) emits HIGHESTMODSEQ = ms0.
    let sel = send_cmd(&mut conn, "a4 SELECT INBOX (CONDSTORE)\r\n", "a4").await;
    assert!(
        sel.contains(&format!("* OK [HIGHESTMODSEQ {ms0}]")),
        "SELECT HIGHESTMODSEQ mismatch: {sel}"
    );

    // 4. JMAP mutation (`jmap_email_set_update` marking m1 $seen) advances HIGHESTMODSEQ
    //    identically to mailboxes.jmap_email_state + 1 and surfaces via UID FETCH (CHANGEDSINCE)
    //    and UID SEARCH MODSEQ.
    let patch =
        serde_json::json!({ m1.to_string(): { "keywords": { "$seen": true } } }).to_string();
    owner
        .execute(
            "SELECT jmap_email_set_update($1, $2::text::jsonb)",
            &[&MAILBOX_ID, &patch],
        )
        .await
        .unwrap();
    let state1 = email_state(owner).await;
    assert_eq!(state1, state0 + 1);
    let ms1 = modseq_of(state1);

    let st2 = send_cmd(&mut conn, "a5 STATUS INBOX (HIGHESTMODSEQ)\r\n", "a5").await;
    assert!(st2.contains(&format!("HIGHESTMODSEQ {ms1}")), "{st2}");

    let f_delta = send_cmd(
        &mut conn,
        &format!("a6 UID FETCH 1:* (FLAGS MODSEQ) (CHANGEDSINCE {ms0})\r\n"),
        "a6",
    )
    .await;
    assert!(
        f_delta.contains(&format!("UID {u1} FLAGS (\\Seen) MODSEQ ({ms1})")),
        "expected m1 in CHANGEDSINCE delta: {f_delta}"
    );
    assert!(
        !f_delta.contains(&format!("UID {u2} ")),
        "unmodified m2 must not appear in CHANGEDSINCE {ms0}: {f_delta}"
    );

    let srch = send_cmd(&mut conn, &format!("a7 UID SEARCH MODSEQ {ms1}\r\n"), "a7").await;
    assert!(
        srch.contains(&format!("ALL {u1} MODSEQ {ms1}")),
        "UID SEARCH MODSEQ mismatch: {srch}"
    );

    // 5. Conditional UID STORE ... (UNCHANGEDSINCE ms0) MUST fail with [MODIFIED u1]
    //    because JMAP mutated m1 to ms1 > ms0!
    let cstore_fail = send_cmd(
        &mut conn,
        &format!("a8 UID STORE {u1} (UNCHANGEDSINCE {ms0}) +FLAGS (\\Flagged)\r\n"),
        "a8",
    )
    .await;
    assert!(
        cstore_fail.contains(&format!("a8 OK [MODIFIED {u1}]")),
        "expected [MODIFIED {u1}] on stale UNCHANGEDSINCE: {cstore_fail}"
    );
    let still_unflagged: bool = owner
        .query_one("SELECT is_flagged FROM messages WHERE id = $1", &[&m1])
        .await
        .unwrap()
        .get(0);
    assert!(!still_unflagged, "stale UNCHANGEDSINCE must not mutate m1");

    // 6. Conditional UID STORE with current modseq (ms1) succeeds and surfaces in jmap_email_changes!
    let cstore_ok = send_cmd(
        &mut conn,
        &format!("a9 UID STORE {u1} (UNCHANGEDSINCE {ms1}) +FLAGS (\\Flagged)\r\n"),
        "a9",
    )
    .await;
    assert!(cstore_ok.contains("a9 OK STORE completed"), "{cstore_ok}");
    let state2 = email_state(owner).await;
    assert_eq!(state2, state1 + 1);
    let ms2 = modseq_of(state2);
    assert!(
        cstore_ok.contains(&format!("MODSEQ ({ms2})")),
        "STORE reply must carry new MODSEQ ({ms2}): {cstore_ok}"
    );
    let jdelta1 = jmap_changes(owner, state1).await;
    assert_eq!(jdelta1["updated"], serde_json::json!([m1]));
    assert_eq!(jdelta1["newState"], state2.to_string());

    // 7. IMAP APPEND surfaces as exact 'created' in jmap_email_changes (no BZ011).
    conn.write_all(b"a10 APPEND INBOX (\\Seen) {11}\r\n")
        .await
        .unwrap();
    let mut ready_buf = [0u8; 256];
    let n = conn.read(&mut ready_buf).await.unwrap();
    assert!(
        String::from_utf8_lossy(&ready_buf[..n]).contains("+ Ready"),
        "expected literal continuation"
    );
    let app = send_cmd(&mut conn, "hello world\r\n", "a10").await;
    assert!(app.contains("a10 OK [APPENDUID"), "APPEND failed: {app}");
    let state3 = email_state(owner).await;
    assert_eq!(state3, state2 + 1);
    let jdelta2 = jmap_changes(owner, state2).await;
    let created_arr = jdelta2["created"].as_array().unwrap();
    assert_eq!(
        created_arr.len(),
        1,
        "APPEND must record 1 created id: {jdelta2}"
    );
    let m3 = created_arr[0].as_i64().unwrap();
    let u3: i64 = owner
        .query_one("SELECT imap_uid FROM messages WHERE id = $1", &[&m3])
        .await
        .unwrap()
        .get(0);

    // 8. IMAP UID COPY + UID MOVE surface cleanly in jmap_email_changes without BZ011.
    let cpy = send_cmd(
        &mut conn,
        &format!("a11 UID COPY {u3} Archive554\r\n"),
        "a11",
    )
    .await;
    assert!(cpy.contains("a11 OK COPY completed"), "COPY failed: {cpy}");
    let state4 = email_state(owner).await;
    assert_eq!(state4, state3 + 1);
    let jdelta3 = jmap_changes(owner, state3).await;
    assert_eq!(jdelta3["updated"], serde_json::json!([m3]));

    // Append one more message and UID MOVE it to Trash -> surfaces as 'updated' in JMAP
    // and as VANISHED (EARLIER) from Inbox in QRESYNC.
    conn.write_all(b"a11b APPEND INBOX () {9}\r\n")
        .await
        .unwrap();
    let n = conn.read(&mut ready_buf).await.unwrap();
    assert!(String::from_utf8_lossy(&ready_buf[..n]).contains("+ Ready"));
    let app2 = send_cmd(&mut conn, "move test\r\n", "a11b").await;
    assert!(
        app2.contains("a11b OK [APPENDUID"),
        "APPEND 2 failed: {app2}"
    );
    let state4a = email_state(owner).await;
    let ms4a = modseq_of(state4a);
    let m4 = jmap_changes(owner, state4).await["created"][0]
        .as_i64()
        .unwrap();
    let u4: i64 = owner
        .query_one("SELECT imap_uid FROM messages WHERE id = $1", &[&m4])
        .await
        .unwrap()
        .get(0);
    let mov = send_cmd(&mut conn, &format!("a11c UID MOVE {u4} Trash\r\n"), "a11c").await;
    assert!(
        mov.contains(&format!("* VANISHED {u4}")),
        "QRESYNC-enabled MOVE must emit * VANISHED {u4}: {mov}"
    );
    assert!(mov.contains("a11c OK MOVE completed"), "MOVE failed: {mov}");
    let state4b = email_state(owner).await;
    assert_eq!(state4b, state4a + 1);
    let ms4b = modseq_of(state4b);
    assert_eq!(
        jmap_changes(owner, state4a).await["updated"],
        serde_json::json!([m4])
    );

    // 9. IMAP UID STORE \Deleted + EXPUNGE: unexpunged \Deleted is NOT vanished until
    //    EXPUNGE; EXPUNGE purges m2, bumps state to state6, emits * VANISHED + [HIGHESTMODSEQ],
    //    and surfaces as 'destroyed' in jmap_email_changes & QRESYNC even after hard DELETE!
    let mark_del = send_cmd(
        &mut conn,
        &format!("a12 UID STORE {u2} +FLAGS.SILENT (\\Deleted)\r\n"),
        "a12",
    )
    .await;
    assert!(mark_del.contains("a12 OK STORE completed"), "{mark_del}");
    let state5 = email_state(owner).await;
    assert_eq!(state5, state4b + 1);
    let ms5 = modseq_of(state5);

    // Before EXPUNGE, unexpunged \Deleted u2 MUST NOT appear in VANISHED (EARLIER)!
    let f_pre_exp = send_cmd(
        &mut conn,
        &format!("a12b UID FETCH 1:* (FLAGS MODSEQ) (VANISHED CHANGEDSINCE {ms4b})\r\n"),
        "a12b",
    )
    .await;
    assert!(
        !f_pre_exp.contains("* VANISHED (EARLIER)"),
        "unexpunged \\Deleted u2 must NOT be reported as VANISHED before EXPUNGE: {f_pre_exp}"
    );
    assert!(
        f_pre_exp.contains(&format!("UID {u2} FLAGS (\\Deleted) MODSEQ ({ms5})")),
        "unexpunged \\Deleted u2 must still appear in FETCH: {f_pre_exp}"
    );

    let exp = send_cmd(&mut conn, "a13 EXPUNGE\r\n", "a13").await;
    let state6 = email_state(owner).await;
    assert_eq!(state6, state5 + 1, "EXPUNGE must bump jmap_email_state");
    let ms6 = modseq_of(state6);
    assert!(
        exp.contains(&format!("* VANISHED {u2}")),
        "QRESYNC-enabled EXPUNGE must emit * VANISHED {u2}: {exp}"
    );
    assert!(
        exp.contains(&format!("a13 OK [HIGHESTMODSEQ {ms6}] EXPUNGE completed")),
        "CONDSTORE EXPUNGE must return [HIGHESTMODSEQ {ms6}]: {exp}"
    );

    // Confirm row m2 is hard-deleted from messages, yet jmap_email_changes & QRESYNC both know it vanished!
    let exists_m2: i64 = owner
        .query_one("SELECT count(*) FROM messages WHERE id = $1", &[&m2])
        .await
        .unwrap()
        .get(0);
    assert_eq!(exists_m2, 0, "EXPUNGE must hard-delete m2");

    let jdelta4 = jmap_changes(owner, state4b).await;
    assert_eq!(jdelta4["destroyed"], serde_json::json!([m2]));

    // UID FETCH ... (CHANGEDSINCE ms4a VANISHED) reports BOTH moved u4 and expunged u2!
    let f_van = send_cmd(
        &mut conn,
        &format!("a14 UID FETCH 1:* (FLAGS MODSEQ) (CHANGEDSINCE {ms4a} VANISHED)\r\n"),
        "a14",
    )
    .await;
    assert!(
        f_van.contains("* VANISHED (EARLIER)")
            && f_van.contains(&u2.to_string())
            && f_van.contains(&u4.to_string()),
        "UID FETCH CHANGEDSINCE VANISHED must report {u2} and {u4}: {f_van}"
    );

    // Fresh SELECT INBOX (QRESYNC (554001 <ms1>)) reports BOTH vanished u2 AND changed m1/m3!
    let qsel = send_cmd(
        &mut conn,
        &format!("a15 SELECT INBOX (QRESYNC (554001 {ms1}))\r\n"),
        "a15",
    )
    .await;
    assert!(
        qsel.contains(&format!("* OK [HIGHESTMODSEQ {ms6}]")),
        "QRESYNC SELECT HIGHESTMODSEQ mismatch: {qsel}"
    );
    assert!(
        qsel.contains(&format!("* VANISHED (EARLIER) {u2}")),
        "QRESYNC SELECT must emit VANISHED (EARLIER) {u2}: {qsel}"
    );
    assert!(
        qsel.contains(&format!("UID {u1} FLAGS (\\Seen \\Flagged) MODSEQ ({ms2})")),
        "QRESYNC SELECT must emit changed m1: {qsel}"
    );

    // QRESYNC 4th parameter seq-match-data bounding (RFC 7162 §3.2.5.2):
    // Live Inbox now has seq 1 -> u1, seq 2 -> u3 (u2 and u4 vanished).
    // Passing (1,2 u1,u3) confirms seq 1..2 align through u3 -> u2 (<= u3) is bounded out,
    // while u4 (> u3) is still reported!
    let qsel_bounded = send_cmd(
        &mut conn,
        &format!("a15b SELECT INBOX (QRESYNC (554001 {ms1} (1:2 {u1},{u3})))\r\n"),
        "a15b",
    )
    .await;
    assert!(
        qsel_bounded.contains(&format!("* VANISHED (EARLIER) {u4}"))
            && !qsel_bounded.contains(&format!("* VANISHED (EARLIER) {u2}")),
        "seq-match-data (1:2 {u1},{u3}) must bound out u2 <= u3 and emit only u4: {qsel_bounded}"
    );

    // End-to-end incremental JMAP Email/changes from 0 across ALL operations (ZERO BZ011!).
    let full_delta = jmap_changes(owner, 0).await;
    assert_eq!(full_delta["newState"], state6.to_string());
    assert_eq!(full_delta["hasMoreChanges"], false);

    let _ = send_cmd(&mut conn, "a16 LOGOUT\r\n", "a16").await;
    drop(conn);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn rfc7162_negotiation_bad_rejections_silent_store_concurrency_and_litigation_hold() {
    let Some(db) = setjoin_conformance::harness::Db::for_case("imap-modseq-edge") else {
        return;
    };
    serial().await;
    let owner = db.connect().await.unwrap();
    let outcome = {
        use futures_util::FutureExt;
        std::panic::AssertUnwindSafe(run_edge_scenario(&db, &owner))
            .catch_unwind()
            .await
    };
    cleanup(&owner).await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

async fn run_edge_scenario(db: &setjoin_conformance::harness::Db, owner: &tokio_postgres::Client) {
    let (m1, m2, state0) = seed_fixture(owner).await;
    let ms0 = modseq_of(state0);
    let u1: i64 = owner
        .query_one("SELECT imap_uid FROM messages WHERE id = $1", &[&m1])
        .await
        .unwrap()
        .get(0);
    let u2: i64 = owner
        .query_one("SELECT imap_uid FROM messages WHERE id = $1", &[&m2])
        .await
        .unwrap()
        .get(0);

    let srv = Server::new(executor(db), ThreatPolicy::Unwired, WebhookPolicy::Unwired)
        .with_auth_db(worker_executor(db));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(Arc::new(srv).serve(listener, rx));

    // Separate connection verifies RFC 7162 §3.1: STATUS (... HIGHESTMODSEQ) activates CONDSTORE
    // AND emits untagged * OK [HIGHESTMODSEQ <n>] Highest when a mailbox is already selected!
    {
        let mut status_conn = TcpStream::connect(addr).await.unwrap();
        let _ = read_greeting(&mut status_conn).await;
        let _ = send_cmd(
            &mut status_conn,
            &format!("s1 LOGIN {EMAIL} {PASSWORD}\r\n"),
            "s1",
        )
        .await;
        let plain_s = send_cmd(&mut status_conn, "s1b SELECT INBOX\r\n", "s1b").await;
        assert!(
            !plain_s.contains("HIGHESTMODSEQ"),
            "plain SELECT before STATUS must not emit HIGHESTMODSEQ: {plain_s}"
        );
        let st = send_cmd(
            &mut status_conn,
            "s2 STATUS INBOX (HIGHESTMODSEQ)\r\n",
            "s2",
        )
        .await;
        assert!(
            st.contains(&format!("* OK [HIGHESTMODSEQ {ms0}] Highest"))
                && st.contains(&format!("HIGHESTMODSEQ {ms0})")),
            "STATUS (HIGHESTMODSEQ) while selected must emit untagged HIGHESTMODSEQ and STATUS value: {st}"
        );
        let sel = send_cmd(&mut status_conn, "s3 SELECT INBOX\r\n", "s3").await;
        assert!(
            sel.contains(&format!("* OK [HIGHESTMODSEQ {ms0}]")),
            "STATUS (HIGHESTMODSEQ) must persistently activate CONDSTORE for subsequent SELECT: {sel}"
        );
        let _ = send_cmd(&mut status_conn, "s4 LOGOUT\r\n", "s4").await;
    }

    let mut conn = TcpStream::connect(addr).await.unwrap();
    let _ = read_greeting(&mut conn).await;
    let login = send_cmd(&mut conn, &format!("e1 LOGIN {EMAIL} {PASSWORD}\r\n"), "e1").await;
    assert!(login.contains("e1 OK"), "{login}");

    // 1. RFC 7162 BAD rejections BEFORE ENABLE QRESYNC
    let bad_qsel = send_cmd(&mut conn, "e2 SELECT INBOX (QRESYNC (554001 1))\r\n", "e2").await;
    assert!(
        bad_qsel.contains("e2 BAD"),
        "SELECT (QRESYNC) without ENABLE QRESYNC must return BAD: {bad_qsel}"
    );

    // Plain SELECT without CONDSTORE enabled -> no HIGHESTMODSEQ yet.
    let plain_sel = send_cmd(&mut conn, "e3 SELECT INBOX\r\n", "e3").await;
    assert!(plain_sel.contains("e3 OK [READ-WRITE]"), "{plain_sel}");
    assert!(
        !plain_sel.contains("HIGHESTMODSEQ"),
        "plain SELECT before CONDSTORE activation must not emit HIGHESTMODSEQ: {plain_sel}"
    );

    // RFC 7162 BAD rejections on FETCH modifiers
    for (tag, cmd) in [
        (
            "e4",
            "e4 UID FETCH 1:* (FLAGS) (CHANGEDSINCE 1 VANISHED)\r\n",
        ),
        ("e5", "e5 FETCH 1:* (FLAGS) (CHANGEDSINCE 1 VANISHED)\r\n"),
        ("e6", "e6 UID FETCH 1:* (FLAGS) (VANISHED)\r\n"),
        ("e7", "e7 UID FETCH 1:* (FLAGS) (CHANGEDSINCE 0)\r\n"),
    ] {
        let rsp = send_cmd(&mut conn, cmd, tag).await;
        assert!(
            rsp.contains(&format!("{tag} BAD")),
            "expected BAD for {cmd:?}, got: {rsp}"
        );
    }

    // 2. Persistent session-level CONDSTORE activation via FETCH (MODSEQ)
    let mod_fetch = send_cmd(&mut conn, "e8 FETCH 1 (MODSEQ)\r\n", "e8").await;
    assert!(
        mod_fetch.contains(&format!("* OK [HIGHESTMODSEQ {ms0}]")),
        "first CONDSTORE command while selected must emit HIGHESTMODSEQ: {mod_fetch}"
    );
    // Subsequent plain SELECT in the same session MUST still emit HIGHESTMODSEQ!
    let plain_sel2 = send_cmd(&mut conn, "e9 SELECT INBOX\r\n", "e9").await;
    assert!(
        plain_sel2.contains(&format!("* OK [HIGHESTMODSEQ {ms0}]")),
        "CONDSTORE must persist across subsequent plain SELECT: {plain_sel2}"
    );

    // 3. RFC 7162 §3.1.3: STORE (UNCHANGEDSINCE n) ... .SILENT MUST still emit
    //    * <seq> FETCH (UID <uid> MODSEQ (<new>)) without FLAGS!
    let silent_cond = send_cmd(
        &mut conn,
        &format!("e10 UID STORE {u1} (UNCHANGEDSINCE {ms0}) +FLAGS.SILENT (\\Flagged)\r\n"),
        "e10",
    )
    .await;
    let state1 = email_state(owner).await;
    assert_eq!(state1, state0 + 1);
    let ms1 = modseq_of(state1);
    assert!(
        silent_cond.contains(&format!("* 1 FETCH (UID {u1} MODSEQ ({ms1}))")),
        "conditional .SILENT STORE must emit untagged MODSEQ FETCH: {silent_cond}"
    );
    assert!(
        !silent_cond.contains("FLAGS ("),
        "conditional .SILENT STORE must suppress FLAGS: {silent_cond}"
    );
    assert!(
        silent_cond.contains("e10 OK STORE completed"),
        "{silent_cond}"
    );

    // 4. Real concurrent interleaving: a concurrent JMAP transaction locks mailboxes +
    //    mutates m1 BEFORE committing while IMAP UID STORE (UNCHANGEDSINCE ms1) waits
    //    on the lock; once JMAP commits (ms2), IMAP MUST see locked modseq > ms1 and
    //    return [MODIFIED u1] without setting \Answered!
    let mut jmap_conn = db.connect().await.unwrap();
    let jmap_tx = jmap_conn.transaction().await.unwrap();
    let patch =
        serde_json::json!({ m1.to_string(): { "keywords": { "$seen": true } } }).to_string();
    jmap_tx
        .execute(
            "SELECT jmap_email_set_update($1, $2::text::jsonb)",
            &[&MAILBOX_ID, &patch],
        )
        .await
        .unwrap();

    // Launch IMAP conditional STORE while jmap_tx holds the mailbox + message lock!
    let imap_cmd = format!("e11 UID STORE {u1} (UNCHANGEDSINCE {ms1}) +FLAGS (\\Answered)\r\n");
    conn.write_all(imap_cmd.as_bytes()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(120)).await;
    jmap_tx.commit().await.unwrap();

    let mut buf = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut chunk = [0u8; 4096];
    let race_rsp = loop {
        let s = String::from_utf8_lossy(&buf);
        if s.lines().any(|l| l.starts_with("e11 ")) && s.ends_with("\r\n") {
            break s.into_owned();
        }
        match tokio::time::timeout_at(deadline, conn.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => buf.extend_from_slice(&chunk[..n]),
            other => panic!("concurrent STORE read failed: {other:?}"),
        }
    };
    assert!(
        race_rsp.contains(&format!("e11 OK [MODIFIED {u1}]")),
        "concurrent JMAP commit must cause conditional STORE to return [MODIFIED {u1}]: {race_rsp}"
    );
    let answered_after_race: bool = owner
        .query_one("SELECT is_answered FROM messages WHERE id = $1", &[&m1])
        .await
        .unwrap()
        .get(0);
    assert!(
        !answered_after_race,
        "racing conditional STORE must NOT overwrite m1 after JMAP commit"
    );

    // 5. ENABLE QRESYNC + BAD checks on QRESYNC args (modseq 0, '*' in known_uids, invalid seq-match-data)
    let en = send_cmd(&mut conn, "e12 ENABLE QRESYNC\r\n", "e12").await;
    assert!(en.contains("* ENABLED QRESYNC CONDSTORE"), "{en}");
    for (tag, cmd) in [
        ("e13", "e13 SELECT INBOX (QRESYNC (554001 0))\r\n"),
        ("e14", "e14 SELECT INBOX (QRESYNC (554001 1 1:*))\r\n"),
        (
            "e14b",
            "e14b SELECT INBOX (QRESYNC (554001 1 (2:1 1:2)))\r\n",
        ),
        (
            "e14c",
            "e14c SELECT INBOX (QRESYNC (554001 1 (1:2 10:12)))\r\n",
        ),
        ("e14d", "e14d SELECT INBOX (QRESYNC (554001 1 (+1 1)))\r\n"),
        (
            "e14e",
            "e14e SELECT INBOX (QRESYNC (554001 1 (1 4294967296)))\r\n",
        ),
    ] {
        let rsp = send_cmd(&mut conn, cmd, tag).await;
        assert!(
            rsp.contains(&format!("{tag} BAD")),
            "expected BAD for {cmd:?}, got: {rsp}"
        );
    }

    // 6. Litigation-held \Deleted message on EXPUNGE MUST NOT be purged, announced as
    //    VANISHED, OR emit [HIGHESTMODSEQ ...] (RFC 7162 §6)!
    let sel_hold = send_cmd(&mut conn, "e15 SELECT INBOX\r\n", "e15").await;
    assert!(sel_hold.contains("e15 OK [READ-WRITE]"), "{sel_hold}");
    owner
        .execute(
            "UPDATE messages SET held = TRUE WHERE id = $1 AND mailbox_id = $2",
            &[&m2, &MAILBOX_ID],
        )
        .await
        .unwrap();
    let del_hold = send_cmd(
        &mut conn,
        &format!("e16 UID STORE {u2} +FLAGS.SILENT (\\Deleted)\r\n"),
        "e16",
    )
    .await;
    assert!(del_hold.contains("e16 OK STORE completed"), "{del_hold}");
    let exp_hold = send_cmd(&mut conn, "e17 EXPUNGE\r\n", "e17").await;
    assert!(
        !exp_hold.contains("VANISHED") && !exp_hold.contains("EXPUNGE\r\n"),
        "litigation-held (notPurged) message must NEVER be announced as VANISHED/EXPUNGE: {exp_hold}"
    );
    assert!(
        exp_hold.contains("e17 OK EXPUNGE completed") && !exp_hold.contains("HIGHESTMODSEQ"),
        "held-only EXPUNGE (0 purged) must NOT emit [HIGHESTMODSEQ]: {exp_hold}"
    );
    let held_still_exists: i64 = owner
        .query_one("SELECT count(*) FROM messages WHERE id = $1", &[&m2])
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        held_still_exists, 1,
        "litigation-held message must survive EXPUNGE"
    );

    // Release hold so we can also prove:
    //   (a) Self-MOVE (INBOX -> INBOX) does NOT emit * VANISHED / * <seq> EXPUNGE
    //   (b) EXPUNGE after an unseen concurrent JMAP flag mutation omits [HIGHESTMODSEQ ...] (RFC 7162 §6)!
    owner
        .execute(
            "UPDATE messages SET held = FALSE WHERE id = $1 AND mailbox_id = $2",
            &[&m2, &MAILBOX_ID],
        )
        .await
        .unwrap();

    let self_mov = send_cmd(&mut conn, &format!("e17b UID MOVE {u1} INBOX\r\n"), "e17b").await;
    assert!(
        self_mov.contains("e17b OK MOVE completed")
            && !self_mov.contains("* VANISHED")
            && !self_mov.contains("EXPUNGE\r\n"),
        "self-MOVE to same selected folder must not emit VANISHED/EXPUNGE: {self_mov}"
    );

    // Intervening unseen JMAP flag update on m1 advances mailbox MODSEQ past session's seen cursor:
    // EXPUNGE of already-\Deleted m2 must purge m2 + emit * VANISHED u2, but OMIT [HIGHESTMODSEQ]!
    let patch2 =
        serde_json::json!({ m1.to_string(): { "keywords": { "$flagged": false } } }).to_string();
    owner
        .execute(
            "SELECT jmap_email_set_update($1, $2::text::jsonb)",
            &[&MAILBOX_ID, &patch2],
        )
        .await
        .unwrap();
    let exp_concurrent = send_cmd(&mut conn, "e17c EXPUNGE\r\n", "e17c").await;
    assert!(
        exp_concurrent.contains(&format!("* VANISHED {u2}"))
            && exp_concurrent.contains("e17c OK EXPUNGE completed")
            && !exp_concurrent.contains("HIGHESTMODSEQ"),
        "EXPUNGE after unseen concurrent JMAP flag update must emit * VANISHED but omit [HIGHESTMODSEQ]: {exp_concurrent}"
    );

    let _ = send_cmd(&mut conn, "e18 LOGOUT\r\n", "e18").await;
    drop(conn);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}
