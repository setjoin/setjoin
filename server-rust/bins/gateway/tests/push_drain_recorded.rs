//! #408: seed-plus-one-tick oracle for `push-intent-drain`. Frozen Go's real
//! `pushjobs.Worker.Run` (overlay `tests/conformance/drain/`) runs one tick
//! over seeded queues with the real provider set pointed at an owned loopback
//! peer (Web Push, APNs, FCM, HMS, OAuth) and a fake object store; the Rust
//! worker's tick must leave the same rows, make the same outbound requests
//! (including decrypted Web Push bodies) and store the same digest mail.
//! Nothing is ever sent to a real provider or store.
//!
//! Record: `GOFREE_RECORD_DRAIN=all|case,case` (+ `GOFREE_GO_SOURCE`); delete a
//! golden to re-record it. Replay needs no Go (it needs python3 and openssl for
//! the peer, as the mailctl push oracle does).
mod common;
mod drain_oracle;
#[path = "drain_oracle/peers.rs"]
mod peers;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use drain_oracle::{repo_root, settle, BoxError, GoTick};
use peers::{FakeS3, PushPeer};
use serde_json::{json, Map, Value};
use setjoin_conformance::harness::Db;
use setjoin_gateway::push_drain::{GuestDigest, PushIntentDrain};
use setjoin_pg::workers::WorkerDatabase;
use std::{collections::BTreeMap, sync::Arc};
use tokio_postgres::{Client, SimpleQueryMessage};

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
const KEY: &str = "gofree-drain-encryption-key";
const HMAC: &str = "gofree-drain-audit-hmac-key";
const NAMES: [&str; 16] = [
    "a", "b", "c", "d", "e", "f", "g", "s", "h", "i", "j", "k", "l", "m", "n", "o",
];

struct Case {
    name: &'static str,
    seed: &'static [&'static str],
    /// Read-only observations as `(label, sql)`; each row is one text column.
    observe: &'static [(&'static str, &'static str)],
}

const MAIL_OBSERVE: &[(&str, &str)] = &[
    ("intents", "SELECT coalesce(m.subject,'<gone>')||':'||i.status||':'||i.attempts||':'||coalesce(i.last_error,'')||':'||(i.next_attempt_at>now()+interval '60 seconds') FROM push_intents i LEFT JOIN messages m ON m.id=i.message_id AND m.mailbox_id=i.mailbox_id WHERE i.mailbox_id IN ({ALLM}) ORDER BY 1"),
    ("devices", "SELECT u.username||':'||d.push_provider||':'||coalesce(push_decrypt_token(d.push_token_enc),'<undecryptable>')||':'||(d.revoked_at IS NOT NULL) FROM push_devices d JOIN users u ON u.id=d.user_id WHERE d.user_id IN ({ALLU}) ORDER BY 1"),
];
const CHAT_OBSERVE: &[(&str, &str)] = &[
    ("chat_intents", "SELECT m.body||':'||i.status||':'||i.attempts||':'||coalesce(i.last_error,'') FROM chat_push_intents i JOIN chat_messages m ON m.id=i.message_id WHERE i.channel_id IN (9100001,9100002,9100003) ORDER BY m.id"),
    ("devices", "SELECT u.username||':'||d.push_provider||':'||coalesce(push_decrypt_token(d.push_token_enc),'<undecryptable>')||':'||(d.revoked_at IS NOT NULL) FROM push_devices d JOIN users u ON u.id=d.user_id WHERE d.user_id IN ({ALLU}) ORDER BY 1"),
];
const DIGEST_OBSERVE: &[(&str, &str)] = &[
    ("guest_intents", "SELECT u.username||':'||g.kind||':'||g.ref||':'||(g.sent_at IS NOT NULL) FROM guest_notification_intents g JOIN users u ON u.id=g.user_id WHERE g.user_id IN ({ALLU}) ORDER BY g.id"),
    ("outbound", "SELECT rcpt_addrs::text||':'||status||':'||regexp_replace(message_id,'[0-9]+','N')||':'||regexp_replace(raw_ref,'[0-9a-f]{64}','H')||':'||from_addr FROM outbound_queue WHERE from_addr='noreply@gofree-drain.test' ORDER BY rcpt_addrs::text"),
];

const CASES: &[Case] = &[
    Case {
        name: "push-mail-matrix",
        seed: &[
            // user a: every provider, plus a revoked, an empty and an undecryptable device.
            "INSERT INTO push_devices(user_id,push_provider,push_token_enc) VALUES ({a.u},'apns',pgp_sym_encrypt('ok-apns-a','{KEY}')::bytea),({a.u},'fcm',pgp_sym_encrypt('ok-fcm-a','{KEY}')::bytea),({a.u},'hms',pgp_sym_encrypt('ok-hms-a','{KEY}')::bytea),({a.u},'webpush',pgp_sym_encrypt('{WP:ok-web-a}','{KEY}')::bytea),({a.u},'apns',pgp_sym_encrypt('ok-revoked','{KEY}')::bytea),({a.u},'fcm',pgp_sym_encrypt('','{KEY}')::bytea),({a.u},'fcm',pgp_sym_encrypt('ok-undecryptable','other-key')::bytea)",
            "UPDATE push_devices SET revoked_at=now() WHERE user_id={a.u} AND push_provider='apns' AND pgp_sym_decrypt(push_token_enc,'{KEY}')='ok-revoked'",
            "INSERT INTO user_notification_prefs(user_id,push_enabled) VALUES ({b.u},false)",
            "INSERT INTO push_devices(user_id,push_provider,push_token_enc) VALUES ({b.u},'fcm',pgp_sym_encrypt('ok-fcm-b','{KEY}')::bytea)",
            "INSERT INTO messages(mailbox_id,folder_id,message_id,from_addr,from_name,thread_id,raw_ref,size_bytes,subject,received_at) VALUES ({a.m},1,'<m1@gofree-drain.test>','sender@x.test','Zoë <Ünï> & \"Co\"','t1','r1',1,'Hello <b>x</b> & more','2026-10-25 10:00:00.123456+00'),({b.m},1,'<m2@gofree-drain.test>','sender@x.test','B','t2','r2',1,'prefs-off','2026-10-25 10:00:00+00'),({c.m},1,'<m3@gofree-drain.test>','sender@x.test','C','t3','r3',1,'no-devices','2026-10-25 10:00:00+00')",
            "INSERT INTO push_intents(mailbox_id,message_id,received_at,next_attempt_at) SELECT mailbox_id,id,received_at,now()-interval '3 minutes' FROM messages WHERE mailbox_id IN ({a.m},{b.m},{c.m})",
            "INSERT INTO push_intents(mailbox_id,message_id,received_at,next_attempt_at) VALUES ({a.m},999999999,'2026-10-25 10:00:00+00',now()-interval '2 minutes')",
            // not yet due: untouched
            "INSERT INTO messages(mailbox_id,folder_id,message_id,from_addr,from_name,thread_id,raw_ref,size_bytes,subject,received_at) VALUES ({c.m},1,'<m4@gofree-drain.test>','sender@x.test','C','t4','r4',1,'not-due','2026-10-25 10:00:00+00')",
            "INSERT INTO push_intents(mailbox_id,message_id,received_at,next_attempt_at) SELECT mailbox_id,id,received_at,now()+interval '1 hour' FROM messages WHERE mailbox_id={c.m} AND subject='not-due'",
        ],
        observe: MAIL_OBSERVE,
    },
    Case {
        name: "push-mail-failures",
        seed: &[
            "INSERT INTO push_devices(user_id,push_provider,push_token_enc) VALUES ({d.u},'fcm',pgp_sym_encrypt('fail-fcm-d','{KEY}')::bytea),({e.u},'apns',pgp_sym_encrypt('gone-apns-e','{KEY}')::bytea),({e.u},'webpush',pgp_sym_encrypt('{WP:gone-web-e}','{KEY}')::bytea),({f.u},'hms',pgp_sym_encrypt('fail-hms-f','{KEY}')::bytea),({g.u},'fcm',pgp_sym_encrypt('ok-fcm-g','{KEY}')::bytea),({g.u},'apns',pgp_sym_encrypt('gone-apns-g','{KEY}')::bytea),({g.u},'hms',pgp_sym_encrypt('fail-hms-g','{KEY}')::bytea)",
            "INSERT INTO messages(mailbox_id,folder_id,message_id,from_addr,from_name,thread_id,raw_ref,size_bytes,subject,received_at) VALUES ({d.m},1,'<d@gofree-drain.test>','s@x.test','S','td','rd',1,'retry-once','2026-10-25 10:00:00+00'),({e.m},1,'<e@gofree-drain.test>','s@x.test','S','te','re',1,'all-pruned','2026-10-25 10:00:00+00'),({f.m},1,'<f@gofree-drain.test>','s@x.test','S','tf','rf',1,'exhausted','2026-10-25 10:00:00+00'),({g.m},1,'<g@gofree-drain.test>','s@x.test','S','tg','rg',1,'success-prune-fail','2026-10-25 10:00:00+00')",
            "INSERT INTO push_intents(mailbox_id,message_id,received_at,next_attempt_at,attempts) SELECT mailbox_id,id,received_at,now()-interval '3 minutes',CASE WHEN subject='exhausted' THEN 4 ELSE 0 END FROM messages WHERE mailbox_id IN ({d.m},{e.m},{f.m},{g.m})",
        ],
        observe: MAIL_OBSERVE,
    },
    Case {
        name: "push-chat-fanout",
        seed: &[
            "INSERT INTO chat_channels(id,kind,name,created_by) OVERRIDING SYSTEM VALUE VALUES (9100001,'channel','general',{s.u}),(9100002,'dm',NULL,{s.u}),(9100003,'group_dm',NULL,{s.u})",
            "INSERT INTO chat_channel_members(channel_id,user_id) VALUES (9100001,{s.u}),(9100001,{a.u}),(9100001,{d.u}),(9100001,{e.u}),(9100002,{s.u}),(9100002,{a.u}),(9100003,{s.u}),(9100003,{a.u}),(9100003,{c.u}),(9100003,{d.u})",
            "INSERT INTO chat_messages(id,channel_id,seq,author_id,body,broadcast) OVERRIDING SYSTEM VALUE VALUES (9200001,9100001,1,{s.u},'plain-older',NULL),(9200002,9100001,2,{s.u},'mention-a',NULL),(9200003,9100001,3,{s.u},'plain-newest',NULL),(9200004,9100002,1,{s.u},'dm-1',NULL),(9200005,9100003,1,{s.u},'groupdm-1',NULL),(9200006,9100001,4,{s.u},'broadcast-here','channel'),(9200007,9100001,5,{s.u},'gone-message',NULL)",
            "INSERT INTO chat_mentions(message_id,mentioned_user_id) VALUES (9200002,{a.u})",
            "UPDATE chat_messages SET deleted_at=now() WHERE id=9200007",
            "INSERT INTO push_devices(user_id,push_provider,push_token_enc) VALUES ({a.u},'apns',pgp_sym_encrypt('ok-apns-a','{KEY}')::bytea),({a.u},'webpush',pgp_sym_encrypt('{WP:ok-web-a}','{KEY}')::bytea),({c.u},'hms',pgp_sym_encrypt('ok-hms-c','{KEY}')::bytea),({d.u},'fcm',pgp_sym_encrypt('fail-fcm-d','{KEY}')::bytea),({e.u},'apns',pgp_sym_encrypt('gone-apns-e','{KEY}')::bytea)",
            "INSERT INTO chat_push_intents(channel_id,message_id,sender_user_id,next_attempt_at) VALUES (9100001,9200001,{s.u},now()-interval '9 minutes'),(9100001,9200002,{s.u},now()-interval '8 minutes'),(9100001,9200003,{s.u},now()-interval '7 minutes'),(9100002,9200004,{s.u},now()-interval '6 minutes'),(9100003,9200005,{s.u},now()-interval '5 minutes'),(9100001,9200006,{s.u},now()-interval '4 minutes'),(9100001,9200007,{s.u},now()-interval '3 minutes')",
        ],
        observe: CHAT_OBSERVE,
    },
    Case {
        name: "push-guest-digest",
        seed: &[
            "INSERT INTO system_config(key,value) VALUES ('org.name',to_jsonb('Gofree <Org> & Co'::text)) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            "INSERT INTO chat_channels(id,kind,name,created_by) OVERRIDING SYSTEM VALUE VALUES (9100001,'channel','general',{s.u}),(9100002,'dm',NULL,{s.u})",
            "INSERT INTO chat_channel_members(channel_id,user_id) VALUES (9100001,{s.u}),(9100001,{h.u}),(9100001,{i.u}),(9100002,{s.u}),(9100002,{h.u})",
            "INSERT INTO chat_messages(id,channel_id,seq,author_id,body) OVERRIDING SYSTEM VALUE VALUES (9200001,9100001,1,{s.u},'Hi guest, a long message with \"quotes\", tab\tand a very long tail so that the excerpt reaches one hundred characters in total, past the end'),(9200002,9100002,1,{s.u},'Direct hello Zoë'),(9200003,9100001,2,{s.u},'deleted one')",
            "UPDATE chat_messages SET deleted_at=now() WHERE id=9200003",
            "INSERT INTO chat_mentions(message_id,mentioned_user_id) VALUES (9200001,{h.u}),(9200003,{h.u})",
            "INSERT INTO meetings(id,title,owner_user_id,scheduled_start,chat_channel_id) OVERRIDING SYSTEM VALUE VALUES (9300001,'Standup <daily>',{s.u},'2026-11-03 09:30:00+00',9100001),(9300002,'Unscheduled',{s.u},NULL,9100001)",
            "INSERT INTO guest_accounts(user_id,invited_email,invited_by_email,host_domain_id,status) VALUES ({h.u},'gofree-guest-h@guest.test','host@x.test',{DOM},'active'),({i.u},'gofree-guest-i@guest.test','host@x.test',{DOM},'active'),({j.u},'gofree-guest-j@guest.test','host@x.test',{DOM},'active'),({k.u},'gofree-guest-k@guest.test','host@x.test',{DOM},'expired'),({l.u},'gofree-guest-l@guest.test','host@x.test',{DOM},'active'),({m.u},'gofree-guest-m@guest.test','host@x.test',{DOM},'active'),({n.u},'gofree-guest-n@guest.test','host@x.test',{DOM},'active')",
            "UPDATE users SET enabled=false WHERE id={j.u}",
            "INSERT INTO sessions(user_id,expires_at,last_seen_at) VALUES ({l.u},now()+interval '1 day',now()-interval '10 minutes')",
            "INSERT INTO guest_notification_intents(user_id,kind,ref,created_at,sent_at) VALUES ({m.u},'dm','9100002:9200002',now()-interval '30 minutes',now()-interval '5 minutes')",
            "INSERT INTO guest_notification_intents(user_id,kind,ref,created_at) VALUES ({h.u},'mention','9100001:9200001',now()-interval '60 minutes'),({h.u},'dm','9100002:9200002',now()-interval '59 minutes'),({h.u},'mention','9100001:9200003',now()-interval '58 minutes'),({h.u},'meeting_invite','9300001',now()-interval '57 minutes'),({h.u},'meeting_invite','9300002',now()-interval '56 minutes'),({h.u},'meeting_invite','0',now()-interval '55 minutes'),({h.u},'dm','garbage',now()-interval '54 minutes'),({i.u},'meeting_invite','9300001',now()-interval '50 minutes'),({j.u},'dm','9100002:9200002',now()-interval '40 minutes'),({k.u},'dm','9100002:9200002',now()-interval '40 minutes'),({l.u},'dm','9100002:9200002',now()-interval '40 minutes'),({m.u},'dm','9100002:9200002',now()-interval '40 minutes'),({n.u},'dm','9100002:9200099',now()-interval '40 minutes'),({o.u},'dm','9100002:9200002',now()-interval '40 minutes')",
        ],
        observe: DIGEST_OBSERVE,
    },
    Case {
        // The object store refuses the write: nothing is queued or stamped and
        // the batch stays pending for a later tick (Go: "send failed").
        name: "push-guest-digest-store-fails",
        seed: &[
            "INSERT INTO chat_channels(id,kind,name,created_by) OVERRIDING SYSTEM VALUE VALUES (9100002,'dm',NULL,{s.u})",
            "INSERT INTO chat_channel_members(channel_id,user_id) VALUES (9100002,{s.u}),(9100002,{h.u})",
            "INSERT INTO chat_messages(id,channel_id,seq,author_id,body) OVERRIDING SYSTEM VALUE VALUES (9200002,9100002,1,{s.u},'Direct hello')",
            "INSERT INTO guest_accounts(user_id,invited_email,invited_by_email,host_domain_id,status) VALUES ({h.u},'gofree-guest-h@guest.test','host@x.test',{DOM},'active')",
            "INSERT INTO guest_notification_intents(user_id,kind,ref,created_at) VALUES ({h.u},'dm','9100002:9200002',now()-interval '60 minutes')",
        ],
        observe: DIGEST_OBSERVE,
    },
    Case {
        name: "push-reaps",
        seed: &[
            "INSERT INTO chat_channels(id,kind,name,created_by) OVERRIDING SYSTEM VALUE VALUES (9100001,'channel','general',{s.u})",
            "INSERT INTO chat_messages(id,channel_id,seq,author_id,body) OVERRIDING SYSTEM VALUE VALUES (9200001,9100001,1,{s.u},'old-done'),(9200002,9100001,2,{s.u},'old-failed'),(9200003,9100001,3,{s.u},'old-pending'),(9200004,9100001,4,{s.u},'new-done')",
            "INSERT INTO chat_push_intents(channel_id,message_id,sender_user_id,status,created_at,next_attempt_at) VALUES (9100001,9200001,{s.u},'done',now()-interval '8 days',now()+interval '1 day'),(9100001,9200002,{s.u},'failed',now()-interval '8 days',now()+interval '1 day'),(9100001,9200003,{s.u},'pending',now()-interval '8 days',now()+interval '1 day'),(9100001,9200004,{s.u},'done',now()-interval '1 day',now()+interval '1 day')",
            "INSERT INTO guest_accounts(user_id,invited_email,invited_by_email,host_domain_id,status) VALUES ({h.u},'gofree-guest-h@guest.test','host@x.test',{DOM},'active')",
            "INSERT INTO guest_notification_intents(user_id,kind,ref,created_at,sent_at) VALUES ({h.u},'dm','1:1',now()-interval '9 days',now()-interval '8 days'),({h.u},'dm','2:2',now()-interval '1 day',now()-interval '1 hour')",
            "INSERT INTO guest_notification_intents(user_id,kind,ref,created_at) VALUES ({i.u},'dm','3:3',now()-interval '9 days'),({i.u},'dm','4:4',now()-interval '1 day')",
        ],
        observe: &[
            ("chat_intents", "SELECT m.body||':'||i.status FROM chat_push_intents i JOIN chat_messages m ON m.id=i.message_id WHERE i.channel_id=9100001 ORDER BY m.id"),
            ("guest_intents", "SELECT u.username||':'||g.ref||':'||(g.sent_at IS NOT NULL) FROM guest_notification_intents g JOIN users u ON u.id=g.user_id WHERE g.user_id IN ({ALLU}) ORDER BY g.ref"),
        ],
    },
];

struct Fixture {
    ids: BTreeMap<&'static str, (i64, i64)>,
    domain: i64,
    peer_url: String,
}

impl Fixture {
    fn render(&self, sql: &str) -> String {
        let mut out = sql
            .replace("{KEY}", KEY)
            .replace("{DOM}", &self.domain.to_string());
        for (name, (user, mailbox)) in &self.ids {
            out = out
                .replace(&format!("{{{name}.u}}"), &user.to_string())
                .replace(&format!("{{{name}.m}}"), &mailbox.to_string());
        }
        let all = |pick: fn(&(i64, i64)) -> i64| {
            self.ids
                .values()
                .map(|v| pick(v).to_string())
                .collect::<Vec<_>>()
                .join(",")
        };
        out = out
            .replace("{ALLU}", &all(|v| v.0))
            .replace("{ALLM}", &all(|v| v.1));
        while let Some(start) = out.find("{WP:") {
            let end = start + out[start..].find('}').expect("WP placeholder");
            let token = out[start + 4..end].to_owned();
            out.replace_range(start..=end, &self.webpush(&token));
        }
        out
    }

    /// A Web Push subscription whose endpoint is the owned peer.
    fn webpush(&self, token: &str) -> String {
        let public = std::fs::read(
            repo_root()
                .unwrap()
                .join("server-rust/bins/mailctl/tests/fixtures/push-web-public.der"),
        )
        .unwrap();
        let public = &public[public.len() - 65..];
        json!({
            "endpoint": format!("{}/webpush/capability?d={token}", self.peer_url),
            "keys": {"p256dh": URL_SAFE_NO_PAD.encode(public), "auth": URL_SAFE_NO_PAD.encode([1u8; 16])},
        })
        .to_string()
    }
}

// Multi-threaded: the blocking Go container run must not stall the fake S3.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_drain_seed_plus_one_tick() -> Result<(), BoxError> {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(db) = Db::for_case("push-drain-tick") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let record = std::env::var("GOFREE_RECORD_DRAIN").ok();
    let only = std::env::var("GOFREE_DRAIN_ONLY").ok();
    let listed = |filter: &Option<String>, name: &str| {
        filter
            .as_deref()
            .is_none_or(|f| f == "all" || f.split(',').any(|t| t == name))
    };
    let selected: Vec<&Case> = CASES
        .iter()
        .filter(|c| {
            let recording = record.is_some() && listed(&record, c.name);
            !(record.is_some() && !recording || !listed(&only, c.name))
        })
        .collect();
    assert!(!selected.is_empty(), "no case selected");

    let peer = PushPeer::start()?;
    let s3 = FakeS3::start().await;
    let fixture = fixture(&owner, peer.url()).await?;
    let config = provider_config(&peer, &s3)?;
    let mut failures = Vec::new();
    for case in selected {
        let recording = record.is_some() && listed(&record, case.name);
        let result = run_case(&db, &owner, &fixture, &peer, &s3, &config, case, recording).await;
        reset(&owner, &fixture).await;
        if let Err(error) = result {
            failures.push(format!("{}: {error}", case.name));
        }
    }
    let ids = fixture.render("{ALLM}");
    let users = fixture.render("{ALLU}");
    let _ = owner
        .batch_execute(&format!(
            "DELETE FROM mailboxes WHERE id IN ({ids}); DELETE FROM users WHERE id IN ({users}); DELETE FROM domains WHERE id={}",
            fixture.domain
        ))
        .await;
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}

async fn fixture(owner: &Client, peer_url: String) -> Result<Fixture, BoxError> {
    owner.batch_execute("DELETE FROM mailboxes WHERE email LIKE '%@gofree-drain.test'; DELETE FROM users WHERE username LIKE 'gofree-drain-%'; DELETE FROM domains WHERE name='gofree-drain.test'").await?;
    let domain: i64 = owner
        .query_one(
            "INSERT INTO domains(name) VALUES ('gofree-drain.test') RETURNING id",
            &[],
        )
        .await?
        .get(0);
    let mut ids = BTreeMap::new();
    for name in NAMES {
        let username = format!("gofree-drain-{name}");
        let email = format!("{username}@gofree-drain.test");
        let user: i64 = owner
            .query_one(
                "INSERT INTO users(username,domain_id,email,display_name) VALUES ($1,$2,$3,$4) RETURNING id",
                &[&username, &domain, &email, &format!("User {} Name", name.to_uppercase())],
            )
            .await?
            .get(0);
        let mailbox: i64 = owner
            .query_one(
                "INSERT INTO mailboxes(user_id,domain_id,email,display_name,is_primary) VALUES ($1,$2,$3,$4,true) RETURNING id",
                &[&user, &domain, &email, &format!("User {}", name.to_uppercase())],
            )
            .await?
            .get(0);
        ids.insert(name, (user, mailbox));
    }
    let fixture = Fixture {
        ids,
        domain,
        peer_url,
    };
    owner
        .query_typed(
            "SELECT set_config('app.encryption_key',$1,false)",
            &[(&KEY, tokio_postgres::types::Type::TEXT)],
        )
        .await?;
    reset(owner, &fixture).await;
    Ok(fixture)
}

/// Remove everything a case seeds, leaving the fixture users in place.
async fn reset(owner: &Client, fixture: &Fixture) {
    for sql in [
        "DELETE FROM push_intents WHERE mailbox_id IN ({ALLM})",
        "DELETE FROM chat_push_intents WHERE channel_id IN (9100001,9100002,9100003)",
        "DELETE FROM push_devices WHERE user_id IN ({ALLU})",
        "DELETE FROM user_notification_prefs WHERE user_id IN ({ALLU})",
        "DELETE FROM messages WHERE mailbox_id IN ({ALLM})",
        "DELETE FROM guest_notification_intents WHERE user_id IN ({ALLU})",
        "DELETE FROM guest_accounts WHERE user_id IN ({ALLU})",
        "DELETE FROM sessions WHERE user_id IN ({ALLU})",
        "DELETE FROM chat_mentions WHERE message_id BETWEEN 9200001 AND 9200009",
        "DELETE FROM chat_messages WHERE id BETWEEN 9200001 AND 9200009",
        "DELETE FROM chat_channel_members WHERE channel_id IN (9100001,9100002,9100003)",
        "DELETE FROM meetings WHERE id IN (9300001,9300002)",
        "DELETE FROM chat_channels WHERE id IN (9100001,9100002,9100003)",
        "DELETE FROM outbound_queue WHERE from_addr='noreply@gofree-drain.test'",
        "DELETE FROM system_config WHERE key='org.name'",
        "UPDATE users SET enabled=true WHERE id IN ({ALLU})",
    ] {
        let _ = owner.batch_execute(&fixture.render(sql)).await;
    }
}

/// Provider and transport configuration shared by Go (container paths) and
/// Rust (host paths): every provider points at the owned peer.
struct ProviderConfig {
    /// `(name, host value, container value)`
    env: Vec<(String, String, String)>,
    s3_endpoint: String,
}

fn provider_config(peer: &PushPeer, s3: &FakeS3) -> Result<ProviderConfig, BoxError> {
    let root = repo_root()?;
    let fixtures = root.join("server-rust/bins/mailctl/tests/fixtures");
    let folder = root.join("test-results/gofree-drainw");
    let sa = folder.join(format!("sa-{}.json", std::process::id()));
    std::fs::write(
        &sa,
        json!({
            "type": "service_account", "project_id": "fixture-project",
            "client_email": "synthetic@fixture.invalid", "private_key_id": "fixture-key",
            "private_key": std::fs::read_to_string(fixtures.join("smime-key.pem"))?,
            "token_uri": format!("{}/oauth/fcm", peer.url()),
        })
        .to_string(),
    )?;
    let vapid: Value =
        serde_json::from_str(&std::fs::read_to_string(fixtures.join("push-vapid.json"))?)?;
    let proxy = peer.url();
    let host = |p: &std::path::Path| p.display().to_string();
    let container =
        |p: &std::path::Path| format!("/src/{}", p.strip_prefix(&root).unwrap().display());
    let mut env = Vec::new();
    let mut both = |k: &str, v: String| env.push((k.to_owned(), v.clone(), v));
    both(
        "VAPID_PRIVATE_KEY",
        vapid["private"].as_str().unwrap().into(),
    );
    both("APNS_CERT_PASSWORD", "synthetic".into());
    both("APNS_BUNDLE_ID", "test.fixture.app".into());
    both("HMS_APP_ID", "fixture-app".into());
    both("HMS_APP_SECRET", "synthetic-secret".into());
    both("DB_ENCRYPTION_KEY", KEY.into());
    both("MAILCTL_ORACLE_WEBPUSH_LOOPBACK", "1".into());
    both(
        "MAILCTL_ORACLE_APNS_ADDR",
        format!("127.0.0.1:{}", peer.port),
    );
    for name in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
        both(name, proxy.clone());
    }
    for name in ["NO_PROXY", "no_proxy"] {
        both(name, "127.0.0.1,localhost".into());
    }
    let p12 = fixtures.join("push-apns.p12");
    let ca = fixtures.join("push-ca.pem");
    env.push(("APNS_CERT_PATH".into(), host(&p12), container(&p12)));
    env.push(("FCM_SERVICE_ACCOUNT_FILE".into(), host(&sa), container(&sa)));
    env.push(("SSL_CERT_FILE".into(), host(&ca), container(&ca)));
    Ok(ProviderConfig {
        env,
        s3_endpoint: format!("127.0.0.1:{}", s3.addr.port()),
    })
}

#[allow(clippy::too_many_arguments)]
async fn run_case(
    db: &Db,
    owner: &Client,
    fixture: &Fixture,
    peer: &PushPeer,
    s3: &FakeS3,
    config: &ProviderConfig,
    case: &Case,
    recording: bool,
) -> Result<(), BoxError> {
    reset(owner, fixture).await;
    for sql in case.seed {
        owner
            .batch_execute(&fixture.render(sql))
            .await
            .map_err(|e| format!("seed `{sql}`: {}", db_text(&e)))?;
    }
    peer.take()?;
    s3.take();
    s3.reject_puts(case.name.contains("store-fails"));
    if recording {
        let mut env: Vec<(String, String)> = config
            .env
            .iter()
            .map(|(k, _, c)| (k.clone(), c.clone()))
            .collect();
        env.push(("GOFREE_DRAIN_DSN".into(), db.dsn.clone()));
        env.push(("GOFREE_DRAIN_S3".into(), config.s3_endpoint.clone()));
        GoTick {
            package: "internal/pushjobs",
            overlay: "push_tick_test.go.txt",
            test: "TestGoFreePushDrainTick",
            file: "gofree_push_tick_test.go",
            env,
            docker: vec![],
        }
        .run()?;
    } else {
        for (name, value, _) in &config.env {
            std::env::set_var(name, value);
        }
        std::env::set_var("S3_ENDPOINT", &config.s3_endpoint);
        std::env::set_var("S3_BUCKET", "mailblobs");
        std::env::set_var("S3_ACCESS_KEY", "test-access");
        std::env::set_var("S3_SECRET_KEY", "test-secret");
        let (providers, _) = setjoin_push::build();
        let store = setjoin_gateway::recovery_worker::S3Store::from_env()?;
        let worker = PushIntentDrain::new(
            WorkerDatabase::new(&db.dsn)?.with_audit_keys(KEY.into(), HMAC.into()),
            providers,
            Some(GuestDigest {
                store: Arc::new(store),
                from_addr: "noreply@gofree-drain.test".into(),
                from_name: "SetJoin".into(),
                webmail_url: "https://gofree-drain.test".into(),
            }),
        );
        worker.tick().await;
    }
    let mut rows = Map::new();
    for (label, sql) in case.observe {
        let observed = text_rows(owner, &fixture.render(sql)).await?;
        let masked: Vec<String> = observed
            .into_iter()
            .map(|row| row.replace(&fixture.peer_url, "{PEER}"))
            .collect();
        rows.insert((*label).into(), json!(masked));
    }
    let requests = peer.take()?;
    let puts: Vec<Value> = s3.take().into_iter().map(mask_put).collect();
    let observation = json!({"rows": rows, "requests": requests, "object_puts": puts});
    if recording && requests.is_empty() && puts.is_empty() && case.name != "push-reaps" {
        return Err(format!("Go's tick made no outbound effect: {observation}").into());
    }
    settle(case.name, observation, recording)
}

/// The key and the Message-ID/Date headers carry a hash, a clock and a nanosecond counter.
fn mask_put(put: Value) -> Value {
    let path = put["path"].as_str().unwrap_or("");
    let masked_path = match path.rsplit_once('/') {
        Some((dir, file)) if file.ends_with(".eml") && file.len() == 68 => {
            format!("{dir}/{{HASH}}.eml")
        }
        _ => path.to_owned(),
    };
    let body = put["body"]
        .as_str()
        .unwrap_or("")
        .split("\r\n")
        .map(|line| {
            if line.starts_with("Message-ID: <digest/") {
                let host = line.rsplit_once('@').map(|(_, h)| h).unwrap_or("");
                format!("Message-ID: <digest/{{N}}@{host}")
            } else if line.starts_with("Date: ") {
                "Date: {DATE}".to_owned()
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\r\n");
    json!({"path": masked_path, "content_type": put["content_type"], "body": body})
}

async fn text_rows(owner: &Client, sql: &str) -> Result<Vec<String>, BoxError> {
    let mut out = Vec::new();
    for message in owner
        .simple_query(sql)
        .await
        .map_err(|e| format!("`{sql}`: {}", db_text(&e)))?
    {
        if let SimpleQueryMessage::Row(row) = message {
            out.push(row.get(0).unwrap_or("<null>").to_string());
        }
    }
    Ok(out)
}

fn db_text(error: &tokio_postgres::Error) -> String {
    error.as_db_error().map_or_else(
        || error.to_string(),
        |d| format!("{} ({})", d.message(), d.code().code()),
    )
}
