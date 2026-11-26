//! #411 / Wave 2.4 (#551): seed-plus-tick verification for the `blob-cleanup`
//! worker after cutover from retired `blob_cleanup_queue`/`blobs.ref_count` to
//! Mark-and-Sweep GC (`V288`/`V289`).
//!
//! - Immutable frozen-Go goldens (`blob-orphans`, `blob-idle`) are replayed in
//!   memory without modifying any golden JSON file (filtering out Mark-and-Sweep
//!   read-only list probes such as `GET ?versions` / `tmp/blob-upload/`).
//! - Wave 2.4 Mark-and-Sweep reclamation, grace/cooldown fencing, flaky S3
//!   retries, and bare-64-hex orphan protection are verified directly via
//!   `BlobCleanup::tick()`.
mod common;
mod drain_oracle;
#[path = "drive_workers_oracle/fake_s3.rs"]
#[allow(dead_code)]
mod fake_s3;
use drain_oracle::BoxError;
use fake_s3::DriveS3;
use serde_json::{json, Value};
use setjoin_conformance::harness::Db;
use setjoin_gateway::{blob_cleanup::BlobCleanup, recovery_worker::S3Store};
use setjoin_pg::workers::WorkerDatabase;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc};
use tokio_postgres::Client;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const HOUR: i64 = 3600;

fn sha(label: &str) -> String {
    format!("{:x}", Sha256::digest(label.as_bytes()))
}

struct Fixture {
    user: i64,
    domain: i64,
    mailbox: i64,
}

fn render(fixture: &Fixture, text: &str, labels: &mut BTreeMap<String, String>) -> String {
    let mut out = text.replace("{mb}", &fixture.mailbox.to_string());
    while let Some(start) = out.find("{sha:") {
        let end = start + out[start..].find('}').expect("sha placeholder");
        let label = out[start + 5..end].to_owned();
        let hash = sha(&label);
        labels.insert(hash.clone(), format!("<{label}>"));
        out.replace_range(start..=end, &hash);
    }
    out
}

fn db_text(e: tokio_postgres::Error) -> String {
    e.as_db_error()
        .map(|d| d.to_string())
        .unwrap_or_else(|| e.to_string())
}

const CLEAN: &str = "DELETE FROM orphaned_message_blobs;
    DELETE FROM work_items WHERE kind IN ('blob.s3_reap_retry','blob.promote_recover','blob.promote_verify');
    DELETE FROM work_dead_letters WHERE kind IN ('blob.s3_reap_retry','blob.promote_recover','blob.promote_verify');
    DELETE FROM messages WHERE message_id LIKE 'gofree-blobs2-%';
    DELETE FROM blobs WHERE NOT public.blob_has_live_reference(sha256) OR minio_ref LIKE 'gofree-b2/%';";

async fn fixture(owner: &Client) -> Result<Fixture, BoxError> {
    owner.batch_execute(CLEAN).await.map_err(db_text)?;
    owner.batch_execute("DELETE FROM mailboxes WHERE email='gofree-blobs2-a@gofree-blobs2.test'; DELETE FROM users WHERE username='gofree-blobs2-a'; DELETE FROM domains WHERE name='gofree-blobs2.test'").await?;
    let domain: i64 = owner
        .query_one(
            "INSERT INTO domains(name) VALUES ('gofree-blobs2.test') RETURNING id",
            &[],
        )
        .await?
        .get(0);
    let user: i64 = owner.query_one("INSERT INTO users(username,domain_id,email,display_name) VALUES ('gofree-blobs2-a',$1,'gofree-blobs2-a@gofree-blobs2.test','A') RETURNING id", &[&domain]).await?.get(0);
    let mailbox: i64 = owner.query_one("INSERT INTO mailboxes(user_id,domain_id,email,display_name,is_primary) VALUES ($1,$2,'gofree-blobs2-a@gofree-blobs2.test','A',true) RETURNING id", &[&user, &domain]).await?.get(0);
    Ok(Fixture {
        user,
        domain,
        mailbox,
    })
}

async fn reset(owner: &Client) -> Result<(), BoxError> {
    owner.batch_execute(CLEAN).await.map_err(db_text)?;
    Ok(())
}

async fn teardown(owner: &Client, fixture: &Fixture) {
    let _ = reset(owner).await;
    let _ = owner
        .batch_execute(&format!(
            "DELETE FROM mailboxes WHERE id={}; DELETE FROM users WHERE id={}; DELETE FROM domains WHERE id={}",
            fixture.mailbox, fixture.user, fixture.domain
        ))
        .await;
}

async fn column(owner: &Client, sql: &str) -> Result<Vec<String>, BoxError> {
    Ok(owner
        .query(sql, &[])
        .await?
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect())
}

/// Normalize digest placeholders and compare only mutating S3 DELETE calls
/// against the immutable frozen-Go orphan/idle goldens (filtering out the
/// read-only Wave 2.4 version-list and staging-sweep GET probes).
fn normalize_for_golden(value: Value, labels: &BTreeMap<String, String>) -> Value {
    let mut text = value.to_string();
    for (hash, label) in labels {
        text = text.replace(hash, label);
    }
    let mut value: Value = serde_json::from_str(&text).unwrap();
    if let Some(requests) = value["s3"]["requests"].as_array_mut() {
        requests.retain(|r| {
            r["method"] == "DELETE"
                && !r["path"]
                    .as_str()
                    .is_some_and(|p| p.starts_with("/mailblobs/tmp/blob-upload/"))
        });
        requests.sort_by_key(|r| r.to_string());
    }
    value
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blob_cleanup_seed_plus_one_tick() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("blob-cleanup-tick") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let s3 = DriveS3::start().await;
    let fx = fixture(&owner).await?;
    let store = Arc::new(S3Store::new(
        &format!("http://127.0.0.1:{}", s3.addr.port()),
        "mailblobs",
        "test-access",
        "test-secret",
    )?);
    let worker = BlobCleanup::new(WorkerDatabase::new(&db.dsn)?, store);

    let result: Result<(), BoxError> = async {
        // 1. Replay immutable frozen-Go `blob-idle` golden.
        reset(&owner).await?;
        s3.reset();
        worker.tick().await;
        let idle_obs = json!({
            "blobs": column(&owner, "SELECT sha256||'|'||minio_ref FROM blobs WHERE minio_ref LIKE 'gofree-b2/%' ORDER BY 1").await?,
            "queue": Vec::<String>::new(),
            "orphans": column(&owner, "SELECT raw_ref FROM orphaned_message_blobs ORDER BY 1").await?,
            "s3": {"requests": s3.take_log(), "keys": s3.keys()},
        });
        drain_oracle::settle("blob-idle", normalize_for_golden(idle_obs, &BTreeMap::new()), false)?;

        // 2. Replay immutable frozen-Go `blob-orphans` golden (prefixed + legacy bare 64-hex
        //    not in `blobs` + inline text + referenced protection + refused/flaky retry).
        reset(&owner).await?;
        s3.reset();
        let mut labels = BTreeMap::new();
        for key in [
            "inbound/{sha:in}",
            "blobs/{sha:out}",
            "{sha:bare}",
            "dmarc/{sha:report}.eml",
            "system:welcome:42",
            "dsn/7/8",
            "weird key+plus/é",
            "inbound/{sha:refused}",
            "{sha:flaky}",
            "inbound/{sha:referenced}",
            "inbound/{sha:no-object}",
        ] {
            let rendered = render(&fx, key, &mut labels);
            owner
                .execute("INSERT INTO orphaned_message_blobs(raw_ref) VALUES ($1)", &[&rendered])
                .await?;
            if !key.contains("no-object") {
                s3.put(&rendered, b"x", HOUR);
            }
        }
        owner
            .batch_execute("INSERT INTO orphaned_message_blobs(raw_ref) VALUES (E'Message-ID: <inline@x.test>\\r\\nSubject: draft\\r\\n\\r\\nbody'), (E'single\\nbreak')")
            .await?;
        let referenced_ref = render(&fx, "inbound/{sha:referenced}", &mut labels);
        owner
            .execute(
                "INSERT INTO messages(mailbox_id,folder_id,message_id,from_addr,thread_id,raw_ref,size_bytes) VALUES ($1,1,'gofree-blobs2-ref','a@x.test','t',$2,1)",
                &[&fx.mailbox, &referenced_ref],
            )
            .await?;
        s3.reject_delete(&render(&fx, "inbound/{sha:refused}", &mut labels));
        s3.flaky_delete(&render(&fx, "{sha:flaky}", &mut labels), 1);

        worker.tick().await;
        worker.tick().await;
        let orphans_obs = json!({
            "blobs": column(&owner, "SELECT sha256||'|'||minio_ref FROM blobs WHERE minio_ref LIKE 'gofree-b2/%' ORDER BY 1").await?,
            "queue": Vec::<String>::new(),
            "orphans": column(&owner, "SELECT raw_ref FROM orphaned_message_blobs ORDER BY 1").await?,
            "s3": {"requests": s3.take_log(), "keys": s3.keys()},
        });
        drain_oracle::settle("blob-orphans", normalize_for_golden(orphans_obs, &labels), false)?;

        // 3. Wave 2.4 Mark-and-Sweep live tick semantics via BlobCleanup::tick():
        //    - young unreferenced (<24h) stays active
        //    - live referenced (>48h, avatar_sha256) stays active
        //    - unreferenced >48h + past cooldown purges from DB & S3
        //    - flaky S3 delete leaves durable purging row and succeeds on retry tick
        //    - bare 64-hex in `orphaned_message_blobs` that exists in `public.blobs`
        //      is dequeued WITHOUT bypassing Mark-and-Sweep grace!
        reset(&owner).await?;
        s3.reset();
        let sha_young = sha("ms-young-1h");
        let sha_live = sha("ms-live-avatar");
        let sha_due = sha("ms-due-purge");
        let sha_flaky = sha("ms-flaky-purge");
        for (digest, age) in [
            (&sha_young, "1 hour"),
            (&sha_live, "72 hours"),
            (&sha_due, "72 hours"),
            (&sha_flaky, "72 hours"),
        ] {
            owner
                .execute(
                    &format!(
                        "INSERT INTO public.blobs(sha256,minio_ref,size_bytes,created_at) \
                         VALUES ($1,'gofree-b2/'||$1,5,now()-interval '{age}')"
                    ),
                    &[digest],
                )
                .await?;
            s3.put(digest, b"hello", HOUR);
        }
        owner
            .execute(
                "UPDATE public.users SET avatar_sha256 = $1 WHERE id = $2",
                &[&sha_live, &fx.user],
            )
            .await?;
        // Pre-age reclaim_eligible past 24h cooldown for due + flaky.
        for digest in [&sha_due, &sha_flaky] {
            owner
                .execute(
                    "INSERT INTO public.blob_gc_state(blob_sha256,gc_state,reclaim_eligible_at,last_touched_at) \
                     VALUES ($1,'reclaim_eligible',now()-interval '25 hours',now()-interval '72 hours')",
                    &[digest],
                )
                .await?;
        }
        // Put young canonical blob in orphaned_message_blobs too — MUST NOT bypass Mark-and-Sweep!
        owner
            .execute(
                "INSERT INTO public.orphaned_message_blobs(raw_ref) VALUES ($1)",
                &[&sha_young],
            )
            .await?;
        s3.flaky_delete(&sha_flaky, 1);

        // Tick 1: due purges, flaky fails in Tx 2B leaving durable purging, young & live untouched.
        worker.tick().await;
        let keys_t1 = s3.keys();
        assert!(!keys_t1.contains(&sha_due), "due blob must be deleted from S3 on tick 1");
        assert!(keys_t1.contains(&sha_young), "young blob must be protected by 24h grace");
        assert!(keys_t1.contains(&sha_live), "live avatar blob must be protected");
        assert!(keys_t1.contains(&sha_flaky), "flaky blob must stay in S3 after failed delete");
        let flaky_state: String = owner
            .query_one(
                "SELECT gc_state FROM public.blob_gc_state WHERE blob_sha256 = $1",
                &[&sha_flaky],
            )
            .await?
            .get(0);
        assert_eq!(flaky_state, "purging", "failed S3 delete must leave durable purging state");

        // Tick 2: flaky retries and purges cleanly.
        worker.tick().await;
        let keys_t2 = s3.keys();
        assert!(!keys_t2.contains(&sha_flaky), "flaky blob must purge on retry tick 2");
        assert!(keys_t2.contains(&sha_young), "young blob must remain intact");
        assert!(keys_t2.contains(&sha_live), "live avatar blob must remain intact");

        owner
            .execute("UPDATE public.users SET avatar_sha256 = NULL WHERE id = $1", &[&fx.user])
            .await?;
        Ok(())
    }
    .await;

    teardown(&owner, &fx).await;
    result
}
