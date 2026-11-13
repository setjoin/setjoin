//! #409: seed-plus-one-tick oracle for `drive-maintenance` and `drive-preview`.
//! Frozen Go's real `drive.Worker.tick` / `drive.PreviewWorker.tick` (recording
//! overlays in `tests/conformance/drain/`, run in the CI image through
//! `drain_oracle::GoTick`) run over a seeded database with a MinIO client and
//! the real S3 retention driver pointed at an owned fake S3 (and, for previews,
//! a fake `DRIVE_PREVIEW_CMD` shell command). The Rust workers must leave the
//! same rows and make the same S3 requests. Nothing reaches a real store.
//!
//! Record: `GOFREE_RECORD_DRAIN=all|case,case` (+ `GOFREE_GO_SOURCE`); delete a
//! golden to re-record it. Replay needs no Go.
mod common;
mod drain_oracle;
#[path = "drive_workers_oracle/fake_s3.rs"]
mod fake_s3;
use drain_oracle::{settle, BoxError, GoTick};
use fake_s3::DriveS3;
use serde_json::{json, Value};
use setjoin_conformance::harness::Db;
use setjoin_gateway::{
    drive_workers::{DriveMaintenance, DrivePreview, PreviewBounds},
    recovery_worker::S3Store,
};
use setjoin_pg::workers::WorkerDatabase;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc};
use tokio_postgres::Client;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
/// A seeded version: its SQL statements and the S3 objects it needs.
type Seeded = (Vec<String>, Vec<(String, Vec<u8>, i64)>);
const HOUR: i64 = 3600;
const REGULAR: i64 = 9_400_001;
const GXP_COMPLIANCE: i64 = 9_400_002;
const GXP_DEFAULT: i64 = 9_400_003;

fn sha(label: &str) -> String {
    format!("{:x}", Sha256::digest(label.as_bytes()))
}

#[derive(Default)]
struct Case {
    name: String,
    /// SQL statements; `{sha:label}` becomes the label's SHA-256, `{u}` the fixture user.
    seed: Vec<String>,
    /// `(key, body, age in seconds)`; keys take `{sha:label}` too.
    objects: Vec<(String, Vec<u8>, i64)>,
    reject_delete: Vec<String>,
    reject_retention: Vec<String>,
    deny_list: bool,
    env: Vec<(String, String)>,
    ticks: u32,
    no_retention: bool,
    /// Preview only: run the worker's `Run` loop (inert check) instead of one tick.
    run_loop: bool,
    bounds: Option<(u64, u64)>,
}

fn maintenance_cases() -> Vec<Case> {
    let mut cases = Vec::new();
    // Zero-ref chunk GC, the sweep's own enqueue and every GC branch.
    cases.push(Case {
        name: "drive-maint-gc".into(),
        seed: vec![
            "INSERT INTO drive_chunks(scope_key,sha256,size_bytes,storage_ref,ref_count) VALUES ('g','{sha:gc-delete}',7777,'drive/g/{sha:gc-delete}',0),('g','{sha:gc-dequeue}',7777,'drive/g/{sha:gc-dequeue}',1),('g','{sha:gc-swept}',7777,'drive/g/{sha:gc-swept}',0),('g','{sha:gc-claimed}',7777,'drive/g/{sha:gc-claimed}',0),('g','{sha:gc-oldclaim}',7777,'drive/g/{sha:gc-oldclaim}',0),('g','{sha:gc-s3fail}',7777,'drive/g/{sha:gc-s3fail}',0),('g','{sha:gc-legacy}',7777,'legacy/blob-one',0),('g','{sha:gc-live}',7777,'drive/g/{sha:gc-live}',3)".into(),
            "INSERT INTO drive_chunks(scope_key,sha256,size_bytes,storage_ref,ref_count,retain_until) VALUES ('s9400002','{sha:gc-retained}',7777,'drive/s9400002/{sha:gc-retained}',0,'2031-05-06 07:08:09.25+00'),('s9400002','{sha:gc-expired}',7777,'drive/s9400002/{sha:gc-expired}',0,'2020-01-01 00:00:00+00')".into(),
            "INSERT INTO drive_chunk_gc_queue(scope_key,sha256) VALUES ('g','{sha:gc-delete}'),('g','{sha:gc-dequeue}'),('g','{sha:gc-s3fail}'),('g','{sha:gc-legacy}'),('s9400002','{sha:gc-retained}'),('s9400002','{sha:gc-expired}')".into(),
            "INSERT INTO drive_upload_claims(scope_key,sha256,user_id,claimed_at) VALUES ('g','{sha:gc-claimed}',{u},now()-interval '1 day'),('g','{sha:gc-oldclaim}',{u},now()-interval '8 days')".into(),
            "INSERT INTO drive_changes(space_id,seq,node_id,op,at) VALUES (9400001,1,1,'create',now()-interval '100 days'),(9400001,2,1,'update',now()-interval '1 day')".into(),
        ],
        objects: [
            ("drive/g/{sha:gc-delete}", 30 * HOUR),
            ("drive/g/{sha:gc-s3fail}", 30 * HOUR),
            ("legacy/blob-one", 30 * HOUR),
            ("drive/g/{sha:gc-live}", 30 * HOUR),
        ]
        .into_iter()
        .map(|(k, a)| (k.to_owned(), b"x".to_vec(), a))
        .collect(),
        reject_delete: vec!["drive/g/{sha:gc-s3fail}".into()],
        ..Default::default()
    });
    // tmp/upload reaper plus the canonical-orphan reaper (key grammar, age,
    // registration and storage-delete failure).
    let mut reap = Case {
        name: "drive-maint-reap".into(),
        seed: vec![
            "INSERT INTO drive_chunks(scope_key,sha256,size_bytes,storage_ref,ref_count) VALUES ('g','{sha:registered}',7777,'drive/g/{sha:registered}',1)".into(),
        ],
        reject_delete: vec![
            "tmp/upload/old-fail".into(),
            "drive/s9400002/{sha:locked}".into(),
        ],
        ..Default::default()
    };
    for (key, age) in [
        ("tmp/upload/old1", 48 * HOUR),
        ("tmp/upload/fresh", HOUR),
        ("tmp/upload/old-fail", 48 * HOUR),
        ("tmp/upload/nested/old2", 48 * HOUR),
        ("tmp/other/old", 48 * HOUR),
        ("drive/g/{sha:orphan}", 48 * HOUR),
        ("drive/g/{sha:registered}", 48 * HOUR),
        ("drive/g/{sha:fresh}", HOUR),
        ("drive/s9400002/{sha:orphan2}", 48 * HOUR),
        ("drive/s9400002/{sha:locked}", 48 * HOUR),
        ("drive/s+9400002/{sha:signed}", 48 * HOUR),
        ("drive/s0/{sha:zero}", 48 * HOUR),
        ("drive/s09/{sha:leading}", 48 * HOUR),
        ("drive/x/{sha:badscope}", 48 * HOUR),
        ("drive/g/NOTHEX", 48 * HOUR),
        ("drive/g/{sha:deep}/extra", 48 * HOUR),
        ("drive/top-level", 48 * HOUR),
        ("other/g/{sha:elsewhere}", 48 * HOUR),
    ] {
        reap.objects.push((key.to_owned(), b"x".to_vec(), age));
    }
    cases.push(reap);
    // A full inventory page: 203 stale orphans over two ticks, so the second
    // starts after the 200th key (the process-local cursor).
    let mut page = Case {
        name: "drive-maint-pages".into(),
        ticks: 2,
        ..Default::default()
    };
    for i in 0..203 {
        page.objects.push((
            format!("drive/g/{{sha:orphan-{i:03}}}"),
            b"x".to_vec(),
            48 * HOUR,
        ));
    }
    cases.push(page);
    // WORM retries: modes, the default mode, an applied chunk, a rejected
    // retention call and a non-GXP scope.
    let worm = |name: &str, no_retention: bool| {
        Case {
        name: name.into(),
        seed: vec![
            "INSERT INTO drive_chunks(scope_key,sha256,size_bytes,storage_ref,ref_count,retain_until,worm_applied_until) VALUES ('s9400002','{sha:w-null}',7777,'drive/s9400002/{sha:w-null}',1,'2030-01-02 03:04:05.123456+00',NULL),('s9400002','{sha:w-stale}',7777,'drive/s9400002/{sha:w-stale}',1,'2030-01-02 03:04:05+00','2029-01-01 00:00:00+00'),('s9400002','{sha:w-applied}',7777,'drive/s9400002/{sha:w-applied}',1,'2030-01-02 03:04:05+00','2030-01-02 03:04:05+00'),('s9400002','{sha:w-rejected}',7777,'drive/s9400002/{sha:w-rejected}',1,'2031-06-07 08:09:10.5+00',NULL),('s9400003','{sha:w-default}',7777,'drive/s9400003/{sha:w-default}',1,'2032-03-04 05:06:07.000001+00',NULL),('g','{sha:w-regular}',7777,'drive/g/{sha:w-regular}',1,'2030-01-02 03:04:05+00',NULL)".into(),
        ],
        reject_retention: vec!["drive/s9400002/{sha:w-rejected}".into()],
        no_retention,
        ..Default::default()
    }
    };
    cases.push(worm("drive-maint-worm", false));
    cases.push(worm("drive-maint-no-retention", true));
    // Storage listing refused: both steps log and carry on; DB work still runs.
    cases.push(Case {
        name: "drive-maint-list-denied".into(),
        seed: vec![
            "INSERT INTO drive_chunks(scope_key,sha256,size_bytes,storage_ref,ref_count) VALUES ('g','{sha:ld-gc}',7777,'drive/g/{sha:ld-gc}',0)".into(),
        ],
        objects: vec![("tmp/upload/old1".into(), b"x".to_vec(), 48 * HOUR)],
        deny_list: true,
        ..Default::default()
    });
    cases
}

/// `DRIVE_PREVIEW_CMD`: behaviour keyed by the first four source bytes.
const PREVIEW_CMD: &str = "case \"$(head -c 4 {in})\" in FAIL) echo boom >&2; exit 3;; EMPT) : > {outdir}/o.pdf;; NOPD) echo x > {outdir}/o.txt;; BIGG) head -c 5000000 /dev/zero > {outdir}/o.pdf;; *) { printf '%s' '%PDF-1.4 '; cat {in}; } > {outdir}/o.pdf;; esac";

/// A pending version `n` in `space` whose content is `chunks` `(label, body)`.
fn version(n: i64, space: i64, chunks: &[(&str, &str)]) -> Seeded {
    let scope = if space == REGULAR {
        "g".to_owned()
    } else {
        format!("s{space}")
    };
    let node = 9_500_000 + n;
    let ver = 9_600_000 + n;
    let mut sql = vec![
        format!("INSERT INTO drive_nodes(id,space_id,kind,name,created_by) OVERRIDING SYSTEM VALUE VALUES ({node},{space},'file','f{n}.docx',{{u}})"),
        format!("INSERT INTO drive_files(node_id,space_id) VALUES ({node},{space})"),
        format!("INSERT INTO drive_file_versions(id,file_node_id,space_id,content_sha256,size_bytes,author_user_id,preview_status) OVERRIDING SYSTEM VALUE VALUES ({ver},{node},{space},'{{sha:v{n}}}',1,{{u}},'pending')"),
    ];
    let mut objects = Vec::new();
    for (ordinal, (label, body)) in chunks.iter().enumerate() {
        sql.push(format!("INSERT INTO drive_chunks(scope_key,sha256,size_bytes,storage_ref) VALUES ('{scope}','{{sha:{label}}}',{},'drive/{scope}/{{sha:{label}}}') ON CONFLICT DO NOTHING", body.len()));
        sql.push(format!("INSERT INTO drive_version_chunks(version_id,stream,ordinal,scope_key,chunk_sha256) VALUES ({ver},'content',{ordinal},'{scope}','{{sha:{label}}}')"));
        objects.push((
            format!("drive/{scope}/{{sha:{label}}}"),
            body.as_bytes().to_vec(),
            HOUR,
        ));
    }
    (sql, objects)
}

fn preview_case(name: &str, versions: Vec<Seeded>) -> Case {
    let mut case = Case {
        name: name.into(),
        env: vec![("DRIVE_PREVIEW_CMD".into(), PREVIEW_CMD.into())],
        ..Default::default()
    };
    for (sql, objects) in versions {
        case.seed.extend(sql);
        case.objects.extend(objects);
    }
    case
}

fn preview_cases() -> Vec<Case> {
    let mut cases = Vec::new();
    cases.push(preview_case(
        "drive-preview-render",
        vec![
            version(1, REGULAR, &[("hello", "hello")]),
            version(2, GXP_COMPLIANCE, &[("bigg", "BIGG")]),
            version(3, REGULAR, &[("part-a", "part-a|"), ("part-b", "part-b")]),
            version(4, GXP_DEFAULT, &[("hello-gxp", "hello gxp")]),
        ],
    ));
    cases.push(preview_case(
        "drive-preview-failures",
        vec![
            version(1, REGULAR, &[("fail", "FAIL: no")]),
            version(2, REGULAR, &[("empty", "EMPTY")]),
            version(3, REGULAR, &[("nopdf", "NOPDF")]),
            version(4, REGULAR, &[]),
            {
                // A manifest chunk whose object is absent from storage.
                let (sql, _) = version(5, REGULAR, &[("missing", "gone")]);
                (sql, vec![])
            },
        ],
    ));
    cases.push(preview_case(
        "drive-preview-batch",
        (1..=7)
            .map(|n| {
                version(
                    n,
                    REGULAR,
                    &[(
                        ["b1", "b2", "b3", "b4", "b5", "b6", "b7"][n as usize - 1],
                        "batch",
                    )],
                )
            })
            .collect(),
    ));
    let mut states = preview_case(
        "drive-preview-states",
        vec![version(1, REGULAR, &[("st", "state")])],
    );
    for (n, status) in [(2, "none"), (3, "ready"), (4, "failed"), (5, "unsupported")] {
        let (mut sql, objects) = version(n, REGULAR, &[("st-other", "other")]);
        sql[2] = sql[2].replace("'pending'", &format!("'{status}'"));
        states.seed.extend(sql);
        states.objects.extend(objects);
    }
    cases.push(states);
    // Input and output admission bounds (the Go package vars).
    let mut bounds = preview_case(
        "drive-preview-bounds",
        vec![
            version(1, REGULAR, &[("small", "tiny")]),
            version(2, REGULAR, &[("declared", "0123456789abcdef")]),
            {
                // Declared 4 bytes, stored 16: the streamed copy trips the bound.
                let (mut sql, objects) = version(3, REGULAR, &[("lying", "0123456789abcdef")]);
                sql.push("UPDATE drive_chunks SET size_bytes=4 WHERE sha256='{sha:lying}'".into());
                (sql, objects)
            },
            version(4, REGULAR, &[("bigout", "BIGG")]),
        ],
    );
    bounds.bounds = Some((12, 100));
    bounds.env.extend([
        ("GOFREE_PREVIEW_SRC_MAX".into(), "12".into()),
        ("GOFREE_PREVIEW_OUT_MAX".into(), "100".into()),
    ]);
    cases.push(bounds);
    // No command: Run returns at once and nothing is claimed.
    let mut inert = preview_case(
        "drive-preview-inert",
        vec![version(1, REGULAR, &[("idle", "idle")])],
    );
    inert.env = vec![
        ("DRIVE_PREVIEW_CMD".into(), String::new()),
        ("GOFREE_PREVIEW_RUN".into(), "1".into()),
    ];
    inert.run_loop = true;
    cases.push(inert);
    cases
}

struct Fixture {
    user: i64,
    domain: i64,
}

fn render(fixture: &Fixture, text: &str, labels: &mut BTreeMap<String, String>) -> String {
    let mut out = text.replace("{u}", &fixture.user.to_string());
    while let Some(start) = out.find("{sha:") {
        let end = start + out[start..].find('}').expect("sha placeholder");
        let label = out[start + 5..end].to_owned();
        let hash = sha(&label);
        labels.insert(hash.clone(), format!("<{label}>"));
        out.replace_range(start..=end, &hash);
    }
    out
}

async fn fixture(owner: &Client) -> Result<Fixture, BoxError> {
    cleanup_all(owner).await;
    owner.batch_execute("DELETE FROM users WHERE username='gofree-drive5-a'; DELETE FROM domains WHERE name='gofree-drive5.test'").await?;
    let domain: i64 = owner
        .query_one(
            "INSERT INTO domains(name) VALUES ('gofree-drive5.test') RETURNING id",
            &[],
        )
        .await?
        .get(0);
    let user: i64 = owner.query_one("INSERT INTO users(username,domain_id,email,display_name) VALUES ('gofree-drive5-a',$1,'gofree-drive5-a@gofree-drive5.test','A') RETURNING id", &[&domain]).await?.get(0);
    owner.batch_execute(&format!("INSERT INTO drive_spaces(id,name,classification,owner_user_id,retention_days,worm_mode) OVERRIDING SYSTEM VALUE VALUES ({REGULAR},'g5-regular','regular',{user},NULL,NULL),({GXP_COMPLIANCE},'g5-gxp','gxp',{user},30,'compliance'),({GXP_DEFAULT},'g5-secure','secure',{user},NULL,NULL)")).await?;
    Ok(Fixture { user, domain })
}

/// Clears everything a case seeds (ids in the reserved 94/95/96 million
/// ranges). Every zero-ref chunk and queue row goes too: the sweep acts on the
/// whole table. Replica role skips the WORM trigger (GXP versions are immutable
/// inside retention) and the FK checks, so each table is cleared explicitly and
/// the chunks the fixture versions referenced are removed before their links.
fn clean_sql(user: &str, spaces: bool) -> String {
    format!(
        "SET session_replication_role = replica;
         DELETE FROM drive_chunks WHERE sha256 IN (SELECT chunk_sha256 FROM drive_version_chunks WHERE version_id BETWEEN 9600000 AND 9699999);
         DELETE FROM drive_version_chunks WHERE version_id BETWEEN 9600000 AND 9699999;
         DELETE FROM drive_file_versions WHERE id BETWEEN 9600000 AND 9699999;
         DELETE FROM drive_files WHERE node_id BETWEEN 9500000 AND 9599999;
         DELETE FROM drive_nodes WHERE id BETWEEN 9500000 AND 9599999;
         DELETE FROM drive_changes WHERE space_id IN ({REGULAR},{GXP_COMPLIANCE},{GXP_DEFAULT});
         DELETE FROM drive_upload_claims WHERE user_id IN ({user});
         DELETE FROM drive_chunk_gc_queue;
         DELETE FROM drive_chunks WHERE ref_count=0 OR size_bytes=7777;
         {}
         SET session_replication_role = origin;",
        if spaces {
            format!("DELETE FROM drive_acl_generations WHERE space_id IN ({REGULAR},{GXP_COMPLIANCE},{GXP_DEFAULT}); DELETE FROM drive_spaces WHERE id IN ({REGULAR},{GXP_COMPLIANCE},{GXP_DEFAULT});")
        } else {
            String::new()
        }
    )
}

async fn reset(owner: &Client, fixture: &Fixture) -> Result<(), BoxError> {
    owner
        .batch_execute(&clean_sql(&fixture.user.to_string(), false))
        .await
        .map_err(db_text)?;
    let foreign: i64 = owner
        .query_one(
            "SELECT count(*) FROM drive_file_versions WHERE preview_status='pending'",
            &[],
        )
        .await?
        .get(0);
    if foreign != 0 {
        return Err(format!(
            "{foreign} foreign pending Drive versions would be rendered by the tick"
        )
        .into());
    }
    Ok(())
}

fn db_text(e: tokio_postgres::Error) -> String {
    e.as_db_error()
        .map(|d| d.to_string())
        .unwrap_or_else(|| e.to_string())
}

async fn cleanup_all(owner: &Client) {
    let user = "SELECT id FROM users WHERE username='gofree-drive5-a'";
    if let Err(e) = owner.batch_execute(&clean_sql(user, true)).await {
        eprintln!("drive worker oracle cleanup failed: {}", db_text(e));
    }
}

async fn teardown(owner: &Client, fixture: &Fixture) {
    cleanup_all(owner).await;
    let _ = owner
        .batch_execute(&format!(
            "DELETE FROM users WHERE id={}; DELETE FROM domains WHERE id={}",
            fixture.user, fixture.domain
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

const MAINT_OBSERVE: &[(&str, &str)] = &[
    ("chunks", "SELECT scope_key||'|'||sha256||'|rc='||ref_count||'|applied='||coalesce(to_char(worm_applied_until AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US'),'-')||'|ref='||storage_ref FROM drive_chunks WHERE size_bytes=7777 ORDER BY 1"),
    ("queue", "SELECT scope_key||'|'||sha256 FROM drive_chunk_gc_queue ORDER BY 1"),
    ("claims", "SELECT scope_key||'|'||sha256 FROM drive_upload_claims WHERE user_id IN (SELECT id FROM users WHERE username='gofree-drive5-a') ORDER BY 1"),
    ("journal", "SELECT space_id||'|'||seq FROM drive_changes WHERE space_id IN (9400001,9400002,9400003) ORDER BY 1"),
];

const PREVIEW_OBSERVE: &[(&str, &str)] = &[
    ("versions", "SELECT (id-9600000)||':'||preview_status||':'||coalesce(preview_sha256,'-') FROM drive_file_versions WHERE id BETWEEN 9600000 AND 9699999 ORDER BY id"),
    ("preview_chunks", "SELECT (version_id-9600000)||':'||ordinal||':'||scope_key||':'||chunk_sha256 FROM drive_version_chunks WHERE stream='preview' AND version_id BETWEEN 9600000 AND 9699999 ORDER BY 1"),
    ("chunks", "SELECT scope_key||'|'||sha256||'|'||size_bytes||'|'||storage_ref||'|rc='||ref_count FROM drive_chunks WHERE sha256 IN (SELECT chunk_sha256 FROM drive_version_chunks WHERE version_id BETWEEN 9600000 AND 9699999) ORDER BY 1"),
];

/// Label every known digest, order requests as a multiset and fold long runs
/// of deletes into a count plus digest, so the golden stays reviewable.
fn normalize(value: Value, labels: &BTreeMap<String, String>) -> Value {
    let mut text = value.to_string();
    for (hash, label) in labels {
        text = text.replace(hash, label);
    }
    let mut value: Value = serde_json::from_str(&text).unwrap();
    // List-request knobs that never change what the store returns here
    // (`delimiter=` empty, `encoding-type=url`, `fetch-owner`) differ by client
    // library; the retention XML is compared by its mode and date, as the Drive
    // route oracle does (minio omits the namespace attribute the S3 client sends).
    if let Some(requests) = value["s3"]["requests"].as_array_mut() {
        for request in requests {
            if let Some(query) = request.get_mut("query").and_then(Value::as_object_mut) {
                for key in ["delimiter", "encoding-type", "fetch-owner"] {
                    query.remove(key);
                }
            }
            if let Some(xml) = request["body"]
                .as_str()
                .filter(|_| request["query"]["retention"].is_string())
            {
                let part = |open: &str, close: &str| {
                    xml.split(open)
                        .nth(1)
                        .and_then(|r| r.split(close).next())
                        .unwrap_or("")
                        .to_owned()
                };
                let (mode, until) = (
                    part("<Mode>", "</Mode>"),
                    part("<RetainUntilDate>", "</RetainUntilDate>"),
                );
                request["body"] = json!({"mode": mode, "until": until});
            }
        }
    }
    if let Some(requests) = value["s3"]["requests"].as_array().cloned() {
        let mut deletes: Vec<String> = Vec::new();
        let mut others: Vec<String> = Vec::new();
        for request in &requests {
            let line = request.to_string();
            if request["method"] == "DELETE" {
                deletes.push(line);
            } else {
                others.push(line);
            }
        }
        deletes.sort();
        others.sort();
        let mut merged: Vec<Value> = others
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        if deletes.len() > 20 {
            let digest = format!("{:x}", Sha256::digest(deletes.join("\n").as_bytes()));
            merged.push(json!({"deletes": deletes.len(), "digest": digest}));
        } else {
            merged.extend(
                deletes
                    .iter()
                    .map(|l| serde_json::from_str::<Value>(l).unwrap()),
            );
        }
        value["s3"]["requests"] = Value::Array(merged);
    }
    value
}

fn go_env(
    db: &Db,
    s3: &DriveS3,
    case: &Case,
    labels: &mut BTreeMap<String, String>,
    fixture: &Fixture,
) -> Vec<(String, String)> {
    let mut env = vec![
        ("GOFREE_DRAIN_DSN".to_owned(), db.dsn.clone()),
        (
            "GOFREE_DRAIN_S3".to_owned(),
            format!("127.0.0.1:{}", s3.addr.port()),
        ),
        (
            "GOFREE_DRIVE_TICKS".to_owned(),
            case.ticks.max(1).to_string(),
        ),
    ];
    if case.no_retention {
        env.push(("GOFREE_DRIVE_NO_RETENTION".into(), "1".into()));
    }
    for (k, v) in &case.env {
        env.push((k.clone(), render(fixture, v, labels)));
    }
    env
}

#[allow(clippy::too_many_arguments)]
async fn run_case(
    db: &Db,
    owner: &Client,
    fixture: &Fixture,
    s3: &DriveS3,
    case: &Case,
    preview: bool,
    recording: bool,
) -> Result<(), BoxError> {
    reset(owner, fixture).await?;
    s3.reset();
    let mut labels = BTreeMap::new();
    for sql in &case.seed {
        let sql = render(fixture, sql, &mut labels);
        owner
            .batch_execute(&sql)
            .await
            .map_err(|e| format!("seed `{sql}`: {}", db_text(e)))?;
    }
    for (key, body, age) in &case.objects {
        s3.put(&render(fixture, key, &mut labels), body, *age);
    }
    for key in &case.reject_delete {
        s3.reject_delete(&render(fixture, key, &mut labels));
    }
    for key in &case.reject_retention {
        s3.reject_retention(&render(fixture, key, &mut labels));
    }
    if case.deny_list {
        s3.deny_list();
    }
    let mut returned = None;
    if recording {
        let env = go_env(db, s3, case, &mut labels, fixture);
        let (overlay, test, file) = if preview {
            (
                "drive_preview_tick_test.go.txt",
                "TestGoFreeDrivePreviewTick",
                "gofree_drive_preview_tick_test.go",
            )
        } else {
            (
                "drive_maintenance_tick_test.go.txt",
                "TestGoFreeDriveMaintenanceTick",
                "gofree_drive_maintenance_tick_test.go",
            )
        };
        GoTick {
            package: "internal/drive",
            overlay,
            test,
            file,
            env,
            docker: vec![],
        }
        .run()?;
        if case.run_loop {
            returned = Some(true);
        }
    } else {
        let store = Arc::new(S3Store::new(
            &format!("http://127.0.0.1:{}", s3.addr.port()),
            "mailblobs",
            "test-access",
            "test-secret",
        )?);
        let worker_db = WorkerDatabase::new(&db.dsn)?;
        if preview {
            let command = case
                .env
                .iter()
                .find(|(k, _)| k == "DRIVE_PREVIEW_CMD")
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            let mut worker = DrivePreview::new(worker_db, store, command);
            if let Some((source, output)) = case.bounds {
                worker = worker.with_bounds(PreviewBounds { source, output });
            }
            if case.run_loop {
                let finished = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    worker.run_until(std::future::pending()),
                )
                .await;
                returned = Some(finished.is_ok());
            } else {
                worker.tick().await;
            }
        } else {
            let worker = DriveMaintenance::new(worker_db, store, !case.no_retention);
            for _ in 0..case.ticks.max(1) {
                worker.tick().await;
            }
        }
    }
    let mut observation = serde_json::Map::new();
    for (label, sql) in if preview {
        PREVIEW_OBSERVE
    } else {
        MAINT_OBSERVE
    } {
        observation.insert((*label).into(), json!(column(owner, sql).await?));
    }
    observation.insert(
        "s3".into(),
        json!({"requests": s3.take_log(), "keys": s3.keys()}),
    );
    if let Some(returned) = returned {
        observation.insert("run_returned".into(), json!(returned));
    }
    settle(
        &case.name,
        normalize(Value::Object(observation), &labels),
        recording,
    )
}

async fn run_all(prefix: &str, preview: bool, cases: Vec<Case>) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case(prefix) else {
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
    let selected: Vec<&Case> = cases
        .iter()
        .filter(|c| {
            let recording = record.is_some() && listed(&record, &c.name);
            !(record.is_some() && !recording || !listed(&only, &c.name))
        })
        .collect();
    if selected.is_empty() {
        return Ok(());
    }
    let s3 = DriveS3::start().await;
    let fixture = fixture(&owner).await?;
    let mut failures = Vec::new();
    for case in selected {
        let recording = record.is_some() && listed(&record, &case.name);
        if let Err(error) = run_case(&db, &owner, &fixture, &s3, case, preview, recording).await {
            failures.push(format!("{}: {error}", case.name));
        }
        let _ = reset(&owner, &fixture).await;
    }
    teardown(&owner, &fixture).await;
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}

// Multi-threaded: the blocking Go container run must not stall the fake S3.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drive_maintenance_seed_plus_one_tick() -> Result<(), BoxError> {
    run_all("drive-maintenance-tick", false, maintenance_cases()).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drive_preview_seed_plus_one_tick() -> Result<(), BoxError> {
    run_all("drive-preview-tick", true, preview_cases()).await
}
