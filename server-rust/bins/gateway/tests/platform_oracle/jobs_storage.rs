//! F08 slice `jobs-storage` (#301) oracle: a table-driven runner over the shared
//! Platform harness. Each case names one request, its persona, its seed rows and the
//! table whose rows are the observed effect. Record mode runs frozen Go behind the front
//! door; replay serves the same request from Rust with no Go upstream.
use super::{admin_token, masked, pin_load_values, record, SERIAL};
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{
    platform_jobs::PlatformJobsRoute, Body, BoxFuture, Config, Gateway, Intercept,
    RequestContext, RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

struct Probe {
    inner: PlatformJobsRoute<setjoin_gateway::jmap::jwks::Jwks>,
    changed_status: bool,
    cancel_only: bool,
}
impl Intercept for Probe {
    fn matches(&self, r: &Request<Body>) -> bool {
        self.inner.matches(r)
    }
    fn admits_member(&self, h: hyper::HeaderMap, s: &'static str) -> BoxFuture<bool> {
        self.inner.admits_member(h, s)
    }
    fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let changed=self.changed_status&&(!self.cancel_only||r.uri().path().ends_with("/cancel"));
        let future = self.inner.handle(r, c);
        Box::pin(async move {
            let mut response = future.await;
            if changed {
                *response.status_mut() = hyper::StatusCode::IM_A_TEAPOT;
            }
            response
        })
    }
}

/// One request and what it must observe.
pub struct Case {
    pub method: &'static str,
    pub pattern: &'static str,
    /// Values for `{id}` style placeholders, in order.
    pub fill: Vec<String>,
    pub query: String,
    pub perm: &'static str,
    pub body: String,
    pub headers: Vec<(&'static str, String)>,
    /// SQL executed (as the owner) before the request, after Go has started.
    pub seed: Vec<String>,
    /// SQL executed afterwards on every path.
    pub cleanup: Vec<String>,
    /// SQL returning one `jsonb::text` row per observed effect row.
    pub effects: &'static str,
    pub table: &'static str,
    pub channels: Vec<&'static str>,
    pub status: u16,
    /// `(from, to)` text substitutions applied to the response body before comparing.
    pub replace: Vec<(String, String)>,
    /// Extra access-token claims (`acr`, `amr`, `iat`).
    pub claims: Value,
}

fn specs(action: &str, label: &str, user: i64, mailbox: i64) -> Option<Case> {
    let base = |method, pattern, perm, status| Case {
        method,
        pattern,
        fill: vec![],
        query: String::new(),
        perm,
        body: String::new(),
        headers: vec![],
        seed: vec![WIPE.into()],
        cleanup: vec![WIPE.into()],
        effects: COUNTS,
        table: "queues",
        channels: vec![],
        status,
        replace: vec![],
        claims: json!({}),
    };
    let mut c = match action {
        "jobs-summary" => base("GET", "/admin/jobs/summary/{queue}", "queue.read", 200),
        "jobs-list" => base("GET", "/admin/jobs/{queue}", "queue.read", 200),
        "jobs-journal-retry" => base("POST", "/admin/jobs/journal/{id}/retry", "queue.write", 204),
        "jobs-bulk-detail" => base("GET", "/admin/jobs/bulk_role/{id}", "roles.manage", 200),
        "jobs-bulk-retry" => base("POST", "/admin/jobs/bulk_role/{id}/retry", "roles.manage", 204),
        "storage-migration-cancel" => base("POST", "/admin/storage/migrate/{id}/cancel", "system.config", 200),
        "storage-migration-start" => base("POST", "/admin/storage/migrate", "system.config", 202),
        "storage-dr-start" => base("POST", "/admin/storage/dr-scan", "system.config", 202),
        "storage-reconcile" => base("POST", "/admin/storage/dr-scan/{id}/reconcile", "system.config", 200),
        "storage-status" => base("GET", "/admin/storage/status", "domains.read", 200),
        "storage-dr-list" => base("GET", "/admin/storage/dr-scan", "domains.read", 200),
        "storage-dr-get" => base("GET", "/admin/storage/dr-scan/{id}", "reports.read", 200),
        "storage-migrate-list" => base("GET", "/admin/storage/migrate", "mail.pipeline", 200),
        "storage-migrate-get" => base("GET", "/admin/storage/migrate/{id}", "mail.security", 200),
        _ => return None,
    };
    queues(&mut c, action, label, user, mailbox);
    storage(&mut c, action, label);
    if action=="storage-status" && label=="cluster-error" {c.status=503;}
    if label == "denied" {
        c.status = 403;
    }
    if label == "ignored-query" {
        c.query = "?limit=-1&q=%00&x=%zz".into();
    }
    Some(c)
}

/// Every queue table is emptied around a case (the database is private to this ticket).
const WIPE: &str = "DELETE FROM journal_queue; DELETE FROM outbound_queue; DELETE FROM scheduled_actions; DELETE FROM bulk_role_jobs; DELETE FROM storage_dr_scans; DELETE FROM storage_migrations";
const COUNTS: &str = "SELECT jsonb_build_object('journal',(SELECT count(*) FROM journal_queue),'outbound',(SELECT count(*) FROM outbound_queue),'scheduled',(SELECT count(*) FROM scheduled_actions),'bulk',(SELECT count(*) FROM bulk_role_jobs),'scans',(SELECT count(*) FROM storage_dr_scans),'migrations',(SELECT count(*) FROM storage_migrations))::text";

fn journal_rows(mailbox: i64, rows: &[(i64, &str, i32, &str, &str)]) -> String {
    let values: Vec<String> = rows
        .iter()
        .map(|(id, status, attempts, queued, error)| {
            let error = if error.is_empty() { "NULL".to_string() } else { format!("'{error}'") };
            format!("({id},'<m{id}@plat3.test>','a@plat3.test','b@plat3.test','ref{id}',{mailbox},'{status}',{attempts},'{queued}',{error})")
        })
        .collect();
    format!("INSERT INTO journal_queue(id,message_id,envelope_from,envelope_to,raw_ref,journal_mailbox_id,status,attempt_count,queued_at,last_error) VALUES {}", values.join(","))
}

/// Seed rows and requests for the jobs routes.
fn queues(c: &mut Case, action: &str, label: &str, user: i64, mailbox: i64) {
    if !action.starts_with("jobs-") {
        return;
    }
    let journal = journal_rows(
        mailbox,
        &[
            (9301, "pending", 0, "2026-10-01T10:01:00Z", ""),
            (9302, "deferred", 2, "2026-10-01T10:02:00Z", "temporary <failure> & retry"),
            (9303, "failed", 5, "2026-10-01T10:03:00Z", "boom"),
            (9304, "dead", 9, "2026-10-01T10:04:00Z", "gave up"),
            (9305, "delivered", 1, "2026-10-01T10:05:00Z", ""),
            (9306, "dead", 8, "2026-10-01T10:00:30Z", "older dead"),
        ],
    );
    let outbound = "INSERT INTO outbound_queue(id,message_id,from_addr,rcpt_addrs,raw_ref,status,attempt_count,next_attempt_at,last_error,queued_at) VALUES \
        (9311,'<o1@plat3.test>','a@plat3.test','{b@plat3.test}','r1','pending',0,'2026-10-02T10:00:00Z',NULL,'2026-10-01T10:01:00Z'),\
        (9312,'<o2@plat3.test>','a@plat3.test','{b@plat3.test}','r2','sending',1,'2026-10-02T10:00:00Z',NULL,'2026-10-01T10:02:00Z'),\
        (9313,'<o3@plat3.test>','a@plat3.test','{b@plat3.test}','r3','deferred',3,'2026-10-02T11:00:00Z','4xx try later','2026-10-01T10:03:00Z'),\
        (9314,'<o4@plat3.test>','a@plat3.test','{b@plat3.test}','r4','bounced',6,'2026-10-02T10:00:00Z','5xx rejected','2026-10-01T10:04:00Z'),\
        (9315,'<o5@plat3.test>','a@plat3.test','{b@plat3.test}','r5','delivered',1,'2026-10-02T10:00:00Z',NULL,'2026-10-01T10:05:00Z')";
    let scheduled = "INSERT INTO scheduled_actions(id,action_kind,fire_at,status,attempts,last_error,created_at) VALUES \
        ('00000000-0000-4000-8000-000000009321','snooze','2026-10-02T10:00:00Z','pending',0,NULL,'2026-10-01T10:01:00Z'),\
        ('00000000-0000-4000-8000-000000009322','send_later','2026-10-02T10:00:00Z','processing',1,NULL,'2026-10-01T10:02:00Z'),\
        ('00000000-0000-4000-8000-000000009323','snooze','2026-10-02T10:00:00Z','failed',3,'lost <mailbox>','2026-10-01T10:03:00Z'),\
        ('00000000-0000-4000-8000-000000009324','reminder','2026-10-02T10:00:00Z','done',1,NULL,'2026-10-01T10:04:00Z')";
    let bulk = format!(
        "INSERT INTO bulk_role_jobs(id,op,role_id,actor_id,user_ids,status,total,processed,results,error,created_at,updated_at) VALUES \
        (9331,'assign',7,{user},'{{1,2,3}}','queued',3,0,'[]'::jsonb,NULL,'2026-10-01T10:01:00Z','2026-10-01T10:01:00Z'),\
        (9332,'revoke',8,{user},'{{4}}','running',1,0,'[]'::jsonb,NULL,'2026-10-01T10:02:00Z','2026-10-01T10:02:00Z'),\
        (9333,'assign',9,{user},'{{5,6}}','done',2,2,'[{{\"user\":5,\"ok\":true}},{{\"user\":6,\"ok\":true}}]'::jsonb,NULL,'2026-10-01T10:03:00Z','2026-10-01T10:03:00Z'),\
        (9334,'assign',10,{user},'{{7,8}}','error',2,1,'[{{\"user\":7,\"ok\":true}}]'::jsonb,'worker <crashed> & stopped','2026-10-01T10:04:00Z','2026-10-01T10:04:00Z')"
    );
    c.cleanup.push("DELETE FROM admin_audit_log WHERE action='bulk_role_job_retry' AND false".into());
    let all = |c: &mut Case| {
        c.seed.push(journal.clone());
        c.seed.push(outbound.to_string());
        c.seed.push(scheduled.to_string());
        c.seed.push(bulk.clone());
    };
    // `unknown` and `denied` still exercise the real tables.
    let queue_label = |l: &str| -> &'static str {
        match l {
            "outbound" => "outbound",
            "scheduled" => "scheduled",
            "bulk-role" => "bulk_role",
            "unknown" => "nope",
            _ => "journal",
        }
    };
    match action {
        "jobs-summary" | "jobs-list" => {
            if label != "empty" {
                all(c);
            }
            // The outbound rows' trigger queued a `dsn` action with a random id; the list
            // shows ids, so that run-specific row is removed for this case.
            if action == "jobs-list" && label == "scheduled" {
                c.seed.push("DELETE FROM scheduled_actions WHERE action_kind = 'dsn'".into());
            }
            c.fill = vec![queue_label(label).into()];
            if label == "unknown" {
                c.status = 400;
            }
            if action == "jobs-list" {
                match label {
                    "attention" => c.query = "?status=attention".into(),
                    "active" => c.query = "?status=active".into(),
                    "done" => c.query = "?status=done".into(),
                    "all" => c.query = "?status=all".into(),
                    "page" => c.query = "?limit=2&offset=1".into(),
                    "bad-limit" => c.query = "?limit=0&offset=-5".into(),
                    "huge-limit" => c.query = "?limit=500&offset=999999999".into(),
                    "bad-status" => c.query = "?status=nothing".into(),
                    _ => {}
                }
            }
            // The default queue of a label like `attention` is the journal.
        }
        "jobs-journal-retry" => {
            c.effects = "SELECT jsonb_build_object('id',id,'status',status,'attempts',attempt_count,'rescheduled',next_attempt_at IS NOT NULL)::text FROM journal_queue ORDER BY id";
            c.table = "journal_queue";
            if label != "empty" {
                c.seed.push(journal.clone());
            }
            c.fill = vec![match label {
                "not-dead" => "9303".into(),
                "missing" => "9999".into(),
                "bad-id" => "abc".into(),
                _ => "9304".into(),
            }];
            c.status = match label {
                "not-dead" | "missing" | "repeat" => 404,
                "bad-id" => 400,
                _ => 204,
            };
        }
        "jobs-bulk-detail" | "jobs-bulk-retry" => {
            c.effects = "SELECT jsonb_build_object('id',id,'status',status,'error',error,'processed',processed,'results',results)::text FROM bulk_role_jobs ORDER BY id";
            c.table = "bulk_role_jobs";
            c.seed.push(bulk.clone());
            c.fill = vec![match label {
                "not-error" => "9333".into(),
                "missing" => "9999".into(),
                "bad-id" => "abc".into(),
                "queued" => "9331".into(),
                _ => "9334".into(),
            }];
            let detail = action == "jobs-bulk-detail";
            c.status = match (detail, label) {
                (_, "bad-id") => 400,
                (true, "missing") => 404,
                (false, "not-error" | "missing" | "repeat" | "queued") => 409,
                (true, _) => 200,
                (false, _) => 204,
            };
        }
        _ => {}
    }
}

const SCANS: &str = "INSERT INTO storage_dr_scans(id,status,total_scanned,orphaned_count,missing_count,reimported_count,details,started_at,completed_at,refcount_drift_count) VALUES ";
const MIGRATIONS: &str = "INSERT INTO storage_migrations(id,source_driver,target_driver,status,total_blobs,migrated,last_key,error_message,started_at,completed_at) VALUES ";

/// Seed rows and requests for the storage read models.
fn storage(c: &mut Case, action: &str, label: &str) {
    if !action.starts_with("storage-") {
        return;
    }
    if action == "storage-reconcile" {
        let sha = "a".repeat(64);
        c.fill = vec!["9601".into()];
        c.table = "storage-reconcile";
        c.effects = "SELECT jsonb_build_object('scans',(SELECT jsonb_agg(jsonb_build_object('id',id,'status',status,'reimported',reimported_count) ORDER BY id) FROM storage_dr_scans),'blobs',(SELECT jsonb_agg(jsonb_build_object('sha',sha256,'ref',minio_ref,'size',size_bytes,'type',content_type,'count',ref_count) ORDER BY sha256) FROM blobs WHERE sha256=repeat('a',64)))::text";
        c.seed.push(format!("DELETE FROM blobs WHERE sha256='{sha}'; INSERT INTO storage_dr_scans(id,status,details) VALUES(9601,'completed','[{{\"sha256\":\"{sha}\",\"issue\":\"orphaned\"}}]'::jsonb)"));
        c.cleanup.push(format!("DELETE FROM blobs WHERE sha256='{sha}'"));
        match label {
            "bad-id" => { c.fill = vec!["abc".into()]; c.status = 400; },
            "missing" => { c.fill = vec!["9999".into()]; c.status = 404; },
            "running" => { c.seed.push("UPDATE storage_dr_scans SET status='running'".into()); c.status = 409; },
            "bad-details" => { c.seed.push("UPDATE storage_dr_scans SET details='[42]'::jsonb".into()); c.status = 500; },
            "null-details" => { c.seed.push("UPDATE storage_dr_scans SET details='null'::jsonb".into()); },
            _ => {},
        }
        return;
    }
    if matches!(action,"storage-migration-start"|"storage-migration-cancel") {
        if action=="storage-migration-start" { c.query="?target=posix".into(); } else { c.fill=vec!["9700".into()]; }
        c.body="{\"actor_id\":196,\"mailbox_id\":196}".into();
        c.seed.push("SELECT setval('storage_migrations_id_seq',9700,false)".into());
        let sha=setjoin_backup::digest(b"blob");
        c.seed.push(format!("DELETE FROM blobs WHERE sha256='{sha}'; INSERT INTO blobs(sha256,minio_ref,size_bytes,content_type,ref_count) VALUES('{sha}','mailblobs/{sha}',4,'text/plain',1)"));
        c.cleanup.push(format!("DELETE FROM blobs WHERE sha256='{sha}'"));
        if action=="storage-migration-cancel" && label=="drain-timeout" {c.status=503;}
        if action=="storage-migration-start" {
            match label {
                "no-target"=>{c.query=String::new();c.status=400;},
                "same-target"=>{c.query="?target=s3".into();c.status=400;},
                "unknown-target"=>{c.query="?target=other%3Cdriver%3E".into();c.status=500;},
                "invalid-utf8-target"=>{c.query="?target=%FF".into();c.status=500;},
                "backup-s3"|"backup-s3-http-io"|"backup-s3-env-region"=>c.query="?target=backup_s3".into(),
                "oss"|"oss-scope"=>c.query="?target=oss".into(),
                _=>{},
            }
        } else if !matches!(label,"success"|"scoped"|"repeat"|"drain-timeout") {
            let state=match label {"terminal"=>"completed","cutover"=>"cutover",_=>"backfill"};
            c.seed.push(format!("INSERT INTO storage_migrations(id,source_driver,target_driver,status) VALUES(9700,'s3','posix','{state}')"));
            c.status=match label {"denied"=>403,"bad-id"=>400,"missing"=>404,_=>409};
            if label=="bad-id"{c.fill=vec!["abc".into()];}
            if label=="missing"{c.fill=vec!["9999".into()];}
        }
        if label=="native-closed"{c.status=503;}
        if action=="storage-migration-cancel"&&label=="repeat" {c.status=409;}
        c.table="storage_migrations";
        c.effects="SELECT jsonb_build_object('id',id,'source',source_driver,'target',target_driver,'status',status,'total',total_blobs,'migrated',migrated,'last',last_key,'error',error_message,'started',started_at IS NOT NULL,'completed',completed_at IS NOT NULL)::text FROM storage_migrations ORDER BY id";
        return;
    }
    if action == "storage-dr-start" {
        c.seed.push("SELECT setval('storage_dr_scans_id_seq',9600,false)".into());
        c.seed.push("DELETE FROM blobs WHERE sha256 IN(repeat('b',64),repeat('c',64)); INSERT INTO blobs(sha256,minio_ref,size_bytes,content_type,ref_count) VALUES(repeat('b',64),'mailblobs/b',4,'text/plain',1),(repeat('c',64),'mailblobs/c',4,'text/plain',0)".into());
        c.cleanup.push("DELETE FROM blobs WHERE sha256 IN(repeat('b',64),repeat('c',64))".into());
        if label=="list-error" {c.seed.push("DELETE FROM blobs WHERE sha256=repeat('c',64)".into());}
        if label=="cursor-error" {
            c.seed.push("ALTER TABLE public.blobs RENAME TO gofree_plat3b_blobs; CREATE FUNCTION public.gofree_plat3b_scan_key(text) RETURNS text LANGUAGE plpgsql VOLATILE AS $$BEGIN IF $1=repeat('c',64) THEN RAISE EXCEPTION 'late storage catalog cursor failure'; END IF; RETURN $1; END$$; CREATE VIEW public.blobs AS SELECT public.gofree_plat3b_scan_key(b.sha256) AS sha256,b.minio_ref,b.size_bytes,b.content_type,b.ref_count,b.created_at FROM public.gofree_plat3b_blobs b ORDER BY b.sha256; GRANT SELECT ON public.blobs TO setjoin_app,setjoin_worker".into());
            c.cleanup.insert(0,"DO $$BEGIN IF to_regclass('public.gofree_plat3b_blobs') IS NOT NULL THEN DROP VIEW IF EXISTS public.blobs; ALTER TABLE public.gofree_plat3b_blobs RENAME TO blobs; END IF; END$$; DROP FUNCTION IF EXISTS public.gofree_plat3b_scan_key(text)".into());
        }

        if label=="insert-error" {
            c.seed.push("CREATE FUNCTION public.gofree_plat3b_scan_refuse() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'storage scan insert refused'; END$$; CREATE TRIGGER gofree_plat3b_scan_refuse BEFORE INSERT ON storage_dr_scans FOR EACH ROW EXECUTE FUNCTION public.gofree_plat3b_scan_refuse()".into());
            c.cleanup.push("DROP TRIGGER IF EXISTS gofree_plat3b_scan_refuse ON storage_dr_scans; DROP FUNCTION IF EXISTS public.gofree_plat3b_scan_refuse()".into());
            c.status=500;
        }
        c.table = "storage_dr_scans";
        c.effects = "SELECT jsonb_build_object('id',id,'status',status,'total',total_scanned,'orphaned',orphaned_count,'missing',missing_count,'drift',refcount_drift_count,'reimported',reimported_count,'details',details,'completed',completed_at IS NOT NULL)::text FROM storage_dr_scans ORDER BY id";
        return;
    }
    match action {
        "storage-dr-list" | "storage-dr-get" => {
            c.table = "storage_dr_scans";
            c.effects = "SELECT jsonb_build_object('id',id,'status',status)::text FROM storage_dr_scans ORDER BY id";
            let details = "'[{\"sha256\":\"aa\",\"issue\":\"orphaned\",\"size\":12345},{\"sha256\":\"bb\",\"issue\":\"missing\"},{\"sha256\":\"cc\",\"issue\":\"refcount_drift\",\"refCountExpected\":3,\"refCountActual\":1.5e300},{\"sha256\":\"<d>&\",\"issue\":\"orphaned\",\"size\":9007199254740993}]'::jsonb";
            let rows: Vec<String> = match label {
                "empty" | "denied" if action == "storage-dr-list" => vec![],
                "null-details" => vec![format!("(9401,'completed',3,0,0,0,NULL,'2026-10-01T10:00:00Z','2026-10-01T10:05:00Z',0)")],
                "odd-details" => vec![format!("(9401,'completed',3,0,0,0,'[1,null,\"x\",{{\"b\":2,\"a\":[1,2.50,true]}},[3]]'::jsonb,'2026-10-01T10:00:00Z','2026-10-01T10:05:00.123456Z',0)")],
                "object-details" => vec![format!("(9401,'completed',3,0,0,0,'{{\"not\":\"a list\"}}'::jsonb,'2026-10-01T10:00:00Z',NULL,0)")],
                _ => vec![
                    format!("(9401,'completed',1500,2,1,1,{details},'2026-10-01T10:00:00Z','2026-10-01T10:05:00Z',1)"),
                    "(9402,'running',20,0,0,0,'[]'::jsonb,'2026-10-02T10:00:00.5Z',NULL,0)".into(),
                    "(9403,'failed',0,0,0,0,'[]'::jsonb,'2026-10-03T10:00:00Z','2026-10-03T10:00:01Z',0)".into(),
                ],
            };
            if !rows.is_empty() {
                c.seed.push(format!("{SCANS}{}", rows.join(",")));
            }
            if action == "storage-dr-get" {
                c.fill = vec![match label {
                    "missing" => "9999".into(),
                    "bad-id" => "abc".into(),
                    "running" => "9402".into(),
                    "failed" => "9403".into(),
                    _ => "9401".into(),
                }];
                c.status = match label {
                    "missing" => 404,
                    "bad-id" => 400,
                    "denied" => 403,
                    _ => 200,
                };
            }
        }
        _ => {
            c.table = "storage_migrations";
            c.effects = "SELECT jsonb_build_object('id',id,'status',status)::text FROM storage_migrations ORDER BY id";
            let rows: Vec<String> = match label {
                "empty" | "denied" if action == "storage-migrate-list" => vec![],
                "null-started" => vec!["(9501,'s3','posix','failed',NULL,NULL,NULL,'x',NULL,NULL)".into()],
                _ => vec![
                    "(9501,'s3','posix','completed',100,100,'zz-last','',  '2026-10-01T10:00:00Z','2026-10-01T10:30:00Z')".into(),
                    "(9502,'s3','oss','backfill',300,100,'k-100',NULL,'2026-10-02T10:00:00.25Z',NULL)".into(),
                    "(9503,'s3','posix','dual_write',NULL,NULL,NULL,NULL,'2026-10-03T10:00:00Z',NULL)".into(),
                    "(9504,'s3','posix','cancelled',0,0,NULL,NULL,'2026-10-04T10:00:00Z','2026-10-04T10:01:00Z')".into(),
                    "(9505,'s3','oss','cutover',7,3,'<k>&',NULL,'2026-10-05T10:00:00Z',NULL)".into(),
                ],
            };
            if !rows.is_empty() {
                c.seed.push(format!("{MIGRATIONS}{}", rows.join(",")));
            }
            if action == "storage-migrate-get" {
                c.fill = vec![match label {
                    "missing" => "9999".into(),
                    "bad-id" => "abc".into(),
                    "backfill" => "9502".into(),
                    "pending" => "9503".into(),
                    "zero-total" => "9504".into(),
                    "escaped" => "9505".into(),
                    "null-started" => "9501".into(),
                    _ => "9501".into(),
                }];
                c.status = match label {
                    "missing" | "null-started" => 404,
                    "bad-id" => 400,
                    "denied" => 403,
                    _ => 200,
                };
            }
        }
    }
}


/// Replace run-time ISO timestamps in a document with `<timestamp>`; the fixed `2026-10-0x`
/// seeds stay readable.
fn scrub_times(text: &str) -> String {
    let b = text.as_bytes();
    let digit = |i: usize| b.get(i).is_some_and(u8::is_ascii_digit);
    let mut out = String::new();
    let mut i = 0;
    while i < b.len() {
        let shaped = i + 19 <= b.len()
            && (0..4).all(|k| digit(i + k))
            && b[i + 4] == b'-'
            && digit(i + 5)
            && digit(i + 6)
            && b[i + 7] == b'-'
            && digit(i + 8)
            && digit(i + 9)
            && b[i + 10] == b'T'
            && digit(i + 11)
            && digit(i + 12)
            && b[i + 13] == b':'
            && digit(i + 14)
            && digit(i + 15)
            && b[i + 16] == b':'
            && digit(i + 17)
            && digit(i + 18);
        if !shaped {
            let ch = text[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }
        let mut end = i + 19;
        if b.get(end) == Some(&b'.') {
            end += 1;
            while digit(end) {
                end += 1;
            }
        }
        if b.get(end) == Some(&b'Z') {
            end += 1;
        } else if matches!(b.get(end), Some(b'+' | b'-')) && digit(end + 1) && digit(end + 2) && b.get(end + 3) == Some(&b':') {
            end += 6;
        }
        if text[i..].starts_with("2026-10-0") {
            out.push_str(&text[i..end]);
        } else {
            out.push_str("<timestamp>");
        }
        i = end;
    }
    out
}

pub async fn run(action: &str, kind: &str) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let mutant = kind.ends_with("-status-mutant");
    let label = kind.strip_suffix("-status-mutant").unwrap_or(kind);
    let Some(db) = Db::for_case("plat3-http") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "plat3-admin").await?;
    let b = fixture::account(&owner, "plat3-other").await?;
    let case = specs(action, label, a.user, a.mailbox).ok_or("unknown jobs-storage action")?;
    let domain_of = |id: i64| {
        let owner = &owner;
        async move {
            Ok::<String, BoxError>(owner.query_one("SELECT name FROM domains WHERE id=$1", &[&id]).await?.get(0))
        }
    };
    let domain_names = [(domain_of(a.domain).await?, "host-a.test"), (domain_of(b.domain).await?, "host-b.test")];
    let names = |text: &str| {
        let mut out = text.to_owned();
        for (domain, name) in &domain_names {
            out = out.replace(domain.as_str(), name);
        }
        out = out.replace(&format!("\"actor_id\":{}", a.user), "\"actor_id\":\"<admin>\"");
        scrub_times(&out)
    };
    let sent_body = case.body.clone();
    let (permissions, scope): (Vec<&str>, Option<i64>) = match label {
        "denied" => (vec!["users.read"], None),
        "scoped" => (vec![case.perm], Some(b.domain)),
        _ => (vec![case.perm], None),
    };
    let role = format!("plat3-role-{}", a.user);
    owner.execute("INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,$2,$3)", &[&role, &permissions, &scope]).await?;
    owner.execute("INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by,eligible) SELECT $1,id,$1,false FROM admin_role_groups WHERE name=$2", &[&a.user, &role]).await?;
    let audit_start: i64 = owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[]).await?.get(0);
    let receipts = owner
        .query("SELECT operation_id::text FROM rust_operation_receipts WHERE family='F08'", &[])
        .await?
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect::<Vec<_>>();
    let users: Vec<(i64, &str)> = vec![(a.user, "<admin>"), (b.user, "<other>")];
    let migration_target = if matches!(action,"storage-migration-start"|"storage-migration-cancel") { Some(MigrationTarget::new(a.user)?) } else { None };
    if let Some(target)=&migration_target {
        if action=="storage-migration-start"&&matches!(label,"skip"|"repair") {target.seed(if label=="skip"{b"blob"}else{b"oops"})?;}
    }
    let blocked_target=if action=="storage-migration-cancel" && label=="drain-timeout" {Some(BlockedTarget::new(migration_target.as_ref().unwrap())?)}else{None};
    let runtime_to_stop = std::sync::Mutex::new(None::<Arc<setjoin_gateway::platform_storage::Runtime>>);
    let source_release=Arc::new(tokio::sync::Notify::new());
    let source_waiting=Arc::new(std::sync::atomic::AtomicBool::new(false));
    let wire=Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));
    let wire_errors=Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let capture=Arc::new(std::sync::atomic::AtomicBool::new(false));
    let result = async {
        let scan_start = action == "storage-dr-start";
        let migration=matches!(action,"storage-migration-start"|"storage-migration-cancel");
        let cancel=action=="storage-migration-cancel";
        let live_cancel=cancel&&matches!(label,"success"|"scoped"|"repeat"|"drain-timeout");
        let list_error=label=="list-error";
        let corrupt=label=="corrupt-source";
        let bucket_denied=label=="bucket-denied";
        let oss_scope=label=="oss-scope";
        let aws_scope=label=="backup-s3-env-region";
        let legacy_location=action=="storage-migration-start"&&label=="success";
        let (release,waiting)=(source_release.clone(),source_waiting.clone());
        let(peer_wire,peer_errors,peer_capture)=(wire.clone(),wire_errors.clone(),capture.clone());
        let s3=common::fake_upstream(move |mut r| {
            let(peer_wire,peer_errors,peer_capture)=(peer_wire.clone(),peer_errors.clone(),peer_capture.clone());
            let(release,waiting)=(release.clone(),waiting.clone());
            async move {
            if peer_capture.load(std::sync::atomic::Ordering::SeqCst)&&!r.uri().query().unwrap_or("").contains("location") {
                use http_body_util::BodyExt as _;
                let bytes=r.body_mut().collect().await.unwrap().to_bytes();
                if oss_scope {
                    let auth=r.headers().get("authorization").and_then(|v|v.to_str().ok()).unwrap_or("");
                    let credential=auth.split_whitespace().flat_map(|s|s.split(',')).find_map(|s|s.strip_prefix("Credential=")).unwrap_or("");
                    let fields=credential.split('/').collect::<Vec<_>>();
                    if !auth.starts_with("OSS4-HMAC-SHA256 ")||fields.len()!=5||fields[0]!="test-access"||fields[3]!="oss"||fields[4]!="aliyun_v4_request" {
                        peer_errors.lock().unwrap().push(format!("invalid OSS credential scope: {auth}"));
                    } else {
                        peer_wire.lock().unwrap().push(json!({"operation":"get","path":r.uri().path(),"credential_scope":format!("test-access/<date>/{}/oss/aliyun_v4_request",fields[2])}));
                    }
                } else {match common::s3::observe_list(&r,&bytes) {
                    Ok(signed)=>{
                        let listing=r.uri().query().is_some_and(|q|q.contains("list-type=2"));
                        let mut entry=json!({"operation":if listing{"list"}else{"get"},"path":r.uri().path().trim_end_matches('/'),"signature_valid":signed["signature_valid"]});
                        if aws_scope{entry["credential_scope"]=signed["scope"].clone();}
                        peer_wire.lock().unwrap().push(entry);
                    },
                    Err(error)=>peer_errors.lock().unwrap().push(error),
                }}
            }
            if migration && r.method()==hyper::Method::GET && r.uri().path().starts_with("/mailblobs/") && (legacy_location || r.uri().query().unwrap_or("").is_empty()) {
                if live_cancel && !list_error {
                    waiting.store(true,std::sync::atomic::Ordering::SeqCst);
                    release.notified().await;
                }
                return Response::builder().header("last-modified","Thu, 01 Oct 2026 00:00:00 GMT")
                    .header("content-type","text/plain").header("content-length","4").body(common::full(if corrupt{"oops"}else{"blob"})).unwrap();
            }
            if scan_start && r.uri().query().is_some_and(|q| q.contains("list-type=2")) {
                if list_error {return Response::builder().status(403).body(common::full("<Error><Code>AccessDenied</Code><Message>list refused</Message></Error>")).unwrap();}
                return Response::new(common::full(format!("<ListBucketResult><Name>mailblobs</Name><IsTruncated>false</IsTruncated><Contents><Key>{}</Key><Size>4</Size><LastModified>2026-10-01T00:00:00Z</LastModified></Contents><Contents><Key>{}</Key><Size>4</Size><LastModified>2026-10-01T00:00:00Z</LastModified></Contents></ListBucketResult>", "a".repeat(64), "b".repeat(64))));
            }
            if r.method() == hyper::Method::HEAD {
                return Response::builder().header("content-length", "4")
                    .header("content-type", "text/plain")
                    .header("last-modified", "Thu, 01 Oct 2026 00:00:00 GMT")
                    .body(common::full("")).unwrap();
            }
            if bucket_denied&&r.uri().path()=="/" {return Response::builder().status(403).body(common::full("<Error><Code>AccessDenied</Code></Error>")).unwrap();}
            let xml = if r.uri().query().is_some_and(|q| q.contains("location")) {
                "<LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></LocationConstraint>"
            } else {
                "<ListAllMyBucketsResult><Owner><ID>storage-oracle</ID></Owner><Buckets><Bucket><Name>mail</Name><CreationDate>2026-10-01T00:00:00Z</CreationDate></Bucket></Buckets></ListAllMyBucketsResult>"
            };
            Response::new(common::full(xml))
        }}).await;
        let master = if action == "storage-status" {
            let recording = std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
            let bind = if recording { "127.0.0.1:9333" } else { "127.0.0.1:0" };
            let listener = tokio::net::TcpListener::bind(bind).await?;
            let addr = listener.local_addr()?;
            let mode=match label {"multi"=>1,"cluster-error"=>2,"dir-error"=>3,"new-topology"=>4,"http-error-json"=>5,_=>0};
            let task = tokio::spawn(async move {
                loop {
                    let Ok((socket, _)) = listener.accept().await else { break };
                    tokio::spawn(async move {
                        let svc = hyper::service::service_fn(move |r: Request<hyper::body::Incoming>| async move {
                            if mode==2&&r.uri().path()=="/cluster/status"||mode==3&&r.uri().path()=="/dir/status" {
                                return Ok::<_,std::convert::Infallible>(Response::new(common::full("not JSON")));
                            }
                            let body = if r.uri().path() == "/cluster/status" {
                                r#"{"IsLeader":true,"Leader":"node:9333"}"#
                            } else if mode==1 {
                                r#"{"Version":"3.99","Topology":{"dc-b":{"rack-z":{"DataNodes":[{"Url":"z:8080","Free":3,"Max":5,"Volumes":[1]}]},"rack-a":{"DataNodes":[{"Url":"a:8080","Free":7,"Max":9,"Volumes":[]}]}},"dc-a":{"rack-c":{"DataNodes":[{"Url":"c:8080","Free":2,"Max":4,"Volumes":[1,2]}]}}}}"#
                            } else if mode==4 {
                                r#"{"Version":"3.99","Topology":{"dc":{"DataCenters":[{"Id":"new-dc"}]}}}"#
                            } else {
                                r#"{"Version":"3.99","Topology":{"dc1":{"rack1":{"DataNodes":[{"Url":"node:8080","Free":7,"Max":10,"Volumes":[1,2]}]}}}}"#
                            };
                            Ok::<_, std::convert::Infallible>(Response::builder().status(if mode==5{503}else{200}).body(common::full(body)).unwrap())
                        });
                        let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(socket), svc).await;
                    });
                }
            });
            Some((addr, task))
        } else { None };
        let mut extra_env=vec![];
        if let Some(target)=&migration_target {
            extra_env.push(("--volume",format!("{}:/gofree-plat3b-target",target.0.display())));
            extra_env.push(("--workdir","/gofree-plat3b-target".into()));
            extra_env.push(("STORAGE_ACCESS_KEY","test-access".into()));
            extra_env.push(("STORAGE_SECRET_KEY","test-secret".into()));
            extra_env.push(("STORAGE_ENDPOINT",format!("http://{s3}")));
            if label=="backup-s3-env-region"{extra_env.push(("AWS_REGION","us-west-2".into()));}
        }
        let go = common::go_oracle::start_named_with_env(&db,s3,"gofree-plat3-http",&extra_env).await?;
        let recording = go.is_some();
        let patient = std::time::Duration::from_secs(30);
        let exec = ScopedExecutor::from_dsn_with(
            db.app.as_deref().unwrap_or(&db.dsn),
            4,
            setjoin_pg::Timeouts { pool_wait: patient, create: patient, statement: patient },
        )
        .map_err(|e| e.0)?
        .with_audit_keys("22".repeat(32), String::new());
        let worker = ScopedExecutor::from_dsn_with(
            &db.dsn,
            4,
            setjoin_pg::Timeouts { pool_wait: patient, create: patient, statement: patient },
        )
        .map_err(|e| e.0)?
        .with_audit_keys("22".repeat(32), String::new());
        let migration_config=migration_target.as_ref().map(|target|setjoin_gateway::platform_storage::MigrationConfig {
            provider:String::new(), endpoint:format!("http://{s3}"),bucket:if matches!(label,"backup-s3"|"backup-s3-http-io"|"backup-s3-env-region"|"oss"|"oss-scope"){"mailblobs".into()}else{target.0.join("mailblobs").to_string_lossy().into_owned()},
            access:"test-access".into(),secret:"test-secret".into(),
        });
        let storage_runtime = Some({
            let master_url = master.as_ref().map(|(addr, _)| format!("http://{addr}")).unwrap_or_else(|| "http://127.0.0.1:1".into());
            let runtime=setjoin_gateway::platform_storage::Runtime::new(
                Arc::new(setjoin_gateway::recovery_worker::S3Store::new(&format!("http://{s3}"), "mailblobs", "test-access", "test-secret")?),
                master_url,
            )?.with_database(setjoin_pg::workers::WorkerDatabase::new(&db.dsn).map_err(|e| e.to_string())?);
            Ok::<_,String>(Arc::new(if let Some(config)=migration_config {runtime.with_migration_config(config)}else{runtime}))
        }.map_err(|e| e.to_string())?);
        *runtime_to_stop.lock().unwrap() = storage_runtime.clone();
        let adapter = Probe {
            inner: PlatformJobsRoute { exec, worker, storage: storage_runtime, keys: Arc::new(common::recovery_keys()), issuer: "mailserver".into() },
            changed_status: mutant,
            cancel_only: action=="storage-migration-cancel",
        };
        let mut inventory: Value = serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().ok_or("routes")? {
            if r["family"] == "F08" && r["slice"] == "jobs-storage" {
                if recording {
                    r["state"] = json!("OFF");
                    r["upstream"] = json!("go-mail");
                } else {
                    assert_eq!(r["state"], "ON", "bundled jobs-storage ownership");
                    assert_eq!(r["upstream"], "local-rust");
                }
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
        if label=="cursor-error" {
            if let Ok(ledger)=std::env::var("GOFREE_RESOURCE_LEDGER") {
                use std::io::Write;
                writeln!(std::fs::OpenOptions::new().append(true).open(ledger)?,"Planned own-DB cursor fixture: temporary public.blobs view, gofree_plat3b_blobs rename and gofree_plat3b_scan_key function; restored before fixture deletion")?;
            }
        }
        for statement in &case.seed {
            owner.batch_execute(statement).await?;
        }
        capture.store(matches!(label,"one-run"|"backup-s3-http-io"|"backup-s3-env-region"|"oss-scope"),std::sync::atomic::Ordering::SeqCst);
        let mut concrete = case.pattern.to_owned();
        for value in &case.fill {
            let open = concrete.find('{').ok_or("no placeholder left")?;
            let close = concrete[open..].find('}').ok_or("unclosed placeholder")? + open;
            concrete.replace_range(open..=close, value);
        }
        if action=="storage-migration-cancel"&&matches!(label,"success"|"scoped"|"repeat"|"drain-timeout") {
            // #539: starting a migration needs an organization-wide grant. The scoped case
            // borrows one only for the fixture start; it is gone before the cancel is observed.
            let fixture_role = format!("plat3-fixture-{}", a.user);
            if label=="scoped" {
                owner.execute("INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,$2,NULL)", &[&fixture_role, &vec!["system.config"]]).await?;
                owner.execute("INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by,eligible) SELECT $1,id,$1,false FROM admin_role_groups WHERE name=$2", &[&a.user, &fixture_role]).await?;
            }
            let started=common::send(address,Request::post("/api/admin/storage/migrate?target=posix")
                .header("host","mail.test").header("origin","http://mail.test")
                .header("authorization",format!("Bearer {}",admin_token(a.user)))
                .body(common::full(""))?).await;
            if label=="scoped" {
                owner.execute("DELETE FROM admin_role_assignments WHERE role_group_id IN (SELECT id FROM admin_role_groups WHERE name=$1)", &[&fixture_role]).await?;
                owner.execute("DELETE FROM admin_role_groups WHERE name=$1", &[&fixture_role]).await?;
            }
            if started.status()!=202 {return Err("cancel fixture could not start migration".into());}
            let _=common::body_bytes(started).await;
            if let Some(blocked)=&blocked_target {
                tokio::time::timeout(std::time::Duration::from_secs(20),async {
                    loop {
                        let ready=if let Some(go)=&go {go.has_open_file(&blocked.container_path)?}else{blocked.reader_present()?};
                        if ready {return Ok::<_,BoxError>(());}
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                }).await.map_err(|_|"migration did not open blocked target")??;
            } else {
            tokio::time::timeout(std::time::Duration::from_secs(15),async {
                while !source_waiting.load(std::sync::atomic::Ordering::SeqCst) {tokio::time::sleep(std::time::Duration::from_millis(10)).await;}
            }).await.map_err(|_|"migration did not reach source I/O")?;
            }
        }
        if label=="native-closed" {
            if recording{return Err("native lifecycle regression is not a Go recording".into());}
            let runtime={runtime_to_stop.lock().unwrap().clone()};
            runtime.unwrap().shutdown().await;
        }
        if label=="orphan" {
            let runtime={runtime_to_stop.lock().unwrap().clone()};
            if let Some(runtime)=runtime{runtime.recover().await;}
        }
        let effects = async |c: &tokio_postgres::Client| -> Result<Value, BoxError> {
            Ok(json!(super::rows(c, case.effects).await?))
        };
        if label == "repeat" {
            let uri = format!("/api{concrete}{}", case.query);
            let mut request = Request::builder()
                .method(case.method)
                .uri(uri)
                .header("host", "mail.test")
                .header("origin", "http://mail.test")
                .header("content-type", "application/json")
                .header("x-request-id", "gofree-plat3-oracle")
                .header("authorization", format!("Bearer {}", admin_token(a.user)));
            for (name, value) in &case.headers {
                request = request.header(*name, value.as_str());
            }
            let first = common::send(address, request.body(common::full(sent_body.clone()))?).await;
            let first_status = first.status().as_u16();
            let data = common::body_bytes(first).await;
            if recording && !(200..300).contains(&first_status) {
                return Err(format!("initial {action}: {first_status} {data:?}").into());
            }
        }
        if action=="storage-migration-start" && label=="repeat" { wait_migrations(&owner).await?; }
        if action == "storage-dr-start" && label == "repeat" {
            wait_scans(&owner).await?;
        }
        let before = effects(&owner).await?;
        let last: i64 = owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[]).await?.get(0);
        let mut listeners = vec![];
        for channel in &case.channels {
            listeners.push((*channel, db.listen(channel).await?));
        }
        let uri = format!("/api{concrete}{}", case.query);
        let build = || -> Result<Request<Body>, BoxError> {
            let mut request = Request::builder()
                .method(case.method)
                .uri(uri.clone())
                .header("host", "mail.test")
                .header("origin", "http://mail.test")
                .header("content-type", "application/json")
                .header("x-request-id", "gofree-plat3-oracle")
                .header("authorization", format!("Bearer {}", admin_token(a.user)));
            for (name, value) in &case.headers {
                request = request.header(*name, value.as_str());
            }
            Ok(request.body(common::full(sent_body.clone()))?)
        };
        let response = common::send(address, build()?).await;
        let status = response.status().as_u16();
        let mut headers = serde_json::Map::new();
        for name in response.headers().keys() {
            headers.insert(name.to_string(), json!(response.headers().get_all(name).iter().map(|v| v.to_str().unwrap().to_owned()).collect::<Vec<_>>()));
        }
        let raw = String::from_utf8(common::body_bytes(response).await.to_vec())?;
        let cancel_phase=if let Some(blocked)=&blocked_target {
            let rows=super::rows(&owner,case.effects).await?;
            let in_flight=if let Some(go)=&go {go.has_open_file(&blocked.container_path)?}else{blocked.reader_present()?};
            blocked.release()?;
            wait_migrations(&owner).await?;
            Some(json!({"rows":rows,"in_flight":in_flight}))
        }else{None};
        // The scoped cancel is refused, so the migration keeps running and copies the blob as soon
        // as the held source is released. The recorded state is the one before that release;
        // reading the directory after it races the copy.
        let held_target = if action=="storage-migration-cancel" && label=="scoped" { migration_target.as_ref().map(|t| t.snapshot()).transpose()? } else { None };
        if action=="storage-migration-cancel" {source_release.notify_waiters();}
        if action=="storage-migration-start" && status==202 { wait_migrations(&owner).await?; }
        if action == "storage-dr-start" && status == 202 { wait_scans(&owner).await?; }
        let after = effects(&owner).await?;
        let mut audit: Vec<Value> = owner
            .query("SELECT to_jsonb(a)::text FROM admin_audit_log a WHERE id>$1 ORDER BY id", &[&last])
            .await?
            .iter()
            .map(|r| serde_json::from_str(&r.get::<_, String>(0)))
            .collect::<Result<_, _>>()?;
        for row in &mut audit {
            if row["id"].as_i64().is_none_or(|n| n <= 0) {
                return Err("invalid audit id".into());
            }
            row["id"] = json!("<audit>");
            for key in ["checksum", "prev_checksum"] {
                if row[key].as_str().is_some_and(|s| !s.is_empty()) {
                    row[key] = json!("<checksum>");
                }
            }
            *row = masked(row.clone(), &users, &names)?;
        }
        let mut notify = vec![];
        for (channel, listener) in &mut listeners {
            for event in listener.drain(&owner).await? {
                let payload = serde_json::from_str::<Value>(&event).unwrap_or(json!(event));
                notify.push(json!({"channel":channel,"payload":masked(payload, &users, &names)?}));
            }
        }
        if recording && case.status != 0 && status != case.status {
            return Err(format!("Go {action}/{label}: expected {}, got {status}: {raw}", case.status).into());
        }
        let mut text = names(&raw);
        for (from, to) in &case.replace {
            text = text.replace(from.as_str(), to);
        }
        text = pin_load_values(&text);
        if let Some(date) = headers.get_mut("date") {
            *date = json!(["<timestamp>"]);
        }
        if let Some(length) = headers.get_mut("content-length") {
            *length = json!([text.len().to_string()]);
        }
        let (before, after) = (masked(before, &users, &names)?, masked(after, &users, &names)?);
        let effects = json!([{"table":case.table,"before":before,"after":after}]);
        let mut req = json!({"method":case.method,"path":case.pattern,"external_path":format!("/api{concrete}")});
        if !case.body.is_empty() {
            req["body"] = json!(names(&case.body));
        }
        if !case.query.is_empty() {
            req["query"] = json!(case.query);
        }
        if !wire_errors.lock().unwrap().is_empty(){return Err(format!("invalid S3 authentication: {:?}",wire_errors.lock().unwrap()).into());}
        let mut observation = json!({"request":req,"response":{"status":status,"headers":headers,"body":text},"effects":effects,"audit":audit,"notify":notify});
        if let Some(target)=&migration_target {
            // The cancelled copy drops its staged write (which removes the `.tmp-*` file) just
            // after the status flips, so let that finish before the directory is read; a file
            // that is never removed still fails the comparison.
            for _ in 0..200 {
                if held_target.is_some() || !target.has_staged_temp() {break;}
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            observation["target_objects"]=match held_target { Some(held) => held, None => target.snapshot()? };
        }
        if let Some(phase)=cancel_phase {observation["cancel_phase"]=phase;}
        if matches!(label,"one-run"|"backup-s3-http-io"|"backup-s3-env-region"|"oss-scope") {observation["outbound"]=json!(*wire.lock().unwrap());}
        if !recording {
            let metrics = common::send(address, Request::get("/_gateway/metrics").body(common::full(""))?).await;
            let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            if !metrics.lines().any(|l| l == "setjoin_gateway_proxied_to_go_by_family_total{family=\"F08\"} 0") {
                return Err(format!("F08 replay forwarded to Go: {metrics}").into());
            }
        }
        server.abort();
        if label=="native-closed" {
            if status!=503||before!=after||serde_json::from_str::<Value>(&raw)?["detail"]!="migration admission is closed — service shutdown in progress" {
                return Err(format!("closed admission accepted work: {observation}").into());
            }
            eprintln!("NATIVE-CHECK: storage migration closed admission");
            return Ok(());
        }
        if let Some((_, task)) = master { task.abort(); }
        let stem = format!("{action}-{label}");
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/platform/goldens");
        std::fs::create_dir_all(&dir)?;
        let file = dir.join(format!("{stem}.json"));
        let row_file = dir.join(format!("{stem}-row-effects.json"));
        let route_name = format!("{} {}", case.method, case.pattern);
        if recording {
            let source = std::env::var("GOFREE_GO_SOURCE")?;
            let document=json!({"format":1,"route":route_name,"case":label,"go_source":source,"observation":observation});
            if action=="storage-status"&&label=="multi"&&std::env::var_os("GOFREE_VERIFY_GO").is_some() {
                let mut expected:Value=serde_json::from_slice(&std::fs::read(&file)?)?;
                let mut actual=document;
                order_review(&mut expected["observation"])?;
                order_review(&mut actual["observation"])?;
                golden::compare(&expected,&actual)?;
            } else {record(&file,&document)?;}
            if case.method == "POST" {
                record(&row_file, &json!({"format":1,"route":route_name,"case":format!("{label}-row-effects"),"go_source":source,"effects":observation["effects"]}))?;
            }
        } else {
            // A baseline pinned in platform/divergences.json is an owner-approved security fix:
            // it replays against the reviewed expectation under platform/security/.
            let mut expected: Value = if common::is_pinned(&file) {
                common::golden_doc(&file, "observation", &observation)
            } else {
                serde_json::from_slice(&std::fs::read(&file)?)?
            };
            if let Some(body) = expected["observation"]["response"]["body"].as_str() {
                expected["observation"]["response"]["body"] = json!(pin_load_values(body));
            }
            if action=="storage-status"&&label=="multi" {
                order_review(&mut expected["observation"])?;
                order_review(&mut observation)?;
            }
            let compared = golden::compare(&expected["observation"], &observation);
            if mutant {
                let error = compared.err().ok_or("planted status mutant survived")?;
                if !error.contains("/response/status") {
                    return Err(format!("mutant failed outside response status: {error}").into());
                }
                eprintln!("MUTANT-REJECTED: {route_name} :: changed-status");
                return Ok(());
            }
            compared?;
            if case.method == "POST" {
                let expected: Value = if common::is_pinned(&row_file) {
                    common::golden_doc(&row_file, "effects", &observation["effects"])
                } else {
                    serde_json::from_slice(&std::fs::read(row_file)?)?
                };
                golden::compare(&expected["effects"], &observation["effects"])?;
            }
            eprintln!("GOLDEN-REPLAY: {route_name} :: {label}");
        }
        Ok::<_, BoxError>(())
    }
    .await;
    source_release.notify_waiters();
    if let Some(blocked)=&blocked_target {blocked.release()?;}
    let runtime = runtime_to_stop.lock().unwrap().take();
    if let Some(runtime) = runtime { runtime.shutdown().await; }
    for statement in &case.cleanup {
        owner.batch_execute(statement).await?;
    }
    owner.execute("DELETE FROM rust_operation_receipts WHERE family='F08' AND operation_id::text<>ALL($1)", &[&receipts]).await?;
    owner.execute("DELETE FROM admin_role_assignments WHERE user_id=$1", &[&a.user]).await?;
    owner.execute("DELETE FROM admin_role_groups WHERE name=$1", &[&role]).await?;
    for account in [&a, &b] {
        common::remove_blob_account(&owner, account).await?;
    }
    owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE id>{audit_start}; COMMIT;")).await?;
    result
}

async fn wait_scans(owner: &tokio_postgres::Client) -> Result<(), BoxError> {
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            let active: bool = owner.query_one("SELECT EXISTS(SELECT 1 FROM storage_dr_scans WHERE status='running')", &[]).await?.get(0);
            if !active { return Ok::<_, BoxError>(()); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }).await.map_err(|_| "storage scan did not finish")?
}

struct MigrationTarget(std::path::PathBuf);
impl MigrationTarget {
    fn new(user:i64) -> Result<Self,BoxError> {
        use std::os::unix::fs::DirBuilderExt;
        let path=std::env::temp_dir().join(format!("gofree-plat3b-target-{}-{user}",std::process::id()));
        if let Ok(ledger)=std::env::var("GOFREE_RESOURCE_LEDGER") {
            use std::io::Write;
            writeln!(std::fs::OpenOptions::new().append(true).open(ledger)?,"Planned owned migration target {} (remove on Drop)",path.display())?;
        }
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
    fn seed(&self,bytes:&[u8])->Result<(),BoxError> {
        use std::os::unix::fs::OpenOptionsExt;
        use std::io::Write;
        let key=setjoin_backup::digest(b"blob");
        let root=self.0.join("mailblobs").join(&key[..2]);
        std::fs::create_dir_all(&root)?;
        let mut file=std::fs::OpenOptions::new().create_new(true).write(true).mode(0o600).open(root.join(key))?;
        file.write_all(bytes)?;
        Ok(())
    }
    fn has_staged_temp(&self) -> bool {
        let Ok(shards)=std::fs::read_dir(self.0.join("mailblobs")) else {return false};
        shards.flatten().any(|shard| std::fs::read_dir(shard.path()).is_ok_and(|entries| entries.flatten().any(|e| e.file_name().to_string_lossy().starts_with(".tmp-"))))
    }
    fn snapshot(&self) -> Result<Value,BoxError> {
        use std::os::unix::fs::PermissionsExt;
        let mut objects=vec![];
        let root=self.0.join("mailblobs");
        if !root.exists() {return Ok(json!([]));}
        for shard in std::fs::read_dir(root)? {
            for entry in std::fs::read_dir(shard?.path())? {
                let path=entry?.path();
                use std::os::unix::fs::FileTypeExt;
                if std::fs::metadata(&path)?.file_type().is_fifo() {
                    objects.push(json!({"key":path.file_name().unwrap().to_str().unwrap(),"kind":"fifo","mode":std::fs::metadata(&path)?.permissions().mode()&0o777}));
                    continue;
                }
                let bytes=std::fs::read(&path)?;
                objects.push(json!({"key":path.file_name().unwrap().to_str().unwrap(),"bytes":String::from_utf8(bytes)?,"mode":std::fs::metadata(&path)?.permissions().mode()&0o777}));
            }
        }
        objects.sort_by_key(Value::to_string);
        Ok(json!(objects))
    }
}
impl Drop for MigrationTarget { fn drop(&mut self) { let _=std::fs::remove_dir_all(&self.0); } }
async fn wait_migrations(owner:&tokio_postgres::Client) -> Result<(),BoxError> {
    tokio::time::timeout(std::time::Duration::from_secs(20),async {
        loop {
            let active:bool=owner.query_one("SELECT EXISTS(SELECT 1 FROM storage_migrations WHERE status IN('dual_write','backfill'))",&[]).await?.get(0);
            if !active {return Ok::<_,BoxError>(());}
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }).await.map_err(|_|"storage migration did not finish")?
}

struct BlockedTarget {
    path:std::path::PathBuf,
    container_path:String,
    anchor:std::sync::Mutex<Option<std::fs::File>>,
}
impl BlockedTarget {
    fn new(target:&MigrationTarget)->Result<Self,BoxError> {
        use std::os::unix::process::CommandExt;
        let key=setjoin_backup::digest(b"blob");
        let root=target.0.join("mailblobs").join(&key[..2]);
        std::fs::create_dir_all(&root)?;
        let path=root.join(&key);
        let status=std::process::Command::new("mkfifo").arg0("gofree-plat3b-mkfifo").args(["-m","600"]).arg(&path).status()?;
        if !status.success(){return Err("could not create owned FIFO".into());}
        let anchor=std::fs::OpenOptions::new().read(true).write(true).open(&path)?;
        Ok(Self{path,container_path:format!("/gofree-plat3b-target/mailblobs/{}/{key}",&key[..2]),anchor:std::sync::Mutex::new(Some(anchor))})
    }
    fn reader_present(&self)->Result<bool,BoxError> {
        let count=std::fs::read_dir("/proc/self/fd")?.filter_map(Result::ok)
            .filter(|fd|std::fs::read_link(fd.path()).is_ok_and(|path|path==self.path)).count();
        Ok(count>=2)
    }
    fn release(&self)->Result<(),BoxError> {
        use std::io::Write;
        if let Some(mut file)=self.anchor.lock().unwrap().take(){file.write_all(b"blob")?;}
        Ok(())
    }
}
impl Drop for BlockedTarget {fn drop(&mut self){let _=self.release();}}

fn order_review(observation:&mut Value)->Result<(),BoxError> {
    let review:Value=serde_json::from_str(include_str!("../../../../tests/conformance/platform/storage-order-review.json"))?;
    if review["reviewed"]!=true||review["route"]!="GET /admin/storage/status"||review["case"]!="multi" {
        return Err("storage topology order comparison has no reviewed authority".into());
    }
    let raw=observation["response"]["body"].as_str().ok_or("missing status body")?;
    let mut body:Value=serde_json::from_str(raw)?;
    if format!("{}\n",setjoin_platform::config::go_any(&body))!=raw {return Err("status JSON encoding changed beyond array ordering".into());}
    let topology=body["topology"].as_array_mut().ok_or("missing topology entries")?;
    for center in topology.iter_mut() {
        center["racks"].as_array_mut().ok_or("missing racks")?.sort_by_key(Value::to_string);
    }
    topology.sort_by_key(Value::to_string);
    body["volumes"].as_array_mut().ok_or("missing volumes")?.sort_by_key(Value::to_string);
    observation["response"]["body"]=json!(format!("{}\n",setjoin_platform::config::go_any(&body)));
    Ok(())
}
