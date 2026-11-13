//! #266: real front-door requests and committed effects, recorded once from Go.
mod common;
use common::BoxError;
use http_body_util::BodyExt;
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::harness::Db;
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};

/// Per-file serial guard (#362). Every case snapshots the global
/// `admin_audit_log` window (`id > max(id)` before the request) and its
/// cleanup deletes the shared `chat-oracle@test` denial rows, so parallel
/// cases would observe or remove each other's audits. The cargo workspace and
/// the other test binaries keep their normal parallelism.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The gateway adapter falls back to a Go forward when a scoped read hits its
/// 1 s pool wait / 2 s statement default, which happens on a CPU-starved shared
/// host and masquerades as a parity failure (#368). Only the deadlines are
/// widened; every assertion is unchanged.
fn loaded_host_exec(dsn: &str) -> Result<setjoin_pg::ScopedExecutor, BoxError> {
    let patient = std::time::Duration::from_secs(30);
    Ok(setjoin_pg::ScopedExecutor::from_dsn_with(
        dsn,
        1,
        setjoin_pg::Timeouts {
            pool_wait: patient,
            create: patient,
            statement: patient,
        },
    )
    .map_err(|e| e.0)?)
}

#[tokio::test]
async fn hold_success() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("hold", "success", false).await
}

#[tokio::test]
async fn hold_foreign() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("hold", "foreign", false).await
}

#[tokio::test]
async fn hold_invalid() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("hold", "invalid", false).await
}

#[tokio::test]
async fn hold_repeat() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("hold", "repeat", false).await
}

#[tokio::test]
async fn retention_success() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("retention", "success", false).await
}

#[tokio::test]
async fn retention_foreign() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("retention", "foreign", false).await
}

#[tokio::test]
async fn retention_invalid() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("retention", "invalid", false).await
}

#[tokio::test]
async fn retention_repeat() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("retention", "repeat", false).await
}

#[tokio::test]
async fn classification_success() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("classification", "success", false).await
}

#[tokio::test]
async fn classification_foreign() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("classification", "foreign", false).await
}

#[tokio::test]
async fn classification_invalid() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("classification", "invalid", false).await
}

#[tokio::test]
async fn classification_repeat() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("classification", "repeat", false).await
}

#[tokio::test]
async fn list_success() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("list", "success", false).await
}

#[tokio::test]
async fn list_foreign() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("list", "foreign", false).await
}

#[tokio::test]
async fn list_invalid() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("list", "invalid", false).await
}

#[tokio::test]
async fn list_repeat() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("list", "repeat", false).await
}

#[tokio::test]
async fn audit_success() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("audit", "success", false).await
}

#[tokio::test]
async fn audit_foreign() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("audit", "foreign", false).await
}

#[tokio::test]
async fn audit_invalid() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("audit", "invalid", false).await
}

#[tokio::test]
async fn audit_repeat() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("audit", "repeat", false).await
}

#[tokio::test]
async fn verify_success() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("verify", "success", false).await
}

#[tokio::test]
async fn verify_foreign() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("verify", "foreign", false).await
}

#[tokio::test]
async fn verify_invalid() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("verify", "invalid", false).await
}

#[tokio::test]
async fn hold_disabled() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("hold", "disabled", false).await
}

#[tokio::test]
async fn audit_csv() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("audit", "csv", false).await
}

#[tokio::test]
async fn hold_go_json() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("hold", "go-json", false).await
}

#[tokio::test]
async fn classification_bad_days() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("classification", "bad-days", false).await
}

#[tokio::test]
async fn classification_bad_worm() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("classification", "bad-worm", false).await
}

#[tokio::test]
async fn classification_federated() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("classification", "federated", false).await
}

#[tokio::test]
async fn hold_rejects_status() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let error = run("hold", "success", true)
        .await
        .expect_err("status mutant must differ");
    assert!(error.to_string().contains("/response/status"), "{error}");
    eprintln!("MUTANT-REJECTED: POST /admin/chat-channels/{{id}}/hold :: changed-status");
    Ok(())
}

#[tokio::test]
async fn retention_rejects_status() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let error = run("retention", "success", true)
        .await
        .expect_err("status mutant must differ");
    assert!(error.to_string().contains("/response/status"), "{error}");
    eprintln!("MUTANT-REJECTED: PUT /admin/chat-channels/{{id}}/retention :: changed-status");
    Ok(())
}

#[tokio::test]
async fn classification_rejects_status() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let error = run("classification", "success", true)
        .await
        .expect_err("status mutant must differ");
    assert!(error.to_string().contains("/response/status"), "{error}");
    eprintln!("MUTANT-REJECTED: POST /admin/chat-channels/{{id}}/classification :: changed-status");
    Ok(())
}

#[tokio::test]
async fn list_rejects_status() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let error = run("list", "success", true)
        .await
        .expect_err("status mutant must differ");
    assert!(error.to_string().contains("/response/status"), "{error}");
    eprintln!("MUTANT-REJECTED: GET /admin/chat-channels :: changed-status");
    Ok(())
}

#[tokio::test]
async fn audit_rejects_status() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let error = run("audit", "success", true)
        .await
        .expect_err("status mutant must differ");
    assert!(error.to_string().contains("/response/status"), "{error}");
    eprintln!("MUTANT-REJECTED: GET /admin/chat-channels/{{id}}/audit :: changed-status");
    Ok(())
}

#[tokio::test]
async fn verify_rejects_status() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let error = run("verify", "success", true)
        .await
        .expect_err("status mutant must differ");
    assert!(error.to_string().contains("/response/status"), "{error}");
    eprintln!("MUTANT-REJECTED: GET /admin/chat-channels/{{id}}/audit/verify :: changed-status");
    Ok(())
}

#[tokio::test]
async fn verify_broken() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("verify", "broken", false).await
}

#[tokio::test]
async fn verify_notarized() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("verify", "notarized", false).await
}

#[tokio::test]
async fn verify_truncated() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("verify", "truncated", false).await
}

#[tokio::test]
async fn verify_notary_mismatch() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("verify", "notary-mismatch", false).await
}

#[tokio::test]
async fn verify_anchors() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("verify", "anchors", false).await
}

#[tokio::test]
async fn hold_rollback() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("hold", "rollback", false).await
}

#[tokio::test]
async fn classification_rollback() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("classification", "rollback", false).await
}

#[tokio::test]
async fn list_audit_fault() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("list", "audit-fault", false).await
}

#[tokio::test]
async fn retention_pg_range() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("retention", "pg-range", false).await
}

#[tokio::test]
async fn hold_surrogate() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("hold", "surrogate", false).await
}

#[tokio::test]
async fn hold_unknown_number() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("hold", "unknown-number", false).await
}

#[tokio::test]
async fn hold_commit_after() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("hold", "commit-after", false).await
}

#[tokio::test]
async fn hold_commit_before() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("hold", "commit-before", false).await
}

#[tokio::test]
async fn classification_commit_after() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("classification", "commit-after", false).await
}

#[tokio::test]
async fn classification_commit_before() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("classification", "commit-before", false).await
}

#[tokio::test]
async fn classification_commit_knobs_after() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("classification", "commit-knobs-after", false).await
}

#[tokio::test]
async fn classification_commit_knobs_before() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("classification", "commit-knobs-before", false).await
}

#[tokio::test]
async fn hold_kill_switch() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("hold", "kill-switch", false).await
}

#[tokio::test]
async fn retention_kill_switch() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("retention", "kill-switch", false).await
}

#[tokio::test]
async fn classification_kill_switch() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("classification", "kill-switch", false).await
}

#[tokio::test]
async fn list_kill_switch() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("list", "kill-switch", false).await
}

#[tokio::test]
async fn audit_kill_switch() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("audit", "kill-switch", false).await
}

#[tokio::test]
async fn verify_kill_switch() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("verify", "kill-switch", false).await
}

#[tokio::test]
async fn hold_rejects_missing_audit() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let error = run_db_mutant("no-audit")
        .await
        .expect_err("missing audit must differ");
    assert!(error.to_string().contains("/effects/acts"), "{error}");
    eprintln!("MUTANT-REJECTED: POST /admin/chat-channels/{{id}}/hold :: no-audit");
    Ok(())
}

#[tokio::test]
async fn hold_rejects_double_bump() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let error = run_db_mutant("double-bump")
        .await
        .expect_err("extra state bumps must differ");
    assert!(
        error.to_string().contains("/effects/channel/changeSeq"),
        "{error}"
    );
    eprintln!("MUTANT-REJECTED: POST /admin/chat-channels/{{id}}/hold :: double-bump");
    Ok(())
}

#[tokio::test]
async fn hold_rejects_missing_actor_filter() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let error = run_db_mutant("no-tenant-filter")
        .await
        .expect_err("missing actor filter must differ");
    assert!(
        error.to_string().contains("/audit") || error.to_string().contains("/effects"),
        "{error}"
    );
    eprintln!("MUTANT-REJECTED: POST /admin/chat-channels/{{id}}/hold :: no-tenant-filter");
    Ok(())
}

#[tokio::test]
async fn list_offset_overflow() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("list", "offset-overflow", false).await
}

#[tokio::test]
async fn retention_gxp_floor() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("retention", "gxp-floor", false).await
}

#[tokio::test]
async fn hold_bad_json() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("hold", "bad-json", false).await
}

#[tokio::test]
async fn retention_bad_json() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("retention", "bad-json", false).await
}

#[tokio::test]
async fn classification_bad_json() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("classification", "bad-json", false).await
}

#[tokio::test]
async fn hold_encoded_id() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("hold", "encoded-id", false).await
}

#[tokio::test]
async fn inventory_kill_switches_preserve_all_six_requests_and_f12_counters() -> Result<(), BoxError>
{
    let _serial = SERIAL.lock().await;
    for route in [
        "hold",
        "retention",
        "classification",
        "list",
        "audit",
        "verify",
    ] {
        run(route, "inventory-kill-switch", false).await?;
    }
    Ok(())
}

fn token(user: i64) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let header =
        URL_SAFE_NO_PAD.encode(json!({"alg":"ES256","kid":"test-es256-1","typ":"JWT"}).to_string());
    let claims=URL_SAFE_NO_PAD.encode(json!({"uid":user,"email":"chat-oracle@test","admin":true,"perms":["chat.compliance_manage"],"typ":"access","jti":"chat1-test","fam":"chat1-test","iss":"mailserver","aud":["mailserver-gateway"],"iat":now-10,"exp":now+600}).to_string());
    let key = SigningKey::from_slice(&[0x11; 32]).unwrap();
    let sig: p256::ecdsa::Signature = key.sign(format!("{header}.{claims}").as_bytes());
    format!(
        "{header}.{claims}.{}",
        URL_SAFE_NO_PAD.encode(sig.to_bytes())
    )
}

async fn run(route: &str, case: &str, mutant: bool) -> Result<(), BoxError> {
    run_inner(route, case, mutant, None).await
}

async fn run_inner(
    route: &str,
    case: &str,
    mutant: bool,
    database_mutant: Option<&str>,
) -> Result<(), BoxError> {
    let (method, canonical) = match route {
        "hold" => ("POST", "/admin/chat-channels/{id}/hold"),
        "retention" => ("PUT", "/admin/chat-channels/{id}/retention"),
        "classification" => ("POST", "/admin/chat-channels/{id}/classification"),
        "list" => ("GET", "/admin/chat-channels"),
        "audit" => ("GET", "/admin/chat-channels/{id}/audit"),
        "verify" => ("GET", "/admin/chat-channels/{id}/audit/verify"),
        _ => unreachable!(),
    };
    let Some(db) = Db::for_case("chat1") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let (account, foreign) = principal_pair(&owner).await?;
    let role:i64=owner.query_one("INSERT INTO admin_role_groups(name,permissions) VALUES ($1,ARRAY['chat.compliance_view','chat.compliance_manage']) RETURNING id", &[&format!("chat1-{}",account.user)]).await?.get(0);
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id) VALUES ($1,$2)",
            &[&account.user, &role],
        )
        .await?;
    let toggle: Option<bool> = owner
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.chat_compliance'",
            &[],
        )
        .await?
        .map(|r| r.get(0));
    owner.execute("INSERT INTO feature_toggles(key,enabled) VALUES ('feature.chat_compliance',$1) ON CONFLICT(key) DO UPDATE SET enabled=$1",&[&(case!="disabled")]).await?;
    let channel_owner = if case == "foreign" {
        account.user
    } else {
        foreign.user
    };
    let channel:i64=owner.query_one("INSERT INTO chat_channels(kind,name,created_by) VALUES ('channel','chat1-oracle',$1) RETURNING id",&[&channel_owner]).await?.get(0);
    owner
        .execute(
            "INSERT INTO chat_channel_members(channel_id,user_id,role) VALUES ($1,$2,'owner')",
            &[&channel, &channel_owner],
        )
        .await?;
    if matches!(route, "audit" | "verify") {
        owner
            .execute(
                "SELECT chat_channel_set_hold($1,$2,true,$3)",
                &[
                    &account.user,
                    &channel,
                    &if matches!(case, "csv" | "csv-fault") {
                        "=SUM(1,2)"
                    } else {
                        "chat1-matter"
                    },
                ],
            )
            .await?;
    }
    if case == "federated" {
        owner
            .execute(
                "UPDATE chat_channels SET federated_room_id='chat1-room' WHERE id=$1",
                &[&channel],
            )
            .await?;
    }
    if case == "broken" {
        owner
            .execute(
                "UPDATE chat_audit_log SET notes='tampered' WHERE channel_id=$1",
                &[&channel],
            )
            .await?;
    }
    if matches!(case, "notarized" | "notary-row-fault") {
        notarize(&owner, channel, account.user, false).await?;
    }
    if case == "truncated" {
        notarize(&owner, channel, account.user, false).await?;
        owner
            .execute(
                "DELETE FROM chat_audit_log WHERE channel_id=$1",
                &[&channel],
            )
            .await?;
    }
    if case == "notary-mismatch" {
        notarize(&owner, channel, account.user, true).await?;
    }
    if case == "anchors" {
        owner.execute(r#"SELECT chat_access_audit($1,$2,'chain.anchor','channel',$2,NULL,'{"idFrom":1,"idTo":1,"count":1,"digest":"wrong-digest"}'::jsonb,NULL,NULL)"#,&[&account.user,&channel]).await?;
    }
    if case == "gxp-floor" {
        owner
            .execute(
                "UPDATE chat_channels SET retention_days=30,worm_mode='governance' WHERE id=$1",
                &[&channel],
            )
            .await?;
        owner
            .execute(
                "SELECT chat_channel_set_classification($1,$2,'gxp')",
                &[&account.user, &channel],
            )
            .await?;
    }
    let fault = if matches!(case, "rollback" | "audit-fault") {
        let name = format!("gofree_chat1_fault_{}", account.user);
        let table = if case == "audit-fault" {
            "admin_audit_log"
        } else {
            "chat_audit_log"
        };
        let predicate = if case == "audit-fault" {
            format!(
                "NEW.user_id={} AND NEW.action='chat_channel_admin_list'",
                account.user
            )
        } else {
            format!("NEW.channel_id={channel}")
        };
        record_resource(&format!(
            "Planned SQL fault function/trigger public.{name} on {table}, assigned fixture DB only"
        ))?;
        let sql=format!("BEGIN; CREATE FUNCTION public.{name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF {predicate} THEN RAISE EXCEPTION 'chat1 oracle audit fault'; END IF; RETURN NEW; END $$; CREATE TRIGGER {name} BEFORE INSERT ON public.{table} FOR EACH ROW EXECUTE FUNCTION public.{name}(); COMMIT;");
        if let Err(error) = owner.batch_execute(&sql).await {
            let _ = owner.batch_execute("ROLLBACK").await;
            return Err(error.into());
        }
        Some((name, table))
    } else {
        None
    };
    let knobs = case.starts_with("commit-knobs-");
    let (mut app_dsn, mut worker_dsn, mut cut_task) = if case.starts_with("commit-") {
        if std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some() {
            return Err("wire loss invariants do not run in recording mode".into());
        }
        record_resource("Planned gofree-chat1 PostgreSQL wire proxy, ephemeral loopback listener, assigned app DSN only")?;
        let (dsn, task) = common::commit::commit_cut_proxy(
            if knobs {
                &db.dsn
            } else {
                db.app.as_deref().unwrap_or(&db.dsn)
            },
            if case.ends_with("after") {
                common::commit::CommitCut::AfterCommit
            } else {
                common::commit::CommitCut::BeforeCommit
            },
        )
        .await;
        if knobs {
            (
                db.app.clone().unwrap_or_else(|| db.dsn.clone()),
                dsn,
                Some(task),
            )
        } else {
            (dsn, db.dsn.clone(), Some(task))
        }
    } else {
        (
            db.app.clone().unwrap_or_else(|| db.dsn.clone()),
            db.dsn.clone(),
            None,
        )
    };
    let mut mutant_schema = None;
    let result=async {
        if let Some(kind)=database_mutant{let(dsn,schema)=plant_mutant(&owner,&app_dsn,kind,account.user,foreign.user).await?;app_dsn=dsn;mutant_schema=Some(schema);}
        if matches!(case,"query-fault"|"csv-fault"|"verify-fault") {
            let schema=format!("gofree_chat1_query_{}",account.user);
            record_resource(&format!("Planned query fault schema {schema}, assigned DB only"))?;
            let signature=if case=="query-fault"{"chat_effective_retention(bigint) RETURNS integer"}else{"verify_chat_audit_chain(bigint) RETURNS TABLE(row_id bigint,valid boolean,occurred_at timestamptz,action text)"};
            owner.batch_execute(&format!("CREATE SCHEMA {schema}; GRANT USAGE ON SCHEMA {schema} TO PUBLIC; CREATE FUNCTION {schema}.{signature} LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'chat1 query fault'; END $$;")).await?;
            worker_dsn=format!("{}?options=-csearch_path%3D{schema}%2Cpublic",db.dsn);
            mutant_schema=Some(schema);
        }
        /* coverage query faults */
        if matches!(case,"parse-fault"|"read-fault"|"notary-fault"|"live-fault"|"notary-row-fault"|"anchor-parse-fault"|"anchor-fault") {
            let schema=format!("gofree_chat1_query_{}",account.user);
            record_resource(&format!("Planned {case} schema {schema}, assigned DB only"))?;
            let ddl;
            match case {
                "parse-fault"|"live-fault"=>ddl=format!("CREATE TABLE {schema}.{}(id bigint);",if route=="list"{"chat_channels"}else{"chat_audit_log"}),
                "notary-fault"=>ddl=format!("CREATE TABLE {schema}.admin_audit_log(id bigint);"),
                "anchor-parse-fault"=>ddl=format!("CREATE FUNCTION {schema}.chat_chain_anchor_verify(bigint) RETURNS integer LANGUAGE sql AS 'SELECT 1';"),
                "anchor-fault"=>ddl=format!("CREATE FUNCTION {schema}.chat_chain_anchor_verify(bigint) RETURNS TABLE(anchor_id bigint,id_from bigint,id_to bigint,valid boolean,reconciled_from_purge integer,revisions_unchained integer) LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'chat1 anchor fault'; END $$;"),
                "read-fault"|"notary-row-fault"=>{
                    let column=if case=="read-fault"{"notes"}else{"after_state"};let ty=if case=="read-fault"{"text"}else{"jsonb"};
                    let projection:String=owner.query_one("SELECT string_agg(CASE WHEN attname=$1 THEN $2::text ELSE quote_ident(attname) END,',' ORDER BY attnum) FROM pg_attribute WHERE attrelid='public.chat_audit_log'::regclass AND attnum>0 AND NOT attisdropped",&[&column,&format!("{schema}.fail({column}) AS {column}")]).await?.get(0);
                    ddl=format!("CREATE SEQUENCE {schema}.reads; CREATE FUNCTION {schema}.fail({ty}) RETURNS {ty} LANGUAGE plpgsql VOLATILE AS $$ BEGIN IF nextval('{schema}.reads')>{} THEN RAISE EXCEPTION 'chat1 read fault'; END IF; RETURN $1; END $$; CREATE VIEW {schema}.chat_audit_log AS SELECT {projection} FROM public.chat_audit_log;",if case=="read-fault"{0}else{1});
                },_=>unreachable!()
            }
            owner.batch_execute(&format!("BEGIN; CREATE SCHEMA {schema}; GRANT USAGE ON SCHEMA {schema} TO PUBLIC; {ddl} COMMIT;")).await?;
            worker_dsn=format!("{}?options=-csearch_path%3D{schema}%2Cpublic",db.dsn);mutant_schema=Some(schema);
        }
        let rollback=matches!(case,"kill-switch"|"inventory-kill-switch");
        let endpoint=common::fake_upstream(move |request|async move {
            if !rollback{return Response::new(common::full("unused"))}
            let method=request.method().to_string();let uri=request.uri().to_string();let body=request.into_body().collect().await.unwrap().to_bytes();
            Response::builder().status(418).header("x-gofree-chat1-go","yes").body(common::full(json!({"method":method,"uri":uri,"body":String::from_utf8_lossy(&body)}).to_string())).unwrap()
        }).await;
        let oracle_db=Db{dsn:worker_dsn.clone(),direct:db.direct.clone(),app:db.app.clone()};
        let oracle=common::go_oracle::start(&oracle_db,endpoint).await?;
        let recording=oracle.is_some();
        let mut listener=db.listen(&format!("chat:{}",foreign.user)).await?;
        let before:i64=owner.query_one("SELECT coalesce(max(id),0) FROM admin_audit_log",&[]).await?.get(0);
        let gateway=Gateway::new(Config{upstream:if rollback{Some(format!("http://{endpoint}").parse()?)}else{oracle.as_ref().map(|o|format!("http://{}",o.address).parse()).transpose()?},trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},if recording {RouteTable::proxy_all()}else{
            let adapter=setjoin_gateway::chat::ChatRoute{exec:loaded_host_exec(&app_dsn)?.with_audit_keys("22".repeat(32),String::new()),worker:loaded_host_exec(&worker_dsn)?.with_audit_keys("22".repeat(32),String::new()),keys:std::sync::Arc::new(common::recovery_keys()),issuer:"mailserver".into()};
            if mutant{RouteTable::proxy_all().with(ChangedStatus(adapter))}else{RouteTable::proxy_all().with(adapter)}
        })?.with_enabled(case!="kill-switch");
        let gateway=if case=="inventory-kill-switch" {
            let mut inventory:Value=serde_json::from_str(include_str!("../route-inventory.json"))?;
            for r in inventory["routes"].as_array_mut().unwrap() {
                if r["family"]=="F12" && r["slice"]=="golden-routes" {r["state"]="OFF".into();r["upstream"]="go-mail".into();}
            }
            gateway.with_inventory(&inventory.to_string())?
        }else{gateway};
        let listen=tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address=listen.local_addr()?;
        let server=tokio::spawn(gateway.serve(listen));
        let path=if case=="encoded-mount"{format!("/%61pi/%61dmin/%63hat-channels/{channel}/hold")}else if case=="invalid-query-utf8"{format!("/api/admin/chat-channels?userId={channel_owner}&q=%FF")}else if case=="encoded-bad-id"{"/api/admin/chat-channels/%5C/hold".into()}else if case=="bad-id"{format!("/api/admin/chat-channels/bad/{route}")}else if case=="encoded-id"{"/api/admin/chat-channels/%2F/hold".into()}else if route=="list"{if case=="invalid"{"/api/admin/chat-channels?userId=bad".into()}else{format!("/api/admin/chat-channels?userId={channel_owner}{}",if case=="offset-overflow"{"&offset=999999999999999999999999"}else{""})}}else if route=="verify"{if case=="invalid"{"/api/admin/chat-channels/bad/audit/verify".into()}else{format!("/api/admin/chat-channels/{channel}/audit/verify")}}else if route=="audit"&&matches!(case,"csv"|"csv-fault"){format!("/api/admin/chat-channels/{channel}/audit?format=csv")}else if route=="audit"&&case=="invalid"{format!("/api/admin/chat-channels/{channel}/audit?beforeId=bad")}else{format!("/api/admin/chat-channels/{channel}/{route}")};
        let body=if case=="bad-json"{"{"}else if case=="gxp-floor"{r#"{"retentionDays":5}"#}else if case=="unknown-number"{r#"{"on":true,"reason":"chat1-matter","future":1e400}"#}else if case=="surrogate"{r#"{"on":true,"reason":"\ud800"}"#}else if case=="pg-range"&&route=="classification"{r#"{"classification":"gxp","retentionDays":2147483648,"wormMode":"governance"}"#}else if case=="pg-range"{r#"{"retentionDays":2147483648}"#}else if case=="bad-worm"{r#"{"classification":"gxp","retentionDays":30,"wormMode":"unsupported"}"#}else if case=="bad-days"{r#"{"classification":"gxp","retentionDays":0,"wormMode":"governance"}"#}else if case=="go-json"{r#"{"ON":true,"on":null,"rea\u017fon":"chat1-matter","userId":0}"#}else if matches!(route,"list"|"audit"|"verify"){""}else if route=="classification"{if case=="invalid"{r#"{"classification":"regular","retentionDays":30,"wormMode":"governance"}"#}else{r#"{"classification":"gxp","retentionDays":30,"wormMode":"governance"}"#}}else if route=="retention"{if case=="invalid"{r#"{"retentionDays":0}"#}else{r#"{"retentionDays":30}"#}}else if case=="invalid"{r#"{"on":false}"#}else{r#"{"on":true,"reason":"chat1-matter"}"#};
        let wire_body=if case=="invalid-utf8" {let mut bytes=br#"{"on":true,"reason":""#.to_vec();bytes.extend_from_slice(&[0xe1,0x80]);bytes.extend_from_slice(br#""}"#);bytes}else{body.as_bytes().to_vec()};
        let mut first=if matches!(case,"repeat"|"request-ids") {
            let response=common::send(address,Request::builder().method(method).uri(&path).header("host","mail.test").header("origin","http://mail.test").header("authorization",format!("Bearer {}",token(account.user))).header("x-request-id",if case=="request-ids"{""}else{"chat1-oracle"}).header("content-type","application/json").body(common::full(wire_body.clone()))?).await;
            let status=response.status().as_u16();let mut headers=serde_json::Map::new();for(k,v) in response.headers(){if !matches!(k.as_str(),"date"|"content-length"){headers.insert(k.as_str().into(),v.to_str()?.into());}}
            let bytes=common::body_bytes(response).await;
            Some(json!({"status":status,"headers":headers,"body":if bytes.is_empty(){Value::Null}else{serde_json::from_slice::<Value>(&bytes)?}}))
        }else{None};
        let response=common::send(address,Request::builder().method(method).uri(&path).header("host","mail.test").header("origin","http://mail.test").header("authorization",format!("Bearer {}",token(if case=="foreign"{foreign.user}else{account.user}))).header("x-request-id",if case=="request-ids"{""}else{"chat1-oracle"}).header("content-type","application/json").body(common::full(wire_body.clone()))?).await;
        let status=response.status().as_u16();
        let mut headers=serde_json::Map::new();
        for (key,value) in response.headers() { if !matches!(key.as_str(),"date"|"content-length") {headers.insert(key.as_str().into(),value.to_str()?.into());}}
        if matches!(case,"csv"|"csv-fault"){let value=headers.get("content-disposition").and_then(Value::as_str).ok_or("CSV disposition missing")?;
            let date=value.strip_prefix(&format!("attachment; filename=chat-audit-{channel}-")).and_then(|v|v.strip_suffix(".csv")).ok_or("bad CSV disposition")?;
            if date.len()!=8||!date.bytes().all(|b|b.is_ascii_digit()){return Err("bad CSV date".into());}headers.insert("content-disposition".into(),"attachment; filename=chat-audit-<channel>-<date>.csv".into());}
        let bytes=common::body_bytes(response).await;
        if !recording&&!rollback{
            let response=common::send(address,Request::builder().uri("/_gateway/metrics").body(common::full(""))?).await;
            let metrics=String::from_utf8(common::body_bytes(response).await.to_vec())?;
            if !metrics.lines().any(|l|l=="setjoin_gateway_proxied_to_go_total 0")||!metrics.lines().any(|l|l=="setjoin_gateway_proxied_to_go_by_family_total{family=\"F12\"} 0"){return Err(format!("native Chat forwarded to Go: {metrics}").into());}
        }
        if case=="inventory-kill-switch" {
            let response=common::send(address,Request::builder().uri("/_gateway/metrics").body(common::full(""))?).await;
            let metrics=String::from_utf8(common::body_bytes(response).await.to_vec())?;
            if !metrics.lines().any(|l|l=="setjoin_gateway_proxied_to_go_total 1")||!metrics.lines().any(|l|l=="setjoin_gateway_proxied_to_go_by_family_total{family=\"F12\"} 1"){return Err(format!("Chat rollback did not count exactly one F12 Go forward: {metrics}").into());}
        }
        server.abort(); let _=server.await;
        if rollback {
            let echo:Value=serde_json::from_slice(&bytes)?;
            if status!=418||headers.get("x-gofree-chat1-go").and_then(Value::as_str)!=Some("yes")||echo["method"]!=method||echo["uri"]!=path||echo["body"]!=body{return Err("kill switch did not forward the original Chat request".into());}
            let audits:i64=owner.query_one("SELECT count(*) FROM admin_audit_log WHERE id>$1",&[&before]).await?.get(0);if audits!=0{return Err("kill switch ran native authorization/auditing".into());}
            return Ok(());
        }
        if case=="request-ids" {
            let first=first.as_ref().ok_or("first request missing")?;
            let a=first["headers"]["x-request-id"].as_str().ok_or("first request ID missing")?;
            let b=headers.get("x-request-id").and_then(Value::as_str).ok_or("second request ID missing")?;
            if first["status"]!=204||status!=204||a==b||a.len()!=36||b.len()!=36||a.as_bytes()[14]!=b'4'||b.as_bytes()[14]!=b'4'{return Err("requests without an inbound ID must receive distinct UUIDv4 IDs".into());}
            return Ok(());
        }
        if case.starts_with("commit-") {
            if status!=503{return Err(format!("unknown COMMIT must return 503, got {status}").into());}
            let operation=headers.get("x-operation-id").and_then(Value::as_str).ok_or("unknown COMMIT omitted lookup ID")?;
            if operation.len()!=32||!operation.bytes().all(|b|b.is_ascii_hexdigit()){return Err("invalid lookup ID".into());}
            let mut id=[0;16];for(i,byte)in id.iter_mut().enumerate(){*byte=u8::from_str_radix(&operation[i*2..i*2+2],16)?;}
            let cut=tokio::time::timeout(std::time::Duration::from_secs(10),cut_task.take().ok_or("wire proxy missing")?).await???;
            let committed=cut==common::commit::CommitCut::AfterCommit;
            let auth=setjoin_pg::MailboxAuthContext::from_authenticated_session(setjoin_contracts::ids::ActorId::new(account.user).unwrap(),setjoin_contracts::ids::MailboxId::new(account.mailbox).unwrap(),setjoin_contracts::ids::Generation(1));
            let exec=setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),1).map_err(|e|e.0)?;
            let found=setjoin_pg::lookup_command(&exec,&auth,setjoin_contracts::ids::OperationId(id),setjoin_pg::ReceiptCommand{family:"F12",command:if route=="classification"{if knobs{"classification.knobs"}else{"chat_channel_set_classification"}}else{"chat_channel_set_hold"}}).await.map_err(|e|format!("receipt lookup: {:?}",e.sqlstate))?;
            if (found==setjoin_pg::OperationLookup::Committed)!=committed{return Err("lookup disagrees with the actual COMMIT cut".into());}
            if route=="hold"{
                let row=owner.query_one("SELECT legal_hold,(SELECT count(*) FROM chat_audit_log WHERE channel_id=$1) FROM chat_channels WHERE id=$1 AND created_by=$2",&[&channel,&channel_owner]).await?;
                if row.get::<_,bool>(0)!=committed||row.get::<_,i64>(1)!=if committed{1}else{0}{return Err("commit-loss effects changed or repeated".into());}
            }else{
                let row=owner.query_one("SELECT classification,retention_days,worm_mode,(SELECT count(*) FROM chat_audit_log WHERE channel_id=$1) FROM chat_channels WHERE id=$1 AND created_by=$2",&[&channel,&channel_owner]).await?;
                let changed=!knobs&&committed;let preset=!knobs||committed;
                if row.get::<_,String>(0)!=if changed{"gxp"}else{"regular"}||row.get::<_,Option<i32>>(1)!=if preset{Some(30)}else{None}||row.get::<_,Option<String>>(2).as_deref()!=if preset{Some("governance")}else{None}||row.get::<_,i64>(3)!=if changed{1}else{0}{return Err("classification commit boundary changed or repeated effects".into());}
            }
            record_resource("Reaped gofree-chat1 PostgreSQL wire proxy; receipt lookup resolved without replay")?;
            return Ok(());
        }
        let mut response_body=if bytes.is_empty(){Value::Null}else{serde_json::from_slice(&bytes).unwrap_or(json!(String::from_utf8_lossy(&bytes)))};
        if let Some(instance)=response_body.get_mut("instance"){*instance=instance.as_str().unwrap().replace(&format!("/{channel}/"),"/{id}/").into();}
        if route=="list" {
            let email:String=owner.query_one("SELECT email FROM users WHERE id=$1",&[&channel_owner]).await?.get(0);
            if !(case=="offset-overflow"&&response_body.as_array().is_some_and(|a|a.is_empty())){normalize_list(&mut response_body,channel,channel_owner,&email)?;}
            if let Some(first)=first.as_mut(){normalize_list(&mut first["body"],channel,channel_owner,&email)?;}
        }
        if matches!(case,"csv"|"csv-fault"){normalize_csv(&mut response_body,channel,account.user)?;}
        if route=="audit"&&!matches!(case,"csv"|"csv-fault"){normalize_audit(&owner,&mut response_body,channel,account.user).await?;if let Some(first)=first.as_mut(){normalize_audit(&owner,&mut first["body"],channel,account.user).await?;}}
        if route=="verify"{normalize_verify(&owner,&mut response_body,channel).await?;}
        let row:String=owner.query_one("SELECT jsonb_build_object('classification',classification,'retentionDays',retention_days,'wormMode',worm_mode,'legalHold',legal_hold,'legalHoldReason',legal_hold_reason,'changeSeq',change_seq,'lastPurgedSeq',last_purged_seq)::text FROM chat_channels WHERE id=$1",&[&channel]).await?.get(0);
        let verified:bool=owner.query_one("SELECT coalesce(bool_and(valid),true) FROM verify_chat_audit_chain($1)",&[&channel]).await?.get(0);
        let acts:String=owner.query_one("SELECT coalesce(jsonb_agg(jsonb_build_object('id',id,'userId',CASE WHEN user_id=$2 THEN 'admin' ELSE 'foreign' END,'action',action,'targetType',target_type,'targetId',CASE WHEN target_id=$1 THEN 'channel' ELSE target_id::text END,'before',before_state,'after',after_state-'_checksum'-'_prev_checksum','notes',notes) ORDER BY id),'[]')::text FROM chat_audit_log WHERE channel_id=$1",&[&channel,&account.user]).await?.get(0);
        let audit:String=owner.query_one("SELECT coalesce(jsonb_agg(jsonb_build_object('action',action,'targetType',target_type,'targetId',CASE WHEN target_id=$1 THEN 'channel' ELSE target_id::text END,'before',before_state,'after',after_state,'notes',notes,'ip',host(ip)) ORDER BY id),'[]')::text FROM admin_audit_log WHERE id>$2",&[&channel,&before]).await?.get(0);
        let mut audit:Value=serde_json::from_str(&audit)?;
        for a in audit.as_array_mut().unwrap(){if let Some(target)=a.pointer_mut("/before/target"){*target=target.as_str().unwrap().replace(&format!("/{channel}/"),"/{id}/").into();}}
        let mut observation=json!({"request":{"method":method,"path":canonical,"body":if case=="invalid-utf8"{use base64::Engine;json!({"encoding":"base64","data":base64::engine::general_purpose::STANDARD.encode(&wire_body)})}else{json!(body)}},"response":{"status":status,"headers":headers,"body":response_body},"effects":{"chainValid":verified,"channel":serde_json::from_str::<Value>(&row)?,"acts":serde_json::from_str::<Value>(&acts)?},"audit":audit,"notify":listener.drain(&owner).await?});
        if let Some(first)=first {observation["firstResponse"]=first;}
        let path=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/conformance/chat/goldens/{route}-{case}.json"));
        if recording {
            if status!=expected_status(route,case) {return Err(format!("unexpected Go response: {observation:#}").into());}
            let row_path=path.with_file_name(format!("{route}-{case}-row-effects.json"));
            setjoin_conformance::golden::record(&row_path,&json!({"format":1,"route":format!("{method} {canonical}"),"case":format!("{route}-{case}-row-effects"),"go_source":std::env::var("GOFREE_GO_SOURCE")?,"effects":[observation["effects"].clone(),observation["audit"].clone(),observation["notify"].clone()]}))?;
            setjoin_conformance::golden::record(&path,&json!({"format":1,"route":format!("{method} {canonical}"),"case":format!("{route}-{case}"),"go_source":std::env::var("GOFREE_GO_SOURCE")?,"normalization":["fixture actor/channel IDs","audit chain checksum (verified independently)","generated timestamps"],"observation":observation}))?;
        } else {
            if !mutant && database_mutant.is_none() && status != expected_status(route,case) { return Err(format!("expected hold success (204), received {status}: {observation}").into()); }
            if database_mutant==Some("no-tenant-filter")&&(status!=204||observation["effects"]["channel"]["legalHold"]!=true||observation["effects"]["acts"][0]["userId"]!="foreign"){return Err("actor-filter mutant did not produce the unauthorized foreign write".into());}
            let mut expected:Value=serde_json::from_slice(&std::fs::read(&path)?)?;
            normalize_notes(&mut expected);
            let mut observation=observation;normalize_notes(&mut observation);
            setjoin_conformance::golden::compare(&expected["observation"],&observation)?;
            let mut rows:Value=serde_json::from_slice(&std::fs::read(path.with_file_name(format!("{route}-{case}-row-effects.json")))?)?;
            normalize_notes(&mut rows);
            setjoin_conformance::golden::compare(&rows["effects"],&json!([observation["effects"],observation["audit"],observation["notify"]]))?;
            eprintln!("GOLDEN-REPLAY: {method} {canonical} :: {route}-{case}");
        }
        drop(oracle);
        Ok::<_,BoxError>(())
    }.await;
    if let Some(schema) = mutant_schema {
        owner
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await?;
        record_resource(&format!("Removed mutant schema {schema}"))?;
    }
    if let Some(task) = cut_task {
        task.abort();
        let _ = task.await;
        record_resource("Aborted/reaped gofree-chat1 wire proxy after failed case")?;
    }
    if let Some((name, table)) = fault {
        owner
            .batch_execute(&format!(
                "DROP TRIGGER {name} ON public.{table}; DROP FUNCTION public.{name}();"
            ))
            .await?;
        record_resource(&format!("Removed SQL fault {name}"))?;
    }
    owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM chat_channel_members WHERE channel_id={channel}; DELETE FROM chat_audit_log WHERE channel_id={channel}; DELETE FROM chat_channels WHERE id={channel}; DELETE FROM admin_audit_log WHERE user_id={} OR (user_id IS NULL AND before_state->>'actor'='chat-oracle@test'); COMMIT;",account.user)).await?;
    owner
        .execute("DELETE FROM admin_role_groups WHERE id=$1", &[&role])
        .await?;
    if let Some(enabled) = toggle {
        owner
            .execute(
                "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.chat_compliance'",
                &[&enabled],
            )
            .await?;
    } else {
        owner
            .execute(
                "DELETE FROM feature_toggles WHERE key='feature.chat_compliance'",
                &[],
            )
            .await?;
    }
    remove_principal(&owner, &account).await?;
    remove_principal(&owner, &foreign).await?;
    result
}

// Only generated channel IDs in console audit URL notes. Preserve free text.
fn normalize_notes(v: &mut Value) {
    match v {
        Value::Object(m) => {
            for (k, v) in m.iter_mut() {
                if k == "notes" {
                    if let Some(path) = v.as_str() {
                        let parts: Vec<_> = path.split('/').collect();
                        if parts.len() >= 5
                            && parts[1] == "admin"
                            && parts[2] == "chat-channels"
                            && parts[3].parse::<i64>().is_ok()
                        {
                            *v = format!("/admin/chat-channels/{{id}}/{}", parts[4..].join("/"))
                                .into();
                        }
                    }
                } else {
                    normalize_notes(v)
                }
            }
        }
        Value::Array(a) => {
            for v in a {
                normalize_notes(v)
            }
        }
        _ => {}
    }
}

fn expected_status(route: &str, case: &str) -> u16 {
    if matches!(
        case,
        "invalid-query-utf8"
            | "query-fault"
            | "verify-fault"
            | "parse-fault"
            | "read-fault"
            | "notary-fault"
            | "live-fault"
            | "notary-row-fault"
            | "anchor-parse-fault"
            | "anchor-fault"
    ) {
        500
    } else if matches!(case, "encoded-id" | "encoded-mount") {
        404
    } else if matches!(case, "bad-json" | "bad-id" | "encoded-bad-id") {
        400
    } else if case == "gxp-floor" {
        409
    } else if matches!(case, "rollback" | "pg-range") {
        500
    } else if case == "federated" {
        422
    } else if matches!(case, "bad-days" | "bad-worm") {
        400
    } else if case == "disabled" {
        404
    } else if case == "foreign" {
        403
    } else if route == "classification" && case == "repeat" {
        422
    } else if case == "invalid" {
        if matches!(route, "classification" | "list" | "audit" | "verify") {
            400
        } else {
            422
        }
    } else if matches!(route, "list" | "audit" | "verify") {
        200
    } else {
        204
    }
}

fn normalize_list(body: &mut Value, channel: i64, user: i64, email: &str) -> Result<(), BoxError> {
    if let Some(rows) = body.as_array_mut() {
        if rows.len() != 1 {
            return Err("list must return the fixture channel".into());
        }
        for row in rows {
            if row["id"] != channel {
                return Err("foreign channel in list".into());
            }
            row["id"] = "<channel>".into();
            for p in row["participants"].as_array_mut().unwrap() {
                if p["userId"] != user || p["email"] != email {
                    return Err("unexpected participant".into());
                }
                p["userId"] = "<channel-owner>".into();
                p["email"] = "<channel-owner-email>".into();
            }
        }
    }
    Ok(())
}

async fn normalize_audit(
    owner: &tokio_postgres::Client,
    body: &mut Value,
    channel: i64,
    user: i64,
) -> Result<(), BoxError> {
    if let Some(rows) = body.as_array_mut() {
        for row in rows {
            let time = row["occurredAt"]
                .as_str()
                .ok_or("audit timestamp missing")?;
            chrono::DateTime::parse_from_rfc3339(time)?;
            row["occurredAt"] = "<time>".into();
            if row["userId"] != user || row["targetId"] != channel {
                return Err("audit provenance mismatch".into());
            }
            row["userId"] = "<admin>".into();
            row["targetId"] = "<channel>".into();
            let id = row["id"].as_i64().ok_or("audit ID missing")?;
            let checksum:String=owner.query_one("SELECT after_state->>'_checksum' FROM chat_audit_log WHERE channel_id=$1 AND id=$2",&[&channel,&id]).await?.get(0);
            if row["afterState"]["_checksum"] != checksum {
                return Err("audit checksum mismatch".into());
            }
            row["afterState"]["_checksum"] = "<checksum>".into();
        }
    }
    Ok(())
}

fn normalize_csv(body: &mut Value, channel: i64, user: i64) -> Result<(), BoxError> {
    let mut lines = body
        .as_str()
        .ok_or("CSV body missing")?
        .split('\n')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let meta = lines.first_mut().ok_or("CSV metadata missing")?;
    if let Some((prefix, time)) = meta.rsplit_once("verifiedAt=") {
        chrono::DateTime::parse_from_rfc3339(time)?;
        *meta = format!("{prefix}verifiedAt=<time>");
    }
    for line in lines.iter_mut().skip(2).filter(|l| !l.is_empty()) {
        let mut fields = line.splitn(8, ',').map(str::to_owned).collect::<Vec<_>>();
        if fields.len() != 8 {
            return Err("invalid CSV row".into());
        }
        chrono::DateTime::parse_from_rfc3339(&fields[1])?;
        if fields[2] != user.to_string() || fields[6] != channel.to_string() {
            return Err("CSV provenance mismatch".into());
        }
        fields[1] = "<time>".into();
        fields[2] = "<admin>".into();
        fields[6] = "<channel>".into();
        *line = fields.join(",");
    }
    *body = lines.join("\n").into();
    Ok(())
}

struct ChangedStatus<K: setjoin_authz::token::KeySource + 'static>(
    setjoin_gateway::chat::ChatRoute<K>,
);
impl<K: setjoin_authz::token::KeySource + 'static> setjoin_gateway::Intercept for ChangedStatus<K> {
    fn matches(&self, r: &hyper::Request<setjoin_gateway::Body>) -> bool {
        setjoin_gateway::Intercept::matches(&self.0, r)
    }
    fn handle(
        &self,
        r: hyper::Request<setjoin_gateway::Body>,
        c: setjoin_gateway::RequestContext,
    ) -> setjoin_gateway::BoxFuture<hyper::Response<setjoin_gateway::Body>> {
        let future = setjoin_gateway::Intercept::handle(&self.0, r, c);
        Box::pin(async move {
            let mut response = future.await;
            *response.status_mut() = hyper::StatusCode::NOT_IMPLEMENTED;
            response
        })
    }
}

async fn normalize_verify(
    owner: &tokio_postgres::Client,
    body: &mut Value,
    channel: i64,
) -> Result<(), BoxError> {
    if body.get("channelId").is_none() {
        return Ok(());
    }
    if body["channelId"] != channel {
        return Err("verification returned another channel".into());
    }
    body["channelId"] = "<channel>".into();
    chrono::DateTime::parse_from_rfc3339(
        body["verifiedAt"]
            .as_str()
            .ok_or("verification timestamp missing")?,
    )?;
    body["verifiedAt"] = "<time>".into();
    if body.get("liveHead").is_some() {
        let row=owner.query_one("SELECT id,after_state->>'_checksum' FROM chat_audit_log WHERE channel_id=$1 ORDER BY id DESC LIMIT 1",&[&channel]).await?;
        if body["liveHead"]["id"] != row.get::<_, i64>(0)
            || body["liveHead"]["checksum"] != row.get::<_, String>(1)
        {
            return Err("verification live head mismatch".into());
        }
        body["liveHead"]["checksum"] = "<checksum>".into();
    }
    if body.get("notarizedHead").is_some() {
        let raw:String=owner.query_one("SELECT (after_state->'heads'->$1::text)::text FROM admin_audit_log WHERE action='chat.chain_notary' ORDER BY id DESC LIMIT 1",&[&channel.to_string()]).await?.get(0);
        let head: Value = serde_json::from_str(&raw)?;
        if body["notarizedHead"] != head {
            return Err("verification notarized head mismatch".into());
        }
        body["notarizedHead"]["checksum"] = "<notary-checksum>".into();
    }
    Ok(())
}
async fn notarize(
    owner: &tokio_postgres::Client,
    channel: i64,
    user: i64,
    bad: bool,
) -> Result<(), BoxError> {
    let mut checksum: String = owner
        .query_one(
            "SELECT after_state->>'_checksum' FROM chat_audit_log WHERE channel_id=$1 AND id=1",
            &[&channel],
        )
        .await?
        .get(0);
    if bad {
        checksum = "wrong-notary-checksum".into();
    }
    let mut heads = serde_json::Map::new();
    heads.insert(channel.to_string(), json!({"id":1,"checksum":checksum}));
    let after = json!({"heads":heads}).to_string();
    owner.execute("SELECT audit_write($1,'chat.chain_notary','chat',NULL,NULL,$2::text::jsonb,NULL,'chat1-fixture','core')",&[&user,&after]).await?;
    Ok(())
}

fn record_resource(line: &str) -> Result<(), BoxError> {
    use std::io::Write;
    if let Ok(path) = std::env::var("GOFREE_RESOURCE_LEDGER") {
        writeln!(
            std::fs::OpenOptions::new().append(true).open(path)?,
            "{line}"
        )?;
    }
    Ok(())
}

async fn run_db_mutant(kind: &str) -> Result<(), BoxError> {
    run_inner(
        "hold",
        if kind == "no-tenant-filter" {
            "foreign"
        } else {
            "success"
        },
        false,
        Some(kind),
    )
    .await
}

async fn plant_mutant(
    owner: &tokio_postgres::Client,
    base: &str,
    kind: &str,
    user: i64,
    foreign: i64,
) -> Result<(String, String), BoxError> {
    let id: String = owner
        .query_one("SELECT replace(gen_random_uuid()::text,'-','')", &[])
        .await?
        .get(0);
    if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) || base.contains("options=") {
        return Err("invalid mutant schema/DSN".into());
    }
    let schema = format!("gofree_chat1_mutant_{id}");
    let mut definition:String=owner.query_one("SELECT pg_get_functiondef('public.chat_channel_set_hold(bigint,bigint,boolean,text)'::regprocedure)",&[]).await?.get(0);
    let original = "CREATE OR REPLACE FUNCTION public.chat_channel_set_hold(";
    if definition.matches(original).count() != 1 {
        return Err("mutant reducer signature moved".into());
    }
    definition = definition.replacen(
        original,
        &format!("CREATE OR REPLACE FUNCTION {schema}.chat_channel_set_hold("),
        1,
    );
    let mut setup = String::new();
    match kind {
        "no-audit" => {
            let start = definition
                .find("PERFORM chat_access_audit(")
                .ok_or("audit call moved")?;
            let end = start
                + definition[start..]
                    .find(';')
                    .ok_or("audit call incomplete")?
                + 1;
            definition.replace_range(start..end, "NULL;");
        }
        "double-bump" => {
            let marker = "BEGIN\n";
            if definition.matches(marker).count() != 1 {
                return Err("reducer body marker moved".into());
            }
            definition = definition.replacen(
                marker,
                "BEGIN\n UPDATE chat_channels SET change_seq=change_seq+2 WHERE id=p_channel_id;\n",
                1,
            );
        }
        "no-tenant-filter" => {
            // Make the role query's user predicate accept another principal,
            // preserving the verified token identity and app credential.
            let user_expr = format!(
                "CASE WHEN user_id={user} THEN {foreign}::bigint ELSE user_id END AS user_id"
            );
            let projection:String=owner.query_one("SELECT string_agg(CASE WHEN attname='user_id' THEN $1::text ELSE quote_ident(attname) END,',' ORDER BY attnum) FROM pg_attribute WHERE attrelid='public.admin_role_assignments'::regclass AND attnum>0 AND NOT attisdropped",&[&user_expr]).await?.get(0);
            setup=format!("CREATE VIEW {schema}.admin_role_assignments AS SELECT {projection} FROM public.admin_role_assignments; GRANT SELECT ON {schema}.admin_role_assignments TO PUBLIC;");
        }
        _ => return Err("unsupported database mutant".into()),
    }
    record_resource(&format!(
        "Planned {kind} mutant schema {schema}, assigned fixture DB only"
    ))?;
    let sql=format!("BEGIN; CREATE SCHEMA {schema}; GRANT USAGE ON SCHEMA {schema} TO PUBLIC; {setup} {definition}; COMMIT;");
    if let Err(e) = owner.batch_execute(&sql).await {
        let _ = owner.batch_execute("ROLLBACK").await;
        return Err(e.into());
    }
    let dsn = if base.starts_with("postgres://") || base.starts_with("postgresql://") {
        format!(
            "{base}{}options=-csearch_path%3D{schema}%2Cpublic",
            if base.contains('?') { '&' } else { '?' }
        )
    } else {
        format!("{base} options='-csearch_path={schema},public'")
    };
    Ok((dsn, schema))
}

#[tokio::test]
async fn hold_request_ids() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("hold", "request-ids", false).await
}

#[tokio::test]
async fn list_query_fault() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("list", "query-fault", false).await
}

#[tokio::test]
async fn audit_csv_fault() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("audit", "csv-fault", false).await
}

#[tokio::test]
async fn verify_query_fault() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("verify", "verify-fault", false).await
}

// Chat's authenticated seam needs a primary mailbox, not unrelated mail
// messages and their partition/state fixtures. Keep user/mailbox IDs divergent.
struct Principal {
    user: i64,
    mailbox: i64,
    domain: i64,
}
async fn principal_pair(
    owner: &tokio_postgres::Client,
) -> Result<(Principal, Principal), BoxError> {
    owner.batch_execute("BEGIN").await?;
    let result = async {
        let account = principal_in_transaction(owner, "chat1-admin").await?;
        let foreign = principal_in_transaction(owner, "chat1-foreign").await?;
        owner.batch_execute("COMMIT").await?;
        Ok::<_, tokio_postgres::Error>((account, foreign))
    }
    .await;
    match result {
        Ok(pair) => Ok(pair),
        Err(error) => {
            let _ = owner.batch_execute("ROLLBACK").await;
            Err(format!("Chat principal-pair setup: {error:?}").into())
        }
    }
}
async fn principal_in_transaction(
    owner: &tokio_postgres::Client,
    label: &str,
) -> Result<Principal, tokio_postgres::Error> {
    let unique: String = owner
        .query_one("SELECT replace(gen_random_uuid()::text,'-','')", &[])
        .await?
        .get(0);
    let domain_name = format!("oracle-{unique}.test");
    let email = format!("{label}@{domain_name}");
    let domain: i64 = owner
        .query_one(
            "INSERT INTO domains(name,is_local) VALUES($1,true) RETURNING id",
            &[&domain_name],
        )
        .await?
        .get(0);
    let user:i64=owner.query_one("INSERT INTO users(username,domain_id,email,display_name,password_hash) VALUES($1,$2,$1,$3,'x') RETURNING id",&[&email,&domain,&label]).await?.get(0);
    let mut mailbox: i64 = owner
        .query_one("SELECT nextval('mailboxes_id_seq')", &[])
        .await?
        .get(0);
    if mailbox == user {
        mailbox = owner
            .query_one("SELECT nextval('mailboxes_id_seq')", &[])
            .await?
            .get(0);
    }
    owner.execute("INSERT INTO mailboxes(id,user_id,domain_id,email,display_name,type,is_primary) VALUES($1,$2,$3,$4,$5,'personal',true)",&[&mailbox,&user,&domain,&email,&label]).await?;
    Ok(Principal {
        user,
        mailbox,
        domain,
    })
}
async fn remove_principal(owner: &tokio_postgres::Client, p: &Principal) -> Result<(), BoxError> {
    owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM mailbox_audit_log WHERE mailbox_id={}; COMMIT;",p.mailbox)).await?;
    owner.batch_execute(&format!("BEGIN; DELETE FROM mailboxes WHERE id={} AND user_id={}; DELETE FROM users WHERE id={} AND domain_id={}; COMMIT;",p.mailbox,p.user,p.user,p.domain)).await?;
    owner
        .execute("DELETE FROM domains WHERE id=$1", &[&p.domain])
        .await?;
    Ok(())
}

#[tokio::test]
async fn hold_bad_id() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("hold", "bad-id", false).await
}

#[tokio::test]
async fn retention_bad_id() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("retention", "bad-id", false).await
}

#[tokio::test]
async fn classification_bad_id() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("classification", "bad-id", false).await
}

#[tokio::test]
async fn audit_bad_id() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("audit", "bad-id", false).await
}

#[tokio::test]
async fn classification_pg_range() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("classification", "pg-range", false).await
}

#[tokio::test]
async fn list_parse_fault() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("list", "parse-fault", false).await
}

#[tokio::test]
async fn audit_parse_fault() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("audit", "parse-fault", false).await
}

#[tokio::test]
async fn audit_read_fault() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("audit", "read-fault", false).await
}

#[tokio::test]
async fn verify_notary_fault() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("verify", "notary-fault", false).await
}

#[tokio::test]
async fn verify_live_fault() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("verify", "live-fault", false).await
}

#[tokio::test]
async fn verify_notary_row_fault() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("verify", "notary-row-fault", false).await
}

#[tokio::test]
async fn verify_anchor_parse_fault() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("verify", "anchor-parse-fault", false).await
}

#[tokio::test]
async fn verify_anchor_fault() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("verify", "anchor-fault", false).await
}

#[tokio::test]
async fn hold_encoded_bad_id() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("hold", "encoded-bad-id", false).await
}

#[tokio::test]
async fn hold_invalid_utf8() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("hold", "invalid-utf8", false).await
}

#[tokio::test]
async fn list_invalid_query_utf8() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("list", "invalid-query-utf8", false).await
}

#[tokio::test]
async fn hold_encoded_mount() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run("hold", "encoded-mount", false).await
}
