#![allow(dead_code)] // Shared across independent Office HTTP test binaries.
use crate::common::BoxError;
use setjoin_conformance::{fixture, harness::Db};
use sha2::{Digest, Sha256};
pub struct Seed {
    pub account: fixture::Account,
    pub token: String,
    pub space: i64,
    pub node: i64,
    pub version: i64,
    pub qualification: String,
    pub launch: serde_json::Value,
}
pub async fn seed(db: &Db) -> Result<(tokio_postgres::Client, Seed), BoxError> {
    let c = db.connect().await?;
    let a = fixture::account(&c, "office1-owner").await?;
    let token = format!("office1-fixture-launch-token-{}", a.user);
    let hash = format!("{:x}", Sha256::digest(&token));

    c.execute(
        "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,1,$1)",
        &[&a.user],
    )
    .await?;
    c.batch_execute("UPDATE feature_toggles SET enabled=true WHERE key IN ('feature.drive','feature.drive_history','feature.office_editing')").await?;
    let space: i64 = c
        .query_one(
            "SELECT drive_space_create($1,'Office1','regular')",
            &[&a.user],
        )
        .await?
        .get(0);
    let node: i64 = c
        .query_one(
            "SELECT drive_node_create($1,$2,NULL,'file','proposal.docx')",
            &[&a.user, &space],
        )
        .await?
        .get(0);
    c.query_one("SELECT drive_chunk_register($1,$2,'84d89877f0d4041efb6bf91a16f0248f2fd573e6af05c19f96bedb9f882f7882',10)",&[&a.user,&space]).await?;
    let raw:String=c.query_one("SELECT drive_file_put_version($1,$2,repeat('a',64),10,'application/octet-stream',NULL,('[{\"sha256\":\"'||'84d89877f0d4041efb6bf91a16f0248f2fd573e6af05c19f96bedb9f882f7882'||'\",\"size\":10}]')::jsonb,'v1','test')::text",&[&a.user,&node]).await?.get(0);
    let version = serde_json::from_str::<serde_json::Value>(&raw)?["versionId"]
        .as_i64()
        .ok_or("version")?;
    c.execute("INSERT INTO office_provider_policies(provider_id,enabled,entitlement_state,build_id,config) VALUES('office1',true,'valid','test-1','{\"editorUrl\":\"https://editor.test/launch\",\"wopiPublicBaseUrl\":\"https://setjoin.test\",\"proofMode\":\"test_disabled\"}')",&[]).await?;
    let q:String=c.query_one("INSERT INTO office_provider_qualifications(provider_id,provider_generation,config_sha256,status,profile,checks,discovery_fingerprint,route_revision,created_by,expires_at) SELECT provider_id,1,config_sha256,'passed','existing-provider','{\"discovery\":\"pass\",\"proof\":\"pass\",\"editor\":\"pass\",\"wopiSave\":\"pass\"}',repeat('f',64),1,$1,now()+interval '1 hour' FROM office_provider_policies WHERE provider_id='office1' RETURNING id::text",&[&a.user]).await?.get(0);
    c.execute("UPDATE office_provider_policies SET generation=2,route_state='active_for_scope',active_qualification_id=$1::text::uuid WHERE provider_id='office1'",&[&q]).await?;
    c.batch_execute("INSERT INTO office_provider_health_observations(provider_id,provider_generation,state,capacity_state,facts,expires_at) VALUES('office1',2,'healthy','available','{}',now()+interval '1 hour')").await?;
    let launch_raw: String = c
        .query_one(
            "SELECT office_launch_begin($1,$2,$3,'office1','device1','cohort1',$4,3600)::text",
            &[&a.user, &node, &version, &hash],
        )
        .await?
        .get(0);

    let launch = serde_json::from_str(&launch_raw)?;
    Ok((
        c,
        Seed {
            account: a,
            token,
            space,
            node,
            version,
            qualification: q,
            launch,
        },
    ))
}
pub async fn cleanup(c: &tokio_postgres::Client, seed: &Seed) -> Result<(), BoxError> {
    c.batch_execute("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM office_provider_health_observations WHERE provider_id='office1'; DELETE FROM office_provider_qualifications WHERE provider_id='office1'; DELETE FROM office_provider_policies WHERE provider_id='office1'; COMMIT;").await?;
    c.execute("DELETE FROM office_save_receipts WHERE space_id IN (SELECT id FROM drive_spaces WHERE owner_user_id=$1)",&[&seed.account.user]).await?;
    c.execute("DELETE FROM office_editor_sessions WHERE space_id IN (SELECT id FROM drive_spaces WHERE owner_user_id=$1)",&[&seed.account.user]).await?;
    c.execute("DELETE FROM drive_nodes WHERE space_id IN (SELECT id FROM drive_spaces WHERE owner_user_id=$1)",&[&seed.account.user]).await?;
    c.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM drive_audit_log WHERE space_id IN (SELECT id FROM drive_spaces WHERE owner_user_id={}); COMMIT;",seed.account.user)).await?;
    c.execute(
        "DELETE FROM drive_spaces WHERE owner_user_id=$1",
        &[&seed.account.user],
    )
    .await?;
    c.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_role_assignments WHERE user_id={}; COMMIT;",seed.account.user)).await?;
    c.execute(
        "DELETE FROM drive_upload_claims WHERE user_id=$1",
        &[&seed.account.user],
    )
    .await?;
    c.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE user_id={0} OR (action='console.denied' AND before_state->>'actor'='office1+{0}@test'); COMMIT;",seed.account.user)).await?;
    crate::common::remove_blob_account(c, &seed.account).await?;

    Ok(())
}

pub fn token(user: i64, admin: bool) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let h = URL_SAFE_NO_PAD
        .encode(serde_json::json!({"alg":"ES256","kid":"test-es256-1","typ":"JWT"}).to_string());
    let b=URL_SAFE_NO_PAD.encode(serde_json::json!({"uid":user,"email":format!("office1+{user}@test"),"admin":admin,"typ":"access","jti":"office1","fam":"office1","iss":"mailserver","aud":["mailserver-gateway"],"iat":now-10,"exp":now+600}).to_string());
    let key = SigningKey::from_slice(&[0x11; 32]).unwrap();
    let sig: p256::ecdsa::Signature = key.sign(format!("{h}.{b}").as_bytes());
    format!("{h}.{b}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

/// Full business-row observation, independently through the owner connection.
/// Rust operation receipts are system metadata, excluded by the foundation rule.
pub async fn snapshot(c: &tokio_postgres::Client, s: &Seed) -> Result<serde_json::Value, BoxError> {
    let specifications=[
 ("providers","SELECT to_jsonb(t)::text FROM office_provider_policies t WHERE provider_id='office1' ORDER BY provider_id"),
 ("qualifications","SELECT to_jsonb(t)::text FROM office_provider_qualifications t WHERE provider_id='office1' ORDER BY created_at,id"),
 ("health","SELECT to_jsonb(t)::text FROM office_provider_health_observations t WHERE provider_id='office1' ORDER BY id"),
 ("sessions","SELECT to_jsonb(t)::text FROM office_editor_sessions t WHERE space_id=$1 ORDER BY id"),
 ("launches","SELECT to_jsonb(t)::text FROM office_editor_launches t WHERE space_id=$1 ORDER BY id"),
 ("locks","SELECT to_jsonb(t)::text FROM office_wopi_locks t WHERE space_id=$1 ORDER BY session_id"),
 ("receipts","SELECT to_jsonb(t)::text FROM office_save_receipts t WHERE space_id=$1 ORDER BY id"),
 ("versions","SELECT to_jsonb(t)::text FROM drive_file_versions t WHERE space_id=$1 ORDER BY id"),
 ("version_chunks","SELECT to_jsonb(vc)::text FROM drive_version_chunks vc JOIN drive_file_versions v ON v.id=vc.version_id WHERE v.space_id=$1 ORDER BY vc.version_id,vc.stream,vc.ordinal"),
 ("files","SELECT to_jsonb(t)::text FROM drive_files t WHERE space_id=$1 ORDER BY node_id"),
 ("nodes","SELECT to_jsonb(t)::text FROM drive_nodes t WHERE space_id=$1 ORDER BY id"),
 ("spaces","SELECT to_jsonb(t)::text FROM drive_spaces t WHERE id=$1"),
 ("changes","SELECT to_jsonb(t)::text FROM drive_changes t WHERE space_id=$1 ORDER BY seq"),
 ("drive_audit","SELECT (to_jsonb(t)-'checksum')::text FROM drive_audit_log t WHERE space_id=$1 ORDER BY id"),
 ];
    let invalid: i64 = c
        .query_one(
            "SELECT count(*) FROM verify_drive_audit_chain($1) WHERE NOT valid",
            &[&s.space],
        )
        .await?
        .get(0);
    if invalid != 0 {
        return Err("invalid Drive audit chain".into());
    }
    let mut rows = serde_json::Map::new();
    for (table, sql) in specifications {
        let values = if sql.contains("$1") {
            c.query(sql, &[&s.space]).await?
        } else {
            c.query(sql, &[]).await?
        };
        let values = values
            .iter()
            .map(|row| serde_json::from_str::<serde_json::Value>(&row.get::<_, String>(0)))
            .collect::<Result<Vec<_>, _>>()?;
        rows.insert(table.into(), values.into());
    }
    let invalid:i64=c.query_one("SELECT count(*) FROM admin_audit_log t CROSS JOIN LATERAL verify_audit_chain(t.id,t.id) v WHERE (t.user_id=$1 OR (t.action='console.denied' AND t.before_state->>'actor'=$2)) AND NOT v.valid",&[&s.account.user,&format!("office1+{}@test",s.account.user)]).await?.get(0);
    if invalid != 0 {
        return Err("invalid core audit chain".into());
    }
    let audits=c.query("SELECT (to_jsonb(t)-'checksum')::text FROM admin_audit_log t WHERE user_id=$1 OR (action='console.denied' AND before_state->>'actor'=$2) ORDER BY id",&[&s.account.user,&format!("office1+{}@test",s.account.user)]).await?;
    rows.insert(
        "core_audit".into(),
        audits
            .iter()
            .map(|r| serde_json::from_str::<serde_json::Value>(&r.get::<_, String>(0)).unwrap())
            .collect::<Vec<_>>()
            .into(),
    );
    let claims=c.query("SELECT to_jsonb(u)::text FROM drive_upload_claims u WHERE user_id=$1 ORDER BY scope_key,sha256",&[&s.account.user]).await?;
    rows.insert(
        "claims".into(),
        claims
            .iter()
            .map(|r| serde_json::from_str::<serde_json::Value>(&r.get::<_, String>(0)).unwrap())
            .collect::<Vec<_>>()
            .into(),
    );
    let authorizations=c.query("SELECT to_jsonb(t)::text FROM drive_upload_authorizations t WHERE user_id=$1 ORDER BY scope_key,sha256,target_node_id",&[&s.account.user]).await?;
    rows.insert(
        "authorizations".into(),
        authorizations
            .iter()
            .map(|r| serde_json::from_str::<serde_json::Value>(&r.get::<_, String>(0)).unwrap())
            .collect::<Vec<_>>()
            .into(),
    );
    let chunks=c.query("SELECT (to_jsonb(ch)||jsonb_build_object('ref_count',(SELECT count(*) FROM drive_version_chunks vc JOIN drive_file_versions v ON v.id=vc.version_id WHERE vc.scope_key=ch.scope_key AND vc.chunk_sha256=ch.sha256 AND v.space_id=$2)))::text, ch.ref_count=(SELECT count(*) FROM drive_version_chunks vc WHERE vc.scope_key=ch.scope_key AND vc.chunk_sha256=ch.sha256) FROM drive_chunks ch WHERE EXISTS(SELECT 1 FROM drive_upload_claims u WHERE u.scope_key=ch.scope_key AND u.sha256=ch.sha256 AND u.user_id=$1) OR EXISTS(SELECT 1 FROM drive_version_chunks vc JOIN drive_file_versions v ON v.id=vc.version_id WHERE vc.scope_key=ch.scope_key AND vc.chunk_sha256=ch.sha256 AND v.space_id=$2) ORDER BY scope_key,sha256",&[&s.account.user,&s.space]).await?;
    if chunks.iter().any(|row| !row.get::<_, bool>(1)) {
        return Err("Drive global chunk refcount differs from its reference rows".into());
    }
    rows.insert(
        "chunks".into(),
        chunks
            .iter()
            .map(|r| serde_json::from_str::<serde_json::Value>(&r.get::<_, String>(0)).unwrap())
            .collect::<Vec<_>>()
            .into(),
    );
    let mut result = serde_json::Value::Object(rows);
    normalize_rows(&mut result, s)?;
    Ok(result)
}
fn normalize_rows(value: &mut serde_json::Value, s: &Seed) -> Result<(), BoxError> {
    use std::collections::HashMap;
    let mut ids: HashMap<(String, String), String> = HashMap::new();
    for (table, kind) in [
        ("versions", "version"),
        ("sessions", "session"),
        ("launches", "launch"),
        ("qualifications", "qualification"),
        ("receipts", "receipt"),
        ("health", "health"),
        ("core_audit", "audit"),
        ("drive_audit", "drive-audit"),
    ] {
        for (i, row) in value[table].as_array().unwrap().iter().enumerate() {
            if let Some(id) = row.get("id") {
                ids.insert(
                    (
                        kind.into(),
                        id.as_str()
                            .map(str::to_owned)
                            .unwrap_or_else(|| id.to_string()),
                    ),
                    format!("<{kind}:{i}>"),
                );
            }
        }
    }
    fn walk(
        v: &mut serde_json::Value,
        key: &str,
        table: &str,
        s: &Seed,
        ids: &HashMap<(String, String), String>,
    ) -> Result<(), BoxError> {
        if v.is_null() {
            return Ok(());
        }
        let id_kind = match key {
            "id" => match table {
                "versions" => "version",
                "sessions" => "session",
                "launches" => "launch",
                "qualifications" => "qualification",
                "receipts" => "receipt",
                "health" => "health",
                "core_audit" => "audit",
                "drive_audit" => "drive-audit",
                "nodes" => "file",
                "spaces" => "space",
                _ => "",
            },
            "session_id" | "sessionId" => "session",
            "launch_id" | "launchId" => "launch",
            "active_qualification_id" | "qualificationId" => "qualification",
            "synthetic_receipt_id" => "receipt",
            "baseVersionId" | "base_version_id" | "version_id" | "versionId" | "headVersionId"
            | "head_version_id" | "current_version_id" | "expected_base_id"
            | "result_version_id" | "parent_version_id" => "version",
            "space_id" | "spaceId" => "space",
            "file_node_id" | "fileNodeId" | "node_id" | "target_id" => "file",
            "author_user_id" | "user_id" | "actor_user_id" | "actorUserId" | "owner_user_id"
            | "created_by" | "updated_by" | "holder_user_id" => "actor",
            _ => "",
        };
        if id_kind == "actor" && v.as_i64() == Some(s.account.user) {
            *v = "<actor>".into();
            return Ok(());
        }
        if id_kind == "file" && v.as_i64() == Some(s.node) {
            *v = "<file>".into();
            return Ok(());
        }
        if id_kind == "space" && v.as_i64() == Some(s.space) {
            *v = "<space>".into();
            return Ok(());
        }
        if let Some(id) = ids.get(&(
            id_kind.into(),
            v.as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| v.to_string()),
        )) {
            *v = id.clone().into();
            return Ok(());
        }
        match v {
            serde_json::Value::Object(o) => {
                let target_kind = o
                    .get("target_type")
                    .and_then(|v| v.as_str())
                    .map(|t| match t {
                        "version" => "version_id",
                        "space" => "space_id",
                        _ => "file_node_id",
                    });
                if let Some(kind) = target_kind {
                    if let Some(id) = o.get_mut("target_id") {
                        walk(id, kind, table, s, ids)?;
                    }
                }
                for (k, v) in o {
                    walk(v, k, table, s, ids)?
                }
            }
            serde_json::Value::Array(a) => {
                for v in a {
                    walk(v, key, table, s, ids)?
                }
            }
            serde_json::Value::String(text)
                if key == "at"
                    || key.ends_with("_at")
                    || matches!(key, "createdAt" | "expiresAt" | "updatedAt" | "observedAt") =>
            {
                chrono::DateTime::parse_from_rfc3339(text)?;
                *text = "<timestamp>".into()
            }
            serde_json::Value::String(text) if key == "_checksum" => {
                if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err("invalid Drive checksum encoding".into());
                }
                *text = "<verified-drive-checksum>".into()
            }
            serde_json::Value::String(text) if key == "token_hash" => {
                if *text != setjoin_office::token_hash(&s.token) {
                    return Err("unexpected fixture launch hash".into());
                }
                *text = "<launch-hash>".into()
            }
            serde_json::Value::String(text) if key == "operation_key" && text.len() == 64 => {
                *text = "<derived-operation-key>".into()
            }
            serde_json::Value::String(text)
                if key == "actor" && *text == format!("office1+{}@test", s.account.user) =>
            {
                *text = "<actor-email>".into()
            }
            _ => {}
        }
        Ok(())
    }
    for (table, rows) in value.as_object_mut().unwrap() {
        walk(rows, table, table, s, &ids)?
    }
    Ok(())
}

pub fn effects(before: &serde_json::Value, after: &serde_json::Value) -> Vec<serde_json::Value> {
    before
        .as_object()
        .unwrap()
        .iter()
        .filter_map(|(table, old)| {
            if after[table] != *old {
                Some(serde_json::json!({"table":table,"before":old,"after":after[table]}))
            } else {
                None
            }
        })
        .collect()
}
pub fn headers(
    headers: &hyper::HeaderMap,
) -> Result<serde_json::Map<String, serde_json::Value>, BoxError> {
    let mut result = serde_json::Map::new();
    for (name, value) in headers {
        if !matches!(
            name.as_str(),
            "date" | "content-length" | "transfer-encoding" | "connection"
        ) {
            result.insert(
                name.as_str().into(),
                std::str::from_utf8(value.as_bytes())?.into(),
            );
        }
    }
    Ok(result)
}
pub fn compare_or_record(
    name: &str,
    route: &str,
    case: &str,
    observation: &serde_json::Value,
    recording: bool,
    mutator: bool,
) -> Result<(), BoxError> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/office/goldens");
    let path = root.join(format!("{name}.json"));
    if recording {
        let source = std::env::var("GOFREE_GO_SOURCE")?;
        setjoin_conformance::golden::record(
            &path,
            &serde_json::json!({"format":1,"route":route,"case":case,"go_source":source,"normalization":["fixture IDs by field and relation; timestamps validated as RFC3339; receipt metadata excluded; JSON response whitespace; response Date, framing/length headers; temporary S3 key; independently verified SigV4 nonces"],"observation":observation}),
        )?;
        if mutator {
            setjoin_conformance::golden::record(
                &root.join(format!("{name}-row-effects.json")),
                &serde_json::json!({"format":1,"route":route,"case":format!("{case}-row-effects"),"go_source":source,"effects":observation["effects"]}),
            )?;
        }
    } else {
        let document: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        setjoin_conformance::golden::compare(&document["observation"], observation)?;
        if mutator {
            let document: serde_json::Value = serde_json::from_slice(&std::fs::read(
                root.join(format!("{name}-row-effects.json")),
            )?)?;
            setjoin_conformance::golden::compare(&document["effects"], &observation["effects"])?;
        }
        eprintln!("GOLDEN-REPLAY: {route} :: {case}");
    }
    Ok(())
}

pub static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
/// Plant the mutation in executable SQL, on a private schema selected only by
/// this app pool. Never change the recorded observation to simulate a mutant.
pub async fn mutant_dsn(
    c: &tokio_postgres::Client,
    db: &Db,
    kind: &str,
) -> Result<(String, String), BoxError> {
    let (function, signature) = if kind == "tenant" {
        ("office_wopi_file_query", "bigint,text")
    } else {
        (
            "office_provider_configure",
            "bigint,text,bigint,text,text,text,jsonb,text",
        )
    };
    let name = format!("{function}({signature})");
    let mut definition: String = c
        .query_one(
            "SELECT pg_get_functiondef($1::text::regprocedure)",
            &[&name],
        )
        .await?
        .get(0);
    match kind {
        "audit" | "notify" => {
            let marker = if kind == "audit" {
                "PERFORM public.audit_write("
            } else {
                "PERFORM public.app_notify("
            };
            let start = definition.find(marker).ok_or("mutant call not found")?;
            let end = start + definition[start..].find(");").ok_or("mutant call end")? + 2;
            definition.replace_range(start..end, "PERFORM 1;");
        }
        "bump" => {
            let marker = "office_provider_policies.generation+1";
            if !definition.contains(marker) {
                return Err("mutant generation not found".into());
            }
            definition = definition.replacen(marker, "office_provider_policies.generation+2", 1);
        }
        "tenant" => {
            let marker = "l.token_hash=p_token_hash";
            let callback = "public.office_wopi_callback_allowed(l.id,p_token_hash,'download')";
            if !definition.contains(marker) || !definition.contains(callback) {
                return Err("mutant launch credential predicate not found".into());
            }
            definition = definition.replacen(marker, "true", 1).replacen(
                callback,
                "public.office_wopi_callback_allowed(l.id,l.token_hash,'download')",
                1,
            );
        }
        _ => return Err("unknown SQL mutant".into()),
    }
    let id: String = c
        .query_one("SELECT replace(gen_random_uuid()::text,'-','')", &[])
        .await?
        .get(0);
    if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid mutant schema id".into());
    }
    let schema = format!("gofree_office1_mutant_{id}");
    let header = format!("CREATE OR REPLACE FUNCTION public.{function}(");
    if !definition.starts_with(&header) {
        return Err("unexpected function definition header".into());
    }
    definition = definition.replacen(
        &header,
        &format!("CREATE OR REPLACE FUNCTION {schema}.{function}("),
        1,
    );
    if let Ok(path) = std::env::var("GOFREE_RESOURCE_LEDGER") {
        use std::io::Write;
        writeln!(
            std::fs::OpenOptions::new().append(true).open(path)?,
            "Planned owned SQL mutant schema {schema}; drop after replay"
        )?;
    }
    let result=c.batch_execute(&format!("BEGIN;CREATE SCHEMA {schema};{definition};GRANT USAGE ON SCHEMA {schema} TO setjoin_app;GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA {schema} TO setjoin_app;COMMIT;")).await;
    if let Err(error) = result {
        let _ = c.batch_execute("ROLLBACK").await;
        return Err(error.into());
    }
    let base = db.app.as_deref().unwrap_or(&db.dsn);
    if base.contains("options=") {
        c.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await?;
        return Err("mutant DSN already has options".into());
    }
    Ok((
        format!(
            "{base}{}options=-csearch_path%3D{schema}%2Cpublic",
            if base.contains('?') { '&' } else { '?' }
        ),
        schema,
    ))
}
