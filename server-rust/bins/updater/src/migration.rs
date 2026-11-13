//! Owner-only transactional expand migrations, with durable manifest evidence.
use crate::{control::Connection, files::*, stage};
use anyhow::{ensure, Result};
use serde_json::{json, Value};
use setjoin_release_format::{sha256, Manifest};
use std::path::Path;

pub async fn registry(
    db: &Connection,
    target: &Manifest,
    root: &Path,
    slot: &str,
    phase: &str,
) -> Result<Value> {
    let query="SELECT s.mode,s.registry_digest,count(*) FILTER(WHERE public.feature_registry_classify(t.key)='unknown') FROM public.feature_toggle_registry_state s LEFT JOIN public.feature_toggles t ON true WHERE s.singleton GROUP BY s.mode,s.registry_digest";
    let result = db.client.query_one(query, &[]).await;
    let state = match result {
        Ok(r) => {
            json!({"present":true,"mode":r.get::<_,String>(0),"catalog_digest":r.get::<_,String>(1),"unknown_rows":r.get::<_,i64>(2)})
        }
        Err(e) if e.code().is_some_and(|c| c.code() == "42P01") => {
            json!({"present":false,"unknown_rows":0})
        }
        Err(e) => return Err(e.into()),
    };
    let contract = target.feature_registry.as_ref();
    if state["present"] == false {
        ensure!(
            (phase == "preflight"
                && target.schema_from < 183
                && target.schema_to >= 183
                && contract.is_some())
                || (target.schema_to < 183 && contract.is_none()),
            "feature registry absent"
        );
        return Ok(state);
    }
    let mode = state["mode"].as_str().unwrap();
    ensure!(
        matches!(mode, "observe" | "enforce"),
        "invalid feature registry mode"
    );
    if phase == "rollback" && contract.is_none() && target.schema_to < 183 && mode == "observe" {
        return Ok(state);
    }
    let c = contract
        .ok_or_else(|| anyhow::anyhow!("target does not declare feature registry compatibility"))?;
    ensure!(
        c.compatible_modes.iter().flatten().any(|v| v == mode),
        "unsupported feature registry mode"
    );
    let unknown = state["unknown_rows"].as_i64().unwrap();
    ensure!(
        unknown >= 0 && (mode != "enforce" || unknown == 0),
        "unknown feature rows in enforce mode"
    );
    let live = state["catalog_digest"].as_str().unwrap();
    ensure!(
        live == c.catalog_digest
            || (phase != "post_commit"
                && c.compatible_rollback_digests
                    .iter()
                    .flatten()
                    .any(|v| v == live)),
        "registry digest differs"
    );
    let rollback = installed_manifest(root, slot)?;
    if let Some(other) = rollback.as_ref().and_then(|m| m.feature_registry.as_ref()) {
        ensure!(
            c.compatible_rollback_digests
                .iter()
                .flatten()
                .any(|v| v == &other.catalog_digest),
            "rollback digest undeclared"
        );
    }
    if mode == "enforce" {
        let other = rollback
            .as_ref()
            .and_then(|m| m.feature_registry.as_ref())
            .ok_or_else(|| anyhow::anyhow!("enforce rollback cohort missing"))?;
        ensure!(
            live == c.catalog_digest
                && other.catalog_digest == live
                && other
                    .compatible_modes
                    .iter()
                    .flatten()
                    .any(|m| m == "enforce"),
            "enforce rollback cohort incompatible"
        );
    }
    Ok(state)
}
pub fn installed_manifest(root: &Path, slot: &str) -> Result<Option<Manifest>> {
    let id = stage::active(root, slot)?;
    let path = root.join("releases").join(&id).join("manifest.json");
    if !path.try_exists()? {
        return Ok(None);
    }
    let m = Manifest::parse(&read(&path, 1 << 20, false)?)?;
    ensure!(m.release_id == id, "installed manifest identity differs");
    Ok(Some(m))
}
async fn current(db: &Connection) -> Result<i32> {
    Ok(db
        .client
        .query_one(
            "SELECT COALESCE(MAX(version),0) FROM public.schema_migrations",
            &[],
        )
        .await?
        .get(0))
}
async fn evidence(
    db: &Connection,
    m: &Manifest,
    digest: &str,
    migration: &setjoin_release_format::Migration,
) -> Result<()> {
    let version = i32::try_from(migration.to_schema)?;
    let r=db.client.query_one("SELECT release_id,manifest_digest,migration_id,migration_sha256 FROM public.upgrade_schema_migration_evidence WHERE schema_version=$1",&[&version]).await?;
    ensure!(
        r.get::<_, String>(0) == m.release_id
            && r.get::<_, String>(1) == digest
            && r.get::<_, String>(2) == migration.id
            && r.get::<_, String>(3) == migration.sha256,
        "migration evidence differs"
    );
    Ok(())
}
pub async fn apply(db: &mut Connection, root: &Path, m: &Manifest, digest: &str) -> Result<()> {
    let mut version = i64::from(current(db).await?);
    ensure!(
        version >= m.schema_from && version <= m.schema_to,
        "migration schema range differs"
    );
    for migration in m.migrations.iter().flatten() {
        if version >= migration.to_schema {
            evidence(db, m, digest, migration).await?;
            continue;
        }
        ensure!(version == migration.from_schema, "migration chain differs");
        let bytes = read(
            &root
                .join("releases")
                .join(&m.release_id)
                .join("share/migrations")
                .join(format!("{}.sql", migration.id)),
            16 << 20,
            false,
        )?;
        ensure!(
            !bytes.is_empty() && sha256(&bytes) == migration.sha256,
            "migration digest differs"
        );
        let sql = String::from_utf8(bytes)?;
        validate_sql(&sql).map_err(|e| anyhow::anyhow!("migration {:?}: {e}", migration.id))?;
        let applied=async {
            let tx=db.client.transaction().await?;tx.batch_execute(&sql).await?;
            let actual:i32=tx.query_one("SELECT COALESCE(MAX(version),0) FROM public.schema_migrations",&[]).await?.get(0);
            ensure!(i64::from(actual)==migration.to_schema,"migration recorded incorrect schema");
            tx.execute("INSERT INTO public.upgrade_schema_migration_evidence(schema_version,release_id,manifest_digest,migration_id,migration_sha256) VALUES($1,$2,$3,$4,$5)",&[&actual,&m.release_id,&digest,&migration.id,&migration.sha256]).await?;
            tx.commit().await?;Ok::<_,anyhow::Error>(())
        }.await;
        if let Err(error) = applied {
            if i64::from(current(db).await?) != migration.to_schema {
                return Err(error);
            }
            evidence(db, m, digest, migration).await?;
        }
        version = migration.to_schema;
    }
    ensure!(version == m.schema_to, "migration chain ended early");
    Ok(())
}
fn validate_sql(sql: &str) -> Result<()> {
    use sqlparser::tokenizer::Whitespace;
    use sqlparser::{
        dialect::PostgreSqlDialect,
        tokenizer::{Token, Tokenizer},
    };
    let tokens = Tokenizer::new(&PostgreSqlDialect {}, sql).tokenize()?;
    let mut pending: std::collections::VecDeque<_> = tokens.into();
    let mut words = Vec::new();
    while let Some(token) = pending.pop_front() {
        match token {
            Token::Word(w) if w.quote_style.is_none() => words.push(w.value.to_ascii_lowercase()),
            // Frozen Go stops a block comment at the FIRST closing marker.
            // Keep its false rejection of keywords in a valid nested comment,
            // while delegating all tokenization to the maintained parser.
            Token::Whitespace(Whitespace::MultiLineComment(comment)) if comment.contains("/*") => {
                if let Some((_, tail)) = comment.split_once("*/") {
                    for token in Tokenizer::new(&PostgreSqlDialect {}, tail)
                        .tokenize()?
                        .into_iter()
                        .rev()
                    {
                        pending.push_front(token);
                    }
                }
            }
            _ => (),
        }
    }
    for (i, w) in words.iter().enumerate() {
        ensure!(
            !matches!(
                w.as_str(),
                "begin"
                    | "commit"
                    | "rollback"
                    | "savepoint"
                    | "vacuum"
                    | "cluster"
                    | "reindex"
                    | "concurrently"
                    | "program"
                    | "call"
            ),
            "migration SQL is unsafe: statement {w:?} is updater-owned or nontransactional"
        );
        ensure!(
            !(w == "alter" && words.get(i + 1).is_some_and(|v| v == "system")),
            "ALTER SYSTEM unsupported"
        );
        ensure!(
            !(w == "alter"
                && words.get(i + 1).is_some_and(|v| v == "type")
                && words[i + 2..words.len().min(i + 7)]
                    .iter()
                    .any(|v| v == "add")),
            "ALTER TYPE ADD unsupported"
        );
        ensure!(
            !(matches!(w.as_str(), "create" | "drop")
                && words.get(i + 1).is_some_and(|v| matches!(
                    v.as_str(),
                    "database" | "tablespace" | "subscription"
                ))),
            "unsupported nontransactional DDL"
        );
    }
    Ok(())
}
