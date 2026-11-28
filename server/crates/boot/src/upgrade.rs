//! Organization-config startup upgrade, preserving Go's two transaction cuts.
use setjoin_config_secret::{is_config_secret_envelope, keyring_from_env, ConfigSecretCodec};
use setjoin_pg::{workers::WorkerConnection, Type};

pub(crate) async fn run(db: &WorkerConnection) -> Result<usize, String> {
    let deployment = db
        .query(
            "SELECT value #>> '{}' FROM system_config WHERE key='identity.deployment_id'",
            &[],
        )
        .await?;
    let deployment = deployment
        .first()
        .ok_or("identity deployment ID missing")?
        .get::<_, Option<String>>(0)
        .unwrap_or_default();
    let codec = ConfigSecretCodec::new(keyring_from_env(&deployment).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let connectors = batch(db, &codec, false).await?;
    let named = batch(db, &codec, true).await?;
    Ok(connectors + named)
}
async fn batch(
    db: &WorkerConnection,
    codec: &ConfigSecretCodec,
    named: bool,
) -> Result<usize, String> {
    db.batch("BEGIN").await?;
    let result=async {
        let query=if named { "SELECT key,value::text,encrypted FROM system_config WHERE key='assist.api_key' ORDER BY key FOR UPDATE" }
            else { "SELECT key,value::text,encrypted FROM system_config WHERE encrypted OR right(key,4)='_enc' ORDER BY key FOR UPDATE" };
        let candidates=db.query(query,&[]).await?;
        let candidates=candidates.into_iter().filter(|row| {
            let key=row.get::<_,String>(0);
            named || key.starts_with("ad_sync_") || key.starts_with("ldap_sync_")
        }).collect::<Vec<_>>();
        // Validate the whole candidate set before generating any replacement.
        for row in &candidates {
            let key=row.get::<_,String>(0);
            let value=row.get::<_,String>(1);
            if is_config_secret_envelope(value.as_bytes()) {
                codec.decrypt(&key,value.as_bytes()).map_err(|e|e.to_string())?;
            }
        }
        let mut changes=Vec::new();
        let mut upgraded=0;
        for row in candidates {
            let key=row.get::<_,String>(0);
            let value=row.get::<_,String>(1);
            if is_config_secret_envelope(value.as_bytes()) {
                if !row.get::<_,bool>(2) { changes.push(serde_json::json!({"key":key,"replace":false})); }
            } else {
                let encrypted=codec.encrypt(&key,value.as_bytes()).map_err(|e|e.to_string())?;
                let value:serde_json::Value=serde_json::from_slice(&encrypted).map_err(|e|e.to_string())?;
                changes.push(serde_json::json!({"key":key,"value":value,"replace":true}));
                upgraded+=1;
            }
        }
        if !changes.is_empty() {
            let changes=serde_json::to_string(&changes).map_err(|e|e.to_string())?;
            db.query("SELECT boot_config_secret_apply($1::text::jsonb)",&[(&changes,Type::TEXT)]).await?;
        }
        Ok::<_,String>(upgraded)
    }.await;
    match result {
        Ok(count) => {
            db.batch("COMMIT").await?;
            Ok(count)
        }
        Err(error) => {
            let _ = db.batch("ROLLBACK").await;
            Err(error)
        }
    }
}
