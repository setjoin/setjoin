//! Startup secret migration: hold Go's row locks through audited crypto and one
//! reducer apply; no request can choose its database, master or active profile.
use super::*;
use serde_json::{json, Value};
use setjoin_config_secret::CryptoProfile;
use setjoin_pg::{operator::OperatorConnection, Type};
pub async fn reseal(dsn: &str, master: &[u8], profile: CryptoProfile) -> Result<i32, String> {
    if master.is_empty() {
        return Err("OIDC client secret reseal requires the deployment master".into());
    }
    tokio::time::timeout(Duration::from_secs(30),async{
        let connection=OperatorConnection::connect(dsn).await?;
        connection.batch("BEGIN").await?;
        let result=async{
            let rows=connection.query("SELECT key,value::text,encrypted FROM system_config WHERE key LIKE 'oidc_provider_%_config' ORDER BY key FOR UPDATE",&[]).await?;
            let mut candidates=Vec::new();
            // Validate every existing envelope/type before sealing/writing any row.
            for row in rows{
                let raw:String=row.get(1);let value:Value=serde_json::from_str(&raw).map_err(|_|"invalid OIDC configuration JSON")?;
                if !value.is_object()&&!value.is_null(){return Err("OIDC configuration is not an object".to_owned());}
                let secret=match value.get("client_secret"){
                    None|Some(Value::Null)=>"",
                    Some(Value::String(s))=>s,
                    _=>return Err("OIDC client_secret is not a string".into()),
                };
                if secret.is_empty(){continue;}
                if decode_secret(secret).is_some_and(|b|b.starts_with(b"EK01")){
                    open_secret(secret,master)?;
                }else{candidates.push((row.get::<_,String>(0),value.clone(),row.get::<_,bool>(2),secret.to_owned()));}
            }
            let mut changes=Vec::new();
            for (key,before,encrypted,plain) in candidates{
                let sealed=setjoin_config_secret::seal_column(plain.as_bytes(),master,profile).map_err(|_|"OIDC secret sealing failed")?;
                changes.push(json!({"key":key,"before":before,"encrypted":encrypted,"sealed":URL_SAFE_NO_PAD.encode(sealed)}));
            }
            let rows=connection.query("SELECT rust_identity_rp_reseal($1::text::jsonb)",&[(&json!(changes).to_string(),Type::TEXT)]).await?;
            Ok::<i32,String>(rows[0].get(0))
        }.await;
        match result{Ok(count)=>{connection.batch("COMMIT").await?;Ok(count)},Err(error)=>{let _=connection.batch("ROLLBACK").await;Err(error)}}
    }).await.map_err(|_|"OIDC startup reseal timed out".to_owned())?
}
