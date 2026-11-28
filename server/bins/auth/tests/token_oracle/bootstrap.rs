use super::*;
const FOREIGN_SECRET: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub(super) fn timestamp(raw: &Value) -> Result<(), Err> {
    let raw = raw.as_str().ok_or("missing timestamp")?;
    let value = chrono::DateTime::parse_from_rfc3339(raw)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    if (now - value.timestamp()).abs() > 30 {
        return Err(format!("unexpected timestamp: {raw}").into());
    }
    Ok(())
}
impl Seed {
    pub(super) async fn bootstrap_seed(
        &self,
        c: &tokio_postgres::Client,
        keys: &Value,
    ) -> Result<(), Err> {
        let sealed = setjoin_config_secret::seal_column(
            FOREIGN_SECRET.as_bytes(),
            keys["secret"].as_str().unwrap().as_bytes(),
            setjoin_config_secret::CryptoProfile::Standard,
        )?;
        c.execute("INSERT INTO devices(user_id,device_name,platform,os_version,app_version,fingerprint,hmac_secret_enc,hmac_secret_key_id,last_seen) VALUES($1,'Foreign device','foreign','foreign-os','0.0.1','idlogin3-fingerprint-0123456789abcdef',$2,'v1',now())",&[&self.b.user,&sealed]).await?;
        Ok(())
    }
    pub(super) fn bootstrap_response(&self, raw: &mut String) -> Result<Option<String>, Err> {
        let Ok(v) = serde_json::from_str::<Value>(raw) else {
            return Ok(None);
        };
        if v.get("device_id").is_none() {
            return Ok(None);
        }
        timestamp(&v["registered_at"])?;
        let secret = v["hmac_secret"]
            .as_str()
            .ok_or("missing device secret")?
            .to_owned();
        if !secret.is_empty()
            && (secret.len() != 64 || !secret.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err("device secret is not 32 random bytes in hex".into());
        }
        let id = v["device_id"].as_i64().ok_or("invalid device ID")?;
        if id <= 0 {
            return Err("invalid device ID".into());
        }
        // Keep wire map order; mask only values after validating the independent observation.
        *raw = raw
            .replace(
                &format!("\"device_id\":{id},"),
                "\"device_id\":\"<device-a>\",",
            )
            .replace(v["registered_at"].as_str().unwrap(), "<timestamp>");
        if !secret.is_empty() {
            *raw = raw.replace(&secret, "<random-secret>");
        }
        Ok(Some(secret))
    }
    pub(super) async fn bootstrap_rows(
        &self,
        c: &tokio_postgres::Client,
        keys: &Value,
        issued: Option<&str>,
    ) -> Result<Value, Err> {
        let rows=c.query("SELECT id,user_id,to_jsonb(d)::text,hmac_secret_enc FROM devices d WHERE user_id=ANY($1::bigint[]) ORDER BY user_id,id",&[&vec![self.a.user,self.b.user]]).await?;
        let mut devices = Vec::new();
        let mut ids = Vec::new();
        for row in rows {
            let id: i64 = row.get(0);
            let user: i64 = row.get(1);
            let a = user == self.a.user;
            ids.push((id, a));
            let mut v: Value = serde_json::from_str(&row.get::<_, String>(2))?;
            let enc: Vec<u8> = row.get(3);
            let plain = setjoin_config_secret::open_column(
                &enc,
                keys["secret"].as_str().unwrap().as_bytes(),
            )?;
            let expected = if a {
                issued.ok_or("actor row exists without issued-secret observation")?
            } else {
                FOREIGN_SECRET
            };
            if plain != expected.as_bytes() {
                return Err(
                    "stored envelope does not contain the secret handed to its owner".into(),
                );
            }
            if v["hmac_secret_key_id"] != "v1" {
                return Err("wrong key version".into());
            }
            v["id"] = json!(if a { "<device-a>" } else { "<device-b>" });
            v["user_id"] = json!(if a { "<actor>" } else { "<foreign>" });
            v["hmac_secret_enc"] = json!(if a {
                "<sealed-actor-secret>"
            } else {
                "<sealed-foreign-secret>"
            });
            for key in ["registered_at", "last_seen", "created_at", "updated_at"] {
                if let Some(t) = v.get_mut(key).filter(|v| !v.is_null()) {
                    timestamp(t)?;
                    *t = json!("<timestamp>");
                }
            }
            devices.push(v);
        }
        let raw:String=c.query_one("SELECT COALESCE(jsonb_agg(to_jsonb(e) ORDER BY device_id,id),'[]')::text FROM device_events e WHERE device_id=ANY($1::bigint[])",&[&ids.iter().map(|(id,_)|*id).collect::<Vec<_>>()]).await?.get(0);
        let mut events: Value = serde_json::from_str(&raw)?;
        for e in events.as_array_mut().unwrap() {
            let a = ids
                .iter()
                .find(|(id, _)| Some(*id) == e["device_id"].as_i64())
                .ok_or("foreign event row")?
                .1;
            e["device_id"] = json!(if a { "<device-a>" } else { "<device-b>" });
            e["id"] = json!("<event-id>");
            for key in ["created_at", "occurred_at"] {
                if let Some(t) = e.get_mut(key).filter(|v| !v.is_null()) {
                    timestamp(t)?;
                    *t = json!("<timestamp>");
                }
            }
        }
        Ok(json!({"devices":devices,"device_events":events}))
    }
    pub(super) async fn bootstrap_cleanup(&self, c: &tokio_postgres::Client) -> Result<(), Err> {
        c.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM device_events WHERE device_id IN (SELECT id FROM devices WHERE user_id IN ({},{}));DELETE FROM devices WHERE user_id IN ({},{});COMMIT;",self.a.user,self.b.user,self.a.user,self.b.user)).await?;
        c.execute(
            "DELETE FROM session_revocations WHERE user_id=ANY($1::bigint[])",
            &[&vec![self.a.user, self.b.user]],
        )
        .await?;
        Ok(())
    }
}
