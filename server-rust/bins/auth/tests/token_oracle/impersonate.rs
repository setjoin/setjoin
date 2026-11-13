use super::*;
impl Seed {
    pub(super) async fn impersonation_seed(
        &self,
        c: &tokio_postgres::Client,
        kind: &str,
    ) -> Result<(), Err> {
        let group = if matches!(kind, "missing-permission" | "domain-scope" | "disabled") {
            let perms = if kind == "missing-permission" {
                vec!["users.view"]
            } else {
                vec!["users.impersonate"]
            };
            let scope = if kind == "domain-scope" {
                Some(self.a.domain)
            } else {
                None
            };
            c.query_one("INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,$2,$3) RETURNING id",&[&format!("idlogin3-impersonate-{}",self.a.user),&perms,&scope]).await?.get::<_,i64>(0)
        } else {
            1
        };
        c.execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
            &[&self.a.user, &group],
        )
        .await?;
        match kind {
            "peer" => {
                c.execute("INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,1,$2)",&[&self.b.user,&self.a.user]).await?;
            }
            "expired-grant" => {
                c.execute("UPDATE admin_role_assignments SET expires_at=now()-interval '1 second' WHERE user_id=$1",&[&self.a.user]).await?;
            }
            "inactive-grant" => {
                c.execute("UPDATE admin_role_assignments SET eligible=true,activated_until=NULL WHERE user_id=$1",&[&self.a.user]).await?;
            }
            "disabled" => {
                c.execute(
                    "UPDATE users SET enabled=false WHERE id=$1",
                    &[&self.a.user],
                )
                .await?;
            }
            _ => {}
        }
        Ok(())
    }
    pub(super) async fn impersonation_rows(
        &self,
        c: &tokio_postgres::Client,
    ) -> Result<Value, Err> {
        let raw:String=c.query_one("SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY id),'[]')::text FROM audit_log a WHERE user_id=ANY($1::bigint[]) AND event_type LIKE 'admin_impersonate%'",&[&vec![self.a.user,self.b.user]]).await?.get(0);
        let mut rows: Value = serde_json::from_str(&raw)?;
        for row in rows.as_array_mut().unwrap() {
            row["id"] = json!("<audit-id>");
            row["occurred_at"] = json!("<timestamp>");
            row["user_id"] = json!(if row["user_id"] == self.a.user {
                "<actor>"
            } else {
                "<foreign>"
            });
            if row["metadata"]["target_user_id"] == self.b.user {
                row["metadata"]["target_user_id"] = json!("<foreign>");
            }
            if row["metadata"]["target_email"] == self.foreign {
                row["metadata"]["target_email"] = json!("foreign@idlogin3.test");
            }
        }
        Ok(rows)
    }
    pub(super) fn impersonation_cookie(
        &self,
        headers: &mut Value,
        keys: &Value,
    ) -> Result<Value, Err> {
        let cookie = headers["set-cookie"]
            .as_str()
            .ok_or("missing impersonation cookie")?;
        let token = cookie
            .split(';')
            .next()
            .unwrap()
            .strip_prefix("access_token=")
            .ok_or("wrong cookie name")?;
        let verify = setjoin_authz::legacy_jwt::LegacyKeys::new(
            keys["secret"].as_str().unwrap().as_bytes(),
            &["authserver-hmac-1"],
            None,
        )?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        let mut claims = Value::Object(
            verify
                .validate(token, "mailserver", "mailserver-gateway", now as f64)
                .ok_or("Go/Rust impersonation signature failed")?,
        );
        if claims["uid"] != self.b.user
            || claims["act"] != self.a.user
            || claims["admin"] == true
            || claims["typ"] != "access"
            || claims["sub"] != self.b.user.to_string()
        {
            return Err(format!("wrong issued impersonation authority: {claims}").into());
        }
        let iat = claims["iat"].as_i64().ok_or("missing issued-at")?;
        if (now - iat).abs() > 5
            || claims["exp"].as_i64() != Some(iat + 900)
            || claims["nbf"] != iat
        {
            return Err("wrong impersonation lifetime".into());
        }
        let jti = claims["jti"].as_str().ok_or("missing JTI")?;
        if jti.len() != 32 || !jti.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err("invalid random JTI".into());
        }
        let normalized = cookie.replacen(token, "<signed-impersonation-token>", 1);
        headers["set-cookie"] = json!(normalized);
        claims["uid"] = json!("<foreign>");
        claims["email"] = json!("foreign@idlogin3.test");
        claims["act"] = json!("<actor>");
        claims["sub"] = json!("<foreign>");
        for key in ["iat", "exp", "nbf"] {
            claims[key] = json!("<timestamp>");
        }
        claims["jti"] = json!("<random-jti>");
        Ok(claims)
    }
    pub(super) async fn impersonation_cleanup(
        &self,
        c: &tokio_postgres::Client,
    ) -> Result<(), Err> {
        c.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM audit_log WHERE user_id IN ({},{}) AND event_type LIKE 'admin_impersonate%';DELETE FROM admin_role_assignments WHERE user_id IN ({},{});COMMIT;",self.a.user,self.b.user,self.a.user,self.b.user)).await?;
        c.execute(
            "DELETE FROM admin_role_groups WHERE name=$1",
            &[&format!("idlogin3-impersonate-{}", self.a.user)],
        )
        .await?;
        Ok(())
    }
}
