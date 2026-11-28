//! Complete SCIM revocation store/evidence observation, under the fixture owner.
use super::{json, Err, Seed, Value};
impl Seed {
    pub(super) async fn scim_seed(&self, c: &tokio_postgres::Client) -> Result<(), Err> {
        for (user, label) in [(self.a.user, "a"), (self.b.user, "b")] {
            let id = format!("idlogin3-session-{label}");
            let client = format!("idlogin3-client-{label}");
            let external = format!("idlogin3-external-{label}");
            c.execute(
                "UPDATE users SET scim_external_id=$2 WHERE id=$1",
                &[&user, &external],
            )
            .await?;
            c.execute("INSERT INTO sessions(id,user_id,token_hash,auth_method,created_at,last_seen_at,expires_at) VALUES($1,$2,digest($1,'sha256'),'password','2026-01-02','2026-01-02','2036-01-02')",&[&id,&user]).await?;
            c.execute("INSERT INTO oidc_tokens(id,client_id,user_id,subject,scopes,expires_at,created_at) VALUES($1,$2,$3,'fixture',ARRAY['openid'],'2036-01-02','2026-01-02')",&[&id,&client,&user]).await?;
            c.execute("INSERT INTO ws_subscriptions(connection_id,session_id,user_id,subscribed_at,last_ping_at) VALUES($1,$1,$2,'2026-01-02','2026-01-02')",&[&id,&user]).await?;
            c.execute("INSERT INTO session_revocations(user_id,scope,not_before,reason,created_at,expires_at) VALUES($1,'all','2020-01-02','fixture','2020-01-02','2036-01-02')",&[&user]).await?;
            let flow = if label == "a" {
                "33333333-3333-4333-8333-333333333331"
            } else {
                "33333333-3333-4333-8333-333333333332"
            };
            c.execute("INSERT INTO identity_auth_link_elevations(flow_id,user_id,session_jti,session_hash,kind,provider_key,created_at,expires_at) VALUES($1::text::uuid,$2,$3,digest($3,'sha256'),'oidc','fixture','2036-01-02','2036-01-02 00:05')",&[&flow,&user,&id]).await?;
            c.execute("INSERT INTO mfa_reauth_step_ups(token_hash,user_id,session_jti,created_at,expires_at,operation,proof_method,bound_factor_generation,token_scope) VALUES($1,$2,$1,'2026-01-02','2036-01-02','device.register.native','password',0,'session')",&[&id,&user]).await?;
            c.execute("INSERT INTO webauthn_ceremonies(challenge_hash,user_id,kind,operation,session_jti,created_at,expires_at) VALUES($1,$2,'registration','webauthn.register',$1,'2026-01-02','2036-01-02')",&[&id,&user]).await?;
        }
        Ok(())
    }
    pub(super) fn normalize_store(&self, v: &mut Value) {
        match v {
            Value::Array(a) => {
                for v in a {
                    self.normalize_store(v)
                }
            }
            Value::Object(m) => {
                for key in ["user_id", "target_id", "created_by"] {
                    if let Some(v) = m.get_mut(key) {
                        if *v == self.a.user {
                            *v = json!("<actor>")
                        } else if *v == self.b.user {
                            *v = json!("<foreign>")
                        }
                    }
                }
                if let Some(v) = m.get_mut("id").filter(|v| v.is_number()) {
                    *v = json!("<id>");
                }
                if m.get("reason").and_then(Value::as_str) == Some("token_revoke_all")
                    || m.get("action").and_then(Value::as_str) == Some("revoke_user_sessions")
                    || m.contains_key("not_before") && !m.contains_key("reason")
                {
                    for key in ["not_before", "expires_at", "created_at", "occurred_at"] {
                        if let Some(v) = m.get_mut(key).filter(|v| !v.is_null()) {
                            *v = json!("<timestamp>");
                        }
                    }
                }
                if let Some(v) = m.get_mut("revoked_at").filter(|v| !v.is_null()) {
                    *v = json!("<timestamp>");
                }
                for v in m.values_mut() {
                    self.normalize_store(v)
                }
            }
            _ => {}
        }
    }
    pub(super) async fn stores(&self, c: &tokio_postgres::Client) -> Result<Value, Err> {
        let mut out = json!({"oauth_tokens":self.rows(c).await?});
        for table in [
            "sessions",
            "oidc_tokens",
            "ws_subscriptions",
            "session_revocations",
            "identity_auth_link_elevations",
            "mfa_reauth_step_ups",
            "webauthn_ceremonies",
        ] {
            // Fixed table allowlist; request text never enters fixture SQL.
            // V279 (#523) added refresh_family columns the frozen-Go goldens predate: the
            // fixture rows must leave them NULL, then they are projected out.
            let projected = if table == "oidc_tokens" {
                let set: i64 = c
                    .query_one("SELECT count(*) FROM oidc_tokens WHERE user_id=ANY($1::bigint[]) AND (refresh_family IS NOT NULL OR refresh_family_expires_at IS NOT NULL)", &[&vec![self.a.user, self.b.user]])
                    .await?
                    .get(0);
                assert_eq!(set, 0, "fixture oidc_tokens rows must not carry a refresh family");
                "(to_jsonb(t) - 'refresh_family' - 'refresh_family_expires_at')"
            } else {
                "to_jsonb(t)"
            };
            let sql=format!("SELECT COALESCE(jsonb_agg({projected} ORDER BY user_id,{projected}::text),'[]')::text FROM {table} t WHERE user_id=ANY($1::bigint[])");
            let raw: String = c
                .query_one(&sql, &[&vec![self.a.user, self.b.user]])
                .await?
                .get(0);
            let mut rows: Value = serde_json::from_str(&raw)?;
            self.normalize_store(&mut rows);
            out[table] = rows;
        }
        Ok(out)
    }
    pub(super) async fn scim_audit(&self, c: &tokio_postgres::Client) -> Result<Value, Err> {
        let ids = vec![self.a.user, self.b.user];
        let valid:bool=c.query_one("SELECT COALESCE(bool_and(valid),true) FROM verify_audit_chain((SELECT min(id) FROM admin_audit_log WHERE action='revoke_user_sessions' AND target_type='user' AND target_id=ANY($1::bigint[])),(SELECT max(id) FROM admin_audit_log WHERE action='revoke_user_sessions' AND target_type='user' AND target_id=ANY($1::bigint[])))",&[&ids]).await?.get(0);
        if !valid {
            return Err("invalid persisted audit chain".into());
        }
        let raw:String=c.query_one("SELECT COALESCE(jsonb_agg(to_jsonb(t)-'checksum' ORDER BY id),'[]')::text FROM admin_audit_log t WHERE action='revoke_user_sessions' AND target_type='user' AND target_id=ANY($1::bigint[])",&[&ids]).await?.get(0);
        let mut rows: Value = serde_json::from_str(&raw)?;
        self.normalize_store(&mut rows);
        Ok(rows)
    }
    pub(super) async fn scim_cleanup(&self, c: &tokio_postgres::Client) -> Result<(), Err> {
        c.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM admin_audit_log WHERE action='revoke_user_sessions' AND target_type='user' AND target_id IN ({},{});COMMIT;",self.a.user,self.b.user)).await?;
        for table in [
            "oidc_tokens",
            "ws_subscriptions",
            "sessions",
            "identity_auth_link_elevations",
            "mfa_reauth_step_ups",
            "webauthn_ceremonies",
            "session_revocations",
        ] {
            c.execute(
                &format!("DELETE FROM {table} WHERE user_id=ANY($1::bigint[])"),
                &[&vec![self.a.user, self.b.user]],
            )
            .await?;
        }
        Ok(())
    }
}
