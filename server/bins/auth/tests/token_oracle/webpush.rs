use super::*;
const KEY: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const FOREIGN: &str = r#"{"endpoint":"https://foreign.push.idlogin3.test/send","keys":{"auth":"foreign","p256dh":"foreign"}}"#;
impl Seed {
    pub(super) async fn webpush_seed(&self, c: &tokio_postgres::Client) -> Result<(), Err> {
        c.execute("INSERT INTO push_devices(user_id,push_provider,push_token_enc,device_name) VALUES($1,'webpush',pgp_sym_encrypt($2::text,$3),'Foreign subscription')",&[&self.b.user,&FOREIGN,&KEY]).await?;
        Ok(())
    }
    pub(super) async fn webpush_rows(&self, c: &tokio_postgres::Client) -> Result<Value, Err> {
        let rows=c.query("SELECT user_id,to_jsonb(d)::text,pgp_sym_decrypt(push_token_enc,$2) FROM push_devices d WHERE user_id=ANY($1::bigint[]) ORDER BY user_id,id",&[&vec![self.a.user,self.b.user],&KEY]).await?;
        let mut out = Vec::new();
        let mut ai = 0;
        let mut bi = 0;
        for row in rows {
            let a = row.get::<_, i64>(0) == self.a.user;
            let raw: String = row.get(1);
            let plain: String = row.get(2);
            if !a && plain != FOREIGN {
                return Err("foreign subscription changed".into());
            }
            let mut v: Value = serde_json::from_str(&raw)?;
            let n = if a {
                ai += 1;
                ai
            } else {
                bi += 1;
                bi
            };
            v["id"] = json!(format!("<push-{}-{n}>", if a { "a" } else { "b" }));
            v["user_id"] = json!(if a { "<actor>" } else { "<foreign>" });
            v["push_token_enc"] = json!(format!("<PGP encrypted: {plain}>"));
            for key in ["created_at", "last_used_at", "revoked_at"] {
                if let Some(t) = v.get_mut(key).filter(|v| !v.is_null()) {
                    super::bootstrap::timestamp(t)?;
                    *t = json!("<timestamp>");
                }
            }
            out.push(v);
        }
        Ok(json!(out))
    }
    pub(super) async fn webpush_cleanup(&self, c: &tokio_postgres::Client) -> Result<(), Err> {
        c.execute(
            "DELETE FROM push_devices WHERE user_id=ANY($1::bigint[])",
            &[&vec![self.a.user, self.b.user]],
        )
        .await?;
        Ok(())
    }
}
