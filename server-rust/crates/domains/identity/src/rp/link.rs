//! A link is authorized by the established session and its sealed flow, never
//! by the address asserted by a provider or an HTTP-owned target user.
use super::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use setjoin_pg::{CommandOutcome, StatementFailure, Type};
use sha2::{Digest, Sha256};
#[derive(Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Wire {
    user_id: i64,
    kind: String,
    provider_key: String,
    flow_id: String,
    session_jti: String,
    session_hash: String,
    expires_at: i64,
}
pub struct LinkFlow(Wire);
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
fn fresh(session: &crate::session::Session, seconds: i64) -> bool {
    matches!(session.text("acr"), "aal2" | "aal3")
        && session
            .claims()
            .get("iat")
            .and_then(Value::as_i64)
            .is_some_and(|iat| (now() as i128) - (iat as i128) <= seconds as i128)
}
fn row(rows: &[setjoin_pg::Row]) -> Result<Value, StatementFailure> {
    serde_json::from_str(&rows[0].get::<_, String>(0)).map_err(|_| StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid identity link result".into(),
    })
}
impl LinkFlow {
    pub fn begin(
        session: &crate::session::Session,
        cookie: &str,
        provider: &Provider,
    ) -> Option<Self> {
        Self::begin_for(session, cookie, "oidc", provider.key())
    }
    pub fn begin_saml(
        session: &crate::session::Session,
        cookie: &str,
        provider: &crate::saml::Registration,
    ) -> Option<Self> {
        Self::begin_for(session, cookie, "saml", provider.key())
    }
    fn begin_for(
        session: &crate::session::Session,
        cookie: &str,
        kind: &str,
        provider_key: String,
    ) -> Option<Self> {
        if session.user() <= 0
            || cookie.is_empty()
            || session.text("jti").is_empty()
            || !fresh(session, 300)
        {
            return None;
        }
        Some(Self(Wire {
            user_id: session.user(),
            kind: kind.into(),
            provider_key,
            flow_id: uuid::Uuid::new_v4().to_string(),
            session_jti: session.text("jti").into(),
            session_hash: format!("{:x}", Sha256::digest(cookie.as_bytes())),
            expires_at: now() + 600,
        }))
    }
    pub fn flow_id(&self) -> &str {
        &self.0.flow_id
    }
    pub fn seal(&self, master: &[u8]) -> Result<String, &'static str> {
        crate::webauthn::CookieCipher::new(master)
            .seal(&serde_json::to_vec(&self.0).map_err(|_| "link serialization")?)
    }
    pub async fn persist(
        &self,
        worker: &ScopedExecutor,
    ) -> CommandOutcome<Value, StatementFailure> {
        let w = &self.0;
        let hash = hex_hash(&w.session_hash).expect("own hash");
        let (command, sql) = if w.kind == "saml" {
            (
                "saml-link-begin",
                "SELECT rust_identity_saml_link_begin($1,$2::text::uuid,$3,$4,$5,$6)::text",
            )
        } else {
            (
                "rp-link-begin",
                "SELECT rust_identity_rp_link_begin($1,$2::text::uuid,$3,$4,$5,$6)::text",
            )
        };
        worker
            .clone()
            .with_user_receipt(setjoin_pg::ReceiptCommand {
                family: "F21",
                command,
            })
            .run_user_command(
                setjoin_contracts::ids::ActorId::new(w.user_id).expect("verified session"),
                setjoin_contracts::ids::OperationId(
                    *uuid::Uuid::parse_str(&w.flow_id)
                        .expect("own flow")
                        .as_bytes(),
                ),
                sql,
                &[
                    (&w.user_id, Type::INT8),
                    (&w.flow_id, Type::TEXT),
                    (&w.session_jti, Type::TEXT),
                    (&hash, Type::BYTEA),
                    (&w.provider_key, Type::TEXT),
                    (&w.expires_at, Type::INT8),
                ],
                row,
            )
            .await
    }
}
fn hex_hash(s: &str) -> Option<Vec<u8>> {
    if s.len() != 64 {
        return None;
    }
    (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}
pub struct AuthorizedLink(LinkFlow);
impl LinkFlow {
    pub fn open(wire: &str, master: &[u8], provider: &Provider) -> Option<Self> {
        Self::open_kind(wire, master, "oidc", &provider.key())
    }
    /// The SAML counterpart, for the ACS completing a link `begin_saml` started.
    pub fn open_saml(
        wire: &str,
        master: &[u8],
        registration: &crate::saml::Registration,
    ) -> Option<Self> {
        Self::open_kind(wire, master, "saml", &registration.key())
    }
    fn open_kind(wire: &str, master: &[u8], kind: &str, key: &str) -> Option<Self> {
        let bytes = crate::webauthn::CookieCipher::new(master).open(wire)?;
        let v: Wire = serde_json::from_slice(&bytes).ok()?;
        if v.kind != kind
            || v.provider_key != key
            || v.flow_id.is_empty()
            || v.session_jti.is_empty()
            || v.expires_at < now()
        {
            return None;
        }
        Some(Self(v))
    }
    pub async fn authorize(
        self,
        session: &crate::session::Session,
        raw: &str,
        exec: &ScopedExecutor,
    ) -> Result<AuthorizedLink, &'static str> {
        let w = &self.0;
        if session.text("typ") != "access"
            || session.user() != w.user_id
            || format!("{:x}", Sha256::digest(raw.as_bytes())) != w.session_hash
            || !fresh(session, 900)
        {
            return Err("linking session changed");
        }
        let live=exec.read("SELECT EXISTS(SELECT 1 FROM sessions WHERE user_id=$1 AND token_hash=digest($2,'sha256') AND expires_at>statement_timestamp())",&[(&w.user_id,Type::INT8),(&raw,Type::TEXT)]).await.ok().is_some_and(|r|r[0].get::<_,bool>(0));
        if !live {
            return Err("linking session is no longer active");
        }
        Ok(AuthorizedLink(self))
    }
}
impl LinkFlow {
    /// The cross-site callback verified an assertion for this sealed flow but cannot prove the
    /// session (the SameSite=Strict `access_token` cookie is not sent, #547): hold the assertion,
    /// bound to the flow, for the same-site completion request. Returns the one-time token (only
    /// its SHA-256 is stored). Holding links nothing and mints nothing.
    pub async fn hold(&self, worker: &ScopedExecutor, assertion: &Assertion) -> Option<String> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use ring::rand::SecureRandom;
        let mut raw = [0u8; 32];
        ring::rand::SystemRandom::new().fill(&mut raw).ok()?;
        let token = URL_SAFE_NO_PAD.encode(raw);
        let hash = Sha256::digest(token.as_bytes()).to_vec();
        let groups = assertion.groups.as_ref().map(|g| serde_json::to_string(g).unwrap());
        let w = &self.0;
        let rows = worker
            .protocol_query(
                "SELECT rust_identity_rp_link_hold($1,$2::text::uuid,$3,$4,$5,$6::text::jsonb)::text",
                &[
                    (&w.provider_key, Type::TEXT),
                    (&w.flow_id, Type::TEXT),
                    (&hash, Type::BYTEA),
                    (&assertion.issuer, Type::TEXT),
                    (&assertion.subject, Type::TEXT),
                    (&groups, Type::TEXT),
                ],
            )
            .await
            .ok()?;
        (row(&rows).ok()?["status"] == "held").then_some(token)
    }
}
impl AuthorizedLink {
    /// Single use, for this provider and this link flow only; the authorized session (not the
    /// completion URL) is what permits the take.
    pub async fn take_held(&self, worker: &ScopedExecutor, token: &str) -> Option<Assertion> {
        let hash = Sha256::digest(token.as_bytes()).to_vec();
        let w = &self.0 .0;
        let rows = worker
            .protocol_query(
                "SELECT rust_identity_rp_link_take($1,$2::text::uuid,$3)::text",
                &[(&w.provider_key, Type::TEXT), (&w.flow_id, Type::TEXT), (&hash, Type::BYTEA)],
            )
            .await
            .ok()?;
        let v = row(&rows).ok()?;
        if v["status"] != "taken" {
            return None;
        }
        Some(Assertion {
            email: String::new(),
            subject: v["subject"].as_str()?.to_owned(),
            issuer: v["issuer"].as_str()?.to_owned(),
            groups: v["groups"]
                .as_array()
                .map(|a| a.iter().filter_map(|g| g.as_str().map(str::to_owned)).collect()),
            kind: "oidc",
        })
    }
    pub fn flow_id(&self) -> &str {
        &self.0 .0.flow_id
    }
    pub async fn finish(
        self,
        worker: &ScopedExecutor,
        assertion: &Assertion,
        provider: &dyn Federated,
        allow_super: bool,
    ) -> CommandOutcome<Value, StatementFailure> {
        let w = &self.0 .0;
        let hash = hex_hash(&w.session_hash).expect("authorized cookie hash");
        let groups = assertion
            .groups
            .as_ref()
            .map(|g| serde_json::to_string(g).unwrap());
        let mappings = serde_json::to_string(provider.mappings()).unwrap();
        let operation = uuid::Uuid::new_v4();
        let (command, sql) = if w.kind == "saml" {
            ("saml-link-finish","SELECT rust_identity_saml_link_finish($1,$2,$3,$4,$5::text::uuid,$6,$7::text::jsonb,$8::text::jsonb,$9)::text")
        } else {
            ("rp-link-finish","SELECT rust_identity_rp_link_finish($1,$2,$3,$4,$5::text::uuid,$6,$7::text::jsonb,$8::text::jsonb,$9)::text")
        };
        worker.clone().with_user_receipt(setjoin_pg::ReceiptCommand{family:"F21",command}).run_user_command(setjoin_contracts::ids::ActorId::new(w.user_id).expect("verified link session"),setjoin_contracts::ids::OperationId(*operation.as_bytes()),
            sql,
            &[(&w.user_id,Type::INT8),(&assertion.issuer,Type::TEXT),(&assertion.subject,Type::TEXT),(&w.provider_key,Type::TEXT),(&w.flow_id,Type::TEXT),(&hash,Type::BYTEA),(&groups,Type::TEXT),(&mappings,Type::TEXT),(&allow_super,Type::BOOL)],row).await
    }
}
