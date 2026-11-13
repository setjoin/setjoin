//! The ACS side of a registration (#546): tracking-cookie admission, verification,
//! replay consumption, claim mapping and the audit rows. HTTP stays in the auth
//! binary; identity resolution and session minting reuse the OIDC RP's reducers.
use super::*;
use crate::saml_acs::{self, Claims, Expect, Fail};
use setjoin_pg::Type;

/// The SP-signed tracking JWT of a login this SP started.
pub struct Tracking {
    pub request_id: String,
    pub uri: String,
    /// `login` or `link`; a link never mints a session.
    pub purpose: String,
    /// The link flow a link-purpose login belongs to.
    pub flow: Option<String>,
}

pub enum Consumed {
    Fresh,
    Replayed,
    Failed,
}

/// Post-login redirect, same-origin paths only: one leading slash, no scheme or
/// authority, no backslash or control character, bounded, and never back into the
/// SAML endpoints (which would loop).
pub fn relay_target(raw: &str) -> String {
    if crate::mutants::on("saml-relay-open") {
        return raw.to_owned();
    }
    let safe = raw.starts_with('/')
        && !raw.starts_with("//")
        && raw.len() <= 512
        && !raw.contains('\\')
        && !raw.chars().any(|c| c.is_control())
        && !raw.starts_with("/auth/saml/");
    if safe {
        raw.to_owned()
    } else {
        "/".to_owned()
    }
}

/// A relay token is the random URL-safe value login issued (56 characters).
pub fn valid_relay(raw: &str) -> bool {
    !raw.is_empty()
        && raw.len() <= 128
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

impl Registration {
    pub fn id(&self) -> i64 {
        self.id
    }
    pub fn entity(&self) -> &str {
        &self.entity
    }
    pub fn acs_url(&self) -> &str {
        self.acs.as_str()
    }
    /// The tracking cookie's Path: the ACS endpoint alone.
    pub fn acs_path(&self) -> &str {
        self.acs.path()
    }
    pub fn jit(&self) -> bool {
        self.jit
    }
    /// Per-registration IdP-initiated SSO; default off.
    pub fn idp_initiated(&self) -> bool {
        self.idp_initiated || crate::mutants::on("saml-idp-initiated-default")
    }
    pub fn mappings(&self) -> &[crate::rp::Mapping] {
        &self.mappings
    }
    /// The same-site endpoint that finishes a link the ACS held.
    pub fn link_complete_path(&self) -> String {
        match self.acs.path().strip_suffix("/acs") {
            Some(base) => format!("{base}/link/complete"),
            None => "/".into(),
        }
    }
    /// Hold a verified link-purpose assertion for the completion request of `flow`; the
    /// one-time token is returned and only its SHA-256 is stored.
    pub async fn hold_link(
        &self,
        worker: &ScopedExecutor,
        flow: &str,
        subject: &str,
        groups: &Option<Vec<String>>,
    ) -> Option<String> {
        use sha2::{Digest, Sha256};
        let mut raw = [0u8; 32];
        SystemRandom::new().fill(&mut raw).ok()?;
        let token = URL_SAFE_NO_PAD.encode(raw);
        let hash = Sha256::digest(token.as_bytes()).to_vec();
        let groups = groups.as_ref().map(|g| json!(g).to_string());
        let rows = worker
            .protocol_query(
                "SELECT rust_identity_saml_link_hold($1,$2::text::uuid,$3,$4,$5::text::jsonb)::text",
                &[
                    (&self.id, Type::INT8),
                    (&flow, Type::TEXT),
                    (&hash, Type::BYTEA),
                    (&subject, Type::TEXT),
                    (&groups, Type::TEXT),
                ],
            )
            .await
            .ok()?;
        let v: Value = serde_json::from_str(&rows.first()?.try_get::<_, String>(0).ok()?).ok()?;
        (v["status"] == "held").then_some(token)
    }
    /// Single-use release of the held assertion for this link flow.
    pub async fn take_link(
        &self,
        worker: &ScopedExecutor,
        flow: &str,
        token: &str,
    ) -> Option<(String, Option<Vec<String>>)> {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(token.as_bytes()).to_vec();
        let rows = worker
            .protocol_query(
                "SELECT rust_identity_saml_link_take($1,$2::text::uuid,$3)::text",
                &[(&self.id, Type::INT8), (&flow, Type::TEXT), (&hash, Type::BYTEA)],
            )
            .await
            .ok()?;
        let v: Value = serde_json::from_str(&rows.first()?.try_get::<_, String>(0).ok()?).ok()?;
        if v["status"] != "taken" {
            return None;
        }
        let groups = v["groups"]
            .as_array()
            .map(|a| a.iter().filter_map(|g| g.as_str().map(str::to_owned)).collect());
        Some((v["subject"].as_str()?.to_owned(), groups))
    }
    /// The identity of a held link, for the sealed finish.
    pub fn held_assertion(&self, subject: String, groups: Option<Vec<String>>) -> crate::rp::Assertion {
        crate::rp::Assertion::saml(self.entity.clone(), subject, String::new(), groups)
    }
    /// The cookie name login set for this relay token.
    pub fn tracking_cookie(relay: &str) -> String {
        format!("saml_{relay}")
    }
    /// Admit the tracking cookie of a login this SP started: SP signature, issuer,
    /// audience, purpose, subject = this relay token, and its 90 second window.
    pub fn open_tracking(&self, relay: &str, jwt: &str) -> Option<Tracking> {
        let claims = self.sp_jwt_claims(jwt)?;
        let now = now();
        let audience = match &claims["aud"] {
            Value::Array(a) => a.iter().any(|v| *v == self.root),
            Value::String(s) => *s == self.root,
            _ => false,
        };
        if claims["iss"] != self.root
            || !audience
            || claims["saml-authn-request"] != true
            || claims["sub"] != relay
            || claims["exp"].as_i64()? < now
            || claims["nbf"].as_i64()? > now + 30
        {
            return None;
        }
        // The purpose and the registration are SP-signed: a cookie for one registration or
        // purpose is not an answer to another.
        let unbound = crate::mutants::on("saml-purpose-unbound");
        if claims["reg"].as_i64() != Some(self.id) && !unbound {
            return None;
        }
        let purpose = claims["purpose"].as_str().unwrap_or("").to_owned();
        let flow = claims["flow"].as_str().map(str::to_owned);
        if !unbound && !(purpose == "login" || (purpose == "link" && flow.is_some())) {
            return None;
        }
        Some(Tracking {
            request_id: claims["id"].as_str().filter(|s| !s.is_empty())?.to_owned(),
            uri: claims["uri"].as_str().unwrap_or("/").to_owned(),
            purpose,
            flow,
        })
    }
    /// Verify one SAMLResponse (already decoded) for this registration.
    pub fn verify_acs(
        &self,
        xml: &[u8],
        in_response_to: Option<&str>,
        at: i64,
    ) -> Result<Claims, Fail> {
        saml_acs::process(
            xml,
            &self.pins,
            &Expect {
                idp_entity_id: &self.entity,
                audiences: &self.audiences,
                acs_url: self.acs.as_str(),
                in_response_to,
                now: at,
            },
        )
    }
    /// Consume the assertion (and, SP-initiated, its request) exactly once.
    pub async fn consume(
        &self,
        worker: &ScopedExecutor,
        claims: &Claims,
        request_id: Option<&str>,
    ) -> Consumed {
        let expires = claims.not_on_or_after.saturating_add(saml_acs::SKEW);
        let request = request_id.map(str::to_owned);
        let rows = worker
            .protocol_query(
                "SELECT rust_identity_saml_consume($1,$2,$3,$4)::text",
                &[
                    (&self.id, Type::INT8),
                    (&claims.assertion_id, Type::TEXT),
                    (&request, Type::TEXT),
                    (&expires, Type::INT8),
                ],
            )
            .await;
        let status = rows
            .ok()
            .and_then(|r| r.first().and_then(|r| r.try_get::<_, String>(0).ok()))
            .and_then(|s| serde_json::from_str::<Value>(&s).ok())
            .and_then(|v| v["status"].as_str().map(str::to_owned));
        match status.as_deref() {
            Some("consumed") => Consumed::Fresh,
            Some("replayed") if crate::mutants::on("saml-replay-ignored") => Consumed::Fresh,
            Some("replayed") => Consumed::Replayed,
            _ => Consumed::Failed,
        }
    }
    /// An email for provisioning, from the registration's mapped attribute, then the
    /// customary attribute names, then an email-shaped NameID. Never used to find a
    /// user; the link key is (registration, NameID).
    pub fn email(&self, claims: &Claims) -> Option<String> {
        let mut names: Vec<&str> = self
            .attribute_map
            .iter()
            .filter(|(_, field)| field.as_str() == "email")
            .map(|(attribute, _)| attribute.as_str())
            .collect();
        names.extend([
            "email",
            "mail",
            "emailaddress",
            "urn:oid:0.9.2342.19200300.100.1.3",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        ]);
        for name in names {
            if let Some(v) = claims.attributes.get(name).and_then(|v| v.first()) {
                if !v.is_empty() {
                    return Some(v.clone());
                }
            }
        }
        let id = claims
            .name_id
            .strip_prefix("mailto:")
            .unwrap_or(&claims.name_id);
        id.contains('@').then(|| id.to_owned())
    }
    /// The group attribute (default `memberOf`); a malformed set is refused as OIDC's.
    pub fn groups(&self, claims: &Claims) -> Result<Option<Vec<String>>, &'static str> {
        let name = if self.group_attribute.is_empty() {
            "memberOf"
        } else {
            &self.group_attribute
        };
        let groups = claims.attributes.get(name).cloned();
        if groups.as_ref().is_some_and(|g| {
            g.len() > 1000
                || g.iter().any(|s| {
                    s.trim().is_empty() || s.len() > 1024 || s.chars().any(char::is_control)
                })
        }) {
            return Err("invalid SAML group assertion");
        }
        Ok(groups)
    }
    /// The sealed identity this login resolves; subject is the NameID, provider the
    /// registration's IdP entity ID.
    pub fn assertion(&self, claims: &Claims, groups: Option<Vec<String>>) -> crate::rp::Assertion {
        crate::rp::Assertion::saml(
            self.entity.clone(),
            claims.name_id.clone(),
            self.email(claims).unwrap_or_default(),
            groups,
        )
    }
}

impl crate::rp::Federated for Registration {
    fn key(&self) -> String {
        Registration::key(self)
    }
    fn mappings(&self) -> &[crate::rp::Mapping] {
        &self.mappings
    }
}

/// One audit row per ACS outcome (`saml.acs.success`, `saml.acs.<failure class>`):
/// a single `audit_write` statement. The actor is the signed-in user on success and
/// NULL on a failure (nothing is authenticated); no assertion content is recorded.
pub async fn audit(
    exec: &ScopedExecutor,
    registration: i64,
    action: &str,
    actor: Option<i64>,
    ip: &str,
    notes: &str,
) {
    let action = format!("saml.acs.{action}");
    let _ = exec
        .protocol_statement(
            "SELECT audit_write($1,$2,'saml_registration',$3,NULL,NULL,NULLIF($4,'')::inet,$5,'core')",
            &[
                (&actor, Type::INT8),
                (&action, Type::TEXT),
                (&registration, Type::INT8),
                (&ip, Type::TEXT),
                (&notes, Type::TEXT),
            ],
        )
        .await;
}
