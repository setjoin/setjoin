//! Only verified, nonce-bound, email-verified assertions reach account resolution.
use super::*;
use serde_json::{json, Value};
use setjoin_pg::{StatementFailure, Type};

pub struct Assertion {
    pub(super) email: String,
    pub(super) subject: String,
    pub(super) issuer: String,
    pub(super) groups: Option<Vec<String>>,
    /// `oidc`, or `saml` for a verified SAML ACS login (#546). A SAML identity is the
    /// exact (registration IdP entity, NameID) pair and is never matched by address.
    pub(super) kind: &'static str,
}
impl Assertion {
    /// A verified SAML assertion's identity: provider = registration IdP entity ID,
    /// subject = NameID. Only the ACS, after signature verification, builds one.
    pub fn saml(issuer: String, subject: String, email: String, groups: Option<Vec<String>>) -> Self {
        Self { email, subject, issuer, groups, kind: "saml" }
    }
    pub fn subject(&self) -> &str {
        &self.subject
    }
}
/// What federated resolution needs of its provider (OIDC provider or SAML registration).
pub trait Federated: Sync {
    fn key(&self) -> String;
    fn mappings(&self) -> &[Mapping];
}
impl Federated for Provider {
    fn key(&self) -> String {
        Provider::key(self)
    }
    fn mappings(&self) -> &[Mapping] {
        &self.config.group_mappings
    }
}
impl VerifiedClaims {
    pub fn assertion(
        self,
        nonce: Option<&str>,
        provider: &Provider,
    ) -> Result<Assertion, &'static str> {
        if !self.nonce_matches(nonce) || !self.email_verified {
            return Err("unverified assertion");
        }
        // `email_verified` vouches for the `email` claim only. Frozen Go also fell
        // back to preferred_username/upn, which the IdP does not verify and which
        // drove JIT creation and the per-login email update (security fix #530).
        let fallback: &[&str] = if crate::mutants::on("rp-email-fallback") {
            &["email", "preferred_username", "upn"]
        } else {
            &["email"]
        };
        let email = fallback
            .iter()
            .find_map(|k| self.raw[*k].as_str().filter(|s| !s.is_empty()))
            .ok_or("no email in ID token")?
            .to_owned();
        let subject = self.raw["sub"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or("no subject in ID token")?
            .to_owned();
        let claim = if provider.config.group_claim.is_empty() {
            "groups"
        } else {
            &provider.config.group_claim
        };
        let groups = match self.raw.get(claim) {
            None => None,
            Some(Value::String(s)) => Some(vec![s.clone()]),
            Some(Value::Array(a)) => Some(
                a.iter()
                    .map(|v| {
                        v.as_str()
                            .map(str::to_owned)
                            .ok_or("invalid OIDC group assertion")
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            _ => return Err("invalid OIDC group assertion"),
        };
        if groups.as_ref().is_some_and(|g| {
            g.len() > 1000
                || g.iter().any(|s| {
                    s.trim().is_empty() || s.len() > 1024 || s.chars().any(char::is_control)
                })
        }) {
            return Err("invalid OIDC group assertion");
        }
        Ok(Assertion {
            email,
            subject,
            issuer: self.raw["iss"].as_str().unwrap_or("").into(),
            groups,
            kind: "oidc",
        })
    }
}
pub enum Lookup<'a> {
    Existing(Resolution),
    Missing(Missing<'a>),
}
pub struct Missing<'a> {
    assertion: &'a Assertion,
    /// The source serves normalized reads (the new user is created with its link and fence).
    normalized: bool,
    /// `feature.identity_model_v2` is on: settlement reconciles normalized grants and needs
    /// the link even where the source is not (yet) serving (#547).
    feature: bool,
}
#[derive(Clone)]
pub struct Resolution {
    pub(super) user: crate::totp::CompletionUser,
    pub(super) fence: Option<Value>,
}
impl Resolution {
    pub fn user(&self) -> &crate::totp::CompletionUser {
        &self.user
    }
}
fn failed(detail: &str) -> StatementFailure {
    StatementFailure {
        sqlstate: None,
        hint: None,
        message: detail.into(),
    }
}
impl Assertion {
    /// Go's exact-pair cascade. The trusted worker is used only for normalized
    /// cross-tenant identity reducers; candidate identity never comes from HTTP.
    pub async fn resolve(
        &self,
        exec: &ScopedExecutor,
        worker: &ScopedExecutor,
    ) -> Result<Lookup<'_>, StatementFailure> {
        let normalized = crate::login::enabled(exec, "feature.identity_model_v2")
            .await
            .unwrap_or(false);
        let mut evidence = Value::Null;
        let mut serve = false;
        let mut user = None;
        let mut fence = None;
        if normalized {
            let rows = worker
                .read(
                    "SELECT identity_auth_resolve($3,$1,$2)::text",
                    &[(&self.issuer, Type::TEXT), (&self.subject, Type::TEXT), (&self.kind, Type::TEXT)],
                )
                .await
                .map_err(|_| failed("normalized identity resolution unavailable"))?;
            evidence = serde_json::from_str(&rows[0].get::<_, String>(0))
                .map_err(|_| failed("normalized identity resolution unavailable"))?;
            serve = evidence["serveNormalized"] == true;
            if serve && evidence["found"] == true {
                user = Some(
                    evidence["userId"]
                        .as_str()
                        .and_then(|s| s.parse::<i64>().ok())
                        .ok_or_else(|| failed("normalized identity resolution unavailable"))?,
                );
                fence = Some(
                    json!({"source_id":number(&evidence,"sourceId")?,"source_generation":number(&evidence,"sourceGeneration")?,"link_id":number(&evidence,"linkId")?,"link_generation":number(&evidence,"linkGeneration")?}),
                );
            }
        }
        if !serve {
            // Credential lookup is the authentication boundary, as password lookup.
            let exact = if self.kind == "saml" {
                "SELECT id FROM users WHERE saml_name_id=$1 AND saml_idp_entity_id=$2 AND enabled"
            } else {
                "SELECT id FROM users WHERE oidc_subject=$1 AND oidc_issuer=$2 AND enabled"
            };
            if let Ok(rows) = exec
                .read(
                    exact,
                    &[(&self.subject, Type::TEXT), (&self.issuer, Type::TEXT)],
                )
                .await
            {
                user = rows.first().map(|r| r.get(0));
            }
            let mut address_hit = false;
            // SAML: the link is (registration, NameID), never an address (#546).
            if user.is_none() && (self.kind == "oidc" || crate::mutants::on("saml-link-by-email")) {
                let address = setjoin_authz::address::canonical(&self.email);
                if let Ok(rows)=exec.read("SELECT u.id FROM users u WHERE u.enabled AND (lower(u.email)=lower($1) OR lower(u.ad_upn)=lower($1) OR EXISTS(SELECT 1 FROM aliases a JOIN mailboxes mb ON mb.id=a.mailbox_id WHERE mb.user_id=u.id AND lower(a.email)=lower($1))) AND identity_address_claim_count(lower($1))=1 AND NOT identity_address_quarantined(lower($1)) LIMIT 1",&[(&address.as_str(),Type::TEXT)]).await {user=rows.first().map(|r|r.get(0));address_hit=user.is_some();}
            }
            if evidence["sourceId"].is_string() {
                let source = number(&evidence, "sourceId")?;
                let generation = number(&evidence, "sourceGeneration")?;
                let link = optional_number(&evidence, "linkId");
                let linkgen = optional_number(&evidence, "linkGeneration");
                let norm = optional_number(&evidence, "userId");
                let _ = worker
                    .protocol_statement(
                        "SELECT identity_auth_shadow_observe($9,$1,$2,$3,$4,$5,$6,$7,$8)",
                        &[
                            (&self.issuer, Type::TEXT),
                            (&self.subject, Type::TEXT),
                            (&source, Type::INT8),
                            (&generation, Type::INT8),
                            (&link, Type::INT8),
                            (&linkgen, Type::INT8),
                            (&norm, Type::INT8),
                            (&user, Type::INT8),
                            (&self.kind, Type::TEXT),
                        ],
                    )
                    .await;
            }
            if address_hit {
                let id = user.unwrap();
                let guest = exec
                    .read("SELECT is_guest_account($1)", &[(&id, Type::INT8)])
                    .await
                    .map_err(|_| failed("account type resolution failed"))?[0]
                    .get::<_, bool>(0);
                return Err(failed(if guest {
                    "sso: identity resolves to a guest account"
                } else {
                    "explicit account linking is required"
                }));
            }
        }
        let Some(user) = user else {
            return Ok(Lookup::Missing(Missing {
                assertion: self,
                normalized: serve,
                feature: normalized,
            }));
        };
        let rows=exec.read("SELECT email,EXISTS(SELECT 1 FROM admin_role_assignments ara WHERE ara.user_id=u.id AND (ara.expires_at IS NULL OR ara.expires_at>now())) FROM users u WHERE u.id=$1 AND u.enabled",&[(&user,Type::INT8)]).await?;
        let r = rows
            .first()
            .ok_or_else(|| failed("normalized identity resolution unavailable"))?;
        let guest = exec
            .read("SELECT is_guest_account($1)", &[(&user, Type::INT8)])
            .await
            .map_err(|_| failed("account type resolution failed"))?[0]
            .get::<_, bool>(0);
        if guest {
            return Err(failed("sso: identity resolves to a guest account"));
        }
        Ok(Lookup::Existing(Resolution {
            user: crate::totp::CompletionUser {
                user,
                email: r.get(0),
                admin: r.get(1),
            },
            fence,
        }))
    }
}
fn optional_number(v: &Value, k: &str) -> Option<i64> {
    v[k].as_str().and_then(|s| s.parse().ok())
}
fn number(v: &Value, k: &str) -> Result<i64, StatementFailure> {
    optional_number(v, k)
        .filter(|n| *n > 0)
        .ok_or_else(|| failed("normalized identity resolution unavailable"))
}
impl Assertion {
    pub async fn settle(
        &self,
        exec: &ScopedExecutor,
        worker: &ScopedExecutor,
        provider: &dyn Federated,
        resolution: &Resolution,
        allow_super: bool,
    ) -> Result<crate::totp::CompletionUser, StatementFailure> {
        let normalized = crate::login::enabled(exec, "feature.identity_model_v2")
            .await
            .unwrap_or(false);
        let key = provider.key();
        let bind = worker
            .protocol_statement(
                "SELECT identity_source_provider_bind($3,$1,$2)",
                &[(&self.issuer, Type::TEXT), (&key, Type::TEXT), (&self.kind, Type::TEXT)],
            )
            .await;
        if normalized && bind.is_err() {
            return Err(failed("normalized identity source binding failed"));
        }
        // A SAML assertion never rewrites an existing account's address (#546): the
        // user is the (registration, NameID) link, and an IdP-asserted attribute is
        // not allowed to move the mailbox identity. OIDC keeps Go's per-login update.
        let email = if self.kind == "saml" {
            resolution.user.email.clone()
        } else {
            normalized_email(&self.email)
                .ok_or_else(|| failed("SSO profile reconciliation failed"))?
        };
        let groups = self.groups.as_ref().map(|v| json!(v).to_string());
        let mappings = serde_json::to_string(provider.mappings())
            .map_err(|_| failed("SSO entitlement reconciliation failed"))?;
        let user = resolution.user.user;
        let operation = setjoin_contracts::ids::OperationId(*uuid::Uuid::new_v4().as_bytes());
        let outcome=worker.clone().with_user_receipt(setjoin_pg::ReceiptCommand{family:"F21",command:"rp-settle"}).run_user_command(setjoin_contracts::ids::ActorId::new(user).map_err(|_|failed("SSO entitlement transaction unavailable"))?,operation,"SELECT rust_identity_rp_settle($1,$2,$3,$4::text::jsonb,$5::text::jsonb,$6,$7)::text",&[(&user,Type::INT8),(&email,Type::TEXT),(&key,Type::TEXT),(&groups,Type::TEXT),(&mappings,Type::TEXT),(&allow_super,Type::BOOL),(&normalized,Type::BOOL)],json_row).await;
        match outcome {
            setjoin_pg::CommandOutcome::Committed(v) if v["status"] == "settled" => {}
            setjoin_pg::CommandOutcome::Committed(v) => {
                return Err(failed(match v["status"].as_str() {
                    Some("profile_failed") => "SSO profile reconciliation failed",
                    Some("normalized_failed") => "normalized SSO entitlement reconciliation failed",
                    _ => "SSO entitlement reconciliation failed",
                }))
            }
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                return Err(StatementFailure {
                    sqlstate: None,
                    hint: Some(uuid::Uuid::from_bytes(operation.0).to_string()),
                    message: "SSO entitlement commit failed".into(),
                })
            }
            _ => return Err(failed("SSO entitlement transaction unavailable")),
        }
        let rows=exec.read("SELECT email,EXISTS(SELECT 1 FROM admin_role_assignments ara WHERE ara.user_id=u.id AND (ara.expires_at IS NULL OR ara.expires_at>now())) FROM users u WHERE u.id=$1 AND u.enabled",&[(&user,Type::INT8)]).await.map_err(|_|failed("SSO authorization state unavailable"))?;
        let r = rows
            .first()
            .ok_or_else(|| failed("SSO authorization state unavailable"))?;
        Ok(crate::totp::CompletionUser {
            user,
            email: r.get(0),
            admin: r.get(1),
        })
    }
}
fn json_row(rows: &[setjoin_pg::Row]) -> Result<Value, StatementFailure> {
    serde_json::from_str(
        &rows
            .first()
            .ok_or_else(|| failed("empty SSO result"))?
            .get::<_, String>(0),
    )
    .map_err(|_| failed("invalid SSO result"))
}
pub fn normalized_email(raw: &str) -> Option<String> {
    let s = setjoin_authz::address::canonical(raw).as_str().to_owned();
    let (local, domain) = s.rsplit_once('@')?;
    // Shared Go provisioning grammar (matching uses the less restrictive fold).
    if s.len() > 254
        || s.bytes().any(|b| b < 32 || b == 127)
        || local.is_empty()
        || !local.is_ascii()
        || local.contains("..")
        || local.starts_with('.')
        || local.ends_with('.')
        || domain.is_empty()
        || !domain.contains('.')
        || domain.contains('_')
        || domain.starts_with('[')
        || local.contains([' ', '<', '>'])
    {
        return None;
    }
    if matches!(
        local.trim_matches('"'),
        "postmaster" | "abuse" | "webmaster" | "hostmaster" | "mailer-daemon" | "nobody"
    ) {
        return None;
    }
    let parsed = mailparse::addrparse(&s).ok()?;
    if parsed.len() != 1 || !matches!(&parsed[0],mailparse::MailAddr::Single(a) if a.addr==s) {
        return None;
    }
    Some(s)
}
impl Resolution {
    pub async fn mint(
        &self,
        exec: &ScopedExecutor,
        refresh: &str,
        expiry: i64,
        family: &str,
    ) -> setjoin_pg::CommandOutcome<Value, StatementFailure> {
        use sha2::{Digest, Sha256};
        let user = self.user.user;
        let hash = Sha256::digest(refresh.as_bytes()).to_vec();
        let fence = self.fence.as_ref().map(Value::to_string);
        exec.clone()
            .with_user_receipt(setjoin_pg::ReceiptCommand {
                family: "F21",
                command: "rp-mint",
            })
            .run_user_command(
                setjoin_contracts::ids::ActorId::new(user).expect("resolved user"),
                setjoin_contracts::ids::OperationId(
                    *uuid::Uuid::parse_str(family)
                        .expect("generated family")
                        .as_bytes(),
                ),
                "SELECT rust_identity_rp_mint($1,$2::text::jsonb,$3,$4,$5::text::uuid)::text",
                &[
                    (&user, Type::INT8),
                    (&fence, Type::TEXT),
                    (&hash, Type::BYTEA),
                    (&expiry, Type::INT8),
                    (&family, Type::TEXT),
                ],
                json_row,
            )
            .await
    }
}

impl Missing<'_> {
    pub async fn create(
        self,
        exec: &ScopedExecutor,
        worker: &ScopedExecutor,
    ) -> Result<Resolution, StatementFailure> {
        let a = self.assertion;
        let email = normalized_email(&a.email).ok_or_else(|| failed("user creation failed"))?;
        let (local, domain) = email
            .split_once('@')
            .ok_or_else(|| failed("user creation failed"))?;
        // Owner-approved security fix 2026-11-05 (#547): with `feature.identity_model_v2` on, the
        // settlement that follows reconciles with normalized=true and needs the authentication
        // link. A source in shadow (or legacy) read mode used to create a legacy user without one,
        // so every retry failed 409 against an orphan. Create user and link together through the
        // same reducer whenever the feature is on; only a serving source keeps the mint fence.
        let through_link = self.normalized
            || (self.feature && !crate::mutants::on("rp-jit-shadow-orphan"));
        let (user, fence) = if through_link {
            let rows = worker
                .protocol_query(
                    "SELECT identity_auth_jit($5,$1,$2,$3,$4)::text",
                    &[
                        (&a.issuer, Type::TEXT),
                        (&a.subject, Type::TEXT),
                        (&email, Type::TEXT),
                        (&local, Type::TEXT),
                        (&a.kind, Type::TEXT),
                    ],
                )
                .await
                .map_err(|_| failed("user creation failed"))?;
            let value = json_row(&rows).map_err(|_| failed("user creation failed"))?;
            // `identity_auth_jit` answers a soft address collision as {state:'blocked'}: an
            // existing person holds the address and email is not proof, so a link is required.
            if value["state"] == "blocked" && !crate::mutants::on("rp-jit-blocked-500") {
                return Err(failed("explicit account linking is required"));
            }
            let user = number(&value, "userId").map_err(|_| failed("user creation failed"))?;
            if !self.normalized && value["created"] != true {
                // Not serving: an existing link here means legacy and normalized disagree.
                return Err(failed("user creation failed"));
            }
            let fence = if self.normalized {
                Some(json!({"source_id":number(&value,"sourceId")?,"source_generation":number(&value,"sourceGeneration")?,"link_id":number(&value,"linkId")?,"link_generation":number(&value,"linkGeneration")?}))
            } else {
                None
            };
            (user, fence)
        } else {
            let rows=exec.protocol_query("INSERT INTO users(username,email,display_name,domain_id,sync_source,enabled,oidc_subject,oidc_issuer,saml_name_id,saml_idp_entity_id) SELECT $1,$2,$1,id,'sso',true,CASE WHEN $6='oidc' THEN NULLIF($3,'') END,CASE WHEN $6='oidc' THEN NULLIF($4,'') END,CASE WHEN $6='saml' THEN NULLIF($3,'') END,CASE WHEN $6='saml' THEN NULLIF($4,'') END FROM domains WHERE name=$5 AND is_local ON CONFLICT DO NOTHING RETURNING id",&[(&local,Type::TEXT),(&email,Type::TEXT),(&a.subject,Type::TEXT),(&a.issuer,Type::TEXT),(&domain,Type::TEXT),(&a.kind,Type::TEXT)]).await.map_err(|_|failed("user creation failed"))?;
            let user = rows
                .first()
                .ok_or_else(|| failed("user creation failed"))?
                .get::<_, i64>(0);
            // Go's separate best-effort legacy mailbox statement.
            let _=exec.protocol_statement("INSERT INTO mailboxes(user_id,domain_id,email,display_name,type,is_primary) SELECT u.id,u.domain_id,u.email,u.display_name,'personal',true FROM users u WHERE u.id=$1 ON CONFLICT DO NOTHING",&[(&user,Type::INT8)]).await;
            (user, None)
        };
        let rows=exec.read("SELECT email,EXISTS(SELECT 1 FROM admin_role_assignments ara WHERE ara.user_id=u.id AND (ara.expires_at IS NULL OR ara.expires_at>now())) FROM users u WHERE u.id=$1 AND u.enabled",&[(&user,Type::INT8)]).await.map_err(|_|failed("user creation failed"))?;
        let r = rows.first().ok_or_else(|| failed("user creation failed"))?;
        Ok(Resolution {
            user: crate::totp::CompletionUser {
                user,
                email: r.get(0),
                admin: r.get(1),
            },
            fence,
        })
    }
}
impl Resolution {
    pub fn normalized(&self) -> bool {
        self.fence.is_some()
    }
    /// Keep the normalized source/link fence through admission, signing, anchor
    /// and Go's independent best-effort tail; no credential publishes in callbacks.
    pub async fn mint_normalized<P, PF, F, FF>(
        &self,
        worker: &ScopedExecutor,
        prepare: P,
        tail: F,
    ) -> setjoin_pg::CommandOutcome<Value, StatementFailure>
    where
        P: FnOnce(String) -> PF,
        PF: Future<Output = Result<(String, i64), Value>>,
        F: FnOnce(&Value) -> FF,
        FF: Future<Output = ()>,
    {
        use sha2::{Digest, Sha256};
        let user = self.user.user;
        let f = self.fence.as_ref().expect("normalized resolution");
        let source = f["source_id"].as_i64().unwrap();
        let source_gen = f["source_generation"].as_i64().unwrap();
        let link = f["link_id"].as_i64().unwrap();
        let link_gen = f["link_generation"].as_i64().unwrap();
        let operation = uuid::Uuid::new_v4();
        let family = operation.to_string();
        let fence = f.to_string();
        worker.clone().with_user_receipt(setjoin_pg::ReceiptCommand{family:"F21",command:"rp-mint"}).run_user_async_proof_command_with_tail(
            setjoin_contracts::ids::ActorId::new(user).expect("resolved principal"),setjoin_contracts::ids::OperationId(*operation.as_bytes()),
            "SELECT identity_auth_mint_fence($1,$2,$3,$4,$5)",&[(&user,Type::INT8),(&source,Type::INT8),(&source_gen,Type::INT8),(&link,Type::INT8),(&link_gen,Type::INT8)],
            |_|async move{
                let (refresh,expiry)=match prepare(family.clone()).await{Ok(v)=>v,Err(v)=>return Ok(setjoin_pg::ProvenStatement::new("SELECT $1::text").bind(v.to_string(),Type::TEXT))};
                Ok(setjoin_pg::ProvenStatement::new("SELECT rust_identity_rp_mint($1,$2::text::jsonb,$3,$4,$5::text::uuid)::text").bind(user,Type::INT8).bind(fence,Type::TEXT).bind(Sha256::digest(refresh.as_bytes()).to_vec(),Type::BYTEA).bind(expiry,Type::INT8).bind(family,Type::TEXT))
            },json_row,tail).await
    }
}

impl Resolution {
    pub async fn guest_scope(&self, exec: &ScopedExecutor) -> Result<bool, StatementFailure> {
        Ok(exec
            .read(
                "SELECT is_guest_account($1)",
                &[(&self.user.user, Type::INT8)],
            )
            .await?[0]
            .get(0))
    }
}
