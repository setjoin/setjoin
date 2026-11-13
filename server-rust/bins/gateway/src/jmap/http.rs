//! JMAP HTTP peripherals (#316), sharing the verified request admission chain.
use super::{JmapCommands, reply, token::KeySource};
use crate::{Body, RequestContext};
use hyper::{Method, Request, Response};
use serde_json::{Value, json};
use setjoin_contracts::ids::{ActorId, Generation, MailboxId};
use setjoin_pg::MailboxAuthContext;

pub fn matches(method: &Method, path: &str) -> bool {
    (*method == Method::POST
        && matches!(
            path,
            "/api/mail/attachment-transfer-token" | "/mail/attachment-transfer-token"
        ))
        || (matches!(*method, Method::GET | Method::HEAD) && path == "/.well-known/jmap")
        || (*method == Method::POST
            && path.starts_with("/jmap/upload/")
            && !path[13..].is_empty()
            && path[13..].split('/').count() == 1)
        || (matches!(*method, Method::GET | Method::HEAD)
            && path.starts_with("/jmap/download/")
            && path[15..].split('/').count() == 3
            && !path[15..].split('/').any(str::is_empty))
        || (matches!(*method, Method::GET | Method::HEAD)
            && path.starts_with("/jmap/recovery-raw/")
            && path[19..].split('/').count() == 2
            && !path[19..].split('/').any(str::is_empty))
}
impl<K: KeySource> JmapCommands<K> {
    pub(super) async fn try_http(
        &self,
        req: &mut Request<Body>,
        ctx: &RequestContext,
    ) -> Option<Response<Body>> {
        let services = self.services.as_ref()?;
        let authorized = setjoin_authz::authorize_user_request(
            &self.exec,
            &self.keys,
            &self.issuer,
            req.headers(),
            ctx.identity.proto,
        )
        .await?;
        let actor = authorized.context();
        if actor.mailbox_id() == 0 && req.uri().path() == "/.well-known/jmap" {
            let id=reply::request_id(req.headers().get("x-request-id"),super::random()?);
            return Some(guest_session(&self.exec,actor.user_id(),ctx,id).await);
        }
        let auth = MailboxAuthContext::from_authenticated_session(
            ActorId::new(actor.user_id()).ok()?,
            MailboxId::new(actor.mailbox_id()).ok()?,
            Generation(1),
        );
        let id = reply::request_id(req.headers().get("x-request-id"), super::random()?);
        if req
            .uri()
            .path()
            .ends_with("/mail/attachment-transfer-token")
        {
            return Some(self.mint_transfer(req, ctx, &auth, &authorized, &id).await);
        }
        if req.uri().path().starts_with("/jmap/upload/") {
            return Some(self.upload(req, ctx, &auth, &id).await);
        }
        if req.uri().path().starts_with("/jmap/download/") {
            return Some(self.download(req, ctx, &auth, &id).await);
        }
        if req.uri().path().starts_with("/jmap/recovery-raw/") {
            let mut response = self.recovery_raw(req, ctx, &auth, &id).await;
            let cache = if response.status().is_success() {
                "private, no-store"
            } else {
                "no-store"
            };
            response
                .headers_mut()
                .insert("cache-control", cache.parse().unwrap());
            return Some(response);
        }
        let s = setjoin_jmap::session::settings(&self.exec, &auth).await;
        let enabled = |key: &str| s.flags.get(key).copied().unwrap_or(false);
        let tasks = json!({"sharedLists":enabled("feature.shared_task_lists")});
        let submission = json!({"maxDelayedSend":31536000,"submissionExtensions":{}});
        let vendor = "urn:setjoin:params:jmap:mail";
        let mailbox = actor.mailbox_id().to_string();
        let base = format!("https://{}", services.hostname);
        let platform = req
            .headers()
            .get("x-setjoin-native-platform")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        let caps = if !authorized.device_id().is_empty()
            && matches!(platform, "desktop" | "ios" | "android")
        {
            let operation = super::random()?;
            let envelope = setjoin_contracts::command::CommandEnvelope {
                operation: setjoin_contracts::ids::OperationId(operation),
                authority: auth.authority(),
                binding: setjoin_db::lifecycle::accepted_contract(),
                payload_digest: setjoin_contracts::ids::Digest(
                    <sha2::Sha256 as sha2::Digest>::digest(format!(
                        "{}:{platform}",
                        authorized.device_id()
                    ))
                    .into(),
                ),
                command: (),
            };
            match setjoin_jmap::session::register_device(
                &self.exec,
                &auth,
                &envelope,
                authorized.device_id(),
                platform,
            )
            .await
            {
                setjoin_pg::CommandOutcome::Committed(device) => {
                    setjoin_jmap::session::device_caps(&self.exec, &auth, device).await
                }
                setjoin_pg::CommandOutcome::Unknown { operation } => {
                    let mut response = reply::response(
                        "native device registration outcome unknown\n".into(),
                        ctx.identity.proto,
                        id,
                    );
                    *response.status_mut() = hyper::StatusCode::SERVICE_UNAVAILABLE;
                    response.headers_mut().insert(
                        "x-operation-id",
                        setjoin_pg::operation_hex(operation).parse().ok()?,
                    );
                    return Some(response);
                }
                _ => setjoin_jmap::session::effective_caps(&self.exec, &auth).await,
            }
        } else {
            setjoin_jmap::session::effective_caps(&self.exec, &auth).await
        };
        let mut effective: Value = match caps {
            Ok(raw) => serde_json::from_str(&raw).ok()?,
            Err(_) => {
                json!({"apps":{"mail":false,"calendar":false,"contacts":false,"tasks":false,"approvals":false,"drive":false,"chat":false,"meet":false},
                "features":{"assist":false,"bundles":false,"external_labels":false,"guest_accounts":false,"guest_invite":false,"mail_search_builder":false,"sender_control_center":false,"shared_mail_work":false,"shared_mail_comments":false},
                "offline":{"allowed":false,"approvalState":"pending","maxOfflineDays":0,"wipeOnLogout":"admin_default","requireApproval":true,"biometricUnlock":false,"windowsSsoUnlock":false}})
            }
        };
        if let Some(offline) = effective.get_mut("offline").and_then(Value::as_object_mut) {
            offline.insert(
                "biometricUnlock".into(),
                json!(enabled("feature.biometric_unlock")),
            );
            offline.insert(
                "windowsSsoUnlock".into(),
                json!(enabled("feature.windows_sso_unlock")),
            );
        }
        let permissions = if actor.signed_admin() {
            setjoin_jmap::session::permissions(&services.worker, &auth)
                .await
                .unwrap_or_else(|_| {
                    // Owner-approved security fix 2026-11-05 (#484): fail closed.
                    if setjoin_contracts::mutants::on("authority-lookup-keeps-signed-grants") {
                        actor.signed_permissions().to_vec()
                    } else {
                        Vec::new()
                    }
                })
        } else {
            actor.signed_permissions().to_vec()
        };
        let mut capabilities = json!({
            "urn:ietf:params:jmap:core":{"maxSizeUpload":services.max_upload,"maxConcurrentUpload":4,"maxSizeRequest":10000000,"maxConcurrentRequests":4,"maxCallsInRequest":32,"maxObjectsInGet":256,"maxObjectsInSet":128,"collationAlgorithms":["i;unicode-casemap"]},
            "urn:ietf:params:jmap:mail":{},"urn:ietf:params:jmap:calendars":{},"urn:ietf:params:jmap:contacts":{},
            "urn:ietf:params:jmap:tasks":tasks,"urn:ietf:params:jmap:submission":submission,
            "urn:setjoin:params:jmap:reminders":{},"urn:ietf:params:jmap:blob":{"maxSizeBlobSet":services.max_upload,"supportedTypeNames":["application/octet-stream"]},
            (vendor):{"snoozeUntilOnEmailSet":true,"sendAtOnEmailSubmissionSet":true,"emailSubmissionGetAndQuery":true,"effectiveAccess":true,"newsletterBundles":true,"admin":{"consoles":consoles(&permissions),"permissions":permissions}},
        });
        if s.strict {
            capabilities[vendor]["appsStrictEntitlements"] = json!(true);
        }
        let account_caps = json!({"urn:ietf:params:jmap:mail":{},"urn:ietf:params:jmap:calendars":{},"urn:ietf:params:jmap:contacts":{},"urn:ietf:params:jmap:tasks":tasks,"urn:ietf:params:jmap:submission":submission,"urn:ietf:params:jmap:blob":{},(vendor):{}});
        let mut body = json!({
            "capabilities":capabilities,"accounts":{(mailbox.clone()):{"name":actor.email(),"isPersonal":true,"isReadOnly":false,"accountCapabilities":account_caps}},
            "primaryAccounts":{"urn:ietf:params:jmap:mail":mailbox,"urn:ietf:params:jmap:calendars":mailbox,"urn:ietf:params:jmap:contacts":mailbox,"urn:ietf:params:jmap:tasks":mailbox},
            "username":actor.email(),"apiUrl":format!("{base}/jmap"),"downloadUrl":format!("{base}/jmap/download/{{accountId}}/{{blobId}}/{{name}}?type={{type}}"),
            "uploadUrl":format!("{base}/jmap/upload/{{accountId}}"),"eventSourceUrl":format!("{base}/jmap/eventsource?types={{types}}&closeafter={{closeafter}}&ping={{ping}}"),
            "state":authorized.session_state().encode(),"purgeConfig":{"deletedPurgeDays":s.deleted_days,"spamPurgeDays":s.spam_days},
            "branding":{"name":s.brand_name,"logoUrl":s.brand_logo},"effectiveCapabilities":effective,
        });
        if let Ok(delegated) = setjoin_jmap::session::delegated(&services.worker, &auth).await {
            for d in delegated {
                let has = |grant: &str| d.grants.iter().any(|g| g == grant);
                let mut caps = json!({"urn:ietf:params:jmap:mail":{},(vendor):{"delegateGrants":d.grants,"sendAsAliases":d.aliases}});
                if has("send_as") || has("send_on_behalf") || has("full_access") {
                    caps["urn:ietf:params:jmap:submission"] = submission.clone();
                }
                body["accounts"][d.id.to_string()] = json!({"name":d.email,"isPersonal":false,"isReadOnly":!has("full_access"),"accountCapabilities":caps});
            }
        }
        if enabled("dengbao.sod_mode") {
            if let Ok(class) = setjoin_jmap::session::sod_class(&services.worker, &auth).await {
                body["dengbao"] = json!({"sodMode":true,"sodClass":class});
            }
        }
        if !s.help_email.is_empty() {
            body["helpEmail"] = json!(s.help_email);
        }
        let body = reply::go_compact(&body.to_string())? + "\n";
        Some(reply::response(body, ctx.identity.proto, id))
    }
}

pub(super) fn problem(
    status: u16,
    kind: &str,
    detail: &str,
    ctx: &RequestContext,
    id: &str,
) -> Response<Body> {
    let mut r = reply::response(
        crate::problem::jmap(status, kind, detail) + "\n",
        ctx.identity.proto,
        id.into(),
    );
    *r.status_mut() = hyper::StatusCode::from_u16(status).unwrap();
    r.headers_mut()
        .insert("content-type", "application/problem+json".parse().unwrap());
    r
}
pub(super) fn envelope(
    auth: &MailboxAuthContext,
    operation: [u8; 16],
    digest: [u8; 32],
) -> setjoin_contracts::command::CommandEnvelope<()> {
    setjoin_contracts::command::CommandEnvelope {
        operation: setjoin_contracts::ids::OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: setjoin_contracts::ids::Digest(digest),
        command: (),
    }
}

// Frozen Go console visibility matrix; this projection grants no authority.
const CONSOLES: [(&str, &[&str]); 5] = [
    (
        "mail",
        &[
            "domains.read",
            "queue.read",
            "reports.read",
            "mail.pipeline",
            "mail.security",
            "exchange.assessment.read",
            "exchange.assessment.run",
            "exchange.assessment.decide",
            "exchange.assessment.attest",
            "exchange.assessment.audit",
            "exchange.assessment.publish",
            "exchange.assessment.delete",
        ],
    ),
    (
        "system",
        &[
            "system.config",
            "system.upgrade",
            "backup.read",
            "mail.offline_policy",
            "office.view",
            "office.manage",
        ],
    ),
    ("logs", &["audit.read"]),
    (
        "auth",
        &[
            "users.read",
            "identity.write",
            "access.policy_read",
            "access.policy_write",
        ],
    ),
    (
        "access",
        &[
            "roles.manage",
            "sharing.read",
            "chat.compliance_view",
            "chat.compliance_manage",
            "chat.ediscovery",
            "drive.view",
            "federation.manage",
            "system.recovery",
        ],
    ),
];

/// Go's `ConsolesForPerms`: `None` is a nil slice, which Go renders as `null`.
fn consoles(perms: &[String]) -> Option<Vec<&'static str>> {
    let out: Vec<&'static str> = CONSOLES
        .iter()
        .filter(|(_, scopes)| scopes.iter().any(|w| perms.iter().any(|p| p == w)))
        .map(|(id, _)| *id)
        .collect();
    (!out.is_empty()).then_some(out)
}

pub(super) fn uuid() -> Option<String> {
    let mut b = super::random()?;
    b[6] = (b[6] & 15) | 64;
    b[8] = (b[8] & 63) | 128;
    let h = reply::hex(&b);
    Some(format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
}

async fn guest_session(exec:&setjoin_pg::ScopedExecutor,user:i64,ctx:&RequestContext,id:String)->Response<Body>{
    use setjoin_pg::Type;
    let mut chat=false;let mut meet=false;let mut drive=false;
    if let Ok(rows)=exec.read("SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key='feature.chat'),false) AND check_user_app_entitlement($1,'chat'), coalesce((SELECT enabled FROM feature_toggles WHERE key='feature.meet'),false) AND coalesce((SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'),false) AND check_user_app_entitlement($1,'meet'),coalesce((SELECT enabled FROM feature_toggles WHERE key='feature.drive'),false) AND coalesce((SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'),false) AND check_user_app_entitlement($1,'drive')",&[(&user,Type::INT8)]).await {
        if let Some(r)=rows.first(){chat=r.get(0);meet=r.get(1);drive=r.get(2);}
    }
    let mut create=false;let mut host=false;let mut download=false;
    if meet||drive {
        if let Ok(rows)=exec.read_user_scoped(ActorId::new(user).expect("verified guest"),
            "SELECT guest_profile_flag($1,'allow_meet_create'),guest_profile_flag($1,'allow_meet_host'),guest_profile_flag($1,'allow_download')",&[(&user,Type::INT8)]).await {
            if let Some(r)=rows.first(){if meet{create=r.get(0);host=r.get(1);}if drive{download=r.get(2);}}
        }
    }
    let value=json!({"accounts":{},"capabilities":{},"isGuest":true,"effectiveCapabilities":{
        "apps":{"mail":false,"calendar":false,"contacts":false,"tasks":false,"approvals":false,"drive":false,"chat":chat,"meet":meet},
        "features":{"assist":false,"bundles":false,"external_labels":false,"guest_accounts":false,"guest_invite":false,"mail_search_builder":false,"sender_control_center":false,"shared_mail_work":false,"shared_mail_comments":false},
        "guest":{"allowMeetCreate":create,"allowMeetHost":host,"allowDownload":download},
        "offline":{"allowed":false,"approvalState":"pending","maxOfflineDays":0,"wipeOnLogout":"admin_default","requireApproval":true,"biometricUnlock":false,"windowsSsoUnlock":false}}});
    reply::response(value.to_string()+"\n",ctx.identity.proto,id)
}
