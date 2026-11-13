use super::{
    JmapCommands,
    http::{envelope, problem},
    reply,
    token::KeySource,
};
use crate::{Body, RequestContext, recovery_worker::ObjectStore};
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response};
use setjoin_contracts::ids::{ActorId, Generation, MailboxId};
use setjoin_pg::MailboxAuthContext;
use sha2::{Digest, Sha256};
impl<K: KeySource> JmapCommands<K> {
    pub(super) async fn recovery_raw(
        &self,
        req: &Request<Body>,
        ctx: &RequestContext,
        auth: &MailboxAuthContext,
        id: &str,
    ) -> Response<Body> {
        let services = self.services.as_ref().unwrap();
        let Some(boot) = services.continuity_boot.as_deref() else {
            return problem(
                404,
                "notFound",
                "recovery raw endpoint is disabled",
                ctx,
                id,
            );
        };
        if super::gates::toggle_state(&self.exec, "feature.client_recovery_receipts").await
            != Some(true)
        {
            return problem(
                404,
                "notFound",
                "recovery raw endpoint is disabled",
                ctx,
                id,
            );
        }
        let parts = req.uri().path()[19..]
            .split('/')
            .map(|s| String::from_utf8_lossy(&crate::inventory::unescape(s)).into_owned())
            .collect::<Vec<_>>();
        let account = parts[0].parse::<i64>().ok().filter(|n| *n > 0);
        let message = parts[1].parse::<i64>().ok().filter(|n| *n > 0);
        let denied = || problem(403, "forbidden", "recovery account access denied", ctx, id);
        let (Some(account), Some(message)) = (account, message) else {
            return denied();
        };
        if !setjoin_jmap::http_blob::account_read(&services.worker, auth, account)
            .await
            .unwrap_or(false)
        {
            return denied();
        }
        let target = MailboxAuthContext::from_authenticated_session(
            ActorId::new(auth.actor().get()).unwrap(),
            MailboxId::new(account).unwrap(),
            Generation(1),
        );
        let Some(operation) = super::random() else {
            return problem(500, "serverFail", "recovery context unavailable", ctx, id);
        };
        let env = envelope(
            &target,
            operation,
            Sha256::digest(req.uri().to_string()).into(),
        );
        let missing = || {
            problem(
                404,
                "emailNotFound",
                "recoverable message not found",
                ctx,
                id,
            )
        };
        let raw = match setjoin_jmap::http_blob::recovery_context(
            &self.exec, &target, &env, message, boot,
        )
        .await
        {
            setjoin_pg::CommandOutcome::Committed(raw) => raw,
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                let mut r = problem(
                    503,
                    "serverUnavailable",
                    "recovery outcome unknown",
                    ctx,
                    id,
                );
                r.headers_mut().insert(
                    "x-operation-id",
                    setjoin_pg::operation_hex(operation).parse().unwrap(),
                );
                return r;
            }
            _ => return missing(),
        };
        let value: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(_) => return missing(),
        };
        let Some(list) = value["list"].as_array().filter(|l| l.len() == 1) else {
            return missing();
        };
        let Some(reference) = list[0]["rawRef"].as_str() else {
            return missing();
        };
        let unavailable = || problem(503, "serverUnavailable", "raw MIME unavailable", ctx, id);
        let bytes = if reference.contains('\n') {
            reference.as_bytes().to_vec()
        } else {
            let Some(store) = &services.store else {
                return unavailable();
            };
            match store.read(reference, (50 << 20) + 1).await {
                Ok(bytes) => bytes,
                Err(_) => return unavailable(),
            }
        };
        if bytes.is_empty() || bytes.len() > 50 << 20 {
            return unavailable();
        }
        let mut r = reply::response(String::new(), ctx.identity.proto, id.into());
        let len = bytes.len();
        *r.body_mut() = Full::new(bytes::Bytes::from(bytes))
            .map_err(|n| match n {})
            .boxed();
        let h = r.headers_mut();
        h.insert("content-type", "message/rfc822".parse().unwrap());
        h.insert("content-length", len.to_string().parse().unwrap());
        h.insert(
            "content-disposition",
            format!("attachment; filename=\"recovery-{message}.eml\"")
                .parse()
                .unwrap(),
        );
        h.insert(
            "content-security-policy",
            "default-src 'none'; sandbox".parse().unwrap(),
        );
        r
    }
}

/// Go disables this surface when loading fails; it does not generate a key.
pub(super) fn boot_from_env() -> Option<String> {
    let path = std::env::var_os("CONTINUITY_SIGNING_KEY_FILE")
        .unwrap_or_else(|| "/etc/setjoin/continuity-signing-key.pem".into());
    let path = std::path::Path::new(&path);
    if !path.is_absolute()
        || path
            .components()
            .collect::<std::path::PathBuf>()
            .as_os_str()
            != path.as_os_str()
    {
        return None;
    }
    let id = std::env::var("CONTINUITY_SIGNING_KEY_ID").unwrap_or_else(|_| "continuity-v1".into());
    if id.is_empty()
        || id.len() > 64
        || !id.as_bytes()[0].is_ascii_alphanumeric()
        || !id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._:-".contains(&c))
    {
        return None;
    }
    let pem = zeroize::Zeroizing::new(std::fs::read(path).ok()?);
    let begin = pem.windows(11).position(|v| v == b"-----BEGIN ")?;
    if !pem[begin..].starts_with(b"-----BEGIN PRIVATE KEY-----") {
        return None;
    }
    let footer = b"-----END PRIVATE KEY-----";
    let end = pem.windows(footer.len()).position(|v| v == footer)? + footer.len();
    if !matches!(&pem[end..], b"" | b"\n" | b"\r\n") {
        return None;
    }
    use tokio_rustls::rustls::pki_types::{PrivateKeyDer, pem::PemObject};
    let key = PrivateKeyDer::from_pem_slice(&pem).ok()?;
    let der = zeroize::Zeroizing::new(key.secret_der().to_vec());
    ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(&der).ok()?;
    super::http::uuid()
}
