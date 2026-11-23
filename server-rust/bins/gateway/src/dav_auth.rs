//! Shared HTTP Basic credential verification for DAV and native Drive token routes (#355a).
use crate::{runtime_access::RuntimeGate, Body, RequestContext};
use base64::{engine::general_purpose::STANDARD, Engine};
use hyper::{HeaderMap, Request, Response};
use setjoin_authz::{
    auth_chain::Chain,
    basic::{self, PasswordCache, Verdict, Verified, DAV_POLICY},
};
use setjoin_pg::ScopedExecutor;
use setjoin_threat::{ConnectionMeta, ThreatAction, ThreatGate};
use std::sync::Arc;

#[derive(Clone)]
pub struct DavBasicAuth {
    pub chain: Option<Arc<Chain>>,
    pub password_cache: Arc<PasswordCache>,
    pub threat: Option<Arc<dyn ThreatGate>>,
    pub runtime: Option<Arc<dyn RuntimeGate>>,
}

impl Default for DavBasicAuth {
    fn default() -> Self {
        Self {
            chain: None,
            password_cache: Arc::new(PasswordCache::new()),
            threat: None,
            runtime: None,
        }
    }
}

impl DavBasicAuth {
    /// Authenticate an `Authorization: Basic ...` header with the #355a policy
    /// (app passwords only, guest/TOTP-account passwords refused), shared
    /// `ThreatGate` (`protocol = "http"`), and `RuntimeGate::enforce_basic`.
    pub async fn authenticate(
        &self,
        exec: &ScopedExecutor,
        r: &mut Request<Body>,
        c: &RequestContext,
    ) -> Result<Verified, Response<Body>> {
        let Some((email, secret)) = parse_basic_header(r.headers()) else {
            return Err(crate::deny::unauthorized(r.headers(), c));
        };
        if !self.chain.as_ref().is_none_or(|ch| ch.basic_allowed()) {
            return Err(crate::deny::unauthorized(r.headers(), c));
        }
        let Some(threat) = self.threat.as_ref() else {
            return Err(crate::admission::problem(
                r.headers(),
                &c.identity,
                503,
                "service unavailable",
            ));
        };
        let ua = r
            .headers()
            .get(hyper::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let meta = ConnectionMeta {
            source_ip: c.identity.client_ip.to_string(),
            username: email.clone(),
            protocol: "http".into(),
            user_agent: ua,
            ..Default::default()
        };
        let (action, delay) = threat.intercept(&meta).await;
        match action {
            ThreatAction::Reject | ThreatAction::Tarpitted => {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                return Err(crate::deny::unauthorized(r.headers(), c));
            }
            ThreatAction::RateLimited => {
                return Err(crate::deny::unauthorized(r.headers(), c));
            }
            ThreatAction::Allow => {}
        }
        let verdict = basic::verify(exec, &self.password_cache, &email, &secret, DAV_POLICY).await;
        let (success, user_id, verified) = match verdict {
            Verdict::AppPassword(user) => (true, user.user_id, Some(user)),
            Verdict::AccountPassword(_) | Verdict::Refused => (false, 0, None),
        };
        threat.record_result(&meta, success, user_id).await;
        let Some(user) = verified else {
            return Err(crate::deny::unauthorized(r.headers(), c));
        };
        if let Some(runtime) = &self.runtime {
            if let Some(resp) = runtime.enforce_basic(r, c, user.user_id).await {
                return Err(resp);
            }
        }
        Ok(user)
    }
}

pub(crate) fn has_scheme(headers: &HeaderMap, prefix: &[u8]) -> bool {
    headers
        .get(hyper::header::AUTHORIZATION)
        .is_some_and(|v| v.as_bytes().starts_with(prefix))
}

fn parse_basic_header(headers: &HeaderMap) -> Option<(String, String)> {
    let encoded = headers
        .get(hyper::header::AUTHORIZATION)?
        .as_bytes()
        .strip_prefix(b"Basic ")?;
    let decoded = STANDARD.decode(encoded).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (email, secret) = text.split_once(':')?;
    Some((email.to_owned(), secret.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::{HeaderValue, AUTHORIZATION};

    fn auth_headers(value: &[u8]) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(AUTHORIZATION, HeaderValue::from_bytes(value).unwrap());
        h
    }

    #[test]
    fn parse_basic_header_enforces_case_strict_base64_and_colon() {
        assert_eq!(
            parse_basic_header(&auth_headers(b"Basic dXNlcjpzZWNyZXQ=")),
            Some(("user".into(), "secret".into()))
        );
        assert_eq!(
            parse_basic_header(&auth_headers(b"Basic dXNlcjpzZTpjcmV0")),
            Some(("user".into(), "se:cret".into()))
        );
        assert_eq!(
            parse_basic_header(&auth_headers(b"basic dXNlcjpzZWNyZXQ=")),
            None
        );
        assert_eq!(parse_basic_header(&auth_headers(b"Basic !!!")), None);
        assert_eq!(
            parse_basic_header(&auth_headers(b"Basic dXNlcjpzZWNyZXQ")),
            None
        );
        assert_eq!(parse_basic_header(&auth_headers(b"Basic dXNlcg==")), None);
        assert_eq!(parse_basic_header(&auth_headers(b"Basic //86YWI=")), None);
    }
}
