//! Shared HTTP Basic (#355a) and Kerberos/SPNEGO Negotiate (#355b) credential
//! verification for DAV and native Drive token routes.
use crate::{runtime_access::RuntimeGate, Body, RequestContext};
use base64::{engine::general_purpose::STANDARD, Engine};
use hyper::{HeaderMap, Request, Response};
use setjoin_authz::{
    auth_chain::Chain,
    basic::{PasswordCache, Verified},
    kerberos::KerberosValidator,
    policy_gate::{
        self, BoxFuture as GateBoxFuture, GateDenial, GateThreatAction, GateThreatMeta,
        ProtocolSurface, ThreatAdapter,
    },
};
use setjoin_pg::ScopedExecutor;
use setjoin_threat::{ConnectionMeta, ThreatAction, ThreatGate};
use std::{sync::Arc, time::Duration};

struct ThreatBridge(Arc<dyn ThreatGate>);

impl ThreatBridge {
    fn to_meta(meta: &GateThreatMeta) -> ConnectionMeta {
        ConnectionMeta {
            source_ip: meta.source_ip.clone(),
            username: meta.username.clone(),
            protocol: meta.protocol.clone(),
            user_agent: meta.user_agent.clone(),
            user_id: meta.user_id,
            app_password: meta.app_password,
            device_bound: meta.device_bound,
            ..Default::default()
        }
    }

    fn from_action(action: ThreatAction) -> GateThreatAction {
        match action {
            ThreatAction::Allow => GateThreatAction::Allow,
            ThreatAction::Reject => GateThreatAction::Reject,
            ThreatAction::Tarpitted => GateThreatAction::Tarpitted,
            ThreatAction::RateLimited => GateThreatAction::RateLimited,
        }
    }
}

impl ThreatAdapter for ThreatBridge {
    fn intercept<'a>(
        &'a self,
        meta: &'a GateThreatMeta,
    ) -> GateBoxFuture<'a, (GateThreatAction, Duration)> {
        let cm = Self::to_meta(meta);
        Box::pin(async move {
            let (action, delay) = self.0.intercept(&cm).await;
            (Self::from_action(action), delay)
        })
    }

    fn check_account_lockout<'a>(
        &'a self,
        meta: &'a GateThreatMeta,
    ) -> GateBoxFuture<'a, (GateThreatAction, Duration)> {
        let cm = Self::to_meta(meta);
        Box::pin(async move {
            let (action, delay) = self.0.check_account_lockout(&cm).await;
            (Self::from_action(action), delay)
        })
    }

    fn record_result<'a>(
        &'a self,
        meta: &'a GateThreatMeta,
        success: bool,
        user_id: i64,
    ) -> GateBoxFuture<'a, ()> {
        let cm = Self::to_meta(meta);
        Box::pin(async move { self.0.record_result(&cm, success, user_id).await })
    }

    fn record_ip_failure<'a>(&'a self, meta: &'a GateThreatMeta) -> GateBoxFuture<'a, ()> {
        let cm = Self::to_meta(meta);
        Box::pin(async move { self.0.record_ip_failure(&cm).await })
    }

    fn evaluate_post_auth<'a>(
        &'a self,
        meta: &'a mut GateThreatMeta,
    ) -> GateBoxFuture<'a, (GateThreatAction, String)> {
        let mut cm = Self::to_meta(meta);
        Box::pin(async move {
            let (action, reason) = self.0.evaluate_post_auth(&mut cm).await;
            (Self::from_action(action), reason)
        })
    }
}

#[derive(Clone)]
pub struct DavBasicAuth {
    pub chain: Option<Arc<Chain>>,
    pub password_cache: Arc<PasswordCache>,
    pub threat: Option<Arc<dyn ThreatGate>>,
    pub runtime: Option<Arc<dyn RuntimeGate>>,
    pub kerberos: Option<Arc<dyn KerberosValidator>>,
}

impl Default for DavBasicAuth {
    fn default() -> Self {
        Self {
            chain: None,
            password_cache: Arc::new(PasswordCache::new()),
            threat: None,
            runtime: None,
            kerberos: None,
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
        let Some(threat) = self.threat.as_ref() else {
            if !self.chain.as_ref().is_none_or(|ch| ch.basic_allowed()) {
                return Err(crate::deny::unauthorized(r.headers(), c));
            }
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
            .unwrap_or("");
        let bridge = ThreatBridge(threat.clone());
        let client_ip = c.identity.client_ip.to_string();
        let user = policy_gate::verify_basic_with_threat(
            exec,
            &self.password_cache,
            self.chain.as_deref(),
            &bridge,
            ProtocolSurface::CalDav,
            &email,
            &secret,
            &client_ip,
            ua,
        )
        .await
        .map_err(|denial| match denial {
            GateDenial::Unavailable(_) => {
                crate::admission::problem(r.headers(), &c.identity, 503, "service unavailable")
            }
            _ => crate::deny::unauthorized(r.headers(), c),
        })?;
        if let Some(runtime) = &self.runtime {
            if let Some(resp) = runtime.enforce_basic(r, c, user.user_id).await {
                return Err(resp);
            }
        }
        Ok(user)
    }

    /// Authenticate an `Authorization: Negotiate ...` header natively (#355b, #542)
    /// via `PolicyGate`'s shared two-phase ThreatGate + SPNEGO verifier.
    pub async fn authenticate_negotiate(
        &self,
        exec: &ScopedExecutor,
        r: &mut Request<Body>,
        c: &RequestContext,
    ) -> Result<Verified, Response<Body>> {
        if !has_scheme(r.headers(), b"Negotiate ") {
            return Err(crate::deny::unauthorized(r.headers(), c));
        }
        if !self.chain.as_ref().is_some_and(|ch| ch.kerberos_allowed())
            || self.kerberos.is_none()
        {
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
        let client_ip = c.identity.client_ip.to_string();
        let ua = r
            .headers()
            .get(hyper::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let bridge = ThreatBridge(threat.clone());
        let user = policy_gate::verify_negotiate_two_phase(
            exec,
            self.chain.as_deref(),
            self.kerberos.as_deref(),
            &bridge,
            r.headers(),
            &client_ip,
            ua,
        )
        .await
        .map_err(|denial| match denial {
            GateDenial::Unavailable(_) => {
                crate::admission::problem(r.headers(), &c.identity, 503, "service unavailable")
            }
            _ => crate::deny::unauthorized(r.headers(), c),
        })?;
        if let Some(runtime) = &self.runtime {
            if let Some(resp) = runtime.enforce_kerberos(r, c, user.user_id).await {
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
